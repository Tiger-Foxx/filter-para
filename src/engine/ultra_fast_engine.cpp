#include "ultra_fast_engine.h"
#include "../utils.h"
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>

// ============================================================
// CONSTRUCTOR
// ============================================================
UltraFastEngine::UltraFastEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
    : RuleEngine(rules) {
    
    std::cout << "🚀 Initializing UltraFastEngine (Zero-Copy, Lock-Free)" << std::endl;
    
    BuildOptimizedIndex();
    
    std::cout << "✅ UltraFastEngine ready!" << std::endl;
    std::cout << "   • Blocked IPs (exact): " << blocked_ips_.size() << std::endl;
    std::cout << "   • Blocked IP ranges: " << blocked_ip_ranges_.size() << std::endl;
    std::cout << "   • Blocked src ports: " << blocked_src_ports_.size() << std::endl;
    std::cout << "   • Blocked dst ports: " << blocked_dst_ports_.size() << std::endl;
    std::cout << "   • URI patterns: " << uri_patterns_.size() << std::endl;
    std::cout << "   • Header patterns: " << header_patterns_.size() << std::endl;
}

// ============================================================
// BUILD OPTIMIZED INDEX
// ============================================================
void UltraFastEngine::BuildOptimizedIndex() {
    std::cout << "🔧 Building optimized rule index..." << std::endl;
    
    // ============================================================
    // L3: Index IP rules into hash tables
    // ============================================================
    if (rules_by_layer_.count(RuleLayer::L3)) {
        for (const auto& rule : rules_by_layer_.at(RuleLayer::L3)) {
            if (rule->type_str == "ip_src_in" || rule->type_str == "ip_dst_in") {
                for (const auto& value : rule->values) {
                    if (value.find('/') != std::string::npos) {
                        // CIDR range
                        auto [network, mask] = ParseCIDR(value);
                        blocked_ip_ranges_.push_back({network, mask, rule->id});
                    } else {
                        // Exact IP
                        uint32_t ip = IPStringToUint32(value);
                        blocked_ips_.insert(ip);
                    }
                }
            }
        }
    }
    
    // ============================================================
    // L4: Index port rules into hash tables
    // ============================================================
    if (rules_by_layer_.count(RuleLayer::L4)) {
        for (const auto& rule : rules_by_layer_.at(RuleLayer::L4)) {
            if (rule->type_str == "tcp_src_port" || rule->type_str == "udp_src_port") {
                for (const auto& value : rule->values) {
                    uint16_t port = static_cast<uint16_t>(std::stoi(value));
                    blocked_src_ports_.insert(port);
                }
            } else if (rule->type_str == "tcp_dst_port" || rule->type_str == "udp_dst_port") {
                for (const auto& value : rule->values) {
                    uint16_t port = static_cast<uint16_t>(std::stoi(value));
                    blocked_dst_ports_.insert(port);
                }
            }
        }
    }
    
    // ============================================================
    // L7: Compile regex patterns (with JIT)
    // ============================================================
    if (rules_by_layer_.count(RuleLayer::L7)) {
        for (const auto& rule : rules_by_layer_.at(RuleLayer::L7)) {
            if (rule->type_str == "http_uri_regex") {
                for (const auto& pattern : rule->values) {
                    FastPattern fp;
                    fp.pattern = pattern;
                    fp.rule_id = rule->id;
                    fp.action = rule->action;
                    
                    // Compile PCRE2 with JIT
                    int error_code;
                    PCRE2_SIZE error_offset;
                    fp.compiled = pcre2_compile(
                        (PCRE2_SPTR)pattern.c_str(),
                        PCRE2_ZERO_TERMINATED,
                        PCRE2_CASELESS | PCRE2_UTF,
                        &error_code,
                        &error_offset,
                        nullptr
                    );
                    
                    if (fp.compiled) {
                        // Enable JIT compilation for 10x speed boost
                        pcre2_jit_compile(fp.compiled, PCRE2_JIT_COMPLETE);
                        fp.match_data = pcre2_match_data_create_from_pattern(fp.compiled, nullptr);
                        uri_patterns_.push_back(std::move(fp));
                    }
                }
            } else if (rule->type_str == "http_header_contains") {
                // Simple substring matching for headers (faster than regex)
                for (const auto& pattern : rule->values) {
                    FastPattern fp;
                    fp.pattern = pattern;
                    fp.rule_id = rule->id;
                    fp.action = rule->action;
                    fp.compiled = nullptr;  // No regex for simple contains
                    fp.match_data = nullptr;
                    header_patterns_.push_back(std::move(fp));
                }
            }
        }
    }
    
    optimized_index_built_ = true;
}

// ============================================================
// 🚀 ULTRA FAST FILTER PACKET
// ============================================================
FilterResult UltraFastEngine::FilterPacket(const PacketData& packet) {
    HighResTimer timer;
    
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    
    // ============================================================
    // EARLY EXIT: Skip non-HTTP traffic immediately
    // ============================================================
    
    // Skip HTTP responses (server → client)
    if ((packet.src_port == 80 || packet.src_port == 443) && packet.dst_port > 1024) {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "http_response", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // Skip ICMP
    if (packet.protocol == 1) {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "icmp", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // Skip DNS (port 53)
    if (packet.src_port == 53 || packet.dst_port == 53) {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "dns", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // ============================================================
    // L3: IP CHECKS (O(1) hash lookup)
    // ============================================================
    uint32_t src_ip = IPStringToUint32(packet.src_ip);
    uint32_t dst_ip = IPStringToUint32(packet.dst_ip);
    
    if (CheckBlockedIP(src_ip) || CheckBlockedIP(dst_ip)) {
        l3_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "ip_blocked", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // ============================================================
    // L4: PORT CHECKS (O(1) hash lookup)
    // ============================================================
    if (CheckBlockedPort(packet.src_port, packet.dst_port)) {
        l4_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "port_blocked", timer.ElapsedMillis(), RuleLayer::L4);
    }
    
    // ============================================================
    // L7: HTTP PATTERN MATCHING (only if HTTP request)
    // ============================================================
    // Only check L7 if this is a real HTTP request (has method + URI)
    if (!packet.http_method.empty() && !packet.http_uri.empty()) {
        
        // Check URI patterns (with JIT-compiled regex)
        for (const auto& pattern : uri_patterns_) {
            int rc = pcre2_jit_match(
                pattern.compiled,
                (PCRE2_SPTR)packet.http_uri.c_str(),
                packet.http_uri.length(),
                0,
                0,
                pattern.match_data,
                nullptr
            );
            
            if (rc > 0) {
                l7_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(pattern.action, pattern.rule_id, timer.ElapsedMillis(), RuleLayer::L7);
            }
        }
        
        // Check header patterns (simple substring matching)
        for (const auto& pattern : header_patterns_) {
            if (packet.http_user_agent.find(pattern.pattern) != std::string::npos) {
                l7_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(pattern.action, pattern.rule_id, timer.ElapsedMillis(), RuleLayer::L7);
            }
        }
    }
    
    // ✅ ACCEPT
    accepted_packets_.fetch_add(1, std::memory_order_relaxed);
    return FilterResult(RuleAction::ACCEPT, "default", timer.ElapsedMillis(), RuleLayer::L7);
}

// ============================================================
// HELPER: Parse CIDR notation
// ============================================================
std::pair<uint32_t, uint32_t> UltraFastEngine::ParseCIDR(const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        uint32_t ip = IPStringToUint32(cidr);
        return {ip, 0xFFFFFFFF};
    }
    
    std::string ip_str = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
    
    uint32_t ip = IPStringToUint32(ip_str);
    uint32_t mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));
    uint32_t network = ip & mask;
    
    return {network, mask};
}

// ============================================================
// HELPER: Match HTTP patterns (simplified, no full reassembly)
// ============================================================
bool UltraFastEngine::MatchHTTPPatterns(const PacketData& packet, std::string& matched_rule) {
    // This is already handled in FilterPacket for maximum speed
    return false;
}
