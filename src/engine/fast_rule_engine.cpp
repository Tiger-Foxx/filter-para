#include "fast_rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>

// ============================================================
// CONSTRUCTOR
// ============================================================
FastRuleEngine::FastRuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
    : RuleEngine(rules) {
    
    std::cout << "🚀 Building optimized rule index (hash tables)..." << std::endl;
    BuildOptimizedIndex();
    std::cout << "✅ Optimized index built:" << std::endl;
    std::cout << "   • Blocked IPs (exact): " << blocked_ips_.size() << std::endl;
    std::cout << "   • Blocked IP ranges: " << blocked_ip_ranges_.size() << std::endl;
    std::cout << "   • Blocked src ports: " << blocked_src_ports_.size() << std::endl;
    std::cout << "   • Blocked dst ports: " << blocked_dst_ports_.size() << std::endl;
    std::cout << "   • L7 rules (sequential): " << l7_rules_.size() << std::endl;
}

// ============================================================
// BUILD OPTIMIZED INDEX
// ============================================================
void FastRuleEngine::BuildOptimizedIndex() {
    // ✅ INDEX L3 RULES (IP-based)
    for (const auto& rule : rules_by_layer_[RuleLayer::L3]) {
        if (rule->type_str == "ip_src_in" || rule->type_str == "ip_dst_in") {
            // Parse IP ranges/CIDR
            for (const auto& value : rule->values) {
                if (value.find('/') != std::string::npos) {
                    // CIDR notation (e.g., "192.168.0.0/24")
                    auto [network, mask] = ParseCIDR(value);
                    blocked_ip_ranges_.push_back({network, mask, rule->id});
                } else {
                    // Single IP
                    uint32_t ip = IPStringToUint32(value);
                    blocked_ips_.insert(ip);
                }
            }
        }
        // Note: ip_src_country rules remain sequential (need GeoIP lookup)
    }
    
    // ✅ INDEX L4 RULES (Port-based)
    for (const auto& rule : rules_by_layer_[RuleLayer::L4]) {
        if (rule->type_str == "tcp_src_port" || rule->type_str == "udp_src_port") {
            for (const auto& value : rule->values) {
                try {
                    uint16_t port = std::stoul(value);
                    blocked_src_ports_.insert(port);
                } catch (...) {}
            }
        } else if (rule->type_str == "tcp_dst_port" || rule->type_str == "udp_dst_port") {
            for (const auto& value : rule->values) {
                try {
                    uint16_t port = std::stoul(value);
                    blocked_dst_ports_.insert(port);
                } catch (...) {}
            }
        }
    }
    
    // ✅ KEEP L7 RULES SEQUENTIAL (complex patterns, regex, etc.)
    for (const auto& rule : rules_by_layer_[RuleLayer::L7]) {
        l7_rules_.push_back(rule.get());
    }
    
    optimized_index_built_ = true;
}

// ============================================================
// FAST FILTER PACKET (with hash lookups)
// ============================================================
FilterResult FastRuleEngine::FilterPacket(const PacketData& packet) {
    HighResTimer timer;
    
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    
    // ============================================================
    // EARLY EXIT: Skip HTTP responses (server → client)
    // ============================================================
    // Si src_port = 80/443 et dst_port > 1024 → c'est une réponse HTTP
    if ((packet.src_port == 80 || packet.src_port == 443) && packet.dst_port > 1024) {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "http_response", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // Skip ICMP (ping) - protocol 1
    if (packet.protocol == 1) {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "icmp", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // ============================================================
    // L3: IP CHECKS (O(1) hash lookup or O(k) for k ranges)
    // ============================================================
    uint32_t src_ip = IPStringToUint32(packet.src_ip);
    uint32_t dst_ip = IPStringToUint32(packet.dst_ip);
    
    std::string matched_rule;
    
    // Check exact IP blocks (O(1))
    if (blocked_ips_.count(src_ip) || blocked_ips_.count(dst_ip)) {
        l3_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "ip_blocked_exact", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // Check IP ranges (O(k) where k = number of ranges, typically < 50)
    if (CheckBlockedIP(src_ip, matched_rule) || CheckBlockedIP(dst_ip, matched_rule)) {
        l3_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, matched_rule, timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // Fallback: Check remaining L3 rules sequentially (country-based, etc.)
    for (const auto& rule : rules_by_layer_[RuleLayer::L3]) {
        if (rule->type_str != "ip_src_in" && rule->type_str != "ip_dst_in") {
            if (EvaluateRule(*rule, packet)) {
                l3_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMillis(), RuleLayer::L3);
            }
        }
    }
    
    // ============================================================
    // L4: PORT CHECKS (O(1) hash lookup)
    // ============================================================
    if (CheckBlockedPorts(packet.src_port, packet.dst_port, matched_rule)) {
        l4_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, matched_rule, timer.ElapsedMillis(), RuleLayer::L4);
    }
    
    // Fallback: Check remaining L4 rules sequentially
    for (const auto& rule : rules_by_layer_[RuleLayer::L4]) {
        if (rule->type_str != "tcp_src_port" && rule->type_str != "tcp_dst_port" &&
            rule->type_str != "udp_src_port" && rule->type_str != "udp_dst_port") {
            if (EvaluateRule(*rule, packet)) {
                l4_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMillis(), RuleLayer::L4);
            }
        }
    }
    
    // ============================================================
    // L7: APPLICATION LAYER (sequential, but optimized with JIT regex)
    // ============================================================
    // ONLY check L7 for HTTP requests (client → server with HTTP method)
    bool is_http_request = !packet.http_method.empty() && 
                           (packet.dst_port == 80 || packet.dst_port == 443);
    
    if (is_http_request) {
        for (Rule* rule : l7_rules_) {
            if (EvaluateRule(*rule, packet)) {
                l7_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMillis(), RuleLayer::L7);
            }
        }
    }
    
    // ✅ ACCEPT
    accepted_packets_.fetch_add(1, std::memory_order_relaxed);
    return FilterResult(RuleAction::ACCEPT, "default", timer.ElapsedMillis(), RuleLayer::L7);
}

// ============================================================
// FAST LOOKUP HELPERS
// ============================================================
bool FastRuleEngine::CheckBlockedIP(uint32_t ip, std::string& rule_id) {
    for (const auto& range : blocked_ip_ranges_) {
        if ((ip & range.mask) == range.network) {
            rule_id = range.rule_id;
            return true;
        }
    }
    return false;
}

bool FastRuleEngine::CheckBlockedPorts(uint16_t src_port, uint16_t dst_port, std::string& rule_id) {
    if (blocked_src_ports_.count(src_port)) {
        rule_id = "port_src_blocked";
        return true;
    }
    
    if (blocked_dst_ports_.count(dst_port)) {
        rule_id = "port_dst_blocked";
        return true;
    }
    
    // Check port pairs (if we have combined rules)
    uint64_t pair = (static_cast<uint64_t>(src_port) << 16) | dst_port;
    if (blocked_port_pairs_.count(pair)) {
        rule_id = "port_pair_blocked";
        return true;
    }
    
    return false;
}

// ============================================================
// HELPER: Parse CIDR notation
// ============================================================
std::pair<uint32_t, uint32_t> FastRuleEngine::ParseCIDR(const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        // Not a CIDR, treat as single IP
        uint32_t ip = IPStringToUint32(cidr);
        return {ip, 0xFFFFFFFF};
    }
    
    std::string ip_str = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
    
    uint32_t ip = IPStringToUint32(ip_str);
    uint32_t mask = (prefix_len == 0) ? 0 : (~0u << (32 - prefix_len));
    uint32_t network = ip & mask;
    
    return {network, mask};
}
