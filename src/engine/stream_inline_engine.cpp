#include "stream_inline_engine.h"
#include "../utils.h"

#include <iostream>
#include <algorithm>
#include <linux/in.h>  // For IPPROTO_TCP

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================

StreamInlineEngine::StreamInlineEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
    size_t max_tcp_streams)
    : RuleEngine(rules) {
    
    std::cout << "🚀 Initializing StreamInlineEngine (High-Performance WAF)" << std::endl;
    
    // Create TCP reassembler
    tcp_reassembler_ = std::make_unique<TCPReassembler>(max_tcp_streams, 30);
    
    // Build optimized indexes
    BuildOptimizedIndex();
    
    std::cout << "✅ StreamInlineEngine ready!" << std::endl;
    std::cout << "   • Blocked src IPs (exact): " << blocked_src_ips_.size() << std::endl;
    std::cout << "   • Blocked dst IPs (exact): " << blocked_dst_ips_.size() << std::endl;
    std::cout << "   • Blocked src IP ranges: " << blocked_src_ip_ranges_.size() << std::endl;
    std::cout << "   • Blocked dst IP ranges: " << blocked_dst_ip_ranges_.size() << std::endl;
    std::cout << "   • Blocked src ports: " << blocked_src_ports_.size() << std::endl;
    std::cout << "   • Blocked dst ports: " << blocked_dst_ports_.size() << std::endl;
    std::cout << "   • HTTP URI patterns: " << http_uri_patterns_.size() << std::endl;
    std::cout << "   • HTTP header patterns: " << http_header_patterns_.size() << std::endl;
    std::cout << "   • HTTP payload patterns: " << http_payload_patterns_.size() << std::endl;
    std::cout << "   • HTTP method patterns: " << http_method_patterns_.size() << std::endl;
    std::cout << "   • TCP reassembler: max " << max_tcp_streams << " streams" << std::endl;
}

StreamInlineEngine::~StreamInlineEngine() {
    // Cleanup PCRE2 patterns handled by unique_ptr destructors
}

// ============================================================
// BUILD OPTIMIZED INDEX
// ============================================================

void StreamInlineEngine::BuildOptimizedIndex() {
    std::cout << "🔧 Building optimized rule index..." << std::endl;
    
    IndexL3Rules();
    IndexL4Rules();
    IndexL7Rules();
    
    index_built_ = true;
}

void StreamInlineEngine::IndexL3Rules() {
    if (!rules_by_layer_.count(RuleLayer::L3)) {
        std::cout << "⚠️  No L3 rules found in rules_by_layer_" << std::endl;
        return;
    }
    
    std::cout << "🔍 Indexing L3 rules (" << rules_by_layer_.at(RuleLayer::L3).size() << " total)..." << std::endl;
    
    for (const auto& rule : rules_by_layer_.at(RuleLayer::L3)) {
        std::cout << "   📋 Rule: " << rule->id << " (type: '" << rule->type_str << "')" << std::endl;
        
        // Handle IP source rules
        if (rule->type_str == "ip_src_in" || rule->type_str == "ip_src_range") {
            std::cout << "      → IP source rule with " << rule->values.size() << " values" << std::endl;
            for (const auto& value : rule->values) {
                std::cout << "         • Value: '" << value << "'" << std::endl;
                if (value.find('/') != std::string::npos) {
                    // CIDR range
                    auto [network, mask] = ParseCIDR(value);
                    blocked_src_ip_ranges_.push_back({network, mask});
                    std::cout << "           ✓ Added as CIDR range" << std::endl;
                } else {
                    // Exact IP
                    uint32_t ip = IPStringToUint32(value);
                    blocked_src_ips_.insert(ip);
                    std::cout << "           ✓ Added as exact IP" << std::endl;
                }
            }
        }
        
        // Handle IP destination rules
        else if (rule->type_str == "ip_dst_in" || rule->type_str == "ip_dst_range") {
            std::cout << "      → IP destination rule with " << rule->values.size() << " values" << std::endl;
            for (const auto& value : rule->values) {
                if (value.find('/') != std::string::npos) {
                    // CIDR range
                    auto [network, mask] = ParseCIDR(value);
                    blocked_dst_ip_ranges_.push_back({network, mask});
                } else {
                    // Exact IP
                    uint32_t ip = IPStringToUint32(value);
                    blocked_dst_ips_.insert(ip);
                }
            }
        }
        
        // Skip GeoIP rules (not implemented)
        else if (rule->type_str == "ip_src_country" || rule->type_str == "ip_dst_country") {
            std::cout << "      ⚠️  GeoIP rule skipped (not implemented)" << std::endl;
        }
        
        else {
            std::cout << "      ⚠️  Unknown L3 rule type: '" << rule->type_str << "'" << std::endl;
        }
    }
}

void StreamInlineEngine::IndexL4Rules() {
    if (!rules_by_layer_.count(RuleLayer::L4)) {
        std::cout << "⚠️  No L4 rules found in rules_by_layer_" << std::endl;
        return;
    }
    
    std::cout << "🔍 Indexing L4 rules (" << rules_by_layer_.at(RuleLayer::L4).size() << " total)..." << std::endl;
    
    for (const auto& rule : rules_by_layer_.at(RuleLayer::L4)) {
        std::cout << "   📋 Rule: " << rule->id << " (type: '" << rule->type_str << "')" << std::endl;
        
        // Source port rules
        if (rule->type_str == "tcp_src_port" || rule->type_str == "udp_src_port") {
            std::cout << "      → Source port rule with " << rule->values.size() << " values" << std::endl;
            for (const auto& value : rule->values) {
                uint16_t port = static_cast<uint16_t>(std::stoi(value));
                blocked_src_ports_.insert(port);
                std::cout << "         • Added port: " << port << std::endl;
            }
        }
        
        // Destination port rules
        else if (rule->type_str == "tcp_dst_port" || rule->type_str == "udp_dst_port") {
            std::cout << "      → Destination port rule with " << rule->values.size() << " values" << std::endl;
            for (const auto& value : rule->values) {
                uint16_t port = static_cast<uint16_t>(std::stoi(value));
                blocked_dst_ports_.insert(port);
                std::cout << "         • Added port: " << port << std::endl;
            }
        }
        
        else {
            std::cout << "      ⚠️  Unknown L4 rule type: '" << rule->type_str << "'" << std::endl;
        }
    }
}

void StreamInlineEngine::IndexL7Rules() {
    if (!rules_by_layer_.count(RuleLayer::L7)) {
        std::cout << "⚠️  No L7 rules found in rules_by_layer_" << std::endl;
        return;
    }
    
    std::cout << "🔍 Indexing L7 rules (" << rules_by_layer_.at(RuleLayer::L7).size() << " total)..." << std::endl;
    
    for (const auto& rule : rules_by_layer_.at(RuleLayer::L7)) {
        std::cout << "   📋 Rule: " << rule->id << " (type: '" << rule->type_str << "')" << std::endl;
        
        // HTTP URI regex patterns
        if (rule->type_str == "http_uri_regex") {
            std::cout << "      → HTTP URI regex with " << rule->values.size() << " patterns" << std::endl;
            for (const auto& pattern_str : rule->values) {
                auto compiled_pattern = std::make_unique<CompiledPattern>();
                compiled_pattern->rule_id = rule->id;
                compiled_pattern->pattern_string = pattern_str;
                compiled_pattern->type = rule->type_str;
                compiled_pattern->action = rule->action;
                
                int error_code;
                compiled_pattern->compiled = CompilePCRE2Pattern(pattern_str, error_code);
                
                if (compiled_pattern->compiled) {
                    // Enable JIT compilation for 10x speed boost
                    pcre2_jit_compile(compiled_pattern->compiled, PCRE2_JIT_COMPLETE);
                    compiled_pattern->match_data = pcre2_match_data_create_from_pattern(
                        compiled_pattern->compiled, nullptr
                    );
                    http_uri_patterns_.push_back(std::move(compiled_pattern));
                } else {
                    std::cerr << "⚠️  Failed to compile pattern: " << pattern_str << std::endl;
                }
            }
        }
        
        // HTTP URI contains (convert to simple substring check)
        else if (rule->type_str == "http_uri_contains") {
            for (const auto& pattern_str : rule->values) {
                auto compiled_pattern = std::make_unique<CompiledPattern>();
                compiled_pattern->rule_id = rule->id;
                compiled_pattern->pattern_string = pattern_str;
                compiled_pattern->type = rule->type_str;
                compiled_pattern->action = rule->action;
                compiled_pattern->compiled = nullptr; // No regex needed for contains
                compiled_pattern->match_data = nullptr;
                http_uri_patterns_.push_back(std::move(compiled_pattern));
            }
        }
        
        // HTTP header contains/regex
        else if (rule->type_str == "http_header_contains" || rule->type_str == "http_header_regex") {
            for (const auto& pattern_str : rule->values) {
                auto compiled_pattern = std::make_unique<CompiledPattern>();
                compiled_pattern->rule_id = rule->id;
                compiled_pattern->pattern_string = pattern_str;
                compiled_pattern->type = rule->type_str;
                compiled_pattern->field = rule->field; // e.g., "user-agent"
                compiled_pattern->action = rule->action;
                
                if (rule->type_str == "http_header_regex") {
                    int error_code;
                    compiled_pattern->compiled = CompilePCRE2Pattern(pattern_str, error_code);
                    if (compiled_pattern->compiled) {
                        pcre2_jit_compile(compiled_pattern->compiled, PCRE2_JIT_COMPLETE);
                        compiled_pattern->match_data = pcre2_match_data_create_from_pattern(
                            compiled_pattern->compiled, nullptr
                        );
                    }
                } else {
                    compiled_pattern->compiled = nullptr; // Simple substring check
                    compiled_pattern->match_data = nullptr;
                }
                
                http_header_patterns_.push_back(std::move(compiled_pattern));
            }
        }
        
        // HTTP method
        else if (rule->type_str == "http_method") {
            for (const auto& method : rule->values) {
                auto compiled_pattern = std::make_unique<CompiledPattern>();
                compiled_pattern->rule_id = rule->id;
                compiled_pattern->pattern_string = method;
                compiled_pattern->type = rule->type_str;
                compiled_pattern->action = rule->action;
                compiled_pattern->compiled = nullptr;
                compiled_pattern->match_data = nullptr;
                http_method_patterns_.push_back(std::move(compiled_pattern));
            }
        }
        
        // HTTP payload regex
        else if (rule->type_str == "http_payload_regex") {
            for (const auto& pattern_str : rule->values) {
                auto compiled_pattern = std::make_unique<CompiledPattern>();
                compiled_pattern->rule_id = rule->id;
                compiled_pattern->pattern_string = pattern_str;
                compiled_pattern->type = rule->type_str;
                compiled_pattern->action = rule->action;
                
                int error_code;
                compiled_pattern->compiled = CompilePCRE2Pattern(pattern_str, error_code);
                
                if (compiled_pattern->compiled) {
                    pcre2_jit_compile(compiled_pattern->compiled, PCRE2_JIT_COMPLETE);
                    compiled_pattern->match_data = pcre2_match_data_create_from_pattern(
                        compiled_pattern->compiled, nullptr
                    );
                    http_payload_patterns_.push_back(std::move(compiled_pattern));
                }
            }
        }
    }
}

// ============================================================
// MAIN FILTERING FUNCTION (INLINE) - UNIFIED VERSION
// ============================================================
// This is the ONLY entry point for packet filtering
// Handles: Early exits, L3/L4 checks, TCP reassembly, L7 HTTP analysis
// ============================================================

FilterResult StreamInlineEngine::FilterPacket(const PacketData& packet) {
    HighResTimer timer;
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    
    // ============================================================
    // EARLY EXITS (minimize latency for non-target traffic)
    // ============================================================
    
    // Skip HTTP responses (server → client)
    if ((packet.src_port == 80 || packet.src_port == 443 || packet.src_port == 8080) 
        && packet.dst_port > 1024) {
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
    
    if (CheckBlockedSrcIP(src_ip)) {
        l3_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "src_ip_blocked", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    if (CheckBlockedDstIP(dst_ip)) {
        l3_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "dst_ip_blocked", timer.ElapsedMillis(), RuleLayer::L3);
    }
    
    // ============================================================
    // L4: PORT CHECKS (O(1) hash lookup)
    // ============================================================
    
    if (CheckBlockedSrcPort(packet.src_port)) {
        l4_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "src_port_blocked", timer.ElapsedMillis(), RuleLayer::L4);
    }
    
    if (CheckBlockedDstPort(packet.dst_port)) {
        l4_drops_.fetch_add(1, std::memory_order_relaxed);
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::DROP, "dst_port_blocked", timer.ElapsedMillis(), RuleLayer::L4);
    }
    
    // Note: L7 TCP reassembly requires raw packet data
    // Use FilterPacketWithRawData() for full L7 analysis
    
    // ============================================================
    // ACCEPT
    // ============================================================
    
    accepted_packets_.fetch_add(1, std::memory_order_relaxed);
    double elapsed = timer.ElapsedMillis();
    total_processing_time_us_.fetch_add(static_cast<uint64_t>(elapsed * 1000), std::memory_order_relaxed);
    
    return FilterResult(RuleAction::ACCEPT, "default", elapsed, RuleLayer::L7);
}

// ============================================================
// FILTER PACKET WITH RAW DATA (for TCP reassembly)
// ============================================================

FilterResult StreamInlineEngine::FilterPacketWithRawData(
    unsigned char* raw_data,
    int raw_len,
    const PacketData& packet) {
    
    // First do all L3/L4 checks (reuse FilterPacket logic)
    FilterResult quick_result = FilterPacket(packet);
    
    // If already dropped or not HTTP, return immediately
    if (quick_result.action == RuleAction::DROP) {
        return quick_result;
    }
    
    // Skip if not HTTP port
    bool is_http_port = (packet.dst_port == 80 || 
                         packet.dst_port == 443 ||
                         packet.dst_port == 8080 ||
                         packet.dst_port == 8443 ||
                         packet.dst_port == 8000 ||
                         packet.dst_port == 3000 ||
                         packet.dst_port == 5000);
    
    if (packet.protocol != IPPROTO_TCP || !is_http_port) {
        return quick_result;
    }
    
    // ============================================================
    // L7: TCP REASSEMBLY + HTTP PATTERN MATCHING
    // ============================================================
    
    HighResTimer l7_timer;
    
    // Process with TCP reassembler
    auto http_data = tcp_reassembler_->ProcessPacket(raw_data, raw_len, 
                                                     const_cast<PacketData&>(packet));
    
    if (http_data && http_data->is_complete) {
        // We have a complete HTTP request - check L7 rules
        std::string matched_rule;
        if (MatchHTTPPatterns(*http_data, matched_rule)) {
            l7_drops_.fetch_add(1, std::memory_order_relaxed);
            dropped_packets_.fetch_add(1, std::memory_order_relaxed);
            return FilterResult(RuleAction::DROP, matched_rule, l7_timer.ElapsedMillis(), RuleLayer::L7);
        }
    }
    
    // ACCEPT (passed all checks)
    return quick_result;
}

// ============================================================
// L7 HTTP PATTERN MATCHING
// ============================================================

bool StreamInlineEngine::MatchHTTPPatterns(const HTTPData& http_data, std::string& matched_rule) {
    // Check HTTP method patterns
    for (const auto& pattern : http_method_patterns_) {
        if (http_data.method == pattern->pattern_string) {
            matched_rule = pattern->rule_id;
            return true;
        }
    }
    
    // Check HTTP URI patterns
    for (const auto& pattern : http_uri_patterns_) {
        if (pattern->type == "http_uri_contains") {
            // Simple substring check
            if (http_data.uri.find(pattern->pattern_string) != std::string::npos) {
                matched_rule = pattern->rule_id;
                return true;
            }
        } else if (pattern->type == "http_uri_regex") {
            // PCRE2-JIT regex matching
            if (MatchPattern(*pattern, http_data.uri)) {
                matched_rule = pattern->rule_id;
                return true;
            }
        }
    }
    
    // Check HTTP header patterns
    for (const auto& pattern : http_header_patterns_) {
        std::string header_value;
        
        // Get header value based on field
        if (!pattern->field.empty()) {
            auto it = http_data.headers.find(pattern->field);
            if (it != http_data.headers.end()) {
                header_value = it->second;
            }
        } else {
            // Check common headers if no specific field
            header_value = http_data.user_agent;
        }
        
        if (header_value.empty()) continue;
        
        if (pattern->type == "http_header_contains") {
            // Simple substring check
            if (header_value.find(pattern->pattern_string) != std::string::npos) {
                matched_rule = pattern->rule_id;
                return true;
            }
        } else if (pattern->type == "http_header_regex") {
            // PCRE2-JIT regex matching
            if (MatchPattern(*pattern, header_value)) {
                matched_rule = pattern->rule_id;
                return true;
            }
        }
    }
    
    // Check HTTP payload patterns (body)
    if (!http_data.payload.empty()) {
        for (const auto& pattern : http_payload_patterns_) {
            if (MatchPattern(*pattern, http_data.payload)) {
                matched_rule = pattern->rule_id;
                return true;
            }
        }
    }
    
    return false;
}

bool StreamInlineEngine::MatchPattern(const CompiledPattern& pattern, const std::string& text) const {
    if (!pattern.compiled || !pattern.match_data) {
        return false;
    }
    
    int rc = pcre2_jit_match(
        pattern.compiled,
        (PCRE2_SPTR)text.c_str(),
        text.length(),
        0,
        0,
        pattern.match_data,
        nullptr
    );
    
    return rc > 0;
}

// ============================================================
// HELPERS
// ============================================================

std::pair<uint32_t, uint32_t> StreamInlineEngine::ParseCIDR(const std::string& cidr) {
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

pcre2_code* StreamInlineEngine::CompilePCRE2Pattern(const std::string& pattern, int& error_code) {
    PCRE2_SIZE error_offset;
    
    pcre2_code* compiled = pcre2_compile(
        (PCRE2_SPTR)pattern.c_str(),
        PCRE2_ZERO_TERMINATED,
        PCRE2_CASELESS | PCRE2_UTF | PCRE2_DOTALL,
        &error_code,
        &error_offset,
        nullptr
    );
    
    return compiled;
}

// ============================================================
// CLEANUP
// ============================================================

void StreamInlineEngine::CleanupExpiredStreams() {
    if (tcp_reassembler_) {
        tcp_reassembler_->CleanupExpiredStreams();
    }
}

// ============================================================
// STATISTICS
// ============================================================

void StreamInlineEngine::PrintPerformanceStats() const {
    RuleEngine::PrintPerformanceStats();
    
    if (tcp_reassembler_) {
        tcp_reassembler_->PrintStats();
    }
}
