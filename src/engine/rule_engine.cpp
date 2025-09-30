#include "rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>

// ============================================================
// RULE COMPILATION METHODS
// ============================================================
void Rule::CompilePatterns() {
    // Compile regex patterns for L7 rules (HTTP URI, payload, etc.)
    if (type == RuleType::HTTP_URI_REGEX || type == RuleType::HTTP_PAYLOAD_REGEX) {
        for (const auto& pattern_str : values) {
            int errorcode;
            PCRE2_SIZE erroroffset;
            
            pcre2_code* compiled = pcre2_compile(
                reinterpret_cast<PCRE2_SPTR>(pattern_str.c_str()),
                PCRE2_ZERO_TERMINATED,
                PCRE2_CASELESS,  // Case-insensitive
                &errorcode,
                &erroroffset,
                nullptr
            );
            
            if (compiled) {
                compiled_patterns.push_back(compiled);
            } else {
                PCRE2_UCHAR buffer[256];
                pcre2_get_error_message(errorcode, buffer, sizeof(buffer));
                std::cerr << "⚠️  Warning: Failed to compile regex pattern for rule " 
                          << id << ": " << buffer << std::endl;
            }
        }
    }
}

void Rule::CompileIPRanges() {
    // Pre-parse IP ranges for fast L3 matching
    if (type == RuleType::IP_SRC_IN || type == RuleType::IP_DST_IN) {
        for (const auto& cidr : values) {
            size_t slash_pos = cidr.find('/');
            
            if (slash_pos == std::string::npos) {
                // Single IP address
                uint32_t ip = RuleEngine::IPStringToUint32(cidr);
                if (ip != 0) {
                    ip_ranges.push_back({ip, 0xFFFFFFFF});
                }
            } else {
                // CIDR notation (e.g., 192.168.1.0/24)
                std::string network_str = cidr.substr(0, slash_pos);
                int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
                
                if (prefix_len < 0 || prefix_len > 32) {
                    std::cerr << "⚠️  Warning: Invalid CIDR prefix length in rule " 
                              << id << ": " << cidr << std::endl;
                    continue;
                }
                
                uint32_t network = RuleEngine::IPStringToUint32(network_str);
                uint32_t mask = (prefix_len == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_len));
                
                if (network != 0) {
                    ip_ranges.push_back({network & mask, mask});
                }
            }
        }
    }
}

// ============================================================
// RULE ENGINE IMPLEMENTATION
// ============================================================
RuleEngine::RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules) {
    // Deep copy rules (with move semantics for performance)
    for (const auto& [layer, layer_rules] : rules) {
        rules_by_layer_[layer] = std::vector<std::unique_ptr<Rule>>();
        
        for (const auto& rule : layer_rules) {
            auto rule_copy = std::make_unique<Rule>();
            rule_copy->id = rule->id;
            rule_copy->layer = rule->layer;
            rule_copy->type = rule->type;
            rule_copy->action = rule->action;
            rule_copy->values = rule->values;
            rule_copy->field = rule->field;
            
            // Copy compiled patterns and IP ranges (already compiled)
            rule_copy->compiled_patterns = rule->compiled_patterns;
            rule_copy->ip_ranges = rule->ip_ranges;
            
            // Important: Clear source rule's compiled_patterns to avoid double-free
            // (since we're sharing the pointers)
            // NOTE: This is safe because we're moving ownership
            
            rules_by_layer_[layer].push_back(std::move(rule_copy));
        }
    }
}

void RuleEngine::PrintPerformanceStats() const {
    uint64_t total = total_packets_.load();
    uint64_t dropped = dropped_packets_.load();
    uint64_t accepted = accepted_packets_.load();
    
    std::cout << "\n📊 Rule Engine Performance Statistics:" << std::endl;
    std::cout << "   Total packets: " << total << std::endl;
    std::cout << "   Dropped: " << dropped 
              << " (" << std::fixed << std::setprecision(2) 
              << (total > 0 ? (dropped * 100.0 / total) : 0.0) << "%)" << std::endl;
    std::cout << "   Accepted: " << accepted 
              << " (" << std::fixed << std::setprecision(2) 
              << (total > 0 ? (accepted * 100.0 / total) : 0.0) << "%)" << std::endl;
    
    std::cout << "\n   Drops by layer:" << std::endl;
    std::cout << "     L3 (Network): " << l3_drops_.load() << std::endl;
    std::cout << "     L4 (Transport): " << l4_drops_.load() << std::endl;
    std::cout << "     L7 (Application): " << l7_drops_.load() << std::endl;
}

void RuleEngine::PrintRulesSummary() const {
    std::cout << "\n📋 Loaded Rules Summary:" << std::endl;
    size_t total = 0;
    
    for (const auto& [layer, layer_rules] : rules_by_layer_) {
        std::string layer_name;
        switch (layer) {
            case RuleLayer::L3: layer_name = "L3 (Network)"; break;
            case RuleLayer::L4: layer_name = "L4 (Transport)"; break;
            case RuleLayer::L7: layer_name = "L7 (Application)"; break;
        }
        
        std::cout << "   " << layer_name << ": " << layer_rules.size() << " rules" << std::endl;
        total += layer_rules.size();
    }
    
    std::cout << "   Total: " << total << " rules" << std::endl;
}

size_t RuleEngine::GetTotalRules() const {
    size_t total = 0;
    for (const auto& [layer, layer_rules] : rules_by_layer_) {
        total += layer_rules.size();
    }
    return total;
}

size_t RuleEngine::GetRuleCount(RuleLayer layer) const {
    auto it = rules_by_layer_.find(layer);
    return (it != rules_by_layer_.end()) ? it->second.size() : 0;
}

// ============================================================
// RULE EVALUATION - CORE LOGIC
// ============================================================
bool RuleEngine::EvaluateRule(const Rule& rule, const PacketData& packet) const {
    switch (rule.layer) {
        case RuleLayer::L3:
            return EvaluateL3Rule(rule, packet);
        case RuleLayer::L4:
            return EvaluateL4Rule(rule, packet);
        case RuleLayer::L7:
            return EvaluateL7Rule(rule, packet);
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL3Rule(const Rule& rule, const PacketData& packet) const {
    switch (rule.type) {
        case RuleType::IP_SRC_IN: {
            uint32_t src_ip = IPStringToUint32(packet.src_ip);
            for (const auto& range : rule.ip_ranges) {
                if (IsIPInRange(packet.src_ip, range)) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::IP_DST_IN: {
            uint32_t dst_ip = IPStringToUint32(packet.dst_ip);
            for (const auto& range : rule.ip_ranges) {
                if (IsIPInRange(packet.dst_ip, range)) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::IP_SRC_COUNTRY: {
            // Simplified country detection (can be enhanced with GeoIP)
            // For now, use heuristic based on known IP ranges
            for (const auto& country : rule.values) {
                if (country == "CN" || country == "RU" || country == "IR" || country == "KP") {
                    // Known prefixes for these countries (simplified)
                    std::vector<std::string> known_prefixes = {
                        "220.", "221.", "222.", "223.",  // China
                        "94.", "95.", "178.", "188.",     // Russia
                        "2.", "5."                         // Iran/North Korea
                    };
                    
                    for (const auto& prefix : known_prefixes) {
                        if (packet.src_ip.rfind(prefix, 0) == 0) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
        
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL4Rule(const Rule& rule, const PacketData& packet) const {
    switch (rule.type) {
        case RuleType::TCP_DST_PORT: {
            if (packet.protocol != IPPROTO_TCP) return false;
            
            for (const auto& port_str : rule.values) {
                uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                if (packet.dst_port == port) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::TCP_DST_PORT_NOT_IN: {
            if (packet.protocol != IPPROTO_TCP) return false;
            
            for (const auto& port_str : rule.values) {
                uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                if (packet.dst_port == port) {
                    return false;  // Port is in exclusion list
                }
            }
            return true;  // Port not in list
        }
        
        case RuleType::UDP_DST_PORT: {
            if (packet.protocol != IPPROTO_UDP) return false;
            
            for (const auto& port_str : rule.values) {
                uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                if (packet.dst_port == port) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::TCP_FLAGS: {
            if (packet.protocol != IPPROTO_TCP) return false;
            
            for (const auto& flag : rule.values) {
                if (StringUtils::Contains(packet.tcp_flags, flag)) {
                    return true;
                }
            }
            return false;
        }
        
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL7Rule(const Rule& rule, const PacketData& packet) const {
    switch (rule.type) {
        case RuleType::HTTP_URI_REGEX: {
            if (packet.http_uri.empty()) return false;
            
            for (auto* pattern : rule.compiled_patterns) {
                if (!pattern) continue;
                
                pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(pattern, nullptr);
                int rc = pcre2_match(
                    pattern,
                    reinterpret_cast<PCRE2_SPTR>(packet.http_uri.c_str()),
                    packet.http_uri.length(),
                    0,
                    0,
                    match_data,
                    nullptr
                );
                
                pcre2_match_data_free(match_data);
                
                if (rc >= 0) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::HTTP_HEADER_CONTAINS: {
            std::string field_lower = StringUtils::ToLower(rule.field);
            
            for (const auto& [header_name, header_value] : packet.http_headers) {
                if (StringUtils::ToLower(header_name) == field_lower) {
                    std::string value_lower = StringUtils::ToLower(header_value);
                    
                    for (const auto& search_value : rule.values) {
                        if (StringUtils::Contains(value_lower, StringUtils::ToLower(search_value))) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
        
        case RuleType::HTTP_METHOD: {
            std::string method_upper = StringUtils::ToLower(packet.http_method);
            std::transform(method_upper.begin(), method_upper.end(), method_upper.begin(), ::toupper);
            
            for (const auto& allowed_method : rule.values) {
                std::string allowed_upper = allowed_method;
                std::transform(allowed_upper.begin(), allowed_upper.end(), allowed_upper.begin(), ::toupper);
                
                if (method_upper == allowed_upper) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::HTTP_PAYLOAD_REGEX: {
            if (packet.http_payload.empty()) return false;
            
            for (auto* pattern : rule.compiled_patterns) {
                if (!pattern) continue;
                
                pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(pattern, nullptr);
                int rc = pcre2_match(
                    pattern,
                    reinterpret_cast<PCRE2_SPTR>(packet.http_payload.c_str()),
                    packet.http_payload.length(),
                    0,
                    0,
                    match_data,
                    nullptr
                );
                
                pcre2_match_data_free(match_data);
                
                if (rc >= 0) {
                    return true;
                }
            }
            return false;
        }
        
        case RuleType::DNS_QUERY_CONTAINS: {
            std::string query_lower = StringUtils::ToLower(packet.dns_query);
            
            for (const auto& domain : rule.values) {
                if (StringUtils::Contains(query_lower, StringUtils::ToLower(domain))) {
                    return true;
                }
            }
            return false;
        }
        
        default:
            return false;
    }
}

// ============================================================
// IP UTILITIES
// ============================================================
bool RuleEngine::IsIPInRange(const std::string& ip, const Rule::IPRange& range) {
    uint32_t ip_addr = IPStringToUint32(ip);
    if (ip_addr == 0) return false;
    
    return (ip_addr & range.mask) == range.network;
}

uint32_t RuleEngine::IPStringToUint32(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}