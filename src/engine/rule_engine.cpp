#include "rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>
#include <pcre2.h>

// ============================================================
// RULE COMPILATION METHODS
// ============================================================
void Rule::CompilePatterns() {
    if (type == RuleType::PATTERN) {
        for (const auto& pattern_str : values) {
            int errorcode;
            PCRE2_SIZE erroroffset;
            
            pcre2_code* compiled = pcre2_compile(
                reinterpret_cast<PCRE2_SPTR>(pattern_str.c_str()),
                PCRE2_ZERO_TERMINATED,
                PCRE2_CASELESS,
                &errorcode,
                &erroroffset,
                nullptr
            );
            
            if (compiled) {
                compiled_patterns_.push_back(compiled);
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
    if (type == RuleType::IP_RANGE) {
        for (const auto& cidr : values) {
            size_t slash_pos = cidr.find('/');
            
            if (slash_pos == std::string::npos) {
                uint32_t ip = RuleEngine::IPStringToUint32(cidr);
                if (ip != 0) {
                    ip_ranges_.push_back({ip, 0xFFFFFFFF});
                }
            } else {
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
                    ip_ranges_.push_back({network & mask, mask});
                }
            }
        }
    }
}

// ============================================================
// RULE ENGINE IMPLEMENTATION
// ============================================================
RuleEngine::RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules) {
    for (const auto& [layer, layer_rules] : rules) {
        rules_by_layer_[layer] = std::vector<std::unique_ptr<Rule>>();
        
        for (const auto& rule : layer_rules) {
            auto rule_copy = std::make_unique<Rule>();
            rule_copy->id = rule->id;
            rule_copy->layer = rule->layer;
            rule_copy->type = rule->type;
            rule_copy->type_str = rule->type_str;  // ✅ FIXED: Copy type_str!
            rule_copy->action = rule->action;
            rule_copy->values = rule->values;
            rule_copy->field = rule->field;
            
            rule_copy->compiled_patterns_ = rule->compiled_patterns_;
            rule_copy->ip_ranges_ = rule->ip_ranges_;
            
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
        case RuleType::IP_RANGE: {
            // ✅ CORRECTION : Convertir string → uint32_t AVANT IsIPInRange
            uint32_t src_ip_int = IPStringToUint32(packet.src_ip);
            uint32_t dst_ip_int = IPStringToUint32(packet.dst_ip);
            
            for (const auto& range : rule.ip_ranges_) {
                if (IsIPInRange(src_ip_int, range) || IsIPInRange(dst_ip_int, range)) {
                    return true;
                }
            }
            return false;
        }
        case RuleType::GEO: {
            return false; // Placeholder for GeoIP
        }
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL4Rule(const Rule& rule, const PacketData& packet) const {
    switch (rule.type) {
        case RuleType::PORT: {
            for (const auto& port_str : rule.values) {
                uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                if (packet.dst_port == port) {
                    return true;
                }
            }
            return false;
        }
        case RuleType::PROTOCOL: {
            for (const auto& proto_str : rule.values) {
                if (packet.protocol == static_cast<uint8_t>(std::stoi(proto_str))) {
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
        case RuleType::PATTERN: {
            // Si pas de données HTTP, pas besoin d'évaluer
            if (packet.http_method.empty() && packet.http_uri.empty()) {
                return false;
            }
            
            for (auto* pattern : rule.compiled_patterns_) {
                // Déterminer quel champ HTTP vérifier selon le champ de la règle
                if (rule.field == "user-agent" || rule.field == "http.user_agent") {
                    if (MatchPattern(pattern, packet.http_user_agent)) {
                        return true;
                    }
                } else if (rule.field == "host" || rule.field == "http.host") {
                    if (MatchPattern(pattern, packet.http_host)) {
                        return true;
                    }
                } else if (rule.field == "method" || rule.field == "http.method") {
                    if (MatchPattern(pattern, packet.http_method)) {
                        return true;
                    }
                } else {
                    // Par défaut, vérifier l'URI HTTP (pour http_uri_regex, http_uri_contains)
                    if (MatchPattern(pattern, packet.http_uri)) {
                        return true;
                    }
                    
                    // Vérifier aussi le user-agent par défaut
                    if (MatchPattern(pattern, packet.http_user_agent)) {
                        return true;
                    }
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
bool RuleEngine::IsIPInRange(uint32_t ip_addr, const Rule::IPRange& range) {
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

std::string RuleEngine::IPUint32ToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN)) {
        return std::string(buf);
    }
    return "";
}

bool RuleEngine::MatchPattern(void* compiled_pattern, const std::string& text) const {
    if (!compiled_pattern || text.empty()) {
        return false;
    }
    pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(static_cast<pcre2_code*>(compiled_pattern), nullptr);
    int rc = pcre2_match(
        static_cast<pcre2_code*>(compiled_pattern),
        reinterpret_cast<PCRE2_SPTR>(text.c_str()),
        text.length(),
        0,
        0,
        match_data,
        nullptr
    );
    pcre2_match_data_free(match_data);
    return rc >= 0;
}