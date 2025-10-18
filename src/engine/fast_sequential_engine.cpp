#include "fast_sequential_engine.h"
#include "../utils.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>  // Pour IPPROTO_TCP, IPPROTO_UDP

// ============================================================
// CONSTRUCTOR
// ============================================================
FastSequentialEngine::FastSequentialEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
    : RuleEngine(rules) {
    
    BuildOptimizedStructures();
}

// ============================================================
// BUILD OPTIMIZED HASH STRUCTURES
// ============================================================
void FastSequentialEngine::BuildOptimizedStructures() {
    // ============================================================
    // L3: Build IP hash tables and range lists
    // ============================================================
    if (rules_by_layer_.find(RuleLayer::L3) != rules_by_layer_.end()) {
        const auto& l3_rules = rules_by_layer_.at(RuleLayer::L3);
        
        for (const auto& rule : l3_rules) {
            if (rule->type == RuleType::IP_RANGE) {
                // Add compiled IP ranges
                for (const auto& range : rule->ip_ranges_) {
                    IPRange fast_range;
                    fast_range.network = range.network;
                    fast_range.mask = range.mask;
                    fast_range.rule_id = rule->id;
                    ip_ranges_.push_back(fast_range);
                    
                    // For /32, /31, /30 (small ranges), extract individual IPs for O(1) lookup
                    ExtractIPsFromRange(fast_range);
                }
            }
        }
    }
    
    // ============================================================
    // L4: Build port hash tables
    // ============================================================
    if (rules_by_layer_.find(RuleLayer::L4) != rules_by_layer_.end()) {
        const auto& l4_rules = rules_by_layer_.at(RuleLayer::L4);
        
        for (const auto& rule : l4_rules) {
            if (rule->type == RuleType::PORT) {
                bool is_tcp = (rule->type_str.find("tcp") != std::string::npos);
                bool is_udp = (rule->type_str.find("udp") != std::string::npos);
                
                for (const auto& port_str : rule->values) {
                    uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                    
                    if (is_tcp || (!is_tcp && !is_udp)) {  // Default to TCP if not specified
                        blocked_tcp_ports_.insert(port);
                        tcp_port_rules_[port] = rule->id;
                    }
                    
                    if (is_udp) {
                        blocked_udp_ports_.insert(port);
                        udp_port_rules_[port] = rule->id;
                    }
                }
            }
        }
    }
}

// ============================================================
// EXTRACT INDIVIDUAL IPS FROM SMALL RANGES
// ============================================================
void FastSequentialEngine::ExtractIPsFromRange(const IPRange& range) {
    // Only extract for very small ranges (<=256 IPs)
    uint32_t range_size = ~range.mask + 1;
    
    if (range_size <= 256) {
        for (uint32_t i = 0; i < range_size; ++i) {
            uint32_t ip = range.network + i;
            blocked_ips_.insert(ip);
            ip_rules_[ip] = range.rule_id;
        }
    }
}

// ============================================================
// FAST IP MATCHING
// ============================================================
bool FastSequentialEngine::IsIPBlocked(uint32_t ip, std::string& matched_rule_id) const {
    if (ip == 0) return false;
    
    // O(1) hash lookup for exact IPs
    if (blocked_ips_.count(ip) > 0) {
        auto it = ip_rules_.find(ip);
        if (it != ip_rules_.end()) {
            matched_rule_id = it->second;
        }
        return true;
    }
    
    // O(n) range check (but n is small, typically <100 ranges)
    for (const auto& range : ip_ranges_) {
        if ((ip & range.mask) == range.network) {
            matched_rule_id = range.rule_id;
            return true;
        }
    }
    
    return false;
}

// ============================================================
// FAST PORT MATCHING
// ============================================================
bool FastSequentialEngine::IsPortBlocked(uint16_t port, uint8_t protocol, 
                                         std::string& matched_rule_id) const {
    if (protocol == IPPROTO_TCP) {
        if (blocked_tcp_ports_.count(port) > 0) {
            auto it = tcp_port_rules_.find(port);
            if (it != tcp_port_rules_.end()) {
                matched_rule_id = it->second;
            }
            return true;
        }
    } else if (protocol == IPPROTO_UDP) {
        if (blocked_udp_ports_.count(port) > 0) {
            auto it = udp_port_rules_.find(port);
            if (it != udp_port_rules_.end()) {
                matched_rule_id = it->second;
            }
            return true;
        }
    }
    
    return false;
}

// ============================================================
// MAIN FILTERING FUNCTION - ULTRA OPTIMIZED
// ============================================================
FilterResult FastSequentialEngine::FilterPacket(const PacketData& packet) {
    std::string matched_rule_id;
    
    // ============================================================
    // L3: IP CHECK (O(1) or O(n) with small n)
    // ============================================================
    uint32_t src_ip = IPStringToUint32(packet.src_ip);
    uint32_t dst_ip = IPStringToUint32(packet.dst_ip);
    
    if (IsIPBlocked(src_ip, matched_rule_id)) {
        return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L3);
    }
    
    if (IsIPBlocked(dst_ip, matched_rule_id)) {
        return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L3);
    }
    
    // ============================================================
    // L4: PORT CHECK (O(1))
    // ============================================================
    if (packet.dst_port > 0) {
        if (IsPortBlocked(packet.dst_port, packet.protocol, matched_rule_id)) {
            return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L4);
        }
    }
    
    if (packet.src_port > 0) {
        if (IsPortBlocked(packet.src_port, packet.protocol, matched_rule_id)) {
            return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L4);
        }
    }
    
    // ============================================================
    // DEFAULT: ACCEPT
    // ============================================================
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}
