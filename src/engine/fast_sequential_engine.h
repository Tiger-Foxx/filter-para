#pragma once

#include "rule_engine.h"
#include <unordered_set>
#include <unordered_map>
#include <vector>

// ============================================================
// FAST SEQUENTIAL ENGINE - ZERO-COPY, HASH O(1)
// ============================================================
// Ultra-optimized single-threaded engine with:
// - Hash tables for O(1) IP/port lookups
// - Zero statistics overhead
// - Early exit on first match
// - No TCP reassembly
// - Only L3/L4 filtering
// ============================================================

class FastSequentialEngine : public RuleEngine {
public:
    explicit FastSequentialEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    ~FastSequentialEngine() override = default;

    FilterResult FilterPacket(const PacketData& packet) override;
    
    // Build optimized lookup structures
    void BuildOptimizedStructures();

private:
    // ============================================================
    // HASH TABLES FOR O(1) LOOKUPS
    // ============================================================
    
    // L3: IP addresses (individual IPs extracted from ranges)
    std::unordered_set<uint32_t> blocked_ips_;
    
    // L3: IP ranges (network/mask pairs)
    struct IPRange {
        uint32_t network;
        uint32_t mask;
        std::string rule_id;
    };
    std::vector<IPRange> ip_ranges_;
    
    // L4: TCP ports
    std::unordered_set<uint16_t> blocked_tcp_ports_;
    
    // L4: UDP ports
    std::unordered_set<uint16_t> blocked_udp_ports_;
    
    // Map port -> rule_id for debug
    std::unordered_map<uint16_t, std::string> tcp_port_rules_;
    std::unordered_map<uint16_t, std::string> udp_port_rules_;
    
    // Map IP -> rule_id for debug
    std::unordered_map<uint32_t, std::string> ip_rules_;
    
    // ============================================================
    // FAST MATCHING FUNCTIONS
    // ============================================================
    
    // Check if IP is blocked (O(1) hash lookup + O(n) range check)
    bool IsIPBlocked(uint32_t ip, std::string& matched_rule_id) const;
    
    // Check if port is blocked (O(1) hash lookup)
    bool IsPortBlocked(uint16_t port, uint8_t protocol, std::string& matched_rule_id) const;
    
    // Extract individual IPs from CIDR ranges (for small ranges)
    void ExtractIPsFromRange(const IPRange& range);
};
