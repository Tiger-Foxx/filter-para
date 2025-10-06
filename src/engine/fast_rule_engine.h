#pragma once

#include "rule_engine.h"
#include <unordered_set>
#include <unordered_map>
#include <memory>

// ============================================================
// FAST RULE ENGINE - Hash-based O(1) lookups
// ============================================================
class FastRuleEngine : public RuleEngine {
public:
    explicit FastRuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    ~FastRuleEngine() override = default;

    FilterResult FilterPacket(const PacketData& packet) override;

private:
    // ============================================================
    // HASH TABLES FOR O(1) LOOKUPS (L3/L4)
    // ============================================================
    
    // L3: IP-based blocking
    struct IPRange {
        uint32_t network;
        uint32_t mask;
        std::string rule_id;
    };
    
    std::unordered_set<uint32_t> blocked_ips_;           // Exact IPs
    std::vector<IPRange> blocked_ip_ranges_;              // CIDR ranges
    
    // L4: Port-based blocking
    std::unordered_set<uint16_t> blocked_src_ports_;
    std::unordered_set<uint16_t> blocked_dst_ports_;
    std::unordered_set<uint64_t> blocked_port_pairs_;    // src:dst combined
    
    // L7: Keep sequential for complex rules (regex, etc.)
    std::vector<Rule*> l7_rules_;
    
    // Compilation flag
    bool optimized_index_built_ = false;
    
    // Build optimized indices from rules
    void BuildOptimizedIndex();
    
    // Fast lookup functions
    bool CheckBlockedIP(uint32_t ip, std::string& rule_id);
    bool CheckBlockedPorts(uint16_t src_port, uint16_t dst_port, std::string& rule_id);
    
    // Helper: Parse CIDR notation
    static std::pair<uint32_t, uint32_t> ParseCIDR(const std::string& cidr);
};
