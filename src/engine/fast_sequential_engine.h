#pragma once

#include "rule_engine.h"
#include <unordered_set>
#include <unordered_map>
#include <vector>

// ============================================================
// FAST SEQUENTIAL ENGINE - UN SEUL THREAD, TOUTES LES RÈGLES
// ============================================================
// Mode séquentiel ORIGINAL:
// - 1 seul thread
// - Toutes les règles (~24 règles)
// - Hash O(1) pour IP/ports
// - Baseline pour comparaison
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
    
    // L3: IP addresses
    std::unordered_set<uint32_t> blocked_ips_;
    
    // L3: IP ranges
    struct IPRange {
        uint32_t network;
        uint32_t mask;
        std::string rule_id;
    };
    std::vector<IPRange> ip_ranges_;
    
    // L4: TCP/UDP ports
    std::unordered_set<uint16_t> blocked_tcp_ports_;
    std::unordered_set<uint16_t> blocked_udp_ports_;
    
    // Maps for debug
    std::unordered_map<uint16_t, std::string> tcp_port_rules_;
    std::unordered_map<uint16_t, std::string> udp_port_rules_;
    std::unordered_map<uint32_t, std::string> ip_rules_;
    
    // Helper functions
    bool IsIPBlocked(uint32_t ip, std::string& matched_rule_id) const;
    bool IsPortBlocked(uint16_t port, uint8_t protocol, std::string& matched_rule_id) const;
    void ExtractIPsFromRange(const IPRange& range);
};
