#ifndef ULTRA_FAST_ENGINE_H
#define ULTRA_FAST_ENGINE_H

#include "rule_engine.h"
#include <atomic>
#include <array>
#include <memory>
#include <unordered_set>
#include <vector>
#include <string>
#include <pcre2.h>

// ============================================================
// 🚀 ULTRA FAST ENGINE - Zero-Copy, Lock-Free, Inline
// ============================================================
// Design Philosophy:
// 1. NO mutex locks - lock-free atomic operations only
// 2. NO packet copying - process in-place
// 3. NO TCP reassembly buffering - simple pattern matching
// 4. Hash tables for O(1) L3/L4 lookups
// 5. Compile-time optimizations with constexpr
// ============================================================

class UltraFastEngine : public RuleEngine {
public:
    explicit UltraFastEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    virtual ~UltraFastEngine() = default;

    // Main filtering function - MUST BE FAST!
    FilterResult FilterPacket(const PacketData& packet) override;

    // Build optimized index from rules
    void BuildOptimizedIndex();

private:
    // ============================================================
    // OPTIMIZED DATA STRUCTURES (O(1) lookups)
    // ============================================================
    
    // L3: IP filtering
    std::unordered_set<uint32_t> blocked_ips_;           // Exact IPs
    std::vector<Rule::IPRange> blocked_ip_ranges_;              // CIDR ranges
    
    // L4: Port filtering  
    std::unordered_set<uint16_t> blocked_src_ports_;
    std::unordered_set<uint16_t> blocked_dst_ports_;
    std::unordered_set<uint64_t> blocked_port_pairs_;    // Combined src+dst
    
    // L7: Simplified pattern matching (NO full HTTP parsing)
    struct FastPattern {
        std::string pattern;
        pcre2_code* compiled;
        pcre2_match_data* match_data;
        std::string rule_id;
        RuleAction action;
    };
    
    std::vector<FastPattern> uri_patterns_;
    std::vector<FastPattern> header_patterns_;
    
    // Flags
    std::atomic<bool> optimized_index_built_{false};
    
    // ============================================================
    // FAST HELPERS - Inline for zero function call overhead
    // ============================================================
    
    inline bool CheckBlockedIP(uint32_t ip) const {
        // Exact match: O(1)
        if (blocked_ips_.count(ip)) return true;
        
        // CIDR ranges: O(k) where k is small
        for (const auto& range : blocked_ip_ranges_) {
            if ((ip & range.mask) == range.network) {
                return true;
            }
        }
        return false;
    }
    
    inline bool CheckBlockedPort(uint16_t src_port, uint16_t dst_port) const {
        return blocked_src_ports_.count(src_port) || 
               blocked_dst_ports_.count(dst_port);
    }
    
    // Parse CIDR notation
    std::pair<uint32_t, uint32_t> ParseCIDR(const std::string& cidr);
    
    // Simple HTTP pattern matching (no full parsing)
    bool MatchHTTPPatterns(const PacketData& packet, std::string& matched_rule);
};

#endif // ULTRA_FAST_ENGINE_H
