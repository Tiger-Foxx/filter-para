#ifndef STREAM_INLINE_ENGINE_H
#define STREAM_INLINE_ENGINE_H

#include "rule_engine.h"
#include "../handlers/tcp_reassembler.h"

#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <pcre2.h>

// ============================================================
// 🚀 STREAM INLINE ENGINE - Real WAF Performance
// ============================================================
// Design:
// 1. Hash tables for O(1) L3/L4 lookups
// 2. PCRE2-JIT for ultra-fast regex matching
// 3. Streaming HTTP parsing with TCP reassembly
// 4. Inline processing (no workers, no queues)
// 5. RESPECTS ALL RULES from JSON file
// ============================================================

class StreamInlineEngine : public RuleEngine {
public:
    explicit StreamInlineEngine(
        const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
        size_t max_tcp_streams = 50000
    );
    virtual ~StreamInlineEngine();

    // Main filtering function (INLINE - called from NFQUEUE callback)
    // This is the ONLY entry point - handles all L3/L4/L7 checks with TCP reassembly
    FilterResult FilterPacket(const PacketData& packet) override;
    
    // Wrapper for processing with raw packet data (for TCP reassembly)
    FilterResult FilterPacketWithRawData(
        unsigned char* raw_data,
        int raw_len,
        const PacketData& packet
    );
    
    // Cleanup expired TCP streams
    void CleanupExpiredStreams();
    
    // Cleanup expired blocked connections
    void CleanupExpiredBlockedConnections();
    
    // Statistics
    void PrintPerformanceStats() const override;
    
private:
    // ============================================================
    // OPTIMIZED DATA STRUCTURES
    // ============================================================
    
    // L3: IP filtering (O(1) lookups)
    std::unordered_set<uint32_t> blocked_src_ips_;
    std::unordered_set<uint32_t> blocked_dst_ips_;
    std::vector<Rule::IPRange> blocked_src_ip_ranges_;
    std::vector<Rule::IPRange> blocked_dst_ip_ranges_;
    
    // L4: Port filtering (O(1) lookups)
    std::unordered_set<uint16_t> blocked_src_ports_;
    std::unordered_set<uint16_t> blocked_dst_ports_;
    
    // L7: HTTP pattern matching (PCRE2-JIT compiled)
    struct CompiledPattern {
        std::string rule_id;
        std::string pattern_string;
        std::string type;  // "http_uri_regex", "http_header_contains", etc.
        std::string field; // For header checks: "user-agent", "host", etc.
        RuleAction action;
        
        // PCRE2 compiled pattern
        pcre2_code* compiled;
        pcre2_match_data* match_data;
        
        CompiledPattern() : compiled(nullptr), match_data(nullptr) {}
        ~CompiledPattern() {
            if (match_data) pcre2_match_data_free(match_data);
            if (compiled) pcre2_code_free(compiled);
        }
    };
    
    std::vector<std::unique_ptr<CompiledPattern>> http_uri_patterns_;
    std::vector<std::unique_ptr<CompiledPattern>> http_header_patterns_;
    std::vector<std::unique_ptr<CompiledPattern>> http_payload_patterns_;
    std::vector<std::unique_ptr<CompiledPattern>> http_method_patterns_;
    
    // TCP Reassembler (streaming mode)
    std::unique_ptr<TCPReassembler> tcp_reassembler_;
    
    // Connection tracking for blocked connections
    struct ConnectionKey {
        std::string src_ip;
        uint16_t src_port;
        std::string dst_ip;
        uint16_t dst_port;
        
        bool operator==(const ConnectionKey& other) const {
            return src_ip == other.src_ip && src_port == other.src_port &&
                   dst_ip == other.dst_ip && dst_port == other.dst_port;
        }
    };
    
    struct ConnectionKeyHash {
        size_t operator()(const ConnectionKey& key) const {
            return std::hash<std::string>{}(key.src_ip + ":" + std::to_string(key.src_port) +
                                           "-" + key.dst_ip + ":" + std::to_string(key.dst_port));
        }
    };
    
    struct BlockedConnectionInfo {
        time_t blocked_at;      // Timestamp when blocked
        std::string rule_id;    // Which rule triggered the block
    };
    
    std::unordered_map<ConnectionKey, BlockedConnectionInfo, ConnectionKeyHash> blocked_connections_;
    std::mutex blocked_connections_mutex_;
    
    // Performance flags
    std::atomic<bool> index_built_{false};
    
    // ============================================================
    // INITIALIZATION
    // ============================================================
    
    void BuildOptimizedIndex();
    void IndexL3Rules();
    void IndexL4Rules();
    void IndexL7Rules();
    
    // ============================================================
    // FAST INLINE CHECKS
    // ============================================================
    
    // L3 checks (inline for zero overhead)
    inline bool CheckBlockedSrcIP(uint32_t ip) const {
        if (blocked_src_ips_.count(ip)) return true;
        for (const auto& range : blocked_src_ip_ranges_) {
            if ((ip & range.mask) == range.network) return true;
        }
        return false;
    }
    
    inline bool CheckBlockedDstIP(uint32_t ip) const {
        if (blocked_dst_ips_.count(ip)) return true;
        for (const auto& range : blocked_dst_ip_ranges_) {
            if ((ip & range.mask) == range.network) return true;
        }
        return false;
    }
    
    // L4 checks (inline for zero overhead)
    inline bool CheckBlockedSrcPort(uint16_t port) const {
        return blocked_src_ports_.count(port) > 0;
    }
    
    inline bool CheckBlockedDstPort(uint16_t port) const {
        return blocked_dst_ports_.count(port) > 0;
    }
    
    // ============================================================
    // L7 HTTP PATTERN MATCHING
    // ============================================================
    
    bool MatchHTTPPatterns(const HTTPData& http_data, std::string& matched_rule);
    bool MatchPattern(const CompiledPattern& pattern, const std::string& text) const;
    
    // ============================================================
    // HELPERS
    // ============================================================
    
    std::pair<uint32_t, uint32_t> ParseCIDR(const std::string& cidr);
    pcre2_code* CompilePCRE2Pattern(const std::string& pattern, int& error_code);
};

#endif // STREAM_INLINE_ENGINE_H
