#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <atomic>
#include <cstdint>

// Forward declarations
struct PacketData;

// ============================================================
// ENUMERATIONS
// ============================================================
enum class RuleLayer {
    L3 = 3,  // Network layer (IP)
    L4 = 4,  // Transport layer (TCP/UDP)
    L7 = 7   // Application layer (HTTP, DNS, etc.)
};

enum class RuleType {
    IP_RANGE,
    PORT,
    PROTOCOL,
    PATTERN,
    GEO,
    RATE_LIMIT
};

enum class RuleAction {
    ACCEPT,
    DROP
    // REJECT supprimé car non utilisé dans le code actuel
};

// ============================================================
// RULE STRUCTURE
// ============================================================
struct Rule {
    // IP Range structure
    struct IPRange {
        uint32_t network;
        uint32_t mask;
    };

    // Basic rule information
    std::string id;
    RuleLayer layer;
    RuleType type;
    RuleAction action;
    std::vector<std::string> values;
    std::string field;

    // Compiled patterns for L7 (PCRE2)
    std::vector<void*> compiled_patterns_;  // pcre2_code*

    // Compiled IP ranges for L3
    std::vector<IPRange> ip_ranges_;

    // Methods
    void CompilePatterns();
    void CompileIPRanges();
};

// ============================================================
// FILTER RESULT
// ============================================================
struct FilterResult {
    RuleAction action;
    std::string rule_id;
    double processing_time_ms;
    RuleLayer layer;

    FilterResult(RuleAction act, const std::string& id, double time, RuleLayer lyr)
        : action(act), rule_id(id), processing_time_ms(time), layer(lyr) {}
};

// ============================================================
// PACKET DATA STRUCTURE (COHÉRENTE)
// ============================================================
struct PacketData {
    // L3 (Network layer) - UTILISER std::string pour IP
    std::string src_ip;     // Format string "192.168.1.1"
    std::string dst_ip;     // Format string "10.0.0.1"
    uint8_t protocol;
    
    // L4 (Transport layer)
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;      // Utiliser uint8_t au lieu de string
    uint32_t tcp_seq;
    
    // L7 (Application layer)
    std::string http_method;
    std::string http_uri;
    std::string http_host;
    std::string http_user_agent;
    
    // Connection tracking
    uint64_t connection_hash;
    uint32_t packet_id;
    
    // Timestamps
    uint64_t timestamp_ns;
};

// ============================================================
// RULE ENGINE - BASE CLASS
// ============================================================
class RuleEngine {
public:
    explicit RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    virtual ~RuleEngine() = default;

    // Pure virtual methods
    virtual FilterResult FilterPacket(const PacketData& packet) = 0;

    // Statistics
    virtual void PrintPerformanceStats() const;
    void PrintRulesSummary() const;
    
    // Getters
    size_t GetTotalRules() const;
    size_t GetRuleCount(RuleLayer layer) const;

    // IP utilities (PUBLIC)
    static bool IsIPInRange(uint32_t ip, const Rule::IPRange& range);
    static uint32_t IPStringToUint32(const std::string& ip);
    static std::string IPUint32ToString(uint32_t ip);

protected:
    // Rule storage (organized by layer)
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;

    // Performance counters
    mutable std::atomic<uint64_t> total_packets_{0};
    mutable std::atomic<uint64_t> dropped_packets_{0};
    mutable std::atomic<uint64_t> accepted_packets_{0};
    mutable std::atomic<uint64_t> l3_drops_{0};
    mutable std::atomic<uint64_t> l4_drops_{0};
    mutable std::atomic<uint64_t> l7_drops_{0};
    mutable std::atomic<double> total_processing_time_ms_{0.0};

    // Rule evaluation methods (CONST)
    bool EvaluateRule(const Rule& rule, const PacketData& packet) const;
    bool EvaluateL3Rule(const Rule& rule, const PacketData& packet) const;
    bool EvaluateL4Rule(const Rule& rule, const PacketData& packet) const;
    bool EvaluateL7Rule(const Rule& rule, const PacketData& packet) const;

    // Pattern matching (PCRE2)
    bool MatchPattern(void* compiled_pattern, const std::string& text) const;
    bool MatchPattern(void* compiled_pattern, const uint8_t* data, size_t len) const;
};