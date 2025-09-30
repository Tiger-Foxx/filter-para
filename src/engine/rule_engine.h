#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <atomic>
#include <cstdint>

// IMPORTANT: Define PCRE2_CODE_UNIT_WIDTH before including pcre2.h
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

// ============================================================
// ENUMS & TYPES
// ============================================================

enum class RuleLayer {
    L3 = 3,  // Network layer (IP)
    L4 = 4,  // Transport layer (TCP/UDP)
    L7 = 7   // Application layer (HTTP/DNS)
};

enum class RuleType {
    // L3 Types
    IP_SRC_IN,
    IP_DST_IN,
    IP_SRC_COUNTRY,
    
    // L4 Types
    TCP_DST_PORT,
    TCP_DST_PORT_NOT_IN,
    UDP_DST_PORT,
    TCP_FLAGS,
    
    // L7 Types
    HTTP_URI_REGEX,
    HTTP_HEADER_CONTAINS,
    HTTP_METHOD,
    HTTP_PAYLOAD_REGEX,
    DNS_QUERY_CONTAINS
};

enum class RuleAction {
    DROP,
    ACCEPT,
    REJECT
};

// ============================================================
// PACKET DATA STRUCTURE
// ============================================================

struct PacketData {
    // L3 Data
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;
    uint16_t ip_length;
    
    // L4 Data
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    std::string tcp_flags;
    
    // L7 Data
    std::string http_method;
    std::string http_uri;
    std::string http_version;
    std::unordered_map<std::string, std::string> http_headers;
    std::string http_payload;
    std::string user_agent;
    std::string host;
    std::string dns_query;
    
    // Metadata
    size_t packet_size;
    uint64_t timestamp_ns;
    bool is_reassembled;
    
    PacketData() : protocol(0), ip_length(0), src_port(0), dst_port(0),
                   seq_num(0), ack_num(0), packet_size(0), 
                   timestamp_ns(0), is_reassembled(false) {}
};

// ============================================================
// RULE STRUCTURE
// ============================================================

struct Rule {
    // IP Range structure for compiled IP matching
    struct IPRange {
        uint32_t network;
        uint32_t mask;
    };
    
    std::string id;
    RuleLayer layer;
    RuleType type;
    RuleAction action;
    std::vector<std::string> values;
    std::string field;  // For http_header_contains
    
    // Compiled patterns for performance
    std::vector<pcre2_code*> compiled_patterns_;
    std::vector<IPRange> ip_ranges_;
    
    Rule() : layer(RuleLayer::L3), type(RuleType::IP_SRC_IN), 
             action(RuleAction::DROP) {}
    
    ~Rule() {
        // Free PCRE2 compiled patterns
        for (auto* pattern : compiled_patterns_) {
            if (pattern) {
                pcre2_code_free(pattern);
            }
        }
    }
    
    // Non-copyable (contains raw pointers)
    Rule(const Rule&) = delete;
    Rule& operator=(const Rule&) = delete;
    
    // Moveable
    Rule(Rule&& other) noexcept 
        : id(std::move(other.id)),
          layer(other.layer),
          type(other.type),
          action(other.action),
          values(std::move(other.values)),
          field(std::move(other.field)),
          compiled_patterns_(std::move(other.compiled_patterns_)),
          ip_ranges_(std::move(other.ip_ranges_)) {
        other.compiled_patterns_.clear();
    }
    
    void CompilePatterns();
    void CompileIPRanges();
};

// ============================================================
// FILTER RESULT
// ============================================================

struct FilterResult {
    RuleAction action;
    std::string rule_id;
    double decision_time_ms;
    RuleLayer matched_layer;
    
    FilterResult(RuleAction act = RuleAction::ACCEPT, 
                 const std::string& id = "default",
                 double time_ms = 0.0,
                 RuleLayer layer = RuleLayer::L3)
        : action(act), rule_id(id), decision_time_ms(time_ms), 
          matched_layer(layer) {}
};

// ============================================================
// ABSTRACT RULE ENGINE
// ============================================================

class RuleEngine {
public:
    explicit RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    
    virtual ~RuleEngine() = default;
    
    // Pure virtual methods - must be implemented by derived classes
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual FilterResult FilterPacket(const PacketData& packet) = 0;
    
    // Statistics
    virtual void PrintPerformanceStats() const;
    size_t GetTotalRules() const;
    size_t GetRuleCount(RuleLayer layer) const;
    
    // IP utilities (now public for external use)
    static bool IsIPInRange(const std::string& ip, const Rule::IPRange& range);
    static uint32_t IPStringToUint32(const std::string& ip);

protected:
    // Rule storage (organized by layer for efficiency)
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    
    // Rule evaluation helpers (non-const for derived classes)
    bool EvaluateL3Rule(const Rule& rule, const PacketData& packet);
    bool EvaluateL4Rule(const Rule& rule, const PacketData& packet);
    bool EvaluateL7Rule(const Rule& rule, const PacketData& packet);
    
    // Statistics (atomic for thread safety)
    mutable std::atomic<uint64_t> total_packets_{0};
    mutable std::atomic<uint64_t> l3_drops_{0};
    mutable std::atomic<uint64_t> l4_drops_{0};
    mutable std::atomic<uint64_t> l7_drops_{0};
    
private:
    // Helper to deep-copy rules (handles compiled patterns)
    std::unique_ptr<Rule> CloneRule(const Rule& rule);
};

#endif // RULE_ENGINE_H