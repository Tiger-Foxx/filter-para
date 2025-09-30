#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <atomic>
#include <cstdint>
#include <chrono>

// Forward declaration pour éviter includes circulaires
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

// ============================================================
// ENUMERATIONS FOR RULE ENGINE
// ============================================================

// Layer classification
enum class RuleLayer {
    L3 = 3,  // Network layer (IP)
    L4 = 4,  // Transport layer (TCP/UDP)
    L7 = 7   // Application layer (HTTP/DNS)
};

// Rule types
enum class RuleType {
    // L3 Rules
    IP_SRC_IN,
    IP_DST_IN,
    IP_SRC_COUNTRY,
    
    // L4 Rules
    TCP_DST_PORT,
    TCP_DST_PORT_NOT_IN,
    UDP_DST_PORT,
    TCP_FLAGS,
    
    // L7 Rules
    HTTP_URI_REGEX,
    HTTP_HEADER_CONTAINS,
    HTTP_METHOD,
    HTTP_PAYLOAD_REGEX,
    DNS_QUERY_CONTAINS
};

// Rule actions
enum class RuleAction {
    DROP,
    ACCEPT,
    REJECT  // Reject with ICMP/TCP RST
};

// ============================================================
// PACKET DATA STRUCTURE
// ============================================================
struct PacketData {
    // L3 data
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;  // IPPROTO_TCP, IPPROTO_UDP, etc.
    uint16_t ip_length;
    
    // L4 data
    uint16_t src_port;
    uint16_t dst_port;
    std::string tcp_flags;  // "SYN", "ACK", "FIN", etc.
    uint32_t seq_num;
    uint32_t ack_num;
    
    // L7 data (HTTP)
    std::string http_method;
    std::string http_uri;
    std::string http_version;
    std::unordered_map<std::string, std::string> http_headers;
    std::string http_payload;
    std::string user_agent;
    std::string host;
    
    // L7 data (DNS)
    std::string dns_query;
    uint16_t dns_qtype;
    
    // Metadata
    size_t packet_size;
    uint64_t timestamp_ns;
    bool is_reassembled;  // True if HTTP was reassembled
    
    PacketData() : protocol(0), ip_length(0), src_port(0), dst_port(0),
                   seq_num(0), ack_num(0), dns_qtype(0), packet_size(0),
                   timestamp_ns(0), is_reassembled(false) {}
};

// ============================================================
// RULE STRUCTURE WITH OPTIMIZATIONS
// ============================================================
struct Rule {
    std::string id;
    RuleLayer layer;
    RuleType type;
    RuleAction action;
    std::vector<std::string> values;
    std::string field;  // Pour http_header_contains (ex: "user-agent")
    
    // Pre-compiled patterns pour performance
    std::vector<pcre2_code*> compiled_patterns;
    
    // Pre-parsed IP ranges pour performance
    struct IPRange {
        uint32_t network;
        uint32_t mask;
    };
    std::vector<IPRange> ip_ranges;
    
    Rule() : layer(RuleLayer::L3), type(RuleType::IP_SRC_IN), 
             action(RuleAction::DROP) {}
    
    ~Rule() {
        // Cleanup PCRE2 patterns
        for (auto* pattern : compiled_patterns) {
            if (pattern) {
                pcre2_code_free(pattern);
            }
        }
    }
    
    // Pre-compile regex patterns for L7 rules
    void CompilePatterns();
    
    // Pre-parse IP ranges for L3 rules
    void CompileIPRanges();
};

// ============================================================
// FILTER RESULT
// ============================================================
struct FilterResult {
    RuleAction action;
    std::string rule_id;
    double decision_time_ms;  // Decision time in milliseconds
    RuleLayer matched_layer;
    
    FilterResult() : action(RuleAction::ACCEPT), rule_id("default"),
                     decision_time_ms(0.0), matched_layer(RuleLayer::L3) {}
    
    FilterResult(RuleAction act, const std::string& rid, double time, RuleLayer layer)
        : action(act), rule_id(rid), decision_time_ms(time), matched_layer(layer) {}
};

// ============================================================
// ABSTRACT RULE ENGINE BASE CLASS
// ============================================================
class RuleEngine {
public:
    explicit RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    
    virtual ~RuleEngine() = default;
    
    // Pure virtual methods - MUST be implemented by subclasses
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual FilterResult FilterPacket(const PacketData& packet) = 0;
    
    // Common utilities
    virtual void PrintPerformanceStats() const;
    void PrintRulesSummary() const;
    
    // Getters
    size_t GetTotalRules() const;
    size_t GetRuleCount(RuleLayer layer) const;

protected:
    // Rule storage (organized by layer for efficiency)
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    
    // Performance metrics (thread-safe)
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> dropped_packets_{0};
    std::atomic<uint64_t> accepted_packets_{0};
    
    std::atomic<uint64_t> l3_drops_{0};
    std::atomic<uint64_t> l4_drops_{0};
    std::atomic<uint64_t> l7_drops_{0};
    
    // Helper methods for rule evaluation
    bool EvaluateRule(const Rule& rule, const PacketData& packet) const;
    
    // Layer-specific evaluators
    bool EvaluateL3Rule(const Rule& rule, const PacketData& packet) const;
    bool EvaluateL4Rule(const Rule& rule, const PacketData& packet) const;
    bool EvaluateL7Rule(const Rule& rule, const PacketData& packet) const;
    
    // IP utilities
    static bool IsIPInRange(const std::string& ip, const Rule::IPRange& range);
    static uint32_t IPStringToUint32(const std::string& ip);
};

#endif // RULE_ENGINE_H