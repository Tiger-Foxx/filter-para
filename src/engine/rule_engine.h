#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <regex>
#include <atomic>
#include <cstdint>
#include <netinet/in.h>

// ============================================================
// ENUMERATIONS
// ============================================================
enum class RuleLayer {
    L3 = 3,  // Network layer (IP)
    L4 = 4,  // Transport layer (TCP/UDP)
    L7 = 7   // Application layer (HTTP, DNS, etc.)
};

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

enum class RuleAction {
    DROP,
    ACCEPT,
    REJECT
};

// ============================================================
// IP RANGE STRUCTURE
// ============================================================
struct IPRange {
    uint32_t network;
    uint32_t mask;
    
    IPRange() : network(0), mask(0) {}
    IPRange(uint32_t net, uint32_t m) : network(net), mask(m) {}
    
    bool Contains(uint32_t ip) const {
        return (ip & mask) == (network & mask);
    }
};

// ============================================================
// RULE STRUCTURE
// ============================================================
struct Rule {
    std::string id;
    RuleLayer layer;
    RuleType type;
    RuleAction action;
    std::vector<std::string> values;
    std::string field;  // For http_header_contains
    
    // Compiled patterns for performance
    std::vector<std::regex> compiled_patterns_;
    std::vector<IPRange> compiled_ip_ranges_;
    bool patterns_compiled_ = false;
    bool ip_ranges_compiled_ = false;
    
    Rule() = default;
    
    void CompilePatterns();
    void CompileIPRanges();
    
    const std::vector<std::regex>& GetCompiledPatterns() {
        if (!patterns_compiled_) CompilePatterns();
        return compiled_patterns_;
    }
    
    const std::vector<IPRange>& GetCompiledIPRanges() {
        if (!ip_ranges_compiled_) CompileIPRanges();
        return compiled_ip_ranges_;
    }
};

// ============================================================
// PACKET DATA STRUCTURE
// ============================================================
struct PacketData {
    // L3 data
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;
    uint16_t ip_length;
    
    // L4 data
    uint16_t src_port;
    uint16_t dst_port;
    std::string tcp_flags;
    uint32_t seq_num;
    uint32_t ack_num;
    
    // L7 data
    std::string http_method;
    std::string http_uri;
    std::string http_version;
    std::unordered_map<std::string, std::string> http_headers;
    std::string http_payload;
    std::string user_agent;
    std::string host;
    
    // DNS data
    std::string dns_query;
    
    // Metadata
    uint64_t timestamp_ns;
    size_t packet_size;
    bool is_reassembled;
    
    PacketData() : protocol(0), ip_length(0), src_port(0), dst_port(0),
                   seq_num(0), ack_num(0), timestamp_ns(0), packet_size(0),
                   is_reassembled(false) {}
};

// ============================================================
// FILTER RESULT STRUCTURE
// ============================================================
struct FilterResult {
    RuleAction action;
    std::string rule_id;
    double decision_time_ms;
    RuleLayer matched_layer;
    
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
    
    // Pure virtual methods - must be implemented by derived classes
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual FilterResult FilterPacket(const PacketData& packet) = 0;
    
    // Common interface
    virtual void PrintPerformanceStats() const;
    size_t GetTotalRules() const;
    size_t GetRuleCount(RuleLayer layer) const;

    // ✅ IP utilities MOVED TO PUBLIC
    static bool IsIPInRange(const std::string& ip, const Rule::IPRange& range);
    static uint32_t IPStringToUint32(const std::string& ip);

protected:
    // Rule storage (organized by layer for efficiency)
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    
    // Rule evaluation methods
    bool EvaluateL3Rule(const Rule& rule, const PacketData& packet);
    bool EvaluateL4Rule(const Rule& rule, const PacketData& packet);
    bool EvaluateL7Rule(const Rule& rule, const PacketData& packet);
    
    // Statistics
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> l3_drops_{0};
    std::atomic<uint64_t> l4_drops_{0};
    std::atomic<uint64_t> l7_drops_{0};
    std::atomic<uint64_t> accepts_{0};
};

#endif // RULE_ENGINE_H