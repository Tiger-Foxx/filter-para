#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H

#include <string>
#include <unordered_map>
#include <deque>
#include <memory>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <vector>

// Forward declaration
struct PacketData;

// ============================================================
// HTTP DATA STRUCTURE
// ============================================================
struct HTTPData {
    std::string method;
    std::string uri;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string payload;
    std::string user_agent;
    std::string host;
    bool is_complete = false;
};

// ============================================================
// TCP STREAM STATE
// ============================================================
struct TCPStream {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    
    std::string reassembled_data;
    uint32_t expected_seq = 0;
    bool syn_seen = false;
    bool fin_seen = false;
    bool rst_seen = false;
    
    std::deque<std::pair<uint32_t, std::string>> out_of_order_packets;
    size_t out_of_order_count = 0;
    
    bool http_parsing_started = false;
    bool http_headers_complete = false;
    size_t content_length = 0;
    
    std::shared_ptr<HTTPData> current_http_request;
    
    std::chrono::steady_clock::time_point creation_time;
    std::chrono::steady_clock::time_point last_activity;
    
    uint64_t packets_received = 0;
    uint64_t bytes_received = 0;
    
    TCPStream() : creation_time(std::chrono::steady_clock::now()), 
                  last_activity(creation_time) {}
};

// ============================================================
// TCP REASSEMBLER
// ============================================================
class TCPReassembler {
public:
    explicit TCPReassembler(size_t max_streams = 10000, uint32_t timeout_seconds = 60);
    ~TCPReassembler();
    
    // Main processing function
    std::shared_ptr<HTTPData> ProcessPacket(unsigned char* packet_data, int packet_len, PacketData& parsed_packet);
    
    // Cleanup
    void Cleanup();
    void CleanupExpiredStreams();
    
    // Statistics
    struct Stats {
        size_t active_streams;
        uint64_t total_streams_created;
        uint64_t streams_completed;
        uint64_t streams_timeout;
        uint64_t total_bytes_reassembled;
        uint64_t out_of_order_packets;
        double avg_stream_duration_ms;
    };
    
    Stats GetStats() const;
    void PrintStats() const;

private:
    // Stream management
    std::string GetStreamKey(const std::string& src_ip, uint16_t src_port,
                            const std::string& dst_ip, uint16_t dst_port) const;
    
    TCPStream* GetOrCreateStream(const std::string& src_ip, uint16_t src_port,
                                const std::string& dst_ip, uint16_t dst_port);
    
    void RemoveStream(const std::string& stream_key);
    
    // TCP reassembly
    void ProcessTCPSegment(TCPStream* stream, uint32_t seq_num, const std::string& payload);
    void HandleOutOfOrderPackets(TCPStream* stream);
    
    // HTTP parsing
    bool IsHTTPRequest(const std::string& data) const;
    std::shared_ptr<HTTPData> ParseHTTPRequest(TCPStream* stream);
    bool ParseHTTPHeaders(const std::string& data, HTTPData& http_data);
    
    // Configuration
    size_t max_streams_;
    uint32_t timeout_seconds_;
    
    // Stream storage
    std::unordered_map<std::string, std::unique_ptr<TCPStream>> streams_;
    
    // Statistics
    std::atomic<uint64_t> total_streams_created_{0};
    std::atomic<uint64_t> streams_completed_{0};
    std::atomic<uint64_t> streams_timeout_{0};
    std::atomic<uint64_t> total_bytes_reassembled_{0};
    std::atomic<uint64_t> out_of_order_packets_{0};
    
    static constexpr size_t MAX_OUT_OF_ORDER = 100;
};

#endif // TCP_REASSEMBLER_H