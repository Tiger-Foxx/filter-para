#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H

#include <string>
#include <unordered_map>
#include <deque>
#include <memory>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <atomic>

// Forward declaration
struct PacketData;

// ============================================================
// HTTP DATA STRUCTURE
// ============================================================
struct HTTPData {
    std::string method;      // GET, POST, etc.
    std::string uri;         // Request URI
    std::string version;     // HTTP/1.1, HTTP/2, etc.
    std::unordered_map<std::string, std::string> headers;
    std::string payload;     // Body content
    std::string user_agent;  // Extracted for convenience
    std::string host;        // Extracted for convenience
    bool is_complete;        // True if entire request is reassembled
    
    HTTPData() : is_complete(false) {}
};

// ============================================================
// TCP STREAM STATE
// ============================================================
struct TCPStream {
    // Stream identification
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    
    // TCP state
    uint32_t expected_seq;   // Next expected sequence number
    bool syn_seen;
    bool fin_seen;
    bool rst_seen;
    
    // Reassembly buffers
    std::deque<std::pair<uint32_t, std::string>> out_of_order_packets;
    std::string reassembled_data;  // Complete reassembled stream
    
    // HTTP parsing state
    bool http_parsing_started;
    bool http_headers_complete;
    size_t content_length;
    std::shared_ptr<HTTPData> current_http_request;
    
    // Timestamps for cleanup
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point creation_time;
    
    // Statistics
    uint64_t packets_received;
    uint64_t bytes_received;
    uint64_t out_of_order_count;
    
    TCPStream()
        : src_port(0), dst_port(0), expected_seq(0),
          syn_seen(false), fin_seen(false), rst_seen(false),
          http_parsing_started(false), http_headers_complete(false),
          content_length(0), packets_received(0), bytes_received(0),
          out_of_order_count(0) {
        last_activity = std::chrono::steady_clock::now();
        creation_time = last_activity;
    }
};

// ============================================================
// TCP REASSEMBLER - PER-WORKER INSTANCE
// ============================================================
class TCPReassembler {
public:
    explicit TCPReassembler(size_t max_streams = 1000, 
                           uint32_t timeout_seconds = 30);
    
    ~TCPReassembler();
    
    // Main reassembly function
    std::shared_ptr<HTTPData> ProcessPacket(unsigned char* packet_data, 
                                           int packet_len,
                                           PacketData& parsed_packet);
    
    // Cleanup expired streams
    void Cleanup();
    void CleanupExpiredStreams();
    
    // Statistics
    struct Stats {
        size_t active_streams;
        size_t total_streams_created;
        size_t streams_completed;
        size_t streams_timeout;
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
    bool ProcessTCPSegment(TCPStream* stream, uint32_t seq_num, 
                          const std::string& payload);
    
    void HandleOutOfOrderPackets(TCPStream* stream);
    
    // HTTP parsing
    std::shared_ptr<HTTPData> ParseHTTPRequest(TCPStream* stream);
    bool ParseHTTPHeaders(const std::string& data, HTTPData& http_data);
    bool IsHTTPRequest(const std::string& data) const;
    
    // Configuration
    size_t max_streams_;
    uint32_t timeout_seconds_;
    
    // Stream storage (NO MUTEX - per-worker, no shared access)
    std::unordered_map<std::string, std::unique_ptr<TCPStream>> streams_;
    
    // Statistics (atomic for thread-safety if needed for metrics)
    mutable std::atomic<size_t> total_streams_created_{0};
    mutable std::atomic<size_t> streams_completed_{0};
    mutable std::atomic<size_t> streams_timeout_{0};
    mutable std::atomic<uint64_t> total_bytes_reassembled_{0};
    mutable std::atomic<uint64_t> out_of_order_packets_{0};
    
    // Helper constants
    static constexpr size_t MAX_STREAM_SIZE = 10 * 1024 * 1024; // 10 MB max per stream
    static constexpr size_t MAX_OUT_OF_ORDER = 100; // Max out-of-order packets per stream
};

#endif // TCP_REASSEMBLER_H