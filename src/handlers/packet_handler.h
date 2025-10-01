#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <atomic>
#include <functional>
#include <memory>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <thread>
#include <chrono>

// ============================================================
// Forward declaration des types NFQUEUE (évite include complet)
// ============================================================
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

// Forward declarations
struct PacketData;
class WorkerPool;
class TCPReassembler;
struct FilterResult;

// ============================================================
// PACKET HANDLER - NFQUEUE INTERFACE (SINGLE THREAD)
// ============================================================
class PacketHandler {
public:
    // Callback type for packet processing result
    using PacketCallback = std::function<void(bool dropped)>;
    
    explicit PacketHandler(int queue_num, WorkerPool* worker_pool, bool debug_mode = false);
    ~PacketHandler();
    
    // Lifecycle management
    bool Initialize();
    void Start(PacketCallback callback = nullptr);
    void Stop();
    
    // Packet processing - called by NFQUEUE callback
    int HandlePacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa);
    
    // Statistics
    struct Stats {
        uint64_t total_packets;
        uint64_t dropped_packets;
        uint64_t accepted_packets;
        uint64_t reassembled_packets;
        double drop_rate;
        double reassembly_rate;
        size_t blocked_connections;
    };
    
    Stats GetStats() const;
    void PrintStats() const;

private:
    // NFQUEUE configuration
    int queue_num_;
    WorkerPool* worker_pool_;
    bool debug_mode_;
    
    // NFQUEUE handles
    struct nfq_handle* nfq_handle_;
    struct nfq_q_handle* queue_handle_;
    int netlink_fd_;
    
    // TCP Reassembler
    std::unique_ptr<TCPReassembler> tcp_reassembler_;
    
    // Callback
    PacketCallback packet_callback_;
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Connection tracking
    std::unordered_set<uint64_t> blocked_connections_;
    mutable std::mutex connections_mutex_;
    
    // HTTP ports for reassembly detection
    std::unordered_set<uint16_t> http_ports_ = {80, 443, 8080, 8443, 8000, 3000};
    
    // ============================================================
    // L7 PACKET BUFFERING (per-connection queuing)
    // ============================================================
    struct PendingPacket {
        uint32_t nfq_id;                    // NFQUEUE packet ID
        struct nfq_q_handle* qh;            // Queue handle
        PacketData parsed_data;             // Parsed packet data
        std::chrono::steady_clock::time_point timestamp;  // For timeout
        
        PendingPacket(uint32_t id, struct nfq_q_handle* q, const PacketData& data)
            : nfq_id(id), qh(q), parsed_data(data), 
              timestamp(std::chrono::steady_clock::now()) {}
    };
    
    // Map: connection_key -> list of pending packets
    std::unordered_map<uint64_t, std::vector<PendingPacket>> pending_packets_;
    mutable std::mutex pending_mutex_;
    
    // Timeout for pending packets (5 seconds)
    static constexpr uint32_t PENDING_TIMEOUT_MS = 5000;
    
    // Helper to flush pending packets
    void FlushPendingPackets(uint64_t connection_key, uint32_t verdict);
    void CheckPendingTimeouts();
    
    // Statistics (atomic)
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> dropped_packets_{0};
    std::atomic<uint64_t> accepted_packets_{0};
    std::atomic<uint64_t> reassembled_packets_{0};
    
    // Packet parsing
    bool ParsePacket(unsigned char* data, int len, PacketData& packet);
    
    // TCP reassembly helpers
    bool NeedsHTTPReassembly(const PacketData& packet);
    void HandleTCPReassembly(unsigned char* data, int len, PacketData& packet);
    
    // Connection tracking
    uint64_t GetConnectionKey(const PacketData& packet);
    bool IsConnectionBlocked(uint64_t connection_key);
    void BlockConnection(uint64_t connection_key);
};

#endif // PACKET_HANDLER_H