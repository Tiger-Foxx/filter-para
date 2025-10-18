#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <atomic>
#include <functional>
#include <memory>
#include <cstdint>

// ============================================================
// Forward declaration des types NFQUEUE (évite include complet)
// ============================================================
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

// Forward declarations
class RuleEngine;
struct FilterResult;

// Include PacketData definition
#include "../engine/rule_engine.h"

// ============================================================
// PACKET HANDLER - ULTRA-FAST ZERO-COPY NFQUEUE INTERFACE
// ============================================================
// Simplified for maximum performance:
// - No TCP reassembly
// - No statistics tracking (only in debug mode)
// - No buffering/queuing
// - Direct inline filtering
// - Immediate verdict
// ============================================================
class PacketHandler {
public:
    explicit PacketHandler(int queue_num, RuleEngine* engine, bool debug_mode = false);
    ~PacketHandler();
    
    // Lifecycle management
    bool Initialize();
    void Start();
    void Stop();
    
    // Packet processing - called by NFQUEUE callback
    int HandlePacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa);
    
    // Statistics
    void PrintStats() const;

private:
    // NFQUEUE configuration
    int queue_num_;
    RuleEngine* engine_;  // Direct engine pointer (sequential or parallel)
    bool debug_mode_;
    
    // NFQUEUE handles
    struct nfq_handle* nfq_handle_;
    struct nfq_q_handle* queue_handle_;
    int netlink_fd_;
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Statistics (thread-safe counters)
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> dropped_packets_{0};
    
    // Packet parsing (zero-copy, stack allocation)
    bool ParsePacket(unsigned char* data, int len, PacketData& packet);
};

#endif // PACKET_HANDLER_H