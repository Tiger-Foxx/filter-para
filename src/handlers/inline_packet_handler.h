#ifndef INLINE_PACKET_HANDLER_H
#define INLINE_PACKET_HANDLER_H

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <atomic>
#include <memory>
#include <functional>
#include <string>

#include "../engine/ultra_fast_engine.h"

// ============================================================
// 🚀 INLINE PACKET HANDLER - Zero-Copy, Direct Verdict
// ============================================================
// NO workers, NO queues, NO async - Just FAST!
// ============================================================

class InlinePacketHandler {
public:
    InlinePacketHandler(int queue_num, 
                       std::shared_ptr<UltraFastEngine> engine,
                       bool debug_mode = false);
    ~InlinePacketHandler();

    // Start/Stop
    void Start();
    void Stop();
    
    // Stats
    void PrintStats() const;
    
private:
    // NFQUEUE handles
    struct nfq_handle* nfq_handle_;
    struct nfq_q_handle* queue_handle_;
    int queue_num_;
    int socket_fd_;
    
    // Rule engine (single instance, no per-worker copies)
    std::shared_ptr<UltraFastEngine> engine_;
    
    // State
    std::atomic<bool> running_{false};
    bool debug_mode_;
    
    // Statistics (lock-free atomic)
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> accepted_packets_{0};
    std::atomic<uint64_t> dropped_packets_{0};
    std::atomic<uint64_t> error_packets_{0};
    
    // ============================================================
    // PACKET PROCESSING (inline, no copying)
    // ============================================================
    static int PacketCallback(struct nfq_q_handle *qh, 
                             struct nfgenmsg *nfmsg,
                             nfq_data *nfa, 
                             void *data);
    
    int HandlePacket(struct nfq_q_handle *qh, 
                    struct nfgenmsg *nfmsg,
                    nfq_data *nfa);
    
    // Parse packet in-place (no copying)
    bool ParsePacketInline(unsigned char* data, int len, PacketData& packet);
    
    // Quick HTTP parsing (no reassembly, just check first packet)
    void QuickHTTPParse(unsigned char* data, int len, PacketData& packet);
};

#endif // INLINE_PACKET_HANDLER_H
