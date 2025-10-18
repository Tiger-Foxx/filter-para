#include "packet_handler.h"
#include "../engine/rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <errno.h>

// ============================================================
// Headers réseau POSIX/glibc
// ============================================================
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// ============================================================
// libnetfilter_queue
// ============================================================
extern "C" {
    #include <libnetfilter_queue/libnetfilter_queue.h>
}

// ============================================================
// Définir les constantes NF_* si non définies (évite conflicts)
// ============================================================
#ifndef NF_DROP
#define NF_DROP 0
#endif

#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif

#ifndef NF_STOLEN
#define NF_STOLEN 2
#endif

#ifndef NF_QUEUE
#define NF_QUEUE 3
#endif

#ifndef NF_REPEAT
#define NF_REPEAT 4
#endif

#ifndef NF_STOP
#define NF_STOP 5
#endif

// ============================================================
// CALLBACK C POUR NFQUEUE
// ============================================================
static int nfq_packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                               struct nfq_data *nfa, void *data) {
    auto* handler = static_cast<PacketHandler*>(data);
    return handler->HandlePacket(qh, nfmsg, nfa);
}

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
PacketHandler::PacketHandler(int queue_num, RuleEngine* engine, bool debug_mode)
    : queue_num_(queue_num),
      engine_(engine),
      debug_mode_(debug_mode),
      nfq_handle_(nullptr),
      queue_handle_(nullptr),
      netlink_fd_(-1) {
    
    LOG_DEBUG(debug_mode_, "Ultra-fast PacketHandler initialized for queue " + std::to_string(queue_num_));
}

PacketHandler::~PacketHandler() {
    Stop();
}

// ============================================================
// INITIALIZE
// ============================================================
bool PacketHandler::Initialize() {
    nfq_handle_ = nfq_open();
    if (!nfq_handle_) {
        std::cerr << "❌ ERROR: nfq_open() failed" << std::endl;
        return false;
    }

    if (nfq_unbind_pf(nfq_handle_, AF_INET) < 0) {
        std::cerr << "⚠️  WARNING: nfq_unbind_pf() failed (may be normal)" << std::endl;
    }

    if (nfq_bind_pf(nfq_handle_, AF_INET) < 0) {
        std::cerr << "❌ ERROR: nfq_bind_pf() failed" << std::endl;
        nfq_close(nfq_handle_);
        return false;
    }

    queue_handle_ = nfq_create_queue(nfq_handle_, queue_num_, &nfq_packet_callback, this);
    if (!queue_handle_) {
        std::cerr << "❌ ERROR: nfq_create_queue() failed for queue " << queue_num_ << std::endl;
        nfq_close(nfq_handle_);
        return false;
    }

    if (nfq_set_mode(queue_handle_, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        std::cerr << "❌ ERROR: nfq_set_mode() failed" << std::endl;
        nfq_destroy_queue(queue_handle_);
        nfq_close(nfq_handle_);
        return false;
    }

    if (nfq_set_queue_maxlen(queue_handle_, 10000) < 0) {
        std::cerr << "⚠️  WARNING: nfq_set_queue_maxlen() failed" << std::endl;
    }

    netlink_fd_ = nfq_fd(nfq_handle_);
    if (netlink_fd_ < 0) {
        std::cerr << "❌ ERROR: nfq_fd() failed" << std::endl;
        return false;
    }

    std::cout << "✅ PacketHandler initialized (queue " << queue_num_ << ")" << std::endl;
    return true;
}

// ============================================================
// START - ULTRA-SIMPLE MAIN LOOP
// ============================================================
void PacketHandler::Start() {
    if (!nfq_handle_ || !queue_handle_) {
        std::cerr << "❌ ERROR: PacketHandler not initialized" << std::endl;
        return;
    }

    running_.store(true, std::memory_order_release);
    
    if (debug_mode_) {
        std::cout << "🚀 Ultra-fast PacketHandler listening on queue " << queue_num_ << std::endl;
    }

    char buffer[65536] __attribute__((aligned));
    
    while (running_.load(std::memory_order_acquire)) {
        int len = recv(netlink_fd_, buffer, sizeof(buffer), 0);
        
        if (len < 0) {
            if (errno == ENOBUFS) {
                continue; // Buffer overrun, skip
            }
            if (errno == EINTR || errno == EBADF || !running_.load(std::memory_order_acquire)) {
                break; // Interrupted or stopped
            }
            break; // Other error
        }

        if (len == 0) continue;

        // Process packet immediately (inline, no queuing)
        nfq_handle_packet(nfq_handle_, buffer, len);
    }
    
    if (debug_mode_) {
        std::cout << "🛑 PacketHandler stopped" << std::endl;
        std::cout << "   Total packets: " << total_packets_.load() << std::endl;
        std::cout << "   Dropped: " << dropped_packets_.load() << std::endl;
    }
}

// ============================================================
// STOP - MINIMAL CLEANUP
// ============================================================
void PacketHandler::Stop() {
    running_.store(false, std::memory_order_release);
    
    // Close netlink socket to unblock recv()
    if (netlink_fd_ >= 0) {
        close(netlink_fd_);
        netlink_fd_ = -1;
    }

    if (queue_handle_) {
        nfq_unbind_pf(nfq_handle_, AF_INET);
        nfq_destroy_queue(queue_handle_);
        queue_handle_ = nullptr;
    }

    if (nfq_handle_) {
        nfq_close(nfq_handle_);
        nfq_handle_ = nullptr;
    }
    
    if (debug_mode_) {
        std::cout << "✅ PacketHandler stopped cleanly" << std::endl;
    }
}

// ============================================================
// MAIN PACKET HANDLING - ULTRA-FAST INLINE PROCESSING
// ============================================================
int PacketHandler::HandlePacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                nfq_data *nfa) {
    
    total_packets_.fetch_add(1, std::memory_order_relaxed);

    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (!packet_hdr) {
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, nullptr);
    }

    uint32_t nfq_id = ntohl(packet_hdr->packet_id);
    
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    if (packet_len < 0) {
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }

    // ============================================================
    // ZERO-COPY PACKET PARSING (stack allocation)
    // ============================================================
    PacketData parsed_packet;
    if (!ParsePacket(packet_data, packet_len, parsed_packet)) {
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }

    // ============================================================
    // DIRECT INLINE FILTERING - NO BUFFERING, NO ASYNC
    // ============================================================
    FilterResult result = engine_->FilterPacket(parsed_packet);
    
    uint32_t verdict = (result.action == RuleAction::DROP) ? NF_DROP : NF_ACCEPT;
    
    if (result.action == RuleAction::DROP) {
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        if (debug_mode_) {
            std::cout << "DROP by rule: " << result.rule_id << std::endl;
        }
    }
    
    // IMMEDIATE VERDICT (no queuing, no async)
    return nfq_set_verdict(qh, nfq_id, verdict, 0, nullptr);
}

// ============================================================
// PACKET PARSING - SIMPLIFIED FOR L3/L4 ONLY
// ============================================================
bool PacketHandler::ParsePacket(unsigned char* data, int len, PacketData& packet) {
    if (len < sizeof(struct iphdr)) {
        return false;
    }

    struct iphdr* ip_header = (struct iphdr*)data;
    
    char src_ip_buf[INET_ADDRSTRLEN];
    char dst_ip_buf[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ip_header->saddr, src_ip_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip_buf, INET_ADDRSTRLEN);
    
    packet.src_ip = std::string(src_ip_buf);
    packet.dst_ip = std::string(dst_ip_buf);
    packet.protocol = ip_header->protocol;

    int ip_header_len = ip_header->ihl * 4;
    if (len <= ip_header_len) {
        return true;
    }

    // Parse TCP header
    if (ip_header->protocol == IPPROTO_TCP) {
        if (len < ip_header_len + sizeof(struct tcphdr)) {
            return true;
        }
        
        struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
        packet.src_port = ntohs(tcp_header->source);
        packet.dst_port = ntohs(tcp_header->dest);
    } 
    // Parse UDP header
    else if (ip_header->protocol == IPPROTO_UDP) {
        if (len < ip_header_len + sizeof(struct udphdr)) {
            return true;
        }
        
        struct udphdr* udp_header = (struct udphdr*)(data + ip_header_len);
        packet.src_port = ntohs(udp_header->source);
        packet.dst_port = ntohs(udp_header->dest);
    }

    return true;
}

// ============================================================
// STATISTICS
// ============================================================
void PacketHandler::PrintStats() const {
    uint64_t total = total_packets_.load(std::memory_order_relaxed);
    uint64_t dropped = dropped_packets_.load(std::memory_order_relaxed);
    uint64_t accepted = total - dropped;
    
    std::cout << "\n";
    std::cout << "📊 ========== PACKET STATISTICS ========== 📊\n";
    std::cout << "   Total packets processed: " << total << "\n";
    std::cout << "   ✅ ACCEPTED: " << accepted << " (" << (total > 0 ? (accepted * 100.0 / total) : 0) << "%)\n";
    std::cout << "   ❌ DROPPED: " << dropped << " (" << (total > 0 ? (dropped * 100.0 / total) : 0) << "%)\n";
    std::cout << "📊 ========================================== 📊\n";
    std::cout << "\n";
}

// ============================================================
