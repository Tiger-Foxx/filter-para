#include "inline_packet_handler.h"
#include "../utils.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
InlinePacketHandler::InlinePacketHandler(int queue_num,
                                         std::shared_ptr<UltraFastEngine> engine,
                                         bool debug_mode)
    : queue_num_(queue_num),
      engine_(engine),
      debug_mode_(debug_mode),
      nfq_handle_(nullptr),
      queue_handle_(nullptr),
      socket_fd_(-1) {
    
    std::cout << "🚀 Initializing InlinePacketHandler (Zero-Copy Mode)" << std::endl;
}

InlinePacketHandler::~InlinePacketHandler() {
    Stop();
}

// ============================================================
// START
// ============================================================
void InlinePacketHandler::Start() {
    if (running_.load()) {
        std::cout << "⚠️  InlinePacketHandler already running" << std::endl;
        return;
    }
    
    std::cout << "🔧 Opening NFQUEUE (queue " << queue_num_ << ")..." << std::endl;
    
    // Open netfilter queue
    nfq_handle_ = nfq_open();
    if (!nfq_handle_) {
        throw std::runtime_error("Failed to open NFQUEUE");
    }
    
    // Unbind existing handler (if any)
    if (nfq_unbind_pf(nfq_handle_, AF_INET) < 0) {
        std::cout << "⚠️  Could not unbind existing NFQUEUE handler (may be OK)" << std::endl;
    }
    
    // Bind to AF_INET
    if (nfq_bind_pf(nfq_handle_, AF_INET) < 0) {
        nfq_close(nfq_handle_);
        throw std::runtime_error("Failed to bind NFQUEUE to AF_INET");
    }
    
    // Create queue
    queue_handle_ = nfq_create_queue(nfq_handle_, queue_num_, 
                                     &InlinePacketHandler::PacketCallback, this);
    if (!queue_handle_) {
        nfq_close(nfq_handle_);
        throw std::runtime_error("Failed to create NFQUEUE");
    }
    
    // Set queue mode (copy packet payload)
    if (nfq_set_mode(queue_handle_, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        nfq_destroy_queue(queue_handle_);
        nfq_close(nfq_handle_);
        throw std::runtime_error("Failed to set NFQUEUE mode");
    }
    
    // Get socket fd
    socket_fd_ = nfq_fd(nfq_handle_);
    
    running_.store(true);
    
    std::cout << "✅ InlinePacketHandler started on queue " << queue_num_ << std::endl;
    std::cout << "📦 Processing packets INLINE (no workers, no queues)" << std::endl;
    
    // ============================================================
    // MAIN LOOP - Direct packet processing
    // ============================================================
    char buffer[4096] __attribute__((aligned(4)));
    
    while (running_.load()) {
        int received = recv(socket_fd_, buffer, sizeof(buffer), 0);
        
        if (received < 0) {
            if (errno == EINTR) continue;
            std::cerr << "❌ recv() error: " << strerror(errno) << std::endl;
            break;
        }
        
        // Process packet INLINE (no queue, no thread, direct verdict)
        nfq_handle_packet(nfq_handle_, buffer, received);
    }
    
    std::cout << "🛑 InlinePacketHandler main loop exited" << std::endl;
}

// ============================================================
// STOP
// ============================================================
void InlinePacketHandler::Stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "🛑 Stopping InlinePacketHandler..." << std::endl;
    
    running_.store(false);
    
    if (queue_handle_) {
        nfq_destroy_queue(queue_handle_);
        queue_handle_ = nullptr;
    }
    
    if (nfq_handle_) {
        nfq_unbind_pf(nfq_handle_, AF_INET);
        nfq_close(nfq_handle_);
        nfq_handle_ = nullptr;
    }
    
    PrintStats();
    
    std::cout << "✅ InlinePacketHandler stopped" << std::endl;
}

// ============================================================
// PACKET CALLBACK (static trampoline)
// ============================================================
int InlinePacketHandler::PacketCallback(struct nfq_q_handle *qh,
                                       struct nfgenmsg *nfmsg,
                                       nfq_data *nfa,
                                       void *data) {
    InlinePacketHandler* handler = static_cast<InlinePacketHandler*>(data);
    return handler->HandlePacket(qh, nfmsg, nfa);
}

// ============================================================
// 🚀 HANDLE PACKET (INLINE - NO COPY, NO QUEUE)
// ============================================================
int InlinePacketHandler::HandlePacket(struct nfq_q_handle *qh,
                                      struct nfgenmsg *nfmsg,
                                      nfq_data *nfa) {
    
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    
    // Get packet header
    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (!packet_hdr) {
        error_packets_.fetch_add(1, std::memory_order_relaxed);
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, nullptr);
    }
    
    uint32_t nfq_id = ntohl(packet_hdr->packet_id);
    
    // Get packet payload (zero-copy pointer)
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    if (packet_len < 0) {
        error_packets_.fetch_add(1, std::memory_order_relaxed);
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }
    
    // ============================================================
    // PARSE PACKET INLINE (no copying, stack-allocated)
    // ============================================================
    PacketData packet;  // Stack allocation!
    
    if (!ParsePacketInline(packet_data, packet_len, packet)) {
        error_packets_.fetch_add(1, std::memory_order_relaxed);
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }
    
    // ============================================================
    // QUICK HTTP PARSE (first packet only, no reassembly)
    // ============================================================
    if (packet.protocol == IPPROTO_TCP && packet.dst_port == 80) {
        QuickHTTPParse(packet_data, packet_len, packet);
    }
    
    // ============================================================
    // FILTER PACKET (inline, immediate)
    // ============================================================
    FilterResult result = engine_->FilterPacket(packet);
    
    // ============================================================
    // VERDICT (immediate, no async queue)
    // ============================================================
    uint32_t verdict = (result.action == RuleAction::DROP) ? NF_DROP : NF_ACCEPT;
    
    if (verdict == NF_DROP) {
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
    } else {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
    }
    
    return nfq_set_verdict(qh, nfq_id, verdict, 0, nullptr);
}

// ============================================================
// PARSE PACKET INLINE (no copying)
// ============================================================
bool InlinePacketHandler::ParsePacketInline(unsigned char* data, int len, PacketData& packet) {
    if (len < sizeof(struct iphdr)) {
        return false;
    }
    
    struct iphdr* ip_header = (struct iphdr*)data;
    
    // L3: IP
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;
    
    packet.src_ip = inet_ntoa(src_addr);
    packet.dst_ip = inet_ntoa(dst_addr);
    packet.protocol = ip_header->protocol;
    
    int ip_header_len = ip_header->ihl * 4;
    
    // L4: Ports
    if (packet.protocol == IPPROTO_TCP && len >= ip_header_len + sizeof(struct tcphdr)) {
        struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
        packet.src_port = ntohs(tcp_header->source);
        packet.dst_port = ntohs(tcp_header->dest);
        packet.tcp_flags = tcp_header->th_flags;
        packet.tcp_seq = ntohl(tcp_header->seq);
    } else if (packet.protocol == IPPROTO_UDP && len >= ip_header_len + sizeof(struct udphdr)) {
        struct udphdr* udp_header = (struct udphdr*)(data + ip_header_len);
        packet.src_port = ntohs(udp_header->source);
        packet.dst_port = ntohs(udp_header->dest);
    } else {
        packet.src_port = 0;
        packet.dst_port = 0;
    }
    
    return true;
}

// ============================================================
// QUICK HTTP PARSE (first packet only)
// ============================================================
void InlinePacketHandler::QuickHTTPParse(unsigned char* data, int len, PacketData& packet) {
    struct iphdr* ip_header = (struct iphdr*)data;
    int ip_header_len = ip_header->ihl * 4;
    
    if (len < ip_header_len + sizeof(struct tcphdr)) {
        return;
    }
    
    struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;
    int payload_offset = ip_header_len + tcp_header_len;
    
    if (payload_offset >= len) {
        return;  // No payload
    }
    
    int payload_len = len - payload_offset;
    if (payload_len < 10) {
        return;  // Too short to be HTTP
    }
    
    const char* payload = (const char*)(data + payload_offset);
    
    // Quick check for HTTP methods (no full parsing)
    if (strncmp(payload, "GET ", 4) == 0) {
        packet.http_method = "GET";
        // Extract URI quickly (up to space or newline)
        const char* uri_start = payload + 4;
        const char* uri_end = uri_start;
        while (uri_end < payload + payload_len && *uri_end != ' ' && *uri_end != '\r' && *uri_end != '\n') {
            uri_end++;
        }
        packet.http_uri = std::string(uri_start, uri_end - uri_start);
    } else if (strncmp(payload, "POST ", 5) == 0) {
        packet.http_method = "POST";
        const char* uri_start = payload + 5;
        const char* uri_end = uri_start;
        while (uri_end < payload + payload_len && *uri_end != ' ' && *uri_end != '\r' && *uri_end != '\n') {
            uri_end++;
        }
        packet.http_uri = std::string(uri_start, uri_end - uri_start);
    }
    // Add more methods if needed
}

// ============================================================
// STATS
// ============================================================
void InlinePacketHandler::PrintStats() const {
    uint64_t total = total_packets_.load();
    uint64_t accepted = accepted_packets_.load();
    uint64_t dropped = dropped_packets_.load();
    uint64_t errors = error_packets_.load();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "📊 InlinePacketHandler Statistics" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total packets:    " << total << std::endl;
    std::cout << "Accepted:         " << accepted << " (" << (total ? accepted * 100 / total : 0) << "%)" << std::endl;
    std::cout << "Dropped:          " << dropped << " (" << (total ? dropped * 100 / total : 0) << "%)" << std::endl;
    std::cout << "Errors:           " << errors << std::endl;
    std::cout << "========================================\n" << std::endl;
}
