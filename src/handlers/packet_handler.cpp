#include "packet_handler.h"
#include "tcp_reassembler.h"
#include "../engine/rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <iomanip>

// ============================================================
// ORDRE CRITIQUE : Linux headers AVANT toute chose
// ============================================================
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <errno.h>

// ============================================================
// CALLBACK C POUR NFQUEUE
// ============================================================
static int nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data) {
    auto* handler = static_cast<PacketHandler*>(data);
    return handler->HandlePacket(qh, nfmsg, nfa);
}

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
PacketHandler::PacketHandler(int queue_num, RuleEngine* rule_engine, bool debug_mode)
    : queue_num_(queue_num),
      rule_engine_(rule_engine),
      debug_mode_(debug_mode),
      nfq_handle_(nullptr),
      queue_handle_(nullptr),
      netlink_fd_(-1),
      tcp_reassembler_(std::make_unique<TCPReassembler>()) {
    
    LOG_DEBUG(debug_mode_, "PacketHandler initialized for queue " + std::to_string(queue_num_));
}

PacketHandler::~PacketHandler() {
    Stop();
}

// ============================================================
// INITIALIZE
// ============================================================
bool PacketHandler::Initialize() {
    // Open NFQueue handle
    nfq_handle_ = nfq_open();
    if (!nfq_handle_) {
        std::cerr << "❌ ERROR: nfq_open() failed" << std::endl;
        return false;
    }

    // Unbind existing handler (if any)
    if (nfq_unbind_pf(nfq_handle_, AF_INET) < 0) {
        std::cerr << "⚠️  WARNING: nfq_unbind_pf() failed (may be normal)" << std::endl;
    }

    // Bind to AF_INET
    if (nfq_bind_pf(nfq_handle_, AF_INET) < 0) {
        std::cerr << "❌ ERROR: nfq_bind_pf() failed" << std::endl;
        nfq_close(nfq_handle_);
        return false;
    }

    // Create queue
    queue_handle_ = nfq_create_queue(nfq_handle_, queue_num_, nfq_callback, this);
    if (!queue_handle_) {
        std::cerr << "❌ ERROR: nfq_create_queue() failed for queue " << queue_num_ << std::endl;
        nfq_close(nfq_handle_);
        return false;
    }

    // Set copy mode (full packet)
    if (nfq_set_mode(queue_handle_, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        std::cerr << "❌ ERROR: nfq_set_mode() failed" << std::endl;
        nfq_destroy_queue(queue_handle_);
        nfq_close(nfq_handle_);
        return false;
    }

    // Set queue length
    if (nfq_set_queue_maxlen(queue_handle_, 10000) < 0) {
        std::cerr << "⚠️  WARNING: nfq_set_queue_maxlen() failed" << std::endl;
    }

    // Get netlink FD
    netlink_fd_ = nfq_fd(nfq_handle_);
    if (netlink_fd_ < 0) {
        std::cerr << "❌ ERROR: nfq_fd() failed" << std::endl;
        return false;
    }

    std::cout << "✅ PacketHandler initialized (queue " << queue_num_ << ")" << std::endl;
    return true;
}

// ============================================================
// START
// ============================================================
void PacketHandler::Start(PacketCallback callback) {
    if (!nfq_handle_ || !queue_handle_) {
        std::cerr << "❌ ERROR: PacketHandler not initialized" << std::endl;
        return;
    }

    packet_callback_ = callback;
    running_.store(true);

    std::cout << "🚀 PacketHandler listening on queue " << queue_num_ << std::endl;

    char buffer[65536] __attribute__((aligned));
    
    while (running_.load()) {
        int len = recv(netlink_fd_, buffer, sizeof(buffer), 0);
        
        if (len < 0) {
            if (errno == ENOBUFS) {
                std::cerr << "⚠️  WARNING: Packet buffer overrun" << std::endl;
                continue;
            }
            if (errno == EINTR || !running_.load()) {
                break;
            }
            std::cerr << "❌ ERROR: recv() failed: " << strerror(errno) << std::endl;
            break;
        }

        if (len == 0) continue;

        nfq_handle_packet(nfq_handle_, buffer, len);
    }

    std::cout << "🛑 PacketHandler stopped" << std::endl;
}

// ============================================================
// STOP
// ============================================================
void PacketHandler::Stop() {
    running_.store(false);

    if (queue_handle_) {
        nfq_destroy_queue(queue_handle_);
        queue_handle_ = nullptr;
    }

    if (nfq_handle_) {
        nfq_close(nfq_handle_);
        nfq_handle_ = nullptr;
    }

    if (tcp_reassembler_) {
        tcp_reassembler_->Cleanup();
    }

    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        blocked_connections_.clear();
    }

    std::cout << "🧹 PacketHandler cleaned up" << std::endl;
}

// ============================================================
// MAIN PACKET HANDLING FUNCTION
// ============================================================
int PacketHandler::HandlePacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                nfq_data *nfa) {
    HighResTimer timer;
    
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    uint64_t packet_id = total_packets_.load(std::memory_order_relaxed);

    // Get packet header
    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (!packet_hdr) {
        LOG_DEBUG(debug_mode_, "Cannot get packet header");
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    uint32_t nfq_id = ntohl(packet_hdr->packet_id);
    
    // Get packet payload
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    if (packet_len < 0) {
        LOG_DEBUG(debug_mode_, "Cannot get packet payload");
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }

    try {
        // Parse packet data
        PacketData parsed_packet;
        if (!ParsePacket(packet_data, packet_len, parsed_packet)) {
            LOG_DEBUG(debug_mode_, "Failed to parse packet " + std::to_string(packet_id));
            return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
        }

        // Check if connection is already blocked (efficiency optimization)
        uint64_t conn_key = GetConnectionKey(parsed_packet);
        if (conn_key != 0 && IsConnectionBlocked(conn_key)) {
            dropped_packets_.fetch_add(1, std::memory_order_relaxed);
            if (packet_callback_) packet_callback_(true);
            
            LOG_DEBUG(debug_mode_, "DROPPED packet " + std::to_string(packet_id) + 
                     " - connection already blocked");
            return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, nullptr);
        }

        // Handle TCP reassembly for HTTP if needed
        if (NeedsHTTPReassembly(parsed_packet)) {
            reassembled_packets_.fetch_add(1, std::memory_order_relaxed);
            HandleTCPReassembly(packet_data, packet_len, parsed_packet);
        }

        // Apply filtering rules (L3 → L4 → L7 sequential)
        FilterResult result = rule_engine_->FilterPacket(parsed_packet);
        
        // Execute verdict
        uint32_t verdict = NF_ACCEPT;
        if (result.action == RuleAction::DROP) {
            verdict = NF_DROP;
            dropped_packets_.fetch_add(1, std::memory_order_relaxed);
            
            // Block entire connection for efficiency
            if (conn_key != 0) {
                BlockConnection(conn_key);
            }

            if (packet_callback_) packet_callback_(true);
            
            LOG_DEBUG(debug_mode_, "DROPPED packet " + std::to_string(packet_id) + 
                     " by rule " + result.rule_id + 
                     " in " + std::to_string(result.processing_time_ms) + "ms");
        } else {
            accepted_packets_.fetch_add(1, std::memory_order_relaxed);
            if (packet_callback_) packet_callback_(false);
            
            LOG_DEBUG(debug_mode_, "ACCEPTED packet " + std::to_string(packet_id) + 
                     " in " + std::to_string(result.processing_time_ms) + "ms");
        }

        // Log progress every 1000 packets
        if (packet_id % 1000 == 0) {
            auto total = total_packets_.load(std::memory_order_relaxed);
            auto dropped = dropped_packets_.load(std::memory_order_relaxed);
            auto accepted = accepted_packets_.load(std::memory_order_relaxed);
            auto reassembled = reassembled_packets_.load(std::memory_order_relaxed);
            
            double drop_rate = (double)dropped / total * 100.0;
            double reassembly_rate = (double)reassembled / total * 100.0;
            
            std::cout << "📊 Processed " << total << " packets: "
                      << "dropped=" << dropped << " (" << std::fixed << std::setprecision(1) 
                      << drop_rate << "%), "
                      << "reassembled=" << reassembled << " (" << reassembly_rate << "%)"
                      << std::endl;
        }

        return nfq_set_verdict(qh, nfq_id, verdict, 0, nullptr);

    } catch (const std::exception& e) {
        std::cerr << "❌ Exception handling packet " << packet_id << ": " << e.what() << std::endl;
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }
}

// ============================================================
// PACKET PARSING
// ============================================================
bool PacketHandler::ParsePacket(unsigned char* data, int len, PacketData& packet) {
    if (len < sizeof(struct iphdr)) {
        return false;
    }

    struct iphdr* ip_header = (struct iphdr*)data;
    
    // Extract L3 information (CORRECTION: utiliser std::string)
    char src_ip_buf[INET_ADDRSTRLEN];
    char dst_ip_buf[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ip_header->saddr, src_ip_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip_buf, INET_ADDRSTRLEN);
    
    packet.src_ip = std::string(src_ip_buf);
    packet.dst_ip = std::string(dst_ip_buf);
    packet.protocol = ip_header->protocol;
    packet.timestamp_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();

    // Extract L4 information
    int ip_header_len = ip_header->ihl * 4;
    if (len <= ip_header_len) {
        return true; // IP-only packet (valid)
    }

    if (ip_header->protocol == IPPROTO_TCP) {
        if (len < ip_header_len + sizeof(struct tcphdr)) {
            return true; // Truncated TCP packet
        }
        
        struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
        
        packet.src_port = ntohs(tcp_header->source);
        packet.dst_port = ntohs(tcp_header->dest);
        packet.tcp_seq = ntohl(tcp_header->seq);
        
        // TCP flags (utiliser uint8_t, pas string)
        packet.tcp_flags = 0;
        if (tcp_header->syn) packet.tcp_flags |= 0x02;
        if (tcp_header->ack) packet.tcp_flags |= 0x10;
        if (tcp_header->fin) packet.tcp_flags |= 0x01;
        if (tcp_header->rst) packet.tcp_flags |= 0x04;
        if (tcp_header->psh) packet.tcp_flags |= 0x08;
        if (tcp_header->urg) packet.tcp_flags |= 0x20;
        
    } else if (ip_header->protocol == IPPROTO_UDP) {
        if (len < ip_header_len + sizeof(struct udphdr)) {
            return true; // Truncated UDP packet
        }
        
        struct udphdr* udp_header = (struct udphdr*)(data + ip_header_len);
        
        packet.src_port = ntohs(udp_header->source);
        packet.dst_port = ntohs(udp_header->dest);
    }

    return true;
}

// ============================================================
// TCP REASSEMBLY HELPERS
// ============================================================
bool PacketHandler::NeedsHTTPReassembly(const PacketData& packet) {
    // Only TCP packets
    if (packet.protocol != IPPROTO_TCP) {
        return false;
    }

    // Check if traffic on HTTP ports
    return http_ports_.count(packet.src_port) > 0 || http_ports_.count(packet.dst_port) > 0;
}

void PacketHandler::HandleTCPReassembly(unsigned char* data, int len, PacketData& packet) {
    if (!tcp_reassembler_) {
        return;
    }

    // Try to reassemble and extract HTTP data
    auto http_data = tcp_reassembler_->ProcessPacket(data, len, packet);
    if (http_data && http_data->is_complete) {
        // Update packet with HTTP L7 data
        packet.http_method = http_data->method;
        packet.http_uri = http_data->uri;
        packet.http_host = http_data->host;
        packet.http_user_agent = http_data->user_agent;
        
        LOG_DEBUG(debug_mode_, "Successfully reassembled HTTP request: " + 
                 http_data->method + " " + http_data->uri);
    }
}

// ============================================================
// CONNECTION TRACKING
// ============================================================
uint64_t PacketHandler::GetConnectionKey(const PacketData& packet) {
    if (packet.protocol != IPPROTO_TCP) {
        return 0;
    }

    // Create a hash-based connection key (4-tuple)
    // CORRECTION: Convertir src_ip/dst_ip en uint32_t pour hash
    uint32_t src_ip_int = RuleEngine::IPStringToUint32(packet.src_ip);
    uint32_t dst_ip_int = RuleEngine::IPStringToUint32(packet.dst_ip);
    
    std::hash<uint64_t> hasher;
    uint64_t key1 = (static_cast<uint64_t>(src_ip_int) << 32) | packet.src_port;
    uint64_t key2 = (static_cast<uint64_t>(dst_ip_int) << 32) | packet.dst_port;
    
    return hasher(key1 ^ key2);
}

bool PacketHandler::IsConnectionBlocked(uint64_t connection_key) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return blocked_connections_.count(connection_key) > 0;
}

void PacketHandler::BlockConnection(uint64_t connection_key) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    blocked_connections_.insert(connection_key);
    
    // Prevent unlimited growth (simple LRU)
    if (blocked_connections_.size() > 50000) {
        // Remove oldest 10000 connections
        auto it = blocked_connections_.begin();
        for (int i = 0; i < 10000 && it != blocked_connections_.end(); ++i) {
            it = blocked_connections_.erase(it);
        }
    }
}

// ============================================================
// STATISTICS
// ============================================================
PacketHandler::Stats PacketHandler::GetStats() const {
    Stats stats;
    stats.total_packets = total_packets_.load(std::memory_order_relaxed);
    stats.dropped_packets = dropped_packets_.load(std::memory_order_relaxed);
    stats.accepted_packets = accepted_packets_.load(std::memory_order_relaxed);
    stats.reassembled_packets = reassembled_packets_.load(std::memory_order_relaxed);
    
    if (stats.total_packets > 0) {
        stats.drop_rate = (double)stats.dropped_packets / stats.total_packets * 100.0;
        stats.reassembly_rate = (double)stats.reassembled_packets / stats.total_packets * 100.0;
    } else {
        stats.drop_rate = 0.0;
        stats.reassembly_rate = 0.0;
    }
    
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        stats.blocked_connections = blocked_connections_.size();
    }
    
    return stats;
}

void PacketHandler::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 PacketHandler Statistics:" << std::endl;
    std::cout << "   Total packets: " << stats.total_packets << std::endl;
    std::cout << "   Dropped: " << stats.dropped_packets 
              << " (" << std::fixed << std::setprecision(2) << stats.drop_rate << "%)" << std::endl;
    std::cout << "   Accepted: " << stats.accepted_packets << std::endl;
    std::cout << "   Reassembled: " << stats.reassembled_packets 
              << " (" << std::fixed << std::setprecision(2) << stats.reassembly_rate << "%)" << std::endl;
    std::cout << "   Blocked connections: " << stats.blocked_connections << std::endl;
}