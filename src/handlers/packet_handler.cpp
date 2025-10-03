#include "packet_handler.h"
#include "tcp_reassembler.h"
#include "../engine/rule_engine.h"
#include "../engine/worker_pool.h"
#include "../utils.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <iomanip>
#include <errno.h>
#include <thread>
#include <chrono>
#include <atomic>

// ============================================================
// ORDRE CRITIQUE : Headers réseau POSIX/glibc d'abord
// ============================================================
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// ============================================================
// PUIS libnetfilter_queue
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
PacketHandler::PacketHandler(int queue_num, WorkerPool* worker_pool, bool debug_mode)
    : queue_num_(queue_num),
      worker_pool_(worker_pool),
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
// START
// ============================================================
void PacketHandler::Start(PacketCallback callback) {
    if (!nfq_handle_ || !queue_handle_) {
        std::cerr << "❌ ERROR: PacketHandler not initialized" << std::endl;
        return;
    }

    packet_callback_ = callback;
    running_.store(true);
    
    // ✅ START VERDICT WORKER THREAD (rend les verdicts asynchrones)
    verdict_thread_ = std::thread(&PacketHandler::VerdictWorker, this);

    std::cout << "🚀 PacketHandler listening on queue " << queue_num_ << std::endl;

    char buffer[65536] __attribute__((aligned));
    auto last_timeout_check = std::chrono::steady_clock::now();
    
    while (running_.load()) {
        int len = recv(netlink_fd_, buffer, sizeof(buffer), 0);
        
        if (len < 0) {
            if (errno == ENOBUFS) {
                std::cerr << "⚠️  WARNING: Packet buffer overrun" << std::endl;
                continue;
            }
            if (errno == EINTR || errno == EBADF || !running_.load()) {
                // EINTR: Interrupted by signal
                // EBADF: Socket closed (called from Stop())
                if (debug_mode_) {
                    std::cout << "   recv() interrupted: " << strerror(errno) << std::endl;
                }
                break;
            }
            std::cerr << "❌ ERROR: recv() failed: " << strerror(errno) << std::endl;
            break;
        }

        if (len == 0) continue;

        nfq_handle_packet(nfq_handle_, buffer, len);
        
        // Periodically check for timed-out buffered packets (every 1 second)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_timeout_check).count() > 1000) {
            CheckPendingTimeouts();
            last_timeout_check = now;
        }
    }

    std::cout << "🛑 PacketHandler loop exited cleanly" << std::endl;
}

// ============================================================
// STOP
// ============================================================
void PacketHandler::Stop() {
    running_.store(false);
    
    std::cout << "🧹 Stopping PacketHandler..." << std::endl;
    
    // ✅ STOP VERDICT WORKER THREAD
    {
        std::lock_guard<std::mutex> lock(verdict_mutex_);
        verdict_cv_.notify_all();  // Wake up verdict thread
    }
    
    if (verdict_thread_.joinable()) {
        verdict_thread_.join();
        std::cout << "   ✅ Verdict worker thread stopped" << std::endl;
    }

    // Flush all pending packets (ACCEPT them) - DO THIS FIRST!
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        if (!pending_packets_.empty()) {
            std::cout << "   Flushing " << pending_packets_.size() << " pending connections..." << std::endl;
            
            size_t total_packets = 0;
            for (auto& [conn_key, packets] : pending_packets_) {
                for (const auto& pending : packets) {
                    nfq_set_verdict(pending.qh, pending.nfq_id, NF_ACCEPT, 0, nullptr);
                    total_packets++;
                }
            }
            pending_packets_.clear();
            
            std::cout << "   ✅ Flushed " << total_packets << " buffered packets (ACCEPTED)" << std::endl;
        }
    }
    
    // Close netlink socket to unblock recv()
    if (netlink_fd_ >= 0) {
        close(netlink_fd_);
        netlink_fd_ = -1;
        std::cout << "   ✅ Closed netlink socket" << std::endl;
    }

    if (queue_handle_) {
        nfq_destroy_queue(queue_handle_);
        queue_handle_ = nullptr;
        std::cout << "   ✅ Destroyed NFQUEUE" << std::endl;
    }

    if (nfq_handle_) {
        nfq_close(nfq_handle_);
        nfq_handle_ = nullptr;
        std::cout << "   ✅ Closed NFQ handle" << std::endl;
    }

    if (tcp_reassembler_) {
        tcp_reassembler_->Cleanup();
        std::cout << "   ✅ Cleaned up TCP reassembler" << std::endl;
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

    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (!packet_hdr) {
        LOG_DEBUG(debug_mode_, "Cannot get packet header");
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    uint32_t nfq_id = ntohl(packet_hdr->packet_id);
    
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    if (packet_len < 0) {
        LOG_DEBUG(debug_mode_, "Cannot get packet payload");
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }

    try {
        PacketData parsed_packet;
        if (!ParsePacket(packet_data, packet_len, parsed_packet)) {
            LOG_DEBUG(debug_mode_, "Failed to parse packet " + std::to_string(packet_id));
            return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
        }

        uint64_t conn_key = GetConnectionKey(parsed_packet);
        
        // ============================================================
        // 1. CHECK IF CONNECTION ALREADY BLOCKED
        // ============================================================
        if (conn_key != 0 && IsConnectionBlocked(conn_key)) {
            dropped_packets_.fetch_add(1, std::memory_order_relaxed);
            if (packet_callback_) packet_callback_(true);
            
            LOG_DEBUG(debug_mode_, "DROPPED packet " + std::to_string(packet_id) + 
                     " - connection already blocked");
            return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, nullptr);
        }

        // ============================================================
        // 2. HANDLE HTTP REASSEMBLY (if needed)
        // ============================================================
        bool http_complete = false;
        bool has_http_data = false;  // Track if packet actually has HTTP payload
        
        if (NeedsHTTPReassembly(parsed_packet)) {
            // ✅ FIX: Only call reassembler if packet has actual payload
            // SYN/ACK/FIN packets without data don't need reassembly
            int ip_header_len = (packet_data[0] & 0x0F) * 4;
            if (packet_len > ip_header_len + 20) {  // Has TCP payload
                struct tcphdr* tcp_hdr = (struct tcphdr*)(packet_data + ip_header_len);
                int tcp_header_len = tcp_hdr->doff * 4;
                int payload_len = packet_len - ip_header_len - tcp_header_len;
                
                if (payload_len > 0) {
                    has_http_data = true;
                    reassembled_packets_.fetch_add(1, std::memory_order_relaxed);
                    HandleTCPReassembly(packet_data, packet_len, parsed_packet);
                    
                    // Check if HTTP request is now complete
                    http_complete = !parsed_packet.http_method.empty() && 
                                   !parsed_packet.http_uri.empty();
                    
                    if (http_complete) {
                        LOG_DEBUG(debug_mode_, "✅ HTTP REQUEST COMPLETE: " + 
                                 parsed_packet.http_method + " " + parsed_packet.http_uri);
                        
                        // ✅ HTTP COMPLETE: Evaluate rules for ALL buffered packets + current
                        if (conn_key != 0) {
                            LOG_DEBUG(debug_mode_, "🔍 Evaluating buffered packets for completed HTTP request");
                        }
                    } else {
                        LOG_DEBUG(debug_mode_, "⏳ HTTP incomplete (has data but not complete), BUFFERING packet " + std::to_string(packet_id));
                        
                        // ✅ BUFFER THIS PACKET - don't send verdict yet
                        {
                            std::lock_guard<std::mutex> lock(pending_mutex_);
                            pending_packets_[conn_key].emplace_back(nfq_id, qh, parsed_packet);
                            
                            LOG_DEBUG(debug_mode_, "[DEBUG] BUFFERED packet " + std::to_string(packet_id) + 
                                     " - waiting for complete HTTP request (total buffered: " + 
                                     std::to_string(pending_packets_[conn_key].size()) + ")");
                        }
                        
                        // ❌ NO VERDICT - packet is held in buffer
                        return 0;
                    }
                } else {
                    // ✅ FIX: TCP control packet (SYN/ACK/FIN) without payload → ACCEPT immediately
                    LOG_DEBUG(debug_mode_, "� TCP control packet without HTTP data, ACCEPTING immediately");
                }
            }
        }

        // ============================================================
        // 3. EVALUATE RULES ASYNCHRONOUSLY (NO BUSY-WAIT!)
        // ============================================================
        
        // ✅ ASYNC VERSION: Submit packet to worker and return IMMEDIATELY
        // Le worker appellera le callback quand l'évaluation sera terminée
        worker_pool_->SubmitPacket(parsed_packet, 
            [this, qh, nfq_id, packet_id, conn_key, http_complete](FilterResult result) {
            
            // Ce callback est appelé par le worker thread (pas par HandlePacket!)
            uint32_t verdict = NF_ACCEPT;
            
            if (result.action == RuleAction::DROP) {
                verdict = NF_DROP;
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                
                if (conn_key != 0) {
                    BlockConnection(conn_key);
                }

                if (packet_callback_) packet_callback_(true);
                
                LOG_DEBUG(debug_mode_, "❌ DROPPED packet " + std::to_string(packet_id) + 
                         " by rule " + result.rule_id + 
                         " in " + std::to_string(result.processing_time_ms) + "ms");
            } else {
                accepted_packets_.fetch_add(1, std::memory_order_relaxed);
                if (packet_callback_) packet_callback_(false);
                
                LOG_DEBUG(debug_mode_, "✅ ACCEPTED packet " + std::to_string(packet_id) + 
                         " in " + std::to_string(result.processing_time_ms) + "ms");
            }
            
            // ✅ FLUSH ALL BUFFERED PACKETS for this connection with same verdict
            if (http_complete && conn_key != 0) {
                LOG_DEBUG(debug_mode_, "🚀 Flushing buffered packets with verdict: " + 
                         std::string(verdict == NF_DROP ? "DROP" : "ACCEPT"));
                FlushPendingPackets(conn_key, verdict);
            }
            
            // ✅ ENQUEUE VERDICT (ne bloque PAS le thread HandlePacket!)
            {
                std::lock_guard<std::mutex> lock(verdict_mutex_);
                verdict_queue_.push({nfq_id, qh, verdict});
                verdict_cv_.notify_one();  // Wake up verdict thread
            }
        });
        
        // ✅ RETURN IMMEDIATELY - NO WAIT!
        // Le verdict sera rendu par le verdict_thread_ de manière asynchrone
        // ❌ ANCIEN CODE: return nfq_set_verdict() ici = busy-wait!
        // ✅ NOUVEAU CODE: return 0 = paquet pris en charge, verdict plus tard
        
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

        return 0;  // ✅ ASYNC: HandlePacket returns immediately!

    } catch (const std::exception& e) {
        std::cerr << "❌ Exception handling packet " << packet_id << ": " << e.what() << std::endl;
        
        // ✅ ASYNC: Enqueue ACCEPT verdict même en cas d'erreur
        {
            std::lock_guard<std::mutex> lock(verdict_mutex_);
            verdict_queue_.push({nfq_id, qh, NF_ACCEPT});
            verdict_cv_.notify_one();
        }
        return 0;
    }
}

// ============================================================
// VERDICT WORKER THREAD (ASYNC VERDICT RENDERING)
// ============================================================
void PacketHandler::VerdictWorker() {
    std::cout << "🚀 Verdict worker thread started" << std::endl;
    
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(verdict_mutex_);
        
        // Attendre qu'un verdict soit disponible (ou que running_ devienne false)
        verdict_cv_.wait(lock, [this] {
            return !verdict_queue_.empty() || !running_.load();
        });
        
        // Rendre TOUS les verdicts dans la queue (batch processing!)
        while (!verdict_queue_.empty()) {
            VerdictTask task = verdict_queue_.front();
            verdict_queue_.pop();
            
            // Unlock avant de rendre le verdict (nfq_set_verdict peut être lent)
            lock.unlock();
            
            // ✅ RENDER VERDICT (ne bloque AUCUN autre thread!)
            nfq_set_verdict(task.qh, task.nfq_id, task.verdict, 0, nullptr);
            
            // Relock pour le prochain verdict
            lock.lock();
        }
    }
    
    // ✅ FLUSH REMAINING VERDICTS on shutdown
    std::lock_guard<std::mutex> lock(verdict_mutex_);
    while (!verdict_queue_.empty()) {
        VerdictTask task = verdict_queue_.front();
        verdict_queue_.pop();
        nfq_set_verdict(task.qh, task.nfq_id, task.verdict, 0, nullptr);
    }
    
    std::cout << "🛑 Verdict worker thread stopped" << std::endl;
}

// ============================================================
// PACKET PARSING
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
    packet.timestamp_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();

    int ip_header_len = ip_header->ihl * 4;
    if (len <= ip_header_len) {
        return true;
    }

    if (ip_header->protocol == IPPROTO_TCP) {
        if (len < ip_header_len + sizeof(struct tcphdr)) {
            return true;
        }
        
        struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
        
        packet.src_port = ntohs(tcp_header->source);
        packet.dst_port = ntohs(tcp_header->dest);
        packet.tcp_seq = ntohl(tcp_header->seq);
        
        packet.tcp_flags = 0;
        if (tcp_header->syn) packet.tcp_flags |= 0x02;
        if (tcp_header->ack) packet.tcp_flags |= 0x10;
        if (tcp_header->fin) packet.tcp_flags |= 0x01;
        if (tcp_header->rst) packet.tcp_flags |= 0x04;
        if (tcp_header->psh) packet.tcp_flags |= 0x08;
        if (tcp_header->urg) packet.tcp_flags |= 0x20;
        
    } else if (ip_header->protocol == IPPROTO_UDP) {
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
// TCP REASSEMBLY HELPERS
// ============================================================
bool PacketHandler::NeedsHTTPReassembly(const PacketData& packet) {
    if (packet.protocol != IPPROTO_TCP) {
        return false;
    }

    return http_ports_.count(packet.src_port) > 0 || http_ports_.count(packet.dst_port) > 0;
}

void PacketHandler::HandleTCPReassembly(unsigned char* data, int len, PacketData& packet) {
    if (!tcp_reassembler_) {
        return;
    }

    auto http_data = tcp_reassembler_->ProcessPacket(data, len, packet);
    if (http_data && http_data->is_complete) {
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
    
    if (blocked_connections_.size() > 50000) {
        auto it = blocked_connections_.begin();
        for (int i = 0; i < 10000 && it != blocked_connections_.end(); ++i) {
            it = blocked_connections_.erase(it);
        }
    }
}

// ============================================================
// L7 PACKET BUFFERING
// ============================================================
void PacketHandler::FlushPendingPackets(uint64_t connection_key, uint32_t verdict) {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    
    auto it = pending_packets_.find(connection_key);
    if (it == pending_packets_.end()) {
        return; // No pending packets
    }
    
    size_t count = it->second.size();
    if (count > 0) {
        LOG_DEBUG(debug_mode_, "Flushing " + std::to_string(count) + 
                 " buffered packets with verdict=" + (verdict == NF_DROP ? "DROP" : "ACCEPT"));
        
        // Send verdict for all buffered packets
        for (const auto& pending : it->second) {
            nfq_set_verdict(pending.qh, pending.nfq_id, verdict, 0, nullptr);
            
            if (verdict == NF_DROP) {
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                if (packet_callback_) packet_callback_(true);
            } else {
                accepted_packets_.fetch_add(1, std::memory_order_relaxed);
                if (packet_callback_) packet_callback_(false);
            }
        }
    }
    
    // Remove from map
    pending_packets_.erase(it);
}

void PacketHandler::CheckPendingTimeouts() {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    std::vector<uint64_t> expired_connections;
    
    for (auto& [conn_key, packets] : pending_packets_) {
        if (packets.empty()) continue;
        
        // Check oldest packet
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - packets.front().timestamp).count();
        
        if (age > PENDING_TIMEOUT_MS) {
            LOG_DEBUG(debug_mode_, "TIMEOUT: Flushing " + std::to_string(packets.size()) + 
                     " buffered packets after " + std::to_string(age) + "ms (ACCEPT by default)");
            
            // Accept all timed-out packets
            for (const auto& pending : packets) {
                nfq_set_verdict(pending.qh, pending.nfq_id, NF_ACCEPT, 0, nullptr);
                accepted_packets_.fetch_add(1, std::memory_order_relaxed);
                if (packet_callback_) packet_callback_(false);
            }
            
            expired_connections.push_back(conn_key);
        }
    }
    
    // Clean up expired connections
    for (uint64_t conn_key : expired_connections) {
        pending_packets_.erase(conn_key);
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