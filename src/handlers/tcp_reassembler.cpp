#include "tcp_reassembler.h"
#include "../engine/rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
TCPReassembler::TCPReassembler(size_t max_streams, uint32_t timeout_seconds)
    : max_streams_(max_streams), timeout_seconds_(timeout_seconds) {
    streams_.reserve(max_streams_ / 2); // Pre-allocate for performance
}

TCPReassembler::~TCPReassembler() {
    Cleanup();
}

// ============================================================
// MAIN PROCESSING FUNCTION
// ============================================================
std::shared_ptr<HTTPData> TCPReassembler::ProcessPacket(unsigned char* packet_data,
                                                        int packet_len,
                                                        PacketData& parsed_packet) {
    // Only process TCP packets
    if (parsed_packet.protocol != IPPROTO_TCP) {
        return nullptr;
    }
    
    // Extract IP header
    if (packet_len < sizeof(struct iphdr)) {
        return nullptr;
    }
    
    struct iphdr* ip_header = (struct iphdr*)packet_data;
    int ip_header_len = ip_header->ihl * 4;
    
    // Extract TCP header
    if (packet_len < ip_header_len + sizeof(struct tcphdr)) {
        return nullptr;
    }
    
    struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;
    
    // Extract payload
    int payload_offset = ip_header_len + tcp_header_len;
    if (payload_offset >= packet_len) {
        return nullptr; // No payload
    }
    
    int payload_len = packet_len - payload_offset;
    if (payload_len <= 0) {
        return nullptr;
    }
    
    std::string payload(reinterpret_cast<char*>(packet_data + payload_offset), payload_len);
    
    // Get or create stream (using std::string IPs from PacketData)
    TCPStream* stream = GetOrCreateStream(
        parsed_packet.src_ip, parsed_packet.src_port,
        parsed_packet.dst_ip, parsed_packet.dst_port
    );
    
    if (!stream) {
        return nullptr; // Max streams reached
    }
    
    // Update stream statistics
    stream->packets_received++;
    stream->bytes_received += payload_len;
    stream->last_activity = std::chrono::steady_clock::now();
    
    // Handle TCP flags
    if (tcp_header->syn) {
        stream->syn_seen = true;
        stream->expected_seq = ntohl(tcp_header->seq) + 1;
        return nullptr; // SYN packet has no data
    }
    
    if (tcp_header->fin) {
        stream->fin_seen = true;
    }
    
    if (tcp_header->rst) {
        stream->rst_seen = true;
        RemoveStream(GetStreamKey(parsed_packet.src_ip, parsed_packet.src_port,
                                 parsed_packet.dst_ip, parsed_packet.dst_port));
        return nullptr;
    }
    
    // Process TCP segment
    uint32_t seq_num = ntohl(tcp_header->seq);
    
    // ✅ TOUJOURS essayer d'assembler (même si out-of-order)
    // Python behavior: on stocke le segment et on continue
    ProcessTCPSegment(stream, seq_num, payload);
    
    // Try to parse HTTP if we have enough data
    if (stream->reassembled_data.size() >= 16) { // Minimum HTTP request size
        if (!stream->http_parsing_started) {
            // Check if this looks like HTTP
            if (IsHTTPRequest(stream->reassembled_data)) {
                stream->http_parsing_started = true;
                return ParseHTTPRequest(stream);
            } else {
                // Not HTTP traffic, remove stream to save memory
                RemoveStream(GetStreamKey(parsed_packet.src_ip, parsed_packet.src_port,
                                         parsed_packet.dst_ip, parsed_packet.dst_port));
                return nullptr;
            }
        } else {
            // Continue parsing
            return ParseHTTPRequest(stream);
        }
    }
    
    return nullptr;
}

// ============================================================
// STREAM MANAGEMENT
// ============================================================
std::string TCPReassembler::GetStreamKey(const std::string& src_ip, uint16_t src_port,
                                        const std::string& dst_ip, uint16_t dst_port) const {
    // Create bidirectional stream key (normalized)
    std::stringstream ss;
    if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
        ss << src_ip << ":" << src_port << "-" << dst_ip << ":" << dst_port;
    } else {
        ss << dst_ip << ":" << dst_port << "-" << src_ip << ":" << src_port;
    }
    return ss.str();
}

TCPStream* TCPReassembler::GetOrCreateStream(const std::string& src_ip, uint16_t src_port,
                                            const std::string& dst_ip, uint16_t dst_port) {
    std::string key = GetStreamKey(src_ip, src_port, dst_ip, dst_port);
    
    auto it = streams_.find(key);
    if (it != streams_.end()) {
        return it->second.get();
    }
    
    // Check max streams limit
    if (streams_.size() >= max_streams_) {
        // Remove oldest stream (simple LRU)
        auto oldest_it = streams_.begin();
        auto oldest_time = oldest_it->second->last_activity;
        
        for (auto iter = streams_.begin(); iter != streams_.end(); ++iter) {
            if (iter->second->last_activity < oldest_time) {
                oldest_it = iter;
                oldest_time = iter->second->last_activity;
            }
        }
        
        streams_.erase(oldest_it);
        streams_timeout_.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Create new stream
    auto new_stream = std::make_unique<TCPStream>();
    new_stream->src_ip = src_ip;
    new_stream->src_port = src_port;
    new_stream->dst_ip = dst_ip;
    new_stream->dst_port = dst_port;
    
    TCPStream* stream_ptr = new_stream.get();
    streams_[key] = std::move(new_stream);
    
    total_streams_created_.fetch_add(1, std::memory_order_relaxed);
    
    return stream_ptr;
}

void TCPReassembler::RemoveStream(const std::string& stream_key) {
    auto it = streams_.find(stream_key);
    if (it != streams_.end()) {
        streams_completed_.fetch_add(1, std::memory_order_relaxed);
        streams_.erase(it);
    }
}

// ============================================================
// TCP REASSEMBLY LOGIC
// ============================================================
void TCPReassembler::ProcessTCPSegment(TCPStream* stream, uint32_t seq_num,
                                      const std::string& payload) {
    if (payload.empty()) {
        return;
    }
    
    // ✅ FIX: Initialize expected_seq with first data packet seen (like Python)
    // This handles cases where we don't see the SYN packet
    if (stream->expected_seq == 0 && !stream->syn_seen) {
        stream->expected_seq = seq_num;
    }
    
    // Check for in-order packet
    if (seq_num == stream->expected_seq) {
        // In-order packet - assemble immediately
        stream->reassembled_data += payload;
        stream->expected_seq += payload.size();
        
        total_bytes_reassembled_.fetch_add(payload.size(), std::memory_order_relaxed);
        
        // Check if we can process any out-of-order packets now
        HandleOutOfOrderPackets(stream);
        
        return;
    }
    
    // Out-of-order packet
    if (seq_num > stream->expected_seq) {
        // Future packet - store for later (Python behavior)
        if (stream->out_of_order_packets.size() < MAX_OUT_OF_ORDER) {
            stream->out_of_order_packets.emplace_back(seq_num, payload);
            stream->out_of_order_count++;
            out_of_order_packets_.fetch_add(1, std::memory_order_relaxed);
            
            // Keep sorted by sequence number
            std::sort(stream->out_of_order_packets.begin(),
                     stream->out_of_order_packets.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
        }
        
        return;
    }
    
    // Old/duplicate packet - ignore silently (may be retransmission)
}

void TCPReassembler::HandleOutOfOrderPackets(TCPStream* stream) {
    while (!stream->out_of_order_packets.empty()) {
        auto& front = stream->out_of_order_packets.front();
        
        if (front.first == stream->expected_seq) {
            // This packet is now in order
            stream->reassembled_data += front.second;
            stream->expected_seq += front.second.size();
            
            total_bytes_reassembled_.fetch_add(front.second.size(), std::memory_order_relaxed);
            
            stream->out_of_order_packets.pop_front();
        } else if (front.first < stream->expected_seq) {
            // Old packet - discard
            stream->out_of_order_packets.pop_front();
        } else {
            // Still out of order
            break;
        }
    }
}

// ============================================================
// HTTP PARSING
// ============================================================
bool TCPReassembler::IsHTTPRequest(const std::string& data) const {
    // Check for HTTP method at start
    static const std::vector<std::string> http_methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };
    
    for (const auto& method : http_methods) {
        if (data.size() >= method.size() &&
            data.compare(0, method.size(), method) == 0) {
            return true;
        }
    }
    
    return false;
}

std::shared_ptr<HTTPData> TCPReassembler::ParseHTTPRequest(TCPStream* stream) {
    // ✅ LLHTTP VERSION (10-20x plus rapide!)
    
    // Initialize llhttp parser if not already done
    if (!stream->llhttp_parser) {
        stream->llhttp_parser = std::make_unique<LLHTTPParser>();
    }
    
    // Parse reassembled data with llhttp
    const uint8_t* data = reinterpret_cast<const uint8_t*>(stream->reassembled_data.data());
    size_t length = stream->reassembled_data.size();
    
    if (length == 0) {
        return nullptr;
    }
    
    // Feed data to llhttp parser
    bool parse_success = stream->llhttp_parser->Parse(data, length);
    
    if (!parse_success) {
        // Parse error - données HTTP malformées
        return nullptr;
    }
    
    // Check if HTTP request is complete
    if (!stream->llhttp_parser->IsComplete()) {
        return nullptr;  // Need more data
    }
    
    // ✅ HTTP REQUEST COMPLETE!
    const auto& llhttp_req = stream->llhttp_parser->GetRequest();
    
    // Convert llhttp result to HTTPData format
    if (!stream->current_http_request) {
        stream->current_http_request = std::make_shared<HTTPData>();
    }
    
    auto& http_data = stream->current_http_request;
    http_data->method = llhttp_req.method;
    http_data->uri = llhttp_req.url;
    http_data->version = llhttp_req.version;
    http_data->headers = llhttp_req.headers;
    http_data->payload = llhttp_req.body;
    http_data->is_complete = true;
    
    // Extract user-agent and host (pour compatibilité avec code existant)
    auto ua_it = http_data->headers.find("user-agent");
    if (ua_it != http_data->headers.end()) {
        http_data->user_agent = ua_it->second;
    }
    
    auto host_it = http_data->headers.find("host");
    if (host_it != http_data->headers.end()) {
        http_data->host = host_it->second;
    }
    
    // Create a copy to return (important: don't return the stream's working copy!)
    auto result = std::make_shared<HTTPData>(*http_data);
        
        // Reset stream for next request
        stream->current_http_request.reset();
        stream->reassembled_data.clear();
        stream->http_headers_complete = false;
        stream->content_length = 0;
        stream->http_parsing_started = false;
        
        return result;
    }
    
    return nullptr;
}

bool TCPReassembler::ParseHTTPHeaders(const std::string& data, HTTPData& http_data) {
    std::istringstream stream(data);
    std::string line;
    
    // Parse request line (first line)
    if (!std::getline(stream, line)) {
        return false;
    }
    
    // Remove trailing \r if present
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    
    // Parse method, URI, version
    std::istringstream request_line(line);
    if (!(request_line >> http_data.method >> http_data.uri >> http_data.version)) {
        return false;
    }
    
    // Parse headers
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.empty()) {
            break; // End of headers
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            continue; // Invalid header
        }
        
        std::string header_name = StringUtils::Trim(line.substr(0, colon_pos));
        std::string header_value = StringUtils::Trim(line.substr(colon_pos + 1));
        
        // Convert to lowercase for case-insensitive matching
        std::string header_name_lower = StringUtils::ToLower(header_name);
        
        http_data.headers[header_name_lower] = header_value;
        
        // Extract common headers for convenience
        if (header_name_lower == "user-agent") {
            http_data.user_agent = header_value;
        } else if (header_name_lower == "host") {
            http_data.host = header_value;
        }
    }
    
    return true;
}

// ============================================================
// CLEANUP
// ============================================================
void TCPReassembler::Cleanup() {
    streams_.clear();
}

void TCPReassembler::CleanupExpiredStreams() {
    auto now = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::seconds(timeout_seconds_);
    
    std::vector<std::string> expired_keys;
    
    for (const auto& [key, stream] : streams_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - stream->last_activity
        );
        
        if (elapsed > timeout_duration) {
            expired_keys.push_back(key);
        }
    }
    
    for (const auto& key : expired_keys) {
        streams_timeout_.fetch_add(1, std::memory_order_relaxed);
        streams_.erase(key);
    }
}

// ============================================================
// STATISTICS
// ============================================================
TCPReassembler::Stats TCPReassembler::GetStats() const {
    Stats stats;
    stats.active_streams = streams_.size();
    stats.total_streams_created = total_streams_created_.load();
    stats.streams_completed = streams_completed_.load();
    stats.streams_timeout = streams_timeout_.load();
    stats.total_bytes_reassembled = total_bytes_reassembled_.load();
    stats.out_of_order_packets = out_of_order_packets_.load();
    
    // Calculate average stream duration
    if (!streams_.empty()) {
        auto now = std::chrono::steady_clock::now();
        double total_duration = 0.0;
        
        for (const auto& [key, stream] : streams_) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - stream->creation_time
            );
            total_duration += duration.count();
        }
        
        stats.avg_stream_duration_ms = total_duration / streams_.size();
    } else {
        stats.avg_stream_duration_ms = 0.0;
    }
    
    return stats;
}

void TCPReassembler::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 TCP Reassembler Statistics:" << std::endl;
    std::cout << "   Active streams: " << stats.active_streams << std::endl;
    std::cout << "   Total streams created: " << stats.total_streams_created << std::endl;
    std::cout << "   Streams completed: " << stats.streams_completed << std::endl;
    std::cout << "   Streams timeout: " << stats.streams_timeout << std::endl;
    std::cout << "   Total bytes reassembled: " << stats.total_bytes_reassembled << std::endl;
    std::cout << "   Out-of-order packets: " << stats.out_of_order_packets << std::endl;
    std::cout << "   Avg stream duration: " << std::fixed << std::setprecision(2) 
              << stats.avg_stream_duration_ms << "ms" << std::endl;
}