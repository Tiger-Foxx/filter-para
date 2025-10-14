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
    // ✅ PERFORMANCE: Reserve less memory initially, grow as needed
    streams_.reserve(1000);  // Start with 1000, not max_streams/2 (5000)
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
    std::lock_guard<std::mutex> lock(streams_mutex_);  // ✅ SEGFAULT FIX: Protect map access
    
    std::string key = GetStreamKey(src_ip, src_port, dst_ip, dst_port);
    
    auto it = streams_.find(key);
    if (it != streams_.end()) {
        return it->second.get();
    }
    
    // ✅ SEGFAULT FIX: Aggressive cleanup if we hit max streams
    if (streams_.size() >= max_streams_) {
        // Emergency: Remove 20% of oldest streams at once (batch cleanup)
        size_t to_remove = max_streams_ / 5;  // Remove 20%
        
        std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> stream_ages;
        stream_ages.reserve(streams_.size());
        
        for (const auto& [key, stream] : streams_) {
            stream_ages.emplace_back(key, stream->last_activity);
        }
        
        // Sort by age (oldest first)
        std::sort(stream_ages.begin(), stream_ages.end(),
                  [](const auto& a, const auto& b) { return a.second < b.second; });
        
        // Remove oldest 20%
        for (size_t i = 0; i < to_remove && i < stream_ages.size(); ++i) {
            streams_.erase(stream_ages[i].first);
            streams_timeout_.fetch_add(1, std::memory_order_relaxed);
        }
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
    std::lock_guard<std::mutex> lock(streams_mutex_);  // ✅ SEGFAULT FIX: Protect erase
    
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
    if (!stream->current_http_request) {
        stream->current_http_request = std::make_shared<HTTPData>();
    }
    
    auto& http_data = stream->current_http_request;
    
    // Parse HTTP headers if not done yet
    if (!stream->http_headers_complete) {
        size_t header_end = stream->reassembled_data.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            return nullptr; // Headers not complete yet
        }
        
        std::string headers_section = stream->reassembled_data.substr(0, header_end);
        
        if (!ParseHTTPHeaders(headers_section, *http_data)) {
            return nullptr; // Invalid HTTP format
        }
        
        stream->http_headers_complete = true;
        
        // Extract Content-Length if present
        auto it = http_data->headers.find("content-length");
        if (it != http_data->headers.end()) {
            try {
                stream->content_length = std::stoull(it->second);
            } catch (...) {
                stream->content_length = 0;
            }
        }
        
        // Extract payload if present
        size_t payload_start = header_end + 4; // Skip "\r\n\r\n"
        if (payload_start < stream->reassembled_data.size()) {
            http_data->payload = stream->reassembled_data.substr(payload_start);
        }
    } else {
        // Continue collecting payload
        size_t header_end = stream->reassembled_data.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            size_t payload_start = header_end + 4;
            if (payload_start < stream->reassembled_data.size()) {
                http_data->payload = stream->reassembled_data.substr(payload_start);
            }
        }
    }
    
    // Check if request is complete
    bool is_complete = false;
    
    // ✅ CRITICAL OPTIMIZATION: Don't wait for body for most requests!
    // GET, HEAD, DELETE, CONNECT, TRACE have NO body → complete when headers parsed
    // Only POST, PUT, PATCH need body
    std::string method_upper = http_data->method;
    std::transform(method_upper.begin(), method_upper.end(), method_upper.begin(), ::toupper);
    
    bool method_has_body = (method_upper == "POST" || method_upper == "PUT" || method_upper == "PATCH");
    
    if (method_has_body && stream->content_length > 0) {
        // POST/PUT/PATCH with body - wait for complete payload
        if (http_data->payload.size() >= stream->content_length) {
            is_complete = true;
        }
    } else {
        // GET/HEAD/DELETE/etc OR no body → complete immediately when headers parsed!
        is_complete = stream->http_headers_complete;
    }
    
    // Return a COPY if complete, otherwise nullptr
    if (is_complete) {
        http_data->is_complete = true;
        
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
    std::lock_guard<std::mutex> lock(streams_mutex_);  // ✅ SEGFAULT FIX: Protect clear
    streams_.clear();
}

void TCPReassembler::CleanupExpiredStreams() {
    std::lock_guard<std::mutex> lock(streams_mutex_);  // ✅ SEGFAULT FIX: Protect iteration
    
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
    std::lock_guard<std::mutex> lock(streams_mutex_);  // ✅ SEGFAULT FIX: Protect read
    
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