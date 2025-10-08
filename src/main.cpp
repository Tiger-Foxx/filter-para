#include "engine/stream_inline_engine.h"
#include "loaders/rule_loader.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <cstdlib>
#include <csignal>
#include <memory>
#include <getopt.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <endian.h>

// Network byte order conversions (without arpa/inet.h)
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohs(x) __builtin_bswap16(x)
#define htons(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)
#define htonl(x) __builtin_bswap32(x)
#else
#define ntohs(x) (x)
#define htons(x) (x)
#define ntohl(x) (x)
#define htonl(x) (x)
#endif

// ============================================================
// GLOBAL STATE (for signal handling)
// ============================================================
std::unique_ptr<StreamInlineEngine> g_engine;
struct nfq_handle* g_nfq_handle = nullptr;
struct nfq_q_handle* g_queue_handle = nullptr;
std::atomic<bool> g_running{true};

// ============================================================
// COMMAND-LINE ARGUMENTS PARSING
// ============================================================
struct CommandLineArgs {
    std::string rules_file = "rules/example_rules.json";
    int queue_num = 0;
    size_t max_tcp_streams = 50000;
    bool debug_mode = false;
    bool show_help = false;
    bool show_version = false;
};

void PrintUsage(const char* program_name) {
    std::cout << "\n";
    std::cout << "🐯 Tiger-Fox C++ Network Filtering System 🦊\n";
    std::cout << "===============================================\n";
    std::cout << "Stream-Inline Architecture for Ultra High-Performance WAF\n";
    std::cout << "\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  -r, --rules FILE       Rules file path (default: rules/example_rules.json)\n";
    std::cout << "  -q, --queue NUM        NFQUEUE number (default: 0)\n";
    std::cout << "  -s, --streams NUM      Max TCP streams (default: 50000)\n";
    std::cout << "  -v, --verbose          Enable debug/verbose mode\n";
    std::cout << "  -h, --help             Show this help message\n";
    std::cout << "  -V, --version          Show version information\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  sudo " << program_name << "                           # Default settings\n";
    std::cout << "  sudo " << program_name << " --streams 100000           # 100K TCP streams\n";
    std::cout << "  sudo " << program_name << " --queue 1 --verbose        # Queue 1 with debug\n";
    std::cout << "  sudo " << program_name << " --rules custom_rules.json  # Custom rules file\n";
    std::cout << "\n";
    std::cout << "CloudLab Testing:\n";
    std::cout << "  Architecture: injector (10.10.1.10) → filter → server (10.10.2.20)\n";
    std::cout << "  From injector: wrk -t 12 -c 400 -d 30s http://10.10.2.20/\n";
    std::cout << "\n";
    std::cout << "Requirements:\n";
    std::cout << "  - Root privileges (sudo)\n";
    std::cout << "  - IP forwarding enabled\n";
    std::cout << "  - iptables NFQUEUE rule configured\n";
    std::cout << "\n";
    std::cout << "Signals:\n";
    std::cout << "  Ctrl+C (SIGINT)  - Graceful shutdown\n";
    std::cout << "  SIGTERM          - Graceful shutdown\n";
    std::cout << "\n";
}

void PrintVersion() {
    std::cout << "\n";
    std::cout << "🐯 Tiger-Fox C++ Network Filtering System 🦊\n";
    std::cout << "===============================================\n";
    std::cout << "Version: 2.0.0 (Stream-Inline)\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Architecture: Stream-Inline (Zero-Latency WAF)\n";
    std::cout << "Author: Pascal DONFACK ARTHUR MONTGOMERY (Tiger Fox)\n";
    std::cout << "\n";
    std::cout << "Features:\n";
    std::cout << "  ✓ Single-threaded inline processing (no queues/mutex)\n";
    std::cout << "  ✓ O(1) hash table lookups for L3/L4\n";
    std::cout << "  ✓ TCP stream reassembly for complete HTTP analysis\n";
    std::cout << "  ✓ PCRE2-JIT compiled regex (10x faster)\n";
    std::cout << "  ✓ Full L7 WAF rules (XSS, SQL injection, etc.)\n";
    std::cout << "  ✓ Real NFQUEUE inline filtering\n";
    std::cout << "\n";
    std::cout << "Dependencies:\n";
    std::cout << "  - libnetfilter_queue\n";
    std::cout << "  - PCRE2 (with JIT)\n";
    std::cout << "  - nlohmann-json\n";
    std::cout << "\n";
}

CommandLineArgs ParseArguments(int argc, char* argv[]) {
    CommandLineArgs args;
    
    // Define long options
    static struct option long_options[] = {
        {"rules",    required_argument, 0, 'r'},
        {"queue",    required_argument, 0, 'q'},
        {"streams",  required_argument, 0, 's'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {"version",  no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "r:q:s:vhV", long_options, &option_index)) != -1) {
        switch (c) {
            case 'r':
                args.rules_file = std::string(optarg);
                break;
                
            case 'q':
                try {
                    args.queue_num = std::stoi(optarg);
                    if (args.queue_num < 0 || args.queue_num > 65535) {
                        std::cerr << "❌ Error: Invalid queue number (must be 0-65535)\n";
                        exit(EXIT_FAILURE);
                    }
                } catch (...) {
                    std::cerr << "❌ Error: Invalid queue number format\n";
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 's':
                try {
                    args.max_tcp_streams = std::stoul(optarg);
                    if (args.max_tcp_streams < 100 || args.max_tcp_streams > 1000000) {
                        std::cerr << "❌ Error: Invalid stream count (must be 100-1000000)\n";
                        exit(EXIT_FAILURE);
                    }
                } catch (...) {
                    std::cerr << "❌ Error: Invalid stream count format\n";
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 'v':
                args.debug_mode = true;
                break;
                
            case 'h':
                args.show_help = true;
                break;
                
            case 'V':
                args.show_version = true;
                break;
                
            case '?':
                // getopt_long already printed an error message
                exit(EXIT_FAILURE);
                
            default:
                abort();
        }
    }
    
    // Check for non-option arguments
    if (optind < argc) {
        std::cerr << "❌ Error: Unexpected argument: " << argv[optind] << "\n";
        std::cerr << "   Use --help for usage information\n";
        exit(EXIT_FAILURE);
    }
    
    return args;
}

// ============================================================
// SIGNAL HANDLER
// ============================================================
void SignalHandler(int signal) {
    std::cout << "\n🛑 Received signal " << signal << ", shutting down gracefully..." << std::endl;
    g_running = false;
}

// ============================================================
// IP TO STRING (without arpa/inet.h to avoid header conflicts)
// ============================================================
std::string IPToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF);
    return oss.str();
}

// ============================================================
// PARSE PACKET DATA (inline)
// ============================================================
bool ParsePacketData(unsigned char* data, int len, PacketData& packet) {
    if (len < sizeof(struct iphdr)) {
        return false;
    }
    
    struct iphdr* ip_header = (struct iphdr*)data;
    
    // L3: IP (convert directly without inet_ntoa)
    packet.src_ip = IPToString(ip_header->saddr);
    packet.dst_ip = IPToString(ip_header->daddr);
    
    packet.protocol = ip_header->protocol;
    
    int ip_header_len = ip_header->ihl * 4;
    
    // L4: Ports
    if (packet.protocol == IPPROTO_TCP && len >= ip_header_len + sizeof(struct tcphdr)) {
        struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
        packet.src_port = ntohs(tcp_header->source);
        packet.dst_port = ntohs(tcp_header->dest);
        
        // Build TCP flags
        packet.tcp_flags = 0;
        if (tcp_header->syn) packet.tcp_flags |= 0x02;
        if (tcp_header->ack) packet.tcp_flags |= 0x10;
        if (tcp_header->fin) packet.tcp_flags |= 0x01;
        if (tcp_header->rst) packet.tcp_flags |= 0x04;
        if (tcp_header->psh) packet.tcp_flags |= 0x08;
        if (tcp_header->urg) packet.tcp_flags |= 0x20;
        
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
// NFQUEUE CALLBACK (INLINE PROCESSING)
// ============================================================
static int PacketCallback(struct nfq_q_handle *qh,
                         struct nfgenmsg *nfmsg,
                         struct nfq_data *nfa,
                         void *data) {
    
    static std::atomic<uint64_t> callback_count{0};
    uint64_t pkt_num = callback_count.fetch_add(1) + 1;
    
    std::cout << "[DEBUG] 📦 PacketCallback called (packet #" << pkt_num << ")" << std::endl;
    
    // Get packet ID
    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (!packet_hdr) {
        std::cout << "[DEBUG] ⚠️  No packet header, ACCEPTING" << std::endl;
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, nullptr);
    }
    
    uint32_t nfq_id = ntohl(packet_hdr->packet_id);
    std::cout << "[DEBUG] 📋 Packet ID: " << nfq_id << std::endl;
    
    // Get packet payload
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    if (packet_len < 0) {
        std::cout << "[DEBUG] ⚠️  Invalid payload, ACCEPTING" << std::endl;
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }
    
    std::cout << "[DEBUG] 📏 Payload length: " << packet_len << " bytes" << std::endl;
    
    // Parse packet data
    PacketData parsed_packet;
    if (!ParsePacketData(packet_data, packet_len, parsed_packet)) {
        std::cout << "[DEBUG] ⚠️  Parse failed, ACCEPTING" << std::endl;
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
    }
    
    std::cout << "[DEBUG] 🔍 Parsed: " << parsed_packet.src_ip << ":" << parsed_packet.src_port 
              << " → " << parsed_packet.dst_ip << ":" << parsed_packet.dst_port 
              << " (proto=" << (int)parsed_packet.protocol << ")" << std::endl;
    
    // INLINE FILTERING with TCP reassembly
    FilterResult result = g_engine->FilterPacketWithRawData(
        packet_data,
        packet_len,
        parsed_packet
    );
    
    // Set verdict IMMEDIATELY (no queue, no async)
    uint32_t verdict = (result.action == RuleAction::DROP) ? NF_DROP : NF_ACCEPT;
    
    if (verdict == NF_DROP) {
        std::cout << "[DEBUG] ❌ DROPPING packet #" << pkt_num << " (rule: " << result.rule_id << ")" << std::endl;
    } else {
        std::cout << "[DEBUG] ✅ ACCEPTING packet #" << pkt_num << std::endl;
    }
    
    return nfq_set_verdict(qh, nfq_id, verdict, 0, nullptr);
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================
int main(int argc, char* argv[]) {
    // Parse command-line arguments
    CommandLineArgs args = ParseArguments(argc, argv);
    
    // Handle --help
    if (args.show_help) {
        PrintUsage(argv[0]);
        return EXIT_SUCCESS;
    }
    
    // Handle --version
    if (args.show_version) {
        PrintVersion();
        return EXIT_SUCCESS;
    }
    
    // Print banner
    std::cout << "\n";
    std::cout << "🐯 ========================================== 🦊\n";
    std::cout << "   Tiger-Fox C++ Network Filtering System\n";
    std::cout << "   Stream-Inline Architecture (Zero-Latency)\n";
    std::cout << "🐯 ========================================== 🦊\n";
    std::cout << "\n";
    
    // Setup signal handlers
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    
    try {
        // ============================================================
        // LOAD RULES
        // ============================================================
        std::cout << "📋 Loading rules from " << args.rules_file << "..." << std::endl;
        
        auto rules = RuleLoader::LoadRules(args.rules_file);
        
        if (rules.empty()) {
            std::cerr << "❌ Error: No rules loaded\n";
            return EXIT_FAILURE;
        }
        
        // ============================================================
        // CREATE ENGINE
        // ============================================================
        std::cout << "\n🚀 Creating StreamInlineEngine..." << std::endl;
        
        g_engine = std::make_unique<StreamInlineEngine>(rules, args.max_tcp_streams);
        
        std::cout << std::endl;
        
        // ============================================================
        // SETUP NFQUEUE
        // ============================================================
        std::cout << "🔧 Opening NFQUEUE (queue " << args.queue_num << ")..." << std::endl;
        
        g_nfq_handle = nfq_open();
        if (!g_nfq_handle) {
            std::cerr << "❌ Error: Failed to open NFQUEUE\n";
            return EXIT_FAILURE;
        }
        
        // Unbind existing handler (if any)
        if (nfq_unbind_pf(g_nfq_handle, AF_INET) < 0) {
            std::cout << "⚠️  Could not unbind existing NFQUEUE handler (may be OK)\n";
        }
        
        // Bind to AF_INET
        if (nfq_bind_pf(g_nfq_handle, AF_INET) < 0) {
            nfq_close(g_nfq_handle);
            std::cerr << "❌ Error: Failed to bind NFQUEUE to AF_INET\n";
            return EXIT_FAILURE;
        }
        
        // Create queue
        g_queue_handle = nfq_create_queue(g_nfq_handle, args.queue_num, &PacketCallback, nullptr);
        if (!g_queue_handle) {
            nfq_close(g_nfq_handle);
            std::cerr << "❌ Error: Failed to create NFQUEUE\n";
            return EXIT_FAILURE;
        }
        
        // Set queue mode (copy full packet)
        if (nfq_set_mode(g_queue_handle, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
            nfq_destroy_queue(g_queue_handle);
            nfq_close(g_nfq_handle);
            std::cerr << "❌ Error: Failed to set NFQUEUE mode\n";
            return EXIT_FAILURE;
        }
        
        // Get socket fd
        int socket_fd = nfq_fd(g_nfq_handle);
        
        std::cout << "✅ NFQUEUE ready on queue " << args.queue_num << std::endl;
        std::cout << "\n📡 Processing packets INLINE (press Ctrl+C to stop)...\n" << std::endl;
        
        // ============================================================
        // MAIN LOOP (INLINE PROCESSING)
        // ============================================================
        char buffer[4096] __attribute__((aligned(4)));
        
        std::cout << "[DEBUG] 🔁 Entering main receive loop (socket_fd=" << socket_fd << ")..." << std::endl;
        
        while (g_running) {
            int received = recv(socket_fd, buffer, sizeof(buffer), 0);
            
            if (received < 0) {
                if (errno == EINTR) {
                    std::cout << "[DEBUG] ⚠️  recv() interrupted by signal, continuing..." << std::endl;
                    continue;  // Signal interrupted
                }
                std::cerr << "❌ recv() error: " << strerror(errno) << std::endl;
                break;
            }
            
            std::cout << "[DEBUG] 📥 Received " << received << " bytes from NFQUEUE" << std::endl;
            
            // Process packet INLINE (callback returns verdict immediately)
            nfq_handle_packet(g_nfq_handle, buffer, received);
            
            // Periodically cleanup expired TCP streams (every 1000 packets)
            static int packet_count = 0;
            if (++packet_count >= 1000) {
                g_engine->CleanupExpiredStreams();
                packet_count = 0;
            }
        }
        
        std::cout << "\n🛑 Shutting down..." << std::endl;
        
        // ============================================================
        // CLEANUP
        // ============================================================
        if (g_queue_handle) {
            nfq_destroy_queue(g_queue_handle);
        }
        
        if (g_nfq_handle) {
            nfq_unbind_pf(g_nfq_handle, AF_INET);
            nfq_close(g_nfq_handle);
        }
        
        // Print statistics
        std::cout << "\n";
        g_engine->PrintPerformanceStats();
        
        std::cout << "\n✅ Tiger-Fox terminated successfully\n" << std::endl;
        return EXIT_SUCCESS;
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Fatal error: " << e.what() << "\n" << std::endl;
        
        // Cleanup on error
        if (g_queue_handle) nfq_destroy_queue(g_queue_handle);
        if (g_nfq_handle) nfq_close(g_nfq_handle);
        
        return EXIT_FAILURE;
        
    } catch (...) {
        std::cerr << "\n❌ Fatal error: Unknown exception\n" << std::endl;
        
        // Cleanup on error
        if (g_queue_handle) nfq_destroy_queue(g_queue_handle);
        if (g_nfq_handle) nfq_close(g_nfq_handle);
        
        return EXIT_FAILURE;
    }
}