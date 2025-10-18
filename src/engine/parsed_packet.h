#pragma once

#include <atomic>
#include <cstdint>
#include <netinet/in.h>
#include <linux/netfilter.h>

// Forward declaration
struct nfq_q_handle;

/**
 * Structure ParsedPacket - Cache-aligned (64 bytes = 1 cache line)
 * 
 * Utilise uint32_t pour IPs (pas std::string) pour éviter allocations.
 * Alignée sur 64 bytes pour éviter false sharing entre workers.
 * 
 * Layout mémoire optimisé pour minimiser cache misses.
 */
struct alignas(64) ParsedPacket {
    // === L3 Data (IPv4 only pour l'instant) ===
    uint32_t src_ip;            // Host byte order (pas network!)
    uint32_t dst_ip;            // Host byte order
    uint8_t protocol;           // IPPROTO_TCP, IPPROTO_UDP, etc.
    uint8_t ttl;                // Time To Live
    uint16_t ip_total_length;   // Total length from IP header
    
    // === L4 Data ===
    uint16_t src_port;          // Host byte order
    uint16_t dst_port;          // Host byte order
    uint16_t tcp_flags;         // TCP flags (SYN, ACK, etc.)
    uint16_t payload_length;    // L4 payload length
    
    // === NFQUEUE Context ===
    nfq_q_handle* qh;           // Queue handle
    uint32_t nfq_id;            // Packet ID pour verdict
    
    // === Synchronisation atomique ===
    // Verdict final (NF_ACCEPT ou NF_DROP)
    std::atomic<uint32_t> verdict;
    
    // Early exit flag : set par le premier worker qui trouve DROP
    std::atomic<bool> drop_detected;
    
    // Padding pour atteindre exactement 64 bytes
    uint8_t _padding[6];
    
    // === Constructeur ===
    ParsedPacket() 
        : src_ip(0), dst_ip(0), protocol(0), ttl(0), ip_total_length(0),
          src_port(0), dst_port(0), tcp_flags(0), payload_length(0),
          qh(nullptr), nfq_id(0),
          verdict(NF_ACCEPT), drop_detected(false)
    {
        static_assert(sizeof(ParsedPacket) == 64, 
                      "ParsedPacket must be exactly 64 bytes (1 cache line)");
    }
};

// Vérification à la compilation
static_assert(sizeof(ParsedPacket) == 64, 
              "ParsedPacket doit faire exactement 64 bytes");
static_assert(alignof(ParsedPacket) == 64,
              "ParsedPacket doit être aligné sur 64 bytes");
