#pragma once

#include "parsed_packet.h"
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif

/**
 * FastPacketParser - Parser ultra-rapide avec support SIMD optionnel
 * 
 * Objectif : Parsing < 100ns par paquet
 * - Aucune allocation mémoire (zero-copy)
 * - SIMD pour comparaisons IP si AVX2 disponible
 * - Inline pour éliminer call overhead
 */
class FastPacketParser {
public:
    /**
     * Parse un paquet IPv4 brut en ParsedPacket
     * 
     * @param raw_data Pointeur vers les données brutes (IP header)
     * @param raw_len Longueur totale
     * @param out Structure ParsedPacket à remplir
     * @return true si parsing réussi, false sinon
     */
    static inline bool Parse(const unsigned char* raw_data, size_t raw_len, ParsedPacket& out) {
        // Vérification taille minimale (IPv4 header = 20 bytes min)
        if (raw_len < sizeof(struct iphdr)) {
            return false;
        }
        
        const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(raw_data);
        
        // Vérification version IPv4
        if (ip->version != 4) {
            return false; // IPv6 non supporté pour l'instant
        }
        
        // === L3 PARSING ===
        // Conversion Network → Host byte order UNE SEULE FOIS
        out.src_ip = ntohl(ip->saddr);
        out.dst_ip = ntohl(ip->daddr);
        out.protocol = ip->protocol;
        out.ttl = ip->ttl;
        out.ip_total_length = ntohs(ip->tot_len);
        
        // Calculer offset L4
        size_t ip_header_len = ip->ihl * 4; // ihl = nombre de mots de 32 bits
        
        if (ip_header_len < 20 || ip_header_len > raw_len) {
            return false; // Header invalide
        }
        
        const unsigned char* l4_data = raw_data + ip_header_len;
        size_t l4_len = raw_len - ip_header_len;
        
        // === L4 PARSING (protocol-specific) ===
        if (ip->protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(l4_data);
            
            out.src_port = ntohs(tcp->source);
            out.dst_port = ntohs(tcp->dest);
            
            // Flags TCP (6 bits : URG, ACK, PSH, RST, SYN, FIN)
            out.tcp_flags = 0;
            out.tcp_flags |= (tcp->urg ? 0x20 : 0);
            out.tcp_flags |= (tcp->ack ? 0x10 : 0);
            out.tcp_flags |= (tcp->psh ? 0x08 : 0);
            out.tcp_flags |= (tcp->rst ? 0x04 : 0);
            out.tcp_flags |= (tcp->syn ? 0x02 : 0);
            out.tcp_flags |= (tcp->fin ? 0x01 : 0);
            
            // Calculer payload TCP
            size_t tcp_header_len = tcp->doff * 4;
            out.payload_length = (l4_len > tcp_header_len) ? (l4_len - tcp_header_len) : 0;
            
        } else if (ip->protocol == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(l4_data);
            
            out.src_port = ntohs(udp->source);
            out.dst_port = ntohs(udp->dest);
            out.tcp_flags = 0;
            
            uint16_t udp_len = ntohs(udp->len);
            out.payload_length = (udp_len > sizeof(struct udphdr)) ? 
                                 (udp_len - sizeof(struct udphdr)) : 0;
            
        } else if (ip->protocol == IPPROTO_ICMP && l4_len >= sizeof(struct icmphdr)) {
            // ICMP n'a pas de ports
            out.src_port = 0;
            out.dst_port = 0;
            out.tcp_flags = 0;
            out.payload_length = l4_len - sizeof(struct icmphdr);
            
        } else {
            // Protocole non reconnu ou taille insuffisante
            out.src_port = 0;
            out.dst_port = 0;
            out.tcp_flags = 0;
            out.payload_length = 0;
        }
        
        // === INIT ATOMICS ===
        out.verdict.store(NF_ACCEPT, std::memory_order_relaxed);
        out.drop_detected.store(false, std::memory_order_relaxed);
        
        return true;
    }
    
#ifdef __AVX2__
    /**
     * Compare une IP avec un tableau de règles IPs en utilisant SIMD (AVX2)
     * 
     * Permet de comparer 8 IPs en parallèle au lieu de 1.
     * Gain théorique : 30-40% sur les règles avec beaucoup d'IPs.
     * 
     * @param packet_ip IP du paquet (host byte order)
     * @param rule_ips Tableau d'IPs de règles (host byte order)
     * @param count Nombre d'IPs dans le tableau
     * @return true si match trouvé, false sinon
     */
    static inline bool CompareIP_SIMD(uint32_t packet_ip, const uint32_t* rule_ips, size_t count) {
        // Broadcast de l'IP du paquet dans tous les lanes du registre AVX2
        __m256i pkt_vec = _mm256_set1_epi32(static_cast<int32_t>(packet_ip));
        
        size_t i = 0;
        
        // Traiter par blocs de 8 IPs (256 bits / 32 bits = 8)
        for (; i + 8 <= count; i += 8) {
            // Charger 8 IPs de règles
            __m256i rule_vec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&rule_ips[i]));
            
            // Comparer 8 IPs en parallèle
            __m256i cmp = _mm256_cmpeq_epi32(pkt_vec, rule_vec);
            
            // Extraire masque de comparaison
            int mask = _mm256_movemask_epi8(cmp);
            
            if (mask != 0) {
                return true; // Au moins un match trouvé
            }
        }
        
        // Traiter résidu (< 8 IPs restantes) en scalar
        for (; i < count; ++i) {
            if (packet_ip == rule_ips[i]) {
                return true;
            }
        }
        
        return false;
    }
#endif
    
    /**
     * Version scalar de la comparaison IP (fallback sans AVX2)
     */
    static inline bool CompareIP_Scalar(uint32_t packet_ip, const uint32_t* rule_ips, size_t count) {
        for (size_t i = 0; i < count; ++i) {
            if (packet_ip == rule_ips[i]) {
                return true;
            }
        }
        return false;
    }
};
