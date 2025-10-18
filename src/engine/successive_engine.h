#pragma once

#include "rule_engine.h"
#include "fast_sequential_engine.h"
#include <vector>
#include <memory>

// ============================================================
// SUCCESSIVE ENGINE - 3 WORKERS UN APRÈS L'AUTRE
// ============================================================
// Mode "successive" demandé par le prof:
// - 3 workers avec règles partitionnées (~8 règles chacun)
// - Exécution SUCCESSIVE: Worker1 → Worker2 → Worker3
// - Hash O(1) pour chaque worker
// - Temps total = somme des temps individuels (PLUS LENT)
// ============================================================

class SuccessiveEngine : public RuleEngine {
public:
    // Constructeur: partitionne les règles entre 3 workers
    explicit SuccessiveEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                              size_t num_workers = 3);
    ~SuccessiveEngine() override = default;

    FilterResult FilterPacket(const PacketData& packet) override;

private:
    // ============================================================
    // WORKER STRUCTURE (mini-engine avec ses propres règles)
    // ============================================================
    struct IPRange {
        uint32_t network;
        uint32_t mask;
        std::string rule_id;
    };
    
    struct Worker {
        std::vector<std::unique_ptr<Rule>> rules;
        
        // Hash tables pour ce worker
        std::unordered_set<uint32_t> blocked_ips;
        std::vector<IPRange> ip_ranges;
        std::unordered_set<uint16_t> blocked_tcp_ports;
        std::unordered_set<uint16_t> blocked_udp_ports;
        std::unordered_map<uint16_t, std::string> tcp_port_rules;
        std::unordered_map<uint16_t, std::string> udp_port_rules;
        std::unordered_map<uint32_t, std::string> ip_rules;
        
        size_t worker_id;
    };
    
    std::vector<std::unique_ptr<Worker>> workers_;
    size_t num_workers_;
    
    // Fonction pour filtrer avec UN worker spécifique
    FilterResult FilterWithWorker(const PacketData& packet, Worker& worker);
    void BuildWorkerStructures(Worker& worker);
};
