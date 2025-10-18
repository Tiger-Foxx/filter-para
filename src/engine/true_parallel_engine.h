#pragma once

#include "rule_engine.h"
#include "fast_sequential_engine.h"
#include <vector>
#include <memory>
#include <thread>
#include <atomic>

// ============================================================
// TRUE PARALLEL ENGINE - SIMPLE & FAST
// ============================================================
// Concept simple :
// 1. 3 workers avec règles partitionnées (chacun 1/3 des règles)
// 2. Pour chaque paquet :
//    - Les 3 workers évaluent EN PARALLÈLE
//    - Chaque worker check SES règles uniquement
//    - Si UN worker dit DROP → verdict = DROP
//    - Si les 3 disent ACCEPT → verdict = ACCEPT
// 3. Synchronisation : attendre que les 3 aient fini
// 4. Performance : 3x moins de règles par worker = 3x plus rapide
// ============================================================

class TrueParallelEngine : public RuleEngine {
public:
    explicit TrueParallelEngine(
        const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
        size_t num_workers = 3);
    
    ~TrueParallelEngine() override;

    FilterResult FilterPacket(const PacketData& packet) override;

private:
    // ============================================================
    // WORKER - Moteur séquentiel avec SA partition de règles
    // ============================================================
    struct Worker {
        std::unique_ptr<FastSequentialEngine> engine;  // Son moteur avec SES règles
        size_t worker_id;
        
        // État de travail pour le paquet courant
        const PacketData* current_packet{nullptr};
        FilterResult current_result{RuleAction::ACCEPT, "", 0.0, RuleLayer::L3};
        std::atomic<bool> done{false};
        
        std::thread thread;
        
        Worker(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules, size_t id)
            : engine(std::make_unique<FastSequentialEngine>(rules)), worker_id(id) {}
    };
    
    std::vector<std::unique_ptr<Worker>> workers_;
    size_t num_workers_;
    
    // ============================================================
    // Synchronisation SIMPLE
    // ============================================================
    std::atomic<bool> packet_ready_{false};    // Paquet prêt à être traité
    std::atomic<bool> shutdown_{false};        // Signal d'arrêt
    
    // Worker loop
    void WorkerLoop(size_t worker_id);
};
