#pragma once

#include "rule_engine.h"
#include "fast_sequential_engine.h"
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

// ============================================================
// TRUE PARALLEL ENGINE - PRODUCTION GRADE
// ============================================================
// Architecture de recherche avec synchronisation optimale :
//
// CONCEPT :
// --------
// 3 workers avec règles partitionnées évaluent LE MÊME paquet EN PARALLÈLE
// - Worker 0 : règles 0-7   (1/3 des règles)
// - Worker 1 : règles 8-15  (1/3 des règles)
// - Worker 2 : règles 16-23 (1/3 des règles)
//
// LOGIQUE DE DÉCISION (ET logique) :
// -----------------------------------
// Pour qu'un paquet soit ACCEPTÉ, il faut que LES 3 workers disent ACCEPT
// Si UN SEUL worker dit DROP → le paquet est DROP
//
// SYNCHRONISATION :
// -----------------
// 1. Thread principal prépare le paquet
// 2. Signale aux 3 workers via condition_variable (pas de spin-wait !)
// 3. Workers évaluent EN PARALLÈLE leurs règles
// 4. OPTIMISATION : Si un worker trouve DROP, les autres arrêtent (early exit)
// 5. Barrier : attendre que les 3 aient fini (ou détecté le DROP)
// 6. Combiner résultats : un seul DROP suffit
//
// VARIABLES D'ÉTAT PAR WORKER :
// ------------------------------
// - current_packet : pointeur vers le paquet à traiter
// - my_result : résultat de l'évaluation (ACCEPT ou DROP)
// - done : flag atomic indiquant que ce worker a fini
//
// GLOBAL SHARED STATE :
// ---------------------
// - drop_detected : atomic bool (si true, les autres workers arrêtent)
// - workers_finished : atomic counter (combien ont fini)
// - packet_ready : nouveau paquet disponible
//
// PERFORMANCE :
// -------------
// - Condition variables : pas de burn CPU
// - Early exit : dès qu'un DROP est trouvé
// - Memory ordering explicite : acquire/release semantics
// - Cache-friendly : chaque worker a ses propres variables
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
    // WORKER STATE (cache-aligned pour éviter false sharing)
    // ============================================================
    struct alignas(64) Worker {  // 64 bytes = taille d'une cache line
        // Moteur avec règles partitionnées
        std::unique_ptr<FastSequentialEngine> engine;
        size_t worker_id;
        
        // État de travail (variables d'état dédiées)
        const PacketData* current_packet{nullptr};
        FilterResult my_result{RuleAction::ACCEPT, "", 0.0, RuleLayer::L3};
        
        // Synchronisation
        std::atomic<bool> done{false};
        
        // Thread
        std::thread thread;
        
        Worker(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules, size_t id)
            : engine(std::make_unique<FastSequentialEngine>(rules)), worker_id(id) {}
    };
    
    std::vector<std::unique_ptr<Worker>> workers_;
    size_t num_workers_;
    
    // ============================================================
    // SHARED STATE (pour coordination entre workers)
    // ============================================================
    
    // Flags de contrôle
    std::atomic<bool> packet_ready_{false};      // Nouveau paquet prêt
    std::atomic<bool> drop_detected_{false};     // Un worker a trouvé DROP (early exit)
    std::atomic<size_t> workers_finished_{0};    // Compteur : combien ont fini
    std::atomic<bool> shutdown_{false};          // Signal de terminaison
    
    // Synchronisation
    std::mutex start_mutex_;
    std::condition_variable start_cv_;   // Pour réveiller les workers
    
    std::mutex done_mutex_;
    std::condition_variable done_cv_;    // Pour que le main thread attende
    
    // Worker loop
    void WorkerLoop(size_t worker_id);
};
