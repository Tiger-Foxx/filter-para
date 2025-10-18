#include "true_parallel_engine.h"
#include "../utils.h"
#include <iostream>

// ============================================================
// CONSTRUCTOR - PARTITIONNER LES RÈGLES
// ============================================================
TrueParallelEngine::TrueParallelEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
    size_t num_workers)
    : RuleEngine(rules), num_workers_(num_workers) {
    
    if (num_workers_ == 0 || num_workers_ > 8) {
        num_workers_ = 3;
    }
    
    // Collecter toutes les règles
    std::vector<Rule*> all_rules;
    for (auto& [layer, layer_rules] : rules_by_layer_) {
        for (auto& rule : layer_rules) {
            all_rules.push_back(rule.get());
        }
    }
    
    size_t total_rules = all_rules.size();
    size_t rules_per_worker = total_rules / num_workers_;
    
    std::cout << "⚡ Parallel mode: " << total_rules << " rules → "
              << num_workers_ << " workers (~" << rules_per_worker << " rules each)" << std::endl;
    
    // Partitionner les règles entre workers
    size_t start_idx = 0;
    for (size_t w = 0; w < num_workers_; ++w) {
        size_t num_rules = rules_per_worker;
        if (w < total_rules % num_workers_) {
            num_rules++;  // Distribuer le reste
        }
        
        // Créer la partition pour ce worker
        std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> worker_rules;
        for (size_t i = 0; i < num_rules && start_idx < total_rules; ++i, ++start_idx) {
            Rule* orig = all_rules[start_idx];
            auto cloned = orig->Clone();
            cloned->CompileIPRanges();
            worker_rules[orig->layer].push_back(std::move(cloned));
        }
        
        workers_.push_back(std::make_unique<Worker>(worker_rules, w));
        std::cout << "  ✓ Worker " << w << ": " << num_rules << " rules" << std::endl;
    }
    
    // Démarrer les threads
    for (auto& worker : workers_) {
        worker->thread = std::thread(&TrueParallelEngine::WorkerLoop, this, worker->worker_id);
    }
    
    std::cout << "✅ " << num_workers_ << " workers started (true parallelism)" << std::endl;
}

// ============================================================
// DESTRUCTOR
// ============================================================
TrueParallelEngine::~TrueParallelEngine() {
    shutdown_.store(true, std::memory_order_release);
    
    // Réveiller tous les workers
    packet_ready_.store(true, std::memory_order_release);
    
    for (auto& worker : workers_) {
        if (worker->thread.joinable()) {
            worker->thread.join();
        }
    }
}

// ============================================================
// WORKER LOOP - Attend un paquet, l'évalue, signale qu'il a fini
// ============================================================
void TrueParallelEngine::WorkerLoop(size_t worker_id) {
    Worker* worker = workers_[worker_id].get();
    
    while (!shutdown_.load(std::memory_order_acquire)) {
        // Attendre qu'un paquet soit disponible (spin wait très rapide)
        while (!packet_ready_.load(std::memory_order_acquire) && 
               !shutdown_.load(std::memory_order_acquire)) {
            // Spin wait (très rapide, pas de sleep)
            std::this_thread::yield();
        }
        
        if (shutdown_.load(std::memory_order_acquire)) {
            break;
        }
        
        // Évaluer le paquet avec NOS règles
        worker->current_result = worker->engine->FilterPacket(*worker->current_packet);
        
        // Signaler qu'on a fini
        worker->done.store(true, std::memory_order_release);
        
        // Attendre le prochain paquet
        while (packet_ready_.load(std::memory_order_acquire) && 
               !shutdown_.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }
}

// ============================================================
// FILTER PACKET - Distribuer aux workers, attendre, combiner résultats
// ============================================================
FilterResult TrueParallelEngine::FilterPacket(const PacketData& packet) {
    // Reset l'état des workers
    for (auto& worker : workers_) {
        worker->current_packet = &packet;
        worker->done.store(false, std::memory_order_release);
    }
    
    // GO ! Lancer les workers
    packet_ready_.store(true, std::memory_order_release);
    
    // Attendre que TOUS les workers aient fini (spin wait)
    bool all_done = false;
    while (!all_done) {
        all_done = true;
        for (auto& worker : workers_) {
            if (!worker->done.load(std::memory_order_acquire)) {
                all_done = false;
                break;
            }
        }
        if (!all_done) {
            std::this_thread::yield();
        }
    }
    
    // Stopper les workers
    packet_ready_.store(false, std::memory_order_release);
    
    // Combiner les résultats : si UN worker dit DROP → DROP
    for (auto& worker : workers_) {
        if (worker->current_result.action == RuleAction::DROP) {
            return worker->current_result;  // Premier DROP trouvé
        }
    }
    
    // Tous ont dit ACCEPT
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}
