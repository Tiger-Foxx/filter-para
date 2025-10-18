#include "true_parallel_engine.h"
#include "../utils.h"
#include <iostream>

// ============================================================
// CONSTRUCTOR - PARTITIONNER LES RÈGLES ENTRE WORKERS
// ============================================================
TrueParallelEngine::TrueParallelEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
    size_t num_workers)
    : RuleEngine(rules), num_workers_(num_workers) {
    
    if (num_workers_ == 0 || num_workers_ > 8) {
        num_workers_ = 3;
    }
    
    std::cout << "\n🔬 ===== PARALLEL ENGINE INITIALIZATION =====" << std::endl;
    
    // Collecter toutes les règles
    std::vector<Rule*> all_rules;
    for (auto& [layer, layer_rules] : rules_by_layer_) {
        for (auto& rule : layer_rules) {
            all_rules.push_back(rule.get());
        }
    }
    
    size_t total_rules = all_rules.size();
    size_t rules_per_worker = total_rules / num_workers_;
    
    std::cout << "📊 Total rules: " << total_rules << std::endl;
    std::cout << "👷 Workers: " << num_workers_ << std::endl;
    std::cout << "📐 Rules per worker: ~" << rules_per_worker << std::endl;
    std::cout << "\n🔀 Partitioning rules..." << std::endl;
    
    // Partitionner les règles entre workers
    size_t start_idx = 0;
    for (size_t w = 0; w < num_workers_; ++w) {
        size_t num_rules = rules_per_worker;
        if (w < total_rules % num_workers_) {
            num_rules++;  // Distribuer le reste équitablement
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
        std::cout << "  ✓ Worker " << w << ": " << num_rules << " rules (indices " 
                  << (start_idx - num_rules) << "-" << (start_idx - 1) << ")" << std::endl;
    }
    
    std::cout << "\n🚀 Starting worker threads..." << std::endl;
    
    // Démarrer les threads workers
    for (auto& worker : workers_) {
        worker->thread = std::thread(&TrueParallelEngine::WorkerLoop, this, worker->worker_id);
    }
    
    std::cout << "✅ " << num_workers_ << " worker threads started (true parallelism)" << std::endl;
    std::cout << "=========================================\n" << std::endl;
}

// ============================================================
// DESTRUCTOR - ARRÊTER PROPREMENT LES WORKERS
// ============================================================
TrueParallelEngine::~TrueParallelEngine() {
    // Signal shutdown
    shutdown_.store(true, std::memory_order_release);
    
    // Réveiller tous les workers
    {
        std::lock_guard<std::mutex> lock(start_mutex_);
        packet_ready_.store(true, std::memory_order_release);
    }
    start_cv_.notify_all();
    
    // Attendre que tous les threads terminent
    for (auto& worker : workers_) {
        if (worker->thread.joinable()) {
            worker->thread.join();
        }
    }
}

// ============================================================
// WORKER LOOP - Boucle permanente de chaque worker
// ============================================================
// COMPORTEMENT :
// 1. Attendre qu'un paquet soit prêt (condition_variable, pas de spin !)
// 2. Évaluer le paquet avec MES règles
// 3. Si je trouve DROP : le signaler immédiatement (early exit)
// 4. Incrémenter workers_finished et notifier si je suis le dernier
// 5. Retour à l'étape 1
// ============================================================
void TrueParallelEngine::WorkerLoop(size_t worker_id) {
    Worker* me = workers_[worker_id].get();
    
    while (true) {
        // ============================================================
        // ÉTAPE 1 : ATTENDRE UN PAQUET (avec condition_variable)
        // ============================================================
        {
            std::unique_lock<std::mutex> lock(start_mutex_);
            start_cv_.wait(lock, [this]() {
                return packet_ready_.load(std::memory_order_acquire) || 
                       shutdown_.load(std::memory_order_acquire);
            });
        }
        
        // Check shutdown
        if (shutdown_.load(std::memory_order_acquire)) {
            break;
        }
        
        // ============================================================
        // ÉTAPE 2 : ÉVALUER LE PAQUET AVEC MES RÈGLES
        // ============================================================
        // OPTIMISATION : Early exit si un autre worker a déjà trouvé DROP
        if (drop_detected_.load(std::memory_order_acquire)) {
            // Pas la peine d'évaluer, juste signaler qu'on a "fini"
            me->my_result = FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
        } else {
            // Évaluer avec MES règles partitionnées
            me->my_result = me->engine->FilterPacket(*me->current_packet);
            
            // ============================================================
            // ÉTAPE 3 : SI DROP TROUVÉ, SIGNALER AUX AUTRES (early exit)
            // ============================================================
            if (me->my_result.action == RuleAction::DROP) {
                // Signaler immédiatement aux autres workers
                drop_detected_.store(true, std::memory_order_release);
            }
        }
        
        // ============================================================
        // ÉTAPE 4 : SIGNALER QUE J'AI FINI
        // ============================================================
        me->done.store(true, std::memory_order_release);
        
        size_t finished = workers_finished_.fetch_add(1, std::memory_order_acq_rel) + 1;
        
        // Si je suis le dernier à finir, notifier le thread principal
        if (finished == num_workers_) {
            std::lock_guard<std::mutex> lock(done_mutex_);
            done_cv_.notify_one();
        }
        
        // ============================================================
        // ÉTAPE 5 : ATTENDRE QUE LE THREAD PRINCIPAL RÉINITIALISE
        // ============================================================
        // Attendre que packet_ready repasse à false (le thread principal
        // signale qu'il a lu les résultats et qu'on peut continuer)
        {
            std::unique_lock<std::mutex> lock(start_mutex_);
            start_cv_.wait(lock, [this]() {
                return !packet_ready_.load(std::memory_order_acquire) || 
                       shutdown_.load(std::memory_order_acquire);
            });
        }
    }
}

// ============================================================
// FILTER PACKET - Orchestration du filtrage parallèle
// ============================================================
// ALGORITHME :
// 1. Reset des états (drop_detected, workers_finished, done flags)
// 2. Distribuer le paquet aux 3 workers (pointeur, zero-copy)
// 3. Signaler via packet_ready + notify_all()
// 4. Attendre que les 3 workers aient fini (condition_variable)
// 5. Combiner les résultats (logique ET) : un seul DROP suffit
// 6. Reset packet_ready pour le prochain paquet
// 7. Retourner le verdict
// ============================================================
FilterResult TrueParallelEngine::FilterPacket(const PacketData& packet) {
    // ============================================================
    // PHASE 1 : RESET DES ÉTATS
    // ============================================================
    drop_detected_.store(false, std::memory_order_release);
    workers_finished_.store(0, std::memory_order_release);
    
    for (auto& worker : workers_) {
        worker->done.store(false, std::memory_order_release);
    }
    
    // ============================================================
    // PHASE 2 : DISTRIBUER LE PAQUET AUX WORKERS (zero-copy)
    // ============================================================
    // Chaque worker reçoit un POINTEUR vers le même paquet
    // Memory ordering : s'assurer que les workers voient current_packet
    // AVANT de voir packet_ready = true
    for (auto& worker : workers_) {
        worker->current_packet = &packet;
    }
    
    // Memory fence : garantir que les écritures ci-dessus sont visibles
    std::atomic_thread_fence(std::memory_order_release);
    
    // ============================================================
    // PHASE 3 : SIGNALER AUX WORKERS (GO!)
    // ============================================================
    {
        std::lock_guard<std::mutex> lock(start_mutex_);
        packet_ready_.store(true, std::memory_order_release);
    }
    start_cv_.notify_all();  // Réveiller les 3 workers
    
    // ============================================================
    // PHASE 4 : ATTENDRE QUE TOUS LES WORKERS AIENT FINI
    // ============================================================
    {
        std::unique_lock<std::mutex> lock(done_mutex_);
        done_cv_.wait(lock, [this]() {
            return workers_finished_.load(std::memory_order_acquire) == num_workers_;
        });
    }
    
    // ============================================================
    // PHASE 5 : COMBINER LES RÉSULTATS (logique ET)
    // ============================================================
    // Pour ACCEPT : il faut que LES 3 workers disent ACCEPT
    // Si UN SEUL dit DROP → le paquet est DROP
    FilterResult final_result(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
    
    for (auto& worker : workers_) {
        if (worker->my_result.action == RuleAction::DROP) {
            // Un worker a trouvé une règle qui DROP ce paquet
            final_result = worker->my_result;
            break;  // Pas besoin de vérifier les autres
        }
    }
    
    // ============================================================
    // PHASE 6 : RESET POUR LE PROCHAIN PAQUET
    // ============================================================
    {
        std::lock_guard<std::mutex> lock(start_mutex_);
        packet_ready_.store(false, std::memory_order_release);
    }
    start_cv_.notify_all();  // Signaler aux workers qu'ils peuvent continuer
    
    // ============================================================
    // PHASE 7 : RETOURNER LE VERDICT
    // ============================================================
    return final_result;
}
