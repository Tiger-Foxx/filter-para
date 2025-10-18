#include "ultra_parallel_engine.h"
#include "../utils.h"
#include <iostream>
#include <algorithm>

// ============================================================
// CONSTRUCTOR - AVEC PARTITIONNEMENT DES RÈGLES
// ============================================================
UltraParallelEngine::UltraParallelEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
    size_t num_workers)
    : RuleEngine(rules), debug_mode_(false) {
    
    // Auto-detect CPU cores if not specified
    if (num_workers == 0) {
        num_workers_ = 3; // Par défaut 3 workers pour la recherche
    } else {
        num_workers_ = num_workers;
    }
    
    // Clamp to reasonable range (2-16 workers)
    num_workers_ = std::max(size_t(2), std::min(size_t(16), num_workers_));
    
    // ============================================================
    // PARTITIONNER LES RÈGLES ENTRE LES WORKERS
    // ============================================================
    
    // Collecter toutes les règles dans un vecteur plat
    std::vector<Rule*> all_rules;
    for (auto& [layer, layer_rules] : rules_by_layer_) {
        for (auto& rule : layer_rules) {
            all_rules.push_back(rule.get());
        }
    }
    
    size_t total_rules = all_rules.size();
    size_t rules_per_worker = total_rules / num_workers_;
    size_t remainder = total_rules % num_workers_;
    
    std::cout << "📊 Parallel mode: " << total_rules << " rules" 
              << " | " << num_workers_ << " workers"
              << " | ~" << rules_per_worker << " rules per worker" << std::endl;
    
    // Créer les workers avec leurs partitions de règles
    size_t start_idx = 0;
    
    for (size_t worker_id = 0; worker_id < num_workers_; ++worker_id) {
        // Calculer combien de règles ce worker doit traiter
        size_t num_rules_for_this_worker = rules_per_worker;
        if (worker_id < remainder) {
            num_rules_for_this_worker++; // Distribuer le reste équitablement
        }
        
        // Créer un sous-ensemble de règles pour ce worker
        std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> worker_rules;
        
        for (size_t i = 0; i < num_rules_for_this_worker && start_idx < total_rules; ++i, ++start_idx) {
            Rule* original_rule = all_rules[start_idx];
            auto cloned_rule = original_rule->Clone();
            // Recompiler les IP ranges pour la règle clonée
            cloned_rule->CompileIPRanges();
            worker_rules[original_rule->layer].push_back(std::move(cloned_rule));
        }
        
        // Créer le worker avec ses règles partitionnées
        workers_.push_back(std::make_unique<Worker>(worker_rules, worker_id));
        
        std::cout << "👷 Worker " << worker_id << ": " 
                  << num_rules_for_this_worker << " rules" << std::endl;
    }
    
    // Démarrer les threads permanents des workers
    StartWorkers();
    
    std::cout << "🏁 UltraParallelEngine: " << num_workers_ 
              << " permanent workers started (rules partitioned)" << std::endl;
}

// ============================================================
// DESTRUCTOR - ARRÊTER LES WORKERS
// ============================================================
UltraParallelEngine::~UltraParallelEngine() {
    StopWorkers();
    workers_.clear();
}

// ============================================================
// START PERMANENT WORKER THREADS
// ============================================================
void UltraParallelEngine::StartWorkers() {
    shutdown_.store(false, std::memory_order_release);
    
    for (auto& worker : workers_) {
        worker->thread = std::thread(&UltraParallelEngine::WorkerThreadLoop, this, worker->worker_id);
    }
}

// ============================================================
// STOP PERMANENT WORKER THREADS
// ============================================================
void UltraParallelEngine::StopWorkers() {
    // Signal shutdown
    shutdown_.store(true, std::memory_order_release);
    
    // Wake up all workers
    {
        std::lock_guard<std::mutex> lock(packet_mutex_);
        packet_available_.store(true, std::memory_order_release);
    }
    packet_ready_cv_.notify_all();
    
    // Wait for all workers to finish
    for (auto& worker : workers_) {
        if (worker->thread.joinable()) {
            worker->thread.join();
        }
    }
}

// ============================================================
// WORKER THREAD LOOP (PERMANENT THREAD)
// ============================================================
void UltraParallelEngine::WorkerThreadLoop(size_t worker_id) {
    if (debug_mode_) {
        std::cout << "[WORKER-" << worker_id << "] 🚀 Thread started" << std::endl;
    }
    
    while (true) {
        // Wait for a packet to be available
        std::unique_lock<std::mutex> lock(packet_mutex_);
        
        if (debug_mode_) {
            std::cout << "[WORKER-" << worker_id << "] 💤 Waiting for packet..." << std::endl;
        }
        
        packet_ready_cv_.wait(lock, [this]() {
            return packet_available_.load(std::memory_order_acquire) || 
                   shutdown_.load(std::memory_order_acquire);
        });
        
        if (debug_mode_) {
            std::cout << "[WORKER-" << worker_id << "] 👁️ Woke up!" << std::endl;
        }
        
        // Check shutdown
        if (shutdown_.load(std::memory_order_acquire)) {
            if (debug_mode_) {
                std::cout << "[WORKER-" << worker_id << "] 🛑 Shutdown signal received" << std::endl;
            }
            break;
        }
        
        // Copy packet pointer locally before unlocking
        const PacketData* packet_to_process = current_packet_;
        lock.unlock();
        
        if (debug_mode_) {
            std::cout << "[WORKER-" << worker_id << "] 🔍 Processing packet..." << std::endl;
        }
        
        // Process the packet (WITHOUT holding the lock)
        if (packet_to_process) {
            WorkerEvaluate(*packet_to_process, worker_id);
        }
        
        // Signal that this worker is done
        size_t finished_count = workers_finished_.fetch_add(1, std::memory_order_acq_rel) + 1;
        
        if (debug_mode_) {
            std::cout << "[WORKER-" << worker_id << "] ✔️ Finished (count: " << finished_count << ")" << std::endl;
        }
        
        // Last worker notifies main thread
        if (finished_count == num_workers_) {
            if (debug_mode_) {
                std::cout << "[WORKER-" << worker_id << "] 📣 I'm the last one, notifying main thread!" << std::endl;
            }
            workers_done_cv_.notify_one();
        }
    }
}

// ============================================================
// WORKER EVALUATION (appelé par le thread permanent)
// ============================================================
void UltraParallelEngine::WorkerEvaluate(const PacketData& packet, size_t worker_id) {
    // Early exit si un autre worker a déjà trouvé un DROP
    if (race_state_.verdict_found.load(std::memory_order_acquire)) {
        if (debug_mode_) {
            std::cout << "[WORKER-" << worker_id << "] ⏩ Skipping (another worker found DROP)" << std::endl;
        }
        return;
    }
    
    if (debug_mode_) {
        std::cout << "[WORKER-" << worker_id << "] 🔎 Checking rules..." << std::endl;
    }
    
    // Évaluer le paquet avec les règles de CE worker uniquement
    FilterResult result = workers_[worker_id]->engine->FilterPacket(packet);
    
    if (debug_mode_) {
        std::cout << "[WORKER-" << worker_id << "] 📝 Result: " 
                  << (result.action == RuleAction::DROP ? "DROP" : "ACCEPT") << std::endl;
    }
    
    // Si DROP trouvé, essayer de gagner la course
    if (result.action == RuleAction::DROP) {
        bool expected = false;
        if (race_state_.verdict_found.compare_exchange_strong(expected, true, 
                                                               std::memory_order_acq_rel)) {
            // 🏆 CE WORKER A GAGNÉ !
            race_state_.winner_id.store(worker_id, std::memory_order_release);
            
            std::lock_guard<std::mutex> lock(race_state_.result_mutex);
            race_state_.result = result;
            
            if (debug_mode_) {
                std::cout << "[WORKER-" << worker_id << "] 🏆 WON THE RACE - Rule: " 
                          << result.rule_id << std::endl;
            }
        } else if (debug_mode_) {
            std::cout << "[WORKER-" << worker_id << "] 🥈 Found DROP but someone was faster" << std::endl;
        }
    }
}

// ============================================================
// MAIN FILTERING FUNCTION - DISTRIBUER AUX WORKERS
// ============================================================
FilterResult UltraParallelEngine::FilterPacket(const PacketData& packet) {
    if (debug_mode_) {
        std::cout << "[PARALLEL] 🔵 New packet: " << packet.src_ip << ":" << packet.src_port 
                  << " → " << packet.dst_ip << ":" << packet.dst_port << std::endl;
    }
    
    // Reset race state pour ce nouveau paquet
    race_state_.Reset();
    workers_finished_.store(0, std::memory_order_release);
    
    // Partager le paquet avec tous les workers (zero-copy via pointer)
    {
        std::lock_guard<std::mutex> lock(packet_mutex_);
        current_packet_ = &packet;
        packet_available_.store(true, std::memory_order_release);
    }
    
    if (debug_mode_) {
        std::cout << "[PARALLEL] 📢 Notifying " << num_workers_ << " workers..." << std::endl;
    }
    
    // Réveiller tous les workers
    packet_ready_cv_.notify_all();
    
    if (debug_mode_) {
        std::cout << "[PARALLEL] ⏳ Waiting for workers to finish..." << std::endl;
    }
    
    // Attendre que tous les workers aient fini (sans lock sur packet_mutex_)
    {
        std::unique_lock<std::mutex> lock(workers_done_mutex_);
        workers_done_cv_.wait(lock, [this]() {
            size_t finished = workers_finished_.load(std::memory_order_acquire);
            if (debug_mode_ && finished > 0) {
                std::cout << "[PARALLEL] 📊 Workers finished: " << finished << "/" << num_workers_ << std::endl;
            }
            return finished == num_workers_;
        });
    }
    
    if (debug_mode_) {
        std::cout << "[PARALLEL] ✅ All workers finished!" << std::endl;
    }
    
    // Reset packet availability pour le prochain paquet
    {
        std::lock_guard<std::mutex> lock(packet_mutex_);
        packet_available_.store(false, std::memory_order_release);
        current_packet_ = nullptr;
    }
    
    // Retourner le résultat
    if (race_state_.verdict_found.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(race_state_.result_mutex);
        if (debug_mode_) {
            std::cout << "[PARALLEL] ❌ Verdict: DROP (rule: " << race_state_.result.rule_id << ")" << std::endl;
        }
        return race_state_.result;
    }
    
    // Aucun worker n'a trouvé de DROP -> ACCEPT
    if (debug_mode_) {
        std::cout << "[PARALLEL] ✅ Verdict: ACCEPT" << std::endl;
    }
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}
