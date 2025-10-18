#include "optimized_parallel_engine.h"
#include "fast_packet_parser.h"
#include "utils.h"
#include <sched.h>
#include <pthread.h>
#include <chrono>
#include <iostream>
#include <arpa/inet.h>

// ============================================================================
// FUTEX WRAPPERS (Linux-only syscalls directs)
// ============================================================================

int OptimizedParallelEngine::futex_wait(std::atomic<uint64_t>* addr, uint64_t expected) {
    return syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, expected, nullptr, nullptr, 0);
}

int OptimizedParallelEngine::futex_wake(std::atomic<uint64_t>* addr, int count) {
    return syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, count, nullptr, nullptr, 0);
}

// ============================================================================
// CONSTRUCTEUR
// ============================================================================

OptimizedParallelEngine::OptimizedParallelEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_by_layer,
    size_t num_workers
) : RuleEngine(rules_by_layer),
    num_workers_(num_workers),
    sync_barrier_(num_workers + 1)  // +1 pour le thread principal
{
    if (num_workers == 0 || num_workers > 16) {
        throw std::invalid_argument("num_workers must be between 1 and 16");
    }
    
    // Compter le nombre total de règles
    size_t total_rules = 0;
    for (const auto& [layer, layer_rules] : rules_by_layer) {
        total_rules += layer_rules.size();
    }
    
    std::cout << "[OptimizedParallelEngine] ========================================" << std::endl;
    std::cout << "[OptimizedParallelEngine] Initializing with " << num_workers_ 
              << " workers" << std::endl;
    std::cout << "[OptimizedParallelEngine] Total rules: " << total_rules << std::endl;
    
    // Aplatir toutes les règles dans un seul vecteur pour partitionnement
    std::vector<std::unique_ptr<Rule>> all_rules_flat;
    all_rules_flat.reserve(total_rules);
    
    for (const auto& [layer, layer_rules] : rules_by_layer) {
        for (const auto& rule_ptr : layer_rules) {
            // Clone les règles (on ne peut pas move car elles sont const)
            auto new_rule = std::make_unique<Rule>(*rule_ptr);
            all_rules_flat.push_back(std::move(new_rule));
        }
    }
    
    // Partitionnement équilibré des règles
    size_t rules_per_worker = all_rules_flat.size() / num_workers_;
    size_t remainder = all_rules_flat.size() % num_workers_;
    
    workers_.reserve(num_workers_);
    size_t rule_start = 0;
    
    for (size_t i = 0; i < num_workers_; ++i) {
        auto worker = std::make_unique<Worker>();
        worker->cpu_id = static_cast<int>(i); // CPU affinity : worker 0 → CPU 0, etc.
        
        // Partitionnement : premiers workers ont +1 règle si remainder > 0
        size_t num_rules = rules_per_worker + (i < remainder ? 1 : 0);
        size_t rule_end = rule_start + num_rules;
        
        // Créer le sous-ensemble de règles pour ce worker
        std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> worker_rules_by_layer;
        
        for (size_t j = rule_start; j < rule_end; ++j) {
            RuleLayer layer = all_rules_flat[j]->layer;
            worker_rules_by_layer[layer].push_back(std::move(all_rules_flat[j]));
        }
        
        // Compter les règles de ce worker
        size_t worker_rule_count = 0;
        for (const auto& [layer, layer_rules] : worker_rules_by_layer) {
            worker_rule_count += layer_rules.size();
        }
        
        std::cout << "[OptimizedParallelEngine]   Worker " << i 
                  << " -> CPU " << worker->cpu_id
                  << " | Rules [" << rule_start << "-" << rule_end << ") = " 
                  << worker_rule_count << " rules" << std::endl;
        
        // Créer le FastSequentialEngine pour ce worker
        worker->engine = std::make_unique<FastSequentialEngine>(worker_rules_by_layer);
        
        rule_start = rule_end;
        
        // Démarrer le thread worker
        worker->thread = std::thread(
            &OptimizedParallelEngine::WorkerLoop, 
            this, 
            worker.get(),
            i
        );
        
        workers_.push_back(std::move(worker));
    }
    
    std::cout << "[OptimizedParallelEngine] All workers started successfully" << std::endl;
    std::cout << "[OptimizedParallelEngine] ========================================" << std::endl;
}

// ============================================================================
// DESTRUCTEUR
// ============================================================================

OptimizedParallelEngine::~OptimizedParallelEngine() {
    std::cout << "[OptimizedParallelEngine] Shutting down..." << std::endl;
    
    // Signaler arrêt à tous les workers
    for (auto& worker : workers_) {
        worker->running.store(false, std::memory_order_release);
    }
    
    // Bump sequence et wake pour débloquer les workers en attente
    packet_sequence_.fetch_add(1, std::memory_order_release);
    futex_wake(&packet_sequence_, static_cast<int>(num_workers_));
    
    // Attendre que tous les threads se terminent
    for (auto& worker : workers_) {
        if (worker->thread.joinable()) {
            worker->thread.join();
        }
    }
    
    std::cout << "[OptimizedParallelEngine] All workers stopped" << std::endl;
    
    // Afficher stats finales
    std::cout << "[OptimizedParallelEngine] Final stats:" << std::endl;
    std::cout << "  Total packets: " << stats_.packets_processed.load() << std::endl;
    std::cout << "  Dropped: " << stats_.packets_dropped.load() << std::endl;
    std::cout << "  Early exits: " << stats_.early_exits.load() << std::endl;
    std::cout << "  Futex wakes: " << stats_.futex_wakes.load() << std::endl;
    
    for (size_t i = 0; i < num_workers_; ++i) {
        std::cout << "  Worker " << i << " - Packets: " 
                  << stats_.worker_packets[i].load()
                  << " | Drops: " << stats_.worker_drops[i].load()
                  << " | Early exits: " << stats_.worker_early_exits[i].load() << std::endl;
    }
}

// ============================================================================
// FILTER PACKET (Interface legacy)
// ============================================================================

FilterResult OptimizedParallelEngine::FilterPacket(const PacketData& packet) {
    // Conversion PacketData → ParsedPacket
    ParsedPacket parsed;
    ConvertPacketData(packet, parsed);
    
    return FilterPacketFast(parsed);
}

// ============================================================================
// FILTER PACKET FAST (Interface optimisée)
// ============================================================================

FilterResult OptimizedParallelEngine::FilterPacketFast(ParsedPacket& parsed_packet) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // === PHASE 1 : PUBLICATION ===
    // Reset early exit flag
    parsed_packet.drop_detected.store(false, std::memory_order_release);
    
    // Publier le pointeur du paquet (release ordering pour visibility)
    current_packet_.store(&parsed_packet, std::memory_order_release);
    
    // Incrémenter la séquence (acquire-release ordering)
    uint64_t seq = packet_sequence_.fetch_add(1, std::memory_order_acq_rel);
    
    // === PHASE 2 : WAKEUP (FUTEX) ===
    // Réveiller TOUS les workers en un seul syscall (~50ns)
    int woken = futex_wake(&packet_sequence_, static_cast<int>(num_workers_));
    stats_.futex_wakes.fetch_add(1, std::memory_order_relaxed);
    
    (void)woken; // Éviter warning unused
    
    // LOG: Paquet publié
    // std::cout << "[OptimizedParallelEngine] Packet seq=" << seq 
    //           << " published, woken=" << woken << " workers" << std::endl;
    
    // === PHASE 3 : BARRIER (ATTENDRE FIN) ===
    // Le thread principal attend ici avec les workers
    sync_barrier_.arrive_and_wait();
    
    // Après la barrière : tous les workers ont terminé leur évaluation
    
    // === PHASE 4 : RÉCUPÉRATION RÉSULTAT ===
    uint32_t verdict = parsed_packet.verdict.load(std::memory_order_acquire);
    RuleAction action = (verdict == NF_DROP) ? RuleAction::DROP : RuleAction::ACCEPT;
    
    // Trouver quel worker a matché (si DROP)
    std::string rule_id;
    RuleLayer layer = RuleLayer::L3;
    
    if (action == RuleAction::DROP) {
        // Parcourir les workers pour trouver celui qui a trouvé le DROP
        for (auto& worker : workers_) {
            if (worker->my_result == RuleAction::DROP) {
                rule_id = worker->matched_rule_id;
                layer = worker->matched_layer;
                break;
            }
        }
        
        stats_.packets_dropped.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Compter early exits (si au moins un worker a sauté)
    bool any_early_exit = parsed_packet.drop_detected.load(std::memory_order_acquire);
    if (any_early_exit) {
        stats_.early_exits.fetch_add(1, std::memory_order_relaxed);
    }
    
    // === PHASE 5 : CLEANUP ===
    // Reset pointer pour prochain paquet
    current_packet_.store(nullptr, std::memory_order_release);
    
    // === MESURES TIMING ===
    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_us = std::chrono::duration<double, std::micro>(
        end_time - start_time
    ).count();
    
    double elapsed_ms = elapsed_us / 1000.0;  // Convert us → ms
    
    stats_.packets_processed.fetch_add(1, std::memory_order_relaxed);
    stats_.total_processing_time_ns.fetch_add(
        static_cast<uint64_t>(elapsed_us * 1000),
        std::memory_order_relaxed
    );
    
    // LOG: Résultat
    // if (action == RuleAction::DROP) {
    //     std::cout << "[OptimizedParallelEngine] Packet seq=" << seq 
    //               << " -> DROP by rule " << rule_id 
    //               << " (time=" << elapsed_us << "us)" << std::endl;
    // }
    
    return {action, rule_id, elapsed_ms, layer};
}

// ============================================================================
// WORKER LOOP (Boucle principale de chaque worker)
// ============================================================================

void OptimizedParallelEngine::WorkerLoop(Worker* worker, size_t worker_id) {
    std::cout << "[OptimizedParallelEngine] Worker " << worker_id 
              << " starting on thread " << std::this_thread::get_id() << std::endl;
    
    // === CPU AFFINITY (Pinning sur core dédié) ===
    if (worker->cpu_id >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(worker->cpu_id, &cpuset);
        
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) == 0) {
            std::cout << "[OptimizedParallelEngine] Worker " << worker_id 
                      << " pinned to CPU " << worker->cpu_id << std::endl;
        } else {
            std::cerr << "[OptimizedParallelEngine] Warning: Failed to set CPU affinity for worker " 
                      << worker_id << std::endl;
        }
    }
    
    // Séquence vue par ce worker
    uint64_t seen_seq = packet_sequence_.load(std::memory_order_acquire);
    
    while (worker->running.load(std::memory_order_relaxed)) {
        // === ATTENTE FUTEX (Sleep efficace avec ~0% CPU) ===
        uint64_t current_seq = packet_sequence_.load(std::memory_order_acquire);
        
        if (current_seq == seen_seq) {
            // Bloquer sur futex jusqu'à ce que packet_sequence_ change
            futex_wait(&packet_sequence_, seen_seq);
            // Futex retourne si :
            // - packet_sequence_ != seen_seq (nouveau paquet)
            // - ou signal/spurious wakeup (on re-check la condition)
            continue;
        }
        
        // Nouvelle séquence détectée = nouveau paquet disponible
        seen_seq = current_seq;
        
        // Check shutdown avant traitement
        if (!worker->running.load(std::memory_order_relaxed)) {
            break;
        }
        
        // === RÉCUPÉRATION DU PAQUET ===
        ParsedPacket* packet = current_packet_.load(std::memory_order_acquire);
        
        if (packet == nullptr) {
            // Spurious wakeup ou shutdown
            // Il faut quand même participer à la barrier pour éviter deadlock
            sync_barrier_.arrive_and_wait();
            continue;
        }
        
        // LOG: Worker démarre évaluation
        // std::cout << "[OptimizedParallelEngine] Worker " << worker_id 
        //           << " evaluating seq=" << seen_seq << std::endl;
        
        // === ÉVALUATION DES RÈGLES ===
        worker->my_result = RuleAction::ACCEPT;
        worker->matched_rule_id.clear();
        worker->matched_layer = RuleLayer::L3;
        
        // Early exit check : si un autre worker a déjà trouvé DROP, skip
        if (packet->drop_detected.load(std::memory_order_acquire)) {
            // Un autre worker a déjà trouvé DROP → économiser CPU
            worker->local_early_exits++;
            stats_.worker_early_exits[worker_id].fetch_add(1, std::memory_order_relaxed);
            
            // LOG: Early exit
            // std::cout << "[OptimizedParallelEngine] Worker " << worker_id 
            //           << " early exit (DROP already found)" << std::endl;
        } else {
            // Convertir ParsedPacket → PacketData pour FastSequentialEngine
            // TODO: Optimiser FastSequentialEngine pour accepter ParsedPacket directement
            PacketData pkt_data;
            
            // Conversion ultra-rapide (pas d'allocation dynamique)
            struct in_addr addr;
            addr.s_addr = htonl(packet->src_ip); // Host → network order
            pkt_data.src_ip = inet_ntoa(addr);
            
            addr.s_addr = htonl(packet->dst_ip);
            pkt_data.dst_ip = inet_ntoa(addr);
            
            pkt_data.src_port = packet->src_port;
            pkt_data.dst_port = packet->dst_port;
            
            // Protocol est déjà uint8_t
            pkt_data.protocol = packet->protocol;
            
            // Évaluer avec MES règles partitionnées (1/3 des règles totales)
            FilterResult result = worker->engine->FilterPacket(pkt_data);
            
            worker->my_result = result.action;
            worker->matched_rule_id = result.rule_id;
            worker->matched_layer = result.layer;
            
            // Si DROP trouvé, update atomic verdict + signal early exit
            if (result.action == RuleAction::DROP) {
                // Compare-And-Swap sur le verdict (premier gagne)
                uint32_t expected = NF_ACCEPT;
                bool success = packet->verdict.compare_exchange_strong(
                    expected, NF_DROP,
                    std::memory_order_release,
                    std::memory_order_relaxed
                );
                
                // Signaler aux autres workers (même si on n'a pas gagné le CAS)
                packet->drop_detected.store(true, std::memory_order_release);
                
                // Stats
                worker->local_drops_found++;
                stats_.worker_drops[worker_id].fetch_add(1, std::memory_order_relaxed);
                
                // LOG: DROP trouvé
                // std::cout << "[OptimizedParallelEngine] Worker " << worker_id 
                //           << " found DROP: " << result.rule_id 
                //           << " (CAS " << (success ? "won" : "lost") << ")" << std::endl;
            }
        }
        
        // Stats
        worker->local_packets_processed++;
        stats_.worker_packets[worker_id].fetch_add(1, std::memory_order_relaxed);
        
        // === SYNCHRONISATION FINALE (BARRIER) ===
        // Attendre que tous les workers (+ main) arrivent
        sync_barrier_.arrive_and_wait();
        
        // Après barrier, le main thread a récupéré les résultats
        // On peut continuer à la prochaine itération
    }
    
    std::cout << "[OptimizedParallelEngine] Worker " << worker_id 
              << " exiting (packets=" << worker->local_packets_processed
              << ", drops=" << worker->local_drops_found
              << ", early_exits=" << worker->local_early_exits << ")" << std::endl;
}

// ============================================================================
// CONVERSION LEGACY (PacketData → ParsedPacket)
// ============================================================================

void OptimizedParallelEngine::ConvertPacketData(
    const PacketData& data, 
    ParsedPacket& parsed
) {
    // Convertir IPs string → uint32_t (host byte order)
    parsed.src_ip = ntohl(inet_addr(data.src_ip.c_str()));
    parsed.dst_ip = ntohl(inet_addr(data.dst_ip.c_str()));
    
    parsed.src_port = data.src_port;
    parsed.dst_port = data.dst_port;
    
    // Protocol est déjà uint8_t dans les deux structures
    parsed.protocol = data.protocol;
    
    // Valeurs par défaut
    parsed.tcp_flags = 0;
    parsed.ttl = 64;
    parsed.ip_total_length = 0;
    parsed.payload_length = 0;
    
    // Init atomics
    parsed.verdict.store(NF_ACCEPT, std::memory_order_relaxed);
    parsed.drop_detected.store(false, std::memory_order_relaxed);
}

// ============================================================================
// RESET STATS
// ============================================================================

void OptimizedParallelEngine::ResetStats() {
    stats_.packets_processed.store(0, std::memory_order_relaxed);
    stats_.packets_dropped.store(0, std::memory_order_relaxed);
    stats_.total_processing_time_ns.store(0, std::memory_order_relaxed);
    stats_.futex_wakes.store(0, std::memory_order_relaxed);
    stats_.early_exits.store(0, std::memory_order_relaxed);
    
    for (size_t i = 0; i < num_workers_; ++i) {
        stats_.worker_packets[i].store(0, std::memory_order_relaxed);
        stats_.worker_drops[i].store(0, std::memory_order_relaxed);
        stats_.worker_early_exits[i].store(0, std::memory_order_relaxed);
    }
}
