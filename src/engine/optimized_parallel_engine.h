#pragma once

#include "rule_engine.h"
#include "fast_sequential_engine.h"
#include "parsed_packet.h"
#include <atomic>
#include <thread>
#include <barrier>
#include <vector>
#include <memory>
#include <array>
#include <string>
#include <unordered_map>

// Linux futex (syscall direct)
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * OptimizedParallelEngine - Moteur parallèle ultra-optimisé
 * 
 * Architecture :
 * - Futex pour réveil instantané (~50-100ns overhead)
 * - std::barrier pour synchronisation finale (~100-200ns overhead)
 * - 3 workers permanents avec règles partitionnées
 * - CPU affinity pour éviter migration de threads
 * - Early exit avec atomic drop_detected
 * - Cache-aligned structures pour éviter false sharing
 * - Parsing SIMD (AVX2) si disponible
 * 
 * Performance attendue : ~700ns par paquet (vs 1350ns sequential)
 * Speedup : 1.9-2.0x sur systèmes Linux modernes
 */
class OptimizedParallelEngine : public RuleEngine {
public:
    /**
     * Constructeur
     * 
     * @param rules_by_layer Toutes les règles organisées par couche (seront partitionnées entre workers)
     * @param num_workers Nombre de workers parallèles (défaut: 3)
     */
    OptimizedParallelEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_by_layer, size_t num_workers = 3);
    
    /**
     * Destructeur - Arrête proprement les workers
     */
    ~OptimizedParallelEngine();
    
    /**
     * Interface legacy (compatibilité PacketData)
     * Convertit PacketData → ParsedPacket puis appelle FilterPacketFast
     */
    FilterResult FilterPacket(const PacketData& packet) override;
    
    /**
     * Interface optimisée (zero-copy, direct parsing)
     * 
     * @param parsed_packet Paquet déjà parsé par FastPacketParser
     * @return FilterResult avec action, rule_id, timing, layer
     */
    FilterResult FilterPacketFast(ParsedPacket& parsed_packet);
    
    /**
     * Statistiques détaillées
     */
    struct Stats {
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> packets_dropped{0};
        std::atomic<uint64_t> total_processing_time_ns{0};
        std::atomic<uint64_t> futex_wakes{0};
        std::atomic<uint64_t> early_exits{0};
        
        // Stats par worker
        std::array<std::atomic<uint64_t>, 3> worker_packets{};
        std::array<std::atomic<uint64_t>, 3> worker_drops{};
        std::array<std::atomic<uint64_t>, 3> worker_early_exits{};
    };
    
    const Stats& GetStats() const { return stats_; }
    void ResetStats();
    
private:
    // === Futex Wrappers (Linux-only) ===
    static int futex_wait(std::atomic<uint64_t>* addr, uint64_t expected);
    static int futex_wake(std::atomic<uint64_t>* addr, int count);
    
    // === Worker Structure (128 bytes aligned pour éviter false sharing) ===
    struct alignas(128) Worker {
        std::thread thread;
        int cpu_id{-1};
        
        // Engine avec règles partitionnées (1/3 des règles totales)
        std::unique_ptr<FastSequentialEngine> engine;
        
        // Résultat local (pas atomic, lecture après barrier)
        RuleAction my_result{RuleAction::ACCEPT};
        std::string matched_rule_id;
        RuleLayer matched_layer{RuleLayer::L3};
        
        // Control
        std::atomic<bool> running{true};
        
        // Stats locales
        uint64_t local_packets_processed{0};
        uint64_t local_drops_found{0};
        uint64_t local_early_exits{0};
    };
    
    // === Members ===
    std::vector<std::unique_ptr<Worker>> workers_;
    const size_t num_workers_;
    
    // === Synchronisation : futex sur séquence + barrier pour join ===
    alignas(64) std::atomic<uint64_t> packet_sequence_{0};
    alignas(64) std::atomic<ParsedPacket*> current_packet_{nullptr};
    
    // Barrier : main thread + workers (num_workers_ + 1)
    std::barrier<> sync_barrier_;
    
    // Stats globales
    Stats stats_;
    
    // === Methods ===
    void WorkerLoop(Worker* worker, size_t worker_id);
    void ConvertPacketData(const PacketData& data, ParsedPacket& parsed);
};
