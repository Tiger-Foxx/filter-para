#pragma once

#include "fast_sequential_engine.h"
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <future>
#include <queue>

// ============================================================
// ULTRA PARALLEL ENGINE - PERMANENT WORKERS RACING
// ============================================================
// Research-grade parallel filtering with:
// - N PERMANENT workers running from start to finish
// - Each worker has PARTITIONED rules (N times less than sequential)
// - Workers race on each packet (zero-copy sharing)
// - First worker to find DROP wins (atomic CAS)
// - Lock-free atomic verdict flag
// - Workers synchronized via condition variables
// ============================================================

class UltraParallelEngine : public RuleEngine {
public:
    explicit UltraParallelEngine(
        const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
        size_t num_workers = 0);
    
    ~UltraParallelEngine() override;

    FilterResult FilterPacket(const PacketData& packet) override;
    
    // For performance comparison
    void SetDebugMode(bool debug) { debug_mode_ = debug; }
    
    // Start/Stop permanent workers
    void StartWorkers();
    void StopWorkers();

private:
    // ============================================================
    // WORKER STRUCTURE (PERMANENT THREAD)
    // ============================================================
    struct Worker {
        std::unique_ptr<FastSequentialEngine> engine;
        size_t worker_id;
        std::thread thread;
        
        Worker(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules, 
               size_t id)
            : engine(std::make_unique<FastSequentialEngine>(rules)), worker_id(id) {}
    };
    
    std::vector<std::unique_ptr<Worker>> workers_;
    size_t num_workers_;
    bool debug_mode_;
    
    // ============================================================
    // PACKET DISTRIBUTION TO WORKERS
    // ============================================================
    
    // Current packet being processed (shared pointer for zero-copy)
    const PacketData* current_packet_{nullptr};
    
    // Synchronization for workers
    std::mutex packet_mutex_;               // Protects current_packet_ and packet_available_
    std::mutex workers_done_mutex_;         // Separate mutex for workers completion
    std::condition_variable packet_ready_cv_;
    std::condition_variable workers_done_cv_;
    
    std::atomic<bool> packet_available_{false};
    std::atomic<size_t> workers_finished_{0};
    std::atomic<bool> shutdown_{false};
    
    // ============================================================
    // RACING MECHANISM (per packet)
    // ============================================================
    
    struct RaceState {
        std::atomic<bool> verdict_found{false};
        std::atomic<int> winner_id{-1};
        FilterResult result{RuleAction::ACCEPT, "", 0.0, RuleLayer::L3};
        std::mutex result_mutex;
        
        void Reset() {
            verdict_found.store(false, std::memory_order_release);
            winner_id.store(-1, std::memory_order_release);
            result = FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
        }
    };
    
    RaceState race_state_;
    
    // ============================================================
    // WORKER THREAD FUNCTIONS
    // ============================================================
    
    // Main loop for permanent worker thread
    void WorkerThreadLoop(size_t worker_id);
    
    // Evaluate single packet (called by worker thread)
    void WorkerEvaluate(const PacketData& packet, size_t worker_id);
};
