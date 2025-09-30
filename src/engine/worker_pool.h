#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "rule_engine.h"
#include "../handlers/tcp_reassembler.h"

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <memory>
#include <unordered_map>

// ============================================================
// WORK ITEM FOR DISPATCH
// ============================================================
struct WorkItem {
    unsigned char* packet_data;  // Raw packet buffer
    int packet_len;
    PacketData parsed_packet;
    uint32_t nfqueue_id;         // For verdict
    uint64_t timestamp_ns;
    
    // Callback for verdict
    std::function<void(uint32_t verdict)> verdict_callback;
    
    WorkItem() : packet_data(nullptr), packet_len(0), nfqueue_id(0), timestamp_ns(0) {}
    
    ~WorkItem() {
        // Note: packet_data ownership managed externally (stack-allocated in NFQUEUE callback)
    }
};

// ============================================================
// WORKER POOL - HYBRID MULTI-WORKER ARCHITECTURE
// ============================================================
class WorkerPool {
public:
    explicit WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       size_t num_workers = 0);
    
    ~WorkerPool();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // Main dispatch function (called by PacketHandler)
    bool DispatchPacket(const WorkItem& work_item);
    
    // Statistics
    struct Stats {
        size_t num_workers;
        uint64_t total_dispatched;
        uint64_t total_processed;
        uint64_t queue_full_drops;
        std::vector<uint64_t> worker_packet_counts;
        std::vector<double> worker_avg_times_ms;
        double overall_avg_time_ms;
        double load_balance_variance;  // Measure of load distribution
    };
    
    Stats GetStats() const;
    void PrintStats() const;

private:
    // Worker management
    void WorkerLoop(size_t worker_id);
    size_t GetOptimalWorkerCount() const;
    void SetWorkerAffinity(size_t worker_id);
    
    // Hash-based dispatch
    size_t ComputeWorkerHash(const PacketData& packet) const;
    
    // Per-worker resources
    struct WorkerContext {
        std::thread thread;
        std::queue<std::unique_ptr<WorkItem>> queue;
        std::unique_ptr<std::mutex> queue_mutex;
        std::unique_ptr<std::condition_variable> queue_cv;
        std::unique_ptr<TCPReassembler> reassembler;
        
        // Per-worker stats
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> packets_dropped{0};
        std::atomic<uint64_t> packets_accepted{0};
        std::atomic<double> total_processing_time_ms{0.0};
        
        WorkerContext() 
            : queue_mutex(std::make_unique<std::mutex>()),
              queue_cv(std::make_unique<std::condition_variable>()),
              reassembler(std::make_unique<TCPReassembler>()) {}

        WorkerContext(const WorkerContext&) = delete;
        WorkerContext& operator=(const WorkerContext&) = delete;

        WorkerContext(WorkerContext&& other) noexcept
            : thread(std::move(other.thread)),
              queue(std::move(other.queue)),
              queue_mutex(std::move(other.queue_mutex)),
              queue_cv(std::move(other.queue_cv)),
              reassembler(std::make_unique<TCPReassembler>()) 
        {
            packets_processed.store(other.packets_processed.load());
            packets_dropped.store(other.packets_dropped.load());
            packets_accepted.store(other.packets_accepted.load());
            total_processing_time_ms.store(other.total_processing_time_ms.load());
        }
    };
    
    std::vector<WorkerContext> workers_;
    size_t num_workers_;
    
    // Rule engine (shared read-only)
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Global stats
    std::atomic<uint64_t> total_dispatched_{0};
    std::atomic<uint64_t> queue_full_drops_{0};
    
    // Configuration
    static constexpr size_t MAX_QUEUE_SIZE_PER_WORKER = 10000;
    static constexpr size_t CLEANUP_INTERVAL_PACKETS = 1000;
};

#endif // WORKER_POOL_H