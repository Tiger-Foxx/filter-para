#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "rule_engine.h"
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <functional>
#include <vector>

// Forward declarations
class TCPReassembler;
struct PacketData;

// ============================================================
// WORKER POOL - HASH-BASED DISPATCH
// ============================================================

class WorkerPool {
public:
    // Statistics structure
    struct Stats {
        uint64_t total_packets;
        uint64_t total_dropped;
        uint64_t total_accepted;
        double avg_processing_time_ms;
        std::vector<uint64_t> worker_packet_counts;
        std::vector<double> worker_avg_times;
    };
    
    explicit WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       size_t num_workers = 0);
    
    ~WorkerPool();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // Packet processing
    bool DispatchPacket(const PacketData& packet, std::function<void(FilterResult)> callback);
    
    // Statistics
    Stats GetStats() const;
    void PrintStats() const;

private:
    // Worker context (per-worker state)
    struct WorkerContext {
        std::thread thread;
        std::queue<std::pair<PacketData, std::function<void(FilterResult)>>> queue;
        std::unique_ptr<std::mutex> queue_mutex;
        std::unique_ptr<std::condition_variable> queue_cv;
        std::unique_ptr<TCPReassembler> reassembler;
        
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> packets_dropped{0};
        std::atomic<uint64_t> packets_accepted{0};
        mutable std::atomic<double> total_processing_time_ms{0.0};
        
        WorkerContext() 
            : queue_mutex(std::make_unique<std::mutex>()),
              queue_cv(std::make_unique<std::condition_variable>()),
              reassembler(std::make_unique<TCPReassembler>()) {}
        
        // Non-copyable
        WorkerContext(const WorkerContext&) = delete;
        WorkerContext& operator=(const WorkerContext&) = delete;
        
        // Moveable
        WorkerContext(WorkerContext&& other) noexcept
            : thread(std::move(other.thread)),
              queue(std::move(other.queue)),
              queue_mutex(std::move(other.queue_mutex)),
              queue_cv(std::move(other.queue_cv)),
              reassembler(std::move(other.reassembler))
        {
            packets_processed.store(other.packets_processed.load());
            packets_dropped.store(other.packets_dropped.load());
            packets_accepted.store(other.packets_accepted.load());
            total_processing_time_ms.store(other.total_processing_time_ms.load());
        }
    };
    
    std::vector<WorkerContext> workers_;
    std::atomic<bool> running_{false};
    size_t num_workers_;
    
    // Rules (reference from constructor)
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_by_layer_;
    
    // Worker management
    void WorkerLoop(size_t worker_id);
    size_t GetOptimalWorkerCount() const;
    size_t DispatchToWorker(const PacketData& packet) const;
    void SetWorkerAffinity(size_t worker_id);
    
    // Helpers
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    uint32_t HashPacket(const PacketData& packet) const;
};

#endif // WORKER_POOL_H