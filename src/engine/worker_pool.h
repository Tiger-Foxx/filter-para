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
#include <memory>
#include <functional>

// ============================================================
// WORKER POOL - HASH-BASED PACKET DISPATCH
// ============================================================
class WorkerPool {
public:
    explicit WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       size_t num_workers = 0);
    ~WorkerPool();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // Packet processing
    void EnqueuePacket(const PacketData& packet, std::function<void(FilterResult)> callback);
    
    // Statistics
    struct Stats {
        size_t num_workers;
        std::vector<uint64_t> packets_per_worker;
        std::vector<uint64_t> drops_per_worker;
        std::vector<uint64_t> accepts_per_worker;
        std::vector<double> avg_time_per_worker;
        uint64_t total_packets;
        uint64_t total_drops;
        uint64_t queue_overflows;
        double load_variance;
    };
    Stats GetStats() const;
    void PrintStats() const;

private:
    // Worker context
    struct WorkerContext {
        std::thread thread;
        std::queue<std::pair<PacketData, std::function<void(FilterResult)>>> queue;
        std::unique_ptr<std::mutex> queue_mutex;
        std::unique_ptr<std::condition_variable> queue_cv;
        std::unique_ptr<TCPReassembler> reassembler;
        
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> packets_dropped{0};
        std::atomic<uint64_t> packets_accepted{0};
        std::atomic<double> total_processing_time_ms{0.0};
        
        WorkerContext() 
            : queue_mutex(std::make_unique<std::mutex>()),
              queue_cv(std::make_unique<std::condition_variable>()),
              reassembler(std::make_unique<TCPReassembler>()) {}
        
        // ✅ Suppression des constructeurs de copie
        WorkerContext(const WorkerContext&) = delete;
        WorkerContext& operator=(const WorkerContext&) = delete;
        
        // ✅ Constructeur de déplacement
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
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    
    size_t num_workers_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> queue_overflows_{0};
    
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    
    // Worker management
    void WorkerLoop(size_t worker_id);
    size_t HashDispatch(const PacketData& packet) const;
    void SetWorkerAffinity(size_t worker_id);
    
    // Statistics
    double CalculateLoadVariance() const;
};

#endif // WORKER_POOL_H