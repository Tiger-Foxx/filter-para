#pragma once

#include "rule_engine.h"
#include "../handlers/tcp_reassembler.h"  // ✅ INCLUDE COMPLET (pas de forward declaration)

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <memory>

// ============================================================
// WORKER POOL - HASH-BASED DISPATCH MULTI-THREADING
// ============================================================
class WorkerPool {
public:
    // Constructor / Destructor
    explicit WorkerPool(
        const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
        size_t num_workers = std::thread::hardware_concurrency()
    );
    ~WorkerPool();

    // Core operations
    void Start();
    void Stop();
    void SubmitPacket(const PacketData& packet, std::function<void(FilterResult)> callback);

    // Statistics structure (COMPLETE)
    struct Stats {
        size_t num_workers;                      // ✅ ADDED
        uint64_t total_dispatched;
        uint64_t total_processed;
        uint64_t total_dropped;
        uint64_t total_accepted;
        uint64_t queue_overflows;                // ✅ ADDED
        double avg_processing_time_ms;
        double load_variance;                    // ✅ ADDED
        std::vector<uint64_t> packets_per_worker;   // ✅ ADDED
        std::vector<uint64_t> drops_per_worker;     // ✅ ADDED
        std::vector<uint64_t> accepts_per_worker;   // ✅ ADDED
        std::vector<double> avg_time_per_worker;    // ✅ ADDED
    };

    Stats GetStats() const;
    void PrintStats() const;

private:
    // Worker context structure
    struct WorkerContext {
        std::thread thread;
        std::queue<std::pair<PacketData, std::function<void(FilterResult)>>> queue;
        std::unique_ptr<std::mutex> queue_mutex;
        std::unique_ptr<std::condition_variable> queue_cv;
        std::unique_ptr<TCPReassembler> reassembler;  // ✅ MAINTENANT COMPLET
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
              reassembler(std::move(other.reassembler))
        {
            packets_processed.store(other.packets_processed.load());
            packets_dropped.store(other.packets_dropped.load());
            packets_accepted.store(other.packets_accepted.load());
            total_processing_time_ms.store(other.total_processing_time_ms.load());
        }
    };

    std::vector<WorkerContext> workers_;
    size_t num_workers_;
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> total_dispatched_{0};
    std::atomic<uint64_t> queue_overflows_{0};  // ✅ ADDED

    static constexpr size_t MAX_QUEUE_SIZE = 10000;

    // Hash dispatch (4-tuple)
    size_t HashDispatch(const PacketData& packet) const;
    void WorkerLoop(size_t worker_id);
    double CalculateLoadVariance() const;  // ✅ ADDED
};