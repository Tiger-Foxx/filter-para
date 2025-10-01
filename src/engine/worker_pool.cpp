#include "worker_pool.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

// ============================================================
// CONCRETE RULE ENGINE FOR HYBRID MODE
// ============================================================
class HybridRuleEngine : public RuleEngine {
public:
    using RuleEngine::RuleEngine;
    
    FilterResult FilterPacket(const PacketData& packet) override {
        HighResTimer timer;
        
        // L3 (Network layer)
        if (rules_by_layer_.count(RuleLayer::L3)) {
            for (const auto& rule : rules_by_layer_.at(RuleLayer::L3)) {
                if (EvaluateL3Rule(*rule, packet)) {
                    l3_drops_.fetch_add(1, std::memory_order_relaxed);
                    return FilterResult(RuleAction::DROP, rule->id, timer.ElapsedMillis(), RuleLayer::L3);
                }
            }
        }
        
        // L4 (Transport layer)
        if (rules_by_layer_.count(RuleLayer::L4)) {
            for (const auto& rule : rules_by_layer_.at(RuleLayer::L4)) {
                if (EvaluateL4Rule(*rule, packet)) {
                    l4_drops_.fetch_add(1, std::memory_order_relaxed);
                    return FilterResult(RuleAction::DROP, rule->id, timer.ElapsedMillis(), RuleLayer::L4);
                }
            }
        }
        
        // L7 (Application layer)
        if (rules_by_layer_.count(RuleLayer::L7)) {
            for (const auto& rule : rules_by_layer_.at(RuleLayer::L7)) {
                if (EvaluateL7Rule(*rule, packet)) {
                    l7_drops_.fetch_add(1, std::memory_order_relaxed);
                    return FilterResult(RuleAction::DROP, rule->id, timer.ElapsedMillis(), RuleLayer::L7);
                }
            }
        }
        
        return FilterResult(RuleAction::ACCEPT, "default", timer.ElapsedMillis(), RuleLayer::L3);
    }
};

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
WorkerPool::WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       size_t num_workers)
    : rules_by_layer_(rules), num_workers_(num_workers == 0 ? SystemUtils::GetCPUCoreCount() : num_workers) {
    
    std::cout << "WorkerPool created with " << num_workers_ << " workers" << std::endl;
}

WorkerPool::~WorkerPool() {
    Stop();
}

// ============================================================
// START / STOP
// ============================================================
void WorkerPool::Start() {
    if (running_.load()) {
        std::cerr << "WorkerPool already running" << std::endl;
        return;
    }
    
    std::cout << "Starting WorkerPool with " << num_workers_ << " workers..." << std::endl;
    
    // Resize worker vector
    workers_.resize(num_workers_);
    
    // Start worker threads
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_[i].thread = std::thread(&WorkerPool::WorkerLoop, this, i);
        SetWorkerAffinity(i);
    }
    
    running_.store(true);
    std::cout << "✅ WorkerPool started successfully" << std::endl;
}

void WorkerPool::Stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "Stopping WorkerPool..." << std::endl;
    running_.store(false);
    
    // Notify all workers
    for (auto& worker : workers_) {
        worker.queue_cv->notify_all();
    }
    
    // Join all threads
    for (auto& worker : workers_) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }
    
    std::cout << "✅ WorkerPool stopped" << std::endl;
}

// ============================================================
// WORKER LOOP
// ============================================================
void WorkerPool::WorkerLoop(size_t worker_id) {
    auto& worker = workers_[worker_id];
    HybridRuleEngine rule_engine(rules_by_layer_);
    
    std::cout << "Worker " << worker_id << " started" << std::endl;
    
    while (running_.load()) {
        std::pair<PacketData, std::function<void(FilterResult)>> work_item;
        
        // Wait for work
        {
            std::unique_lock<std::mutex> lock(*worker.queue_mutex);
            worker.queue_cv->wait(lock, [&]() {
                return !worker.queue.empty() || !running_.load();
            });
            
            if (!running_.load() && worker.queue.empty()) {
                break;
            }
            
            if (!worker.queue.empty()) {
                work_item = std::move(worker.queue.front());
                worker.queue.pop();
            } else {
                continue;
            }
        }
        
        // Process packet
        HighResTimer timer;
        
        try {
            // Apply rules
            FilterResult result = rule_engine.FilterPacket(work_item.first);
            
            // Update stats
            worker.packets_processed.fetch_add(1, std::memory_order_relaxed);
            if (result.action == RuleAction::DROP) {
                worker.packets_dropped.fetch_add(1, std::memory_order_relaxed);
            } else {
                worker.packets_accepted.fetch_add(1, std::memory_order_relaxed);
            }
            
            double elapsed_ms = timer.ElapsedMillis();
            double current = worker.total_processing_time_ms.load(std::memory_order_relaxed);
            double new_value = current + elapsed_ms;
            while (!worker.total_processing_time_ms.compare_exchange_weak(
                current, new_value, std::memory_order_relaxed)) {
                new_value = current + elapsed_ms;
            }
            
            // Callback
            if (work_item.second) {
                work_item.second(result);
            }
            
            // Periodic cleanup
            if (worker.packets_processed.load() % 1000 == 0) {
                worker.reassembler->CleanupExpiredStreams();
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Worker " << worker_id << " exception: " << e.what() << std::endl;
        }
    }
    
    std::cout << "Worker " << worker_id << " stopped" << std::endl;
}

// ============================================================
// PACKET SUBMISSION
// ============================================================
void WorkerPool::SubmitPacket(const PacketData& packet, std::function<void(FilterResult)> callback) {
    if (!running_.load()) {
        return;
    }
    
    // Hash-based dispatch
    size_t worker_id = HashDispatch(packet);
    auto& worker = workers_[worker_id];
    
    // Check queue size
    {
        std::lock_guard<std::mutex> lock(*worker.queue_mutex);
        if (worker.queue.size() >= MAX_QUEUE_SIZE) {
            queue_overflows_.fetch_add(1, std::memory_order_relaxed);
            return;  // Drop packet
        }
        
        worker.queue.emplace(packet, callback);
    }
    
    worker.queue_cv->notify_one();
    total_dispatched_.fetch_add(1, std::memory_order_relaxed);
}

// ============================================================
// HASH DISPATCH
// ============================================================
size_t WorkerPool::HashDispatch(const PacketData& packet) const {
    // 4-tuple hash for TCP flows
    std::hash<std::string> hasher;
    std::string flow_key = packet.src_ip + ":" + std::to_string(packet.src_port) +
                          "->" + packet.dst_ip + ":" + std::to_string(packet.dst_port);
    size_t hash = hasher(flow_key);
    return hash % num_workers_;
}

// ============================================================
// WORKER AFFINITY
// ============================================================
void WorkerPool::SetWorkerAffinity(size_t worker_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker_id % SystemUtils::GetCPUCoreCount(), &cpuset);
    
    int rc = pthread_setaffinity_np(workers_[worker_id].thread.native_handle(),
                                    sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        std::cerr << "Warning: Failed to set affinity for worker " << worker_id << std::endl;
    }
#endif
}

// ============================================================
// STATISTICS
// ============================================================
WorkerPool::Stats WorkerPool::GetStats() const {
    Stats stats{};
    stats.num_workers = num_workers_;
    stats.total_dispatched = total_dispatched_.load();
    stats.total_processed = 0;
    stats.total_dropped = 0;
    stats.total_accepted = 0;
    stats.queue_overflows = queue_overflows_.load();
    
    for (const auto& worker : workers_) {
        uint64_t packets = worker.packets_processed.load();
        uint64_t drops = worker.packets_dropped.load();
        uint64_t accepts = worker.packets_accepted.load();
        double total_time = worker.total_processing_time_ms.load();
        
        stats.packets_per_worker.push_back(packets);
        stats.drops_per_worker.push_back(drops);
        stats.accepts_per_worker.push_back(accepts);
        stats.avg_time_per_worker.push_back(packets > 0 ? total_time / packets : 0.0);
        
        stats.total_processed += packets;
        stats.total_dropped += drops;
        stats.total_accepted += accepts;
    }
    
    if (stats.total_processed > 0) {
        double total_time = 0.0;
        for (const auto& worker : workers_) {
            total_time += worker.total_processing_time_ms.load();
        }
        stats.avg_processing_time_ms = total_time / stats.total_processed;
    } else {
        stats.avg_processing_time_ms = 0.0;
    }
    
    stats.load_variance = CalculateLoadVariance();
    
    return stats;
}

void WorkerPool::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 WorkerPool Statistics:" << std::endl;
    std::cout << "   Total workers: " << stats.num_workers << std::endl;
    std::cout << "   Total dispatched: " << stats.total_dispatched << std::endl;
    std::cout << "   Total processed: " << stats.total_processed << std::endl;
    std::cout << "   Total dropped: " << stats.total_dropped << std::endl;
    std::cout << "   Queue overflows: " << stats.queue_overflows << std::endl;
    std::cout << "   Avg processing time: " << std::fixed << std::setprecision(2) 
              << stats.avg_processing_time_ms << "ms" << std::endl;
    std::cout << "   Load variance: " << std::fixed << std::setprecision(2) 
              << stats.load_variance << std::endl;
    
    std::cout << "\n   Per-worker stats:" << std::endl;
    for (size_t i = 0; i < stats.num_workers; ++i) {
        std::cout << "   Worker " << i << ": "
                  << stats.packets_per_worker[i] << " packets, "
                  << stats.drops_per_worker[i] << " drops, "
                  << "avg " << std::fixed << std::setprecision(2) 
                  << stats.avg_time_per_worker[i] << "ms" << std::endl;
    }
}

double WorkerPool::CalculateLoadVariance() const {
    if (workers_.empty()) return 0.0;
    
    double mean = 0.0;
    for (const auto& worker : workers_) {
        mean += worker.packets_processed.load();
    }
    mean /= workers_.size();
    
    double variance = 0.0;
    for (const auto& worker : workers_) {
        double diff = worker.packets_processed.load() - mean;
        variance += diff * diff;
    }
    
    return variance / workers_.size();
}