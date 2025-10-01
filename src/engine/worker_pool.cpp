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
    // ✅ CORRECTION : Passer les règles par référence (const) au lieu de copier
    explicit HybridRuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
        : rules_ref_(rules) {}
    
    FilterResult FilterPacket(const PacketData& packet) override {
        HighResTimer timer;
        
        // L3 (Network layer)
        if (rules_ref_.count(RuleLayer::L3)) {
            for (const auto& rule : rules_ref_.at(RuleLayer::L3)) {
                if (EvaluateL3Rule(*rule, packet)) {
                    l3_drops_.fetch_add(1, std::memory_order_relaxed);
                    return FilterResult(RuleAction::DROP, rule->id, timer.ElapsedMillis(), RuleLayer::L3);
                }
            }
        }
        
        // L4 (Transport layer)
        if (rules_ref_.count(RuleLayer::L4)) {
            for (const auto& rule : rules_ref_.at(RuleLayer::L4)) {
                if (EvaluateL4Rule(*rule, packet)) {
                    l4_drops_.fetch_add(1, std::memory_order_relaxed);
                    return FilterResult(RuleAction::DROP, rule->id, timer.ElapsedMillis(), RuleLayer::L4);
                }
            }
        }
        
        // L7 (Application layer)
        if (rules_ref_.count(RuleLayer::L7)) {
            for (const auto& rule : rules_ref_.at(RuleLayer::L7)) {
                if (EvaluateL7Rule(*rule, packet)) {
                    l7_drops_.fetch_add(1, std::memory_order_relaxed);
                    return FilterResult(RuleAction::DROP, rule->id, timer.ElapsedMillis(), RuleLayer::L7);
                }
            }
        }
        
        return FilterResult(RuleAction::ACCEPT, "default", timer.ElapsedMillis(), RuleLayer::L3);
    }

private:
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_ref_;
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
        return;
    }
    
    std::cout << "Initializing WorkerPool with " << num_workers_ << " workers..." << std::endl;
    
    workers_.resize(num_workers_);
    
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_[i].thread = std::thread(&WorkerPool::WorkerLoop, this, i);
        SetWorkerAffinity(i);
    }
    
    running_.store(true);
    std::cout << "✅ WorkerPool initialized successfully" << std::endl;
}

void WorkerPool::Stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "Shutting down WorkerPool..." << std::endl;
    running_.store(false);
    
    for (auto& worker : workers_) {
        worker.queue_cv->notify_all();
    }
    
    for (auto& worker : workers_) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }
    
    std::cout << "✅ WorkerPool shut down" << std::endl;
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
        
        HighResTimer timer;
        
        try {
            FilterResult result = rule_engine.FilterPacket(work_item.first);
            
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
            
            if (work_item.second) {
                work_item.second(result);
            }
            
            if (worker.packets_processed.load() % 1000 == 0) {
                worker.reassembler->Cleanup();
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Worker " << worker_id << " exception: " << e.what() << std::endl;
        }
    }
    
    std::cout << "Worker " << worker_id << " stopped" << std::endl;
}

// ============================================================
// PACKET SUBMIT
// ============================================================
void WorkerPool::SubmitPacket(const PacketData& packet, std::function<void(FilterResult)> callback) {
    if (!running_.load()) {
        return;
    }
    
    size_t worker_id = HashDispatch(packet);
    auto& worker = workers_[worker_id];
    
    {
        std::lock_guard<std::mutex> lock(*worker.queue_mutex);
        if (worker.queue.size() >= MAX_QUEUE_SIZE) {
            queue_overflows_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        
        worker.queue.emplace(packet, callback);
    }
    
    worker.queue_cv->notify_one();
}

// ============================================================
// HASH DISPATCH
// ============================================================
size_t WorkerPool::HashDispatch(const PacketData& packet) const {
    uint32_t src_ip = RuleEngine::IPStringToUint32(packet.src_ip);
    uint32_t dst_ip = RuleEngine::IPStringToUint32(packet.dst_ip);
    
    std::hash<uint64_t> hasher;
    uint64_t key1 = (static_cast<uint64_t>(src_ip) << 32) | packet.src_port;
    uint64_t key2 = (static_cast<uint64_t>(dst_ip) << 32) | packet.dst_port;
    
    return hasher(key1 ^ key2) % num_workers_;
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
    
    stats.load_variance = CalculateLoadVariance();
    
    return stats;
}

void WorkerPool::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 WorkerPool Statistics:" << std::endl;
    std::cout << "   Total workers: " << stats.num_workers << std::endl;
    std::cout << "   Total processed: " << stats.total_processed << std::endl;
    std::cout << "   Total drops: " << stats.total_dropped << std::endl;
    std::cout << "   Queue overflows: " << stats.queue_overflows << std::endl;
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