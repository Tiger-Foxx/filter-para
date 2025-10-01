#include "worker_pool.h"
#include "rule_engine.h"
#include "../handlers/tcp_reassembler.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <sched.h>

// ============================================================
// HYBRID RULE ENGINE (moteur léger pour chaque worker)
// ============================================================
class HybridRuleEngine : public RuleEngine {
public:
    explicit HybridRuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
        // ✅ CORRECTION : Appeler le constructeur parent RuleEngine
        : RuleEngine(rules), rules_ref_(rules) {}

    FilterResult FilterPacket(const PacketData& packet) override {
        HighResTimer timer;
        
        total_packets_.fetch_add(1, std::memory_order_relaxed);
        
        // Évaluation séquentielle L3 → L4 → L7
        for (const auto& rule : rules_by_layer_[RuleLayer::L3]) {
            if (EvaluateRule(*rule, packet)) {
                l3_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMs(), RuleLayer::L3);
            }
        }
        
        for (const auto& rule : rules_by_layer_[RuleLayer::L4]) {
            if (EvaluateRule(*rule, packet)) {
                l4_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMs(), RuleLayer::L4);
            }
        }
        
        for (const auto& rule : rules_by_layer_[RuleLayer::L7]) {
            if (EvaluateRule(*rule, packet)) {
                l7_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMs(), RuleLayer::L7);
            }
        }
        
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "default", timer.ElapsedMs(), RuleLayer::L7);
    }

private:
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_ref_;
};

// ============================================================
// WORKER POOL IMPLEMENTATION
// ============================================================
WorkerPool::WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules, size_t num_workers)
    : rules_ref_(rules), num_workers_(num_workers == 0 ? std::thread::hardware_concurrency() : num_workers) {}

WorkerPool::~WorkerPool() {
    Stop();
}

void WorkerPool::Start() {
    if (running_.load()) {
        return;
    }
    
    running_.store(true);
    
    std::cout << "🚀 Starting WorkerPool with " << num_workers_ << " workers" << std::endl;
    
    for (size_t i = 0; i < num_workers_; ++i) {
        auto queue = std::make_unique<ThreadSafeQueue>();
        auto engine = std::make_unique<HybridRuleEngine>(rules_ref_);
        auto reassembler = std::make_unique<TCPReassembler>();
        
        worker_queues_.push_back(std::move(queue));
        worker_engines_.push_back(std::move(engine));
        worker_reassemblers_.push_back(std::move(reassembler));
        
        worker_threads_.emplace_back(&WorkerPool::WorkerLoop, this, i);
        
        SetWorkerAffinity(i);
    }
    
    std::cout << "✅ All workers started" << std::endl;
}

void WorkerPool::Stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    for (auto& queue : worker_queues_) {
        queue->Stop();
    }
    
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    worker_threads_.clear();
    worker_queues_.clear();
    worker_engines_.clear();
    worker_reassemblers_.clear();
    
    std::cout << "🛑 WorkerPool stopped" << std::endl;
}

void WorkerPool::DispatchPacket(const PacketData& packet, PacketCallback callback) {
    if (!running_.load()) {
        return;
    }
    
    size_t worker_id = HashDispatch(packet);
    
    if (worker_id < worker_queues_.size()) {
        auto work_item = std::make_unique<WorkItem>(packet, callback);
        worker_queues_[worker_id]->Enqueue(std::move(work_item));
    }
}

void WorkerPool::WorkerLoop(size_t worker_id) {
    auto& queue = worker_queues_[worker_id];
    auto& engine = worker_engines_[worker_id];
    auto& reassembler = worker_reassemblers_[worker_id];
    
    std::cout << "🧵 Worker " << worker_id << " started (thread ID: " << std::this_thread::get_id() << ")" << std::endl;
    
    while (running_.load()) {
        auto work_item = queue->Dequeue();
        if (!work_item) {
            continue;
        }
        
        PacketData packet = work_item->packet;
        
        // TCP reassembly si nécessaire
        if (packet.protocol == IPPROTO_TCP) {
            // TODO: Appeler reassembler
        }
        
        // Filtrage
        FilterResult result = engine->FilterPacket(packet);
        
        // Callback
        if (work_item->callback) {
            work_item->callback(result.action == RuleAction::DROP);
        }
    }
    
    std::cout << "🛑 Worker " << worker_id << " stopped" << std::endl;
}

size_t WorkerPool::HashDispatch(const PacketData& packet) const {
    uint32_t src_ip_int = RuleEngine::IPStringToUint32(packet.src_ip);
    uint32_t dst_ip_int = RuleEngine::IPStringToUint32(packet.dst_ip);
    
    std::hash<uint64_t> hasher;
    uint64_t key = (static_cast<uint64_t>(src_ip_int) << 32) | packet.src_port;
    key ^= (static_cast<uint64_t>(dst_ip_int) << 32) | packet.dst_port;
    
    return hasher(key) % num_workers_;
}

void WorkerPool::SetWorkerAffinity(size_t worker_id) {
    #ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker_id % std::thread::hardware_concurrency(), &cpuset);
    
    int rc = pthread_setaffinity_np(worker_threads_[worker_id].native_handle(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        std::cerr << "⚠️  Warning: Failed to set CPU affinity for worker " << worker_id << std::endl;
    }
    #endif
}

WorkerPool::Stats WorkerPool::GetStats() const {
    Stats stats;
    stats.total_workers = num_workers_;
    stats.running_workers = worker_threads_.size();
    
    for (const auto& engine : worker_engines_) {
        stats.total_accepted += engine->GetTotalRules(); // Placeholder
    }
    
    return stats;
}

void WorkerPool::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 WorkerPool Statistics:" << std::endl;
    std::cout << "   Total workers: " << stats.total_workers << std::endl;
    std::cout << "   Running workers: " << stats.running_workers << std::endl;
    std::cout << "   Total accepted: " << stats.total_accepted << std::endl;
}