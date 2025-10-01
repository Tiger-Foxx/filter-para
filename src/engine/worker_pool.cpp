#include "worker_pool.h"
#include "rule_engine.h"
#include "../handlers/tcp_reassembler.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <netinet/in.h>  // Pour IPPROTO_TCP

#ifdef __linux__
#include <sched.h>
#include <pthread.h>
#endif

// ============================================================
// HYBRID RULE ENGINE (moteur léger pour chaque worker)
// ============================================================
class HybridRuleEngine : public RuleEngine {
public:
    explicit HybridRuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
        : RuleEngine(rules) {}

    FilterResult FilterPacket(const PacketData& packet) override {
        HighResTimer timer;
        
        total_packets_.fetch_add(1, std::memory_order_relaxed);
        
        // Évaluation séquentielle L3 → L4 → L7
        for (const auto& rule : rules_by_layer_[RuleLayer::L3]) {
            if (EvaluateRule(*rule, packet)) {
                l3_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMillis(), RuleLayer::L3);
            }
        }
        
        for (const auto& rule : rules_by_layer_[RuleLayer::L4]) {
            if (EvaluateRule(*rule, packet)) {
                l4_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMillis(), RuleLayer::L4);
            }
        }
        
        for (const auto& rule : rules_by_layer_[RuleLayer::L7]) {
            if (EvaluateRule(*rule, packet)) {
                l7_drops_.fetch_add(1, std::memory_order_relaxed);
                dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                return FilterResult(rule->action, rule->id, timer.ElapsedMillis(), RuleLayer::L7);
            }
        }
        
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(RuleAction::ACCEPT, "default", timer.ElapsedMillis(), RuleLayer::L7);
    }
};

// ============================================================
// WORKER POOL IMPLEMENTATION
// ============================================================
WorkerPool::WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules, size_t num_workers)
    : rules_by_layer_(rules), 
      num_workers_(num_workers == 0 ? std::thread::hardware_concurrency() : num_workers) {
    workers_.reserve(num_workers_);
}

WorkerPool::~WorkerPool() {
    Stop();
}

void WorkerPool::Start() {
    if (running_.load()) {
        return;
    }
    
    running_.store(true);
    
    std::cout << "🚀 Starting WorkerPool with " << num_workers_ << " workers" << std::endl;
    
    // Créer les workers avec WorkerContext
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back();
        
        // Lancer le thread du worker
        workers_[i].thread = std::thread(&WorkerPool::WorkerLoop, this, i);
        
        // Définir l'affinité CPU
        SetWorkerAffinity(i);
    }
    
    std::cout << "✅ All workers started" << std::endl;
}

void WorkerPool::Stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    // Réveiller tous les workers
    for (auto& worker : workers_) {
        std::lock_guard<std::mutex> lock(*worker.queue_mutex);
        worker.queue_cv->notify_all();
    }
    
    // Attendre que tous les threads se terminent
    for (auto& worker : workers_) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }
    
    workers_.clear();
    
    std::cout << "🛑 WorkerPool stopped" << std::endl;
}

void WorkerPool::SubmitPacket(const PacketData& packet, std::function<void(FilterResult)> callback) {
    if (!running_.load()) {
        return;
    }
    
    total_dispatched_.fetch_add(1, std::memory_order_relaxed);
    
    size_t worker_id = HashDispatch(packet);
    
    if (worker_id < workers_.size()) {
        auto& worker = workers_[worker_id];
        
        std::unique_lock<std::mutex> lock(*worker.queue_mutex);
        
        // Vérifier la taille de la queue
        if (worker.queue.size() >= MAX_QUEUE_SIZE) {
            queue_overflows_.fetch_add(1, std::memory_order_relaxed);
            lock.unlock();
            // Appeler le callback avec DROP si la queue est pleine
            if (callback) {
                callback(FilterResult(RuleAction::DROP, "queue_overflow", 0.0, RuleLayer::L3));
            }
            return;
        }
        
        worker.queue.push({packet, callback});
        lock.unlock();
        worker.queue_cv->notify_one();
    }
}

void WorkerPool::WorkerLoop(size_t worker_id) {
    auto& worker = workers_[worker_id];
    
    // Créer le moteur de règles local à ce worker
    HybridRuleEngine engine(rules_by_layer_);
    
    std::cout << "🧵 Worker " << worker_id << " started (thread ID: " << std::this_thread::get_id() << ")" << std::endl;
    
    while (running_.load()) {
        std::pair<PacketData, std::function<void(FilterResult)>> work_item;
        
        {
            std::unique_lock<std::mutex> lock(*worker.queue_mutex);
            
            // Attendre qu'il y ait du travail ou que le système s'arrête
            worker.queue_cv->wait(lock, [&]() {
                return !worker.queue.empty() || !running_.load();
            });
            
            if (!running_.load() && worker.queue.empty()) {
                break;
            }
            
            if (worker.queue.empty()) {
                continue;
            }
            
            work_item = std::move(worker.queue.front());
            worker.queue.pop();
        }
        
        HighResTimer timer;
        
        PacketData packet = work_item.first;
        auto callback = work_item.second;
        
        // TCP reassembly si nécessaire
        if (packet.protocol == IPPROTO_TCP && !packet.http_method.empty()) {
            // Le reassembler a déjà été appelé dans packet_handler
            // On peut utiliser directement les données HTTP
        }
        
        // Filtrage avec le moteur local
        FilterResult result = engine.FilterPacket(packet);
        
        // Mettre à jour les statistiques du worker
        worker.packets_processed.fetch_add(1, std::memory_order_relaxed);
        
        // Pour atomic<double>, fetch_add n'est pas disponible en C++17
        // On utilise compare_exchange_weak en boucle
        double old_time = worker.total_processing_time_ms.load(std::memory_order_relaxed);
        while (!worker.total_processing_time_ms.compare_exchange_weak(
            old_time, old_time + result.processing_time_ms, 
            std::memory_order_relaxed, std::memory_order_relaxed)) {
            // La boucle continue jusqu'à ce que l'échange réussisse
        }
        
        if (result.action == RuleAction::DROP) {
            worker.packets_dropped.fetch_add(1, std::memory_order_relaxed);
        } else {
            worker.packets_accepted.fetch_add(1, std::memory_order_relaxed);
        }
        
        // Appeler le callback
        if (callback) {
            callback(result);
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
    
    int rc = pthread_setaffinity_np(workers_[worker_id].thread.native_handle(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        std::cerr << "⚠️  Warning: Failed to set CPU affinity for worker " << worker_id << std::endl;
    }
    #endif
}

double WorkerPool::CalculateLoadVariance() const {
    if (workers_.empty()) return 0.0;
    
    // Calculer la moyenne de paquets par worker
    double total = 0.0;
    for (const auto& worker : workers_) {
        total += worker.packets_processed.load();
    }
    double mean = total / workers_.size();
    
    // Calculer la variance
    double variance = 0.0;
    for (const auto& worker : workers_) {
        double diff = worker.packets_processed.load() - mean;
        variance += diff * diff;
    }
    return variance / workers_.size();
}

WorkerPool::Stats WorkerPool::GetStats() const {
    Stats stats;
    stats.num_workers = num_workers_;
    stats.total_dispatched = total_dispatched_.load();
    stats.total_processed = 0;
    stats.total_dropped = 0;
    stats.total_accepted = 0;
    stats.queue_overflows = queue_overflows_.load();
    stats.avg_processing_time_ms = 0.0;
    
    stats.packets_per_worker.resize(workers_.size());
    stats.drops_per_worker.resize(workers_.size());
    stats.accepts_per_worker.resize(workers_.size());
    stats.avg_time_per_worker.resize(workers_.size());
    
    for (size_t i = 0; i < workers_.size(); ++i) {
        const auto& worker = workers_[i];
        uint64_t processed = worker.packets_processed.load();
        uint64_t dropped = worker.packets_dropped.load();
        uint64_t accepted = worker.packets_accepted.load();
        double total_time = worker.total_processing_time_ms.load();
        
        stats.packets_per_worker[i] = processed;
        stats.drops_per_worker[i] = dropped;
        stats.accepts_per_worker[i] = accepted;
        stats.avg_time_per_worker[i] = processed > 0 ? total_time / processed : 0.0;
        
        stats.total_processed += processed;
        stats.total_dropped += dropped;
        stats.total_accepted += accepted;
        stats.avg_processing_time_ms += total_time;
    }
    
    if (stats.total_processed > 0) {
        stats.avg_processing_time_ms /= stats.total_processed;
    }
    
    stats.load_variance = CalculateLoadVariance();
    
    return stats;
}

void WorkerPool::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 WorkerPool Statistics:" << std::endl;
    std::cout << "   Number of workers: " << stats.num_workers << std::endl;
    std::cout << "   Total dispatched: " << stats.total_dispatched << std::endl;
    std::cout << "   Total processed: " << stats.total_processed << std::endl;
    std::cout << "   Total dropped: " << stats.total_dropped << std::endl;
    std::cout << "   Total accepted: " << stats.total_accepted << std::endl;
    std::cout << "   Queue overflows: " << stats.queue_overflows << std::endl;
    std::cout << "   Avg processing time: " << std::fixed << std::setprecision(3) 
              << stats.avg_processing_time_ms << " ms" << std::endl;
    std::cout << "   Load variance: " << std::fixed << std::setprecision(2) 
              << stats.load_variance << std::endl;
    
    std::cout << "\n   Per-worker breakdown:" << std::endl;
    for (size_t i = 0; i < stats.packets_per_worker.size(); ++i) {
        std::cout << "      Worker " << i << ": "
                  << stats.packets_per_worker[i] << " packets, "
                  << stats.drops_per_worker[i] << " drops, "
                  << stats.accepts_per_worker[i] << " accepts, "
                  << std::fixed << std::setprecision(3) 
                  << stats.avg_time_per_worker[i] << " ms avg" << std::endl;
    }
}