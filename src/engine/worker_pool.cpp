#include "worker_pool.h"
#include "../utils.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// For CPU affinity
#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
WorkerPool::WorkerPool(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       size_t num_workers)
    : num_workers_(num_workers > 0 ? num_workers : GetOptimalWorkerCount()) {
    
    // Deep copy rules (shared read-only across workers)
    for (const auto& [layer, layer_rules] : rules) {
        rules_by_layer_[layer] = std::vector<std::unique_ptr<Rule>>();
        
        for (const auto& rule : layer_rules) {
            auto rule_copy = std::make_unique<Rule>();
            rule_copy->id = rule->id;
            rule_copy->layer = rule->layer;
            rule_copy->type = rule->type;
            rule_copy->action = rule->action;
            rule_copy->values = rule->values;
            rule_copy->field = rule->field;
            
            // Copy pre-compiled patterns and IP ranges
            rule_copy->compiled_patterns = rule->compiled_patterns;
            rule_copy->ip_ranges = rule->ip_ranges;
            
            rules_by_layer_[layer].push_back(std::move(rule_copy));
        }
    }
    
    std::cout << "🔧 WorkerPool initialized with " << num_workers_ << " workers" << std::endl;
}

WorkerPool::~WorkerPool() {
    Shutdown();
}

// ============================================================
// INITIALIZATION
// ============================================================
bool WorkerPool::Initialize() {
    std::cout << "🚀 Initializing worker pool..." << std::endl;
    
    // Resize workers vector
    workers_.resize(num_workers_);
    
    // Start worker threads
    running_.store(true, std::memory_order_release);
    
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_[i].thread = std::thread(&WorkerPool::WorkerLoop, this, i);
        
        // Set CPU affinity
        SetWorkerAffinity(i);
        
        std::cout << "  ✓ Worker " << i << " started on CPU " << (i % SystemUtils::GetCPUCoreCount()) << std::endl;
    }
    
    std::cout << "✅ All workers initialized successfully" << std::endl;
    return true;
}

// ============================================================
// SHUTDOWN
// ============================================================
void WorkerPool::Shutdown() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    
    std::cout << "🛑 Shutting down worker pool..." << std::endl;
    
    running_.store(false, std::memory_order_release);
    
    // Wake up all workers
    for (auto& worker : workers_) {
        worker.queue_cv->notify_all();
    }
    
    // Join all threads
    for (size_t i = 0; i < workers_.size(); ++i) {
        if (workers_[i].thread.joinable()) {
            workers_[i].thread.join();
            std::cout << "  ✓ Worker " << i << " stopped" << std::endl;
        }
    }
    
    // Cleanup TCP reassemblers
    for (auto& worker : workers_) {
        if (worker.reassembler) {
            worker.reassembler->Cleanup();
        }
    }
    
    std::cout << "✅ Worker pool shutdown complete" << std::endl;
}

// ============================================================
// MAIN DISPATCH FUNCTION
// ============================================================
bool WorkerPool::DispatchPacket(const WorkItem& work_item) {
    total_dispatched_.fetch_add(1, std::memory_order_relaxed);
    
    // Compute target worker via hash dispatch
    size_t worker_id = ComputeWorkerHash(work_item.parsed_packet);
    
    auto& worker = workers_[worker_id];
    
    // Check queue capacity
    {
        std::unique_lock<std::mutex> lock(*worker.queue_mutex);
        
        if (worker.queue.size() >= MAX_QUEUE_SIZE_PER_WORKER) {
            queue_full_drops_.fetch_add(1, std::memory_order_relaxed);
            return false;  // Queue full, drop packet
        }
        
        // Create work item copy (deep copy of data)
        auto work_copy = std::make_unique<WorkItem>();
        work_copy->packet_data = nullptr;  // Will be handled in worker
        work_copy->packet_len = work_item.packet_len;
        work_copy->parsed_packet = work_item.parsed_packet;
        work_copy->nfqueue_id = work_item.nfqueue_id;
        work_copy->timestamp_ns = work_item.timestamp_ns;
        work_copy->verdict_callback = work_item.verdict_callback;
        
        worker.queue.push(std::move(work_copy));
    }
    
    // Notify worker
    worker.queue_cv->notify_one();
    
    return true;
}

// ============================================================
// WORKER LOOP
// ============================================================
void WorkerPool::WorkerLoop(size_t worker_id) {
    auto& worker = workers_[worker_id];
    RuleEngine rule_engine(rules_by_layer_);
    
    // Initialize rule engine
    if (!rule_engine.Initialize()) {
        std::cerr << "❌ Worker " << worker_id << " failed to initialize rule engine" << std::endl;
        return;
    }
    
    std::cout << "Worker " << worker_id << " ready" << std::endl;
    
    uint64_t packets_since_cleanup = 0;
    
    while (running_.load(std::memory_order_acquire)) {
        std::unique_ptr<WorkItem> work_item;
        
        // Wait for work
        {
            std::unique_lock<std::mutex> lock(*worker.queue_mutex);
            
            worker.queue_cv->wait(lock, [&] {
                return !worker.queue.empty() || !running_.load(std::memory_order_acquire);
            });
            
            if (!running_.load(std::memory_order_acquire) && worker.queue.empty()) {
                break;  // Shutdown
            }
            
            if (!worker.queue.empty()) {
                work_item = std::move(worker.queue.front());
                worker.queue.pop();
            }
        }
        
        if (!work_item) {
            continue;
        }
        
        // Process packet
        HighResTimer timer;
        
        try {
            // TCP reassembly if needed (HTTP traffic)
            if (work_item->parsed_packet.protocol == IPPROTO_TCP) {
                uint16_t dst_port = work_item->parsed_packet.dst_port;
                uint16_t src_port = work_item->parsed_packet.src_port;
                
                // Check if HTTP port (80, 443, 8080, 8443, 8000, 3000)
                static const std::vector<uint16_t> http_ports = {80, 443, 8080, 8443, 8000, 3000};
                bool is_http_traffic = (std::find(http_ports.begin(), http_ports.end(), dst_port) != http_ports.end() ||
                                       std::find(http_ports.begin(), http_ports.end(), src_port) != http_ports.end());
                
                if (is_http_traffic) {
                    // Note: packet_data is not available here (stack-allocated in NFQUEUE callback)
                    // In real implementation, we'd need to pass raw packet buffer
                    // For now, skip reassembly (would require architecture change)
                    
                    // TODO: Pass raw packet buffer through WorkItem for reassembly
                }
            }
            
            // Apply filtering rules (L3 → L4 → L7 sequential)
            FilterResult result = rule_engine.FilterPacket(work_item->parsed_packet);
            
            // Update worker stats
            worker.packets_processed.fetch_add(1, std::memory_order_relaxed);
            
            double processing_time_ms = timer.ElapsedMicros() / 1000.0;
            
            // Atomic update of average time (using compare-exchange loop)
            double current_total = worker.total_processing_time_ms.load(std::memory_order_relaxed);
            double new_total = current_total + processing_time_ms;
            while (!worker.total_processing_time_ms.compare_exchange_weak(
                current_total, new_total, std::memory_order_relaxed)) {
                new_total = current_total + processing_time_ms;
            }
            
            // Execute verdict
            uint32_t verdict = (result.action == RuleAction::DROP) ? 2 : 1;  // NF_DROP=2, NF_ACCEPT=1
            
            if (result.action == RuleAction::DROP) {
                worker.packets_dropped.fetch_add(1, std::memory_order_relaxed);
            } else {
                worker.packets_accepted.fetch_add(1, std::memory_order_relaxed);
            }
            
            // Call verdict callback
            if (work_item->verdict_callback) {
                work_item->verdict_callback(verdict);
            }
            
        } catch (const std::exception& e) {
            std::cerr << "❌ Worker " << worker_id << " exception: " << e.what() << std::endl;
            
            // On error, accept packet
            if (work_item->verdict_callback) {
                work_item->verdict_callback(1);  // NF_ACCEPT
            }
        }
        
        // Periodic cleanup of TCP reassembler
        packets_since_cleanup++;
        if (packets_since_cleanup >= CLEANUP_INTERVAL_PACKETS) {
            worker.reassembler->CleanupExpiredStreams();
            packets_since_cleanup = 0;
        }
    }
    
    rule_engine.Shutdown();
    std::cout << "Worker " << worker_id << " terminated" << std::endl;
}

// ============================================================
// HASH DISPATCH
// ============================================================
size_t WorkerPool::ComputeWorkerHash(const PacketData& packet) const {
    // Hash-based on 4-tuple (src_ip, src_port, dst_ip, dst_port)
    // Ensures same TCP flow always goes to same worker
    
    std::hash<std::string> hasher;
    
    std::string flow_key = packet.src_ip + ":" + std::to_string(packet.src_port) + 
                          "->" + packet.dst_ip + ":" + std::to_string(packet.dst_port);
    
    uint64_t hash = hasher(flow_key);
    
    return hash % num_workers_;
}

// ============================================================
// WORKER AFFINITY
// ============================================================
void WorkerPool::SetWorkerAffinity(size_t worker_id) {
    #ifdef __linux__
    int cpu_core = worker_id % SystemUtils::GetCPUCoreCount();
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core, &cpuset);
    
    int rc = pthread_setaffinity_np(workers_[worker_id].thread.native_handle(),
                                   sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        std::cerr << "⚠️  Warning: Failed to set affinity for worker " << worker_id 
                  << " to CPU " << cpu_core << std::endl;
    }
    #else
    (void)worker_id;  // Unused
    #endif
}

// ============================================================
// OPTIMAL WORKER COUNT
// ============================================================
size_t WorkerPool::GetOptimalWorkerCount() const {
    int cpu_cores = SystemUtils::GetCPUCoreCount();
    
    // Use all available cores
    return std::max(1, cpu_cores);
}

// ============================================================
// STATISTICS
// ============================================================
WorkerPool::Stats WorkerPool::GetStats() const {
    Stats stats;
    stats.num_workers = num_workers_;
    stats.total_dispatched = total_dispatched_.load(std::memory_order_relaxed);
    stats.queue_full_drops = queue_full_drops_.load(std::memory_order_relaxed);
    
    stats.worker_packet_counts.resize(num_workers_);
    stats.worker_avg_times_ms.resize(num_workers_);
    
    uint64_t total_processed = 0;
    double total_time = 0.0;
    
    for (size_t i = 0; i < num_workers_; ++i) {
        const auto& worker = workers_[i];
        
        uint64_t processed = worker.packets_processed.load(std::memory_order_relaxed);
        double worker_total_time = worker.total_processing_time_ms.load(std::memory_order_relaxed);
        
        stats.worker_packet_counts[i] = processed;
        stats.worker_avg_times_ms[i] = (processed > 0) ? (worker_total_time / processed) : 0.0;
        
        total_processed += processed;
        total_time += worker_total_time;
    }
    
    stats.total_processed = total_processed;
    stats.overall_avg_time_ms = (total_processed > 0) ? (total_time / total_processed) : 0.0;
    
    // Calculate load balance variance
    if (num_workers_ > 0 && total_processed > 0) {
        double avg_load = (double)total_processed / num_workers_;
        double variance = 0.0;
        
        for (size_t i = 0; i < num_workers_; ++i) {
            double diff = stats.worker_packet_counts[i] - avg_load;
            variance += diff * diff;
        }
        
        stats.load_balance_variance = variance / num_workers_;
    } else {
        stats.load_balance_variance = 0.0;
    }
    
    return stats;
}

void WorkerPool::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n📊 WorkerPool Statistics:" << std::endl;
    std::cout << "   Workers: " << stats.num_workers << std::endl;
    std::cout << "   Total dispatched: " << stats.total_dispatched << std::endl;
    std::cout << "   Total processed: " << stats.total_processed << std::endl;
    std::cout << "   Queue full drops: " << stats.queue_full_drops << std::endl;
    std::cout << "   Overall avg time: " << std::fixed << std::setprecision(3) 
              << stats.overall_avg_time_ms << "ms" << std::endl;
    std::cout << "   Load balance variance: " << std::fixed << std::setprecision(2) 
              << stats.load_balance_variance << std::endl;
    
    std::cout << "\n   Per-worker breakdown:" << std::endl;
    for (size_t i = 0; i < stats.num_workers; ++i) {
        const auto& worker = workers_[i];
        
        uint64_t processed = stats.worker_packet_counts[i];
        uint64_t dropped = worker.packets_dropped.load(std::memory_order_relaxed);
        uint64_t accepted = worker.packets_accepted.load(std::memory_order_relaxed);
        double avg_time = stats.worker_avg_times_ms[i];
        
        double drop_rate = (processed > 0) ? ((double)dropped / processed * 100.0) : 0.0;
        
        std::cout << "     Worker " << i << ": " 
                  << processed << " packets, "
                  << "dropped=" << dropped << " (" << std::fixed << std::setprecision(1) 
                  << drop_rate << "%), "
                  << "avg=" << std::fixed << std::setprecision(3) << avg_time << "ms"
                  << std::endl;
    }
}