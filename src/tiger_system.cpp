#include "tiger_system.h"
#include "utils.h"
#include "engine/fast_sequential_engine.h"
#include "engine/successive_engine.h"
#include "engine/true_parallel_engine.h"
#include "handlers/packet_handler.h"
#include "loaders/rule_loader.h"

#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <fstream>
#include <thread>
#include <chrono>

// Static instance for signal handling
TigerSystem* TigerSystem::instance_ = nullptr;

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================
TigerSystem::TigerSystem(const std::string& rules_file, int queue_num, 
                         const std::string& mode, size_t num_workers, bool debug_mode)
    : rules_file_(rules_file), queue_num_(queue_num), mode_(mode),
      num_workers_(num_workers), debug_mode_(debug_mode),
      process_pid_(getpid()) {
    
    instance_ = this;
    
    std::cout << "\n";
    std::cout << "🐯 ========================================== 🦊\n";
    std::cout << "   Tiger-Fox Ultra-Fast Network Filter\n";
    std::cout << "   Mode: " << (mode_ == "sequential" ? "SEQUENTIAL" : "PARALLEL") << "\n";
    std::cout << "🐯 ========================================== 🦊\n";
    std::cout << "\n";
}

TigerSystem::~TigerSystem() {
    Shutdown();
    instance_ = nullptr;
}

// ============================================================
// INITIALIZATION
// ============================================================
bool TigerSystem::Initialize() {
    std::cout << "🚀 Initializing Tiger-Fox System...\n" << std::endl;
    
    // Validate environment
    if (!ValidateEnvironment()) {
        return false;
    }
    
    // Print system info
    PrintSystemInfo();
    
    // Load rules
    std::cout << "📋 Loading filtering rules..." << std::endl;
    auto rules_by_layer = RuleLoader::LoadRules(rules_file_);
    
    if (rules_by_layer.empty()) {
        std::cerr << "❌ Error: No rules loaded" << std::endl;
        return false;
    }
    
    // Setup IP forwarding
    if (system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1") != 0) {
        std::cerr << "⚠️  Warning: Failed to enable IP forwarding" << std::endl;
    }
    
    // Setup iptables rules - DISABLED (manual control preferred)
    // User should configure iptables manually before running:
    // sudo iptables -I FORWARD -s 10.10.1.10 -d 10.10.2.20 -j NFQUEUE --queue-num 0
    /*
    if (!SetupIPTables()) {
        std::cerr << "❌ Error: Failed to setup iptables" << std::endl;
        return false;
    }
    */
    std::cout << "ℹ️  iptables configuration skipped (manual control)" << std::endl;
    std::cout << "   Please ensure iptables rules are configured before running!" << std::endl;
    
    // ============================================================
    // CREATE ENGINE BASED ON MODE
    // ============================================================
    std::cout << "\n🔧 Initializing engine..." << std::endl;
    
    // Compter le nombre de règles chargées
    size_t original_rule_count = 0;
    for (const auto& [layer, layer_rules] : rules_by_layer) {
        original_rule_count += layer_rules.size();
    }
    
    if (mode_ == "sequential") {
        // ============================================================
        // MODE SEQUENTIAL: 1 thread, toutes les règles (baseline)
        // ============================================================
        std::cout << "   Mode: SEQUENTIAL (1 thread, all " << original_rule_count << " rules)" << std::endl;
        
        engine_ = std::make_unique<FastSequentialEngine>(rules_by_layer);
        
    } else if (mode_ == "successive") {
        // ============================================================
        // MODE SUCCESSIVE: 3 workers UN APRÈS L'AUTRE (idée du prof)
        // ============================================================
        std::cout << "   Mode: SUCCESSIVE (3 workers executing one after another)" << std::endl;
        
        size_t num_successive_workers = 3;
        engine_ = std::make_unique<SuccessiveEngine>(rules_by_layer, num_successive_workers);
        
    } else if (mode_ == "parallel") {
        // ============================================================
        // MODE PARALLEL: True parallelism avec workers permanents
        // ============================================================
        std::cout << "   Mode: PARALLEL (true parallelism with " << num_workers_ << " workers)" << std::endl;
        std::cout << "   Rules partitioned: ~" << (original_rule_count / num_workers_) 
                  << " rules per worker" << std::endl;
        
        engine_ = std::make_unique<TrueParallelEngine>(rules_by_layer, num_workers_);
    } else {
        std::cerr << "❌ Error: Invalid mode: " << mode_ << std::endl;
        return false;
    }
    
    // ============================================================
    // INITIALIZE PACKET HANDLER
    // ============================================================
    std::cout << "🔧 Initializing packet handler..." << std::endl;
    packet_handler_ = std::make_unique<PacketHandler>(
        queue_num_, engine_.get(), debug_mode_
    );
    
    if (!packet_handler_->Initialize()) {
        std::cerr << "❌ Error: Failed to initialize packet handler" << std::endl;
        return false;
    }
    
    std::cout << "\n✅ Tiger-Fox System initialized successfully!" << std::endl;
    std::cout << "   Process PID: " << process_pid_ << std::endl;
    std::cout << "   Queue number: " << queue_num_ << std::endl;
    std::cout << "   Mode: " << mode_ << std::endl;
    std::cout << "\n";
    
    return true;
}

// ============================================================
// RUN SYSTEM
// ============================================================
void TigerSystem::Run() {
    if (!engine_ || !packet_handler_) {
        std::cerr << "❌ Error: System not initialized" << std::endl;
        return;
    }
    
    running_.store(true, std::memory_order_release);
    
    // Setup signal handlers
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);
    
    std::cout << "🚀 Tiger-Fox is now running!" << std::endl;
    std::cout << "   Press Ctrl+C to stop\n" << std::endl;
    
    // Start packet handler (blocking call)
    packet_handler_->Start();
    
    std::cout << "\n🛑 Shutting down Tiger-Fox..." << std::endl;
}

// ============================================================
// SHUTDOWN
// ============================================================
void TigerSystem::Shutdown() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    
    running_.store(false, std::memory_order_release);
    
    std::cout << "\n🧹 Cleaning up resources..." << std::endl;
    
    // Shutdown packet handler
    if (packet_handler_) {
        packet_handler_->Stop();
        packet_handler_->PrintStats();
        packet_handler_.reset();
    }
    
    // Shutdown engine
    if (engine_) {
        engine_.reset();
    }
    
    // Cleanup iptables - DISABLED (manual control preferred)
    // User should remove iptables rules manually:
    // sudo iptables -D FORWARD -s 10.10.1.10 -d 10.10.2.20 -j NFQUEUE --queue-num 0
    /*
    CleanupIPTables();
    */
    std::cout << "ℹ️  iptables cleanup skipped (manual control)" << std::endl;
    
    std::cout << "✅ Tiger-Fox stopped cleanly" << std::endl;
}

// ============================================================
// SIGNAL HANDLER
// ============================================================
void TigerSystem::SignalHandler(int signal) {
    if (instance_) {
        std::cout << "\n\n⚠️  Signal " << signal << " received, shutting down..." << std::endl;
        instance_->running_.store(false, std::memory_order_release);
    }
}

// ============================================================
// IPTABLES MANAGEMENT
// ============================================================
bool TigerSystem::SetupIPTables() {
    std::cout << "🔧 Setting up iptables rules..." << std::endl;
    
    // ✅ Setup asymmetric filtering (CloudLab topology)
    // eno2 (10.10.2.1) = server side
    // enp5s0f0 (10.10.1.1) = client side
    
    // Check if rules already exist
    std::string check_cmd = "iptables -C FORWARD -i enp5s0f0 -o eno2 -j NFQUEUE --queue-num " + 
                            std::to_string(queue_num_) + " 2>/dev/null";
    int exists = system(check_cmd.c_str());
    
    if (exists == 0) {
        std::cout << "   ℹ️  iptables rules already configured" << std::endl;
        return true;
    }
    
    // Rule 1: ACCEPT return traffic (server → client)
    std::string accept_cmd = "iptables -A FORWARD -i eno2 -o enp5s0f0 -j ACCEPT";
    if (system(accept_cmd.c_str()) != 0) {
        std::cerr << "⚠️  Warning: Failed to add ACCEPT rule (may already exist)" << std::endl;
    }
    
    // Rule 2: NFQUEUE for incoming traffic (client → server)
    std::string nfqueue_cmd = "iptables -A FORWARD -i enp5s0f0 -o eno2 -j NFQUEUE --queue-num " + 
                              std::to_string(queue_num_);
    if (system(nfqueue_cmd.c_str()) != 0) {
        std::cerr << "❌ Error: Failed to add NFQUEUE rule" << std::endl;
        return false;
    }
    
    std::cout << "✅ iptables rules configured:" << std::endl;
    std::cout << "   • ACCEPT: eno2 → enp5s0f0 (return traffic)" << std::endl;
    std::cout << "   • NFQUEUE " << queue_num_ << ": enp5s0f0 → eno2 (filtered traffic)" << std::endl;
    
    return true;
}

bool TigerSystem::CleanupIPTables() {
    std::cout << "🧹 Removing iptables rules..." << std::endl;
    
    // Remove NFQUEUE rule
    std::string nfqueue_cmd = "iptables -D FORWARD -i enp5s0f0 -o eno2 -j NFQUEUE --queue-num " + 
                              std::to_string(queue_num_) + " 2>/dev/null";
    system(nfqueue_cmd.c_str());
    
    // Remove ACCEPT rule
    std::string accept_cmd = "iptables -D FORWARD -i eno2 -o enp5s0f0 -j ACCEPT 2>/dev/null";
    system(accept_cmd.c_str());
    
    std::cout << "✅ iptables rules removed" << std::endl;
    return true;
}

bool TigerSystem::EnableIPForwarding() {
    std::cout << "🔧 Enabling IP forwarding..." << std::endl;
    
    // Write to /proc/sys/net/ipv4/ip_forward
    std::ofstream forward_file("/proc/sys/net/ipv4/ip_forward");
    if (!forward_file.is_open()) {
        std::cerr << "⚠️  Warning: Cannot open /proc/sys/net/ipv4/ip_forward" << std::endl;
        return false;
    }
    
    forward_file << "1" << std::endl;
    forward_file.close();
    
    std::cout << "✅ IP forwarding enabled" << std::endl;
    return true;
}

// ============================================================
// VALIDATION
// ============================================================
bool TigerSystem::ValidateEnvironment() {
    std::cout << "🔍 Validating environment...\n" << std::endl;
    
    // Check root privileges
    if (!SystemUtils::IsRootUser()) {
        std::cerr << "❌ Error: Root privileges required" << std::endl;
        std::cerr << "   Run with: sudo ./tiger-fox [options]" << std::endl;
        return false;
    }
    std::cout << "✅ Root privileges: OK" << std::endl;
    
    // Check rules file exists
    std::ifstream rules_check(rules_file_);
    if (!rules_check.good()) {
        std::cerr << "❌ Error: Rules file not found: " << rules_file_ << std::endl;
        return false;
    }
    rules_check.close();
    std::cout << "✅ Rules file: OK" << std::endl;
    
    // Check CPU cores
    int cpu_cores = SystemUtils::GetCPUCoreCount();
    if (cpu_cores < 2) {
        std::cerr << "⚠️  Warning: Only " << cpu_cores << " CPU core(s) detected" << std::endl;
        std::cerr << "   Multi-worker mode may not be beneficial" << std::endl;
    } else {
        std::cout << "✅ CPU cores: " << cpu_cores << std::endl;
    }
    
    // Check libnetfilter_queue availability
    if (system("which iptables > /dev/null 2>&1") != 0) {
        std::cerr << "❌ Error: iptables not found" << std::endl;
        return false;
    }
    std::cout << "✅ iptables: OK" << std::endl;
    
    std::cout << "\n";
    return true;
}

void TigerSystem::PrintSystemInfo() const {
    std::cout << "📊 System Information:" << std::endl;
    std::cout << "   Mode: Hybrid Multi-Worker" << std::endl;
    std::cout << "   Queue number: " << queue_num_ << std::endl;
    std::cout << "   Workers: " << (num_workers_ == 0 ? "auto" : std::to_string(num_workers_)) << std::endl;
    std::cout << "   Rules file: " << rules_file_ << std::endl;
    std::cout << "   Debug mode: " << (debug_mode_ ? "enabled" : "disabled") << std::endl;
    std::cout << "   PID: " << process_pid_ << std::endl;
    std::cout << "\n";
}

// ============================================================
// END OF FILE
// ============================================================