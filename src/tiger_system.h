#ifndef TIGER_SYSTEM_H
#define TIGER_SYSTEM_H

#include <string>
#include <memory>
#include <atomic>
#include <csignal>
#include <unistd.h>

// Forward declarations
class RuleEngine;
class PacketHandler;

// ============================================================
// TIGER SYSTEM - MAIN ORCHESTRATOR (SIMPLIFIED)
// ============================================================
class TigerSystem {
public:
    explicit TigerSystem(const std::string& rules_file, 
                        int queue_num = 0,
                        const std::string& mode = "sequential",
                        size_t num_workers = 0,
                        bool debug_mode = false);
    
    ~TigerSystem();
    
    // Lifecycle management
    bool Initialize();
    void Run();
    void Shutdown();

private:
    // Configuration
    std::string rules_file_;
    int queue_num_;
    std::string mode_;  // "sequential" or "parallel"
    size_t num_workers_;
    bool debug_mode_;
    
    // Components
    std::unique_ptr<RuleEngine> engine_;  // Sequential or Parallel engine
    std::unique_ptr<PacketHandler> packet_handler_;
    
    // System state
    std::atomic<bool> running_{false};
    pid_t process_pid_;
    
    // Setup helpers
    bool SetupIPTables();
    bool CleanupIPTables();
    bool EnableIPForwarding();
    
    // Signal handling
    static void SignalHandler(int signal);
    static TigerSystem* instance_;
    
    // Validation
    bool ValidateEnvironment();
    void PrintSystemInfo() const;
};

#endif // TIGER_SYSTEM_H