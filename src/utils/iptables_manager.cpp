#include "iptables_manager.h"
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <cstdio>
#include <array>

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================

IPTablesManager::IPTablesManager() {
    // Constructor
}

IPTablesManager::~IPTablesManager() {
    Cleanup();
}

// ============================================================
// INITIALIZATION
// ============================================================

bool IPTablesManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return true;
    }
    
    std::cout << "🔧 Initializing IPTables Dynamic Blocking..." << std::endl;
    
    // Create custom chain if it doesn't exist
    if (!ChainExists()) {
        if (!CreateChain()) {
            std::cerr << "❌ Failed to create iptables chain: " << CHAIN_NAME << std::endl;
            return false;
        }
        std::cout << "✅ Created iptables chain: " << CHAIN_NAME << std::endl;
    } else {
        std::cout << "✅ Using existing iptables chain: " << CHAIN_NAME << std::endl;
    }
    
    // Make sure our chain is referenced from INPUT (if not already)
    // This makes packets go through our chain first
    std::string check_cmd = "iptables -C INPUT -j " + std::string(CHAIN_NAME) + " 2>/dev/null";
    int ret = system(check_cmd.c_str());
    
    if (ret != 0) {
        // Rule doesn't exist, add it
        std::string add_cmd = "iptables -I INPUT 1 -j " + std::string(CHAIN_NAME);
        if (!ExecuteIPTables(add_cmd)) {
            std::cerr << "❌ Failed to link chain to INPUT" << std::endl;
            return false;
        }
        std::cout << "✅ Linked " << CHAIN_NAME << " to INPUT chain" << std::endl;
    }
    
    initialized_ = true;
    std::cout << "✅ IPTables Dynamic Blocking ready" << std::endl;
    return true;
}

// ============================================================
// CLEANUP
// ============================================================

void IPTablesManager::Cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }
    
    std::cout << "\n🧹 Cleaning up IPTables rules..." << std::endl;
    
    // Remove jump rule from INPUT
    std::string remove_jump = "iptables -D INPUT -j " + std::string(CHAIN_NAME) + " 2>/dev/null";
    system(remove_jump.c_str());
    
    // Flush all rules in our chain
    std::string flush_cmd = "iptables -F " + std::string(CHAIN_NAME) + " 2>/dev/null";
    system(flush_cmd.c_str());
    
    // Delete the chain
    DeleteChain();
    
    blocked_ips_.clear();
    initialized_ = false;
    
    std::cout << "✅ IPTables cleanup complete" << std::endl;
}

// ============================================================
// BLOCK / UNBLOCK IP
// ============================================================

bool IPTablesManager::BlockIP(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        std::cerr << "❌ IPTablesManager not initialized" << std::endl;
        return false;
    }
    
    // Check if already blocked
    if (blocked_ips_.count(ip)) {
        return true; // Already blocked
    }
    
    // Add iptables rule to DROP packets from this IP
    // Using our custom chain for organization
    std::ostringstream cmd;
    cmd << "iptables -I " << CHAIN_NAME << " -s " << ip << " -j DROP";
    
    if (!ExecuteIPTables(cmd.str())) {
        std::cerr << "❌ Failed to block IP: " << ip << std::endl;
        return false;
    }
    
    blocked_ips_.insert(ip);
    
    std::cout << "🚫 BLOCKED IP: " << ip;
    if (!reason.empty()) {
        std::cout << " (Reason: " << reason << ")";
    }
    std::cout << " [Total: " << blocked_ips_.size() << " IPs blocked]" << std::endl;
    
    return true;
}

bool IPTablesManager::UnblockIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    if (!blocked_ips_.count(ip)) {
        return true; // Not blocked
    }
    
    // Remove iptables rule
    std::ostringstream cmd;
    cmd << "iptables -D " << CHAIN_NAME << " -s " << ip << " -j DROP 2>/dev/null";
    
    system(cmd.str().c_str());
    blocked_ips_.erase(ip);
    
    std::cout << "✅ UNBLOCKED IP: " << ip << std::endl;
    
    return true;
}

// ============================================================
// QUERY
// ============================================================

bool IPTablesManager::IsBlocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_ips_.count(ip) > 0;
}

size_t IPTablesManager::GetBlockedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_ips_.size();
}

void IPTablesManager::ClearAllRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }
    
    // Flush all rules in our chain
    std::string flush_cmd = "iptables -F " + std::string(CHAIN_NAME);
    ExecuteIPTables(flush_cmd);
    
    blocked_ips_.clear();
    
    std::cout << "🧹 Cleared all blocking rules" << std::endl;
}

// ============================================================
// HELPERS
// ============================================================

bool IPTablesManager::ExecuteIPTables(const std::string& args) {
    int ret = system(args.c_str());
    return (ret == 0);
}

bool IPTablesManager::ChainExists() const {
    std::string cmd = "iptables -L " + std::string(CHAIN_NAME) + " -n 2>/dev/null";
    int ret = system(cmd.c_str());
    return (ret == 0);
}

bool IPTablesManager::CreateChain() {
    std::string cmd = "iptables -N " + std::string(CHAIN_NAME);
    return ExecuteIPTables(cmd);
}

bool IPTablesManager::DeleteChain() {
    std::string cmd = "iptables -X " + std::string(CHAIN_NAME) + " 2>/dev/null";
    return ExecuteIPTables(cmd);
}
