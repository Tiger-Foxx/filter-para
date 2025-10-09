#ifndef IPTABLES_MANAGER_H
#define IPTABLES_MANAGER_H

#include <string>
#include <unordered_set>
#include <mutex>
#include <memory>

// ============================================================
// IPTABLES DYNAMIC BLOCKING MANAGER
// ============================================================
// Gère le blocage dynamique d'IPs via iptables
// Permet de bloquer au niveau kernel AVANT NFQUEUE
// Ultra-rapide : règles iptables = kernel filtering
// ============================================================

class IPTablesManager {
public:
    IPTablesManager();
    ~IPTablesManager();
    
    // Block an IP address (adds iptables rule)
    bool BlockIP(const std::string& ip, const std::string& reason = "");
    
    // Unblock an IP address (removes iptables rule)
    bool UnblockIP(const std::string& ip);
    
    // Check if IP is blocked
    bool IsBlocked(const std::string& ip) const;
    
    // Get statistics
    size_t GetBlockedCount() const;
    
    // Clear all dynamic rules
    void ClearAllRules();
    
    // Initialize iptables chain
    bool Initialize();
    
    // Cleanup (remove chain and rules)
    void Cleanup();

private:
    mutable std::mutex mutex_;
    std::unordered_set<std::string> blocked_ips_;
    
    // Custom chain name for our rules
    static constexpr const char* CHAIN_NAME = "TIGER_FOX_BLOCK";
    
    // Execute iptables command
    bool ExecuteIPTables(const std::string& args);
    
    // Check if chain exists
    bool ChainExists() const;
    
    // Create our custom chain
    bool CreateChain();
    
    // Delete our custom chain
    bool DeleteChain();
    
    bool initialized_{false};
};

#endif // IPTABLES_MANAGER_H
