#include "utils.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <sys/types.h>

// Pour SetThreadAffinity (Linux-specific)
#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

// ============================================================
// STRING UTILITIES IMPLEMENTATION
// ============================================================
namespace StringUtils {
    std::vector<std::string> Split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::stringstream ss(str);
        std::string token;
        
        while (std::getline(ss, token, delimiter)) {
            if (!token.empty()) {
                tokens.push_back(token);
            }
        }
        
        return tokens;
    }
    
    std::string Trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\n\r\f\v");
        if (start == std::string::npos) {
            return "";
        }
        
        size_t end = str.find_last_not_of(" \t\n\r\f\v");
        return str.substr(start, end - start + 1);
    }
    
    std::string ToLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), 
                      [](unsigned char c) { return std::tolower(c); });
        return result;
    }
    
    bool StartsWith(const std::string& str, const std::string& prefix) {
        // C++17 compatible (pas de starts_with en C++17)
        return str.size() >= prefix.size() && 
               str.compare(0, prefix.size(), prefix) == 0;
    }
    
    bool EndsWith(const std::string& str, const std::string& suffix) {
        return str.size() >= suffix.size() && 
               str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    
    bool Contains(const std::string& str, const std::string& substr) {
        return str.find(substr) != std::string::npos;
    }
}

// ============================================================
// NETWORK UTILITIES IMPLEMENTATION
// ============================================================
namespace NetworkUtils {
    bool IsPrivateIP(const std::string& ip) {
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
        if (result != 1) return false;
        
        uint32_t addr = ntohl(sa.sin_addr.s_addr);
        
        // 10.0.0.0/8
        if ((addr >= 0x0A000000) && (addr <= 0x0AFFFFFF)) return true;
        // 172.16.0.0/12
        if ((addr >= 0xAC100000) && (addr <= 0xAC1FFFFF)) return true;
        // 192.168.0.0/16
        if ((addr >= 0xC0A80000) && (addr <= 0xC0A8FFFF)) return true;
        
        return false;
    }
    
    bool IsValidIPv4(const std::string& ip) {
        struct sockaddr_in sa;
        return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
    }
    
    bool IsValidIPv6(const std::string& ip) {
        struct sockaddr_in6 sa;
        return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) == 1;
    }
    
    uint32_t IPv4ToUint32(const std::string& ip) {
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
            return ntohl(sa.sin_addr.s_addr);
        }
        return 0;
    }
    
    bool IsInSubnet(const std::string& ip, const std::string& subnet) {
        auto pos = subnet.find('/');
        if (pos == std::string::npos) {
            return ip == subnet; // Exact match
        }
        
        std::string network = subnet.substr(0, pos);
        int prefix_len = std::stoi(subnet.substr(pos + 1));
        
        uint32_t ip_addr = IPv4ToUint32(ip);
        uint32_t net_addr = IPv4ToUint32(network);
        
        if (prefix_len <= 0 || prefix_len > 32) return false;
        
        uint32_t mask = 0xFFFFFFFF << (32 - prefix_len);
        return (ip_addr & mask) == (net_addr & mask);
    }
}

// ============================================================
// SYSTEM UTILITIES IMPLEMENTATION
// ============================================================
namespace SystemUtils {
    int GetCPUCoreCount() {
        int count = std::thread::hardware_concurrency();
        return count > 0 ? count : 1;
    }
    
    bool IsRootUser() {
        return geteuid() == 0;
    }
    
    pid_t GetCurrentPID() {
        return getpid();
    }
    
    void SetThreadAffinity(std::thread& thread, int core_id) {
        #ifdef __linux__
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);
        
        int rc = pthread_setaffinity_np(thread.native_handle(), 
                                       sizeof(cpu_set_t), &cpuset);
        if (rc != 0) {
            std::cerr << "⚠️  Warning: Failed to set thread affinity to core " 
                      << core_id << std::endl;
        }
        #else
        (void)thread; // Unused
        (void)core_id;
        std::cerr << "⚠️  Warning: Thread affinity not supported on this platform" << std::endl;
        #endif
    }
    
    void SetHighPriority() {
        #ifdef __linux__
        // Set nice value to -10 (higher priority)
        if (nice(-10) == -1) {
            std::cerr << "⚠️  Warning: Failed to set high priority" << std::endl;
        }
        #else
        std::cerr << "⚠️  Warning: Priority adjustment not supported on this platform" << std::endl;
        #endif
    }
}