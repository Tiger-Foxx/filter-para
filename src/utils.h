#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <thread>
#ifdef _WIN32
#include <process.h>
typedef int pid_t;
#else
#include <unistd.h>
#endif

// ============================================================
// HIGH-RESOLUTION TIMER FOR PERFORMANCE MEASUREMENT
// ============================================================
class HighResTimer {
public:
    HighResTimer() : start_(std::chrono::high_resolution_clock::now()) {}
    
    // Reset timer
    void Reset() {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    // Get elapsed time in microseconds
    uint64_t ElapsedMicros() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
    }
    
    // Get elapsed time in nanoseconds
    uint64_t ElapsedNanos() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_).count();
    }
    
    // Get elapsed time in milliseconds (double precision)
    double ElapsedMillis() const {
        return ElapsedMicros() / 1000.0;
    }

private:
    std::chrono::high_resolution_clock::time_point start_;
};

// ============================================================
// STRING UTILITIES
// ============================================================
namespace StringUtils {
    // Split string by delimiter
    std::vector<std::string> Split(const std::string& str, char delimiter);
    
    // Trim whitespace from both ends
    std::string Trim(const std::string& str);
    
    // Convert to lowercase
    std::string ToLower(const std::string& str);
    
    // Check if string starts with prefix
    bool StartsWith(const std::string& str, const std::string& prefix);
    
    // Check if string ends with suffix
    bool EndsWith(const std::string& str, const std::string& suffix);
    
    // Check if string contains substring
    bool Contains(const std::string& str, const std::string& substr);
}

// ============================================================
// NETWORK UTILITIES
// ============================================================
namespace NetworkUtils {
    // Check if IP is private (RFC1918)
    bool IsPrivateIP(const std::string& ip);
    
    // Validate IPv4 address
    bool IsValidIPv4(const std::string& ip);
    
    // Validate IPv6 address
    bool IsValidIPv6(const std::string& ip);
    
    // Convert IPv4 string to uint32_t (network byte order)
    uint32_t IPv4ToUint32(const std::string& ip);
    
    // Check if IP is in subnet (CIDR notation)
    bool IsInSubnet(const std::string& ip, const std::string& subnet);
}

// ============================================================
// SYSTEM UTILITIES
// ============================================================
namespace SystemUtils {
    // Get number of CPU cores
    int GetCPUCoreCount();
    
    // Check if running as root
    bool IsRootUser();
    
    // Get current process PID
    pid_t GetCurrentPID();
    
    // Set thread affinity to specific CPU core (Linux only)
    void SetThreadAffinity(std::thread& thread, int core_id);
    
    // Set process to high priority
    void SetHighPriority();
}

// ============================================================
// DEBUG LOGGING MACRO
// ============================================================
#define LOG_DEBUG(enabled, message) \
    do { \
        if (enabled) { \
            std::cout << "[DEBUG] " << message << std::endl; \
        } \
    } while (0)

#endif // UTILS_H