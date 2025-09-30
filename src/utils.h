#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <thread>  // ✅ AJOUTÉ

#ifdef _WIN32
#include <process.h>
typedef int pid_t;
#else
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#endif

// ============================================================
// HIGH-RESOLUTION TIMER
// ============================================================
class HighResTimer {
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    
public:
    HighResTimer() : start_time_(std::chrono::high_resolution_clock::now()) {}
    
    void Reset() {
        start_time_ = std::chrono::high_resolution_clock::now();
    }
    
    double ElapsedSeconds() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(end - start_time_).count();
    }
    
    double ElapsedMillis() const {
        return ElapsedSeconds() * 1000.0;
    }
    
    uint64_t ElapsedMicros() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start_time_).count();
    }
    
    uint64_t ElapsedNanos() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_time_).count();
    }
};

// ============================================================
// STRING UTILITIES
// ============================================================
namespace StringUtils {
    std::vector<std::string> Split(const std::string& str, char delimiter);
    std::string Trim(const std::string& str);
    std::string ToLower(const std::string& str);
    bool StartsWith(const std::string& str, const std::string& prefix);
    bool EndsWith(const std::string& str, const std::string& suffix);
    bool Contains(const std::string& str, const std::string& substr);
}

// ============================================================
// NETWORK UTILITIES
// ============================================================
namespace NetworkUtils {
    bool IsPrivateIP(const std::string& ip);
    bool IsValidIPv4(const std::string& ip);
    bool IsValidIPv6(const std::string& ip);
    uint32_t IPv4ToUint32(const std::string& ip);
    bool IsInSubnet(const std::string& ip, const std::string& subnet);
}

// ============================================================
// SYSTEM UTILITIES
// ============================================================
namespace SystemUtils {
    int GetCPUCoreCount();
    bool IsRootUser();
    pid_t GetCurrentPID();
    void SetThreadAffinity(std::thread& thread, int core_id);  // ✅ Maintenant `std::thread` est défini
    void SetHighPriority();
}

// ============================================================
// DEBUG LOGGING
// ============================================================
#define LOG_DEBUG(enabled, msg) \
    do { if (enabled) std::cout << "[DEBUG] " << msg << std::endl; } while(0)

#endif // UTILS_H