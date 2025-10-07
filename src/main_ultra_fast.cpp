// ============================================================
// 🚀 TIGER-FOX ULTRA FAST MODE
// ============================================================
// Single-threaded, zero-copy, inline processing
// No workers, no queues, no async - PURE SPEED!
// ============================================================

#include <iostream>
#include <csignal>
#include <memory>
#include <cstring>

#include "handlers/inline_packet_handler.h"
#include "engine/ultra_fast_engine.h"
#include "loaders/rule_loader.h"
#include "utils.h"

// Global handler for signal handling
std::unique_ptr<InlinePacketHandler> g_handler;

void SignalHandler(int signal) {
    std::cout << "\n🛑 Received signal " << signal << ", stopping..." << std::endl;
    if (g_handler) {
        g_handler->Stop();
    }
    exit(0);
}

void PrintBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🐯 TIGER-FOX ULTRA FAST MODE 🦊                       ║
║                                                          ║
║   Zero-Copy | Lock-Free | Inline | PCRE2-JIT           ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
)" << std::endl;
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    // ============================================================
    // PARSE ARGUMENTS
    // ============================================================
    bool debug_mode = false;
    int queue_num = 0;
    std::string rules_file = "rules/example_rules.json";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            debug_mode = true;
        } else if (strcmp(argv[i], "--queue") == 0 && i + 1 < argc) {
            queue_num = std::atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rules") == 0 && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n";
            std::cout << "Options:\n";
            std::cout << "  --verbose, -v         Enable debug mode\n";
            std::cout << "  --queue NUM          NFQUEUE number (default: 0)\n";
            std::cout << "  --rules FILE         Rules file (default: rules/example_rules.json)\n";
            std::cout << "  --help, -h           Show this help\n";
            return 0;
        }
    }
    
    std::cout << "⚙️  Configuration:" << std::endl;
    std::cout << "   • Mode: ULTRA FAST (single-threaded inline)" << std::endl;
    std::cout << "   • Queue: " << queue_num << std::endl;
    std::cout << "   • Rules: " << rules_file << std::endl;
    std::cout << "   • Debug: " << (debug_mode ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    // ============================================================
    // LOAD RULES
    // ============================================================
    std::cout << "📋 Loading rules from " << rules_file << "..." << std::endl;
    
    RuleLoader loader;
    auto rules = loader.LoadFromFile(rules_file);
    
    if (rules.empty()) {
        std::cerr << "❌ No rules loaded!" << std::endl;
        return 1;
    }
    
    std::cout << "✅ Loaded " << loader.GetTotalRuleCount() << " rules:" << std::endl;
    std::cout << "   • L3 (Network):     " << loader.GetRuleCount(RuleLayer::L3) << std::endl;
    std::cout << "   • L4 (Transport):   " << loader.GetRuleCount(RuleLayer::L4) << std::endl;
    std::cout << "   • L7 (Application): " << loader.GetRuleCount(RuleLayer::L7) << std::endl;
    std::cout << std::endl;
    
    // ============================================================
    // CREATE ULTRA FAST ENGINE
    // ============================================================
    std::cout << "🚀 Creating UltraFastEngine..." << std::endl;
    
    auto engine = std::make_shared<UltraFastEngine>(rules);
    
    std::cout << std::endl;
    
    // ============================================================
    // CREATE INLINE HANDLER
    // ============================================================
    std::cout << "🔧 Creating InlinePacketHandler..." << std::endl;
    
    try {
        g_handler = std::make_unique<InlinePacketHandler>(queue_num, engine, debug_mode);
    } catch (const std::exception& e) {
        std::cerr << "❌ Failed to create handler: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << std::endl;
    
    // ============================================================
    // SETUP SIGNAL HANDLERS
    // ============================================================
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    
    std::cout << "📡 Press Ctrl+C to stop" << std::endl;
    std::cout << std::endl;
    
    // ============================================================
    // START (blocks until stopped)
    // ============================================================
    try {
        g_handler->Start();
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "✅ Exiting cleanly" << std::endl;
    
    return 0;
}
