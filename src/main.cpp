#include "tiger_system.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <cstdlib>
#include <getopt.h>

// ============================================================
// COMMAND-LINE ARGUMENTS PARSING
// ============================================================
struct CommandLineArgs {
    std::string rules_file = "rules/example_rules.json";
    int queue_num = 0;
    size_t num_workers = 0;  // 0 = auto-detect (for parallel mode)
    std::string mode = "sequential";  // "sequential" or "parallel"
    bool debug_mode = false;
    bool show_help = false;
    bool show_version = false;
};

void PrintUsage(const char* program_name) {
    std::cout << "\n";
    std::cout << "🐯 Tiger-Fox Ultra-Fast Network Filtering System 🦊\n";
    std::cout << "===============================================\n";
    std::cout << "Two Modes for Performance Research\n";
    std::cout << "\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  -m, --mode MODE        Filtering mode: sequential or parallel (default: sequential)\n";
    std::cout << "  -r, --rules FILE       Rules file path (default: rules/example_rules.json)\n";
    std::cout << "  -q, --queue NUM        NFQUEUE number (default: 0)\n";
    std::cout << "  -w, --workers NUM      Number of workers for parallel mode (default: auto-detect)\n";
    std::cout << "  -v, --verbose          Enable debug/verbose mode\n";
    std::cout << "  -h, --help             Show this help message\n";
    std::cout << "  -V, --version          Show version information\n";
    std::cout << "\n";
    std::cout << "Modes:\n";
    std::cout << "  sequential             Single-threaded ultra-fast filtering (hash O(1))\n";
    std::cout << "  parallel               N-workers racing in parallel (first DROP wins)\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  sudo " << program_name << " --mode sequential              # Ultra-fast single-threaded\n";
    std::cout << "  sudo " << program_name << " --mode parallel --workers 4    # 4 workers racing\n";
    std::cout << "  sudo " << program_name << " -m parallel -w 8 -v             # 8 workers with debug\n";
    std::cout << "\n";
    std::cout << "Benchmarking (from injector node):\n";
    std::cout << "  wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/\n";
    std::cout << "\n";
    std::cout << "Requirements:\n";
    std::cout << "  - Root privileges (sudo)\n";
    std::cout << "  - IP forwarding enabled\n";
    std::cout << "  - iptables NFQUEUE rule configured\n";
    std::cout << "\n";
}

void PrintVersion() {
    std::cout << "\n";
    std::cout << "🐯 Tiger-Fox Ultra-Fast Network Filtering System 🦊\n";
    std::cout << "===============================================\n";
    std::cout << "Version: 2.0.0 (Research Edition)\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "\n";
    std::cout << "Modes:\n";
    std::cout << "  ✓ SEQUENTIAL: Single-threaded with hash O(1) lookups\n";
    std::cout << "  ✓ PARALLEL:   N-workers racing (first DROP wins)\n";
    std::cout << "\n";
    std::cout << "Features:\n";
    std::cout << "  ✓ Zero-copy packet processing\n";
    std::cout << "  ✓ Hash tables for O(1) IP/port lookups\n";
    std::cout << "  ✓ L3/L4 filtering only (max speed)\n";
    std::cout << "  ✓ No TCP reassembly overhead\n";
    std::cout << "  ✓ Lock-free atomic operations\n";
    std::cout << "  ✓ Direct NFQUEUE inline filtering\n";
    std::cout << "\n";
    std::cout << "Performance Target: > 2,500 req/s (beat Suricata/Snort)\n";
    std::cout << "\n";
}

CommandLineArgs ParseArguments(int argc, char* argv[]) {
    CommandLineArgs args;
    
    // Define long options
    static struct option long_options[] = {
        {"mode",     required_argument, 0, 'm'},
        {"rules",    required_argument, 0, 'r'},
        {"queue",    required_argument, 0, 'q'},
        {"workers",  required_argument, 0, 'w'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {"version",  no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "m:r:q:w:vhV", long_options, &option_index)) != -1) {
        switch (c) {
            case 'm':
                args.mode = std::string(optarg);
                if (args.mode != "sequential" && args.mode != "parallel") {
                    std::cerr << "❌ Error: Invalid mode. Must be 'sequential' or 'parallel'\n";
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 'r':
                args.rules_file = std::string(optarg);
                break;
                
            case 'q':
                try {
                    args.queue_num = std::stoi(optarg);
                    if (args.queue_num < 0 || args.queue_num > 65535) {
                        std::cerr << "❌ Error: Invalid queue number (must be 0-65535)\n";
                        exit(EXIT_FAILURE);
                    }
                } catch (...) {
                    std::cerr << "❌ Error: Invalid queue number format\n";
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 'w':
                try {
                    args.num_workers = std::stoul(optarg);
                    if (args.num_workers < 1 || args.num_workers > 128) {
                        std::cerr << "❌ Error: Invalid worker count (must be 1-128)\n";
                        exit(EXIT_FAILURE);
                    }
                } catch (...) {
                    std::cerr << "❌ Error: Invalid worker count format\n";
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 'v':
                args.debug_mode = true;
                break;
                
            case 'h':
                args.show_help = true;
                break;
                
            case 'V':
                args.show_version = true;
                break;
                
            case '?':
                // getopt_long already printed an error message
                exit(EXIT_FAILURE);
                
            default:
                abort();
        }
    }
    
    // Check for non-option arguments
    if (optind < argc) {
        std::cerr << "❌ Error: Unexpected argument: " << argv[optind] << "\n";
        std::cerr << "   Use --help for usage information\n";
        exit(EXIT_FAILURE);
    }
    
    return args;
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================
int main(int argc, char* argv[]) {
    // Parse command-line arguments
    CommandLineArgs args = ParseArguments(argc, argv);
    
    // Handle --help
    if (args.show_help) {
        PrintUsage(argv[0]);
        return EXIT_SUCCESS;
    }
    
    // Handle --version
    if (args.show_version) {
        PrintVersion();
        return EXIT_SUCCESS;
    }
    
    // Print banner
    std::cout << "\n";
    std::cout << "🐯 ========================================== 🦊\n";
    std::cout << "   Tiger-Fox C++ Network Filtering System\n";
    std::cout << "   Hybrid Multi-Worker Architecture\n";
    std::cout << "🐯 ========================================== 🦊\n";
    std::cout << "\n";
    
    try {
        // Create and initialize Tiger-Fox system
        TigerSystem tiger_system(
            args.rules_file,
            args.queue_num,
            args.mode,
            args.num_workers,
            args.debug_mode
        );
        
        // Initialize system
        if (!tiger_system.Initialize()) {
            std::cerr << "❌ Error: Failed to initialize Tiger-Fox system\n";
            return EXIT_FAILURE;
        }
        
        // Run system (blocks until Ctrl+C or SIGTERM)
        tiger_system.Run();
        
        // Shutdown (called automatically by destructor, but explicit is good)
        tiger_system.Shutdown();
        
        std::cout << "\n✅ Tiger-Fox terminated successfully\n" << std::endl;
        return EXIT_SUCCESS;
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Fatal error: " << e.what() << "\n" << std::endl;
        return EXIT_FAILURE;
        
    } catch (...) {
        std::cerr << "\n❌ Fatal error: Unknown exception\n" << std::endl;
        return EXIT_FAILURE;
    }
}