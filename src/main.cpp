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
    size_t num_workers = 0;  // 0 = auto-detect
    bool debug_mode = false;
    bool show_help = false;
    bool show_version = false;
};

void PrintUsage(const char* program_name) {
    std::cout << "\n";
    std::cout << "🐯 Tiger-Fox C++ Network Filtering System 🦊\n";
    std::cout << "===============================================\n";
    std::cout << "Hybrid Multi-Worker Architecture for High-Performance Filtering\n";
    std::cout << "\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  -r, --rules FILE       Rules file path (default: rules/example_rules.json)\n";
    std::cout << "  -q, --queue NUM        NFQUEUE number (default: 0)\n";
    std::cout << "  -w, --workers NUM      Number of workers (default: auto-detect CPU cores)\n";
    std::cout << "  -v, --verbose          Enable debug/verbose mode\n";
    std::cout << "  -h, --help             Show this help message\n";
    std::cout << "  -V, --version          Show version information\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  sudo " << program_name << "                           # Auto-detect workers\n";
    std::cout << "  sudo " << program_name << " --workers 8                # Use 8 workers\n";
    std::cout << "  sudo " << program_name << " --queue 1 --verbose        # Queue 1 with debug\n";
    std::cout << "  sudo " << program_name << " --rules custom_rules.json  # Custom rules file\n";
    std::cout << "\n";
    std::cout << "CloudLab Testing:\n";
    std::cout << "  Architecture: injector (10.10.1.10) → filter → server (10.10.2.20)\n";
    std::cout << "  From injector: wrk -t 12 -c 400 -d 30s http://10.10.2.20/\n";
    std::cout << "\n";
    std::cout << "Requirements:\n";
    std::cout << "  - Root privileges (sudo)\n";
    std::cout << "  - IP forwarding enabled\n";
    std::cout << "  - iptables NFQUEUE rule configured\n";
    std::cout << "\n";
    std::cout << "Signals:\n";
    std::cout << "  Ctrl+C (SIGINT)  - Graceful shutdown\n";
    std::cout << "  SIGTERM          - Graceful shutdown\n";
    std::cout << "\n";
}

void PrintVersion() {
    std::cout << "\n";
    std::cout << "🐯 Tiger-Fox C++ Network Filtering System 🦊\n";
    std::cout << "===============================================\n";
    std::cout << "Version: 1.0.0\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Architecture: Hybrid Multi-Worker\n";
    std::cout << "Author: Pascal DONFACK ARTHUR MONTGOMERY (Tiger Fox)\n";
    std::cout << "\n";
    std::cout << "Features:\n";
    std::cout << "  ✓ Multi-worker parallel processing\n";
    std::cout << "  ✓ Hash-based flow dispatch\n";
    std::cout << "  ✓ TCP reassembly for HTTP L7 analysis\n";
    std::cout << "  ✓ Unified L3/L4/L7 rule filtering\n";
    std::cout << "  ✓ CPU affinity and NUMA awareness\n";
    std::cout << "  ✓ Real NFQUEUE inline filtering\n";
    std::cout << "\n";
    std::cout << "Dependencies:\n";
    std::cout << "  - libnetfilter_queue\n";
    std::cout << "  - PCRE2\n";
    std::cout << "  - nlohmann-json\n";
    std::cout << "  - pthread\n";
    std::cout << "\n";
}

CommandLineArgs ParseArguments(int argc, char* argv[]) {
    CommandLineArgs args;
    
    // Define long options
    static struct option long_options[] = {
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
    
    while ((c = getopt_long(argc, argv, "r:q:w:vhV", long_options, &option_index)) != -1) {
        switch (c) {
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