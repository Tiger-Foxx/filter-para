# Tiger-Fox C++ Hybrid Network Filtering System

🔥 **High-Performance Multi-Worker Inline Network Filtering**

## Overview

Tiger-Fox is a research-grade network filtering system implementing **hybrid multi-worker architecture** for inline packet filtering with true L7 HTTP analysis via optimized TCP reassembly.

**Key Features:**
- ✅ Multi-worker parallel processing (hash-based flow dispatch)
- ✅ True TCP reassembly for HTTP L7 analysis
- ✅ Unified L3/L4/L7 rule filtering
- ✅ Zero-copy packet processing
- ✅ CPU affinity and NUMA awareness
- ✅ Real NFQUEUE inline filtering

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NFQUEUE (Kernel)                     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │      PacketHandler          │
         │   (Queue Management)        │
         └──────────┬──────────────────┘
                    │
        ┌───────────┴───────────┐
        │   Hash Dispatcher     │
        │  (4-tuple based)      │
        └───────────┬───────────┘
                    │
     ┌──────────────┼──────────────┐
     ▼              ▼              ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│ Worker 0│   │ Worker 1│   │ Worker N│
│ Core 0  │   │ Core 1  │   │ Core N  │
└─────────┘   └─────────┘   └─────────┘
     │              │              │
     └──────────────┼──────────────┘
                    │
              ┌─────┴─────┐
              │ L3 → L4 → │
              │    L7     │
              └───────────┘
```

## Quick Start

### Installation (Ubuntu 22.04+)

```bash
# Install dependencies
chmod +x install_deps.sh
sudo ./install_deps.sh

# Build
chmod +x build.sh
./build.sh

# Run
sudo ./build/tiger-fox --workers 8
```

### Usage

```bash
# Auto-detect CPU cores
sudo ./build/tiger-fox

# Specify worker count
sudo ./build/tiger-fox --workers 8

# Custom queue number
sudo ./build/tiger-fox --queue 1

# Debug mode
sudo ./build/tiger-fox --debug

# Help
./build/tiger-fox --help
```

## CloudLab Testing

```
INJECTOR (wrk)         FILTER               SERVER (nginx)
10.10.1.10      →      10.10.1.1/2.1    →   10.10.2.20
                       [tiger-fox]
```

**From injector:**
```bash
wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/
```

## Performance

- **Throughput:** 10Gbps+ on modern hardware
- **Latency:** <100μs per packet (without reassembly)
- **Reassembly:** <500μs for complete HTTP request
- **Rules:** 600+ rules evaluated per packet
- **Scalability:** Linear with CPU cores

## Project Structure

```
tiger-fox-cpp/
├── src/
│   ├── main.cpp                    # Entry point
│   ├── tiger_system.h/.cpp         # System orchestration
│   ├── utils.h/.cpp                # Utilities
│   ├── engine/
│   │   ├── rule_engine.h/.cpp      # Rule evaluation engine
│   │   └── worker_pool.h/.cpp      # Worker management
│   ├── handlers/
│   │   ├── packet_handler.h/.cpp   # NFQUEUE interface
│   │   └── tcp_reassembler.h/.cpp  # TCP stream reconstruction
│   └── loaders/
│       └── rule_loader.h/.cpp      # JSON rule parser
├── rules/
│   └── tiger_rules.json            # 600+ filtering rules
├── CMakeLists.txt
├── build.sh
└── README.md
```

## Rule Format

```json
{
  "rules": [
    {
      "id": "block_sql_injection",
      "layer": 7,
      "type": "http_uri_regex",
      "values": ["(?i)(union|select).*from"],
      "action": "drop"
    }
  ]
}
```

## Requirements

- **OS:** Linux (Ubuntu 20.04+)
- **Privileges:** Root (for NFQUEUE)
- **RAM:** 4GB minimum
- **CPU:** Multi-core recommended

## License

Academic research project - Master's in Computer Engineering

---

**Author:** Pascal DONFACK ARTHUR MONTGOMERY (Tiger Fox)  
**Last Updated:** 2025-09-30
