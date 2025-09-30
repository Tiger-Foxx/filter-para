# Tiger-Fox C++ Network Filtering System

🔥 **High-Performance Multi-Worker Network Filtering Research Project**

## Overview

Tiger-Fox is a cutting-edge network filtering system designed for academic research and performance evaluation. It implements unified rule filtering across L3/L4/L7 layers with multiple processing modes to compare sequential vs parallel approaches in network security filtering.

**⚠️ RESEARCH PROJECT - NOT PRODUCTION TESTED**

This is an experimental implementation developed for Master's research in Computer Engineering. While functionally complete, it has not undergone extensive production testing.

## 🏗️ Architecture

### CloudLab Deployment
```
INJECTOR                FILTER               SERVER
(wrk client)           (Tiger-Fox)          (nginx)
10.10.1.10      →       10.10.1.1/2.1    →   10.10.2.20
                        [NFQUEUE inline]
```

### Filtering Modes

1. **Sequential Mode** (Baseline)
   - Single-threaded processing
   - L3 → L4 → L7 rule evaluation order
   - Early termination on first DROP match

2. **Hybrid Mode** (Multi-Worker) **⭐ RECOMMENDED**
   - Multiple worker threads (auto-scaled to CPU cores)
   - Hash-based packet dispatch to preserve TCP flows
   - Per-worker TCP reassembly (no locks)
   - True parallelism like Suricata IDS

3. **Sequential-Hyb Mode** (Experimental)
   - Single packet stream with rule parallelization
   - Tests if rule parallelization helps performance

## 🚀 Features

### Core Capabilities
- ✅ **Real NFQUEUE filtering** - Actual packet DROP/ACCEPT decisions
- ✅ **TCP Reassembly** - Complete HTTP request reconstruction for L7 analysis
- ✅ **Multi-layer rules** - L3 (IP), L4 (TCP/UDP), L7 (HTTP) unified filtering
- ✅ **High-performance C++** - Zero-copy parsing, lockfree data structures
- ✅ **CPU Affinity** - Workers bound to specific CPU cores
- ✅ **Connection tracking** - Efficient blocking of malicious flows
- ✅ **Performance metrics** - Detailed latency and throughput measurement

### Rule Types Supported
- **L3**: IP source/destination matching, geo-location blocking
- **L4**: TCP/UDP port filtering, flag-based rules
- **L7**: HTTP URI regex, header inspection, method filtering

## 🔧 Installation

### Dependencies (Ubuntu 20.04+)
```bash
chmod +x install_deps.sh
sudo ./install_deps.sh
```

### Build
```bash
chmod +x build.sh
./build.sh
```

The build script will:
- Configure with CMake (optimized Release build)
- Compile with `-O3 -march=native` for maximum performance
- Link against libnetfilter_queue, PCRE2, nlohmann-json
- Generate optimized `tiger-fox` executable

## 🎮 Usage

### Basic Commands
```bash
# Sequential mode (baseline)
sudo ./build/tiger-fox --sequential

# Hybrid multi-worker mode (recommended)
sudo ./build/tiger-fox --hybrid

# Custom worker count
sudo ./build/tiger-fox --hybrid --workers 8

# Debug mode with verbose logging
sudo ./build/tiger-fox --hybrid --verbose

# Custom NFQUEUE number
sudo ./build/tiger-fox --queue 1
```

### CloudLab Testing Workflow
1. **Setup filter machine**:
   ```bash
   sudo ./build/tiger-fox --hybrid --verbose
   ```

2. **From injector machine**:
   ```bash
   # Performance test
   wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/
   
   # Attack simulation
   curl "http://10.10.2.20/?id=1' OR 1=1--"
   curl -H "User-Agent: sqlmap" http://10.10.2.20/
   ```

3. **Observe results**:
   - Monitor DROP/ACCEPT rates on filter
   - Compare sequential vs hybrid performance
   - Analyze latency percentiles

## 📊 Performance Metrics

Tiger-Fox captures detailed performance metrics:

### Real-time Stats
- **Packets/second throughput**
- **DROP rate percentage** 
- **Average decision time**
- **P95/P99 latency percentiles**
- **Per-worker load distribution**
- **TCP reassembly efficiency**

### Rule Performance
- **Top matched rules** by hit count
- **Slowest rules** by evaluation time
- **Layer breakdown** (L3/L4/L7 performance)
- **Early termination** effectiveness

## 🔬 Research Applications

### Academic Use Cases
- **Network security research** - Rule optimization algorithms
- **Parallel computing** - Multi-worker vs single-threaded analysis  
- **Performance evaluation** - Latency vs throughput trade-offs
- **System architecture** - Inline filtering vs proxy comparison

### Benchmarking Scenarios
```bash
# Baseline (no filtering)
# Direct: injector → server

# Sequential filtering
sudo ./tiger-fox --sequential

# Multi-worker filtering  
sudo ./tiger-fox --hybrid --workers 8

# Rule parallelization
sudo ./tiger-fox --sequential-hyb
```

## 📁 Project Structure
```
tiger-fox-cpp/
├── src/
│   ├── main.cpp                    # Entry point with argument parsing
│   ├── tiger_system.h/.cpp         # Main system orchestration
│   ├── engine/
│   │   ├── rule_engine.h/.cpp           # Abstract base class
│   │   ├── sequential_engine.h/.cpp     # Sequential mode implementation
│   │   ├── hybrid_engine.h/.cpp         # Multi-worker mode implementation
│   │   └── sequential_hyb_engine.h/.cpp # Rule parallelization mode
│   ├── handlers/
│   │   ├── packet_handler.h/.cpp        # NFQUEUE interface
│   │   └── tcp_reassembler.h/.cpp       # TCP stream reconstruction
│   ├── loaders/
│   │   └── rule_loader.h/.cpp           # JSON rule parsing
│   └── utils/
│       └── utils.h/.cpp                 # Performance utilities
├── rules/
│   └── tiger_rules.json                 # Unified rule database (700+ rules)
├── build/                               # CMake build directory
├── CMakeLists.txt                       # Build configuration
├── install_deps.sh                      # Dependency installation
├── build.sh                            # Build script
└── README.md                           # This file
```

## 🔑 Rule Format

Rules are defined in unified JSON format:

```json
{
  "rules": [
    {
      "id": "block_tor_ips",
      "layer": 3,
      "type": "ip_src_in", 
      "values": ["192.42.116.0/24", "199.87.154.0/24"],
      "action": "drop"
    },
    {
      "id": "block_sql_injection",
      "layer": 7,
      "type": "http_uri_regex",
      "values": ["(?i)(union|select|insert|drop).*from"],
      "action": "drop"
    }
  ]
}
```

## ⚠️ Important Notes

### System Requirements
- **Linux only** (tested on Ubuntu 20.04+)
- **Root privileges** required for NFQUEUE access
- **IP forwarding** must be enabled
- **Minimum 4GB RAM** for full rule set
- **Multi-core CPU** recommended for hybrid mode

### Network Setup
Tiger-Fox configures iptables automatically:
```bash
# Automatically added by Tiger-Fox
iptables -I FORWARD -j NFQUEUE --queue-num 0
sysctl -w net.ipv4.ip_forward=1
```

### Performance Considerations
- **Hybrid mode** scales with CPU cores (recommended for research)
- **Sequential mode** provides consistent baseline measurements
- **TCP reassembly** adds latency but enables L7 HTTP analysis
- **Rule optimization** affects performance significantly

## 🐛 Troubleshooting

### Common Issues
1. **Permission denied**: Run with `sudo`
2. **NFQUEUE bind failed**: Check if another process uses the queue
3. **No packets captured**: Verify traffic flows through filter machine
4. **High CPU usage**: Normal for intensive packet processing

### Debug Mode
```bash
sudo ./build/tiger-fox --hybrid --verbose
```

Provides detailed packet-by-packet logging for analysis.

## 📚 Academic References

This project implements concepts from:
- **Suricata IDS** - Multi-threaded packet processing architecture
- **DPDK** - High-performance packet processing techniques  
- **NetFilter** - Linux kernel packet filtering framework
- **PCRE2** - Optimized regular expression matching

## 👥 Contributors

**Author**: Pascal DONFACK ARTHUR MONTGOMERY (Tiger Fox)  
**Academic Supervisors**: 
- Dr HYPPOLITE MICHEL TAPAMO KENFACK (CC)
- Dr DJOB MVONDO (MC)

**Institution**: Master's in Computer Engineering  
**Research Focus**: Network filtering optimization and parallel processing

## 📄 License

This project is developed for academic research purposes. 

---

**⭐ For best performance, use `--hybrid` mode with automatic worker scaling!**

*Last updated: September 2025*
