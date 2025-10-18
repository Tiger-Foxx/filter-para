# 🐯🦊 TIGER-FOX - Ultra-Fast Network Filter

**Research project: Sequential vs Parallel filtering performance comparison**

---

## 🎯 Overview

High-performance L3/L4 network packet filtering system with two modes:
- **Sequential**: Single-threaded with hash O(1) optimizations (baseline)
- **Parallel**: Multi-worker racing with rule partitioning (experimental)

**Goal**: Prove that multi-core parallelism improves network filtering performance.

**Target**: > 2,500 req/s (beating Suricata/Snort)

---

## 🚀 Quick Start

### 1. Build
```bash
sudo ./build.sh
```

### 2. Configure iptables (on filter node)
```bash
sudo iptables -I FORWARD -s 10.10.1.10 -d 10.10.2.20 -j NFQUEUE --queue-num 0
```

### 3. Run Sequential mode
```bash
sudo ./build/tiger-fox --mode sequential --config config.json --queue-num 0
```

### 4. Run Parallel mode (3 workers)
```bash
sudo ./build/tiger-fox --mode parallel --workers 3 --config config.json --queue-num 0
```

### 5. Benchmark (from injector node)
```bash
wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/
```

---

## 📊 Architecture

### Sequential Mode
- 1 thread
- 69 rules (23 × 3)
- Hash O(1) lookups for IPs/ports
- Zero-copy stack allocation

**Expected**: 2,000-3,000 req/s

### Parallel Mode
- 3 permanent worker threads
- ~8 rules per worker (23 / 3)
- Lock-free atomic racing
- Condition variable synchronization

**Expected**: 3,500-6,000 req/s (2-3x faster)

---

## 📁 Key Files

**Source Code:**
- `src/engine/fast_sequential_engine.{h,cpp}` - Sequential mode
- `src/engine/ultra_parallel_engine.{h,cpp}` - Parallel mode  
- `src/handlers/packet_handler.{h,cpp}` - NFQUEUE handler
- `src/tiger_system.{h,cpp}` - Main orchestrator
- `src/main.cpp` - Entry point

**Configuration:**
- `config.json` - Main config
- `rules/example_rules.json` - 23 L3/L4 filtering rules

**Scripts:**
- `build.sh` - Compile project
- `check_files.sh` - Validate source files
- `test_both_modes.sh` - Automated test script
- `install_deps.sh` - Install dependencies

**Documentation:**
- `IMPLEMENTATION.md` - Complete technical documentation
- `notes.txt` - Original requirements

---

## 🔧 Dependencies

```bash
sudo apt install -y \
    build-essential cmake \
    libnetfilter-queue-dev \
    libpcre2-dev \
    nlohmann-json3-dev
```

Or: `sudo ./install_deps.sh`

---

## 📈 Performance Comparison

| Aspect | Sequential | Parallel (3w) |
|--------|-----------|---------------|
| Rules total | 69 (23×3) | 23 |
| Rules/worker | 69 | ~8 |
| Threads | 1 | 3 permanent |
| Hash O(1) | ✅ | ✅ |
| Expected req/s | 2,500 | 5,000 |
| **Speed-up** | **1x** | **~2-3x** |

---

## 🧪 Testing

### Automated test
```bash
./test_both_modes.sh
```

### Manual comparison
```bash
# Sequential
sudo ./build/tiger-fox --mode sequential --queue-num 0

# Parallel
sudo ./build/tiger-fox --mode parallel --workers 3 --queue-num 0
```

### Cleanup
```bash
sudo pkill tiger-fox
sudo iptables -D FORWARD -s 10.10.1.10 -d 10.10.2.20 -j NFQUEUE --queue-num 0
```

---

## 📚 Documentation

See **IMPLEMENTATION.md** for:
- Complete architecture details
- Performance analysis
- Technical deep-dive
- Benchmark instructions

---

## ✅ Status

- [x] Sequential mode implemented (hash O(1))
- [x] Parallel mode implemented (permanent workers)
- [x] Rule partitioning (8 rules/worker)
- [x] Zero-copy packet sharing
- [x] Lock-free atomic racing
- [x] Build system configured
- [ ] CloudLab benchmark (pending)

**Ready for testing!** 🚀
