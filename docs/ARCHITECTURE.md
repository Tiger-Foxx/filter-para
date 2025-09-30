# Tiger-Fox Architecture Documentation

## Hybrid Multi-Worker Design

### Core Principles

1. **Hash-Based Dispatch:** Each TCP flow (4-tuple) always goes to same worker
2. **Per-Worker Reassembly:** No shared state, no locks between workers
3. **Sequential Per-Worker:** Each worker evaluates L3→L4→L7 sequentially
4. **Early Termination:** Stop at first DROP match

### Flow Dispatch Algorithm

```cpp
uint32_t flow_hash = hash(src_ip, src_port, dst_ip, dst_port);
size_t worker_id = flow_hash % num_workers;
```

### TCP Reassembly Strategy

- Each worker has independent reassembler
- Same flow always → same worker → consistent reassembly
- Timeout-based cleanup (30s default)
- Memory-bounded (max 1000 streams per worker)

### Performance Optimizations

1. **CPU Affinity:** Workers pinned to specific cores
2. **Zero-Copy:** Direct packet buffer access
3. **Compiled Patterns:** PCRE2 patterns pre-compiled
4. **IP Range Trees:** Fast CIDR matching
5. **Connection Tracking:** Block entire flows efficiently

## Rule Evaluation Order

```
Packet arrives
    ↓
L3 Rules (IP-based)
    ↓ (if no match)
L4 Rules (Port/Protocol)
    ↓ (if no match)
L7 Rules (HTTP/DNS)
    ↓ (if no match)
ACCEPT
```

First DROP wins, no further evaluation.

## Memory Management

- **Packet Buffers:** Stack-allocated (4KB)
- **Reassembly Buffers:** Heap, bounded per stream
- **Rule Storage:** Loaded once, shared read-only
- **Connection State:** Hash map with LRU eviction

## Thread Safety

- **Workers:** No shared mutable state
- **Metrics:** Atomic counters
- **Rule Engine:** Read-only after load
- **Reassemblers:** Per-worker, isolated

---

Last Updated: 2025-09-30
