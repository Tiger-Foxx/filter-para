# 🚀 TIGER-FOX V3: STREAM-INLINE ARCHITECTURE

## 🎯 Objectif
Atteindre **4,000+ req/s** avec détection L7 complète (XSS, SQL injection, etc.)

---

## 🏗️ Architecture Stream-Inline

### Principe fondamental
**"Process packets as they arrive, decide as soon as possible"**

### Composants principaux

```
┌────────────────────────────────────────────────────────────────┐
│                         NFQUEUE CALLBACK                        │
│                         (Single Thread)                         │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. EARLY EXITS (0.001ms)                                      │
│     └─ Response? ICMP? DNS? → ACCEPT immédiatement            │
│                                                                 │
│  2. L3/L4 CHECKS (0.005ms)                                     │
│     └─ Hash table lookup → DROP si match                       │
│                                                                 │
│  3. TCP STREAM TRACKING (0.010ms)                              │
│     └─ Trouve ou crée stream dans hash table                   │
│                                                                 │
│  4. HTTP PARSING INCRÉMENTAL (0.020ms)                         │
│     ├─ Premier paquet: Parse headers                           │
│     ├─ Headers complets? → Check L7 rules                      │
│     └─ Body fragments: Streaming pattern match                 │
│                                                                 │
│  5. VERDICT IMMÉDIAT                                           │
│     └─ NF_ACCEPT ou NF_DROP (kernel reçoit réponse)           │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Innovations clés

### 1. **Streaming Pattern Matching**
```cpp
// Pas besoin d'attendre le dernier paquet !
// On match au fur et à mesure
class StreamingMatcher {
    // Buffer sliding window (4KB max)
    std::array<char, 4096> window_;
    size_t window_size_ = 0;
    
    bool AddFragmentAndMatch(const char* data, size_t len) {
        // Copie fragment dans window
        memcpy(window_.data() + window_size_, data, len);
        window_size_ += len;
        
        // Match PCRE2 sur window
        if (pcre2_jit_match(...)) {
            return true;  // MATCH TROUVÉ → DROP
        }
        
        // Slide window (garde 1KB overlap pour patterns split)
        if (window_size_ > 3072) {
            memmove(window_.data(), window_.data() + 2048, 1024);
            window_size_ = 1024;
        }
        
        return false;
    }
};
```

**Avantage** : 
- ✅ Détecte `<script>alert('XSS')</script>` même si split sur 3 paquets
- ✅ Pas besoin de réassembler 100% de la requête
- ✅ DROP dès qu'un pattern match

### 2. **Zero-Copy HTTP Parser**
```cpp
// Parse headers sans copier les données
struct HttpRequest {
    std::string_view method;   // Pointe dans le paquet original
    std::string_view uri;
    std::string_view host;
    std::string_view user_agent;
    size_t headers_complete_offset;  // Offset où headers finissent
    bool headers_complete;
};

// Parsing incrémental (llhttp ou http-parser)
bool ParseHttpIncremental(const char* data, size_t len, HttpRequest& req);
```

### 3. **Hash-based Stream Tracking**
```cpp
// Clé de stream = (src_ip, dst_ip, src_port, dst_port, protocol)
struct StreamKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    
    size_t hash() const {
        return std::hash<uint64_t>{}(
            (uint64_t(src_ip) << 32) | dst_ip
        ) ^ std::hash<uint32_t>{}(
            (uint32_t(src_port) << 16) | dst_port
        );
    }
};

// Stream state (dans hash table pour O(1) lookup)
struct StreamState {
    HttpRequest http_request;
    StreamingMatcher matcher;
    uint32_t last_seq;
    uint64_t last_activity;
    bool verdict_sent;
};

std::unordered_map<StreamKey, StreamState, StreamKeyHash> streams_;
```

### 4. **Inline Verdict** (pas de queue)
```cpp
int PacketCallback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data) {
    // Get packet
    unsigned char *packet_data;
    int len = nfq_get_payload(nfa, &packet_data);
    uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);
    
    // EARLY EXITS
    if (IsResponse(packet_data, len)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);  // IMMEDIATE
    }
    
    // L3/L4 checks (hash lookup)
    if (IsBlockedIP(packet_data) || IsBlockedPort(packet_data)) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);  // IMMEDIATE
    }
    
    // Get or create stream
    StreamKey key = ExtractStreamKey(packet_data, len);
    StreamState& stream = streams_[key];
    
    // Parse HTTP incrementally
    const char* payload = GetTcpPayload(packet_data, len);
    size_t payload_len = GetTcpPayloadLen(packet_data, len);
    
    // Parse headers
    if (!stream.http_request.headers_complete) {
        ParseHttpIncremental(payload, payload_len, stream.http_request);
        
        if (stream.http_request.headers_complete) {
            // Headers complets → check L7 rules
            if (IsBlockedUri(stream.http_request.uri) ||
                IsBlockedUserAgent(stream.http_request.user_agent)) {
                streams_.erase(key);  // Cleanup
                return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);  // IMMEDIATE
            }
        }
    }
    
    // Streaming pattern match sur body
    if (stream.http_request.headers_complete && payload_len > 0) {
        if (stream.matcher.AddFragmentAndMatch(payload, payload_len)) {
            // PATTERN MATCH → DROP
            streams_.erase(key);
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);  // IMMEDIATE
        }
    }
    
    // ACCEPT
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);  // IMMEDIATE
}
```

---

## 📊 Estimation de performance

### Latence par paquet (single-threaded inline)

| Opération | Temps | Cumulatif |
|-----------|-------|-----------|
| Early exit check | 0.001ms | 0.001ms |
| Hash lookup IP/Port | 0.005ms | 0.006ms |
| Stream lookup/create | 0.010ms | 0.016ms |
| HTTP parsing | 0.020ms | 0.036ms |
| Pattern matching (PCRE2-JIT) | 0.050ms | 0.086ms |
| Verdict | 0.001ms | 0.087ms |

**Total : ~0.1ms par paquet**

### Débit estimé

- **Paquets/seconde** : 1 / 0.0001 = **10,000 pps**
- **Requêtes HTTP** : Si requête = 5 paquets → **2,000 req/s**
- **Avec early exits** : 50% trafic = réponses → **4,000 req/s effective**

---

## 🔥 Optimisations supplémentaires

### 1. **Hyperscan** au lieu de PCRE2 (optionnel)
```cpp
// Hyperscan peut scanner 100+ patterns en parallèle
// Intel open-source, utilisé par Suricata
hs_database_t* db;
hs_compile_multi(patterns, flags, ids, count, HS_MODE_BLOCK, nullptr, &db, &compile_err);

// Scanning ultra rapide
hs_scan(db, data, len, 0, scratch, OnMatch, context);
```

**Gain** : 5-10x plus rapide que PCRE2 pour multi-patterns

### 2. **Memory Pool** pour streams
```cpp
// Évite malloc/free à chaque stream
template<typename T>
class MemoryPool {
    std::vector<T*> free_list_;
    std::vector<std::unique_ptr<T[]>> blocks_;
    
    T* Allocate() {
        if (free_list_.empty()) {
            // Alloue block de 1024 streams
            auto block = std::make_unique<T[]>(1024);
            for (int i = 0; i < 1024; i++) {
                free_list_.push_back(&block[i]);
            }
            blocks_.push_back(std::move(block));
        }
        T* obj = free_list_.back();
        free_list_.pop_back();
        return obj;
    }
};
```

### 3. **Affinity CPU** (optionnel multi-thread)
```cpp
// Si vraiment besoin de parallélisme:
// 1 thread par CPU core
// Chaque thread traite une NFQUEUE séparée
// iptables -A FORWARD -m cpu --cpu 0 -j NFQUEUE --queue-num 0
// iptables -A FORWARD -m cpu --cpu 1 -j NFQUEUE --queue-num 1
```

---

## 🎯 Plan d'implémentation

### Phase 1: Core Stream-Inline
- [ ] Supprimer workers/queues actuels
- [ ] Implémenter StreamKey + hash table
- [ ] Implémenter parsing HTTP incrémental (llhttp)
- [ ] Inline verdict dans callback NFQUEUE

### Phase 2: Streaming Pattern Matching
- [ ] Implémenter StreamingMatcher avec sliding window
- [ ] Intégrer PCRE2-JIT
- [ ] Tester avec patterns XSS/SQL

### Phase 3: Optimisations
- [ ] Ajouter memory pool
- [ ] Benchmarker PCRE2-JIT vs Hyperscan
- [ ] Cleanup timeout streams

### Phase 4: Testing
- [ ] Benchmark avec wrk
- [ ] Vérifier détection XSS/SQL
- [ ] Mesurer latence end-to-end

---

## 🚀 Résultat attendu

**Performance cible** :
- ✅ **4,000+ req/s** (avec détection L7)
- ✅ **Latence < 0.5ms** par requête
- ✅ **Détection complète** XSS, SQL injection, etc.
- ✅ **Single-threaded** (ou multi-thread optionnel)

**Plus rapide que l'actuel parce que** :
- Pas de queue → Pas de latence
- Pas de mutex → Pas de contention
- Streaming match → Verdict rapide
- Hash tables → O(1) lookups
