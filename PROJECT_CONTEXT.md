# 📋 RÉSUMÉ DU PROJET TIGER-FOX

## 🎯 Objectif Global
Système de **filtrage réseau haute performance** pour recherche académique (Master Cybersécurité).
Comparer 3 architectures de filtrage pour identifier les gains réels du parallélisme.

---

## 🏗️ ARCHITECTURE GLOBALE

```
Réseau (injector)
       ↓
   iptables (NFQUEUE)
       ↓
   PacketHandler (lit NFQUEUE)
       ↓
   Parse Packet (IP/TCP/UDP)
       ↓
   RuleEngine (FilterPacket)
       ↓
   Verdict (ACCEPT/DROP)
       ↓
   nfq_set_verdict()
       ↓
   Réseau (receiver)
```

---

## 📊 TROIS MODES IMPLÉMENTÉS

### 1. SEQUENTIAL (Baseline)
- **1 thread** unique
- **24 règles** à checker séquentiellement
- **Hash tables** pour O(1) lookups (IP, ports)
- **Performance attendue** : ~2000-3000 req/s

**Fichier** : `src/engine/fast_sequential_engine.cpp`

### 2. SUCCESSIVE (Idée du professeur)
- **3 workers** exécutant UN APRÈS L'AUTRE
- Worker 1 → Worker 2 → Worker 3
- Chaque worker a **8 règles**
- **Pipeline séquentiel** : pas de parallélisme réel

**Fichier** : `src/engine/successive_engine.cpp`

### 3. PARALLEL (Notre recherche)
- **3 workers** exécutant EN PARALLÈLE
- Chaque worker a **8 règles** (partitionnées)
- **Évaluation simultanée** du même paquet
- **Logique ET** : un DROP suffit pour rejeter

**Fichier** : `src/engine/true_parallel_engine.cpp` ← **PROBLÈME ICI**

---

## 🔍 DÉTAILS TECHNIQUES

### Règles de Filtrage
```json
{
  "rule_id": "BLOCK_SSH",
  "action": "DROP",
  "layer": "L4",
  "protocol": "TCP",
  "src_ip": "10.10.1.10",
  "dst_port": 22,
  "description": "Block SSH from injector"
}
```

**Types de règles** :
- L3 : IP source/destination, ranges
- L4 : TCP/UDP ports, flags

**Pas de règles L7** : pas de DPI, pas de regex, juste IP/port pour vitesse max

### PacketData Structure
```cpp
struct PacketData {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;  // "TCP", "UDP", "ICMP"
    // Pas de payload analysis
};
```

### FilterResult
```cpp
struct FilterResult {
    RuleAction action;      // ACCEPT ou DROP
    std::string rule_id;    // Règle qui a matché (si DROP)
    double match_time_us;   // Temps d'évaluation
    RuleLayer layer;        // L3 ou L4
};
```

---

## 🚀 INFRASTRUCTURE DE TEST

### CloudLab Setup
```
[injector] ←→ [filter] ←→ [receiver]
10.10.1.10    10.10.1.1    10.10.2.20
              10.10.2.1
```

**Filter node** :
- Interface eno2 : vers injector
- Interface enp5s0f0 : vers receiver
- IP forwarding enabled
- iptables NFQUEUE rule

### Benchmark avec wrk
```bash
# Sur injector
wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/
```

**Métriques collectées** :
- Requests/sec
- Latency (p50, p99)
- Packets dropped (%)
- CPU usage

---

## 📝 FICHIERS IMPORTANTS

### Moteurs
- `src/engine/rule_engine.h` - Interface abstraite
- `src/engine/fast_sequential_engine.cpp` - Mode séquentiel (baseline)
- `src/engine/successive_engine.cpp` - Mode successive
- `src/engine/true_parallel_engine.cpp` - Mode parallèle ← **À OPTIMISER**

### Handlers
- `src/handlers/packet_handler.h/.cpp` - Interface NFQUEUE

### Loaders
- `src/loaders/rule_loader.cpp` - Parse JSON rules

### Utils
- `src/utils.h/.cpp` - ParsePacket(), helper functions

### Main
- `src/main.cpp` - Entry point, argument parsing
- `src/tiger_system.cpp` - Orchestration

---

## 🔢 STATISTIQUES ACTUELLES

### Mode Sequential
- ✅ Fonctionne correctement
- ✅ ~2500-3000 req/s
- ✅ Latence stable

### Mode Successive
- ✅ Fonctionne correctement
- ⚠️ Légèrement plus lent que sequential (overhead)
- ✅ Pas de bugs

### Mode Parallel
- ❌ **PROBLÈME** : implémentation actuelle à valider
- ❓ Performance inconnue (pas encore testé en production)
- ❓ Synchronisation optimale ?

---

## 🎓 QUESTIONS DE RECHERCHE

1. **Le partitionnement des règles donne-t-il un speedup réel ?**
   - Théorie : 3x plus rapide (3 workers, 1/3 des règles chacun)
   - Réalité : overhead de synchronisation à mesurer

2. **Quel est le coût de la synchronisation ?**
   - Condition variables vs autres primitives
   - Impact sur la latence

3. **Early exit fonctionne-t-il bien ?**
   - Si un worker trouve DROP rapidement, les autres arrêtent-ils efficacement ?

4. **Scalabilité : N workers ?**
   - Est-ce que ça scale à 4, 8, 16 workers ?
   - Ou est-ce que 3 est le sweet spot ?

5. **Comparaison avec Suricata/Snort**
   - Pouvons-nous battre les IDS commerciaux ?
   - Avec quelle architecture ?

---

## 🛠️ BUILD SYSTEM

### CMakeLists.txt
```cmake
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -flto")

add_executable(tiger-fox
    src/main.cpp
    src/tiger_system.cpp
    src/engine/fast_sequential_engine.cpp
    src/engine/successive_engine.cpp
    src/engine/true_parallel_engine.cpp
    src/handlers/packet_handler.cpp
    ...
)

target_link_libraries(tiger-fox
    netfilter_queue
    pthread
    atomic
)
```

### Compilation
```bash
sudo ./build.sh
# Génère : build/tiger-fox (binaire)
```

---

## 📦 DÉPENDANCES

### Système
- libnetfilter-queue-dev
- iptables
- gcc/g++ 11+

### C++ Standard
- C++17 minimum
- C++20 souhaitable (std::barrier, std::jthread)

### Bibliothèques Optionnelles (à discuter)
- Intel TBB (Thread Building Blocks)
- Boost.Asio / Boost.Lockfree
- Folly (Facebook)
- DPDK (si on veut bypasser le kernel)

---

## 🔬 MÉTHODOLOGIE DE RECHERCHE

### Phase 1 : Implémentation
- ✅ Mode sequential (fait)
- ✅ Mode successive (fait)
- 🚧 Mode parallel (en cours d'optimisation)

### Phase 2 : Validation
- Test fonctionnel (paquets passent/bloqués correctement)
- Test de charge (wrk)
- Test de stabilité (longue durée)

### Phase 3 : Benchmarking
- Mesurer req/s pour chaque mode
- Mesurer latence (p50, p99, max)
- Mesurer CPU usage
- Mesurer cache misses (perf)

### Phase 4 : Analyse
- Calculer le speedup réel
- Identifier les bottlenecks
- Expliquer les différences théorie vs réalité

### Phase 5 : Rédaction
- Mémoire de master
- Graphiques et tableaux comparatifs
- Conclusions scientifiques

---

## 🎯 CRITÈRES DE SUCCÈS

### Performance
- ✅ Mode parallel > mode sequential (sinon échec)
- ✅ Battre Suricata (~2500 req/s)
- ✅ Latence raisonnable (<10ms p99)

### Qualité du Code
- ✅ Pas de bugs (pas de race conditions)
- ✅ Pas de memory leaks
- ✅ Code propre et commenté

### Recherche
- ✅ Résultats reproductibles
- ✅ Analyse scientifique rigoureuse
- ✅ Contribution à l'état de l'art

---

## PAS de CONTRAINTES À  RESPECTER



---

**Ce contexte devrait suffire pour qu'une IA experte comprenne parfaitement le projet et propose une solution optimale !** 🎓
