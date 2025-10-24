# 🚀 Scripts d'Évaluation Tiger-Fox

## 📋 Deux Modes Disponibles

### 1️⃣ **Mode Automatique** (tous les tests d'un coup)
Lance automatiquement 11 tests : sequential + parallel (2,3,4,5,6,7,8,16 workers) + 2 bonus

**Filtreur:**
```bash
chmod +x eval.sh
./eval.sh
```

**Injecteur** (3 sec après le filtreur):
```bash
chmod +x eval_inj.sh
./eval_inj.sh
```

⏱️ **Durée totale:** ~15 minutes  
📁 **Résultats:** `filter_results_*/` et `injector_results_*/`

---

### 2️⃣ **Mode Manuel** (test par test)
Lance UN SEUL test que vous choisissez

**Filtreur:**
```bash
chmod +x eval_mini.sh

# Mode séquentiel
./eval_mini.sh sequential

# Mode parallèle avec 4 workers
./eval_mini.sh parallel 4
```

**Injecteur** (lancez-le dès que le filtreur affiche "Lancez maintenant"):
```bash
chmod +x eval_inj_mini.sh

# Mode séquentiel
./eval_inj_mini.sh sequential

# Mode parallèle avec 4 workers
./eval_inj_mini.sh parallel 4
```

⏱️ **Durée par test:** ~75 secondes  
📁 **Résultats:** `execution_mode_*/` et `inj_mode_*/`

---

## 🔧 Prérequis

### Filtreur:
```bash
sudo apt-get install -y sysstat linux-tools-$(uname -r) powerstat
```

### Injecteur:
```bash
sudo apt-get install -y wrk
```

---

## 📊 Données Collectées

### Filtreur:
- ✅ **CPU global** (tous les cœurs) → `cpu_all.csv`
- ✅ **CPU Tiger-Fox** (processus) → `cpu_app.csv`
- ✅ **CPU intervalles** (évolution) → `cpu_log_interval.csv`
- ⚡ **Énergie CPU** (Package, Cores, RAM) → `energy_cpu_watts.csv` + `energy_cpu_summary.csv`
- 🔋 **Énergie MACHINE** (totale) → `energy_machine_watts.csv` + `energy_machine_summary.csv`

### Injecteur:
- ✅ **Ping latences** → `ping_latencies.csv` + `ping_results.txt`
- ✅ **Wrk throughput** → `wrk_results.txt`
- ✅ **Wrk latences** → `wrk_latency_distribution.csv`
- ✅ **Résumé** → `summary.csv`

---

## 💡 Exemples d'Usage

### Test rapide d'un seul mode:
```bash
# Filtreur
./eval_mini.sh parallel 4

# Injecteur (dans un autre terminal)
./eval_inj_mini.sh parallel 4
```

### Évaluation complète (tous les modes):
```bash
# Filtreur
./eval.sh

# Injecteur (dans un autre terminal, 3 sec après)
./eval_inj.sh
```

---

## ⚠️ Synchronisation

**Mode Automatique:**
- Le filtreur fait une pause de **5 secondes** entre chaque test
- L'injecteur attend **7 secondes** après chaque test
- Total: **12 secondes** de marge pour la synchronisation

**Mode Manuel:**
- Lancez d'abord le **filtreur**
- Attendez le message "Lancez maintenant eval_inj_mini.sh"
- Lancez ensuite l'**injecteur**

---

## 🐛 En Cas de Problème

### Le filtreur ne démarre pas:
```bash
sudo pkill -9 tiger-fox
sudo iptables -F
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0
```

### L'injecteur ne peut pas pinguer:
```bash
# Vérifiez que le filtreur tourne
ssh filter-node "ps aux | grep tiger-fox"

# Testez la connectivité
ping 10.10.2.20
```

### Fichiers énergétiques vides:
```bash
# Vérifiez les logs bruts
cat energy_cpu_turbostat.log
cat energy_machine_powerstat.log

# Testez manuellement
sudo turbostat --show PkgWatt,CorWatt,RAMWatt sleep 5
sudo powerstat 1 5
```
