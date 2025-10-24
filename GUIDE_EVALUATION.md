# 🎯 Guide d'Évaluation Automatique Tiger-Fox

## 📋 Prérequis à Installer

### Sur le nœud FILTREUR :
```bash
# Outils de mesure CPU
sudo apt-get update
sudo apt-get install -y sysstat

# Outil de mesure énergétique (RECOMMANDÉ)
sudo apt-get install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)

# Vérification
mpstat -V
turbostat --version  # Doit fonctionner avec sudo
```

### Sur le nœud INJECTEUR :
```bash
# Outil de benchmark HTTP
sudo apt-get update
sudo apt-get install -y wrk

# Vérification
wrk --version
```

---

## 🚀 Procédure d'Évaluation Complète

### Étape 1️⃣ : Démarrer sur le FILTREUR
```bash
ssh filter-node
cd /users/The_Fox/filter-para

# Donner les permissions d'exécution
chmod +x eval.sh

# Lancer l'évaluation automatique
./eval.sh
```

**Ce script va automatiquement :**
- ✅ Tester le mode **sequential**
- ✅ Tester le mode **parallel** avec 2, 3, 4, 5, 6, 7, 8, et 16 workers
- ✅ Effectuer 2 tests bonus avec charge doublée (sequential + parallel 4 workers)
- ✅ Mesurer CPU (global, par cœur, par intervalle)
- ✅ Mesurer l'énergie avec `turbostat` (Package, Cores, RAM en Watts)
- ✅ Créer des dossiers organisés avec tous les CSV/logs
- ✅ Arrêter proprement Tiger-Fox entre chaque test

**Durée totale : environ 15 minutes** (11 tests × ~75 secondes)

---

### Étape 2️⃣ : Démarrer sur l'INJECTEUR (3 secondes après le filtreur)

**Ouvrez un autre terminal pendant que le filtreur tourne :**

```bash
ssh injector-node
cd /users/The_Fox/filter-para

# Donner les permissions d'exécution
chmod +x eval_inj.sh

# Lancer l'évaluation automatique
./eval_inj.sh
```

**Ce script va automatiquement :**
- ✅ Synchroniser avec le filtreur (attend 3s au début de chaque test)
- ✅ Tester avec les mêmes modes (sequential, parallel 2-16 workers)
- ✅ Effectuer **PING** pendant 20s
- ✅ Effectuer **WRK** pendant 50s
  - Tests normaux : `-t4 -c500` (4 threads, 500 connexions)
  - Tests bonus : `-t8 -c1000` (8 threads, 1000 connexions)
- ✅ Extraire automatiquement les statistiques (latence, req/s, etc.)
- ✅ Créer des fichiers CSV formatés
- ✅ Générer un résumé global

**Durée totale : synchronisée avec le filtreur (~15 minutes)**

---

## 📊 Structure des Résultats

### Sur le FILTREUR :
```
filter_results_YYYYMMDD_HHMMSS/
├── test_01_sequential/
│   ├── cpu_all.csv                 # CPU global et par cœur
│   ├── cpu_app.csv                 # CPU de Tiger-Fox
│   ├── cpu_percent_intervals.csv   # CPU à intervalles (1s)
│   ├── energy_watts.csv            # Package;Core;RAM en Watts
│   ├── energy_summary.csv          # Consommation moyenne
│   ├── energy_turbostat.log        # Log brut turbostat
│   ├── tiger_fox_output.log        # Logs de Tiger-Fox
│   └── test_metadata.txt           # Métadonnées du test
├── test_02_parallel_02_workers/
├── test_03_parallel_03_workers/
├── ...
├── test_09_parallel_16_workers/
├── test_bonus_sequential/
└── test_bonus_parallel_4_workers/
```

### Sur l'INJECTEUR :
```
injector_results_YYYYMMDD_HHMMSS/
├── test_01_sequential/
│   ├── ping_results.txt            # Résultats bruts ping
│   ├── ping_latencies.csv          # Latences extraites (ms)
│   ├── wrk_results.txt             # Résultats bruts wrk
│   ├── wrk_latency_distribution.csv # Distribution des latences
│   ├── summary.csv                 # Résumé des métriques
│   └── test_metadata.txt           # Métadonnées du test
├── test_02_parallel_02_workers/
├── ...
├── test_bonus_sequential/
├── test_bonus_parallel_4_workers/
└── global_summary.csv              # RÉSUMÉ DE TOUS LES TESTS
```

---

## 📥 Récupération des Résultats

### Depuis votre machine locale :

```bash
# Récupérer les résultats du filtreur
scp -r filter-node:/users/The_Fox/filter-para/filter_results_* ./

# Récupérer les résultats de l'injecteur
scp -r injector-node:/users/The_Fox/filter-para/injector_results_* ./
```

---

## 📈 Analyse des Résultats

Une fois les deux dossiers récupérés :

```bash
# Mettre à jour le script d'analyse si nécessaire
python3 analyze_results.py
```

Le script générera les graphiques :
- 📊 `graph_ping_latencies.png` - Évolution des latences ICMP
- 📊 `graph_wrk_requests_per_sec.png` - Throughput HTTP
- 📊 `graph_wrk_latencies.png` - Latences HTTP
- 📊 `graph_cpu_system_intervals.png` - Évolution CPU
- ⚡ `graph_energy_consumption.png` - **NOUVEAU** : Consommation énergétique

---

## ⚠️ Gestion des Erreurs

### Si un test échoue :

**Symptôme : Tiger-Fox ne démarre pas**
```bash
# Vérifier les logs
cat filter_results_*/test_XX_*/tiger_fox_output.log

# Nettoyer les processus zombies
sudo pkill -9 tiger-fox
sudo iptables -F
```

**Symptôme : L'injecteur ne peut pas pinguer le serveur**
```bash
# Vérifier la connectivité
ping 10.10.2.20

# Vérifier que le filtreur est actif
ssh filter-node "ps aux | grep tiger-fox"
```

**Symptôme : turbostat ne fonctionne pas**
```bash
# Installer le bon kernel tools
sudo apt-get install linux-tools-$(uname -r)

# Ou désactiver temporairement (le script continuera sans)
```

### Redémarrer proprement :

```bash
# Sur le filtreur
sudo pkill -9 tiger-fox
sudo iptables -F
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0

# Relancer
./eval.sh
```

---

## 💡 Conseils

1. **Lancez d'abord le filtreur**, attendez 2-3 secondes, puis lancez l'injecteur
2. Les scripts sont **synchronisés automatiquement** grâce aux marges de temps
3. **Ne touchez à rien** pendant l'exécution (~15 minutes)
4. À la fin, vous aurez **11 tests complets** :
   - 1 sequential
   - 8 parallel (2, 3, 4, 5, 6, 7, 8, 16 workers)
   - 2 bonus (sequential + parallel 4 workers avec charge doublée)
5. Les fichiers sont **bien formatés en CSV** pour analyse facile

---

## 📝 Résumé des Métriques Collectées

### Côté FILTREUR :
- ✅ **CPU global** : % user, system, idle par cœur
- ✅ **CPU Tiger-Fox** : % utilisé par le processus
- ✅ **Énergie** : Watts (Package, Cores, RAM) avec moyenne
- ✅ **Logs** : Sorties de Tiger-Fox pour debug

### Côté INJECTEUR :
- ✅ **Ping** : min, avg, max, packet loss
- ✅ **Wrk Throughput** : req/s, transfer/s
- ✅ **Wrk Latency** : avg, max, distribution (50%, 75%, 90%, 99%)
- ✅ **Résumé global** : Toutes les métriques dans un CSV

---

## 🎓 Pour le Rapport

Les scripts génèrent **tout ce dont vous avez besoin** :

1. **Graphiques** via `analyze_results.py`
2. **Tableaux** via les fichiers `summary.csv` et `global_summary.csv`
3. **Analyse énergétique** via `energy_summary.csv`
4. **Comparaison modes** : Sequential vs Parallel (2-16 workers)
5. **Impact charge** : Tests normaux vs tests bonus

Bon courage ! 🚀
