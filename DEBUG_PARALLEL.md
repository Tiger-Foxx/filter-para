# 🐛 DEBUG MODE PARALLÈLE - LOGS DÉTAILLÉS

## Logs ajoutés pour diagnostiquer le problème

### 📍 Dans FilterPacket (thread principal)
```
[PARALLEL] 🔵 New packet: <src_ip>:<port> → <dst_ip>:<port>
[PARALLEL] 📢 Notifying 3 workers...
[PARALLEL] ⏳ Waiting for workers to finish...
[PARALLEL] 📊 Workers finished: X/3
[PARALLEL] ✅ All workers finished!
[PARALLEL] ✅ Verdict: ACCEPT  (ou ❌ DROP)
```

### 📍 Dans WorkerThreadLoop (threads workers)
```
[WORKER-0] 🚀 Thread started
[WORKER-0] 💤 Waiting for packet...
[WORKER-0] 👁️ Woke up!
[WORKER-0] 🔍 Processing packet...
[WORKER-0] 🔎 Checking rules...
[WORKER-0] 📝 Result: ACCEPT (ou DROP)
[WORKER-0] ✔️ Finished (count: X)
[WORKER-0] 📣 I'm the last one, notifying main thread!
```

---

## 🧪 Comment tester sur CloudLab

### Sur le nœud filter:

```bash
# Méthode 1: Script automatique
sudo ./test_parallel_debug.sh

# Méthode 2: Manuelle
sudo iptables -F FORWARD
sudo iptables -A FORWARD -i enp4s0f0 -o enp4s0f1 -j ACCEPT
sudo iptables -A FORWARD -i enp4s0f1 -o enp4s0f0 -j NFQUEUE --queue-num 0
sudo ./build/tiger-fox --mode parallel --workers 3 --queue-num 0 --verbose
```

### Sur le nœud injector:

```bash
# Test simple
ping 10.10.2.20

# Devrait voir sur filter:
# [PARALLEL] 🔵 New packet: 10.10.1.10:0 → 10.10.2.20:0
# [WORKER-0] 👁️ Woke up!
# [WORKER-1] 👁️ Woke up!
# [WORKER-2] 👁️ Woke up!
# ...
```

---

## 🔍 Scénarios de debug

### Scénario 1: Aucun log n'apparaît
**Symptôme**: Rien ne s'affiche après le démarrage

**Diagnostic**:
- ✅ Le programme est lancé?
- ✅ iptables est bien configuré?
- ✅ Le trafic arrive bien au filtre?

**Vérification**:
```bash
# Sur filter
sudo iptables -L -n -v  # Vérifier que des paquets passent
sudo tcpdump -i enp4s0f1 icmp  # Voir si les pings arrivent
```

### Scénario 2: Les logs s'arrêtent à "Waiting for workers"
**Symptôme**:
```
[PARALLEL] 📢 Notifying 3 workers...
[PARALLEL] ⏳ Waiting for workers to finish...
(blocage ici, pas de suite)
```

**Diagnostic**: Les workers ne se réveillent PAS
- Problème de condition_variable
- Les workers ne sont pas démarrés
- Deadlock sur packet_mutex_

**Logs attendus pour confirmer**:
```
[WORKER-0] 👁️ Woke up!  ← Si absent, workers ne voient pas notify_all()
```

### Scénario 3: Workers se réveillent mais ne finissent jamais
**Symptôme**:
```
[WORKER-0] 👁️ Woke up!
[WORKER-1] 👁️ Woke up!
[WORKER-2] 👁️ Woke up!
(blocage ici, pas de "Finished")
```

**Diagnostic**: Workers bloqués dans WorkerEvaluate ou FilterPacket

**Logs attendus**:
```
[WORKER-0] 🔍 Processing packet...
[WORKER-0] 🔎 Checking rules...
[WORKER-0] 📝 Result: ACCEPT
[WORKER-0] ✔️ Finished (count: 1)
```

### Scénario 4: Workers finissent mais thread principal bloqué
**Symptôme**:
```
[WORKER-0] ✔️ Finished (count: 1)
[WORKER-1] ✔️ Finished (count: 2)
[WORKER-2] ✔️ Finished (count: 3)
[WORKER-2] 📣 I'm the last one, notifying main thread!
(blocage ici, pas de "All workers finished")
```

**Diagnostic**: workers_done_cv_.notify_one() ne réveille pas le thread principal
- Problème avec workers_done_mutex_
- Le wait() n'est pas déclenché

---

## 🎯 Ce qu'on cherche à voir

### ✅ Séquence normale (ACCEPT):
```
[PARALLEL] 🔵 New packet: 10.10.1.10:0 → 10.10.2.20:0
[PARALLEL] 📢 Notifying 3 workers...
[WORKER-0] 👁️ Woke up!
[WORKER-1] 👁️ Woke up!
[WORKER-2] 👁️ Woke up!
[WORKER-0] 🔍 Processing packet...
[WORKER-1] 🔍 Processing packet...
[WORKER-2] 🔍 Processing packet...
[WORKER-0] 🔎 Checking rules...
[WORKER-1] 🔎 Checking rules...
[WORKER-2] 🔎 Checking rules...
[WORKER-0] 📝 Result: ACCEPT
[WORKER-1] 📝 Result: ACCEPT
[WORKER-2] 📝 Result: ACCEPT
[WORKER-0] ✔️ Finished (count: 1)
[WORKER-1] ✔️ Finished (count: 2)
[WORKER-2] ✔️ Finished (count: 3)
[WORKER-2] 📣 I'm the last one, notifying main thread!
[PARALLEL] ✅ All workers finished!
[PARALLEL] ✅ Verdict: ACCEPT
```

### ✅ Séquence avec DROP:
```
[PARALLEL] 🔵 New packet: 10.10.1.10:0 → 10.10.2.20:0
[PARALLEL] 📢 Notifying 3 workers...
[WORKER-0] 👁️ Woke up!
[WORKER-1] 👁️ Woke up!
[WORKER-2] 👁️ Woke up!
[WORKER-0] 🔍 Processing packet...
[WORKER-0] 🔎 Checking rules...
[WORKER-0] 📝 Result: DROP
[WORKER-0] 🏆 WON THE RACE - Rule: BLOCK_INJECTOR_TEST
[WORKER-1] 🔍 Processing packet...
[WORKER-2] 🔍 Processing packet...
[WORKER-1] ⏩ Skipping (another worker found DROP)
[WORKER-2] ⏩ Skipping (another worker found DROP)
[WORKER-0] ✔️ Finished (count: 1)
[WORKER-1] ✔️ Finished (count: 2)
[WORKER-2] ✔️ Finished (count: 3)
[WORKER-2] 📣 I'm the last one, notifying main thread!
[PARALLEL] ✅ All workers finished!
[PARALLEL] ❌ Verdict: DROP (rule: BLOCK_INJECTOR_TEST)
```

---

## 💡 Si ça ne marche toujours pas

Envoie-moi la sortie complète du programme avec `--verbose`, en particulier:
1. Les logs au démarrage (création des workers)
2. Les premiers logs quand tu envoies un ping
3. Où exactement ça bloque

Avec ces logs détaillés, on pourra identifier précisément le problème !
