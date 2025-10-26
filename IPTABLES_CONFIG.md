# 🔥 CONFIGURATION IPTABLES OPTIMALE
## Pour tester Tiger-Fox sans filtrer les réponses

---

## ⚠️ PROBLÈME : Les réponses du serveur passent par le filtre

Actuellement, ta règle iptables filtre **TOUS** les paquets FORWARD :
```bash
sudo iptables -A FORWARD -i enp4s0f1 -o enp4s0f0 -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -i enp4s0f0 -o enp4s0f1 -j ACCEPT
```

**Problème** : Les réponses HTTP du serveur (10.10.2.20 → injector) passent aussi par NFQUEUE !

---

## ✅ SOLUTION : Filtrer seulement les NOUVELLES connexions

### Option 1 : Filtrer seulement l'aller (SYN + établi)
```bash
# Nettoyer
sudo iptables -F FORWARD

# Filtrer uniquement les paquets entrants de l'injector vers le serveur
sudo iptables -A FORWARD -i enp4s0f1 -o enp4s0f0 -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 0

# Accepter directement les réponses du serveur (pas de filtrage)
sudo iptables -A FORWARD -i enp4s0f0 -o enp4s0f1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Log pour débug
sudo iptables -A FORWARD -j LOG --log-prefix "FORWARD_DROP: "
```

### Option 2 : Filtrer seulement les SYN (nouvelles connexions TCP)
```bash
# Nettoyer
sudo iptables -F FORWARD

# Filtrer uniquement les SYN (début de connexion TCP)
sudo iptables -A FORWARD -i enp4s0f1 -o enp4s0f0 -p tcp --syn -j NFQUEUE --queue-num 0

# Accepter tout le reste directement
sudo iptables -A FORWARD -j ACCEPT
```

### Option 3 : Filtrer tout l'aller, accepter tout le retour
```bash
# Nettoyer
sudo iptables -F FORWARD

# Filtrer TOUS les paquets injector → serveur
sudo iptables -A FORWARD -i enp4s0f1 -o enp4s0f0 -j NFQUEUE --queue-num 0

# Accepter TOUS les paquets serveur → injector (SANS filtrage)
sudo iptables -A FORWARD -i enp4s0f0 -o enp4s0f1 -j ACCEPT
```

---

## 🎯 RECOMMANDATION : Option 3 (la plus simple)

Ta config actuelle est déjà correcte !
```bash
sudo iptables -A FORWARD -i enp4s0f1 -o enp4s0f0 -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -i enp4s0f0 -o enp4s0f1 -j ACCEPT
```

**C'est bon !** Les réponses du serveur (enp4s0f0 → enp4s0f1) ne passent PAS par NFQUEUE.

---

## 🔍 Vérifier que ça marche

```bash
# Voir les règles
sudo iptables -L FORWARD -n -v --line-numbers

# Compteurs de paquets
watch -n 1 'sudo iptables -L FORWARD -n -v'

# Voir les paquets qui passent dans NFQUEUE
sudo tcpdump -i enp4s0f1 -nn
```

---

## ⚠️ POURQUOI LES INTERFACES CHANGENT APRÈS REBOOT

Après reboot, iptables est vidé automatiquement. Les règles avec `*` signifient "toute interface".

**Solution : Sauvegarder les règles**
```bash
# Sauvegarder
sudo iptables-save > /etc/iptables/rules.v4

# Restaurer au boot
sudo iptables-restore < /etc/iptables/rules.v4
```

Ou installer `iptables-persistent` :
```bash
sudo apt install iptables-persistent
# Sauvegarde automatique au reboot
```

---

## 📊 TEST SIMPLE

```bash
# Terminal 1 : Lance tiger-fox
sudo ./build/tiger-fox --mode parallel --workers 3 --queue-num 0

# Terminal 2 : Envoie requêtes wrk
wrk -t 4 -c 500 -d 30s http://10.10.2.20

# Terminal 3 : Vérifie les compteurs iptables
watch -n 1 'sudo iptables -L FORWARD -n -v'
```

Tu dois voir :
- Ligne 1 (NFQUEUE) : Compteur qui augmente (paquets injecteur → serveur)
- Ligne 2 (ACCEPT) : Compteur qui augmente (paquets serveur → injecteur)

Si ligne 2 ne bouge pas → Problème de routing !
