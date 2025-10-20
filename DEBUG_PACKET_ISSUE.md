# DEBUG : Pourquoi les paquets ne passent plus ?

## 🚨 SYMPTÔME

```bash
ping 10.10.2.20
# 100% packet loss
```

## 🔍 TESTS À FAIRE

### Test 1 : Le filtre tourne-t-il ?

```bash
ps aux | grep tiger-fox
```

Si rien → Le filtre a crashé !

### Test 2 : Le filtre reçoit-il des paquets ?

Ajoute un printf dans TrueSequentialEngine :

```cpp
FilterResult TrueSequentialEngine::FilterPacket(const PacketData& packet) {
    std::cout << "PACKET RECEIVED: " << packet.src_ip << " -> " << packet.dst_ip << std::endl;
    // ...
}
```

Recompile et relance. Si tu ne vois RIEN → Le filtre ne reçoit pas de paquets !

### Test 3 : Le filtre bloque-t-il tout ?

Vérifie si TOUS les paquets sont DROP :

```cpp
FilterResult TrueSequentialEngine::FilterPacket(const PacketData& packet) {
    // ...
    std::cout << "RESULT: " << (matched ? "DROP" : "ACCEPT") << std::endl;
    // ...
}
```

Si tout est DROP → Bug dans la logique de matching !

### Test 4 : Le filtre répond-il à nfqueue ?

Dans `packet_handler.cpp`, vérifie que `nfq_set_verdict()` est appelé :

```cpp
std::cout << "VERDICT: " << verdict << " for packet" << std::endl;
nfq_set_verdict(qh, id, verdict, 0, nullptr);
```

Si pas de output → Le filtre ne répond pas !

## 🐛 BUGS POSSIBLES

### Bug 1 : Deadlock dans barrier

**Symptôme** : Le filtre ne crash pas mais ne répond plus

**Cause** : Un worker est bloqué dans `sync_barrier_.arrive_and_wait()`

**Solution** : Vérifier que TOUS les workers participent à la barrier

### Bug 2 : TrueSequentialEngine matche TOUT

**Symptôme** : Tous les paquets sont DROP même les ICMP ping

**Cause** : Logique de matching trop large

**Test** :
```bash
# Lancer avec fichier de règles VIDE
sudo ./build/tiger-fox --mode sequential --rules rules/empty.json --queue-num 0
```

Si ça marche → Les règles bloquent tout !

### Bug 3 : Conversion IP incorrecte

**Symptôme** : IPs mal parsées, donc aucun match, donc tout ACCEPT (ou pire, tout DROP)

**Test** : Ajoute debug dans MatchIPRule :

```cpp
std::cout << "Checking IP: " << std::hex << src_ip << " vs " << range.network << "/" << range.mask << std::endl;
```

### Bug 4 : Le filtre n'accepte RIEN par défaut

**Cause** : Peut-être que le code DROP par défaut au lieu d'ACCEPT ?

**Vérification** : Ligne 80 de true_sequential_engine.cpp :

```cpp
return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);  // ✅ Bon !
```

## 🎯 ACTION IMMÉDIATE

### Option 1 : Revenir à FastSequentialEngine temporairement

Pour vérifier si c'est TrueSequentialEngine le problème :

```cpp
// Dans tiger_system.cpp
if (mode_ == "sequential") {
    engine_ = std::make_unique<FastSequentialEngine>(rules_by_layer);  // Ancien, qui marche
    // engine_ = std::make_unique<TrueSequentialEngine>(rules_by_layer);
}
```

Recompile et teste. Si ça marche → TrueSequentialEngine a un bug !

### Option 2 : Test avec mode successive

```bash
sudo ./build/tiger-fox --mode successive --queue-num 0
```

Si ça marche → Le parallèle a un problème spécifique !

### Option 3 : Ajouter des logs partout

```cpp
// Ligne 46 de true_sequential_engine.cpp
FilterResult TrueSequentialEngine::FilterPacket(const PacketData& packet) {
    std::cout << "[TrueSeq] Filtering packet " << packet.src_ip << " -> " << packet.dst_ip 
              << " proto=" << (int)packet.protocol << std::endl;
    
    for (const Rule* rule : all_rules_) {
        bool matched = false;
        
        switch (rule->type) {
            case RuleType::IP_RANGE:
                matched = MatchIPRule(rule, packet);
                if (matched) {
                    std::cout << "[TrueSeq] IP MATCH! Rule " << rule->id << std::endl;
                }
                break;
            // ...
        }
        
        if (matched && rule->action == RuleAction::DROP) {
            std::cout << "[TrueSeq] DROP packet! Rule " << rule->id << std::endl;
            return FilterResult(RuleAction::DROP, rule->id, 0.0, rule->layer);
        }
    }
    
    std::cout << "[TrueSeq] ACCEPT packet (no match)" << std::endl;
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}
```

Ça va générer BEAUCOUP de logs, mais tu sauras EXACTEMENT ce qui se passe !

## 📊 CE QUE TU DOIS FAIRE MAINTENANT

1. **Teste si le filtre tourne** : `ps aux | grep tiger-fox`
2. **Regarde les logs** : Y a-t-il des erreurs ?
3. **Teste mode successive** : Pour isoler si c'est parallèle ou TrueSeq
4. **Si rien ne marche** : Reviens à FastSequentialEngine temporairement

Dis-moi ce que tu trouves ! 🔍
