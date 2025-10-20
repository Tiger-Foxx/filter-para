#include "true_sequential_engine.h"
#include "../utils.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>

TrueSequentialEngine::TrueSequentialEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_by_layer)
    : RuleEngine(rules_by_layer) {
    
    // Aplatir toutes les règles dans un seul vecteur
    // Ordre : L3 → L4 → L7 (comme dans le fichier JSON)
    
    size_t total_rules = 0;
    for (const auto& [layer, layer_rules] : rules_by_layer_) {
        total_rules += layer_rules.size();
    }
    
    all_rules_.reserve(total_rules);
    
    // L3 first
    if (rules_by_layer_.find(RuleLayer::L3) != rules_by_layer_.end()) {
        for (const auto& rule : rules_by_layer_.at(RuleLayer::L3)) {
            all_rules_.push_back(rule.get());
        }
    }
    
    // L4 second
    if (rules_by_layer_.find(RuleLayer::L4) != rules_by_layer_.end()) {
        for (const auto& rule : rules_by_layer_.at(RuleLayer::L4)) {
            all_rules_.push_back(rule.get());
        }
    }
    
    // L7 third
    if (rules_by_layer_.find(RuleLayer::L7) != rules_by_layer_.end()) {
        for (const auto& rule : rules_by_layer_.at(RuleLayer::L7)) {
            all_rules_.push_back(rule.get());
        }
    }
    
    std::cout << "   📊 TRUE Sequential mode: 1 thread, " << all_rules_.size() 
              << " rules (rule-by-rule traversal)" << std::endl;
}

FilterResult TrueSequentialEngine::FilterPacket(const PacketData& packet) {
    // Parcourir TOUTES les règles une par une
    // Early exit dès qu'un DROP est trouvé
    
    for (const Rule* rule : all_rules_) {
        bool matched = false;
        
        // Évaluer selon le type de règle
        switch (rule->type) {
            case RuleType::IP_RANGE:
                matched = MatchIPRule(rule, packet);
                break;
            
            case RuleType::PORT:
                matched = MatchPortRule(rule, packet);
                break;
            
            case RuleType::PATTERN:
                matched = MatchPatternRule(rule, packet);
                break;
            
            case RuleType::PROTOCOL:
            case RuleType::GEO:
            case RuleType::RATE_LIMIT:
                // Non implémenté pour l'instant
                matched = false;
                break;
        }
        
        // Si match et action DROP → early exit
        if (matched && rule->action == RuleAction::DROP) {
            return FilterResult(RuleAction::DROP, rule->id, 0.0, rule->layer);
        }
    }
    
    // Aucune règle ne matche → ACCEPT
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}

bool TrueSequentialEngine::MatchIPRule(const Rule* rule, const PacketData& packet) const {
    // Convertir les IPs string → uint32_t
    uint32_t src_ip = IPStringToUint32(packet.src_ip);
    uint32_t dst_ip = IPStringToUint32(packet.dst_ip);
    
    if (src_ip == 0 && dst_ip == 0) {
        return false;
    }
    
    // Vérifier chaque range de la règle
    for (const auto& range : rule->ip_ranges_) {
        // Check source IP
        if (src_ip != 0 && (src_ip & range.mask) == range.network) {
            return true;
        }
        
        // Check destination IP
        if (dst_ip != 0 && (dst_ip & range.mask) == range.network) {
            return true;
        }
    }
    
    return false;
}

bool TrueSequentialEngine::MatchPortRule(const Rule* rule, const PacketData& packet) const {
    // Vérifier si c'est une règle TCP ou UDP
    bool is_tcp = (rule->type_str.find("tcp") != std::string::npos);
    bool is_udp = (rule->type_str.find("udp") != std::string::npos);
    
    // Si la règle spécifie un protocole, vérifier la correspondance
    if (is_tcp && packet.protocol != IPPROTO_TCP) {
        return false;
    }
    if (is_udp && packet.protocol != IPPROTO_UDP) {
        return false;
    }
    
    // Vérifier chaque port de la règle
    for (const auto& port_str : rule->values) {
        uint16_t rule_port = static_cast<uint16_t>(std::stoi(port_str));
        
        // Check destination port
        if (packet.dst_port == rule_port) {
            return true;
        }
        
        // Check source port
        if (packet.src_port == rule_port) {
            return true;
        }
    }
    
    return false;
}

bool TrueSequentialEngine::MatchPatternRule(const Rule* rule, const PacketData& packet) const {
    // Pour L7, on ignore pour l'instant (pas de payload dans PacketData)
    // Dans une vraie implémentation, on checkerait le payload HTTP/DNS
    return false;
}
