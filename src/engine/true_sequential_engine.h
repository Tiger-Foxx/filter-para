#pragma once

#include "rule_engine.h"
#include <vector>
#include <memory>

/**
 * TrueSequentialEngine - Moteur séquentiel VRAI (parcourt toutes les règles)
 * 
 * Architecture :
 * - 1 seul thread
 * - Parcourt TOUTES les règles une par une (comme le parallèle)
 * - Early exit dès qu'un DROP est trouvé
 * - Pas de hash tables, pas de triche !
 * 
 * C'est la VRAIE baseline pour comparaison juste avec le parallèle !
 */
class TrueSequentialEngine : public RuleEngine {
public:
    /**
     * Constructeur
     * 
     * @param rules_by_layer Toutes les règles organisées par couche
     */
    TrueSequentialEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules_by_layer);
    
    /**
     * Filtre un paquet en parcourant TOUTES les règles
     * Early exit dès qu'un DROP est trouvé
     */
    FilterResult FilterPacket(const PacketData& packet) override;

private:
    // Toutes les règles dans un seul vecteur (ordre L3 → L4 → L7)
    std::vector<Rule*> all_rules_;
    
    // Méthodes d'évaluation par type de règle
    bool MatchIPRule(const Rule* rule, const PacketData& packet) const;
    bool MatchPortRule(const Rule* rule, const PacketData& packet) const;
    bool MatchPatternRule(const Rule* rule, const PacketData& packet) const;
};
