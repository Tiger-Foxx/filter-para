#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Forward declarations
enum class RuleLayer;
enum class RuleType;
enum class RuleAction;
struct Rule;

// Include rule_engine.h for complete definitions
#include "../engine/rule_engine.h"

// ============================================================
// RULE LOADER - JSON PARSING
// ============================================================

class RuleLoader {
public:
    // Load rules from JSON file
    static std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> 
        LoadRules(const std::string& file_path);
    
    // Validate rules file format
    static bool ValidateRulesFile(const std::string& file_path);

private:
    // JSON parsing helpers
    static std::unique_ptr<Rule> ParseRule(const nlohmann::json& rule_json);
    static RuleLayer ParseRuleLayer(int layer);
    static RuleType ParseRuleType(const std::string& type_str);
    static RuleAction ParseRuleAction(const std::string& action_str);
    
    // Rule validation
    static bool ValidateRule(const std::unique_ptr<Rule>& rule);
    
    // Statistics
    static void PrintRulesSummary(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    
    // Type mappings
    static const std::unordered_map<std::string, RuleType> rule_type_map_;
    static const std::unordered_map<std::string, RuleAction> rule_action_map_;
};

#endif // RULE_LOADER_H