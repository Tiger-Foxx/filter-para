#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>

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
    
    // Print summary of loaded rules
    static void PrintRulesSummary(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);

private:
    // Parse individual rule from JSON
    static std::unique_ptr<Rule> ParseRule(const nlohmann::json& rule_json);
    
    // Parse enum types from strings
    static RuleLayer ParseRuleLayer(int layer);
    static RuleType ParseRuleType(const std::string& type_str);
    static RuleAction ParseRuleAction(const std::string& action_str);
    
    // Validate rule consistency
    static bool ValidateRule(const std::unique_ptr<Rule>& rule);
    
    // Static lookup tables for parsing
    static const std::unordered_map<std::string, RuleType> rule_type_map_;
    static const std::unordered_map<std::string, RuleAction> rule_action_map_;
};

#endif // RULE_LOADER_H