#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Forward declarations
struct Rule;
enum class RuleLayer;
enum class RuleType;
enum class RuleAction;

class RuleLoader {
public:
    // Load rules from JSON file
    static std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> 
        LoadRules(const std::string& file_path);
    
    // Validate rules file format
    static bool ValidateRulesFile(const std::string& file_path);

private:
    // Parse single rule from JSON
    static std::unique_ptr<Rule> ParseRule(const nlohmann::json& rule_json);
    
    // Parse rule components
    static RuleLayer ParseRuleLayer(int layer);
    static RuleType ParseRuleType(const std::string& type_str);
    static RuleAction ParseRuleAction(const std::string& action_str);
    
    // Validate rule
    static bool ValidateRule(const std::unique_ptr<Rule>& rule);
    
    // Print summary
    static void PrintRulesSummary(
        const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules
    );
    
    // Type mappings
    static const std::unordered_map<std::string, RuleType> rule_type_map_;
    static const std::unordered_map<std::string, RuleAction> rule_action_map_;
};