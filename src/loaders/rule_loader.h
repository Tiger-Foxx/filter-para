#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>  // ✅ Include direct au lieu de forward declaration

// Forward declarations
enum class RuleLayer;
enum class RuleType;
enum class RuleAction;
struct Rule;

// ============================================================
// RULE LOADER - JSON PARSING
// ============================================================
class RuleLoader {
public:
    // Main loading function
    static std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> 
        LoadRules(const std::string& file_path);
    
    // Validation
    static bool ValidateRulesFile(const std::string& file_path);
    
    // Statistics
    static void PrintRulesSummary(const std::unordered_map<RuleLayer, 
                                  std::vector<std::unique_ptr<Rule>>>& rules);

private:
    using json = nlohmann::json;
    
    // Parsing helpers
    static std::unique_ptr<Rule> ParseRule(const json& rule_json);
    static RuleLayer ParseRuleLayer(int layer);
    static RuleType ParseRuleType(const std::string& type_str);
    static RuleAction ParseRuleAction(const std::string& action_str);
    
    // Validation
    static bool ValidateRule(const std::unique_ptr<Rule>& rule);
    
    // Lookup tables
    static const std::unordered_map<std::string, RuleType> rule_type_map_;
    static const std::unordered_map<std::string, RuleAction> rule_action_map_;
};

#endif // RULE_LOADER_H