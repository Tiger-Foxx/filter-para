#include "rule_loader.h"
#include "../engine/rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

// ============================================================
// STATIC LOOKUP TABLES
// ============================================================
const std::unordered_map<std::string, RuleType> RuleLoader::rule_type_map_ = {
    // L3 Rules
    {"ip_src_in", RuleType::IP_SRC_IN},
    {"ip_dst_in", RuleType::IP_DST_IN},
    {"ip_src_country", RuleType::IP_SRC_COUNTRY},
    
    // L4 Rules
    {"tcp_dst_port", RuleType::TCP_DST_PORT},
    {"tcp_dst_port_not_in", RuleType::TCP_DST_PORT_NOT_IN},
    {"udp_dst_port", RuleType::UDP_DST_PORT},
    {"tcp_flags", RuleType::TCP_FLAGS},
    
    // L7 Rules
    {"http_uri_regex", RuleType::HTTP_URI_REGEX},
    {"http_header_contains", RuleType::HTTP_HEADER_CONTAINS},
    {"http_method", RuleType::HTTP_METHOD},
    {"http_payload_regex", RuleType::HTTP_PAYLOAD_REGEX},
    {"dns_query_contains", RuleType::DNS_QUERY_CONTAINS}
};

const std::unordered_map<std::string, RuleAction> RuleLoader::rule_action_map_ = {
    {"drop", RuleAction::DROP},
    {"accept", RuleAction::ACCEPT},
    {"reject", RuleAction::REJECT}
};

// ============================================================
// MAIN LOADING FUNCTION
// ============================================================
std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> 
RuleLoader::LoadRules(const std::string& file_path) {
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer;
    
    try {
        std::cout << "📋 Loading rules from: " << file_path << std::endl;
        
        // Read JSON file
        std::ifstream file(file_path);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open rules file: " + file_path);
        }
        
        nlohmann::json json_data;
        file >> json_data;
        file.close();
        
        // Initialize layer containers
        rules_by_layer[RuleLayer::L3] = std::vector<std::unique_ptr<Rule>>();
        rules_by_layer[RuleLayer::L4] = std::vector<std::unique_ptr<Rule>>();
        rules_by_layer[RuleLayer::L7] = std::vector<std::unique_ptr<Rule>>();
        
        // Parse rules array
        size_t total_rules = 0;
        size_t valid_rules = 0;
        
        if (json_data.contains("rules") && json_data["rules"].is_array()) {
            for (const auto& rule_json : json_data["rules"]) {
                total_rules++;
                
                try {
                    auto rule = ParseRule(rule_json);
                    if (rule && ValidateRule(rule)) {
                        rules_by_layer[rule->layer].push_back(std::move(rule));
                        valid_rules++;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "⚠️  Warning: Skipping invalid rule " << total_rules 
                              << ": " << e.what() << std::endl;
                }
            }
        } else {
            throw std::runtime_error("Invalid rules file format: missing 'rules' array");
        }
        
        std::cout << "✅ Loaded " << valid_rules << "/" << total_rules << " rules successfully" << std::endl;
        
        // Print summary
        PrintRulesSummary(rules_by_layer);
        
        return rules_by_layer;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error loading rules: " << e.what() << std::endl;
        throw;
    }
}

// ============================================================
// RULE PARSING
// ============================================================
std::unique_ptr<Rule> RuleLoader::ParseRule(const nlohmann::json& rule_json) {
    auto rule = std::make_unique<Rule>();
    
    // Parse required fields
    if (!rule_json.contains("id") || !rule_json["id"].is_string()) {
        throw std::runtime_error("Missing or invalid rule 'id'");
    }
    rule->id = rule_json["id"];
    
    if (!rule_json.contains("layer") || !rule_json["layer"].is_number_integer()) {
        throw std::runtime_error("Missing or invalid rule 'layer' for rule: " + rule->id);
    }
    rule->layer = ParseRuleLayer(rule_json["layer"]);
    
    if (!rule_json.contains("type") || !rule_json["type"].is_string()) {
        throw std::runtime_error("Missing or invalid rule 'type' for rule: " + rule->id);
    }
    rule->type = ParseRuleType(rule_json["type"]);
    
    if (!rule_json.contains("action") || !rule_json["action"].is_string()) {
        throw std::runtime_error("Missing or invalid rule 'action' for rule: " + rule->id);
    }
    rule->action = ParseRuleAction(rule_json["action"]);
    
    if (!rule_json.contains("values") || !rule_json["values"].is_array()) {
        throw std::runtime_error("Missing or invalid rule 'values' for rule: " + rule->id);
    }
    
    // Parse values array (can be strings or numbers)
    for (const auto& value : rule_json["values"]) {
        if (value.is_string()) {
            rule->values.push_back(value);
        } else if (value.is_number()) {
            rule->values.push_back(std::to_string(value.get<int>()));
        } else {
            std::cerr << "⚠️  Warning: Skipping non-string/non-number value in rule " 
                      << rule->id << std::endl;
        }
    }
    
    // Parse optional field (for http_header_contains)
    if (rule_json.contains("field") && rule_json["field"].is_string()) {
        rule->field = rule_json["field"];
    }
    
    // Pre-compile patterns and IP ranges for performance
    rule->CompilePatterns();
    rule->CompileIPRanges();
    
    return rule;
}

// ============================================================
// ENUM PARSING
// ============================================================
RuleLayer RuleLoader::ParseRuleLayer(int layer) {
    switch (layer) {
        case 3: return RuleLayer::L3;
        case 4: return RuleLayer::L4;
        case 7: return RuleLayer::L7;
        default:
            throw std::runtime_error("Invalid rule layer: " + std::to_string(layer) + 
                                   " (must be 3, 4, or 7)");
    }
}

RuleType RuleLoader::ParseRuleType(const std::string& type_str) {
    auto it = rule_type_map_.find(type_str);
    if (it == rule_type_map_.end()) {
        throw std::runtime_error("Unknown rule type: " + type_str);
    }
    return it->second;
}

RuleAction RuleLoader::ParseRuleAction(const std::string& action_str) {
    auto it = rule_action_map_.find(action_str);
    if (it == rule_action_map_.end()) {
        throw std::runtime_error("Unknown rule action: " + action_str);
    }
    return it->second;
}

// ============================================================
// RULE VALIDATION
// ============================================================
bool RuleLoader::ValidateRule(const std::unique_ptr<Rule>& rule) {
    if (!rule) {
        return false;
    }
    
    // Check required fields
    if (rule->id.empty()) {
        std::cerr << "⚠️  Warning: Rule has empty ID" << std::endl;
        return false;
    }
    
    if (rule->values.empty()) {
        std::cerr << "⚠️  Warning: Rule " << rule->id << " has no values" << std::endl;
        return false;
    }
    
    // Validate rule type against layer
    bool valid_combination = false;
    
    switch (rule->layer) {
        case RuleLayer::L3:
            valid_combination = (rule->type == RuleType::IP_SRC_IN ||
                               rule->type == RuleType::IP_DST_IN ||
                               rule->type == RuleType::IP_SRC_COUNTRY);
            break;
            
        case RuleLayer::L4:
            valid_combination = (rule->type == RuleType::TCP_DST_PORT ||
                               rule->type == RuleType::TCP_DST_PORT_NOT_IN ||
                               rule->type == RuleType::UDP_DST_PORT ||
                               rule->type == RuleType::TCP_FLAGS);
            break;
            
        case RuleLayer::L7:
            valid_combination = (rule->type == RuleType::HTTP_URI_REGEX ||
                               rule->type == RuleType::HTTP_HEADER_CONTAINS ||
                               rule->type == RuleType::HTTP_METHOD ||
                               rule->type == RuleType::HTTP_PAYLOAD_REGEX ||
                               rule->type == RuleType::DNS_QUERY_CONTAINS);
            break;
    }
    
    if (!valid_combination) {
        std::cerr << "⚠️  Warning: Rule " << rule->id 
                  << " has invalid type/layer combination" << std::endl;
        return false;
    }
    
    // Additional validation for specific rule types
    if (rule->type == RuleType::HTTP_HEADER_CONTAINS && rule->field.empty()) {
        std::cerr << "⚠️  Warning: Rule " << rule->id 
                  << " (http_header_contains) missing 'field' parameter" << std::endl;
        return false;
    }
    
    return true;
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
void RuleLoader::PrintRulesSummary(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules) {
    std::cout << "\n📊 Rules Summary:" << std::endl;
    
    size_t total_rules = 0;
    for (const auto& [layer, layer_rules] : rules) {
        size_t count = layer_rules.size();
        total_rules += count;
        
        std::string layer_name;
        switch (layer) {
            case RuleLayer::L3: layer_name = "L3 (Network)"; break;
            case RuleLayer::L4: layer_name = "L4 (Transport)"; break;
            case RuleLayer::L7: layer_name = "L7 (Application)"; break;
        }
        
        std::cout << "   " << layer_name << ": " << count << " rules" << std::endl;
        
        // Show breakdown by rule type for this layer
        std::unordered_map<RuleType, int> type_counts;
        for (const auto& rule : layer_rules) {
            type_counts[rule->type]++;
        }
        
        for (const auto& [type, count] : type_counts) {
            std::string type_name;
            switch (type) {
                case RuleType::IP_SRC_IN: type_name = "IP Source"; break;
                case RuleType::IP_DST_IN: type_name = "IP Destination"; break;
                case RuleType::IP_SRC_COUNTRY: type_name = "IP Country"; break;
                case RuleType::TCP_DST_PORT: type_name = "TCP Port"; break;
                case RuleType::TCP_DST_PORT_NOT_IN: type_name = "TCP Port (exclude)"; break;
                case RuleType::UDP_DST_PORT: type_name = "UDP Port"; break;
                case RuleType::TCP_FLAGS: type_name = "TCP Flags"; break;
                case RuleType::HTTP_URI_REGEX: type_name = "HTTP URI"; break;
                case RuleType::HTTP_HEADER_CONTAINS: type_name = "HTTP Header"; break;
                case RuleType::HTTP_METHOD: type_name = "HTTP Method"; break;
                case RuleType::HTTP_PAYLOAD_REGEX: type_name = "HTTP Payload"; break;
                case RuleType::DNS_QUERY_CONTAINS: type_name = "DNS Query"; break;
            }
            std::cout << "     - " << type_name << ": " << count << std::endl;
        }
    }
    
    std::cout << "   Total rules: " << total_rules << std::endl;
    std::cout << std::endl;
}

bool RuleLoader::ValidateRulesFile(const std::string& file_path) {
    try {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            std::cerr << "❌ Cannot open rules file: " << file_path << std::endl;
            return false;
        }
        
        nlohmann::json json_data;
        file >> json_data;
        file.close();
        
        if (!json_data.contains("rules") || !json_data["rules"].is_array()) {
            std::cerr << "❌ Invalid rules file format: missing 'rules' array" << std::endl;
            return false;
        }
        
        std::cout << "✅ Rules file format is valid" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error validating rules file: " << e.what() << std::endl;
        return false;
    }
}