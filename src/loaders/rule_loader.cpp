#include "rule_loader.h"
#include "../engine/rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <fstream>
#include <stdexcept>

// Static member definitions
const std::unordered_map<std::string, RuleType> RuleLoader::rule_type_map_ = {
    // Types génériques
    {"ip_range", RuleType::IP_RANGE},
    {"port", RuleType::PORT},
    {"protocol", RuleType::PROTOCOL},
    {"pattern", RuleType::PATTERN},
    {"geo", RuleType::GEO},
    {"rate_limit", RuleType::RATE_LIMIT},
    
    // L3 - Types IP spécifiques
    {"ip_src_in", RuleType::IP_RANGE},
    {"ip_dst_in", RuleType::IP_RANGE},
    {"ip_src_range", RuleType::IP_RANGE},
    {"ip_dst_range", RuleType::IP_RANGE},
    {"ip_src_country", RuleType::GEO},
    {"ip_dst_country", RuleType::GEO},
    
    // L4 - Types port/protocole spécifiques
    {"tcp_src_port", RuleType::PORT},
    {"tcp_dst_port", RuleType::PORT},
    {"udp_src_port", RuleType::PORT},
    {"udp_dst_port", RuleType::PORT},
    {"tcp_flags", RuleType::PROTOCOL},
    {"icmp_type", RuleType::PROTOCOL},
    
    // L7 - Types HTTP/pattern spécifiques
    {"http_uri_regex", RuleType::PATTERN},
    {"http_uri_contains", RuleType::PATTERN},
    {"http_method", RuleType::PATTERN},
    {"http_header_contains", RuleType::PATTERN},
    {"http_header_regex", RuleType::PATTERN},
    {"http_payload_regex", RuleType::PATTERN},
    {"http_user_agent", RuleType::PATTERN},
    {"http_host", RuleType::PATTERN},
    {"dns_query", RuleType::PATTERN},
    {"dns_query_regex", RuleType::PATTERN}
};

const std::unordered_map<std::string, RuleAction> RuleLoader::rule_action_map_ = {
    {"drop", RuleAction::DROP},
    {"accept", RuleAction::ACCEPT}
    // REJECT supprimé
};

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
        
        // Parse rules
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
        
        PrintRulesSummary(rules_by_layer);
        
        return rules_by_layer;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error loading rules: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<Rule> RuleLoader::ParseRule(const nlohmann::json& rule_json) {
    auto rule = std::make_unique<Rule>();
    
    // Parse required fields
    if (!rule_json.contains("id") || !rule_json["id"].is_string()) {
        throw std::runtime_error("Missing or invalid rule 'id'");
    }
    rule->id = rule_json["id"];
    
    if (!rule_json.contains("layer") || !rule_json["layer"].is_number_integer()) {
        throw std::runtime_error("Missing or invalid rule 'layer'");
    }
    rule->layer = ParseRuleLayer(rule_json["layer"]);
    
    if (!rule_json.contains("type") || !rule_json["type"].is_string()) {
        throw std::runtime_error("Missing or invalid rule 'type'");
    }
    rule->type = ParseRuleType(rule_json["type"]);
    
    if (!rule_json.contains("action") || !rule_json["action"].is_string()) {
        throw std::runtime_error("Missing or invalid rule 'action'");
    }
    rule->action = ParseRuleAction(rule_json["action"]);
    
    if (!rule_json.contains("values") || !rule_json["values"].is_array()) {
        throw std::runtime_error("Missing or invalid rule 'values'");
    }
    
    // Parse values
    for (const auto& value : rule_json["values"]) {
        if (value.is_string()) {
            rule->values.push_back(value);
        } else if (value.is_number()) {
            rule->values.push_back(std::to_string(value.get<int>()));
        }
    }
    
    // Parse optional field
    if (rule_json.contains("field") && rule_json["field"].is_string()) {
        rule->field = rule_json["field"];
    }
    
    // Compile patterns
    rule->CompilePatterns();
    rule->CompileIPRanges();
    
    return rule;
}

RuleLayer RuleLoader::ParseRuleLayer(int layer) {
    switch (layer) {
        case 3: return RuleLayer::L3;
        case 4: return RuleLayer::L4;
        case 7: return RuleLayer::L7;
        default:
            throw std::runtime_error("Invalid rule layer: " + std::to_string(layer));
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

bool RuleLoader::ValidateRule(const std::unique_ptr<Rule>& rule) {
    if (!rule || rule->id.empty() || rule->values.empty()) {
        return false;
    }
    return true;
}

void RuleLoader::PrintRulesSummary(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules) {
    
    std::cout << "\n📊 Rules Summary:" << std::endl;
    
    size_t total = 0;
    for (const auto& [layer, layer_rules] : rules) {
        std::string layer_name;
        switch (layer) {
            case RuleLayer::L3: layer_name = "L3 (Network)"; break;
            case RuleLayer::L4: layer_name = "L4 (Transport)"; break;
            case RuleLayer::L7: layer_name = "L7 (Application)"; break;
        }
        
        std::cout << "   " << layer_name << ": " << layer_rules.size() << " rules" << std::endl;
        total += layer_rules.size();
    }
    
    std::cout << "   Total: " << total << " rules\n" << std::endl;
}

bool RuleLoader::ValidateRulesFile(const std::string& file_path) {
    try {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            return false;
        }
        
        nlohmann::json json_data;
        file >> json_data;
        file.close();
        
        return json_data.contains("rules") && json_data["rules"].is_array();
        
    } catch (...) {
        return false;
    }
}