#include "successive_engine.h"
#include "../utils.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>

// ============================================================
// CONSTRUCTOR - PARTITIONNER LES RÈGLES ENTRE WORKERS
// ============================================================
SuccessiveEngine::SuccessiveEngine(
    const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
    size_t num_workers)
    : RuleEngine(rules), num_workers_(num_workers) {
    
    // Collecter toutes les règles dans un vecteur plat
    std::vector<Rule*> all_rules;
    for (const auto& [layer, layer_rules] : rules_by_layer_) {
        for (const auto& rule : layer_rules) {
            all_rules.push_back(rule.get());
        }
    }
    
    size_t total_rules = all_rules.size();
    size_t rules_per_worker = total_rules / num_workers_;
    size_t remainder = total_rules % num_workers_;
    
    std::cout << "   📊 Successive mode: " << total_rules << " rules → " 
              << num_workers_ << " workers (successive execution)" << std::endl;
    
    // Créer les workers et partitionner les règles
    size_t start_idx = 0;
    
    for (size_t worker_id = 0; worker_id < num_workers_; ++worker_id) {
        auto worker = std::make_unique<Worker>();
        worker->worker_id = worker_id;
        
        // Calculer combien de règles pour ce worker
        size_t num_rules_for_this_worker = rules_per_worker;
        if (worker_id < remainder) {
            num_rules_for_this_worker++;
        }
        
        // Cloner les règles pour ce worker
        for (size_t i = 0; i < num_rules_for_this_worker && start_idx < total_rules; ++i, ++start_idx) {
            Rule* original_rule = all_rules[start_idx];
            auto cloned_rule = original_rule->Clone();
            cloned_rule->CompileIPRanges();
            worker->rules.push_back(std::move(cloned_rule));
        }
        
        // Construire les structures hash pour ce worker
        BuildWorkerStructures(*worker);
        
        std::cout << "      Worker " << worker_id << ": " 
                  << worker->rules.size() << " rules" << std::endl;
        
        workers_.push_back(std::move(worker));
    }
    
    std::cout << "   ✅ Successive workers ready (will execute ONE AFTER ANOTHER)" << std::endl;
}

// ============================================================
// BUILD OPTIMIZED HASH STRUCTURES POUR UN WORKER
// ============================================================
void SuccessiveEngine::BuildWorkerStructures(Worker& worker) {
    // Construire les hash tables pour les règles de ce worker
    for (const auto& rule : worker.rules) {
        if (rule->layer == RuleLayer::L3 && rule->type == RuleType::IP_RANGE) {
            // Add compiled IP ranges
            for (const auto& range : rule->ip_ranges_) {
                IPRange fast_range;
                fast_range.network = range.network;
                fast_range.mask = range.mask;
                fast_range.rule_id = rule->id;
                worker.ip_ranges.push_back(fast_range);
                
                // Extract individual IPs for small ranges
                uint32_t range_size = ~range.mask + 1;
                if (range_size <= 256) {  // /24 ou plus petit
                    for (uint32_t i = 0; i < range_size; ++i) {
                        uint32_t ip = ntohl(range.network) + i;
                        worker.blocked_ips.insert(htonl(ip));
                        worker.ip_rules[htonl(ip)] = rule->id;
                    }
                }
            }
        } else if (rule->layer == RuleLayer::L4) {
            if (rule->type == RuleType::PORT) {
                bool is_tcp = (rule->type_str.find("tcp") != std::string::npos);
                bool is_udp = (rule->type_str.find("udp") != std::string::npos);
                
                for (const auto& port_str : rule->values) {
                    uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                    
                    if (is_tcp || (!is_tcp && !is_udp)) {
                        worker.blocked_tcp_ports.insert(port);
                        worker.tcp_port_rules[port] = rule->id;
                    }
                    
                    if (is_udp) {
                        worker.blocked_udp_ports.insert(port);
                        worker.udp_port_rules[port] = rule->id;
                    }
                }
            }
        }
    }
}

// ============================================================
// FILTRAGE AVEC UN WORKER SPÉCIFIQUE
// ============================================================
FilterResult SuccessiveEngine::FilterWithWorker(const PacketData& packet, Worker& worker) {
    std::string matched_rule_id;
    
    // L3: IP CHECK
    uint32_t src_ip = IPStringToUint32(packet.src_ip);
    uint32_t dst_ip = IPStringToUint32(packet.dst_ip);
    
    // Check blocked IPs (O(1))
    if (src_ip != 0 && worker.blocked_ips.count(src_ip) > 0) {
        auto it = worker.ip_rules.find(src_ip);
        if (it != worker.ip_rules.end()) {
            matched_rule_id = it->second;
        }
        return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L3);
    }
    
    if (dst_ip != 0 && worker.blocked_ips.count(dst_ip) > 0) {
        auto it = worker.ip_rules.find(dst_ip);
        if (it != worker.ip_rules.end()) {
            matched_rule_id = it->second;
        }
        return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L3);
    }
    
    // Check IP ranges
    for (const auto& range : worker.ip_ranges) {
        if ((src_ip & range.mask) == range.network || 
            (dst_ip & range.mask) == range.network) {
            return FilterResult(RuleAction::DROP, range.rule_id, 0.0, RuleLayer::L3);
        }
    }
    
    // L4: PORT CHECK (O(1))
    if (packet.protocol == IPPROTO_TCP && packet.dst_port > 0) {
        if (worker.blocked_tcp_ports.count(packet.dst_port) > 0) {
            auto it = worker.tcp_port_rules.find(packet.dst_port);
            if (it != worker.tcp_port_rules.end()) {
                matched_rule_id = it->second;
            }
            return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L4);
        }
    } else if (packet.protocol == IPPROTO_UDP && packet.dst_port > 0) {
        if (worker.blocked_udp_ports.count(packet.dst_port) > 0) {
            auto it = worker.udp_port_rules.find(packet.dst_port);
            if (it != worker.udp_port_rules.end()) {
                matched_rule_id = it->second;
            }
            return FilterResult(RuleAction::DROP, matched_rule_id, 0.0, RuleLayer::L4);
        }
    }
    
    // Ce worker n'a rien trouvé
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}

// ============================================================
// MAIN FILTERING - EXÉCUTER LES WORKERS UN APRÈS L'AUTRE
// ============================================================
FilterResult SuccessiveEngine::FilterPacket(const PacketData& packet) {
    // Exécuter Worker 1, puis Worker 2, puis Worker 3 SUCCESSIVEMENT
    // Si un worker trouve un DROP, on arrête immédiatement
    
    for (auto& worker : workers_) {
        FilterResult result = FilterWithWorker(packet, *worker);
        
        if (result.action == RuleAction::DROP) {
            // Un worker a trouvé un DROP → arrêt immédiat
            return result;
        }
        // Sinon continuer avec le worker suivant
    }
    
    // Tous les workers ont fini, aucun DROP trouvé → ACCEPT
    return FilterResult(RuleAction::ACCEPT, "", 0.0, RuleLayer::L3);
}
