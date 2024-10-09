# rule_manager.py
import json

def load_rules(rules_file):
    with open(rules_file, 'r') as file:
        return json.load(file)

def check_rule(packet_info, rules):
    for rule in rules:
        if (rule['src_ip'] == packet_info['src_ip'] or rule['src_ip'] == "ANY") and \
           (rule['dst_ip'] == packet_info['dst_ip'] or rule['dst_ip'] == "ANY") and \
           (rule['protocol'] == packet_info['protocol'] or rule['protocol'] == "ANY"):
            return rule['action']
    return "ALLOW"  # Default to allow if no rules match
