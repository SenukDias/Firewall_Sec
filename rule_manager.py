# rule_manager.py
import json

# Load firewall rules from a JSON file
def load_rules(rule_file):
    with open(rule_file, 'r') as file:
        return json.load(file)

# Check if a packet matches a rule
def check_rule(packet_info, rules):
    for rule in rules:
        if (rule['src_ip'] == packet_info['src_ip'] and
            rule['dst_ip'] == packet_info['dst_ip'] and
            rule['protocol'] == packet_info['protocol'] and
            rule['port'] == packet_info['port']):
            return rule['action']
    return "ALLOW"  # Default action is to allow
