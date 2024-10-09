# cli.py
import sys
from rule_manager import load_rules

RULES_FILE = "firewall_rules.json"

def add_rule(src_ip, dst_ip, protocol, port, action):
    rules = load_rules(RULES_FILE)
    new_rule = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port,
        "action": action
    }
    rules.append(new_rule)
    with open(RULES_FILE, 'w') as file:
        json.dump(rules, file, indent=4)
    print(f"Added rule: {new_rule}")

def remove_rule(index):
    rules = load_rules(RULES_FILE)
    if 0 <= index < len(rules):
        removed = rules.pop(index)
        with open(RULES_FILE, 'w') as file:
            json.dump(rules, file, indent=4)
        print(f"Removed rule: {removed}")
    else:
        print("Invalid index")

def list_rules():
    rules = load_rules(RULES_FILE)
    for i, rule in enumerate(rules):
        print(f"{i}: {rule}")

def main():
    if len(sys.argv) < 2:
        print("Usage: cli.py [add|remove|list] ...")
        sys.exit(1)

    action = sys.argv[1]
    if action == "add" and len(sys.argv) == 7:
        add_rule(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif action == "remove" and len(sys.argv) == 3:
        remove_rule(int(sys.argv[2]))
    elif action == "list":
        list_rules()
    else:
        print("Invalid arguments")

if __name__ == "__main__":
    main()
