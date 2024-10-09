import sys
import json  # Import the json module
from rule_manager import load_rules

RULES_FILE = "firewall_rules.json"

def add_rule(source, destination, protocol, port, action):
    rules = load_rules(RULES_FILE)  # Load existing rules
    new_rule = {
        'source': source,
        'destination': destination,
        'protocol': protocol,
        'port': port,
        'action': action
    }
    rules.append(new_rule)  # Add new rule to the existing rules

    # Save updated rules back to the file
    with open(RULES_FILE, 'w') as file:
        json.dump(rules, file, indent=4)  # Write updated rules
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
    if not rules:  # Check if there are no rules
        print("No rules found.")
        return
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

