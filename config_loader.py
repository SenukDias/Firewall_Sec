# config_loader.py
import os
from rule_manager import load_rules


def monitor_config(rule_file):
    last_modified = os.path.getmtime(rule_file)

    while True:
        new_modified = os.path.getmtime(rule_file)
        if new_modified != last_modified:
            last_modified = new_modified
            return load_rules(rule_file)
