# firewall_main.py
from packet_sniffer import sniff_packets
from config_loader import monitor_config
from logger import setup_logger
import threading

RULES_FILE = "firewall_rules.json"
LOG_FILE = "firewall.log"


def main():
    setup_logger(LOG_FILE)

    # Load initial rules
    rules = monitor_config(RULES_FILE)

    # Start packet sniffing in a separate thread
    sniffer_thread = threading.Thread(target=sniff_packets, args=(rules,))
    sniffer_thread.start()

    # Monitor the rule file for changes and update rules dynamically
    while True:
        new_rules = monitor_config(RULES_FILE)
        if new_rules != rules:
            rules = new_rules
            print("Firewall rules updated!")


if __name__ == "__main__":
    main()
