# firewall_main.py
import argparse
import logging
import json
from packet_sniffer import start_sniffing
from rule_manager import load_rules
from nat_manager import enable_nat, disable_nat
from vpn_manager import start_vpn, stop_vpn

RULES_FILE = "firewall_rules.json"

def setup_logging():
    # Create a custom logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler('firewall.log')
    c_handler.setLevel(logging.DEBUG)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add them to handlers
    c_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

def main():
    parser = argparse.ArgumentParser(description="Firewall CLI")
    parser.add_argument('--enable-nat', action='store_true', help="Enable NAT")
    parser.add_argument('--disable-nat', action='store_true', help="Disable NAT")
    parser.add_argument('--start-vpn', metavar='vpn_config', help="Start VPN")
    parser.add_argument('--stop-vpn', action='store_true', help="Stop VPN")

    args = parser.parse_args()

    if args.enable_nat:
        enable_nat()
        print("NAT enabled")
    elif args.disable_nat:
        disable_nat()
        print("NAT disabled")
    elif args.start_vpn:
        start_vpn(args.start_vpn)
        print("VPN started")
    elif args.stop_vpn:
        stop_vpn()
        print("VPN stopped")
    else:
        with open(RULES_FILE, 'r') as f:
            rules = json.load(f)
        print("Starting firewall...")
        start_sniffing(rules)

if __name__ == "__main__":
    setup_logging()
    main()
