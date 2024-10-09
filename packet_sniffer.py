# packet_sniffer.py
from scapy.all import sniff
from packet_processor import process_ip_packet
import logging
import json

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def start_sniffing(rules, iface="ens160"):
    def process_packet(packet):
        if packet.haslayer('IP'):
            raw_packet = bytes(packet)
            if not process_ip_packet(raw_packet, rules):
                logging.info(f"Packet blocked")
            else:
                logging.info(f"Packet allowed")
        else:
            logging.warning("Packet does not have an IP layer")

    try:
        # Specify network interface and enable promiscuous mode
        sniff(filter="ip", iface=iface, prn=process_packet, promisc=True)
    except Exception as e:
        logging.error(f"Error occurred while sniffing: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with open('firewall_rules.json', 'r') as f:
        rules = json.load(f)
    start_sniffing(rules)