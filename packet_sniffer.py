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
            packet_info = {
                'src_ip': packet['IP'].src,
                'dst_ip': packet['IP'].dst,
                'protocol': packet['IP'].proto,
                'port': packet['IP'].dport if packet.haslayer('TCP') else None
            }
            if not process_ip_packet(packet_info, rules):
                logging.info(f"Packet blocked: {packet_info}")
            else:
                logging.info(f"Packet allowed: {packet_info}")
        else:
            logging.warning("Packet does not have an IP layer")

    try:
        # Specify network interface and enable promiscuous mode
        sniff(filter="ip", iface=iface, prn=process_packet, promisc=True)
    except Exception as e:
        logging.error(f"Error occurred while sniffing: {e}")

if __name__ == "__main__":
    with open('firewall_rules.json', 'r') as f:
        rules = json.load(f)
    start_sniffing(rules)

