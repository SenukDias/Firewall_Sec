# packet_sniffer.py
from scapy.all import sniff
from packet_processor import process_ip_packet
import logging

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def start_sniffing(rules):
    def process_packet(packet):
        packet_info = {
            'src_ip': packet[0][1].src,
            'dst_ip': packet[0][1].dst,
            'protocol': packet[0][1].proto
        }
        process_ip_packet(packet_info, rules)

    # Specify network interface and enable promiscuous mode
    sniff(filter="ip", iface="ens160", prn=process_packet, promisc=True)

