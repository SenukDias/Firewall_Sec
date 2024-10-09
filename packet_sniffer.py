# packet_sniffer.py
from scapy.all import sniff
from packet_processor import process_ip_packet
import logging

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def start_sniffing(rules, iface="ens160"):
    def process_packet(packet):
        if packet.haslayer('IP'):
            packet_info = {
                'src_ip': packet['IP'].src,
                'dst_ip': packet['IP'].dst,
                'protocol': packet['IP'].proto
            }
            process_ip_packet(packet_info, rules)
        else:
            logging.warning("Packet does not have an IP layer")

    try:
        # Specify network interface and enable promiscuous mode
        sniff(filter="ip", iface=iface, prn=process_packet, promisc=True)
    except Exception as e:
        logging.error(f"Error occurred while sniffing: {e}")

