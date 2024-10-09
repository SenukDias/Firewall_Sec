# packet_sniffer.py
import socket
from packet_processor import process_ip_packet


def start_sniffing(rules):
    # Raw socket for sniffing packets
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(("0.0.0.0", 0))

    # Capture all incoming packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("Sniffing packets...")

    while True:
        packet, addr = sniffer.recvfrom(65565)
        if process_ip_packet(packet, rules):
            print(f"Allowed packet from {addr}")
        else:
            print(f"Blocked packet from {addr}")
