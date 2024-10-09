# packet_processor.py
import struct
import socket
import logging
from rule_manager import check_rule
from logger import log_packet

TCP = 6
UDP = 17
ICMP = 1

def process_ip_packet(packet, rules):
    # Parse IP header
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])

    packet_info = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': str(protocol),  # Convert protocol to string
        'port': None
    }

    logging.debug(f"Packet info: {packet_info}")
    for rule in rules:
        logging.debug(f"Checking rule: {rule}")
        if (rule['source'] == 'ANY' or rule['source'] == src_ip) and \
           (rule['destination'] == 'ANY' or rule['destination'] == dst_ip) and \
           (rule['protocol'] == 'ANY' or rule['protocol'] == protocol) and \
           (rule['port'] == 'ANY' or rule['port'] == packet_info['port']):
            if rule['action'] == 'BLOCK':
                logging.info(f"Blocking packet: {packet_info}")
                return False  # Block the packet
            elif rule['action'] == 'ALLOW':
                logging.info(f"Allowing packet: {packet_info}")
                return True  # Allow the packet

    logging.info(f"No matching rule found, allowing packet: {packet_info}")
    return True  # Default action is to allow the packet
    logging.info(f"No matching rule found, allowing packet: {packet_info}")
    return True  # Default action is to allow the packet