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

    if protocol == TCP:
        process_tcp_packet(packet[20:], packet_info)
    elif protocol == UDP:
        process_udp_packet(packet[20:], packet_info)
    elif protocol == ICMP:
        process_icmp_packet(packet_info)

    action = process_packet_info(packet_info, rules)
    log_packet(packet_info, action)

    return action == "ALLOW"


def process_tcp_packet(segment, packet_info):
    tcp_header = struct.unpack('!HHLLBBHHH', segment[:20])
    packet_info['port'] = tcp_header[0]
    packet_info['protocol'] = 'TCP'


def process_udp_packet(segment, packet_info):
    udp_header = struct.unpack('!HHHH', segment[:8])
    packet_info['port'] = udp_header[0]
    packet_info['protocol'] = 'UDP'


def process_icmp_packet(packet_info):
    packet_info['protocol'] = 'ICMP'


def process_packet_info(packet_info, rules):
    src_ip = packet_info['src_ip']
    dst_ip = packet_info['dst_ip']
    protocol = packet_info['protocol']
    port = packet_info.get('port', None)

    for rule in rules:
        if (rule['source'] == 'ANY' or rule['source'] == src_ip) and \
           (rule['destination'] == 'ANY' or rule['destination'] == dst_ip) and \
           (rule['protocol'] == 'ANY' or rule['protocol'] == protocol) and \
           (rule['port'] == 'ANY' or rule['port'] == port):
            if rule['action'] == 'BLOCK':
                logging.info(f"Blocking packet: {packet_info}")
                return "BLOCK"  # Block the packet
            elif rule['action'] == 'ALLOW':
                logging.info(f"Allowing packet: {packet_info}")
                return "ALLOW"  # Allow the packet

    logging.info(f"No matching rule found, allowing packet: {packet_info}")
    return "ALLOW"  # Default action is to allow the packet
