# packet_processor.py
import struct
import socket
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
        'protocol': protocol,
        'port': None
    }

    if protocol == TCP:
        process_tcp_packet(packet[20:], packet_info)
    elif protocol == UDP:
        process_udp_packet(packet[20:], packet_info)
    elif protocol == ICMP:
        process_icmp_packet(packet_info)

    action = check_rule(packet_info, rules)
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
