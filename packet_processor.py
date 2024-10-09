# packet_processor.py
import struct
import socket
import logging
import os

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

    # Extract port if the protocol is TCP or UDP
    if protocol == TCP:  # TCP
        tcp_header = struct.unpack('!HHLLBBHHH', packet[20:40])
        packet_info['port'] = tcp_header[1]  # Destination port
    elif protocol == UDP:  # UDP
        udp_header = struct.unpack('!HHHH', packet[20:28])
        packet_info['port'] = udp_header[1]  # Destination port

    logging.info(f"Processing packet: {packet_info}")
    for rule in rules:
        if (rule['source'] == 'ANY' or rule['source'] == src_ip) and \
           (rule['destination'] == 'ANY' or rule['destination'] == dst_ip) and \
           (rule['protocol'] == 'ANY' or rule['protocol'] == str(protocol)) and \
           (rule['port'] == 'ANY' or rule['port'] == packet_info['port']):
            if rule['action'] == 'BLOCK':
                logging.info(f"Blocking packet: {packet_info}")
                # Add iptables rule to drop the packet
                os.system(f"iptables -A INPUT -s {src_ip} -d {dst_ip} -j DROP")
                return False  # Block the packet
            elif rule['action'] == 'ALLOW':
                logging.info(f"Packet allowed: {packet_info}")
                return True  # Allow the packet

    logging.info(f"No matching rule found, allowing packet: {packet_info}")
    return True  # Default action is to allow the packet