# packet_sniffer.py
import socket
import struct


def sniff_packets():
    # Create a raw socket to listen on all interfaces
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        # Receive packets
        raw_packet = raw_socket.recvfrom(65565)[0]
        # Parse the Ethernet frame
        ethernet_header = raw_packet[0:14]
        eth_header = struct.unpack("!6s6sH", ethernet_header)
        eth_protocol = socket.ntohs(eth_header[2])

        # Handle only IP packets (IPv4)
        if eth_protocol == 8:
            process_ip_packet(raw_packet[14:])
