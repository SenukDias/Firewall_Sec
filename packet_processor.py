# packet_processor.py
from rule_manager import check_rule
from logger import log_packet


def process_ip_packet(packet):
    # Parse the IP header
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])

    # Extract source and destination IP addresses
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    protocol = ip_header[6]

    # Build packet information
    packet_info = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'port': None  # We can parse TCP/UDP later
    }

    # Apply firewall rules
    action = check_rule(packet_info)
    log_packet(packet_info, action)

    return action == "ALLOW"  # Allow or block packet based on rule
