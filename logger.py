# logger.py
import logging

def setup_logger(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(message)s')

def log_packet(packet_info, action):
    logging.info(f"Packet {action}: {packet_info}")
