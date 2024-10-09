# vpn_manager.py
import os

def start_vpn(vpn_config_file):
    os.system(f"openvpn --config {vpn_config_file} &")

def stop_vpn():
    os.system("pkill openvpn")
