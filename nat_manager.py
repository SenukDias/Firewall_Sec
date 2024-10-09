# nat_manager.py
import os

def enable_nat():
    os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    os.system("iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT")
    os.system("iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT")

def disable_nat():
    os.system("iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE")
    os.system("iptables -D FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT")
    os.system("iptables -D FORWARD -i eth1 -o eth0 -j ACCEPT")
