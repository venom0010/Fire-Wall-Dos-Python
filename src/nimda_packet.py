"""
Nimda Malware Packet Simulation
Maurizio Gonzalez
Date: 3/16/2025

Sends a fake Nimda malware HTTP request to test firewall detection.
"""

from scapy.all import IP, TCP, Raw, send
import random

# Random source port
source_port = random.randint(1024, 65535)

def send_nimda_packet(target_ip, source_port, target_port=80, source_ip="192.168.xxx.xx"):
    packet = (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=source_port, dport=target_port)
        / Raw(load="GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )
    send(packet)

if __name__ == "__main__":
    target_ip = "192.168.xxx.xx"
    send_nimda_packet(target_ip, source_port)
