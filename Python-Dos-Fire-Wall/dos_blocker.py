"""
DoS Attack Detection & Mitigation Script
Maurizio Gonzalez
Date: 3/16/2015

Features:
- Whitelist & Blacklist functionality to allow/deny specific IPs.
- Signature detection for known malicious payloads (e.g., Nimda worm).
- Rate-limiting to detect & block high packet-rate IPs.
- Logging system to track blocked threats.
- Persistent iptables rules (saved after updates).

Requires root privileges to execute.
"""

import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

# Threshold for packet rate detection
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Reads IPs from a file and returns a set
def read_ip_file(filename):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            return set(line.strip() for line in file)
    return set()

# Detects Nimda worm payload
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload)
        if b"GET /scripts/root.exe" in payload:
            print("[DEBUG] Nimda signature detected")
            return True
    return False

# Logs events to a timestamped file
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    with open(os.path.join(log_folder, f"log_{timestamp}.txt"), "a") as file:
        file.write(f"{message}\n")

# Saves iptables rules persistently
def save_iptables_rules():
    iptables_dir = "/etc/iptables"
    if not os.path.exists(iptables_dir):
        os.makedirs(iptables_dir)
    os.system("sudo iptables-save > /etc/iptables/rules.v4")

# Handles incoming packets
def packet_callback(packet):
    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return

    if src_ip in blacklist_ips or is_nimda_worm(packet):
        print(f"Blocking malicious IP: {src_ip}")
        os.system(f"iptables -I INPUT 1 -s {src_ip} -j DROP")
        log_event(f"Blocked IP: {src_ip}")
        save_iptables_rules()
        return

    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            print(f"IP: {ip}, Packet rate: {packet_rate}")

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -I INPUT 1 -s {ip} -j DROP")
                log_event(f"Blocked IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)
                save_iptables_rules()

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist_ips.txt")
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)
