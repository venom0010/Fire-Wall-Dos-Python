# Fire-Wall-Dos-Python
This project detects and mitigates **Denial-of-Service (DoS) attacks** using Python and Scapy. It includes:
- **DoS Blocker** (detects & blocks high-rate traffic and Nimda worm signatures).
- **DoS Flooder** (simulates a flood attack).
- **Nimda Worm Packet** (sends a malicious request to test detection).

- ## 📌 Its Features
- **IP Whitelist & Blacklist** , Explicitly allow or deny certain IPs.
- **Packet Rate Limiting** , Blocks sources sending too many packets per second.
- **Signature Detection** , Identifies known attack payloads.
- **Logging System** , Records all blocked IPs and events.
- **Persistent iptables Rules** , Ensures blocked IPs stay blocked after reboot.

- ## 🚀 Setup & How to use
### **1️⃣ Install Dependencies**
Run on both machines:
```bash
sudo apt update && sudo apt install python3-pip net-tools
pip3 install scapy
```

- ## Run the DoS Blocker on the Target
  sudo python3 dos_blocker.py

- ## Run the Flooder/Nimda Attack on the Attacker
  sudo python3 flooder.py
  or
  sudo python3 nimda_packet.py

- ## 🛑 Stop Scripts
  ctrl + c

  ## THANK YOU FOR READING ;)
