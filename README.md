# Python Network Sniffer

A simple packet sniffer written in Python using **Scapy**.  
This tool captures live network traffic and displays useful information such as Ethernet addresses, IP headers, and TCP/UDP/ICMP details.  

**Disclaimer:** This project is for educational purposes only. Do not use it on networks you do not own or have explicit permission to monitor.

---

## Features
- Captures live network packets
- Displays Ethernet source/destination and frame type
- Extracts IP header details (source, destination, protocol, TTL)
- Identifies transport layer protocols:
  - **TCP**: source/destination ports, flags  
  - **UDP**: source/destination ports  
  - **ICMP**: type and code  

---

## Requirements
- Python 3.x
- [Scapy](https://scapy.readthedocs.io/en/latest/)
