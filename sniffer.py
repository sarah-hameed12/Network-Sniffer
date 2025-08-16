#for a windows device

from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

def process_packet(packet):
    print("\n--- Packet Captured ---")

    if Ether in packet:
        eth = packet[Ether]
        print(f"Ethernet: {eth.src} -> {eth.dst} | Type: {eth.type}")

    if IP in packet:
        ip = packet[IP]
        print(f"IP: {ip.src} -> {ip.dst} | Protocol: {ip.proto} | TTL: {ip.ttl}")

        if TCP in packet:
            tcp = packet[TCP]
            print(f"TCP: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}")

        elif UDP in packet:
            udp = packet[UDP]
            print(f"UDP: {udp.sport} -> {udp.dport}")

        elif ICMP in packet:
            icmp = packet[ICMP]
            print(f"ICMP: Type={icmp.type} Code={icmp.code}")

print("Sniffing started... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)

