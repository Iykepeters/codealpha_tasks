from scapy.all import sniff, IP, TCP, UDP, Ether

def packet_callback(packet):
    """
    Callback function that processes each packet captured.
    """
    try:
        # Check if the packet has an Ethernet layer
        if Ether in packet:
            print(f"\n[+] Ethernet Frame: {packet[Ether].src} -> {packet[Ether].dst}")
        
        # Check if the packet has an IP layer
        if IP in packet:
            print(f"[+] IP Packet: {packet[IP].src} -> {packet[IP].dst}")
            print(f"    Protocol: {packet[IP].proto}, Length: {packet[IP].len}")

            # Check if the packet is a TCP packet
            if TCP in packet:
                print(f"    TCP Segment: Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
            
            # Check if the packet is a UDP packet
            elif UDP in packet:
                print(f"    UDP Segment: Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting network sniffer...")
    try:
        # Start sniffing packets
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping sniffer. Goodbye!")
