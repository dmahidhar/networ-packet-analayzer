from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

def packet_callback(packet):
    """
    Callback function that is called for each captured packet.
    Displays relevant information like timestamp, source/destination IPs, protocol, and payload data.
    """
    # Get the timestamp of the packet capture
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n[{timestamp}]")

    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Display basic IP info
        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst}")
        
        # Identify the protocol (TCP/UDP/Other)
        if packet.haslayer(TCP):
            print(f"Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport} --> Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport} --> Destination Port: {packet[UDP].dport}")
        else:
            print(f"Protocol: Other (Protocol Number: {proto})")

        # Display payload data if available
        payload = packet[IP].payload
        if payload:
            print(f"Payload Data: {bytes(payload)[:50]}")  # Display the first 50 bytes of payload data

    else:
        print("Non-IP packet detected")

def start_sniffer(interface=None):
    """
    Starts the packet sniffer on the specified interface.
    If no interface is provided, scapy will sniff on all available interfaces.
    
    Parameters:
    - interface (str): The network interface to sniff on (e.g., "eth0", "wlan0").
    """
    print("Starting packet sniffer...")
    if interface:
        print(f"Sniffing on interface: {interface}")
        sniff(iface=interface, prn=packet_callback, store=False)
    else:
        print("Sniffing on all available interfaces")
        sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    # Replace 'eth0' with the desired interface or leave it None to sniff on all interfaces
    interface = input("Enter the interface to sniff on (leave blank for all interfaces): ").strip() or None
    start_sniffer(interface)
