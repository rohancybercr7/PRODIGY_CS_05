from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import binascii

# Function to parse and display relevant packet information
def packet_callback(packet):
    # Check if the packet contains an IP layer
    if IP in packet:
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        protocol = packet[IP].proto  # Protocol type (TCP, UDP, etc.)

        # Print basic IP layer details
        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst} | Protocol: {protocol}")
        
        # Check for TCP or UDP and display related information
        if TCP in packet:
            print(f"  Protocol: TCP | Source Port: {packet[TCP].sport} --> Destination Port: {packet[TCP].dport}")
            print(f"  Payload Data (Hex): {binascii.hexlify(packet[TCP].payload)}")
        elif UDP in packet:
            print(f"  Protocol: UDP | Source Port: {packet[UDP].sport} --> Destination Port: {packet[UDP].dport}")
            print(f"  Payload Data (Hex): {binascii.hexlify(packet[UDP].payload)}")

        print("-" * 50)  # Separator for readability

# Start sniffing the network
def start_sniffer(interface=None):
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=False, iface=interface, filter="ip")  # Filters for IP packets

if __name__ == "__main__":
    # Optionally, specify an interface (e.g., 'eth0', 'wlan0', etc.)
    start_sniffer()
