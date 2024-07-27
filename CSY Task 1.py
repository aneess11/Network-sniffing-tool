from scapy.all import sniff, IP, TCP, UDP, ICMP
import os

# Define the file path for saving captured packets
output_file_path = os.path.join(os.getcwd(), "captured_packets.txt")

# Open the file to save the captured packet information
with open(output_file_path, "w") as f:

    def packet_callback(packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            
            packet_info = f"\nIP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})"
            print(packet_info)
            f.write(packet_info + "\n")
            
            # Check for TCP packets
            if packet.haslayer(TCP):
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                tcp_info = f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}"
                print(tcp_info)
                f.write(tcp_info + "\n")
            
            # Check for UDP packets
            elif packet.haslayer(UDP):
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                udp_info = f"UDP Datagram: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}"
                print(udp_info)
                f.write(udp_info + "\n")
            
            # Check for ICMP packets
            elif packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                icmp_info = f"ICMP Packet: Type={icmp_type} Code={icmp_code}"
                print(icmp_info)
                f.write(icmp_info + "\n")

    # Capture packets
    print("Starting network sniffer...")
    sniff(prn=packet_callback, count=10)

# Inform the user that packet capture is complete
print(f"Packet capture complete. Information saved to {output_file_path}")

