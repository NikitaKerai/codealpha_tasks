from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Protocol type mapping
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, str(protocol))

        print(f"[+] Protocol: {proto_name}")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        
        # Print payload size if available
        if hasattr(packet, 'payload'):
            print(f"    Payload Length : {len(packet.payload)} bytes\n")

# Start sniffing (filter for IP packets only)
print("Starting packet capture... Press CTRL+C to stop.\n")
sniff(filter="ip", prn=process_packet, count=20)  # capture 20 packets
