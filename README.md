# Network Sniffer
## Overview
This project is a network sniffer tool implemented in Python using Scapy.
## Features
-  Packet Sniffing - sniff() is used to capture live network packets.
-  Protocol Identification - Uses a protocol mapping dictionary to translate protocol numbers into human-readable protocol names (TCP, UDP, ICMP).
-   Payload Size Calculation - Uses len(packet.payload) to determine the size of the encapsulated payload (data size).

# Secure Code Review
## Overview
This project is a secure Python script for analyzing PCAP (packet capture) files to extract unique destination ports from TCP and UDP traffic. It emphasises secure coding practices, robust error handling, and safe resource usage.
## Features
- Processes two PCAP files and identifies unique destination ports
- Handles large files efficiently using PcapReader
- Validates input files before processing
- Logs errors and progress using Python's logging module
- Written following secure coding guidelines
