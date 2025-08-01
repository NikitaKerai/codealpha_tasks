# Network Sniffer
## Overview
This project is a network sniffer tool implemented in Python using Scapy.
## Features
-  Packet Sniffing - sniff() is used to capture live network packets.
-  Protocol Identification - Uses a protocol mapping dictionary to translate protocol numbers into human-readable protocol names (TCP, UDP, ICMP).
-   Payload Size Calculation - Uses len(packet.payload) to determine the size of the encapsulated payload (data size).

# Secure Code Review
