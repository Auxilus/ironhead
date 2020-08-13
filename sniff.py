#!/usr/bin/env python3

from collections import Counter
from scapy.all import sniff

packet_counts = Counter()

def custom_action(packet):
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    if packet[0][1].src == "192.168.1.35":
        packet.display()

sniff(filter="ip", prn=custom_action)
