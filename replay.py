#!/usr/bin/env python3

from scapy.all import *
import sys

packets = rdpcap(sys.argv[1])

#ip = RandIP()._fix()
#mac = RandMAC()._fix()
ip = "192.168.1.39"
mac = "dc:a6:32:4a:be:71"

for packet in packets:
    #packet[0].src = mac
    #packet.getlayer(IP).src = ip
    packet.show()
    sendp(packet, inter=1)
    #sendp(packet, inter=0, count=1999)
