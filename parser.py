from scapy.layers.inet import *
from scapy.utils import hexdump, hexstr
from scapy.all import wrpcap
from importlib import *
import socket
import urllib.parse

last = None

def dissect_whatsapp(packet):
    print("whatsapp TODO")

def dissect_web(packet):
    pkthex = hexstr(packet, onlyasc=True)
    if "GET" in pkthex:
        path = pkthex.split("GET ")[1].split("HTTP")[0]
        path = urllib.parse.unquote(path)
        headers = pkthex.split("GET")[1].split("HTTP")[1]
        host = headers.split("Host: ")[1].split("..")[0]
        print("[GET] http://{}{}".format(host, path, headers))

def arp(packet):
    hexstr(packet)

def ipv6(packet):
    hexstr(packet)

def ipv4(packet):
    show_payload = False
    ip_src = packet.getlayer(IP).src
    ip_dst = packet.getlayer(IP).dst
    hosts = {'src': ip_src, 'dst': ip_dst}
    try:
        hosts['src'] = "{}:{}".format(ip_src, socket.gethostbyaddr(ip_src)[0])
    except Exception as e:
        pass
        #print("gethostbyaddr: {}".format(str(e)))
    try:
        hosts['dst'] = "{}:{}".format(ip_dst, socket.gethostbyaddr(ip_dst)[0])
    except Exception as e:
        pass
        #print("gethostbyaddr: {}".format(str(e)))

    if packet.haslayer(TCP):
        sport = packet.getlayer(TCP).sport
        dport = packet.getlayer(TCP).dport
    if packet.haslayer(UDP):
        sport = packet.getlayer(UDP).sport
        dport = packet.getlayer(UDP).dport

    if ("whatsapp" in hosts['src']) or ("whatsapp" in hosts['dst']):
        dissect_whatsapp(packet)
    elif "GET" in hexstr(packet, onlyasc=True):
        dissect_web(packet)

    else:
        if (packet.haslayer(TCP)):
            msg = "[TCP] {} -> {}".format(hosts['src'], hosts['dst'])
        elif (packet.haslayer(UDP)):
            msg = "[UDP] {} -> {}".format(hosts['src'], hosts['dst'])
        else:
            msg = "[UNKNOWN]"

        global last
        if not last == msg:
            print(msg)
            last = msg

handlers = {
        2048: ipv4,
        2054: arp,
        34525: ipv6
}

def parse(packet):
    ether_type = packet[0].type
    if ether_type not in handlers:
        print("[unknown] [{}] {}".format(ether_type, packet))
    handlers.get(ether_type)(packet)
