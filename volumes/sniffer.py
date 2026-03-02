#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-2b06a793de6e', filter='icmp', prn=print_pkt)
#pkt = sniff(iface='br-2b06a793de6e', filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)
#pkt = sniff(iface='br-2b06a793de6e', filter='net 128.230.0.0/16', prn=print_pkt)
