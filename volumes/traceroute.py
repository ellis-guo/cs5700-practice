#!/usr/bin/env python3
from scapy.all import *

dst = '1.2.3.4'

for ttl in range(1, 20):
    pkt = IP(dst=dst, ttl=ttl) / ICMP()
    reply = sr1(pkt, timeout=1, verbose=0)
    if reply is None:
        print(f"{ttl}: No reply")
    elif reply[ICMP].type == 11:  # time exceeded
        print(f"{ttl}: {reply.src}")
    elif reply[ICMP].type == 0:   # echo reply
        print(f"{ttl}: {reply.src} (destination reached)")
        break
