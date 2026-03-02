
#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.src = '1.2.3.4'
a.dst = '10.9.0.5'
b = ICMP()
p = a/b
send(p)
print("Packet sent!")
