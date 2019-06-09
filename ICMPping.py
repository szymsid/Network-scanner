from scapy.all import *
from port import PortType
import sys

def icmp_ping(targets):
    alive_hosts = []
    for host in targets:
        pkt = sr1(IP(dst=host)/ICMP(type=8),retry=0, timeout=1)

        if pkt != None:
            alive_hosts.append((pkt.src, pkt.ttl))
    return alive_hosts

addr = sys.argv[1]
targets = []
for i in range(30,35):
    targets.append(addr + str(i))

hosts = icmp_ping(targets)

output = open('ICMPoutput', 'w')
for h in hosts:
    output.write(h[0] + " " +str(h[1]))
    output.write("\n")

output.close()