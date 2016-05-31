#! /usr/bin/env python
from scapy.all import *

if __name__ == "__main__":
    hostname = "google.com"
    for i in range(1, 30):
        pkt = IP(dst=hostname, ttl=i) / ICMP()
        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0, timeout=2)
        if reply is None:
            print "%d hops away: *" % i
        elif reply.type == 0:
            # We've reached our destination
            print "%d hops away: " % i , reply.src
            print "Done!"
            break
        else:
            # We're in the middle somewhere
            print "%d hops away: " % i , reply.src
