#!/usr/bin/env python3

import sys
from scapy.all import *

flop = False
flopCount = 0
assets = "192.168.70.102"
honeypot = "192.168.70.200"

def packt_summary(pkt):
    global flop
    global flopCount
    global honeypot
    global assets
    
    if IP in pkt:
        if pkt[IP].dst == assets:
            flop = False
            print(pkt[IP].src + " to Victim")
        if pkt[IP].dst == honeypot and not flop:
            flop = True
            flopCount = flopCount + 1
            print(pkt[IP].src + " to HoneyPot")
            print(flopCount)
            if flopCount == 10:
                print("REROUTEING ATTACKS TO HONEYPOT")
                os.system("iptables -t nat -D PREROUTING 1")
                sys.exit()

sniff(prn=packt_summary)
