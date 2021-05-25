#!/usr/bin/env python

import sys
from scapy.all import *

flop = "false"
flopCount = 0
assets = "192.168.70.102"
honeypot = "192.168.70.200"

def packt_summary(pkt):
	global flop
	global flopCount
	global honeypot
	global assets
	if IP in pkt:
		if packt[IP].dst == assets:
			flop = "false"
			print packt[IP].src + " to Victim"
		if packt[IP].dst == honeypot and flop == "false":
			flop = "true"
			flopCount = flopCount + 1
			print packt[IP].src + " to HoneyPot"
			print flopCount
			if flopCount == 10:
				print "REROUTEING ATTACKS TO HONEYPOT"
				os.system("iptables -t nat -D PREROUTING 1")
				sys.exit()
sniff(prn=packt_summary)
