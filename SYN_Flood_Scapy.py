#!/usr/bin/env python3

import logging
import argparse
from scapy.all import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def send_packet(dest_ip):
    logging.info("Field values of packet sent")
    p = IP(dst=dest_ip, id=1111, ttl=99) / TCP(sport=RandShort(), dport=[22, 23, 80, 445], seq=12345, ack=1000, window=1000, flags="S") / "Send Packets"
    ls(p)
    logging.info("Sending packets in 0.3 second intervals for timeout of 4 sec")
    try:
        ans, unans = srloop(p, inter=0.3, retry=2, timeout=4)
        logging.info("Sent %d packets, received %d responses", len(ans), len(unans))
    except Exception as e:
        logging.error("Error sending packets: %s", str(e))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send TCP SYN packets to specified destination IP addresses.')
    parser.add_argument('dest_ip', metavar='destination IP', type=str, help='the destination IP address')
    args = parser.parse_args()
    send_packet(args.dest_ip)
