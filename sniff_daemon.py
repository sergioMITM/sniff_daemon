#!/usr/bin/env python2

from os import geteuid, devnull
import logging
# shut up scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
from sys import exit
import argparse
from subprocess import Popen, PIPE
import os
from defrag import get_load
from parse_http import get_body_url
from sniff_creds import get_creds, check_bruteforce
import time
 
##########################
# built from net-creds.py
# https://github.com/DanMcInerney/net-creds/blob/master/net-creds.py
#########################

args = None

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   parser.add_argument("-f", "--proxy_ip", help="This is the address of the proxy server; -f 192.168.0.4")
   parser.add_argument("-x", "--proxy_port", help="This is the port of the proxy server; -p 8080")
   return parser.parse_args()

def iface_finder():
    DN = open(devnull, 'w')
    try:
        ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        for line in ipr.communicate()[0].splitlines():
            if 'default' in line:
                l = line.split()
                iface = l[4]
                return iface
    except IOError:
        exit('[-] Could not find an internet active interface; please specify one with -i <interface>')

def pkt_parser(pkt):
    global args
    # Get rid of uninteresting packets
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6): return
    if pkt.haslayer(ARP): return
    #Get rid of all packets except requests from proxy users (to proxy and proxy port) 
    if pkt.haslayer(IP) and str(pkt[IP].dst) != args.proxy_ip: return
    if pkt.haslayer(TCP) and str(pkt[TCP].dport) != args.proxy_port: return

    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
	full_load = get_load(pkt)
	headers, body, url = get_body_url(full_load)
	get_creds(body,headers,url,pkt)

def main():
    global args
    args = parse_args()
    # Read packets from either pcap or interface
    if args.pcap:
        try:
            for pkt in PcapReader(args.pcap):
                pkt_parser(pkt)
        except IOError:
            exit('[-] Could not open %s' % args.pcap)

    else:
        # Check for root
        if geteuid():
            exit('[-] Please run as root')
	if args.proxy_ip and args.proxy_port: 
		proxy_ip = args.proxy_ip
		proxy_port = args.proxy_port
	else:
            exit('[-] The -f and -x flags are required: proxy IP address and port respectively')

        #Find the active interface
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = iface_finder()
        print '[*] Using interface:', conf.iface

	while True:	
	    #sniff for 5 minutes
            sniff(iface=conf.iface, prn=pkt_parser, filter="not src %s" % proxy_ip, store=0, timeout=300)
	    check_bruteforce()
	    time.sleep(600)
	
if __name__ == "__main__":
   main()
