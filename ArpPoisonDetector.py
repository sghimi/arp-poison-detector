
import logging
import time
from scapy.all import *

logging.basicConfig(filename='arp_poisoning.log',
					format='[%(asctime)s] %(message)s',
					datefmt='%d/%m/%Y %I:%M:%S %p',
					level=logging.DEBUG)

ip_to_mac = {}

def arp_monitor_callback(pkt):
	if ARP in pkt and pkt[ARP].op in (1,2): #ARP request or reply
		if pkt[ARP].psrc in ip_to_mac: #known IP
			if ip_to_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc: #MAC address mismatch
				print('\n[!] ARP Poisoning detected!')
				print('Victim IP: ' + pkt[ARP].psrc)
				print('Victim MAC: ' + ip_to_mac[pkt[ARP].psrc])
				print('Attacker IP: ' + pkt[ARP].pdst)
				print('Attacker MAC: ' + pkt[ARP].hwsrc)
				logging.warning('ARP Poisoning detected! Victim IP: ' + pkt[ARP].psrc + ', Victim MAC: ' + ip_to_mac[pkt[ARP].psrc] + ', Attacker IP: ' + pkt[ARP].pdst + ', Attacker MAC: ' + pkt[ARP].hwsrc)
		else:
			ip_to_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

print('[*] Starting ARP Monitor...')
sniff(prn=arp_monitor_callback, filter='arp', store=0)