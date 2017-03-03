# Tommy Tang
# Sep 30, 2016
# Scapy Lab
import sys
import re
import base64
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

re_visa = "4\d{3}[\s\-]*\d{4}[\s\-]*\d{4}[\s\-]*\d{4}[^0-9]"
re_master = "5\d{3}[\s\-]*\d{4}[\s\-]*\d{4}[\s\-]*\d{4}[^0-9]"
re_disc = "6011[\s\-]*\d{4}[\s\-]*\d{4}[\s\-]*\d{4}[^0-9]"
re_ax = "3\d{3}[\s\-]*\d{6}[\s\-]*\d{5}[^0-9]"

if len(sys.argv) == 1:
	mode = "eth0"
elif sys.argv[1] == "-i":
	mode = sys.argv[2]
elif sys.argv[1] == "-r":
	mode = "read"
elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
	print ("usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]\n\n" +
	"A network sniffer that identifies basic vulnerabilities\n\n" +
	"optional arguments:\n-h, --help    show this help message and exit\n" +
  	"-i INTERFACE  Network interface to sniff on\n-r PCAPFILE   A PCAP file to read")
  	sys.exit()
else:
	print "Incorrect syntax. Type --help for manual."
	sys.exit()

if mode == "read":
	if len(sys.argv) is not 3:
		print "Incorrect syntax. Type --help for manual."
		sys.exit()
	packet = rdpcap(sys.argv[2])
	plength = len(packet)
else:
	plength = -1
idx = 0
alnum = 0
while True:
	try:
		alert = None
		ip = None
		proto = "unknown"
		raw = None
		nmap_det = False
		if mode != "read":
			packet = sniff(iface=mode, count=1)
			idx = 0
		if packet[idx].getlayer(IP) is not None:
			ip = str(packet[idx].getlayer(IP).src)
			proto = str(packet[idx].getlayer(IP).proto)
		if packet[idx].getlayer(TCP) is not None:
			flags = bin(packet[idx].getlayer(TCP).flags)
			if flags == b'0b0':
				alert = "NULL scan"
				alnum+=1
				proto = "TCP"
				raw = "binary data"
				nmap_det = True
			elif flags == b'0b1':
				alert = "FIN scan"
				alnum+=1
				proto = "TCP"
				raw = "binary data"
				nmap_det = True
			elif flags == b'0b101001':
				alert = "XMAS scan"
				alnum+=1
				proto = "TCP"
				raw = "binary data"
				nmap_det = True
		if packet[idx].getlayer(Raw) is not None:
			raw = str(packet[idx].getlayer(Raw))
			if "Nikto" in raw:
				alert = "Nikto scan"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
			if "PASS" in raw or "LOGIN" in raw:
				alert = "Plain username/password"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
			if "Authorization: Basic" in raw:
				alert = "Plain username/password: "
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
				encoded = re.search("(?:Basic) (.*)", raw)
				alert+= base64.b64decode(encoded.group(1))
			if "phpMyAdmin" in raw:
				alert = "Someone looking for phpMyAdmin stuff"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
			if "masscan" in raw:
				alert = "masscan"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
			if "Nmap" in raw and nmap_det is False:
				alert = "Other nmap scan"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
			if (re.search(re_visa, raw) is not None) or \
			(re.search(re_master, raw) is not None) or \
			(re.search(re_ax, raw) is not None) or \
			(re.search(re_disc, raw) is not None):
				alert = "Credit card number in the clear"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)
			if "() { (a)=>\\" in raw or "() { :;};" in raw:
				alert = "Shellshock scanning"
				alnum+=1
				if packet[idx].getlayer(TCP) is not None:
					proto = str(packet[idx].getlayer(TCP).dport)

		if alert is not None:
			print "ALERT #%d, %s is detected from %s (%s) (%s)!\n" % (alnum, alert, ip, proto, raw)
		idx+=1
		if idx == plength:
			print "File scan complete"
			sys.exit()
	except IndexError:
		sys.exit()
	except KeyboardInterrupt:
		sys.exit()
	except Exception, e:
		print e
		sys.exit()
