# Passive Browser Reconaissance
# For Linux - Sniffs traffic on a given interface to passively identify potentially vulnerable applications and software
# Credit to Silver Moon (m00n.silv3r@gmail.com) for the Linux packet sniffer code
# Author(s): Josh Hawkins (@hawkhax)
# Version 0.01
# https://github.com/jahawkins/pbr

import socket, sys, string
from struct import *

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW, socket.ntohs(0x0003))
    #Currently hardcoded to wlan0, should make this a parameter
    s.bind(("eth0",0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

SavedLines = []
# receive a packet
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
   # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 : 
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

	#TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]
            lines = string.split(data,"\n")
            for line in lines:
		fullLine = s_addr + ' : ' + line
            	if (("Java/" in line) and ("User-Agent" in line)) and (fullLine not in SavedLines):
			strings = string.split(line, " ")
			for substr in strings:
				if ("Java" in substr):
					print s_addr + " is running Java version " + (string.split(substr,"/"))[1]
					SavedLines.append(fullLine)
		if ("x-flash-version" in line) and (fullLine not in SavedLines):
			print s_addr + " is running Flash Player version" + ((string.split(line,":"))[1]).replace(",", ".")
			SavedLines.append(fullLine)
		# If the browser is Internet Explorer, find the version
		if (("User-Agent" in line) and ("MSIE" in line))and (fullLine not in SavedLines):
			strings = string.split(line, ";")
			for substr in strings:
				if ("MSIE" in substr):
					print s_addr + " is running Internet Explorer version " + (string.split(substr," "))[2]
					SavedLines.append(fullLine)
