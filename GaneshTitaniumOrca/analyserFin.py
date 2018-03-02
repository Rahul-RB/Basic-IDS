import sys
import socket
import dpkt

from ipaddress import ip_address
from tabulate import tabulate
from pprint import pprint

class CatchIPs:
	
	def __init__(self, fileName):
		self.fileName = fileName
		self.blackIPDict = {}
		self.attackerList = []
		self.scannedPorts = {}
		
	def isPortScan(self, IP):
		ports = self.scannedPorts[IP]
		return len(ports)>=1000
	
	def parsePcapFile(self):
		# Open pcap file
		with open(self.fileName, 'rb') as fp:
			pcap = dpkt.pcap.Reader(fp) # Parse file
			print("Parsing PCAP File now...")
			for ts, buf in pcap:
				try:
				# Extract TCP data if present else fail silently
					eth = dpkt.ethernet.Ethernet(buf)
					ip= eth.data
					tcp=ip.data
					
					# Check if SYN ACK is set. 
					synFlag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
					ackFlag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
					finFlag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
					
					# Find port number and src, dest IPs
					# [TODO]: FIND PORT, dest
					port = tcp.dport
					srcIpAddrString = socket.inet_ntoa(ip.src)
					# IF Packet is a TCP-SYN
					if(finFlag==False and synFlag == True and ackFlag == False):
						# blackIPDict maps: ip->[SYN_count, non_SYN_count]
						self.blackIPDict[ip.src] = self.blackIPDict.get(ip.src, [0, 0, 0, []])
						self.blackIPDict[ip.src][0]+=1
						self.blackIPDict[ip.src][3].append(port)
					elif(finFlag==True and synFlag==False and ackFlag==False):
						#IF Packet is a TCP-FIN
						self.blackIPDict[ip.src] = self.blackIPDict.get(ip.src, [0, 0, 0, []])
						self.blackIPDict[ip.src][1]+=1
						self.blackIPDict[ip.src][3].append(port)
					else:
						self.blackIPDict[ip.src] = self.blackIPDict.get(ip.src, [0, 0, 0, []])
						self.blackIPDict[ip.src][2]+=1
						self.blackIPDict[ip.src][3].append(port)
				# print(synFlag, ackFlag, ip.dst, srcIpAddrString, port)
				except:
					pass
					# traceback.print_exc() # [IMP]: Uncomment while developing
	
			return self.__table(self.__detect_attackers(), headers=["IP Address", "Port","Scan Type"])
	
	def getCount(self):
		ip_count = list()
		for ip, count in self.blackIPDict.items():
			if(count[0] > 3 * count[2]):
				ip_count.append([socket.inet_ntoa(ip), count[0],"SYN"])
			if(count[1] > 3*count[2]):
				ip_count.append([socket.inet_ntoa(ip), count[1],"FIN"])
		return self.__table(ip_count, headers=["IP Address", "Count","Scan Type"])
	
	def get_ips(self):
		return self.__table(self.attackerList, headers=["IP Address", "Port","Scan Type"])
	
	def __detect_attackers(self):
		
#		pprint(self.blackIPDict.items())
		for ip, count in self.blackIPDict.items():
			if(count[0] > 3 * count[2]):
				for port in count[3]:
					self.scannedPorts[socket.inet_ntoa(ip)] = self.scannedPorts.get(socket.inet_ntoa(ip), [])
					self.scannedPorts[socket.inet_ntoa(ip)].append(port)
					self.attackerList.append([socket.inet_ntoa(ip), int(port),"SYN"])
			if(count[1]>3*count[2]):				
				for port in count[3]:
					self.scannedPorts[socket.inet_ntoa(ip)] = self.scannedPorts.get(socket.inet_ntoa(ip), [])
					self.scannedPorts[socket.inet_ntoa(ip)].append(port)
					self.attackerList.append([socket.inet_ntoa(ip), int(port),"FIN"])
		return self.attackerList
		
	def get_port_lists(self):
		return self.scannedPorts
	
	def __table(self, info, headers):
		# print(info)
		# print(headers)
		return tabulate(info, headers = headers, tablefmt="psql")
	

try:
	cipObj = CatchIPs(sys.argv[1])
except:
	print("Enter the path to a PCAP File.")
	print("Eg: $ python3 CatchIPs.py '../pcapFiles/file.pcap'")
	print("Exiting now")
	exit()

cipObj.parsePcapFile()

print("Potential Blacklist IP Addresses with number of SYN packets sent:")
print(cipObj.getCount())
inp = input("Do you want to see the ports attacked/scanned? [y/N] : ")
if(inp.startswith('y') or inp.startswith('Y')):
	print(cipObj.get_ips())

print("Conclusion on Port Scan:")
finalRes = []
for IP in cipObj.get_port_lists().keys():
	res = cipObj.isPortScan(IP)
	finalRes.append([IP,res])

print(tabulate(finalRes,headers=["IP Address","Did [IP] do a port scan?"],tablefmt="psql"))