# CNS Assignment 2 
## Put table of names and USN of Akhil, Rahul and Gurunandan


## Objectives :

1. Forming Malformed Packets
Craft a TCP packet or set of TCP packets (using a tool or a piece of code) to send to a target.
Observe the target's response with a packet capturing tool or view the results of those packet attacks in the log files on the target.
2. Anomaly Detection
Programmatically analyze trace data to detect port scanning activity.
Observe the target's response with a packet capturing tool or view the results of those packet attacks in the log files on the target.
Develop a Python program that analyzes a PCAP file in order to detect possible port scans.

## Part 1: Forming Malformed Packets - Packet Crafting
### Brief on Packet Crafting:
- Packet crafting is a technique that allows network administrators to probe firewall rule-sets and find entry points into a targeted system or network. 
- Testing may target the firewall, IDS, TCP/IP stack, router or any other component of the network.
- The act of packet crafting can be broken into four stages: Packet Assembly, Packet Editing, Packet Play and Packet Decoding.

### Packet crafting techniques:
- Protocol manipulation
- Ping fragmentation
- Half open packets
- Packet duplication
- Packet flag manipulation

### Forming malformed packets with Scapy and testing them on website firewalls.
Please note:
1. We will be testing our malformed packets on a site which is legally safe to "hack".
2. The source IP is the actual IP address of the system.

The site is : www.hackthissite.org .

#### Step 1: 
In this step, we use scapy's methods of forming packets with simple interfaces [1] and sending them to the intentionally vulnerable site.
	<put pic: attackerPics/scapyDefault.png>
Analysis: We do observe that the website gave no response. The firewall rules on the site are capable of dropping/ignoring our packets. Hence in the coming steps, we'll, by trial and error, make a packet which is malicious but can bypass firewall rules.

#### Step 2:
In this step we tried setting Reset flag and seeing how the firewall rules of the site behave:
<put pic: attackerPics/scapyWithReset.png>
Analysis: The firewall rules of the website are crafted carefully to avoid a potentially dangerous reset packet. Thus the line of defence isn't yet bypassed.

#### Step 3:
SYN Flooding the servers. This is also called the DOS attack. <write the same as Ganesh's in another way: Hint: go to google translate, translate english to some language, translate the translated thing back to english, change grammar>
<put pic: attackerPics/dos1.png>

## Part 2: Anamoly Detection

### Usage:

To run:
	`python3 analyserFin.py <PATH-TO-PCAP-FILE>`
Example:
	`python3 analyserFin.py "../victimOutputs/nmapFinScan.pcap"`

### Information

Steps in detecting malicious IPs:
1. Get PCAP file from command line and parse it with DPKT [2],[4].
2. In `parse()` method, get the `TCP` values from packets and then get their SYN and ACK flags with following:
	`synFlag = (TCP.flags & dpkt.tcp.TH_SYN)!=0`
	`ackFlag = (TCP.flags & dpkt.tcp.TH_ACK)!=0`
3. Then get destination port `dport` from `TCP` values.
4. Finally check whether the packet was only a `SYN` type packet by checking values of `synFlag` and `ackFlag`. If only `synFlag` was set then increment the counter of SYN packet corresponding to that IP, else do the same for ACK packet of the same IP.

A single Python script was used to detect IP addresses potentially trying to attack the victim. In most cases, the attacker is `123.45.67.89` while the victim is `123.45.67.88`. 

### Scans and their Outputs

1. TCP SYN scan or Port scanning with 'netcat' (`nc`) as: 
		`nc -z -v 123.45.67.88 1-10000` 
	where: 
	`-z` check only if a port is open, it doesn't send any data.
	`-v` is for verbose output.
	`1-10000` is port range.
	- The TCP SYN (Half Open) scans are called half open because the attacking system doesn’t close the open connections. 
	- The attacking scanner will send a SYN packet to the target and wait for a response. 
	- If the port is open, the target will send a SYN|ACK. If the port is closed, the target will send an RST. 
	- A bit noisy scan, but not as noisy as a Vanilla TCP scan, like the one done in SYN FLOOD.
	Below are pictures at attacker and victim side of scans. Victim side shows wireshark output, whereas attacker side shows the terminal output.
	<put pics : attackerPics/portScanNC.png ; victimPics/portScanNCWireshark.png>
	Following pic shows the output from the Python script which detects the IP to be malicious since it scanned more than 1000 ports.
	<put pic : victimPics/portScanNCConclusion.png>

2. A SYN flood attack using `hping3`:
		`sudo hping3 -S --flood -V 123.45.67.88`
	This attack floods the victim with SYN packets without waiting for replies. The aim of this scan is to attack the client. This scan caused our Victim machine to crash after 5 seconds of flooding through a 1 GigaBit network switch. So to get the below results, we had to manually terminate flooding.
	Below are pictures at attacker and victim side of scans. Victim side shows wireshark output, whereas attacker side shows the terminal output.
	<put pics : attackerPics/hping3SynFlood.png ; victimPics/hping3SynFloodWireshark.png>
	Following pic shows the output from the Python script which detects the IP to be malicious since it scanned more than 1000 ports.
	<put pic : victimPics/hping3SynFloodConclusion.png>

3. A `nmap` FIN scan:
	`sudo nmap -sF 123.45.67.88`
	 - The TCP FIN scan has the ability to pass undetected through most firewalls, packet filters, and scan detection programs. 
	 - The attacking system sends FIN packets to the targeted system. 
	 - The closed ports will respond with an RST. 
	 - The open ports will ignore the packets. 
	 - The attacking system will take note of which ports it received an RST on and report on the ports that did not respond with an RST.
	Below are pictures at attacker and victim side of scans. Victim side shows wireshark output, whereas attacker side shows the terminal output.
	<put pics : attackerPics/nmapFinScan.png ; victimPics/nmapFinScanWireshark.png>
	Following pic shows the output from the Python script which detects the IP to be malicious since it scanned more than 1000 ports.
	<put pic : victimPics/nmapFinScanConclusion.png>

Thus we have identified Port Scanning activity even done through various port scanning techniques.

## Acknowledgement: 
- This project is developed as part of assignment for Computer Networks Security.
- We would like to thank our professors, Dr. Alka Agrawal and Prof. Amulya G

## Bibliography

[1]: http://packetlife.net/blog/2011/may/23/introduction-scapy/
[2]: https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
[3]: https://www.sans.org/reading-room/whitepapers/auditing/port-scanning-techniques-defense-70
[4]: http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
[OTHERS-1]: http://www.hackingarticles.in/penetration-testing/ 
[OTHERS-2]: https://www.blackmoreops.com/2015/04/21/denial-of-service-attack-dos-using-hping3-with-spoofed-ip-in-kali-linux/