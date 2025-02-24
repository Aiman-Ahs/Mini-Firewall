import os
import sys
import time
from collections import defaultdict #used to store & manage packet counts for each IP address
from scapy.all import sniff, IP, TCP #imports sniff function and IP class
#from scapy, this allows us to analyze network packets

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")
#max allowed packet rate for an IP per second

def readIPFile(filename):
    with open(filename, "r") as file: #open in read mode & close file when done
        ips = [line.strip() for line in file]
    return set(ips)
#reads IPs from a file and returns them as a set

def isNimdaWorm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        #check if TCP layer exists and if destination port is 80
        payload = packet[TCP].payload
        #extract payload from TCP layer
        return "GET /scripts/root.exe" in str(payload) #return true 
    return False
#checks if a packet is part of Nimda worm attack

def logEvent(message):
    logFolder = "logs"
    os.makedirs(logFolder, exist_ok = True)
    timestamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
    logFile = os.path.join(logFolder, f"log_{timestamp}.txt")
    with open(logFile, "a") as file: #open in append mode
        file.write(f"{message}\n")
#logs event to a file

def packetCallback(packet):
    srcIP = packet[IP].src
    #extract source IP from IP layer of packet
    if srcIP in whitelistIPs:
        return

    if srcIP in blacklistIPs:
        os.system(f"iptables -A INPUT -s {srcIP} -j DROP")
        logEvent(f"Blocking blacklisted IP: {srcIP}")
        return
    #block and log IP if blacklisted
    
    if isNimdaWorm(packet):
        print(f"Blocking Nimda source IP: {srcIP}")
        os.system(f"iptables -A INPUT -s {srcIP} -j DROP")
        logEvent(f"Blocking Nimda source IP: {srcIP}")
        return
    #blacklist Nimda worm source IPs
    
    packetCount[srcIP] += 1
    #increment packet count for source IP address
    currentTime = time.time() #record current time (self-explanatory)
    timeInterval = currentTime - startTime[0]
    #calculate time interval (start time is a list, containing start time as 1st element)

    if timeInterval >= 1:
        #checks if DOS attack is happening once every second
        for ip, count in packetCount.items(): #iterate thru packet count for each IP address
            packetRate = count / timeInterval
            print(f"IP: {ip}, Packet rate: {packetRate}")
            if packetRate > THRESHOLD and ip not in blockedIPs:
                print(f"Blocking IP: {ip}, packet rate: {packetRate}")
                #print message indicating that IP address is being blocked
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                #actually block the IP address using iptables command
                logEvent(f"Blocking IP: {ip}, packet rate: {packetRate}")
                blockedIPs.add(ip)
                #add blocked IP to blockedIPs set
        packetCount.clear()
        startTime[0] = currentTime
        #clear packet count dictionary and restart the time

if __name__ == "__main__": #main guard and main function combined
    if os.geteuid() != 0:
        #check that script has been executed using root privileges
        print("This script requires root privileges") 
        sys.exit(1)
        #exit script with error code 1

    whitelistIPs = readIPFile("whitelist.txt")
    blacklistIPs = readIPFile("blacklist.txt")
    #read whitelisted and blacklisted IPs from files
    packetCount = defaultdict(int)
    #initialize packet count dictionary
    startTime = [time.time()]
    #record start time in a list
    blockedIPs = set()
    print("Monitoring network traffic...")
    sniff(filter = "ip", prn = packetCallback)
    #we start sniffing IP packets and pass them to packetCallback function for analysis

    #require root privileges for 2 reasons
    #1. need it to access raw network traffic
    #2. in the case we want to block an IP, we need it to modify system's firewall config.

    #defaultdict is a specialized dictionary DSA; it can automatically assign a default value, 'ie0'
    #to a new IP address when it's first encountered. This simplifies packet counting process