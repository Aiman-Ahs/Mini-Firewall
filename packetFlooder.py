import sys
import time
from scapy.all import Ether, IP, TCP, sendp

TARGET_IP = "192.168.x.x" #replace with target IP address
INTERFACE = "eth0" #replace with your network interface
NUM_PACKETS = 100
DURATION = 5

def sendPackets(targetIP, interface, numPackets, duration):
    packet = Ether() / IP(dst = targetIP) / TCP()
    endTime = time.time() + duration
    packetCount = 0

    while time.time() < endTime and packetCount < numPackets:
        sendp(packet, iface = interface)
        packetCount += 1

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3")
        sys.exit(1)
    sendPackets(TARGET_IP, INTERFACE, NUM_PACKETS, DURATION)