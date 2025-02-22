from scapy.all import Ether, IP, TCP, Raw, send

def sendNimdaPacket(targetIP, targetPort = 80, sourceIP = "192.168.2.36", sourcePort = 12345):
    packet = (
        IP(src = sourceIP, dst = targetIP) 
        / TCP(sport = sourcePort, dport = targetPort)
        / Raw(load = "GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )
    send(packet)

if __name__ == "__main__":
    targetIP = "192.168.2.20"
    sendNimdaPacket(targetIP)
