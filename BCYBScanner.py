from scapy.all import *
from port import PortType
import sys
import socket

def ack_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    window = None
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/TCP(sport=sport, dport=port, flags="A"), timeout=1, verbose=0)

            scan_result[address][port] = PortType(1)
            if pkt != None:
                if pkt.haslayer(TCP):
                    if pkt[TCP].flags == "R":
                        scan_result[address][port] = PortType(5)
                        if window == None or window == 0:
                            window = pkt[TCP].window
                elif pkt.haslayer(ICMP):
                    if int(pkt[ICMP].type) == 3 and int(pkt[ICMP].code) in [1,2,3,9,10,13]:
                        scan_result[address][port] = PortType(4)
        scan_result[address]["window"] = window

    return scan_result

def fin_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    window = None
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/TCP(sport=sport, dport=port, flags="F"), timeout=1, verbose=0)

            scan_result[address][port] = PortType(1)

            if pkt != None:
                if pkt.haslayer(TCP):
                    if pkt[TPC].flags == "R":
                        scan_result[address][port] = PortType(3)
                        if window == None or window == 0:
                            window = pkt[TCP].window
                elif pkt.haslayer(ICMP):
                    if int(pkt[ICMP].type) == 3 and int(pkt[ICMP].type) in [1,2,3,9,10,13]:
                        scan_result[address][port] = PortType(4)
            else:
                scan_result[address][port] = PortType(6)
        scan_result[address]["window"] = window

    return scan_result

def SocketScan(targets, ports):
    scan_result = {}
    window = None
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result [address] = {}
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            response = sock.connect_ex((address, port))
            
            if response == 0:
                scan_result[address][port] = PortType(2)
            else:
                scan_result[address][port] = PortType(3)    
            
            sock.close()
        scan_result[address]["window"] = window

    return scan_result

def syn_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    window = None
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)

            scan_result[address][port] = PortType(1)
            if pkt != None:
                if pkt.haslayer(TCP):
                    if pkt[TCP].flags == "SA":
                        send = sr(IP(dst=address)/TCP(sport=sport, dport=port, flags="R"), timeout=1, verbose=0)
                        scan_result[address][port] = PortType(2)
                        if window == None or window == 0:
                            window = pkt[TCP].window
                    if pkt[TCP].flags == "R":
                        send_result[address][port] = PortType(3)
        scan_result[address]["window"] = window

    return scan_result

def tcp_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    window = None
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
            scan_result[address][port] = PortType(1)
            if pkt != None:
                if pkt.haslayer(TCP):
                    if pkt[TCP].flags == "SA":
                        send = sr(IP(dst=address)/TCP(sport=sport, dport=port, flags="RA"), timeout=1, verbose=0)
                        scan_result[address][port] = PortType(2)
                        if window == None or window == 0:
                            window = pkt[TCP].window
                    if pkt[TCP].flags == "R":
                        scan_result[address][port] = PortType(3)

        scan_result[address]["window"] = window

    return scan_result

def udp_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/UDP(sport=sport, dport=port), timeout=1, verbose=0)

            scan_result[address][port] = PortType(1)
            
            if pkt != None:
                if pkt.haslayer(ICMP):
                    if int(pkt[ICMP].type) == 3:
                        if int(pkt[ICMP].code) == 3:
                            scan_result[address][port] = PortType(3)
                        elif int(pkt[ICMP].code in [1,2,9,10,13]):
                            scan_result[address][port] = PortType(4)
                elif pkt.haslayer(UDP):
                    scan_result[address][port] = PortType(2)
            else:
                scan_result[address][port] = PortType(6)
        scan_result[address]["window"] = None
    
    return scan_result

def window_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    window = None

    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/TCP(sport=sport, dport=port, flags="A"), timeout=1, verbose=0)

            scan_result[address][port] = PortType(1)
            if pkt != None:
                if pkt.haslayer(TCP):
                    if pkt[TCP].window == 0:
                        scan_result[address][port] = PortType(3)
                    elif pkt[TCP].window >0:
                        scan_result[address][port] = PortType(2)
                        if window == None or window == 0:
                            window = pkt[TCP].window
                elif pkt.haslayer(ICMP):
                    if int(pkt[ICMP].type) == 3 and int(pkt[ICMP].type) in [1,2,3,9,10,13]:
                        scan_result[address][port] = PortType(4)
        scan_result[address]["window"] = window           
    
    return scan_result

def xmas_scan(targets, ports):
    scan_result = {}
    sport = RandShort()
    window = None
    for address in targets:
        print("Checking host:   {}".format(address))
        scan_result[address] = {}
        for port in ports:
            pkt = sr1(IP(dst=address)/TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)

            scan_result[address][port] = PortType(1)
            if pkt != None:
                if pkt.haslayer(TCP):
                    if pkt[TCP].flags == "R":
                        scan_result[address][port] = PortType(3)
                    if window == None or window == 0:
                        window = pkt[TCP].window
                elif pkt.haslayer(ICMP):
                    if int(pkt[ICMP].type) == 3 and int(pkt[ICMP].code) in [1,2,3,9,10,13]:
                        scan_result[address][port] = PortType(4)
            else:
                scan_result[address][port] = PortType(6)

        scan_result[address]["window"] = window

    return scan_result

def checkOS(ttl, windowSize):
    print("Possible OS:")
    if ttl == 128:
        if windowSize == 65535:
            print("Windows XP")
        elif windowSize == 8192:
            print("Windows Vista or newer(Server 2008")
        else:    
            print("Any Windows")
    elif ttl < 128:
        if windowSize == 5840:
            print("Linux kernel 2.4 or 2.6")
        elif windowSize == 5720:
            print("Google linux")
        elif windowSize == 65535:
            print("FreeBSD")
        else:
            print("Unix based system")    
    elif ttl > 128:
        if windowSize == 4128:
            print("Cisco router")
        else:
            print("Undefinde")
    else:
        print("Undefined")

if len(sys.argv) != 2:
    print("You need to choose scan type\n -a\-f\-s\-S\-t\-u\-w\-x")
    sys.exit()

scanType = sys.argv[1]
data = open('ICMPoutput', 'r').readlines()
targets = {}
for i in range(0,len(data)):
    data[i] = data[i].strip('\n')
    pair = data[i].split()
    targets[pair[0]] = int(pair[1])  

#zakres kończący się o 1 więcej, do 80 -> range(1,81) lub lista z numerami portów
#ports = range(1,81)
ports = [21,22,53,80,8080]

try:
    if scanType == "-a":
        result = ack_scan(targets.keys(), ports)
    elif scanType == "-f":
        result = fin_scan(targets.keys(), ports)
    elif scanType == "-s":
        result = syn_scan(targets.keys(), ports)
    elif scanType == "-S":
        result = SocketScan(targets.keys(), ports)
    elif scanType == "-t":
        result = tcp_scan(targets.keys(), ports)
    elif scanType == "-u":
        result = udp_scan(targets.keys(), ports)
    elif scanType == "-w":
        result = window_scan(targets.keys(), ports)
    elif scanType == "-x":
        result = xmas_scan(targets.keys(), ports)

except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved. Exiting")
    sys.exit()

except socket.error:
    print("Couldn't connect to server")
    sys.exit()

for address in result.keys():
    print("Host:    {}".format(address))
    checkOS(targets[address],result[address]["window"])
    for port in result[address].keys():
        if port != "window":
            if result[address][port] != PortType(1):
                print("Port {}:     {}".format(port, result[address][port].getType()))

print("Done")