import random
import socket
import sys
from colorama import init, Fore, Back, Style
from scapy.all import *
        
def traceroute(hostname, ip, maxhops):
    print(Fore.YELLOW + "*** Traceroute by Bit ***")
    print(Fore.YELLOW + "Trace %s, maxhops %d" % (hostname, maxhops))
    fail = 0;
    succ = 0;
    
    for i in range(maxhops):
        TTL = i + 1

        #Create IP header
        L3 = IP(dst=ip, ttl=TTL, flags="DF", chksum=0)  
        del L3[IP].chksum

        #Create ICMP header
        L4 = ICMP(type=8, chksum=0, seq=TTL, id=0xFEED)
        del L4[ICMP].chksum

        #Payload
        PAYLOAD = bytearray(0)

        #Pack
        packet = L3/L4/PAYLOAD

        #Send
        response = sr1(packet, timeout=3, verbose=False)
        if response:
            #response.display()
            responseIP = response.getlayer(IP)
            responseICMP = responseIP.getlayer(ICMP)

            requestIP = responseICMP.payload
            requestICMP = requestIP.payload
                  
            if (responseICMP.type == 11 or responseICMP.type == 0):
                seq = requestICMP.seq if requestICMP else -1
                pargs = (responseIP.len, responseIP.src, response.time - packet.sent_time, TTL, seq)
                print(Fore.GREEN + "%-4d bytes from %-15s latency %-4.3f s (TTL %d, SEQ %d)" % pargs)

            if (responseICMP.type == 0 and responseIP.src == ip):
                break

            succ += 1
        else:
            print(Fore.RED + "%s host timeout" % (ip))
            fail += 1

    print(Fore.YELLOW + "Succ: %d Fails: %d Total: %d" % (succ, fail, succ + fail))
        

if __name__ == "__main__":
    init(autoreset=True)
    argc = len(sys.argv) - 1

    if (argc < 1):
        print("Usage: python3 main.py [ip] (max hops)")
        sys.exit(0)

    ip = sys.argv[1]

    hostname = ip
            
    try:
        socket.inet_aton(ip)
    except socket.error:
        ip = socket.gethostbyname(ip)

    if (argc >= 2):
        maxhops = sys.argv[2]
    else:
        maxhops = 30
        
    traceroute(hostname, ip, maxhops)
