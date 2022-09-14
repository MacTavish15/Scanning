from scapy.all import *
import ipaddress
import sys
from socket import getservbyport


def SynScan(host):
    ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags='S'),timeout=2,verbose=0)
    print("Open ports at %s" % host)
    for (s,r,) in ans:
        if s.haslayer(TCP) and r.haslayer(TCP):
            if s[TCP].dport == r[TCP].sport:
                try:
                    print(str(s[TCP].dport) + " : " + getservbyport(s[TCP].dport) + " IS OPEN !")
                except:
                    print(str(s[TCP].dport) + " IS OPEN !")
try:
    if sys.argv[2] == '-p':
            
        ports = sys.argv[3].split(',')
        ports = [eval(p) for p in ports]
        hosts = [str (ip)  for ip in ipaddress.IPv4Network(sys.argv[1])]

        for host in hosts:
            SynScan(host)
    else: 
        print("Error in syntax ! example : sudo python3 Scanning.py 192.168.1.0/24 -p 80,54,45,8080 or 192.168.1.1 -p 80,54,45,8080")
except:
    print("Error in syntax ! example : sudo python3 Scanning.py 192.168.1.0/24 -p 80,54,45,8080 or 192.168.1.1 -p 80,54,45,8080")
