import scapy.all as scapy
import argparse
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    print("IP \t\t\t\t MAC\n-----------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t\t" + element[1].hwsrc)

def get_args():
    parser = argparse.ArgumentParser(description="Process an IP range.")
    parser.add_argument("-r", "--range", required=True, help="network range to scan")
    args = parser.parse_args()
    scan(args.range)   


get_args()