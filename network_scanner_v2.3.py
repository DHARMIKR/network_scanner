#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():

    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP Range")
    (values, arguments) = parser.parse_args()
    return values.target

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    clients_list = []
    for element in answered_list:
        client_dict = {"MAC": element[1].hwsrc, "IP": element[1].psrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("\nMAC Address\t\t\tIP\n--------------------------------------------------")
    for client in result_list:
        print(client["MAC"] + "\t\t" + client["IP"])

print(''' ____  _                          _ _ 
|  _ \| |__   __ _ _ __ _ __ ___ (_) | __ 
| | | | '_ \ / _` | '__| '_ ` _ \| | |/ / 
| |_| | | | | (_| | |  | | | | | | |   < 
|____/|_| |_|\__,_|_|  |_| |_| |_|_|_|\_\ 
''')

Target = get_arguments()


if Target is not None:
    scan_result = scan(Target)
    print_result(scan_result)
else:
    ip_address = raw_input("IP Address>")
    scan_result = scan(ip_address)
    print_result(scan_result)
