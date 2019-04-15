# This script analyzes pcaps that have been captured and provides a visualization and statistics
# Shows active IPs on a subnet, how many DNS packets have been transmitted, who hosts are talking to, MAC addresses
# and more

import scapy.all
import argparse
import collections
import sys
import os
import webbrowser
from graphviz import Digraph
from jinja2 import Environment, FileSystemLoader
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import ARP

__author__ = 'Amanda Sossong'
__date__ = '20190419'
__version__ = '1.0'


def _args():
    """The _args function uses the argparse library to parse the user's command line arguments
    :return: The command line arguments"""
    arg_parser = argparse.ArgumentParser(description='Outputs a visualization and statistics of a packet capture')
    arg_parser.add_argument('pcap_file', help='A pcap file')
    return arg_parser.parse_args()


def _parse_pcap(pcap):
    """The _parse_pcap function uses the scapy library to parse through a pcap for traffic data
    :param pcap: A raw pcap that needs to be parsed
    :return Nothing:"""
    print("Parsing " + str(pcap) + "...")
    pkt = scapy.all.rdpcap(pcap)
    src_ip_list = []
    src_mac_list = []
    src_port_list = []
    dns_query_list = []
    transport_list = []
    arp_list = []
    for packet in pkt:
        try:
            if IP in packet:
                src = packet['IP.src']
                dst = packet['IP.dst']
                if TCP in packet:
                    transport_list.append('TCP')
                    src_ip_list.append(src)
                    src_ip_list.append(dst)
                    src_port = packet['TCP.sport']
                    dst_port = packet['TCP.dport']
                    src_port_list.append(src_port)
                    src_port_list.append(dst_port)
                elif UDP in packet:
                    transport_list.append('UDP')
                    src_ip_list.append(src)
                    src_ip_list.append(dst)
                    src_port = packet['UDP.sport']
                    dst_port = packet['UDP.dport']
                    if DNS in packet:
                        dns_query = []
                        if packet.haslayer(DNSQR):
                            query = packet['DNSQR.qname']
                            str_query = str(query, 'utf-8')
                            # response = packet['DNSRR.rrname']
                        dns_query.extend((src, src_port, str_query, dst, dst_port))
                        dns_query_list.append(dns_query)
                    src_port_list.append(src_port)
                    src_port_list.append(dst_port)
                elif ICMP in packet:
                    transport_list.append('ICMP')
                    icmp_type = packet['ICMP.type']
                    if icmp_type == 0:
                        icmp_type = "Echo-Request"
                    elif icmp_type == 8:
                        icmp_type = "Echo-Reply"
            elif ARP in packet:
                arp_packet = []
                op_code = packet['ARP.op']
                src = packet['ARP.psrc']
                dst = packet['ARP.pdst']
                arp_packet.extend((src, dst, op_code))
                arp_list.append(arp_packet)
                # print(f"{src} says {op_code} {dst}")
        except IndexError as er:
            print(er)
            continue
    src_ips = src_ip_list[::2]
    dst_ips = src_ip_list[1::2]
    src_macs = src_mac_list[::2]
    dst_macs = src_mac_list[1::2]
    print("DONE")
    statistics(src_ips, dst_ips, src_port_list, transport_list, dns_query_list, arp_list)


def statistics(src_ips, dst_ips, port_list, transport, dns_queries, arps):
    """The statistics function takes lists from a parsed pcap as input, analyzes the contents and prints a visual
    to a .svg file. A report is then written to an .html file and opened in the default web browser.
    :param src_ips: A list of source addresses from the pcap file
    :param dst_ips: A list of destination addresses
    :param port_list: A list of ports from the pcap file
    :param transport: A list of transport protocols
    :param arps: A list of ARP requests and replies
    :param dns_queries: A list of DNS queries
    :return: Statistics for the hosts in the pcap"""
    print("--------------------------\nPCAP Statistics Report\n--------------------------")
    ip_count = collections.Counter(src_ips)
    dests = collections.Counter(dst_ips)
    port_count = collections.Counter(port_list)
    trans_count = collections.Counter(transport)
    # mac_count = collections.Counter(mac_list)
    # print("--------------------------\nHost Transmissions\n--------------------------")
    # for key, value in ip_count.items():
    #     print(f"Host {key} has sent {value} packet(s)")
    # print("--------------------------\nTransport Protocols\n--------------------------")
    # for key, value in trans_count.items():
    #     print(f"{key} Packets transmitted: {value}")
    # print("--------------------------\n Port Numbers\n--------------------------")
    # for key, value in port_count.items():
    #     print(f"Port {key} was used {value} times")
    # print("--------------------------")
    # print(type(ip_count))
    print("Visualizing...")
    dot = Digraph(comment='Network Diagram', format='svg')
    dot.attr('node', shape='square')
    already_done = []
    for address_pair in zip(src_ips, dst_ips):
        if address_pair not in already_done:
            dot.node(address_pair[0])
            dot.node(address_pair[1])
            dot.edge(address_pair[0], address_pair[1])
            already_done.append(address_pair)

    dot.render('graph-output/net-map')
    file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)
    template = env.get_template('capmap.html')
    render = template.render(data=ip_count, trans=trans_count, ports=port_count, dns=dns_queries, arp=arps)
    filename = os.path.abspath("html/index.html")
    with open(filename, 'w') as f:
        f.write(render)
    webbrowser.open_new_tab(filename)


def main():
    """The main function loads a pcap file and parses the payload, giving a visualization of the packet and
    adds to the statistics of the subnet
    :return: nothing"""
    args = _args()
    _parse_pcap(args.pcap_file)
    print(str(args.pcap_file) + " has been analyzed")

    sys.exit(0)


if __name__ == '__main__':
    main()

