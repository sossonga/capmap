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
from scapy.layers.inet import TCP, UDP, ICMP

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
    for packet in pkt:
        try:
            s = packet['IP.src']
            d = packet['IP.dst']
            if TCP in packet:
                src_ip_list.append('TCP')
                src_ip_list.append(s)
                src_ip_list.append(d)
                sp = packet['TCP.sport']
                dp = packet['TCP.dport']
                src_port_list.append(sp)
                src_port_list.append(dp)
            elif UDP in packet:
                src_ip_list.append('UDP')
                src_ip_list.append(s)
                src_ip_list.append(d)
                sp = packet['UDP.sport']
                dp = packet['UDP.dport']
                src_port_list.append(sp)
                src_port_list.append(dp)
        except IndexError:
            continue
    transport = src_ip_list[::3]
    src_ips = src_ip_list[1::3]
    dst_ips = src_ip_list[2::3]
    src_macs = src_mac_list[::2]
    dst_macs = src_mac_list[1::2]
    print("DONE")
    statistics(src_ips, dst_ips, src_port_list, transport)


def statistics(src_ips, dst_ips, port_list, transport):
    """The statistics function takes a parsed through pcap as input, analyzes the contents and appends the data
    to a text file for statistics. The statistics are then printed.
    :param src_ips: A list of source addresses from the pcap file
    :param dst_ips: A list of destination addresses from the pcap file
    :param port_list: A list of ports from the pcap file
    :param transport: A list of transport protocols from the pcap file
    :return: Statistics for the hosts in a subnet"""
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

    dot = Digraph(comment='Network Diagram', format='jpeg')
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
    render = template.render(data=ip_count, trans=trans_count, ports=port_count)
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

