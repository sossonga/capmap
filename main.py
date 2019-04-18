# This script analyzes pcaps that have been captured and provides a visualization and statistics
# Shows active IPs on a subnet, how many DNS packets have been transmitted, who hosts are talking to, MAC addresses, etc

import scapy.all
import argparse
import collections
import sys
import os
import webbrowser
from graphviz import Digraph
from jinja2 import Environment, FileSystemLoader
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import ARP

__author__ = 'Amanda Sossong'
__date__ = '20190419'
__version__ = '1.0'


def _args():
    """The _args function uses the argparse library to parse the user's command line arguments
    :return: The command line arguments"""
    arg_parser = argparse.ArgumentParser(description='Outputs a visualization and the statistics of a packet capture')
    arg_parser.add_argument('pcap_file', help='A pcap file')
    return arg_parser.parse_args()


def _parse_pcap(pcap):
    """The _parse_pcap function uses the scapy library to parse through a pcap for network data
    :param pcap: A raw pcap that needs to be parsed
    :return: None"""
    print("Parsing " + str(pcap) + "...")
    # read pcap file
    pkt = scapy.all.rdpcap(pcap)

    # list initializations
    master_ip_list = []
    master_mac_list = []
    master_port_list = []
    dns_query_list = []
    transport_list = []
    arp_list = []
    convo_list = []

    for packet in pkt:
        # if this is a layer 3 packet
        if IP in packet:
            src = packet['IP.src']
            dst = packet['IP.dst']
            mac_src = packet['Ether.src']
            mac_dst = packet['Ether.dst']
            master_mac_list.extend([mac_src, mac_dst])
            # if transport layer is TCP
            if TCP in packet:
                # append TCP to list of transport protocols
                transport_list.append('TCP')
                # append string of source -> destination to list of conversations
                packet_string = src + " -> " + dst
                convo_list.append(packet_string)
                # append source and destination addresses to list of addresses
                master_ip_list.extend([src, dst])
                # append source and destination ports to list of ports
                src_port = packet['TCP.sport']
                dst_port = packet['TCP.dport']
                master_port_list.extend([src_port, dst_port])
            # else if transport layer is UDP
            elif UDP in packet:
                # append UDP to list of transport protocols
                transport_list.append('UDP')
                # append string of source -> destination to list of conversations
                packet_string = src + " -> " + dst
                convo_list.append(packet_string)
                # append source and destination addresses to list of addresses
                master_ip_list.extend([src, dst])
                # append source and destination ports to list of ports
                src_port = packet['UDP.sport']
                dst_port = packet['UDP.dport']
                master_port_list.extend([src_port, dst_port])
                # if packet has DNS
                if DNS in packet:
                    # initialize list
                    dns_query = []
                    # if packet has a DNS query
                    if packet.haslayer(DNSQR):
                        # cast name of query to a string
                        query = packet['DNSQR.qname']
                        str_query = str(query, 'utf-8')
                    # append source address, source port, query, destination address, and destination port to dns list
                    dns_query.extend((src, src_port, str_query, dst, dst_port))
                    dns_query_list.append(dns_query)
            # if ICMP is in packet
            elif ICMP in packet:
                # append ICMP to list of transport protocols
                transport_list.append('ICMP')
                # icmp_type = packet['ICMP.type']
        # else if this is a layer 2 packet
        elif ARP in packet:
            # initialize list
            arp_packet = []
            # append opcode, source address and destination address to list of arp packets
            op_code = packet['ARP.op']
            src = packet['ARP.psrc']
            dst = packet['ARP.pdst']
            arp_packet.extend([src, dst, op_code])
            arp_list.append(arp_packet)

    # split master ip list into a list of source IPs
    src_ips = master_ip_list[::2]
    # split master ip list into a list of destination IPs
    dst_ips = master_ip_list[1::2]

    print("DONE")

    statistics(src_ips, dst_ips, convo_list, master_mac_list, master_port_list, transport_list, dns_query_list,
               arp_list)


def statistics(src_ips, dst_ips, transmissions, mac_list, port_list, transport, dns_queries, arps):
    """The statistics function takes lists from a parsed pcap as input, analyzes the contents and prints a visual
    to a .svg file. A report is then written to an .html file and opened in the default web browser.
    :param src_ips: A list of source addresses from the pcap file
    :param dst_ips: A list of destination addresses
    :param transmissions: A list of source -> destination addresses
    :param mac_list: A list of MAC addresses from the pcap file
    :param port_list: A list of ports from the pcap file
    :param transport: A list of transport protocols
    :param arps: A list of ARP requests and replies
    :param dns_queries: A list of DNS queries
    :return: Statistics for the hosts in the pcap"""
    print("Calculating Statistics...")
    # count number of unique conversations
    packet_count = collections.Counter(transmissions)
    packet_sorted = collections.Counter.most_common(packet_count)
    # count number of unique ports
    port_count = collections.Counter(port_list)
    port_sorted = collections.Counter.most_common(port_count)
    # count number of unique transport protocols
    trans_count = collections.Counter(transport)
    trans_sorted = collections.Counter.most_common(trans_count)
    # count number of unique MAC addresses
    mac_count = collections.Counter(mac_list)
    mac_sorted = collections.Counter.most_common(mac_count)

    print("DONE\nVisualizing...")

    # create a graph for the network hosts
    net_diagram = Digraph(comment='Network Diagram', format='svg')
    net_diagram.attr('node', shape='square')
    # initialize list
    already_done = []
    # zip together source IPs and destination IPs
    for address_pair in zip(src_ips, dst_ips):
        if address_pair not in already_done:
            # create nodes for the source IP and destination IP
            net_diagram.node(address_pair[0])
            net_diagram.node(address_pair[1])
            # create an edge between the source and destination
            net_diagram.edge(address_pair[0], address_pair[1])
            # append to the list of matched hosts
            already_done.append(address_pair)
    # render a graph to the specified file
    net_diagram.render('graph-output/net-map')

    # load the template from the specified folder
    file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)
    template = env.get_template('capmap.html')
    # render the template and pass in lists for processing in the template
    render = template.render(trans=trans_sorted, ports=port_sorted, dns=dns_queries, arp=arps, packets=packet_sorted,
                             macs=mac_sorted)
    # write the completed template to the specified .html file
    filename = os.path.abspath("html/index.html")
    with open(filename, 'w') as f:
        f.write(render)
    # open the .html file in the default web browser
    webbrowser.open_new_tab(filename)

    print("DONE")


def main():
    """The main function loads a pcap file and parses the payload, giving a visualization of the packet and
    adds to the statistics of the subnet
    :return: nothing"""
    args = _args()
    _parse_pcap(args.pcap_file)
    print(f"{str(args.pcap_file)} has been analyzed. Please open html/index.html if not done automatically.")

    sys.exit(0)


if __name__ == '__main__':
    main()

