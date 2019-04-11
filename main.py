# This script analyzes pcaps that have been captured and provides a visualization and statistics
# Shows active IPs on a subnet, how many DNS packets have been transmitted, who hosts are talking to, MAC addresses
# and more

import scapy.all
import argparse
import collections
import sys
import networkx as nx
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
    dst_ip_list = []
    for packet in pkt:
        try:
            ip = get_src_ip(packet)
            dip = get_dst_ip(packet)
            src_ip_list.append(ip)
            dst_ip_list.append(dip)
        except IndexError:
            continue
    statistics(src_ip_list, dst_ip_list)


def get_transport(packet):
    """The get_transport function extracts the transport protocol from the input packet
    :param packet:
    :return the transport protocol (TCP/UDP):"""
    if TCP in packet:
        transport = 'TCP'
        return transport
    elif UDP in packet:
        transport = 'UDP'
        return transport


def get_src_ip(packet):
    """The get_src_ip function extracts the source IP from the input packet
    :param packet:
    :return the source IP address:"""
    src = packet['IP.src']
    return src


def get_dst_ip(packet):
    """The get_dst_ip function extracts the destination IP from the input packet
    :param packet:
    :return the destination IP address:"""
    dst = packet['IP.dst']
    return dst


def get_src_mac(packet):
    """The get_src_mac function extracts the source MAC address from the input packet
    :param packet:
    :return the source MAC address:"""
    src = packet['Ether.src']
    return src

def get_dst_mac(packet):
    """The get_dst_mac function extracts the destination MAC address from the input packet
    :param packet:
    :return the destination MAC address:"""
    dst = packet['Ether.dst']
    return dst


def visualize(filename, parsed_pcap):
    """The visualize function takes a parsed pcap as input, analyzes the contents and creates a visualization
    :param filename: name of the pcap file
    :param parsed_pcap: A pcap that has been parsed through
    :return: A visual representation of the pcap data"""
    print("Visualizing " + str(filename) + "...")
    file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)
    template = env.get_template('capmap.html')
    output = template.render(pkt=parsed_pcap)
    # print(output)
    # return parsed_pcap


def statistics(src_ip_list, dst_ip_list):
    """The statistics function takes a parsed through pcap as input, analyzes the contents and appends the data
    to a text file for statistics. The statistics are then printed.
    :param src_ip_list: A list of source IP addresses from the pcap file
    :param dst_ip_list: A list of destination IP addresses from the pcap file
    :return: Statistics for the hosts in a subnet"""
    print("Calculating statistics...")
    src_ip_count = collections.Counter(src_ip_list)
    dst_ip_count = collections.Counter(dst_ip_list)
    for key, value in src_ip_count.items():
        print(f"IP Address {key} has sent {value} packets")
    print("--------------------------")
    for key, value in dst_ip_count.items():
        print(f"IP Address {key} has received {value} packets")
    return src_ip_list


def main():
    """The main function loads a pcap file and parses the payload, giving a visualization of the packet and
    adds to the statistics of the subnet
    :return: nothing"""
    args = _args()
    _parse_pcap(args.pcap_file)
    # visualize(args.pcap_file, pkt)
    print(str(args.pcap_file) + " has been analyzed")

    sys.exit(0)


if __name__ == '__main__':
    main()

