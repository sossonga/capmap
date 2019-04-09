# This script analyzes pcaps that have been captured and provides a visualization and statistics
# Shows active IPs on a subnet, how many DNS packets have been transmitted, who hosts are talking to, MAC addresses
# and more

import scapy.all
import argparse
import sys
import networkx as nx
import matplotlib.pyplot as plt

__author__ = 'Amanda Sossong'
__date__ = '20190322'
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
    :return: A parsed pcap for visualization"""
    # print("Parsing " + str(pcap) + "...")
    pkt = scapy.all.rdpcap(pcap)
    netgraph = nx.Graph()
    for packet in pkt:
        try:
            print(f"{packet['IP.src']}, {packet['Ether.src']} -> {packet['IP.dst']}, {packet['Ether.dst']}")
            netgraph.add_nodes_from([packet['IP.src'], packet['IP.dst']])
            netgraph.add_edge((packet['IP.src']), (packet['IP.dst']))
        except IndexError:
            continue
    nx.draw(netgraph, with_labels=True, font_weight='bold')


def visualize(parsed_pcap):
    """The visualize function takes a parsed pcap as input, analyzes the contents and creates a visualization
    :param parsed_pcap: A pcap that has been parsed through
    :return: A visual representation of the pcap data"""
    print("Visualizing " + str(parsed_pcap) + "...")
    netgraph = nx.Graph()

    return parsed_pcap


def statistics(parsed_pcap):
    """The statistics function takes a parsed through pcap as input, analyzes the contents and appends the data
    to a text file for statistics. The statistics are then printed.
    :param parsed_pcap: A pcap that has been parsed through
    :return: Statistics for the hosts in a subnet"""
    print("Calculating statistics...")
    return parsed_pcap


def main():
    """The main function loads a pcap file and parses the payload, giving a visualization of the packet and
    adds to the statistics of the subnet
    :return: nothing"""
    args = _args()
    _parse_pcap(args.pcap_file)
    visualize(args.pcap_file)
    statistics(args.pcap_file)
    print(str(args.pcap_file) + " has been analyzed")

    sys.exit(0)
    # print("Hello World!")


if __name__ == '__main__':
    main()

