# capmap
The friendly tool for packet analysis and network mapping.

capmap uses scapy, jinja2, and graphviz to provide a map of the network and statistics on who your hosts are talking to.  
The script parses each packet in the pcap for the following:
* Source IP Address
* Destination IP Address
* Source MAC Address
* Destination MAC Address
* Source Port
* Destination Port
* Transport Protocol (TCP/UDP)
* DNS Queries
* ICMP echo-requests/echo-replies
* ARP requests/replies

## Tools
### scapy
capmap uses the [scapy](https://scapy.readthedocs.io/en/latest/index.html) library to parse through a pcap file.  
It parses through TCP, UDP, ICMP, IP, MAC, and ARP data.
```
[IP.src]
[IP.dst]
[Ether.src]
[Ether.dst]
[TCP.sport]
[TCP.dport]
[UDP.sport]
[UDP.dport]
[DNSQR.qname]
[ARP.op]
[ARP.prsc]
[ARP.pdst]
```

### jinja2
capmap uses the [jinja2](http://jinja.pocoo.org/docs/2.10/) library to create a HTML template for the statistics output and network visualization.  
in main.py:
```
file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)
    template = env.get_template('capmap.html')
    # render the template and pass in lists for processing in the template
    render = template.render(trans=trans_sorted, ports=port_sorted, dns=dns_queries, arp=arps,      
                             packets=packet_sorted,macs=mac_sorted)
    # write the completed template to the specified .html file
    filename = os.path.abspath("html/index.html")
    with open(filename, 'w') as f:
        f.write(render)
```
in templates/capmap.html:
```
{% for key, value in packets %}
        <tr>
            <td>{{ key }}</td>
            <td>{{ value }}</td>
        </tr>
{% endfor %}
```

### graphviz
capmap uses the [graphviz](https://graphviz.readthedocs.io/en/stable/) library to create a graph of the network hosts and saves it to a .svg file.  


![Image of Network Graph](graph-output/net-map.svg)
```
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
```

## Tutorial
On the command line, enter the path of the pcap file after the script path.  
```
python3 main.py pcaps/test.pcap
```
