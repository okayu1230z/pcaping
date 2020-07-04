# -*- coding: utf-8 -*-
#!/usr/bin/python3

'''
pcap_analysis.py

dpkt
    dpkt is a python module for fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols
    dpkt document ; https://dpkt.readthedocs.io/en/latest/print_http_requests.html
'''

import os
import sys
import dpkt
import socket
import pathlib
import collections

def touch(path):
    f = open(path, 'w')
    f.close()

def main():
    args = sys.argv

    # this is simple argument check, please refactor.
    if "pcap_analysis.py" not in args[-1]:
        filename = args[1]
        pcap_reader = dpkt.pcap.Reader(open(filename, 'rb'))
        base = os.path.splitext(os.path.basename(filename))[0]
        output_tcp_log = base + "_tcp.log"
        output_udp_log = base + "_udp.log"
        output_log = base + ".log"
    else:
        print('** pcap_analysis.py wants argment')
        return
    
    touch(output_log)
    touch(output_tcp_log)
    touch(output_udp_log)

    LOCAL_IP = ['10.', '172', '192']

    total_count = tcp_count = udp_count = arp_count = other_count = 0

    tcp_ip_list = []
    udp_ip_list = []

    for t, buf in pcap_reader:
        eth = dpkt.ethernet.Ethernet(buf)
        p_type = str(eth.data.__class__.__name__)
        
        total_count += 1
        if p_type == 'IP':
            ip_addr = socket.inet_ntoa(eth.data.dst)
            if ip_addr[:3] in LOCAL_IP:
                total_count -= 1
                continue
            elif (eth.data.data.__class__.__name__) == 'TCP':
                tcp_count += 1
                #tcp_ip_list.append(socket.inet_ntoa(eth.data.src))
                tcp_ip_list.append(ip_addr)
            elif (eth.data.data.__class__.__name__) == 'UDP':
                udp_count += 1
                udp_ip_list.append(ip_addr)
            else:
                other_count += 1
                print(eth.data.data.__class__.__name__)
        elif p_type == 'ARP':
            arp_count += 1
        else:
            other_count += 1
            print(p_type)

        # stopper
        #total_count += 1
        #if total_count == 30:
        #    return

    pathlib.Path(output_log).touch()
    with open(output_log, mode='a') as f:
        f.write("total_count:" + str(total_count) + ":" + str(total_count/total_count)+"\n")
        f.write("tcp_count:" + str(tcp_count) + ":" + str(tcp_count/total_count) +"\n")
        f.write("udp_count:" + str(udp_count) + ":" + str(udp_count/total_count) +"\n")
        f.write("arp_count:" + str(arp_count) + ":" + str(arp_count/total_count) +"\n")
        f.write("other_count:" + str(other_count) + ":" + str(other_count/total_count) +"\n")

    print("total_count:" + str(total_count) + ":" + str(total_count/total_count))
    print("tcp_count:" + str(tcp_count) + ":" + str(tcp_count/total_count)[:5])
    print("udp_count:" + str(udp_count) + ":" + str(udp_count/total_count)[:5])
    print("arp_count:" + str(arp_count) + ":" + str(arp_count/total_count)[:5])
    print("other_count:" + str(other_count) + ":" + str(other_count/total_count))

    with open(output_log, mode='a') as f:
        f.write("total_count:" + str(total_count) + ":" + str(total_count/total_count)+"\n")
        f.write("tcp_count:" + str(tcp_count) + ":" + str(tcp_count/total_count) +"\n")
        f.write("udp_count:" + str(udp_count) + ":" + str(udp_count/total_count) +"\n")
        f.write("arp_count:" + str(arp_count) + ":" + str(arp_count/total_count) +"\n")
        f.write("other_count:" + str(other_count) + ":" + str(other_count/total_count) +"\n")

    tcp_ip_dict = collections.Counter(tcp_ip_list).most_common()
    udp_ip_dict = collections.Counter(udp_ip_list).most_common()

    with open(output_tcp_log, mode='a') as f:
        for t_tuple in tcp_ip_dict:
            f.write(str(t_tuple[0])+":"+str(t_tuple[1])+"\n")

    with open(output_udp_log, mode='a') as f:
        for u_tuple in udp_ip_dict:
            f.write(str(u_tuple[0])+":"+str(u_tuple[1])+"\n")

if __name__ == "__main__":
    main()