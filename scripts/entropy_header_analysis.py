#!/usr/bin/env python3

import struct
from scapy.all import rdpcap
import matplotlib.pyplot as plt
import numpy as np
import sys

# Function to parse the pcap file and extract UDP packets
def parse_pcap(file_path):
    packets = rdpcap(file_path)
    udp_packets = [pkt for pkt in packets if pkt.haslayer('UDP')]
    return udp_packets

# Function to filter packets based on specific conditions
def filter_packets(packets, src_ip=None, dst_ip=None, src_port_range=None, dst_port_range=None):
    filtered_packets = []
    for packet in packets:
        if src_ip and packet['IP'].src != src_ip:
            continue
        if dst_ip and packet['IP'].dst != dst_ip:
            continue
        if src_port_range:
            if not (src_port_range[0] <= packet['UDP'].sport <= src_port_range[1]):
                continue
        if dst_port_range:
            if not (dst_port_range[0] <= packet['UDP'].dport <= dst_port_range[1]):
                continue
        filtered_packets.append(packet)
    return filtered_packets

# Function to extract and plot header values
def plot_header_values(packets, block_size):
    for offset in range(0, 32, block_size):
        values = []
        for idx, packet in enumerate(packets):
            udp_payload = bytes(packet['UDP'].payload)
            if len(udp_payload) >= offset + block_size:
                block = udp_payload[offset:offset + block_size]
                value = int.from_bytes(block, byteorder='big')
                values.append((idx, value))
        
        if values:
            indices, value_list = zip(*values)
            plt.figure(figsize=(12, 6))
            plt.scatter(indices, value_list, s=2)
            plt.xlabel('Packet Index')
            plt.ylabel(f'{block_size * 8}-bit Value at Offset {offset}')
            plt.title(f'{block_size * 8}-bit Values at Offset {offset}')
            plt.savefig(f'{block_size * 8}-bit-offset-{offset}.png')
            plt.close()

# Define the file path and parse the pcap file
file_path = sys.argv[1]
udp_packets = parse_pcap(file_path)

# Define filter conditions (example values)
dst_ip = '172.30.12.151'
src_port_range = (3478, 3481)

# Filter packets based on conditions
filtered_packets = filter_packets(udp_packets, dst_ip=dst_ip, src_port_range=src_port_range)

# Plot 8-bit, 16-bit, and 32-bit header values at various offsets for filtered packets
plot_header_values(filtered_packets, 1)  # 8-bit values
plot_header_values(filtered_packets, 2)  # 16-bit values
plot_header_values(filtered_packets, 4)  # 32-bit values
