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

def is_rtp(packet):
    try:
        udp_payload = bytes(packet['UDP'].payload)
        version = (udp_payload[0] >> 6) & 0x03
        if version != 2:
            return False
        
        payload_type = udp_payload[1] & 0x7F
        if 0 <= payload_type <= 127:
            return True
        
        return False
    
    except (IndexError, KeyError, AttributeError):
        return False

def plot_1_byte_values(packets):
    for offset in range(0, 8):
        values_rtp_pt = []
        values_media_type = []
        times = []
        start_time = packets[0].time
        for idx, packet in enumerate(packets):
            udp_payload = bytes(packet['UDP'].payload)
            if len(udp_payload) > offset:
                value = udp_payload[offset]
                times.append(packet.time - start_time)
                if is_rtp(packet):
                    values_rtp_pt.append(value)
                    values_media_type.append(None)
                else:
                    values_rtp_pt.append(None)
                    values_media_type.append(value)
    
        if len(list(filter(lambda x: x is not None, values_rtp_pt))) == 0:
            print(f'1 byte graph at offset {offset}: no RTP PT found')

        if len(list(filter(lambda x: x is not None, values_media_type))) == 0:
            print(f'1 byte graph at offset {offset}: no media types found')

        plt.figure(figsize=(12, 6))
        plt.scatter(times, values_rtp_pt, s=2, color='red', label='RTP PT')
        plt.scatter(times, values_media_type, s=2, color='blue', label='Media Type')
        plt.xlabel('Time [s]')
        plt.ylabel('1-byte Value')
        plt.ylim(0, 255)
        plt.title(f'1-byte Values at Offset {offset}')
        plt.legend()
        plt.savefig(f'1-byte-values-offset-{offset}.png')
        plt.close()

def plot_2_byte_values(packets):
    for offset in range(0, 7):
        values_frame_seq = []
        values_rtp_seq = []
        times = []
        start_time = packets[0].time
        for idx, packet in enumerate(packets):
            udp_payload = bytes(packet['UDP'].payload)
            if len(udp_payload) >= offset + 2:
                value = int.from_bytes(udp_payload[offset:offset + 2], byteorder='big')
                times.append(packet.time - start_time)
                if is_rtp(packet):
                    values_rtp_seq.append(value)
                    values_frame_seq.append(None)
                else:
                    values_rtp_seq.append(None)
                    values_frame_seq.append(value)
    
        if len(list(filter(lambda x: x is not None, values_frame_seq))) == 0:
            print(f'2 byte graph at offset {offset}: no frame sequences')

        if len(list(filter(lambda x: x is not None, values_rtp_seq))) == 0:
            print(f'2 byte graph at offset {offset}: no RTP sequences')

        plt.figure(figsize=(12, 6))
        plt.scatter(times, values_rtp_seq, s=2, color='red', label='RTP Seq')
        plt.scatter(times, values_frame_seq, s=2, color='blue', label='Frame Seq')
        plt.xlabel('Time [s]')
        plt.ylabel('2-byte Value')
        plt.ylim(0, 65535)
        plt.title(f'2-byte Values at Offset {offset}')
        plt.legend()
        plt.savefig(f'2-byte-values-offset-{offset}.png')
        plt.close()

def plot_4_byte_values(packets):
    for offset in range(0, 5):
        values_rtp_ts = []
        values_encrypted = []
        times = []
        start_time = packets[0].time
        for idx, packet in enumerate(packets):
            udp_payload = bytes(packet['UDP'].payload)
            if len(udp_payload) >= offset + 4:
                value = int.from_bytes(udp_payload[offset:offset + 4], byteorder='big')
                times.append(packet.time - start_time)
                if is_rtp(packet):
                    values_rtp_ts.append(value)
                    values_encrypted.append(None)
                else:
                    values_rtp_ts.append(None)
                    values_encrypted.append(value)
    
        if len(list(filter(lambda x: x is not None, values_rtp_ts))) == 0:
            print(f'4 byte graph at offset {offset}: no timestamps found')

        if len(list(filter(lambda x: x is not None, values_encrypted))) == 0:
            print(f'4 byte graph at offset {offset}: no encrypted data found')

        plt.figure(figsize=(12, 6))
        plt.scatter(times, values_rtp_ts, s=2, color='red', label='RTP TS')
        plt.scatter(times, values_encrypted, s=2, color='blue', label='Encrypted')
        plt.xlabel('Time [s]')
        plt.ylabel('4-byte Value')
        plt.ylim(0, 4294967295)
        plt.title(f'4-byte Values at Offset {offset}')
        plt.legend()
        plt.savefig(f'4-byte-values-offset-{offset}.png')
        plt.close()

# Define the file path and parse the pcap file
file_path = sys.argv[1]
udp_packets = parse_pcap(file_path)

# Define filter conditions (example values)
# src_port_range = (3478, 3481)

# Filter packets based on conditions
filtered_packets = udp_packets #filter_packets(udp_packets) #, src_port_range=src_port_range)

# Plot 1-byte, 2-byte, and 4-byte header values for filtered packets at different offsets
plot_1_byte_values(filtered_packets)  # 1-byte values for RTP packet type
plot_2_byte_values(filtered_packets)  # 2-byte values for RTP sequence number
plot_4_byte_values(filtered_packets)  # 4-byte values for RTP timestamp
