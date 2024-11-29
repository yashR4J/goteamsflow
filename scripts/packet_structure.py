import sys
import scapy.all as scapy
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict

pcap_file = sys.argv[1]
packets = scapy.rdpcap(pcap_file)

def extract_packet_features(packets):
    features = defaultdict(list)
    
    for packet in packets:
        if packet.haslayer(scapy.UDP):
            udp_layer = packet[scapy.UDP]
            ip_layer = packet[scapy.IP]
            
            # Extract packet features
            features['time'].append(packet.time)
            features['src_ip'].append(ip_layer.src)
            features['dst_ip'].append(ip_layer.dst)
            features['src_port'].append(udp_layer.sport)
            features['dst_port'].append(udp_layer.dport)
            features['length'].append(len(packet))
            features['payload'].append(bytes(udp_layer.payload))
    
    return pd.DataFrame(features)

def group_packets_by_criteria(df):
    # Define criteria for grouping (example: by destination port)
    video_ports = [3478, 3479]  # Example ports for video traffic
    audio_ports = [3480, 3481]  # Example ports for audio traffic
    screen_share_ports = [5008, 5009]  # Example ports for screen sharing traffic
    
    df['media_type'] = 'unknown'
    
    df.loc[df['dst_port'].isin(video_ports), 'media_type'] = 'video'
    df.loc[df['dst_port'].isin(audio_ports), 'media_type'] = 'audio'
    df.loc[df['dst_port'].isin(screen_share_ports), 'media_type'] = 'screen_share'
    
    # Further refine the classification based on additional context
    df['traffic_type'] = 'unknown'
    df.loc[(df['dst_port'] == 443) & (df['src_port'] == 53), 'traffic_type'] = 'DNS Query'
    df.loc[(df['dst_port'] == 443) & (df['traffic_type'] != 'DNS Query'), 'traffic_type'] = 'Authentication'
    df.loc[df['dst_port'].isin([3478, 3479, 3480, 3481]), 'traffic_type'] = 'Media Transmission'
    
    return df

# Plot packet features
def plot_packet_features(df):
    # Plot packet length over time
    plt.figure(figsize=(12, 6))
    plt.scatter(df['time'], df['length'], c=df['media_type'].map({'video': 'red', 'audio': 'blue', 'screen_share': 'green', 'unknown': 'grey'}), alpha=0.5)
    plt.xlabel('Time')
    plt.ylabel('Packet Length')
    plt.title('Packet Length Over Time')
    plt.legend(handles=[
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Video'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Audio'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='Screen Share'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='grey', markersize=10, label='Unknown')
    ])
    plt.show()
    
    # Plot packet count by media type
    plt.figure(figsize=(8, 6))
    df['media_type'].value_counts().plot(kind='bar', color=['red', 'blue', 'green', 'grey'])
    plt.xlabel('Media Type')
    plt.ylabel('Packet Count')
    plt.title('Packet Count by Media Type')
    plt.show()
    
    # Plot packet count by traffic type
    plt.figure(figsize=(8, 6))
    df['traffic_type'].value_counts().plot(kind='bar', color=['orange', 'purple', 'cyan', 'grey'])
    plt.xlabel('Traffic Type')
    plt.ylabel('Packet Count')
    plt.title('Packet Count by Traffic Type')
    plt.show()

# Main execution
if __name__ == "__main__":
    df = extract_packet_features(packets)
    df_grouped = group_packets_by_criteria(df)
    plot_packet_features(df_grouped)
