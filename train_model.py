from scapy.all import rdpcap, IP, TCP
from collections import defaultdict
import numpy as np

def extract_training_data_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    flow_stats = defaultdict(lambda: {
        'packet_count': 0,
        'byte_count': 0,
        'start_time': None,
        'last_time': None
    })

    training_data = []

    for packet in packets:
        # Keep only IP + TCP packets
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)

            current_time = packet.time

            if stats['start_time'] is None:
                stats['start_time'] = current_time

            stats['last_time'] = current_time

            # Prevent division by zero
            duration = max(stats['last_time'] - stats['start_time'], 0.001)

            packet_size = len(packet)
            packet_rate = stats['packet_count'] / duration
            byte_rate = stats['byte_count'] / duration

            training_data.append([
                packet_size,
                packet_rate,
                byte_rate
            ])

    return np.array(training_data)