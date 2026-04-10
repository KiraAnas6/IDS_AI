from scapy.all import IP, TCP
from main import IntrusionDetectionSystem
import numpy as np

def test_ids():
    ids = IntrusionDetectionSystem()

    # Train anomaly detector so it doesn't crash
    ids.detection_engine.train_anomaly_detector(np.array([
        [60, 1, 60],
        [70, 2, 140],
        [80, 3, 240],
        [90, 2, 180],
        [100, 1, 100]
    ]))

    # TEMP test-friendly rules
    ids.detection_engine.signature_rules = {
        'syn_flood': {
            'condition': lambda features: (
                int(features['tcp_flags']) == 0x02 and
                features['packet_rate'] > 1
            )
        },
        'port_scan': {
            'condition': lambda features: (
                features['packet_size'] < 100 and
                features['packet_rate'] > 1
            )
        }
    }

    test_packets = []

    # Normal traffic
    test_packets.append(
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A")
    )

    # SYN flood simulation (same flow repeated)
    for _ in range(5):
        test_packets.append(
            IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S")
        )

    print("Starting IDS Test...")

    for i, packet in enumerate(test_packets, 1):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        features = ids.traffic_analyzer.analyze_packet(packet)

        if features:
            print("Features:", features)

            threats = ids.detection_engine.detect_threats(features)

            if threats:
                print(f"Detected threats: {threats}")

                for threat in threats:
                    packet_info = {
                        'source_ip': packet[IP].src,
                        'destination_ip': packet[IP].dst,
                        'source_port': packet[TCP].sport,
                        'destination_port': packet[TCP].dport,
                    }
                    ids.alert_system.generate_alert(threat, packet_info)
            else:
                print("No threats detected.")
        else:
            print("Packet ignored.")

    print("\nIDS Test Completed.")

if __name__ == "__main__":
    test_ids()