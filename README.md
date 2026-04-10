# IDS 
On this Project I will create an IDS from scratch that will using machine learning , this **IDS** will be a hybrid between detection signature and anomalies .

## Packages Needed 
- numpy 
- sklearn
- python-nmap
- scapy : Scapy is a networking library that allows us to perform network and network-related operations using Python.

## Core Components
- A packet capture system
- Traffic analysis module
- A detection engine
- An alert system

## Ideas to Extend the IDS
To enhance or extend the IDS, you can consider designing or implementing the following features / improvements:
- Machine Learning enhancements: You can enhance the IDS capabilities by incorporating deep learning models like Auto Encoders for anomaly detection and using RNNs for sequential pattern analysis. This will improve the system’s ability to identify complex and evolving threats by leveraging advanced feature engineering.

- Performance optimizations: You can optimize the IDS using PyPy for faster execution, packet sampling to handle high-traffic networks, and parallel processing to scale the system efficiently.

- Integration capabilities: You can extend the IDS by considering support for a REST API for remote monitoring, enabling seamless interaction with external systems.

## For Now I should train it 
- capture normal traffic
- extract needed data from it 
```
[
    packet_size,
    packet_rate,
    byte_rate
]
```