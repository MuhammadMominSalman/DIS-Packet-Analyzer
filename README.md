# Python DIS Packet Capture and Analysis
This repository contains a Python program for capturing and analyzing DIS (Distributed Interactive Simulation) packets over a network. The program joins two multicast groups, filters for DIS packets, decodes them, and presents the information in a readable format. Additionally, it performs networking analytics such as packet rate, latency, and total packet count, and visualizes the results. A GUI is also provided for real-time monitoring of packet statistics.

## Features

### Capture and Decode Packets
- **Multicast Group Joining**: Simultaneously joins two multicast groups using the UDP protocol and multi-threading.
- **DIS Packet Filtering**: Filters and captures only DIS packets from the network.
- **Packet Decoding**: Extracts information such as entity state, position, and velocity from each packet.
- **Readable Output**: Presents the decoded information in a human-readable format.

### Networking Analytics
- **Packet Rate Over Time**: Visualizes the number of packets received per minute in a graph.
- **Latency Calculation**: Calculates and displays the average delay between packets in milliseconds.
- **Total Packet Count**: Tracks the total number of packets captured.

### GUI Application
- **Real-Time Statistics**: Displays real-time packet capture statistics in a GUI built with `Tkinter`.
- **Packet Information**: Shows decoded DIS packet information.
- **Analytics Graphs**: Displays graphs for packet rate, latency, and other metrics.

## Installation

1. Clone the repository

2. Install the required Python libraries :
   - Python 3.10 or above
    ```bash
    pip install -r requirements.txt
    ```
