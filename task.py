import socket
import struct
import threading
from opendis.dis7 import EntityStatePdu
from scapy.all import Ether, IP, UDP
import dpkt
import time
import matplotlib.pyplot as plt
import numpy as np
from collections import deque

# Global statistics variables
packet_count = 0
packet_timestamps = deque()  # To store timestamps of received packets
latency_list = []  # To store latencies between packets


def multicast_listener(multicast_group, port):
    """listens for UDP packets on a specific multicast group and port. 

    :param 1: multicast group
    :param 2: port number

    """

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Allow reuse of addresses
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the multicast group and port
    sock.bind(("", port))

    # Request membership to the multicast group
    mreq = struct.pack("4sl", socket.inet_aton(multicast_group), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
    while True:
        data, addr = sock.recvfrom(1024)
        process_packet(data)

def process_packet(data):
    """
    The process_packet function extracts information like entity state, position,
    and velocity from the DIS packet using EntityStatePdu.
    Capture only DIS packets by filtering UDP packets on port 3000 (DIS Protocol)
    
    :param 1: data
    """
    global packet_count, packet_timestamps, latency_list
    pkt = Ether(data)
    print("At process data part")
    print(pkt[UDP].dport)
    if IP in pkt and UDP in pkt and pkt[UDP].dport == 3000:
        try:
            # Increment packet count
            packet_count += 1

            # Record the current time
            current_time = time.time()
            packet_timestamps.append(current_time)

            # Calculate latency (time difference between the last two packets)
            if len(packet_timestamps) > 1:
                latency = (packet_timestamps[-1] - packet_timestamps[-2]) * 1000  # Convert to ms
                latency_list.append(latency)
            
            # Decode the DIS packet
            dis_pdu = dpkt.ethernet.Ethernet(data).data.data.data
            entity_pdu = EntityStatePdu()
            entity_pdu.decode(dis_pdu)

            # Extract entity state information
            entity_id = entity_pdu.entityID
            position = entity_pdu.entityLocation
            velocity = entity_pdu.entityLinearVelocity

            # Print the decoded information
            print(f"Entity ID: {entity_id}")
            print(f"Position: ({position.x}, {position.y}, {position.z})")
            print(f"Velocity: ({velocity.x}, {velocity.y}, {velocity.z})\n")

        except Exception as e:
            print(f"Failed to decode packet: {e}")

def analyze_packet_rate():
    global packet_timestamps

    # Calculate the number of packets received every minute (60 seconds)
    time_window = 60
    packet_rate = []

    # Iterate over the timestamps and calculate the rate per minute
    for i in range(0, len(packet_timestamps)):
        # Filter timestamps within the last `time_window` seconds
        start_time = packet_timestamps[i]
        count_in_window = sum(1 for ts in packet_timestamps if start_time <= ts < start_time + time_window)
        packet_rate.append(count_in_window)

    return packet_rate

def display_statistics():
    global packet_timestamps, latency_list, packet_count

    # Calculate packet rate over time
    packet_rate = analyze_packet_rate()

    # Calculate average latency
    avg_latency = np.mean(latency_list) if latency_list else 0

    # Print statistics
    print(f"Total packets captured: {packet_count}")
    print(f"Average latency between packets: {avg_latency:.2f} ms")

    # Plot packet rate over time
    plt.figure(figsize=(10, 5))
    plt.plot(packet_rate, label="Packet Rate (packets/minute)")
    plt.xlabel("Time (minutes)")
    plt.ylabel("Packets")
    plt.title("Packet Rate Over Time")
    plt.legend()
    plt.grid(True)
    plt.show()

    # Plot latency over time
    if latency_list:
        plt.figure(figsize=(10, 5))
        plt.plot(latency_list, label="Latency (ms)")
        plt.xlabel("Packet Number")
        plt.ylabel("Latency (ms)")
        plt.title("Latency Between Packets")
        plt.legend()
        plt.grid(True)
        plt.show()

def main():
    # Define multicast groups and ports
    multicast_group1 = '224.0.0.1'
    multicast_group2 = '224.0.0.2'
    port = 3000

    # Create threads for each multicast listener
    thread1 = threading.Thread(target=multicast_listener, args=(multicast_group1, port))
    thread2 = threading.Thread(target=multicast_listener, args=(multicast_group2, port))

    # Start both threads
    thread1.start()
    thread2.start()

    # Run the packet capture for a fixed duration (e.g., 1 minute) or until manual termination
    capture_duration = 60  # seconds
    time.sleep(capture_duration)

    # Stop the threads
    thread1.join(0)
    thread2.join(0)

    # Display statistics
    display_statistics()

if __name__ == "__main__":
    main()