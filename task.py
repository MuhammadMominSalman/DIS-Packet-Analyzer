import socket
import struct
import threading
from opendis.dis7 import EntityStatePdu
from scapy.all import IP, Ether, UDP
import dpkt
import time
import matplotlib.pyplot as plt
import numpy as np
from collections import deque
import sys
import time

from io import BytesIO

from opendis.DataOutputStream import DataOutputStream
from opendis.RangeCoordinates import *

# Global statistics variables
packet_count = 0
packet_timestamps = deque()  # To store timestamps of received packets
latency_list = []  # To store latencies between packets


def multicast_sender(multicast_group, port):
    """send UDP packets on a specific multicast group and port. 

    :param 1: multicast group
    :param 2: port number

    """
    # 2 hop restriction in network
    ttl = struct.pack('b', 2)

    # Create a UDP socket
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    data = "Hello World"
    
    while True:
        # Send from the multicast group and port
        sock.sendto(data.encode(), (multicast_group, port))
        time.sleep(2)

def multicast_dis_packet_sender(multicast_group, port):
    """send UDP packets on a specific multicast group and port. 

    :param 1: multicast group
    :param 2: port number

    """
    # 2 hop restriction in network
    ttl = struct.pack('b', 2)

    # Create a UDP socket
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    pdu = EntityStatePdu()
    pdu.entityID.entityID = 42
    pdu.entityID.siteID = 17
    pdu.entityID.applicationID = 23
    pdu.marking.setString('Igor3d')

    gps = GPS() # conversion helper
     # Entity in Monterey, CA, USA facing North, no roll or pitch
    montereyLocation = gps.llarpy2ecef(deg2rad(36.6),   # longitude (radians)
                                       deg2rad(-121.9), # latitude (radians)
                                       1,               # altitude (meters)
                                       0,               # roll (radians)
                                       0,               # pitch (radians)
                                       0                # yaw (radians)
                                       )

    pdu.entityLocation.x = montereyLocation[0]
    pdu.entityLocation.y = montereyLocation[1]
    pdu.entityLocation.z = montereyLocation[2]
    pdu.entityOrientation.psi = montereyLocation[3]
    pdu.entityOrientation.theta = montereyLocation[4]
    pdu.entityOrientation.phi = montereyLocation[5]


    memoryStream = BytesIO()
    outputStream = DataOutputStream(memoryStream)
    pdu.serialize(outputStream)
    data = memoryStream.getvalue()
    
    while True:
        # Send from the multicast group and port
        sock.sendto(data, (multicast_group, port))
        time.sleep(5)

def multicast_listener(multicast_groups, ports):
    """listens for UDP packets on a specific multicast group and port. 

    :param 1: multicast groups
    :param 2: port numbers

    """
    socket_list = []
    for _, (multicast_group, port) in enumerate(zip(multicast_groups, ports)):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        # Allow reuse of addresses
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to the multicast group and port
        sock.bind(('', port))

        # Request membership to the multicast group
        mreq = struct.pack("4sl", socket.inet_aton(multicast_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        socket_list.append(sock)
    
    while True:
        for sock in socket_list:
            data, _ = sock.recvfrom(4096)
            # Sanity check
            # print(sock.recv(1024).decode())
            process_packet(data)
            # process_dis_packet(data)

def process_dis_packet(packet):
    """Process a DIS packet and extract relevant information."""
    # Example processing of an Entity State PDU
    # Assuming the packet is an Entity State PDU, the PDU header is 12 bytes
    pdu_header = packet[:12]
    
    # Unpack the PDU header
    pdu_type, protocol_version, exercise_id, pdu_length, timestamp, pdu_status, padding = struct.unpack('>BBHIIH', pdu_header)
    
    print(f"PDU Type: {pdu_type}")
    print(f"Protocol Version: {protocol_version}")
    print(f"Exercise ID: {exercise_id}")
    print(f"PDU Length: {pdu_length}")
    print(f"Timestamp: {timestamp}")
    print(f"PDU Status: {pdu_status}")
    print(f"Padding: {padding}")
    
    # Process the Entity State PDU body (starting from byte 12)
    # Example: Extract entity ID (site, application, entity)
    entity_id = packet[12:18]
    site_id, application_id, entity_number = struct.unpack('>HHH', entity_id)
    
    print(f"Entity ID - Site: {site_id}, Application: {application_id}, Entity: {entity_number}")

def process_packet(data):
    """
    The process_packet function extracts information like entity state, position,
    and velocity from the DIS packet using EntityStatePdu.
    Capture only DIS packets by filtering UDP packets on port 3000 (DIS Protocol)
    
    :param 1: data
    """
    global packet_count, packet_timestamps, latency_list
    pkt = Ether(data)
    print(pkt[IP])
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
    time_window = 10
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
    port1 = 6060
    port2 = 6061

    # # Create thread for each multicast sender
    thread1 = threading.Thread(target=multicast_dis_packet_sender, args=(multicast_group1, port1))
    thread2 = threading.Thread(target=multicast_dis_packet_sender, args=(multicast_group2, port2))
    # Create thread for multicast listener
    thread3 = threading.Thread(target=multicast_listener, args=([multicast_group1, multicast_group2], [port1, port2]))

    # Start both threads
    thread1.start()
    thread2.start()
    thread3.start()


    # Run the packet capture for a fixed duration (e.g., 1 minute) or until manual termination
    capture_duration = 25  # seconds
    time.sleep(capture_duration)

    # Stop the threads
    thread1.join(0)
    thread2.join(0)
    thread3.join(0)

    # Display statistics
    display_statistics()
    sys.exit()

if __name__ == "__main__":
    main()