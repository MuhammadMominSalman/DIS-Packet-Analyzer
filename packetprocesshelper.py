import struct
import dpkt
import time
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import IP, Ether, UDP
from collections import deque
from opendis.dis7 import *
from opendis.RangeCoordinates import *
from opendis.PduFactory import createPdu

# Global statistics variables
packet_count = 0
packet_timestamps = deque()  # To store timestamps of received packets
latency_list = []  # To store latencies between packets

def process_dis_packet(packet):
    """Process a DIS packet and extract relevant information."""
    # Example processing of an Entity State PDU
    # Assuming the packet is an Entity State PDU, the PDU header is 14 bytes
    pdu_header = packet[:14]
    
    # Unpack the PDU header
    pdu_type, protocol_version, exercise_id, pdu_length, timestamp, pdu_status = struct.unpack('>BBHIIH', pdu_header)
    
    print(f"PDU Type: {pdu_type}")
    print(f"Protocol Version: {protocol_version}")
    print(f"Exercise ID: {exercise_id}")
    print(f"PDU Length: {pdu_length}")
    print(f"Timestamp: {timestamp}")
    print(f"PDU Status: {pdu_status}")
    # print(f"Padding: {padding}")
    
    # Process the Entity State PDU body (starting from byte 12)
    # Example: Extract entity ID (site, application, entity)
    entity_id = packet[12:18]
    site_id, application_id, entity_number = struct.unpack('>HHH', entity_id)
    
    print(f"Entity ID - Site: {site_id}, Application: {application_id}, Entity: {entity_number}")

def print_dis_packet(data):
    gps = GPS()
    pdu = createPdu(data)
    pduTypeName = pdu.__class__.__name__
    if pdu.pduType == 1: # PduTypeDecoders.EntityStatePdu:
        loc = (pdu.entityLocation.x, 
               pdu.entityLocation.y, 
               pdu.entityLocation.z,
               pdu.entityOrientation.psi,
               pdu.entityOrientation.theta,
               pdu.entityOrientation.phi
               )

        body = gps.ecef2llarpy(*loc)

        print("Received {}\n".format(pduTypeName)
              + " Id        : {}\n".format(pdu.entityID.entityID)
              + " Latitude  : {:.2f} degrees\n".format(rad2deg(body[0]))
              + " Longitude : {:.2f} degrees\n".format(rad2deg(body[1]))
              + " Altitude  : {:.0f} meters\n".format(body[2])
              + " Yaw       : {:.2f} degrees\n".format(rad2deg(body[3]))
              + " Pitch     : {:.2f} degrees\n".format(rad2deg(body[4]))
              + " Roll      : {:.2f} degrees\n".format(rad2deg(body[5]))
              )
    else:
        print("Received {}, {} bytes".format(pduTypeName, len(data)), flush=True)

def process_packet(data):
    """
    The process_packet function extracts information like entity state, position,
    and velocity from the DIS packet using EntityStatePdu.
    Capture only DIS packets by filtering UDP packets on port 3000 (DIS Protocol)
    
    :param 1: data
    """
    global packet_count, packet_timestamps, latency_list
    pkt = Ether(data)
    # if IP in pkt and UDP in pkt and pkt[UDP].dport == 3000:
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