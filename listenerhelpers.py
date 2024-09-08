import struct
import socket
from packetprocesshelper import process_packet, process_dis_packet, print_dis_packet


executing = True
def multicast_listener(multicast_groups, ports):
    """listens for UDP packets on a specific multicast group and port. 

    :param 1: multicast groups
    :param 2: port numbers

    """
    global executing
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
    
    while executing:
        for sock in socket_list:
            data, _ = sock.recvfrom(1024)
            # Sanity check
            # print(sock.recv(1024).decode())
            process_packet(data)
            process_dis_packet(data)
            # print_dis_packet(data)

def stop_execting_reciever():
    global executing
    executing = False