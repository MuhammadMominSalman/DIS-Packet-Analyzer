import threading
import sys
import time
from senderhelpers import multicast_dis_packet_sender
from listenerhelpers import multicast_listener
from packetprocesshelper import display_statistics

def main():
    # Define multicast groups and ports
    multicast_group1 = '224.0.0.1'
    multicast_group2 = '224.0.0.2'
    port1 = 6060
    port2 = 6061

    # # Create thread for each multicast sender
    thread1 = threading.Thread(target=multicast_dis_packet_sender, daemon = True, args=(multicast_group1, port1))
    thread2 = threading.Thread(target=multicast_dis_packet_sender, daemon = True, args=(multicast_group2, port2))
    # Create thread for multicast listener
    thread3 = threading.Thread(target=multicast_listener, daemon = True, args=([multicast_group1, multicast_group2], [port1, port2]))

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

if __name__ == "__main__":
    main()