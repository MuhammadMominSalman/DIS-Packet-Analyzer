import sys
import threading
from collections import deque
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QHBoxLayout)
from PyQt5.QtCore import QTimer
from senderhelpers import multicast_dis_packet_sender, stop_execting_sender
from listenerhelpers import multicast_listener, stop_execting_reciever
from packetprocesshelper import display_statistics, get_packet_count


class PacketCaptureApp(QWidget):
    def __init__(self):
        super().__init__()
        # Define multicast groups and ports
        self.multicast_group1 = '224.0.0.1'
        self.multicast_group2 = '224.0.0.2'
        self.port1 = 6060
        self.port2 = 6061


        # Initialize UI components
        self.initUI()

        # Packet statistics
        self.packet_count = 0
        self.packet_timestamps = deque()
        self.latency_list = []

        # Thread control
        self.running = False

    def initUI(self):
        # Layouts
        main_layout = QVBoxLayout()
        button_layout = QHBoxLayout()

        # Start/Stop buttons
        self.start_button = QPushButton('Start Sending and Recieving', self)
        self.stop_button = QPushButton('Stop Sending and Display Statistics', self)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)

        # Packet count label
        self.packet_count_label = QLabel('Total Packets Captured: 0', self)

        # Button layout
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        # Add widgets to main layout
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.packet_count_label)

        # Set main layout
        self.setLayout(main_layout)

        # Set window title and size
        self.setWindowTitle('DIS Packet Capture')
        self.setGeometry(100, 100, 400, 200)

        # Timer to update statistics
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_statistics)
        self.timer.start(1000)  # Update every second

    def start_capture(self):
        if not self.running:
            self.running = True
            # # Create thread for each multicast sender
            self.thread1 = threading.Thread(target=multicast_dis_packet_sender, daemon = True, args=(self.multicast_group1, self.port1))
            self.thread2 = threading.Thread(target=multicast_dis_packet_sender, daemon = True, args=(self.multicast_group2, self.port2))
            # Create thread for multicast listener
            self.thread3 = threading.Thread(target=multicast_listener, daemon = True, 
                                       args=([self.multicast_group1, self.multicast_group2], [self.port1, self.port2]))

            # Start both threads
            self.thread1.start()
            self.thread2.start()
            self.thread3.start()

    def stop_capture(self):
        if self.running:
            self.running = False
            stop_execting_sender()
            stop_execting_reciever()
            # Stop the threads
            self.thread1.join(0)
            self.thread2.join(0)
            self.thread3.join(0)

            # Display statistics
            display_statistics()

    def update_statistics(self):
        self.packet_count = get_packet_count()
        self.packet_count_label.setText(f'Total Packets Captured: {self.packet_count}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketCaptureApp()
    ex.show()
    sys.exit(app.exec_())
