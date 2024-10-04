import tkinter as tk
from tkinter import scrolledtext
import threading
from scapy.all import sniff, IP, get_if_list, TCP, UDP, ICMP
import socket  # To map protocol numbers to human-readable names

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer Tool")

        # Text box to display captured packets
        self.packet_display = scrolledtext.ScrolledText(root, width=100, height=30)
        self.packet_display.grid(column=0, row=0, padx=10, pady=10)

        # Button to start packet sniffing
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(column=0, row=1, pady=10)

        # Button to stop packet sniffing
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(column=0, row=2, pady=10)

        # Label to show number of packets captured
        self.packet_count_label = tk.Label(root, text="Packets Captured: 0")
        self.packet_count_label.grid(column=0, row=3, pady=10)

        # Variable to control sniffing thread and packet count
        self.sniffing = False
        self.packet_count = 0

        # Display available interfaces for debugging
        print("Available interfaces:", get_if_list())

    def packet_handler(self, packet):
        """Handles each captured packet"""
        print(f"Packet captured: {packet.summary()}")  # Debugging print
        if IP in packet:
            ip_layer = packet[IP]

            # Get protocol name from the protocol number
            protocol_name = self.get_protocol_name(packet.proto)

            # Try to decode the payload as a UTF-8 string (if applicable)
            try:
                payload_data = bytes(packet[IP].payload).decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                payload_data = str(packet[IP].payload)

            # Display packet information in the text box
            packet_info = (
                f"Source: {ip_layer.src}, "
                f"Destination: {ip_layer.dst}, "
                f"Protocol: {protocol_name}, "
                f"Payload: {payload_data}\n"
            )

            self.packet_display.insert(tk.END, packet_info)
            self.packet_display.see(tk.END)  # Auto-scroll

            # Increment packet count and update the label
            self.packet_count += 1
            self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")

    def get_protocol_name(self, proto):
        """Maps protocol number to protocol name"""
        protocol_mapping = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return protocol_mapping.get(proto, f"Unknown ({proto})")

    def start_sniffing(self):
        """Starts the packet sniffing in a separate thread"""
        self.sniffing = True
        self.packet_display.insert(tk.END, "Starting packet capture...\n")
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def sniff_packets(self):
        """Captures packets"""
        iface = "Wi-Fi"  # Change this to the correct interface
        print(f"Sniffing on interface: {iface}")
        sniff(iface=iface, prn=self.packet_handler, stop_filter=lambda x: not self.sniffing)
        print("Sniffing ended...")

    def stop_sniffing(self):
        """Stops packet sniffing"""
        self.sniffing = False
        self.packet_display.insert(tk.END, "Stopping packet capture...\n")


# Run the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
