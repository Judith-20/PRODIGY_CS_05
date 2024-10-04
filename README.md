# Packet Sniffer Tool

This is a Python-based Packet Sniffer tool with a GUI built using Tkinter. The tool captures and displays network packets in real-time, showing details such as the source and destination IP addresses, protocols, and packet payload data.

## Features

- **Packet Capture**: Sniffs and captures network packets in real-time.
- **Protocol Analysis**: Displays protocol information for each captured packet (TCP, UDP, ICMP, etc.).
- **Payload Decoding**: Attempts to decode the payload of each packet as text (UTF-8).
- **GUI Interface**: A user-friendly graphical interface using Tkinter, which allows you to start and stop packet sniffing with a click of a button.
- **Packet Count**: Displays the total number of packets captured.

## How It Works

- The tool captures packets from a specified network interface and displays:
  - **Source IP Address**: The IP address of the device that sent the packet.
  - **Destination IP Address**: The IP address of the device that the packet is being sent to.
  - **Protocol**: The communication protocol used by the packet (TCP, UDP, ICMP, etc.).
  - **Payload**: The data carried by the packet, which is displayed if it can be decoded as text.

## Installation

### Prerequisites

- **Python**: Ensure that Python is installed on your system.
- **Scapy**: Install the Scapy library using pip:
  ```bash
  pip install scapy
  ```
- **Tkinter**: Tkinter is usually bundled with Python. If it's missing, install it via your package manager.


### Installation Steps
1. Clone this repository or download the files.

2. Ensure that you have the required dependencies installed (`Scapy` and `Tkinter`).

3. Open the project in your preferred code editor (e.g., Visual Studio Code).


## Running the Tool

1. Open a terminal and navigate to the project directory.

2. Run the script with administrator privileges (this is required for packet sniffing):

    - On **Windows**:
        - Open Command Prompt as administrator and run the script:
            ```bash
            python packet_sniffer.py
            ```

    - On **Linux/Mac**:
        ```bash
        sudo python3 packet_sniffer.py
        ```
3. A GUI window will appear with buttons to start and stop sniffing.

## Usage
- Click Start Sniffing to begin capturing packets.
- Captured packets will be displayed in the text box, showing the following information:
    - Source IP address
    - Destination IP address
    - Protocol (TCP, UDP, ICMP, etc.)
    - Payload (decoded if possible)
- Click Stop Sniffing to stop capturing packets.

# Example Output
Below is an example of what the output may look like when capturing packets:

```bash
Source: 192.168.1.30, Destination: 8.8.8.8, Protocol: UDP, Payload: some decoded text...
Source: 10.0.0.5, Destination: 224.0.0.251, Protocol: TCP, Payload: b'\x01\x02...'
```

# Known Issues
- Some payloads may not be readable due to the binary nature of the data.
- Capturing packets may require administrative/root privileges.
- Ensure you have the correct network interface specified for your system.