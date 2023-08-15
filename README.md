# Packet Sniffer

The Packet Sniffer is a Python script designed to capture and analyze HTTP request traffic on a specified network interface. It uses the Scapy library to intercept network packets and identify HTTP requests, allowing you to monitor and potentially analyze user credentials being transmitted over HTTP.

## Features

- Captures HTTP request URLs and displays them.
- Identifies and prints possible user credentials present in captured packets.

## Prerequisites

- Python 3.x
- Scapy library (install using `pip install scapy`)

## Usage

1. Make sure you have Python 3.x installed on your system.

2. Install the Scapy library if you haven't already:
   ```
   pip install scapy
   ```

3. Download the `packet_sniffer.py` script.

4. Open a terminal and navigate to the directory containing the script.

5. Enable monitor mode on your wireless network interface (if applicable):

   To enable monitor mode, you can use the following commands (replace `<interface>` with the name of your wireless interface):

   ```sh
   sudo ifconfig <interface> down
   sudo iw <interface> set monitor control
   sudo ifconfig <interface> up
   ```

6. Run the script using the following command:
   ```
   python3 packet_sniffer.py <interface>
   ```
   Replace `<interface>` with the name of the network interface you want to sniff (e.g., `eth0`, `en0`, etc.).

7. The script will start capturing HTTP request traffic on the specified interface. When an HTTP request is detected, it will display the URL and, if present, any possible user credentials found in the request.

8. To stop the script, press `Ctrl + C` in the terminal.

## Example

```
python3 packet_sniffer.py eth0
```

Output:
```
[+] Starting HTTP Request Sniffer on interface: eth0
[+] HTTP request URL: www.example.com/login
[+] Possible user credentials are -> b'username=admin&password=secretpassword'
```

## Disclaimer

This script is intended for educational and ethical purposes only. Unauthorized interception of network traffic is a violation of privacy and may be illegal. Always ensure you have proper authorization before using this script on any network.
