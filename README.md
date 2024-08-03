Network Sniffer and Packet Analyzer CLI Tool

This Python script is a powerful network sniffer and packet analyzer. It captures live network traffic on a specified interface, identifies potential threats based on user-defined keywords, and alerts the user. The tool is built with the Scapy library, providing a flexible and detailed network analysis.
Features

  Live Packet Capture: Sniffs packets on a specified network interface in real-time.
  Protocol Analysis: Identifies and provides detailed information about IP, TCP, UDP, and DNS traffic.
  custom Alerting System: Alerts the user when packets containing specified keywords are detected.
  User-Friendly Interface: Displays a colorful banner and provides meaningful output with easy-to-read formatting.
  Cross-Platform Compatibility: Works on any platform that supports Python and Scapy.

Requirements

    Python 3.x
    Scapy
    Elevated privileges (e.g., sudo on Unix-like systems)

Installation

  Clone the repository:

    git clone https://github.com/ALBINJoseph01/Network-Sniffer-and-Packet-Analyzer-CLI-Tool.git
    cd Network-Sniffer-and-Packet-Analyzer-CLI-Tool

Install the required dependencies:

    pip install -r requirements.txt

Alternatively, install Scapy directly:

    pip install scapy

Usage

To run the Packet Analyzer:

    sudo python network_sniffing_cli.py -i <interface> [-k <keyword1> <keyword2> ...]

Arguments

    -i, --interface: (Required) The network interface to listen on (e.g., eth0, wlan0).
    -k, --keywords: (Optional) Space-separated list of keywords to trigger alerts (e.g., attack exploit malware).

Example

    sudo python packet_analyzer.py -i eth0 -k attack exploit malware

This command will start sniffing on the eth0 interface and will alert the user if any packets contain the words "attack," "exploit," or "malware."
Stopping the Sniffer

    Press Ctrl+C to stop sniffing. The tool will exit gracefully and stop capturing packets.

When you run the script, a custom ASCII banner will be displayed, adding a personalized touch to your tool.
Notes

    Permissions: Running this script requires elevated privileges to capture network traffic.
    Network Interface: Ensure the specified interface is active and valid for capturing traffic.
    Compliance: Make sure you have permission to monitor network traffic and that it complies with your local laws and organizational policies.

License

This project is licensed under the MIT License. See the LICENSE file for more details.
Contributing

Contributions are welcome! If you find any bugs or have suggestions for new features, please create an issue or submit a pull request.
