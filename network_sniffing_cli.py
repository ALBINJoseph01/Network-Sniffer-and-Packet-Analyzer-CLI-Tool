import argparse
import re
import threading
import sys
from scapy.all import sniff, IP, TCP, UDP, DNS
import socket
RED = "\33[91m"
END= "\033[0m"
banner = f"""
  {RED}


  _______          _                    _                      _                _  __  __ _                     _ _            
 |__   __|        | |    _             | |                    | |              (_)/ _|/ _(_)                   | (_)           
    | | ___   ___ | |   (_)  _ __   ___| |___      _____  _ __| | __  ___ _ __  _| |_| |_ _ _ __   __ _     ___| |_            
    | |/ _ \ / _ \| |       | '_ \ / _ | __\ \ /\ / / _ \| '__| |/ / / __| '_ \| |  _|  _| | '_ \ / _` |   / __| | |           
    | | (_) | (_) | |    _  | | | |  __| |_ \ V  V | (_) | |  |   <  \__ | | | | | | | | | | | | | (_| |  | (__| | |           
    |_|\___/ \___/|_|   (_) |_| |_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |___|_| |_|_|_| |_| |_|_| |_|\__, |   \___|_|_|           
                                                                 ______                            __/ ______                  
                _   _                                       _   |______|_____ _   _      _        |___|______|  _      ___ __  
     /\        | | | |                 _     ____     /\   | |    |  _ |_   _| \ | |    | |                    | |    / _ /_ | 
    /  \  _   _| |_| |__   ___  _ __  (_)   / __ \   /  \  | |    | |_) || | |  \| |    | | ___  ___  ___ _ __ | |__ | | | | | 
   / /\ \| | | | __| '_ \ / _ \| '__|      / / _` | / /\ \ | |    |  _ < | | | . ` |_   | |/ _ \/ __|/ _ | '_ \| '_ \| | | | | 
  / ____ | |_| | |_| | | | (_) | |     _  | | (_| |/ ____ \| |____| |_) _| |_| |\  | |__| | (_) \__ |  __| |_) | | | | |_| | | 
 /_/    \_\__,_|\__|_| |_|\___/|_|    (_)  \ \__,_/_/    \_|______|____|_____|_| \_|\____/ \___/|___/\___| .__/|_| |_|\___/|_| 
                                            \____/                                                       | |                   
                                                                                                         |_|                                                                                                                                     

{END}"""  
print(banner)

class PacketAnalyzer:
    def __init__(self, output_function, alert_keywords):
        self.output_function = output_function
        self.alert_keywords = alert_keywords
        self.stop_sniffing = False

    def start_sniffing(self, iface):
        self.stop_sniffing = False
        sniff_thread = threading.Thread(target=self.sniff_packets, args=(iface,))
        sniff_thread.start()

    def stop_sniffing(self):
        self.stop_sniffing = True

    def sniff_packets(self, iface):
        try:
            sniff(iface=iface, prn=self.packet_callback, stop_filter=self.stop_filter, store=0)
        except PermissionError:
            sys.stderr.write("Permission denied. Try running the script with elevated privileges (e.g., sudo).\n")
            sys.exit(1)
        except socket.error as e:
            sys.stderr.write(f"Socket error: {e}\n")
            sys.exit(1)

    def stop_filter(self, packet):
        return self.stop_sniffing

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            protocol_info = ""
            if TCP in packet:
                protocol_info = f"TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}"
            elif UDP in packet:
                protocol_info = f"UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}"
            elif DNS in packet:
                protocol_info = f"DNS Query: {packet[DNS].qd.qname.decode()}"

            packet_info = f"IP {ip_src} -> {ip_dst} | Protocol: {protocol_info}"
            self.output_function(packet_info)

            # Check for potential threats
            self.check_for_threats(packet_info)

    def check_for_threats(self, packet_info):
        for keyword in self.alert_keywords:
            if re.search(keyword, packet_info, re.IGNORECASE):
                self.alert_user(f"Potential threat detected: {packet_info}")

    def alert_user(self, message):
        sys.stderr.write(f"ALERT: {message}\n")

def main():
    parser = argparse.ArgumentParser(description="Network Sniffer and Packet Analyzer CLI Tool")
    parser.add_argument('-i', '--interface', required=True, help='Network interface to listen on (e.g., eth0, wlan0)')
    parser.add_argument('-k', '--keywords', nargs='*', default=[], help='Keywords to trigger alerts (e.g., malicious attack exploit)')
    args = parser.parse_args()

    def print_output(message):
        print(message)

    # Check if interface is valid
    try:
        socket.if_nametoindex(args.interface)
    except ValueError:
        sys.stderr.write(f"Invalid network interface: {args.interface}\n")
        sys.exit(1)

    analyzer = PacketAnalyzer(output_function=print_output, alert_keywords=args.keywords)
    try:
        print(f"Starting sniffing on interface {args.interface}. Press Ctrl+C to stop.")
        analyzer.start_sniffing(args.interface)
        while True:
            try:
                pass
            except KeyboardInterrupt:
                analyzer.stop_sniffing()
                print("\nSniffing stopped.")
                break
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
