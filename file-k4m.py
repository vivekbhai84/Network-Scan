#!/usr/bin/env python3
"""
Network Scanner Tool
Scans local network for open ports and active devices
"""

import nmap
import socket
import argparse
import json
from datetime import datetime
import os

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {
            "scan_time": datetime.now().isoformat(),
            "hosts": {}
        }

    def get_local_subnet(self):
        """Get local subnet based on current IP"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return '.'.join(local_ip.split('.')[:3]) + '.0/24'

    def scan_network(self, subnet=None):
        """Scan network for active hosts"""
        if not subnet:
            subnet = self.get_local_subnet()
        
        print(f"[*] Scanning network: {subnet}")
        self.nm.scan(hosts=subnet, arguments='-sn')
        
        for host in self.nm.all_hosts():
            if self.nm[host].state() == 'up':
                self.results["hosts"][host] = {"status": "up"}
                print(f"[+] Found active host: {host}")

    def scan_ports(self, host):
        """Scan open ports on a host"""
        print(f"[*] Scanning ports on {host}")
        self.nm.scan(host, arguments='-p- -sS -T4')
        
        open_ports = []
        for proto in self.nm[host].all_protocols():
            lport = self.nm[host][proto].keys()
            for port in lport:
                open_ports.append(port)
        
        self.results["hosts"][host]["open_ports"] = open_ports
        print(f"[+] Open ports on {host}: {open_ports}")

    def save_results(self, filename="scan_results.json"):
        """Save scan results to JSON file"""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"[*] Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("--subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--host", help="Specific host to scan")
    parser.add_argument("--output", default="scan_results.json", help="Output file")
    args = parser.parse_args()

    scanner = NetworkScanner()
    
    if args.host:
        scanner.scan_ports(args.host)
    else:
        scanner.scan_network(args.subnet)
        for host in scanner.results["hosts"]:
            scanner.scan_ports(host)
    
    scanner.save_results(args.output)

if __name__ == "__main__":
    main()