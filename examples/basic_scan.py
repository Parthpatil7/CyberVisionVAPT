#!/usr/bin/env python3
"""
Example: Basic single target scan
"""

from cybervision.modules.port_scanner import PortScanner
from cybervision.modules.default_creds import DefaultCredentialsChecker
from cybervision.modules.report_generator import ReportGenerator

# Target IP
target = "192.168.1.100"

print(f"Scanning {target}...")

# Initialize scanner
port_scanner = PortScanner()

# Scan for open ports
print("\n[+] Scanning for open ports...")
open_ports = port_scanner.get_open_ports(target)

for port_info in open_ports:
    print(f"  Port {port_info['port']}: {port_info['service']}")

# Check for default credentials
print("\n[+] Checking for default credentials...")
creds_checker = DefaultCredentialsChecker()
weak_creds = creds_checker.check_device(target)

for url, creds in weak_creds.items():
    for cred in creds:
        print(f"  Found: {cred['username']}:{cred['password']} on {url}")

# Generate report
print("\n[+] Generating report...")
report = ReportGenerator(target)
report.add_port_scan_results(open_ports)

for url, creds in weak_creds.items():
    report.add_weak_credentials(creds)

print(report.generate_text_report())
