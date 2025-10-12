#!/usr/bin/env python3
"""
Example: Vulnerability scanning for known CVEs
"""

from cybervision.modules.port_scanner import PortScanner
from cybervision.modules.vuln_scanner import VulnerabilityScanner

# Target IP
target = "192.168.1.100"

print(f"Vulnerability Scan on {target}...")

# Scan for open HTTP/HTTPS ports
print("\n[+] Scanning for web services...")
port_scanner = PortScanner()
open_ports = port_scanner.get_open_ports(target, [80, 443, 8000, 8080, 8081])

if not open_ports:
    print("No HTTP/HTTPS services found")
    exit()

# Scan for vulnerabilities
print("\n[+] Scanning for known vulnerabilities...")
vuln_scanner = VulnerabilityScanner()

all_vulnerabilities = []

for port_info in open_ports:
    port = port_info['port']
    protocol = "https" if "HTTPS" in port_info['service'] else "http"
    
    print(f"\n  Scanning {protocol}://{target}:{port}...")
    
    vulnerabilities = vuln_scanner.scan(target, port, protocol)
    
    if vulnerabilities:
        all_vulnerabilities.extend(vulnerabilities)
        print(f"  Found {len(vulnerabilities)} vulnerabilities!")
        
        for vuln in vulnerabilities:
            print(f"\n    [{vuln['severity']}] {vuln['cve']}")
            print(f"    Description: {vuln['description']}")
            print(f"    Device: {vuln['device_type']}")
    else:
        print("  No known vulnerabilities found")

# Summary
print(f"\n{'='*60}")
print(f"Total Vulnerabilities Found: {len(all_vulnerabilities)}")

critical = sum(1 for v in all_vulnerabilities if v['severity'] == 'Critical')
high = sum(1 for v in all_vulnerabilities if v['severity'] == 'High')
medium = sum(1 for v in all_vulnerabilities if v['severity'] == 'Medium')

if critical > 0:
    print(f"⚠️  Critical: {critical}")
if high > 0:
    print(f"⚠️  High: {high}")
if medium > 0:
    print(f"  Medium: {medium}")
