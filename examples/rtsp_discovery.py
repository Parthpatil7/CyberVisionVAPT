#!/usr/bin/env python3
"""
Example: RTSP stream discovery and testing
"""

from cybervision.modules.port_scanner import PortScanner
from cybervision.modules.rtsp_scanner import RTSPScanner

# Target IP
target = "192.168.1.100"

print(f"RTSP Stream Discovery on {target}...")

# First, check if RTSP port is open
print("\n[+] Checking for RTSP port...")
port_scanner = PortScanner()
open_ports = port_scanner.get_open_ports(target, [554])

if not open_ports:
    print("RTSP port (554) is not open")
    exit()

print("RTSP port is open!")

# Scan for RTSP streams
print("\n[+] Discovering RTSP streams...")
rtsp_scanner = RTSPScanner()
streams = rtsp_scanner.scan(target, 554)

print(f"\nFound {len(streams)} RTSP streams:")
for stream in streams:
    print(f"\n  URL: {stream['url']}")
    print(f"  Status Code: {stream['status_code']}")
    print(f"  Requires Auth: {stream['requires_auth']}")
    
    if stream.get('security_issue'):
        print(f"  ⚠️  Security Issue: {stream['security_issue']}")

# Check for weak credentials on authenticated streams
print("\n[+] Testing for weak credentials...")
vulnerable = rtsp_scanner.check_default_credentials(target, 554, streams)

if vulnerable:
    print(f"\nFound {len(vulnerable)} streams with weak credentials:")
    for stream in vulnerable:
        creds = stream['weak_credentials']
        print(f"  {stream['url']}: {creds['username']}/{creds['password']}")
else:
    print("\nNo weak credentials found")
