#!/usr/bin/env python3
"""
CyberVisionVAPT - Main Scanner
Orchestrates all scanning modules for comprehensive VAPT assessment
"""

import sys
import argparse
from typing import List, Dict, Optional
from datetime import datetime

from cybervision.modules.port_scanner import PortScanner
from cybervision.modules.default_creds import DefaultCredentialsChecker
from cybervision.modules.vuln_scanner import VulnerabilityScanner
from cybervision.modules.rtsp_scanner import RTSPScanner
from cybervision.modules.report_generator import ReportGenerator
from cybervision.utils.helpers import validate_ip, parse_target


class CyberVisionScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, target: str, verbose: bool = False):
        """
        Initialize scanner
        
        Args:
            target: Target IP, hostname, or CIDR range
            verbose: Enable verbose output
        """
        self.target = target
        self.verbose = verbose
        self.report = ReportGenerator(target)
        
        # Initialize modules
        self.port_scanner = PortScanner()
        self.creds_checker = DefaultCredentialsChecker()
        self.vuln_scanner = VulnerabilityScanner()
        self.rtsp_scanner = RTSPScanner()
    
    def log(self, message: str, level: str = "INFO"):
        """Print log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def scan_ports(self, host: str) -> List[Dict]:
        """
        Scan for open ports
        
        Args:
            host: Target host
            
        Returns:
            List of open ports
        """
        self.log(f"Scanning ports on {host}")
        open_ports = self.port_scanner.get_open_ports(host)
        
        if self.verbose:
            for port_info in open_ports:
                self.log(f"  Found open port: {port_info['port']} ({port_info['service']})", "DEBUG")
        
        return open_ports
    
    def check_default_credentials(self, host: str, ports: List[Dict]) -> List[Dict]:
        """
        Check for default credentials
        
        Args:
            host: Target host
            ports: List of open ports
            
        Returns:
            List of weak credentials found
        """
        self.log(f"Checking for default credentials on {host}")
        
        # Extract HTTP/HTTPS ports
        http_ports = [
            p['port'] for p in ports 
            if p['service'] in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTP-Proxy', 'HTTPS-Alt']
        ]
        
        all_creds = []
        results = self.creds_checker.check_device(host, http_ports)
        
        for url, creds in results.items():
            all_creds.extend(creds)
            if self.verbose:
                for cred in creds:
                    self.log(f"  Found weak credentials on {url}: {cred['username']}/{cred['password']}", "WARNING")
        
        return all_creds
    
    def scan_vulnerabilities(self, host: str, ports: List[Dict]) -> List[Dict]:
        """
        Scan for known vulnerabilities
        
        Args:
            host: Target host
            ports: List of open ports
            
        Returns:
            List of vulnerabilities found
        """
        self.log(f"Scanning for vulnerabilities on {host}")
        
        all_vulns = []
        
        # Scan HTTP/HTTPS services
        for port_info in ports:
            if port_info['service'] in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTP-Proxy', 'HTTPS-Alt']:
                port = port_info['port']
                protocol = "https" if "HTTPS" in port_info['service'] else "http"
                
                vulns = self.vuln_scanner.scan(host, port, protocol)
                all_vulns.extend(vulns)
                
                if self.verbose and vulns:
                    for vuln in vulns:
                        self.log(f"  Found vulnerability: {vuln['cve']} ({vuln['severity']})", "WARNING")
        
        return all_vulns
    
    def scan_rtsp(self, host: str, ports: List[Dict]) -> List[Dict]:
        """
        Scan for RTSP streams
        
        Args:
            host: Target host
            ports: List of open ports
            
        Returns:
            List of RTSP streams found
        """
        # Check if RTSP port is open
        rtsp_open = any(p['port'] == 554 for p in ports)
        
        if not rtsp_open:
            return []
        
        self.log(f"Scanning RTSP streams on {host}")
        
        streams = self.rtsp_scanner.scan(host, 554)
        
        if self.verbose:
            for stream in streams:
                self.log(f"  Found RTSP stream: {stream['url']} (Status: {stream['status_code']})", "DEBUG")
                if stream.get('security_issue'):
                    self.log(f"    Security Issue: {stream['security_issue']}", "WARNING")
        
        # Check for weak credentials on authenticated streams
        vulnerable_streams = self.rtsp_scanner.check_default_credentials(host, 554, streams)
        
        if self.verbose and vulnerable_streams:
            for stream in vulnerable_streams:
                creds = stream['weak_credentials']
                self.log(f"  Weak RTSP credentials: {stream['url']} ({creds['username']}/{creds['password']})", "WARNING")
        
        return streams + vulnerable_streams
    
    def scan_target(self, host: str):
        """
        Perform comprehensive scan on a single target
        
        Args:
            host: Target host
        """
        self.log(f"Starting scan on target: {host}")
        self.log("=" * 60)
        
        # Port scanning
        open_ports = self.scan_ports(host)
        self.report.add_port_scan_results(open_ports)
        
        if not open_ports:
            self.log("No open ports found. Scan complete.", "INFO")
            return
        
        # Default credentials check
        weak_creds = self.check_default_credentials(host, open_ports)
        self.report.add_weak_credentials(weak_creds)
        
        # Vulnerability scanning
        vulnerabilities = self.scan_vulnerabilities(host, open_ports)
        self.report.add_vulnerabilities(vulnerabilities)
        
        # RTSP scanning
        rtsp_streams = self.scan_rtsp(host, open_ports)
        self.report.add_rtsp_streams(rtsp_streams)
        
        self.log("=" * 60)
        self.log(f"Scan complete for {host}")
    
    def run(self):
        """Execute the scan"""
        self.log("CyberVisionVAPT - Starting Security Assessment")
        self.log(f"Target: {self.target}")
        
        # Parse target
        target_info = parse_target(self.target)
        
        if target_info['type'] == 'cidr':
            self.log(f"Scanning CIDR range with {len(target_info['ips'])} hosts")
            for ip in target_info['ips']:
                self.scan_target(ip)
        else:
            self.scan_target(self.target)
        
        # Generate and display report
        self.log("\nGenerating report...")
        print("\n" + self.report.generate_text_report())
        
        return self.report


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="CyberVisionVAPT - Automated Vulnerability Assessment and Penetration Testing tool for CCTV cameras & DVRs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
  %(prog)s 192.168.1.0/24 -v
  %(prog)s camera.example.com -o report.txt
  %(prog)s 10.0.0.50 -v --json report.json
        """
    )
    
    parser.add_argument('target', help='Target IP address, hostname, or CIDR range')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Save text report to file')
    parser.add_argument('--json', help='Save JSON report to file')
    
    args = parser.parse_args()
    
    try:
        # Create and run scanner
        scanner = CyberVisionScanner(args.target, args.verbose)
        report = scanner.run()
        
        # Save reports if requested
        if args.output:
            report.save_report(args.output, format='text')
            print(f"\n[+] Text report saved to: {args.output}")
        
        if args.json:
            report.save_report(args.json, format='json')
            print(f"[+] JSON report saved to: {args.json}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
