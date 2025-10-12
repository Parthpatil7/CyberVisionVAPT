#!/usr/bin/env python3
"""
Port Scanner Module
Scans for common CCTV/DVR ports and services
"""

import socket
import concurrent.futures
from typing import List, Dict, Tuple


class PortScanner:
    """Scans for open ports on target devices"""
    
    # Common CCTV/DVR ports
    COMMON_PORTS = {
        80: "HTTP",
        443: "HTTPS",
        554: "RTSP",
        8000: "HTTP-Alt",
        8080: "HTTP-Proxy",
        8081: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9000: "HTTP-Admin",
        37777: "DVR (Dahua)",
        34567: "DVR (Hikvision)",
        6036: "DVR (Foscam)",
        9527: "DVR (Xiongmai)",
        3777: "DVR (Provision)",
        5000: "UPNP/Admin",
        5001: "UPNP/Admin-SSL",
    }
    
    def __init__(self, timeout: float = 2.0, max_workers: int = 50):
        """
        Initialize the port scanner
        
        Args:
            timeout: Connection timeout in seconds
            max_workers: Maximum number of concurrent workers
        """
        self.timeout = timeout
        self.max_workers = max_workers
    
    def scan_port(self, host: str, port: int) -> Tuple[int, bool, str]:
        """
        Scan a single port
        
        Args:
            host: Target host IP or hostname
            port: Port number to scan
            
        Returns:
            Tuple of (port, is_open, service_name)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            is_open = result == 0
            service = self.COMMON_PORTS.get(port, "Unknown")
            
            return (port, is_open, service)
        except socket.gaierror:
            return (port, False, "DNS Error")
        except socket.error:
            return (port, False, "Connection Error")
    
    def scan(self, host: str, ports: List[int] = None) -> Dict[int, Dict[str, any]]:
        """
        Scan multiple ports on a host
        
        Args:
            host: Target host IP or hostname
            ports: List of ports to scan (uses COMMON_PORTS if None)
            
        Returns:
            Dictionary mapping ports to their scan results
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, service = future.result()
                results[port] = {
                    "open": is_open,
                    "service": service
                }
        
        return results
    
    def get_open_ports(self, host: str, ports: List[int] = None) -> List[Dict[str, any]]:
        """
        Get list of open ports
        
        Args:
            host: Target host IP or hostname
            ports: List of ports to scan
            
        Returns:
            List of open ports with their details
        """
        scan_results = self.scan(host, ports)
        open_ports = [
            {"port": port, "service": details["service"]}
            for port, details in scan_results.items()
            if details["open"]
        ]
        return open_ports
