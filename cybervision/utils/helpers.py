#!/usr/bin/env python3
"""
Utility functions for CyberVisionVAPT
"""

import ipaddress
import re
from typing import List, Union


def validate_ip(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
    """
    Validate IP range in CIDR notation
    
    Args:
        ip_range: IP range in CIDR notation (e.g., 192.168.1.0/24)
        
    Returns:
        True if valid IP range
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def expand_ip_range(ip_range: str) -> List[str]:
    """
    Expand IP range to list of individual IPs
    
    Args:
        ip_range: IP range in CIDR notation
        
    Returns:
        List of IP addresses
    """
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number
        
    Returns:
        True if valid port
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def parse_target(target: str) -> dict:
    """
    Parse target specification
    
    Args:
        target: Target (IP, hostname, or CIDR range)
        
    Returns:
        Dictionary with target information
    """
    result = {
        "type": "unknown",
        "value": target,
        "ips": []
    }
    
    # Check if CIDR range
    if "/" in target:
        if validate_ip_range(target):
            result["type"] = "cidr"
            result["ips"] = expand_ip_range(target)
    # Check if single IP
    elif validate_ip(target):
        result["type"] = "ip"
        result["ips"] = [target]
    # Otherwise assume hostname
    else:
        result["type"] = "hostname"
        result["ips"] = [target]
    
    return result


def format_bytes(bytes_num: int) -> str:
    """
    Format bytes to human-readable format
    
    Args:
        bytes_num: Number of bytes
        
    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} PB"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    return sanitized
