#!/usr/bin/env python3
"""
Default Credentials Checker
Tests common default credentials for CCTV cameras and DVRs
"""

import requests
import base64
from typing import List, Dict, Tuple, Optional
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class DefaultCredentialsChecker:
    """Checks for default credentials on CCTV/DVR systems"""
    
    # Common default credentials for various manufacturers
    DEFAULT_CREDENTIALS = [
        # Generic
        ("admin", "admin"),
        ("admin", "12345"),
        ("admin", ""),
        ("admin", "password"),
        ("root", "root"),
        ("root", "12345"),
        ("root", ""),
        ("user", "user"),
        ("default", "default"),
        
        # Hikvision
        ("admin", "12345"),
        ("admin", "hikivision"),
        
        # Dahua
        ("admin", "admin"),
        ("admin", "888888"),
        ("666666", "666666"),
        
        # Foscam
        ("admin", ""),
        ("admin", "foscam"),
        
        # Axis
        ("root", "pass"),
        ("root", "root"),
        
        # D-Link
        ("admin", "admin"),
        ("admin", ""),
        
        # TP-Link
        ("admin", "admin"),
        
        # Xiongmai/XM
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "tlJwpbo6"),
        ("default", "default"),
        
        # Samsung
        ("admin", "4321"),
        ("root", "root"),
        
        # Provision-ISR
        ("admin", "admin"),
        ("admin", "123456"),
    ]
    
    def __init__(self, timeout: int = 5):
        """
        Initialize credentials checker
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
    
    def test_http_basic_auth(self, url: str, username: str, password: str) -> bool:
        """
        Test HTTP Basic Authentication
        
        Args:
            url: Target URL
            username: Username to test
            password: Password to test
            
        Returns:
            True if credentials are valid
        """
        try:
            response = self.session.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout
            )
            return response.status_code == 200
        except:
            return False
    
    def test_http_digest_auth(self, url: str, username: str, password: str) -> bool:
        """
        Test HTTP Digest Authentication
        
        Args:
            url: Target URL
            username: Username to test
            password: Password to test
            
        Returns:
            True if credentials are valid
        """
        try:
            response = self.session.get(
                url,
                auth=HTTPDigestAuth(username, password),
                timeout=self.timeout
            )
            return response.status_code == 200
        except:
            return False
    
    def test_credentials(self, host: str, port: int = 80, 
                        protocol: str = "http") -> List[Dict[str, str]]:
        """
        Test default credentials on a target
        
        Args:
            host: Target host IP or hostname
            port: Port number
            protocol: Protocol to use (http/https)
            
        Returns:
            List of valid credentials found
        """
        valid_credentials = []
        url = f"{protocol}://{host}:{port}"
        
        for username, password in self.DEFAULT_CREDENTIALS:
            # Try Basic Auth
            if self.test_http_basic_auth(url, username, password):
                valid_credentials.append({
                    "username": username,
                    "password": password,
                    "auth_type": "Basic",
                    "url": url
                })
                continue
            
            # Try Digest Auth
            if self.test_http_digest_auth(url, username, password):
                valid_credentials.append({
                    "username": username,
                    "password": password,
                    "auth_type": "Digest",
                    "url": url
                })
        
        return valid_credentials
    
    def check_device(self, host: str, ports: List[int] = None) -> Dict[str, List]:
        """
        Check multiple ports on a device for default credentials
        
        Args:
            host: Target host
            ports: List of ports to check
            
        Returns:
            Dictionary of results per port
        """
        if ports is None:
            ports = [80, 8000, 8080, 8081]
        
        results = {}
        
        for port in ports:
            # Try HTTP
            http_results = self.test_credentials(host, port, "http")
            if http_results:
                results[f"http://{host}:{port}"] = http_results
            
            # Try HTTPS
            https_results = self.test_credentials(host, port, "https")
            if https_results:
                results[f"https://{host}:{port}"] = https_results
        
        return results
