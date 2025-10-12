#!/usr/bin/env python3
"""
Report Generator
Generates comprehensive security assessment reports
"""

import json
from datetime import datetime
from typing import Dict, List, Optional


class ReportGenerator:
    """Generates security assessment reports in various formats"""
    
    SEVERITY_COLORS = {
        "Critical": "\033[91m",  # Red
        "High": "\033[93m",      # Yellow
        "Medium": "\033[94m",    # Blue
        "Low": "\033[92m",       # Green
        "Info": "\033[97m",      # White
    }
    RESET_COLOR = "\033[0m"
    
    def __init__(self, target: str):
        """
        Initialize report generator
        
        Args:
            target: Target being assessed
        """
        self.target = target
        self.timestamp = datetime.now()
        self.findings = {
            "open_ports": [],
            "vulnerabilities": [],
            "weak_credentials": [],
            "rtsp_streams": [],
            "security_issues": []
        }
    
    def add_port_scan_results(self, results: List[Dict]):
        """Add port scan results"""
        self.findings["open_ports"] = results
    
    def add_vulnerabilities(self, vulns: List[Dict]):
        """Add vulnerability scan results"""
        self.findings["vulnerabilities"].extend(vulns)
    
    def add_weak_credentials(self, creds: List[Dict]):
        """Add weak credentials findings"""
        self.findings["weak_credentials"].extend(creds)
    
    def add_rtsp_streams(self, streams: List[Dict]):
        """Add RTSP stream findings"""
        self.findings["rtsp_streams"].extend(streams)
    
    def add_security_issue(self, issue: Dict):
        """Add general security issue"""
        self.findings["security_issues"].append(issue)
    
    def calculate_risk_score(self) -> int:
        """
        Calculate overall risk score (0-100)
        
        Returns:
            Risk score
        """
        score = 0
        
        # Critical vulnerabilities
        critical_count = sum(
            1 for v in self.findings["vulnerabilities"] 
            if v.get("severity") == "Critical"
        )
        score += critical_count * 25
        
        # High severity vulnerabilities
        high_count = sum(
            1 for v in self.findings["vulnerabilities"] 
            if v.get("severity") == "High"
        )
        score += high_count * 15
        
        # Weak credentials
        score += len(self.findings["weak_credentials"]) * 20
        
        # Unauthenticated RTSP streams
        unauth_streams = sum(
            1 for s in self.findings["rtsp_streams"] 
            if s.get("accessible") and not s.get("requires_auth")
        )
        score += unauth_streams * 10
        
        return min(score, 100)
    
    def generate_text_report(self) -> str:
        """
        Generate text-based report
        
        Returns:
            Formatted text report
        """
        report = []
        report.append("=" * 80)
        report.append("CyberVisionVAPT - Security Assessment Report")
        report.append("=" * 80)
        report.append(f"Target: {self.target}")
        report.append(f"Scan Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Risk Score: {self.calculate_risk_score()}/100")
        report.append("=" * 80)
        report.append("")
        
        # Port Scan Results
        report.append("[+] Open Ports and Services")
        report.append("-" * 80)
        if self.findings["open_ports"]:
            for port_info in self.findings["open_ports"]:
                report.append(f"  Port {port_info['port']}: {port_info['service']}")
        else:
            report.append("  No open ports found")
        report.append("")
        
        # Vulnerabilities
        report.append("[+] Vulnerabilities Detected")
        report.append("-" * 80)
        if self.findings["vulnerabilities"]:
            for vuln in self.findings["vulnerabilities"]:
                severity = vuln.get("severity", "Unknown")
                report.append(f"  [{severity}] {vuln.get('cve', 'N/A')}")
                report.append(f"    Description: {vuln.get('description', 'N/A')}")
                report.append(f"    Device Type: {vuln.get('device_type', 'Unknown')}")
                report.append("")
        else:
            report.append("  No known vulnerabilities detected")
        report.append("")
        
        # Weak Credentials
        report.append("[+] Weak/Default Credentials")
        report.append("-" * 80)
        if self.findings["weak_credentials"]:
            for cred in self.findings["weak_credentials"]:
                report.append(f"  URL: {cred.get('url', 'N/A')}")
                report.append(f"    Username: {cred.get('username', 'N/A')}")
                report.append(f"    Password: {cred.get('password', 'N/A')}")
                report.append(f"    Auth Type: {cred.get('auth_type', 'N/A')}")
                report.append("")
        else:
            report.append("  No default credentials found")
        report.append("")
        
        # RTSP Streams
        report.append("[+] RTSP Streams")
        report.append("-" * 80)
        if self.findings["rtsp_streams"]:
            for stream in self.findings["rtsp_streams"]:
                report.append(f"  URL: {stream.get('url', 'N/A')}")
                report.append(f"    Accessible: {stream.get('accessible', False)}")
                if stream.get("security_issue"):
                    report.append(f"    Security Issue: {stream['security_issue']}")
                if stream.get("weak_credentials"):
                    creds = stream["weak_credentials"]
                    report.append(f"    Weak Credentials: {creds['username']}/{creds['password']}")
                report.append("")
        else:
            report.append("  No RTSP streams found")
        report.append("")
        
        # Recommendations
        report.append("[+] Security Recommendations")
        report.append("-" * 80)
        recommendations = self._generate_recommendations()
        for rec in recommendations:
            report.append(f"  - {rec}")
        report.append("")
        
        report.append("=" * 80)
        report.append("End of Report")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if self.findings["weak_credentials"]:
            recommendations.append("Change all default credentials immediately")
            recommendations.append("Implement strong password policy (minimum 12 characters, mixed case, numbers, symbols)")
        
        if self.findings["vulnerabilities"]:
            recommendations.append("Update firmware to latest version to patch known vulnerabilities")
            recommendations.append("Apply security patches as soon as they become available")
        
        if any(s.get("accessible") for s in self.findings["rtsp_streams"]):
            recommendations.append("Enable authentication on all RTSP streams")
            recommendations.append("Use encrypted protocols (RTSPS) when available")
        
        if self.findings["open_ports"]:
            recommendations.append("Close unnecessary ports and services")
            recommendations.append("Implement network segmentation to isolate camera network")
            recommendations.append("Use firewall rules to restrict access to management interfaces")
        
        recommendations.append("Enable HTTPS and disable HTTP access")
        recommendations.append("Disable unused services and protocols")
        recommendations.append("Regularly monitor and audit device configurations")
        recommendations.append("Implement network-level monitoring and intrusion detection")
        
        return recommendations
    
    def generate_json_report(self) -> str:
        """
        Generate JSON report
        
        Returns:
            JSON-formatted report
        """
        report_data = {
            "target": self.target,
            "scan_date": self.timestamp.isoformat(),
            "risk_score": self.calculate_risk_score(),
            "findings": self.findings,
            "recommendations": self._generate_recommendations()
        }
        
        return json.dumps(report_data, indent=2)
    
    def save_report(self, filename: str, format: str = "text"):
        """
        Save report to file
        
        Args:
            filename: Output filename
            format: Report format (text or json)
        """
        if format == "json":
            content = self.generate_json_report()
        else:
            content = self.generate_text_report()
        
        with open(filename, 'w') as f:
            f.write(content)
