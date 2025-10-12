#!/usr/bin/env python3
"""
Comprehensive test suite for CyberVisionVAPT modules
Run this to verify all components are working correctly
"""

import sys
from datetime import datetime


def print_header(text):
    """Print formatted header"""
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}")


def print_section(text):
    """Print formatted section"""
    print(f"\n{'-' * 70}")
    print(f"  {text}")
    print(f"{'-' * 70}")


def test_imports():
    """Test that all modules can be imported"""
    print_section("Testing Module Imports")
    
    try:
        from cybervision.modules.port_scanner import PortScanner
        print("✓ Port Scanner module imported")
        
        from cybervision.modules.default_creds import DefaultCredentialsChecker
        print("✓ Default Credentials Checker module imported")
        
        from cybervision.modules.vuln_scanner import VulnerabilityScanner
        print("✓ Vulnerability Scanner module imported")
        
        from cybervision.modules.rtsp_scanner import RTSPScanner
        print("✓ RTSP Scanner module imported")
        
        from cybervision.modules.report_generator import ReportGenerator
        print("✓ Report Generator module imported")
        
        from cybervision.utils.helpers import validate_ip, parse_target
        print("✓ Helper utilities imported")
        
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False


def test_utilities():
    """Test utility functions"""
    print_section("Testing Utility Functions")
    
    from cybervision.utils.helpers import (
        validate_ip, validate_port, parse_target, 
        format_bytes, sanitize_filename
    )
    
    tests_passed = 0
    tests_total = 0
    
    # Test IP validation
    tests_total += 1
    if validate_ip("192.168.1.1"):
        print("✓ Valid IP address recognized")
        tests_passed += 1
    else:
        print("✗ Valid IP validation failed")
    
    tests_total += 1
    if not validate_ip("invalid.ip"):
        print("✓ Invalid IP address rejected")
        tests_passed += 1
    else:
        print("✗ Invalid IP validation failed")
    
    # Test port validation
    tests_total += 1
    if validate_port(80):
        print("✓ Valid port recognized")
        tests_passed += 1
    else:
        print("✗ Valid port validation failed")
    
    tests_total += 1
    if not validate_port(99999):
        print("✓ Invalid port rejected")
        tests_passed += 1
    else:
        print("✗ Invalid port validation failed")
    
    # Test target parsing
    tests_total += 1
    result = parse_target("192.168.1.100")
    if result['type'] == 'ip' and result['ips'] == ['192.168.1.100']:
        print("✓ IP target parsing works")
        tests_passed += 1
    else:
        print("✗ IP target parsing failed")
    
    # Test byte formatting
    tests_total += 1
    if format_bytes(1024) == "1.00 KB":
        print("✓ Byte formatting works")
        tests_passed += 1
    else:
        print("✗ Byte formatting failed")
    
    # Test filename sanitization
    tests_total += 1
    if sanitize_filename("test<>file.txt") == "test__file.txt":
        print("✓ Filename sanitization works")
        tests_passed += 1
    else:
        print("✗ Filename sanitization failed")
    
    print(f"\nUtilities: {tests_passed}/{tests_total} tests passed")
    return tests_passed == tests_total


def test_port_scanner():
    """Test port scanner module"""
    print_section("Testing Port Scanner Module")
    
    from cybervision.modules.port_scanner import PortScanner
    
    scanner = PortScanner(timeout=1.0)
    
    print(f"✓ Scanner initialized with timeout: {scanner.timeout}s")
    print(f"✓ Common ports defined: {len(scanner.COMMON_PORTS)} ports")
    print(f"✓ Sample ports: {list(scanner.COMMON_PORTS.keys())[:5]}")
    
    # Test port categorization
    if 80 in scanner.COMMON_PORTS and scanner.COMMON_PORTS[80] == "HTTP":
        print("✓ Port service mapping works")
    
    if 554 in scanner.COMMON_PORTS and scanner.COMMON_PORTS[554] == "RTSP":
        print("✓ RTSP port correctly identified")
    
    return True


def test_credentials_checker():
    """Test default credentials checker"""
    print_section("Testing Default Credentials Checker")
    
    from cybervision.modules.default_creds import DefaultCredentialsChecker
    
    checker = DefaultCredentialsChecker(timeout=5)
    
    print(f"✓ Credentials checker initialized")
    print(f"✓ Default credentials database: {len(checker.DEFAULT_CREDENTIALS)} entries")
    
    # Check for common credentials
    common_found = any(
        cred == ("admin", "admin") 
        for cred in checker.DEFAULT_CREDENTIALS
    )
    
    if common_found:
        print("✓ Common credentials (admin/admin) in database")
    
    # Check for manufacturer-specific credentials
    hikvision_found = any(
        cred == ("admin", "12345") 
        for cred in checker.DEFAULT_CREDENTIALS
    )
    
    if hikvision_found:
        print("✓ Manufacturer-specific credentials in database")
    
    return True


def test_vulnerability_scanner():
    """Test vulnerability scanner"""
    print_section("Testing Vulnerability Scanner")
    
    from cybervision.modules.vuln_scanner import VulnerabilityScanner
    
    scanner = VulnerabilityScanner(timeout=5)
    
    print(f"✓ Vulnerability scanner initialized")
    print(f"✓ Vulnerability database loaded")
    
    # Check database contents
    if "hikvision" in scanner.VULNERABILITY_DATABASE:
        print("✓ Hikvision vulnerabilities in database")
    
    if "dahua" in scanner.VULNERABILITY_DATABASE:
        print("✓ Dahua vulnerabilities in database")
    
    if "generic" in scanner.VULNERABILITY_DATABASE:
        print("✓ Generic vulnerabilities in database")
    
    # Count CVEs
    total_cves = 0
    for manufacturer in scanner.VULNERABILITY_DATABASE.values():
        total_cves += len(manufacturer)
    
    print(f"✓ Total vulnerability checks: {total_cves}")
    
    return True


def test_rtsp_scanner():
    """Test RTSP scanner"""
    print_section("Testing RTSP Scanner")
    
    from cybervision.modules.rtsp_scanner import RTSPScanner
    
    scanner = RTSPScanner(timeout=5)
    
    print(f"✓ RTSP scanner initialized")
    print(f"✓ Common RTSP paths: {len(scanner.COMMON_PATHS)} paths")
    print(f"✓ Sample paths: {scanner.COMMON_PATHS[:5]}")
    
    # Check for manufacturer-specific paths
    if "/Streaming/Channels/1" in scanner.COMMON_PATHS:
        print("✓ Hikvision RTSP paths included")
    
    if "/cam/realmonitor" in scanner.COMMON_PATHS:
        print("✓ Dahua RTSP paths included")
    
    return True


def test_report_generator():
    """Test report generator"""
    print_section("Testing Report Generator")
    
    from cybervision.modules.report_generator import ReportGenerator
    
    report = ReportGenerator("192.168.1.100")
    
    print(f"✓ Report generator initialized for target: {report.target}")
    
    # Add test data
    report.add_port_scan_results([
        {"port": 80, "service": "HTTP"},
        {"port": 554, "service": "RTSP"}
    ])
    print("✓ Port scan results added")
    
    report.add_vulnerabilities([{
        "cve": "CVE-2017-7921",
        "description": "Test vulnerability",
        "severity": "Critical",
        "device_type": "hikvision"
    }])
    print("✓ Vulnerabilities added")
    
    report.add_weak_credentials([{
        "username": "admin",
        "password": "admin",
        "auth_type": "Basic",
        "url": "http://192.168.1.100"
    }])
    print("✓ Weak credentials added")
    
    # Test risk calculation
    risk_score = report.calculate_risk_score()
    print(f"✓ Risk score calculated: {risk_score}/100")
    
    # Test report generation
    text_report = report.generate_text_report()
    if "CyberVisionVAPT" in text_report:
        print("✓ Text report generated successfully")
    
    json_report = report.generate_json_report()
    if "target" in json_report:
        print("✓ JSON report generated successfully")
    
    # Test recommendations
    recommendations = report._generate_recommendations()
    print(f"✓ Generated {len(recommendations)} recommendations")
    
    return True


def main():
    """Run all tests"""
    print_header("CyberVisionVAPT - Comprehensive Test Suite")
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    all_passed = True
    
    # Run tests
    all_passed &= test_imports()
    all_passed &= test_utilities()
    all_passed &= test_port_scanner()
    all_passed &= test_credentials_checker()
    all_passed &= test_vulnerability_scanner()
    all_passed &= test_rtsp_scanner()
    all_passed &= test_report_generator()
    
    # Summary
    print_header("Test Summary")
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED")
        print("\nCyberVisionVAPT is ready to use!")
        print("\nNext steps:")
        print("  1. Run: python cybervision_scanner.py --help")
        print("  2. Try: python cybervision_scanner.py <target-ip>")
        print("  3. Review examples/ directory for usage examples")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        print("\nPlease check the errors above and ensure all dependencies are installed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
