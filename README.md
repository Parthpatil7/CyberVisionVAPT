# CyberVisionVAPT

Automated Vulnerability Assessment and Penetration Testing tool for CCTV cameras & DVRs

## Overview

CyberVisionVAPT is a comprehensive security testing framework designed specifically for IP cameras, CCTV systems, and DVR devices. It automates the process of identifying security vulnerabilities, weak configurations, and potential entry points in surveillance systems.

## Features

- **Port Scanning**: Identifies open ports and services on CCTV/DVR devices
- **Default Credentials Detection**: Tests for commonly used default usernames and passwords across multiple manufacturers
- **Vulnerability Scanning**: Checks for known CVEs affecting popular camera/DVR brands
- **RTSP Stream Discovery**: Locates and tests Real-Time Streaming Protocol (RTSP) endpoints
- **Authentication Testing**: Validates authentication mechanisms on web interfaces and streaming services
- **Comprehensive Reporting**: Generates detailed text and JSON reports with security recommendations
- **Multi-Target Support**: Scan individual IPs, hostnames, or entire network ranges (CIDR notation)

## Supported Devices

The tool includes detection and vulnerability checks for:

- **Hikvision** IP cameras and NVRs
- **Dahua** surveillance systems
- **Axis** network cameras
- **Foscam** IP cameras
- **Xiongmai** DVR systems
- **Samsung** security cameras
- **D-Link** network cameras
- **TP-Link** security cameras
- Generic IP cameras and DVR systems

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Parthpatil7/CyberVisionVAPT.git
cd CyberVisionVAPT
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan

Scan a single IP address:
```bash
python cybervision_scanner.py 192.168.1.100
```

### Verbose Mode

Enable detailed output during scanning:
```bash
python cybervision_scanner.py 192.168.1.100 -v
```

### Network Range Scanning

Scan an entire subnet:
```bash
python cybervision_scanner.py 192.168.1.0/24
```

### Generate Reports

Save results to text file:
```bash
python cybervision_scanner.py 192.168.1.100 -o report.txt
```

Save results in JSON format:
```bash
python cybervision_scanner.py 192.168.1.100 --json report.json
```

### Advanced Usage

Combine options for comprehensive assessment:
```bash
python cybervision_scanner.py 192.168.1.0/24 -v -o scan_results.txt --json scan_results.json
```

## Command-Line Options

```
usage: cybervision_scanner.py [-h] [-v] [-o OUTPUT] [--json JSON] target

positional arguments:
  target                Target IP address, hostname, or CIDR range

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output
  -o OUTPUT, --output OUTPUT
                        Save text report to file
  --json JSON           Save JSON report to file
```

## Security Checks

### 1. Port Scanning
- Scans for common CCTV/DVR ports (80, 443, 554, 8000, 8080, 37777, 34567, etc.)
- Identifies running services

### 2. Default Credentials
Tests for manufacturer default credentials including:
- admin/admin
- admin/12345
- root/root
- And 30+ other common combinations

### 3. Vulnerability Detection
Checks for known CVEs:
- CVE-2017-7921 (Hikvision unauthorized access)
- CVE-2021-36260 (Hikvision command injection)
- CVE-2021-33044 (Dahua authentication bypass)
- Directory traversal vulnerabilities
- Information disclosure issues

### 4. RTSP Security
- Discovers RTSP streaming endpoints
- Tests for unauthenticated streams
- Validates authentication requirements

## Sample Output

```
================================================================================
CyberVisionVAPT - Security Assessment Report
================================================================================
Target: 192.168.1.100
Scan Date: 2025-10-12 18:05:00
Risk Score: 65/100
================================================================================

[+] Open Ports and Services
--------------------------------------------------------------------------------
  Port 80: HTTP
  Port 554: RTSP
  Port 8000: HTTP-Alt

[+] Vulnerabilities Detected
--------------------------------------------------------------------------------
  [Critical] CVE-2017-7921
    Description: Hikvision IP cameras unauthorized access vulnerability
    Device Type: hikvision

[+] Weak/Default Credentials
--------------------------------------------------------------------------------
  URL: http://192.168.1.100:80
    Username: admin
    Password: 12345
    Auth Type: Basic

[+] RTSP Streams
--------------------------------------------------------------------------------
  URL: rtsp://192.168.1.100:554/stream1
    Accessible: True
    Security Issue: No authentication required

[+] Security Recommendations
--------------------------------------------------------------------------------
  - Change all default credentials immediately
  - Implement strong password policy
  - Update firmware to latest version
  - Enable authentication on all RTSP streams
  - Use firewall rules to restrict access
```

## Project Structure

```
CyberVisionVAPT/
├── cybervision/
│   ├── __init__.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── port_scanner.py       # Port scanning functionality
│   │   ├── default_creds.py      # Default credentials checker
│   │   ├── vuln_scanner.py       # Vulnerability detection
│   │   ├── rtsp_scanner.py       # RTSP stream discovery
│   │   └── report_generator.py   # Report generation
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py            # Utility functions
│   └── data/
│       └── __init__.py
├── cybervision_scanner.py         # Main scanner script
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## Legal Disclaimer

**IMPORTANT**: This tool is designed for security professionals and ethical hackers to assess the security of systems they own or have explicit permission to test.

### Legal Notice

- **Authorization Required**: Only use this tool on systems you own or have written permission to test
- **Unauthorized Access**: Accessing systems without permission is illegal and punishable by law
- **Ethical Use**: This tool is intended for defensive security purposes only
- **No Warranty**: This software is provided "as is" without warranty of any kind
- **User Responsibility**: Users are solely responsible for complying with applicable laws and regulations

By using CyberVisionVAPT, you agree to use it responsibly and ethically, and only on systems for which you have proper authorization.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Roadmap

Future enhancements planned:

- [ ] ONVIF protocol testing
- [ ] Firmware analysis capabilities
- [ ] Additional CVE database updates
- [ ] Web UI for easier operation
- [ ] Export to multiple report formats (PDF, HTML)
- [ ] Integration with vulnerability databases
- [ ] Automated exploit verification (ethical testing only)

## License

This project is provided for educational and authorized testing purposes only.

## Author

CyberVisionVAPT Team

## Acknowledgments

- Security researchers who have disclosed vulnerabilities in IP camera systems
- The open-source security community
- MITRE CVE database

## Support

For questions, issues, or feature requests, please open an issue on GitHub.

---

**Remember**: Always obtain proper authorization before testing any systems. Unauthorized access to computer systems is illegal.