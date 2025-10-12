# Quick Reference Guide

## Installation

```bash
# Clone repository
git clone https://github.com/Parthpatil7/CyberVisionVAPT.git
cd CyberVisionVAPT

# Install dependencies
pip install -r requirements.txt

# Run test suite
python test_suite.py
```

## Basic Usage

### Single Target Scan
```bash
python cybervision_scanner.py 192.168.1.100
```

### Network Range Scan
```bash
python cybervision_scanner.py 192.168.1.0/24
```

### Verbose Output
```bash
python cybervision_scanner.py 192.168.1.100 -v
```

### Save Reports
```bash
# Text report
python cybervision_scanner.py 192.168.1.100 -o report.txt

# JSON report
python cybervision_scanner.py 192.168.1.100 --json report.json

# Both formats
python cybervision_scanner.py 192.168.1.100 -o report.txt --json report.json
```

## Module Usage

### Port Scanner
```python
from cybervision.modules.port_scanner import PortScanner

scanner = PortScanner()
open_ports = scanner.get_open_ports("192.168.1.100")

for port_info in open_ports:
    print(f"{port_info['port']}: {port_info['service']}")
```

### Default Credentials Checker
```python
from cybervision.modules.default_creds import DefaultCredentialsChecker

checker = DefaultCredentialsChecker()
results = checker.check_device("192.168.1.100", [80, 8080])

for url, creds in results.items():
    for cred in creds:
        print(f"{cred['username']}:{cred['password']} on {url}")
```

### Vulnerability Scanner
```python
from cybervision.modules.vuln_scanner import VulnerabilityScanner

scanner = VulnerabilityScanner()
vulns = scanner.scan("192.168.1.100", 80, "http")

for vuln in vulns:
    print(f"{vuln['cve']}: {vuln['description']}")
```

### RTSP Scanner
```python
from cybervision.modules.rtsp_scanner import RTSPScanner

scanner = RTSPScanner()
streams = scanner.scan("192.168.1.100", 554)

for stream in streams:
    print(f"{stream['url']} - Accessible: {stream['accessible']}")
```

### Report Generator
```python
from cybervision.modules.report_generator import ReportGenerator

report = ReportGenerator("192.168.1.100")
report.add_port_scan_results([...])
report.add_vulnerabilities([...])

# Generate text report
print(report.generate_text_report())

# Save to file
report.save_report("report.txt", format="text")
report.save_report("report.json", format="json")
```

## Common Ports

| Port  | Service           | Common On               |
|-------|-------------------|-------------------------|
| 80    | HTTP              | All devices             |
| 443   | HTTPS             | All devices             |
| 554   | RTSP              | IP cameras              |
| 8000  | HTTP-Alt          | Many DVRs               |
| 8080  | HTTP-Proxy        | Many devices            |
| 8081  | HTTP-Alt          | Some cameras            |
| 37777 | DVR (Dahua)       | Dahua devices           |
| 34567 | DVR (Hikvision)   | Hikvision devices       |
| 6036  | DVR (Foscam)      | Foscam devices          |
| 9527  | DVR (Xiongmai)    | Xiongmai devices        |

## Default Credentials

### Generic
- admin/admin
- admin/12345
- admin/(blank)
- root/root

### Hikvision
- admin/12345
- admin/hikivision

### Dahua
- admin/admin
- 666666/666666
- admin/888888

### Foscam
- admin/(blank)
- admin/foscam

## CVE Database

### Hikvision
- **CVE-2017-7921**: Unauthorized access vulnerability
- **CVE-2021-36260**: Command injection

### Dahua
- **CVE-2021-33044**: Authentication bypass

### Generic
- **DIR_TRAVERSAL**: Directory traversal
- **INFO_DISCLOSURE**: Configuration file exposure

## Risk Score Calculation

The tool calculates risk scores based on:
- Critical vulnerabilities: +25 per finding
- High vulnerabilities: +15 per finding
- Weak credentials: +20 per finding
- Unauthenticated RTSP: +10 per stream

Maximum score: 100 (highest risk)

## Output Formats

### Text Report
- Human-readable format
- Section-based layout
- Color-coded severity (terminal)
- Security recommendations

### JSON Report
- Machine-readable format
- Structured data
- Easy to parse
- Integration-friendly

## Files and Directories

```
CyberVisionVAPT/
├── cybervision/           # Main package
│   ├── modules/          # Scanning modules
│   ├── utils/            # Utilities
│   └── data/             # Data files
├── examples/             # Example scripts
├── cybervision_scanner.py # Main scanner
├── test_suite.py         # Test suite
├── requirements.txt      # Dependencies
└── README.md            # Documentation
```

## Exit Codes

- `0`: Scan completed successfully
- `1`: Error occurred or user interrupted

## Environment Variables

None currently used. All configuration via command-line arguments.

## Troubleshooting

### Connection Timeouts
- Increase timeout in module initialization
- Check network connectivity
- Verify target is reachable

### Permission Denied
- Run with appropriate network permissions
- Check firewall rules
- Verify target allows connections

### Module Import Errors
- Ensure all dependencies installed: `pip install -r requirements.txt`
- Check Python version (3.7+)
- Verify file structure intact

## Best Practices

1. **Always get permission** before scanning
2. **Start with verbose mode** for debugging
3. **Save reports** for documentation
4. **Regular updates** check for tool updates
5. **Responsible disclosure** report vulnerabilities properly

## Legal Reminder

⚠️ **IMPORTANT**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: README.md, examples/
- Test Suite: Run `python test_suite.py` to verify installation

---

For detailed information, see README.md and SECURITY_BEST_PRACTICES.md
