#!/usr/bin/env python3
"""
CyberVisionVAPT REST API
Flask-based REST API for the CyberVisionVAPT scanning tool
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
import threading
import time
from datetime import datetime
import sys
import os

# Add parent directory to path to import cybervision modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cybervision.modules.port_scanner import PortScanner
from cybervision.modules.default_creds import DefaultCredentialsChecker
from cybervision.modules.vuln_scanner import VulnerabilityScanner
from cybervision.modules.rtsp_scanner import RTSPScanner
from cybervision.modules.report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend integration

# Store active scans in memory (in production, use a database)
scans = {}
scan_lock = threading.Lock()


class ScanTask:
    """Represents a scanning task"""
    def __init__(self, scan_id, target):
        self.scan_id = scan_id
        self.target = target
        self.status = "initializing"
        self.progress = 0
        self.start_time = datetime.now()
        self.end_time = None
        self.results = {
            "target": target,
            "scan_id": scan_id,
            "open_ports": [],
            "vulnerabilities": [],
            "weak_credentials": [],
            "rtsp_streams": [],
            "risk_score": 0
        }
        self.error = None


def perform_scan(scan_id, target):
    """Perform the actual security scan"""
    scan = scans[scan_id]
    
    try:
        # Initialize scanners
        port_scanner = PortScanner()
        cred_checker = DefaultCredentialsChecker()
        vuln_scanner = VulnerabilityScanner()
        rtsp_scanner = RTSPScanner()
        
        # Step 1: Port Scanning
        scan.status = "port_scanning"
        scan.progress = 10
        print(f"[{scan_id}] Starting port scan on {target}")
        
        open_ports = port_scanner.get_open_ports(target)
        scan.results["open_ports"] = open_ports
        scan.progress = 30
        
        # Step 2: Vulnerability Scanning
        scan.status = "vulnerability_scanning"
        print(f"[{scan_id}] Scanning for vulnerabilities")
        
        vulnerabilities = []
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            vulns = vuln_scanner.scan(target, port, service)
            vulnerabilities.extend(vulns)
        
        scan.results["vulnerabilities"] = vulnerabilities
        scan.progress = 50
        
        # Step 3: Default Credentials Check
        scan.status = "credential_testing"
        print(f"[{scan_id}] Testing for default credentials")
        
        http_ports = [p['port'] for p in open_ports if p['service'].lower() in ['http', 'https', 'http-alt', 'http-proxy']]
        weak_creds = cred_checker.check_device(target, http_ports)
        
        # Flatten credentials results
        creds_list = []
        for url, creds in weak_creds.items():
            for cred in creds:
                creds_list.append({
                    "url": url,
                    "username": cred['username'],
                    "password": cred['password'],
                    "auth_type": cred.get('auth_type', 'Unknown')
                })
        
        scan.results["weak_credentials"] = creds_list
        scan.progress = 70
        
        # Step 4: RTSP Stream Scanning
        scan.status = "rtsp_scanning"
        print(f"[{scan_id}] Scanning for RTSP streams")
        
        rtsp_ports = [p['port'] for p in open_ports if p['port'] == 554 or 'rtsp' in p['service'].lower()]
        rtsp_streams = []
        
        for port in rtsp_ports:
            streams = rtsp_scanner.scan(target, port)
            rtsp_streams.extend(streams)
        
        scan.results["rtsp_streams"] = rtsp_streams
        scan.progress = 90
        
        # Calculate risk score
        scan.status = "calculating_risk"
        risk_score = calculate_risk_score(vulnerabilities, creds_list, rtsp_streams)
        scan.results["risk_score"] = risk_score
        
        # Complete scan
        scan.status = "completed"
        scan.progress = 100
        scan.end_time = datetime.now()
        
        print(f"[{scan_id}] Scan completed successfully")
        
    except Exception as e:
        scan.status = "error"
        scan.error = str(e)
        scan.end_time = datetime.now()
        print(f"[{scan_id}] Scan failed: {str(e)}")


def calculate_risk_score(vulnerabilities, credentials, rtsp_streams):
    """Calculate risk score based on findings"""
    score = 0
    
    # Vulnerabilities
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'low').lower()
        if severity == 'critical':
            score += 25
        elif severity == 'high':
            score += 15
        elif severity == 'medium':
            score += 10
        else:
            score += 5
    
    # Weak credentials
    score += len(credentials) * 20
    
    # Unauthenticated RTSP streams
    for stream in rtsp_streams:
        if stream.get('accessible', False):
            score += 10
    
    return min(score, 100)  # Cap at 100


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })


@app.route('/api/scan', methods=['POST'])
def initiate_scan():
    """Initiate a new security scan"""
    data = request.get_json()
    
    if not data or 'target' not in data:
        return jsonify({"error": "Target IP/hostname required"}), 400
    
    target = data['target']
    scan_id = str(uuid.uuid4())
    
    # Create scan task
    scan = ScanTask(scan_id, target)
    
    with scan_lock:
        scans[scan_id] = scan
    
    # Start scan in background thread
    thread = threading.Thread(target=perform_scan, args=(scan_id, target))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "scan_id": scan_id,
        "target": target,
        "status": "initiated",
        "message": "Scan started successfully"
    }), 202


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a scan"""
    scan = scans.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    response = {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "status": scan.status,
        "progress": scan.progress,
        "start_time": scan.start_time.isoformat(),
        "end_time": scan.end_time.isoformat() if scan.end_time else None
    }
    
    if scan.error:
        response["error"] = scan.error
    
    return jsonify(response)


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get the results of a completed scan"""
    scan = scans.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    if scan.status not in ['completed', 'error']:
        return jsonify({
            "error": "Scan not completed",
            "status": scan.status,
            "progress": scan.progress
        }), 400
    
    response = {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "status": scan.status,
        "start_time": scan.start_time.isoformat(),
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
        "results": scan.results
    }
    
    if scan.error:
        response["error"] = scan.error
    
    return jsonify(response)


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    scan_list = []
    
    with scan_lock:
        for scan_id, scan in scans.items():
            scan_list.append({
                "scan_id": scan.scan_id,
                "target": scan.target,
                "status": scan.status,
                "progress": scan.progress,
                "start_time": scan.start_time.isoformat(),
                "end_time": scan.end_time.isoformat() if scan.end_time else None,
                "risk_score": scan.results.get("risk_score", 0)
            })
    
    # Sort by start time (most recent first)
    scan_list.sort(key=lambda x: x['start_time'], reverse=True)
    
    return jsonify({"scans": scan_list, "total": len(scan_list)})


@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan from memory"""
    with scan_lock:
        if scan_id in scans:
            del scans[scan_id]
            return jsonify({"message": "Scan deleted successfully"})
        else:
            return jsonify({"error": "Scan not found"}), 404


if __name__ == '__main__':
    print("Starting CyberVisionVAPT API Server...")
    print("API will be available at http://localhost:5000")
    print("\nAvailable endpoints:")
    print("  GET  /api/health")
    print("  POST /api/scan")
    print("  GET  /api/scan/<scan_id>/status")
    print("  GET  /api/scan/<scan_id>/results")
    print("  GET  /api/scans")
    print("  DELETE /api/scan/<scan_id>")
    
    app.run(debug=True, host='0.0.0.0', port=5000)