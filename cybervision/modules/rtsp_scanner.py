#!/usr/bin/env python3
"""
RTSP Scanner
Tests RTSP (Real-Time Streaming Protocol) endpoints commonly used by IP cameras
"""

import socket
import re
from typing import List, Dict, Optional, Tuple


class RTSPScanner:
    """Scans for RTSP streams and tests authentication"""
    
    # Common RTSP paths
    COMMON_PATHS = [
        "/",
        "/live",
        "/stream",
        "/stream1",
        "/stream2",
        "/video",
        "/video1",
        "/video2",
        "/ch0",
        "/ch1",
        "/cam/realmonitor",
        "/Streaming/Channels/1",
        "/Streaming/Channels/101",
        "/Streaming/Channels/2",
        "/h264",
        "/mpeg4",
        "/onvif1",
        "/onvif2",
        "/videoMain",
        "/videoSub",
        "/av0_0",
        "/av0_1",
        "/media/video1",
        "/media/video2",
    ]
    
    def __init__(self, timeout: int = 5):
        """
        Initialize RTSP scanner
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    def send_rtsp_request(self, host: str, port: int, path: str, 
                         method: str = "DESCRIBE") -> Tuple[Optional[str], Optional[int]]:
        """
        Send RTSP request
        
        Args:
            host: Target host
            port: RTSP port (usually 554)
            path: RTSP path
            method: RTSP method (DESCRIBE, OPTIONS, etc.)
            
        Returns:
            Tuple of (response_text, status_code)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Build RTSP request
            request = (
                f"{method} rtsp://{host}:{port}{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: CyberVisionVAPT\r\n"
                f"\r\n"
            )
            
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse status code
            match = re.search(r'RTSP/\d\.\d (\d+)', response)
            status_code = int(match.group(1)) if match else None
            
            return response, status_code
            
        except Exception as e:
            return None, None
    
    def test_rtsp_auth(self, host: str, port: int, path: str, 
                      username: str, password: str) -> bool:
        """
        Test RTSP authentication
        
        Args:
            host: Target host
            port: RTSP port
            path: RTSP path
            username: Username
            password: Password
            
        Returns:
            True if authentication successful
        """
        try:
            import base64
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Basic authentication
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            
            request = (
                f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Authorization: Basic {credentials}\r\n"
                f"\r\n"
            )
            
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check for success
            match = re.search(r'RTSP/\d\.\d (\d+)', response)
            if match:
                status_code = int(match.group(1))
                return status_code == 200
            
        except:
            pass
        
        return False
    
    def scan(self, host: str, port: int = 554) -> List[Dict[str, any]]:
        """
        Scan for RTSP streams
        
        Args:
            host: Target host
            port: RTSP port
            
        Returns:
            List of discovered RTSP streams
        """
        streams = []
        
        for path in self.COMMON_PATHS:
            response, status_code = self.send_rtsp_request(host, port, path)
            
            if status_code:
                stream_info = {
                    "path": path,
                    "url": f"rtsp://{host}:{port}{path}",
                    "status_code": status_code,
                    "requires_auth": status_code == 401
                }
                
                # Check if stream is accessible without authentication
                if status_code == 200:
                    stream_info["accessible"] = True
                    stream_info["security_issue"] = "No authentication required"
                else:
                    stream_info["accessible"] = False
                
                streams.append(stream_info)
        
        return streams
    
    def check_default_credentials(self, host: str, port: int, 
                                  streams: List[Dict]) -> List[Dict]:
        """
        Check for default credentials on RTSP streams
        
        Args:
            host: Target host
            port: RTSP port
            streams: List of discovered streams
            
        Returns:
            List of streams with weak credentials
        """
        vulnerable_streams = []
        
        # Common RTSP credentials
        credentials = [
            ("admin", "admin"),
            ("admin", "12345"),
            ("admin", ""),
            ("root", "root"),
        ]
        
        for stream in streams:
            if stream.get("requires_auth"):
                for username, password in credentials:
                    if self.test_rtsp_auth(host, port, stream["path"], 
                                          username, password):
                        stream_copy = stream.copy()
                        stream_copy["weak_credentials"] = {
                            "username": username,
                            "password": password
                        }
                        vulnerable_streams.append(stream_copy)
                        break
        
        return vulnerable_streams
