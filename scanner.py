 #!/usr/bin/env python3
"""
Network Discovery & Auditing Tool
====================================
A high-performance, multi-threaded TCP Port Scanner for internal network auditing.
 
Team Contributions:
  Part 1 - Core Networking & Socket  : Hiruth
  Part 2 - Subnet Parsing & IP       : Sahan
  Part 3 - Multi-threaded Engine     : Dulmeth
  Part 4 - CLI Interface & Report    : Sandaruwan
 
Usage:
  python scanner.py --target 192.168.1.0/24 --ports 1-1024 --threads 100
  python scanner.py --target 192.168.1.1    --ports 22,80,443
"""
 
import socket
import ipaddress
import argparse
import concurrent.futures
import sys
import time
from datetime import datetime
from collections import defaultdict
 
 
# ==============================================================
# BANNER
# ==============================================================
 
BANNER = r"""
 _   _      _                      _      ____
| \ | | ___| |___      _____  _ __| | __ / ___|  ___ __ _ _ __  _ __   ___ _ __
|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <   ___) | (_| (_| | | | | | | |  __/ |
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|
 
        [ Network Discovery & Auditing Tool ] | For Internal Use Only
"""
 
 
# ==============================================================
# PART 1 - CORE NETWORKING & SOCKET PROGRAMMING
# Author : Hiruth
# About  : TCP connection handling and port scanning core function
# ==============================================================
 
# Dictionary of well known port numbers and their service names
COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "MS-RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL Database",
    3306:  "MySQL",
    3389:  "RDP",
    5000:  "Flask Server",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter Notebook",
    27017: "MongoDB",
}
 
 
def scan_port(ip: str, port: int, timeout: float):
    """
    Core scanning function written by zeee99.
    Attempts a TCP connection to ip:port using the socket module.
    Returns a result dictionary if the port is open.
    Returns None if the port is closed or filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Set timeout to avoid hanging on filtered ports
            sock.settimeout(timeout)
            # connect_ex returns 0 if connection successful meaning port is open
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Port is open - identify the service name from dictionary
                service = COMMON_PORTS.get(port, "Unknown")
                # Try to grab a service banner
                banner = ""
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw = sock.recv(1024).decode(errors="ignore").strip()
                    banner = raw.split("\n")[0][:60]
                except Exception:
                    pass
                return {
                    "ip":      ip,
                    "port":    port,
                    "service": service,
                    "banner":  banner
                }
    except socket.timeout:
        pass
    except OSError:
        pass
    return None
 
# ======================================================
# END OF PART 1
# ======================================================
 