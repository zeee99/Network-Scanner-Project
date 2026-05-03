Network Scanner Project

A high-performance, multi-threaded **TCP Port Scanner** built in Python for internal network auditing and discovery. Developed as part of a Network Programming Design course work assignment.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Team & Contributions](#team--contributions)

---

## Overview

This tool was built to simulate real-world network auditing workflows used by security professionals. It scans TCP ports across single hosts or entire subnets, identifies open services, and provides a clean report — all via a professional CLI interface.

**Key Technologies Used:**
- `socket` — Core TCP connection handling
- `ipaddress` — CIDR subnet parsing
- `concurrent.futures` — Multi-threaded scanning engine
- `argparse` — Professional command-line interface

---

##  Features

| Feature | Description |
|---|---|
|  Multi-threaded | Up to 1000 concurrent threads for fast scanning |
|  Subnet Support | Accepts full CIDR notation (e.g., `192.168.1.0/24`) |
|  Service Detection | Identifies 20+ common services by port number |
|  Banner Grabbing | Attempts to capture service banners |
|  Scan Report | Grouped, sorted summary table at the end |
|  Output to File | Save results with `--output report.txt` |
|  Timeout Control | Configurable timeout to avoid hanging on filtered ports |
|  Error Handling | Gracefully handles unreachable hosts, closed ports, and network errors |


## Requirements

- **Python 3.10+** (uses `dict | None` type hint syntax)
- No external libraries required — uses Python standard library only

---

## Installation & GitHub Push

```bash
1. Clone the repository
git clone https://github.com/zeee99/Network-Scanner-Project.git
cd Network-Scanner-Project

2. Push to main repository
git add .
git commit -m "xxxx"
git push

3. Install dependencies (none required, but listed for reference)
pip install -r requirements.txt

2. Create a virtual environment (This is an optional step)
python -m venv venv
venv\Scripts\activate    # Windows



## Usage


python scanner.py --target <IP or CIDR> --ports <ports> --threads <N> --timeout <seconds>


### Arguments

| Argument | Short | Description | Default |
|---|---|---|---|
| `--target` | `-t` | IP address or CIDR subnet | *(required)* |
| `--ports` | `-p` | Port(s) to scan | `1-1024` |
| `--threads` | `-T` | Number of concurrent threads | `100` |
| `--timeout` | `-to` | TCP connection timeout (seconds) | `1.0` |
| `--output` | `-o` | Save results to a file | *(optional)* |

---

## Examples

```

### 1. Scan a single host (common ports)
```bash
python scanner.py --target 192.168.1.1 --ports 1-1024
```

### 2. Scan a full subnet
```bash
python scanner.py --target 192.168.1.0/24 --ports 1-1024 --threads 200
```

### 3. Scan specific ports only
```bash
python scanner.py --target 10.0.0.5 --ports 22,80,443,3306,8080
```

### 4. Fast full-port scan with aggressive threading
```bash
python scanner.py --target 192.168.1.1 --ports 1-65535 --threads 500 --timeout 0.5
```

### 5. Save results to a file
```bash
python scanner.py --target 192.168.1.0/24 --ports 80,443 --output results.txt
```

---

### Sample Output

```
 _   _      _                      _      ____
| \ | | ___| |___      _____  _ __| | __ / ___|  ___ __ _ _ __  _ __   ___ _ __
...

[+] Target   : 192.168.1.0/24
[+] Hosts    : 254
[+] Ports    : 1024 (1-1024)
[+] Threads  : 100
[+] Timeout  : 1.0s

[*] Scanning 254 host(s) | 1024 port(s) | 100 thread(s) | timeout=1s
[*] Total scan tasks: 260,096
------------------------------------------------------------

  [OPEN]  192.168.1.1:80      (HTTP)
  [OPEN]  192.168.1.1:443     (HTTPS)
  [OPEN]  192.168.1.5:22      (SSH)
  [OPEN]  192.168.1.10:3306   (MySQL)

[*] Scan complete in 42.3 seconds.

============================================================
          SCAN REPORT
============================================================
  Target   : 192.168.1.0/24
  Ports    : 1024 scanned
  Time     : 2026-04-29 09:00:00
  Open     : 4 port(s) found
============================================================

  Host: 192.168.1.1
  PORT     SERVICE         BANNER
  ------- -------------- ------------------------------
  80       HTTP            HTTP/1.1 200 OK
  443      HTTPS           -

  Host: 192.168.1.5
  PORT     SERVICE         BANNER
  ------- -------------- ------------------------------
  22       SSH             SSH-2.0-OpenSSH_8.9
```

---

## Project Structure

```
Network-Scanner-Project/
├── scanner.py          # Main source code
├── README.md           # Documentation (this file)
└── requirements.txt    # Dependencies 
```

---

## How It Works

### 1. Input Parsing
- `argparse` handles all CLI arguments with validation
- `ipaddress.ip_network()` expands CIDR blocks to individual host IPs
- Port strings like `22,80-90,443` are parsed into a sorted list

### 2. Scanning Engine
- A `ThreadPoolExecutor` from `concurrent.futures` creates a thread pool
- Each thread calls `scan_port()` which opens a raw TCP socket
- `connect_ex()` is used instead of `connect()` to get an error code without raising exceptions
- Timeout is set per-socket to prevent hanging on filtered ports

### 3. Service Detection
- Port numbers are matched against a built-in dictionary of 20+ well-known services
- Banner grabbing sends an HTTP HEAD request and reads the first line of response

### 4. Reporting
- Results are grouped by host IP and sorted
- A formatted table is printed to the console
- Optionally saved to a text file

---

## Disclaimer

This tool is intended **strictly for authorized internal network auditing**. Do not use it to scan networks or hosts without explicit permission. Unauthorized port scanning may be illegal in your jurisdiction.

---

## Team & Contributions

| Member | GitHub | Role |
|---|---|---|
| Hiruth | @zeee99 | Core Networking & Socket |
| Sahan | @Sahan-2004 | Subnet Parsing & IP |
| Dulmeth | @Dulmeth-Arosha | Multi-threaded Engine |
| Sandaruwan | @sandaruwanachintha | CLI Interface & Report  |

> All members have active commit histories visible in the repository.

*Network-Scanner-Project | Group 05 
