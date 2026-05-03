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

# ==============================================================
# PART 2 - SUBNET PARSING & IP ADDRESS HANDLING
# Author : Sahan
# About  : Parses CIDR blocks and port ranges into scannable lists
# ==============================================================

def parse_targets(target: str):
    """
    Written by Friend 1.
    Accepts a single IP address or a full CIDR subnet block.
    Returns a list of all host IP strings to scan.

    Examples:
        '192.168.1.1'    -> ['192.168.1.1']
        '192.168.1.0/24' -> ['192.168.1.1', ..., '192.168.1.254']
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        # Single host - return just that one IP address
        if network.num_addresses == 1:
            return [str(network.network_address)]
        # Full subnet - automatically skip network and broadcast addresses
        return [str(host) for host in network.hosts()]
    except ValueError as e:
        print(f"[ERROR] Invalid target '{target}': {e}")
        sys.exit(1)


def parse_ports(ports_arg: str):
    """
    Written by Friend 1.
    Parses the port argument string into a sorted list of integers.

    Supports multiple formats:
        Single port  :  '80'
        Range        :  '1-1024'
        Comma list   :  '22,80,443'
        Mixed        :  '22,80-90,443'
    """
    ports = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                r_start, r_end = int(start), int(end)
                if not (1 <= r_start <= 65535 and 1 <= r_end <= 65535):
                    raise ValueError
                ports.update(range(r_start, r_end + 1))
            except ValueError:
                print(f"[ERROR] Invalid port range: '{part}'")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError
                ports.add(p)
            except ValueError:
                print(f"[ERROR] Invalid port: '{part}'")
                sys.exit(1)
    return sorted(ports)

# ======================================================
# END OF PART 2
# ======================================================

# ==============================================================
# PART 3 - MULTI-THREADED SCANNING ENGINE
# Author : Dulmeth
# About  : High performance concurrent scanning using ThreadPoolExecutor
# ==============================================================

def run_scan(targets: list, ports: list, threads: int, timeout: float):
    """
    Written by Friend 2.
    Launches concurrent TCP scans using a ThreadPoolExecutor thread pool.
    Instead of scanning one port at a time which is slow, this sends
    many workers at the same time to dramatically speed up the scan.
    Returns a list of all open port result dictionaries.
    """
    open_ports = []
    total_tasks = len(targets) * len(ports)
    completed = 0

    print(f"\n[*] Scanning {len(targets)} host(s) | "
          f"{len(ports)} port(s) | "
          f"{threads} thread(s) | "
          f"timeout={timeout}s")
    print(f"[*] Total scan tasks: {total_tasks:,}")
    print("-" * 60)

    start_time = time.time()

    # Create thread pool with the specified number of worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:

        # Submit every IP and port combination as a separate job to the pool
        future_map = {
            executor.submit(scan_port, ip, port, timeout): (ip, port)
            for ip in targets
            for port in ports
        }

        # Process results as each thread finishes
        for future in concurrent.futures.as_completed(future_map):
            completed += 1

            # Show live progress every 500 tasks or at the very end
            if completed % 500 == 0 or completed == total_tasks:
                pct     = (completed / total_tasks) * 100
                elapsed = time.time() - start_time
                print(
                    f"  Progress: {completed:,}/{total_tasks:,} "
                    f"({pct:.1f}%) | Elapsed: {elapsed:.1f}s",
                    end="\r"
                )

            # If port is open save it and print immediately
            result = future.result()
            if result:
                open_ports.append(result)
                service = result["service"]
                banner  = f" | {result['banner']}" if result["banner"] else ""
                print(
                    f"\n  [OPEN]  "
                    f"{result['ip']}:{result['port']:<6} "
                    f"({service}){banner}"
                )

    elapsed_total = time.time() - start_time
    print(f"\n\n[*] Scan complete in {elapsed_total:.2f} seconds.")
    return open_ports

# ======================================================
# END OF PART 3
# ======================================================
# ==============================================================
# PART 4 - CLI INTERFACE & REPORT GENERATOR
# Author : Sandaruwan
# About  : Professional command line interface and scan report output
# ==============================================================

def build_arg_parser():
    """
    Written by Friend 3.
    Builds the professional command line argument parser using argparse.
    Allows users to define targets, port ranges, thread counts
    and timeouts directly from the terminal.
    """
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Network Discovery & Auditing Tool — Multi-threaded TCP Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python scanner.py --target 192.168.1.0/24 --ports 1-1024 --threads 100
  python scanner.py --target 192.168.1.1    --ports 22,80,443
  python scanner.py --target 10.0.0.0/28   --ports 1-65535 --threads 200 --timeout 0.5
        """
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address or CIDR subnet (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Port(s) to scan. Examples: 80 | 1-1024 | 22,80,443\n(default: 1-1024)"
    )
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", "-to",
        type=float,
        default=1.0,
        help="TCP connection timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Save results to a text file (optional)"
    )
    return parser


def print_report(results: list, target: str, ports_scanned: int):
    """
    Written by Friend 3.
    Prints a clean formatted summary report of all open ports found.
    Results are grouped by host IP and sorted numerically.
    """
    print("\n" + "=" * 60)
    print("          SCAN REPORT")
    print("=" * 60)
    print(f"  Target   : {target}")
    print(f"  Ports    : {ports_scanned} scanned")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Open     : {len(results)} port(s) found")
    print("=" * 60)

    if not results:
        print("  No open ports discovered.")
    else:
        # Group all results by their host IP address
        by_host = defaultdict(list)
        for r in results:
            by_host[r["ip"]].append(r)

        # Sort hosts numerically by IP address
        for ip in sorted(by_host.keys(), key=lambda x: ipaddress.ip_address(x)):
            print(f"\n  Host: {ip}")
            print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
            print(f"  {'-'*7} {'-'*14} {'-'*30}")
            for r in sorted(by_host[ip], key=lambda x: x["port"]):
                banner = r["banner"] if r["banner"] else "-"
                print(f"  {r['port']:<8} {r['service']:<15} {banner}")

    print("\n" + "=" * 60)


# ==============================================================
# MAIN - ENTRY POINT
# Combines all 4 parts together into one working program
# ==============================================================

def main():
    # Show the banner
    print(BANNER)

    # Part 4 - Parse CLI arguments
    parser = build_arg_parser()
    args   = parser.parse_args()

    # Validate thread count
    if args.threads < 1 or args.threads > 1000:
        print("[ERROR] Threads must be between 1 and 1000.")
        sys.exit(1)

    # Part 2 - Parse targets and ports
    targets = parse_targets(args.target)
    ports   = parse_ports(args.ports)

    # Show scan configuration summary
    print(f"[+] Target   : {args.target}")
    print(f"[+] Hosts    : {len(targets)}")
    print(f"[+] Ports    : {len(ports)} ({args.ports})")
    print(f"[+] Threads  : {args.threads}")
    print(f"[+] Timeout  : {args.timeout}s")

    # Warn user if scan is very large
    total = len(targets) * len(ports)
    if total > 50_000:
        confirm = input(f"\n[!] Large scan: {total:,} tasks. Continue? [y/N]: ")
        if confirm.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    # Part 3 - Run the multi-threaded scan (uses Part 1 internally)
    results = run_scan(targets, ports, args.threads, args.timeout)

    # Part 4 - Print the final report
    print_report(results, args.target, len(ports))

    # Save results to file if --output was specified
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(f"Scan Report - {datetime.now()}\n")
                f.write(f"Target: {args.target}\n")
                f.write(f"Open ports found: {len(results)}\n\n")
                for r in sorted(results, key=lambda x: (x["ip"], x["port"])):
                    f.write(f"{r['ip']}:{r['port']} ({r['service']})")
                    if r["banner"]:
                        f.write(f" | {r['banner']}")
                    f.write("\n")
            print(f"\n[+] Results saved to: {args.output}")
        except IOError as e:
            print(f"[ERROR] Could not write to file: {e}")


if __name__ == "__main__":
    main()

# ======================================================
# END OF PART 4
# This is the complete scanner.py file
# ======================================================
