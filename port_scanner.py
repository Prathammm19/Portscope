#!/usr/bin/env python3
"""
Port Scanner + Service Detector
================================
A TCP connect scanner that teaches the core ideas of network reconnaissance:

  1. Sockets  -> the OS-level endpoint for network communication
  2. TCP connect scan -> full three-way handshake per port (SYN/SYN-ACK/ACK)
  3. Service detection -> mapping ports to well-known services + banner grabbing
  4. Concurrency -> scanning 1000s of ports serially is too slow, so we use a
     thread pool to run many connection attempts in parallel

LEGAL/ETHICAL: Only run this against hosts you own or are explicitly
authorized to test. Unauthorized scanning can be illegal even without
causing damage. scanme.nmap.org is provided by the Nmap project specifically
for people to practice scanning against.

Usage:
    python3 port_scanner.py scanme.nmap.org -p 1-1000
    python3 port_scanner.py 127.0.0.1 -p 20,21,22,80,443 --banner
"""

import socket
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# A small lookup table of common ports -> service names.
# socket.getservbyport() can also do this via /etc/services, but keeping our
# own table makes the tool portable and lets us show what's happening.
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    111: "RPCBIND", 123: "NTP", 135: "MSRPC", 139: "NETBIOS", 143: "IMAP",
    161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    514: "SYSLOG", 587: "SMTP-SUB", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE", 1723: "PPTP", 3000: "DEV-HTTP",
    3306: "MYSQL", 3389: "RDP", 5000: "DEV-HTTP", 5432: "POSTGRESQL",
    5900: "VNC", 6379: "REDIS", 8000: "HTTP-ALT", 8080: "HTTP-PROXY",
    8443: "HTTPS-ALT", 9200: "ELASTICSEARCH", 27017: "MONGODB",
}


def guess_service(port: int) -> str:
    """Look up a friendly service name for a port number."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """
    Attempt to read a service banner after connecting.
    Many services (FTP, SSH, SMTP) announce themselves immediately on
    connect. HTTP servers need a nudge (a request) before they respond,
    so we send a minimal HTTP HEAD request as a fallback probe.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
            except socket.timeout:
                banner = ""
            if not banner and port in (80, 8080, 8000, 8443, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, do_banner: bool):
    """
    The core primitive: attempt a full TCP connect to (ip, port).

    connect_ex() returns 0 on success instead of raising an exception,
    which is convenient for scanning -- most ports will be closed/filtered,
    and we don't want exception overhead on every failed attempt.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))  # 0 = open, TCP handshake succeeded
    sock.close()

    if result == 0:
        service = guess_service(port)
        banner = grab_banner(ip, port, timeout) if do_banner else ""
        return (port, "open", service, banner)
    return None  # closed or filtered -- we simply don't report it


def parse_ports(port_spec: str):
    """Parse '1-1000' or '22,80,443' or a mix like '22,80,1000-1010'."""
    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


def run_scan(target: str, ports, timeout=1.0, max_workers=200, do_banner=False, progress=True):
    """
    Resolve the target hostname, then fan the port list out across a
    thread pool. Threads (not processes) are the right tool here because
    the work is I/O-bound: each task spends almost all its time waiting
    on the network, not burning CPU.
    """
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)

    print(f"[*] Scanning {target} ({ip}) -- {len(ports)} ports, {max_workers} threads")
    start = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_port, ip, p, timeout, do_banner): p for p in ports}
        done = 0
        for future in as_completed(futures):
            done += 1
            if progress and done % 200 == 0:
                print(f"    ...{done}/{len(ports)} checked", end="\r")
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda r: r[0])
    elapsed = time.time() - start
    print(f"\n[*] Scan complete in {elapsed:.2f}s -- {len(open_ports)} open port(s)\n")

    if open_ports:
        print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<16}{'BANNER'}")
        for port, state, service, banner in open_ports:
            print(f"{port:<8}{state:<8}{service:<16}{banner[:60]}")
    else:
        print("No open ports found in the given range.")

    return open_ports


def main():
    parser = argparse.ArgumentParser(description="Educational TCP port scanner + service detector")
    parser.add_argument("target", help="Hostname or IP to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports: '1-1024', '22,80,443', or mixed (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-port timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=200, help="Thread pool size")
    parser.add_argument("--banner", action="store_true", help="Attempt banner grabbing on open ports")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    run_scan(args.target, ports, timeout=args.timeout, max_workers=args.workers, do_banner=args.banner)


if __name__ == "__main__":
    main()
