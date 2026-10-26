#!/usr/bin/env python3
"""
Simple TCP Port Scanner - educational project.
Use ONLY on devices you own or have written permission to test.
"""
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}

RISKY = {
    21: "FTP sends data unencrypted. Use SFTP instead.",
    23: "Telnet is unencrypted. Use SSH instead.",
    135: "RPC should not be exposed to untrusted networks.",
    139: "NetBIOS exposure can leak information.",
    445: "SMB is a common attack target. Restrict access.",
    3389: "RDP exposed to the internet is high risk. Use VPN + MFA.",
}


def scan_port(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="Target IP or hostname (must be authorized)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout (sec)")
    args = parser.parse_args()

    if not (1 <= args.start <= args.end <= 65535):
        parser.error("Ports must satisfy 1 <= start <= end <= 65535")
    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0")

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print("Could not resolve host.")
        return

    print(f"Scanning {args.host} ({ip}) ports {args.start}-{args.end}")
    print(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    ports = range(args.start, args.end + 1)
    with ThreadPoolExecutor(max_workers=100) as pool:
        results = pool.map(lambda p: scan_port(ip, p, args.timeout), ports)
        open_ports = [p for p in results if p is not None]

    if not open_ports:
        print("No open ports found.")
        return

    print(f"{'PORT':<8}{'SERVICE':<12}NOTE")
    for p in open_ports:
        service = COMMON_SERVICES.get(p, "unknown")
        note = RISKY.get(p, "")
        print(f"{p:<8}{service:<12}{note}")

    print(f"\nTotal open ports: {len(open_ports)}")


if __name__ == "__main__":
    main()
