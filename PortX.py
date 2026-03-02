import socket
import sys
import time
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, init

init(autoreset=True)

# ================= CONFIG =================
MAX_THREADS = 300
TIMEOUT = 0.5
START_PORT = 1
END_PORT = 65535
BATCH_SIZE = 2000
RATE_DELAY = 0.001
OUTPUT_FILE = "scan_results.txt"

SCAN_TCP = True
SCAN_UDP = True
# ==========================================

stop_scan = False

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy",
}


def signal_handler(sig, frame):
    global stop_scan
    stop_scan = True
    print(f"\n{Fore.RED}[!] Scan interrupted.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ================= DNS =================
def load_targets(file_path):
    try:
        with open(file_path, "r") as f:
            hosts = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Target file not found!")
        sys.exit(1)

    ip_map = {}

    print(f"\n{Fore.CYAN}Resolving DNS...")
    for host in tqdm(hosts, ncols=100, desc="DNS"):
        try:
            ip = socket.gethostbyname(host)
            ip_map.setdefault(ip, []).append(host)
        except:
            tqdm.write(f"{Fore.RED}Failed to resolve: {host}")

    print(f"{Fore.GREEN}Resolved {len(ip_map)} unique IPs\n")
    return ip_map


# ================= TCP =================
def scan_tcp(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except:
        pass
    return None


# ================= UDP =================
def scan_udp(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(b"\x00", (ip, port))
        try:
            sock.recvfrom(1024)
            sock.close()
            return port
        except socket.timeout:
            sock.close()
            return None
    except:
        return None


# ================= SCAN ENGINE =================
def scan_ports(ip, protocol="tcp"):
    open_ports = []
    total_ports = END_PORT - START_PORT + 1

    with tqdm(total=total_ports, ncols=100, desc=f"{protocol.upper()} Scan") as pbar:

        for batch_start in range(START_PORT, END_PORT + 1, BATCH_SIZE):

            if stop_scan:
                break

            batch_end = min(batch_start + BATCH_SIZE - 1, END_PORT)

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

                if protocol == "tcp":
                    futures = [
                        executor.submit(scan_tcp, ip, port)
                        for port in range(batch_start, batch_end + 1)
                    ]
                else:
                    futures = [
                        executor.submit(scan_udp, ip, port)
                        for port in range(batch_start, batch_end + 1)
                    ]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                    pbar.update(1)

            time.sleep(RATE_DELAY)

    return sorted(open_ports)


def detect_service(port):
    try:
        return socket.getservbyport(port).upper()
    except:
        return COMMON_SERVICES.get(port, "Unknown")


# ================= MAIN =================
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py targets.txt")
        sys.exit(1)

    ip_map = load_targets(sys.argv[1])
    open(OUTPUT_FILE, "w").close()

    for ip, domains in ip_map.items():

        print("=" * 60)
        print(f"{Fore.CYAN}Scanning IP: {ip}")
        for d in domains:
            print(f"  - {d}")

        start_time = datetime.now()

        tcp_ports = scan_ports(ip, "tcp") if SCAN_TCP else []
        udp_ports = scan_ports(ip, "udp") if SCAN_UDP else []

        end_time = datetime.now()

        with open(OUTPUT_FILE, "a") as f:

            f.write("=" * 60 + "\n")
            f.write("Targets Group\n")
            f.write("-" * 60 + "\n")
            f.write(f"Resolved IP   : {ip}\n")
            f.write(f"Scan Time     : {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("Associated Domains:\n")
            for d in domains:
                f.write(f"  - {d}\n")

            f.write("\n" + "-" * 60 + "\n\n")

            # TCP
            f.write("Open TCP Ports:\n")
            if tcp_ports:
                for port in tcp_ports:
                    f.write(f"  - {port:<5} ({detect_service(port)})\n")
            else:
                f.write("  None\n")

            f.write(f"\nTotal TCP Ports: {len(tcp_ports)}\n\n")

            # UDP
            f.write("Open UDP Ports:\n")
            if udp_ports:
                for port in udp_ports:
                    f.write(f"  - {port:<5} ({detect_service(port)})\n")
            else:
                f.write("  None\n")

            f.write(f"\nTotal UDP Ports: {len(udp_ports)}\n\n")

            f.write(f"Total Open Ports: {len(tcp_ports) + len(udp_ports)}\n")
            f.write("=" * 60 + "\n\n")

    print(f"{Fore.CYAN}Scan complete. Results saved in {OUTPUT_FILE}")


if __name__ == "__main__":
    main()