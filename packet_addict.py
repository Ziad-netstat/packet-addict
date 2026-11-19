#!/usr/bin/env python3
"""
Packet Addict - packet sniffer + port analyzer in one tool.

Examples:
  python3 packet_addict.py interfaces
  sudo python3 packet_addict.py sniff -i eth0 -c 100
  sudo python3 packet_addict.py sniff -f "tcp port 80" -w capture.pcap
  python3 packet_addict.py scan 192.168.1.1 -p 1-1024
  python3 packet_addict.py scan scanme.nmap.org -p 22,80,443 -t 100

Only sniff networks and scan hosts you own or have permission to test.
"""
import argparse
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import (ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6,
                       PcapWriter, get_if_addr, get_if_list, sniff)

BANNER = r"""
  ____            _        _      _       _     _ _      _
 |  _ \ __ _  ___| | _____| |_   / \   __| | __| (_) ___| |_
 | |_) / _` |/ __| |/ / _ \ __| / _ \ / _` |/ _` | |/ __| __|
 |  __/ (_| | (__|   <  __/ |_ / ___ \ (_| | (_| | | (__| |_
 |_|   \__,_|\___|_|\_\___|\__/_/   \_\__,_|\__,_|_|\___|\__|
"""


# --------------------------------------------------------------------------
# Sniffer
# --------------------------------------------------------------------------
ICMP_NAMES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request",
              11: "time-exceeded"}


class Sniffer:
    def __init__(self, write_path=None, dedupe=False):
        self.dedupe = dedupe
        self._last_raw = None
        self._last_time = 0.0
        self.total = 0
        # Packets are streamed straight to disk, so memory stays flat
        # even if you capture for hours.
        self.writer = PcapWriter(write_path, sync=True) if write_path else None
        self.protocols = Counter()
        self.talkers = Counter()      # source IPs
        self.dst_ports = Counter()    # destination ports seen
        self.syn_sources = Counter()  # who is sending SYNs (scan hint)

    def is_duplicate(self, pkt):
        """On the loopback interface each packet is captured twice.
        Treat an identical packet arriving right after another as a copy."""
        raw, t = bytes(pkt), float(pkt.time)
        dup = raw == self._last_raw and (t - self._last_time) < 0.01
        self._last_raw, self._last_time = raw, t
        return dup

    def handle(self, pkt):
        if self.dedupe and self.is_duplicate(pkt):
            return
        self.total += 1
        if self.writer:
            self.writer.write(pkt)
        line = self.describe(pkt)
        if line:
            print(line)

    def describe(self, pkt):
        ts = time.strftime("%H:%M:%S")

        if ARP in pkt:
            a = pkt[ARP]
            self.protocols["ARP"] += 1
            if a.op == 1:
                return f"{ts} ARP   who-has {a.pdst} tell {a.psrc}"
            return f"{ts} ARP   {a.psrc} is-at {a.hwsrc}"

        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            self.protocols["OTHER"] += 1
            return None

        src, dst = ip.src, ip.dst
        self.talkers[src] += 1

        if TCP in pkt:
            t = pkt[TCP]
            flags = str(t.flags)
            self.protocols["TCP"] += 1
            self.dst_ports[("tcp", t.dport)] += 1
            if flags == "S":
                self.syn_sources[src] += 1
            return (f"{ts} TCP   {src}:{t.sport} -> {dst}:{t.dport} "
                    f"[{flags}] len={len(pkt)}")

        if UDP in pkt:
            u = pkt[UDP]
            self.protocols["UDP"] += 1
            self.dst_ports[("udp", u.dport)] += 1
            extra = ""
            if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                extra = " DNS query: " + pkt[DNSQR].qname.decode(errors="ignore")
                self.protocols["DNS"] += 1
            return (f"{ts} UDP   {src}:{u.sport} -> {dst}:{u.dport} "
                    f"len={len(pkt)}{extra}")

        if ICMP in pkt:
            self.protocols["ICMP"] += 1
            kind = ICMP_NAMES.get(pkt[ICMP].type, f"type={pkt[ICMP].type}")
            return f"{ts} ICMP  {src} -> {dst} {kind}"

        self.protocols["OTHER"] += 1
        return None

    def summary(self):
        print("\n" + "=" * 60)
        print(f"Captured {self.total} packets")
        print("\nProtocols:")
        for proto, n in self.protocols.most_common():
            print(f"  {proto:<6} {n}")
        print("\nTop talkers:")
        for ip, n in self.talkers.most_common(5):
            print(f"  {ip:<40} {n}")
        print("\nMost-targeted ports:")
        for (proto, port), n in self.dst_ports.most_common(10):
            print(f"  {proto}/{port:<6} {service_name(port, proto):<12} {n} pkts")
        suspects = [(ip, n) for ip, n in self.syn_sources.items() if n >= 20]
        if suspects:
            print("\nPossible port scan (many bare SYNs):")
            for ip, n in suspects:
                print(f"  {ip} sent {n} SYN packets")


def run_sniff(args):
    s = Sniffer(write_path=args.write, dedupe=(args.interface == "lo"))
    print(f"[*] Sniffing on {args.interface or 'default interface'}"
          f"{' filter=' + args.filter if args.filter else ''}")
    if args.count:
        print(f"[*] Will stop after {args.count} packets (or press Ctrl+C)\n")
    else:
        print("[*] Capturing until you press Ctrl+C\n")
    try:
        sniff(iface=args.interface, filter=args.filter, prn=s.handle,
              count=args.count, store=False)
    except PermissionError:
        print("[!] Need root to sniff. Run with sudo.")
        return
    except KeyboardInterrupt:
        pass
    s.summary()
    if s.writer:
        s.writer.close()
        print(f"\n[+] Saved {s.total} packets to {args.write} "
              "(open it in Wireshark)")


def run_interfaces(args):
    print("Available network interfaces:\n")
    for name in get_if_list():
        try:
            addr = get_if_addr(name)
        except Exception:
            addr = "-"
        print(f"  {name:<14} {addr}")
    print("\nUse a name with:  sudo python3 packet_addict.py sniff -i NAME")


# --------------------------------------------------------------------------
# Port scanner
# --------------------------------------------------------------------------
def service_name(port, proto="tcp"):
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def probe(host, port, timeout):
    """TCP connect scan on one port, with a small banner grab if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            sock.settimeout(1.0)
            try:
                if port in (80, 8000, 8080, 8888):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(128)
                banner = data.decode(errors="ignore").strip().splitlines()[0]
            except (socket.timeout, OSError, IndexError):
                pass
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""


def run_scan(args):
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Cannot resolve {args.target}")
        return
    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.target} ({ip}) - {len(ports)} ports, "
          f"{args.threads} threads")
    print("[*] Open ports appear as they are found. Press Ctrl+C to stop early.\n")

    total = len(ports)
    done = 0
    open_ports = []
    start = time.time()

    def show_progress():
        print(f"\r[*] Checked {done}/{total} ports, {len(open_ports)} open",
              end="", flush=True)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(probe, ip, p, args.timeout) for p in ports]
        try:
            for fut in as_completed(futures):
                port, is_open, banner = fut.result()
                done += 1
                if is_open:
                    open_ports.append(port)
                    print("\r" + " " * 50 + "\r", end="")  # clear progress line
                    print(f"[+] {port:<6}{service_name(port):<12}{banner}")
                if done % 100 == 0 or done == total:
                    show_progress()
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            print("\n\n[!] Stopped early.")

    elapsed = time.time() - start
    print(f"\n\n[+] Checked {done}/{total} ports in {elapsed:.1f}s")
    if open_ports:
        print("[+] Open ports: " + ", ".join(str(p) for p in sorted(open_ports)))
    else:
        print("[+] No open ports found")


# --------------------------------------------------------------------------
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Packet Addict")
    sub = parser.add_subparsers(dest="cmd")

    ifs = sub.add_parser("interfaces", help="list network interfaces")
    ifs.set_defaults(func=run_interfaces)

    sn = sub.add_parser("sniff", help="capture and analyze live traffic")
    sn.add_argument("-i", "--interface", help="interface, e.g. eth0 or wlan0")
    sn.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 80"')
    sn.add_argument("-c", "--count", type=int, default=0,
                    help="stop after N packets (default: keep going until Ctrl+C)")
    sn.add_argument("-w", "--write", help="save capture to a .pcap file")
    sn.set_defaults(func=run_sniff)

    sc = sub.add_parser("scan", help="TCP port scan with banner grabbing")
    sc.add_argument("target", help="IP or hostname")
    sc.add_argument("-p", "--ports", default="1-1024",
                    help='e.g. "80", "22,80,443", "1-1024"')
    sc.add_argument("-t", "--threads", type=int, default=100)
    sc.add_argument("--timeout", type=float, default=1.0)
    sc.set_defaults(func=run_scan)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
