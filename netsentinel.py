#!/usr/bin/env python3
"""
Termux NetSentinel — defensive live monitor for THIS device and YOUR LAN.

Does not perform ARP spoofing, MitM, deauth, exploitation, or third-party
packet interception. Heuristic alerts are not proof of compromise.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
HERE = Path(__file__).resolve().parent

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"

TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def color(s: str, c: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"{c}{s}{RESET}"


def run(cmd: list[str], timeout: int = 12) -> str:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (p.stdout or "") + (p.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open() as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def append_log(path: Path, line: str) -> None:
    try:
        with path.open("a") as f:
            f.write(line.rstrip() + "\n")
    except OSError:
        pass


def hex_ip_port(hexstr: str, ipv6: bool = False) -> tuple[str, int]:
    ip_hex, port_hex = hexstr.split(":")
    port = int(port_hex, 16)
    if ipv6:
        raw = bytes.fromhex(ip_hex)
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        addr = socket.inet_ntop(socket.AF_INET6, b"".join(words))
        return addr, port
    packed = bytes.fromhex(ip_hex)
    ip = socket.inet_ntoa(packed[::-1])
    return ip, port


def parse_proc_net(path: Path, ipv6: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text()
    except OSError:
        return rows
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            lip, lport = hex_ip_port(parts[1], ipv6)
            rip, rport = hex_ip_port(parts[2], ipv6)
            state = TCP_STATES.get(int(parts[3], 16), f"0x{parts[3]}")
        except (ValueError, OSError, socket.error):
            continue
        rows.append(
            {
                "local": lip,
                "lport": lport,
                "remote": rip,
                "rport": rport,
                "state": state,
                "ipv6": ipv6,
            }
        )
    return rows


def is_unspecified(ip: str) -> bool:
    return ip in ("0.0.0.0", "::", "::0") or ip.startswith(":::")


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1"


def is_private(ip: str) -> bool:
    if ":" in ip:
        return ip.startswith("fe80:") or ip.startswith("fc") or ip.startswith("fd")
    try:
        n = struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return False
    return (
        (n & 0xFF000000) == 0x0A000000
        or (n & 0xFFF00000) == 0xAC100000
        or (n & 0xFFFF0000) == 0xC0A80000
        or (n & 0xFFFF0000) == 0xA9FE0000
    )


def parse_ss() -> list[dict[str, Any]]:
    out = run(["ss", "-tuanH"])
    if not out.strip():
        out = run(["ss", "-tun"])
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        if parts[0] in ("Netid", "State"):
            continue
        if parts[0] in ("tcp", "udp", "u_str", "u_dgr"):
            proto, state, local, remote = parts[0], parts[1], parts[4], parts[5] if len(parts) > 5 else "*:*"
        else:
            continue

        def split_addr(a: str) -> tuple[str, int]:
            if a in ("*", "*:*"):
                return "0.0.0.0", 0
            if a.startswith("[") and "]:" in a:
                ip, p = a.rsplit("]:", 1)
                return ip.strip("[]"), int(p) if p.isdigit() else 0
            if a.count(":") == 1:
                ip, p = a.rsplit(":", 1)
                return ip, int(p) if p.isdigit() else 0
            return a, 0

        lip, lport = split_addr(local)
        rip, rport = split_addr(remote)
        rows.append(
            {
                "local": lip,
                "lport": lport,
                "remote": rip,
                "rport": rport,
                "state": state.upper(),
                "proto": proto,
            }
        )
    return rows


def parse_neighbors() -> list[dict[str, str]]:
    hosts: list[dict[str, str]] = []
    seen = set()
    out = run(["ip", "neigh", "show"])
    if not out.strip():
        out = run(["ip", "n"])
    for line in out.splitlines():
        m = re.search(
            r"([0-9a-fA-F:.]+)\s+dev\s+(\S+).*?lladdr\s+([0-9a-fA-F:]{11,17})\s+(\S+)?",
            line,
        )
        if not m:
            continue
        ip, dev, mac, state = m.group(1), m.group(2), m.group(3).lower(), (m.group(4) or "")
        key = (ip, mac)
        if key in seen:
            continue
        seen.add(key)
        hosts.append({"ip": ip, "mac": mac, "dev": dev, "state": state, "source": "neigh"})
    if not hosts:
        arp = run(["arp", "-a"])
        for line in arp.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if m:
                hosts.append(
                    {
                        "ip": m.group(1),
                        "mac": m.group(2).lower(),
                        "dev": "?",
                        "state": "",
                        "source": "arp",
                    }
                )
    return hosts


def local_addrs() -> dict[str, Any]:
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "ips": [],
        "ifaces": [],
        "gateway": "",
        "subnet": "",
        "ssid": "",
        "bssid": "",
    }
    ip_out = run(["ip", "-4", "addr", "show"])
    for block in re.split(r"\n(?=\d+:)", ip_out):
        name_m = re.search(r"^\d+:\s+([^:@]+)", block)
        ipv4_m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", block)
        if name_m and ipv4_m:
            name = name_m.group(1).strip()
            ip = ipv4_m.group(1)
            pfx = ipv4_m.group(2)
            if name == "lo":
                continue
            info["ifaces"].append({"name": name, "ip": ip, "prefix": pfx})
            info["ips"].append(ip)
            if not info["subnet"] and name.startswith(("wlan", "ap", "swlan", "rmnet", "eth")):
                info["subnet"] = f"{ip}/{pfx}"

    route = run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", route)
    if m:
        info["gateway"] = m.group(1)

    wifi = run(["termux-wifi-connectioninfo"], timeout=5)
    try:
        wj = json.loads(wifi) if wifi.strip().startswith("{") else {}
        info["ssid"] = wj.get("ssid") or ""
        info["bssid"] = (wj.get("bssid") or "").lower()
        if wj.get("ip"):
            info["ips"] = list({*info["ips"], wj["ip"]})
    except json.JSONDecodeError:
        pass
    return info


def iface_counters() -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    try:
        lines = Path("/proc/net/dev").read_text().splitlines()[2:]
    except OSError:
        return out
    for line in lines:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        cols = rest.split()
        if len(cols) < 16:
            continue
        out[name.strip()] = {
            "rx_bytes": int(cols[0]),
            "rx_pkts": int(cols[1]),
            "tx_bytes": int(cols[8]),
            "tx_pkts": int(cols[9]),
        }
    return out


def guess_subnet(info: dict[str, Any]) -> str:
    if info.get("subnet"):
        return info["subnet"]
    gw = info.get("gateway") or ""
    if re.match(r"\d+\.\d+\.\d+\.", gw):
        return ".".join(gw.split(".")[:3]) + ".0/24"
    for ip in info.get("ips") or []:
        if is_private(ip):
            return ".".join(ip.split(".")[:3]) + ".0/24"
    return ""


def nmap_ping(subnet: str) -> list[dict[str, str]]:
    if not subnet or not shutil.which("nmap"):
        return []
    out = run(["nmap", "-sn", "-T4", "--max-retries", "1", subnet], timeout=45)
    hosts = []
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            hosts.append({"ip": m.group(2), "mac": "", "dev": "lan", "state": "up", "source": "nmap"})
        m = re.search(r"MAC Address:\s+([0-9A-F:]+)", line, re.I)
        if m and hosts:
            hosts[-1]["mac"] = m.group(1).lower()
    return hosts


def merge_hosts(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    by_ip: dict[str, dict[str, str]] = {}
    for g in groups:
        for h in g:
            ip = h.get("ip") or ""
            if not ip or is_loopback(ip):
                continue
            cur = by_ip.get(ip, {"ip": ip, "mac": "", "dev": "", "state": "", "source": ""})
            if h.get("mac") and not cur["mac"]:
                cur["mac"] = h["mac"].lower()
            if h.get("dev") and not cur["dev"]:
                cur["dev"] = h["dev"]
            if h.get("state"):
                cur["state"] = h["state"]
            srcs = set(filter(None, (cur["source"], h.get("source"))))
            cur["source"] = "+".join(sorted(srcs))
            by_ip[ip] = cur
    return sorted(by_ip.values(), key=lambda x: x["ip"])


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024:
            return f"{f:.1f}{unit}"
        f /= 1024
    return f"{f:.1f}TB"


def pcap_summary(iface: str) -> str:
    if not shutil.which("tcpdump"):
        return "tcpdump not installed"
    out = run(
        ["tcpdump", "-i", iface, "-c", "20", "-nn", "-q", "-t"],
        timeout=8,
    )
    if not out.strip():
        return "no packets / permission denied (often needs root)"
    lines = [ln for ln in out.splitlines() if ln.strip()][-8:]
    return "\n".join(lines)


class Sentinel:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.config = load_json(HERE / "config.json", load_json(HERE / "config.example.json", {}))
        self.indicators = load_json(HERE / "data" / "indicators.json", {})
        self.trusted_path = Path(args.trusted or self.config.get("trusted_file") or "trusted.json")
        self.trusted = load_json(self.trusted_path, {"macs": {}, "ips": {}})
        self.log_path = Path(self.config.get("log_file") or "netsentinel.log")
        self.prev_counters: dict[str, dict[str, int]] = {}
        self.prev_time = time.time()
        self.seen_lan: set[str] = set()
        self.known_at_start: set[str] = set()
        self.remote_window: deque[tuple[float, str]] = deque()
        self.alerts: deque[str] = deque(maxlen=12)
        self.boot_ts = time.time()
        sus = self.indicators.get("suspicious_ports") or {}
        self.sus_ports = {int(k): v for k, v in sus.items() if str(k).isdigit()}
        extra = self.indicators.get("suspicious_remote_ports_only_if_untrusted") or []
        self.extra_ports = {int(p) for p in extra}

    def trust_name(self, ip: str, mac: str = "") -> str:
        macs = {k.lower(): v for k, v in (self.trusted.get("macs") or {}).items()}
        ips = self.trusted.get("ips") or {}
        if mac and mac.lower() in macs:
            return str(macs[mac.lower()])
        if ip in ips:
            return str(ips[ip])
        return ""

    def is_trusted(self, ip: str, mac: str = "") -> bool:
        return bool(self.trust_name(ip, mac))

    def alert(self, level: str, msg: str) -> None:
        line = f"[{now_iso()}] {level} {msg}"
        self.alerts.appendleft(line)
        append_log(self.log_path, line)

    def prune_window(self) -> None:
        window = float(self.config.get("window_seconds") or 60)
        cutoff = time.time() - window
        while self.remote_window and self.remote_window[0][0] < cutoff:
            self.remote_window.popleft()

    def check_connections(
        self, conns: list[dict[str, Any]], gateway: str, my_ips: set[str]
    ) -> list[str]:
        findings = []
        unique_remotes: set[str] = set()
        for c in conns:
            rip, rport = c["remote"], int(c["rport"] or 0)
            state = c.get("state") or ""
            if is_unspecified(rip) or is_loopback(rip) or rip in my_ips:
                continue
            if state in ("LISTEN", "CLOSE", "TIME_WAIT"):
                continue
            unique_remotes.add(f"{rip}:{rport}")
            if rport in self.sus_ports and self.args.ports:
                findings.append(
                    f"this-device → {rip}:{rport} ({self.sus_ports[rport]}) state={state}"
                )
            if (
                rport in self.extra_ports
                and not is_private(rip)
                and not self.is_trusted(rip)
                and self.args.ports
            ):
                findings.append(f"this-device → untrusted {rip}:{rport} (sensitive service port)")
            if is_private(rip) and rip != gateway and not self.is_trusted(rip) and state == "ESTABLISHED":
                findings.append(f"this-device session to unknown LAN host {rip}:{rport}")

        now = time.time()
        for r in unique_remotes:
            self.remote_window.append((now, r))
        self.prune_window()
        distinct = {x[1] for x in self.remote_window}
        limit = int(self.config.get("max_new_remotes_per_window") or 12)
        if len(distinct) >= limit and time.time() - self.boot_ts > 15:
            findings.append(
                f"burst: {len(distinct)} unique remote endpoints in last "
                f"{self.config.get('window_seconds', 60)}s"
            )
        return findings

    def check_lan(self, hosts: list[dict[str, str]], gateway: str, my_ips: set[str]) -> list[str]:
        findings = []
        for h in hosts:
            ip, mac = h["ip"], h.get("mac") or ""
            if ip in my_ips or ip == gateway:
                continue
            key = mac or ip
            if key not in self.seen_lan:
                self.seen_lan.add(key)
                if time.time() - self.boot_ts > 8 and not self.is_trusted(ip, mac):
                    label = mac or "no-mac"
                    findings.append(f"new LAN host {ip} ({label})")
        return findings

    def snapshot(self) -> dict[str, Any]:
        info = local_addrs()
        my_ips = set(info["ips"])
        gateway = info.get("gateway") or ""
        hosts = parse_neighbors()
        if self.args.scan_lan:
            subnet = guess_subnet(info)
            hosts = merge_hosts(hosts, nmap_ping(subnet))
        else:
            hosts = merge_hosts(hosts)

        conns = parse_proc_net(Path("/proc/net/tcp"), False)
        conns += parse_proc_net(Path("/proc/net/tcp6"), True)
        ss_rows = parse_ss()
        udp = [r for r in ss_rows if r.get("proto") == "udp"]
        established = [
            c
            for c in conns
            if c.get("state") == "ESTABLISHED" and not is_unspecified(c["remote"])
        ]

        counters = iface_counters()
        rates: dict[str, dict[str, float]] = {}
        dt = max(0.5, time.time() - self.prev_time)
        for name, cur in counters.items():
            prev = self.prev_counters.get(name)
            if prev:
                rates[name] = {
                    "rx_bps": max(0, cur["rx_bytes"] - prev["rx_bytes"]) / dt,
                    "tx_bps": max(0, cur["tx_bytes"] - prev["tx_bytes"]) / dt,
                }
        self.prev_counters = counters
        self.prev_time = time.time()

        findings = []
        if self.config.get("alert_on_suspicious_port", True):
            findings += self.check_connections(conns + udp, gateway, my_ips)
        if self.config.get("alert_on_new_lan_host", True):
            findings += self.check_lan(hosts, gateway, my_ips)

        seen_f = set()
        uniq = []
        for f in findings:
            if f not in seen_f:
                seen_f.add(f)
                uniq.append(f)
                self.alert("ALERT", f)

        pcap = ""
        if self.args.pcap:
            iface = ""
            for i in info["ifaces"]:
                if i["name"].startswith(("wlan", "ap", "swlan")):
                    iface = i["name"]
                    break
            if not iface and info["ifaces"]:
                iface = info["ifaces"][0]["name"]
            pcap = pcap_summary(iface) if iface else "no iface"

        return {
            "info": info,
            "hosts": hosts,
            "established": established[:40],
            "listen": [c for c in conns if c.get("state") == "LISTEN"][:20],
            "rates": rates,
            "findings": uniq,
            "pcap": pcap,
            "conn_count": len(established),
        }

    def seed_seen(self, snap: dict[str, Any]) -> None:
        my_ips = set(snap["info"]["ips"])
        gw = snap["info"].get("gateway") or ""
        for h in snap["hosts"]:
            if h["ip"] in my_ips or h["ip"] == gw:
                continue
            self.seen_lan.add(h.get("mac") or h["ip"])
            self.known_at_start.add(h["ip"])

    def render(self, snap: dict[str, Any]) -> str:
        info = snap["info"]
        lines = []
        lines.append(color(f"  NETSENTINEL {VERSION}", BOLD + CYN) + color("  defensive monitor", DIM))
        lines.append(color("  only this device + your LAN membership  •  not a packet tap on others", DIM))
        lines.append("")
        ssid = info.get("ssid") or "?"
        gw = info.get("gateway") or "?"
        ips = ", ".join(info.get("ips") or ["?"])
        lines.append(f"  {color('host', DIM)} {info.get('hostname')}   {color('ssid', DIM)} {ssid}")
        lines.append(f"  {color('ip', DIM)}   {ips}   {color('gw', DIM)} {gw}")
        if info.get("bssid"):
            lines.append(f"  {color('bssid', DIM)} {info['bssid']}")

        lines.append("")
        lines.append(color("  TRAFFIC (this phone)", BOLD))
        interesting = [
            (n, r)
            for n, r in snap["rates"].items()
            if not n.startswith(("lo", "dummy", "ifb"))
        ]
        if not interesting:
            lines.append(color("    waiting for second sample…", DIM))
        for name, r in interesting:
            lines.append(
                f"    {name:10}  rx {human_bytes(int(r['rx_bps']))}/s   tx {human_bytes(int(r['tx_bps']))}/s"
            )

        lines.append("")
        lines.append(color(f"  LAN HOSTS ({len(snap['hosts'])})", BOLD))
        if not snap["hosts"]:
            lines.append(color("    neighbor table empty — try --scan-lan on YOUR network", DIM))
        for h in snap["hosts"][:18]:
            name = self.trust_name(h["ip"], h.get("mac") or "")
            tag = color("trusted", GRN) if name else color("unknown", YEL)
            mac = h.get("mac") or " " * 17
            extra = f"  {name}" if name else ""
            lines.append(f"    {h['ip']:15}  {mac:17}  {tag}{extra}")
        if len(snap["hosts"]) > 18:
            lines.append(color(f"    … {len(snap['hosts']) - 18} more", DIM))

        lines.append("")
        lines.append(color(f"  THIS DEVICE SESSIONS ({snap['conn_count']} established)", BOLD))
        shown = 0
        for c in snap["established"]:
            if is_loopback(c["remote"]) or is_unspecified(c["remote"]):
                continue
            mark = ""
            if int(c["rport"]) in self.sus_ports:
                mark = color("  !", RED)
            dest = f"{c['remote']}:{c['rport']}"
            lines.append(f"    {c['local']}:{c['lport']}  →  {dest:24}  {c['state']}{mark}")
            shown += 1
            if shown >= 12:
                break
        if shown == 0:
            lines.append(color("    no established remote TCP right now", DIM))

        listen = snap["listen"]
        if listen:
            lines.append("")
            lines.append(color("  LISTENING ON THIS PHONE", BOLD))
            for c in listen[:8]:
                lines.append(f"    {c['local']}:{c['lport']}  {c['state']}")

        lines.append("")
        lines.append(color("  ALERTS", BOLD))
        if snap["findings"]:
            for f in snap["findings"]:
                lines.append(color(f"    ! {f}", RED))
        elif self.alerts:
            for a in list(self.alerts)[:6]:
                lines.append(color(f"    {a}", YEL))
        else:
            lines.append(color("    none this tick", GRN))

        if snap.get("pcap"):
            lines.append("")
            lines.append(color("  PCAP SUMMARY", BOLD))
            for ln in str(snap["pcap"]).splitlines():
                lines.append("    " + ln[:100])

        lines.append("")
        lines.append(
            color(
                f"  {now_iso()}   interval={self.args.interval}s   scan_lan={self.args.scan_lan}   Ctrl+C to stop",
                DIM,
            )
        )
        return "\n".join(lines)

    def loop(self) -> None:
        first = self.snapshot()
        self.seed_seen(first)
        if self.args.once:
            print(self.render(first))
            return
        try:
            while True:
                snap = self.snapshot()
                sys.stdout.write("\033[2J\033[H")
                print(self.render(snap))
                time.sleep(max(1, self.args.interval))
        except KeyboardInterrupt:
            print("\n" + color("[*] stopped", DIM))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Defensive Termux network monitor for your device and your LAN."
    )
    p.add_argument("--once", action="store_true", help="one snapshot and exit")
    p.add_argument("--scan-lan", action="store_true", help="nmap ping sweep of your /24")
    p.add_argument("--pcap", action="store_true", help="try a short tcpdump header sample")
    p.add_argument("--interval", type=int, default=4, help="refresh seconds")
    p.add_argument("--trusted", default="", help="path to trusted.json")
    p.add_argument("--no-ports", dest="ports", action="store_false", help="disable port heuristics")
    p.set_defaults(ports=True)
    return p


def main() -> int:
    args = build_parser().parse_args()
    s = Sentinel(args)
    if s.config.get("try_pcap"):
        args.pcap = True
    if not args.interval or args.interval == 4:
        args.interval = int(s.config.get("interval_seconds") or 4)
    s.loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
