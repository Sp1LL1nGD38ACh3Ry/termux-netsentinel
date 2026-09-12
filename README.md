# Termux NetSentinel

Live network monitor for **Termux on Android**. Watches *your* phone's connections and *your* Wi-Fi LAN for new devices, odd ports, and simple threat patterns.

This is a **defensive** tool. It does not spoof ARP, intercept other people's packets, deauth clients, or exploit anything.

## What it can actually see

Android + Termux without root **cannot** sniff every packet on the Wi-Fi like a tap on the router.

| Source | Root needed? | What you get |
|---|---|---|
| This phone's TCP/UDP table (`/proc/net/tcp`, `ss`) | No | Live connections *from/to this device* |
| Neighbor / ARP table + optional `nmap -sn` | No | Who joined your LAN |
| Interface counters (`/proc/net/dev`) | No | Bytes in/out on this phone |
| `tcpdump` / `tshark` summaries | Often yes | Packet headers on interfaces you can open |

If you need whole-house packet inspection, put the phone in hotspot mode and monitor the hotspot interface, or run a tap on the actual router.

## Legal

Only use this on networks you own or have written permission to monitor. Scanning or capturing traffic on other people's networks can be illegal.

## Install (Termux from F-Droid)

```bash
pkg update && pkg upgrade -y
pkg install python git nmap termux-api -y
# optional extras
pkg install tcpdump tshark iproute2 net-tools -y

git clone https://github.com/Sp1LL1nGD38ACh3Ry/termux-netsentinel.git
cd termux-netsentinel
chmod +x install.sh
./install.sh
```

Or one shot after clone:

```bash
python netsentinel.py
```

Grant Termux:API location/Wi-Fi permissions if you want SSID and BSSID in the dashboard.

## Usage

```bash
python netsentinel.py                  # live dashboard
python netsentinel.py --once           # single snapshot then exit
python netsentinel.py --scan-lan       # include nmap ping sweep (noisier)
python netsentinel.py --interval 3     # refresh every 3 seconds
python netsentinel.py --trusted trusted.json
python netsentinel.py --pcap           # try tcpdump header summary if available
```

Copy devices you know into `trusted.json` after the first scan.

Alerts go to the screen and to `netsentinel.log`.

## What gets flagged

- New MAC / IP on the LAN that is not in `trusted.json`
- This device opening connections to commonly abused remote-access ports
- Burst of new unique remote IPs in a short window
- Private-LAN destination that is not the gateway and not trusted

These are **heuristics**, not proof someone is hacking you. A Chromecast, a guest phone, or a game server can look "new" or "odd".

## Files

- `netsentinel.py` — monitor
- `install.sh` — Termux packages + first trusted snapshot
- `config.example.json` — knobs
- `data/indicators.json` — small defensive indicator list

## Limitations

- Encrypted traffic (HTTPS, DoH, most apps) is opaque. You see IPs and ports, not contents.
- Carrier / VPN tunnels hide the real destination behind one hop.
- Nmap sweeps are visible to a watching IDS. Use `--scan-lan` only on your network.
- Battery drain is real if you leave it running with a short interval.
