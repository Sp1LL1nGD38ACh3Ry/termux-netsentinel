#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

echo "[*] Termux NetSentinel installer"
echo "[*] Defensive monitor only. Use on networks you own."

pkg update -y
pkg install -y python git nmap iproute2

# Best-effort extras. Do not fail the install if a package is missing.
for extra in termux-api tcpdump tshark net-tools; do
  pkg install -y "$extra" 2>/dev/null || echo "[!] skipped $extra"
done

python -m pip install --upgrade pip >/dev/null 2>&1 || true

mkdir -p "$HOME/.netsentinel"
if [ ! -f trusted.json ]; then
  cp data/trusted.example.json trusted.json
  echo "[*] wrote trusted.json — edit this after the first scan"
fi
if [ ! -f config.json ]; then
  cp config.example.json config.json
fi

chmod +x netsentinel.py 2>/dev/null || true

echo
echo "[+] Done. Run:"
echo "    python netsentinel.py"
echo "    python netsentinel.py --scan-lan"
echo
echo "[*] Tip: first run, then copy discovered devices into trusted.json"
