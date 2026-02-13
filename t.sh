#!/bin/bash

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash fix.sh"
  exit 1
fi

echo "Stopping Tor..."
systemctl stop tor 2>/dev/null || true
systemctl stop tor@default 2>/dev/null || true

echo "Removing broken Tor installation..."
apt purge -y tor torsocks obfs4proxy >/dev/null 2>&1
rm -rf /etc/tor
rm -rf /var/lib/tor

echo "Reinstalling Tor cleanly..."
apt update -qq >/dev/null 2>&1
apt install -y -qq tor torsocks curl >/dev/null 2>&1

echo "Verifying config..."
if tor -f /etc/tor/torrc --verify-config >/dev/null 2>&1; then
    echo "✔ Config valid"
else
    echo "✘ Config error"
    exit 1
fi

echo "Enabling correct service (tor@default)..."
systemctl enable tor@default >/dev/null 2>&1
systemctl restart tor@default

sleep 5

echo "Checking service status..."
systemctl --no-pager status tor@default

echo ""
echo "Testing Tor connection..."
sleep 5

if torsocks curl -4 -s https://ipinfo.io/ip >/dev/null 2>&1; then
    echo "✔ Tor working"
    echo "Tor IP:"
    torsocks curl -4 -s https://ipinfo.io/ip
else
    echo "✘ Tor still not connecting"
    echo "Likely VPS provider blocking Tor."
fi

echo ""
echo "Done."
