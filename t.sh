#!/bin/bash

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash tor.sh"
  exit 1
fi

echo "Installing Tor + obfs4..."
apt update -qq >/dev/null 2>&1
apt install -y -qq tor torsocks curl obfs4proxy >/dev/null 2>&1

echo "Configuring Tor with bridge support..."

cat > /etc/tor/torrc <<'TORRC'
SocksPort 9050
RunAsDaemon 1
Log notice syslog

UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# ===== PASTE YOUR REAL BRIDGES BELOW =====
# Example format:
# Bridge obfs4 IP:PORT FINGERPRINT cert=XXXX iat-mode=0

TORRC

systemctl enable tor >/dev/null 2>&1
systemctl restart tor

echo "Waiting for Tor bootstrap..."
sleep 10

echo "Checking bootstrap status..."
journalctl -u tor -n 20 | grep Bootstrapped || true

echo ""
echo "Testing Tor connection..."

sleep 5

if torsocks curl -4 -s https://ipinfo.io/ip >/dev/null 2>&1; then
  echo "✔ Tor appears to be working"
  echo "Tor IP:"
  torsocks curl -4 -s https://ipinfo.io/ip
else
  echo "✘ Tor test failed"
  echo ""
  echo "If still failing:"
  echo "1) Get bridges from https://bridges.torproject.org/"
  echo "2) Add them inside /etc/tor/torrc"
  echo "3) Restart: systemctl restart tor"
fi

echo ""
echo "Done."
