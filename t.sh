#!/bin/bash

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash tor.sh"
  exit 1
fi

echo "Installing Tor..."
apt update -qq >/dev/null 2>&1
apt install -y -qq tor torsocks curl >/dev/null 2>&1

echo "Configuring Tor..."

cat > /etc/tor/torrc <<'TORRC'
SocksPort 9050
Log notice syslog
RunAsDaemon 1
TORRC

systemctl enable tor >/dev/null 2>&1
systemctl restart tor

echo "Waiting for Tor bootstrap..."
sleep 5

BOOTSTRAP=$(journalctl -u tor -n 50 | grep "Bootstrapped 100%" || true)

if [ -n "$BOOTSTRAP" ]; then
  echo "✔ Tor fully bootstrapped"
else
  echo "⚠ Tor may still be connecting..."
fi

echo ""
echo "Testing Tor connection..."

sleep 3

if curl --socks5 127.0.0.1:9050 -s https://check.torproject.org | grep -q "Congratulations"; then
  echo "✔ Tor is working!"
  echo ""
  echo "Your Tor IP:"
  torsocks curl -4 -s https://ipinfo.io/ip
else
  echo "✘ Tor test failed"
fi

echo ""
echo "Usage:"
echo "torsocks curl https://ipinfo.io/ip"
echo ""
