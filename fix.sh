#!/usr/bin/env bash
#===============================================================================
# Fix script for hardening issues
#===============================================================================

set +e

echo "Fixing hardening script issues..."

#===============================================================================
# FIX 1: Tor Repository Issue
#===============================================================================
echo "[1/3] Fixing Tor repository..."

# Remove broken Tor repository
rm -f /etc/apt/sources.list.d/tor.list

# Add correct Tor repository
cat > /etc/apt/sources.list.d/tor.list << 'EOF'
deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bullseye main
deb-src [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bullseye main
EOF

# Import Tor GPG key properly
if [[ ! -f /usr/share/keyrings/tor-archive-keyring.gpg ]]; then
    echo "Importing Tor GPG key..."
    curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | \
        gpg --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg 2>/dev/null
fi

# Update apt
apt-get update 2>&1 | grep -v "does not have a Release file"

echo "✓ Tor repository fixed"

#===============================================================================
# FIX 2: Fail2ban sshd-ddos Filter Issue
#===============================================================================
echo "[2/3] Fixing Fail2ban configuration..."

# Create the missing sshd-ddos filter
cat > /etc/fail2ban/filter.d/sshd-ddos.conf << 'EOF'
# Fail2Ban filter for SSH DDOS attacks
[Definition]
failregex = ^.*sshd\[\d+\]: Did not receive identification string from <HOST>
            ^.*sshd\[\d+\]: Connection closed by <HOST> port \d+ \[preauth\]
            ^.*sshd\[\d+\]: Connection reset by <HOST> port \d+ \[preauth\]
ignoreregex =
EOF

# Fix jail.local to remove sshd-ddos or use correct configuration
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban duration (10 minutes default)
bantime = 600

# Time window for failures
findtime = 600

# Max failures before ban
maxretry = 5

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

# Backend for log monitoring
backend = systemd

# Ban action using UFW
banaction = ufw
banaction_allports = ufw

# Email alerts (disabled by default)
destemail = root@localhost
sender = fail2ban@localhost
action = %(action_)s

#---------------------------------------
# SSH Jail
#---------------------------------------
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

#---------------------------------------
# Recidive (repeat offenders)
#---------------------------------------
[recidive]
enabled = true
filter = recidive
banaction = ufw
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3
EOF

# Restart fail2ban
systemctl restart fail2ban 2>/dev/null || service fail2ban restart

echo "✓ Fail2ban configuration fixed"

#===============================================================================
# FIX 3: Fix UFW Logging Issue
#===============================================================================
echo "[3/3] Fixing UFW logging..."

# Set UFW logging to low to reduce noise
ufw logging low 2>/dev/null || true

echo "✓ UFW logging adjusted"

#===============================================================================
# VERIFY FIXES
#===============================================================================
echo ""
echo "Verifying fixes..."
echo ""

# Check Tor repository
if apt-cache policy tor >/dev/null 2>&1; then
    echo "✓ Tor repository: OK"
else
    echo "✗ Tor repository: Still has issues"
fi

# Check Fail2ban
if fail2ban-client status >/dev/null 2>&1; then
    echo "✓ Fail2ban: Running"
    fail2ban-client status sshd >/dev/null 2>&1 && echo "  ✓ SSH jail: Active"
else
    echo "✗ Fail2ban: Not running properly"
fi

# Check UFW
if ufw status | grep -q "active"; then
    echo "✓ UFW: Active"
else
    echo "✗ UFW: Not active"
fi

echo ""
echo "Fixes applied. Now you can run: lynis audit system"
echo ""

# Clean up apt cache
apt-get clean 2>/dev/null || true

exit 0
