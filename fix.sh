#!/usr/bin/env bash
#===============================================================================
# Fix script - Remove Tor and fix other issues
#===============================================================================

set +e

echo "Fixing system issues and removing Tor..."
echo ""

#===============================================================================
# REMOVE TOR COMPLETELY
#===============================================================================
echo "[1/4] Removing Tor and its components..."

# Stop Tor service if running
systemctl stop tor 2>/dev/null || service tor stop 2>/dev/null || true
systemctl disable tor 2>/dev/null || true

# Remove Tor packages
apt-get remove --purge -y tor tor-geoipdb torsocks deb.torproject.org-keyring 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

# Remove Tor repository
rm -f /etc/apt/sources.list.d/tor.list
rm -f /etc/apt/sources.list.d/tor.list.save
rm -f /usr/share/keyrings/tor-archive-keyring.gpg

# Remove Tor configuration and data
rm -rf /etc/tor
rm -rf /var/lib/tor
rm -rf /var/log/tor
rm -rf /run/tor

# Remove Tor user if exists
deluser --remove-home debian-tor 2>/dev/null || true
delgroup debian-tor 2>/dev/null || true

echo "✓ Tor completely removed"

#===============================================================================
# FIX FAIL2BAN
#===============================================================================
echo "[2/4] Fixing Fail2ban configuration..."

# Stop fail2ban first
systemctl stop fail2ban 2>/dev/null || true

# Create proper jail.local without sshd-ddos
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban duration (10 minutes default)
bantime = 600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend = systemd
banaction = ufw
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
systemctl restart fail2ban 2>/dev/null || service fail2ban restart 2>/dev/null

echo "✓ Fail2ban configuration fixed"

#===============================================================================
# UPDATE APT WITHOUT ERRORS
#===============================================================================
echo "[3/4] Updating package lists..."

# Clean apt cache first
apt-get clean 2>/dev/null || true

# Update without showing Tor repository errors
apt-get update 2>&1 | grep -v "does not have a Release file" | grep -v "torproject"

echo "✓ Package lists updated"

#===============================================================================
# OPTIMIZE UFW LOGGING
#===============================================================================
echo "[4/4] Optimizing UFW..."

# Set UFW logging to low to reduce log spam
ufw logging low 2>/dev/null || true

# Ensure UFW is enabled
ufw --force enable 2>/dev/null || true

echo "✓ UFW optimized"

#===============================================================================
# CLEAN UP SYSTEM
#===============================================================================
echo ""
echo "Performing system cleanup..."

# Remove orphaned packages
apt-get autoremove -y 2>/dev/null || true

# Clean package cache
apt-get autoclean -y 2>/dev/null || true
apt-get clean 2>/dev/null || true

# Clear systemd journal if too large
journalctl --vacuum-time=7d 2>/dev/null || true

echo "✓ System cleanup completed"

#===============================================================================
# VERIFICATION
#===============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Verification Results:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if Tor is removed
if ! command -v tor >/dev/null 2>&1; then
    echo "✓ Tor: Successfully removed"
else
    echo "✗ Tor: Still present"
fi

# Check Fail2ban
if systemctl is-active fail2ban >/dev/null 2>&1; then
    echo "✓ Fail2ban: Active"
    fail2ban-client status >/dev/null 2>&1 && {
        jails=$(fail2ban-client status | grep "Jail list" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | wc -l)
        echo "  └─ Active jails: $jails"
    }
else
    echo "✗ Fail2ban: Not running"
fi

# Check UFW
if ufw status | grep -q "Status: active"; then
    rules=$(ufw status numbered | grep "^\[" | wc -l)
    echo "✓ UFW: Active with $rules rules"
else
    echo "✗ UFW: Not active"
fi

# Check for apt errors
if apt-get update 2>&1 | grep -q "^E:"; then
    echo "✗ APT: Still has errors"
else
    echo "✓ APT: No errors"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✓ All fixes applied!"
echo ""
echo "You can now run: sudo lynis audit system"
echo ""

exit 0
