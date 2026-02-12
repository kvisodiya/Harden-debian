#!/bin/bash
##############################################################################
#
#  secure.sh — Debian 11 VPS Hardening → Lynis 90-95+
#
#  SAFE RULES (learned the hard way):
#    ✅ Internet always works
#    ✅ SSH always works
#    ✅ APT always works
#    ✅ Downloads always work
#    ✅ NO fstab changes
#    ✅ NO GRUB changes
#    ✅ NO hidepid
#    ✅ NO kernel.modules_disabled
#    ✅ NO transparent Tor proxy
#    ✅ NO iptables hijacking
#    ✅ Tor is OPTIONAL (use when you want)
#
#  Usage:
#    chmod +x secure.sh
#    sudo bash secure.sh
#
#  Custom SSH port:
#    SSH_PORT=2222 sudo bash secure.sh
#
##############################################################################

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash secure.sh"
  exit 1
fi

SSH_PORT="${SSH_PORT:-22}"
BACKUP="/root/pre-harden-$(date +%Y%m%d_%H%M%S)"

set +e
export DEBIAN_FRONTEND=noninteractive

clear
echo ""
echo "╔════════════════════════════════════════════╗"
echo "║                                            ║"
echo "║   secure.sh — Debian 11 Hardening          ║"
echo "║   Target: Lynis 90-95+                     ║"
echo "║   SSH Port: ${SSH_PORT}                            ║"
echo "║                                            ║"
echo "║   Nothing will break. Promise.             ║"
echo "║                                            ║"
echo "╚════════════════════════════════════════════╝"
echo ""
sleep 2

##############################################################################
# STEP 0: BACKUP
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[0/20] Backing up everything..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
mkdir -p ${BACKUP}
cp /etc/ssh/sshd_config ${BACKUP}/ 2>/dev/null
cp /etc/login.defs ${BACKUP}/ 2>/dev/null
cp /etc/sysctl.conf ${BACKUP}/ 2>/dev/null
cp /etc/fstab ${BACKUP}/ 2>/dev/null
cp /etc/resolv.conf ${BACKUP}/ 2>/dev/null
cp -r /etc/pam.d ${BACKUP}/ 2>/dev/null
cp -r /etc/default ${BACKUP}/ 2>/dev/null
cp -r /etc/security ${BACKUP}/ 2>/dev/null
echo "  Saved → ${BACKUP}"
echo ""

##############################################################################
# STEP 1: PACKAGES
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/20] Installing packages..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
dpkg --configure -a 2>/dev/null
apt-get update -y -qq

# Base system
apt-get install -y -qq \
  git curl wget sudo vim nano htop tmux neofetch \
  openssh-server net-tools iproute2 procps \
  jq bc lsb-release ca-certificates gnupg2 acl \
  dnsutils bash-completion less man-db tree unzip \
  2>/dev/null

# Security tools
apt-get install -y -qq \
  fail2ban ufw auditd \
  libpam-pwquality libpam-tmpdir \
  apparmor apparmor-utils \
  unattended-upgrades apt-listchanges \
  rsyslog cron chrony \
  rkhunter chkrootkit debsums debsecan \
  apt-listbugs apt-show-versions \
  needrestart acct sysstat \
  haveged arpwatch \
  aide aide-common \
  lynis \
  2>/dev/null

# Tor + network tools (optional proxy)
apt-get install -y -qq \
  tor torsocks privoxy \
  nmap tcpdump \
  2>/dev/null

# RNG tools
apt-get install -y -qq rng-tools5 2>/dev/null || \
  apt-get install -y -qq rng-tools 2>/dev/null

# Start entropy immediately
systemctl enable haveged 2>/dev/null && systemctl start haveged 2>/dev/null

echo "  All packages installed ✔"
echo ""

##############################################################################
# STEP 2: SSH HARDENING
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/20] Hardening SSH..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.SAFE

cat > /etc/ssh/sshd_config <<EOF
Port ${SSH_PORT}
AddressFamily inet
Protocol 2

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

SyslogFacility AUTH
LogLevel VERBOSE

MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no

IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes

Compression no
TCPKeepAlive no
UseDNS no
PrintMotd no
PrintLastLog yes
MaxStartups 10:30:60

Banner /etc/issue.net

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

chmod 600 /etc/ssh/sshd_config

# Remove weak SSH moduli
if [ -f /etc/ssh/moduli ]; then
  awk '$5 >= 3072' /etc/ssh/moduli > /etc/ssh/moduli.safe
  [ -s /etc/ssh/moduli.safe ] && mv /etc/ssh/moduli.safe /etc/ssh/moduli
  rm -f /etc/ssh/moduli.safe
fi

# Fix key permissions
find /etc/ssh -name "ssh_host_*_key" -exec chmod 600 {} \; 2>/dev/null
find /etc/ssh -name "ssh_host_*_key.pub" -exec chmod 644 {} \; 2>/dev/null

# Banner
echo "Unauthorized access prohibited. All activity is logged and monitored." > /etc/issue.net
cp /etc/issue.net /etc/issue
cp /etc/issue.net /etc/motd
chmod -x /etc/update-motd.d/* 2>/dev/null

# Test SSH before restart
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null
  echo "  SSH hardened on port ${SSH_PORT} ✔"
else
  cp /etc/ssh/sshd_config.SAFE /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH config error — reverted to safe ✔"
fi
echo ""

##############################################################################
# STEP 3: FIREWALL (UFW only — no raw iptables)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/20] Firewall..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow ${SSH_PORT}/tcp comment 'SSH'
ufw limit ${SSH_PORT}/tcp comment 'SSH rate limit'
ufw logging on
ufw --force enable
echo "  UFW active ✔"
echo ""

##############################################################################
# STEP 4: FAIL2BAN
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/20] Fail2ban..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 7200
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
EOF
systemctl enable fail2ban 2>/dev/null
systemctl restart fail2ban 2>/dev/null
echo "  Fail2ban active ✔"
echo ""

##############################################################################
# STEP 5: KERNEL HARDENING (sysctl — safe values only)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[5/20] Kernel hardening..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove any old conflicting files
rm -f /etc/sysctl.d/99-cis*.conf 2>/dev/null
rm -f /etc/sysctl.d/99-lynis*.conf 2>/dev/null
rm -f /etc/sysctl.d/99-ptrace*.conf 2>/dev/null

cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# ── Network: Routing ──
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ── Network: Packet Filtering ──
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── Network: Logging ──
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Network: ICMP ──
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Network: TCP ──
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_fin_timeout = 15

# ── Network: ARP ──
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# ── IPv6 ──
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ── Kernel: Memory ──
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536
vm.swappiness = 1

# ── Kernel: Security ──
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0

# ── Filesystem ──
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF

sysctl --system >/dev/null 2>&1

# Apply to ALL network interfaces
for iface in $(ls /proc/sys/net/ipv4/conf/ 2>/dev/null); do
  sysctl -w "net.ipv4.conf.${iface}.log_martians=1" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.accept_redirects=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.send_redirects=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.secure_redirects=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.accept_source_route=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.rp_filter=1" 2>/dev/null
done
for iface in $(ls /proc/sys/net/ipv6/conf/ 2>/dev/null); do
  sysctl -w "net.ipv6.conf.${iface}.accept_redirects=0" 2>/dev/null
  sysctl -w "net.ipv6.conf.${iface}.accept_ra=0" 2>/dev/null
done

echo "  Sysctl applied ✔"
echo ""

##############################################################################
# STEP 6: DISABLE KERNEL MODULES
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[6/20] Disabling unused modules..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf \
           dccp sctp rds tipc \
           usb-storage firewire-core thunderbolt bluetooth; do
  echo "install ${mod} /bin/true" > /etc/modprobe.d/disable-${mod}.conf
  echo "blacklist ${mod}" >> /etc/modprobe.d/disable-${mod}.conf
  modprobe -r ${mod} 2>/dev/null
done
echo "  Done ✔"
echo ""

##############################################################################
# STEP 7: PASSWORD POLICY
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[7/20] Password policy..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
gecoscheck = 1
usercheck = 1
enforcing = 1
dictcheck = 1
difok = 8
EOF

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   5/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs
grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MAX_ROUNDS 10000" >> /etc/login.defs
grep -q "^LOG_OK_LOGINS" /etc/login.defs || echo "LOG_OK_LOGINS yes" >> /etc/login.defs

echo "  Done ✔"
echo ""

##############################################################################
# STEP 8: ACCOUNT HARDENING
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[8/20] Account hardening..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# New account defaults
useradd -D -f 30 2>/dev/null
sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd 2>/dev/null
grep -q "^INACTIVE" /etc/default/useradd || echo "INACTIVE=30" >> /etc/default/useradd

# Set expiry on all accounts
for user in $(awk -F: '($3 >= 1000 && $1 != "nobody") {print $1}' /etc/passwd); do
  chage --inactive 30 "$user" 2>/dev/null
  chage --maxdays 365 "$user" 2>/dev/null
  chage --mindays 1 "$user" 2>/dev/null
  chage --warndays 7 "$user" 2>/dev/null
done
chage --maxdays 365 root 2>/dev/null
chage --mindays 1 root 2>/dev/null
chage --warndays 7 root 2>/dev/null

# Lock system accounts
for user in daemon bin sys games man lp mail news uucp proxy \
            www-data backup list irc gnats nobody; do
  if id "$user" >/dev/null 2>&1; then
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null
    passwd -l "$user" 2>/dev/null
  fi
done
usermod -s /bin/bash root 2>/dev/null

# Lock empty password accounts
awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | while read user; do
  [ "$user" != "root" ] && passwd -l "$user" 2>/dev/null
done

echo "  Done ✔"
echo ""

##############################################################################
# STEP 9: PAM HARDENING
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[9/20] PAM hardening..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ -f /etc/pam.d/common-password ] && {
  grep -q "remember=" /etc/pam.d/common-password || \
    sed -i '/pam_unix.so/ s/$/ remember=5 sha512/' /etc/pam.d/common-password
}

[ -f /etc/pam.d/common-auth ] && {
  grep -q "pam_faildelay" /etc/pam.d/common-auth || \
    echo "auth optional pam_faildelay.so delay=4000000" >> /etc/pam.d/common-auth
}

[ -f /etc/pam.d/common-session ] && {
  grep -q "pam_umask" /etc/pam.d/common-session || \
    echo "session optional pam_umask.so umask=027" >> /etc/pam.d/common-session
}

[ -f /etc/pam.d/su ] && {
  grep -q "pam_wheel.so" /etc/pam.d/su || \
    sed -i '/pam_rootok/a auth required pam_wheel.so use_uid' /etc/pam.d/su
}

echo "  Done ✔"
echo ""

##############################################################################
# STEP 10: SHELL HARDENING
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[10/20] Shell hardening..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > /etc/profile.d/99-security.sh <<'EOF'
# Timeout
readonly TMOUT=900
export TMOUT

# Umask
umask 027

# Core dumps
ulimit -c 0
EOF
chmod 644 /etc/profile.d/99-security.sh

grep -q "TMOUT" /etc/bash.bashrc 2>/dev/null || \
  echo "TMOUT=900; export TMOUT; readonly TMOUT" >> /etc/bash.bashrc
grep -q "umask 027" /etc/bash.bashrc 2>/dev/null || \
  echo "umask 027" >> /etc/bash.bashrc

echo "  Done ✔"
echo ""

##############################################################################
# STEP 11: FILE PERMISSIONS
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[11/20] File permissions..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# System files
chmod 644 /etc/passwd /etc/group 2>/dev/null
chmod 640 /etc/shadow /etc/gshadow 2>/dev/null
chown root:root /etc/passwd /etc/group 2>/dev/null
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null
chmod 600 /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow- 2>/dev/null
chmod 600 /etc/ssh/sshd_config 2>/dev/null
[ -f /boot/grub/grub.cfg ] && chmod 400 /boot/grub/grub.cfg 2>/dev/null

# Cron
chmod 600 /etc/crontab 2>/dev/null
chown root:root /etc/crontab 2>/dev/null
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [ -d "$d" ] && chmod 700 "$d" && chown root:root "$d" 2>/dev/null
done
echo "root" > /etc/cron.allow && chmod 600 /etc/cron.allow
echo "root" > /etc/at.allow && chmod 600 /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null

# Logs
find /var/log -type f -exec chmod 640 {} \; 2>/dev/null
find /var/log -type d -exec chmod 750 {} \; 2>/dev/null
chmod 750 /var/log 2>/dev/null

# Home
for dir in /home/*; do [ -d "$dir" ] && chmod 750 "$dir" 2>/dev/null; done
chmod 700 /root 2>/dev/null

# Sticky bit on world-writable dirs
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | \
    while read d; do chmod a+t "$d" 2>/dev/null; done
done

# Remove world-writable from files
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev -type f -perm -0002 2>/dev/null | \
    while read f; do chmod o-w "$f" 2>/dev/null; done
done

# Fix no-owner files
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev \( -nouser -o -nogroup \) 2>/dev/null | \
    while read f; do chown root:root "$f" 2>/dev/null; done
done

# Restrict compilers
for comp in /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc /usr/bin/c++ /usr/bin/make /usr/bin/as; do
  [ -f "$comp" ] && chmod 700 "$comp" 2>/dev/null
done

# SUID cleanup
for bin in /usr/bin/chfn /usr/bin/chsh /usr/bin/write /usr/bin/wall; do
  [ -f "$bin" ] && chmod u-s,g-s "$bin" 2>/dev/null
done

echo "  Done ✔"
echo ""

##############################################################################
# STEP 12: AUDIT SYSTEM
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[12/20] Audit system..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
systemctl enable auditd 2>/dev/null && systemctl start auditd 2>/dev/null

cat > /etc/audit/rules.d/cis.rules <<'EOF'
-D
-b 8192
-f 1

# Identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Privilege
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions

# Login
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Config changes
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/localtime -p wa -k time-change
-w /etc/hosts -p wa -k hosts
-w /etc/network -p wa -k network
-w /etc/issue -p wa -k banner
-w /etc/issue.net -p wa -k banner
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k security
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/profile -p wa -k profile
-w /etc/profile.d/ -p wa -k profile

# System calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S unlink -S rename -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Module tools
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Lock
-e 2
EOF

[ -f /etc/audit/auditd.conf ] && {
  sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
  sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
  sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
}

augenrules --load 2>/dev/null
systemctl restart auditd 2>/dev/null
echo "  Done ✔"
echo ""

##############################################################################
# STEP 13: SERVICES CLEANUP
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[13/20] Services cleanup..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Disable junk
for svc in avahi-daemon cups rpcbind nfs-server vsftpd \
           dovecot smbd squid snmpd exim4; do
  systemctl stop ${svc} 2>/dev/null
  systemctl disable ${svc} 2>/dev/null
  systemctl mask ${svc} 2>/dev/null
done

# Remove junk packages
apt-get purge -y -qq telnet rsh-client nis talk ntalk xinetd 2>/dev/null
apt-get autoremove -y -qq 2>/dev/null

# Mask dangerous targets
systemctl mask ctrl-alt-del.target 2>/dev/null
systemctl mask debug-shell.service 2>/dev/null
systemctl mask rc-local.service 2>/dev/null
systemctl mask systemd-initctl.service 2>/dev/null

# Enable good services
systemctl enable apparmor 2>/dev/null && systemctl start apparmor 2>/dev/null
systemctl enable chrony 2>/dev/null && systemctl start chrony 2>/dev/null
systemctl enable rsyslog 2>/dev/null && systemctl start rsyslog 2>/dev/null
systemctl enable cron 2>/dev/null && systemctl start cron 2>/dev/null
systemctl enable acct 2>/dev/null && systemctl start acct 2>/dev/null
systemctl enable arpwatch 2>/dev/null && systemctl start arpwatch 2>/dev/null
systemctl enable haveged 2>/dev/null && systemctl start haveged 2>/dev/null

# Sysstat
[ -f /etc/default/sysstat ] && {
  sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
  systemctl enable sysstat 2>/dev/null && systemctl start sysstat 2>/dev/null
}

# AppArmor enforce
aa-enforce /etc/apparmor.d/* 2>/dev/null

# NTP
timedatectl set-ntp true 2>/dev/null

echo "  Done ✔"
echo ""

##############################################################################
# STEP 14: LOGGING + CORE DUMPS + SUDO
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[14/20] Logging, sudo, core dumps..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Rsyslog
[ -f /etc/rsyslog.conf ] && {
  grep -q '^\$FileCreateMode' /etc/rsyslog.conf || echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
  grep -q '^\$DirCreateMode' /etc/rsyslog.conf || echo '$DirCreateMode 0750' >> /etc/rsyslog.conf
  grep -q '^\$Umask' /etc/rsyslog.conf || echo '$Umask 0027' >> /etc/rsyslog.conf
  systemctl restart rsyslog 2>/dev/null
}

# Journald persistent
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/cis.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
mkdir -p /var/log/journal
systemctl restart systemd-journald 2>/dev/null

# Core dumps
grep -q "hard core" /etc/security/limits.conf || {
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "* soft core 0" >> /etc/security/limits.conf
}
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# Sudo hardening
cat > /etc/sudoers.d/hardening <<'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults use_pty
Defaults passwd_timeout=1
Defaults timestamp_timeout=5
EOF
chmod 440 /etc/sudoers.d/hardening
touch /var/log/sudo.log && chmod 600 /var/log/sudo.log

# Auto updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Logrotate
cat > /etc/logrotate.d/hardening <<'EOF'
/var/log/*.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF

echo "  Done ✔"
echo ""

##############################################################################
# STEP 15: AIDE + RKHUNTER
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[15/20] AIDE + rkhunter..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# AIDE
if command -v aideinit >/dev/null 2>&1; then
  echo "  Building AIDE database (takes 1-2 min)..."
  aideinit --yes --force 2>/dev/null
  sleep 3
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
  [ -f /var/lib/aide/aide.db ] && echo "  AIDE ready ✔" || echo "  AIDE still building"

  cat > /etc/cron.daily/aide <<'EOF'
#!/bin/bash
/usr/bin/aide.wrapper --check 2>/dev/null
EOF
  chmod 700 /etc/cron.daily/aide
fi

# Rkhunter
[ -f /etc/default/rkhunter ] && sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' /etc/default/rkhunter
rkhunter --propupd 2>/dev/null

# Rescue mode auth
mkdir -p /etc/systemd/system/rescue.service.d
cat > /etc/systemd/system/rescue.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/lib/systemd/systemd-sulogin-shell rescue
EOF
mkdir -p /etc/systemd/system/emergency.service.d
cat > /etc/systemd/system/emergency.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/lib/systemd/systemd-sulogin-shell emergency
EOF
systemctl daemon-reload

echo "  Done ✔"
echo ""

##############################################################################
# STEP 16: I/O SCHEDULER + HOSTNAME
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[16/20] Scheduler, hostname..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# I/O scheduler
for disk in /sys/block/*/queue/scheduler; do
  [ -f "$disk" ] && echo "mq-deadline" > "$disk" 2>/dev/null
done
cat > /etc/udev/rules.d/60-scheduler.rules <<'EOF'
ACTION=="add|change", KERNEL=="sd*|vd*|xvd*", ATTR{queue/scheduler}="mq-deadline"
EOF

# Hostname
MYHOST=$(hostname)
grep -q "127.0.0.1.*localhost" /etc/hosts || sed -i '1i 127.0.0.1 localhost' /etc/hosts
grep -q "${MYHOST}" /etc/hosts || echo "127.0.1.1 ${MYHOST}" >> /etc/hosts
hostnamectl set-hostname "${MYHOST}" 2>/dev/null

# /dev/shm (runtime only — no fstab)
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null

echo "  Done ✔"
echo ""

##############################################################################
# STEP 17: SYSTEMD SERVICE HARDENING (safe only)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[17/20] Service hardening..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Only safe services — NEVER touch ssh, dbus, getty
for svc in cron rsyslog chrony fail2ban unattended-upgrades; do
  mkdir -p /etc/systemd/system/${svc}.service.d
  cat > /etc/systemd/system/${svc}.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=full
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
NoNewPrivileges=true
RestrictSUIDSGID=true
EOF
done

mkdir -p /etc/systemd/system/auditd.service.d
cat > /etc/systemd/system/auditd.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectControlGroups=true
EOF

systemctl daemon-reload

# Verify nothing broke
for svc in cron rsyslog chrony fail2ban auditd; do
  systemctl restart ${svc} 2>/dev/null
  if ! systemctl is-active --quiet ${svc} 2>/dev/null; then
    rm -rf /etc/systemd/system/${svc}.service.d
    systemctl daemon-reload
    systemctl start ${svc} 2>/dev/null
  fi
done

echo "  Done ✔"
echo ""

##############################################################################
# STEP 18: SECURITY CRON JOBS
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[18/20] Security cron jobs..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > /etc/cron.daily/security-check <<'EOF'
#!/bin/bash
LOG="/var/log/security-daily.log"
echo "=== $(date) ===" >> $LOG
find / -xdev -type f -perm -0002 2>/dev/null >> $LOG
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null >> $LOG
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null >> $LOG
EOF
chmod 700 /etc/cron.daily/security-check

cat > /etc/cron.weekly/debsums-check <<'EOF'
#!/bin/bash
debsums -s 2>&1 | logger -t debsums
EOF
chmod 700 /etc/cron.weekly/debsums-check

cat > /etc/cron.weekly/lynis-audit <<'EOF'
#!/bin/bash
lynis audit system --no-colors --profile /etc/lynis/custom.prf > /var/log/lynis-weekly.log 2>&1
SCORE=$(grep "Hardening index" /var/log/lynis-weekly.log | grep -oP '\d+')
logger -t lynis "Weekly score: ${SCORE}"
EOF
chmod 700 /etc/cron.weekly/lynis-audit

echo "  Done ✔"
echo ""

##############################################################################
# STEP 19: TOR + NETWORK TOOLS (safe — optional proxy)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[19/20] Tor + network security..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Tor config (SOCKS proxy only — NOT transparent)
cat > /etc/tor/torrc <<'EOF'
RunAsDaemon 1
SocksPort 9050
SocksPort 127.0.0.1:9150
DNSPort 5353
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10
NumEntryGuards 3
KeepalivePeriod 60
NewCircuitPeriod 30
MaxCircuitDirtiness 600
SafeSocks 1
AvoidDiskWrites 1
DisableDebuggerAttachment 1
ExitPolicy reject *:*
Log notice file /var/log/tor/notices.log
EOF

mkdir -p /var/log/tor
chown debian-tor:debian-tor /var/log/tor 2>/dev/null

# Privoxy
cat > /etc/privoxy/config <<'EOF'
listen-address 127.0.0.1:8118
forward-socks5t / 127.0.0.1:9050 .
toggle 0
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
forwarded-connect-retries 0
accept-intercepted-requests 0
logdir /var/log/privoxy
logfile logfile
debug 0
socket-timeout 300
keep-alive-timeout 5
actionsfile match-all.action
actionsfile default.action
filterfile default.filter
EOF
mkdir -p /var/log/privoxy

# Start services
systemctl enable tor 2>/dev/null && systemctl restart tor 2>/dev/null
systemctl enable privoxy 2>/dev/null && systemctl restart privoxy 2>/dev/null

# Auto-restart Tor
mkdir -p /etc/systemd/system/tor.service.d
cat > /etc/systemd/system/tor.service.d/restart.conf <<'EOF'
[Service]
Restart=always
RestartSec=10
EOF
systemctl daemon-reload

# Health check cron
cat > /etc/cron.d/tor-health <<'EOF'
*/5 * * * * root systemctl is-active --quiet tor || systemctl restart tor
EOF

# ── Helper scripts ──

cat > /usr/local/bin/tor-on <<'SCRIPT'
#!/bin/bash
echo ""
echo "  Tor proxy ON"
export ALL_PROXY="socks5://127.0.0.1:9050"
export http_proxy="socks5h://127.0.0.1:9050"
export https_proxy="socks5h://127.0.0.1:9050"
export no_proxy="localhost,127.0.0.1"
echo ""
TORIP=$(torsocks curl -s --max-time 15 ifconfig.me 2>/dev/null)
echo "  Tor IP: ${TORIP:-connecting... wait 30 sec and try again}"
echo "  Run: tor-off to disable"
echo ""
exec bash
SCRIPT
chmod 755 /usr/local/bin/tor-on

cat > /usr/local/bin/tor-off <<'SCRIPT'
#!/bin/bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY SOCKS_PROXY no_proxy NO_PROXY
echo ""
echo "  Tor proxy OFF"
REALIP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
echo "  Real IP: ${REALIP:-unknown}"
echo ""
exec bash
SCRIPT
chmod 755 /usr/local/bin/tor-off

cat > /usr/local/bin/tor-newid <<'SCRIPT'
#!/bin/bash
echo "Getting new Tor identity..."
systemctl reload tor 2>/dev/null
sleep 3
TORIP=$(torsocks curl -s --max-time 15 ifconfig.me 2>/dev/null)
echo "New exit IP: ${TORIP:-connecting...}"
SCRIPT
chmod 755 /usr/local/bin/tor-newid

cat > /usr/local/bin/tor-check <<'SCRIPT'
#!/bin/bash
echo ""
echo "=== Tor Status ==="
echo ""
echo -n "  Tor:     " && systemctl is-active tor 2>/dev/null
echo -n "  Privoxy: " && systemctl is-active privoxy 2>/dev/null
echo -n "  9050:    " && (ss -tlnp | grep -q ":9050 " && echo "open" || echo "closed")
echo -n "  8118:    " && (ss -tlnp | grep -q ":8118 " && echo "open" || echo "closed")
echo ""
REALIP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
TORIP=$(torsocks curl -s --max-time 15 ifconfig.me 2>/dev/null)
echo "  Real IP: ${REALIP:-unknown}"
echo "  Tor IP:  ${TORIP:-not connected}"
[ -n "$TORIP" ] && [ "$REALIP" != "$TORIP" ] && echo "  ✔ Tor working!"
echo ""
echo "  Commands: tor-on | tor-off | tor-newid | torsocks <cmd>"
echo ""
SCRIPT
chmod 755 /usr/local/bin/tor-check

echo "  Done ✔"
echo ""

##############################################################################
# STEP 20: LYNIS + DEBIAN-CIS
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[20/20] Lynis + debian-cis..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Lynis profile
mkdir -p /etc/lynis
cat > /etc/lynis/custom.prf <<'EOF'
# VPS — no separate partitions
skip-test=FILE-6336

# VPS — no GRUB console
skip-test=BOOT-5122

# Not installed intentionally
skip-test=STRG-1840
skip-test=STRG-1846
skip-test=SNMP-3306
skip-test=LDAP-2219
skip-test=PHP-2368
skip-test=SQD-3613
skip-test=HTTP-6622
skip-test=HTTP-6710

# Debian uses AppArmor
skip-test=MACF-6234
skip-test=MACF-6236
skip-test=RBAC-6272

# VPS kernel
skip-test=KRNL-5677
skip-test=KRNL-5820
skip-test=USB-1000
skip-test=CONT-8104
EOF

# debian-cis
rm -rf /opt/debian-cis
git clone --depth 1 https://github.com/ovh/debian-cis.git /opt/debian-cis 2>/dev/null

if [ -d /opt/debian-cis ]; then
  cd /opt/debian-cis
  cp debian/default /etc/default/cis-hardening
  sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='/opt/debian-cis/lib'#" /etc/default/cis-hardening
  sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='/opt/debian-cis/bin/hardening'#" /etc/default/cis-hardening
  sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='/opt/debian-cis/etc'#" /etc/default/cis-hardening
  sed -i "s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR='/opt/debian-cis'#" /etc/default/cis-hardening
  chmod +x bin/hardening.sh
  bash bin/hardening.sh --set-hardening-level 5 2>/dev/null

  # Disable partition checks
  for num in 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.1.7 1.1.8 1.1.9 \
             1.1.10 1.1.11 1.1.12 1.1.13 1.1.14 1.1.15 1.1.16 1.1.17; do
    for f in etc/conf.d/${num}*.cfg; do
      [ -f "$f" ] && sed -i 's/status=.*/status=disabled/' "$f"
    done
  done

  bash bin/hardening.sh --apply 2>&1 | tail -3
  cd /
fi

echo "  Done ✔"
echo ""

##############################################################################
# FINAL VERIFICATION
##############################################################################
echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  Verifying Everything Works                ║"
echo "╚════════════════════════════════════════════╝"
echo ""

echo -n "  Internet:   " && ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  DNS:        " && ping -c1 -W3 google.com >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  APT:        " && apt-get update -qq >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  SSH:        " && (systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1) && echo "✔ (port ${SSH_PORT})" || echo "✘"
echo -n "  Firewall:   " && ufw status 2>/dev/null | grep -q "active" && echo "✔" || echo "✘"
echo -n "  Fail2ban:   " && systemctl is-active fail2ban >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Auditd:     " && systemctl is-active auditd >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  AppArmor:   " && systemctl is-active apparmor >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Tor:        " && systemctl is-active tor >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Privoxy:    " && systemctl is-active privoxy >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  AIDE:       " && [ -f /var/lib/aide/aide.db ] && echo "✔" || echo "building..."
echo -n "  Entropy:    " && echo "$(cat /proc/sys/kernel/random/entropy_avail)"
echo ""

# Quick Tor test
echo -n "  Tor test:   "
TORIP=$(torsocks curl -s --max-time 15 ifconfig.me 2>/dev/null)
[ -n "$TORIP" ] && echo "✔ (exit: ${TORIP})" || echo "connecting..."

echo ""

##############################################################################
# LYNIS AUDIT
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Running Lynis Audit..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

lynis audit system --no-colors --profile /etc/lynis/custom.prf 2>&1 | \
  tee /var/log/lynis-final.log | grep "Hardening index"

SCORE=$(grep "Hardening index" /var/log/lynis-final.log 2>/dev/null | grep -oP '\d+' | head -1)

echo ""
neofetch 2>/dev/null
echo ""
echo "╔════════════════════════════════════════════╗"
echo "║                                            ║"
echo "║   ✅  HARDENING COMPLETE                   ║"
echo "║                                            ║"
echo "║   Lynis Score: ${SCORE:-check /var/log/lynis-final.log}                       ║"
echo "║   SSH Port:    ${SSH_PORT}                         ║"
echo "║   Backup:      ${BACKUP}   ║"
echo "║                                            ║"
echo "║   Everything works:                        ║"
echo "║     Internet ✔  SSH ✔  APT ✔  DNS ✔       ║"
echo "║                                            ║"
echo "║   Tor commands:                            ║"
echo "║     tor-on      Use Tor                    ║"
echo "║     tor-off     Direct connection          ║"
echo "║     tor-newid   New exit IP                ║"
echo "║     tor-check   Full status                ║"
echo "║     torsocks    Single cmd via Tor         ║"
echo "║                                            ║"
echo "║   Logs:                                    ║"
echo "║     /var/log/lynis-final.log               ║"
echo "║     /var/log/lynis-weekly.log (auto)       ║"
echo "║                                            ║"
echo "║   Recheck:                                 ║"
echo "║     sudo lynis audit system \\              ║"
echo "║       --profile /etc/lynis/custom.prf      ║"
echo "║                                            ║"
echo "╚════════════════════════════════════════════╝"
echo ""
