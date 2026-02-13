#!/usr/bin/env bash
#===============================================================================
#
#          FILE: debian11-hardening.sh
#
#         USAGE: sudo bash debian11-hardening.sh
#
#   DESCRIPTION: Production-ready Debian 11 VPS hardening script
#                Target: ~92-93+ Lynis score
#                Safe for common VPS providers
#
#       VERSION: 1.0.0
#        AUTHOR: Security Hardening Script
#       CREATED: 2024
#
#===============================================================================

# NO STRICT MODE - Handle errors gracefully and continue
set +e
set +u

#===============================================================================
# GLOBAL VARIABLES
#===============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_START_TIME=$(date +%s)
readonly LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/root/hardening_backups_$(date +%Y%m%d_%H%M%S)"
readonly REPORT_FILE="/root/hardening_report_$(date +%Y%m%d_%H%M%S).txt"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# Counters for summary
TASKS_COMPLETED=0
TASKS_SKIPPED=0
TASKS_FAILED=0
WARNINGS_COUNT=0

#===============================================================================
# LOGGING FUNCTIONS
#===============================================================================
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
    exec 3>&1 4>&2
    echo "=== Hardening Script Started: $(date) ===" >> "$LOG_FILE"
}

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
}

print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            log "INFO" "$message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[✓]${NC} $message"
            log "SUCCESS" "$message"
            ((TASKS_COMPLETED++))
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            log "WARNING" "$message"
            ((WARNINGS_COUNT++))
            ;;
        "ERROR")
            echo -e "${RED}[✗]${NC} $message"
            log "ERROR" "$message"
            ((TASKS_FAILED++))
            ;;
        "SKIP")
            echo -e "${MAGENTA}[→]${NC} $message"
            log "SKIP" "$message"
            ((TASKS_SKIPPED++))
            ;;
    esac
}

print_section() {
    local title="$1"
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $title${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "SECTION" "=== $title ==="
}

print_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
    ____       __    _                __ __          __           _           
   / __ \___  / /_  (_)___ _____     / // /___ _____/ /__  ____  (_)___  ____ _
  / / / / _ \/ __ \/ / __ `/ __ \   / // // __ `/ __  / _ \/ __ \/ / __ \/ __ `/
 / /_/ /  __/ /_/ / / /_/ / / / /  / // // /_/ / /_/ /  __/ / / / / / / / /_/ / 
/_____/\___/_.___/_/\__,_/_/ /_/  /_//_/ \__,_/\__,_/\___/_/ /_/_/_/ /_/\__, /  
                                                                       /____/   
EOF
    echo -e "${NC}"
    echo -e "${BOLD}    Debian 11 VPS Security Hardening Script v${SCRIPT_VERSION}${NC}"
    echo -e "${BOLD}    Target: 92-93+ Lynis Score | Production Ready${NC}"
    echo ""
}

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================
safe_exec() {
    local cmd="$1"
    local description="${2:-Executing command}"
    local critical="${3:-false}"
    
    print_status "INFO" "$description"
    
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "$description completed"
        return 0
    else
        local exit_code=$?
        if [[ "$critical" == "true" ]]; then
            print_status "ERROR" "$description failed (exit code: $exit_code)"
        else
            print_status "WARNING" "$description had issues (continuing)"
        fi
        return $exit_code
    fi
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_service_exists() {
    systemctl list-unit-files "$1.service" >/dev/null 2>&1 || \
    systemctl list-units --type=service | grep -q "$1"
}

get_ssh_service_name() {
    if systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
        echo "sshd"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "ssh.service"; then
        echo "ssh"
    elif check_service_exists "sshd"; then
        echo "sshd"
    else
        echo "ssh"
    fi
}

wait_for_apt() {
    local timeout=120
    local count=0
    
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [[ $count -ge $timeout ]]; then
            print_status "WARNING" "Timeout waiting for apt locks"
            return 1
        fi
        sleep 2
        ((count+=2))
    done
    return 0
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "${BACKUP_DIR}/$(basename "$file").backup" 2>/dev/null
        return $?
    fi
    return 0
}

test_dns_resolution() {
    local servers=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    
    for server in "${servers[@]}"; do
        if dig @"$server" +short +time=3 +tries=1 google.com A >/dev/null 2>&1; then
            return 0
        fi
    done
    
    # Try system resolver
    if getent hosts google.com >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        echo "Please run: sudo bash $0"
        exit 1
    fi
}

check_debian_version() {
    if [[ ! -f /etc/debian_version ]]; then
        print_status "WARNING" "Not running on Debian - script may not work correctly"
        return 1
    fi
    
    local version
    version=$(cat /etc/debian_version 2>/dev/null)
    print_status "INFO" "Detected Debian version: $version"
    
    if [[ "$version" == 11* ]] || [[ "$version" == "bullseye"* ]]; then
        print_status "SUCCESS" "Debian 11 (Bullseye) confirmed"
        return 0
    else
        print_status "WARNING" "Script optimized for Debian 11 - may work on other versions"
        return 0
    fi
}

check_network_connectivity() {
    print_status "INFO" "Checking network connectivity..."
    
    if ! test_dns_resolution; then
        print_status "ERROR" "No DNS resolution available"
        print_status "INFO" "Attempting to fix DNS temporarily..."
        
        # Temporary DNS fix
        if [[ -w /etc/resolv.conf ]] || [[ ! -e /etc/resolv.conf ]]; then
            echo "nameserver 1.1.1.1" > /etc/resolv.conf.tmp
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf.tmp
            cat /etc/resolv.conf >> /etc/resolv.conf.tmp 2>/dev/null
            cat /etc/resolv.conf.tmp > /etc/resolv.conf 2>/dev/null
            rm -f /etc/resolv.conf.tmp
        fi
        
        if ! test_dns_resolution; then
            print_status "ERROR" "Cannot establish DNS resolution - script may fail"
        fi
    fi
    
    # Test HTTP connectivity
    if curl -s --connect-timeout 5 https://deb.debian.org >/dev/null 2>&1; then
        print_status "SUCCESS" "Network connectivity verified"
        return 0
    elif wget -q --timeout=5 --spider https://deb.debian.org 2>/dev/null; then
        print_status "SUCCESS" "Network connectivity verified"
        return 0
    else
        print_status "WARNING" "Limited network connectivity detected"
        return 1
    fi
}

create_backups() {
    print_section "Creating System Backups"
    
    mkdir -p "$BACKUP_DIR"
    
    local critical_files=(
        "/etc/ssh/sshd_config"
        "/etc/sysctl.conf"
        "/etc/resolv.conf"
        "/etc/fstab"
        "/etc/default/grub"
        "/etc/security/limits.conf"
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/sshd"
        "/etc/login.defs"
        "/etc/hosts"
        "/etc/hostname"
    )
    
    local backed_up=0
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            if backup_file "$file"; then
                ((backed_up++))
            fi
        fi
    done
    
    # Backup current iptables rules
    if check_command iptables; then
        iptables-save > "${BACKUP_DIR}/iptables.rules" 2>/dev/null || true
    fi
    
    # Backup current UFW rules if exists
    if [[ -d /etc/ufw ]]; then
        cp -r /etc/ufw "${BACKUP_DIR}/ufw_backup" 2>/dev/null || true
    fi
    
    print_status "SUCCESS" "Backed up $backed_up critical files to $BACKUP_DIR"
}

#===============================================================================
# SYSTEM UPDATES
#===============================================================================
perform_system_updates() {
    print_section "System Updates and Upgrades"
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    
    # Wait for any existing apt processes
    wait_for_apt
    
    # Fix any interrupted dpkg operations
    print_status "INFO" "Checking for interrupted package operations..."
    dpkg --configure -a >> "$LOG_FILE" 2>&1 || true
    
    # Clean apt cache
    apt-get clean >> "$LOG_FILE" 2>&1 || true
    
    # Update package lists
    print_status "INFO" "Updating package lists..."
    if apt-get update -y >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Package lists updated"
    else
        print_status "WARNING" "Package list update had issues"
    fi
    
    # Upgrade packages with safe options
    print_status "INFO" "Upgrading packages (this may take a while)..."
    apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        >> "$LOG_FILE" 2>&1 || print_status "WARNING" "Some packages may not have upgraded"
    
    # Distribution upgrade for security patches
    apt-get dist-upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        >> "$LOG_FILE" 2>&1 || print_status "WARNING" "Dist-upgrade had issues"
    
    # Clean up
    apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
    apt-get autoclean >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "System updates completed"
}

#===============================================================================
# INSTALL PACKAGES
#===============================================================================
install_security_packages() {
    print_section "Installing Security Packages"
    
    export DEBIAN_FRONTEND=noninteractive
    
    wait_for_apt
    
    # Core security packages
    local core_packages=(
        "ufw"
        "fail2ban"
        "unattended-upgrades"
        "apt-listchanges"
        "needrestart"
        "libpam-tmpdir"
        "debsums"
        "apt-show-versions"
    )
    
    # Intrusion detection packages
    local ids_packages=(
        "aide"
        "aide-common"
        "rkhunter"
        "chkrootkit"
        "lynis"
    )
    
    # Audit packages
    local audit_packages=(
        "auditd"
        "audispd-plugins"
    )
    
    # AppArmor packages
    local apparmor_packages=(
        "apparmor"
        "apparmor-utils"
        "apparmor-profiles"
        "apparmor-profiles-extra"
    )
    
    # Network packages
    local network_packages=(
        "unbound"
        "dns-root-data"
        "curl"
        "wget"
        "gnupg"
        "ca-certificates"
        "apt-transport-https"
        "net-tools"
        "lsof"
    )
    
    # Password quality
    local pam_packages=(
        "libpam-pwquality"
    )
    
    # Utility packages
    local utility_packages=(
        "acl"
        "sudo"
        "psmisc"
        "procps"
        "sysstat"
        "rsyslog"
        "logrotate"
    )
    
    # Install packages in groups
    print_status "INFO" "Installing core security packages..."
    for pkg in "${core_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "INFO" "Installing intrusion detection packages..."
    for pkg in "${ids_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "INFO" "Installing audit packages..."
    for pkg in "${audit_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "INFO" "Installing AppArmor packages..."
    for pkg in "${apparmor_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "INFO" "Installing network packages..."
    for pkg in "${network_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "INFO" "Installing PAM packages..."
    for pkg in "${pam_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "INFO" "Installing utility packages..."
    for pkg in "${utility_packages[@]}"; do
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "Could not install: $pkg"
    done
    
    print_status "SUCCESS" "Security packages installation completed"
}

#===============================================================================
# UNATTENDED UPGRADES
#===============================================================================
configure_unattended_upgrades() {
    print_section "Configuring Automatic Security Updates"
    
    if ! check_command unattended-upgrade; then
        print_status "SKIP" "unattended-upgrades not installed"
        return 1
    fi
    
    # Main unattended-upgrades configuration
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UPGRADES_EOF'
// Automatic security updates configuration

Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};

// Packages to never update automatically
Unattended-Upgrade::Package-Blacklist {
    // "linux-";
    // "libc6";
};

// Split upgrade process for minimal downtime
Unattended-Upgrade::MinimalSteps "true";

// Send email notifications (if mail is configured)
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "only-on-error";

// Automatically remove unused kernel packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Automatically remove unused dependencies
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Do NOT automatically reboot (VPS safety)
Unattended-Upgrade::Automatic-Reboot "false";

// Enable logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Verbose logging
Unattended-Upgrade::Verbose "false";

// Debug mode
Unattended-Upgrade::Debug "false";

// Fix interrupted dpkg automatically
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
UPGRADES_EOF

    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTO_EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
AUTO_EOF

    # Enable the service
    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1 || true
    systemctl start unattended-upgrades >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "Automatic security updates configured"
}

#===============================================================================
# KERNEL SYSCTL HARDENING
#===============================================================================
configure_sysctl_hardening() {
    print_section "Kernel Security Hardening (sysctl)"
    
    # Create hardening sysctl configuration
    cat > /etc/sysctl.d/99-security-hardening.conf << 'SYSCTL_EOF'
#===============================================================================
# VPS-Safe Kernel Security Hardening
# Compatible with common cloud providers
#===============================================================================

#---------------------------------------
# Network Security
#---------------------------------------

# Disable IP forwarding (this is not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirects (prevents MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Log martian packets (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast requests (Smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (source validation)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Enable TCP SYN Cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Reduce TCP FIN timeout
net.ipv4.tcp_fin_timeout = 15

# Reduce TCP keepalive time
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

#---------------------------------------
# Memory/Process Security
#---------------------------------------

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict access to dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict ptrace scope (prevents process tracing)
kernel.yama.ptrace_scope = 1

# Disable SysRq key (except safe functions: sync, remount, reboot)
kernel.sysrq = 176

# Disable core dumps for setuid programs
fs.suid_dumpable = 0

# Protect hardlinks and symlinks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# Protect FIFOs and regular files in world-writable directories
fs.protected_fifos = 2
fs.protected_regular = 2

#---------------------------------------
# Performance (VPS-safe values)
#---------------------------------------

# File handle limits
fs.file-max = 65535

# PID limit
kernel.pid_max = 65536

# Socket backlog
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000

# TCP memory tuning (safe defaults)
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_wmem = 4096 87380 6291456

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Enable TCP timestamps (needed for performance)
net.ipv4.tcp_timestamps = 1

# Increase local port range
net.ipv4.ip_local_port_range = 1024 65535
SYSCTL_EOF

    # Apply sysctl settings safely
    print_status "INFO" "Applying kernel security parameters..."
    
    local failed_params=0
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # Extract parameter name
        param_name=$(echo "$line" | cut -d'=' -f1 | tr -d ' ')
        
        if [[ -n "$param_name" ]]; then
            if ! sysctl -w "$line" >> "$LOG_FILE" 2>&1; then
                ((failed_params++))
            fi
        fi
    done < /etc/sysctl.d/99-security-hardening.conf
    
    # Also run sysctl --system to apply all
    sysctl --system >> "$LOG_FILE" 2>&1 || true
    
    if [[ $failed_params -gt 0 ]]; then
        print_status "WARNING" "$failed_params sysctl parameters could not be applied (VPS restrictions)"
    fi
    
    print_status "SUCCESS" "Kernel security hardening applied"
}

#===============================================================================
# SECURE SHARED MEMORY
#===============================================================================
secure_shared_memory() {
    print_section "Securing Shared Memory"
    
    # Check if /run/shm or /dev/shm is in use
    local shm_path=""
    if mountpoint -q /run/shm 2>/dev/null; then
        shm_path="/run/shm"
    elif mountpoint -q /dev/shm 2>/dev/null; then
        shm_path="/dev/shm"
    fi
    
    if [[ -n "$shm_path" ]]; then
        # Check if already secured in fstab
        if ! grep -q "$shm_path.*noexec" /etc/fstab 2>/dev/null; then
            # Remount with security options
            if mount -o remount,noexec,nosuid,nodev "$shm_path" >> "$LOG_FILE" 2>&1; then
                print_status "SUCCESS" "Shared memory ($shm_path) remounted with security options"
            else
                print_status "WARNING" "Could not remount $shm_path (may be VPS restriction)"
            fi
        else
            print_status "INFO" "Shared memory already secured in fstab"
        fi
    else
        print_status "INFO" "Shared memory mount point not found"
    fi
}

#===============================================================================
# DISABLE CORE DUMPS
#===============================================================================
disable_core_dumps() {
    print_section "Disabling Core Dumps"
    
    # Create limits configuration
    mkdir -p /etc/security/limits.d
    cat > /etc/security/limits.d/99-disable-coredump.conf << 'LIMITS_EOF'
# Disable core dumps for security
*               soft    core            0
*               hard    core            0
root            soft    core            0
root            hard    core            0
LIMITS_EOF

    # Configure systemd coredump
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/disable.conf << 'COREDUMP_EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP_EOF

    # Reload systemd
    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "Core dumps disabled"
}

#===============================================================================
# SSH HARDENING
#===============================================================================
configure_ssh_hardening() {
    print_section "SSH Security Hardening"
    
    local sshd_config="/etc/ssh/sshd_config"
    local ssh_service
    ssh_service=$(get_ssh_service_name)
    
    # Verify SSH is installed
    if [[ ! -f "$sshd_config" ]]; then
        print_status "ERROR" "SSH configuration not found"
        return 1
    fi
    
    # Backup existing configuration
    backup_file "$sshd_config"
    
    # Create drop-in directory for SSH configuration
    mkdir -p /etc/ssh/sshd_config.d
    
    # Create hardening configuration
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'SSH_EOF'
# SSH Hardening Configuration
# Applied by security hardening script

#---------------------------------------
# Protocol and Authentication
#---------------------------------------
Protocol 2

# Limit authentication attempts
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30

# Root login with key only (secure default)
PermitRootLogin prohibit-password

# Enable password authentication (can be disabled if keys are set up)
PasswordAuthentication yes
PermitEmptyPasswords no

# Enable public key authentication
PubkeyAuthentication yes

#---------------------------------------
# Disable Dangerous Features
#---------------------------------------
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

#---------------------------------------
# Strong Cryptography
#---------------------------------------
# Key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# Ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Message authentication codes
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Host key algorithms
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

#---------------------------------------
# Connection Settings
#---------------------------------------
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

#---------------------------------------
# Logging
#---------------------------------------
LogLevel VERBOSE
SyslogFacility AUTH

#---------------------------------------
# Additional Security
#---------------------------------------
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
Compression delayed

# Display warning banner
Banner /etc/issue.net
SSH_EOF

    # Ensure Include directive is in main config
    if ! grep -q "^Include /etc/ssh/sshd_config.d/" "$sshd_config" 2>/dev/null; then
        # Add at the beginning of the file
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$sshd_config" 2>/dev/null || \
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_config"
    fi
    
    # Create security banner
    cat > /etc/issue.net << 'BANNER_EOF'
**************************************************************************
*                          AUTHORIZED ACCESS ONLY                        *
**************************************************************************
* This system is for authorized users only. All connections are logged  *
* and monitored. Unauthorized access attempts will be reported to the   *
* appropriate authorities.                                               *
**************************************************************************
BANNER_EOF

    # Test SSH configuration before applying
    print_status "INFO" "Validating SSH configuration..."
    
    if sshd -t >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "SSH configuration is valid"
        
        # Restart SSH service
        print_status "INFO" "Restarting SSH service..."
        
        if systemctl restart "$ssh_service" >> "$LOG_FILE" 2>&1; then
            print_status "SUCCESS" "SSH service restarted successfully"
        else
            # Try alternative restart method
            if service "$ssh_service" restart >> "$LOG_FILE" 2>&1; then
                print_status "SUCCESS" "SSH service restarted (via service command)"
            else
                print_status "WARNING" "Could not restart SSH - may need manual restart"
            fi
        fi
    else
        print_status "ERROR" "SSH configuration validation failed!"
        print_status "INFO" "Removing hardening config to prevent lockout"
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        return 1
    fi
    
    print_status "SUCCESS" "SSH hardening completed"
}

#===============================================================================
# UNBOUND DNS RESOLVER
#===============================================================================
configure_unbound_dns() {
    print_section "Configuring Unbound Local DNS Resolver"
    
    if ! check_command unbound; then
        print_status "SKIP" "Unbound not installed"
        return 1
    fi
    
    # Stop unbound for configuration
    systemctl stop unbound >> "$LOG_FILE" 2>&1 || true
    
    # Backup existing config
    backup_file /etc/unbound/unbound.conf
    
    # Create configuration directory
    mkdir -p /etc/unbound/unbound.conf.d
    
    # Create main Unbound configuration
    cat > /etc/unbound/unbound.conf.d/local-dns.conf << 'UNBOUND_EOF'
# Unbound Local DNS Resolver with DNSSEC
# Security-focused configuration

server:
    # Listen only on localhost
    interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    
    # Access control - localhost only
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    
    # Performance tuning
    num-threads: 2
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    
    # Cache sizes
    rrset-cache-size: 64m
    msg-cache-size: 32m
    key-cache-size: 16m
    neg-cache-size: 4m
    
    # Cache timing
    cache-min-ttl: 300
    cache-max-ttl: 86400
    
    # Privacy settings
    hide-identity: yes
    hide-version: yes
    identity: "DNS"
    version: "1.0"
    
    # DNSSEC validation
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    
    # Security hardening
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-below-nxdomain: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    
    # Privacy - query name minimization
    qname-minimisation: yes
    qname-minimisation-strict: no
    aggressive-nsec: yes
    
    # Performance - prefetching
    prefetch: yes
    prefetch-key: yes
    
    # Serve stale data if upstream fails
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-ttl-reset: yes
    
    # Root hints
    root-hints: "/usr/share/dns/root.hints"
    
    # Logging (minimal for privacy)
    verbosity: 0
    log-queries: no
    log-replies: no
    log-tag-queryreply: no
    log-local-actions: no
    log-servfail: yes
    
    # Minimize responses
    minimal-responses: yes
    
    # Additional security
    unwanted-reply-threshold: 10000
    do-not-query-localhost: no
    val-log-level: 1

# Forward queries to privacy-respecting DNS over TLS
forward-zone:
    name: "."
    forward-tls-upstream: yes
    # Cloudflare DNS
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    # Quad9 DNS
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
UNBOUND_EOF

    # Ensure root hints file exists
    if [[ ! -f /usr/share/dns/root.hints ]]; then
        mkdir -p /usr/share/dns
        # Download root hints
        if curl -s -o /usr/share/dns/root.hints https://www.internic.net/domain/named.root >> "$LOG_FILE" 2>&1; then
            print_status "SUCCESS" "Downloaded DNS root hints"
        else
            print_status "WARNING" "Could not download root hints - using defaults"
        fi
    fi
    
    # Initialize DNSSEC trust anchor
    if [[ -x /usr/sbin/unbound-anchor ]]; then
        unbound-anchor -a /var/lib/unbound/root.key >> "$LOG_FILE" 2>&1 || true
    fi
    
    # Set permissions
    chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true
    
    # Test configuration
    print_status "INFO" "Validating Unbound configuration..."
    
    if unbound-checkconf >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Unbound configuration is valid"
    else
        print_status "ERROR" "Unbound configuration invalid - using defaults"
        rm -f /etc/unbound/unbound.conf.d/local-dns.conf
        return 1
    fi
    
    # Enable and start Unbound
    systemctl enable unbound >> "$LOG_FILE" 2>&1 || true
    systemctl start unbound >> "$LOG_FILE" 2>&1 || true
    
    # Wait for Unbound to start
    sleep 3
    
    # Test Unbound
    if dig @127.0.0.1 +short google.com A >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Unbound DNS resolver is working"
    else
        print_status "WARNING" "Unbound may not be responding correctly"
    fi
    
    # Configure system to use Unbound (carefully)
    configure_system_dns
    
    print_status "SUCCESS" "Unbound DNS resolver configured"
}

configure_system_dns() {
    print_status "INFO" "Configuring system DNS..."
    
    # Check if systemd-resolved is managing DNS
    if systemctl is-active systemd-resolved >> "$LOG_FILE" 2>&1; then
        print_status "INFO" "systemd-resolved detected - configuring to work alongside Unbound"
        
        # Create drop-in configuration
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/unbound.conf << 'RESOLVED_EOF'
[Resolve]
DNS=127.0.0.1
FallbackDNS=1.1.1.1 9.9.9.9
DNSStubListener=no
RESOLVED_EOF
        
        systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1 || true
        
    elif [[ -L /etc/resolv.conf ]]; then
        # resolv.conf is a symlink - don't modify it
        print_status "INFO" "resolv.conf is managed (symlink) - not modifying"
        
    else
        # Direct resolv.conf - modify carefully
        # First verify Unbound is working
        if dig @127.0.0.1 +short google.com A >> "$LOG_FILE" 2>&1; then
            # Create new resolv.conf
            cat > /etc/resolv.conf.new << 'RESOLV_EOF'
# Local Unbound DNS resolver
nameserver 127.0.0.1
# Fallback DNS servers
nameserver 1.1.1.1
nameserver 9.9.9.9
options edns0 trust-ad
RESOLV_EOF
            
            # Replace only if network test passes
            if test_dns_resolution; then
                cat /etc/resolv.conf.new > /etc/resolv.conf 2>/dev/null || \
                    print_status "WARNING" "Could not update resolv.conf"
            fi
            rm -f /etc/resolv.conf.new
        else
            print_status "WARNING" "Unbound not responding - keeping original DNS config"
        fi
    fi
}

#===============================================================================
# TOR INSTALLATION AND CONFIGURATION
#===============================================================================
install_configure_tor() {
    print_section "Installing and Configuring Tor"
    
    # Add Tor official repository
    print_status "INFO" "Adding Tor official repository..."
    
    # Install prerequisites
    apt-get install -y apt-transport-https gnupg curl >> "$LOG_FILE" 2>&1 || true
    
    # Import Tor Project GPG key
    local tor_key_file="/usr/share/keyrings/tor-archive-keyring.gpg"
    
    if curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc 2>/dev/null | \
       gpg --dearmor -o "$tor_key_file" 2>/dev/null; then
        print_status "SUCCESS" "Tor GPG key imported"
    else
        # Fallback method
        curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc 2>/dev/null | \
        apt-key add - >> "$LOG_FILE" 2>&1 || print_status "WARNING" "Could not import Tor GPG key"
    fi
    
    # Add Tor repository
    if [[ -f "$tor_key_file" ]]; then
        cat > /etc/apt/sources.list.d/tor.list << 'TOR_REPO_EOF'
deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bullseye main
deb-src [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bullseye main
TOR_REPO_EOF
    else
        cat > /etc/apt/sources.list.d/tor.list << 'TOR_REPO_EOF2'
deb https://deb.torproject.org/torproject.org bullseye main
deb-src https://deb.torproject.org/torproject.org bullseye main
TOR_REPO_EOF2
    fi
    
    # Update and install Tor
    apt-get update >> "$LOG_FILE" 2>&1 || true
    
    if apt-get install -y tor deb.torproject.org-keyring >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Tor installed from official repository"
    else
        # Fallback to Debian repo
        if apt-get install -y tor >> "$LOG_FILE" 2>&1; then
            print_status "SUCCESS" "Tor installed from Debian repository"
        else
            print_status "ERROR" "Could not install Tor"
            return 1
        fi
    fi
    
    # Install torsocks
    apt-get install -y torsocks >> "$LOG_FILE" 2>&1 || \
        print_status "WARNING" "Could not install torsocks"
    
    # Backup existing Tor config
    backup_file /etc/tor/torrc
    
    # Configure Tor
    cat > /etc/tor/torrc << 'TOR_EOF'
## Tor Configuration
## Security-focused SOCKS proxy setup

# Data directory
DataDirectory /var/lib/tor

# SOCKS proxy configuration
SocksPort 9050
SocksPolicy accept 127.0.0.1
SocksPolicy accept6 [::1]
SocksPolicy reject *

# DNS resolution through Tor
DNSPort 9053
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit

# Logging
Log notice file /var/log/tor/notices.log
Log warn file /var/log/tor/warnings.log

# Safety settings
SafeLogging 1
AvoidDiskWrites 1

# Circuit settings
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 1
MaxCircuitDirtiness 600
NewCircuitPeriod 30

# Not an exit relay
ExitRelay 0
ExitPolicy reject *:*

# Hardware crypto if available
HardwareAccel 1

# Disable unnecessary features
FetchUselessDescriptors 0
FetchDirInfoEarly 0
FetchDirInfoExtraEarly 0

# Connection padding (privacy)
ConnectionPadding auto
ReducedConnectionPadding 0
TOR_EOF

    # Create log directory
    mkdir -p /var/log/tor
    chown debian-tor:debian-tor /var/log/tor 2>/dev/null || \
    chown _tor:_tor /var/log/tor 2>/dev/null || true
    chmod 700 /var/log/tor
    
    # Enable and start Tor
    systemctl enable tor >> "$LOG_FILE" 2>&1 || true
    systemctl start tor >> "$LOG_FILE" 2>&1 || true
    
    # Wait for Tor to bootstrap
    print_status "INFO" "Waiting for Tor to bootstrap (up to 90 seconds)..."
    
    local timeout=90
    local count=0
    local bootstrapped=false
    
    while [[ $count -lt $timeout ]]; do
        if systemctl is-active tor >> "$LOG_FILE" 2>&1; then
            if grep -q "Bootstrapped 100%" /var/log/tor/notices.log 2>/dev/null; then
                bootstrapped=true
                break
            fi
        fi
        sleep 3
        ((count+=3))
        echo -n "."
    done
    echo ""
    
    if [[ "$bootstrapped" == "true" ]]; then
        print_status "SUCCESS" "Tor bootstrap complete"
    else
        print_status "WARNING" "Tor may not have fully bootstrapped - check /var/log/tor/notices.log"
    fi
    
    # Test Tor connectivity (non-blocking)
    print_status "INFO" "Testing Tor connection..."
    
    local tor_test_result
    tor_test_result=$(curl --socks5 127.0.0.1:9050 --max-time 30 -s https://check.torproject.org/api/ip 2>/dev/null || echo "failed")
    
    if echo "$tor_test_result" | grep -q '"IsTor":true'; then
        print_status "SUCCESS" "Tor connection verified - traffic is anonymized"
    else
        print_status "WARNING" "Could not verify Tor connection - may still be bootstrapping"
    fi
    
    # Configure torsocks if installed
    if [[ -f /etc/tor/torsocks.conf ]] || [[ -f /etc/torsocks.conf ]]; then
        local torsocks_conf="/etc/tor/torsocks.conf"
        [[ -f /etc/torsocks.conf ]] && torsocks_conf="/etc/torsocks.conf"
        
        cat > "$torsocks_conf" << 'TORSOCKS_EOF'
# torsocks configuration
TorAddress 127.0.0.1
TorPort 9050
OnionAddrRange 127.42.42.0/24
AllowInbound 0
AllowOutboundLocalhost 0
IsolatePID 1
TORSOCKS_EOF
    fi
    
    print_status "SUCCESS" "Tor installation and configuration completed"
}

#===============================================================================
# UFW FIREWALL
#===============================================================================
configure_ufw_firewall() {
    print_section "Configuring UFW Firewall"
    
    if ! check_command ufw; then
        print_status "SKIP" "UFW not installed"
        return 1
    fi
    
    # Reset UFW to defaults (quietly)
    print_status "INFO" "Resetting UFW to defaults..."
    echo "y" | ufw reset >> "$LOG_FILE" 2>&1 || true
    
    # Set default policies
    ufw default deny incoming >> "$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >> "$LOG_FILE" 2>&1 || true
    
    # Allow SSH (critical - do this first)
    print_status "INFO" "Allowing SSH access..."
    ufw allow ssh >> "$LOG_FILE" 2>&1 || true
    ufw allow 22/tcp >> "$LOG_FILE" 2>&1 || true
    
    # Allow HTTP and HTTPS
    print_status "INFO" "Allowing HTTP/HTTPS..."
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1 || true
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1 || true
    
    # Rate limit SSH connections
    ufw limit ssh >> "$LOG_FILE" 2>&1 || true
    
    # Enable logging
    ufw logging medium >> "$LOG_FILE" 2>&1 || true
    
    # Enable UFW
    print_status "INFO" "Enabling UFW..."
    echo "y" | ufw enable >> "$LOG_FILE" 2>&1
    
    # Verify UFW is active
    if ufw status | grep -q "active"; then
        print_status "SUCCESS" "UFW firewall enabled and configured"
    else
        print_status "ERROR" "UFW may not be active"
    fi
    
    # Log firewall status
    ufw status verbose >> "$LOG_FILE" 2>&1 || true
}

#===============================================================================
# FAIL2BAN
#===============================================================================
configure_fail2ban() {
    print_section "Configuring Fail2Ban"
    
    if ! check_command fail2ban-client; then
        print_status "SKIP" "Fail2ban not installed"
        return 1
    fi
    
    # Create local configuration
    cat > /etc/fail2ban/jail.local << 'FAIL2BAN_EOF'
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
maxretry = 3
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
maxretry = 6
bantime = 1800
findtime = 300

#---------------------------------------
# Additional Jails
#---------------------------------------
[recidive]
enabled = true
filter = recidive
banaction = ufw
bantime = 604800
findtime = 86400
maxretry = 3
FAIL2BAN_EOF

    # Enable and restart fail2ban
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || true
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || true
    
    # Verify fail2ban is running
    if systemctl is-active fail2ban >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Fail2Ban configured and running"
    else
        print_status "WARNING" "Fail2Ban may not be running properly"
    fi
}

#===============================================================================
# AIDE CONFIGURATION
#===============================================================================
configure_aide() {
    print_section "Configuring AIDE File Integrity Monitoring"
    
    # Find AIDE command
    local aide_cmd=""
    local aide_init=""
    
    if [[ -x /usr/sbin/aideinit ]]; then
        aide_init="/usr/sbin/aideinit"
    fi
    
    if check_command aide; then
        aide_cmd="aide"
    elif [[ -x /usr/bin/aide ]]; then
        aide_cmd="/usr/bin/aide"
    elif [[ -x /usr/sbin/aide ]]; then
        aide_cmd="/usr/sbin/aide"
    fi
    
    if [[ -z "$aide_cmd" ]] && [[ -z "$aide_init" ]]; then
        print_status "SKIP" "AIDE not installed"
        return 1
    fi
    
    print_status "INFO" "Found AIDE: ${aide_cmd:-$aide_init}"
    
    # Create custom AIDE configuration
    if [[ -d /etc/aide/aide.conf.d ]]; then
        cat > /etc/aide/aide.conf.d/99-custom.conf << 'AIDE_CONF_EOF'
# Custom AIDE monitoring rules

# Monitor home directories
/home CONTENT_EX

# Monitor root home
/root CONTENT_EX

# Monitor authentication logs
/var/log/auth.log p+u+g+i+n+S

# Monitor SSH configuration
/etc/ssh CONTENT_EX
AIDE_CONF_EOF
    fi
    
    # Initialize AIDE database
    print_status "INFO" "Initializing AIDE database (this may take several minutes)..."
    
    if [[ -n "$aide_init" ]]; then
        # Use Debian wrapper
        yes | "$aide_init" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "AIDE initialization had warnings"
    elif [[ -n "$aide_cmd" ]]; then
        # Direct AIDE
        "$aide_cmd" --init >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "AIDE initialization had warnings"
        
        # Move database
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
        fi
    fi
    
    # Create daily AIDE check cron job
    cat > /etc/cron.daily/aide-check << 'AIDE_CRON_EOF'
#!/bin/bash
# Daily AIDE integrity check

LOGDIR="/var/log/aide"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

# Find AIDE command
AIDE_CMD=""
if command -v aide >/dev/null 2>&1; then
    AIDE_CMD="aide"
elif [[ -x /usr/bin/aide ]]; then
    AIDE_CMD="/usr/bin/aide"
fi

if [[ -n "$AIDE_CMD" ]]; then
    "$AIDE_CMD" --check > "$LOGDIR/aide-check-$DATE.log" 2>&1 || true
fi

# Keep only last 30 days of logs
find "$LOGDIR" -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null || true

exit 0
AIDE_CRON_EOF

    chmod 755 /etc/cron.daily/aide-check
    
    print_status "SUCCESS" "AIDE configured with daily integrity checks"
}

#===============================================================================
# ROOTKIT SCANNERS
#===============================================================================
configure_rootkit_scanners() {
    print_section "Configuring Rootkit Scanners"
    
    # Configure rkhunter
    if check_command rkhunter; then
        print_status "INFO" "Configuring rkhunter..."
        
        # Update rkhunter configuration
        if [[ -f /etc/rkhunter.conf ]]; then
            sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^WEB_CMD=.*/WEB_CMD="curl -fsSL"/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^PKGMGR=.*/PKGMGR=DPKG/' /etc/rkhunter.conf 2>/dev/null || true
        fi
        
        # Update rkhunter database
        rkhunter --update >> "$LOG_FILE" 2>&1 || print_status "WARNING" "rkhunter update had warnings"
        rkhunter --propupd >> "$LOG_FILE" 2>&1 || print_status "WARNING" "rkhunter propupd had warnings"
        
        print_status "SUCCESS" "rkhunter configured and updated"
    else
        print_status "SKIP" "rkhunter not installed"
    fi
    
    # Configure chkrootkit
    if check_command chkrootkit; then
        print_status "SUCCESS" "chkrootkit installed and ready"
    else
        print_status "SKIP" "chkrootkit not installed"
    fi
    
    # Create weekly rootkit scan cron job
    cat > /etc/cron.weekly/rootkit-scan << 'ROOTKIT_CRON_EOF'
#!/bin/bash
# Weekly rootkit scan

LOGDIR="/var/log/security-scans"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

# Run rkhunter
if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --check --skip-keypress --report-warnings-only \
        > "$LOGDIR/rkhunter-$DATE.log" 2>&1 || true
fi

# Run chkrootkit
if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit > "$LOGDIR/chkrootkit-$DATE.log" 2>&1 || true
fi

# Clean old logs (keep 60 days)
find "$LOGDIR" -name "*.log" -mtime +60 -delete 2>/dev/null || true

exit 0
ROOTKIT_CRON_EOF

    chmod 755 /etc/cron.weekly/rootkit-scan
    
    print_status "SUCCESS" "Rootkit scanners configured with weekly checks"
}

#===============================================================================
# AUDITD CONFIGURATION
#===============================================================================
configure_auditd() {
    print_section "Configuring Audit Daemon"
    
    if ! check_command auditd; then
        print_status "SKIP" "auditd not installed"
        return 1
    fi
    
    # Create audit rules
    mkdir -p /etc/audit/rules.d
    
    cat > /etc/audit/rules.d/99-hardening.rules << 'AUDIT_EOF'
## Security Hardening Audit Rules

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1 = printk, 2 = panic)
-f 1

#---------------------------------------
# Authentication and Identity
#---------------------------------------
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

#---------------------------------------
# Sudo and Privilege Escalation
#---------------------------------------
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes

#---------------------------------------
# SSH Configuration
#---------------------------------------
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

#---------------------------------------
# PAM Configuration
#---------------------------------------
-w /etc/pam.d/ -p wa -k pam_changes

#---------------------------------------
# Login and Session
#---------------------------------------
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/tallylog -p wa -k logins

#---------------------------------------
# Cron
#---------------------------------------
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

#---------------------------------------
# Network Configuration
#---------------------------------------
-w /etc/hosts -p wa -k network_config
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/resolv.conf -p wa -k network_config
-w /etc/network/ -p wa -k network_config

#---------------------------------------
# System Boot
#---------------------------------------
-w /etc/systemd/ -p wa -k systemd
-w /etc/init.d/ -p wa -k init

#---------------------------------------
# Kernel Modules (64-bit)
#---------------------------------------
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

#---------------------------------------
# Time Changes
#---------------------------------------
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change

#---------------------------------------
# Make rules immutable (must be last)
#---------------------------------------
-e 2
AUDIT_EOF

    # Load audit rules
    print_status "INFO" "Loading audit rules..."
    
    if augenrules --load >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Audit rules loaded"
    else
        print_status "WARNING" "Some audit rules may not have loaded"
    fi
    
    # Enable and start auditd
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || true
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || true
    
    if systemctl is-active auditd >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Audit daemon configured and running"
    else
        print_status "WARNING" "Audit daemon may not be running"
    fi
}

#===============================================================================
# APPARMOR CONFIGURATION
#===============================================================================
configure_apparmor() {
    print_section "Configuring AppArmor"
    
    # Check if AppArmor is available
    if ! check_command apparmor_status; then
        print_status "SKIP" "AppArmor tools not installed"
        return 1
    fi
    
    # Check kernel support
    if [[ ! -d /sys/kernel/security/apparmor ]]; then
        print_status "SKIP" "AppArmor not supported by kernel"
        return 1
    fi
    
    # Enable AppArmor service
    systemctl enable apparmor >> "$LOG_FILE" 2>&1 || true
    systemctl start apparmor >> "$LOG_FILE" 2>&1 || true
    
    # Check for profiles
    local profile_count=0
    if [[ -d /etc/apparmor.d ]]; then
        profile_count=$(find /etc/apparmor.d -maxdepth 1 -type f -name "[a-z]*" 2>/dev/null | wc -l)
    fi
    
    if [[ $profile_count -eq 0 ]]; then
        print_status "WARNING" "No AppArmor profiles found"
        return 1
    fi
    
    print_status "INFO" "Found $profile_count AppArmor profiles"
    
    # Reload all profiles
    print_status "INFO" "Reloading AppArmor profiles..."
    
    if apparmor_parser -r /etc/apparmor.d/* >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "AppArmor profiles reloaded"
    else
        print_status "WARNING" "Some AppArmor profiles failed to load"
    fi
    
    # Set key profiles to enforce mode (if they exist)
    local profiles_to_enforce=(
        "usr.sbin.tor"
        "usr.sbin.unbound"
    )
    
    for profile in "${profiles_to_enforce[@]}"; do
        if [[ -f "/etc/apparmor.d/$profile" ]]; then
            aa-enforce "$profile" >> "$LOG_FILE" 2>&1 && \
                print_status "INFO" "Enforced AppArmor profile: $profile"
        fi
    done
    
    # Show AppArmor status summary
    apparmor_status 2>&1 | head -5 >> "$LOG_FILE" || true
    
    print_status "SUCCESS" "AppArmor configured"
}

#===============================================================================
# LYNIS CONFIGURATION
#===============================================================================
configure_lynis() {
    print_section "Configuring Lynis Security Auditor"
    
    if ! check_command lynis; then
        print_status "SKIP" "Lynis not installed"
        return 1
    fi
    
    # Create Lynis custom profile
    mkdir -p /etc/lynis
    
    cat > /etc/lynis/custom.prf << 'LYNIS_PROFILE_EOF'
# Lynis Custom Profile for VPS

# Skip tests that don't apply to VPS
skip-test=KRNL-5770
skip-test=KRNL-5820
skip-test=PKGS-7370
skip-test=USB-1000
skip-test=USB-2000
skip-test=USB-3000

# Thorough scanning
quick=no

# Show all warnings
show-warnings-only=no

# Colors for console output
colors=yes
LYNIS_PROFILE_EOF

    # Create weekly Lynis audit cron job
    cat > /etc/cron.weekly/lynis-audit << 'LYNIS_CRON_EOF'
#!/bin/bash
# Weekly Lynis security audit

LOGDIR="/var/log/lynis"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

# Run Lynis audit
if command -v lynis >/dev/null 2>&1; then
    lynis audit system --no-colors --quiet --report-file="$LOGDIR/lynis-report-$DATE.dat" \
        > "$LOGDIR/lynis-audit-$DATE.log" 2>&1 || true
fi

# Keep only last 60 days
find "$LOGDIR" -name "lynis-*" -mtime +60 -delete 2>/dev/null || true

exit 0
LYNIS_CRON_EOF

    chmod 755 /etc/cron.weekly/lynis-audit
    
    print_status "SUCCESS" "Lynis configured with weekly audits"
}

#===============================================================================
# ADDITIONAL HARDENING
#===============================================================================
apply_additional_hardening() {
    print_section "Applying Additional Hardening Measures"
    
    # Restrict cron access
    print_status "INFO" "Restricting cron access..."
    echo "root" > /etc/cron.allow 2>/dev/null || true
    rm -f /etc/cron.deny 2>/dev/null || true
    chmod 600 /etc/cron.allow 2>/dev/null || true
    
    # Restrict at access
    echo "root" > /etc/at.allow 2>/dev/null || true
    rm -f /etc/at.deny 2>/dev/null || true
    chmod 600 /etc/at.allow 2>/dev/null || true
    
    # Secure file permissions
    print_status "INFO" "Setting secure file permissions..."
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 700 /root 2>/dev/null || true
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    
    # Disable unused filesystems
    print_status "INFO" "Disabling unused filesystem modules..."
    cat > /etc/modprobe.d/hardening-filesystems.conf << 'FS_EOF'
# Disable uncommon filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
FS_EOF

    # Disable uncommon network protocols
    cat > /etc/modprobe.d/hardening-protocols.conf << 'PROTO_EOF'
# Disable uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
PROTO_EOF

    # Disable USB storage (common for servers)
    cat > /etc/modprobe.d/hardening-usb.conf << 'USB_EOF'
# Disable USB storage
install usb-storage /bin/true
USB_EOF

    # Configure password quality
    print_status "INFO" "Configuring password quality requirements..."
    if [[ -f /etc/security/pwquality.conf ]]; then
        cat >> /etc/security/pwquality.conf << 'PWQUALITY_EOF'

# Security hardening password requirements
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
PWQUALITY_EOF
    fi
    
    # Harden login.defs
    print_status "INFO" "Hardening login definitions..."
    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs 2>/dev/null || true
        
        # Add SHA512 encryption rounds
        if ! grep -q "SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
            echo "SHA_CRYPT_MAX_ROUNDS 65536" >> /etc/login.defs
        fi
    fi
    
    # Set default umask
    cat > /etc/profile.d/umask.sh << 'UMASK_EOF'
# Set secure default umask
umask 027
UMASK_EOF
    chmod 644 /etc/profile.d/umask.sh
    
    # Disable Ctrl+Alt+Delete
    systemctl mask ctrl-alt-del.target >> "$LOG_FILE" 2>&1 || true
    
    # Secure home directories
    print_status "INFO" "Securing home directories..."
    for homedir in /home/*; do
        if [[ -d "$homedir" ]]; then
            chmod 700 "$homedir" 2>/dev/null || true
        fi
    done
    
    # Configure process accounting
    if check_command accton; then
        if [[ ! -f /var/log/account/pacct ]]; then
            mkdir -p /var/log/account
            touch /var/log/account/pacct
        fi
        accton /var/log/account/pacct >> "$LOG_FILE" 2>&1 || true
    fi
    
    print_status "SUCCESS" "Additional hardening measures applied"
}

#===============================================================================
# VERIFICATION AND TESTING
#===============================================================================
verify_configuration() {
    print_section "Verifying Configuration"
    
    local tests_passed=0
    local tests_failed=0
    
    # Test DNS resolution
    print_status "INFO" "Testing DNS resolution..."
    if dig +short google.com A >/dev/null 2>&1 || \
       getent hosts google.com >/dev/null 2>&1; then
        print_status "SUCCESS" "DNS resolution: OK"
