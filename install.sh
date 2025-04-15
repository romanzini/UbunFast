#!/bin/bash

# Production Docker Host Hardening Script (based on https://gist.github.com/rameerez/238927b78f9108a71a77aed34208de11)
# For Ubuntu Server 24.04 LTS (Noble)

set -euo pipefail
IFS=$'\n\t'

# --- Constants ---
REQUIRED_OS="Ubuntu"
REQUIRED_VERSION="24.04"
MIN_RAM_MB=1024
MIN_DISK_GB=20

# --- Aesthetics ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
ICON='\xF0\x9F\x8C\x80'
NC='\033[0m'

# --- Functions ---
print_message() {
  local color=$1
  local message=$2
  echo -e "${color}${ICON} ${message}${NC}"
}

print_error() {
  print_message "${RED}" "ERROR: $1"
}

print_warning() {
  print_message "${YELLOW}" "WARNING: $1"
}

print_success() {
  print_message "${GREEN}" "SUCCESS: $1"
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
  fi
}

check_os() {
  if ! command -v lsb_release >/dev/null 2>&1; then
    print_error "lsb_release command not found. Is this Ubuntu?"
    exit 1
  fi

  local os_name=$(lsb_release -is)
  local os_version=$(lsb_release -rs)

  if [[ "$os_name" != "$REQUIRED_OS" ]]; then
    print_error "This script requires $REQUIRED_OS (found $os_name)"
    exit 1
  fi

  if [[ "$os_version" != "$REQUIRED_VERSION" ]]; then
    print_error "This script requires Ubuntu $REQUIRED_VERSION (found $os_version)"
    exit 1
  fi
}

check_resources() {
  local total_ram_mb=$(free -m | awk '/^Mem:/{print $2}')
  local total_disk_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')

  if ((total_ram_mb < MIN_RAM_MB)); then
    print_error "Insufficient RAM. Required: ${MIN_RAM_MB}MB, Found: ${total_ram_mb}MB"
    exit 1
  fi

  if ((total_disk_gb < MIN_DISK_GB)); then
    print_error "Insufficient disk space. Required: ${MIN_DISK_GB}GB, Found: ${total_disk_gb}GB"
    exit 1
  fi
}

verify_security_settings() {
  local failed=0

  # Check kernel parameters
  local params=(
    "kernel.unprivileged_bpf_disabled=1"
    "net.ipv4.conf.all.log_martians=0"
    "net.ipv4.ip_forward=1"
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
  )

  for param in "${params[@]}"; do
    local name=${param%=*}
    local expected=${param#*=}
    local actual=$(sysctl -n "$name" 2>/dev/null || echo "NOT_FOUND")

    if [[ "$actual" != "$expected" ]]; then
      print_error "Kernel parameter $name = $actual (expected $expected)"
      failed=1
    fi
  done

  # Check Docker settings
  if ! docker info 2>/dev/null | grep -q "Cgroup Driver: systemd"; then
    print_error "Docker is not using systemd cgroup driver"
    failed=1
  fi

  if [[ "$(stat -c %a /var/run/docker.sock)" != "660" ]]; then
    print_error "Docker socket has incorrect permissions"
    failed=1
  fi

  # Check services
  local services=(
    "docker"
    "fail2ban"
    "ufw"
    "auditd"
    "chrony"
  )

  for service in "${services[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
      print_error "Service $service is not running"
      failed=1
    fi
  done

  # Check AIDE database
  if [ ! -f /var/lib/aide/aide.db ]; then
    print_error "AIDE database not initialized"
    failed=1
  fi

  # Check Chrony sync
  if ! chronyc tracking &>/dev/null; then
    print_error "Chrony is not syncing time"
    failed=1
  fi

  # Additional security checks
  if ! ufw status | grep -q "Status: active"; then
    print_error "UFW firewall is not active"
    failed=1
  fi

  if ! grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
    print_error "SSH password authentication is not disabled"
    failed=1
  fi

  if ! apparmor_status | grep -q "apparmor module is loaded."; then
    print_error "AppArmor is not loaded"
    failed=1
  fi

  return $failed
}

handle_error() {
  local line_number=$1
  print_error "Script failed on line ${line_number}"
  print_error "Please check the logs above for more information"
  exit 1
}

# Set up error handling
trap 'handle_error ${LINENO}' ERR

# --- Pre-flight Checks ---
print_message "${YELLOW}" "Performing pre-flight checks..."
check_root
check_os
check_resources

# --- System Updates ---
print_message "${YELLOW}" "Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# --- Essential Packages ---
print_message "${YELLOW}" "Installing essential packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw \
  fail2ban \
  curl \
  wget \
  gnupg \
  lsb-release \
  ca-certificates \
  apt-transport-https \
  software-properties-common \
  sysstat \
  auditd \
  audispd-plugins \
  unattended-upgrades \
  acl \
  apparmor \
  apparmor-utils \
  aide \
  rkhunter \
  logwatch \
  git \
  python3-pyinotify

# --- Time Synchronization ---
print_message "${YELLOW}" "Configuring time synchronization..."
systemctl stop systemd-timesyncd || true
systemctl disable systemd-timesyncd || true
apt-get remove -y systemd-timesyncd || true
DEBIAN_FRONTEND=noninteractive apt-get install -y chrony
if systemctl -q is-enabled systemd-timesyncd 2>/dev/null; then
  systemctl disable systemd-timesyncd
  systemctl stop systemd-timesyncd
fi
systemctl enable chrony.service || true # use .service to avoid alias issues
systemctl start chrony.service
# --- System Hardening ---
print_message "${YELLOW}" "Configuring system security..."

# Configure AppArmor
systemctl enable apparmor
systemctl start apparmor

# Initialize AIDE
aide --config=/etc/aide/aide.conf --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure kernel parameters
cat <<EOF >/etc/sysctl.d/99-security.conf
# Network security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Docker needs IPv4 forwarding
net.ipv4.ip_forward = 1

# System limits
fs.file-max = 1048576
kernel.pid_max = 65536
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_tw_reuse = 1
vm.max_map_count = 262144
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2

# File system hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Additional network hardening
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf
sysctl --system # This loads all configs including the new one

# Configure system limits
cat <<EOF >/etc/security/limits.d/docker.conf
*       soft    nproc     10000
*       hard    nproc     10000
*       soft    nofile    1048576
*       hard    nofile    1048576
*       soft    core      0
*       hard    core      0
*       soft    stack     8192
*       hard    stack     8192
EOF

# --- Docker Installation ---
print_message "${YELLOW}" "Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
rm get-docker.sh

# --- Docker Configuration ---
print_message "${YELLOW}" "Configuring Docker..."
mkdir -p /etc/docker
cat <<EOF >/etc/docker/daemon.json
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "icc": true,
    "live-restore": false,
    "userland-proxy": false,
    "no-new-privileges": true,
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "features": {
        "buildkit": true
    },
    "experimental": false,
    "default-runtime": "runc",
    "storage-driver": "overlay2",
    "metrics-addr": "127.0.0.1:9323",
    "builder": {
        "gc": {
            "enabled": true,
            "defaultKeepStorage": "20GB"
        }
    }
}
EOF

# After Docker daemon.json configuration
print_message "${YELLOW}" "Testing Docker configuration..."
if ! docker info &>/dev/null; then
  print_error "Docker failed to start. Checking configuration..."
  journalctl -u docker.service --no-pager | tail -n 50
  exit 1
fi

systemctl enable docker
systemctl restart docker || {
  print_error "Docker failed to start. Logs:"
  journalctl -u docker.service --no-pager | tail -n 50
  exit 1
}

# Verify Docker configuration
print_message "${YELLOW}" "Verifying Docker configuration..."
docker info | grep -E "Cgroup Driver|Storage Driver|Logging Driver"

# --- User Setup ---
print_message "${YELLOW}" "Creating docker user..."
adduser --system --group --shell /bin/bash --home /home/docker --disabled-password docker
usermod -aG docker docker

# --- SSH Configuration ---

print_message "${YELLOW}" "Configuring SSH..."
mkdir -p /home/docker/.ssh
chown -R docker:docker /home/docker
chmod 755 /home/docker

# Copy root's authorized keys to docker user if they exist
if [ -f /root/.ssh/authorized_keys ]; then
  cp /root/.ssh/authorized_keys /home/docker/.ssh/authorized_keys
  chown -R docker:docker /home/docker/.ssh
  chmod 700 /home/docker/.ssh
  chmod 600 /home/docker/.ssh/authorized_keys
fi

cat <<EOF >/etc/ssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf

Port 22
AddressFamily inet
Protocol 2

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key

SyslogFacility AUTH
LogLevel VERBOSE

LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 10
MaxSessions 5

PubkeyAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

UsePAM yes
AllowAgentForwarding no
AllowTcpForwarding yes  # Required for Docker forwarding
X11Forwarding no
PermitTTY yes
PrintMotd no

ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

AllowUsers docker root

KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

systemctl reload ssh

# --- Firewall Configuration ---
print_message "${YELLOW}" "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

# --- fail2ban Configuration ---
print_message "${YELLOW}" "Configuring fail2ban..."

cat <<EOF >/etc/fail2ban/filter.d/docker.conf
[Definition]
failregex = failed login attempt from <HOST>
ignoreregex =
EOF

cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 10
banaction = ufw
banaction_allports = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 10
bantime = 3600

[docker]
enabled = true
filter = docker
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF

# --- Enable and Start Services ---
print_message "${YELLOW}" "Enabling services..."
systemctl enable docker fail2ban auditd chrony
systemctl restart docker fail2ban auditd chrony

# --- Verify Setup ---
print_message "${YELLOW}" "Verifying security settings..."
if verify_security_settings; then
  print_success "Security verification passed"
else
  print_warning "Some security checks failed. Please review the warnings above."
fi

# Add logging configuration
print_message "${YELLOW}" "Configuring system logging..."
cat <<EOF >/etc/logrotate.d/docker-logs
/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    size=100M
    missingok
    delaycompress
    copytruncate
}
EOF

# Automated cleanup to prevent residual files
print_message "${YELLOW}" "Setting up maintenance tasks..."
cat <<EOF >/etc/cron.daily/docker-cleanup
#!/bin/bash
docker system prune -af --volumes
docker builder prune -af --keep-storage=20GB
EOF
chmod +x /etc/cron.daily/docker-cleanup

# Configure auditd
cat <<EOF >/etc/audit/rules.d/audit.rules
# Docker daemon configuration
-w /usr/bin/dockerd -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /etc/default/docker -k docker
-w /etc/docker/daemon.json -k docker
-w /usr/bin/docker -k docker-bin
EOF

# Reload audit rules
auditctl -R /etc/audit/rules.d/audit.rules

# Configure unattended-upgrades for automated security updates
print_message "${YELLOW}" "Configuring automatic updates..."
cat <<EOF >/etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# --- Final Cleanup ---
apt-get autoremove -y
apt-get clean

print_success "Setup complete! System hardening successful."
print_message "${YELLOW}" "Important next steps:"
print_message "${YELLOW}" "1. Add your SSH public key to /home/docker/.ssh/authorized_keys"
print_message "${YELLOW}" "2. Configure your deployment tools (Kamal, etc.)"
print_message "${YELLOW}" "3. REBOOT THE SYSTEM to apply all security settings"
print_message "${YELLOW}" "4. Review logs in /var/log/ regularly"
print_message "${YELLOW}" "5. Set up external monitoring and alerting"

# Additional verification info
print_message "${GREEN}" "System Information:"
echo "Docker Version: $(docker --version)"
echo "Kernel Version: $(uname -r)"
echo "AppArmor Status: $(aa-status --enabled && echo 'Enabled' || echo 'Disabled')"
echo "UFW Status: $(ufw status | grep Status)"
echo "fail2ban Status: $(fail2ban-client status | grep "Number of jail:")"