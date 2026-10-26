#!/usr/bin/env bash
# ==============================================================================
# deploy/install.sh – Automated ShareGuard deployment installer for Ubuntu 22.04+
#
# Security Properties:
# - Runs service as non-root dedicated 'shareguard' user.
# - Supplementary groups: 'adm' (read Samba logs) and share group (read/restore files).
# - Snapshot directory (/var/lib/shareguard/snapshots) owned by shareguard mode 0700,
#   strictly OUTSIDE all Samba shares.
# - Privileged helper installed to /usr/local/bin/shareguard-helper with mode 0755 root:root.
# - Sudoers configuration validated via visudo before activation.
# ==============================================================================

set -euo pipefail

SHARE_GROUP="${SHARE_GROUP:-officeusers}"
SHARE_ROOT="${SHARE_ROOT:-/srv/samba/share}"
APP_DIR="/opt/shareguard"
DATA_DIR="/var/lib/shareguard"
SNAPSHOT_DIR="${DATA_DIR}/snapshots"
LOG_DIR="/var/log/shareguard"

# 1. Require root execution
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: deploy/install.sh must be executed as root (e.g., sudo ./deploy/install.sh)." >&2
    exit 1
fi

echo "[+] Starting ShareGuard automated deployment on Ubuntu..."

# 2. Install required system packages
echo "[+] Installing system dependencies (Python 3.12, nftables, acl)..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    software-properties-common \
    nftables \
    acl \
    samba-common-bin \
    curl

# Add deadsnakes PPA if python3.12 is not already present
if ! command -v python3.12 >/dev/null 2>&1; then
    echo "[+] Adding deadsnakes PPA for Python 3.12..."
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
    apt-get install -y python3.12 python3.12-venv python3.12-dev
fi

# 3. Create service user and ensure group memberships
echo "[+] Configuring system groups and 'shareguard' service user..."
# Ensure target share group exists
if ! getent group "${SHARE_GROUP}" >/dev/null; then
    echo "[+] Creating share group '${SHARE_GROUP}'..."
    groupadd "${SHARE_GROUP}"
fi

# Ensure adm group exists
if ! getent group adm >/dev/null; then
    groupadd adm
fi

# Create dedicated system user if missing
if ! id -u shareguard >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d "${DATA_DIR}" -M shareguard
    echo "[+] Created system user 'shareguard'."
fi

# Assign supplementary groups
usermod -aG "adm,${SHARE_GROUP}" shareguard
echo "[+] Added 'shareguard' to groups: adm, ${SHARE_GROUP}."

# 4. Create directory structure and set strict permissions
echo "[+] Setting up directory permissions..."
mkdir -p "${DATA_DIR}"
chown shareguard:shareguard "${DATA_DIR}"
chmod 0750 "${DATA_DIR}"

# Snapshot directory MUST be mode 0700 and outside any share
mkdir -p "${SNAPSHOT_DIR}"
chown shareguard:shareguard "${SNAPSHOT_DIR}"
chmod 0700 "${SNAPSHOT_DIR}"
echo "[+] Created snapshot directory at ${SNAPSHOT_DIR} (mode 0700, owned by shareguard)."

mkdir -p "${LOG_DIR}"
chown shareguard:shareguard "${LOG_DIR}"
chmod 0750 "${LOG_DIR}"

mkdir -p "${SHARE_ROOT}"
chgrp -R "${SHARE_GROUP}" "${SHARE_ROOT}" || true

# 5. Install application codebase into /opt/shareguard
echo "[+] Installing application files to ${APP_DIR}..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${APP_DIR}"
cp -r "${SCRIPT_DIR}/server" "${APP_DIR}/"
cp -r "${SCRIPT_DIR}/dashboard" "${APP_DIR}/"
cp -r "${SCRIPT_DIR}/config" "${APP_DIR}/"
cp -r "${SCRIPT_DIR}/scripts" "${APP_DIR}/"
cp "${SCRIPT_DIR}/pyproject.toml" "${APP_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"
cp "${SCRIPT_DIR}/requirements-dev.txt" "${APP_DIR}/"

# 6. Create virtual environment and install pinned dependencies
echo "[+] Creating Python 3.12 virtual environment at ${APP_DIR}/.venv..."
python3.12 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --upgrade pip
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
"${APP_DIR}/.venv/bin/pip" install -e "${APP_DIR}"

# 7. Install privileged root helper
echo "[+] Installing privileged helper /usr/local/bin/shareguard-helper..."
cp "${SCRIPT_DIR}/deploy/shareguard-helper" /usr/local/bin/shareguard-helper
chown root:root /usr/local/bin/shareguard-helper
chmod 0755 /usr/local/bin/shareguard-helper

# 8. Install and validate sudoers configuration
echo "[+] Installing /etc/sudoers.d/shareguard..."
cp "${SCRIPT_DIR}/deploy/sudoers.d/shareguard" /etc/sudoers.d/shareguard
chown root:root /etc/sudoers.d/shareguard
chmod 0440 /etc/sudoers.d/shareguard

echo "[+] Validating sudoers file syntax..."
visudo -cf /etc/sudoers.d/shareguard

# 9. Install systemd service unit
echo "[+] Installing systemd service unit..."
cp "${SCRIPT_DIR}/deploy/shareguard.service" /etc/systemd/system/shareguard.service
chown root:root /etc/systemd/system/shareguard.service
chmod 0644 /etc/systemd/system/shareguard.service

# Create default environment configuration file if missing
if [ ! -f /etc/default/shareguard ]; then
    cat <<EOF > /etc/default/shareguard
# ShareGuard Daemon Environment
SHAREGUARD_MODE=live
SHAREGUARD_CONFIG=/opt/shareguard/config/default.yaml
# Generate a secure secret for production:
SHAREGUARD_ADMIN_KEY=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
EOF
    chmod 0600 /etc/default/shareguard
    chown shareguard:shareguard /etc/default/shareguard
    echo "[+] Generated initial /etc/default/shareguard configuration (mode 0600)."
fi

# 10. Enable and start systemd service
echo "[+] Enabling and starting shareguard.service..."
systemctl daemon-reload
systemctl enable shareguard.service
systemctl restart shareguard.service

echo "[+] ShareGuard live deployment complete!"
echo "[*] Check service status with: systemctl status shareguard.service"
echo "[*] View application logs with: journalctl -u shareguard -f"
