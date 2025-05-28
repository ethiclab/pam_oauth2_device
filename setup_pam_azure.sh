#!/bin/bash

set -euo pipefail

#########################
# INTERACTIVE PROMPT    #
#########################

echo
echo "=== Azure PAM OAuth2 Device Setup ==="
read -rp "Azure CLIENT_ID: " CLIENT_ID
read -rsp "Azure CLIENT_SECRET (hidden): " CLIENT_SECRET; echo
read -rp "Azure TENANT_ID: " TENANT_ID
echo

#########################
# CONFIGURATION SECTION #
#########################

SO_URL="https://github.com/ethiclab/pam_oauth2_device/releases/download/0.3.1-azure/libpam_oauth2_device.so"
INSTALL_PATH="/lib/x86_64-linux-gnu/security/pam_oauth2_device.so"
PAM_CONFIG_PATH="/etc/pam_oauth2_device.json"
LOG_FILE="/var/log/pam_oauth2_device.log"
LOGROTATE_CONF="/etc/logrotate.d/pam_oauth2_device"
PAM_SSH="/etc/pam.d/ssh"
PAM_COMMON_SESSION="/etc/pam.d/common-session"
PAM_LINE="auth sufficient pam_oauth2_device.so config=$PAM_CONFIG_PATH logs=$LOG_FILE log_level=debug"
PAM_MKHOMEDIR_LINE="session required pam_mkhomedir.so skel=/etc/skel umask=0022"
OAUTH_AUTH_URL="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/authorize"
OAUTH_DEVICE_URL="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/devicecode"
OAUTH_TOKEN_URL="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token"
OAUTH_SCOPE="openid profile email"
QR_ENABLED="false"
SSHD_CONFIG="/etc/ssh/sshd_config"

#####################
# INSTALLATION FLOW #
#####################

echo "Installing dependencies..."
sudo apt update
sudo apt install -y curl

echo "Downloading prebuilt pam_oauth2_device.so..."
sudo curl -L --output "$INSTALL_PATH" "$SO_URL"
sudo chmod 0755 "$INSTALL_PATH"

echo "Creating PAM config file $PAM_CONFIG_PATH..."
sudo tee "$PAM_CONFIG_PATH" > /dev/null <<EOF
{
  "client_id": "$CLIENT_ID",
  "client_secret": "$CLIENT_SECRET",
  "tenant_id": "$TENANT_ID",
  "oauth_auth_url": "$OAUTH_AUTH_URL",
  "oauth_device_url": "$OAUTH_DEVICE_URL",
  "oauth_token_url": "$OAUTH_TOKEN_URL",
  "scope": "$OAUTH_SCOPE",
  "qr_enabled": $QR_ENABLED
}
EOF

echo "Creating log file and setting permissions..."
sudo touch "$LOG_FILE"
sudo chown root:root "$LOG_FILE"
sudo chmod 600 "$LOG_FILE"

echo "Installing logrotate config for pam_oauth2_device..."
sudo tee "$LOGROTATE_CONF" > /dev/null <<EOF
$LOG_FILE {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    su root root
}
EOF

echo "Configuring logrotate for pam_oauth2_device..."
if ! command -v logrotate &> /dev/null; then
    echo "Installing logrotate..."
    sudo apt install -y logrotate
fi
echo "Testing logrotate config..."
sudo logrotate -f "$LOGROTATE_CONF" || echo "logrotate test failed"

echo "Ensuring pam_oauth2_device.so is the first auth line in $PAM_SSH..."
if ! grep -Fxq "$PAM_LINE" "$PAM_SSH"; then
    TMP_FILE=$(sudo mktemp)
    { echo "$PAM_LINE"; cat "$PAM_SSH"; } | sudo tee "$TMP_FILE" > /dev/null
    sudo mv "$TMP_FILE" "$PAM_SSH"
    echo "PAM line inserted as first auth rule in $PAM_SSH."
else
    echo "PAM line already present in $PAM_SSH. Skipping."
fi

# PAM common-session: append if missing, always at end (no duplicates)
if ! grep -Fxq "$PAM_MKHOMEDIR_LINE" "$PAM_COMMON_SESSION"; then
    echo "$PAM_MKHOMEDIR_LINE" | sudo tee -a "$PAM_COMMON_SESSION"
fi

#############################
# PATCH SSHD_CONFIG SECTION #
#############################

backup_sshd_config() {
    sudo cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak.$(date +%F-%H%M%S)"
}

patch_sshd_config() {
    backup_sshd_config

    # Utility to replace or add a config line (idempotent)
    replace_or_add() {
        local key="$1"
        local value="$2"
        local file="$3"
        local pattern="^#?${key}[[:space:]]+.*$"

        if grep -Eq "$pattern" "$file"; then
            sudo sed -ri "s|$pattern|$key $value|" "$file"
        else
            echo "$key $value" | sudo tee -a "$file" > /dev/null
        fi
    }

    replace_or_add "LoginGraceTime" "2m" "$SSHD_CONFIG"
    replace_or_add "MaxAuthTries" "3" "$SSHD_CONFIG"
    replace_or_add "PubkeyAuthentication" "yes" "$SSHD_CONFIG"
    replace_or_add "KbdInteractiveAuthentication" "yes" "$SSHD_CONFIG"

    # Add specific lines only if missing
    for extra in \
        "ClientAliveInterval 120" \
        "ClientAliveCountMax 3"
    do
        if ! grep -Fxq "$extra" "$SSHD_CONFIG"; then
            echo "$extra" | sudo tee -a "$SSHD_CONFIG" > /dev/null
        fi
    done
}

echo "Patching sshd_config for device authentication compatibility..."
patch_sshd_config

echo "Reloading sshd to apply changes..."
sudo systemctl reload sshd || sudo service ssh reload || echo "Warning: could not reload sshd, please reload manually."

echo "Setup complete. Microsoft 365 login via device flow is now enabled."
