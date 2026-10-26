# ShareGuard Privileged Helper Installation Guide

The ShareGuard daemon runs with non-privileged user permissions (`shareguard`).
To execute port-targeted firewall operations and terminate rogue Samba sessions without granting the daemon full root access, ShareGuard uses a dedicated, audited helper script: `/usr/local/bin/shareguard-helper`.

---

## 1. Install the Helper Script

Copy the helper script to `/usr/local/bin/`, set the ownership to `root:root`, and set permissions to `0750` or `0755`:

```bash
# Copy helper to system binary directory
sudo cp deploy/shareguard-helper /usr/local/bin/shareguard-helper

# Set owner to root
sudo chown root:root /usr/local/bin/shareguard-helper

# Restrict permissions (executable by root and shareguard group, or world-executable)
sudo chmod 0755 /usr/local/bin/shareguard-helper
```

---

## 2. Configure Sudoers Privileges

Install the sudoers file to allow the `shareguard` user to run only the helper script without a password:

```bash
# Copy sudoers rule
sudo cp deploy/sudoers.d/shareguard /etc/sudoers.d/shareguard

# Set strictly required permissions for sudoers.d files
sudo chown root:root /etc/sudoers.d/shareguard
sudo chmod 0440 /etc/sudoers.d/shareguard

# Validate sudoers syntax
sudo visudo -cf /etc/sudoers.d/shareguard
```

---

## 3. Verify with `--dry-run`

Test the helper under the non-privileged service user using `--dry-run`:

```bash
# Test blocking a test client IP (dry-run logs the exact command without executing)
sudo /usr/local/bin/shareguard-helper block 192.168.56.20 900 --dry-run

# Test listing rules
sudo /usr/local/bin/shareguard-helper list

# Test emergency flush (dry-run)
sudo /usr/local/bin/shareguard-helper flush --dry-run
```

---

## 4. Security Verification

Verify that argument injection is rejected by the helper's internal validation:

```bash
# Attempt shell injection (must fail with exit code 2)
sudo /usr/local/bin/shareguard-helper block "192.168.56.20; reboot" 900

# Attempt loopback block (must fail with exit code 2)
sudo /usr/local/bin/shareguard-helper block 127.0.0.1 900
```
