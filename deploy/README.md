# ShareGuard Live Server Deployment Guide (Ubuntu)

This directory contains the deployment files for running ShareGuard in **LIVE mode** on an Ubuntu Samba file server.

---

## 1. Security Architecture & Least-Privilege Invariants

ShareGuard enforces strict least-privilege principles to isolate detection and recovery from privileged system operations:

```
+-------------------------------------------------------------------------+
|                  ShareGuard Service User ('shareguard')                 |
|                                                                         |
|  - Membership: adm (reads /var/log/samba/ logs)                         |
|  - Membership: officeusers (reads/restores share files)                 |
|  - Dedicated Storage: /var/lib/shareguard/snapshots (mode 0700)         |
|  - System Sandboxing: ProtectSystem=strict, ProtectHome=yes, PrivateTmp |
+-------------------------------------------------------------------------+
                                    |
                     sudo with strict arguments only
                                    v
+-------------------------------------------------------------------------+
|              Audited Root Helper (/usr/local/bin/shareguard-helper)     |
|                                                                         |
|  - Restricts operations to 'shareguard' nftables table only             |
|  - Validates IP syntax strictly with stdlib ipaddress (no loopback)     |
|  - Kills only smbd sessions belonging to the blocked client IP          |
+-------------------------------------------------------------------------+
```

### Permission Matrix

| Path / Resource | Owner:Group | Mode | Access by `shareguard` | Purpose |
|---|---|---|---|---|
| `/opt/shareguard` | `root:root` | `0755` | Read-only | Application code and Python environment |
| `/var/lib/shareguard` | `shareguard:shareguard` | `0750` | Read-Write | Database and runtime state |
| `/var/lib/shareguard/snapshots` | `shareguard:shareguard` | `0700` | Read-Write | Snapshot backups (strictly outside any share) |
| `/var/log/shareguard` | `shareguard:shareguard` | `0750` | Read-Write | Application service logs |
| `/var/log/samba/*.log` | `root:adm` | `0640` | Read-only | Samba `vfs_full_audit` event log stream |
| `/srv/samba/share` | `root:officeusers` | `2770` | Read-Write | Samba share files (for snapshots & restore) |
| `/usr/local/bin/shareguard-helper` | `root:root` | `0755` | Execute via `sudo` | Audited root helper for nftables & smbd session kills |
| `/etc/sudoers.d/shareguard` | `root:root` | `0440` | Sudoers rule | Restricts sudo execution to the helper binary |

---

## 2. Systemd Sandboxing & The `NoNewPrivileges` Trade-off

### The Trade-off
In `deploy/shareguard.service`, the directive `NoNewPrivileges` is explicitly configured as:
```ini
NoNewPrivileges=no
```

#### Why `NoNewPrivileges=no` is Necessary:
When `NoNewPrivileges=yes` is enabled in a systemd service, the Linux kernel sets the `PR_SET_NO_NEW_PRIVS` flag on the process tree. This flag strictly disables SUID transition. Because `shareguard` is a non-root user and must invoke `/usr/local/bin/shareguard-helper` with elevated root privileges via `sudo`, enabling `NoNewPrivileges=yes` causes `sudo` to fail immediately with an authentication/privilege error.

#### Compensating Controls:
To counterbalance `NoNewPrivileges=no`, ShareGuard utilizes comprehensive systemd isolation directives:
1. **`ProtectSystem=strict`**: Mounts the entire filesystem hierarchy (`/usr`, `/boot`, `/etc`, etc.) as read-only.
2. **`ProtectHome=yes`**: Makes `/home`, `/root`, and `/run/user` inaccessible and invisible to the service.
3. **`PrivateTmp=yes`**: Allocates an isolated temporary namespace so temp files cannot be snooped or tampered with.
4. **`ProtectKernelTunables=yes` & `ProtectKernelModules=yes`**: Prevents tampering with `/proc/sys` or loading kernel modules.
5. **`RestrictRealtime=yes` & `LockPersonality=yes`**: Blocks real-time priority escalation and execution domain changes.
6. **Explicit Read/Write Allowlisting**: Write access is strictly scoped to `/var/lib/shareguard`, `/var/log/shareguard`, and the share root `/srv/samba/share`.
7. **Sudoers Path Whitelist**: The `/etc/sudoers.d/shareguard` rule allows execution of **only** the exact path `/usr/local/bin/shareguard-helper`, preventing arbitrary root execution.

---

## 3. Automated Installation

Run the automated installer on the Ubuntu server:

```bash
# Clone the repository and execute installer
sudo ./deploy/install.sh
```

The script will:
1. Install Python 3.12, `nftables`, and `acl`.
2. Create system user `shareguard` and add it to `adm` and `officeusers`.
3. Create `/var/lib/shareguard/snapshots` with mode `0700`.
4. Deploy `/usr/local/bin/shareguard-helper` (`0755`) and `/etc/sudoers.d/shareguard` (`0440`).
5. Deploy `shareguard.service`, reload systemd, and enable the service.

---

## 4. Verification & Testing

Verify the installation using the helper script's `--dry-run` flag:

```bash
# Test blocking a test client IP (logs planned nftables commands without executing)
sudo -u shareguard sudo /usr/local/bin/shareguard-helper block 192.168.1.50 900 --dry-run

# Verify active nftables rules
sudo /usr/local/bin/shareguard-helper list

# Test emergency flush (dry-run)
sudo -u shareguard sudo /usr/local/bin/shareguard-helper flush --dry-run

# Verify systemd service status
systemctl status shareguard.service
```
