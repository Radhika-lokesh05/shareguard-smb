# ShareGuard Threat Model & Operational Risk Assessment

## 1. Executive Summary

ShareGuard is an active ransomware defense and behavioral monitoring layer built specifically for Linux-based Samba (SMB) file servers. It continuously analyzes Samba audit logs (`vfs_full_audit`), inspects real-time file-system activities, computes behavioral anomaly and Shannon entropy metrics, monitors canary decoy files, and executes automated or operator-approved network containment (via Linux `nftables` or `iptables`) alongside point-in-time snapshot recovery.

This document articulates the security boundaries, threat capabilities, out-of-scope risks, engineering trade-offs, fail-safe behaviors, and operational assumptions underpinning the ShareGuard architecture.

---

## 2. In-Scope Protections (What ShareGuard Protects Against)

ShareGuard is engineered to detect and contain malicious activity originating from network clients connecting to shared folders over SMBv2/SMBv3:

### 2.1 Compromised Domain & Workgroup Endpoints
- **Threat:** Legitimate domain users or compromised workstations executing malware payloads (e.g., LockBit, BlackCat/ALPHV, Conti derivatives) with valid SMB credentials.
- **Defense:** ShareGuard attributes every file operation to client IP and authenticated username. When abnormal behavioral patterns emerge, ShareGuard isolates the offending workstation IP at the server firewall level, severing the network connection without touching the client host directly.

### 2.2 Rogue Client-Side Encryption & Renaming
- **Threat:** Ransomware writing encrypted ciphertext over existing files or renaming documents to known ransomware extensions (`.locked`, `.crypt`, `.enc`, etc.).
- **Defense:** Dual-engine detection combining:
  1. Signature rules matching hundreds of known ransomware extensions and ransom note patterns.
  2. Rolling Shannon entropy calculation (detecting shifts from structured documents like docx/xlsx/pdf to high-entropy >7.2 ciphertext).
  3. Machine learning (LightGBM/XGBoost) evaluating burst velocity, write-to-read ratios, and operation cadence.

### 2.3 Rapid Bulk File Modifications & Mass Deletions
- **Threat:** Wiper malware or ransomware rapidly overwriting, zeroing, or unlinking thousands of files across network shares.
- **Defense:** Sliding-window velocity tracking. When client operations exceed safe thresholds (e.g., >30 renames/unlinks per minute), alerts fire immediately and trigger automated isolation or operator notification.

### 2.4 Canary Decoy File Tampering
- **Threat:** Ransomware crawling directory trees alphabetically or breadth-first and encrypting files indiscriminately.
- **Defense:** High-interaction and tripwire canary files (`!000_audit_canary.docx`, etc.) placed strategically in share roots and subdirectories. Any write, rename, or unlink event targeting a canary file triggers an immediate, maximum-severity tripwire alert and rapid isolation.

---

## 3. Out-of-Scope Risks (What ShareGuard Does NOT Protect Against)

ShareGuard is a network file-share behavioral monitor; it is not an Endpoint Detection and Response (EDR) agent or a host-level operating system integrity suite.

| Risk Vector | Description | Recommended Mitigation |
|---|---|---|
| **Local Server Compromise** | An attacker who gains a root or interactive shell on the Samba host can kill ShareGuard, alter firewall rules, or encrypt local storage directly. | OS hardening, SSH key-only access, sudo restrictions, SELinux/AppArmor, external SIEM monitoring. |
| **Physical Console Access** | Direct physical access to the server hardware or hypervisor console. | Server room physical access controls, disk encryption (LUKS), TPM-backed secure boot. |
| **Out-of-Band Protocols** | Data access via protocols other than Samba (NFS, iSCSI, SSH/SFTP, FTP, WebDAV, rsync, local backup agents). | Disable unused protocols; separate NFS/iSCSI onto dedicated, isolated VLANs; enforce firewall filtering. |
| **Low-and-Slow Attacks** | Sophisticated human-operated attacks encrypting 1-2 files per hour or spreading over several months below velocity thresholds. | Multi-layered EDR on endpoints, centralized audit logging, daily delta backup reporting. |
| **Data Exfiltration** | Pure read operations where an attacker downloads sensitive documents without modifying, renaming, or deleting them. | Data Loss Prevention (DLP) tools, access control lists (least privilege), egress traffic filtering. |
| **Corrupted Samba / Kernel** | Zero-day kernel exploits or backdoored Samba binaries bypassing VFS audit hooks. | Regular security patching, vendor updates, minimal software footprint on file servers. |
| **Memory-Only In-Memory Attacks** | Client-side memory tampering or credential dumping on client workstations before SMB operations occur. | Host-based endpoint security (Windows Defender, CrowdStrike, SentinelOne). |

---

## 4. Trade-Offs & Safety Design

Containment systems balancing file availability against ransomware destruction must make deliberate operational trade-offs:

### 4.1 False Positives vs. False Negatives
- **Aggressive blocking** prevents ransomware spread but risks business disruption (e.g., a finance user bulk-compressing quarterly archives might look like high-entropy encryption).
- **Default Shadow Mode:** ShareGuard defaults to `shadow` mode on deployment. In shadow mode, all rules, ML scores, and alerts trigger in full, but network blocks are recorded without applying firewall drops. This permits administrators to establish behavioral baselines and tune allowlists prior to enabling `live` mode.

### 4.2 Auto-Expiring Block TTLs
- Network blocks default to an automatic Time-To-Live (TTL) expiration (typically 60 minutes).
- **Rationale:** Prevents permanent denial-of-service on misidentified workstations or dynamic IP reassignments (DHCP churn). If an infection remains active upon unblock, repeated malicious operations immediately re-trigger containment.

### 4.3 Invariant Non-Blockable Entities
Under no circumstances may ShareGuard block the following IP addresses, regardless of incoming event streams:
- The file server's own network interfaces (`server_ips`).
- The default network gateway (`gateway_ip`).
- Loopback addresses (`127.0.0.1`, `::1`).
- Domain controllers and critical infrastructure explicitly listed in the administrator allowlist.
- Subnet broadcast or multicast addresses.

### 4.4 Global Panic Stop
An administrative escape hatch (`POST /api/panic`) allows instant, single-click flushing of all active ShareGuard blocks and uncouples all firewall intervention, guaranteeing business continuity during misconfiguration or operational emergencies.

---

## 5. Fail-Safe Behaviors & Failure Modes

ShareGuard is designed so that failure of the monitoring tool never degrades the underlying file server's core availability:

```
[Client Traffic] ---> [Samba smbd daemon] ---> [File System]
                              │
                    (vfs_full_audit log)
                              ▼
                      [ShareGuard Engine]
                              │ (Crash / Failure)
                              ▼
               [Engine halts; Samba continues serving]
```

1. **ShareGuard Daemon Crash / Restart:**
   - If ShareGuard crashes or its process is killed, **Samba continues serving files to all non-blocked clients without interruption**.
   - `vfs_full_audit` continues writing to `/var/log/samba/audit.log`. When ShareGuard restarts, it resumes reading from the current log position without dropping file operations.
2. **Firewall / Helper Failure:**
   - All firewall blocks implemented via `deploy/shareguard-helper` are isolated in a dedicated `nftables` table/set (`table inet shareguard`).
   - If `shareguard-helper` or the firewall subagent fails, native Linux firewall operations and existing server connections outside the ShareGuard set remain unaffected.
   - Operators can manually flush all ShareGuard blocks at any time via:
     ```bash
     sudo nft flush table inet shareguard
     ```
3. **Database / ML Model Degradation:**
   - If SQLite or the ML scoring engine becomes unavailable, the system reports `degraded` via `GET /api/status`.
   - The engine continues heuristic and signature-based tracking in memory, maintaining tripwire alert generation.

---

## 6. Foundational Assumptions & Prerequisites

For ShareGuard to provide effective protection, the deployment environment must satisfy the following technical prerequisites:

1. **Samba Configuration Integrity:**
   - The Samba server must have `vfs_full_audit` correctly configured in `smb.conf` with required operations (`openat, close, renameat, unlinkat, write`) and prefix format (`%u|%I|%m|%S`).
   - Audit logs must be rotated safely using standard logrotate (`copytruncate` or file recreation) which ShareGuard's follower tracks seamlessly.
2. **Clock Synchronization (NTP/PTP):**
   - The file server, domain controllers, and network devices must synchronize time via NTP. Timestamps in audit logs and snapshot metadata rely on coherent system time.
3. **Isolated & Immutable Snapshots:**
   - Volume snapshots (ZFS, Btrfs, or rsync-based portable snapshots) must be stored on separate storage pools, read-only mounts, or immutable retention volumes that clients cannot overwrite or delete over SMB.
4. **Least-Privilege Process Execution:**
   - The ShareGuard daemon runs as an unprivileged service user (`shareguard`).
   - Firewall and session termination operations are executed strictly through the dedicated `deploy/shareguard-helper` script authorized via `/etc/sudoers.d/shareguard` with explicit, argument-validated parameters. Shell interpolation (`shell=True`) is strictly prohibited.
