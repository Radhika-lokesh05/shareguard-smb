# ShareGuard Lab Guide (1-VM Architecture)

> **Audience**: Security researchers and developers collecting real SMB audit datasets.  
> **Architecture**: **ONE Ubuntu Server VM** running Samba + **Windows host** acting as the client machine (`client-pc`).  
> **Network Share**: Mapped as `Z:` on Windows (`net use Z: \\192.168.56.101\Finance`).  
> **Target Subfolder**: `Z:\sgtest` (isolated subfolder).

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Server VM Setup (Ubuntu Samba)](#2-server-vm-setup-ubuntu-samba)
3. [Windows Client Setup (Mapping Z:)](#3-windows-client-setup-mapping-z)
4. [Safety Configuration (lab/config.yaml)](#4-safety-configuration-labconfigyaml)
5. [Seed Fake Files](#5-seed-fake-files)
6. [Run Data Collection](#6-run-data-collection)
7. [Retrieve Audit Log & Build Dataset](#7-retrieve-audit-log--build-dataset)
8. [VM Snapshots (VirtualBox & virsh)](#8-vm-snapshots-virtualbox--virsh)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Architecture Overview

```
+--------------------------------------------------------------+
| Windows Host (Client PC: client-pc)                         |
| - Mapped share: Z: (\\192.168.56.101\Finance)               |
| - Target directory: Z:\sgtest                               |
| - Lab tools: lab.make_fake_files, lab.collect, workloads    |
| - Python 3.12 (.venv)                                       |
+--------------------------------------------------------------+
                               |
                   SMB Traffic | (Host-Only Network 192.168.56.0/24)
                               v
+--------------------------------------------------------------+
| Ubuntu Server VM (192.168.56.101)                            |
| - Samba service (smbd) with vfs_full_audit                   |
| - Share: /srv/shares/Finance                                 |
| - Audit log: /var/log/samba/audit.log                        |
+--------------------------------------------------------------+
```

### Clock Independence with Audit Markers
Windows and VM system clocks inevitably drift. ShareGuard does **not** rely on clock synchronization. Instead:
1. `collect.py` creates empty marker file `__sg_start_<run_id>` on `Z:\sgtest` before each run.
2. The Samba server logs the creation in `audit.log` with microsecond-accurate server timestamps.
3. `collect.py` performs the workload or simulated attack.
4. `collect.py` creates `__sg_end_<run_id>` after the run.
5. `ml/build_dataset.py` extracts exact interval boundaries from the server's audit log, ignoring marker touches during feature extraction.

---

## 2. Server VM Setup (Ubuntu Samba)

### 2.1 Network Setup (VirtualBox Host-Only Adapter)
In VirtualBox:
- Add Adapter 1: NAT (for internet).
- Add Adapter 2: Host-Only (`vboxnet0`, IP `192.168.56.101/24`).

### 2.2 Install Samba & Tools
```bash
sudo apt update
sudo apt install -y samba rsyslog
```

### 2.3 Create Lab Share & User
```bash
sudo useradd -M -s /sbin/nologin officeuser
sudo smbpasswd -a officeuser      # Enter password, e.g. LabPass123!
sudo smbpasswd -e officeuser

sudo mkdir -p /srv/shares/Finance
sudo chown -R officeuser:officeuser /srv/shares/Finance
sudo chmod 0770 /srv/shares/Finance
```

### 2.4 Configure Samba with `vfs_full_audit`
Edit `/etc/samba/smb.conf`:

```ini
[global]
   workgroup = WORKGROUP
   server string = ShareGuard Samba Lab
   security = user
   map to guest = never
   log file = /var/log/samba/log.%m
   max log size = 1000

   # vfs_full_audit configuration
   vfs objects = full_audit
   full_audit:prefix = %u|%I|%m|%S
   full_audit:success = openat renameat unlinkat mkdirat close
   full_audit:failure = none
   full_audit:facility = LOCAL7
   full_audit:priority = NOTICE

[Finance]
   path = /srv/shares/Finance
   valid users = officeuser
   read only = no
   browseable = yes
   create mask = 0660
   directory mask = 0770
```

### 2.5 Configure rsyslog for Audit Logging
Create `/etc/rsyslog.d/40-samba-audit.conf`:
```
local7.notice    /var/log/samba/audit.log
```

Apply and start services:
```bash
sudo systemctl restart rsyslog
sudo systemctl restart smbd nmbd
sudo ufw allow samba
```

Verify audit logging:
```bash
tail -f /var/log/samba/audit.log
```

---

## 3. Windows Client Setup (Mapping Z:)

On the Windows host in PowerShell:

```powershell
# Map the Samba share to drive letter Z:
net use Z: \\192.168.56.101\Finance /user:officeuser LabPass123! /persistent:no

# Create isolated lab subfolder
New-Item -ItemType Directory -Path "Z:\sgtest" -Force
```

To disconnect when finished:
```powershell
net use Z: /delete /y
```

---

## 4. Safety Configuration (lab/config.yaml)

To prevent accidental execution against personal or production folders, ShareGuard requires setting `allowed_target_prefix` in `lab/config.yaml`:

```yaml
# lab/config.yaml
allowed_target_prefix: "Z:\\sgtest"
pause_between_runs_seconds: 5.0
client_machine_name: "client-pc"
```

Alternatively, set the environment variable:
```powershell
$env:SHAREGUARD_LAB_ALLOWED_PREFIX = "Z:\sgtest"
```

All lab tools will refuse execution if:
- Target is a drive root (e.g. `Z:\`, `C:\`, `/`).
- Target is a user profile folder (Desktop, Documents, etc.).
- Target contains `..` path traversal.
- Target does not contain `.shareguard_lab_marker`.
- Target is not inside `allowed_target_prefix`.
- `--i-understand-this-is-a-lab` is omitted.

---

## 5. Seed Fake Files

From the workspace root, run `make_fake_files`:

```powershell
./.venv/Scripts/python.exe -m lab.make_fake_files --target Z:\sgtest --count 200 --i-understand-this-is-a-lab
```

Verify the generated SHA-256 manifest:
```powershell
./.venv/Scripts/python.exe -m lab.make_fake_files --target Z:\sgtest --verify --i-understand-this-is-a-lab
```

---

## 6. Run Data Collection

### 6.1 Preview the Plan (Dry Run)
Check the collection plan without modifying files:
```powershell
# Default plan (40 attacks across all styles + 200 min normal work)
./.venv/Scripts/python.exe -m lab.collect --target Z:\sgtest --dry-run

# Quick smoke test plan (~15 min)
./.venv/Scripts/python.exe -m lab.collect --target Z:\sgtest --quick --dry-run
```

### 6.2 Execute Quick Collection (~15 min)
```powershell
./.venv/Scripts/python.exe -m lab.collect --target Z:\sgtest --quick --i-understand-this-is-a-lab
```

### 6.3 Execute Full Collection (~4 hours)
```powershell
./.venv/Scripts/python.exe -m lab.collect --target Z:\sgtest --i-understand-this-is-a-lab
```

### 6.4 Run Individual Workloads Directly
Workloads can also be run standalone:
```powershell
# Run office editing workload for 60 seconds
./.venv/Scripts/python.exe -m lab.workloads.office_edit --target Z:\sgtest --duration 60 --i-understand-this-is-a-lab

# Run bulk copy workload
./.venv/Scripts/python.exe -m lab.workloads.bulk_copy --target Z:\sgtest --duration 60 --i-understand-this-is-a-lab
```

### 6.5 Clean Interruption
Press `Ctrl+C` at any time. `collect.py` catches the signal, safely restores all encrypted files using `manifest.json`, flushes `labels.csv`, and exits cleanly.

---

## 7. Retrieve Audit Log & Build Dataset

### 7.1 Pull the Audit Log from the VM
From Windows PowerShell:
```powershell
scp officeuser@192.168.56.101:/var/log/samba/audit.log ./audit_lab.log
```

### 7.2 Build the ML Dataset
Run `build_dataset.py`, which derives ground truth intervals from the marker files:
```powershell
./.venv/Scripts/python.exe -m ml.build_dataset --log audit_lab.log --labels labels.csv --out ml/artifacts/dataset_lab.parquet
```

The dataset extractor:
- Parses `__sg_start_<run_id>` and `__sg_end_<run_id>` timestamps directly from `audit_lab.log`.
- Discards marker file events from feature calculation.
- Outputs windowed feature vectors labelled with high-precision ground truth.

---

## 8. VM Snapshots (VirtualBox & virsh)

Always snapshot your Ubuntu server VM before collections so it can be restored to a pristine state.

### 8.1 VirtualBox (from Windows PowerShell)
```powershell
# Create snapshot
VBoxManage snapshot "UbuntuSamba" take "clean-samba-baseline" --description "Configured Samba with vfs_full_audit"

# Restore snapshot
VBoxManage controlvm "UbuntuSamba" poweroff
VBoxManage snapshot "UbuntuSamba" restore "clean-samba-baseline"
VBoxManage startvm "UbuntuSamba" --type headless
```

### 8.2 KVM / virsh (if running Linux KVM)
```bash
virsh snapshot-create-as --domain UbuntuSamba --name clean-samba-baseline --description "Configured Samba"
virsh snapshot-revert UbuntuSamba clean-samba-baseline
```

---

## 9. Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| `LabSafetyError: allowed_target_prefix is empty` | Missing prefix configuration | Add `allowed_target_prefix: "Z:\\sgtest"` to `lab/config.yaml` or set `$env:SHAREGUARD_LAB_ALLOWED_PREFIX`. |
| `System error 67 has occurred. The network name cannot be found.` | Samba share name incorrect or network down | Test ping to VM IP: `ping 192.168.56.101`. Verify share name `[Finance]` in `smb.conf`. |
| `PermissionError: [WinError 32] The process cannot access the file` | Windows SMB file lock | Lab tools automatically retry with exponential backoff via `retry_on_windows_busy()`. |
| Missing end marker warning in dataset build | Workload terminated abruptly before end marker was flushed | Check `audit.log` around the run timestamp or supply fallback timestamps in `labels.csv`. |
