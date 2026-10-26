# ShareGuard

**Ransomware guard for small-office Samba (SMB) file servers.**

ShareGuard reads Samba's `vfs_full_audit` log, computes per-client behaviour
features, detects mass-encryption attacks using rules and a machine-learning
model, responds by blocking only the infected client, restores damaged files
from a snapshot, and explains the incident in plain language.
A live Streamlit dashboard shows alerts, clients, and system health.

---

## Quick Start

Prerequisite: Python 3.12. Create venv, install requirements, set credentials, and launch:
- **PowerShell (Windows)**:
  `py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; $env:SHAREGUARD_ADMIN_PASS="AdminPass123!"; .\.venv\Scripts\python.exe scripts/tasks.py sim`
- **Bash (Linux/macOS)**:
  `python3.12 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && export SHAREGUARD_ADMIN_PASS="AdminPass123!" && ./.venv/bin/python scripts/tasks.py sim`
Open **http://127.0.0.1:8501** in your browser (login: `admin` / `AdminPass123!`).


---

## Task Runner (`scripts/tasks.py`)

All commands are run as:

```
./.venv/Scripts/python.exe scripts/tasks.py <command>
```

| Command | Description |
|---|---|
| `setup` | Print dependency installation instructions |
| `test` | Run `pytest server/tests/` |
| `lint` | Run `ruff check .` |
| `api` | Start the FastAPI server (Uvicorn, port 8000) |
| `dashboard` | Start the Streamlit dashboard bound to 127.0.0.1:8501 |
| `sim` | Start API in simulation mode and dashboard together via `scripts/dev.py --sim` |
| `run-sim` | Run real-time detection pipeline on audit log (`server/shareguard/run.py`) |
| `snapshot-demo` | Run snapshot creation, attack, and recovery demo (`server/shareguard/tools/snapshot_demo.py`) |
| `flush-firewall` | Flush ShareGuard firewall rules (emergency undo) |
| `list-blocks` | List active ShareGuard client blocks |
| `build-dataset` | Extract rolling window features from simulated logs to `ml/artifacts/dataset.parquet` |
| `train` | Train ML detector (RandomForest/XGBoost/IsolationForest) with leave-one-attack-style-out CV |
| `evaluate` | Evaluate detector paradigms, generate plots, and compile `docs/ml-report.md` |

---

## Project Structure

```
shareguard/                 ← repo root (workspace root)
├── AGENTS.md               ← contributor & agent rules
├── README.md
├── pyproject.toml          ← project metadata, ruff & pytest config
├── requirements.txt        ← runtime dependencies (pinned)
├── requirements-dev.txt    ← dev/test dependencies (pinned)
├── config/
│   └── default.yaml        ← all configuration (no secrets)
├── scripts/
│   ├── tasks.py            ← task runner (setup/test/lint/api/dashboard/sim/train)
│   └── dev.py              ← start API + dashboard together
├── server/
│   └── shareguard/         ← Python package
│       ├── parser.py       ← vfs_full_audit log parser
│       ├── features.py     ← per-client feature aggregation
│       ├── entropy.py      ← Shannon entropy helpers
│       ├── rules.py        ← rule-based detector
│       ├── ml.py           ← XGBoost/sklearn model wrapper + SHAP
│       ├── engine.py       ← detection orchestrator
│       ├── snapshots.py    ← snapshot interface + fake impl
│       ├── responder.py    ← block interface + fake impl
│       ├── health.py       ← health-check helpers
│       ├── assistant.py    ← plain-language explanation stub
│       ├── api.py          ← FastAPI application
│       ├── db.py           ← SQLAlchemy models + session
│       └── auth.py         ← API-key auth dependency
├── server/tests/
│   └── test_smoke.py       ← trivial import test (CI gate)
├── lab/
│   ├── simulate_log.py     ← generates fake audit-log lines
│   ├── fake_ransomware.py  ← lab-only encryption simulator (marker-file guarded)
│   ├── collect.py          ← feature collection for ML dataset
│   ├── sample_audit.log    ← example log lines
│   └── workloads/          ← workload scripts
├── ml/
│   ├── build_dataset.py    ← builds labelled DataFrame from collected features
│   ├── train.py            ← trains XGBoost model
│   ├── evaluate.py         ← evaluates saved model
│   └── artifacts/          ← saved models (gitignored)
├── dashboard/
│   ├── app.py              ← Streamlit entry point (login gate + st.navigation)
│   ├── api_client.py       ← HTTP client with per-session TTL cache
│   ├── auth.py             ← session-state authentication & RBAC
│   ├── ui.py               ← UI helpers & strict XSS safe_text rendering
│   ├── views/
│   │   ├── overview.py     ← executive system status & live telemetry
│   │   ├── alerts.py       ← paginated incident alerts
│   │   ├── alert_detail.py ← deep-dive investigation & admin actions
│   │   ├── clients.py      ← monitored clients & active blocks
│   │   ├── health.py       ← subsystem component health
│   │   └── settings.py     ← detection policy & panic controls
│   ├── .streamlit/
│   │   └── config.toml     ← dark theme, port 8501, security settings
│   └── README.md           ← dashboard guide & lab exposure warnings
└── .github/workflows/
    └── ci.yml              ← ruff + pytest on every push/PR
```

---

## Run Modes

| Mode | Description |
|---|---|
| **SIMULATION** | Default. Generated logs, no root, works everywhere. |
| **LIVE** | Real Samba on Ubuntu. Needs `sudo` for blocking/snapshots. Never use in CI. |

---

## Safety Defaults

- Response mode: **shadow** (alert-only; never blocks by default)
- Blocks auto-expire after **15 minutes**
- Server/gateway/allowlisted IPs are **never blocked**
- `shell=True` is **never used**

---

## Audit Log Simulator (`lab/simulate_log.py`)

The simulator generates synthetic Samba `vfs_full_audit` log lines for testing detection models and rules. It never touches, creates, or encrypts real files on disk.

```powershell
# Run a 60-second fast attack simulation at 10x accelerated speed
./.venv/Scripts/python.exe -m lab.simulate_log --scenario attack_fast --duration 60 --speed 10 --out audit_sim.log

# Generate normal office workload
./.venv/Scripts/python.exe -m lab.simulate_log --scenario normal_office --duration 120 --speed 5 --out audit_normal.log

# Print directly to stdout (useful for piping into engine/stream)
./.venv/Scripts/python.exe -m lab.simulate_log --scenario attack_rename_only --duration 30 --speed 50

# Specify custom labels CSV output path
./.venv/Scripts/python.exe -m lab.simulate_log --scenario attack_copy_delete --duration 60 --out lab/audit.log --labels lab/labels.csv
```

### Supported Scenarios

| Scenario | Type | Description |
|---|---|---|
| `normal_office` | Benign | Multi-user document opening and saving |
| `normal_bulk_copy` | Benign | Single user copying thousands of files (no renames) |
| `normal_zip` | Benign | Reading many files then writing an archive |
| `normal_backup` | Benign | Sequential read-through of all files |
| `normal_dev` | Benign | Rapid create/unlink of code files |
| `attack_fast` | Attack | High-rate open-write + rename to `.locked`, drops ransom notes, touches canary |
| `attack_slow` | Attack | Low-and-slow variant spread over time |
| `attack_partial` | Attack | Opens for write in many dirs without renaming |
| `attack_rename_only` | Attack | Rapid mass rename without writes |
| `attack_copy_delete` | Attack | Writes encrypted copies then deletes originals |

---

## Log Parser (`server/shareguard/parser.py`)

Parses Samba `vfs_full_audit` logs into structured `AuditEvent` dataclasses.

- Supports both short prefix (`user|ip|...`) and full prefix (`user|ip|machine|share|...`).
- Handles ISO-8601 and syslog timestamps (with automatic year inference).
- `follow(path)` tails a log file like `tail -F` on Windows and Linux, detecting rotation and truncation.
---

## Real-Time Detection Engine (`server/shareguard/engine.py` & `shareguard.run`)

Processes live or replayed Samba `vfs_full_audit` event streams through a per-client state machine:

- **State Transitions**: `NORMAL -> SUSPICIOUS` (ML prob $\ge 0.6$ or rule score $\ge 0.5$) $\to$ `ATTACK` (2 of last 3 windows above attack threshold, or canary touched) $\to$ `RESOLVED` (admin unblock or quiet window timeout) / `NORMAL` (after $M$ quiet windows).
- **Incident Tracking**: Records time-to-detect, plain-language rule reasons, ML probability and SHAP top features, and bounded list of touched files for restore calculations.
- **Response Modes**: `shadow` (default alert-only; records `would_have_blocked`), `enforce_temp` (temporary block with auto-expiry TTL), `enforce_strict` (permanent block until admin unblock). Configurable via `SHAREGUARD_MODE`.
- **Snapshot Safety**: Automatically pauses filesystem snapshots whenever any client is in `SUSPICIOUS` or `ATTACK` state, and resumes once all clients are clear.
- **Safety Invariants**: Server IPs, gateway, backup daemon, and allowlisted addresses are never blocked. Global panic-stop switch disables actions at runtime. File names are treated as untrusted text.

Run the real-time timeline demo CLI:
```powershell
./.venv/Scripts/python.exe -m shareguard.run --sim audit_sim.log --speed 10 --mode shadow
```

## Active Response & Firewall Subsystem (`server/shareguard/responder.py`)

ShareGuard features an automated active response subsystem that neutralizes rogue clients attempting mass encryption:

- **Targeted SMB Blocking**: Drops traffic from attacker IPs on **ports 139 and 445 ONLY**. Administrator SSH (port 22) and other services remain fully functional.
- **Backends**:
  - `nftables` (preferred on modern Linux): Uses a dedicated `table inet shareguard` with sets supporting per-element native timeouts (`timeout <ttl>s`). Blocks auto-expire even if ShareGuard terminates.
  - `iptables` (fallback): Inserts top-of-INPUT drop rules tagged with comment `shareguard`.
  - `FakeResponder`: In-memory implementation for deterministic, zero-I/O testing and simulations.
- **Session Termination (`kill_sessions`)**: Queries `smbstatus --json` (or `smbstatus -p`) and terminates only the smbd worker processes associated with the malicious IP via graceful `SIGTERM` followed by `SIGKILL`.
- **Privileged Root Helper (`deploy/shareguard-helper`)**: Allows running the core daemon without root privileges. The helper re-validates all parameters internally (`ipaddress`, TTL bounds, injection rejection) and communicates through a secure sudoers entry (`deploy/sudoers.d/shareguard`).
- **Emergency Flush**: Instantly restores network access by clearing ShareGuard rules via `python scripts/tasks.py flush-firewall` or `shareguard-helper flush`.

---

## Snapshot Manager & Recovery (`server/shareguard/snapshots.py`)

ShareGuard integrates an automated snapshot lifecycle and surgical rollback engine to protect SMB file shares against ransomware encryption:

- **Backends**:
  - `PortableSnapshotManager`: Pure Python file copies and hard links (cross-platform, works on Windows, macOS, Linux).
  - `RsyncSnapshotManager`: Linux incremental snapshots with `rsync -a --delete --link-dest` via a `CommandRunner` abstraction (always `shell=False`, argument lists only).
  - `FakeSnapshotManager`: In-memory backend for deterministic, zero-I/O testing and simulations.
- **Safety Invariants**:
  - **Path Traversal Protection**: Every path argument is strictly validated to ensure it cannot escape the share root or snapshot root. Directory traversal (`..`), absolute paths, and foreign drive letters are rejected.
  - **Anomaly Pause Lock**: Snapshots are automatically paused during `SUSPICIOUS` or `ATTACK` states. Snapshots will refuse to run while paused to prevent backing up encrypted files.
  - **Clean Snapshot Retention**: Anomaly retention locks protect pre-attack clean snapshots from deletion during retention pruning.
  - **Surgical Restores**: Only files touched or renamed by the attacker are restored. Untouched files and newer legitimate user edits (`skipped: newer user change`) are preserved.
  - **Locked File Cleanup**: Encrypted `.locked` or `.crypto` files are only removed after their restored clean counterpart verifies against the snapshot manifest SHA-256.
  - **Dry Run by Default**: `dry_run=True` is the default across all restore operations to preview changes before any disk modifications occur.

### Running the Recovery Demo

Simulate an end-to-end attack and test surgical recovery:
```powershell
./.venv/Scripts/python.exe scripts/tasks.py snapshot-demo
```
Or directly via the tool module:
```powershell
./.venv/Scripts/python.exe -m shareguard.tools.snapshot_demo --num-files 50
```

---

## FastAPI Backend & Management API (`server/shareguard/api.py`)

ShareGuard provides an active incident response and management API with role-based authentication (`admin` vs `viewer`):

- **Action Endpoints (`admin` only)**:
  - `POST /api/alerts/{id}/block`: Drops SMB traffic on ports 139 and 445; protects server/gateway/allowlist IPs.
  - `POST /api/alerts/{id}/unblock`: Re-enables client network access.
  - `POST /api/alerts/{id}/restore`: Restores attacker-damaged files from clean snapshots. `dry_run=true` previews changes; real restore requires `dry_run=false`, `confirm=true`, and an unexpired prior dry-run.
  - `POST /api/alerts/{id}/resolve`: Closes alert and resolves detection state machine incident.
  - `POST /api/alerts/{id}/false-positive`: Marks alert as false positive, unblocks client, and adds IP to allowlist.
  - `POST /api/panic` & `POST /api/panic/clear`: Global panic stop switch to immediately suppress or restore enforcement.
- **Settings (`GET` viewer, `PUT` admin)**:
  - `GET /api/settings` & `PUT /api/settings`: Manages mode, bounds-checked thresholds, and allowlists. Switching to enforcing mode requires `confirm=true`.
- **Live Event Stream**:
  - `GET /api/events?since=<id>`: Streams sequential engine events for real-time dashboard visualization.
- **Export & Security**:
  - `GET /api/export/alerts.csv`: Downloadable incident log fortified against CSV/formula injection attacks.
  - `GET /api/audit`: Immutable, paginated audit log of all administrative actions.

### Launching API & Live Simulation

Start the API with an automated background simulation loop replaying normal and attack traffic:
```powershell
./.venv/Scripts/python.exe scripts/tasks.py sim
```
Or launch both API and Streamlit dashboard together via the dev runner:
```powershell
./.venv/Scripts/python.exe scripts/dev.py --sim
```
See [docs/api-guide.md](docs/api-guide.md) for full endpoint schemas and network binding options.

---

## Local Plain-Language Incident Assistant (Ollama)

ShareGuard includes a 100% local, plain-language incident assistant (`server/shareguard/assistant.py`) powered by Ollama. It summarizes ransomware incidents in simple terms for office staff, provides step-by-step checklists, cites grounded response playbooks (`docs/knowledge/`), and drafts incident reports.

**Privacy & Safety Invariants:**
- Zero cloud APIs, zero external telemetry: all prompts and audit data stay strictly on your local network.
- The assistant has NO access to containment responders or disk snapshot tools; it cannot execute commands or modify firewall rules.
- Untrusted file names from audit logs are escaped, truncated, and strictly delimited inside data blocks to prevent prompt injection.
- If Ollama is offline or times out, ShareGuard automatically falls back to deterministic template guidance.

### 1. Installing Ollama on Windows
1. Download the Windows installer from [ollama.com/download](https://ollama.com/download) and run the installer.
2. Verify installation by running in PowerShell:
   ```powershell
   ollama --version
   ```

### 2. Pulling the Required Models
ShareGuard uses a lightweight language model for advisory text and an embedding model for semantic playbook retrieval:
```powershell
# 1. Pull the default language model (~2.0 GB download)
ollama pull llama3.2:3b

# 2. Pull the embedding model (~270 MB download)
ollama pull nomic-embed-text
```

### 3. Low-RAM Alternatives
If your server or workstation has limited RAM (e.g. 8 GB or less), you can configure ShareGuard to use smaller, faster models:
- **`llama3.2:1b`** (~1.3 GB RAM): Fast, compact model suitable for entry-level hardware.
- **`qwen2.5:1.5b`** (~1.5 GB RAM): High-efficiency alternative with strong instruction-following.

To switch models, set the environment variable:
```powershell
$env:SHAREGUARD_LLM_MODEL = "llama3.2:1b"
```

### 4. Reaching Ollama from Virtual Machines (Lab Environment)
When running ShareGuard inside an Ubuntu lab VM while Ollama runs on your Windows host:
1. **Configure Host Binding**: By default, Ollama binds only to `127.0.0.1:11434`. To allow access from your VM, set the environment variable on your Windows host and restart Ollama:
   ```powershell
   # Set Ollama to bind to the host-only network adapter
   [System.Environment]::SetEnvironmentVariable('OLLAMA_HOST', '192.168.56.1:11434', 'User')
   ```
2. **Point ShareGuard in the VM to Host**:
   ```bash
   export SHAREGUARD_OLLAMA_URL="http://192.168.56.1:11434"
   ```

> [!WARNING]
> **Firewall & Security Exposure:**
> Do NOT set `OLLAMA_HOST=0.0.0.0` on untrusted networks or machines exposed directly to the public Internet, as Ollama does not include built-in authentication. Always restrict binding to your private Host-Only network adapter (`192.168.56.1`) or place it behind an authenticated reverse proxy.

---

## System Health Diagnostics & Recovery Drills

ShareGuard provides comprehensive proactive health inspection across 9 critical file server defense layers, accessible via **Dashboard → Health** or `GET /api/health-check`:

### 1. The 9 Subsystem Diagnostic Probes
| ID | Probe | What it checks | Failure Impact |
|---|---|---|---|
| `audit_logging` | Samba Audit Logging | `vfs objects = full_audit` present in `smb.conf`; log file exists and has entries within 24h. | High |
| `smb_protocol` | SMB Protocol Version | Disables legacy `SMB1`/`NT1`/`LANMAN` via `server min protocol = SMB2`. | High |
| `guest_access` | Guest & Anonymous Access | Disallows `guest ok = yes` on shares and `map to guest = Bad User` in global. | Medium |
| `snapshots` | Snapshot Boundaries | Snapshots exist, newest is < 24h old, and snapshot storage is strictly outside share roots. | High |
| `restore_test` | Automated Restore Drill | Verifies whether recent synthetic recovery drills passed without file corruption. | High |
| `canary_files` | Canary Tripwires | Verifies that bait decoy files across share roots are present and uncorrupted. | High |
| `disk_space` | Storage Free Space | Alerts if share or backup volume free space drops below 15% (or critical < 5%). | Medium |
| `network_exposure` | Network Exposure | Observes listening ports (139/445) and checks if host firewall (UFW/nftables) is active. | Medium |
| `safety_settings` | Engine Safety Controls | Verifies allowlist has server & gateway IPs, panic stop status, and database health. | High |

### 2. Weighted Scoring & Verdicts
- **Score (0–100%)**: Probes are assigned weighted values configured in `config/default.yaml`. Any probe reporting `unknown` is **strictly excluded** from both earned and possible points so offline or unconfigured checks do not artificially penalize the score.
- **Verdicts**:
  - 🟢 **Good**: Score ≥ 80% with all high-severity probes passing.
  - 🟡 **Needs attention**: Score between 60% and 80%, or warnings present.
  - 🔴 **At risk**: Score < 60%, or any high-severity probe in a failed state.

### 3. Non-Destructive Restore Drills
Backups are only valuable if they can be recovered. ShareGuard includes a synthetic recovery engine:
1. **Isolated Testing**: Copies sample files from the newest snapshot into a temporary directory (never into live shares).
2. **Cryptographic Verification**: Re-computes SHA-256 digests and validates against `manifest.json`.
3. **Automatic Cleanup**: Deletes the temporary directory and logs duration and file count.
4. **On-Demand & Scheduled**:
   - Administrators can trigger on-demand drills via the dashboard **Run restore test** button (rate-limited to 1 drill per minute) or `POST /api/health-check/restore-test`.
   - A background scheduler executes weekly automatic restore drills (`RestoreTestScheduler`).

---

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull request:

1. `ruff check .`
2. `pytest server/tests/ lab/tests/`

---

## Contributing

See `AGENTS.md` for the full rule set.
