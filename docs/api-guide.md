# ShareGuard API Reference & Architecture Guide

ShareGuard exposes a RESTful API powered by **FastAPI** for real-time ransomware incident management, client isolation, file recovery, and administrative controls.

---

## Authentication & Role-Based Access Control (RBAC)

All endpoints require authentication via `X-API-Key` or `Authorization: Bearer <token>`.

| Role | Default Key / Env | Permissions |
|---|---|---|
| **`admin`** | `SHAREGUARD_ADMIN_KEY` / `SHAREGUARD_API_KEY` (default: `admin-key`) | Full access to action endpoints, settings modification, emergency controls, and audit logs. |
| **`viewer`** | `SHAREGUARD_VIEWER_KEY` (default: `viewer-key`) | Read-only access to alerts, events stream, system settings, and CSV exports. Action endpoints return `403 Forbidden`. |
| **Anonymous** | None | Returns `401 Unauthorized`. |

---

## Endpoint Catalog

### 1. Alert Management & Action Endpoints (Admin Only)

Every administrative action writes an immutable record to the `audit_log` table tracking the username, target, action, result, and timestamp.

- **`POST /api/alerts/{id}/block`**:
  - Drops attacker client IP traffic on SMB ports 139 and 445 via the active responder backend.
  - Body: `{"ttl_seconds": 900, "reason": "Active encryption detected"}` (valid bounds: 10s to 86400s / 24h).
  - Safety Invariant: Refuses to block server IPs, gateway IP, loopback, or allowlisted addresses (returns `400 Bad Request`).
- **`POST /api/alerts/{id}/unblock`**:
  - Removes the firewall drop rule for the client IP and marks client unblocked in the database.
- **`POST /api/alerts/{id}/restore`**:
  - Restores only the files modified or encrypted by the attacker using `PortableSnapshotManager`.
  - Body: `{"dry_run": true, "confirm": false}`
  - Safety Invariant:
    1. `dry_run=true` previews restoration without disk writes and caches results for 15 minutes.
    2. Real restoration (`dry_run=false`) requires **both** `confirm=true` **and** an unexpired prior dry-run completed within the last 15 minutes.
- **`POST /api/alerts/{id}/resolve`**:
  - Marks alert as resolved in DB and clears the active detection incident in the engine.
- **`POST /api/alerts/{id}/false-positive`**:
  - Marks alert as false positive, immediately unblocks client if blocked, and optionally adds client IP to the engine allowlist (`expiry_hours: 24`).

### 2. Emergency Panic Controls (Admin Only)

- **`POST /api/panic`**:
  - Engages global panic-stop: immediately disables and suppresses all active firewall and blocking actions across the engine.
- **`POST /api/panic/clear`**:
  - Clears emergency panic-stop and restores enforcement capability.

### 3. Settings & Configuration

- **`GET /api/settings`** (Viewer or Admin):
  - Returns operating mode (`shadow`, `enforce_temp`, `enforce_strict`), detection thresholds, allowlists, block TTL, and panic stop status.
- **`PUT /api/settings`** (Admin Only):
  - Updates detection thresholds within safe bounds. Rejects unknown keys (`422/400`).
  - Switching to an enforcing mode (`enforce_temp` or `enforce_strict`) requires `confirm=true`.

### 4. Live Events Feed & Streaming

- **`GET /api/events?since=<id>&limit=100`** (Viewer or Admin):
  - Incremental near-live dashboard event stream returning events with sequence ID strictly greater than `since`.
  - Returns `{"events": [...], "latest_id": <int>}` for live UI synchronization.

### 5. Data Export & CSV Injection Defense

- **`GET /api/export/alerts.csv`** (Viewer or Admin):
  - Exports incident records as a downloadable CSV.
  - Formula Injection Protection: Automatically prefixes any cell starting with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote `'` to neutralize spreadsheet macro execution.

### 6. Health & Assistant Explanations

- **`GET /api/health-check`**:
  - Aggregated component health status for `database`, `samba_log`, `ml_model`, `canary_files`, and `snapshot_backend`.
- **`POST /api/assistant/explain/{alert_id}`**:
  - Returns deterministic plain-language incident summary explaining triggered rules, ML score, and recommended next steps.
- **`GET /api/audit?limit=50&offset=0`** (Admin Only):
  - Paginated audit trail of all administrative actions.

---

## Server Binding & Simulation Loop

### Default Local Binding
By default, the API binds to localhost (`127.0.0.1:8000`) for host security:
```powershell
./.venv/Scripts/python.exe -m uvicorn shareguard.api:app --host 127.0.0.1 --port 8000
```

### Allowing Remote Connections (Lab VMs or Network)
To expose the API to other devices or virtual machines:
```powershell
./.venv/Scripts/python.exe scripts/dev.py --host 0.0.0.0 --port 8000
```
Or set environment variables:
```powershell
$env:SHAREGUARD__SERVER__HOST = "0.0.0.0"
$env:SHAREGUARD__SERVER__PORT = "8000"
```

### Running Live Simulation
To start the API with an automated background audit-log simulation replaying normal workloads and periodic attacks:
```powershell
./.venv/Scripts/python.exe scripts/tasks.py sim
```
Or via the dev runner:
```powershell
./.venv/Scripts/python.exe scripts/dev.py --sim
```
Live client records and alerts will begin appearing in the API within seconds.
