# ShareGuard Dashboard

Pure-Python Streamlit management interface for the ShareGuard ransomware detection system.

---

## Architecture

The dashboard is strictly an API **client** of the ShareGuard FastAPI backend (`http://127.0.0.1:8000/api`).

```
+--------------------------------------------------------------+
|                    Streamlit Dashboard                       |
|           (dashboard/app.py & dashboard/views/)              |
|                                                              |
|   +-------------------+              +-------------------+   |
|   |   Login Gate      |              |   UI Components   |   |
|   | (dashboard/auth)  |              |  (dashboard/ui)   |   |
|   +---------+---------+              +-------------------+   |
|             |                                                |
|             v                                                |
|   +------------------------------------------------------+   |
|   |         API Client (dashboard/api_client.py)         |   |
|   |   - Per-session TTL cache in st.session_state        |   |
|   |   - Zero shared st.cache_data / st.cache_resource    |   |
|   |   - JWT held in st.session_state memory only         |   |
|   +---------------------------+--------------------------+   |
+-------------------------------|------------------------------+
                                |  HTTP / REST (Bearer Auth)
                                v
+--------------------------------------------------------------+
|                     FastAPI Backend                          |
|                 (server/shareguard/api.py)                   |
|                                                              |
|   - Real-time Detection Pipeline                             |
|   - Active Firewall Responder & Canary Enforcement           |
|   - SQLite Database & Portable Snapshot Recovery             |
+--------------------------------------------------------------+
```

### Security Invariants
- **No Direct System Access**: The dashboard never accesses the SQLite database, raw Samba logs, firewall rules, or snapshot files directly.
- **In-Memory Authentication**: Authentication credentials and Bearer tokens are stored solely in `st.session_state`. They are never written to disk, logged, or exposed in URL query parameters.
- **Cache Isolation**: `st.cache_data` and `st.cache_resource` are strictly avoided for API responses because they are shared across distinct user sessions and could leak data. A lightweight per-session dictionary cache with a 3-second TTL is maintained inside `st.session_state`.
- **Strict Untrusted String Rendering**: File names and telemetry originating from logs/alerts are treated as untrusted text. They are rendered exclusively via `st.text`, `st.code`, or `st.dataframe`. `st.markdown` and `unsafe_allow_html=True` are prohibited for untrusted strings to eliminate XSS risks (`<img onerror>`, `![x]()`, `[click]()`).
- **Role-Based Visibility**: The user role is resolved by the FastAPI backend on login (`/api/auth/login`). Admin-only containment buttons (Block, Restore, Resolve, Panic Stop) are hidden for viewers.

---

## Running the Dashboard

### 1. Standalone
Start the Streamlit dashboard bound to localhost on port 8501:

```powershell
./.venv/Scripts/python.exe scripts/tasks.py dashboard
```

### 2. Full Simulation Environment (Recommended)
Start both the FastAPI backend (with continuous log replay simulation) and the Streamlit dashboard together:

```powershell
./.venv/Scripts/python.exe scripts/tasks.py sim
```
This command polls the API until ready, prints the dashboard URL and session credentials, and terminates both processes cleanly on `Ctrl+C`.

---

## Network Binding & Lab Exposure (`--server.address 0.0.0.0`)

By default, the dashboard binds exclusively to the loopback interface (`127.0.0.1:8501`):

```powershell
./.venv/Scripts/python.exe -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

### Exposing to Lab Virtual Machines
To allow browser connections from other workstations or lab virtual machines:

```powershell
./.venv/Scripts/python.exe -m streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port 8501
```

> [!WARNING]
> **Why Network Exposure Requires Extreme Care:**
> - Binding to `0.0.0.0` exposes the management dashboard to every host on the physical or virtual network adapter.
> - Anyone with network reachability can access the login interface and submit authentication attempts.
> - **Never expose `0.0.0.0` on untrusted networks or the public Internet.** In production or lab environments, always place the dashboard behind an authenticated reverse proxy (e.g. NGINX, Traefik, or Caddy) enforcing HTTPS/TLS encryption and strict firewall access control lists (ACLs).

---

## Dashboard Pages & Features

### 1. Overview (`dashboard/views/overview.py`)
- **System Status Banner**: Displays prominent icon + text status (`🟢 All clear`, `🟡 Suspicious activity`, `🔴 Attack in progress`, or `⏹️ Panic Stop`). Explicitly surfaces `SHADOW MODE` notice when passive monitoring is enabled.
- **Key Metrics Row**: Active Clients, Alerts Today, Files Protected, and Snapshot Age (with warnings for stale snapshots).
- **Live Activity Chart**: Real-time Plotly graph plotting file operations/sec and ML anomaly risk per client over the previous 15 minutes.
- **Incident Cards & Monitored Clients**: Top active client connections and latest 5 incident cards with one-click drill-down to investigation view.

### 2. Alerts Feed (`dashboard/views/alerts.py`)
- **Filtering & Search**: Status selector (open, resolved, false_positive), client IP selector, time window filter, and keyword search across usernames, rules, and affected file paths.
- **CSV Export**: Direct streaming export from the `/api/export/alerts.csv` endpoint defending against spreadsheet formula injection.
- **Paged Table & Inspector**: 5 key columns (*ID*, *Time*, *Client IP*, *Severity*, *State*), row-level expansion drawers displaying touched files and rules, and pagination controls.

### 3. Alert Detail & Response (`dashboard/views/alert_detail.py`)
- **Query Parameter Linking**: Directly accessible via `?alert=<id>`, with graceful fallback for invalid or missing incident identifiers.
- **Incident Timeline**: Chronological progression from first anomaly to detection, containment, restoration, and resolution, complete with Time-to-Detect (TTD) metrics.
- **Explainability**: Horizontal Plotly bar chart depicting SHAP feature contributions (pushing toward normal vs. attack) and plain-language rule descriptions.
- **Affected File Artifacts**: Paged list of touched file paths rendered strictly as unformatted text (`safe_text`).
- **Two-Step Snapshot Restoration**: Admin-only restoration flow requiring a dry-run preview calculation (reverted count, skipped count, total bytes) before confirming in a modal dialog (`@st.dialog`).
- **Administrator Containment**: Block client with configurable TTL, unblock client, mark false positive with allowlisting, and invoke the natural language incident explanation assistant.

### 4. Monitored Clients (`dashboard/views/clients.py`)
- **Live Connection Telemetry**: Real-time listing of active SMB client connections, session usernames, connection times, and active firewall blocks.
- **Client Drill-down & Timeline**: Dropdown selector to inspect individual clients with dedicated current state metrics.
- **Incident History & Activity Chart**: Responsive Plotly timeline chart displaying anomaly risk scores and incident frequency over time for the selected client.
- **Safe Text Invariant**: Client usernames and IPs rendered strictly through `safe_text` and dataframes.

### 5. System Health (`dashboard/views/health.py`)
- **Diagnostic Probes Checklist**: Subsystem status for database, Samba audit log stream, machine learning models, canary bait files, and snapshot backend.
- **Accessible Indicators**: Accessible icon + text badges (`✅ Pass`, `⚠️ Warn`, `❌ Fail`, `❔ Unknown`).
- **Placeholder State Handling**: Gracefully handles and explains backend placeholder telemetry returned by `/api/health-check`.
- **Plain-Words Fix Guides**: Expandable troubleshooting steps for every subsystem detailing common failure causes and resolution procedures.
- **Automated Restore Drill**: Admin button to initiate synthetic restore verification drills with informational fallback when endpoints are pending.

### 6. Settings & Policy Management (`dashboard/views/settings.py`)
- **Role-Based Access Control**: Viewers see read-only settings with disabled inputs; administrators have full policy control.
- **Emergency Panic Controls**: High-visibility panic stop button to immediately halt all active containment blocks, and resume enforcement button.
- **Operating Mode Selector**: Switch between `shadow`, `enforce_temp`, and `enforce_strict` modes with a mandatory `@st.dialog` confirmation modal explaining enforcing mode risks in plain language.
- **Safe Threshold Bounds**: Slider and number controls strictly bounded within API validation ranges (ML confidence, rename rates, delete rates, write rates, Shannon entropy).
- **Protected IP Allowlist**: Allowlist editor with stdlib `ipaddress` validation on input and configurable expiration intervals.
- **Administrative Audit Trail**: Paged table for administrators tracking configuration changes, panic state transitions, and operator interventions.

---

## Testing

Run the dashboard automated test suite with `pytest`:

```powershell
./.venv/Scripts/python.exe -m pytest server/tests/test_dashboard.py
```
Tests utilize `streamlit.testing.v1.AppTest` with in-memory API client mocking for deterministic execution in under 2 seconds.
