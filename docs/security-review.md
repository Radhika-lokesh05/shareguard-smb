# ShareGuard – Comprehensive Security Review

**Review Date:** October 2026  
**Auditor:** Automated Security Reviewer  
**Scope:** Entire repository (`server/`, `dashboard/`, `deploy/`, `lab/`, `scripts/`, `config/`, documentation)  
**Security Standard:** Principle of Least Privilege, Defense in Depth, Fail-Safe Defaults  

---

## Executive Summary

ShareGuard has solid architectural boundaries:
- Zero instances of `shell=True` in subprocess calls.
- Read-only diagnostic probes.
- Strict IP validation via `ipaddress` for blocking and response actions.
- Built-in dry-run snapshot recovery guards.

However, a thorough audit across authentication, path traversal, API middleware, secrets management, and helper scripts revealed several vulnerabilities and hardening opportunities that must be addressed before deployment.

---

## Security Findings Matrix

| Finding ID | Severity | File & Location | Vulnerability Category | Summary |
|---|---|---|---|---|
| **SG-SEC-01** | **High** | `server/shareguard/health.py:1184-1189` | Path Traversal | Synthetic restore drill copies files without validating destination paths remain within ephemeral tempdir |
| **SG-SEC-02** | **High** | `server/shareguard/auth.py:48-52` | Broken Authentication | Default static keys (`admin-key`) used without requiring custom secrets in LIVE mode |
| **SG-SEC-03** | **High** | `server/shareguard/auth.py:128-150` | Insecure Credential Storage | Plaintext password comparison used instead of salted cryptographic hashes |
| **SG-SEC-04** | **High** | `server/shareguard/api.py:530-540` | Brute Force / DoS | Login endpoint lacks rate limiting and lockout mechanism |
| **SG-SEC-05** | **Medium** | `server/shareguard/canary.py:131` | Path Traversal | Decoy target file path not validated against `share_root` boundary |
| **SG-SEC-06** | **Medium** | `server/shareguard/api.py:381` | Insecure Headers / CORS | Missing CORS allowlist, security headers middleware, and request body size limiter |
| **SG-SEC-07** | **Medium** | `server/shareguard/api.py:560,750` | Input Validation | Missing strict `ipaddress` validation on alert queries and client unblocking endpoints |
| **SG-SEC-08** | **Medium** | `deploy/shareguard-helper:72-133` | Firewall Bypass / Incomplete Config | `init_nftables` fails to initialize `blocked_ips_v6` set and rule for IPv6 drop |
| **SG-SEC-09** | **Medium** | `deploy/shareguard-helper:225-245` | Privilege Escalation / Unchecked Kill | Helper kills PIDs matching IP string from `smbstatus` without verifying process name is `smbd` |
| **SG-SEC-10** | **Low** | Workspace root | Secrets Hygiene | Missing `.env.example` template for configuration |
| **SG-SEC-11** | **Low** | `server/shareguard/parser.py:371-424` | Denial of Service / Resource Leak | `follow()` generator lacks cooperative cancellation and logrotate inode tracking |

---

## Detailed Findings & Proposed Fixes

### [SG-SEC-01] Path Traversal in Restore Drill
- **Severity:** High
- **Location:** `server/shareguard/health.py:1184-1191`
- **What could go wrong:** During synthetic recovery drills, `rel_path` from `manifest.json` is joined directly: `dest_file = tmp_dir / rel_path`. If an attacker or corrupted snapshot introduces `../` sequences in the manifest, files could be written outside `tmp_dir` into arbitrary host directories.
- **Proposed Fix:** Validate that `(tmp_dir / rel_path).resolve()` is strictly relative to `tmp_dir` using `.is_relative_to(tmp_dir)` and reject any paths with `..` or leading slashes.

### [SG-SEC-02] Insecure Default Keys in LIVE Mode
- **Severity:** High
- **Location:** `server/shareguard/auth.py:46-52`, `server/shareguard/run.py`
- **What could go wrong:** In simulation mode, default keys (`admin-key`, `viewer-key`) allow convenient testing. However, if deployed in LIVE mode without setting `SHAREGUARD_ADMIN_KEY`, the server accepts well-known default credentials, allowing attackers to manipulate blocks and settings.
- **Proposed Fix:** Add an explicit startup check: if the server mode is `live`, check `SHAREGUARD_ADMIN_KEY` and refuse startup if it is unset, empty, or set to insecure defaults (`"admin-key"`, `"change-me"`).

### [SG-SEC-03] Insecure Credential Storage & Token Lifetime
- **Severity:** High
- **Location:** `server/shareguard/auth.py:128-150`, `server/shareguard/api.py:530`
- **What could go wrong:** Passwords are compared in plaintext with environment variables. Furthermore, successful login returns the static API key as the token, which never expires.
- **Proposed Fix:**
  1. Support password hashing using salted PBKDF2/scrypt/bcrypt.
  2. Implement time-bounded HMAC-SHA256 signed bearer tokens with configurable expiration (e.g., 2 hours).

### [SG-SEC-04] Lack of Login Rate Limiting & Account Lockout
- **Severity:** High
- **Location:** `server/shareguard/api.py:530-540`
- **What could go wrong:** Automated attackers can mount rapid brute-force attacks against `/api/auth/login` to guess credentials without being throttled.
- **Proposed Fix:** Implement in-memory IP/username rate limiting (e.g., max 5 failed attempts per 60 seconds; 5-minute lockout on failure) returning `429 Too Many Requests`.

### [SG-SEC-05] Canary File Path Validation
- **Severity:** Medium
- **Location:** `server/shareguard/canary.py:131-135`
- **What could go wrong:** In `CanaryManager.deploy()`, while `target_dir` is checked against `self.share_root`, `target_file = target_dir / filename` is not resolved and validated. A template with `filename = "../../../escape.txt"` could escape the share root.
- **Proposed Fix:** Resolve `target_file` and assert `target_file.resolve().is_relative_to(self.share_root)`.

### [SG-SEC-06] Missing CORS, Security Headers, and Request Body Limits
- **Severity:** Medium
- **Location:** `server/shareguard/api.py:381`
- **What could go wrong:** The FastAPI application lacks CORS controls, security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`), and body size limits. Large request payloads could lead to memory exhaustion.
- **Proposed Fix:**
  1. Add `CORSMiddleware` restricted to configured dashboard origins.
  2. Add middleware injecting standard OWASP security headers.
  3. Add request body size limit middleware (10 MB cap).
  4. Ensure uncaught exceptions return generic error responses without stack traces.

### [SG-SEC-07] Loose IP Input Validation on Query & Unblock Endpoints
- **Severity:** Medium
- **Location:** `server/shareguard/api.py:560,749`
- **What could go wrong:** Alert filters and client unblock endpoints accept arbitrary string IPs without validating format against `ipaddress.ip_address`.
- **Proposed Fix:** Validate all input IP parameters with `ipaddress.ip_address()`, rejecting malformed inputs with `400 Bad Request`.

### [SG-SEC-08] Incomplete IPv6 Initialization in Sudo Helper
- **Severity:** Medium
- **Location:** `deploy/shareguard-helper:72-133`
- **What could go wrong:** `init_nftables()` creates `blocked_ips` for IPv4 and a drop rule for IPv4 only. If an IPv6 client is blocked, `cmd_block()` attempts to add an element to `NFT_SET_V6`, which does not exist or has no drop rule in the chain.
- **Proposed Fix:** Initialize both `blocked_ips` (IPv4) and `blocked_ips_v6` (IPv6) sets and rules in `init_nftables()`.

### [SG-SEC-09] Unvalidated Process Termination in Helper
- **Severity:** Medium
- **Location:** `deploy/shareguard-helper:225-245`
- **What could go wrong:** `cmd_kill_sessions()` parses PIDs from `smbstatus` output and issues `kill -TERM` / `kill -KILL`. If output format shifts or matches an unrelated process, arbitrary processes could be terminated.
- **Proposed Fix:** Before sending signals, inspect `/proc/<pid>/comm` or `/proc/<pid>/cmdline` to verify the process is indeed `smbd`.

### [SG-SEC-10] Secrets Hygiene: Missing `.env.example`
- **Severity:** Low
- **Location:** Workspace root
- **What could go wrong:** Developers may accidentally commit `.env` or struggle to configure secure keys without a sanitized reference template.
- **Proposed Fix:** Provide `.env.example` with dummy values and explicit security guidance.

### [SG-SEC-11] Audit Follower Resource & Rotation Handling
- **Severity:** Low
- **Location:** `server/shareguard/parser.py:371-424`
- **What could go wrong:** `follow()` uses an infinite loop without an external cancellation/stop event, and detects rotation only by size shrinkage rather than inode identity change (logrotate standard move-and-create).
- **Proposed Fix:** Support an optional `stop_event: threading.Event` and detect inode changes (`st_ino`) on platforms where available.
