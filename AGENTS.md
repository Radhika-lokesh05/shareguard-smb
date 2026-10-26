# ShareGuard – Agent & Contributor Rules

These rules apply to every agent, contributor, and automated workflow in this
repository. They take precedence over any model defaults.

---

## Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 only |
| API | FastAPI + Uvicorn |
| Database | SQLAlchemy (ORM) + SQLite |
| ML | scikit-learn, XGBoost, SHAP, pandas |
| Dashboard | Streamlit (pure Python, client of the FastAPI API) |
| Charts | Plotly (inside Streamlit only) |
| Tests | pytest |
| Linter | ruff |

**Forbidden**: React, Node.js, npm, any JavaScript build step, any JS framework.

---

## Run Modes

### SIMULATION (default)
- Works on Windows, macOS, Linux — no root required.
- Uses generated audit logs from `lab/simulate_log.py`.
- All Linux-only system calls (iptables, smbcontrol, btrfs) must be behind
  interfaces with a **fake implementation** used automatically when running in
  simulation mode or in tests.

### LIVE
- Real Samba on Ubuntu; requires `sudo` for blocking and snapshots.
- Never enable LIVE mode in CI or on developer machines.

---

## Safety Rules

1. **Default response mode is `shadow`** (alert only — no blocking, no file ops).
2. **Never block** the server's own IPs, the gateway, or any address in
   `config.response.allowlist`.
3. **All blocks auto-expire** — default TTL is 15 minutes
   (`config.response.block_ttl_minutes`).
4. **Never use `shell=True`** in any `subprocess` call.
5. **Validate IPs** with `ipaddress` (stdlib) before using them in any system call.
6. **Validate paths** against the configured share root before any file operation.

---

## Input Handling

- Treat every file name read from a log line as **untrusted text**.
- **Escape / truncate** untrusted strings before passing them to the UI,
  database, or LLM prompts. Never execute them.
- **In Streamlit**: never use `unsafe_allow_html=True`.
- Render untrusted strings with `st.text`, `st.code`, or a dataframe.
  `st.markdown` is only acceptable for trusted, hard-coded strings (it can
  render links and images).

---

## Lab-Only Fake Ransomware

`lab/fake_ransomware.py` is a simulation tool **only**.

- It **must refuse to run** unless the file `SHAREGUARD_LAB_MARKER` exists
  inside the target folder.
- It must never be imported or called from production code paths.

---

## Code Quality

- Every module must have **type hints**, **docstrings**, and **pytest tests**.
- Keep functions small (single responsibility).
- Configuration lives in `config/default.yaml` and environment variables.
  **No secrets in git** (no API keys, passwords, or tokens).

---

## Definition of Done

A task is complete **only when all of the following are true**:

1. `pytest server/tests/` passes with no errors.
2. `ruff check .` passes with no errors.
3. The relevant README section is updated.
4. The feature can be demonstrated with one documented command.
