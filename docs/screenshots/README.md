# ShareGuard Dashboard Responsive UI Verification

This directory contains visual responsive verification assets and guidelines for the ShareGuard Streamlit dashboard across all pages and responsive breakpoints.

## Responsive Target Widths
- **Mobile (360 px)**: iPhone SE / Android Compact view. Verifies zero horizontal scrolling, single-column vertical stacking, accessible tap targets (minimum 44px), and readable chart legends.
- **Tablet (768 px)**: iPad / Tablet portrait view. Verifies 2-column grid balance, metrics flow, and table column visibility.
- **Desktop (1440 px)**: High-resolution widescreen workstation. Verifies wide layout utilization, multi-column analytics, and full timeline readability.

## Verified Views
1. **Login Gate** (`/`)
2. **Overview (Live)** (`/Overview`)
3. **Alerts Feed** (`/Alerts`)
4. **Alert Detail & Incident Response** (`/Alert_Detail`)
5. **Monitored Clients & Activity History** (`/Clients`)
6. **System Health & Subsystem Checklist** (`/System_Health`)
7. **Settings & Policy Management** (`/Settings`)

## Chrome DevTools Responsive Verification Checklist
Follow these steps to manually capture and inspect all views in Chrome DevTools:

1. **Launch the Dashboard**:
   ```powershell
   ./.venv/Scripts/python.exe -m streamlit run dashboard/app.py
   ```
2. **Open Chrome DevTools**:
   - Press `F12` or `Ctrl + Shift + I`.
   - Toggle Device Toolbar (`Ctrl + Shift + M`).
3. **Configure Responsive Dimensions**:
   - In the top dimension bar, select **Responsive**.
   - Test **360 x 800 px** (Mobile):
     - Verify no horizontal scrollbar on `<body>`.
     - Confirm all buttons are full-width or comfortably tappable.
     - Confirm tables wrap or scroll internally within their container width.
   - Test **768 x 1024 px** (Tablet):
     - Confirm metrics and subcontainers flow smoothly without awkward gaps.
   - Test **1440 x 900 px** (Desktop):
     - Confirm widescreen layouts utilize screen real estate cleanly.
4. **Theme Verification (Light & Dark)**:
   - Click the Streamlit hamburger menu (top-right) -> **Settings** -> **Theme**.
   - Switch between **Dark** (default) and **Light** themes.
   - Verify that all Plotly chart elements, text captions, and status badges remain crisp and readable with high contrast.
5. **Capture Full Page Screenshots**:
   - Open Chrome Command Menu (`Ctrl + Shift + P`).
   - Type `Capture full size screenshot` and press Enter.
   - Save the screenshots into this folder (`docs/screenshots/`).
