# Playbook: How to Check That Backups Are Good

This guide explains how to verify that your file backups and storage snapshots are intact, uncorrupted, and safe to restore before making any changes to your network shares.

---

## 1. Understand What a Clean Snapshot Is
- ShareGuard maintains automated, read-only storage snapshots of your Samba file shares.
- A **clean snapshot** is a point-in-time image created *before* the attacker started modifying, deleting, or encrypting files.
- Because snapshots are read-only and immutable, the ransomware cannot encrypt or delete the stored snapshot data through normal SMB file sharing.

## 2. Check the Snapshot Timestamp
- In the ShareGuard Alert Detail view, examine the **Incident Timeline**.
- Note the **First Anomaly** timestamp. This marks the exact second the attacker began abnormal file operations.
- Verify that the target restoration snapshot was captured **prior** to the first anomaly timestamp.

## 3. Run a Safe Dry-Run Restoration Preview
- Never perform a direct file overwrite without previewing the changes first.
- In ShareGuard, click **Preview Restore (Dry Run)** on the Alert Detail page.
- Review the summary numbers:
  - **Files to Restore**: Count of damaged or missing files that will be returned to their clean state.
  - **Files Skipped**: Files that are already identical to their pre-incident clean version.
  - **Total Data Volume**: Estimated size of data that will be rewritten.

## 4. Test Restore into an Isolated Test Folder
- Before restoring an entire department's share, test opening a few restored sample files (e.g., PDFs, spreadsheets, images).
- Verify that the restored test files open cleanly in their standard desktop programs without corruption errors.

## 5. Verify Offsite and Cloud Backups
- If your office maintains separate daily offsite backups or cloud mirrors, verify that those services have not synced encrypted files.
- Temporarily pause automatic cloud sync services until the file server is confirmed clean.
