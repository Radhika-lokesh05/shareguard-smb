# Playbook: How to Get Computers Clean Again Before Reconnecting

Before an infected or quarantined workstation is permitted to access office network shares again, it must be thoroughly sanitized to guarantee no malware or persistent backdoors remain.

---

## 1. Keep the Machine Isolated Until Certified Clean
- **Maintain quarantine**: The computer must remain disconnected from both Wi-Fi and wired Ethernet networks until all sanitization steps are complete.
- **Do not assume anti-virus alone is sufficient**: Advanced ransomware often leaves behind secondary remote-access trojans (RATs) that standard quick scans may miss.

## 2. Preserve Crucial Local Data (If Safe)
- If essential local business files reside solely on the affected workstation's local hard drive and are not in network backups:
  - Connect a clean, disposable external USB drive.
  - Copy necessary documents only (e.g., text, PDFs, spreadsheets) — never copy executable files (.exe, .bat, .dll).
  - Scan the external drive on an isolated, air-gapped machine with up-to-date endpoint protection before opening files elsewhere.

## 3. Recommended Remediation: Complete Wipe and Re-image
- **The safest path is a clean re-installation**: Wiping the storage drive completely and reinstalling the operating system from a verified, clean corporate image or official installation media is the industry gold standard.
- **Eliminates stealth persistence**: Re-imaging guarantees the removal of scheduled tasks, hidden registry run keys, and rootkits installed by threat actors.

## 4. Deep Endpoint Scans (If Re-imaging Is Delayed)
- If a full re-image cannot be performed immediately:
  - Run a full offline or boot-time antivirus scan using trusted, updated endpoint detection and response (EDR) software.
  - Scan for known ransomware indicators, secondary persistence mechanisms, and unauthorized remote access software (e.g. unauthorized AnyDesk or TeamViewer instances).
  - Verify that Windows Defender or third-party endpoint protection is healthy and receiving definitions.

## 5. Mandatory Password and Credential Resets
- **Reset account passwords**: Before reconnecting the device, reset the Windows user password, local administrator passwords, and any domain or email credentials associated with that user from a separate, known-clean device.
- **Revoke active sessions**: Invalidate any active Kerberos tickets or cloud session tokens for the affected user account.

## 6. Gradual Reconnection and Verification
- **Test on an isolated network segment**: If possible, reconnect the sanitized device to a guest or quarantine network first to observe outbound network behavior.
- **Restore ShareGuard access**: Verify that ShareGuard firewall blocks for the client IP have expired or been reviewed by an administrator.
- **Monitor closely**: Watch the ShareGuard dashboard for 24 to 48 hours to confirm normal, non-anomalous file operations on Samba shares.
