# Playbook: First 15 Minutes of a Ransomware Incident

This guide is written for office managers, business owners, and staff facing a suspected ransomware incident. Follow these calm, immediate steps to stop the infection from spreading across your office network.

---

## 1. Disconnect the Affected Computer (Isolate Immediately)
- **Unplug the network cable**: Pull the Ethernet cable out of the back of the suspicious computer immediately.
- **Turn off Wi-Fi**: If the computer connects over Wi-Fi, toggle the Wi-Fi switch off or disconnect from the office network.
- **Do NOT power off abruptly**: Leave the computer powered on if possible. Powering down abruptly can destroy memory evidence needed to identify how the malware got in.

## 2. Protect the Samba File Server
- **Do NOT turn off the main file server**: The server contains critical transaction logs and system telemetry.
- **Verify server status**: Log into the ShareGuard dashboard from an uncompromised computer or administrator device.
- **Check active containment**: Look at the Overview page to verify whether ShareGuard has automatically isolated the attacking client IP address.

## 3. Identify Who and What Is Affected
- **Identify the workstation**: Note the IP address, device name, and logged-in user reported on the ShareGuard alert screen.
- **Check surrounding desks**: Ask nearby team members if they are experiencing slow file access, renaming errors, or ransom notes.
- **Record the timeline**: Write down the exact clock time you first noticed unusual behavior or received an alert.

## 4. Notify Your Team Calmly
- **Brief your staff**: Instruct team members not to open unexpected email attachments or click unknown links.
- **Tell staff not to save new work over network shares**: Ask employees to save ongoing local drafts to prevent any partial file overwrites until the incident is cleared.

## 5. Prepare for Next Steps
- Open the **What Not to Do** playbook before attempting any recovery or file repairs.
- Contact your IT support provider and insurance claims team as described in the **Who to Inform** playbook.
