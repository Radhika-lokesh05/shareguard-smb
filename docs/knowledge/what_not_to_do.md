# Playbook: What NOT to Do During a Ransomware Incident

When ransomware strikes, panic can lead to mistakes that cause permanent data loss or legal complications. Avoid these critical mistakes.

---

## 1. Do NOT Pay the Ransom in a Hurry
- **Payment guarantees nothing**: Criminals frequently provide defective decryption keys or demand second payments.
- **Repeat targeting**: Paying marks your organization as willing to pay, making you a prime target for future extortion.
- **Legal sanctions risk**: Depending on your jurisdiction, paying extortion money to certain sanctioned criminal groups can violate anti-money laundering and national security sanctions laws.
- **Always explore snapshots first**: ShareGuard snapshots allow you to revert compromised shares without negotiating with extortionists.

## 2. Do NOT Reboot the File Server or Infected Computers
- **Preserve volatile memory**: Crucial forensic evidence, encryption keys, and network traces reside in volatile computer memory (RAM).
- **Restarting can trigger payloads**: Some ransomware strains embed persistence mechanisms that trigger additional encryption or lockout routines upon system reboot.
- **Simply disconnect**: Isolate computers by unplugging network cables rather than turning them off or restarting.

## 3. Do NOT Delete Locked, Encrypted, or Suspicious Files
- **Do not empty the Recycle Bin or delete .locked files**: Security researchers and decryption tools often require samples of encrypted files along with original unencrypted copies to analyze malware keys.
- **Files may still be recoverable**: Future decryptors or specialized forensic tools may recover files you thought were lost.

## 4. Do NOT Reconnect Infected Computers to the Network
- **Quarantine must remain strict**: Never plug an affected computer back into the office network just to check if it works.
- **Lateral movement threat**: Active malware will immediately scan the local subnet and attempt to re-infect newly restored Samba shares.

## 5. Do NOT Attempt Direct Communication Without Guidance
- **Avoid personal communications**: Do not email, chat, or message extortionists using personal or office email accounts.
- **Involve professionals**: Allow your designated IT managed service provider, incident response firm, or insurer-approved negotiators to handle communications if deemed necessary.
