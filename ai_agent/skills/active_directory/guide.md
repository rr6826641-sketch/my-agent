# Active Directory Attack & Defense Playbook

AD attacks are chain-based: enumerate → identify a weakness → move laterally →
repeat until Domain Admin. This playbook covers the standard (and still-practical)
attack classes. Windows-native commands listed are for run_terminal on a
compromised domain-joined host; BloodHound-style analysis is done by gathering
and correlating the same data manually when no collector is available.

## 0. Service Probe First

- `ad_svc_probe` against the DC/domain hosts to identify AD-related services
  (LDAP 389/636, Kerberos 88, SMB 445, RPC 135, Global Catalog 3268/3269, NTP 123).
- Port scan the whole segment: SMB, RDP, WinRM (5985/5986) are your lateral-movement
  doors. WinRM is usually the least monitored.

## 1. Enumeration (pre-attack)

- Domain info: `net user /domain`, `net group /domain`, `net group "Domain Admins" /domain`.
- AD enumeration (PowerShell, if available):
  - `Get-ADUser -Filter * -Properties *`
  - `Get-ADGroup -Filter *` and group membership: `Get-ADGroupMember "Domain Admins"`
  - `Get-ADComputer -Filter * -Properties operatingsystem` (high-value targets:
    DCs, SQL servers, file servers, backup servers)
  - SPNs: `setspn -T domain -Q */*` — every SPN is a potential Kerberoast target.
  - `Get-ADObject` for ACLs on high-value objects (see ACL abuse below).
- SMB shares: `net view \host /all`, `net share`. Look for readable scripts,
  configs, backups, and "Everyone: full" shares.
- GPOs: `Get-GPO -All` (via Group Policy module) — look for startup scripts with
  credentials, weak password policies, and unsupported legacy settings.

## 2. Password-Only Attacks (no domain user needed)

- **LLMNR/NBT-NS poisoning** (Responder): when a host queries a name that doesn't
  resolve, poisoned responses capture NTLMv2 hashes. Hashcat mode 5600 to crack.
  Confirmation: `ipconfig /flushdns` triggers; `nmap -sU -p 137,138` for NBT.
- **SMB relay**: capture NTLMv2 and relay to targets with SMB signing disabled
  (check with nmap script `smb2-security-mode`). Relay can land you a session
  without cracking.
- **Password spraying**: `net user /domain` first for the username list, then try
  `Password1`, `Welcome1`, `P@ssw0rd`, season-year combos against ALL users.
  Lockout policy matters — stay under the threshold (default 10 attempts).
- Default/local accounts: `Administrator` with no password or blank in test beds,
  `Guest` enabled, cached credentials (`cmdkey /list`).

## 3. Kerberos Attacks (domain user needed)

- **AS-REP Roasting**: users with "Do not require Kerberos preauthentication"
  (DONT_REQ_PREAUTH) expose an AS-REP that can be cracked offline.
  Extract: `Get-DomainUser -PreauthNotRequired` (PowerView) or
  `Get-ADUser -Properties DoesNotRequirePreAuth -Filter *`.
- **Kerberoasting**: request TGS tickets for any SPN; the ticket contains the
  service account's hash (RC4 or AES) — crack offline (hashcat modes 13100/19700).
  Extract: `setspn -T domain -Q */*`, then request tickets with a Kerberoast
  script; low-priv users can request these tickets in default configs.
- **AS-REP vs Kerberoast**: AS-REP = no preauth user; Kerberoast = any SPN-bound
  service account. Both need ONLY a valid domain user context.
- **Pass-the-ticket**: reuse a harvested TGT/TGS (`klist` / ticket files) on
  another host — no password needed.

- **Golden/Silver Tickets** (DC compromise required for golden; any Kerberos
  service key for silver): forge tickets with the krbtgt hash (golden — full
  domain) or a service account hash (silver — single service). Mitigation: protect
  krbtgt with regular rotation; monitor ticket lifetimes.
- **Delegation abuse**: unconstrained delegation (printer bug / coerce attacks),
  constrained delegation (S4U2Self/S4U2Proxy → impersonate any user on the target
  service), resource-based constrained delegation (RBCD). Enumerate with
  `Get-DomainUser -TrustedToAuth` / `Get-DomainComputer -TrustedToAuth`.

## 4. Lateral Movement & Privilege Escalation

- **Pass-the-Hash / Pass-the-Key**: reuse NTLM hashes or Kerberos keys without the
  password — `psexec`, `wmiexec`, `smbexec`, `evil-winrm` (WinRM) are the classic
  carriers.
- **Token manipulation** (local admin): `token::whoami`, `token::elevate`,
  impersonate a domain admin's token if present.
- **DCSync** (DC or replication rights): `lsadump::dcsync /domain:dom /user:krbtgt`
  — needs Replicating Directory Changes rights; golden ticket + DCSync = domain done.
- **ACL abuse**: objects with GenericAll/GenericWrite/WriteDACL/WriteOwner over
  users or groups — e.g., write the `msDS-AllowedToActOnBehalfOfOtherIdentity`
  attribute (RBCD), reset a user's password (`net user x newpass /domain` when you
  hold GenericAll), or add yourself to a privileged group.
- **LAPS**: if deployed, steal `ms-Mcs-AdmPwd` from machines you have read access to
  instead of cracking local passwords.
- **Unconstrained delegation hosts**: coerce auth via MS-RPC (SpoolSample/PrinterBug)
  from the DC → get the DC's TGT in memory → golden ticket.

## 5. Domain Trusts & Persistence

- Trust enumeration: `nltest /domain_trusts`, `Get-DomainTrust`. Child→parent
  (SID history / extraSids) can escalate to the forest root (sidHistory injection,
  "ExtraSids attack").
- Persistence: admin accounts, SID history injection, GPO persistence
  (scheduled task in a pushed GPO), skeleton key on the DC, DSRM account.
  Recommend detection-focused reporting; do not plant persistence without explicit
  user approval.

## 6. Reporting Focus (defender lens)

For each finding report the attack path end-to-end (initial access → lateral move →
DA), the exact commands run, the evidence (hashes/tickets captured, screenshots),
and the mitigation: monitor event IDs 4624/4625 (logon), 4768/4769 (Kerberos),
4742 (account changes), 7045 (service install), 4104 (script block logging),
enable SMB signing, disable LLMNR/NBT-NS, enforce LAPS, protect krbtgt,
limit delegation, and audit ACLs with BloodHound-style tooling.
