---
layout: post
title: "Common High-Impact Privileges in Windows"
date: 2025-11-14 04:00:00 +01:00
categories: ["Windows", "Active Directory"]
tags: ["privileges", "windows-security", "priv-esc", "access-token"]
image: /assets/img/posts/win-priv/01.png
permalink: /windows-privileges-overview/
redirect_from:
  - /posts/windows-priv-overview/
draft: false
excerpt: "A short overview of the Windows privileges that matter most, what they let an attacker do, and why they’re worth paying attention to."
---

When a user logs in, the operating system creates an **access token** containing their identity, group memberships, and a set of **privileges** (often called "user rights"). It's crucial to understand that these privileges are not the same as file permissions; they are high-level, system-wide authorities. Since they can override standard Access Control Lists (ACLs), incorrectly assigning or exploiting these privileges is a primary method for attackers to escalate their access. 

The following are some of the most critical privileges to monitor and control:

---
### Privilege breakdown

- **SeBackupPrivilege / SeRestorePrivilege** – These two rights sit at the top of the risk hierarchy. They let a user read or write _any_ file on a Windows host without regard for ACL restrictions, effectively nullifying normal file-system security. With `SeBackupPrivilege`, an attacker can pull highly sensitive data such as the SAM, SYSTEM hives, or domain credential stores. `SeRestorePrivilege` goes the other direction, enabling the overwrite of protected system files, the placement of persistent payloads, and unauthorized manipulation of object ownership.

- **SeDebugPrivilege** – This “debug programs” right authorizes a user to attach to and tamper with any running process, including SYSTEM-level services. In adversarial hands, it’s an immediate escalation path, supporting memory inspection, credential theft, and direct code injection into privileged processes. Granting this to any non-admin account is effectively handing over the keys to the machine.

- **SeTcbPrivilege** –  This privilege places an account inside the system’s trusted computing boundary. With it, an attacker can craft arbitrary security tokens, impersonate SYSTEM, and override core OS security mechanisms. Compromise of an account holding this right nearly guarantees full host takeover.

- **SeImpersonatePrivilege** – This right allows a user to assume another authenticated security context. It’s a foundational component of numerous modern privilege-escalation techniques, particularly the [Potato family](https://github.com/AtvikSecurity/CentralizedPotatoes?tab=readme-ov-file) of attacks/exploits. If a service account with weak protections holds this privilege, an attacker can escalate by impersonating higher-privileged users and operating with their authority.

- **SeShutdownPrivilege** – While often dismissed as low-impact, this right can be weaponized to disrupt operations, interfere with monitoring, or force system restarts at strategically damaging moments. Attackers may also use shutdown or reboot events to trigger persistence mechanisms or evade detection tools.

- **SeChangeNotifyPrivilege** – This “bypass traverse checking” right is enabled for all users by default, as it underpins normal directory traversal in Windows. It doesn’t directly facilitate escalation, but it remains a fundamental component of the token model and is worth noting for completeness.

![diagram]({{ '/assets/img/posts/win-priv/02.png' | relative_url }})

---
## Practical hardening advice

Implementing the measures below greatly reduces privilege-related risk and forces attackers to work much harder to gain meaningful access.

- **Enforce the Principle of Least Privilege**  
This is non-negotiable. Privileges should never be handed out casually or “just in case.” Evaluate every request with scrutiny and grant only what is absolutely required. If a process doesn’t consistently need powerful rights like `SeDebugPrivilege`, it has no business holding them long-term.
    
- **Maintain a Centralized Privilege Inventory**  
Visibility is everything. Maintain a comprehensive, continuously updated list of all privileged assignments, especially those tied to service accounts and administrative identities. This record becomes indispensable during audits, investigations, and post-incident analysis.
    
- **Use Group Policy to Control Privilege Assignments**  
Manual configuration invites mistakes. Standardize privilege management through Group Policy:

```
Windows Settings → Security Settings → Local Policies → User Rights Assignment
```

Centralized control ensures consistency, reduces drift, and prevents misconfigurations that quietly weaken your defenses.
    
- **Perform Routine Service Account Reviews**  
Service accounts are common footholds for attackers. Regularly reassess their required rights and verify they’re operating under the least-privileged context possible. Avoid binding critical services to overly privileged domain accounts unless there is no viable alternative.
    
- **Monitor and Alert on Privileged Activity**  
Enable detailed auditing for all sensitive operations. Event ID **4672** (“Special privileges assigned to new logon”) should be on your radar. Configure your SIEM to alert on privilege usage by unexpected accounts or during abnormal activity windows. These spikes often signal the early stages of a compromise.

---
## Sources

- [https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)

- [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment)

- [https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b)

- [https://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/](https://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/)

- [https://github.com/AtvikSecurity/CentralizedPotatoes?tab=readme-ov-file](https://github.com/AtvikSecurity/CentralizedPotatoes?tab=readme-ov-file)

- [https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
