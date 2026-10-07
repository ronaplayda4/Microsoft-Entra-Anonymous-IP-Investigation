# Microsoft Entra ID – Anonymous IP Investigation

## Overview

This project documents an identity-security investigation performed in a controlled Microsoft security lab using **Microsoft Defender XDR**, **Microsoft Entra ID Protection**, **Conditional Access**, **Advanced Hunting**, and **KQL**.

Microsoft Entra ID Protection generated a **Medium-severity** incident after detecting multiple cloud identities using the same anonymous VPN exit IP located in the Netherlands.

The investigation focused on four questions:

- Why did the activity trigger an identity-protection alert?
- Was either identity compromised?
- Why did Conditional Access block one identity while another successfully authenticated?
- What security-control gap did the different outcomes reveal?

> **Final verdict:** Benign Positive – Authorized Security Testing

---

## Environment

- Microsoft Defender XDR
- Microsoft Entra ID
- Microsoft Entra ID Protection
- Microsoft Sentinel
- Conditional Access
- Advanced Hunting
- Kusto Query Language (KQL)

---

## Incident Summary

| Field | Finding |
|---|---|
| Alert | Anonymous IP address involving multiple users |
| Severity | Medium |
| Detection source | Microsoft Entra ID Protection |
| Location | Netherlands (NL) |
| Affected identities | Two cloud identities |
| Verdict | Benign Positive – Authorized Security Testing |

The VPN activity was intentionally generated as part of an authorized SOC lab. The detection itself was valid: Entra ID Protection correctly correlated multiple identities using the same anonymous VPN exit IP.

---

## Investigation

### 1. Incident Triage

I reviewed the Defender incident attack story, affected identities, shared IP address, timestamps, and related authentication activity.

The incident showed that two cloud identities were associated with the same anonymous VPN IP, which provided the starting point for correlation and sign-in analysis.

### 2. First Identity – Failed and Blocked Sign-ins

I used Microsoft Defender Advanced Hunting and the `SigninLogs` table to investigate the first identity.

The investigation identified:

- **ResultType 50126** – credential validation failure / invalid username or password
- **ResultType 53003** – access blocked by Conditional Access
- **ConditionalAccessStatus = failure**
- No **ResultType 0** successful sign-in was identified for this identity in the reviewed activity

The expanded 53003 event confirmed that Conditional Access prevented token issuance.

### 3. Second Identity – Successful Sign-in

The second identity was observed using the same VPN exit IP.

Advanced Hunting identified:

- **ResultType 50140** – "Keep me signed in" interruption
- Multiple **ResultType 0** events
- **ConditionalAccessStatus = notApplied**

ResultType 0 confirmed that the second identity successfully authenticated to the Microsoft 365 Security and Compliance Center.

### 4. Root Cause Analysis

I reviewed the Conditional Access configuration to determine why two identities using the same VPN IP received different outcomes.

The geographic blocking policy was scoped to the first test identity but did **not** include the second identity at the time of the observed events.

Therefore:

```text
First identity
VPN sign-in from NL
        ↓
Conditional Access applied
        ↓
Access blocked (53003)

Second identity
Same VPN IP / NL
        ↓
Conditional Access not applied
        ↓
Successful sign-in (ResultType 0)
```

The successful authentication was caused by **policy scope**, not by the account's administrative privileges.

---

## KQL Investigation

Example hunting query used during the investigation:

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress == "<VPN-IP>"
| project TimeGenerated,
          UserPrincipalName,
          IPAddress,
          Location,
          ResultType,
          ResultDescription,
          ConditionalAccessStatus,
          AppDisplayName
| order by TimeGenerated desc
```

A more targeted investigation can additionally filter by a sanitized user identifier:

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName contains "<USER>"
| where IPAddress == "<VPN-IP>"
| project TimeGenerated,
          UserPrincipalName,
          IPAddress,
          Location,
          ResultType,
          ResultDescription,
          ConditionalAccessStatus,
          AppDisplayName
| order by TimeGenerated desc
```

---

## Findings

The investigation established that:

1. The anonymous-IP detection was legitimate and accurately correlated multiple identities using the same VPN exit IP.
2. The first identity experienced both invalid-credential attempts and Conditional Access blocks.
3. The second identity successfully authenticated because the relevant Conditional Access policy was not applied to that identity.
4. The activity was generated intentionally as part of an authorized lab.
5. No evidence of unauthorized account compromise was identified.

### Final Classification

**Benign Positive – Authorized Security Testing**

---

## MITRE ATT&CK Context

**T1110 – Brute Force** is relevant to the repeated invalid-credential behavior observed during the lab.

The anonymous-IP detection itself is an identity-risk signal and should not, by itself, be treated as proof that a specific ATT&CK technique succeeded.

---

## Security Lessons Learned

This investigation demonstrated why an analyst should validate the underlying telemetry instead of making a decision from an alert title or severity alone.

It also demonstrated how **Conditional Access policy scope** can produce different authentication outcomes for users connecting from the same suspicious IP address.

In a production environment, a successful authentication from an anonymous VPN—particularly for a privileged identity—would warrant additional investigation of MFA, device context, normal user behavior, subsequent activity, and active sessions.

---

## Skills Demonstrated

- Microsoft Defender XDR incident investigation
- Microsoft Entra ID Protection
- Identity threat investigation
- Conditional Access analysis
- KQL / Advanced Hunting
- Sign-in log analysis
- Authentication-result interpretation
- Alert triage and correlation
- Benign-positive validation
- Root-cause analysis
- Security incident documentation

---

## Evidence Sanitization

Before publication, identifying information should be minimized.

**Redacted:**
- Usernames and display names
- User principal names
- Microsoft tenant/domain identifiers
- Sign-in request identifiers

**Retained where relevant:**
- VPN exit IP used for correlation
- General geographic location
- ResultType values
- Conditional Access status
- Timestamps and security-event descriptions

The VPN exit IP is retained because it is material to demonstrating how the activity was correlated and represents temporary third-party VPN infrastructure rather than a personal/home IP address.

---

## Disclaimer

This investigation was performed in a **controlled Microsoft security lab** for cybersecurity training and portfolio development. Suspicious authentication activity documented in this repository was generated intentionally for educational purposes.
