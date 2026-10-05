# Zero Trust identity audit: Riverbend Components (fictional)

NIST SP 800-53 moderate baseline | Generated 2026-10-05 01:34 UTC

- Weighted identity risk exposure: **49.9 / 100 (High)**
- MFA coverage of enabled human accounts: **62%**
- Privileged human accounts with phishing-resistant MFA: **0%**
- Accounts: 20 enabled of 22, 6 privileged, 3 service, 2 guest
- Accounts with critical or high findings: **11**

## Zero Trust Maturity Model, Identity pillar (indicative)

| Function | Estimated stage | Basis |
|---|---|---|
| Authentication | Traditional | Some accounts lack MFA or are shared, so access still relies on passwords alone. |
| Identity Stores | Traditional | Accounts of departed people remain enabled, so offboarding is not tied to the identity store. |
| Access Management | Traditional | Privileged access is unreviewed, held by external accounts, or available to service accounts interactively. |

## Findings by priority

### [CRITICAL] ZT-ID-01: Privileged account without MFA
Controls: IA-2(1) | ZTMM function: Authentication  
- it.admin: No MFA method registered.
- j.miller: No MFA method registered.

Remediation: Require phishing-resistant MFA for this account before any further privileged sign-in.

### [CRITICAL] ZT-ID-05: Terminated person's account still enabled
Controls: PS-4, AC-2 | ZTMM function: Identity Stores  
- d.harris: HR status is terminated but the account is enabled.

Remediation: Disable the account immediately and connect HR offboarding to account deprovisioning.

### [HIGH] ZT-ID-02: Standard user account without MFA
Controls: IA-2(2) | ZTMM function: Authentication  
- floor.kiosk: No MFA method registered.
- frontdesk: No MFA method registered.
- r.patel: No MFA method registered.
- t.brooks: No MFA method registered.

Remediation: Enroll the user in MFA and block sign-in until enrollment is complete.

### [HIGH] ZT-ID-06: Enabled account inactive beyond the allowed period
Controls: AC-2(3) | ZTMM function: Identity Stores  
- contractor.hv: Last sign-in 140 days ago (limit 90).
- t.brooks: Last sign-in 212 days ago (limit 90).

Remediation: Disable the account, confirm with its owner whether it is still needed, and automate inactivity disabling.

### [HIGH] ZT-ID-08: Service account allows interactive sign-in
Controls: AC-6, AC-2 | ZTMM function: Access Management  
- svc-backup: Service account can sign in interactively.
- svc-erp: Service account can sign in interactively.

Remediation: Deny interactive and remote desktop logon rights to service accounts, or convert them to managed service identities.

### [HIGH] ZT-ID-10: Admin rights on a daily-use account
Controls: AC-6(2) | ZTMM function: Access Management  
- e.adams: Account has admin rights and an email mailbox, so it is used for daily work.
- j.miller: Account has admin rights and an email mailbox, so it is used for daily work.

Remediation: Give the administrator a separate admin-only account without email, and remove admin rights from the daily account.

### [HIGH] ZT-ID-11: Guest or external account holds privileged access
Controls: AC-6, AC-2 | ZTMM function: Access Management  
- contractor.hv: External account holds privileged access.

Remediation: Remove privileged rights from external accounts, or grant them only through time-limited, approved access.

### [MEDIUM] ZT-ID-03: Privileged account uses phishable MFA (SMS, voice, push, or code)
Controls: IA-2(1) | ZTMM function: Authentication  
- contractor.hv: MFA method is 'sms', which can be phished.
- e.adams: MFA method is 'sms', which can be phished.

Remediation: Move administrators to phishing-resistant MFA such as FIDO2 security keys or certificate-based (PIV/CAC) authentication.

### [MEDIUM] ZT-ID-04: Shared or generic account in use
Controls: AC-2, IA-2 | ZTMM function: Authentication  
- floor.kiosk: Account is marked as shared by more than one person.
- frontdesk: Account is marked as shared by more than one person.
- it.admin: Account is marked as shared by more than one person.

Remediation: Replace the shared account with individually assigned accounts so every action is attributable to one person.

### [MEDIUM] ZT-ID-07: Account created but never used
Controls: AC-2 | ZTMM function: Identity Stores  
- p.wright: Created 95 days ago and never signed in (grace 30 days).

Remediation: Disable unused accounts and create accounts only when a person starts work.

### [MEDIUM] ZT-ID-09: Service account password older than the allowed age
Controls: IA-5 | ZTMM function: Access Management  
- svc-backup: Password is 1900 days old (limit 365).
- svc-erp: Password is 2600 days old (limit 365).
- svc-scanner: Password is 1400 days old (limit 365).

Remediation: Rotate the credential and move to automatically rotated credentials such as group managed service accounts.

### [MEDIUM] ZT-ID-12: Privileged access not reviewed within the review period
Controls: AC-6(7) | ZTMM function: Access Management  
- e.adams: Privileged access last reviewed 200 days ago (limit 90).
- j.miller: Privileged access last reviewed 400 days ago (limit 90).
- svc-erp: Privileged access last reviewed 700 days ago (limit 90).

Remediation: Have the account's manager or system owner recertify the privileged access and record the review.

### [MEDIUM] ZT-ID-13: Too many privileged accounts for the organization's size
Controls: AC-6, AC-6(5) | ZTMM function: Access Management  
- 6 of 20 enabled accounts are privileged (allowed: 2, from 10% or a minimum of 2).

Remediation: Reduce standing administrator accounts to the minimum needed and use time-limited elevation for occasional tasks.

## All checks

| Check | Title | Severity | Result | In scope | Failed | Not assessed |
|---|---|---|---|---|---|---|
| ZT-ID-01 | Privileged account without MFA | Critical | Fail | 4 | 2 | 0 |
| ZT-ID-02 | Standard user account without MFA | High | Fail | 13 | 4 | 1 |
| ZT-ID-03 | Privileged account uses phishable MFA (SMS, voice, push, or code) | Medium | Fail | 2 | 2 | 0 |
| ZT-ID-04 | Shared or generic account in use | Medium | Fail | 20 | 3 | 0 |
| ZT-ID-05 | Terminated person's account still enabled | Critical | Fail | 12 | 1 | 0 |
| ZT-ID-06 | Enabled account inactive beyond the allowed period | High | Fail | 19 | 2 | 0 |
| ZT-ID-07 | Account created but never used | Medium | Fail | 1 | 1 | 0 |
| ZT-ID-08 | Service account allows interactive sign-in | High | Fail | 3 | 2 | 0 |
| ZT-ID-09 | Service account password older than the allowed age | Medium | Fail | 3 | 3 | 0 |
| ZT-ID-10 | Admin rights on a daily-use account | High | Fail | 4 | 2 | 0 |
| ZT-ID-11 | Guest or external account holds privileged access | High | Fail | 2 | 1 | 0 |
| ZT-ID-12 | Privileged access not reviewed within the review period | Medium | Fail | 6 | 3 | 3 |
| ZT-ID-13 | Too many privileged accounts for the organization's size | Medium | Fail | 1 | 1 | 0 |

_This report is generated by an automated audit aid from the account data supplied. It does not replace a formal assessment or the judgment of a qualified auditor. Zero Trust Maturity Model stages are indicative estimates for the Identity pillar based on account data only._
