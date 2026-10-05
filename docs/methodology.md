# Audit methodology

This document explains how `iam_audit` turns an account export into findings, a risk score, and Zero Trust Maturity Model estimates, so the results can be reviewed and reproduced.

## 1. Which accounts are checked

Only enabled accounts are checked. An account with a blank `enabled` value is treated as enabled, because an auditor cannot assume an account is off without evidence. An account is **privileged** if its `privileged` column is true or if it belongs to any group in the policy's `privileged_groups` list. **Human** accounts are those of type `user`, `admin`, `shared`, or `guest`; `service` accounts are excluded from MFA checks and have their own checks.

## 2. Checks

| Check | What fails | Scope | NIST SP 800-53 | ZTMM function |
|---|---|---|---|---|
| ZT-ID-01 | No MFA | Privileged human accounts | IA-2(1) | Authentication |
| ZT-ID-02 | No MFA | Non-privileged human accounts | IA-2(2) | Authentication |
| ZT-ID-03 | MFA method is not phishing-resistant | Privileged human accounts with MFA | IA-2(1) | Authentication |
| ZT-ID-04 | Account is shared | All accounts | AC-2, IA-2 | Authentication |
| ZT-ID-05 | HR status is terminated | User and admin accounts | PS-4, AC-2 | Identity Stores |
| ZT-ID-06 | No sign-in for more than 90 days | Accounts that have signed in before | AC-2(3) | Identity Stores |
| ZT-ID-07 | Never signed in, created more than 30 days ago | Accounts that never signed in | AC-2 | Identity Stores |
| ZT-ID-08 | Interactive sign-in allowed | Service accounts | AC-6, AC-2 | Access Management |
| ZT-ID-09 | Password older than 365 days | Service accounts | IA-5 | Access Management |
| ZT-ID-10 | Admin rights on an account with a mailbox | Privileged human accounts | AC-6(2) | Access Management |
| ZT-ID-11 | Privileged access | Guest accounts | AC-6, AC-2 | Access Management |
| ZT-ID-12 | Access not reviewed in 90 days | Privileged accounts | AC-6(7) | Access Management |
| ZT-ID-13 | Privileged accounts exceed 10% of enabled accounts, or 2, whichever is larger | Organization | AC-6, AC-6(5) | Access Management |

The day counts and percentages are organization-defined parameters. NIST SP 800-53 leaves values such as the inactivity period for each organization to set; the defaults reflect common practice and can be changed with `--policy`.

Phishing-resistant methods default to FIDO2 security keys and passkeys, certificate-based authentication (such as PIV or CAC smart cards), and Windows Hello for Business, in line with CISA's guidance on phishing-resistant MFA and OMB Memorandum M-22-09. SMS, voice, push notifications, and one-time codes are treated as phishable.

Checks apply only when one of their controls is in the selected NIST SP 800-53 baseline. Several least-privilege controls are in the moderate and high baselines only, so the low baseline runs fewer checks.

## 3. Outcomes and missing data

Each check reports, for each account in scope, a pass, a fail, or "not assessed" when the export lacks the required value. A check as a whole fails if any account fails it, is not applicable if no accounts are in scope, and is not assessed if no account in scope had the needed data. Missing data never counts as a pass.

## 4. Identity risk exposure

Each check carries a severity weight: critical 10, high 6, medium 3, low 1. The score weights each check by the share of in-scope accounts that fail it:

```
risk exposure = 100 x sum(weight x failing accounts / assessed accounts) / sum(weight)
```

The sum covers checks with at least one assessed account. A check failed by every account in scope contributes its full weight; one failed by a single account in a hundred contributes very little. Bands: below 10 Low, 10 to below 25 Moderate, 25 to below 50 High, 50 or more Critical.

Severities reflect the author's professional judgment of how directly each gap enables account takeover, persistence, or privilege escalation in small and mid-sized organizations. They are a prioritization aid, not a quantitative risk model.

## 5. Zero Trust Maturity Model estimates

The CISA Zero Trust Maturity Model (version 2.0) describes four stages, Traditional, Initial, Advanced, and Optimal, across five pillars. This tool estimates three functions of the **Identity** pillar using only what an account export can show:

| Function | Traditional | Initial | Advanced |
|---|---|---|---|
| Authentication | Any account lacks MFA or is shared | MFA everywhere, but some admins use phishable MFA | MFA everywhere and phishing-resistant MFA for all admins |
| Identity Stores | Departed staff accounts remain enabled | No departed staff accounts, but inactive or unused accounts remain | No departed, inactive, or unused accounts |
| Access Management | Unreviewed privileged access, privileged guests, or interactive service accounts | Those are resolved, but admins use daily accounts, service credentials are stale, or admin accounts are too many | All access management checks pass |

The tool never reports Optimal. That stage depends on capabilities such as continuous validation, automated lifecycle across all identity stores, and just-in-time access, which cannot be evidenced from an account list. The estimates are indicative and support, but do not replace, a full maturity assessment.

## 6. Limitations

- Results are only as accurate as the export. Last sign-in values from directory replicas can lag by days.
- The tool reviews accounts, not the systems they access, so it cannot see application-level permissions or conditional access policies.
- It does not replace a formal assessment or the judgment of a qualified auditor.
