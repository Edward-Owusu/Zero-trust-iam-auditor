# Account export reference

The tool reads one CSV file with one row per account. Start from `samples/accounts_template.csv`. Only `username` is required. A blank cell means "not reported": checks that need that value are reported as not assessed for that account instead of being passed.

## Columns

| Column | Values | Used by |
|---|---|---|
| `username` | text, unique | All findings |
| `display_name` | text | Informational |
| `account_type` | `user`, `admin`, `service`, `shared`, `guest` (default `user`) | Scope of most checks |
| `enabled` | true/false (blank is treated as enabled) | All checks skip disabled accounts |
| `privileged` | true/false | Marks an account as privileged even if no privileged group is listed |
| `groups` | group names separated by `;` | Accounts in any group listed in the policy's `privileged_groups` are privileged |
| `mfa_enabled` | true/false | ZT-ID-01, ZT-ID-02 |
| `mfa_method` | `none`, `sms`, `voice`, `app_push`, `totp`, `fido2`, `certificate`, `windows_hello` | ZT-ID-03 |
| `last_login_days` | days since last sign-in, or `never` | ZT-ID-06, ZT-ID-07 |
| `created_days` | days since the account was created | ZT-ID-07 |
| `employment_status` | `active`, `leave`, `terminated` | ZT-ID-05 |
| `mailbox_enabled` | true/false | ZT-ID-10 |
| `interactive_login` | true/false (service accounts) | ZT-ID-08 |
| `password_age_days` | days since the password was set (service accounts) | ZT-ID-09 |
| `last_access_review_days` | days since privileged access was last recertified | ZT-ID-12 |

Values are not case-sensitive. `yes`/`no` and `1`/`0` are accepted for true/false. A UTF-8 byte order mark, which Excel adds, is accepted.

## Organization-defined parameters

Thresholds live in `src/iam_audit/data/policy.json`. To change them without editing the package, create a JSON file with only the values you want to change and pass it with `--policy`:

```json
{
  "inactivity_days": 45,
  "privileged_groups": ["Domain Admins", "Enterprise Admins", "Global Administrator", "IT-Tier0"]
}
```

Note that supplying `privileged_groups` replaces the default list rather than adding to it.

## Building the export

No single system holds every column, so most organizations combine two or three sources into one spreadsheet. Always export with read-only permissions, and treat the resulting file as sensitive: it lists your accounts and their weaknesses.

**Active Directory.** The PowerShell below, run by an account with read access to the directory, produces most account columns. `LastLogonDate` comes from a replicated attribute that can lag the true last sign-in by up to about two weeks, which is acceptable for a 90-day inactivity check. The presence of a `mail` attribute is used as a proxy for a mailbox.

```powershell
Import-Module ActiveDirectory
$now = Get-Date
Get-ADUser -Filter * -Properties Enabled, LastLogonDate, whenCreated, MemberOf, PasswordLastSet, mail |
  Select-Object `
    @{n='username';          e={$_.SamAccountName}},
    @{n='display_name';      e={$_.Name}},
    @{n='enabled';           e={$_.Enabled}},
    @{n='groups';            e={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ';'}},
    @{n='last_login_days';   e={ if ($_.LastLogonDate) { [int]($now - $_.LastLogonDate).TotalDays } else { 'never' } }},
    @{n='created_days';      e={[int]($now - $_.whenCreated).TotalDays}},
    @{n='mailbox_enabled';   e={[bool]$_.mail}},
    @{n='password_age_days'; e={ if ($_.PasswordLastSet) { [int]($now - $_.PasswordLastSet).TotalDays } }} |
  Export-Csv accounts_ad.csv -NoTypeInformation -Encoding UTF8
```

**MFA registration.** Directories such as Active Directory do not record MFA. Take `mfa_enabled` and `mfa_method` from your identity provider's MFA registration report, for example the user registration details report for authentication methods in the Microsoft Entra admin center, which can be downloaded as CSV, or the equivalent report in Okta, Duo, or Google Workspace. Record the strongest method each user has registered.

**HR status.** Join `employment_status` from an HR system export on employee ID or email.

**Account type, interactive logon, and access reviews.** Mark `account_type` from your naming convention (for example `svc-` and `adm-` prefixes). Take `interactive_login` for service accounts from the "Deny log on locally" and "Deny log on through Remote Desktop Services" policy assignments, and `last_access_review_days` from your access review records.

Verify the script and report names against your own environment and vendor documentation before relying on them, as product menus and attributes change over time.
