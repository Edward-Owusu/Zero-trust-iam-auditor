"""Identity checks.

Each per-account check returns one of:

* ``None``                  - the account is out of scope for this check
* ``NOT_ASSESSED``          - in scope, but the export lacks the data needed
* ``(PASS, "")``            - in scope and compliant
* ``(FAIL, "explanation")`` - in scope and non-compliant

Only enabled accounts are checked. A blank `enabled` value is treated as
enabled, because an auditor cannot assume an account is off without evidence.
"""

from __future__ import annotations

from typing import Callable

from .loader import NEVER, Account

PASS = "PASS"
FAIL = "FAIL"
NOT_ASSESSED = "NOT_ASSESSED"
NOT_APPLICABLE = "NOT_APPLICABLE"

Outcome = tuple[str, str] | str | None


def is_enabled(a: Account) -> bool:
    return a.enabled is not False


def _mfa_missing(a: Account) -> Outcome:
    if a.mfa_enabled is None:
        return NOT_ASSESSED
    if not a.mfa_enabled or a.mfa_method == "none":
        return FAIL, "No MFA method registered."
    return PASS, ""


def zt01(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.is_human and a.privileged):
        return None
    return _mfa_missing(a)


def zt02(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.is_human and not a.privileged):
        return None
    return _mfa_missing(a)


def zt03(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.is_human and a.privileged and a.mfa_enabled):
        return None
    if not a.mfa_method:
        return NOT_ASSESSED
    if a.mfa_method not in p["phishing_resistant_methods"]:
        return FAIL, f"MFA method is '{a.mfa_method}', which can be phished."
    return PASS, ""


def zt04(a: Account, p: dict) -> Outcome:
    if not is_enabled(a):
        return None
    if a.account_type == "shared":
        return FAIL, "Account is marked as shared by more than one person."
    return PASS, ""


def zt05(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.account_type in ("user", "admin")):
        return None
    if a.employment_status is None:
        return NOT_ASSESSED
    if a.employment_status == "terminated":
        return FAIL, "HR status is terminated but the account is enabled."
    return PASS, ""


def zt06(a: Account, p: dict) -> Outcome:
    if not is_enabled(a) or a.last_login_days == NEVER:
        return None
    if a.last_login_days is None:
        return NOT_ASSESSED
    limit = p["inactivity_days"]
    if a.last_login_days > limit:
        return FAIL, f"Last sign-in {a.last_login_days} days ago (limit {limit})."
    return PASS, ""


def zt07(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.last_login_days == NEVER):
        return None
    if a.created_days is None:
        return NOT_ASSESSED
    grace = p["never_used_grace_days"]
    if a.created_days > grace:
        return FAIL, f"Created {a.created_days} days ago and never signed in (grace {grace} days)."
    return PASS, ""


def zt08(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.account_type == "service"):
        return None
    if a.interactive_login is None:
        return NOT_ASSESSED
    if a.interactive_login:
        return FAIL, "Service account can sign in interactively."
    return PASS, ""


def zt09(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.account_type == "service"):
        return None
    if a.password_age_days is None:
        return NOT_ASSESSED
    limit = p["service_password_max_age_days"]
    if a.password_age_days > limit:
        return FAIL, f"Password is {a.password_age_days} days old (limit {limit})."
    return PASS, ""


def zt10(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.is_human and a.privileged):
        return None
    if a.mailbox_enabled is None:
        return NOT_ASSESSED
    if a.mailbox_enabled:
        return FAIL, "Account has admin rights and an email mailbox, so it is used for daily work."
    return PASS, ""


def zt11(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.account_type == "guest"):
        return None
    if a.privileged:
        return FAIL, "External account holds privileged access."
    return PASS, ""


def zt12(a: Account, p: dict) -> Outcome:
    if not (is_enabled(a) and a.privileged):
        return None
    if a.last_access_review_days is None:
        return NOT_ASSESSED
    limit = p["privileged_review_max_days"]
    if a.last_access_review_days > limit:
        return FAIL, f"Privileged access last reviewed {a.last_access_review_days} days ago (limit {limit})."
    return PASS, ""


ACCOUNT_CHECKS: dict[str, Callable[[Account, dict], Outcome]] = {
    "ZT-ID-01": zt01, "ZT-ID-02": zt02, "ZT-ID-03": zt03, "ZT-ID-04": zt04,
    "ZT-ID-05": zt05, "ZT-ID-06": zt06, "ZT-ID-07": zt07, "ZT-ID-08": zt08,
    "ZT-ID-09": zt09, "ZT-ID-10": zt10, "ZT-ID-11": zt11, "ZT-ID-12": zt12,
}


def privileged_ratio(accounts: list[Account], p: dict) -> tuple[str, str]:
    """ZT-ID-13: organization-level check on the number of privileged accounts."""
    enabled = [a for a in accounts if is_enabled(a)]
    privileged = [a for a in enabled if a.privileged]
    allowed = max(int(p["max_privileged_ratio"] * len(enabled)), p.get("min_privileged_allowance", 2))
    detail = (f"{len(privileged)} of {len(enabled)} enabled accounts are privileged "
              f"(allowed: {allowed}, from {p['max_privileged_ratio']:.0%} or a minimum of "
              f"{p.get('min_privileged_allowance', 2)}).")
    return (FAIL if len(privileged) > allowed else PASS), detail
