"""Read an account export (CSV) into normalized Account records.

The CSV needs one row per account. Only `username` is strictly required;
any column that is missing or blank is treated as "not reported", and the
checks that depend on it are skipped for that account rather than passed.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path

ACCOUNT_TYPES = ("user", "admin", "service", "shared", "guest")
HUMAN_TYPES = ("user", "admin", "shared", "guest")
NEVER = -1  # last_login_days value "never": the account has never signed in

_TRUE = {"true", "yes", "y", "1", "enabled"}
_FALSE = {"false", "no", "n", "0", "disabled"}


class DataError(ValueError):
    """Raised when the account export cannot be read."""


@dataclass
class Account:
    username: str
    row: int
    account_type: str = "user"
    enabled: bool | None = None
    privileged_flag: bool | None = None
    groups: list[str] = field(default_factory=list)
    mfa_enabled: bool | None = None
    mfa_method: str | None = None
    last_login_days: int | None = None
    created_days: int | None = None
    employment_status: str | None = None
    mailbox_enabled: bool | None = None
    interactive_login: bool | None = None
    password_age_days: int | None = None
    last_access_review_days: int | None = None
    privileged: bool = False  # resolved by the engine from flag + group membership

    @property
    def is_human(self) -> bool:
        return self.account_type in HUMAN_TYPES


def _bool(value: str, column: str, row: int) -> bool | None:
    v = (value or "").strip().lower()
    if not v:
        return None
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise DataError(f"Row {row}: column '{column}' must be true or false, got '{value}'.")


def _int(value: str, column: str, row: int) -> int | None:
    v = (value or "").strip()
    if not v:
        return None
    try:
        n = int(float(v))
    except ValueError as exc:
        raise DataError(f"Row {row}: column '{column}' must be a number, got '{value}'.") from exc
    if n < 0:
        raise DataError(f"Row {row}: column '{column}' cannot be negative.")
    return n


def _text(value: str) -> str | None:
    v = (value or "").strip().lower()
    return v or None


def parse_accounts(text: str) -> list[Account]:
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    if not reader.fieldnames or "username" not in [f.strip() for f in reader.fieldnames]:
        raise DataError("The file needs a header row with at least a 'username' column.")
    accounts: list[Account] = []
    seen: set[str] = set()
    for i, raw in enumerate(reader, start=2):  # row 1 is the header
        r = {(k or "").strip(): (v or "") for k, v in raw.items()}
        name = r.get("username", "").strip()
        if not name:
            continue
        if name.lower() in seen:
            raise DataError(f"Row {i}: username '{name}' appears more than once.")
        seen.add(name.lower())
        acct_type = _text(r.get("account_type", "")) or "user"
        if acct_type not in ACCOUNT_TYPES:
            raise DataError(f"Row {i}: account_type must be one of {', '.join(ACCOUNT_TYPES)}, got '{acct_type}'.")
        groups = [g.strip() for g in r.get("groups", "").split(";") if g.strip()]
        accounts.append(Account(
            username=name,
            row=i,
            account_type=acct_type,
            enabled=_bool(r.get("enabled", ""), "enabled", i),
            privileged_flag=_bool(r.get("privileged", ""), "privileged", i),
            groups=groups,
            mfa_enabled=_bool(r.get("mfa_enabled", ""), "mfa_enabled", i),
            mfa_method=_text(r.get("mfa_method", "")),
            last_login_days=(NEVER if r.get("last_login_days", "").strip().lower() == "never"
                             else _int(r.get("last_login_days", ""), "last_login_days", i)),
            created_days=_int(r.get("created_days", ""), "created_days", i),
            employment_status=_text(r.get("employment_status", "")),
            mailbox_enabled=_bool(r.get("mailbox_enabled", ""), "mailbox_enabled", i),
            interactive_login=_bool(r.get("interactive_login", ""), "interactive_login", i),
            password_age_days=_int(r.get("password_age_days", ""), "password_age_days", i),
            last_access_review_days=_int(r.get("last_access_review_days", ""), "last_access_review_days", i),
        ))
    if not accounts:
        raise DataError("The file has a header but no account rows.")
    return accounts


def load_accounts(path: str | Path) -> list[Account]:
    return parse_accounts(Path(path).read_text(encoding="utf-8-sig"))
