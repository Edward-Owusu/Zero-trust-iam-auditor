"""Run an identity audit over a list of accounts."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks import ACCOUNT_CHECKS, FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS, is_enabled, privileged_ratio
from .loader import Account

DATA_DIR = Path(__file__).parent / "data"
BASELINES = ("low", "moderate", "high")
SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}
RISK_BANDS = [(10, "Low"), (25, "Moderate"), (50, "High"), (101, "Critical")]
ZTMM_STAGES = ("Traditional", "Initial", "Advanced", "Optimal")


def _load(name: str) -> dict:
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


def load_policy(path: str | Path | None = None) -> dict:
    policy = _load("policy.json")
    if path:
        policy.update(json.loads(Path(path).read_text(encoding="utf-8")))
    policy["privileged_groups"] = [g.lower() for g in policy["privileged_groups"]]
    policy["phishing_resistant_methods"] = [m.lower() for m in policy["phishing_resistant_methods"]]
    return policy


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    controls: list[str]
    ztmm_function: str
    account: str | None
    account_type: str | None
    detail: str
    remediation: str


@dataclass
class RuleStat:
    rule_id: str
    title: str
    severity: str
    controls: list[str]
    ztmm_function: str
    status: str
    in_scope: int
    failed: int
    not_assessed: int


@dataclass
class ZtmmEstimate:
    function: str
    stage: str
    basis: str


@dataclass
class AuditResult:
    organization: str
    baseline: str
    generated_at: str
    tool_version: str
    risk_score: float
    risk_rating: str
    metrics: dict[str, Any]
    rules: list[RuleStat] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ztmm: list[ZtmmEstimate] = field(default_factory=list)

    def findings_by_account(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.account or "(organization)", []).append(f)
        return out

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def risk_rating(score: float) -> str:
    for upper, label in RISK_BANDS:
        if score < upper:
            return label
    return "Critical"


def _resolve_privileged(accounts: list[Account], policy: dict) -> None:
    groups = set(policy["privileged_groups"])
    for a in accounts:
        a.privileged = bool(a.privileged_flag) or any(g.lower() in groups for g in a.groups)


def _pct(num: int, den: int) -> float | None:
    return round(100 * num / den, 1) if den else None


def _ztmm(stats: dict[str, RuleStat]) -> list[ZtmmEstimate]:
    def failed(*ids: str) -> bool:
        return any(stats[i].status == FAIL for i in ids if i in stats)

    def assessed(*ids: str) -> bool:
        return all(i in stats and stats[i].status in (PASS, FAIL, NOT_APPLICABLE) for i in ids)

    out: list[ZtmmEstimate] = []

    # Authentication
    if not assessed("ZT-ID-01", "ZT-ID-02", "ZT-ID-04"):
        out.append(ZtmmEstimate("Authentication", "Not assessed", "MFA data missing for some accounts."))
    elif failed("ZT-ID-01", "ZT-ID-02", "ZT-ID-04"):
        out.append(ZtmmEstimate("Authentication", "Traditional",
                                "Some accounts lack MFA or are shared, so access still relies on passwords alone."))
    elif failed("ZT-ID-03") or not assessed("ZT-ID-03"):
        out.append(ZtmmEstimate("Authentication", "Initial",
                                "All accounts use MFA, but administrators do not all use phishing-resistant MFA."))
    else:
        out.append(ZtmmEstimate("Authentication", "Advanced",
                                "All accounts use MFA and all administrators use phishing-resistant MFA. "
                                "Optimal also needs continuous validation, which an account export cannot show."))

    # Identity Stores (account lifecycle hygiene)
    if not assessed("ZT-ID-05", "ZT-ID-06"):
        out.append(ZtmmEstimate("Identity Stores", "Not assessed", "Employment status or sign-in data missing."))
    elif failed("ZT-ID-05"):
        out.append(ZtmmEstimate("Identity Stores", "Traditional",
                                "Accounts of departed people remain enabled, so offboarding is not tied to the identity store."))
    elif failed("ZT-ID-06", "ZT-ID-07"):
        out.append(ZtmmEstimate("Identity Stores", "Initial",
                                "Departed staff are removed, but inactive or unused accounts remain enabled."))
    else:
        out.append(ZtmmEstimate("Identity Stores", "Advanced",
                                "No orphaned, inactive, or unused accounts. Optimal needs evidence of fully "
                                "automated lifecycle across all identity stores, which an export cannot show."))

    # Access Management
    am_core = ("ZT-ID-08", "ZT-ID-11", "ZT-ID-12")
    am_more = ("ZT-ID-09", "ZT-ID-10", "ZT-ID-13")
    if not [i for i in am_core + am_more if i in stats]:
        out.append(ZtmmEstimate("Access Management", "Not assessed", "No access management checks apply at this baseline."))
    elif failed(*am_core):
        out.append(ZtmmEstimate("Access Management", "Traditional",
                                "Privileged access is unreviewed, held by external accounts, or available "
                                "to service accounts interactively."))
    elif failed(*am_more):
        out.append(ZtmmEstimate("Access Management", "Initial",
                                "Privileged access is reviewed, but admins share daily-use accounts, service "
                                "credentials are stale, or standing admin accounts are too many."))
    else:
        out.append(ZtmmEstimate("Access Management", "Advanced",
                                "Privileged access is separated, reviewed, and limited. Optimal needs just-in-time, "
                                "per-session access, which an export cannot show."))
    return out


def audit(
    accounts: list[Account],
    baseline: str = "moderate",
    organization: str = "Unnamed organization",
    policy: dict | None = None,
) -> AuditResult:
    from . import __version__

    baseline = baseline.lower()
    if baseline not in BASELINES:
        raise ValueError(f"Baseline must be one of {BASELINES}, got '{baseline}'")
    policy = policy or load_policy()
    _resolve_privileged(accounts, policy)

    controls = {c["id"]: c for c in _load("controls.json")["controls"]}
    rules_meta = _load("rules.json")["rules"]
    in_baseline = {cid for cid, c in controls.items() if baseline in c["baselines"]}

    findings: list[Finding] = []
    stats: dict[str, RuleStat] = {}
    for meta in rules_meta:
        scoped_controls = [c for c in meta["controls"] if c in in_baseline]
        if not scoped_controls:
            continue
        in_scope = failed = not_assessed = 0

        def add(account: Account | None, detail: str) -> None:
            findings.append(Finding(meta["id"], meta["title"], meta["severity"], scoped_controls,
                                    meta["ztmm_function"], account.username if account else None,
                                    account.account_type if account else None, detail, meta["remediation"]))

        if meta["id"] == "ZT-ID-13":
            status, detail = privileged_ratio(accounts, policy)
            in_scope = 1
            if status == FAIL:
                failed = 1
                add(None, detail)
        else:
            check = ACCOUNT_CHECKS[meta["id"]]
            for a in accounts:
                outcome = check(a, policy)
                if outcome is None:
                    continue
                in_scope += 1
                if outcome == NOT_ASSESSED:
                    not_assessed += 1
                elif outcome[0] == FAIL:
                    failed += 1
                    add(a, outcome[1])
            assessed = in_scope - not_assessed
            if in_scope == 0:
                status = NOT_APPLICABLE
            elif failed:
                status = FAIL
            elif assessed == 0:
                status = NOT_ASSESSED
            else:
                status = PASS
        stats[meta["id"]] = RuleStat(meta["id"], meta["title"], meta["severity"], scoped_controls,
                                     meta["ztmm_function"], status, in_scope, failed, not_assessed)

    # Weighted risk exposure: each check contributes its severity weight times the share of
    # in-scope accounts that fail it, so one failing account in a hundred counts less than all of them.
    total_w = fail_w = 0.0
    for s in stats.values():
        assessed = s.in_scope - s.not_assessed
        if assessed <= 0:
            continue
        w = SEVERITY_WEIGHTS[s.severity]
        total_w += w
        fail_w += w * (s.failed / assessed)
    score = round(100 * fail_w / total_w, 1) if total_w else 0.0

    enabled = [a for a in accounts if is_enabled(a)]
    humans = [a for a in enabled if a.is_human]
    humans_known = [a for a in humans if a.mfa_enabled is not None]
    privileged = [a for a in enabled if a.privileged]
    priv_humans_mfa = [a for a in privileged if a.is_human and a.mfa_enabled and a.mfa_method]
    phish_res = [a for a in priv_humans_mfa if a.mfa_method in policy["phishing_resistant_methods"]]
    with_findings = {f.account for f in findings if f.account}
    high_risk = {f.account for f in findings if f.account and f.severity in ("critical", "high")}

    metrics = {
        "accounts_total": len(accounts),
        "accounts_enabled": len(enabled),
        "accounts_privileged": len(privileged),
        "accounts_service": sum(1 for a in enabled if a.account_type == "service"),
        "accounts_guest": sum(1 for a in enabled if a.account_type == "guest"),
        "mfa_coverage_pct": _pct(sum(1 for a in humans_known if a.mfa_enabled and a.mfa_method != "none"),
                                 len(humans_known)),
        "privileged_phishing_resistant_pct": _pct(len(phish_res),
                                                  sum(1 for a in privileged if a.is_human)),
        "accounts_with_findings": len(with_findings),
        "accounts_high_risk": len(high_risk),
    }

    order = list(SEVERITY_WEIGHTS)
    findings.sort(key=lambda f: (order.index(f.severity), f.rule_id, f.account or ""))
    return AuditResult(
        organization=organization,
        baseline=baseline,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tool_version=__version__,
        risk_score=score,
        risk_rating=risk_rating(score) if total_w else "Not rated",
        metrics=metrics,
        rules=list(stats.values()),
        findings=findings,
        ztmm=_ztmm(stats),
    )
