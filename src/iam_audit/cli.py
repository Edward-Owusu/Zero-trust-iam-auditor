"""Command-line interface.

Examples:
    iam-audit samples/riverbend_components_accounts.csv --org "Riverbend Components"
    iam-audit accounts.csv --baseline high --format html csv --out reports --fail-on critical
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import BASELINES, audit, load_policy
from .loader import DataError, load_accounts
from .reporting import WRITERS, grouped_findings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iam-audit",
                                description="Audit an account export against Zero Trust identity practices "
                                            "mapped to NIST SP 800-53 and the CISA Zero Trust Maturity Model.")
    p.add_argument("accounts", help="Path to the account export CSV")
    p.add_argument("--org", default=None, help="Organization name for the report (default: file name)")
    p.add_argument("--baseline", choices=BASELINES, default="moderate", help="NIST SP 800-53 baseline (default: moderate)")
    p.add_argument("--format", nargs="+", choices=sorted(WRITERS), default=["html", "csv"],
                   help="Report formats (default: html csv)")
    p.add_argument("--out", default="reports", help="Output directory (default: reports)")
    p.add_argument("--policy", help="JSON file overriding organization-defined parameters")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="Exit with code 2 if any finding at or above this severity exists")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        accounts = load_accounts(args.accounts)
        policy = load_policy(args.policy)
    except (OSError, DataError, ValueError) as exc:
        print(f"Could not read input: {exc}", file=sys.stderr)
        return 1

    org = args.org or Path(args.accounts).stem.replace("_", " ")
    result = audit(accounts, baseline=args.baseline, organization=org, policy=policy)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(args.accounts).stem + f"_{result.baseline}"
    for fmt in args.format:
        path = out / f"{stem}.{fmt}"
        path.write_text(WRITERS[fmt](result), encoding="utf-8")
        print(f"Wrote {path}")

    m = result.metrics
    print(f"\n{result.organization} | {result.baseline.title()} baseline | {m['accounts_total']} accounts")
    print(f"Identity risk exposure: {result.risk_score:.1f}/100 ({result.risk_rating})")
    mfa = "n/a" if m["mfa_coverage_pct"] is None else f"{m['mfa_coverage_pct']:.0f}%"
    print(f"MFA coverage: {mfa} | Accounts with critical or high findings: {m['accounts_high_risk']}")
    for z in result.ztmm:
        print(f"  ZTMM {z.function}: {z.stage}")
    for g in grouped_findings(result)[:5]:
        f = g["finding"]
        n = len(g["accounts"])
        who = f" ({n} account{'s' if n != 1 else ''})" if n else ""
        print(f"  [{f.severity.upper():8}] {f.rule_id} {f.title}{who}")

    if args.fail_on:
        order = ["critical", "high", "medium", "low"]
        if any(order.index(f.severity) <= order.index(args.fail_on) for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
