"""Interactive dashboard for the Zero Trust IAM Auditor.

Run locally:   streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iam_audit import __version__, audit, parse_accounts  # noqa: E402
from iam_audit.engine import BASELINES  # noqa: E402
from iam_audit.loader import DataError  # noqa: E402
from iam_audit.reporting import DISCLAIMER, STATUS_TEXT, grouped_findings, to_csv, to_html, to_json, to_markdown  # noqa: E402

SAMPLES = {
    "Small manufacturer with identity gaps (fictional)":
        ("Riverbend Components (fictional)", ROOT / "samples" / "riverbend_components_accounts.csv"),
    "Cold storage warehouse with mature controls (fictional)":
        ("Northfield Cold Logistics (fictional)", ROOT / "samples" / "northfield_cold_logistics_accounts.csv"),
}
TEMPLATE = ROOT / "samples" / "accounts_template.csv"
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

st.set_page_config(page_title="Zero Trust IAM Auditor", page_icon="🔐", layout="wide")
st.title("Zero Trust identity audit")
st.write(
    "Upload an account export and find the identity gaps attackers use most: missing MFA, "
    "forgotten accounts, standing admin rights, and misused service accounts. Each finding maps to "
    "NIST SP 800-53 controls and the CISA Zero Trust Maturity Model Identity pillar."
)

with st.sidebar:
    st.header("1. Choose data")
    source = st.radio("Account data", ["Use a sample", "Upload my own CSV"], label_visibility="collapsed")
    text: str | None = None
    org = "My organization"
    if source == "Use a sample":
        choice = st.selectbox("Sample organization", list(SAMPLES))
        org, path = SAMPLES[choice]
        text = path.read_text(encoding="utf-8")
    else:
        upload = st.file_uploader("Account export (.csv)", type=["csv"])
        st.download_button("Download blank template", TEMPLATE.read_bytes(),
                           file_name="accounts_template.csv", mime="text/csv")
        org = st.text_input("Organization name", "My organization")
        if upload is not None:
            text = upload.getvalue().decode("utf-8-sig", errors="replace")

    st.header("2. Choose baseline")
    baseline = st.selectbox("NIST SP 800-53 baseline", BASELINES, index=1, format_func=str.title)
    st.caption(f"iam_audit {__version__}. Runs entirely in this session; uploaded files are not stored.")

if text is None:
    st.info("Upload an account export in the sidebar, or switch to a sample, to see results.")
    st.stop()

try:
    accounts = parse_accounts(text)
except DataError as exc:
    st.error(f"The file could not be read. {exc} Fix the file and upload it again.")
    st.stop()

result = audit(accounts, baseline=baseline, organization=org)
m = result.metrics

st.subheader(result.organization)
st.caption(f"{m['accounts_total']} accounts, {m['accounts_enabled']} enabled, "
           f"{m['accounts_privileged']} privileged. {result.baseline.title()} baseline.")


def pct(v):
    return "n/a" if v is None else f"{v:.0f}%"


c1, c2, c3, c4 = st.columns(4)
c1.metric(f"Risk exposure: {result.risk_rating}", f"{result.risk_score:.1f} / 100")
c2.metric("MFA coverage", pct(m["mfa_coverage_pct"]))
c3.metric("Admins with phishing-resistant MFA", pct(m["privileged_phishing_resistant_pct"]))
c4.metric("Accounts with critical or high findings", m["accounts_high_risk"])

st.markdown("#### Zero Trust Maturity Model: Identity pillar")
st.dataframe(pd.DataFrame([{"Function": z.function, "Estimated stage": z.stage, "Basis": z.basis}
                           for z in result.ztmm]), hide_index=True)

tab_f, tab_a, tab_c = st.tabs(["Findings", "Accounts needing action", "All checks"])
with tab_f:
    groups = grouped_findings(result)
    if not groups:
        st.success("No findings for this baseline.")
    for g in groups:
        f = g["finding"]
        n = len(g["accounts"])
        label = f"{SEVERITY_ICON[f.severity]} {f.severity.title()}: {f.rule_id} {f.title}"
        if n:
            label += f" ({n} account{'s' if n != 1 else ''})"
        with st.expander(label):
            st.markdown(f"**Controls:** {', '.join(f.controls)} · **ZTMM function:** {f.ztmm_function}")
            for d in g["details"]:
                st.markdown(f"- {d}")
            st.markdown(f"**Remediation:** {f.remediation}")
with tab_a:
    rows = [{"Account": a, "Type": fs[0].account_type or "",
             "Findings": len(fs), "Issues": "; ".join(f.title for f in fs)}
            for a, fs in result.findings_by_account().items()]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.success("No accounts need action.")
with tab_c:
    st.dataframe(pd.DataFrame([{"Check": s.rule_id, "Title": s.title, "Controls": ", ".join(s.controls),
                                "Severity": s.severity.title(), "Result": STATUS_TEXT[s.status],
                                "Failing": f"{s.failed} of {s.in_scope}", "Not assessed": s.not_assessed}
                               for s in result.rules]), hide_index=True)

st.subheader("Download the report")
d1, d2, d3, d4 = st.columns(4)
d1.download_button("HTML report", to_html(result), "identity_audit.html", "text/html")
d2.download_button("Markdown", to_markdown(result), "identity_audit.md", "text/markdown")
d3.download_button("CSV findings", to_csv(result), "identity_audit_findings.csv", "text/csv")
d4.download_button("JSON results", to_json(result), "identity_audit.json", "application/json")
st.caption(DISCLAIMER)
