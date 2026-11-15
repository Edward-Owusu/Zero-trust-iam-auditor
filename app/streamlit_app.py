"""Interactive dashboard for the Zero Trust IAM Auditor.

Run locally:   streamlit run app/streamlit_app.py

Layout: no sidebar. The main screen is a maturity ladder for the CISA Zero Trust Identity pillar, and an
identity roster that sorts every account needing action into lanes by account type.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ui  # noqa: E402
from iam_audit import __version__, audit, parse_accounts  # noqa: E402
from iam_audit.engine import BASELINES, ZTMM_STAGES  # noqa: E402
from iam_audit.loader import DataError  # noqa: E402
from iam_audit.reporting import DISCLAIMER, STATUS_TEXT, grouped_findings, to_csv, to_html, to_json, to_markdown  # noqa: E402

SAMPLES = {
    "Small manufacturer with identity gaps (fictional)":
        ("Riverbend Components (fictional)", ROOT / "samples" / "riverbend_components_accounts.csv"),
    "Cold storage warehouse with mature controls (fictional)":
        ("Northfield Cold Logistics (fictional)", ROOT / "samples" / "northfield_cold_logistics_accounts.csv"),
}
TEMPLATE = ROOT / "samples" / "accounts_template.csv"
STAGE_COLOR = {"Traditional": "#B42318", "Initial": "#D97706", "Advanced": "#4338CA", "Optimal": "#15803D"}
RATING_COLOR = {"Low": "#15803D", "Moderate": "#D97706", "High": "#C2410C", "Critical": "#B42318"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

PAL = ui.Palette(accent="#4338CA", band="#1E2235", band_text="#FFFFFF", band_sub="#B8BEDA",
                 card="#FFFFFF", line="#DCE1EE", ink="#1E2235", muted="#5B6280")
ui.setup("Zero Trust identity audit", "CISA Zero Trust Maturity Model · Identity pillar",
         "Upload an account export and find the identity gaps attackers use most: missing MFA, forgotten accounts, "
         "standing admin rights and misused service accounts. Each finding maps to NIST SP 800-53.", "🔐", PAL)
st.markdown("""<style>
.ladder { display:grid; grid-template-columns: 170px repeat(4, 1fr); gap:6px; align-items:stretch; margin-bottom:8px }
.ladder .fn { font-weight:700; color:#1E2235; display:flex; align-items:center }
.ladder .st { border-radius:8px; padding:9px 8px; text-align:center; font-size:12.5px; font-weight:600;
              background:#E9ECF5; color:#8A90AA }
.ladder .st.on { color:#fff }
.ladder .basis { grid-column: 2 / 6; font-size:12.5px; color:#5B6280; margin:-2px 0 10px }
.lane h4 { font: 700 13px Arial; letter-spacing:.08em; text-transform:uppercase; color:#5B6280; margin:0 0 6px }
</style>""", unsafe_allow_html=True)

# ---- Top row ----------------------------------------------------------------------------------------
t1, t2, t3 = st.columns([1.6, 2.8, 1.2], vertical_alignment="top")
text, org = None, "My organization"
with t1:
    st.caption("Account data")
    source = ui.choose("Account data", ["Use a sample", "Upload my own CSV"], key="source", format_func=ui.source_label)
with t2:
    if source == "Use a sample":
        st.caption("Sample organization")
        org, path = SAMPLES[st.selectbox("Sample organization", list(SAMPLES), label_visibility="collapsed")]
        text = path.read_text(encoding="utf-8")
    else:
        st.caption("Account export (.csv)")
        upload = st.file_uploader("Account export (.csv)", type=["csv"], label_visibility="collapsed")
        if upload is not None:
            text = upload.getvalue().decode("utf-8-sig", errors="replace")
with t3:
    st.caption("NIST SP 800-53 baseline")
    baseline = st.selectbox("NIST SP 800-53 baseline", BASELINES, index=1, format_func=str.title,
                            label_visibility="collapsed")
if source != "Use a sample":
    o1, o2 = st.columns([2, 1], vertical_alignment="bottom")
    org = o1.text_input("Organization name", "My organization")
    o2.download_button("Download blank template", TEMPLATE.read_bytes(), file_name="accounts_template.csv",
                       mime="text/csv")

if text is None:
    st.info("Upload an account export above, or switch to a sample, to see results.")
    ui.footer("iam_audit", __version__, "Zero-trust-iam-auditor", DISCLAIMER)
    st.stop()
try:
    accounts = parse_accounts(text)
except DataError as exc:
    st.error(f"The file could not be read. {exc} Fix the file and upload it again.")
    st.stop()

result = audit(accounts, baseline=baseline, organization=org)
m = result.metrics


def pct(v):
    return "n/a" if v is None else f"{v:.0f}%"


st.markdown(f"<div class='g-sec'>{escape(result.organization)}</div>", unsafe_allow_html=True)
st.caption(f"{m['accounts_total']} accounts, {m['accounts_enabled']} enabled, {m['accounts_privileged']} privileged, "
           f"{m['accounts_service']} service. {result.baseline.title()} baseline.")
g, tl = st.columns([1, 3], vertical_alignment="center")
with g:
    st.markdown(ui.gauge(result.risk_score, f"{result.risk_rating} risk",
                         RATING_COLOR.get(result.risk_rating, PAL.accent), PAL,
                         caption="Risk exposure, higher is worse"), unsafe_allow_html=True)
with tl:
    ui.tiles([(pct(m["mfa_coverage_pct"]), "MFA coverage"),
              (pct(m["privileged_phishing_resistant_pct"]), "Admins with phishing-resistant MFA", "#B42318"),
              (m["accounts_high_risk"], "Accounts with critical or high findings", "#C2410C"),
              (m["accounts_with_findings"], "Accounts needing any action")], PAL)

view = ui.choose("View", ["Maturity ladder", "Identity roster", "Findings", "All checks"], key="view")

if view == "Maturity ladder":
    ui.section("Where you stand on the Identity pillar", "Estimated from the account export alone. Advanced and "
               "Optimal need evidence an export cannot show, such as continuous validation.")
    rows = []
    for z in result.ztmm:
        reached = ZTMM_STAGES.index(z.stage) if z.stage in ZTMM_STAGES else -1
        cells = "".join(
            f"<div class='st{' on' if i <= reached else ''}' style='{'background:' + STAGE_COLOR[z.stage] if i <= reached else ''}'>"
            f"{'● ' + s if i == reached else s}</div>" for i, s in enumerate(ZTMM_STAGES))
        rows.append(f"<div class='ladder'><div class='fn'>{escape(z.function)}</div>{cells}"
                    f"<div class='basis'>{escape(z.basis)}</div></div>")
    st.markdown("".join(rows), unsafe_allow_html=True)

elif view == "Identity roster":
    ui.section("Accounts needing action, by type", "Worst finding sets the colour. Fix the left-most lanes first.")
    by_acct = result.findings_by_account()
    lanes: dict[str, list] = {}
    for acct, fs in by_acct.items():
        lanes.setdefault((fs[0].account_type or "other").lower(), []).append((acct, fs))
    order = sorted(lanes, key=lambda t: min(SEV_RANK[f.severity] for _, fs in lanes[t] for f in fs))
    if not order:
        st.success("No accounts need action.")
    cols = st.columns(max(1, min(len(order), 5)))
    for i, lane in enumerate(order):
        with cols[i % len(cols)]:
            st.markdown(f"<div class='lane'><h4>{escape(lane)} · {len(lanes[lane])}</h4></div>", unsafe_allow_html=True)
            for acct, fs in sorted(lanes[lane], key=lambda x: min(SEV_RANK[f.severity] for f in x[1])):
                worst = min(fs, key=lambda f: SEV_RANK[f.severity]).severity
                items = "".join(f"<div class='s'>· {escape(f.title)}</div>" for f in fs)
                ui.card(f"<div class='h'>{escape(acct)}</div>", f"{ui.sev_pill(worst)}"
                        f"<span class='s'>{len(fs)} finding(s)</span>{items}", accent=ui.SEV_COLORS[worst])

elif view == "Findings":
    groups = grouped_findings(result)
    if not groups:
        st.success("No findings for this baseline.")
    for g in groups:
        f = g["finding"]
        n = len(g["accounts"])
        details = "".join(f"<li>{escape(d)}</li>" for d in g["details"])
        ui.card(f"<div class='h'>{ui.sev_pill(f.severity)}{escape(f.rule_id)} · {escape(f.title)}"
                f"<span class='s' style='float:right'>{n} account(s)</span></div>",
                f"<ul class='s' style='margin:4px 0 6px 18px;padding:0'>{details}</ul>"
                f"<div class='f'><b>Fix:</b> {escape(f.remediation)}</div>"
                f"<div class='s'>Controls {escape(', '.join(f.controls))} · ZTMM {escape(f.ztmm_function)}</div>",
                accent=ui.SEV_COLORS[f.severity])
else:
    st.dataframe(pd.DataFrame([{"Check": s.rule_id, "Title": s.title, "Controls": ", ".join(s.controls),
                                "Severity": s.severity.title(), "Result": STATUS_TEXT[s.status],
                                "Failing": f"{s.failed} of {s.in_scope}", "Not assessed": s.not_assessed}
                               for s in result.rules]), hide_index=True, use_container_width=True)

ui.downloads([("HTML report", to_html(result), "identity_audit.html", "text/html"),
              ("Markdown", to_markdown(result), "identity_audit.md", "text/markdown"),
              ("CSV findings", to_csv(result), "identity_audit_findings.csv", "text/csv"),
              ("JSON results", to_json(result), "identity_audit.json", "application/json")])
ui.footer("iam_audit", __version__, "Zero-trust-iam-auditor", DISCLAIMER)
