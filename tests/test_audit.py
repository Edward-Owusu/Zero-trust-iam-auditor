import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iam_audit import audit, load_accounts, load_policy, parse_accounts  # noqa: E402
from iam_audit.checks import FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS  # noqa: E402
from iam_audit.cli import main  # noqa: E402
from iam_audit.loader import NEVER, DataError  # noqa: E402
from iam_audit.reporting import WRITERS  # noqa: E402

WEAK = ROOT / "samples" / "riverbend_components_accounts.csv"
MATURE = ROOT / "samples" / "northfield_cold_logistics_accounts.csv"
HEADER = ("username,account_type,enabled,privileged,groups,mfa_enabled,mfa_method,last_login_days,"
          "created_days,employment_status,mailbox_enabled,interactive_login,password_age_days,"
          "last_access_review_days\n")


def run(rows: str, **kw):
    return audit(parse_accounts(HEADER + rows), **kw)


def ids(result):
    return {f.rule_id for f in result.findings}


def stat(result, rule_id):
    return next(s for s in result.rules if s.rule_id == rule_id)


class TestLoader(unittest.TestCase):
    def test_parses_booleans_numbers_and_never(self):
        a = parse_accounts(HEADER + "x,user,Yes,,Staff;Sales,1,app_push,never,10,active,,,,\n")[0]
        self.assertTrue(a.enabled)
        self.assertTrue(a.mfa_enabled)
        self.assertEqual(a.groups, ["Staff", "Sales"])
        self.assertEqual(a.last_login_days, NEVER)
        self.assertIsNone(a.privileged_flag)

    def test_bad_values_report_row_number(self):
        with self.assertRaisesRegex(DataError, "Row 2"):
            parse_accounts(HEADER + "x,user,maybe,,,,,,,,,,,\n")
        with self.assertRaisesRegex(DataError, "account_type"):
            parse_accounts(HEADER + "x,robot,true,,,,,,,,,,,\n")

    def test_duplicate_and_missing_header(self):
        with self.assertRaisesRegex(DataError, "more than once"):
            parse_accounts(HEADER + "x,user,true,,,,,,,,,,,\nX,user,true,,,,,,,,,,,\n")
        with self.assertRaisesRegex(DataError, "username"):
            parse_accounts("name,enabled\nx,true\n")

    def test_utf8_bom_is_accepted(self):
        self.assertEqual(len(parse_accounts("\ufeff" + HEADER + "x,user,true,,,,,,,,,,,\n")), 1)


class TestChecks(unittest.TestCase):
    def test_privileged_by_group_membership(self):
        r = run("adm,admin,true,,Domain Admins,false,none,1,100,active,false,false,,10\n")
        self.assertIn("ZT-ID-01", ids(r))
        self.assertEqual(r.metrics["accounts_privileged"], 1)

    def test_phishable_mfa_on_admin(self):
        r = run("adm,admin,true,true,,true,sms,1,100,active,false,false,,10\n")
        self.assertIn("ZT-ID-03", ids(r))
        r = run("adm,admin,true,true,,true,fido2,1,100,active,false,false,,10\n")
        self.assertNotIn("ZT-ID-03", ids(r))

    def test_disabled_accounts_are_ignored(self):
        r = run("old,user,false,,,false,none,900,2000,terminated,,,,\n")
        self.assertEqual(r.findings, [])

    def test_terminated_but_enabled(self):
        r = run("gone,user,true,,,true,app_push,5,500,terminated,true,,,\n")
        self.assertIn("ZT-ID-05", ids(r))

    def test_stale_and_never_used(self):
        r = run("a,user,true,,,true,totp,120,500,active,true,,,\n"
                "b,user,true,,,true,totp,never,45,active,true,,,\n"
                "c,user,true,,,true,totp,never,5,active,true,,,\n")
        found = {(f.rule_id, f.account) for f in r.findings}
        self.assertIn(("ZT-ID-06", "a"), found)
        self.assertIn(("ZT-ID-07", "b"), found)
        self.assertNotIn(("ZT-ID-07", "c"), found)  # new hire within the grace period

    def test_service_account_checks(self):
        r = run("svc,service,true,,,,,0,900,,false,true,800,\n")
        self.assertTrue({"ZT-ID-08", "ZT-ID-09"} <= ids(r))
        self.assertNotIn("ZT-ID-02", ids(r))  # MFA checks do not apply to service accounts

    def test_admin_with_mailbox_and_guest_admin(self):
        r = run("boss,user,true,true,,true,fido2,1,100,active,true,false,,10\n"
                "vendor,guest,true,true,,true,fido2,1,100,,false,false,,10\n")
        found = {(f.rule_id, f.account) for f in r.findings}
        self.assertIn(("ZT-ID-10", "boss"), found)
        self.assertIn(("ZT-ID-11", "vendor"), found)

    def test_missing_data_is_not_assessed_not_passed(self):
        r = run("a,user,true,,,,,1,100,active,true,,,\n")
        self.assertEqual(stat(r, "ZT-ID-02").status, NOT_ASSESSED)

    def test_no_items_in_scope_is_not_applicable(self):
        r = run("a,user,true,,,true,totp,1,100,active,true,,,\n")
        self.assertEqual(stat(r, "ZT-ID-08").status, NOT_APPLICABLE)

    def test_privileged_ratio_uses_minimum_allowance(self):
        users = "".join(f"u{i},user,true,,,true,totp,1,100,active,true,,,\n" for i in range(10))
        two_admins = ("a1,admin,true,true,,true,fido2,1,100,active,false,false,,10\n"
                      "a2,admin,true,true,,true,fido2,1,100,active,false,false,,10\n")
        self.assertEqual(stat(run(users + two_admins), "ZT-ID-13").status, PASS)
        three = two_admins + "a3,admin,true,true,,true,fido2,1,100,active,false,false,,10\n"
        self.assertEqual(stat(run(users + three), "ZT-ID-13").status, FAIL)

    def test_policy_override(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"inactivity_days": 200}, fh)
        r = run("a,user,true,,,true,totp,120,500,active,true,,,\n", policy=load_policy(fh.name))
        self.assertNotIn("ZT-ID-06", ids(r))


class TestAuditResults(unittest.TestCase):
    def test_weak_sample(self):
        r = audit(load_accounts(WEAK))
        self.assertIn(r.risk_rating, {"High", "Critical"})
        self.assertTrue({"ZT-ID-01", "ZT-ID-05", "ZT-ID-08", "ZT-ID-11"} <= ids(r))
        self.assertTrue(all(z.stage == "Traditional" for z in r.ztmm))

    def test_mature_sample(self):
        r = audit(load_accounts(MATURE))
        self.assertEqual(r.risk_rating, "Low")
        self.assertEqual(r.metrics["mfa_coverage_pct"], 100.0)
        stages = {z.function: z.stage for z in r.ztmm}
        self.assertEqual(stages["Authentication"], "Advanced")

    def test_low_baseline_drops_moderate_only_checks(self):
        r = audit(load_accounts(WEAK), baseline="low")
        rule_ids = {s.rule_id for s in r.rules}
        self.assertNotIn("ZT-ID-10", rule_ids)  # AC-6(2) is moderate and high only
        self.assertIn("ZT-ID-01", rule_ids)

    def test_findings_sorted_by_severity(self):
        order = ["critical", "high", "medium", "low"]
        sevs = [order.index(f.severity) for f in audit(load_accounts(WEAK)).findings]
        self.assertEqual(sevs, sorted(sevs))


class TestReportingAndCli(unittest.TestCase):
    def test_writers(self):
        r = audit(load_accounts(WEAK), organization="<script>x</script>")
        for fmt, writer in WRITERS.items():
            self.assertTrue(writer(r).strip(), fmt)
        self.assertNotIn("<script>x</script>", WRITERS["html"](r))
        json.loads(WRITERS["json"](r))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main([str(WEAK), "--out", tmp, "--fail-on", "critical"]), 2)
            self.assertTrue(any(Path(tmp).glob("*.html")))
            self.assertEqual(main([str(MATURE), "--out", tmp, "--fail-on", "high"]), 0)
            bad = Path(tmp) / "bad.csv"
            bad.write_text("name\nx\n", encoding="utf-8")
            self.assertEqual(main([str(bad), "--out", tmp]), 1)


if __name__ == "__main__":
    unittest.main()
