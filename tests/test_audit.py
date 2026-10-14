"""Test suite for secops-audit. Zero dependencies — runs with either:

    python3 -m unittest discover -s tests
    pytest tests/            # if you have pytest

Loads scripts/audit.py directly so no install/packaging is needed.
"""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")

_spec = importlib.util.spec_from_file_location("secops_audit", os.path.join(REPO, "scripts", "audit.py"))
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

DEFAULT_CFG = {"ignore": [], "exclude": [], "min_severity": "LOW", "entropy": False}


def scan_text(text, name="sample.py", cfg=None):
    d = tempfile.mkdtemp()
    path = os.path.join(d, name)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    use = dict(cfg or DEFAULT_CFG)
    return audit.audit(d, use, use.get("min_severity", "LOW"))["findings"]


def ids(findings):
    return {f["id"] for f in findings}


def scan_fixture(filename, entropy=False):
    return audit.scan_file(os.path.join(FIX, filename), filename, entropy)


class DetectionTests(unittest.TestCase):
    def test_detects_aws_key(self):
        self.assertIn("SECRET_AWS_KEY", ids(scan_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')))

    def test_detects_openai_key(self):
        self.assertIn("SECRET_OPENAI",
                      ids(scan_text('k = "sk-proj-AbCdEf0123456789GhIjKlMnOpQrStUv"')))

    def test_detects_private_key_block(self):
        self.assertIn("SECRET_PRIVATE_KEY",
                      ids(scan_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n")))

    def test_detects_dangerous_code(self):
        text = ('import os, pickle\n'
                'os.system("x")\n'
                'pickle.loads(b"")\n')
        found = ids(scan_text(text))
        self.assertIn("CODE_OS_SYSTEM", found)
        self.assertIn("CODE_PICKLE", found)

    def test_detects_sql_concat(self):
        self.assertIn("CODE_SQL_CONCAT",
                      ids(scan_text('cur.execute("SELECT " + name)')))

    def test_detects_iac_public_acl(self):
        self.assertIn("IAC_TF_PUBLIC_ACL",
                      ids(scan_text('acl = "public-read"', name="main.tf")))

    def test_multiline_underscore_key(self):
        self.assertIn("SECRET_GENERIC", ids(scan_text('db_password = "sup3rs3cr3tp@ss"')))

    def test_hashlib_sha256_not_flagged(self):
        self.assertNotIn("CODE_SHA1",
                         ids(scan_text("import hashlib\nhashlib.sha256(b'x')")))


class FalsePositiveTests(unittest.TestCase):
    def test_placeholder_not_flagged(self):
        self.assertNotIn("SECRET_GENERIC", ids(scan_text('api_key = "your_api_key_here"')))

    def test_code_value_not_flagged_as_secret(self):
        found = ids(scan_text("import random\ntoken = random.random()"))
        self.assertNotIn("SECRET_GENERIC", found)
        self.assertIn("CODE_WEAK_RANDOM", found)

    def test_python_os_system_not_flagged_as_php(self):
        self.assertNotIn("CODE_PHP_EXEC", ids(scan_text('import os\nos.system("x")')))

    def test_clean_fixture_has_no_findings(self):
        self.assertEqual(scan_fixture("clean.py"), [])


class IgnoreTests(unittest.TestCase):
    def test_inline_ignore_specific_rule(self):
        text = "import hashlib\nhashlib.md5(b'x')  # secops-audit: ignore CODE_MD5\n"
        self.assertNotIn("CODE_MD5", ids(scan_text(text)))

    def test_inline_ignore_all_rules(self):
        text = 'import os\nos.system("x")  # secops-audit: ignore\n'
        self.assertEqual(scan_text(text), [])

    def test_ignore_whole_file(self):
        text = '# secops-audit: ignore-file\nimport os\nos.system("x")\n'
        self.assertEqual(scan_text(text), [])

    def test_config_allowlist(self):
        cfg = dict(DEFAULT_CFG, ignore=[{"id": "CODE_OS_SYSTEM"}])
        self.assertNotIn("CODE_OS_SYSTEM", ids(scan_text('import os\nos.system("x")', cfg=cfg)))


class EntropyTests(unittest.TestCase):
    # key name the generic rule does NOT recognize, high-entropy value
    SECRETISH = 'K = "9f3Kx2Qz7Lm4Bv8Wp1Rt6Yh5Nd0Cs3Aj"\n'

    def test_entropy_off_by_default(self):
        self.assertNotIn("SECRET_ENTROPY", ids(scan_text(self.SECRETISH)))

    def test_entropy_on(self):
        cfg = dict(DEFAULT_CFG, entropy=True)
        self.assertIn("SECRET_ENTROPY", ids(scan_text(self.SECRETISH, cfg=cfg)))


class OutputTests(unittest.TestCase):
    def test_sarif_shape(self):
        res = audit.audit(FIX, DEFAULT_CFG, "LOW")
        sarif = json.loads(audit.render_sarif(res))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertTrue(run["results"])
        for r in run["results"]:
            self.assertIn("ruleId", r)
            self.assertIn("locations", r)
            self.assertIn(r["level"], {"error", "warning", "note"})

    def test_vulnerable_fixture_hits_expected_rules(self):
        found = ids(scan_fixture("vulnerable.py"))
        for rid in ("SECRET_AWS_KEY", "CODE_OS_SYSTEM", "CODE_SUBPROCESS_SHELL",
                    "CODE_PICKLE", "CODE_MD5", "CODE_WEAK_RANDOM", "CODE_SQL_CONCAT",
                    "CODE_DEBUG", "SECRET_GENERIC"):
            self.assertIn(rid, found, f"expected {rid}")

    def test_fingerprint_is_stable(self):
        f = scan_fixture("vulnerable.py")
        self.assertEqual({x["fingerprint"] for x in f},
                         {x["fingerprint"] for x in scan_fixture("vulnerable.py")})


class BaselineTests(unittest.TestCase):
    def test_save_then_load(self):
        findings = scan_fixture("vulnerable.py")
        d = tempfile.mkdtemp()
        bpath = os.path.join(d, "baseline.json")
        audit.save_baseline(bpath, findings)
        known = audit.load_baseline(bpath)
        self.assertEqual(known, {x["fingerprint"] for x in findings})

    def test_empty_baseline_is_empty_set(self):
        self.assertEqual(audit.load_baseline(os.path.join(tempfile.mkdtemp(), "none.json")), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
