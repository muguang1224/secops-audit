#!/usr/bin/env python3
"""secops-audit — offline, dependency-free security scanner.

Walks a source tree, flags hardcoded secrets, dangerous code patterns, IaC/cloud
misconfigurations, and committed secret files. Heuristic, not a real SAST engine:
expect false positives and review everything. No network, standard library only.

Usage:
    python3 audit.py --path . --out SECURITY.md
    python3 audit.py --path src/ --min-severity MEDIUM --format json
    python3 audit.py --path . --format sarif > results.sarif
    python3 audit.py --path . --baseline .secops-baseline.json --fail-on HIGH
    python3 audit.py --path . --fail-on HIGH   # non-zero exit if HIGH found

Suppress a finding inline with a trailing comment:
    cursor.execute(sql + name)  # secops-audit: ignore CODE_SQL_CONCAT
    # secops-audit: ignore        <- suppress every rule on this line
    # secops-audit: ignore-file   <- suppress the whole file

Or configure an allowlist in .secops-audit.json (see load_config).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter

# --------------------------------------------------------------------------
# Rule tables
# --------------------------------------------------------------------------
# Secret patterns: (id, severity, title, regex). Values are masked in output.
SECRET_RULES = [
    ("SECRET_AWS_KEY", "HIGH", "AWS access key id", r"AKIA[0-9A-Z]{16}"),
    ("SECRET_AWS_SECRET", "HIGH", "AWS secret access key",
     r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    ("SECRET_PRIVATE_KEY", "HIGH", "Private key block",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("SECRET_GOOGLE", "HIGH", "Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("SECRET_GCP_SA_JSON", "HIGH", "GCP service-account key JSON",
     r"\"type\"\s*:\s*\"service_account\""),
    ("SECRET_GITHUB", "HIGH", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("SECRET_SLACK", "HIGH", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("SECRET_STRIPE", "HIGH", "Stripe live key", r"\bsk_live_[0-9a-zA-Z]{20,}"),
    ("SECRET_OPENAI", "HIGH", "OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    ("SECRET_ANTHROPIC", "HIGH", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("SECRET_HUGGINGFACE", "MEDIUM", "Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}"),
    ("SECRET_NPM", "HIGH", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("SECRET_PYPI", "HIGH", "PyPI upload token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}"),
    ("SECRET_SENDGRID", "MEDIUM", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    ("SECRET_MAILGUN", "MEDIUM", "Mailgun key", r"\bkey-[0-9a-f]{32}\b"),
    ("SECRET_TELEGRAM", "MEDIUM", "Telegram bot token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("SECRET_DISCORD", "MEDIUM", "Discord webhook",
     r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    ("SECRET_AZURE_KEY", "HIGH", "Azure account key", r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}"),
    ("SECRET_BASIC_AUTH_URL", "MEDIUM", "Credentials in URL",
     r"https?://[^\s/@:]+:[^\s/@]+@[A-Za-z0-9.\-]+"),
    ("SECRET_JWT", "MEDIUM", "Inline JWT",
     r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("SECRET_TWILIO", "MEDIUM", "Twilio account SID", r"\bAC[0-9a-fA-F]{32}\b"),
]

# Generic assignment: key = "value"  (lookbehind allows db_password, my_token, ...)
GENERIC_SECRET = re.compile(
    r"""(?ix)(?<![A-Za-z0-9])(client[_-]?secret|secret[_-]?key|auth[_-]?token|
    access[_-]?token|api[_-]?key|apikey|secret|token|password|passwd|pwd)
    \s*[:=]\s*(['"])([^'"]{6,})\2"""
)
# Unquoted YAML/env style: password: hunter2
GENERIC_SECRET_YAML = re.compile(
    r"""(?ix)^\s*(api[_-]?key|apikey|secret[_-]?key|secret|token|password|passwd|pwd)
    \s*[:=]\s*([^\s,;#'"]{6,})\s*$"""
)
# For entropy-based detection: a quoted value assigned to any key (catches secrets
# whose key name the generic rule doesn't recognize).
ENTROPY_CANDIDATE = re.compile(
    r"""(?ix)(?<![A-Za-z0-9])([A-Za-z_][A-Za-z0-9_]{0,40})
    \s*[:=]\s*(['"])([^'"]{16,})\2"""
)

PLACEHOLDER = re.compile(
    r"(?i)your[_-]?|example|sample|dummy|placeholder|changeme|change_me|xxxx|"
    r"<[^>]+>|\$\{|\{\{|\.\.\.|redacted|todo|fixme|abc123|fake|goes_here|insert"
)
# Values that are clearly code, not literals (avoid flagging random.random(), os.getenv(...)).
CODEY = re.compile(r"[(){}[\]]|\.\w+\s*\(|->|::|:=")


def is_placeholder(value: str) -> bool:
    if len(value) < 6:
        return True
    if len(set(value)) <= 2:
        return True
    return bool(PLACEHOLDER.search(value))


def looks_like_code(value: str) -> bool:
    return bool(CODEY.search(value))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_random(value: str) -> bool:
    """High-entropy, mixed-charset, non-placeholder, non-code -> probably a secret."""
    if is_placeholder(value) or looks_like_code(value):
        return False
    classes = sum([
        bool(re.search(r"[a-z]", value)),
        bool(re.search(r"[A-Z]", value)),
        bool(re.search(r"[0-9]", value)),
        bool(re.search(r"[^A-Za-z0-9]", value)),
    ])
    return classes >= 3 and shannon_entropy(value) >= 3.5


def mask(value: str) -> str:
    if len(value) <= 6:
        return "******"
    return value[:3] + "…" + "*" * 6


# Code patterns: (id, severity, title, pattern, unless)
CODE_RULES = [
    ("CODE_EVAL", "HIGH", "Dynamic code execution (eval/exec)", r"\b(eval|exec)\s*\(", None),
    ("CODE_OS_SYSTEM", "HIGH", "Shell command via os.system", r"\bos\.system\s*\(", None),
    ("CODE_OS_POPEN", "HIGH", "Shell command via os.popen", r"\bos\.popen\s*\(", None),
    ("CODE_SUBPROCESS_SHELL", "HIGH", "subprocess with shell=True",
     r"subprocess\.(run|call|check_output|Popen)\b[^\n]*shell\s*=\s*True", None),
    ("CODE_PICKLE", "HIGH", "Insecure deserialization (pickle)",
     r"\bpickle\.(load|loads)\s*\(", None),
    ("CODE_MARSHAL", "HIGH", "Insecure deserialization (marshal)",
     r"\bmarshal\.loads?\s*\(", None),
    ("CODE_DILL", "HIGH", "Insecure deserialization (dill)", r"\bdill\.loads?\s*\(", None),
    ("CODE_YAML_UNSAFE", "MEDIUM", "yaml.load without SafeLoader",
     r"\byaml\.load\s*\(", r"SafeLoader|safe_load"),
    ("CODE_TLS_VERIFY", "HIGH", "TLS verification disabled", r"verify\s*=\s*False", None),
    ("CODE_JWT_NOVERIFY", "HIGH", "JWT decoded without signature check",
     r"jwt\.decode\([^\n]*(verify\s*=\s*False|verify_signature['\"]?\s*:\s*False)", None),
    ("CODE_JWT_NONE", "HIGH", "JWT 'none' algorithm accepted",
     r"(?i)algorithm[s]?\s*[:=]\s*\[?[^\n]*['\"]none['\"]", None),
    ("CODE_NODEJS_EXEC", "HIGH", "Node child_process exec (shell)",
     r"child_process\.exec\s*\(|require\(['\"]child_process['\"]\)\.exec\s*\(", None),
    ("CODE_PHP_EXEC", "HIGH", "PHP code/shell execution",
     r"(?<![\w.])(shell_exec|passthru|system|proc_open|popen)\s*\(", None),
    ("CODE_JAVA_RUNTIME", "HIGH", "Java Runtime.exec",
     r"Runtime\.getRuntime\(\)\.exec\s*\(", None),
    ("CODE_MD5", "MEDIUM", "Weak hash (md5)", r"\b(md5|MD5)\s*\(", None),
    ("CODE_SHA1", "MEDIUM", "Weak hash (sha1)", r"\b(sha1|SHA1)\s*\(", None),
    ("CODE_WEAK_RANDOM", "MEDIUM", "Non-crypto RNG for a security value",
     r"(?i)\b(token|secret|salt|nonce|session\w*|otp)\w*\s*=\s*[\w.]*\brandom\b", None),
    ("CODE_MATH_RANDOM", "MEDIUM", "Math.random for a security value",
     r"(?i)\b(token|secret|salt|nonce|otp|session)\w*\s*=\s*[^;\n]*Math\.random", None),
    ("CODE_DEPRECATED_CIPHER", "MEDIUM", "Deprecated/unsafe crypto cipher",
     r"crypto\.createCipher\s*\(|DES\.|createCipheriv\s*\(\s*['\"]des", None),
    ("CODE_SQL_CONCAT", "MEDIUM", "Possible SQL injection (string-built query)",
     r"(?i)\b(execute|query|raw)\s*\([^)\n]*(\+|\bformat\b|%\s*\(|f['\"])", None),
    ("CODE_XSS_SINK", "MEDIUM", "Unsafe HTML sink (XSS risk)",
     r"(dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()", None),
    ("CODE_CORS_ANY", "MEDIUM", "Permissive CORS (any origin)",
     r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]|access-control-allow-origin['\"]?\s*[:,]\s*['\"]\*",
     None),
    ("CODE_CHMOD_777", "MEDIUM", "World-writable permissions",
     r"chmod\s+777|0o777|0o0777", None),
    ("CODE_PATH_TRAVERSAL", "MEDIUM", "Possible path traversal from user input",
     r"\b(open|send_file|send_from_directory|readFile|readFileSync)\s*\([^)\n]*"
     r"(request\.(args|GET|POST|form|params)|req\.(query|params|body))", None),
    ("CODE_OPEN_REDIRECT", "MEDIUM", "Possible open redirect",
     r"\b(redirect|location\.href)\s*[=(][^)\n]*"
     r"(request\.(args|GET|POST|form|params)|req\.(query|params|body)|\$_(GET|POST|REQUEST))",
     None),
    ("CODE_EVAL_TEMPLATE", "MEDIUM", "Dynamic template rendering (SSTI)",
     r"(?i)render_template_string\s*\(|Template\s*\(\s*[^)]*\+|from_string\s*\(", None),
    ("CODE_JSONP", "LOW", "JSONP / callback injection risk",
     r"(?i)callback\s*=\s*(request|req)\b|jsonp\b", None),
    ("CODE_DEBUG", "LOW", "Debug mode enabled", r"\bDEBUG\s*=\s*True", None),
    ("CODE_FLASK_DEBUG", "LOW", "Flask debug run", r"\.run\([^)\n]*debug\s*=\s*True", None),
    ("CODE_HTTP_URL", "LOW", "Plaintext http:// URL",
     r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas\.|www\.w3\.org)", None),
    ("CODE_PROTO_POLLUTION", "LOW", "Possible prototype pollution sink",
     r"__proto__\s*[:=]|Object\.assign\(\s*\w+\s*,\s*(req|request)\.", None),
    ("CODE_SUDO", "LOW", "Elevated privileges in script", r"\bsudo\s+", None),
]

# IaC / container / cloud config: (id, severity, title, pattern, unless)
IAC_RULES = [
    ("IAC_TF_PUBLIC_ACL", "HIGH", "Terraform: public-read ACL",
     r'acl\s*=\s*"public-(read|read-write)"', None),
    ("IAC_TF_OPEN_INGRESS", "HIGH", "Terraform: ingress open to 0.0.0.0/0",
     r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"', None),
    ("IAC_TF_NO_ENCRYPT", "MEDIUM", "Terraform: encryption disabled",
     r"(?i)encrypted\s*=\s*false", None),
    ("IAC_TF_PUBLIC_IP", "MEDIUM", "Terraform: public IP assigned",
     r"associate_public_ip_address\s*=\s*true", None),
    ("IAC_K8S_PRIVILEGED", "HIGH", "K8s: privileged container",
     r"privileged\s*:\s*true", None),
    ("IAC_K8S_HOSTPATH", "MEDIUM", "K8s: hostPath volume mount",
     r"hostPath\s*:", None),
    ("IAC_DOCKER_ADD_URL", "LOW", "Dockerfile: ADD from URL",
     r"^\s*ADD\s+https?://", None),
    ("IAC_GHA_PULL_REQUEST_TARGET", "MEDIUM", "CI: pull_request_target with checkout",
     r"pull_request_target\s*:", None),
    ("IAC_GHA_SCRIPT_INJECTION", "HIGH", "CI: untrusted input in run: (script injection)",
     r"run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment)\.", None),
]

# Committed-file findings (checked on file name/path, not content).
FILE_RULES = [
    (r"(^|/)\.env$", "HIGH", "Committed environment file (.env)"),
    (r"(^|/)\.env\.(local|prod|production|dev|staging)$", "HIGH", "Committed env file"),
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$", "HIGH", "Committed SSH private key"),
    (r"\.(pem|key|p12|pfx|jks|keystore)$", "HIGH", "Committed key/cert material (verify)"),
    (r"(^|/)\.aws/credentials$", "HIGH", "Committed AWS credentials file"),
    (r"(^|/)\.npmrc$", "MEDIUM", "Committed .npmrc (may contain a token)"),
    (r"(^|/)\.pypirc$", "MEDIUM", "Committed .pypirc (may contain a token)"),
    (r"(^|/)\.netrc$", "HIGH", "Committed .netrc (credentials)"),
    (r"(^|/)\.git-credentials$", "HIGH", "Committed git credential store"),
    (r"(^|/)terraform\.tfstate$", "HIGH", "Committed Terraform state (often holds secrets)"),
    (r"(^|/)service[-_]?account.*\.json$", "MEDIUM", "Possible service-account JSON"),
]

CODE_EXTS = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb",
    ".php", ".java", ".kt", ".kts", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".rs", ".swift", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".json", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".sql", ".html", ".htm", ".vue", ".svelte",
    ".tf", ".tfvars", ".gradle", ".properties", ".xml",
}
CODE_NAMES = {"dockerfile", "makefile", "procfile", ".env", ".npmrc", ".pypirc",
              "gemfile", "rakefile", ".netrc"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "dist", "build",
             "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "target",
             "vendor", "site-packages", ".next", ".nuxt", ".terraform"}
MAX_BYTES = 2 * 1024 * 1024
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

DEFAULT_CONFIG = ".secops-audit.json"
ALL_RULES = {}
for _tbl in (SECRET_RULES, CODE_RULES, IAC_RULES):
    for _r in _tbl:
        ALL_RULES[_r[0]] = _r[2]
ALL_RULES["SECRET_GENERIC"] = "Possible hardcoded secret"
ALL_RULES["SECRET_ENTROPY"] = "High-entropy value assigned to a secret-like key"
for _pat, _sev, _title in FILE_RULES:
    ALL_RULES["FILE:" + _title] = _title


# --------------------------------------------------------------------------
# Config + ignore handling
# --------------------------------------------------------------------------
def load_config(root: str, explicit: str | None) -> dict:
    path = explicit or os.path.join(root, DEFAULT_CONFIG)
    cfg = {"ignore": [], "exclude": [], "min_severity": "LOW", "entropy": False}
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg.update({k: data[k] for k in cfg if k in data})
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: could not read config {path}: {exc}", file=sys.stderr)
    return cfg


LINE_IGNORE = re.compile(r"secops-audit:\s*ignore(?:\s+([A-Za-z0-9_,:]+))?", re.IGNORECASE)
FILE_IGNORE = re.compile(r"secops-audit:\s*ignore-file", re.IGNORECASE)


def line_ignore_ids(line: str):
    """Return None if the line isn't ignored; [] for ignore-all; else [rule ids]."""
    m = LINE_IGNORE.search(line)
    if not m:
        return None
    if m.group(1):
        return [x.strip() for x in re.split(r"[,\s]+", m.group(1)) if x.strip()]
    return []


def config_ignores(finding: dict, ignores: list[dict]) -> bool:
    for ig in ignores:
        rid = ig.get("id")
        if rid and rid != "*" and rid != finding["id"]:
            continue
        f = ig.get("file")
        if f and not fnmatch.fnmatch(finding["file"], f):
            continue
        ln = ig.get("line")
        if ln is not None and ln != finding["line"]:
            continue
        return True
    return False


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def iter_files(root: str, exclude: list[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if any(x and x in rel for x in exclude):
                continue
            yield full, rel


def is_texty(rel: str) -> bool:
    ext = os.path.splitext(rel)[1].lower()
    base = os.path.basename(rel).lower()
    return ext in CODE_EXTS or base in CODE_NAMES


def _add(findings, sev, rid, title, rel, line, snippet):
    f = {"severity": sev, "id": rid, "title": title,
         "file": rel, "line": line, "snippet": snippet}
    f["fingerprint"] = fingerprint(f)
    findings.append(f)


def scan_file(full: str, rel: str, entropy: bool) -> list[dict]:
    findings = []
    try:
        if os.path.getsize(full) > MAX_BYTES:
            return findings
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return findings
    if "\x00" in text[:2000]:
        return findings
    if FILE_IGNORE.search(text):
        return findings

    for pattern, sev, title in FILE_RULES:
        if re.search(pattern, rel, re.IGNORECASE):
            _add(findings, sev, "FILE:" + title, title, rel, 0, rel)

    lines = text.splitlines()
    is_dockerfile = os.path.basename(rel).lower().startswith("dockerfile")
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            line = line[:2000]
        skip = line_ignore_ids(line)
        if skip is not None and not skip:
            continue  # ignore-all on this line

        def want(rid: str, sev: str, title: str, snippet: str):
            if skip is not None and rid in skip:
                return
            _add(findings, sev, rid, title, rel, i, snippet)

        for rid, sev, title, pat, unless in CODE_RULES + IAC_RULES:
            if re.search(pat, line):
                if unless and re.search(unless, line):
                    continue
                want(rid, sev, title, line.strip()[:160])
        if is_dockerfile and re.match(r"^\s*USER\s+root\b", line, re.IGNORECASE):
            want("IAC_DOCKER_USER_ROOT", "MEDIUM", "Dockerfile: explicitly runs as root",
                 line.strip()[:160])
        secret_seen = False
        for rid, sev, title, pat in SECRET_RULES:
            for m in re.finditer(pat, line):
                want(rid, sev, title, mask(m.group(0)))
                secret_seen = True
        for m in GENERIC_SECRET.finditer(line):
            val = m.group(3)
            if not is_placeholder(val) and not looks_like_code(val):
                want("SECRET_GENERIC", "MEDIUM", f"Possible hardcoded {m.group(1)}",
                     f"{m.group(1)} = {mask(val)}")
                secret_seen = True
        for m in GENERIC_SECRET_YAML.finditer(line):
            val = m.group(2)
            if not is_placeholder(val) and not looks_like_code(val):
                want("SECRET_GENERIC", "MEDIUM", f"Possible hardcoded {m.group(1)}",
                     f"{m.group(1)} = {mask(val)}")
                secret_seen = True
        if entropy and not secret_seen:
            for m in ENTROPY_CANDIDATE.finditer(line):
                val = m.group(3)
                if looks_random(val):
                    want("SECRET_ENTROPY", "MEDIUM",
                         "High-entropy literal (possible secret)",
                         f"{m.group(1)} = {mask(val)}  [entropy {shannon_entropy(val):.1f}]")
    return findings


def fingerprint(f: dict) -> str:
    base = f"{f['id']}|{f['file']}|{f['snippet']}"
    return hashlib.sha256(base.encode("utf-8", "replace")).hexdigest()[:16]


def audit(root: str, cfg: dict, min_sev: str) -> dict:
    findings, manifests, files_scanned = [], [], 0
    exclude = list(cfg.get("exclude", []))
    entropy = bool(cfg.get("entropy", False))
    for full, rel in iter_files(root, exclude):
        base = os.path.basename(rel).lower()
        if base in {"requirements.txt", "package.json", "go.mod", "pyproject.toml",
                    "gemfile", "pom.xml"}:
            manifests.append(rel)
        if not is_texty(rel):
            continue
        files_scanned += 1
        findings.extend(scan_file(full, rel, entropy))

    # inline-ignores are already applied; here apply config allowlist + dedupe
    ignores = cfg.get("ignore", [])
    seen, uniq = set(), []
    for f in findings:
        if config_ignores(f, ignores):
            continue
        key = (f["id"], f["file"], f["line"], f["snippet"])
        if key in seen:
            continue
        seen.add(key)
        f["fingerprint"] = fingerprint(f)
        uniq.append(f)

    threshold = SEV_ORDER[min_sev]
    uniq = [f for f in uniq if SEV_ORDER[f["severity"]] <= threshold]
    uniq.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["file"], f["line"]))
    return {"findings": uniq, "files_scanned": files_scanned,
            "manifests": sorted(set(manifests))}


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------
def load_baseline(path: str) -> set[str]:
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(json.load(f).get("fingerprints", []))
        except (OSError, json.JSONDecodeError):
            print(f"warning: could not read baseline {path}", file=sys.stderr)
    return set()


def save_baseline(path: str, findings: list[dict]) -> None:
    data = {"fingerprints": sorted({f["fingerprint"] for f in findings})}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def counts(findings: list[dict]) -> dict:
    c = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        c[f["severity"]] += 1
    return c


def render_markdown(res: dict) -> str:
    f = res["findings"]
    c = counts(f)
    out = ["# Security audit", "",
           f"Files scanned: {res['files_scanned']}  ·  "
           f"HIGH: {c['HIGH']}  ·  MEDIUM: {c['MEDIUM']}  ·  LOW: {c['LOW']}", ""]
    out.append("> Heuristic scan — not a substitute for a full SAST/audit. "
               "Review every finding; false positives are expected.")
    out.append("")
    if not f:
        out.append("No findings at this severity threshold. Still work the "
                   "checklists in this skill for logic and authz issues a scanner can't see.")
        return "\n".join(out)
    for sev in ("HIGH", "MEDIUM", "LOW"):
        group = [x for x in f if x["severity"] == sev]
        if not group:
            continue
        out.append(f"## {sev} ({len(group)})")
        out.append("")
        for x in group:
            loc = f"{x['file']}:{x['line']}" if x["line"] else x["file"]
            out.append(f"- **{x['title']}** — `{loc}`")
            if x["snippet"]:
                out.append(f"  - `{x['snippet']}`")
        out.append("")
    if res["manifests"]:
        out.append("## Dependency manifests")
        out.append("")
        for m in res["manifests"]:
            out.append(f"- `{m}` — run a real vuln scanner (`pip-audit`, `npm audit`, `govulncheck`)")
        out.append("")
    out.append("## Next steps")
    out.append("")
    out.append("1. Rotate anything that looks like a live secret; don't just delete the line.")
    out.append("2. Fix HIGH findings before merge.")
    out.append("3. Map the diff to the OWASP quick map; work the compliance checklists if user data is involved.")
    return "\n".join(out)


def render_sarif(res: dict) -> str:
    used_ids = []
    for f in res["findings"]:
        if f["id"] not in used_ids:
            used_ids.append(f["id"])
    rules = []
    for rid in used_ids:
        title = ALL_RULES.get(rid, rid)
        level = "warning"
        for f in res["findings"]:
            if f["id"] == rid:
                level = SARIF_LEVEL[f["severity"]]
                break
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": title},
            "defaultConfiguration": {"level": level},
        })
    results = []
    for f in res["findings"]:
        loc = {"physicalLocation": {"artifactLocation": {"uri": f["file"]}}}
        if f["line"]:
            loc["physicalLocation"]["region"] = {"startLine": f["line"]}
        results.append({
            "ruleId": f["id"],
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']} ({f['file']}"
                                 + (f":{f['line']}" if f["line"] else "") + ")"},
            "locations": [loc],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "secops-audit",
                "informationUri": "https://github.com/muguang1224/secops-audit",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline security scan of a source tree.")
    ap.add_argument("--path", default=".", help="root to scan")
    ap.add_argument("--out", default=None, help="write report to this file")
    ap.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    ap.add_argument("--min-severity", choices=["HIGH", "MEDIUM", "LOW"], default="LOW")
    ap.add_argument("--exclude", default="", help="comma-separated path substrings to skip")
    ap.add_argument("--config", default=None, help="path to .secops-audit.json")
    ap.add_argument("--entropy", action="store_true",
                    help="also flag high-entropy values assigned to secret-like keys")
    ap.add_argument("--baseline", default=None, help="baseline JSON; report only NEW findings")
    ap.add_argument("--save-baseline", action="store_true",
                    help="write current findings' fingerprints into --baseline")
    ap.add_argument("--show-baselined", action="store_true",
                    help="with --baseline, also include already-known findings")
    ap.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "never"], default="never",
                    help="exit non-zero if findings at/above this severity exist")
    args = ap.parse_args(argv)

    cfg = load_config(args.path, args.config)
    if args.exclude:
        cfg["exclude"] = list(cfg.get("exclude", [])) + [x.strip() for x in args.exclude.split(",") if x.strip()]
    if args.entropy:
        cfg["entropy"] = True
    min_sev = args.min_severity if "min_severity" not in cfg or args.min_severity != "LOW" \
        else cfg.get("min_severity", "LOW")

    res = audit(args.path, cfg, min_sev)
    c = counts(res["findings"])

    if args.save_baseline:
        if not args.baseline:
            print("error: --save-baseline requires --baseline", file=sys.stderr)
            return 2
        save_baseline(args.baseline, res["findings"])
        print(f"baseline saved: {args.baseline} ({len(res['findings'])} fingerprints)")

    if args.baseline and not args.save_baseline:
        known = load_baseline(args.baseline)
        new = [f for f in res["findings"] if f["fingerprint"] not in known]
        if not args.show_baselined:
            res["findings"] = new
        else:
            for f in res["findings"]:
                f["baselined"] = f["fingerprint"] in known
        c = counts(res["findings"])

    if args.format == "json":
        payload = {"summary": c, "files_scanned": res["files_scanned"],
                   "manifests": res["manifests"], "findings": res["findings"]}
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    elif args.format == "sarif":
        text = render_sarif(res)
    else:
        text = render_markdown(res)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"HIGH {c['HIGH']}  MEDIUM {c['MEDIUM']}  LOW {c['LOW']}  -> {args.out}")
    else:
        print(text)

    if args.fail_on != "never":
        above = sum(v for k, v in c.items() if SEV_ORDER[k] <= SEV_ORDER[args.fail_on])
        if above:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
