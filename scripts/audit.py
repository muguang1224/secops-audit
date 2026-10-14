#!/usr/bin/env python3
"""secops-audit — offline, dependency-free security scanner.

Walks a source tree, flags hardcoded secrets, dangerous code patterns, and
committed secret files. Heuristic, not a real SAST engine: expect false
positives and review everything. No network, standard library only.

Usage:
    python3 audit.py --path . --out SECURITY.md
    python3 audit.py --path src/ --min-severity MEDIUM --format json
    python3 audit.py --path . --fail-on HIGH   # non-zero exit if HIGH found
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
# Specific secret patterns (regex -> title).
SECRET_RULES = [
    ("SECRET_AWS_KEY", "HIGH", "AWS access key id", r"AKIA[0-9A-Z]{16}"),
    ("SECRET_PRIVATE_KEY", "HIGH", "Private key block",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("SECRET_GOOGLE", "HIGH", "Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("SECRET_GITHUB", "HIGH", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("SECRET_SLACK", "HIGH", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("SECRET_STRIPE", "HIGH", "Stripe live key", r"\bsk_live_[0-9a-zA-Z]{20,}"),
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

PLACEHOLDER = re.compile(
    r"(?i)your[_-]?|example|sample|dummy|placeholder|changeme|change_me|xxxx|"
    r"<[^>]+>|\$\{|\{\{|\.\.\.|redacted|todo|fixme|abc123|fake|goes_here|insert"
)
# Values that are clearly code, not literals (avoid flagging random.random(), os.getenv(...))
CODEY = re.compile(r"[(){}[\]]|\.\w+\s*\(|->|::|:=")


def is_placeholder(value: str) -> bool:
    if len(value) < 6:
        return True
    if len(set(value)) <= 2:
        return True
    return bool(PLACEHOLDER.search(value))


def looks_like_code(value: str) -> bool:
    return bool(CODEY.search(value))


def mask(value: str) -> str:
    if len(value) <= 6:
        return "******"
    return value[:3] + "…" + "*" * 6


# Code patterns: (id, severity, title, pattern, unless)
CODE_RULES = [
    ("CODE_EVAL", "HIGH", "Dynamic code execution (eval/exec)", r"\b(eval|exec)\s*\(", None),
    ("CODE_OS_SYSTEM", "HIGH", "Shell command via os.system", r"\bos\.system\s*\(", None),
    ("CODE_SUBPROCESS_SHELL", "HIGH", "subprocess with shell=True",
     r"subprocess\.(run|call|check_output|Popen)\b[^\n]*shell\s*=\s*True", None),
    ("CODE_PICKLE", "HIGH", "Insecure deserialization (pickle)",
     r"\bpickle\.(load|loads)\s*\(", None),
    ("CODE_TLS_VERIFY", "HIGH", "TLS verification disabled", r"verify\s*=\s*False", None),
    ("CODE_JWT_NOVERIFY", "HIGH", "JWT decoded without signature check",
     r"jwt\.decode\([^\n]*(verify\s*=\s*False|verify_signature['\"]?\s*:\s*False)", None),
    ("CODE_YAML_UNSAFE", "MEDIUM", "yaml.load without SafeLoader",
     r"\byaml\.load\s*\(", r"SafeLoader|safe_load"),
    ("CODE_MD5", "MEDIUM", "Weak hash (md5)", r"\b(md5|MD5)\s*\(", None),
    ("CODE_SHA1", "MEDIUM", "Weak hash (sha1)", r"\b(sha1|SHA1)\s*\(", None),
    ("CODE_WEAK_RANDOM", "MEDIUM", "Non-crypto RNG for a security value",
     r"(?i)\b(token|secret|salt|nonce|session\w*|otp)\w*\s*=\s*[\w.]*\brandom\b", None),
    ("CODE_SQL_CONCAT", "MEDIUM", "Possible SQL injection (string-built query)",
     r"(?i)\b(execute|query|raw)\s*\([^)\n]*(\+|\bformat\b|%\s*\(|f['\"])", None),
    ("CODE_XSS_SINK", "MEDIUM", "Unsafe HTML sink (XSS risk)",
     r"(dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()", None),
    ("CODE_CORS_ANY", "MEDIUM", "Permissive CORS (any origin)",
     r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]|access-control-allow-origin['\"]?\s*[:,]\s*['\"]\*",
     None),
    ("CODE_CHMOD_777", "MEDIUM", "World-writable permissions",
     r"chmod\s+777|0o777|0o0777", None),
    ("CODE_DEBUG", "LOW", "Debug mode enabled", r"\bDEBUG\s*=\s*True", None),
    ("CODE_HTTP_URL", "LOW", "Plaintext http:// URL",
     r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas\.|www\.w3\.org)", None),
    ("CODE_PROTO_POLLUTION", "LOW", "Possible prototype pollution sink",
     r"__proto__\s*[:=]", None),
]

# Committed-file findings (checked on file name/path, not content).
FILE_RULES = [
    (r"(^|/)\.env$", "HIGH", "Committed environment file (.env)"),
    (r"(^|/)\.env\.(local|prod|production|dev)$", "HIGH", "Committed env file"),
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$", "HIGH", "Committed SSH private key"),
    (r"\.(pem|key|p12|pfx|jks)$", "HIGH", "Committed key/cert material (verify)"),
    (r"(^|/)\.aws/credentials$", "HIGH", "Committed AWS credentials file"),
    (r"(^|/)\.npmrc$", "MEDIUM", "Committed .npmrc (may contain a token)"),
    (r"(^|/)\.git-credentials$", "HIGH", "Committed git credential store"),
]

CODE_EXTS = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb",
    ".php", ".java", ".kt", ".kts", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".rs", ".swift", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".json", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".sql", ".html", ".htm", ".vue", ".svelte",
    ".tf", ".gradle", ".properties", ".xml",
}
CODE_NAMES = {"dockerfile", "makefile", "procfile", ".env", ".npmrc", "gemfile", "rakefile"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "dist", "build",
             "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "target",
             "vendor", "site-packages", ".next", ".nuxt"}
MAX_BYTES = 2 * 1024 * 1024
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


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


def scan_file(full: str, rel: str) -> list[dict]:
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

    # file-name based findings
    for pattern, sev, title in FILE_RULES:
        if re.search(pattern, rel, re.IGNORECASE):
            findings.append({"severity": sev, "id": "FILE_" + title.split()[0].upper().strip("()"),
                             "title": title, "file": rel, "line": 0, "snippet": rel})

    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 1000:
            line = line[:1000]
        for rid, sev, title, pat, unless in CODE_RULES:
            if re.search(pat, line):
                if unless and re.search(unless, line):
                    continue
                findings.append({"severity": sev, "id": rid, "title": title,
                                 "file": rel, "line": i,
                                 "snippet": line.strip()[:160]})
        for rid, sev, title, pat in SECRET_RULES:
            for m in re.finditer(pat, line):
                findings.append({"severity": sev, "id": rid, "title": title,
                                 "file": rel, "line": i,
                                 "snippet": mask(m.group(0))})
        for m in GENERIC_SECRET.finditer(line):
            val = m.group(3)
            if not is_placeholder(val) and not looks_like_code(val):
                findings.append({"severity": "MEDIUM", "id": "SECRET_GENERIC",
                                 "title": f"Possible hardcoded {m.group(1)}",
                                 "file": rel, "line": i,
                                 "snippet": f"{m.group(1)} = {mask(val)}"})
        for m in GENERIC_SECRET_YAML.finditer(line):
            val = m.group(2)
            if not is_placeholder(val) and not looks_like_code(val):
                findings.append({"severity": "MEDIUM", "id": "SECRET_GENERIC",
                                 "title": f"Possible hardcoded {m.group(1)}",
                                 "file": rel, "line": i,
                                 "snippet": f"{m.group(1)} = {mask(val)}"})
    return findings


def audit(root: str, exclude: list[str], min_sev: str) -> dict:
    findings = []
    manifests = []
    files_scanned = 0
    for full, rel in iter_files(root, exclude):
        base = os.path.basename(rel).lower()
        if base in {"requirements.txt", "package.json", "go.mod", "pyproject.toml", "gemfile", "pom.xml"}:
            manifests.append(rel)
        if not is_texty(rel):
            continue
        files_scanned += 1
        findings.extend(scan_file(full, rel))

    # dedupe identical (id,file,line,snippet)
    seen = set()
    uniq = []
    for f in findings:
        key = (f["id"], f["file"], f["line"], f["snippet"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    threshold = SEV_ORDER[min_sev]
    uniq = [f for f in uniq if SEV_ORDER[f["severity"]] <= threshold]
    uniq.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["file"], f["line"]))
    return {"findings": uniq, "files_scanned": files_scanned, "manifests": sorted(set(manifests))}


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
                   "checklists in `references/` for logic and authz issues a scanner can't see.")
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
    out.append("3. Map the diff to `references/owasp-quickmap.md`; work the compliance checklists if user data is involved.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline security scan of a source tree.")
    ap.add_argument("--path", default=".", help="root to scan")
    ap.add_argument("--out", default=None, help="write markdown report to this file")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--min-severity", choices=["HIGH", "MEDIUM", "LOW"], default="LOW")
    ap.add_argument("--exclude", default="", help="comma-separated path substrings to skip")
    ap.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "never"], default="never",
                    help="exit non-zero if findings at/above this severity exist")
    args = ap.parse_args(argv)

    exclude = [x.strip() for x in args.exclude.split(",") if x.strip()]
    res = audit(args.path, exclude, args.min_severity)
    c = counts(res["findings"])

    if args.format == "json":
        payload = {"summary": c, "files_scanned": res["files_scanned"],
                   "manifests": res["manifests"], "findings": res["findings"]}
        text = json.dumps(payload, indent=2, ensure_ascii=False)
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
