# secops-audit

[![tests](https://img.shields.io/badge/tests-23%20passing-brightgreen)](#tests)
[![python](https://img.shields.io/badge/python-3.8%2B-blue)](#)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**A security reviewer in a box — for humans and for agents.**

`secops-audit` gives code a fast, offline first pass: it flags hardcoded secrets, dangerous code patterns, IaC/container misconfigurations, and committed key material, then walks you through OWASP-aligned, GDPR-style, and HIPAA-style review checklists for the things a scanner can't see. Standard library only, no network, no install.

It ships as a [Claude / Agent Skill](https://claude.com/docs) **and** a plain CLI you can wire into CI.

## Why

Security is the thing that stops teams from trusting automation with real code. A reviewer that runs on every change is cheaper than a breach — and more useful than a linter, because it asks *why* a pattern is dangerous in the context of the diff, not just whether it matches.

## Quick start

```bash
# full report
python3 scripts/audit.py --path . --out SECURITY.md

# gate CI: non-zero exit if anything HIGH is found
python3 scripts/audit.py --path . --min-severity HIGH --fail-on HIGH

# machine-readable
python3 scripts/audit.py --path src/ --format json > findings.json

# SARIF for GitHub code scanning
python3 scripts/audit.py --path . --format sarif --out secops-audit.sarif
```

Python 3.8+. Zero dependencies. Safe to run in an air-gapped job.

## What it checks

- **Secrets** — AWS (key + secret), private-key blocks, Google, GitHub, Slack, Stripe, OpenAI, Anthropic, Hugging Face, npm, PyPI, SendGrid, Telegram, Discord, Azure, JWTs, credentials-in-URL, and generic `password=` / `api_key=` assignments. Placeholders (`your_key_here`) are ignored; values are always masked.
- **Dangerous code** — `eval`/`exec`, `os.system`, `os.popen`, `subprocess(shell=True)`, `pickle`/`marshal`/`dill` deserialization, `yaml.load` without `SafeLoader`, `verify=False`, `jwt.decode` without verification and `alg: none`, Node/PHP/Java exec, `md5`/`sha1`, non-crypto RNG (`random`, `Math.random`), string-built SQL, XSS sinks, permissive CORS, path traversal, open redirect, SSTI, `chmod 777`.
- **IaC & containers** — Terraform public ACLs / open ingress / unencrypted / public IP, Kubernetes privileged + hostPath, Dockerfile running as root, `ADD` from URL, GitHub Actions `pull_request_target` + script injection.
- **Committed files** — `.env`, `*.pem`/`*.key`, `id_rsa`, `.aws/credentials`, `.npmrc`, `.pypirc`, `.netrc`, `terraform.tfstate`, service-account JSON.
- **Manifests** — nudges you to run `pip-audit` / `npm audit` / `govulncheck`.

Severity-ranked (HIGH/MEDIUM/LOW), line-numbered, output as markdown, JSON, or SARIF.

## Suppressing findings

Inline, on the line that triggers:

```python
cursor.execute(sql + name)   # secops-audit: ignore CODE_SQL_CONCAT
do_something()               # secops-audit: ignore        (suppress every rule on this line)
```

Whole file, anywhere in it:

```python
# secops-audit: ignore-file
```

Or a config file `.secops-audit.json` (auto-discovered in `--path`):

```json
{
  "ignore": [ {"id": "CODE_MD5", "file": "legacy/*.py"}, {"id": "CODE_DEBUG", "file": "tests/*"} ],
  "exclude": ["vendor/", "third_party/"],
  "min_severity": "LOW",
  "entropy": false
}
```

## Reducing noise: baseline mode

Record today's findings, then only fail on what's **new**:

```bash
python3 scripts/audit.py --path . --baseline .secops-baseline.json --save-baseline
# later — reports only findings not in the baseline
python3 scripts/audit.py --path . --baseline .secops-baseline.json --fail-on HIGH
```

## Optional: entropy detection

Runs the same secret-ish key/value shape through a Shannon-entropy + charset check to catch secrets whose *key name* isn't recognized. Off by default because it can be noisy; enable with `--entropy` or `"entropy": true` in the config.

## GitHub Actions

Drop this in `.github/workflows/`:

```yaml
name: secops-audit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: muguang1224/secops-audit@main
        with:
          path: .
          min-severity: MEDIUM
          fail-on: HIGH
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secops-audit.sarif
```

Findings show up under **Security → Code scanning**, and the job fails on HIGH if you set `fail-on`.

## The judgment half

A scanner finds patterns; a reviewer finds logic flaws. After the scan, work the checklists in the skill:

- `references/owasp-quickmap.md` — map findings and the diff to the OWASP Top 10.
- `references/compliance-gdpr.md` — personal-data handling review.
- `references/compliance-hipaa.md` — PHI handling review.

## Tests

```bash
python3 -m unittest discover -s tests      # zero-dependency
# or:  pytest tests/
```

23 tests covering detection, false-positive guards (placeholders, code values, cross-language rules), inline/file/config suppression, entropy, SARIF shape, and baseline round-trip.

## Honest limits

This is a **heuristic** scanner, not a SAST engine. Expect false positives (test fixtures) and false negatives (authz bugs, logic flaws). It is **not legal advice** and a passing scan is **not** a compliance certification. It never auto-fixes: it surfaces findings and leaves the fix to a human.

## Repo layout

```
SKILL.md                          # the Agent Skill
scripts/audit.py                  # the scanner (stdlib only)
action.yml                        # composite GitHub Action
.github/workflows/secops-audit.yml
tests/test_audit.py               # unittest suite
tests/fixtures/                   # vulnerable.py (demo) + clean.py (must stay clean)
references/                       # OWASP / GDPR / HIPAA checklists
```

## 中文简介

`secops-audit` 是一个 Agent Skill，也是一个普通命令行工具。对代码库做**离线**安全审查（纯标准库、零依赖、无网络）：扫硬编码密钥、危险写法、IaC/容器配置问题、误提交的密钥文件；输出 markdown / JSON / **SARIF**（可直接接 GitHub 代码扫描）。支持行内 `# secops-audit: ignore`、`.secops-audit.json` 白名单、**baseline 差异模式**（只报新增）和可选熵检测。附 OWASP / GDPR / HIPAA 三份人工审查清单。它是启发式、不是 SAST，也不是法律建议；只报问题、不自动改代码。

## License

MIT
