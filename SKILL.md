---
name: secops-audit
description: Run an offline, dependency-free security and compliance pass over a codebase or diff. Detects hardcoded secrets, dangerous code patterns (eval, shell=True, pickle, disabled TLS, weak hashing, SQL injection), IaC/container misconfigurations, and committed secret files, then walks the agent through GDPR-style data-handling, HIPAA-style PHI, and OWASP-aligned review checklists. Can run in CI with SARIF output, baseline diffs, and inline/config suppression. Use whenever the user asks to security-review code, check for leaked secrets, audit a repo before shipping or open-sourcing, or review a change for compliance risk.
---

# secops-audit

A "security reviewer in a box" for agents that write or review code. It does two jobs:

1. **Mechanical scan** — `scripts/audit.py` greps a tree for the things that are objectively wrong: committed secrets, `eval`, `shell=True`, `pickle.loads`, `verify=False`, MD5-for-passwords, string-built SQL, committed `.env` files. Findings are line-numbered and severity-ranked.
2. **Judgment review** — reference checklists that make you, the agent, ask the right questions a scanner can't: is this PII handled lawfully? is health data minimized? does this diff widen the attack surface?

The point isn't a green check. It's catching the cheap, high-frequency mistakes *before* a human reviewer or an attacker does.

## When to use this skill

- "Security-review this repo / this PR."
- "Check for leaked secrets before I open-source this."
- "Are we handling user data in a way that would pass a GDPR review?"
- "Add a security gate to my pre-commit / CI."
- Any time code that touches auth, crypto, subprocesses, deserialization, or user input is written.

## How to run it

```bash
# whole tree
python3 scripts/audit.py --path . --out SECURITY.md

# only high+medium, JSON for CI
python3 scripts/audit.py --path src/ --min-severity MEDIUM --format json > findings.json

# SARIF for GitHub code scanning
python3 scripts/audit.py --path . --format sarif --out secops-audit.sarif

# gate a CI job: non-zero exit if HIGH findings exist
python3 scripts/audit.py --path . --fail-on HIGH

# only fail on NEW findings (record today's as the baseline first)
python3 scripts/audit.py --path . --baseline .secops-baseline.json --save-baseline
python3 scripts/audit.py --path . --baseline .secops-baseline.json --fail-on HIGH

# optional: high-entropy secret detection
python3 scripts/audit.py --path . --entropy
```

Standard library only. No network. Safe to run offline.

### Severity model

- **HIGH** — likely exploit or credential exposure. Fix before merge.
- **MEDIUM** — real risk in the wrong context (injection, weak crypto, permissive CORS).
- **LOW** — hygiene / defense-in-depth (http URLs, debug flags, TODOs in auth paths).

## What it checks (scanner)

- **Secrets**: AWS key + secret, private-key blocks, Google/GitHub/Slack/Stripe/OpenAI/Anthropic/Hugging Face/npm/PyPI/SendGrid/Telegram/Discord/Azure tokens, JWTs, credentials-in-URL, and generic `password=` / `api_key=` assignments — with placeholder filtering so `api_key = "your_key_here"` doesn't cry wolf. Values are always masked.
- **Dangerous code**: `eval`/`exec`, `os.system`/`os.popen`, `subprocess(..., shell=True)`, `pickle`/`marshal`/`dill` deserialization, `yaml.load` without `SafeLoader`, `verify=False`, `jwt.decode` without verification and `alg: none`, Node/PHP/Java exec, `md5`/`sha1`, `random`/`Math.random` for security tokens, string-concatenated SQL, XSS sinks, permissive CORS, path traversal, open redirect, SSTI, `chmod 777`.
- **IaC & containers**: Terraform public ACL / open ingress / unencrypted / public IP, Kubernetes privileged + hostPath, Dockerfile running as root, `ADD` from URL, GitHub Actions `pull_request_target` + script injection.
- **Hygiene**: committed `.env` / `*.pem` / `id_rsa` / `terraform.tfstate`, `DEBUG = True`, dependency manifests present (with a nudge to run a real vuln scanner).

## Suppressing findings

Prefer suppression over lowering the threshold. Inline, on the offending line:

```python
cursor.execute(sql + name)   # secops-audit: ignore CODE_SQL_CONCAT
do_something()               # secops-audit: ignore        (suppress every rule on this line)
```

Whole file: put `# secops-audit: ignore-file` anywhere in it. Or use a `.secops-audit.json`
(auto-discovered in `--path`) with an `ignore` list of `{id, file, line?}`, an `exclude` list,
`min_severity`, and `entropy`.

## CI: SARIF + GitHub Action

`--format sarif` emits SARIF 2.1.0 for GitHub code scanning. The repo ships a composite
`action.yml`; wire it up as:

```yaml
- uses: muguang1224/secops-audit@main
  with: { path: ., min-severity: MEDIUM, fail-on: HIGH }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: secops-audit.sarif }
```

## What *you* check (the agent)

After the scan, work the reference checklists against the actual code:

- `references/owasp-quickmap.md` — map findings and the diff to OWASP Top 10 categories.
- `references/compliance-gdpr.md` — personal-data handling review questions.
- `references/compliance-hipaa.md` — PHI handling review questions.

Write the report as: **finding → evidence (file:line) → impact → fix**. Never list a finding you can't point at a line for.

## Guardrails & honesty

- The scanner is **heuristics, not a real SAST engine**. Expect false positives (test fixtures, examples) and false negatives (logic flaws, authz bugs). Say so in the report.
- **Not legal advice.** The compliance checklists are review prompts, not a certification. A passing scan is not "GDPR compliant".
- Never auto-"fix" by deleting code or rotating keys — surface the finding and let a human act.
- Never print a full secret value; the scanner masks them, keep it that way.

## Files

- `scripts/audit.py` — the scanner (stdlib only; md / json / sarif output)
- `action.yml` + `.github/workflows/secops-audit.yml` — CI integration
- `tests/test_audit.py` + `tests/fixtures/` — test suite (`python3 -m unittest discover -s tests`)
- `references/owasp-quickmap.md`
- `references/compliance-gdpr.md`
- `references/compliance-hipaa.md`
