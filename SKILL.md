---
name: secops-audit
description: Run an offline, dependency-free security and compliance pass over a codebase or diff. Detects hardcoded secrets, dangerous code patterns (eval, shell=True, pickle, disabled TLS, weak hashing, SQL injection), and committed secret files, then walks the agent through GDPR-style data-handling, HIPAA-style PHI, and OWASP-aligned review checklists. Use whenever the user asks to security-review code, check for leaked secrets, audit a repo before shipping or open-sourcing, or review a change for compliance risk.
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

# gate a CI job: non-zero exit if HIGH findings exist
python3 scripts/audit.py --path . --fail-on HIGH
```

Standard library only. No network. Safe to run offline.

### Severity model

- **HIGH** — likely exploit or credential exposure. Fix before merge.
- **MEDIUM** — real risk in the wrong context (injection, weak crypto, permissive CORS).
- **LOW** — hygiene / defense-in-depth (http URLs, debug flags, TODOs in auth paths).

## What it checks (scanner)

- **Secrets**: AWS keys, private-key blocks, Google/GitHub/Slack/Stripe tokens, JWTs, and generic `password=` / `api_key=` assignments — with placeholder filtering so `api_key = "your_key_here"` doesn't cry wolf.
- **Dangerous code**: `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`, `pickle.load(s)`, `yaml.load` without `SafeLoader`, `verify=False`, `md5`/`sha1`, `random` for security tokens, string-concatenated SQL, `dangerouslySetInnerHTML`, `innerHTML =`, permissive CORS.
- **Hygiene**: committed `.env` / `*.pem` / `id_rsa`, `DEBUG = True`, `chmod 777`, dependency manifests present (with a nudge to run a real vuln scanner).

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

- `scripts/audit.py` — the scanner (stdlib only)
- `references/owasp-quickmap.md`
- `references/compliance-gdpr.md`
- `references/compliance-hipaa.md`
