# secops-audit

**An Agent Skill that security-reviews code before a human has to.**

`secops-audit` gives an AI agent a fast, offline first pass over a repo or diff: it flags hardcoded secrets, dangerous code patterns, and committed key material, then walks the agent through OWASP-aligned, GDPR-style, and HIPAA-style review checklists for the things a scanner can't see. Standard library only, no network, no install.

> A [Claude / Agent Skill](https://claude.com/docs): a `SKILL.md` plus helper scripts an agent can load and run. Drop the folder into your skills directory and ask "security-review this."

## Why

Security is the thing that stops agents from being trusted with real code. A dedicated "reviewer agent" that runs on every change is far cheaper than a breach — and far more useful than a linter, because it asks *why* a pattern is dangerous in the context of the diff.

## Quick start

```bash
# full report
python3 scripts/audit.py --path . --out SECURITY.md

# gate CI: non-zero exit if anything HIGH is found
python3 scripts/audit.py --path . --min-severity HIGH --fail-on HIGH

# machine-readable
python3 scripts/audit.py --path src/ --format json > findings.json
```

Python 3.8+. Zero dependencies. Safe to run in an air-gapped CI job.

## What it checks

- **Secrets** — AWS keys, private-key blocks, Google/GitHub/Slack/Stripe tokens, JWTs, and generic `password=` / `api_key=` assignments, with placeholder filtering so examples don't cry wolf. Values are always masked.
- **Dangerous code** — `eval`/`exec`, `os.system`, `subprocess(shell=True)`, `pickle.load(s)`, `yaml.load` without `SafeLoader`, `verify=False`, `jwt.decode` without signature check, `md5`/`sha1`, non-crypto RNG for tokens, string-built SQL, `dangerouslySetInnerHTML`, permissive CORS, `chmod 777`.
- **Committed files** — `.env`, `*.pem`/`*.key`, `id_rsa`, `.aws/credentials`, `.npmrc`.
- **Manifests** — nudges you to run `pip-audit` / `npm audit` / `govulncheck` for dependency CVEs.

Severity-ranked (HIGH/MEDIUM/LOW), line-numbered, and written to markdown or JSON.

## The judgment half

A scanner finds patterns; a reviewer finds logic flaws. After the scan, the agent works three checklists in `references/`:

- `owasp-quickmap.md` — map findings and the diff to the OWASP Top 10.
- `compliance-gdpr.md` — personal-data handling review.
- `compliance-hipaa.md` — PHI handling review.

## Honest limits

This is a **heuristic** scanner, not a SAST engine. Expect false positives (test fixtures) and false negatives (authz bugs, logic flaws). It is **not legal advice** and a passing scan is **not** a compliance certification. It never auto-fixes: it surfaces findings and leaves the fix to a human.

## Repo layout

```
SKILL.md                          # the skill
scripts/audit.py                  # the scanner (stdlib only)
references/owasp-quickmap.md      # OWASP Top 10 review map
references/compliance-gdpr.md     # personal-data review checklist
references/compliance-hipaa.md    # PHI review checklist
```

## 中文简介

`secops-audit` 是一个 Agent Skill：对代码库/改动做**离线**安全审查。先用 `scripts/audit.py`（纯标准库、零依赖、无网络）扫出硬编码密钥、危险写法（eval、shell=True、pickle、关闭 TLS、弱哈希、SQL 拼接等）和误提交的密钥文件；再由 agent 依 OWASP / GDPR / HIPAA 三份清单做人工判断。它是启发式扫描器、不是 SAST，也不是法律建议；只报问题、不自动改代码。

## License

MIT
