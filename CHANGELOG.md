# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: [SemVer](https://semver.org/).

## [1.0.0] — 2026-10-14

First stable release: offline, dependency-free security scanning with an agent-facing review layer.

### Added

- **Scanner** (`scripts/audit.py`, standard library only): ~60 rules across secrets, dangerous code, IaC/containers, and committed key material.
- **Secrets**: AWS key + secret, private-key blocks, Google / GitHub / Slack / Stripe / OpenAI / Anthropic / Hugging Face / npm / PyPI / SendGrid / Mailgun / Telegram / Discord / Azure tokens, JWTs, credentials-in-URL, and generic `key = "value"` assignments. Placeholder-aware; values always masked.
- **Dangerous code**: `eval`/`exec`, `os.system`/`os.popen`, `subprocess(shell=True)`, `pickle`/`marshal`/`dill`, unsafe `yaml.load`, `verify=False`, JWT without verification and `alg: none`, Node/PHP/Java exec, `md5`/`sha1`, weak RNG, string-built SQL, XSS sinks, permissive CORS, path traversal, open redirect, SSTI, `chmod 777`.
- **IaC & containers**: Terraform public ACL / open ingress / unencrypted / public IP, Kubernetes privileged + hostPath, Dockerfile-as-root, `ADD` from URL, GitHub Actions `pull_request_target` + script injection.
- **Suppression**: inline `# secops-audit: ignore [RULE]`, whole-file `ignore-file`, and a `.secops-audit.json` allowlist.
- **Output formats**: markdown, JSON, and SARIF 2.1.0 (GitHub code scanning).
- **Baseline mode** (`--baseline` / `--save-baseline`): report and fail only on new findings.
- **Optional entropy detection** (`--entropy`): catch secrets whose key name isn't recognized.
- **CI**: composite `action.yml` + example workflow.
- **Agent Skill**: `SKILL.md` plus bundled, self-contained scripts for Claude / agent runtimes.
- **Review checklists**: OWASP Top 10 quick map, GDPR-style and HIPAA-style data-handling reviews.
- **Tests**: 23 `unittest` cases — `python3 -m unittest discover -s tests`.

### Notes

- This is a heuristic scanner, not a full SAST engine. Expect false positives and false negatives; review every finding.
- Not legal advice. A passing scan is not a compliance certification.
