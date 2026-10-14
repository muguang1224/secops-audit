# OWASP Top 10 — quick review map

Use this to turn scanner hits and a code diff into a structured security review. For each category: the question to ask of *this* change, and the fix pattern.

## A01 Broken Access Control
- Does every new endpoint/route check **authorization**, not just authentication?
- Can a user read or mutate another user's object by changing an id (IDOR)?
- Are admin-only actions actually gated server-side (not just hidden in the UI)?
- Fix: authorize on the server for every object access; default deny.

## A02 Cryptographic Failures
- TLS verified everywhere? (scanner: `verify=False`)
- Passwords hashed with bcrypt/argon2/scrypt — never md5/sha1/plain?
- Secrets in env/secret manager, not source?
- Fix: strong KDFs, verify=True, rotate anything committed.

## A03 Injection
- SQL built by string concatenation or f-strings? (scanner: `CODE_SQL_CONCAT`)
- User input reaching `eval`/`exec`/`os.system`/`shell=True`?
- Fix: parameterized queries, no shell=True, allow-list inputs.

## A04 Insecure Design
- Is there a rate limit / lockout on auth?
- Can the flow be abused by skipping steps (e.g. pay-then-verify)?
- Fix: threat-model the flow; enforce invariants server-side.

## A05 Security Misconfiguration
- Debug on in prod? permissive CORS `*`? verbose error pages? default creds?
- Fix: secure defaults, least privilege, no stack traces to users.

## A06 Vulnerable & Outdated Components
- Run a real scanner on manifests: `pip-audit`, `npm audit`, `govulncheck`.
- Pin and update dependencies.

## A07 Identification & Authentication Failures
- Session tokens from a CSPRNG (not `random`)? (scanner: `CODE_WEAK_RANDOM`)
- JWT signature actually verified? (scanner: `CODE_JWT_NOVERIFY`)

## A08 Software & Data Integrity Failures
- Deserializing untrusted data (`pickle`, `yaml.load` without SafeLoader)? (scanner: `CODE_PICKLE`, `CODE_YAML_UNSAFE`)
- Fix: JSON or `yaml.safe_load`; verify signatures on updates/plugins.

## A09 Logging & Monitoring Failures
- Are auth failures and access-control denials logged (without secrets/PII)?

## A10 Server-Side Request Forgery
- Does user input control a URL the server fetches?
- Fix: allow-list destinations, block internal IP ranges.
