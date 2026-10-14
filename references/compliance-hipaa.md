# HIPAA-style PHI handling review

Review prompts for changes that touch protected health information (PHI). **Not legal advice.** Use as a structured review, not a compliance guarantee.

## 1. Is it PHI?
- Does the data identify a person **and** relate to health, care, or payment for care?
- Watch the indirect identifiers: dates, zip, device ids, free-text notes.

## 2. Minimum necessary
- Does the code expose or transmit more PHI than the task requires?
- Are full records pulled when a projection would do?

## 3. Access control & audit
- Role-based access enforced server-side for every PHI read/write?
- Are access events logged (who, what, when) without copying PHI into logs?

## 4. Encryption
- PHI encrypted at rest and in transit? TLS verified?
- No PHI in URLs, query strings, or analytics events.

## 5. Transmission to third parties
- Is any PHI sent to an outside service? Is there a Business Associate Agreement (BAA) covering it?
- LLM/analytics/SDK calls that receive PHI need explicit coverage — flag them.

## 6. De-identification
- Where data is "anonymized", check it can't be re-identified via combination.
- Prefer aggregation or synthetic data for non-production use.

## 7. Breach readiness
- If this data leaked, could you detect and scope it? Is there an access log to reconstruct exposure?

**Output format:** `area → finding (file:line) → PHI exposure risk → recommended change`.
