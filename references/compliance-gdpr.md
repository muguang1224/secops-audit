# GDPR-style data-handling review

Review prompts for changes that touch personal data. **Not legal advice** — a checklist to make you ask the right questions, not a compliance certificate. A passing scan is not "GDPR compliant".

## 1. Lawful basis & purpose
- What personal data does this change collect or process?
- Is there a stated purpose and lawful basis (consent, contract, legitimate interest)?

## 2. Data minimization
- Does the code collect only what the feature needs? Flag fields that are "nice to have".
- Are you storing raw PII where a hash or an opaque id would do?

## 3. Retention
- Is there a deletion/expiry path for the new data, or does it live forever?
- Do logs contain PII (emails, IPs, ids) that will outlive their purpose?

## 4. Access & security
- Who can read this data? Is access least-privilege and audited?
- Encrypted at rest and in transit?

## 5. Data-subject rights
- Can a user export their data (portability) and delete it (erasure)? Does this change break those paths?

## 6. Third parties / transfers
- Does data flow to a new third party or cross a border? Is that covered by a DPA / transfer mechanism?
- Any analytics/SDK calls that exfiltrate PII?

## 7. Consent & transparency
- If processing is consent-based, is consent captured and revocable?
- Does the privacy notice need updating for this change?

**Output format:** `area → finding (file:line) → risk → recommended change`.
