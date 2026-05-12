# AURA Pre-Send Triage Checklist

Run this internal checklist before sending an app-owner report to a customer.
The goal is to keep the report CTO-useful: rare P1s, ticket-ready fixes, and no
raw scanner noise posing as product judgment.

## 1. Scope

- Target APK/package is correct.
- Report type is `app_owner`, not whole-device expert mode.
- App profile is attached or the report clearly says a generic profile was used.
- Release stage is correct.
- Privacy mode matches audience.
- No unsupported claims such as malware proof, exploit proof, or safety
  certification.

## 2. P1 Calibration

- Every `BLOCKER` would plausibly stop a production release.
- No P1 is based only on absence of a weak signal.
- `debuggable=true` is P1 only for production candidate/production.
- Broad cleartext is P1 only when profile context justifies it, such as high
  sensitivity fintech/health.
- Known exported components are downgraded to review, not silently passed.

## 3. Ticket Readiness

For each customer-visible finding:

- Title is specific enough for a ticket.
- Suggested owner is present.
- Acceptance criteria are concrete.
- Verification command/check is present.
- Manual-review flag is correct.
- Evidence is enough to reproduce without exposing unnecessary sensitive detail.

## 4. Noise Check

- Duplicate raw defensive/offline rows are not presented as separate customer
  task lists.
- INFO findings are context, not release blockers.
- Accepted risks are visible but excluded from blocker counts.
- `UNCLASSIFIED_RELEASE_REVIEW_FINDING` is rare; recurring unclassified items
  should become specific policy rules.

## 5. Retest

- Stable fingerprints are present.
- If previous audit is supplied, fixed/remaining/new counts make sense.
- Retest resolution rate is shown when comparison is available.

## 6. Customer Follow-Up Question

Ask after every pilot:

```text
Which three findings felt least useful or most noisy?
```

Feed the answer back into policy packs, app profiles, or accepted risks.
