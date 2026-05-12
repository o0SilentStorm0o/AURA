# AURA Release-Risk Summarization Notes

doc_id: aura_release_risk

AURA app-owner reports should summarize release risk as ticket-ready review areas, not as malware verdicts. The canonical data model is `ReleaseRiskFinding` and `FindingGroup`. LLM output may rewrite summaries and review questions, but must not create findings, change priority, change status, change severity, or cite evidence that is not already present in the audit JSON.

Use these fixed caveats when evidence comes from installed-app metadata only:

- Manifest-level evidence only.
- Exploitability is not proven.
- Full review should use APK offline analysis, source review, and targeted dynamic testing.

Preferred customer language:

- release risk
- exposed surface
- review area
- hardening gap
- acceptance criteria
- verification
- retest

Avoid customer-facing claims like:

- vulnerability proven
- exploit confirmed
- malware
- unsafe by default
- critical bug without authorization

