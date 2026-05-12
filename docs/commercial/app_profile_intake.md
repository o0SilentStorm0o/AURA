# AURA App Profile Intake

Use this short intake before every app-owner audit. AURA can run without it,
but policy tuning is only commercially useful when the report knows the app
category, release stage, data sensitivity, and expected integration surfaces.

## Product Context

- App name:
- Package name:
- Customer / team:
- Intended distribution: Google Play / enterprise / sideload / SDK demo / other
- Release stage: debug / internal_debug / beta / production_candidate / production
- App category: fintech / health / ecommerce / public_info / internal_enterprise / sdk_library / utility / other
- Data sensitivity: low / medium / high / regulated
- Is this an SDK/library artifact or a full app?

## Sensitive Flows

- Login or account state: yes / no
- Payments, wallet, investment, or financial decisions: yes / no
- Health, medical, or regulated personal data: yes / no
- Messaging, chat, user-generated content, or private uploads: yes / no
- Location-sensitive behavior: yes / no
- Child-facing or safety-critical context: yes / no

## Expected Android Surfaces

- Expected exported activities/services/receivers/providers:
  - component:
  - purpose:
  - expected caller:
  - validation contract:
- Expected deep links/app links:
  - scheme/host/path:
  - auth/payment/callback/redirect/token parameters:
  - autoVerify expected: yes / no
- WebView usage expected: yes / no
  - trusted origins:
  - JavaScript bridge expected: yes / no
- Cleartext exceptions expected: yes / no
  - allowed domain/IP:
  - release-stage limit:
  - reason:

## Accepted Risks

Accepted risks must be explicit and traceable. They suppress repeat noise, but
remain visible in the report.

```json
{
  "type": "EXPORTED_COMPONENT_WITHOUT_GUARD",
  "rawContains": "PaymentCallbackActivity",
  "status": "ACCEPTED_RISK",
  "reason": "Temporary partner integration accepted until signed callback contract ships."
}
```

Allowed statuses:

- `ACCEPTED_RISK`
- `NOT_APPLICABLE`

## JSON Profile Template

```json
{
  "appCategory": "fintech",
  "dataSensitivity": "high",
  "releaseStage": "production_candidate",
  "distribution": "google_play",
  "authFlow": true,
  "payments": true,
  "webviewUsageExpected": false,
  "externalIntegrationsExpected": true,
  "allowedCleartextDomains": [],
  "knownExportedComponents": [],
  "acceptedRisks": []
}
```
