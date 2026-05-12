# Android Component Review Groups

doc_id: android_component_groups

Payment redirect surfaces should be summarized as one review area when they contain payment, checkout, Stripe, FinancialConnections, LinkRedirect, BrowserProxyReturn, or similar callback/return activity names. Recommended review:

- Confirm URI scheme, host, and path constraints.
- Confirm state or nonce validation before accepting callback results.
- Confirm SDK configuration matches the production package name and signing certificate.

Authentication callback surfaces should ask reviewers to confirm state validation, expected caller behavior, redirect constraints, and token/code handling.

Deep link/router surfaces should ask reviewers to confirm accepted schemes, hosts, paths, parameters, and authorization checks before sensitive navigation.

WebView/browser entry points should ask reviewers to confirm trusted origins, URL loading restrictions, JavaScript bridge restrictions, mixed content handling, and file access controls.

Third-party SDK exported surfaces are not bad by default. They should be summarized as privacy/configuration review targets, especially for Facebook, Google/Firebase, Huawei HMS, Sendbird, Ravelin, analytics receivers, push services, and CustomTabs.

Preview/tooling surfaces in release artifacts should be summarized as release hygiene review targets. They should be removed from production builds or protected/documented if intentionally shipped.

