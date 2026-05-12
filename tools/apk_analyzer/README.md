# AURA Offline APK Analyzer

This host-side analyzer inspects APKs without installing or executing them.
It complements the on-device defensive-surface audit with best-effort static
signals that are not reliable inside a no-root Android app:

- `network_security_config` resources
- debug overrides and user-CA trust hints in network security config
- BROWSABLE deep links and app links
- backup/data-extraction rule presence
- `FLAG_SECURE` code patterns
- `filterTouchesWhenObscured` code/resource patterns
- `accessibilityDataSensitive` code/resource patterns
- WebView configuration API patterns
- embedded secret/config/endpoints review
- third-party SDK namespace privacy surface
- target SDK policy risk
- manifest backup/debuggable/cleartext/exported-component metadata

Run it after building fixture APKs:

```bash
python3 tools/apk_analyzer/analyze_apk.py \
  testapps/sensitive-bank/build/outputs/apk/debug/sensitive-bank-debug.apk \
  testapps/leaky-bank/build/outputs/apk/debug/leaky-bank-debug.apk \
  --out artifacts/scenario_runner/offline-apk-analysis.json
```

The output is JSON and every finding carries `confidence` and
`observabilityState`. Static absence findings are deliberately low confidence;
they are research audit signals, not runtime proof.

The analyzer is now a primary input to app-owner release-risk reports. Findings
are intentionally phrased as things to fix or manually verify before release,
not as proof that an app is exploitable.

Unit tests:

```bash
python3 -m unittest tools/apk_analyzer/test_analyze_apk.py
```
