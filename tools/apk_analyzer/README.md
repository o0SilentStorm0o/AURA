# AURA Offline APK Analyzer

This host-side analyzer inspects APKs without installing or executing them.
It complements the on-device defensive-surface audit with best-effort static
signals that are not reliable inside a no-root Android app:

- `network_security_config` resources
- `FLAG_SECURE` code patterns
- `filterTouchesWhenObscured` code/resource patterns
- `accessibilityDataSensitive` code/resource patterns
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

Unit tests:

```bash
python3 -m unittest tools/apk_analyzer/test_analyze_apk.py
```
