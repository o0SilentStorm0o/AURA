# AURA Public Demo Workflow

This folder contains the outreach-safe public demo target list and small helper
scripts for opening Google Play targets and generating target-scoped teaser
reports.

The goal is to create a non-invasive teaser, not an unsolicited vulnerability
report.

Hard boundaries:

- Install only public Google Play builds, unless the owner gives another build.
- Do not use APK mirrors for first-contact demos.
- Do not log in to the target app.
- Do not exercise payment, health, bank, or account flows.
- Do not use root, Frida, MITM, exploit attempts, or protection bypass.
- Do not read screen contents, notification contents, keystrokes, or network payloads.
- Send only `public_teaser` reports before authorization.

Current first-wave targets:

- `gastromapa`: Futured / Gastromapa Lukase Hejlika /
  `com.thefuntasty.gmlh`
- `bikeflip`: Pixelmate / Bikeflip / `com.bikeflip.app`
- `bistro`: GoodRequest / Bistro.sk / `sk.azet.bistro`
- `isnemovna`: Ackee / iSnemovna / `cz.ackee.isnemovna`

Unsupported, abandoned, unavailable, or hobby-only apps should be removed from
the active target list. Dudelo is intentionally not part of the current
first-wave list.

Open a first-wave target on a Google Play emulator:

```bash
python3 tools/public_demo/open_play_target.py gastromapa
```

After manually installing the app from Google Play and running an AURA scan,
pull the export from the app-private path:

```bash
adb exec-out run-as cz.davidstrnadel.aura.research \
  cat files/exports/aura-last-scan.json \
  > artifacts/public-demo/first-wave/aura-last-scan.json
```

Then generate the teaser:

```bash
python3 tools/public_demo/create_teaser_report.py \
  artifacts/public-demo/first-wave/aura-last-scan.json \
  gastromapa \
  --evaluation artifacts/scenario_runner/evaluation.json
```

The helper wraps:

```bash
python3 tools/report_generator/generate_report.py \
  <export.json> \
  --report-type public_teaser \
  --target-package <package> \
  --client-name <client> \
  --public-app-name <app> \
  --public-source-url <play-store-url>
```

Manual review gate:

Before sending, read the report end to end and remove anything that sounds like
an accusation, vulnerability disclosure, or proof of compromise. The correct
framing is: this is a sample of AURA's report structure, and full technical
findings require authorization.

Generated teaser artifacts are written under:

```text
artifacts/demos/<target-id>/aura-public-teaser-<target-id>.md
artifacts/demos/<target-id>/aura-public-teaser-<target-id>.html
artifacts/demos/<target-id>/aura-public-teaser-<target-id>.export.json
```
