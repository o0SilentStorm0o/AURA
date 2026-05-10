# Firmware APK Inventory

This tool is a conservative first step toward OEM/preinstall dataset work. It
does not decompile APKs and does not claim to identify vulnerabilities. It only
walks an extracted firmware directory, records APK file metadata, and produces a
stable JSON inventory that can later feed offline analysis.

Usage:

```bash
python3 tools/firmware_ingest/collect_apks.py /path/to/extracted/firmware \
  --out artifacts/firmware/apk-inventory.json
```

The output can be reviewed before any APK is passed to the offline analyzer.
