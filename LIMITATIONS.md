# LIMITATIONS

AURA is a no-root research prototype. It is not a kernel EDR, MDM product, malware sandbox, or Play Protect replacement.

It does not claim to detect:

- kernel compromise
- rootkits
- bootloader compromise
- baseband compromise
- TEE or secure element compromise
- hidden OEM framework behavior unavailable to third-party apps
- network payloads without user-visible metadata
- abuse that leaves no PackageManager, settings, usage, manifest, or snapshot evidence
- dynamic UI protections that are only applied at runtime and are not visible to static APK heuristics

No-root observability limits are first-class output. Unknown evidence increases uncertainty or abstention; it is not treated as malicious by default.
