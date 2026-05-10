# Binary Transparency Integration Point

Binary Transparency verification is intentionally not implemented in the
Research MVP. The current app only records package identity, signing digests,
source path, installer, and provenance evidence.

Future work should add a host-side verifier that:

- accepts an exported AURA snapshot or APK inventory,
- checks only packages covered by the relevant transparency ecosystem,
- records verifier version, log/source URL, inclusion proof status, and failure
  reason,
- feeds the result back as provenance evidence, never as a hard whitelist.

Until that verifier exists, AURA must not claim that a package is
"transparency verified".
