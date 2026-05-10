# MIGRATION

AURA was locally seeded from the CyberSentinel Android base to reuse a working Kotlin/Compose/Gradle scaffold.

The public research artifact intentionally does not preserve CyberSentinel git history. The initial AURA commit should contain only the cleaned project state:

- AURA app identity and namespace: `cz.davidstrnadel.aura`
- research/product flavor matrix
- AURA model, evaluator, fixtures, tests, and research docs
- no CyberSentinel legacy feature modules in the MVP path

Before the first public push:

- run `git status` and inspect all tracked files
- verify `.gitignore`
- remove `local.properties`, keystores, API keys, secrets, logs, build outputs
- grep for tokens, keys, absolute paths, personal notes
- ensure legacy CyberSentinel modules are removed or isolated
- make the first commit only after cleanup
