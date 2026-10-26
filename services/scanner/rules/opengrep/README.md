# Lomo CodeSecurity OpenGrep rules

This is the product-owned, offline OpenGrep rule pack used by Lomo
CodeSecurity. Version `0.1.0` targets OpenGrep `1.27.0` and is licensed under
Apache-2.0.

The pack intentionally starts small. It detects direct use of dynamic code
evaluation and command-shell execution primitives in Python, JavaScript and
TypeScript, Go, Java, Ruby, and PHP. These are high-impact review signals, not
proof that untrusted input reaches the sink. Scanner evidence remains subject
to human review, and rule matches never authorize an AI advisor to change a
deterministic gate or finding lifecycle.

Runtime scans load only the digest-verified copy projected into the active
offline cache generation. They do not download remote registry rules. Every
rule has a positive and zero fixture in `tests/scanner-runtime/fixtures`; the
release qualification records exact OpenGrep SARIF behavior before marking the
adapter canary verified.

Changes require a version bump, updated per-file and canonical-tree hashes in
`scanner-rules.lock.json`, positive and zero canary evidence, and the complete
eight-scanner qualification matrix.
