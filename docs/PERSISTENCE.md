# Persistence

CodeSecurity uses Docker named volumes by default. This keeps `make up` simple
and is intended to reduce host differences. It is not cross-platform
qualification; macOS, Ubuntu, Fedora, and Windows/WSL still require current
receipt-backed acceptance.

## Volumes

| Volume | Purpose |
| --- | --- |
| `pg_data` | Postgres data |
| `artifacts` | bounded, redacted Syft CycloneDX JSON SBOMs only |
| `scanner_cache` | separately seeded scanner databases/rules used offline |
| `gitea_data`, `gitea_config` | optional Git proxy data |
| `prometheus_data`, `grafana_data` | optional monitoring data |

Generated runtime configuration is not a Docker volume. It lives outside the
checkout at `${XDG_STATE_HOME:-$HOME/.local/state}/lomo-kodesec/runtime.env` by
default and remains an operator-owned secret boundary.

Raw scanner stdout, stderr, SARIF, JSONV2, and JSONL are never persistence inputs. They
are bounded in a private tmpfs request directory, parsed into redacted findings,
and deleted after each tool run. Startup also removes invalid or unindexed files
from the product-owned `artifacts/scans/` subtree when they do not satisfy the
publishable CycloneDX boundary; unrelated root siblings are never swept.

## Temporary Scanner Recovery Spool

Raw tool output and the scanner recovery spool are different boundaries. Raw
tool output is deleted after parsing. A completed or partial scanner result is
then normalized, redacted, strictly validated, deterministically ordered, and
sealed as canonical UTF-8 JSON Lines under
`/run/kodesec-scratch/run-results`. Compose mounts that path on the scanner's
private tmpfs; it is not a named volume, durable evidence store, backup input,
or downloadable artifact.

The scanner creates the result directory with mode `0700` and each spool file
with mode `0600`. It rejects symlinks, non-regular files, ownership/mode drift,
hard-linked entries, unknown names, and concurrent registry ownership. It
writes a unique temporary file, `fsync`s the file, atomically renames it to a
name bound to the run and result digest, then `fsync`s the directory before
exposing the immutable result manifest.

The current default and wire bounds are:

| Boundary | Contract |
| --- | --- |
| Finding | One canonical JSONL record, at most 32 KiB including its newline |
| Page | At most 128 findings and a 4 MiB encoded response; 16 KiB is reserved for the envelope |
| Run | At most 50,000 findings and 336 MiB for the canonical finding stream plus manifest |
| Registry | Four terminal records by default and at most 384 MiB of retained result data |
| Compose tmpfs | 512 MiB for scanner scratch, separate from the 64 MiB `/tmp` mount |
| Recovery window | 1,800 seconds by default, bounded to at most 3,600 seconds |

Unacknowledged evidence is not evicted merely to satisfy the terminal-record
count; new admission fails when retained evidence consumes the configured
capacity. The time-bounded recovery window still applies. Scanner startup
removes recognized temporary and sealed spool files because the process-local
run registry and cursor secret do not survive a scanner restart.

The manifest binds schema version, `completed` or `partial` evidence status,
canonical finding-stream SHA-256, total finding count and bytes, page count and
fixed page limit, bounded summary, sorted artifact declarations, and a digest
of all those fields. Findings are globally ordered by severity, canonical
project-relative path, start/end coordinates, scanner, rule, and fingerprint;
duplicate fingerprints are rejected. Each page repeats the run, immutable
request, and result bindings and carries its ordinal, canonical byte count,
page digest, continuation state, and an HMAC-protected cursor bound to the next
ordinal and byte offset. A cursor from another process, request, run, result,
or byte boundary is invalid.

## PostgreSQL Publication And Acknowledgement

PostgreSQL is the durable source of truth. The worker never treats a scanner
manifest, a page response, or the temporary spool as published evidence. Its
publication sequence is:

1. Validate the strict manifest and bind the exact request digest, result
   digest, artifact-manifest digest, and inspected artifact-provenance digest
   in the durable job checkpoint.
2. Fetch one bounded page at a time. Reject duplicate JSON keys, unknown fields,
   non-canonical values, invalid paths/ranges, discontinuous ordinals, sort
   regression, duplicate fingerprints, oversized items/pages, bad cursors, or
   any page, stream, summary, artifact, count, byte, or digest mismatch.
3. In one PostgreSQL transaction, replace the scan's prior findings and
   artifact indexes, redact and insert each admitted page, re-admit the exact
   attested artifacts, update scan/findings revisions, and commit the typed
   `scanner_persisted` checkpoint with the immutable request/result binding.
4. Only after that transaction is known to have committed, acknowledge the
   exact result with the stable run ID, request digest, and result digest. The
   scanner removes the temporary JSONL and returns `result_available=false`.

The worker keeps only bounded pages in transport while inserting them into the
open transaction; it does not deserialize the complete finding collection as
one HTTP response. If the transaction rolls back or its outcome cannot yet be
proved, no partial finding set becomes authoritative and the spool is retained
for reconciliation.

Once `scanner_persisted=true` is durable, recovery is ACK-only: a replacement
worker reloads the typed binding, repeats the idempotent acknowledgement, and
continues gate/finalization work. It does not page and insert the findings a
second time. A scanner `404` is accepted as acknowledgement success only in
this already-persisted recovery path, where the exact result may already have
been acknowledged and its process-local tombstone expired.

Malformed or otherwise rejected terminal transport is never published. When a
hostile state body still exposes the exact stable run, request digest, and a
syntactically valid result digest, the worker first commits a
`scanner_cleanup=discard` checkpoint with the terminal error, then requests a
DELETE bound to both digests. Failure remains recoverable until that exact
discard is confirmed; an unbound delete cannot erase completed evidence.

Acknowledgement cleanup also treats filesystem durability uncertainty
explicitly. If unlink succeeds but the result-directory `fsync` fails, the
scanner clears the stale pathname, records that directory synchronization is
pending, and retries the durability obligation without attempting to unlink a
name that is already gone. The worker leaves the job recoverable until ACK is
confirmed. On scanner startup, safe reconciliation removes any recognized
sealed name that could have reappeared after a crash.

## Gate And Mode Provenance

Scanner summaries persist both the requested and effective source mode. The
current `incremental_diff` request deliberately executes every enabled core
scanner against the full repository, records `requested_mode=incremental_diff`,
`effective_mode=full`, `changed_files_count=null`, and the warning
`incremental-diff-fallback-full`. The database and UI therefore never present a
full scan as changed-file-only evidence.

Only terminal `completed` evidence is eligible for the deterministic policy
gate. A terminal `partial`, `failed`, or `cancelled` scan cannot pass and is
finalized with the fail-closed incomplete reason; an already fail-closed
`fail`/`incomplete` decision is never relaxed by a later lifecycle path. Local
Advisor output is persisted separately and cannot repair evidence completeness
or change the deterministic gate by itself.

## Experimental Backup

The current backup helper is non-atomic and has not passed a backup/restore
acceptance test. It can observe inconsistent database and volume state while
writers are active. Do not treat it as a production-safe backup or use it as the
only copy of important data. Backup and restore are disabled by default, including
direct script invocation, and are omitted from ordinary command help. They refuse
before runtime initialization, filesystem changes or Docker actions unless
`KODESEC_DISPOSABLE_RECOVERY_TEST` is exactly `1`. Values such as `true`, `yes`,
`01` or an empty value do not opt in. The flag acknowledges disposable testing;
it does not validate recovery or make either helper safe for important data.

For an already initialized, explicitly selected disposable installation only:

```bash
KODESEC_DISPOSABLE_RECOVERY_TEST=1 make backup STATE_DIR=/absolute/private/disposable-lomo-state
```

The backup script writes:

- `postgres.sql`
- `volumes.tar.gz`
- `gitea.tar.gz` when the Git proxy profile has been used

Runtime secrets are intentionally excluded. Backups land under the external
state directory at `backups/<UTC timestamp>/` by default and are created with
owner-only permissions.

## Experimental Restore

Restore is destructive to the destination public schema, is not transactional
across Postgres and volumes, and has not been validated for recovery. Do not run
it against an installation that matters. For a disposable destination only:

```bash
KODESEC_DISPOSABLE_RECOVERY_TEST=1 make restore \
  STATE_DIR=/absolute/private/disposable-lomo-state \
  BACKUP_DIR=/absolute/private/disposable-lomo-backup
```

Restore requires an already initialized destination installation, recreates the
public schema from `postgres.sql`, and unpacks saved volumes. It does not import
source-installation secrets. Neither command initializes an installation. The
same exact opt-in is required when invoking `scripts/backup.sh` or
`scripts/restore.sh` directly; select its disposable state with
`KODESEC_STATE_DIR`. Do not export the opt-in permanently in a shell profile.

Postgres includes runtime config, scanner tool enablement/version state, jobs,
scans, findings, scan artifact indexes, and gate policies. Raw scanner outputs
are not retained. Only publishable sanitized CycloneDX SBOMs stay in the
`artifacts` volume and can appear in `volumes.tar.gz`; the separate tool cache is
operational input, not evidence for download.

Deleting a scan from the UI removes the scan row, findings, jobs, artifact
indexes, and files under `/data/artifacts/scans/<scan-id>/`. Deleting a project
cleans all scans and artifacts for that project.

## Visible Backup Destination

For a disposable backup experiment with a visible destination, set a Compose
project and backup destination explicitly. Keep both outside the source tree:

```bash
COMPOSE_PROJECT_NAME=my-kodesec \
  BACKUP_DEST=/absolute/private/disposable-lomo-backup \
  KODESEC_DISPOSABLE_RECOVERY_TEST=1 \
  make backup STATE_DIR=/absolute/private/disposable-lomo-state
```

The default remains named volumes because it is the least fragile option across
Docker Desktop, OrbStack, and Linux Docker Engine.
