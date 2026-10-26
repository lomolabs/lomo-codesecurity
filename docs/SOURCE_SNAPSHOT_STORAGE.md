# Bounded source snapshot storage

Native Windows and immutable Git checks share the API's dedicated
`source-snapshots` storage. Uploads do not widen source mounts or execute source.

Before writing a new generation, admission requires:

- At most 256 retained or interrupted generations, 65,536 filesystem entries,
  and 64 source-directory levels.
- At most 2 GiB of aggregate source-snapshot storage. Metadata-only accounting
  charges the larger of logical and allocated file size plus filesystem-block
  overhead; new writes reserve their rounded file/manifest and directory cost.
- Enough currently available filesystem space for the new allocation **and a
  further 2 GiB reserve**.

A private, no-follow publication lock serializes admission through completed
publication, and explicit snapshot deletion takes the same lock. A concurrent
operation receives `snapshot_storage_busy`; retry after that operation ends.
No waiting job, extra generation, or automatic retry is created by this boundary.

The inventory is descriptor-relative, metadata-only, depth/entry bounded, and
does not follow links. Interrupted `.pending-*` generation bytes and entries
remain charged. Unknown top-level or generation names, linked entries, or
unreadable/unsafe storage produce
`snapshot_storage_unavailable`; reaching a size/count/depth/free-space limit
produces `snapshot_storage_full`. Both refuse before writing payload bytes.
An identical already-sealed generation is fully validated and reused without
requiring another allocation, even when the new-write budget is full.

Nothing is automatically deleted to regain space. Review obsolete projects and
their retained scans before explicitly deleting them, or provide more storage.
Explicit project deletion reviews at most 256 generation entries before deleting
anything, then removes only fully validated generations bound to that exact
source identity. Other sources remain intact. Recognized private interrupted
`.pending-*` directories are skipped and preserved, so they do not prevent
deleting an obsolete completed project; their bytes remain charged to admission.
An absent generations directory or no matching completed generation returns
zero deleted items. An unavailable snapshot root still requires owner review.

Interrupted or unknown entries, or an inventory above the bounded review limit,
require an exact ownership review; never run a broad prune based only on size.
Normal failed-publication cleanup remains limited to that call's own temporary
generation.

These bounds coordinate API snapshot writers on one local storage filesystem.
They cannot reserve capacity against unrelated applications writing to that
filesystem, physical storage failure, or an owner modifying the private store
outside the API. Ordinary write failures still fail closed and clean only their
own pending publication. This is not a guarantee that the whole host disk can
never fill.

Focused regression (simulated capacity and concurrent publication, not actual
disk exhaustion):

```sh
cd apps/api
../../.kodesec-test/test-venv/bin/python -m pytest -q tests/test_source_snapshot_storage.py
```
