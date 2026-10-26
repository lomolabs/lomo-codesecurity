# Monitoring

Prometheus and Grafana are optional and use the same cross-platform profile on
Linux, macOS, and Windows/WSL2.

```bash
make up-monitoring
```

Open:

- Prometheus: http://127.0.0.1:9090
- Grafana: http://127.0.0.1:3001

The Grafana administrator password and Postgres password are generated in the
owner-only external runtime file. They are deliberately absent from API
responses and the Settings UI. For Adminer use:

- system: `PostgreSQL`
- server: `postgres`
- database, user, and password from the local runtime file

The Prometheus profile scrapes:

- `api:8080/metrics`
- `scanner:8091/metrics`

## Current Metric Coverage

Only the following product metrics currently have an execution-path producer:

| Scrape target | Implemented series | Important limit |
| --- | --- | --- |
| API | `kodesec_advisor_duration_seconds` | Observed for attempted local Advisor calls; it does not describe scan or worker duration. |
| Scanner | `kodesec_scanner_scans_total{status}` and `kodesec_scanner_scan_duration_seconds` | Recorded when execution reaches a `completed` or `partial` scanner response; exceptions before response construction are not a reliable `failed` count. |
| Prometheus | Per-target `up` and normal scrape-engine metrics | `up` proves scrape reachability, not application readiness or durable recovery. |

The Python Prometheus client also exports its standard process, interpreter,
and collector metrics from the API and scanner processes.

Grafana provisions the `CodeSecurity Overview` dashboard automatically. Its API
reachability, API/scanner process CPU and resident memory, scanner-service
duration, and Advisor-duration panels have the producers listed above. Several
other panels currently query
declared but uninstrumented API series: `kodesec_scans_total`,
`kodesec_findings_total`, `kodesec_findings_by_scanner_total`,
`kodesec_scanner_tool_runs_total`, and
`kodesec_scanner_duration_seconds`. Those panels can be empty or zero and are
not release, scan-completeness, or recovery evidence. Do not infer a count from
a metric object merely being registered.

The public product UI and authoritative REST/job state remain the primary
operator surfaces. Grafana is currently supplementary resource and latency
visibility, not a complete durable-work control plane.

## Open Operational Instrumentation Gates

The secure-foundation candidate does not yet export the low-cardinality metrics
needed to operate or qualify the new scanner transport and durable worker:

- recovery-spool records and bytes, oldest retained result, capacity rejection,
  and cleanup-directory synchronization pending;
- manifest/page bytes and counts, protocol/digest/cursor rejection, page retry,
  and PostgreSQL ingestion duration or rollback;
- result ACK and digest-bound discard requested, confirmed, retried, failed, or
  awaiting filesystem `fsync` confirmation;
- durable job queue depth by kind/status, lease claims, heartbeats, expirations,
  takeovers, final-attempt recovery, cancellations, and terminal outcomes;
- outbox intent backlog and oldest age, dispatch/quarantine totals, replay/reset,
  listener reconnect/high-water lag, and PostgreSQL notification-queue usage.

These are open qualification and operations limitations, not hidden behind
existing scanner-duration or container-resource charts. Until they are
implemented and receipt-tested, use bounded local logs plus exact job, scan,
scanner-run, outbox, and checkpoint state for diagnosis. A manual query or a
green `/healthz` response is not a substitute for retained metric evidence.

Future series must use bounded labels such as job kind/status, event type,
scanner ID, and safe error code. Never label by project/source path, run/job/
finding ID, rule ID, request/result digest, cursor, artifact path, capability,
or user-provided text.

The scanner service has Compose resource guardrails:

- `SCANNER_CPUS`
- `SCANNER_MEMORY_LIMIT`
- `SCANNER_PIDS_LIMIT`
- `KODESEC_EXTERNAL_TOOL_TIMEOUT`
- `KODESEC_EXTERNAL_TOOL_NICE`

Set these in the owner-only external runtime file before `make up` when running
on small laptops or shared Linux hosts.

The initial release intentionally does not ship cAdvisor. cAdvisor requires a
privileged container and broad host-observability mounts whose behavior differs
across Docker Engine, Docker Desktop, OrbStack, and WSL2. Selecting
**Monitoring** therefore starts only Prometheus and Grafana; it never grants a
container access to the host root, Docker runtime directory, system devices, or
kernel filesystems. Container-level CPU and memory charts remain out of scope
until a separately reviewed, truthful cross-platform collection boundary
exists.

## Local bug-report bundle

From the reviewed source checkout, run:

```sh
make support-bundle
```

The command prints the path to a private `support-bundle.tar.gz` in a new temporary
directory. It works before first startup and when Docker is missing or unavailable.
It does not initialize configuration, build, restart or stop containers, modify
installation state, inspect your editor/browser profile, or upload anything.
Python and Make are the only collector prerequisites. On Windows, run it in the
same WSL distribution and backend checkout used to start Lomo; this does not
collect Windows editor logs automatically.

If you started with a custom state directory, identify that same directory:

```sh
make support-bundle STATE_DIR=/absolute/path/to/your/lomo-state
```

The default bundle contains OS/architecture and tool versions, source revision,
scanner lock digests, available filesystem space, installation-scoped container
image/status/exit/OOM/restart information, and summaries of recent service logs.
It also runs the existing source-identity checker: a clean checkout reports its
commit and tree; an unpacked source directory reports its local build-input
digest. A dirty, ambiguous or timed-out source check remains an explicit failed
observation. A local digest does not establish publisher trust.
Each observation has a success, failure, timeout or missing-input status. The
manifest hashes each included evidence file. No source files, findings, database,
`runtime.env`, environment dump, credential store or browser/editor profile is
exported. Log summaries include known error classes and counts, without arbitrary
message text that might contain private project information.
For Grype database validation, the default summary also retains known reason
codes and bounded phase timings, such as a deadline spent processing database
rows. It omits operation identifiers and arbitrary exception details; missing
timings are not interpreted as zero elapsed time.
Runtime cache verification failures also retain their fixed target, component,
state, phase and bounded elapsed time, including a timeout after an otherwise
successful preparation. These summaries preserve the distinction between updater
completion and current scanner readiness.

For a difficult runtime failure, you can explicitly include recent log text:

```sh
make support-bundle SUPPORT_LOG_TEXT=1
```

This includes at most 200 lines and 64 KiB per container from a fixed 15-minute
window. Incomplete or truncated reads remain summary-only even with this option.
Generated runtime values, common credential fields (including `credentials` and
non-PEM `private_key` values), authorization headers,
URLs, private user paths and email addresses are redacted. **Review the extracted
files before sharing**: unknown application-specific secrets or private text may
still appear in custom log messages. Keep the default summary-only bundle when
such review is impractical. Nothing is sent automatically.

The collector has a 90-second collection budget and a five-second bound per CLI
call. It terminates only its own timed-out CLI process group, never Docker services.
Logs are bounded samples; rotation, tail limits, truncation and unavailable history
can leave gaps. A silent service is not proof that it is healthy. The manifest
records incomplete observations rather than presenting them as a successful check.
An oversized, duplicate or malformed container inventory explicitly records
`container-details` as `not_collected`; the successful inventory command alone
does not mean that container metadata or logs were collected.

For a useful report, attach the reviewed bundle and describe the action, UTC time,
expected result and actual result. Include whether the issue occurs in Windows
native VS Code or Remote WSL. If startup failed before service logs existed, include
its displayed error separately after reviewing it for private information; the
collector cannot recover console output that was never saved. For extension-only
problems, copy the relevant bounded **CodeSecurity** Output entries after the same
review. Do not attach the whole VS Code user-data directory.

Missing configuration or Docker produces a partial diagnostic bundle, not a repair.
Successful command completion means the archive was created; it does not mean
every observation succeeded. If Docker times out, tool/source information and the
timeout records can still help diagnose startup, but service health and recent
service logs remain unavailable. Keep those gaps in the report.
Use the setup guide to address the reported prerequisite, reproduce once, and collect
a new bundle. Keep the original failure bundle so the before/after difference remains
clear. Temporary files are yours to remove after the report is resolved.
