# Scanner tools

CodeSecurity runs eight external scanners against explicitly authorized source.
The **Tools** page shows their enabled state, installed versions, readiness and
reviewed data. Start with [platform setup](PLATFORM_SETUP.md) and the
[normal workflow](GUI_FIRST_WORKFLOW.md). Platform limits and known issues are
listed in [release status](RELEASE_STATUS.md).

## Included tools

These are the source preview's pinned versions, not a promise to track upstream
latest releases. [The tool lock](../scanner-tools.lock.json) binds binary inputs,
versions, licenses and data; [the rules lock](../scanner-rules.lock.json) binds
reviewed rule trees. Image construction verifies all eight tools.

| Tool | Version | Role | Native evidence |
| --- | --- | --- | --- |
| Trivy | `0.73.0` | Vulnerabilities, secrets and infrastructure configuration | SARIF |
| Gitleaks | `8.30.1` | Secrets | SARIF |
| OpenGrep | `1.27.0` | Static application security checks | SARIF |
| Bearer | `2.1.0+lomo.1` | Application security and privacy checks | JSONV2 |
| Grype | `0.117.0` | Dependency vulnerabilities | SARIF |
| Checkov | `3.3.10` | Infrastructure configuration | SARIF |
| TruffleHog | `3.96.0` | Secrets, with network verification disabled | JSONL |
| Syft | `1.51.0` | Software bill of materials | CycloneDX JSON |

Syft runs before Grype when both are enabled. Grype uses the sanitized SBOM from
that same scan; selecting Grype without Syft produces incomplete evidence.
Tools must produce their expected output even when they find nothing. Missing,
malformed or untrustworthy output cannot become a clean result. Bearer analysis
errors withhold its findings and make that tool incomplete, including when its
process otherwise exits successfully.

The optional `secrets-lite`, `sast-lite` and `iac-lite` scanners are built-in
heuristic checks. They start disabled and are explicitly labeled as internal
fallback scanners. Enable them in Tools when useful; they do not replace the
external tools or expand their language coverage.

## Operator preparation and admission

1. Open **Tools** and choose **Prepare all scanners**.
2. Follow the displayed steps: check available scanner data, download and verify
   required data, then scan with complete coverage.
3. Wait for **Ready to Scan**, then start a scan from the normal project workflow.

Preparation checks the curated locks, not arbitrary upstream latest versions.
The separate updater downloads only reviewed inputs and has no source mount.
Progress shows real stages and activity; an indeterminate indicator is not a
percentage or an estimated finish time. Reloading the page rejoins the durable
job rather than starting another download.

Service health establishes liveness only. **Ready** additionally requires the
selected binary, rules and data to pass availability, integrity and freshness
checks. A built image or a completed download alone does not establish readiness.
OpenGrep and Bearer need validated rule generations as well as their binaries.

On startup, cache status can show **Verifying** while content is checked.
Complete scans and new preparation remain blocked while active verification is
pending or failed. Verification of the previous generation is separate: it can
block rollback without making a verified active generation unusable.

If an enabled scanner is blocked, complete-scan admission fails before creating
a scan or job. An explicitly acknowledged limited scan is available only when
at least one enabled scanner is ready. It runs that subset and records omitted
tools and reasons. Its result remains `partial` and its gate remains incomplete.
Changing finding lifecycle states cannot turn limited evidence into a pass.

## Interpreting coverage and findings

A complete result means the eligible source and native output were processed
without reported omissions. It does not guarantee detection of every flaw.
Rules have specific language, framework, source, sanitizer and sink coverage.
A CWE label alone does not promise detection of every case in that category.

Some rules identify risky APIs without proving attacker-controlled input. For
example, the bundled OpenGrep Python shell rule flags `shell=True`, and Bearer's
pickle rule can flag calls using constant input. Inspect the source and data
flow before deciding exploitability; record a clear reason for false-positive
triage. Undetected issues and unsupported constructs remain possible.

A completed scan can legitimately fail its configured finding policy. Conversely,
a scan with no findings can still be incomplete. Failed, cancelled and partial
results cannot pass [Git push protection](GIT_PUSH_PROTECTION.md). Advisor output
does not determine or repair the deterministic gate.

The current `incremental_diff` request executes a full source view. Results
record `effective_mode=full`, no changed-file count, and
`incremental-diff-fallback-full`; this is not incremental scanner execution.

## Renew expired definitions with updated source

Version 0.1 maintains scanner data through reviewed source updates. A fixed
checkout or source archive is not indefinitely self-updating.

| Input | Start of validity window | Policy |
| --- | --- | --- |
| Trivy OS and Java databases | Publisher `UpdatedAt` | Warn after 7 days; expire after 14 days |
| Grype database | Locked intrinsic build timestamp | Warn after 7 days; expire after 14 days |
| Trivy checks | Verified acquisition timestamp | Warn after 7 days; expire after 14 days |
| Reviewed OpenGrep and Bearer rules | Immutable lock identity | No invented time expiry |

Trivy's publisher `NextUpdate` is an advisory refresh time, separate from the
hard expiry. Warning data remains usable but may omit newer vulnerabilities.
Rebuilding unchanged locks or downloading the same intrinsic database again
cannot renew its window. Recovery from a previous generation preserves the
original timestamps. Trivy checks retain acquisition-relative semantics.

When Tools reports that scanner definitions require a source update:

1. Obtain newer reviewed source with fresh, compatible database locks. Preserve
   the existing state directory, control origin, editor profile and named volumes.
2. Run the [normal source launcher](SOURCE_STARTUP.md) with the same installation
   options. Native Windows uses the [Windows launcher](WINDOWS_SOURCE_STARTUP.md)
   and the existing WSL backend. Changed inputs rebuild the required images.
3. Choose **Prepare all scanners**, then wait for every enabled scanner to be ready.

Source updates do not silently migrate an incompatible database schema. If no
fresh reviewed definitions are available, complete scanning stays blocked.
Do not edit timestamps, disable freshness checks or copy review data into the
active cache. A `requires_lock_refresh` catalog result means the locked intrinsic
candidate cannot be admitted; another download cannot fix that identity. The
selected maintenance path is bundled reviewed source, not a published automatic
signed-data update channel.

## Cancellation, retry and rollback

Preparation has one persisted, host-selected deadline shared by catalog work,
queueing, acquisition, verification and retries. Restarting, refreshing the page
or moving between stages does not reset it. Individual operations also have
shorter bounds. After expiry, inspect the outcome and start a new explicit
preparation only when offered; replaying the old command does not renew it.

**Retry verification** retries an eligible failed observation of the unchanged
cache target. It downloads nothing. Refreshing status does not retry a failed
verification, and invalid content is not repaired by a timeout retry.

A failed preparation with an uncertain published outcome may offer **Check cache
outcome** in its job. This is a bounded read-only check: it cannot download,
activate, roll back or prune data. The original job stays failed even if the check
proves publication succeeded. Current readiness still controls scan admission.

**Cancel** is available before activation reaches its commit boundary. It becomes
unavailable while committing or activating. Cancellation can race with completed
publication; it does not undo an already activated, verified generation. A late
activation can remain valid while its preparation workflow reports a deadline
failure. Inspect the job and active cache rather than assuming rollback occurred.

Under **Advanced scanner maintenance**, **Check curated catalog** checks the
reviewed candidates. **Roll back cache** requires a previous-good generation
whose content, reviewed authority, compatibility and freshness all still pass.
It changes data and rules, not image binaries. Older reviewed locks may be
unavailable to the running source even when their stored bytes are intact.
Rollback is not a way around expiry or an automatic consequence of cancellation.

### Repairing a damaged sole cache selection

Normal preparation can replace a damaged or missing selected generation when
the pointer is valid, there is no previous-good generation, and all six data/rule
components are requested. It needs capacity for the complete replacement while
retaining the old data. Damaged bytes are not copied or declared rollback evidence.
Malformed pointers, unsafe layouts and partial repair requests fail closed.
Do not manually change ownership, permissions or generation pointers to bypass
these checks. Keep the failed state for diagnosis. Findings and published
artifacts are stored separately from the scanner cache.

## Source-owned scanner configuration

CodeSecurity owns scanner rules and configuration. Tools receive a small
environment allowlist and isolated home/cache paths, without service credentials
or ambient Python import overrides. Source must not introduce executable plugins
or silently suppress required checks.

Root `.gitleaksignore`, `.checkov.yaml` and `.checkov.yml` files cause the affected
tool to refuse with `source_control_unsupported:gitleaks` or
`source_control_unsupported:checkov`. Files stay intact; evidence is incomplete.
Hiding a tracked control file from an immutable Git scan is not a workaround.
Gitleaks ignores inline `gitleaks:allow` suppressions. These controls do not imply
that every upstream ignore mechanism or language is supported.

Source capture and analysis have separate bounds. Transport allows at most
5,000 files, 8 MiB per regular file and 64 MiB total decoded source. Eligible
code analysis has a separate 1 MiB file bound; oversized captured code cannot
produce complete coverage. Immutable Git exports include all tracked content.
See the [security policy](../SECURITY.md) for the source and trust boundaries.

## Offline execution and published evidence

Runtime scanners use the internal Compose network and disable updates and
telemetry where applicable. TruffleHog runs with `--no-verification`: discovered
secrets are not tested against external services. Missing data is never fetched
during a scan. Explicit preparation uses the separate source-blind updater's
network access. A changed image still needs actual offline/egress verification;
command-line flags or a health response alone are not that evidence.

Tools run sequentially in owned process groups with execution/resource bounds.
Timeouts terminate the owned process group. Raw scanner reports and diagnostics
stay in private scratch storage and are removed after the tool run. Native
report inputs are capped at 64 MiB; stdout/stderr share bounded container tmpfs
but do not yet have individual streaming limits. Persisted findings are normalized
and redacted. Syft's sanitized CycloneDX SBOM is the current downloadable artifact;
raw SARIF, JSONV2, JSONL and stderr are not published artifacts.

## Troubleshooting and contributor checks

- **Healthy but blocked:** inspect Tools readiness and the specific binary,
  rule, cache or verification reason. Use **Refresh readiness** after addressing
  the stated runtime prerequisite.
- **Verification stopped:** preserve the error; use the offered verification
  retry only for an eligible failed target. Do not bypass content checks.
- **Definitions require source update:** follow the renewal steps above.
- **Scan incomplete:** inspect omitted tools and analysis errors, source bounds,
  unsupported configuration and the Syft/Grype dependency before retrying.
- **Unexpected finding:** inspect source context and rule coverage before triage.

From the source root, `make support-bundle` collects bounded local diagnostics
without uploading or restarting services. [Inspect the bundle before sharing](MONITORING.md#local-bug-report-bundle).
Use `make test-public` for the contributor baseline described in
[Development](DEVELOPMENT.md); it does not qualify an installed platform.

With the backend running, the demo source authorized, a valid private CLI
capability available and all eight tools ready, `make demo-scan` registers and
scans the bundled vulnerable example. It requires complete eight-tool execution
and the Syft SBOM. A finding-policy failure is expected for vulnerable code and
is distinct from scanner execution failure. Never paste credentials into reports.

### Reviewed Trivy DB lock candidate

Maintainer review producers create non-authoritative proposals, not active data.
The build-receipt step precedes `make trivy-db-lock-candidate`,
`make trivy-java-db-lock-candidate` or `make grype-db-lock-candidate`.
Use [Development](DEVELOPMENT.md#review-a-trivy-db-lock-candidate) for prerequisites
and script help. Review exact source/build identities, digests, intrinsic dates,
compatibility and canary results before proposing a lock change. Rebuild after
editing the lock, run the relevant tests, and use normal preparation to acquire
it. Never copy a candidate directory into the product cache.

## Licenses and modified Bearer

The scanner image includes pinned top-level license texts and reviewed
attributions; their bytes are checked against the tool lock during the build.
See the [scanner license index](../services/scanner/licenses/README.md). Lomo's
Apache-2.0 license does not replace third-party licenses. That index alone is not
complete dependency, redistribution, source-distribution or image-SBOM clearance.

Bearer is the modified `2.1.0+lomo.1` build, with its exact
[source recipe](../services/scanner/bearer/source.lock.json) and
[patch](../services/scanner/bearer/lomo.patch). The pinned native builder verifies
inputs and performs selected semantic tests and compilation offline. Runtime
readiness binds its binary and build receipt; a stock binary is not equivalent.
The image retains the recipe, upstream license and modification notice.
