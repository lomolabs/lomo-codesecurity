# Security policy

Lomo CodeSecurity is a local security workbench. It runs scanners against source
that the operator explicitly authorizes. It is **not a sandbox for hostile
repositories**, and a passing scan is not a guarantee that code is secure.

The current release is a 0.1 source preview. There is no published long-term
support or backport policy. Check [release status](docs/RELEASE_STATUS.md) for
platform coverage and known issues.

## Reporting a vulnerability

In [lomolabs/lomo-codesecurity](https://github.com/lomolabs/lomo-codesecurity),
use **Security > Report a vulnerability** to send a private report when that
GitHub feature is enabled. The existence of this policy does not mean that
the reporting channel is available.

If a private reporting channel is unavailable, ask a maintainer through an
existing private contact for secure reporting instructions. Do not put
vulnerability details, working exploit payloads, credentials or private source
in a public issue. No response-time or remediation-time guarantee is offered.

A useful private report includes the affected version, platform, reproducible
steps, expected boundary, observed effect and a minimal synthetic example.
Do not attach runtime state, browser cookies, editor credentials, private
repositories or unreviewed logs. A support bundle is diagnostic material, not
proof that its contents are safe to publish.

## Local service boundary

The default installation exposes only `http://127.0.0.1:8080` for the core
application. An unprivileged TCP relay forwards to the API on an internal
container network. The API, PostgreSQL and runtime scanner have no host-published
ports. The relay receives no persistent volume or runtime secret configuration;
it necessarily carries authenticated traffic transiently in memory.

The API enforces exact Host and Origin checks, restricts its configured origin
to loopback HTTP with an explicit port, and rejects credentials in URL query
strings. Browser mutations require a session-bound CSRF value. Browser sessions
use HttpOnly, SameSite cookies. Editor capabilities are bound to the exact
profile, origin and authority generation, and stored in account-private files.
Browser and editor membership can be revoked independently.

Installation secrets live outside the checkout in owner-private runtime state.
Do not commit, share or copy that state between installations. The application
does not grant Workspace Trust or repair unsafe credential permissions to make
a connection succeed. Local account owners, OS administrators and the Docker
engine remain part of the trusted host boundary.

## Source code and findings

Source access requires narrow, explicit authorization. Selecting repositories
in an editor is separate from granting that access. POSIX and Remote WSL source
uses read-only mounts; supported native Windows source uses bounded, sealed
snapshots. Path containment, source identity and snapshot digests are checked.
Unsafe links, unsupported paths, changed identities and incomplete captures are
refused rather than treated as clean scans.

Source transfer permits at most 8 MiB per regular file, 5,000 files and 64 MiB
of decoded content. Scanner analysis has a separate 1 MiB eligible-file bound.
Capturing a larger code file does not make its analysis complete. Immutable Git
verification includes tracked history content; workspace exclusions do not
remove tracked files from a protected-push check.

Findings and bounded snippets are redacted before local persistence. Only
bounded, redacted supported SBOMs become downloadable scanner artifacts. Raw
tool output is temporary and deleted after processing. Redaction recognizes
known patterns; it cannot guarantee removal of arbitrary secrets. Do not grant
source access when retaining even redacted findings or snippets is unacceptable.

Scanner processes use restricted environments and disposable working state.
Unsupported source-owned scanner configuration is refused. These controls do
not make arbitrary repository content safe to execute or eliminate defects in
third-party scanners.

## Scanner data and complete evidence

Runtime scanners use an internal network and a read-only validated cache.
Scanner preparation runs in a separate updater with network access to reviewed
sources and no project-source mount. Requests select reviewed components, not
arbitrary download URLs or commands. Cache activation checks content, digests,
compatibility and freshness before changing the active selection.

Bundled definitions expire. The preview's maintenance path is refreshed reviewed
source, a rebuild of changed inputs and explicit scanner preparation. It does
not promise a signed automatic update channel. See [scanner maintenance](docs/SCANNER_TOOLS.md).

Only a completed scan can have a passing deterministic gate. Failed, partial,
cancelled, stale or missing evidence cannot authorize a protected push. Finding
dispositions and gate-policy changes do not repair incomplete scanner coverage.
Local Git hooks can be bypassed; they are not remote enforcement.

## Ollama and external requests

Ordinary scans do not invoke AI. Local Ollama is optional. Remote Advisor routes
require explicit host/provider authorization, model identity and a fresh
single-finding disclosure confirmation. Automatic and bulk remote routing are
not allowed. Cancellation cannot recall content already received by a remote
provider. Advisor output is untrusted advice and never determines the gate.

## Host control and practical limits

The API does not mount the Docker socket or execute arbitrary host commands.
Applying source roots, optional components and repository hooks remains an
explicit host-owner action. Do not expose the control origin to a LAN or public
network as a workaround for connection problems.

Keep runtime state and named volumes when updating. Recovery helpers are not a
validated disaster-recovery facility. The source preview has incomplete
cross-platform and failure-recovery qualification; consult [release status](docs/RELEASE_STATUS.md)
and report failures without bypassing source, credential or completeness checks.
