# GUI-first workflow

This is the normal operator path for Lomo CodeSecurity. The web application and
the VS Code extension are the primary product surfaces; Make and API commands
are recovery and automation boundaries. The contracts below describe the
active development source. It has no immutable candidate or platform receipt;
the documented cross-platform acceptance matrix remains required before
release.

Navigation refreshes the visible section and current active work. Terminal job
history is fetched on Jobs or Tools entry; other sections retain its last
observation. A disappeared active job stays unresolved until a fresh terminal
observation succeeds. Explicit Refresh, mutation reconciliation and background
reconciliation continue to read full history.
Project registration reconciles the stored project without changing a section
the user chose while the request was pending.

## 1. Start and connect

On macOS or native Linux, follow the [platform setup guide](PLATFORM_SETUP.md)
and run from the product checkout:

```bash
python3 scripts/start-lomo.py
```

The launcher builds and starts the backend, preserving your existing VS Code
profile and extensions. Open the desired workspace in that profile, install
`lomo-dev.code-security`, then run **CodeSecurity: Get Started**. Its six steps
cover backend, connection/trust, repository selection, preparation/scanning,
finding review and protection. Checkmarks record observed past progress;
commands revalidate current state. Opening a step or pressing its button does
not prove completion. **Connect / Review IDE Access** remains directly available.
Marketplace publication is pending; private rehearsals install the reviewed
VSIX manually. Repeat backend startup with the same state to preserve identity
and reuse unchanged images. Development/QA may explicitly choose `--source-vsix`
to build/install the extension in a dedicated profile. Source authorization
remains a separate step below. See
[source startup](SOURCE_STARTUP.md) for optional checks and manual recovery.

For Windows, use [Windows source startup](WINDOWS_SOURCE_STARTUP.md), choosing
native Windows or Remote WSL and the exact WSL2 backend explicitly. Install
Lomo in the selected native or WSL extension host; host placement and pairing
remain pending until completed and observed.

On a pristine installation with no browser member, active IDE, or consumed
installer authority, the first eligible VS Code profile claims the
one-use owner authority and activates its exact IDE generation. Review and
trust the selected workspace; the integrated dashboard then pairs automatically.
Restricted Mode uses temporary browser storage, so integrated pairing waits
for trust instead of creating a session that would disappear on editor exit.
No terminal value, clipboard step, browser sign-in, or IDE-approval prompt belongs
in this first-owner path. If more
than one new profile starts concurrently, the oldest live enrollment wins and
the others remain pending for owner review.

Use `make auth-info` only for browser-only startup or explicit browser recovery.
Do not paste its
one-time value into a command, issue, log, workspace file, or editor setting.
The browser exchanges it for an HttpOnly session and removes it from the visible
URL. If it was already consumed or exposed, run `make auth-reset`, then
`make up` and `make auth-info` again.

### Approve later VS Code profiles

If browser ownership already exists, or for every profile after the pristine
first owner, use the reviewed flow. In the exact VS Code profile to connect
(local desktop or Remote WSL), wait
for the CodeSecurity status bar to show **Approval needed** and a short
verification code. The extension creates this request automatically; there is
no IDE secret to generate, reveal, copy, or paste.

Run **CodeSecurity: Connect / Review IDE Access**. It opens the exact
**Settings > IDE access** anchor in an already-authenticated external owner
browser. Compare the visible code, endpoint, and recognizable editor/workspace
name with the pending row, then choose **Approve** for that exact request. Do
not approve an unexpected name or code. If no owner browser session remains,
recover that browser with `make auth-info` before reviewing the request.

Approval lets the editor activate only the `kc1.` authority already retained
for that exact endpoint, stable `ks1_` profile slot, and generation. The editor
verifies the pending record in its OS-account-private profile namespace and
atomically promotes it to active. Verify that **IDE access** shows the exact
client as active and the extension status changes to connected. The same
profile reconnects across editor, control-stack, and machine restarts while its
authority remains valid. CodeSecurity uses no static IDE value, OS keyring,
SecretStorage import, copy/paste enrollment, or compatibility path.

Use **Refresh IDE access** to reconcile exact pending and active states,
**Reject** or **Cancel** only the request whose code and client name match, and
**Revoke** only the active IDE member you intend to remove. Rejection,
cancellation, expiry, and revocation fail closed; a concurrent newer generation
is not removed.

The **Paired IDE clients** list shows a loading message until its first
successful read. A failed first read shows that clients could not be loaded,
not that no clients are paired. **No paired IDE clients** appears only after a
successful empty read. **Refresh IDE access** can recover the paired-client
list even if the separate pending-request read fails; in that case Settings
shows the refreshed clients and keeps an explicit pending-request error. A
later successful refresh clears that error. Previously loaded clients remain
visible if a subsequent refresh fails.

Corrupt local and server state have different repair actions. The extension's
local repair modal explicitly confirms and removes only unchanged,
proven-corrupt profile files; it does not delete a Settings client row. Web
Settings' **Remove invalid record** sends the row's redacted, non-secret
`kir1_` token, which CAS-fences the exact profile slot and unchanged raw server
value. Invalid rows have null generation fields; this recovery is not
generation-based. It removes only that unchanged invalid server row and does
not touch the editor's local files. Neither action silently resets every
client.

`make auth-info` remains the first-owner-browser and recovery entry point when
there is no usable owner session. It is not required for routine IDE approval
while Settings is already authenticated.

After IDE access becomes active in a trusted workspace, the extension attempts
to open and enroll its integrated dashboard with a fresh fragment-only invitation.
Explicit ephemeral browser storage is refused with guidance, never overridden.
Later **Open Dashboard**
actions reuse that acknowledged integrated-browser member. Its server
membership survives editor, control-stack, and machine restarts and remains
authorized until exact revoke. A browser can lose its renewable cookie, but
that never authorizes a silent replacement. To authorize one
other local browser profile, run **CodeSecurity: Add Browser to Lomo
CodeSecurity**. Copying the displayed 10-minute code into an unpaired profile
is recommended; the optional system-browser action is rejected when that
profile is already paired. The fragment is removed before application requests
and the invitation is consumed once. Multiple IDE profiles and browser members
can coexist in one local installation; Settings lists their separate identities
and revokes one without disrupting the others.

The ordinary dashboard opens **Projects** when the installation has no scan
history, and **Findings** when results are available. An explicit view or exact
finding link keeps its destination; an unavailable initial read shows an error
instead of treating the installation as empty. Reloading retains the current
view and scan in the URL.

Projects' **Scan setup** checklist reports three live prerequisites in order:
core services, source access, and scanner data. Each incomplete step has one
primary recovery action. Ready checks collapse into a short summary that you
can expand with the mouse or keyboard; a lost prerequisite reopens the guidance.
The normal Scan form is hidden until all three checks are ready, so first-time
users do not discover missing infrastructure only after submitting expensive
work. These checks mean scanning can start. Reviewing the first results and
deliberately enabling repository push protection are separate steps.

The core stack is sufficient for scanning. Monitoring, the local Git proxy, and
the database UI are optional and off by default. The one-shot `schema-init`
container is also not a service that should stay running: an exit status of 0
means database initialization completed successfully.

## 2. Authorize and register source

Adding source has three distinct effects. **Add Folder to Workspace…** in the
CodeSecurity Findings view delegates directly to VS Code's native workspace
action. Its picker adds the selected directories while preserving existing roots;
VS Code owns duplicate handling, remote directory selection, Workspace Trust
and any workspace reload. CodeSecurity does not register a project, authorize
scanner access or start a scan. The action is available in the empty Findings
view, its title menu and VS Code's existing File menu and Command Palette.
Save the resulting workspace if you want to reopen the same set of folders.

On **Projects**, expand **Register Project** to add another scan target. It is
already open for first setup; returning users see existing projects and scan
controls first. Closing this section preserves an unfinished form. **Add Project**
registers an exact directory that the scanner can already access.
**Authorize another source root** in that section prepares a separate,
explicit host action to grant access. **Scan Workspace Folders…** still previews
the selected roots and requires scan confirmation. Adding folders from an
empty-workspace scan prompt stops after the native action; choose the scan
command again when ready. Removing a folder with the editor's workspace action
does not delete its registered project, source authorization or retained findings.

CodeSecurity can register only directories beneath its explicitly configured
read-only source roots (at most 32). The default root is the product checkout. On **Projects**, choose
**Authorize another source root**, enter one exact repository or narrow
development tree, and choose **Copy host command**. Run the copied command from
the Lomo CodeSecurity checkout. It invokes the reviewed owner-only host helper,
then reapplies the CodeSecurity services while preserving the database and
scanner-cache volumes.

The host step is deliberate: changing a Compose bind mount is privileged, while
the control plane has neither the Docker socket nor access to `runtime.env`.
The copied path is URL-safe encoded rather than interpolated into shell syntax;
the helper decodes it, resolves an existing directory, rejects controls,
symlinks at the runtime boundary, broad roots, wrong ownership/permissions, and
concurrent runtime-file changes. Paths containing `$`, quotes, `#`, backslashes,
or edge whitespace are refused because Compose could otherwise reinterpret the
persisted value. The helper serializes authorization changes and atomically
updates only the source fields. Adding a separate repository preserves the first:

```text
KODESEC_REPO_ROOT=/Users/me/dev/team
KODESEC_ALLOWED_ROOTS=/Users/me/dev/team,/Users/me/work/other-repository
```

Do not authorize `/`, `/Users`, `/home`, `/Volumes`, or another broad parent.
Never authorize a common parent merely to reach two independent roots. In the
web application, open **Projects**, expand **Register Project**, enter the exact
absolute directory to scan, then choose **Add Project**. Each selected repository
or nested folder is registered as its own project inside one explicit authorization
boundary. Extra mounts are scanner-only, read-only, and refuse creation of a
missing host path. Startup revalidates persisted roots and refuses a root that
has become a symlink to another location. Compose uses one private runtime
snapshot for both its environment and the generated mounts.

An out-of-root selection is rejected before a project or scan is created. The
web UI opens the same setup panel with the rejected exact path prefilled. VS
Code's **Open Source Setup** action opens that Projects route with the reported
exact POSIX path as a bounded suggestion, including when its integrated browser
first pairs. The path travels only in the URL fragment and never grants access;
review it before copying the host command. Missing or invalid suggestions leave
the source field empty. Change the
runtime boundary deliberately; do not work around the rejection with a broader
mount or a copied directory. For an interactive privileged fallback, run
`make authorize-source`, enter the exact narrow root, and then run `make up`.
**Add another root** preserves existing mounts. **Remove source authorization**
requires choosing the exact root and running the corresponding host command;
the final remaining root cannot be removed. Removal does not delete projects,
scans, database data, or validated scanner cache. Requested authorization is
not reported as mounted until the host applies it and the API observes it.

### Scan multiple workspace folders

For repositories under one opened parent, first choose **CodeSecurity: Choose
repositories in this workspace…**. Bounded discovery lists immediate children;
explicit browsing can select a deeper repository. Review the exact canonical
paths. Selection remains local workspace metadata and grants no source access.
The original parent stays open; each selected child has its own project identity.
Reconnect, refresh, diagnostics, source navigation and protection use those
children and revalidate their filesystem identities before use.

When selected mounted roots are not authorized, the editor can copy one reviewed
batch host command. It binds the installation ID and encodes the complete path
list as data. Run it from the backend source checkout only after reviewing the
paths. The host validates the entire batch, preserves existing roots, and
atomically writes the source configuration before applying it once. Invalid,
overlapping, broad or replaced roots fail without a partial authorization.
The editor and API do not acquire Docker control. Native Windows snapshot
sources follow their separate authorization flow.

Open `examples/security-demo.code-workspace` for two source-only fixtures. The
TerraGoat subset is for scanning only; never run Terraform or its deployment
commands. In VS Code choose **Scan Workspace Folders…**, select individual roots
or **All workspace folders**, review every exact path and authorization result,
then confirm. Cancelling the preview creates no projects or jobs.

Each admitted root owns a distinct project, scan, durable job, and idempotency
identity. The result lists every selected root; it never creates a combined
passing gate. If observation of admitted work is interrupted, its exact job
remains **unconfirmed** with a Jobs action and later roots are not submitted.
Cancellation affects only this batch's current work. Nested roots are not
merged, and Explorer folder/file actions retain their exact clicked scope.
**Refresh Findings** reconciles registered open roots without registering new
ones and preserves root-specific selection and diagnostics. A selected child
with no project or scan keeps its association with the open parent while its
empty findings are cleared, so later scan completion can populate its native
Findings and Problems. Removing the selection or closing the parent still
removes that child context.

## 3. Prepare scanners

Before the first complete scan, open **Tools**. The **Prepare Scanners** panel is
the single readiness workflow. Choose **Prepare all scanners** once; the control
plane atomically records both durable stages, so refreshing or leaving the page
does not lose the preparation intent:

1. **Check available scanner data** compares the running immutable scanner
   image and reviewed locks with the curated catalog.
2. **Download and verify required data** queues the exact required database or
   rules components through the source-blind updater.
3. **Scan with complete coverage** becomes available only when every enabled
   scanner has verified binary, data, rules, and offline-execution readiness.

Preparation never reads a registered source tree. Catalog checks and cache
updates are durable jobs; leaving the page or refreshing the browser does not
start a duplicate operation. Open **Jobs** to see the current stage, component,
elapsed time, last activity, and byte counts when the updater can report them.
A healthy heartbeat with no byte total means the updater is still working, not
that it is 35% complete. A warning after 45 seconds without activity is a prompt
to inspect worker health; it does not by itself mark the durable job failed.

If preparation fails with an uncertain cache outcome, open that job and choose
**Check cache outcome**. This starts a separate read-only check, with up to
15 minutes including queue time. The original preparation stays failed; the
linked check reports whether its published cache is valid. It does not download
or replace data. You can cancel before the check records its final outcome.
Use **View outcome check** to follow it and **Preparation** to return to the
original failure. Scanner readiness must still be verified before a complete scan.

Mutable scanner databases and downloaded checks have an exact seven-day hard
validity window. Trivy's publisher `NextUpdate` timestamp is treated and verified
as a refresh-due hint, but it does not disable an otherwise hard-valid offline
database. Once hard validity or the activation safety margin is exhausted, the
catalog refuses the stale locked candidate before downloading it. Successful
activation keeps the active and previous-good generations for rollback and
prunes only validated unreferenced generations under the cache lock. Reviewed
immutable rule trees remain valid until their lock identity changes rather than
receiving an artificial clock expiry.

If the panel says **Enable a scanner**, enable at least one tool first. If it
lists blocked tools, use the primary preparation action and follow the named
reason. A component marked `requires_lock_refresh` cannot be repaired by
downloading the same expired immutable object again; it requires a reviewed
lock and scanner-candidate update.

## 4. Choose coverage and scan

Open **Projects**, select the registered source, and start a scan.

- **Complete coverage** is the default. The server rejects it before creating a
  scan or job if any enabled scanner is not ready.
- **Limited coverage** is an explicit fallback shown only when at least one
  enabled scanner is ready. Confirming it runs only the ready scanners and
  records the omitted scanners, blocking reasons, and reviewed preflight
  revision. The resulting scan remains `partial`; its deterministic gate is
  permanently incomplete even if every preserved finding is later ignored or
  otherwise changes lifecycle.

A failing security gate on a completed scan means complete scanner execution
found policy-blocking evidence. **Scanner evidence is incomplete** means the
required scanner execution contract was not met. These states are intentionally
different. Partial, failed, and cancelled scans keep any safely persisted
findings and publishable artifacts for review.

## 5. Review findings and use Advisor

Open **Findings** and check the project, source root, coverage target and selected
scan at the top. Status, gate and incomplete-evidence guidance stay above the
review controls. The finding list and selected detail follow those controls;
supporting scan metadata is below the review workspace.

Code evidence starts in a compact viewport near the offending range. Use
**More code** to expand it, **Compact code** to return, or the keyboard-accessible
**Max height** slider for a preferred height. Short snippets use their natural
height. **Copy evidence** copies all captured sanitized text, including context
outside the visible viewport. A bounded-context notice means the scanner did
not capture the complete file; expanding the viewport cannot recover missing text.

Identical same-scan evidence is canonicalized by the server. Historical repeat
badges track the same project, scanner and fingerprint. **Other reports at this
location in this view** is a separate aid: it links independent reports with the
same exact source range on the loaded page. They may describe different issues;
each retains its rule, severity, lifecycle and gate effect. The comparison does
not cover unloaded pages or other repositories. VS Code's inline **+N reports**
label likewise keeps individual Problems, hover actions and Quick Fixes available.

- Use **Search findings** or the severity shortcuts. Expand **Filters and scanner
  counts** for severity, scanner and lifecycle choices; active filter values stay
  visible in its summary. **Clear filters** restores the full selected scan.
- Check findings, verify the visible selected count, then expand **Review actions**
  for bulk lifecycle, Advisor or deletion commands. **Clear selection** removes
  the checked set. Selecting rows alone sends no mutation or Advisor request.
- In the selected detail, use **Lifecycle**, **Run Advisor** or **Delete** for an
  explicit action. For source navigation, use **Refresh IDEs** if needed, choose
  a connected client in **IDE target** (unselected prompt: **Select IDE**), then
  choose **Open source in VS Code**. Refreshing or selecting a target does not
  pair a new member or authorize another source root.
- Expand **Scan scope and derived artifacts** below the list/detail for exact
  scope, refs, duration and retained artifacts. Each artifact has separate
  **Open** and **Download** links; raw scanner output is not offered.

**Manage push protection** opens the selected repository's exact Settings record
when its source identity is verified, including native Windows and immutable
Git sources. An ambiguous or unavailable identity never shows another clone's
protection. Opening Settings
changes no policy, hook or membership. Saving a requested repository policy does
not install its hook or prove protection is applied; use the observed status and
VS Code's explicit **Protect Pushes…** setup. A passing scan gate alone does not
verify installed protection. See [push protection](GIT_PUSH_PROTECTION.md).

To choose a policy for one repository, open **Projects**, select the project,
and use **Repository scan gate** beneath its scan controls. Set the critical/high
limits and secret handling, then choose **Save project gate**. This recalculates
that project's existing scan gates; it does not change other projects, global
defaults, scanner evidence or Git hooks. **Reset draft** discards local edits.
**Reload policy** retains your draft while checking the current saved values.
If another client changed the policy, reload and review before saving again.

Settings groups controls into **Protection**, **Workspace access**, **Advisor**,
**Trusted access** and **Installation**. Section links move within the page and
preserve unsaved input. Existing direct links still open the exact repository,
IDE access or provider section. **Reload Settings** keeps unsaved edits in
each edited section and loads current values into untouched sections. Refresh
does not save your draft. A successful scoped save updates that section while
preserving drafts in other sections. Saving gate defaults, authorizing source,
enrolling a client and applying host services remain separate, explicit actions.

If a save cannot be confirmed, your draft stays visible. The backend may already
have saved it, so the app does not retry automatically. Restore the connection,
use **Reload Settings**, and review the current values before saving again.
An invalid or incomplete success response also leaves the current page and draft
intact instead of claiming that the change was saved.
An invalid Settings read also preserves your draft and disables saving until a
valid **Reload Settings** succeeds. A reload cannot silently replace the known
installation with another one.

An open manual Advisor provider Add/Edit form also survives **Reload Settings**,
including a failed read. Saving waits until current Settings can be verified.
If another client changed the provider collection, the draft stays visible but
cannot overwrite that newer revision. Copy any edits you need, cancel the form,
and reopen the provider to review the saved settings. Reload never adds,
activates or sends finding content to a provider.

In VS Code's **Source Control Repositories** view, use the repository menu's
**Protect Pushes…** or **Check Outgoing Commits…** action. These use that exact
selected repository. The same commands in the Command Palette ask you to choose
a repository first; existing Git and GitLens commands remain available.

Select a finding to load its exact scan-local detail. Finding list and detail
reads carry both the finding revision and the scan's findings revision. If a
lifecycle or Advisor operation advances the finding between those reads, the UI
performs one bounded authoritative refresh while retaining the user's
selection. If it changes again or was removed, the UI asks for a refresh instead
of showing evidence from a different revision.

Lifecycle changes and deletion are revision-fenced. The displayed policy gate
changes only after the server confirms the mutation and the UI reloads the
authoritative scan projection. Bulk lifecycle updates retain the checked findings
while they remain visible in the current scan and filters.

Advisor is optional and explicit. Local Ollama is preferred and needs no remote
source disclosure. An active, tested, authorized Direct or SSH provider can be
selected for one finding only. Before any remote finding content is queued,
the Web UI shows the server-built bounded disclosure with the exact provider,
destination, transport, pinned model digest, finding revision, included
categories, byte count, and confirmation hash. The operator must confirm that
exact preview; connection tests and activation send no finding content, and
automatic, scan-wide, or bulk remote routing remains unavailable.

Review generated advice against the captured evidence before applying it.
The default local model is `qwen3:8b`; this is not an accuracy guarantee. Our
smaller `qwen3:0.6b` QA configuration produced generic code advice and, in one
permissions finding, suggested the reported mode again. Model confidence
is not a calibrated security score. Advisor never changes source automatically
or overrides scanner evidence and push-protection decisions.

Every Advisor action snapshots the selected finding revision, checks it again
before model work, and rechecks it before persisting the result. Concurrent
lifecycle changes discard stale Advisor output. Advisor unavailability or
cancellation never removes scanner evidence and never determines the
deterministic gate. Cancelling an SSH job tears down the product forward; the
product never creates a reverse tunnel to the workstation.

In VS Code, use the CodeSecurity Findings tree or Problems diagnostics to open
the exact source location. Choose **Open Finding in Web** from the tree row,
source hover or Quick Fix to open that exact scan-local finding in the paired
dashboard. **Reveal Finding in Editor** remains separate. Inline annotations
use the same identity. **Rescan Exact Finding File** scans only the selected
finding's supported file through its exact canonical workspace-relative target;
it does not scan the containing workspace or change the registered source
boundary. Unsaved editor contents are not included.

## 6. Understand jobs and recover safely

Jobs groups its overall counts by status and kind in a compact summary. Search
and filters narrow the task list without changing those overall counts. Each
task exposes its own progress, result link and currently valid recovery actions.

On first load, **Jobs** shows **Loading job history**, with unavailable counts
shown as dashes. **No jobs yet** and zero counts appear only after a successful
empty dashboard read. If the initial dashboard read fails, Jobs shows
**History unavailable** and asks you to refresh; it does not treat the failure
as an empty installation. Once history has loaded, a later failed refresh
keeps the already shown rows and counts while reporting the read error. Use
**Refresh** to reconcile them with persisted state.

Jobs report persisted state, not a decorative timer. Scanner lifecycle jobs
expose their real updater stage, current component and position, last activity,
and bounded byte progress when the source provides a total. Active updater work
uses an indeterminate indicator because component sizes and verification time
are not all measurable; it never presents a synthetic completion percentage or
ETA.

- A browser disconnect does not lose a job. Reopen **Jobs** and refresh the
  exact resource.
- If **Work processing unavailable** appears, queued work remains durable. Run
  `make up`, wait for worker health, and refresh.
- Cancellation first persists the request, then waits for process cleanup and
  the terminal updater/scanner receipt. Do not assume closing a progress dialog
  cancelled server work.
- Retry only a terminal job that exposes **Retry**. Do not submit the same work
  again while its original job remains queued, running, or cancelling.
- A stale last-activity time is a diagnostic signal. Inspect the safe job
  detail and `make logs`; do not disable a scanner, delete cache state, or
  recreate the database to make progress appear green.

## Optional components and schema status

The **Settings > Installation > Components** panel separates desired state from observed
runtime state. Saving preferences does not start containers because the API has
no Docker socket. Copy and run the displayed host command, then refresh the
panel. A disabled optional component is neutral and does not make core scanning
unhealthy. An enabled but unreachable component is shown as not running or
unavailable with a safe recovery message rather than a raw DNS exception. If a
desired-off service is still reachable, the panel reports `running undesired`
until the host reconciliation command stops it.

Use these host commands only when the corresponding optional surface is
actually wanted:

```bash
make apply-components COMPONENTS=core
make apply-components COMPONENTS=monitoring
make apply-components COMPONENTS=git-proxy
make apply-components COMPONENTS=db-admin
make apply-components COMPONENTS=all
```

The command accepts exactly eight fixed profile combinations (see `make help`),
stops every deselected optional service without deleting its volumes, and then
starts core plus the selected profiles once.

`schema-init` is successful when it exits 0. It is expected to remain stopped
after that one-shot run; it must not be started repeatedly from a container GUI.
The Components panel may call it completed only when the persisted schema ID
`lomo-kodesec-0.1.0-initial`, exact DDL fingerprint, and initialization
timestamp match the API's startup verification.

## CLI and future CI equivalents

The GUI and automation share the same server-owned contracts:

| Human action | Authenticated API / automation boundary |
| --- | --- |
| Open Prepare Scanners | `GET /v1/scanner/preflight` |
| Check curated data | `POST /v1/scanner/tools/check-latest` |
| Prepare selected reviewed data | `POST /v1/scanner/cache/update` |
| Check an uncertain published cache outcome | browser-only `POST /v1/jobs/{job_id}/reconcile` with current revision |
| Register an authorized directory | `POST /v1/projects` |
| Start a complete or acknowledged limited scan | `POST /v1/scans` |
| Observe durable work | exact job resources plus authenticated events |
| Load exact finding detail | revision-fenced scan-local finding route |
| Run Advisor | revision-fenced single-finding Advisor route |

An editor or CI client must use a scoped capability in an Authorization header
and a unique idempotency key for commands. It must preflight before scanning,
retain the exact scan/job identities, reconcile authoritative resources after
events, and treat limited coverage as non-passing. It must never put a
bootstrap value, IDE authority, capability, source body, finding body, or private path
in a URL, log, test receipt, or source archive.

For a command-line smoke against the checked-in vulnerable fixture, use
`make demo-scan` only with the documented owner-only CLI capability file. It
requires complete eight-tool evidence and a publishable Syft SBOM; it is not a
replacement for the browser, editor, restart, or cross-platform acceptance
matrix.

Developer and CI-focused gates remain:

```bash
make test
make lint
cd tests/playwright && npm test
cd extensions/vscode && npm run test:ui:local
```

Run the browser and editor gates with isolated state and profiles. First-release
acceptance must still bind one immutable commit, sanitized source
archive, scanner image, cache generation, and VSIX across macOS, Ubuntu,
Fedora, native Windows boundary, and Remote WSL results.
