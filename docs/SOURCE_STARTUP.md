# Source-only startup

Build the local backend from a clean Git checkout or
an unpacked source directory. From its root on macOS or native Linux, run:

```sh
python3 scripts/start-lomo.py
```

The optional `--check` preflight does not pull its pinned storage-probe base;
on a pristine engine it may ask you to run normal startup first. For a Windows
editor with a WSL2 backend, follow [Windows source startup](WINDOWS_SOURCE_STARTUP.md).

The launcher checks prerequisites, preserves your installation identity and
reuses unchanged builds. It does not change global Docker or editor settings.
Successful startup means services are running; scanner preparation and complete
scanning are separate steps in the dashboard.

Mac remains the timing reference. New Linux/WSL workflow waits include the
additional 30% allowance for the shared VM host (D-020): backend builds allow
3,600 seconds on Mac,4,680 on native Linux and9,360 in WSL; service health waits
allow180,234 and468 seconds respectively. The owning launcher command allows
210,273 and546 seconds, so it can observe health waiting to its end. Windows's
outer backend command allows10,140 seconds. Timers are finite; this does not
renew a running command, change capacity floors or weaken health checks. Small
version, profile/security and cleanup probes retain their separate bounds.

## Prerequisites and first start

Use the [platform installation guide](PLATFORM_SETUP.md) for dependency commands,
verification, editor placement and recovery on each initial-release platform.

Use Python **3.12 or newer**, Make, and a running local Linux-container
Docker engine with Compose and Buildx. Normal startup builds/starts only the
backend and does not require host Node.js/npm. Keep your existing VS Code
profile and install `lomo-dev.code-security` there. Marketplace publication is
pending; private rehearsals use the reviewed VSIX through **Extensions: Install
from VSIX…**. Do not treat a private rehearsal as Marketplace acquisition.

Development/QA can explicitly request `--source-vsix`. Only this mode needs
npm with stable Node.js **20.18.1 or newer on 20.x, or 22 or newer**. Node.js 21
and prereleases are unsupported by the locked build dependencies. The launcher
checks this before initializing runtime state or opening the selected editor.
Git is required for a Git checkout, not for an independent unpacked source
directory. Extract the complete source outside any existing Git checkout;
an ambiguous parent repository, damaged Git metadata or dirty build inputs
are refused rather than silently reclassified as an archive.
The Docker transport must be a local Unix socket; remote contexts are refused
before any source build. The selected socket is pinned in child environments
without modifying the account's Docker context.
When a build is necessary, the launcher also verifies the reserved `default`
Buildx builder is a single running `docker`-driver node using that same local
engine. The one build explicitly selects `--builder default`; ambient
`BUILDX_BUILDER`/`BUILDKIT_HOST` cannot redirect it. The check runs before
initialization and again before building. No builder is created, bootstrapped,
or selected globally, and no remote builder inventory is probed.
In `--source-vsix` mode, the selected VS Code must meet `extensions/vscode/package.json`'s current
engine requirement. On macOS its application signature must verify; the
launcher does not bypass signature checks or repair the application.
Tool symlinks keep their selected command name when executed (including
OrbStack's multicall `docker` entry point); signature inspection resolves the
VS Code target without changing that launch command.

`--check` inspects prerequisites, clean source identity, existing runtime/source
roots, image identities, the loopback port, and both host and Docker build-layer
filesystem capacity. The minimum is 32 GiB available on each filesystem when
an image build is needed, or 2 GiB for a matching-image restart. After building,
startup rechecks the 2 GiB reserve before starting application services. These
are admission checks, not reservations or measured peak-build guarantees;
other processes can consume space after a measurement. Nothing is pruned.

Use `python3 scripts/start-lomo.py --check --json` for a machine-readable report.
Schema version 1 contains `status`, ordered prerequisite `checks` with typed
IDs/status, detected versions where available, a storage-probe disclosure and
recheck guidance. It stops at the first failed prerequisite and exits nonzero;
later prerequisites are untested. A null version means it could not be parsed,
not that a minimum version has been qualified. Output excludes raw command
diagnostics and runtime credentials. Correct the reported failure and rerun.

On WSL, Docker and containerd may still be starting when the source launcher
begins. Both normal startup and `--check` allow up to 468 seconds for the selected
local engine to respond, using one monotonic readiness clock. Each metadata
query retains its 30-second maximum and uses only the remaining time. This
read-only wait does not restart services, renew preparation deadlines or change
Docker settings. Normal output explains the wait once; `--check --json` keeps
its single typed JSON result. macOS and native Linux retain their single engine
query. A readiness failure points to the selected distro and support bundle.
The Windows check wrapper allows 600 seconds. Additional cold waiting beyond
the original 30-second query reduces the build allowance; normal backend
startup keeps its existing 10,140-second outer ceiling.

Docker's usage/reclaimable-byte report is not a free-capacity measurement.
The launcher instead reuses the scanner Dockerfile's exact pinned Python base
for a temporary `statvfs` probe of the container build-layer filesystem. It
verifies the local image digest, architecture, size bound and absence of
declared volumes, then starts its immutable image ID with no network, mounts,
Docker socket, source or credentials. The probe is read-only, unprivileged,
capability-dropped, resource-limited and has no persistent log. Its exact
run-owned container identity is rechecked before removal, including after a
timeout. A cleanup that cannot be proven stops startup; unrelated containers,
images and volumes are never removed. The probe image is retained as an ordinary
build dependency. No host/global Docker settings change.

`--check` **does create and remove this diagnostic container**, but never pulls
its image, initializes application/runtime state, builds, installs an extension,
opens an editor or prints authentication material. If the pinned base is absent,
it gives an actionable refusal: normal startup prepares that dependency first.
On a pristine engine, normal startup's one pinned base pull necessarily allocates
storage before engine capacity can be measured. That limited bootstrap can fail
on a full Docker disk; the launcher discloses the limitation and never proceeds
to the application build without a successful measurement. The base is already
a source-build input, not a separate mutable helper-image channel. The launcher
verifies the scanner's complete pinned stage list and selects its Python runtime
stage; the preceding Go compiler stage is not used as the storage probe.

The probe measures the actual image-layer backing filesystem, not every possible
separate Docker volume backend or sparse virtual disk's host backing capacity.
The source/state host check remains independent. Scanner preparation still uses
its existing actual cache-volume `statvfs` check before downloads, extraction
and import: carried data, installed data, compressed downloads, the extra Grype
import workspace, and the safety margin must fit. No startup receipt bypasses
that check. The bounded probe has run successfully on the existing Mac engine;
this is storage-boundary evidence, not first-start or low-space platform
acceptance. Those end-to-end checks remain pending.

The first start creates the ordinary owner-only runtime outside the checkout,
builds the scanner and control images once through the maintained source-build
wrapper, and starts the lean stack with health waiting. Normal startup leaves
the editor unchanged. Open your project in your existing profile, install Lomo,
then run **CodeSecurity: Connect / Review IDE Access**.

With the explicit `--source-vsix` development/QA option, it packages the
ordinary extension from clean source, installs it in the persistent **Lomo
CodeSecurity** profile, and opens VS Code on `examples/vulnerable-demo`.
VS Code's installation CLI does not itself create a named profile. If the
profile-specific readiness probe cannot succeed, the installer opens that exact
profile once **on the selected workspace** through the supported window-launch route, then requires a
successful profile-specific extension-list probe before installing. It does
not interpret arbitrary CLI errors as proof of absence or edit VS Code's
internal profile storage. Launch acknowledgement alone is not readiness.
The final open focuses that already-open workspace instead of leaving a second
empty setup window connected under the same IDE capability. The launcher never
uses last-active-window reuse or closes another window automatically. If the
workspace is already open in another profile and the requested profile cannot
be created, setup refuses rather than changing that window's profile. An empty
setup window retained from an earlier failed launch must be closed explicitly;
re-pairing is not necessary. Remote WSL staging keeps its distinct pending flow
and does not install Lomo into a local setup window.

The existing first-owner mechanism enrolls the first eligible IDE profile in a
pristine installation; it does not require a newly created editor profile. Review
and trust the selected workspace to let the extension finish integrated-browser
pairing with persistent storage; it resumes setup after trust is granted.
The launcher never grants trust or extracts or consumes the bootstrap.

If VS Code's `workbench.browser.dataStorage` is set to `ephemeral`, CodeSecurity
refuses integrated-browser pairing without changing the setting. Choose a
persistent browser storage mode, then run **CodeSecurity: Open Dashboard**.
This resumes first-owner setup and reuses an already confirmed browser member
instead of creating a replacement. The installer handoff is removed only after
the server acknowledges that exact browser member.

Already-enrolled profiles keep their authority. Later profiles follow the
normal owner-approval workflow. Use the dashboard to authorize the desired
source, prepare scanner data, and start a scan. Starting healthy services does
not claim that scanner data is prepared, a scan passed, or a platform qualified.

## Use a different local port

The default dashboard and API origin is `http://127.0.0.1:8080`. To use, for
example, `http://127.0.0.1:18080`, change **`CONTROL_PORT` in this installation's
owner-private `runtime.env`**. There is no launcher `--port` option. Compose
derives both the loopback port mapping and the API's `KODESEC_CONTROL_ORIGINS`
from `CONTROL_PORT`; do not add a separate origin field or edit Compose.
Keep the address `127.0.0.1`, with HTTP and an explicit port.

Run the following from the backend source root as its ordinary owner. Select
the same state directory used by this installation. The default is:

```sh
lomo_state="${XDG_STATE_HOME:-$HOME/.local/state}/lomo-kodesec"
```

If you originally used `--state-dir`, set `lomo_state` to that exact absolute
path instead. Do not choose a new state directory to change the port.

**Before the first start of a fresh installation**, initialize its private
configuration without starting containers or an editor:

```sh
make init STATE_DIR="$lomo_state"
```

**For an existing installation**, finish any pending first-owner setup at its
current origin before changing the port. Existing push-protection hooks also
retain their exact API origin. For each protected clone, use its owning profile's
**CodeSecurity: Protect Pushes… → Remove push protection from this clone…**
and confirm complete removal while the old origin is still available. Follow
the [clone-removal contract](GIT_PUSH_PROTECTION.md#removing-protection-and-recovering-an-interrupted-removal)
and preserve any reported ownership or cleanup failure for review. Stop its
stack using its existing runtime, before editing it:

```sh
make down STATE_DIR="$lomo_state"
```

This stops this Compose installation and preserves its named volumes. Do not
add `--volumes`, delete state, rerun initialization with a different directory,
or change the installation/project identities or generated secrets.

Open `$lomo_state/runtime.env` in a trusted local text editor and change only
the existing port line, choosing an unused unprivileged port such as:

```dotenv
CONTROL_PORT=18080
```

Keep the file owner-private, mode `0600`, in its mode-`0700` state directory.
Do not print, upload or copy the full file; it contains installation secrets.

**Only for the fresh installation initialized above, before any editor or
browser has paired**, update the generated first-owner handoff to the chosen
origin using the maintained publisher:

```sh
python3 scripts/publish-first-owner-bootstrap.py "$lomo_state" "$lomo_state/runtime.env"
```

This binds the same unconsumed bootstrap to the new origin. `make init` on an
existing runtime does not refresh that handoff. Do not recreate a first-owner
handoff for an already used installation or edit/copy its token files; use
ordinary owner-approved IDE connection instead.

Check and restart the backend with that same state:

```sh
python3 scripts/start-lomo.py --browser-only --state-dir "$lomo_state" --check --json
python3 scripts/start-lomo.py --browser-only --state-dir "$lomo_state"
```

Open `http://127.0.0.1:18080`. In your existing VS Code profile's **User**
settings, set the following; for a Remote WSL extension host use that selected
WSL window's **Remote** settings instead:

```json
"lomoCodeSecurity.apiBaseUrl": "http://127.0.0.1:18080"
```

Run **CodeSecurity: Connect / Review IDE Access** and follow its connection or
owner-approval prompts. Explicitly apply and verify **Protect Pushes…** again
for each selected clone, then run **Check Outgoing Commits…** before relying on
protection at the new origin. Avoid pushes during the removal/reapply gap;
changing the editor setting does not rewrite an existing hook's configuration.
The origin must match exactly, including the port;
existing IDE authority remains bound to its old origin and is not copied to the
new one. Do not store this installation setting in a shared repository's
workspace settings. Automatic `--source-vsix` editor setup supports only port
8080; install/open the extension manually for a custom port. See the
[Windows-specific custom-port notes](WINDOWS_SOURCE_STARTUP.md#use-a-different-local-port)
for the selected-distro and native first-owner boundary.

If the check reports an occupied port, inspect its listener before deciding
what to stop. On macOS or Linux with `lsof`, use
`lsof -nP -iTCP:18080 -sTCP:LISTEN`; on Linux, `ss -ltnp 'sport = :18080'`
is another option. The launcher accepts only this installation's verified
ingress as an existing listener. Choose another unused port or deliberately
stop the exact conflicting service, then repeat the check. Do not kill an
unidentified process or expose the service beyond loopback to avoid a conflict.

## Repeat starts and identity checks

Rerun the same command with the same state and editor options. It preserves the
installation ID, named volumes, browser/IDE memberships, and profile directories.
It does not stop or delete unrelated resources.
The loopback preflight permits a recently stopped service's TCP `TIME_WAIT`
connections through a probe-local `SO_REUSEADDR` option. A live listener still
conflicts unless it is the exact verified ingress for this installation; no
system networking setting changes and no port is reserved after the probe.

Actual control/scanner image IDs must have coherent original Git commit/tree
and role labels, Linux OS, and the Docker engine architecture. The original
commit must resolve to that exact tree in the local checkout. The launcher then
compares immutable Git objects across the existing role-specific image inputs
plus the shared build/Compose controller files. Current included inputs must
still be clean, including untracked files. A documentation-only change outside
those scopes does not rebuild an unchanged image. Missing historical objects,
missing/malformed images or changed included inputs require a build; comparison
failure never means equality. Only needed image roles are built through the
existing wrapper, and a partial build cannot be recorded as a completed start.

Unpacked sources use `source-sha256:<digest>` instead of a fabricated Git
revision. The digest covers a fixed union of authored launcher, build, runtime
and extension inputs, including relative paths, executable bits and file bytes.
Known generated dependencies and outputs are excluded; links, unsafe entries,
oversized inputs and changes during measurement are refused. This is a local
build-input identity, **not** publisher authentication, an archive checksum,
signature or proof of release acceptance. Obtain source through a trusted
distribution channel independently.

Every normal launcher, image wrapper and extension packager shares this same
snapshot identity. Snapshot image and VSIX reuse requires exact digest equality;
there is no inferred historical per-component equivalence. A changed snapshot
requires new builds, whereas clean Git checkouts retain the narrower unchanged-
input reuse described above. Snapshot image labels and private receipts explicitly
record `kind: source-sha256` and `digest`; Git commit/tree fields are not invented.
Packaging rechecks the source before activating its verified VSIX. Build-command
completion also rechecks source identity; that check detects concurrent edits,
but cannot undo effects already performed by the requested command.

Reused images retain their **original** image ID and source labels; nothing is
relabelled as the current HEAD. The startup receipt separates the current
launcher checkout from each image's original commit/tree/ID. Exact image IDs
and labels are rechecked immediately before starting services. These are
conservative input scopes, not an inferred build graph or a claim that different
source necessarily produces different bytes.

The private `source-launch.json` records source and image identities, plus any
previous explicit source-VSIX binding, never credentials. Backend-only startup
does not inspect or replace the editor's extension. In `--source-vsix` mode,
a receipt is not sufficient evidence:
the launcher rechecks the VSIX hash, VS Code's installed version and location,
and the installed production files against that package. A changed/newer
extension in the selected profile is replaced by the exact source-built VSIX;
settings and credentials are not reset. If VS Code does not expose the exact
installed files afterward, startup reports a failure. Close/reload an already
open profile when replacing an extension so its running host loads those files;
the launcher does not claim a live host reload merely from an installation.

Installed-package discovery uses the exact profile's public extension/version
listing, then a bounded inventory of its effective extension store. VS Code
1.136.1's `--locate-extension` ignores named-profile membership, so it is not
used as installation evidence. The shared observer follows the official
explicit directory, `VSCODE_EXTENSIONS`, active portable-data, and product
default-root precedence without reading or modifying profile storage. It rejects
linked, unsafe, oversized or ambiguous packages; the caller independently
compares the selected files with the exact admitted VSIX. Unsupported wrappers
must select the official application CLI or an explicit extensions directory.

The VSIX has its own original commit/tree binding. It is reusable when those
Git objects remain available, the conservative `extensions/vscode` plus Makefile
inputs are unchanged, and its actual bytes still match the recorded hash.
That admitted digest stays fixed through bounded payload decoding, installed
file verification and the final receipt; a concurrent package replacement is
refused rather than given the earlier source identity.
Reusing it preserves that original source rather than assigning a later
documentation/backend commit. Its installed files are always checked again.
Missing evidence requires packaging through the ordinary source build. The
Windows caller uses this same comparison and stores the same separate VSIX
source binding, whether installed natively or staged for Remote WSL.
For unpacked sources this binding is the explicit shared snapshot record and
exact package hash instead. The same installed-byte checks still apply.

A backend-only start preserves the prior extension's own source binding, even
when newer backend code is built. It cannot make an old VSIX appear to belong
to that newer source commit. No receipt changes scanner freshness requirements.

## Explicit editor and browser choices

The default is **backend only**. The `--browser-only` alias preserves this
behavior. Neither command opens an editor or browser. Open your workspace in
your existing VS Code profile and install Lomo there. Workspace Trust, IDE
membership, source authorization and scan submission remain separate choices.

For explicit source-VSIX development/QA, select an existing workspace folder or
`.code-workspace` file with `--workspace`. Opening it does not authorize source
mounts or silently mark it trusted.

Use an explicit CLI path when `code` is not on PATH:

```sh
python3 scripts/start-lomo.py --source-vsix \
  --code '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code'
```

For source-VSIX mode with a custom runtime, an isolated persistent editor user-data directory
is mandatory. Its first binding requires an empty directory; the launcher writes
an owner-only `.lomo-installation-v1.json` marker with the installation, runtime,
and profile identity. Reuse these same paths later. A non-empty unbound directory
or another runtime's marker is refused, so an already-running editor cannot be
silently adopted with the wrong environment. Use the manual installer for
pre-existing test profiles; the launcher does not manufacture provenance for them:

```sh
python3 scripts/start-lomo.py --source-vsix \
  --state-dir /absolute/private/lomo-state \
  --profile 'Lomo CodeSecurity' \
  --user-data-dir /absolute/private/lomo-editor \
  --extensions-dir /absolute/private/lomo-extensions
```

Existing explicit state/editor directories must already be account-owned and
mode 0700. No existing directory's permissions are repaired. Normal installation
uses the default backend state and the developer's existing editor profile.
Automatic editor startup currently supports the default control origin on
port 8080; a custom port requires explicit editor API-origin configuration and
the manual editor path. The launcher does not edit profile/global settings.

```sh
python3 scripts/start-lomo.py --browser-only
```

Browser-only starts the backend without editor prerequisites, installation, or
launch. It prints only the non-secret loopback address; open it in the browser
you choose. For a first browser-only owner or recovery, invoke `make auth-info`
with the **same `STATE_DIR`** explicitly. That separate deliberate action emits
the existing fragment-only bootstrap URL. The launcher never opens a default
browser, writes a token to argv/environment/clipboard, or generates a new grant.

## WSL boundary and remaining acceptance

This POSIX launcher can build/start a WSL backend with `--browser-only`. It
refuses to infer native Windows installation, paths, profile ownership, or
launch from a WSL `code` wrapper. The optional explicit WSL-only
`--publish-windows-owner` invokes the existing private first-owner handoff after
initialization; its typed result is published, retained, or unavailable. It
does not generate replacement authority or install/open native VS Code.
WSL backend build/start deadlines are twice the Linux deadlines; this is bounded
startup allowance, not a substitute for the separate platform acceptance timing.

For the explicit native editor caller, use
[Windows source startup](WINDOWS_SOURCE_STARTUP.md). It builds in a selected
WSL2 distribution. Its explicit `--source-vsix` mode checks signed native VS Code
and its version before building, then binds an account-private native profile
and verifies installed VSIX bytes.
Its implementation and focused tests are not native Windows acceptance.
The Remote WSL choice verifies the distro's default account, stages the exact
VSIX without installing Lomo locally, and opens the selected remote folder.
Installation through **Extensions: Install from VSIX…** in that remote window,
host placement and pairing remain explicitly pending, not inferred from launch.
Mac/Linux live
first/repeat starts, already-running profile replacement, reboot continuity,
Docker-storage probe/low-space behavior, and Windows/WSL end-to-end acceptance must still use
the maintained platform journeys before claiming initial-release support.


### Platform preparation timing

Fresh runtime initialization persists `KODESEC_PREPARATION_PLATFORM` from the
host: `mac`, `linux`, or `windows` for WSL. This is a local installation setting,
not browser authority. New D-020 work receives1,200/3,120/4,680 seconds,
respectively. A retained runtime is never silently rewritten: missing platform
configuration uses the rebuilt source's Mac default of1,200 seconds. Existing
issued preparation identities retain their original version and deadline. After rebuilding the API and updater
from the same reviewed source, an owner may explicitly set the appropriate value
in that installation's private runtime.env and restart its API through the
normal source launcher. Preserve installation identity, credentials and volumes.
Already-issued jobs and retries keep their original deadlines; only new commands
receive the selected budget. Expired results stay failed. Check the recorded
job's issued/deadline timestamps during acceptance. Scanner execution, data
freshness and source completeness are separate contracts.
