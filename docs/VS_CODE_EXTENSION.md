# VS Code extension

Lomo CodeSecurity brings local scan results into VS Code through the
`lomo-dev.code-security` extension. It connects to the authenticated loopback
API; installing the extension does not install or start the backend.
Marketplace publication is pending. Read [release status](RELEASE_STATUS.md)
for scoped platform coverage, the native Windows automatic-startup defect and
the deferred Fedora/Windows/Remote WSL qualification.

## Install and get started

Follow [platform setup](PLATFORM_SETUP.md), start the backend from its source
checkout, then install the reviewed or locally built VSIX with
**Extensions: Install from VSIX…** in your existing profile. For Remote WSL,
install it in the selected WSL extension host. Browser-only VS Code, virtual
repositories and unsupported remote hosts are not supported source contexts.

Run **CodeSecurity: Get Started**. Its six steps cover backend startup,
connection and trust, repository selection, scanner preparation, findings and
push protection. **Detailed instructions** opens the packaged notes for a step.
Checkmarks reflect observed progress; opening the guide grants no source access,
starts no scan and installs no protection.

Review Workspace Trust normally. A pristine installation's first eligible
profile can use the first-owner connection flow. Later profiles show **Approval
needed**: use **Connect / Review IDE Access** and compare the profile name,
endpoint and verification code in **Settings > IDE access** before approving.
No access secret needs to be copied into the editor.

IDE enrollment remains available in Restricted Mode. Source operations and the
integrated dashboard require Workspace Trust; the dashboard also requires
persistent browser storage. CodeSecurity does not change either setting for you.

## Choose repositories and scan

Use **Choose repositories in this workspace…** when one opened parent contains
several repositories. Keep the parent open and select the individual children
you intend to manage. Review the narrow source authorization offered for those
repositories before applying it. Selection, source authorization and scanning
are separate actions; selecting a child never authorizes its parent or siblings.

Each selected repository retains its own project, scan and gate. Removing a
selection does not delete its project, revoke scanner access or remove push
protection. When adding a folder creates an untitled workspace, retained
selections are revalidated. If the original window cannot be identified, choose
**Restore selections** or select repositories again; neither grants new access.

Open **Tools > Prepare all scanners** in the dashboard before a complete scan.
Missing, expired or invalid data blocks complete coverage. Expired bundled
definitions require refreshed reviewed source and preparation, as described in
[scanner maintenance](SCANNER_TOOLS.md).

| Action | Scope |
| --- | --- |
| **Scan Workspace with Lomo CodeSecurity** | Scan the exact selected workspace repository; choose a root when necessary. |
| **Scan Workspace Folders…** | Review a folder picker and confirm a batch. Each selected root keeps its own job and result. Cancelling before submission starts no scans. |
| **Scan Folder with Lomo CodeSecurity** | Explorer action for one exact authorized descendant folder. |
| **Scan File with Lomo CodeSecurity** | Explorer action for one supported file inside an authorized open source root. |

Scans use disk content; unsaved editor changes are not included. Ordinary
extension scans request complete coverage and do not invoke AI. Progress shows
the job's status and supported cancellation. After an interrupted submission,
inspect **Jobs** before submitting again.

File and folder results are labelled **file only** or **folder only**. They
replace that repository's current editor projection and do not establish
coverage of the whole repository. Earlier scans remain available in the
dashboard's scan history. A partial, failed or cancelled scan may retain useful
findings, but cannot have a passing complete gate.

## Review findings

**CodeSecurity Findings** groups repository and file results. Select a finding
to reveal its source location. **Problems** provides standard diagnostics and
navigation; visible editor lines can also show compact or detailed annotations.
Changing annotation settings does not disable Problems.

**Open Finding in Web** opens the exact finding in the paired dashboard. It is
available from the finding row's browser button or context menu, source hover
and Quick Fix. **Reveal Finding in Editor** is a separate source-navigation
action. Opening a finding does not start Advisor or a new scan.

Finding context actions and Quick Fixes offer Web review, lifecycle changes,
Advisor, an exact-file rescan and deletion where permitted. Quick Fix is an
action menu, not an automatic code repair. Suppressive or risk-accepting
lifecycle changes require a reason; deletion requires confirmation. When several
findings share a location, select the intended finding. Stale selections are
rejected rather than applied to a different result.

**Refresh Findings** reloads current results for the selected roots without
starting scans or registering new projects. It preserves independent outcomes
when one root fails. Problems and rich editor details have capacity bounds; an
explicitly limited projection is not a complete Problems list. Use the Findings
tree and exact Web scan to inspect the remaining results.

After changing source, save and rescan before relying on its findings. Old
annotations become stale or are removed; a reload or reopening the workspace
does not make earlier disk evidence describe the new content.

## Advisor and push protection

**Run Advisor** explicitly requests optional advice for a finding. Local Ollama
is optional; remote review must start from the exact finding in the Web UI with
a fresh disclosure preview and confirmation. Advice can be incorrect and never
changes the deterministic gate or finding lifecycle automatically.

**Protect Pushes…** requests repository-specific approval and provides explicit
On/Off, Apply and host-status actions. Saving a preference alone does not prove
the local hook is installed. **Check Outgoing Commits…** previews and scans
outgoing committed history without performing a push. Both are available from
the Command Palette and a repository's Source Control menu.

Applied protection requires current complete passing evidence. Local commits
remain available. A local hook can be bypassed with `--no-verify` or another
clone; use remote branch controls where enforcement must be unavoidable. See
[Git push protection](GIT_PUSH_PROTECTION.md).

## Connection, settings and recovery

| Setting | Default | Effect |
| --- | --- | --- |
| `lomoCodeSecurity.apiBaseUrl` | `http://127.0.0.1:8080` | Exact loopback service origin. Changing it requires connecting this profile again; the old authority is not sent to the new origin. |
| `lomoCodeSecurity.inlineAnnotations` | `compact` | Choose `off`, `compact` or `detailed` for visible-editor annotations. |

Keep the backend installation data, endpoint and editor profile to preserve
approved membership. **Reconnect to Local Service** retries that profile's
connection. If access was revoked or is no longer active, use **Connect / Review
IDE Access**. Reconnect does not grant source access or replace an approval.

**Open Dashboard** opens the integrated dashboard and offers its explicit
pair-again recovery when needed. **Add Browser to Lomo CodeSecurity** creates a
single-use, ten-minute invitation for another local browser. Browser membership
and IDE access are separate and independently revocable in Settings.

Native Windows source uses bounded snapshots of supported local-drive paths.
POSIX and Remote WSL use authorized read-only mounts. A native
`\\wsl.localhost` workspace must use **Reopen Workspace in Remote WSL** with
Microsoft's WSL extension installed. These implementation paths do not imply
full platform acceptance; consult [release status](RELEASE_STATUS.md).

If a source, credential or snapshot check fails, follow the reported recovery
action. Do not broaden source roots, loosen permissions or copy profile
credentials as a shortcut. Native Windows automatic startup can time out during
private-storage verification; a successful manual Refresh is not a reliable
startup fix. See [the workflow guide](GUI_FIRST_WORKFLOW.md),
[source startup](SOURCE_STARTUP.md) and [security policy](../SECURITY.md).

## Build and check the extension

Follow the [Node.js/npm prerequisites](PLATFORM_SETUP.md#build-the-preview-extension).
From `extensions/vscode/`:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
npm run test:unit
npm run test:activation
npm run test:package
```

`test:package` runs `package` followed by `test:package:reproducible`. The
packager checks the permitted VSIX contents and creates a canonical archive;
the reproducibility checks compare package bytes across changed input times
and time zones. From the repository root, `make vscode-package` builds the
VSIX at `.kodesec-test/vscode/code-security-0.1.0.vsix` without installing it or
opening an editor.

These checks exercise source, activation and package behavior. They do not
constitute a fresh native editor journey, platform qualification or Marketplace
installation/update acceptance. See [development](DEVELOPMENT.md) for the public
baseline and contribution workflow.
