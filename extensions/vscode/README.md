# Lomo CodeSecurity for VS Code

Scan code, dependencies and infrastructure locally. Review findings in Problems,
inline annotations and the CodeSecurity tree, with an optional Advisor.

## Start CodeSecurity

The extension needs the local CodeSecurity application; installing the
extension alone does not install Docker or start scanners.

On macOS or Linux, install a local Linux Docker engine with Compose and Buildx,
official VS Code 1.135+, Python 3.12+, Git and Make. Normal use needs no host
Node.js/npm. Allow at least 32 GiB free on both host and Docker storage for the
initial build. Platform installation commands and checks are in
`docs/PLATFORM_SETUP.md` in the reviewed source.
Use a clean Git checkout (requires Git), or unpack the complete source outside
any existing Git checkout. From that source directory, run:

```sh
python3 scripts/start-lomo.py
```

The launcher builds and starts the backend. Keep your existing VS Code profile,
install `lomo-dev.code-security` there and run **CodeSecurity: Get Started**.
The six-step editor guide covers connection, repositories, scanning, findings and
protection. Its checkmarks record observed past progress; actions recheck current
state. Review Workspace Trust normally. A pristine installation's first eligible
profile can connect through the private installer handoff; later profiles need
owner approval. Repeat the startup command to reuse installation data and pairing.

Marketplace publication is pending. Until publication, install the reviewed
private VSIX through **Extensions: Install from VSIX…**. This does not establish
Marketplace availability or install/update acceptance.

Windows uses a WSL2 backend. Follow `docs/WINDOWS_SOURCE_STARTUP.md` in the
source directory to choose native Windows or Remote WSL. Remote WSL requires installing
Lomo in its selected WSL extension host, not just the Windows Local group. Browser-only VS Code and virtual
repositories are not supported.

Building the extension from source for development? Explicit `--source-vsix`
uses a dedicated profile and requires npm with stable Node.js 20.18.1+ on 20.x,
or 22+ (not 21 or prereleases). With an already built VSIX, use `make vscode-install`, optionally with
`VSCODE_PROFILE="Profile name"`. Open or switch to that profile after installation.
If that exact profile was already open, run **Developer: Reload Window**.

## Connect additional profiles

A later profile shows **Approval needed**. Use **Connect / Review IDE Access**
and approve its matching code and name in dashboard **Settings > IDE access**.
Profiles reconnect across restarts until revoked. **Add Browser to Lomo
CodeSecurity** creates a single-use, ten-minute invitation. Revoke browsers
and editors independently in Settings.

A trusted, connected profile restores findings for its selected repositories
at startup. Browser-membership recovery has its own prompt; native findings in
Problems and the CodeSecurity tree use the profile's IDE access and source
authorization.

## Prepare and scan

1. Trust the workspace after reviewing it. Run **CodeSecurity: Open Dashboard**,
   then **Tools > Prepare all scanners**.
   Required databases and rules are downloaded and verified.
2. Use **Choose repositories in this workspace…** for repositories beneath one
   opened parent. Review and authorize only the selected narrow source roots;
   the parent remains open and is not authorized automatically.
3. Run **Scan Workspace with Lomo CodeSecurity**, or **Scan Workspace Folders…**
   to choose multiple roots. Each root keeps its own job and result.

Right-click a folder or supported file for **Scan Folder with Lomo CodeSecurity**
or **Scan File with Lomo CodeSecurity**. These actions never broaden access.

Missing or expired data blocks complete scanning. Expired bundled
definitions require updated CodeSecurity source. Limited coverage is an explicit
advanced choice, never a complete passing result.

## Review findings

Select a finding to reveal its exact file and range in the editor. Choose
**Open Finding in Web** from its Findings row's browser button or context menu,
source hover, or Quick Fix to open that exact finding in the paired dashboard.
For keyboard access, focus the finding row and open its context menu, or use
Quick Fix at its source range. **Reveal Finding in Editor** remains a separate
action. Lifecycle and Advisor actions are explicit; opening a finding does not
start a scan or Advisor review. **Refresh Findings** updates all roots. Unsaved
edits are not scanned.

Normal scans never invoke AI. Choose a local Ollama model in Settings before
requesting Advisor. Remote providers require separate disclosure approval;
Advisor never changes the scanner-based gate.

## Optional push protection

**Protect Pushes…** requests repository approval. Apply **On** to block normal
pushes without current passing evidence; local commits remain allowed.
**Check Outgoing Commits…** scans committed history without pushing.
Both actions are available from a Git repository's menu in Source Control
Repositories. That menu uses the selected clone; the Command Palette asks you
to choose one. **Open protection settings** opens that clone's exact record.
Apply **Off** after its warning to disable protection. This local hook
can be bypassed with `git push --no-verify` or another clone.

For connection, source-access and recovery help, see `docs/GUI_FIRST_WORKFLOW.md`,
`docs/SOURCE_STARTUP.md` and `docs/SECURITY.md` in your source directory.
