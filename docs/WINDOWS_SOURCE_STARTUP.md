# Windows source startup

The Windows entry point builds the backend in one explicitly selected WSL2
distribution and preserves the existing VS Code profile. Choose native Windows
or Remote WSL explicitly; neither mode substitutes for the other. Native
repositories live on local Windows drives. The backend checkout and Remote WSL
repositories live on the selected distro's ext4 filesystem.

Current-source acquisition and the normal selected-distro prerequisite check
have passed on the retained Windows QA installation, including all thirteen
checks and temporary-probe removal. A subsequent normal current AMD64 backend
upgrade also passes with retained installation data and pairing preserved.
These component results do not establish editor qualification. Native and Remote WSL first/repeat startup,
remote host placement, scans, pairing persistence and foreground UI acceptance
still require their own maintained Windows acceptance lanes.

## Choose the backend and editor explicitly

The [platform installation guide](PLATFORM_SETUP.md#windows-native-and-remote-wsl)
covers Windows packages, selecting a WSL2 distro and checking dependencies.

Install the ordinary source-build prerequisites inside the chosen WSL2 distro:
Python **3.12 or newer**, Git and Make,
and a working local Docker Linux engine with both
`docker compose` and `docker buildx`. Run the shared
[dependency checks](PLATFORM_SETUP.md#requirements-shared-by-the-five-workflows)
in that distro as the backend account; a Windows Docker client version alone
does not verify its Linux engine, plugins or default builder.
Clone (with Git) or unpack the complete selected source into that
distro's ext4 filesystem, not under `/mnt/c` or inside another Git checkout.
Unpacked sources use the shared explicit build-input digest described in
[source identity checks](SOURCE_STARTUP.md#repeat-starts-and-identity-checks),
not an invented commit. All source hashing and builds run inside WSL; no native
Python or alternative Windows hashing implementation is needed. Normal startup
needs no host Node/npm. Install official Microsoft VS Code and Git for Windows
on Windows; a working Git inside WSL does not replace native Git for Windows.
Remote WSL also needs Microsoft's WSL extension in the Windows editor.
Install VS Code on Windows; its WSL extension installs the remote server in the
selected distro. Do not install a second Linux desktop VS Code to substitute
for that host. See [Microsoft's WSL installation flow](https://code.visualstudio.com/docs/remote/wsl#_installation).

From Windows PowerShell, substitute your exact distribution and checkout:

```powershell
wsl.exe -d Ubuntu-26.04 --cd /home/me/lomo-kodesec --exec python3 scripts/start-lomo-windows.py --distro Ubuntu-26.04 --checkout /home/me/lomo-kodesec --editor native --check --json
```

Remove `--check --json` to build/start the backend. Leave this PowerShell
terminal open while using Lomo: after successful startup the command keeps its
WSL session alive, including when VS Code is closed. Press **Ctrl+C** to release
that session. Containers and data are retained, but WSL may shut down the distro
when its last session closes; rerun the same command to resume. No scheduled
task, service, idle-timeout setting or automatic boot enrollment is installed.
Microsoft documents that [systemd services alone do not keep WSL alive](https://learn.microsoft.com/en-us/windows/wsl/systemd).
The `--check --json` command returns normally and does not hold a session. The check
does not create runtime/profile state or an editor, but the shared backend
preflight creates/removes its isolated source-free storage diagnostic. It never
pulls that diagnostic's pinned base in check mode; on a pristine engine it may
ask you to use normal startup to prepare that existing build dependency.
Expect schema version 1 with `status: "passed"` and passed prerequisite checks.
A failed check exits nonzero and leaves later checks untested. Source/state and
Docker build-layer storage each need 32 GiB free for a new build or 2 GiB for a
matching-image restart; scanner cache capacity is checked separately. Correct
the named prerequisite in this same distro and rerun the same command. A
passed backend check still does not prove editor installation or pairing.

Keep the terminal open during cold startup. WSL's local Docker engine gets one
468-second readiness window while Docker/containerd finish starting; individual
queries remain bounded at 30 seconds. The launcher waits without restarting or
reconfiguring those services. If the window expires, check them in this exact
distro and collect a private `make support-bundle`; then correct the reported
prerequisite. The JSON check remains a single report with later checks untested
when readiness fails. Keep the normal backend terminal open after success too,
as described below, so WSL does not idle-exit between editor operations.

The JSON report explicitly leaves editor installation unverified. In your
existing native VS Code profile, open the local-drive workspace, install
`lomo-dev.code-security` and run **CodeSecurity: Connect / Review IDE Access**.
Marketplace publication is pending. For this preview, follow
[Build the preview extension](PLATFORM_SETUP.md#build-the-preview-extension)
inside the selected distro, then use **Extensions: Install from VSIX…** in your
existing native profile. A supplied reviewed VSIX can use the same install
action without Node/npm. Review Workspace Trust normally.
Native mode forwards only the genuine, unconsumed installation first-owner
handoff through the existing account-private publisher. It does not recreate
authority on repeat starts; additional profiles use ordinary owner approval.

## Remote WSL: finish installation in the selected remote window

For Remote WSL, select that mode when starting the backend:

```powershell
wsl.exe -d Ubuntu-26.04 --cd /home/me/lomo-kodesec --exec python3 scripts/start-lomo-windows.py --distro Ubuntu-26.04 --checkout /home/me/lomo-kodesec --editor remote-wsl --check --json
```

Remove `--check --json` to build/start. Use **WSL: Connect to WSL using Distro…**
in your existing VS Code profile, select this distro and open your ext4 workspace.
Install Lomo under **WSL: <distro>**, not only under **Local**. Confirm the
terminal's `id -u` and `echo "$HOME"` match the backend account before connecting.
The backend-only launcher does not launch a remote URI or assert its account
placement. This mode requires the actual WSL account's default
`~/.local/state/lomo-kodesec`. Custom state, HOME and XDG selection are refused
before mutation. It leaves first-owner authority in its original POSIX state;
it does not publish that authority to the native Windows consumer.

## Use a different local port

Follow [the custom-port procedure](SOURCE_STARTUP.md#use-a-different-local-port)
inside the exact selected WSL distro as the backend account. Edit its private
`runtime.env`, not a Windows copy. Keep the same ext4 state directory; Remote
WSL still requires the account's default `~/.local/state/lomo-kodesec` and does
not permit a custom state/HOME override. A custom port does not qualify either
experimental Windows editor workflow.

For custom-port use, run the documented `start-lomo.py --browser-only` commands
inside that distro and leave its terminal/session open while using Lomo. Open
your existing Windows editor manually. Set `lomoCodeSecurity.apiBaseUrl` to the
exact new `http://127.0.0.1:PORT` in **User** settings for native Windows, or in
the selected WSL window's **Remote** settings for Remote WSL, then run
**CodeSecurity: Connect / Review IDE Access**. Check that the chosen port is
available in both WSL and Windows; PowerShell's
`Get-NetTCPConnection -LocalPort 18080 -State Listen` can identify a Windows
listener without stopping it.

For a fresh native Windows installation, this direct WSL route does not publish
a native first-owner handoff. Run `make auth-info STATE_DIR="$lomo_state"` inside
WSL, open its printed fragment-only URL in your own local browser to establish
the browser owner, then approve the native IDE through **Settings > IDE access**.
Keep that URL private. For an existing installation, use its existing owner
browser to approve the connection at the new origin.

Automatic `--source-vsix` setup remains restricted to port 8080. A native
first-owner handoff already published on Windows is bound to its recorded
origin; the normal native Windows wrapper may therefore refuse a changed
origin. Use the backend-only/manual connection route above and ordinary owner
approval. Do not delete or rewrite the native handoff journal, copy credentials
or recreate first-owner authority to bypass that refusal.

## Explicit source-VSIX development and QA

Follow the shared [Node/npm installation and checks](PLATFORM_SETUP.md#build-the-preview-extension)
inside the selected WSL distro before requesting this mode.

To build/install the source extension in a dedicated account-private profile,
add `--source-vsix`, an exact signed `--code 'C:\…\Code.exe'` path and an
existing `--workspace` path. Native workspaces use local Windows paths;
Remote WSL workspaces use canonical ext4 paths such as `/home/me/my-project`.
This opt-in mode requires npm and stable Node.js **20.18.1+ on 20.x, or 22+**
inside WSL. It verifies the signed native Code executable and its engine
version before backend mutation. Node.js 21 and prereleases are unsupported.
The selected editor origin must be port 8080.

In source-VSIX Remote WSL mode, before starting the backend the Windows boundary runs one bounded read-only
UID/home probe through `wsl.exe --distribution <selected-distro>` without a user
override. Both values must match the launcher's current account. Starting with
`-u` or `su` as a different account is refused because the remote URI would open
the distro default instead. No distro default or user configuration is changed.

The launcher stages and rehashes the exact source-built Lomo VSIX in private
Windows package storage; **it never installs Lomo locally in this mode**. A local
Lomo installation in this exact profile is refused during preflight, before the
backend starts. This prevents an empty local profile window from activating
Lomo and claiming an earlier first-owner enrollment than the intended WSL host.
Existing native profiles need their ordinary owner-approved remote setup rather
than silently converting into a pristine remote installation.

The launcher creates the missing empty profile through the existing named-profile
helper and installs the reviewed Microsoft WSL transport
`ms-vscode-remote.remote-wsl@0.104.3`. Its official manifest requires
VS Code `^1.104.0`, below Lomo's own minimum. The existing compatibility lock
records its reviewed asset identity; installation uses VS Code's ordinary
version-qualified Marketplace installer and signature policy, not an independent
transport-byte verification. No unpinned version fallback is used.
See the [official manifest](https://ms-vscode-remote.gallery.vsassets.io/_apis/public/gallery/publisher/ms-vscode-remote/extension/remote-wsl/0.104.3/assetbyname/Microsoft.VisualStudio.Code.Manifest)
and [version-qualified CLI installation](https://code.visualstudio.com/docs/configure/command-line).

The exact folder opens through the official `vscode-remote://wsl+<distro>/...`
URI. **In the “WSL: <distro>” window, choose “Extensions: Install from VSIX…”,
then “Show Local”, select the exact staged Windows package path printed by the
launcher, and choose “Install”.** The remote picker starts in the WSL filesystem;
“Show Local” lets it select the Windows-local package. Follow ordinary
workspace-trust/enrollment prompts. Verify Lomo appears installed in the WSL
host, not the Local group. VS Code owns its server and workspace-extension
placement; this launcher does not create an alternate server or infer remote
profile placement from the local CLI. See the official
[Remote WSL folder flow](https://code.visualstudio.com/docs/remote/wsl) and
[remote VSIX installation guidance](https://code.visualstudio.com/docs/remote/faq).

The resulting receipt deliberately says `remote_installation: pending`.
Staged package bytes, the selected transport version and a window launch do
not prove remote installation, pairing or scans. Repeats preserve that distinction
and never upgrade the receipt to a remote success claim. A pre-existing WSL
server with custom environment/state is not adopted or repaired; remote pairing
must be observed against the intended default-state installation. The
qualification-only server/HOME setup is not a production installation mechanism.

## What source-VSIX setup preserves

In native mode, the existing WSL owner publisher forwards only the genuine, unconsumed
first-owner authority to the canonical native account destination. It never
creates replacement authority on repeats. An unavailable first-owner handoff
does not bypass enrollment: an extra profile uses normal owner approval.

The native editor state lives below `%LOCALAPPDATA%\lomo-kodesec\native-editor`:
`user-data`, `extensions`, a public-package staging directory and an installation
binding marker. The marker binds the installation ID, WSL distro/state directory
and profile name (default **Lomo CodeSecurity**). A nonempty unbound directory,
different binding or unsafe existing permissions is refused, not adopted or
repaired. Changing a runtime/profile does not replace another installation's
state. The WSL `windows-source-launch.json` is private, non-secret provenance;
it is not authority and cannot prove installed bytes on its own.

Storage must be owned by the current Windows account. Its effective ACL may
grant only that account, SYSTEM and built-in Administrators; no other ordinary
trustees or reparse paths are admitted. Only newly created launcher-owned
directories/files receive a new private ACL. No existing ACL, registry entry,
default browser, editor trust policy or global setting is changed.

Native repeat startup checks the exact installed extension ID and location, then reads
the installed production files and compares them with the source-built VSIX.
A mismatching payload is installed again in this same profile, without resetting
settings or credentials. An already-running extension host still needs its
normal reload after an upgrade; successful disk installation is not a live-host
reload claim.

The first missing profile is created through one ordinary VS Code window launch
and observed profile-specific CLI readiness before installation. Windows reads
the selected installation’s bounded, ordinary `bin\code.cmd` as data to
resolve its exact bundled `resources\app\out\cli.js`, including the
official version-directory layout. It then runs the signed `Code.exe` directly
with the same child-process environment as that wrapper; arguments never pass
through a command shell. The fixed four-file public native helper import closure
is hash-bound to the selected source checkout, copied into a disposable
account-private local directory, and
removed after each child operation. This avoids Electron Node's refusal to load
WSL UNC modules without opening a broad UNC host allowlist. Other exact public
installer/package files are read through the selected distro's WSL mapping.
Native workspaces remain local-drive paths;
Remote WSL folders use their exact remote URI. No broad UNC allowlist or
workspace-trust bypass is added.

After startup, follow the extension's normal workspace-trust/enrollment prompts,
prepare scanners through its offered action, and scan the selected workspace.
Source mount authorization is separate from opening a workspace. Native snapshot
admission and Remote WSL mounted-source admission retain their respective
explicit source boundaries.
