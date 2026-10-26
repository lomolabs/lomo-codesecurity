# Install the local backend and editor extension

Lomo 0.1 builds its backend from reviewed source. Use your existing VS Code
profile; a separate profile is optional. The extension ID is
`lomo-dev.code-security`. Marketplace registration and publication are pending;
the preview uses **Extensions: Install from VSIX…** with a supplied or locally
built package. Public acquisition is not yet qualified.

These are installation recipes reviewed against upstream documentation on
2026-09-29. Final clean-install acceptance on all five platforms remains open.
The recorded versions below are observations, not minimum support guarantees.
Installing prerequisites is an explicit host-administration action: Lomo's
launcher checks them and does not install or reconfigure them for you.

## Requirements shared by the five workflows

| Component | Where it runs | Check |
| --- | --- | --- |
| Python 3.12+ | Backend host, or selected WSL distro | `python3 --version` |
| Git and Make | Backend host/distro; native Windows also needs Git for Windows | `git --version`; `make --version` |
| Local Linux Docker engine | Backend host/distro | `docker version` must show client and server |
| Compose and Buildx plugins | Same Docker installation | `docker compose version`; `docker buildx version` |
| Official desktop VS Code 1.135+ | Mac/Linux or Windows desktop | **Help → About**, or `code --version` |
| Microsoft WSL extension | Windows VS Code, for Remote WSL | Installed extension `ms-vscode-remote.remote-wsl` |

Python and VS Code versions above are the launcher's interpreter floor and the
extension's declared engine floor. They are not receipts that every version at
or above those floors has passed release acceptance. For Git, Make, Docker,
Compose and Buildx, the launcher checks the required command/engine behavior;
it does not declare a tested minimum version. Use the recorded environments
below to distinguish observed versions from still-pending platform acceptance.

The launcher admits a local Unix Docker socket and the reserved `default`
Buildx builder with one running `docker`-driver node on that same engine. A
remote context or custom builder is not silently replaced. Check the selected
configuration with `docker context show` and `docker buildx inspect default`.
Use an owner-approved local engine if the preflight refuses your environment.

Run these checks as the account that will start the backend, inside the selected
WSL distro for either Windows workflow:

```sh
python3 --version
git --version
make --version
docker version
docker compose version
docker buildx version
docker info --format '{{.OSType}} {{.Architecture}}'
docker buildx inspect default
```

Expect Python 3.12+, version output from Git/Make and both Docker plugins,
and Docker **Client** and **Server** sections without a connection or permission
error. The engine line must say `linux` with `arm64`/`aarch64` or
`amd64`/`x86_64`. For a source build, the default builder must report
`Driver: docker`, one node named `default`, `Endpoint: default` and
`Status: running`. A printed client version alone does not establish a working
backend. These commands inspect the existing installation; Lomo's preflight
then checks the exact selected socket and builder together. Do not run the
launcher with `sudo` to work around a refused account or engine.

Backend startup and installing a supplied VSIX need no host Node/npm or Go
compiler. Building the preview extension locally needs Node/npm. The backend image
builds its modified Bearer scanner in a pinned native Go container stage. Its
first build needs network access for reviewed source and verified dependencies;
the semantic tests and compilation run without network access. Building the
extension with `--source-vsix` requires npm and stable Node.js 20.18.1+ on 20.x or 22+; Node 21
and prereleases are excluded by the locked dependencies. Ollama and a local
model are optional for Advisor. They are not needed for deterministic scans.

Allow **32 GiB free on both source/state storage and Docker build-layer
storage** for a fresh build, or **2 GiB** for a matching-image restart. These
are admission floors, not measured peak requirements or storage reservations.
Scanner preparation checks cache space separately. Measured CPU, memory, disk
and multi-repository limits are still awaiting final candidate qualification.
The release workload is fifteen independent children under one opened parent;
that target is not a claim of completed platform qualification.

## Build the preview extension

Until a reviewed VSIX download or Marketplace installation is available, build
the extension from the same reviewed source used for the backend. From its root:

```sh
make vscode-package
```

The output is `.kodesec-test/vscode/code-security-0.1.0.vsix`. This command
installs locked build dependencies and packages the extension; it does not install
it in VS Code, open another profile or fetch qualification fixtures. In your
existing profile, use **Extensions: Install from VSIX…**, choose that file, and
run **CodeSecurity: Get Started**. For Windows workflows, build inside the
selected WSL distro; the native Windows file picker can reach the output through
`\\wsl.localhost\<distro>\<checkout-path>`. For Remote WSL, choose **Install
in WSL** for the selected distro and confirm the extension runs in that host.

Install Node/npm only when building the extension yourself, including explicit
`--source-vsix` development/QA setup. Backend startup and installing a supplied
VSIX need neither on the host.

Choose an LTS Node.js release **22 or newer** from the
[official downloads](https://nodejs.org/en/download). The existing build contract
also accepts stable **20.18.1+ on 20.x**; Node 21 and prereleases are excluded.

| Build location | Installation guidance |
| --- | --- |
| Mac ARM64 | Select macOS and ARM64 on the official download page, or follow npm's [macOS/Linux version-manager guidance](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/#macos-or-linux-node-version-managers). |
| Ubuntu or Fedora | Use the official download page's Linux selection or npm's [Linux installation guidance](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/#linux-or-other-operating-systems-node-installers). |
| Windows launcher, native editor or Remote WSL | Install inside the exact selected WSL distro using the Linux guidance above. Both source-VSIX launcher modes build there; Windows Node/npm does not satisfy this check. |
| Direct extension development on Windows | If intentionally running the extension's npm build on Windows, use npm's [Windows installation guidance](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/#macos-or-windows-node-installers). This is separate from the WSL launcher workflow. |

In the same terminal/account that will run the source build, check:

```sh
node --version
npm --version
```

Expect Node to print a stable `v22...` or newer version, or `v20...` at least
20.18.1, and npm to print its version without an error. npm is installed with
Node by the documented installers/version managers. If either command is
missing or selects another installation, reopen the terminal or select the
intended installed version in that shell, then repeat both checks. Continue with
[extension build commands](VS_CODE_EXTENSION.md#build-and-test) or the explicit
[source startup](SOURCE_STARTUP.md) / [Windows setup](WINDOWS_SOURCE_STARTUP.md#explicit-source-vsix-development-and-qa)
flow. These dependency checks do not qualify an editor or platform.

## Mac ARM64

Use native Apple Silicon tools and official ARM64 VS Code. `uname -m` should
print `arm64`. If Git/Make are missing, Apple's Command Line Tools installer is
available through `xcode-select --install`; finish its interactive installation.
If using Homebrew, follow its [official installation instructions](https://docs.brew.sh/Installation),
then install a supported Python and Git:

```sh
brew install python@3.13 git
python3.13 --version
git --version
make --version
```

Use `python3.13` in place of `python3` below if the latter still selects an older
interpreter. Do not replace the system Python. Install official VS Code for
Apple Silicon from [Microsoft's download page](https://code.visualstudio.com/download).
In its Command Palette, **Shell Command: Install 'code' command in PATH** enables
the optional CLI; the graphical workflow does not require it.

The observed Mac engine is OrbStack. Install and start it through the
[vendor's instructions](https://docs.orbstack.dev/install); it includes Docker,
Compose and Buildx. Check the shared prerequisites above before starting Lomo.
Existing Docker installations and workloads require owner review before changing
engines. Lomo does not migrate them. Docker Desktop or other engines are not
claimed qualified by the OrbStack observation.

## Ubuntu

The current platform lane uses Ubuntu 26.04 AMD64. For a fresh host:

```sh
sudo apt update
sudo apt install git make python3 ca-certificates curl
python3 --version
```

Python must report 3.12 or newer. Set up Docker's signed apt repository using
the current [official Ubuntu recipe](https://docs.docker.com/engine/install/ubuntu/).
Review any existing conflicting engine packages before replacing them. After
that repository is configured:

```sh
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl start docker
```

Install the official AMD64 `.deb` from Microsoft's download page with
`sudo apt install ./<downloaded-code-package>.deb`, substituting the actual
downloaded filename. The [VS Code Linux guide](https://code.visualstudio.com/docs/setup/linux)
describes its repository and updates. Keep AppArmor enabled; a denial needs
diagnosis, not a global disablement.

## Fedora

The current platform lane uses Fedora 44 AMD64. Install the basic tools, then
use Docker's signed repository. Review the vendor's key fingerprint when asked:

```sh
sudo dnf install git make python3 dnf-plugins-core
sudo dnf config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl start docker
```

These package names and the DNF5 repository command follow the
[official Fedora recipe](https://docs.docker.com/engine/install/fedora/).
Install Microsoft's official AMD64 `.rpm` using
`sudo dnf install ./<downloaded-code-package>.rpm`, substituting its filename.
Follow [Microsoft's Linux setup guide](https://code.visualstudio.com/docs/setup/linux)
for the signing key and update repository. `getenforce` must remain `Enforcing`.
Do not disable SELinux or recursively relabel broad host directories to make a
failed source mount work.

## Linux Docker account access

Run Lomo as your ordinary account, not through `sudo`. That account must already
be able to use the selected engine. If `docker version` fails with socket
permission denied, follow [Docker's account setup guidance](https://docs.docker.com/engine/install/linux-postinstall/).
For the system engine, an administrator may explicitly choose:

```sh
sudo usermod -aG docker "$USER"
```

Log out and back in, then check `docker version` again. Docker group membership
grants powerful host access; this is an administrator's choice, not a launcher
repair. Do not use world-writable socket permissions. Rootless engines require
their own reviewed setup and successful Lomo admission; they are not implied
qualified by these system-engine commands. Enabling Docker at boot is optional
host policy; an administrator can use `sudo systemctl enable docker` if desired.

## Windows native and Remote WSL

Install official Windows VS Code and Git for Windows. In PowerShell, the
[Git project's WinGet command](https://git-scm.com/install/windows) is:

```powershell
winget install --id Git.Git -e --source winget
git --version
```

Install VS Code from [Microsoft](https://code.visualstudio.com/download) and
reopen PowerShell after installers update PATH. `git --version` must report
Git for Windows; a Git executable available only inside WSL is insufficient
for native repositories.

Inspect your existing WSL installation first:

```powershell
wsl.exe --status
wsl.exe --list --verbose
wsl.exe --list --online
```

For a new installation, use Microsoft's [WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).
An administrator can run `wsl.exe --install -d <distribution-name>` with a name
from the online list, complete any requested Windows reboot and create the
distro's ordinary Linux user. The selected distro must show version **2** in
`wsl.exe --list --verbose`. Do not reinstall or convert an existing distro
without reviewing its data and workloads.

Inside the selected Ubuntu distro, use the Ubuntu dependencies above. Keep the
backend source and runtime on its ext4 filesystem, for example
`/home/me/lomo-kodesec`, not `/mnt/c`. Check Docker as the same Linux account
that will start Lomo. A Windows Docker CLI or an unrelated distro's engine does
not establish readiness for this distro.

Choose one editor workflow explicitly:

| Workflow | Open repositories here | Install Lomo here |
| --- | --- | --- |
| Windows native | Local Windows drive, such as `C:\work\workspace` | Existing Windows VS Code profile, **Local** extension host |
| Remote WSL | Selected distro's ext4, such as `/home/me/workspace` | **WSL: your-distro** extension host in that remote window |

Follow [Windows source startup](WINDOWS_SOURCE_STARTUP.md) for the exact
`--distro`, `--checkout` and `--editor native` or `--editor remote-wsl` invocation.
No Windows Python is required. For Remote WSL, install Microsoft's WSL extension
in Windows, run **WSL: Connect to WSL using Distro…**, and select the same distro.
Confirm `id -u` and `echo "$HOME"` in that window match the backend account;
install Lomo under its **WSL** group. Follow the
[official remote workflow](https://code.visualstudio.com/docs/remote/wsl).
The normal launcher leaves editor installation explicitly unverified until
you complete this step.

## Start and reach the first useful result

Obtain the reviewed source revision or complete release archive supplied with
the candidate. Keep it separate from repositories you plan to scan. From that
clean source directory on Mac, Ubuntu or Fedora:

```sh
python3 scripts/start-lomo.py --check --json
python3 scripts/start-lomo.py
```

The JSON report uses schema version 1. Expect `status: "passed"` and passed
prerequisite checks; a failed check stops admission and later checks remain
untested. The check creates/removes a bounded, source-free temporary Docker
storage probe. It never pulls the probe image; on a pristine engine, normal
startup obtains that pinned build dependency before measuring Docker capacity.
See [the full startup contract](SOURCE_STARTUP.md).

Open your workspace in the chosen VS Code host, install Lomo, and run
**CodeSecurity: Get Started**. The walkthrough follows:

1. Start backend and connect this exact editor profile.
2. Review Workspace Trust and any additional-profile owner approval.
3. Choose individual repositories beneath the opened parent. Review the narrow
   source authorization command before applying it from the backend checkout.
4. Open **Tools → Prepare all scanners**, then submit the selected repositories.
5. Review Findings, Problems and **Open Finding in Web**; navigate exact source.
6. Review gate thresholds and deliberately apply **Protect Pushes…** per clone.

Each selected repository has its own project/job/gate. Removing a selection,
deleting a project, removing scanner authorization and removing push protection
are distinct operations. The parent stays open and is never auto-authorized.
Native Windows snapshots use a separate reviewed source flow; a POSIX mount
command is not offered for a Windows-drive path.

## Recovery and updates

| Observation | Next action |
| --- | --- |
| Missing executable/version | Install the named dependency for the actual host/distro, reopen the terminal if PATH changed, rerun the same check. |
| Daemon unavailable or wrong context | Start the intended local engine and verify its identity; inspect active workloads before any restart. |
| Buildx refused | Review the reserved default builder and local engine. Lomo does not create or switch a global builder. |
| Space admission fails | Review host and Docker storage separately; free owned disposable data or expand capacity deliberately. Lomo never prunes unrelated state. |
| IDE requests approval | Compare its exact code/name/endpoint in the existing owner's Settings. Do not copy credentials or manufacture first-owner state. |
| Source access missing | Revalidate the exact selected child; review host authorization, then retry. Never authorize the parent as a shortcut. |
| Large source refused | Transfer allows 8 MiB/file, 5,000 files and 64 MiB decoded total. Eligible code above 1 MiB remains incomplete even if captured. |
| Scanner data expired | Obtain refreshed reviewed source, rerun startup to rebuild changed inputs, then prepare again. Preserve runtime state and database volumes. |
| Interrupted scan/preparation | Inspect the existing job before retrying; cancellation and incomplete evidence never imply a pass. |

If a failed preparation reports an uncertain cache outcome, its
**Check cache outcome** action starts a separate read-only check with up to
15 minutes, including queue time. It leaves scanner data unchanged and the
original preparation failed. See [preparation recovery](GUI_FIRST_WORKFLOW.md#3-prepare-scanners).

For daily work, see [GUI-first workflow](GUI_FIRST_WORKFLOW.md),
[push protection](GIT_PUSH_PROTECTION.md), and [security boundaries](SECURITY.md).

## Recorded environments and remaining qualification

Acceptance status below was reconciled on October 24. Historical passes retain
their original candidate identities; a later source update still needs its
affected checks. The source package is not a claim that all five lanes are clear.
The current source-preview scope defers full Fedora, Windows native and Remote
WSL qualification. See [release status and known issues](RELEASE_STATUS.md)
before choosing an environment.

| Lane | Recorded environment | Evidence limit |
| --- | --- | --- |
| Mac ARM64 | Recorded host: macOS 26.7; Python 3.13.12; OrbStack Docker 29.4.0; Compose 5.1.2. October 1 focused editor runs use official VS Code 1.140.0. | The fixed evaluator accepts24/24 required categories within the owner-approved no-Mac-OS-reboot scope. Preserve exact candidate/applicability and dependency evidence in the private Mac clearance record; public acquisition remains separate. |
| Ubuntu AMD64 | Ubuntu 26.04, AppArmor enabled; October 11 backend checks: Python 3.14.4, Git 2.53.0, Make 4.4.1, Docker 29.7.2, Compose 5.5.0, Buildx 0.36.1 | The October 24 final functional receipt accepts all 24 required categories, including the current source, scanner data, helper, clean and critical-finding scans, real pushes and retained-state preservation. Useful secret-focused Advisor output passes; the recorded code-remediation quality limitation remains. Public acquisition and the all-platform release are separate. |
| Fedora AMD64 | Fedora 44, SELinux enforcing; October 21 source prerequisite check confirms Python 3.14.7, Git 2.55.0, Make 4.4.1, Docker 29.7.2, Compose 5.5.0, Buildx 0.36.1 | Preparation, the measured fifteen-repository batch, combined-extension actions, scoped protection/recovery controls, support bundles and actual reboot/reconnect have accepted evidence. Cold backend-only startup and genuine first-owner enrollment now pass with existing state preserved. A current-helper clean protected push and a rejected earlier-critical/secret-history push also have accepted effect evidence. The latter whole retains a later editor-state preservation gap; cold acquisition/interruption, invalid-data recovery/offline scanning, current Advisor and remaining controls/final receipt remain open. |
| Windows native | Windows 11 Pro 25H2; current native qualification editor VS Code 1.140.0. October 19 selected WSL backend checks: Python 3.14.4, Git 2.53.0, Make 4.4.1, Docker 29.8.1, Compose 5.5.1, Buildx 0.37.1 | Backend-only startup, eight-scanner preparation, manual Refresh with ten Findings roots/580 findings, and a connected trusted test folder have evidence. Automatic private-storage verification still times out in observed runs; this does not establish unsafe permissions. A native drive-letter case check also exposes a Git-root validation hazard. New native scan/push acceptance, five remaining repository registrations and full lifecycle/recovery/coexistence remain open. Retain the normal backend terminal so WSL stays running; see release status before relying on this experimental lane. |
| Remote WSL | Same selected Ubuntu-26.04 backend dependency inventory as the Windows-native row | Backend dependencies are observed; the actual remote extension host, its dependency placement and full remote journey remain pending. Native qualification cannot substitute for this lane. |

A future fully qualified five-platform release must replace pending cells with
receipts for one coherent candidate, including exact Git, Python, Docker,
Compose, Buildx, VS Code and extension versions. The source preview preserves
these gaps explicitly. A dependency inventory, private VSIX installation or
successful health check alone does not qualify any platform.
