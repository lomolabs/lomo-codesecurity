# Lomo CodeSecurity

Find security issues in your code, dependencies and infrastructure with local
scanners, a browser dashboard and a VS Code extension. Review findings, open
their source locations, and check outgoing Git history before pushing. An
optional Advisor can help explain a finding; ordinary scans do not invoke AI.

**0.1 source preview.** The backend is built locally from source. Mac ARM64 and
Ubuntu AMD64 have completed scoped functional acceptance. Fedora, native Windows
and Remote WSL have incomplete qualification, and native Windows has a known
automatic-startup failure. Read the [release status](docs/RELEASE_STATUS.md)
before installing.

Project repository: [lomolabs/lomo-codesecurity](https://github.com/lomolabs/lomo-codesecurity).
Use the complete source from this repository or a reviewed source archive.
Marketplace publication and its installation/update journey remain pending.

## Start the backend

Use the complete reviewed source supplied for this preview. Keep it in its own
directory, separate from the projects you want to scan. Follow the
[platform setup guide](docs/PLATFORM_SETUP.md) for prerequisites, then run from
the source root on macOS or Linux:

```sh
python3 scripts/start-lomo.py --check --json
python3 scripts/start-lomo.py
```

Normal startup builds and starts the backend. It does not install an extension
or open an editor. Repeat the same command to preserve installation data and
pairing and reuse matching builds. The dashboard uses
`http://127.0.0.1:8080` by default. To choose another loopback port, follow the
[custom-port instructions](docs/SOURCE_STARTUP.md#use-a-different-local-port).

The backend requires Python 3.12+, Git, Make, and a local Linux Docker engine
with Compose and Buildx. The launcher checks prerequisites; it does not install
them or change your Docker configuration. A first source build requires network
access and sufficient free host and Docker storage. See the setup guide for
the exact checks and storage admission floors.

For Windows, follow [Windows source startup](docs/WINDOWS_SOURCE_STARTUP.md).
The backend runs in WSL2. Native Windows VS Code and Remote WSL are separate
workflows; install the extension in the host you actually intend to use.

## Add the editor extension

Install the reviewed VSIX supplied with the same source preview, or build it:

```sh
make vscode-package
```

Building the extension requires the [documented Node.js/npm prerequisites](docs/PLATFORM_SETUP.md#build-the-preview-extension).
The package is written to `.kodesec-test/vscode/code-security-0.1.0.vsix`.
In your existing VS Code profile, choose **Extensions: Install from VSIX…**,
select the package, open your project and run **CodeSecurity: Get Started**.
The extension ID is `lomo-dev.code-security`. Installing it does not start the
backend or replace your other extensions.

Review Workspace Trust normally. The first eligible profile uses the
installation's first-owner connection flow. Additional profiles require owner
approval in **Settings > IDE access**, using the displayed verification code
and profile name. No access secret needs to be copied into the editor.

For browser-only use, follow the [browser connection instructions](docs/SOURCE_STARTUP.md#explicit-editor-and-browser-choices).

## Reach your first finding

1. **Authorize source.** Choose the exact repository you want to scan and
   review its narrow source authorization. Opening a folder or selecting a
   repository does not grant source access. Selecting a child never grants its
   parent or siblings.
2. **Prepare scanners.** Open **Tools > Prepare all scanners**. The updater
   downloads and verifies the required databases and rules without access to
   your source. Complete scans wait for every enabled scanner to be ready.
3. **Scan and review.** Scan the selected repository, folder or supported file.
   Review Findings, Problems and **Open Finding in Web**, including coverage and
   gate status. Each repository has an independent result. A scan can correctly
   fail its gate when it finds a problem.
4. **Choose protection deliberately.** Review gate thresholds, then use
   **Protect Pushes…** to approve and apply protection to that clone. Run
   **Check Outgoing Commits…** to check the committed history you intend to push.
   A failed workspace scan alone does not install a Git hook.

See the [workflow guide](docs/GUI_FIRST_WORKFLOW.md) and
[Git push protection](docs/GIT_PUSH_PROTECTION.md). Incomplete, cancelled,
failed or stale evidence cannot authorize a protected push. Local commits stay
available. A local hook can be bypassed with `--no-verify` or another clone;
use remote branch controls when enforcement must be unavoidable.

## Keep scanner data current

Scanner binaries and data definitions are reviewed source inputs. When bundled
definitions expire, obtain refreshed reviewed source, rerun normal startup to
rebuild changed inputs, and prepare scanners again. Repeatedly downloading an
expired definition does not renew it. A complete passing result is never
inferred from limited coverage. Read [scanner preparation and freshness](docs/SCANNER_TOOLS.md).

Preserve the installation's owner-private runtime state and Docker named
volumes when updating. See [startup and recovery](docs/SOURCE_STARTUP.md) and
[data persistence](docs/PERSISTENCE.md). Backup/restore helpers are not a
validated disaster-recovery facility.

## Privacy and security

The default service address is loopback-only. Sources are narrowly authorized
read-only mounts or bounded snapshots. Runtime scanners operate offline against
validated data. Redacted findings and bounded snippets persist locally; raw
scanner output is temporary. Redaction cannot recognize every possible secret.

Advisor is optional. Local Ollama is the default provider route. Remote
providers require explicit authorization and a single-finding disclosure
preview before content is sent. Advice never changes the deterministic gate.

CodeSecurity is not a sandbox for hostile repositories and does not guarantee
that a passing scan means the code is secure. Read the [security policy and
trust boundaries](SECURITY.md).

## Help and contributions

For a startup or runtime problem, run `make support-bundle` in the backend
checkout. It collects bounded local diagnostics without uploading anything or
restarting services. [Review the bundle before sharing it](docs/MONITORING.md#local-bug-report-bundle).
For a vulnerability, use the [private reporting guidance](SECURITY.md#reporting-a-vulnerability).

Contributions start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[development guide](docs/DEVELOPMENT.md). The [architecture overview](docs/ARCHITECTURE.md)
explains the services and their boundaries.

## License

Project-authored source is licensed under
[Apache-2.0](LICENSE). Third-party engines, dependencies, rules and fixtures
retain their own terms and notices. See the [scanner license index](services/scanner/licenses/README.md)
and the Web build's generated `THIRD_PARTY_LICENSES.md`. These notices do not
establish rights clearance for every future distribution or a trademark license.
