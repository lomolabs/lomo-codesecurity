# 0.1 source-preview status

This preview builds its backend locally from reviewed source and uses a reviewed
or locally built VSIX. Installing the extension does not install the backend.
Source lives in [lomolabs/lomo-codesecurity](https://github.com/lomolabs/lomo-codesecurity).
Marketplace publication and its installation/update journey are pending.

## Platform coverage

| Platform | Accepted scope | Remaining limits |
| --- | --- | --- |
| Mac ARM64 | Scoped functional acceptance includes findings, source navigation, Git protection, recovery and representative companion extensions. | A macOS reboot was excluded. Later focused changes do not imply every accepted case was rerun. |
| Ubuntu AMD64 | Scoped functional acceptance includes clean and critical-finding scans, real Git pushes, recovery and state preservation. | Some Advisor suggestions are insufficiently specific and require careful review. |
| Fedora AMD64 | Basic preparation, eight-scanner scans, multiple repositories, startup/enrollment, reboot/reconnect and accepted permitted/rejected pushes. | Full maintenance, recovery, current Advisor and remaining controls are deferred. An editor-state preservation assertion remains unresolved. |
| Windows native | WSL backend, scanner preparation, manual Refresh, multiple repository findings, complete outgoing-history checks and ordinary permitted/rejected pushes. | Automatic startup can time out during private-storage verification. Source navigation, other protection variants and the full journey are incompletely qualified. |
| Remote WSL | Some backend dependencies have been observed. | The actual Linux extension-host journey, navigation, protection and reconnect remain unqualified. Native Windows checks do not qualify Remote WSL. |

These are scoped observations, not a fully qualified five-platform release.
The tested source and package identities remain attached to their original
results. A source audit, matching package checksum or health check does not
qualify a new platform or establish that every installation works.

## Known issues

- **Windows automatic startup:** private-storage verification can time out.
  This is a failed verification, not proof that permissions are unsafe. Do not
  loosen ACLs, copy credentials or bypass checks. Manual Refresh has worked in
  a retained profile, but is not a reliable automatic-startup fix.
- **Conservative scan reuse:** changes to previous-cache rollback status can
  alter the readiness revision even when active data and binaries are unchanged.
  A previously clean protected push can therefore be refused. Once scanner
  status settles, explicitly run **Check Outgoing Commits…** again. Do not
  treat missing current evidence as a pass.
- **Mixed-workspace summary:** a repository name can repeat in a Mac Refresh
  summary. Review each repository's independent outcome and Problems counts.
- **Advisor quality:** suggestions can be incomplete or incorrect. Review
  them before applying changes; advice never determines the gate.
- **Data expiry:** bundled scanner definitions expire. Obtain refreshed
  reviewed source, rebuild changed inputs and prepare again. Downloading the
  same expired definition does not renew it.
- **Local protection:** Git hooks can be bypassed with `--no-verify` or another
  clone. Use remote branch controls when enforcement must be unavoidable.
- **Recovery:** preserve runtime state and named volumes. Backup/restore
  helpers are not a validated disaster-recovery facility.

Full Fedora, native Windows and Remote WSL qualification remains deferred,
including lifecycle/removal, protection variants, failure recovery, data
maintenance, Advisor and companion-extension behavior. Existing passes do not
erase failed or untested cases.

## Setup and support

Start with [platform setup](PLATFORM_SETUP.md) and the [workflow guide](GUI_FIRST_WORKFLOW.md).
Run `make support-bundle` in the backend checkout for local diagnostics; it
does not upload anything or restart services. [Inspect the bundle before
sharing](MONITORING.md#local-bug-report-bundle). Include the platform, source and
extension versions, action, expected result and actual status. Use the
[security policy](../SECURITY.md#reporting-a-vulnerability) for vulnerabilities.

Use the repository's actual security-reporting and download options; this page
does not promise a distribution channel, publisher verification or legal clearance.
