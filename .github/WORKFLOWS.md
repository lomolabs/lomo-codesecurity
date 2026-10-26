# Repository checks and maintenance

## Intentional vulnerable fixtures

`tests/scanner-runtime/fixtures/dependencies/positive` contains source-only
positive controls. Django, PyYAML, requests and lodash are deliberately pinned
to vulnerable versions so the scanners must detect them. They are not installed
as application dependencies or deployed as sample services.

The exact-directory entries in [dependabot.yml](dependabot.yml) ignore automatic
upgrades only for those four fixture packages. Version-update PRs for those
entries are disabled; security alerts remain enabled. Actual application and
build dependencies retain their security-update behavior. Do not dismiss real
application advisories or upgrade fixtures merely to make a dashboard green.
Changing a fixture requires reviewing its expected scanner result as well.

This uses dependency-specific ignores, not an `exclude-paths` assumption:
[GitHub documents how security updates use the configuration](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-security-updates).

The workflows use GitHub-hosted Ubuntu 24.04 machines, pinned action commits,
bounded jobs and the repository's maintained commands. They do not publish a
release, push code, install into a user's editor, send messages or use deployment
secrets. Checkout credentials are not persisted. No dependency cache is configured.
The browser job retains only its bounded runner receipt, normalized execution
report, whitelisted render-environment JSON and PNG screenshots of synthetic
test fixtures for seven days. These
artifacts are visible with the repository. Raw execution reports, traces,
HTML reports, dependency trees and runtime state are excluded.

## Test workflow

`workflows/tests.yml` runs on pushes to `main`, pull requests targeting `main`,
and manual dispatch. Each job has a 45-minute ceiling.

| Job | What it runs |
| --- | --- |
| Public test baseline | `make test-public`: API/scanner unit suites, Web build, extension unit tests and Playwright contract checks. Explicit PostgreSQL/Docker integration opt-ins remain off. |
| Headless Web journeys | Locked Playwright dependencies, the reviewed digest-pinned browser image, then the ordinary `npm --prefix tests/playwright test` runner. |
| Canonical extension package | Locked extension dependencies and `test:package`, including package boundaries and reproducibility. The resulting VSIX remains on the ephemeral runner. |

Python is selected as 3.12 and host Node.js as 24. The Linux browser phase runs
inside the maintained pinned Playwright image, including that image's runtime
and Chromium. It does not install a host browser or bypass the ordinary runner.

The ordinary Web suite needs four available CPUs. GitHub currently assigns
four CPUs to public Ubuntu 24.04 runners and two to private standard runners.
The workflow explicitly fails if the minimum is absent; it does not replace
the suite with a targeted run or loosen its budgets. Such a failure means no
browser coverage was obtained. See [GitHub's runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Hosted Linux CI uses the explicit D-020 functional VM profile: a fresh
1,560-second controller clock and 2.6× operation waits. It keeps the four-CPU
floor, full ordinary suite, assertions and exact platform screenshots. Raw
performance measurements remain advisory for this VM lane; Mac remains the
performance reference. A new run issues its own clock and does not extend an
earlier failed attempt. This profile does not certify GitHub as the historical
shared-host benchmark environment.

Maintainers can add the `visual-review` PR label to capture a targeted foundation
diagnostic before the full suite. It preserves current expected/actual/diff PNGs
without updating references, and uploads them as a separate `visual-review-*`
artifact. Its expected mismatch can continue to evidence upload; it never
substitutes for the subsequent full ordinary suite or satisfies its assertions.
Remove the label after reviewing the render environment and exact differences.
Do not regenerate references to absorb an unexplained rendering regression.
Apply the label before pushing the reviewed PR update; adding a label alone
does not trigger this workflow.

The Linux foundation references include the current top navigation, compact
Findings and sectioned Settings. They were accepted after comparing all seven
views at four widths against the previous sidebar layout and checking the
recorded render environment. Pixel tolerance remains zero. Keyboard evidence
tests reset a reused code pane with Home before End so each width exercises
fresh scrolling rather than inheriting the previous width's bottom position.

A passing workflow does not qualify Marketplace acquisition, the native editor
journey, other platforms or a complete release. No browser result has been
obtained merely by adding this workflow. See [release status](../docs/RELEASE_STATUS.md).

## CodeQL

`workflows/security.yml` analyzes Python, JavaScript/TypeScript and GitHub
Actions only when the repository is public. If it is private, analysis jobs are
skipped and must not be described as a security pass. This workflow does not
assume a private-repository Code Security entitlement. See [CodeQL availability](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).

The analysis job has `security-events: write` solely to submit code-scanning
results, alongside `contents: read`. Other workflows retain a read-only token.
CodeQL database uploads, dependency caching, TRAP caching and debug artifacts
are disabled in the workflow. Source extraction uses no build command. Results
appear in GitHub code scanning once the public workflow has actually succeeded;
no badge or clean-security claim is inferred from configuration.

## Pinned actions

These commits were resolved from the official repositories. Updating a version
comment alone does not update the action; review and change the full commit pin.

| Action | Reviewed tag | Commit |
| --- | --- | --- |
| `actions/checkout` | `v7.0.1` | [`3d3c42e5aac5ba805825da76410c181273ba90b1`](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1) |
| `actions/setup-node` | `v7.1.0` | [`949feb2413d6458794dcd2491c4babbbce0c15c1`](https://github.com/actions/setup-node/commit/949feb2413d6458794dcd2491c4babbbce0c15c1) |
| `actions/setup-python` | `v7.1.0` | [`6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`](https://github.com/actions/setup-python/commit/6d4fd22b20465ccc0f7354476588e8df7c9ca0e0) |
| `github/codeql-action` | `v4` | [`9b3254085494b55a0f7c4c2b3d2d52cc712ce370`](https://github.com/github/codeql-action/commit/9b3254085494b55a0f7c4c2b3d2d52cc712ce370) |

## Manual dependency maintenance

Dependabot configuration preserves intentional fixture controls. Routine version
updates remain deliberate maintainer work; application and build security alerts
and security-update behavior stay enabled. To review an update:

1. Read the upstream release notes, security advisories and license changes.
   Confirm an action's tag resolves to its reviewed commit in the official
   repository; retain full commit pins in workflows.
2. Update the relevant manifest and lockfile together. For Node dependencies,
   use the selected component's npm tooling and review the lockfile diff. For
   Python production dependencies and scanner inputs, follow the existing
   repository lock-generation and [scanner-maintenance contracts](../docs/SCANNER_TOOLS.md).
3. Run the affected focused tests and `make test-public`. For Web changes run
   the ordinary browser suite; for extension distribution changes run
   `npm --prefix extensions/vscode run test:package`.
4. Review the actual diff and results before merging. Preserve third-party
   notices. Do not refresh scanner-data timestamps without new reviewed data,
   regenerate unexplained screenshots, or treat a skipped check as passing.

`CODEOWNERS` routes reviews for workflow, security, host-tooling and packaging
changes. It does not create branch protection. Review requirements must account
for the available independent maintainers; a sole owner cannot approve their
own change.

Release automation is held separately; see [release preparation](RELEASE.md).
