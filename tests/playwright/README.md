# Web browser tests

This suite builds the production React bundle and serves it with generated
synthetic API fixtures on loopback. It checks Web behavior; it does not run a
developer's repositories or establish native editor, scanner-runtime, full
platform or release acceptance. See [release status](../../docs/RELEASE_STATUS.md).

The ordinary suite covers the current views at desktop, tablet and mobile
widths. It includes screenshot comparisons, accessibility checks, navigation,
finding interactions and scanner-lifecycle UI. Guards reject unexpected
network origins, console/request errors, overflow, unstable layout and excessive
DOM/resource growth. Performance assertions retain their configured timing
and observation requirements; missing observations are not treated as zeros.

## Prepare the test environment

Use the Node.js/npm versions in [platform setup](../../docs/PLATFORM_SETUP.md#build-the-preview-extension).
From the repository root:

```sh
cd tests/playwright
npm ci --ignore-scripts
```

Keep this working directory for the following commands. Preparation needs
network access for locked dependencies and the selected browser runtime.
Test fixtures must remain synthetic: do not replace them with private source,
real scanner output, credentials or an existing browser profile.

### Linux and WSL

Use a working local Linux Docker engine and at least **four available CPUs**.
The ordinary runner checks the CPU requirement before starting its containers.
A smaller machine is a failed admission, not passing browser coverage. GitHub's
private standard runners may be too small; do not weaken the runner to hide
that failure.

Prepare the image pinned by the maintained runner:

```sh
docker pull mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48
```

The ordinary Linux/WSL browser phase uses two bounded containers. The browser
has no external network and receives only locked test dependencies read-only;
the controller shares that container's loopback network and receives the suite
and built Web assets read-only. Only the current results directory is writable.
Both use the reviewed image, and the runner requires exact cleanup after the
run. It starts them with `--pull never`, so preparation must finish first.
No host Chromium installation is needed for this path.

On Fedora with SELinux enforcing, use an owner-prepared disposable checkout
whose labels permit the required read-only container mounts. A mount denial
does not authorize disabling SELinux, using an unconfined label or recursively
relabeling a normal checkout. Report a staging failure if the environment is
not prepared.

### macOS and native Windows

These platforms use the maintained local locked-browser path:

```sh
npm run browser:install
```

The browser cache is repository-local and ignored by Git. Each test uses fresh
browser context state. This path does not claim Linux container/network
isolation. Native Windows and WSL are different execution paths: running the
suite inside WSL exercises the Linux runner, not a Windows browser.

The ordinary run requires reviewed screenshots for its exact operating system
and mode. This source currently has no native Windows screenshot baseline set;
browser installation alone cannot make that full run pass or qualify Windows.
Missing references must remain a visible failure until intentionally created,
independently reviewed and checked by an ordinary run.

## Run the ordinary suite

```sh
npm test
```

This installs/builds the Web application from its separate locked dependencies,
then invokes the maintained ordinary runner. The default is headless. After
that Web build has been prepared, the browser phase alone can be repeated with:

```sh
npm run test:offline
```

These ordinary entry points accept no extra Playwright arguments. Do not bypass
their scope with filters, alternate configurations, retry/timeout changes,
ignored screenshots, output overrides or `--pass-with-no-tests`. A green result
must retain the full declared suite and its existing assertions.

The runner owns its loopback service and result directory. Results include a
runner receipt, normalized execution summary and failure screenshots/traces.
Check the actual outcome, executed/skipped counts, runtime identity and cleanup.
An incomplete run or uncertain cleanup is not a passing run. Treat traces and
diagnostic files as private until reviewed; do not upload a result tree wholesale.
After abnormal native termination, verify that the owned fixture processes and
listener have stopped before starting another run.

The source-preview release process additionally requires actual builds following
the published instructions on Mac, Ubuntu, Fedora, native Windows and Remote
WSL before upload. Those builds are a separate requirement: this browser suite,
a source audit or an old package checksum cannot substitute for them. Passing
the builds does not close deferred full-platform product acceptance.

## Focused checks and diagnosis

The public baseline runs these source/contract checks without starting the
Compose product stack:

```sh
npm run test:compose:check
```

The viewport-fixture regression is also available without launching a browser:

```sh
npm run test:reference-viewport
```

For diagnosis, the explicit targeted runner accepts the ordinary specs,
declared viewport projects and a bounded grep selector. For example:

```sh
npm run test:targeted -- \
  tests/findings.performance.spec.ts \
  --project=desktop-1440 \
  --grep 'compact code evidence'
```

Targeted runs and the `test:foundation` convenience command do not satisfy an
ordinary full-suite result or platform acceptance. Do not promote a targeted
pass to clear a failed ordinary run.

## Review visual changes

Screenshot names are platform-specific. macOS additionally has separate headed
and headless references; the runner selects the exact mode's complete set.
There is no cross-platform or cross-mode fallback. Ordinary runs use exact
comparisons and never update screenshots.

After an intentional visual change, use the dedicated update command:

```sh
npm run test:update
```

Inspect every changed image, preserve the explanation for the original failure,
then rerun `npm test` in the same mode. An update run is not a regression pass.
Do not replace screenshots to absorb an unexplained environment difference.
The default mode is headless; `KODESEC_PLAYWRIGHT_HEADED=1` selects visible mode
where the host display is prepared. Visible fixture tests still do not establish
native editor or complete product acceptance.

## Optional isolated Compose smoke

The separate `npm run test:compose` command creates a disposable product stack,
may build scanner images and removes its exact project containers, networks,
volumes and project-local images afterward. Run it only when you have reviewed
the [maintained smoke entry point](scripts/compose-smoke.mjs) and have an
appropriate idle test environment. It is not part of `npm test` or ordinary
`make test-public`, and does not operate an existing installation.

On Linux/WSL its browser uses a separate bounded host-network container to reach
the disposable stack's exact host-loopback origin. This differs from the
ordinary two-container synthetic suite. Authentication traces may contain the
disposable session cookie; keep them private. Missing cleanup must remain a
failure. The runner does not perform host-wide Docker pruning.

The smoke covers a bounded route/authentication/persistence journey, not all
optional profiles, scanner updates, crash recovery or cross-platform behavior.

## Maintained entry points

- [Package scripts and locked runner version](package.json)
- [Ordinary offline runner](scripts/offline-playwright.mjs)
- [Container image and runtime contracts](scripts/compose-harness-lib.mjs)
- [Test selection, viewports and assertions](playwright.config.ts)
- [Public development guide](../../docs/DEVELOPMENT.md)
