# Development

Read the [architecture overview](ARCHITECTURE.md) and
[security policy](../SECURITY.md) before changing source, credentials, scanner
execution, data maintenance or gate behavior. Use [platform setup](PLATFORM_SETUP.md)
for host prerequisites and [CONTRIBUTING.md](../CONTRIBUTING.md) for review guidance.

## Working from source

Use a clean checkout or complete reviewed source archive. Keep generated output,
runtime state, credentials and diagnostic bundles out of Git. Extract archives
outside another Git checkout so the launcher does not infer an unrelated parent
repository's identity.

The backend requires Python 3.12+, Git, Make and a local Linux Docker engine
with Compose/Buildx. Web development requires Node.js 20.19 or later in the
20.x series, or Node.js 22.12 or later. Extension development uses the separate
Node.js/npm requirements in the [setup guide](PLATFORM_SETUP.md#build-the-preview-extension).
The lockfiles are authoritative build inputs; do not replace locked versions
merely to work around an unrelated environment failure.

```sh
python3 scripts/start-lomo.py --check --json
python3 scripts/start-lomo.py
```

Normal startup builds and starts the backend only. It preserves the installation
and does not install into an editor profile. Use disposable installation state
for integration development, with a dedicated state directory chosen before
initialization, and pass that same selection consistently. Inspect existing
services and port use before starting another stack.

## Public checks

```sh
make test-public
```

This is the exported contributor baseline. It checks the API and scanner unit
suites, builds the Web application, runs extension unit tests and checks the
Playwright test contracts using locked dependencies. Network access is needed
when dependencies are not already available. Checks that require explicitly
selected PostgreSQL or Docker integration environments are not silently enabled.

This target does not launch a desktop editor, alter an installed extension,
qualify a platform or replace full release acceptance. Private infrastructure
controllers, release receipts and large acceptance fixtures are not part of
the public source distribution. A local passing baseline must not be presented
as a new end-to-end product result. Record any skipped or unrun checks in a pull
request.

Run focused component checks while editing; use the baseline before submitting
a change that spans components. Do not point opt-in database tests at an
existing installation.

The public source also contains the Web browser journeys and extension package
checks. These are separate from the baseline:

```sh
npm --prefix tests/playwright test
npm --prefix extensions/vscode run test:package
```

Run the package regression suite from a Git checkout: it creates an independent
archive with `git archive` to verify packaging without Git. A downloaded source
archive can build the VSIX directly with `make vscode-package`.

Install each component's locked dependencies first. Browser journeys also need
the Playwright browsers required by their configuration. Package checks verify
the extension's distribution boundary and reproducibility; they do not qualify
Marketplace installation or updates. Browser tests use their declared fixtures
and do not constitute a fresh desktop or full-platform acceptance run.

## Web development

From `apps/web/`:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
```

The production bundle is served by FastAPI. Vite's development server is a
development aid, not the normal service topology or an alternative to the
API's authentication boundary.

## VS Code development

From `extensions/vscode/`:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
npm run test:unit
```

From the repository root, `make vscode-package` creates the VSIX without opening
an editor or installing it. For manual product use, install it in your existing
profile with **Extensions: Install from VSIX…**. For automated or disruptive
development experiments, use an explicitly selected disposable profile and
synthetic workspace. Do not change an unrelated user's editor settings,
extensions, Workspace Trust or credentials.

## Schema lifecycle

The one-shot schema initializer uses the application's current SQLAlchemy
metadata. It initializes an empty namespace or verifies an existing namespace
against that exact schema. It does not adopt an unknown database or silently
migrate mismatched data. A schema mismatch is a diagnosis to resolve, not a
reason to delete an existing user's database.

## Review a Trivy DB lock candidate

Scanner-data review is maintainer work, separate from normal scanner preparation.
The producer commands create non-authoritative review material; they do not
edit the lock, activate product data or establish release acceptance. Read the
[data-review contract](SCANNER_TOOLS.md#reviewed-trivy-db-lock-candidate) before
using them. Exact command options are available without starting a review:

```sh
python3 scripts/docker-runtime-observation.py --help
python3 scripts/scanner-build-receipt.py --help
python3 scripts/trivy-db-lock-candidate.py --help
python3 scripts/grype-db-lock-candidate.py --help
```

Use a new owner-only review directory outside the checkout. Output directories
must not already exist and their direct parent must be owned by the current
account, mode `0700`, and not a symbolic link. Runtime observation binds exact
Docker/Buildx executables and the local engine before the build producer runs.
The build and candidate producer must execute on the same admitted native host.
Do not substitute emulation or reuse another host's receipt.

A Java database candidate also needs an existing read-only OS database whose
content matches the current lock. Candidate output must never be copied into
an active product cache. Review digests, timestamps, compatibility, canary
results and cleanup before proposing a lock change; then rebuild changed source
and use normal preparation. Fetching the same expired definition is not renewal.

## Diagnose without changing an installation

Use `make support-bundle` for bounded local diagnostics. It does not upload,
restart services or change installation state. [Review its output](MONITORING.md#local-bug-report-bundle)
before sharing. Preserve a failed observation and its actual error; do not
relax source, credential or scanner-data checks to make a test pass.
