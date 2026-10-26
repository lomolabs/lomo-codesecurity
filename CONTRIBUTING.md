# Contributing

Start with the [development guide](docs/DEVELOPMENT.md),
[architecture](docs/ARCHITECTURE.md) and [security boundaries](SECURITY.md).
The project repository is [lomolabs/lomo-codesecurity](https://github.com/lomolabs/lomo-codesecurity).
Use its issues and pull requests where the repository's settings permit them.

## Report a problem

Describe the operating system, source and extension versions, action you took,
expected result and actual result. Include a small synthetic reproduction when
possible. Read [known issues](docs/RELEASE_STATUS.md) first. For a potential
vulnerability, follow the [private reporting policy](SECURITY.md#reporting-a-vulnerability)
instead of posting details publicly.

`make support-bundle` collects bounded diagnostics locally. Inspect its contents
before sharing; do not attach source, runtime credentials, browser profiles or
private installation data. See the [bundle guide](docs/MONITORING.md#local-bug-report-bundle).

## Propose a change

Keep a pull request focused on one problem. Explain the user-visible behavior,
why it changes, how you verified it and any remaining limitations. Update the
relevant guide when commands, setup or security behavior change. Discuss large
architecture changes before implementation when a maintainer contact is available.

Preserve these product rules:

- Source authorization is explicit and narrow. Opening a workspace grants no
  source authority.
- Incomplete, failed or stale evidence cannot become a passing security gate.
- Browser, editor and host permissions remain distinct. Do not weaken checks to
  hide a failing setup or test.
- Scanner data must satisfy reviewed identity, compatibility and freshness.
- Advisor output remains optional advice and cannot authorize a gate decision.
- Changes preserve the user's existing editor profile and unrelated services.

Use synthetic fixtures without live credentials or private code. Retain relevant
third-party notices, and explain the provenance and license of new dependencies
or fixtures. Only contribute material you have the right to submit under the
project's license. Apache-2.0 does not replace third-party terms or grant rights
to another party's trademarks.

## Validate your contribution

Run the checks for the component you changed and the public baseline:

```sh
make test-public
```

The [development guide](docs/DEVELOPMENT.md#public-checks) defines this target's
scope. It does not constitute full product, desktop or platform acceptance.
Report checks that were not run and any failures honestly. Do not update visual
references solely to make an unexplained difference pass.

Use disposable state for integration work and keep it separate from an existing
installation. Do not include generated packages, caches, diagnostics or runtime
state in a pull request. Do not restart or reconfigure someone else's editor,
browser or Docker environment as part of an unattended test.
