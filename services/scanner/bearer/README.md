# Modified Bearer source build

Lomo CodeSecurity builds Bearer `2.1.0+lomo.1` from the exact upstream source
identified in [source.lock.json](source.lock.json), with the cumulative
[lomo.patch](lomo.patch). This is modified software, not the stock upstream
binary. The lock records the upstream repository and commit, archive URL,
size/digest, original module files, recipe inputs and patched file digests.

The [NOTICE](NOTICE) describes the modifications. [LICENSE.txt](LICENSE.txt)
is the unchanged upstream Elastic License 2.0. Original copyright and licensing
notices remain in the upstream source. Preserve these files with distributed
copies; Lomo's Apache-2.0 license does not replace Bearer's license or grant
trademark rights. The [scanner license index](../licenses/README.md) explains
its scope and the additional dependency/distribution review required.

## Modification scope

The patch includes:

- Python subscription tuple-key preservation and its semantic regressions.
- Avoidance of unnecessary trace formatting, preservation of empty detector/cache
  results, and short-circuiting of unreachable outer conjunction branches.
- Bounded empty-result reuse for an admitted immutable rule structure, including
  completed empty children/alias traversals. Positive, incomplete or cancelled
  traversals cannot publish reusable empty results.
- A specialized implementation of one generated JavaScript statement-pair query
  that preserves native capture order and cardinality without eager quadratic
  storage. Unknown query shapes keep the original behavior.
- Query-absence checks that avoid redundant traversal only when the compiled
  structure proves it cannot match. Unknown shapes, sanitizers and active
  execution retain conservative fallbacks.
- Validated installation-specific analysis timing with separate file, whole-scan
  and enclosing execution deadlines.

The selected semantic tests cover positive and empty results, ordering,
cardinality, errors, cycles, cancellation, mutable or mismatched context,
unknown structures and actual reuse. These tests do not establish universal
rule coverage or platform qualification. See the [scanner guide](../../../docs/SCANNER_TOOLS.md)
for coverage limits and incomplete-result handling.

## Maintained image build

The [scanner Dockerfile](../Dockerfile) is the maintained integration. Normal
[source startup](../../../docs/SOURCE_STARTUP.md) builds changed image inputs;
host Go is not required.

The builder uses the exact Go image digest in the source lock, Go 1.26.8,
CGO and a native `linux/amd64` or `linux/arm64` environment. It installs Python 3,
Git and binutils in that isolated stage. The six recipe files copied into the
builder are the source lock, build script, patch, license, notice and Python
helper tests. This README is documentation, not a locked build input.

The bounded image-build fetcher obtains the exact upstream archive and verifies
its size and SHA-256 before preparation. [source-build.py](source-build.py)
validates the recipe and archive, verifies the original files, applies the patch,
and verifies the resulting files. It does not acquire that archive itself or
modify an installed CodeSecurity service.

For recipe development, use a fresh owned builder matching that Dockerfile.
The following paths are inside the builder: the verified archive is at
`/tmp/bearer.tar.gz`, the recipe is at `/recipe`, and source/output directories
must be fresh. Run preparation and dependency acquisition first:

```sh
python3 /recipe/source-build.py prepare --archive /tmp/bearer.tar.gz \
  --source /src --output /prepare-logs
python3 /recipe/source-build.py dependencies --source /src --output /dependency-output
```

Dependency acquisition uses the Go module proxy and checksum service, checks the
locked module-file digests before and after downloading, and runs `go mod verify`.
Then execute the build in a network-disabled step, as the Dockerfile does with
`RUN --network=none`:

```sh
python3 /recipe/source-build.py build --source /src --output /out
```

The build uses the local locked compiler, fixed flags, no module proxy or Go
workspace, and no automatic toolchain upgrade. Dependency and build invocations
each have a finite 900-second deadline. The caller also owns its outer deadline
and builder cleanup. These clocks do not extend scanner runtime deadlines.
Cancellation or expiry stops and reaps the owned process group; inability to
prove it stopped is a build failure.

The offline build runs the thirteen package test selections declared in the
script, validates named test events, and rejects missing, skipped or failed
selected tests. It compiles and checks the binary, then emits `bearer`,
`build.json`, `LICENSE.txt` and `NOTICE`. The receipt records the actual output
size/digest, source and recipe identities, native Go/platform observation,
test results and bounded build-log hashes. Builder image identity and native
platform must also be established by the calling build; a declared compiler
input alone does not prove that environment.

Only the binary, generated receipt, license, notice and source lock are copied
from this stage into runtime. Build logs, Go, source, patch and test fixtures
stay out of the runtime image. Source distributions retain the full reviewed
recipe and patch. The source lock intentionally does not invent a binary digest;
each actual platform build supplies its generated output identity.

## Local helper checks

From the repository root, this checks the Python recipe helper without Docker,
a Go build or network access:

```sh
python3 -m unittest discover -s services/scanner/bearer -p 'test_*.py' -v
```

These checks do not compile Bearer or validate the complete scanner image.
A changed recipe, patch, module input, license or notice needs matching lock
review. Rebuild and verify actual outputs on each native architecture; never
reuse a source digest as a binary digest or relabel a stock binary as modified.

## Runtime contract

Runtime readiness binds the modified binary and generated receipt to the
[tool lock](../../../scanner-tools.lock.json). Bearer uses only the validated
external rules from the [rules lock](../../../scanner-rules.lock.json), with
default-rule fetching, version checks and telemetry disabled. A binary build
alone does not establish rule/data readiness or complete scan evidence.
Old cache generations must satisfy the current reviewed lock contract; they
cannot be accepted merely by substituting a version label.

The adapter supplies `KODESEC_SCAN_PLATFORM`; repository YAML cannot select it.
The patch applies the computed file duration once, with factors 1, 5.2 and 7.8
for Mac, Linux and Windows/WSL. The respective per-file maxima are 30, 156 and
234 seconds. Unset retains upstream timing; unknown lanes and invalid factors
fail closed. Workers receive the already assigned duration.

The independent native whole-scan caps are 600, 1,560 and 2,340 seconds.
Enclosing execution deadlines and cancellation still apply and cannot be renewed
by changing the lane. Source/memory bounds, cleanup grace, data expiry and
incomplete-report rejection remain unchanged. Native Windows source capture has
its separate 30-second per-file bound.

Actual image tests must cover binary/receipt identity, semantic canaries,
positive and zero-result scans, offline execution and failure handling. Source
integration and helper checks do not qualify either native architecture or a
fresh installation. Current platform limits are recorded in
[release status](../../../docs/RELEASE_STATUS.md).
