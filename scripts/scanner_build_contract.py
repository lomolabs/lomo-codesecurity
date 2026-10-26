"""Shared immutable inputs for scanner review builds and their consumers."""

from __future__ import annotations


SCANNER_RUNTIME_BASE_IMAGE = (
    "python:3.12-slim@sha256:"
    "229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)
SCANNER_BEARER_BUILD_IMAGE = (
    "golang:1.26.8-bookworm@sha256:"
    "a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d"
)
SCANNER_FROM_DIRECTIVES = (
    f"FROM {SCANNER_BEARER_BUILD_IMAGE} AS bearer-build",
    f"FROM {SCANNER_RUNTIME_BASE_IMAGE}",
)
SCANNER_BEARER_OFFLINE_BUILD_DIRECTIVE = (
    "RUN --network=none python3 /recipe/source-build.py build --source /src --output /out"
)
SCANNER_BUILDER_BUILD_ARGS = (
    ("SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS", "900"),
    ("SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS", "1800"),
)

SCANNER_BUILD_ARGS: tuple[tuple[str, str], ...] = (
    ("TRIVY_VERSION", "0.73.0"),
    ("GITLEAKS_VERSION", "8.30.1"),
    ("GRYPE_VERSION", "0.117.0"),
    ("SYFT_VERSION", "1.51.0"),
    ("BEARER_VERSION", "2.1.0+lomo.1"),
    ("TRUFFLEHOG_VERSION", "3.96.0"),
    ("OPENGREP_VERSION", "1.27.0"),
    ("CHECKOV_VERSION", "3.3.10"),
    ("SCANNER_VERSION_PROBE_TIMEOUT_SECONDS", "30"),
    ("SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS", "900"),
    ("SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS", "1800"),
    ("SCANNER_BUILD_PLATFORM", "mac"),
)

SCANNER_COPY_ROOTS: tuple[str, ...] = (
    "services/scanner/kodesec_scanner",
    "services/scanner/licenses",
    "services/scanner/rules/opengrep",
    "tests/scanner-runtime/fixtures/opengrep",
    "tests/scanner-runtime/fixtures/bearer/rules-canary",
    "tests/scanner-runtime/fixtures/dependencies",
    "tests/scanner-runtime/fixtures/iac",
)

SCANNER_COPY_SINGLE_FILES: tuple[str, ...] = (
    "services/scanner/bearer/LICENSE.txt",
    "services/scanner/bearer/NOTICE",
    "services/scanner/bearer/lomo.patch",
    "services/scanner/bearer/source-build.py",
    "services/scanner/bearer/source.lock.json",
    "services/scanner/bearer/test_source_build.py",
    "services/scanner/pyproject.toml",
    "services/scanner/build-requirements.lock",
    "services/scanner/scripts/fetch-locked-asset.sh",
    "services/scanner/scripts/verify-tool-licenses.py",
    "scanner-tools.lock.json",
    "scanner-rules.lock.json",
)

# This is the exact effective Docker COPY inventory. Adding a module, rule, or
# canary or license is a build-trust change shared by the producer and every consumer.
SCANNER_COPY_FILES: tuple[str, ...] = (
    "services/scanner/bearer/LICENSE.txt",
    "services/scanner/bearer/NOTICE",
    "services/scanner/bearer/lomo.patch",
    "services/scanner/bearer/source-build.py",
    "services/scanner/bearer/source.lock.json",
    "services/scanner/bearer/test_source_build.py",
    "scanner-rules.lock.json",
    "scanner-tools.lock.json",
    "services/scanner/build-requirements.lock",
    "services/scanner/kodesec_scanner/__init__.py",
    "services/scanner/kodesec_scanner/cache_manifest.py",
    "services/scanner/kodesec_scanner/cache_repair.py",
    "services/scanner/kodesec_scanner/data_catalog.py",
    "services/scanner/kodesec_scanner/execution_metrics.py",
    "services/scanner/kodesec_scanner/external.py",
    "services/scanner/kodesec_scanner/gitleaks_locations.py",
    "services/scanner/kodesec_scanner/grype_identity.py",
    "services/scanner/kodesec_scanner/lite_iac.py",
    "services/scanner/kodesec_scanner/lite_sql.py",
    "services/scanner/kodesec_scanner/main.py",
    "services/scanner/kodesec_scanner/models.py",
    "services/scanner/kodesec_scanner/preparation_budget.py",
    "services/scanner/kodesec_scanner/readonly_recovery.py",
    "services/scanner/kodesec_scanner/recovery_contract.py",
    "services/scanner/kodesec_scanner/redaction.py",
    "services/scanner/kodesec_scanner/release_signature.py",
    "services/scanner/kodesec_scanner/rules.py",
    "services/scanner/kodesec_scanner/run_control.py",
    "services/scanner/kodesec_scanner/runtime_cache.py",
    "services/scanner/kodesec_scanner/settings.py",
    "services/scanner/kodesec_scanner/snippets.py",
    "services/scanner/kodesec_scanner/source_build.py",
    "services/scanner/kodesec_scanner/source_io.py",
    "services/scanner/kodesec_scanner/tools.py",
    "services/scanner/kodesec_scanner/trivy_db_lock_candidate.py",
    "services/scanner/kodesec_scanner/updater.py",
    "services/scanner/kodesec_scanner/updater_main.py",
    "services/scanner/kodesec_scanner/updater_routes.py",
    "services/scanner/kodesec_scanner/updater_service.py",
    "services/scanner/kodesec_scanner/verify_tools.py",
    "services/scanner/licenses/README.md",
    "services/scanner/licenses/bearer.txt",
    "services/scanner/licenses/checkov.txt",
    "services/scanner/licenses/gitleaks.txt",
    "services/scanner/licenses/grype.txt",
    "services/scanner/licenses/opengrep.COPYRIGHT",
    "services/scanner/licenses/opengrep.txt",
    "services/scanner/licenses/syft.txt",
    "services/scanner/licenses/trivy.NOTICE",
    "services/scanner/licenses/trivy.txt",
    "services/scanner/licenses/trufflehog.txt",
    "services/scanner/pyproject.toml",
    "services/scanner/scripts/fetch-locked-asset.sh",
    "services/scanner/scripts/verify-tool-licenses.py",
    "services/scanner/rules/opengrep/LICENSE",
    "services/scanner/rules/opengrep/README.md",
    "services/scanner/rules/opengrep/rules.yml",
    "tests/scanner-runtime/fixtures/bearer/rules-canary/positive.py",
    "tests/scanner-runtime/fixtures/dependencies/positive/package-lock.json",
    "tests/scanner-runtime/fixtures/dependencies/positive/package.json",
    "tests/scanner-runtime/fixtures/dependencies/positive/requirements.txt",
    "tests/scanner-runtime/fixtures/dependencies/zero/README.txt",
    "tests/scanner-runtime/fixtures/iac/positive/Dockerfile",
    "tests/scanner-runtime/fixtures/iac/positive/k8s/deployment.yaml",
    "tests/scanner-runtime/fixtures/iac/positive/main.tf",
    "tests/scanner-runtime/fixtures/iac/zero/README.txt",
    "tests/scanner-runtime/fixtures/iac/zero/main.tf",
    "tests/scanner-runtime/fixtures/iac/zero/safe.py",
    "tests/scanner-runtime/fixtures/opengrep/positive/Unsafe.java",
    "tests/scanner-runtime/fixtures/opengrep/positive/app.js",
    "tests/scanner-runtime/fixtures/opengrep/positive/app.php",
    "tests/scanner-runtime/fixtures/opengrep/positive/app.py",
    "tests/scanner-runtime/fixtures/opengrep/positive/app.rb",
    "tests/scanner-runtime/fixtures/opengrep/positive/main.go",
    "tests/scanner-runtime/fixtures/opengrep/zero/Safe.java",
    "tests/scanner-runtime/fixtures/opengrep/zero/app.js",
    "tests/scanner-runtime/fixtures/opengrep/zero/app.php",
    "tests/scanner-runtime/fixtures/opengrep/zero/app.py",
    "tests/scanner-runtime/fixtures/opengrep/zero/app.rb",
    "tests/scanner-runtime/fixtures/opengrep/zero/main.go",
)

SCANNER_COPY_DIRECTIVES: tuple[str, ...] = (
    "COPY services/scanner/scripts/fetch-locked-asset.sh /usr/local/bin/kodesec-fetch-locked-asset",
    "COPY services/scanner/bearer/source.lock.json /recipe/source.lock.json",
    "COPY services/scanner/bearer/source-build.py /recipe/source-build.py",
    "COPY services/scanner/bearer/lomo.patch /recipe/lomo.patch",
    "COPY services/scanner/bearer/LICENSE.txt /recipe/LICENSE.txt",
    "COPY services/scanner/bearer/NOTICE /recipe/NOTICE",
    "COPY services/scanner/bearer/test_source_build.py /recipe/test_source_build.py",
    "COPY services/scanner/scripts/fetch-locked-asset.sh /usr/local/bin/kodesec-fetch-locked-asset",
    "COPY --from=bearer-build /out/bearer /usr/local/bin/bearer",
    "COPY --from=bearer-build /out/build.json /usr/local/share/kodesec/builds/bearer/build.json",
    "COPY --from=bearer-build /out/LICENSE.txt /usr/local/share/kodesec/builds/bearer/LICENSE.txt",
    "COPY --from=bearer-build /out/NOTICE /usr/local/share/kodesec/builds/bearer/NOTICE",
    "COPY --from=bearer-build /recipe/source.lock.json /usr/local/share/kodesec/builds/bearer/source.lock.json",
    "COPY services/scanner/pyproject.toml ./",
    "COPY services/scanner/build-requirements.lock ./build-requirements.lock",
    "COPY services/scanner/kodesec_scanner ./kodesec_scanner",
    "COPY scanner-tools.lock.json /usr/local/share/kodesec/locks/scanner-tools.lock.json",
    "COPY scanner-rules.lock.json /usr/local/share/kodesec/locks/scanner-rules.lock.json",
    "COPY services/scanner/rules/opengrep /usr/local/share/kodesec/rules/opengrep",
    "COPY tests/scanner-runtime/fixtures/opengrep /usr/local/share/kodesec/canaries/opengrep",
    "COPY tests/scanner-runtime/fixtures/bearer/rules-canary /usr/local/share/kodesec/canaries/bearer/rules-canary",
    "COPY tests/scanner-runtime/fixtures/dependencies /usr/local/share/kodesec/canaries/dependencies",
    "COPY tests/scanner-runtime/fixtures/iac /usr/local/share/kodesec/canaries/iac",
    "COPY services/scanner/licenses /usr/local/share/kodesec/licenses",
    "COPY services/scanner/scripts/verify-tool-licenses.py /tmp/verify-tool-licenses.py",
)
