# Build natively on the maintained producer's admitted Linux platform.
FROM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS bearer-build

ARG SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS=900
ARG SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS=1800

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 git binutils ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY services/scanner/scripts/fetch-locked-asset.sh /usr/local/bin/kodesec-fetch-locked-asset
RUN chown 0:0 /usr/local/bin/kodesec-fetch-locked-asset \
    && chmod 0755 /usr/local/bin/kodesec-fetch-locked-asset
COPY services/scanner/bearer/source.lock.json /recipe/source.lock.json
COPY services/scanner/bearer/source-build.py /recipe/source-build.py
COPY services/scanner/bearer/lomo.patch /recipe/lomo.patch
COPY services/scanner/bearer/LICENSE.txt /recipe/LICENSE.txt
COPY services/scanner/bearer/NOTICE /recipe/NOTICE
COPY services/scanner/bearer/test_source_build.py /recipe/test_source_build.py
RUN kodesec-fetch-locked-asset \
      "https://codeload.github.com/Bearer/bearer/tar.gz/814948ecc198a743b13a75a6bfd4688514285220" \
      /tmp/bearer.tar.gz \
      "218a181286ab11d6d189db879692e9ae556370d0304b9c09732e637f8c77c149" \
      10006472 \
    && python3 /recipe/source-build.py prepare --archive /tmp/bearer.tar.gz \
      --source /src --output /prepare-logs
RUN python3 /recipe/source-build.py dependencies --source /src --output /dependency-output
RUN --network=none python3 /recipe/source-build.py build --source /src --output /out

FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG TRIVY_VERSION=0.73.0
ARG GITLEAKS_VERSION=8.30.1
ARG GRYPE_VERSION=0.117.0
ARG SYFT_VERSION=1.51.0
ARG BEARER_VERSION=2.1.0+lomo.1
ARG TRUFFLEHOG_VERSION=3.96.0
ARG OPENGREP_VERSION=1.27.0
ARG CHECKOV_VERSION=3.3.10
ARG SCANNER_VERSION_PROBE_TIMEOUT_SECONDS=30
ARG SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS=900
ARG SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS=1800

RUN test "${BEARER_VERSION}" = "2.1.0+lomo.1"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    gzip \
    tar \
    unzip \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY services/scanner/scripts/fetch-locked-asset.sh /usr/local/bin/kodesec-fetch-locked-asset
RUN chown 0:0 /usr/local/bin/kodesec-fetch-locked-asset \
    && chmod 0755 /usr/local/bin/kodesec-fetch-locked-asset

# Only immutable production outputs enter the runtime image.
COPY --from=bearer-build /out/bearer /usr/local/bin/bearer
COPY --from=bearer-build /out/build.json /usr/local/share/kodesec/builds/bearer/build.json
COPY --from=bearer-build /out/LICENSE.txt /usr/local/share/kodesec/builds/bearer/LICENSE.txt
COPY --from=bearer-build /out/NOTICE /usr/local/share/kodesec/builds/bearer/NOTICE
COPY --from=bearer-build /recipe/source.lock.json /usr/local/share/kodesec/builds/bearer/source.lock.json
RUN chown -R 0:0 /usr/local/share/kodesec/builds \
    && find /usr/local/share/kodesec/builds -type d -exec chmod 0555 {} + \
    && find /usr/local/share/kodesec/builds -type f -exec chmod 0444 {} +

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) \
        common_arch="amd64"; \
        gitleaks_arch="x64"; \
        opengrep_arch="x86"; \
        trivy_arch="64bit"; \
        trivy_sha256="2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b"; \
        gitleaks_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"; \
        opengrep_sha256="9d47d7de3f22ec5a93b25af9126648191e3d3b5d759dd4f699006138724719b3"; \
        grype_sha256="38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26"; \
        trufflehog_sha256="7105f1cd6577f058a9e39d0578f1a99c8a1e481e4d3512cd8a09acfe22a0fdc0"; \
        syft_sha256="2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f" \
        ;; \
      arm64) \
        common_arch="arm64"; \
        gitleaks_arch="arm64"; \
        opengrep_arch="aarch64"; \
        trivy_arch="ARM64"; \
        trivy_sha256="13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd"; \
        gitleaks_sha256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"; \
        opengrep_sha256="4efcd2f195da8719f16e4eac79fb918442e04d70f3bcc001fd6105c0afd53aae"; \
        grype_sha256="935f628bdf9331ffdd946931ea5fdb50045d3970ba52670cbeb44a88f127291b"; \
        trufflehog_sha256="50acd4c7a3b8ebfe5083d8350956057030c44be3515dedd55b45263495c490b2"; \
        syft_sha256="6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900" \
        ;; \
      *) echo "unsupported scanner architecture: $arch" >&2; exit 1 ;; \
    esac; \
    download_dir="$(mktemp -d)"; \
    fetch() { \
      url="$1"; destination="$2"; expected="$3"; \
      kodesec-fetch-locked-asset "$url" "$destination" "$expected"; \
    }; \
    trivy_archive="$download_dir/trivy.tar.gz"; \
    fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" "$trivy_archive" "$trivy_sha256"; \
    tar -xzf "$trivy_archive" -C /usr/local/bin trivy; \
    gitleaks_archive="$download_dir/gitleaks.tar.gz"; \
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" "$gitleaks_archive" "$gitleaks_sha256"; \
    tar -xzf "$gitleaks_archive" -C /usr/local/bin gitleaks; \
    opengrep_binary="$download_dir/opengrep"; \
    fetch "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_${opengrep_arch}" "$opengrep_binary" "$opengrep_sha256"; \
    install -m 0755 "$opengrep_binary" /usr/local/bin/opengrep; \
    grype_archive="$download_dir/grype.tar.gz"; \
    fetch "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${common_arch}.tar.gz" "$grype_archive" "$grype_sha256"; \
    tar -xzf "$grype_archive" -C /usr/local/bin grype; \
    trufflehog_archive="$download_dir/trufflehog.tar.gz"; \
    fetch "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${common_arch}.tar.gz" "$trufflehog_archive" "$trufflehog_sha256"; \
    tar -xzf "$trufflehog_archive" -C /usr/local/bin trufflehog; \
    syft_archive="$download_dir/syft.tar.gz"; \
    fetch "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${common_arch}.tar.gz" "$syft_archive" "$syft_sha256"; \
    tar -xzf "$syft_archive" -C /usr/local/bin syft; \
    chown 0:0 \
      /usr/local/bin/trivy \
      /usr/local/bin/gitleaks \
      /usr/local/bin/opengrep \
      /usr/local/bin/bearer \
      /usr/local/bin/grype \
      /usr/local/bin/trufflehog \
      /usr/local/bin/syft; \
    chmod 0755 \
      /usr/local/bin/trivy \
      /usr/local/bin/gitleaks \
      /usr/local/bin/opengrep \
      /usr/local/bin/bearer \
      /usr/local/bin/grype \
      /usr/local/bin/trufflehog \
      /usr/local/bin/syft; \
    rm -rf "$download_dir"
RUN groupadd --gid 1000 kodesec && useradd --uid 1000 --gid kodesec --home-dir /app --shell /usr/sbin/nologin kodesec

COPY services/scanner/pyproject.toml ./
COPY services/scanner/build-requirements.lock ./build-requirements.lock
RUN pip install --disable-pip-version-check --only-binary=:all: \
        --require-hashes -r build-requirements.lock

COPY services/scanner/kodesec_scanner ./kodesec_scanner
COPY scanner-tools.lock.json /usr/local/share/kodesec/locks/scanner-tools.lock.json
COPY scanner-rules.lock.json /usr/local/share/kodesec/locks/scanner-rules.lock.json
COPY services/scanner/rules/opengrep /usr/local/share/kodesec/rules/opengrep
COPY tests/scanner-runtime/fixtures/opengrep /usr/local/share/kodesec/canaries/opengrep
COPY tests/scanner-runtime/fixtures/bearer/rules-canary /usr/local/share/kodesec/canaries/bearer/rules-canary
COPY tests/scanner-runtime/fixtures/dependencies /usr/local/share/kodesec/canaries/dependencies
COPY tests/scanner-runtime/fixtures/iac /usr/local/share/kodesec/canaries/iac

RUN pip install --disable-pip-version-check --no-build-isolation --no-deps .
ARG SCANNER_BUILD_PLATFORM=mac

RUN set -eux; \
    test "$CHECKOV_VERSION" = "3.3.10"; \
    checkov_download_dir="$(mktemp -d)"; \
    checkov_wheel="$checkov_download_dir/checkov-3.3.10-py3-none-any.whl"; \
    kodesec-fetch-locked-asset \
      "https://files.pythonhosted.org/packages/84/f6/febd883c86b841392b91737be1a40da53cd6a6de0013c4ff38c91c9ea8b7/checkov-3.3.10-py3-none-any.whl" \
      "$checkov_wheel" \
      "5923565b2d29f6932011e1f479a78cb46fa6aede3110919a8f2028fb5318cbdc"; \
    pip install --disable-pip-version-check --no-index --no-deps "$checkov_wheel"; \
    chown 0:0 /usr/local/bin/checkov; \
    chmod 0755 /usr/local/bin/checkov; \
    rm -rf "$checkov_download_dir"; \
    install -d -m 0755 /usr/local/share/kodesec/canaries/trivy/java; \
    java_canary=/usr/local/share/kodesec/canaries/trivy/java/log4j-core-2.14.1.jar; \
    kodesec-fetch-locked-asset \
      https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar \
      "$java_canary" \
      "ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0" \
      1745700; \
    test "$(wc -c < "$java_canary" | tr -d ' ')" = 1745700; \
    mkdir -p /usr/local/share/kodesec; \
    opengrep_home="/usr/local/share/kodesec/opengrep-home"; \
    opengrep_core="$opengrep_home/.cache/opengrep/v${OPENGREP_VERSION}/opengrep.bin"; \
    opengrep_executable="$opengrep_home/.cache/opengrep/v${OPENGREP_VERSION}/opengrep"; \
    install -d -m 0755 "$opengrep_home"; \
    HOME="$opengrep_home" SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off \
      opengrep --experimental --version; \
    ln -s opengrep.bin "$opengrep_executable"; \
    test ! -L "$opengrep_core"; \
    test -f "$opengrep_core"; \
    test -x "$opengrep_core"; \
    test "$(readlink "$opengrep_executable")" = "opengrep.bin"; \
    chown -R 0:0 "$opengrep_home"; \
    chmod -R a-w,a+rX "$opengrep_home"; \
    rm -rf /root/.cache/opengrep; \
    chown -R 0:0 /usr/local/share/kodesec/canaries /usr/local/share/kodesec/locks /usr/local/share/kodesec/rules; \
    find /usr/local/share/kodesec/canaries /usr/local/share/kodesec/locks /usr/local/share/kodesec/rules -type d -exec chmod 0555 {} +; \
    find /usr/local/share/kodesec/canaries /usr/local/share/kodesec/locks /usr/local/share/kodesec/rules -type f -exec chmod 0444 {} +; \
    python -c 'from hashlib import sha256; from pathlib import Path; from kodesec_scanner.cache_manifest import collect_canonical_tree, load_rules_lock, load_tool_lock; tools=load_tool_lock(Path("/usr/local/share/kodesec/locks/scanner-tools.lock.json")); rules=load_rules_lock(Path("/usr/local/share/kodesec/locks/scanner-rules.lock.json")); expected=rules.value.rule_set("opengrep-reviewed-rules"); observed=collect_canonical_tree(Path("/usr/local/share/kodesec/rules/opengrep"), require_immutable=True); assert observed.algorithm == expected.tree_hash_algorithm and observed.sha256 == expected.tree_sha256 and observed.file_count == expected.tree_file_count and observed.size_bytes == expected.tree_size_bytes; requirement=tools.value.tool("opengrep").requirements[0]; assert requirement.source.sha256 == observed.sha256; positive=collect_canonical_tree(Path("/usr/local/share/kodesec/canaries/opengrep/positive"), require_immutable=True); zero=collect_canonical_tree(Path("/usr/local/share/kodesec/canaries/opengrep/zero"), require_immutable=True); canaries={item.id:item for item in expected.canaries}; assert positive.sha256 == canaries["supported-sinks-positive"].fixture_sha256 and zero.sha256 == canaries["supported-sinks-zero"].fixture_sha256; bearer=rules.value.rule_set("bearer-rules").canaries[0]; assert sha256(Path("/usr/local/share/kodesec/canaries/bearer/rules-canary/positive.py").read_bytes()).hexdigest() == bearer.fixture_sha256'; \
    python -c 'from hashlib import sha256; from pathlib import Path; from kodesec_scanner.cache_manifest import collect_canonical_tree, load_tool_lock; root=Path("/usr/local/share/kodesec/canaries"); tools=load_tool_lock(Path("/usr/local/share/kodesec/locks/scanner-tools.lock.json")); canaries=[canary for tool in tools.value.tools for requirement in tool.requirements for canary in requirement.canaries]; assert all((collect_canonical_tree(root/c.fixture_path, require_immutable=True).sha256 if c.fixture_kind == "tree" else sha256((root/c.fixture_path).read_bytes()).hexdigest()) == c.fixture_sha256 for c in canaries)'; \
    python -m kodesec_scanner.verify_tools \
      --write /usr/local/share/kodesec/tool-manifest.json \
      --probe-timeout-seconds "${SCANNER_VERSION_PROBE_TIMEOUT_SECONDS}" \
      --platform "${SCANNER_BUILD_PLATFORM}"

# Retain exact upstream texts alongside the already pinned binary license metadata.
# This layer requires no acquisition and does not rebuild unchanged scanner tools.
COPY services/scanner/licenses /usr/local/share/kodesec/licenses
COPY services/scanner/scripts/verify-tool-licenses.py /tmp/verify-tool-licenses.py
RUN python /tmp/verify-tool-licenses.py \
      /usr/local/share/kodesec/locks/scanner-tools.lock.json \
      /usr/local/share/kodesec/licenses \
    && chown -R 0:0 /usr/local/share/kodesec/licenses \
    && find /usr/local/share/kodesec/licenses -type d -exec chmod 0555 {} + \
    && find /usr/local/share/kodesec/licenses -type f -exec chmod 0444 {} + \
    && rm /tmp/verify-tool-licenses.py

EXPOSE 8091
RUN install -d -o 1000 -g 1000 -m 0755 \
        /data \
        /data/artifacts \
        /run/kodesec-scratch \
    && install -d -o 1000 -g 1000 -m 0700 \
        /data/source-snapshots \
        /data/source-snapshots/generations \
        /data/tool-cache \
        /data/tool-cache/generations \
        /data/tool-cache/staging \
        /data/tool-cache/tombstones \
    && chown -R 1000:1000 /app
# Provenance changes must not force downloads of unchanged scanner binaries
# and dependencies. Every copied runtime input above still invalidates itself.
ARG KODESEC_SOURCE_COMMIT
ARG KODESEC_SOURCE_TREE
ARG KODESEC_SOURCE_KIND=git
ARG KODESEC_SOURCE_DIGEST=
RUN set -eu; \
    case "$KODESEC_SOURCE_KIND" in \
      git) \
        test -z "$KODESEC_SOURCE_DIGEST"; \
        test "${#KODESEC_SOURCE_COMMIT}" -eq 40; \
        test "${#KODESEC_SOURCE_TREE}" -eq 40; \
        case "${KODESEC_SOURCE_COMMIT}${KODESEC_SOURCE_TREE}" in *[!0-9a-f]*) exit 2 ;; esac ;; \
      source-sha256) \
        test -z "${KODESEC_SOURCE_COMMIT}${KODESEC_SOURCE_TREE}"; \
        test "${#KODESEC_SOURCE_DIGEST}" -eq 64; \
        case "$KODESEC_SOURCE_DIGEST" in *[!0-9a-f]*) exit 2 ;; esac ;; \
      *) exit 2 ;; \
    esac; \
    printf 'scanner:%s%s:%s%s\n' "$KODESEC_SOURCE_COMMIT" "${KODESEC_SOURCE_DIGEST:+source-sha256}" \
        "$KODESEC_SOURCE_TREE" "$KODESEC_SOURCE_DIGEST" > /usr/local/share/kodesec/build-identity; \
    chmod 0444 /usr/local/share/kodesec/build-identity
LABEL org.opencontainers.image.revision="${KODESEC_SOURCE_COMMIT}" \
      dev.lomo.kodesec.source-tree="${KODESEC_SOURCE_TREE}" \
      dev.lomo.kodesec.source-kind="${KODESEC_SOURCE_KIND}" \
      dev.lomo.kodesec.source-digest="${KODESEC_SOURCE_DIGEST}" \
      dev.lomo.kodesec.build-identity="scanner:${KODESEC_SOURCE_COMMIT}${KODESEC_SOURCE_DIGEST:+source-sha256}:${KODESEC_SOURCE_TREE}${KODESEC_SOURCE_DIGEST}"

USER kodesec

CMD ["uvicorn", "kodesec_scanner.main:app", "--host", "0.0.0.0", "--port", "8091"]
