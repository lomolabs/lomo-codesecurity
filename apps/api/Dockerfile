FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS web-build

WORKDIR /web

COPY apps/web/package.json apps/web/package-lock.json apps/web/tsconfig.json apps/web/tsconfig.node.json apps/web/vite.config.ts apps/web/index.html ./
RUN npm ci

COPY apps/web/public ./public
COPY apps/web/src ./src
RUN npm run build

FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 kodesec && useradd --uid 1000 --gid kodesec --home-dir /app --shell /usr/sbin/nologin kodesec

COPY apps/api/requirements-production.lock ./requirements-production.lock
RUN pip install --disable-pip-version-check --only-binary=:all: \
        --require-hashes -r requirements-production.lock

COPY apps/api/pyproject.toml ./
COPY apps/api/kodesec_api ./kodesec_api
COPY services/advisor_connector ./advisor_connector
COPY --from=web-build /web/dist ./static
COPY apps/api/normalize-runtime-payload.sh /tmp/normalize-runtime-payload.sh

RUN pip install --disable-pip-version-check --no-build-isolation --no-deps .

# A user clone may intentionally use umask 077. Docker preserves those source
# modes, so normalize only the immutable runtime payload before USER kodesec.
RUN /bin/sh /tmp/normalize-runtime-payload.sh /app \
    && rm -f /tmp/normalize-runtime-payload.sh

# Docker initializes a fresh named volume from the first container image that
# mounts it. Keep the native-Windows snapshot volume private and writable by
# the shared non-root runtime UID even when scanner starts before the API.
RUN install -d -o 1000 -g 1000 -m 0755 /data \
    && install -d -o 1000 -g 1000 -m 0700 \
        /data/source-snapshots \
        /data/source-snapshots/generations

# Bind the final image without invalidating unchanged dependency layers for
# every source commit. The source inputs above still own their build cache.
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
    esac
LABEL org.opencontainers.image.revision="${KODESEC_SOURCE_COMMIT}" \
      dev.lomo.kodesec.source-tree="${KODESEC_SOURCE_TREE}" \
      dev.lomo.kodesec.source-kind="${KODESEC_SOURCE_KIND}" \
      dev.lomo.kodesec.source-digest="${KODESEC_SOURCE_DIGEST}" \
      dev.lomo.kodesec.build-identity="control:${KODESEC_SOURCE_COMMIT}${KODESEC_SOURCE_DIGEST:+source-sha256}:${KODESEC_SOURCE_TREE}${KODESEC_SOURCE_DIGEST}"

EXPOSE 8080
USER kodesec

# Event streams can remain open indefinitely. Drain active requests briefly,
# then cancel them so application lifespan cleanup runs before Docker's 10s stop.
CMD ["uvicorn", "kodesec_api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--timeout-graceful-shutdown", "5"]
