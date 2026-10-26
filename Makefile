SHELL := /bin/sh
PYTHON ?= python3
REPO_ROOT := $(CURDIR)
TEST_VENV ?= $(REPO_ROOT)/.kodesec-test/test-venv
TEST_PYTHON := $(TEST_VENV)/bin/python
TEST_REQUIREMENTS := $(REPO_ROOT)/apps/api/requirements-test.txt
TEST_REQUIREMENTS_STAMP := $(TEST_VENV)/.requirements-test.stamp
PIP_CACHE_DIR ?= $(REPO_ROOT)/.kodesec-test/pip-cache
STATE_DIR ?= $(if $(XDG_STATE_HOME),$(XDG_STATE_HOME),$(HOME)/.local/state)/lomo-kodesec
RUNTIME_ENV ?= $(STATE_DIR)/runtime.env
COMPOSE := $(PYTHON) "$(REPO_ROOT)/scripts/runtime-compose.py" "$(RUNTIME_ENV)"
SOURCE_APPLY_WAIT_SECONDS ?= 120

.DEFAULT_GOAL := help


.PHONY: help init authorize-source apply-source authorize-advisor-host auth-info auth-reset apply-components up up-monitoring up-git-proxy up-db-admin up-full down restart logs support-bundle status ps api-shell db-shell test test-postgres lint api-requirements-lock api-requirements-lock-check scanner-requirements-lock docker-runtime-observation scanner-build-receipt trivy-db-lock-candidate trivy-java-db-lock-candidate grype-db-lock-candidate pull-service-images pull-tools bootstrap-gitea test-git-proxy demo-scan vscode-package vscode-install backup restore clean

help:
	@echo "Lomo CodeSecurity commands:"
	@echo "  make init           Generate owner-only runtime configuration"
	@echo "  make authorize-source  Authorize one exact narrow read-only source root"
	@echo "  make apply-source   Authorize one source root and recreate only source-bound services"
	@echo "  make authorize-advisor-host  Authorize one exact direct or pinned SSH Advisor route"
	@echo "  make auth-info      Show the local one-time browser bootstrap URL"
	@echo "  make auth-reset     Rotate the consumed browser bootstrap value"
	@echo "  make apply-components COMPONENTS=core|monitoring|git-proxy|db-admin|monitoring-git-proxy|monitoring-db-admin|git-proxy-db-admin|all"
	@echo "  make up             Start the core local stack"
	@echo "  make up-monitoring  Start core plus Prometheus and Grafana"
	@echo "  make up-git-proxy   Start core plus local Gitea Git proxy"
	@echo "  make up-db-admin    Start core plus Adminer Postgres UI"
	@echo "  make up-full        Start core plus monitoring and Git proxy"
	@echo "  make down           Stop the stack"
	@echo "  make logs           Follow service logs"
	@echo "  make support-bundle Collect private bounded diagnostics (no upload or restart)"
	@echo "  make lint           Run source checks"
	@echo "  make api-requirements-lock Regenerate hash-pinned production API dependencies"
	@echo "  make api-requirements-lock-check Verify production API dependency lock is current"
	@echo "  make scanner-requirements-lock Regenerate verified Linux scanner Python pins"
	@echo "  make docker-runtime-observation DOCKER_RUNTIME_OUTPUT_DIR=/absolute/new/path [exact Docker/Buildx inputs]"
	@echo "  make scanner-build-receipt SCANNER_BUILD_OUTPUT_DIR=/absolute/new/path"
	@echo "  make trivy-db-lock-candidate SCANNER_BUILD_RECEIPT=/absolute/path TRIVY_DB_CANDIDATE_OUTPUT_DIR=/absolute/new/path"
	@echo "  make trivy-java-db-lock-candidate SCANNER_BUILD_RECEIPT=/absolute/path TRIVY_JAVA_DB_SUPPORT_DIR=/absolute/current/db TRIVY_JAVA_DB_CANDIDATE_OUTPUT_DIR=/absolute/new/path"
	@echo "  make grype-db-lock-candidate SCANNER_BUILD_RECEIPT=/absolute/path GRYPE_DB_CANDIDATE_OUTPUT_DIR=/absolute/new/path"
	@echo "  make pull-service-images Pull optional Postgres/Gitea/monitoring images"
	@echo "  make bootstrap-gitea Create local test Git user/key"
	@echo "  make test-git-proxy Smoke-test Gitea over SSH"
	@echo "  make demo-scan      Register and scan the vulnerable demo app"
	@echo "  make vscode-package Build the reproducible local VS Code extension"
	@echo "  make vscode-install Build and install into the named VS Code profile"

init:
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/init-runtime.sh

authorize-source: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" \
	  KODESEC_SOURCE_ROOT_B64="$${KODESEC_SOURCE_ROOT_B64:-}" \
	  KODESEC_SOURCE_ROOTS_B64="$${KODESEC_SOURCE_ROOTS_B64:-}" \
	  KODESEC_SOURCE_APPLY="$(KODESEC_SOURCE_APPLY)" \
	  $(PYTHON) scripts/authorize-source.py

apply-source: KODESEC_SOURCE_APPLY := 1
apply-source: authorize-source
	$(COMPOSE) up -d --no-deps --no-build --force-recreate --wait \
	  --wait-timeout $(SOURCE_APPLY_WAIT_SECONDS) scanner
	$(COMPOSE) up -d --no-deps --no-build --force-recreate --wait \
	  --wait-timeout $(SOURCE_APPLY_WAIT_SECONDS) api
	$(COMPOSE) up -d --no-deps --no-build --force-recreate --wait \
	  --wait-timeout $(SOURCE_APPLY_WAIT_SECONDS) worker

authorize-advisor-host: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" \
	  $(PYTHON) scripts/authorize-advisor-host.py

auth-info: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/auth-info.sh

auth-reset: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/rotate-auth.sh

apply-components: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" \
	  KODESEC_COMPONENT_SET="$(COMPONENTS)" \
	  $(PYTHON) scripts/apply_components.py

up: init
	/bin/sh scripts/compose-build.sh $(COMPOSE) up -d --build postgres scanner scanner-updater advisor-connector worker api api-ingress

up-monitoring: init
	/bin/sh scripts/compose-build.sh $(COMPOSE) --profile monitoring up -d --build

up-git-proxy: init
	/bin/sh scripts/compose-build.sh $(COMPOSE) --profile git-proxy up -d --build

up-db-admin: init
	/bin/sh scripts/compose-build.sh $(COMPOSE) --profile db-admin up -d --build

up-full: init
	/bin/sh scripts/compose-build.sh $(COMPOSE) --profile monitoring --profile git-proxy up -d --build

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f --tail=200

support-bundle:
	@$(PYTHON) scripts/support_bundle.py --runtime-env "$(RUNTIME_ENV)" $(if $(filter 1,$(SUPPORT_LOG_TEXT)),--include-log-text,)

status ps:
	$(COMPOSE) ps

api-shell:
	$(COMPOSE) exec api sh

db-shell:
	$(COMPOSE) exec postgres psql -U "$${POSTGRES_USER:-kodesec}" "$${POSTGRES_DB:-kodesec}"

$(TEST_REQUIREMENTS_STAMP): $(TEST_REQUIREMENTS)
	$(PYTHON) -c 'import sys; sys.exit("Python 3.12 or newer is required") if sys.version_info < (3, 12) else None'
	$(PYTHON) -m venv "$(TEST_VENV)"
	PIP_CACHE_DIR="$(PIP_CACHE_DIR)" "$(TEST_PYTHON)" -m pip install --disable-pip-version-check --require-hashes -r "$(TEST_REQUIREMENTS)"
	@touch "$@"

test: $(TEST_REQUIREMENTS_STAMP)
	$(PYTHON) -m compileall apps/api/kodesec_api services/scanner/kodesec_scanner scripts/apply_components.py scripts/source_provenance.py scripts/docker_runtime_contract.py scripts/docker-runtime-observation.py scripts/scanner-build-receipt.py scripts/trivy-db-lock-candidate.py scripts/grype-db-lock-candidate.py
	cd apps/api && env -i \
	  HOME="$${HOME}" USER="$${USER}" LOGNAME="$${LOGNAME:-$${USER}}" \
	  PATH="$${PATH}" TMPDIR="$${TMPDIR:-/tmp}" \
	  "$(TEST_PYTHON)" -m pytest -q tests
	cd services/scanner && "$(TEST_PYTHON)" -m pytest -q tests
	cd apps/web && npm ci --ignore-scripts && npm run build
	cd extensions/vscode && npm ci --ignore-scripts && npm run test:unit
	cd tests/playwright && npm ci --ignore-scripts && npm run test:compose:check

.PHONY: test-public
test-public: test

test-postgres: $(TEST_REQUIREMENTS_STAMP)
	@test -n "$${KODESEC_TEST_DATABASE_URL:-}" || (echo "KODESEC_TEST_DATABASE_URL is required and must name an isolated PostgreSQL database" >&2; exit 2)
	cd apps/api && KODESEC_TEST_DATABASE_URL="$${KODESEC_TEST_DATABASE_URL}" "$(TEST_PYTHON)" -m pytest -q tests

lint:
	$(PYTHON) -m compileall apps/api/kodesec_api services/scanner/kodesec_scanner scripts/apply_components.py scripts/source_provenance.py scripts/docker_runtime_contract.py scripts/docker-runtime-observation.py scripts/scanner-build-receipt.py scripts/trivy-db-lock-candidate.py scripts/grype-db-lock-candidate.py
	cd apps/web && npm run typecheck

api-requirements-lock:
	@set -eu; \
	  lock_tmp="$$(mktemp -d)"; \
	  trap 'rm -rf "$$lock_tmp"' EXIT HUP INT TERM; \
	  for api_platform in x86_64-manylinux2014 aarch64-manylinux2014; do \
	    UV_CACHE_DIR="$(PIP_CACHE_DIR)/uv" uv pip compile \
	      apps/api/pyproject.toml apps/api/build-requirements.in \
	      --python-version 3.12 --python-platform "$$api_platform" \
	      --generate-hashes --no-emit-package kodesec-api \
	      --custom-compile-command 'make api-requirements-lock' \
	      --output-file "$$lock_tmp/$$api_platform.lock" --quiet; \
	  done; \
	  cmp "$$lock_tmp/x86_64-manylinux2014.lock" \
	      "$$lock_tmp/aarch64-manylinux2014.lock"; \
	  cp "$$lock_tmp/x86_64-manylinux2014.lock" \
	      apps/api/requirements-production.lock

api-requirements-lock-check:
	@set -eu; \
	  lock_tmp="$$(mktemp -d)"; \
	  trap 'rm -rf "$$lock_tmp"' EXIT HUP INT TERM; \
	  for api_platform in x86_64-manylinux2014 aarch64-manylinux2014; do \
	    UV_CACHE_DIR="$(PIP_CACHE_DIR)/uv" uv pip compile \
	      apps/api/pyproject.toml apps/api/build-requirements.in \
	      --python-version 3.12 --python-platform "$$api_platform" \
	      --generate-hashes --no-emit-package kodesec-api \
	      --custom-compile-command 'make api-requirements-lock' \
	      --output-file "$$lock_tmp/$$api_platform.lock" --quiet; \
	  done; \
	  cmp "$$lock_tmp/x86_64-manylinux2014.lock" \
	      "$$lock_tmp/aarch64-manylinux2014.lock"; \
	  cmp "$$lock_tmp/x86_64-manylinux2014.lock" \
	      apps/api/requirements-production.lock

scanner-requirements-lock:
	@set -eu; \
	  lock_tmp="$$(mktemp -d)"; \
	  trap 'rm -rf "$$lock_tmp"' EXIT HUP INT TERM; \
	  for scanner_platform in x86_64-manylinux2014 aarch64-manylinux2014; do \
	    UV_CACHE_DIR="$(PIP_CACHE_DIR)/uv" uv pip compile \
	      services/scanner/pyproject.toml services/scanner/build-requirements.in \
	      --python-version 3.12 --python-platform "$$scanner_platform" \
	      --generate-hashes --no-emit-package kodesec-scanner \
	      --no-emit-package checkov \
	      --custom-compile-command 'make scanner-requirements-lock' \
	      --output-file "$$lock_tmp/$$scanner_platform.lock" --quiet; \
	  done; \
	  cmp "$$lock_tmp/x86_64-manylinux2014.lock" \
	      "$$lock_tmp/aarch64-manylinux2014.lock"; \
	  cp "$$lock_tmp/x86_64-manylinux2014.lock" \
	      services/scanner/build-requirements.lock

docker-runtime-observation:
	@test -n "$(DOCKER_RUNTIME_OUTPUT_DIR)" || (echo "DOCKER_RUNTIME_OUTPUT_DIR is required" >&2; exit 2)
	@test -n "$(DOCKER_EXECUTABLE)" -a -n "$(DOCKER_SHA256)" -a -n "$(BUILDX_EXECUTABLE)" -a -n "$(BUILDX_SHA256)" -a -n "$(DOCKER_HOST)" || (echo "exact DOCKER_EXECUTABLE/DOCKER_SHA256/BUILDX_EXECUTABLE/BUILDX_SHA256/DOCKER_HOST are required" >&2; exit 2)
	@$(PYTHON) scripts/docker-runtime-observation.py \
	  --output-dir "$(DOCKER_RUNTIME_OUTPUT_DIR)" \
	  --docker-executable "$(DOCKER_EXECUTABLE)" \
	  --docker-sha256 "$(DOCKER_SHA256)" \
	  --buildx-executable "$(BUILDX_EXECUTABLE)" \
	  --buildx-sha256 "$(BUILDX_SHA256)" \
	  --docker-host "$(DOCKER_HOST)"

scanner-build-receipt:
	@test -n "$(SCANNER_BUILD_OUTPUT_DIR)" || (echo "SCANNER_BUILD_OUTPUT_DIR is required and must be a new absolute path below an owner-only mode-0700 parent" >&2; exit 2)
	@test -n "$(DOCKER_RUNTIME_OBSERVATION)" || (echo "DOCKER_RUNTIME_OBSERVATION is required" >&2; exit 2)
	@$(PYTHON) scripts/scanner-build-receipt.py \
	  --output-dir "$(SCANNER_BUILD_OUTPUT_DIR)" \
	  --runtime-observation "$(DOCKER_RUNTIME_OBSERVATION)"

trivy-db-lock-candidate:
	@test -n "$(SCANNER_BUILD_RECEIPT)" || (echo "SCANNER_BUILD_RECEIPT is required" >&2; exit 2)
	@test -n "$(TRIVY_DB_CANDIDATE_OUTPUT_DIR)" || (echo "TRIVY_DB_CANDIDATE_OUTPUT_DIR is required and must be a new absolute path below an owner-only mode-0700 parent" >&2; exit 2)
	@$(PYTHON) scripts/trivy-db-lock-candidate.py \
	  --build-receipt "$(SCANNER_BUILD_RECEIPT)" \
	  --output-dir "$(TRIVY_DB_CANDIDATE_OUTPUT_DIR)"

trivy-java-db-lock-candidate:
	@test -n "$(SCANNER_BUILD_RECEIPT)" || (echo "SCANNER_BUILD_RECEIPT is required" >&2; exit 2)
	@test -n "$(TRIVY_JAVA_DB_SUPPORT_DIR)" || (echo "TRIVY_JAVA_DB_SUPPORT_DIR is required and must be the immutable current-lock Trivy OS DB directory" >&2; exit 2)
	@test -n "$(TRIVY_JAVA_DB_CANDIDATE_OUTPUT_DIR)" || (echo "TRIVY_JAVA_DB_CANDIDATE_OUTPUT_DIR is required and must be a new absolute path below an owner-only mode-0700 parent" >&2; exit 2)
	@$(PYTHON) scripts/trivy-db-lock-candidate.py \
	  --component-id trivy-java-db \
	  --support-trivy-db "$(TRIVY_JAVA_DB_SUPPORT_DIR)" \
	  --build-receipt "$(SCANNER_BUILD_RECEIPT)" \
	  --output-dir "$(TRIVY_JAVA_DB_CANDIDATE_OUTPUT_DIR)"

grype-db-lock-candidate:
	@test -n "$(SCANNER_BUILD_RECEIPT)" || (echo "SCANNER_BUILD_RECEIPT is required" >&2; exit 2)
	@test -n "$(GRYPE_DB_CANDIDATE_OUTPUT_DIR)" || (echo "GRYPE_DB_CANDIDATE_OUTPUT_DIR is required and must be a new absolute path below an owner-only mode-0700 parent" >&2; exit 2)
	@$(PYTHON) scripts/grype-db-lock-candidate.py \
	  --build-receipt "$(SCANNER_BUILD_RECEIPT)" \
	  --output-dir "$(GRYPE_DB_CANDIDATE_OUTPUT_DIR)"

pull-service-images:
	$(COMPOSE) pull postgres gitea prometheus grafana

pull-tools:
	@echo "'make pull-tools' never updated scanner binaries or offline data and has been removed." >&2
	@echo "Use 'make pull-service-images' for service images; use the explicit scanner lifecycle commands for scanner updates." >&2
	@exit 2

bootstrap-gitea: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/bootstrap-gitea.sh

test-git-proxy: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/bootstrap-gitea.sh --smoke

demo-scan: init
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/bash scripts/demo-scan.sh

vscode-package:
	cd extensions/vscode && npm ci --ignore-scripts && npm run package

vscode-install: vscode-package
	node extensions/vscode/scripts/install.mjs

backup:
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/backup.sh

restore:
	@KODESEC_STATE_DIR="$(STATE_DIR)" KODESEC_RUNTIME_ENV="$(RUNTIME_ENV)" /bin/sh scripts/restore.sh "$(BACKUP_DIR)"

clean:
	$(COMPOSE) down --remove-orphans
