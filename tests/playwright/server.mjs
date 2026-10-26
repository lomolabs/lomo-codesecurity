import { createReadStream, existsSync, statSync } from 'node:fs';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, '..', '..', 'apps', 'web', 'dist');
const port = Number.parseInt(process.env.KODESEC_PLAYWRIGHT_PORT || '41783', 10);
const origin = `http://127.0.0.1:${port}`;
const advisorFixtureUrl = 'http://127.0.0.1:11434';
const advisorDisclosureCategories = [
  'finding_identity',
  'source_location',
  'repository_context',
  'bounded_code_snippet',
  'bounded_scanner_metadata',
];
const advisorDisclosureSigningKey = randomBytes(32);
const advisorDisclosureSigningPurpose = 'lomo-kodesec:advisor-disclosure-confirmation:v1\0';
if (!existsSync(resolve(dist, 'index.html'))) throw new Error(`Missing production bundle: ${dist}`);

const time = {
  created: '2026-08-12T08:00:00Z',
  started: '2026-08-12T08:00:01Z',
  completed: '2026-08-12T08:00:03Z',
  updated: '2026-08-12T08:00:04Z',
};

function advisorProviderConfigDigest(provider) {
  const projection = {
    base_url: provider.base_url,
    enabled: provider.enabled,
    id: provider.id,
    model: provider.model,
    model_digest: provider.model_digest,
    name: provider.name,
    priority: provider.priority,
    ssh_host: provider.ssh_host,
    ssh_port: provider.ssh_port,
    ssh_user: provider.ssh_user,
    transport: provider.transport,
  };
  return createHash('sha256').update(JSON.stringify(projection)).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizeSafeAdvisorIpv4(value) {
  const candidate = typeof value === 'string' ? value.trim().replace(/\.+$/u, '') : '';
  const parts = candidate.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some((octet) => octet > 255)) return null;
  if (octets.every((octet) => octet === 0)
    || octets[0] === 127
    || (octets[0] === 169 && octets[1] === 254)
    || octets[0] >= 224) return null;
  return octets.join('.');
}

function normalizeExactDirectAdvisorUrl(value) {
  const candidate = typeof value === 'string' ? value.trim().replace(/\/+$/u, '') : '';
  if (candidate.length === 0 || candidate.length > 500) return null;
  const match = /^http:\/\/([^/:?#]+):11434$/iu.exec(candidate);
  const host = match ? normalizeSafeAdvisorIpv4(match[1]) : null;
  return host ? `http://${host}:11434` : null;
}

const findingsScaleCounts = Object.freeze({
  'findings-scale-1000': 1_000,
  'findings-scale-5000': 5_000,
  'findings-scale-10000': 10_000,
});

function buildFixture(profile = 'fresh', generation = 1) {
  const project = profile === 'first-run' ? null : {
    id: 11,
    name: profile === 'responsive-long-content' ? `Project${'x'.repeat(113)}`
      : profile === 'persistent' ? 'Persistent Generated Workspace' : 'Generated Demo Service',
    repo_path: '/workspace/generated/demo-service',
    remote_url: '',
    default_branch: 'main',
    revision: 1,
    created_at: time.created,
  };
  const scans = [
    {
      id: 41, project_id: 11, mode: 'full', status: 'completed', gate_decision: 'fail',
      gate_reasons: ['One generated high-severity result exceeds the fixture policy.'],
      scanner_summary: { findings_total: 3 }, created_at: time.created, started_at: time.started,
      completed_at: time.completed, duration_ms: 1420,
    },
    {
      id: 40, project_id: 11, mode: 'incremental_diff', base_ref: 'main', head_ref: 'fixture-change',
      status: 'partial', gate_decision: 'incomplete',
      gate_reasons: ['A generated optional scanner result was incomplete.'],
      scanner_summary: { findings_total: 1 }, error: 'Generated partial-result fixture.',
      created_at: time.created, started_at: time.started, completed_at: time.completed, duration_ms: 980,
    },
    {
      id: 39, project_id: 11, mode: 'full', status: 'running', gate_decision: 'pending', gate_reasons: [],
      scanner_summary: { findings_total: 0 }, created_at: time.created, started_at: time.started,
    },
  ];
  const findings = [
    {
      id: 501, scan_id: 41, scan_finding_number: 1, display_id: 'S41-F001', scanner: 'opengrep',
      rule_id: 'javascript.lang.audit.dynamic-code', severity: 'high', file_path: 'src/handler.ts',
      start_line: 12, end_line: 12, message: 'Dynamic code execution can consume untrusted input.',
      code_snippet: 'export function handle(userInput: string) {\n  const normalized = userInput.trim();\n  return eval(normalized);\n}',
      fingerprint: 'fixture-fingerprint-001', metadata_json: { snippet_start_line: 10 }, suppressed: false,
      lifecycle_status: 'open', gate_exempt: false, occurrence_count: 1, is_repeat: false,
      ai_verdict: 'true_positive', ai_confidence: 0.91,
      ai_reasoning: 'Generated local review preserves scanner evidence and does not change the gate.',
      ai_fix: 'Validate the input against an allowlist before using the dynamic-code sink.',
      created_at: time.created,
    },
    {
      id: 502, scan_id: 41, scan_finding_number: 2, display_id: 'S41-F002', scanner: 'checkov',
      rule_id: 'CKV_FIXTURE_RESOURCE_LIMIT', severity: 'medium', file_path: 'infra/service.yaml',
      start_line: 18, end_line: 20, message: 'Generated workload should define explicit resource limits.',
      code_snippet: 'resources:\n  requests:\n    cpu: 100m\n', fingerprint: 'fixture-fingerprint-002',
      metadata_json: { snippet_start_line: 18 }, suppressed: false, lifecycle_status: 'gate_exempt',
      gate_exempt: true, gate_exempt_reason: 'Generated fixture review decision.', occurrence_count: 2,
      is_repeat: true, first_seen_display_id: 'S40-F001', created_at: time.created,
    },
    {
      id: 503, scan_id: 41, scan_finding_number: 3, display_id: 'S41-F003', scanner: 'trivy',
      rule_id: 'FIXTURE-PACKAGE-METADATA', severity: 'info', file_path: 'package.json', start_line: 4,
      end_line: 4, message: 'Generated package metadata is intentionally incomplete.',
      code_snippet: '{\n  "name": "generated-demo",\n  "private": true\n}', fingerprint: 'fixture-fingerprint-003',
      metadata_json: { snippet_start_line: 2 }, suppressed: true,
      suppression_reason: 'Generated false-positive fixture.', lifecycle_status: 'false_positive', gate_exempt: false,
      occurrence_count: 1, is_repeat: false, created_at: time.created,
    },
  ];
  if (profile === 'focus') {
    findings.push(...Array.from({ length: 11 }, (_, offset) => {
      const findingNumber = offset + 4;
      const line = 30 + findingNumber;
      const snippetStart = line - 20;
      const codeSnippet = Array.from({ length: 41 }, (_value, snippetOffset) => {
        const sourceLine = snippetStart + snippetOffset;
        return sourceLine === line
          ? '  return unsafeSink(generatedInput);'
          : `  const generatedContext${sourceLine} = ${sourceLine};`;
      }).join('\n');
      return {
        id: 500 + findingNumber,
        scan_id: 41,
        scan_finding_number: findingNumber,
        display_id: `S41-F${String(findingNumber).padStart(3, '0')}`,
        scanner: 'opengrep',
        rule_id: `fixture.exact-offender-${findingNumber}`,
        severity: 'low',
        file_path: `src/generated-${findingNumber}.ts`,
        start_line: line,
        end_line: line,
        message: `Generated focus fixture ${findingNumber}.`,
        code_snippet: codeSnippet,
        fingerprint: `fixture-focus-${findingNumber}`,
        metadata_json: { snippet_start_line: snippetStart },
        suppressed: false,
        lifecycle_status: 'open',
        gate_exempt: false,
        occurrence_count: 1,
        is_repeat: false,
        created_at: time.created,
      };
    }));
  }
  if (profile === 'findings-first-viewport') {
    findings[0] = {
      ...findings[0],
      start_line: 9,
      end_line: 9,
      message: 'A sensitive value can reach this dynamic execution path. Review the highlighted source and the surrounding validation before changing the finding lifecycle.',
      code_snippet: Array.from({ length: 23 }, (_, index) => index === 8
        ? '  return eval(generatedInput);'
        : `  const context${index + 1} = ${index + 1};`).join('\n'),
      metadata_json: { snippet_start_line: 1 },
      occurrence_count: 3,
      is_repeat: true,
      first_seen_display_id: 'S40-F001',
    };
  }
  if (profile === 'advisor-evidence') {
    findings[0] = {
      ...findings[0],
      file_path: 'src/<hostile>&evidence.ts',
      start_line: 12,
      end_line: 14,
      code_snippet: [
        'const before = "<script>not markup</script>";\r',
        'unsafeSink(first);\r',
        '\r',
        'unsafeSink(last);\r',
        '',
      ].join('\n'),
      metadata_json: { snippet_start_line: 11 },
      ai_verdict: 'needs_review',
      ai_confidence: 0.875,
      ai_reasoning: '<img src=x onerror="globalThis.__advisorXss=true">\n' + 'Long local explanation. '.repeat(260),
      ai_fix: '',
    };
  }
  if (profile === 'advisor-failure') {
    scans[0] = {
      ...scans[0],
      scanner_summary: {
        findings_total: 3,
        advisor: {
          status: 'failed',
          error_code: 'advisor_unavailable',
          detail: 'Optional local advisor failed; scanner evidence and deterministic gate remain available.',
        },
      },
    };
  }
  if (profile === 'evidence-edges') {
    findings[0] = {
      ...findings[0],
      start_line: 900,
      end_line: 900,
      code_snippet: 'const first = 1;\nconst second = 2;',
      metadata_json: { snippet_start_line: 1 },
    };
    findings[1] = {
      ...findings[1],
      code_snippet: '',
    };
  }
  if (profile === 'scan-state-edges') {
    scans.push({
      id: 38, project_id: 11, mode: 'full', status: 'failed', gate_decision: 'incomplete',
      gate_reasons: ['The generated scanner process failed before it published evidence.'],
      scanner_summary: { findings_total: 0 }, error: 'Generated failed-result fixture.',
      created_at: time.created, started_at: time.started, completed_at: time.completed, duration_ms: 410,
    });
    scans[1] = {
      ...scans[1], status: 'cancelled', gate_decision: 'incomplete',
      gate_reasons: ['The generated scanner run was cancelled before all required stages completed.'],
      scanner_summary: {
        findings_total: 1,
        requested_mode: 'incremental_diff',
        effective_mode: 'full',
        warnings: ['incremental-diff-fallback-full'],
      },
      error: 'Generated cancelled-result fixture.',
    };
    scans[2] = {
      ...scans[2], status: 'analyzing', gate_decision: 'pending',
      scanner_summary: { findings_total: 1 },
    };
    findings[1] = {
      ...findings[1], scan_id: 40, scan_finding_number: 1, display_id: 'S40-F001',
    };
  }
  if (profile === 'advisor-running' || profile === 'scan-state-edges') {
    findings[0] = {
      ...findings[0],
      scan_id: 39,
      display_id: 'S39-F001',
      ai_verdict: undefined,
      ai_confidence: undefined,
      ai_reasoning: undefined,
      ai_fix: undefined,
    };
  }
  if (profile === 'large-findings' || profile === 'paginated-findings' || Object.hasOwn(findingsScaleCounts, profile)) {
    const findingCount = Object.hasOwn(findingsScaleCounts, profile) ? findingsScaleCounts[profile]
      : profile === 'paginated-findings' ? 460 : 10_005;
    findings.splice(0, findings.length, ...Array.from({ length: findingCount }, (_value, index) => {
      const findingNumber = index + 1;
      const line = findingNumber + 20;
      return {
        id: 20_000 + findingNumber,
        scan_id: 41,
        scan_finding_number: findingNumber,
        display_id: `S41-F${String(findingNumber).padStart(3, '0')}`,
        scanner: findingNumber % 2 === 0 ? 'checkov' : 'opengrep',
        rule_id: `fixture.large-result-${findingNumber}`,
        severity: findingNumber === 1 ? 'high' : 'low',
        file_path: `src/generated/batch-${Math.ceil(findingNumber / 100)}.ts`,
        start_line: line,
        end_line: line,
        message: `Generated large-result finding ${findingNumber}.`,
        code_snippet: findingNumber === 250
          ? `const generated${line} = input;\nunsafeSink(generated${line});`
          : null,
        fingerprint: `fixture-large-${findingNumber}`,
        metadata_json: findingNumber === 250 ? { snippet_start_line: line } : {},
        suppressed: false,
        lifecycle_status: 'open',
        gate_exempt: false,
        occurrence_count: 1,
        is_repeat: false,
        created_at: time.created,
      };
    }));
    scans[0] = {
      ...scans[0],
      scanner_summary: {
        findings_total: findings.length,
        severity_counts: { high: 1, low: findings.length - 1 },
        scanner_counts: Object.hasOwn(findingsScaleCounts, profile)
          ? { opengrep: Math.ceil(findingCount / 2), checkov: Math.floor(findingCount / 2) }
          : { opengrep: 5_003, checkov: 5_002 },
        ignored_count: 0,
        gate_exempt_count: 0,
      },
    };
  }
  scans.forEach((scan) => {
    scan.base_ref ??= null;
    scan.head_ref ??= null;
    scan.error ??= null;
    scan.started_at ??= null;
    scan.completed_at ??= null;
    scan.duration_ms ??= null;
    scan.revision ??= 1;
    scan.findings_revision ??= 1;
    scan.job_id ??= null;
    scan.job_revision ??= null;
  });
  findings.forEach((finding) => {
    finding.start_column ??= null;
    finding.end_column ??= null;
    finding.code_snippet ??= null;
    finding.metadata_json ??= {};
    finding.ai_verdict ??= null;
    finding.ai_confidence ??= null;
    finding.ai_reasoning ??= null;
    finding.ai_fix ??= null;
    finding.suppression_reason ??= null;
    finding.gate_exempt_reason ??= null;
    finding.lifecycle_reason ??= null;
    finding.lifecycle_updated_at ??= null;
    finding.first_seen_scan_id ??= null;
    finding.first_seen_display_id ??= null;
    finding.revision ??= 1;
    finding.gate_effect ??= finding.suppressed ? 'excluded' : finding.gate_exempt ? 'non_blocking' : 'blocking';
  });
  const artifacts = [
    { id: 301, scan_id: 41, scanner: 'syft', artifact_type: 'sbom', format: 'cyclonedx-json', path: '/artifacts/generated/syft.cyclonedx.json', size_bytes: 4096, sha256: 'generated-digest-301', created_at: time.completed },
  ];
  if (profile === 'responsive-long-content') {
    artifacts[0] = {
      ...artifacts[0],
      scanner: 'syft-security-bom-generator-with-an-intentionally-long-operator-visible-identity',
      artifact_type: 'software-bill-of-materials-with-an-intentionally-long-type-identity',
      format: 'cyclonedx-json-with-an-intentionally-long-format-identity',
    };
  }
  if (profile === 'scan-state-edges') artifacts[0] = { ...artifacts[0], scan_id: 40 };
  const jobs = [
    { id: 81, kind: 'scan', title: 'Scan #41', status: 'completed', stage: 'completed', detail: 'Generated scan completed with three findings.', progress: 100, scan_id: 41, attempt: 1, max_attempts: 3, revision: 4, can_cancel: false, created_at: time.created, started_at: time.started, completed_at: time.completed, updated_at: time.updated },
    { id: 82, kind: 'advisor', title: 'Advisor triage', status: 'failed', stage: 'unavailable', detail: 'Generated advisor fixture is unavailable; scanner evidence is preserved.', progress: 100, scan_id: 41, finding_id: 501, finding_display_id: 'S41-F001', finding_scan_number: 1, finding_rule_id: 'javascript.lang.audit.dynamic-code', error_code: 'advisor_unavailable', error_detail: 'Generated local advisor is unavailable.', attempt: 3, max_attempts: 3, revision: 6, can_cancel: false, can_retry: true, created_at: time.created, started_at: time.started, completed_at: time.completed, updated_at: time.updated },
    { id: 83, kind: 'scan', title: 'Scan #39', status: 'running', stage: 'normalizing', detail: 'Generated running-state fixture.', progress: 62, scan_id: 39, attempt: 1, max_attempts: 3, revision: 3, can_cancel: true, created_at: time.created, started_at: time.started, updated_at: time.updated },
  ];
  if (profile === 'large-findings' || profile === 'paginated-findings' || Object.hasOwn(findingsScaleCounts, profile)) {
    scans[2] = {
      ...scans[2],
      status: 'completed',
      gate_decision: 'pass',
      completed_at: time.completed,
      duration_ms: 600,
    };
    jobs[2] = {
      ...jobs[2],
      status: 'completed',
      stage: 'completed',
      detail: 'Generated large-result companion scan is complete.',
      progress: 100,
      can_cancel: false,
      completed_at: time.completed,
      revision: 4,
    };
  }
  if (profile === 'quiescent') {
    scans[2] = {
      ...scans[2],
      status: 'completed',
      gate_decision: 'pass',
      gate_reasons: [],
      completed_at: time.completed,
      duration_ms: 640,
      revision: scans[2].revision + 1,
    };
    jobs[2] = {
      ...jobs[2],
      status: 'completed',
      stage: 'completed',
      detail: 'Generated quiescent scan completed and released its durable lease.',
      progress: 100,
      can_cancel: false,
      completed_at: time.completed,
      revision: jobs[2].revision + 1,
    };
  }
  if (profile === 'durable') {
    jobs.splice(0, jobs.length,
      { id: 90, kind: 'scan', title: 'Queued scan', status: 'queued', stage: 'queued', detail: 'Persisted and waiting for an available worker.', progress: 0, scan_id: 39, attempt: 0, max_attempts: 3, revision: 1, can_cancel: true, created_at: time.created, updated_at: time.updated },
      { id: 91, kind: 'advisor', title: 'Leased advisor', status: 'leased', stage: 'claimed', detail: 'Claimed by a worker; execution has not started.', progress: 4, scan_id: 41, finding_id: 501, finding_display_id: 'S41-F001', finding_scan_number: 1, finding_rule_id: 'javascript.lang.audit.dynamic-code', attempt: 1, max_attempts: 3, revision: 2, can_cancel: true, created_at: time.created, updated_at: time.updated },
      { id: 92, kind: 'scan', title: 'Running scan cancellation fixture', status: 'running', stage: 'scanner', detail: 'Running a stable scanner operation.', progress: 47, scan_id: 39, attempt: 1, max_attempts: 3, revision: 3, can_cancel: true, created_at: time.created, started_at: time.started, updated_at: time.updated },
      { id: 93, kind: 'advisor', title: 'Cancelling advisor', status: 'cancelling', stage: 'cancelling', detail: 'Cancellation persisted; waiting for cleanup confirmation.', progress: 61, scan_id: 41, attempt: 1, max_attempts: 3, revision: 4, can_cancel: false, cancel_requested_at: time.updated, created_at: time.created, started_at: time.started, updated_at: time.updated },
      { id: 94, kind: 'scan', title: 'Cancelled scan', status: 'cancelled', stage: 'cancelled', detail: 'Temporary output was removed; prior published evidence remains available.', progress: 36, scan_id: 40, attempt: 1, max_attempts: 3, revision: 5, can_cancel: false, cancel_requested_at: time.started, created_at: time.created, started_at: time.started, completed_at: time.completed, updated_at: time.updated },
      jobs[0],
      jobs[1],
    );
  }
  if (profile === 'focus') {
    jobs.push({
      id: 84, kind: 'advisor', title: 'Exact offender navigation', status: 'completed', stage: 'completed',
      detail: 'Generated deep-link focus fixture.', progress: 100, scan_id: 41, finding_id: 514,
      finding_display_id: 'S41-F014', finding_scan_number: 14, finding_rule_id: 'fixture.exact-offender-14',
      created_at: time.created, started_at: time.started, completed_at: time.completed, updated_at: time.updated,
    });
  }
  const facet = (state, reason = null, componentIds = []) => ({ state, reason, component_ids: componentIds });
  const tool = (id, name, source, status, update, findingsCount) => ({
    id, name, category: id.includes('grep') ? 'sast' : 'iac', lifecycle: source === 'external' ? 'external' : 'internal-lite',
    source, output_format: source === 'external' ? 'sarif' : 'normalized',
    description: `Generated ${name} fixture for deterministic browser tests.`, enabled: source === 'external',
    current_version: 'fixture-1', latest_version: update ? 'fixture-2' : 'fixture-1', installed_version: 'fixture-1',
    available: true, pinned_version: null, status, update_available: update, findings_count: findingsCount,
    artifacts_count: findingsCount, last_checked_at: time.updated, updated_at: time.updated,
    runtime_ready: true,
    readiness: {
      binary: facet('ready'),
      data: facet(source === 'internal' || id === 'checkov' || id === 'opengrep' ? 'not_required' : 'ready'),
      rules: facet(id === 'opengrep' ? 'ready' : 'not_required', null, id === 'opengrep' ? ['opengrep-reviewed-rules'] : []),
      execution: facet('ready'),
    },
  });
  const tools = [
    tool('opengrep', 'OpenGrep', 'external', 'ready', false, 1),
    {
      ...tool('checkov', 'Checkov', 'external', 'update_available', true, 1),
      candidate_release_id: 'checkov-fixture-2',
      candidate_manifest_sha256: 'a'.repeat(64),
    },
    tool('iac-lite', 'Internal IaC Lite', 'internal', 'disabled', false, 0),
  ];
  if (profile === 'first-run') {
    // Exercise admission with the complete external-tool catalog. Only the
    // OpenGrep rules are pending in this generated setup scenario.
    tools.push(
      ...[
        ['trivy', 'Trivy', 'sca', ['trivy-db', 'trivy-java-db', 'trivy-checks'], []],
        ['gitleaks', 'Gitleaks', 'secrets', [], []],
        ['bearer', 'Bearer', 'sast', [], ['bearer-rules']],
        ['grype', 'Grype', 'sca', ['grype-db'], []],
        ['trufflehog', 'TruffleHog', 'secrets', [], []],
        ['syft', 'Syft', 'sbom', [], []],
      ].map(([id, name, category, dataComponents, ruleComponents]) => ({
        ...tool(id, name, 'external', 'ready', false, 0),
        category,
        output_format: id === 'syft' ? 'cyclonedx-json' : id === 'trufflehog' ? 'jsonl' : id === 'bearer' ? 'jsonv2' : 'sarif',
        readiness: {
          binary: facet('ready'),
          data: facet(dataComponents.length ? 'ready' : 'not_required', null, dataComponents),
          rules: facet(ruleComponents.length ? 'ready' : 'not_required', null, ruleComponents),
          execution: facet('ready'),
        },
      })),
    );
  }
  if (profile === 'scanner-lock-refresh') {
    const grype = tool('grype', 'Grype', 'external', 'ready', true, 0);
    grype.runtime_ready = false;
    grype.readiness = {
      ...grype.readiness,
      data: facet('expired', 'The locked Grype database needs fresh reviewed source.', ['grype-db']),
    };
    tools.push(grype);
  }
  const scannerPreparationPending = profile === 'scanner-preparation' || profile === 'first-run';
  if (profile === 'scanner-readiness-missing') {
    tools[1].readiness = undefined;
    tools[1].runtime_ready = undefined;
  }
  if (scannerPreparationPending) {
    tools[0].runtime_ready = false;
    tools[0].readiness = {
      ...tools[0].readiness,
      rules: facet(
        'unavailable',
        'No validated active or previous-good OpenGrep rules generation exists.',
        ['opengrep-reviewed-rules'],
      ),
    };
  }
  const componentState = (componentId) => {
    const requiresLockRefresh = profile === 'scanner-lock-refresh' && componentId === 'grype-db';
    const candidateAvailable = ['trivy-db', 'opengrep-reviewed-rules'].includes(componentId)
      || (profile === 'scanner-lock-refresh' && componentId === 'trivy-checks');
    return {
      component_id: componentId,
      state: requiresLockRefresh ? 'requires_lock_refresh' : candidateAvailable ? 'candidate_available' : 'current',
      current_immutable_ref: requiresLockRefresh ? null : `fixture-current-${componentId}`,
      candidate_immutable_ref: candidateAvailable ? `fixture-candidate-${componentId}` : null,
      candidate_manifest_digest: candidateAvailable ? 'b'.repeat(64) : null,
    };
  };
  const scannerLifecycle = {
    catalog: {
      scope: 'catalog', status: 'completed', revision: 2, job_id: null, job_url: null,
      active_generation: null, previous_generation: null,
      receipt: {
        schema_version: 1,
        result: {
          kind: 'catalog',
          checked_at: time.completed,
          tools: [],
          components: ['trivy-db', 'trivy-java-db', 'trivy-checks', 'opengrep-reviewed-rules', 'bearer-rules', 'grype-db'].map(componentState),
        },
      },
      error_code: null, error_detail: null, started_at: time.started, completed_at: time.completed, updated_at: time.updated,
    },
    cache: {
      scope: 'cache', status: 'idle', revision: 1, job_id: null, job_url: null,
      active_generation: '1'.repeat(64), previous_generation: '0'.repeat(64), receipt: {},
      error_code: null, error_detail: null, started_at: null, completed_at: null, updated_at: time.updated,
    },
  };
  if (scannerPreparationPending) scannerLifecycle.cache.active_generation = null;
  if (profile === 'limited-evidence') {
    scans[1].scanner_summary = {
      findings_total: 1,
      coverage: {
        mode: 'limited',
        complete: false,
        requested_tool_ids: ['opengrep', 'checkov'],
        ready_tool_ids: ['checkov'],
        omitted_tool_ids: ['opengrep'],
        omitted_tools: [{
          id: 'opengrep',
          name: 'OpenGrep',
          blocking_reasons: ['Reviewed offline rules were unavailable.'],
          required_component_ids: ['opengrep-reviewed-rules'],
        }],
        preflight_revision: 'c'.repeat(64),
      },
    };
  }
  if (profile === 'job-activity') {
    const activeHeartbeat = new Date().toISOString();
    jobs[2] = {
      ...jobs[2],
      kind: 'scanner_cache_update',
      title: 'Update verified offline scanner cache',
      stage: 'validating_active',
      detail: 'Revalidating the current immutable cache before preparing its successor.',
      progress: 18,
      heartbeat_at: activeHeartbeat,
      activity: {
        component_id: 'bearer-rules',
        component_index: 1,
        component_total: 6,
        bytes_completed: 5_242_880,
        bytes_total: 10_485_760,
        updated_at: time.updated,
      },
    };
    jobs.push({
      id: 84,
      kind: 'scanner_cache_update',
      title: 'Completed verified offline scanner cache update',
      status: 'completed',
      stage: 'completed',
      detail: 'Verified scanner cache update completed.',
      progress: 100,
      attempt: 1,
      max_attempts: 3,
      revision: 4,
      can_cancel: false,
      can_retry: false,
      created_at: time.created,
      started_at: time.started,
      completed_at: time.completed,
      updated_at: time.updated,
      heartbeat_at: time.updated,
      activity: {
        component_id: 'grype-db',
        component_index: 4,
        component_total: 4,
        bytes_completed: null,
        bytes_total: null,
        updated_at: time.updated,
      },
    });
    jobs.push({
      id: 85,
      kind: 'scanner_cache_update',
      title: 'Resolving verified scanner cache locks',
      status: 'running',
      stage: 'resolving_lock',
      detail: 'Resolving the exact reviewed scanner cache locks.',
      progress: 0,
      attempt: 1,
      max_attempts: 3,
      revision: 2,
      can_cancel: false,
      can_retry: false,
      created_at: time.created,
      started_at: time.started,
      completed_at: null,
      updated_at: activeHeartbeat,
      heartbeat_at: activeHeartbeat,
      activity: {
        component_id: null,
        component_index: null,
        component_total: null,
        bytes_completed: null,
        bytes_total: null,
        updated_at: time.updated,
      },
    });
    jobs.push({
      id: 86,
      kind: 'scan',
      title: 'Scan #42',
      status: 'running',
      stage: 'scanner',
      detail: 'Scanner runtime is executing the enabled tools. Tool-level progress is unavailable.',
      progress: 15,
      scan_id: 42,
      attempt: 1,
      max_attempts: 3,
      revision: 4,
      can_cancel: true,
      can_retry: false,
      created_at: time.created,
      started_at: time.started,
      updated_at: time.updated,
      heartbeat_at: activeHeartbeat,
      activity: null,
    });
    jobs.push({
      id: 87,
      kind: 'scan',
      title: 'Scan with a stale worker heartbeat',
      status: 'running',
      stage: 'scanner',
      detail: 'The durable scan is recorded, but its worker heartbeat is stale.',
      progress: 12,
      scan_id: 43,
      attempt: 1,
      max_attempts: 3,
      revision: 4,
      can_cancel: true,
      can_retry: false,
      created_at: time.created,
      started_at: time.started,
      updated_at: time.updated,
      heartbeat_at: time.updated,
      activity: null,
    });
  }
  if (profile === 'scanner-lifecycle-failures') {
    const catalogJob = {
      id: 95, kind: 'scanner_catalog_check', title: 'Running curated catalog check', status: 'running', stage: 'discovering',
      detail: 'Source-blind catalog discovery is running.', progress: 42, attempt: 1, max_attempts: 3, revision: 3,
      can_cancel: true, can_retry: false, created_at: time.created, started_at: time.started, updated_at: time.updated,
    };
    const cacheJob = {
      id: 96, kind: 'scanner_cache_update', title: 'Failed verified cache update', status: 'failed', stage: 'failed',
      detail: 'The candidate failed validation; the active generation was kept.', progress: 71, attempt: 1, max_attempts: 3,
      revision: 4, can_cancel: false, can_retry: true, error_code: 'candidate_validation_failed',
      error_detail: 'Generated candidate validation failed safely.', created_at: time.created, started_at: time.started,
      completed_at: time.completed, updated_at: time.updated,
    };
    jobs.unshift(catalogJob, cacheJob);
    scannerLifecycle.catalog = {
      ...scannerLifecycle.catalog, status: 'running', revision: 3, job_id: catalogJob.id,
      job_url: `/v1/jobs/${catalogJob.id}`, receipt: {}, completed_at: null,
    };
    scannerLifecycle.cache = {
      ...scannerLifecycle.cache, status: 'failed', revision: 4, job_id: cacheJob.id,
      job_url: `/v1/jobs/${cacheJob.id}`, receipt: {}, error_code: cacheJob.error_code,
      error_detail: cacheJob.error_detail, started_at: time.started, completed_at: time.completed,
    };
  }
  const state = {
    profile,
    generation,
    authRequired: profile === 'auth-required',
    authSessionAuthenticated: profile !== 'auth-required',
    authBootstrapAttempts: [],
    browserMembers: [
      {
        id: `kbm1_${'a'.repeat(32)}`,
        member_name: 'Installation owner browser · aaaaaaaa',
        member_kind: 'owner',
        created_at: time.created,
        last_seen_at: time.updated,
        current: true,
      },
      {
        id: `kbm1_${'b'.repeat(32)}`,
        member_name: 'Local browser · bbbbbbbb',
        member_kind: 'browser',
        created_at: time.started,
        last_seen_at: time.completed,
        current: false,
      },
    ],
    projects: project ? [project] : [],
    scans: profile === 'first-run' ? [] : scans,
    findings: profile === 'first-run' ? [] : findings,
    artifacts: profile === 'first-run' ? [] : artifacts,
    jobs: profile === 'first-run' ? [] : jobs,
    tools,
    scannerLifecycle,
    gatePolicy: null,
    projectGatePolicies: {},
    runtimeConfig: {
      ai_mode: 'auto',
      ollama_base_url: advisorFixtureUrl,
      ollama_model: 'generated-local-model',
      ollama_thinking: false,
      auto_triage_limit: 3,
      component_monitoring_enabled: profile === 'component-truth',
      component_git_proxy_enabled: false,
      component_db_admin_enabled: false,
      gate_preset: 'custom',
      gate_active: true,
      gate_max_critical: 0,
      gate_max_high: -1,
      gate_block_secrets: false,
    },
    firstRunCoreReady: profile !== 'first-run',
    scannerPreparationPending,
    advisorProviderRevision: 1,
    activeAdvisorProviderId: null,
    advisorProviders: [{
      id: 'local-default',
      name: 'Local Ollama',
      transport: 'local',
      priority: 0,
      enabled: true,
      base_url: null,
      model: 'generated-local-model',
      model_digest: 'a'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
      authorization: 'not_required',
      status: 'idle',
      reason: 'Local provider has not been tested yet.',
      reason_code: null,
      remediation: 'test',
      last_activity_at: null,
      content_disclosure_approved: false,
      config_revision: 1,
      config_digest: advisorProviderConfigDigest({
        id: 'local-default', name: 'Local Ollama', transport: 'local', priority: 0, enabled: true,
        base_url: null, model: 'generated-local-model', model_digest: 'a'.repeat(64),
        ssh_host: null, ssh_port: null, ssh_user: null,
      }),
    }],
    advisorProviderReceipts: {},
    advisorProviderConsents: {},
    advisorDisclosureAuthorizations: {},
    advisorAuthorizedDirectHosts: [],
    advisorAuthorizedSshProviderIds: [],
  };
  const localProvider = state.advisorProviders[0];
  if (profile === 'advisor-local-empty') {
    state.advisorProviders = [];
  } else {
    localProvider.status = 'active';
    localProvider.reason = null;
    localProvider.remediation = 'none';
    localProvider.content_disclosure_approved = true;
    state.activeAdvisorProviderId = localProvider.id;
    state.advisorProviderReceipts[localProvider.id] = {
      schema: 'lomo-advisor-provider-receipt/v1',
      provider_id: localProvider.id,
      kind: 'local',
      route: 'local',
      model: localProvider.model,
      model_digest: localProvider.model_digest,
      status: 'ready',
      tested_at: time.completed,
      revision: localProvider.config_revision,
    };
  }
  if (profile === 'advisor-remote-disabled') {
    localProvider.enabled = false;
    localProvider.status = 'idle';
    localProvider.content_disclosure_approved = false;
    state.activeAdvisorProviderId = 'direct-review';
    const remoteProvider = {
      id: 'direct-review',
      name: 'Synthetic Direct Review',
      transport: 'direct',
      priority: 1,
      enabled: true,
      base_url: 'http://192.0.2.202:11434',
      model: 'fixture-advisor-model:latest',
      model_digest: 'b'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
      authorization: 'authorized',
      status: 'active',
      reason: null,
      reason_code: null,
      remediation: 'none',
      last_activity_at: time.completed,
      content_disclosure_approved: true,
      config_revision: 1,
      config_digest: '',
    };
    remoteProvider.config_digest = advisorProviderConfigDigest(remoteProvider);
    state.advisorProviders.push(remoteProvider);
    state.advisorAuthorizedDirectHosts.push('192.0.2.202');
    state.advisorProviderReceipts[remoteProvider.id] = {
      schema: 'lomo-advisor-provider-receipt/v1',
      provider_id: remoteProvider.id,
      kind: 'direct',
      route: 'direct',
      model: remoteProvider.model,
      model_digest: remoteProvider.model_digest,
      status: 'ready',
      tested_at: time.completed,
      revision: remoteProvider.config_revision,
    };
    state.advisorProviderConsents[remoteProvider.id] = {
      schema: 'lomo-advisor-source-consent/v1',
      provider_id: remoteProvider.id,
      provider_config_revision: remoteProvider.config_revision,
      provider_config_digest: remoteProvider.config_digest,
      transport: 'direct',
      destination: advisorProviderDestination(remoteProvider),
      disclosure_mode: 'finding_evidence',
      payload_categories: [...advisorDisclosureCategories],
      model: remoteProvider.model,
      model_digest: remoteProvider.model_digest,
      approved_at: time.completed,
    };
  }
  return state;
}

let fixture = buildFixture();
let requestCounts = {
  findings: 0,
  findingDetails: 0,
  scanSummaries: 0,
  artifacts: 0,
  projects: 0,
  advisorProviderResolutions: 0,
  advisorPreviews: 0,
  advisorSubmissions: 0,
};
let commandRequests = [];
let advisorProviderJobsByIdempotencyKey = new Map();

const lifecycleActions = new Set([
  'open',
  'needs_review',
  'gate_exempt',
  'accepted_risk',
  'ignore',
  'false_positive',
  'fixed',
]);
const reasonRequiredActions = new Set(['gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed']);
const findingCursorKeys = ['a', 'f', 'r', 's', 'v'];

function fixtureHttpError(status, detail) {
  const error = new Error(typeof detail === 'string' ? detail : detail.message || 'Fixture request failed.');
  error.fixtureStatus = status;
  error.fixtureDetail = detail;
  return error;
}

function checkFindingExpectedRevision(raw, revision) {
  if (raw === null) return;
  // Query int parsing accepts base-ten digit separators and zero fractional
  // suffixes. Number(raw) alone would also admit unsupported hex/exponents.
  const normalized = raw.replace(
    /^[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g,
    '',
  );
  const lexicalInteger = /^[+-]?[0-9]+(?:_[0-9]+)*(?:\.0+)?$/.test(normalized);
  const expected = lexicalInteger ? Number(normalized.replaceAll('_', '')) : NaN;
  if (!Number.isSafeInteger(expected) || expected < 1 || expected > 2_147_483_647) {
    throw fixtureHttpError(422, 'expected_revision must be a positive bounded integer');
  }
  if (expected !== revision) throw fixtureHttpError(409, {
    code: 'revision_conflict',
    message: 'findings changed after the selected manifest snapshot',
    revision,
  });
}

function scanById(scanId) {
  return fixture.scans.find((scan) => scan.id === scanId);
}

function requireScan(scanId) {
  const scan = scanById(scanId);
  if (!scan) throw fixtureHttpError(404, 'scan not found');
  return scan;
}

function findingsForScan(scanId) {
  return fixture.findings
    .filter((finding) => finding.scan_id === scanId)
    .sort((left, right) => left.scan_finding_number - right.scan_finding_number);
}

function countFindingFacets(scanId) {
  const all = findingsForScan(scanId);
  const active = all.filter((finding) => !finding.suppressed);
  const severityCounts = {};
  const scannerCounts = {};
  for (const finding of active) {
    const severity = finding.severity || 'info';
    const scanner = finding.scanner || 'unknown';
    severityCounts[severity] = (severityCounts[severity] || 0) + 1;
    scannerCounts[scanner] = (scannerCounts[scanner] || 0) + 1;
  }
  return {
    all,
    active,
    suppressed: all.length - active.length,
    gateExempt: active.filter((finding) => finding.gate_exempt).length,
    severityCounts,
    scannerCounts,
  };
}

function scanSummary(scan) {
  const counts = countFindingFacets(scan.id);
  return {
    scan: {
      id: scan.id,
      project_id: scan.project_id,
      mode: scan.mode,
      status: scan.status,
      gate_decision: scan.gate_decision ?? null,
      gate_reasons: scan.gate_reasons || [],
      error: scan.error ?? null,
      created_at: scan.created_at,
      started_at: scan.started_at ?? null,
      completed_at: scan.completed_at ?? null,
      duration_ms: scan.duration_ms ?? null,
    },
    findings: {
      total: counts.all.length,
      active: counts.active.length,
      suppressed: counts.suppressed,
      gate_exempt: counts.gateExempt,
      severity_counts: counts.severityCounts,
      scanner_counts: counts.scannerCounts,
    },
    revision: scan.revision,
    findings_revision: scan.findings_revision,
  };
}

function fixtureProjectGate(projectId) {
  return fixture.projectGatePolicies[projectId] || fixture.gatePolicy
    || { active: true, max_critical: 0, max_high: 0, block_secrets: false };
}

function evaluateFixtureScanGate(scan) {
  const counts = countFindingFacets(scan.id);
  const policy = fixtureProjectGate(scan.project_id);
  if (scan.status === 'completed') {
    if (!policy.active) {
      scan.gate_decision = 'not_configured';
      scan.gate_reasons = [];
    } else {
      const gateFindings = counts.active.filter((finding) => !finding.gate_exempt);
      const critical = gateFindings.filter((finding) => finding.severity === 'critical').length;
      const high = gateFindings.filter((finding) => finding.severity === 'high').length;
      const secrets = gateFindings.filter((finding) => {
        const searchable = `${finding.scanner} ${finding.rule_id} ${finding.message}`.toLowerCase();
        return searchable.includes('secret') || searchable.includes('token') || searchable.includes('private-key');
      }).length;
      const reasons = [];
      if (policy.max_critical >= 0 && critical > policy.max_critical) reasons.push(`critical findings: ${critical} > max ${policy.max_critical}`);
      if (policy.max_high >= 0 && high > policy.max_high) reasons.push(`high findings: ${high} > max ${policy.max_high}`);
      if (policy.block_secrets && secrets) reasons.push(`secret findings: ${secrets}`);
      scan.gate_decision = reasons.length ? 'fail' : 'pass';
      scan.gate_reasons = reasons;
    }
  } else if (!['fail', 'incomplete'].includes(scan.gate_decision)) {
    scan.gate_decision = 'incomplete';
    scan.gate_reasons = ['Required scanner evidence is incomplete; the deterministic policy gate was not passed.'];
  }
}

function refreshScanFindingState(scan) {
  const counts = countFindingFacets(scan.id);
  scan.scanner_summary = {
    ...(scan.scanner_summary || {}),
    findings_total: counts.active.length,
    severity_counts: counts.severityCounts,
    scanner_counts: counts.scannerCounts,
    ignored_count: counts.suppressed,
    gate_exempt_count: counts.gateExempt,
  };
  evaluateFixtureScanGate(scan);
  scan.revision += 1;
  scan.findings_revision += 1;
}

function applyFixtureGatePolicyToExistingScans() {
  fixture.projectGatePolicies = {};
  for (const scan of fixture.scans) {
    if (!['completed', 'partial', 'failed', 'cancelled'].includes(scan.status)) continue;
    evaluateFixtureScanGate(scan);
    scan.revision += 1;
  }
}

function activeJobForScanIds(scanIds) {
  const activeStatuses = new Set(['queued', 'leased', 'running', 'cancelling']);
  return fixture.jobs.find((job) => job.scan_id && scanIds.has(job.scan_id) && activeStatuses.has(job.status)) || null;
}

function findingFilterDigest(filters) {
  return createHash('sha256').update(JSON.stringify({
    file_path: filters.filePath,
    lifecycle_status: filters.lifecycleStatus,
    scanner: filters.scanner,
    severity: filters.severity,
  })).digest('hex');
}

function encodeFindingCursor({ scanId, revision, after, filterDigest }) {
  return Buffer.from(JSON.stringify({ a: after, f: filterDigest, r: revision, s: scanId, v: 1 }), 'ascii')
    .toString('base64url');
}

function invalidFindingCursor(message = 'finding cursor is invalid') {
  return fixtureHttpError(400, { code: 'cursor_invalid', message });
}

function decodeFindingCursor(cursor) {
  if (typeof cursor !== 'string' || !cursor || cursor.length > 512 || !/^[A-Za-z0-9_-]+$/.test(cursor)) {
    throw invalidFindingCursor();
  }
  let document;
  try {
    const decoded = Buffer.from(cursor, 'base64url');
    if (decoded.length > 256 || decoded.toString('base64url') !== cursor) throw new Error('non-canonical cursor');
    document = JSON.parse(decoded.toString('ascii'));
  } catch {
    throw invalidFindingCursor();
  }
  if (
    !document
    || Array.isArray(document)
    || typeof document !== 'object'
    || JSON.stringify(Object.keys(document).sort()) !== JSON.stringify(findingCursorKeys)
    || !Number.isSafeInteger(document.v)
    || document.v !== 1
    || !Number.isSafeInteger(document.s)
    || document.s < 1
    || !Number.isSafeInteger(document.r)
    || document.r < 1
    || !Number.isSafeInteger(document.a)
    || document.a < 1
    || typeof document.f !== 'string'
    || !/^[0-9a-f]{64}$/.test(document.f)
  ) {
    throw invalidFindingCursor();
  }
  return document;
}

function findingFilters(requestUrl) {
  const filePath = requestUrl.searchParams.get('file_path');
  if (filePath !== null && (
    !filePath
    || filePath.startsWith('/')
    || filePath.includes('\\')
    || /[\x00-\x1f\x7f]/.test(filePath)
    || filePath.split('/').some((segment) => !segment || segment === '.' || segment === '..')
  )) {
    throw fixtureHttpError(422, 'file_path must be an exact canonical project-relative POSIX path');
  }
  const rawSeverity = requestUrl.searchParams.get('severity');
  const severity = rawSeverity === null ? null : rawSeverity.toLowerCase();
  if (severity !== null && !['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
    throw fixtureHttpError(422, 'severity filter is invalid');
  }
  const scanner = requestUrl.searchParams.get('scanner');
  if (scanner !== null && (!scanner || scanner !== scanner.trim())) {
    throw fixtureHttpError(422, 'scanner filter is invalid');
  }
  const lifecycleStatus = requestUrl.searchParams.get('lifecycle_status');
  if (lifecycleStatus !== null && !lifecycleActions.has(lifecycleStatus)) {
    throw fixtureHttpError(422, 'lifecycle_status filter is invalid');
  }
  return { filePath, severity, scanner, lifecycleStatus };
}

function filterFindings(items, filters) {
  return items.filter((finding) => (
    (filters.filePath === null || finding.file_path === filters.filePath)
    && (filters.severity === null || finding.severity === filters.severity)
    && (filters.scanner === null || finding.scanner === filters.scanner)
    && (filters.lifecycleStatus === null || finding.lifecycle_status === filters.lifecycleStatus)
  ));
}

function findingListItem(item) {
  const {
    code_snippet: _codeSnippet,
    metadata_json: _metadata,
    ai_verdict: _aiVerdict,
    ai_confidence: _aiConfidence,
    ai_reasoning: _reasoning,
    ai_fix: _fix,
    suppression_reason: _suppressionReason,
    gate_exempt_reason: _gateExemptReason,
    lifecycle_reason: _lifecycleReason,
    lifecycle_updated_at: _lifecycleUpdatedAt,
    ...summary
  } = item;
  return {
    ...summary,
    advisor_verdict: item.ai_verdict ?? null,
    advisor_confidence: item.ai_confidence ?? null,
  };
}

function boundedFindingDetail(item) {
  let metadata = item.metadata_json || {};
  if (Buffer.byteLength(JSON.stringify(metadata)) > 20_000) metadata = { _kodesec_truncated: true };
  const bounded = (value, length) => typeof value === 'string' ? value.slice(0, length) : value;
  return {
    ...item,
    message: bounded(item.message, 4_000),
    code_snippet: bounded(item.code_snippet, 20_000),
    metadata_json: metadata,
    ai_verdict: bounded(item.ai_verdict, 40),
    ai_reasoning: bounded(item.ai_reasoning, 4_000),
    ai_fix: bounded(item.ai_fix, 4_000),
    suppression_reason: bounded(item.suppression_reason, 500),
    gate_exempt_reason: bounded(item.gate_exempt_reason, 500),
    lifecycle_reason: bounded(item.lifecycle_reason, 500),
  };
}

function durableCommand(request, response, route, input) {
  const key = request.headers['idempotency-key'];
  if (typeof key !== 'string' || !/^web-[0-9a-f-]{36}$/.test(key)) {
    json(response, 422, { error: 'A generated durable Idempotency-Key is required.' });
    return false;
  }
  commandRequests.push({ method: request.method, route, idempotency_key: key, input });
  return true;
}

function queuedJob(values) {
  const id = Math.max(0, ...fixture.jobs.map((job) => job.id)) + 1;
  const job = {
    id,
    kind: 'advisor',
    title: 'Advisor triage',
    status: 'queued',
    stage: 'queued',
    detail: 'Persisted and waiting for the durable worker.',
    progress: 0,
    attempt: 0,
    max_attempts: 3,
    revision: 1,
    can_cancel: true,
    created_at: time.created,
    updated_at: time.updated,
    ...values,
  };
  fixture.jobs.unshift(job);
  return job;
}

function bindLifecycleJob(scopeName, job, values = {}) {
  fixture.scannerLifecycle[scopeName] = {
    ...fixture.scannerLifecycle[scopeName],
    status: job.status,
    revision: fixture.scannerLifecycle[scopeName].revision + 1,
    job_id: job.id,
    job_url: `/v1/jobs/${job.id}`,
    receipt: {},
    error_code: job.error_code || null,
    error_detail: job.error_detail || null,
    started_at: job.started_at || null,
    completed_at: job.completed_at || null,
    updated_at: job.updated_at,
    ...values,
  };
  return fixture.scannerLifecycle[scopeName];
}

function syncLifecycleJob(job) {
  for (const scopeName of ['catalog', 'cache']) {
    if (fixture.scannerLifecycle[scopeName].job_id === job.id) bindLifecycleJob(scopeName, job);
  }
}

function advisorProviderAuthorized(provider) {
  if (provider.transport === 'local') return true;
  if (provider.transport === 'ssh') return fixture.advisorAuthorizedSshProviderIds.includes(provider.id);
  try {
    return fixture.advisorAuthorizedDirectHosts.includes(new URL(provider.base_url).hostname.toLowerCase());
  } catch {
    return false;
  }
}

function advisorReceiptMatches(provider) {
  const receipt = fixture.advisorProviderReceipts[provider.id];
  return Boolean(receipt
    && receipt.provider_id === provider.id
    && receipt.kind === provider.transport
    && receipt.route === provider.transport
    && receipt.model === provider.model
    && receipt.model_digest === provider.model_digest
    && receipt.revision === provider.config_revision);
}

function advisorConsentMatches(provider) {
  const consent = fixture.advisorProviderConsents[provider.id];
  return Boolean(consent
    && provider.content_disclosure_approved
    && consent.provider_id === provider.id
    && consent.provider_config_revision === provider.config_revision
    && consent.provider_config_digest === provider.config_digest
    && consent.transport === provider.transport
    && consent.model === provider.model
    && consent.model_digest === provider.model_digest);
}

function advisorProviderDestination(provider) {
  if (provider.transport === 'direct') return provider.base_url;
  if (provider.transport === 'ssh') return `ssh://${provider.ssh_user}@${provider.ssh_host}:22/ollama/127.0.0.1:11434`;
  return 'local://ollama';
}

function advisorProviderActivationApproval(provider) {
  return {
    schema: 'lomo-advisor-activation-approval/v1',
    provider_id: provider.id,
    provider_config_revision: provider.config_revision,
    provider_config_digest: provider.config_digest,
    transport: provider.transport,
    destination: advisorProviderDestination(provider),
    disclosure_mode: 'finding_evidence',
    payload_categories: [...advisorDisclosureCategories],
    model: provider.model,
    model_digest: provider.model_digest,
  };
}

function advisorFindingPacket(finding) {
  const scan = fixture.scans.find((candidate) => candidate.id === finding.scan_id);
  const project = fixture.projects.find((candidate) => candidate.id === scan?.project_id);
  if (!scan || !project) throw fixtureHttpError(404, 'finding context not found');
  return {
    schema_version: 1,
    finding: {
      id: finding.id,
      display_id: finding.display_id,
      scanner: finding.scanner,
      rule_id: finding.rule_id,
      severity: finding.severity,
      message: finding.message,
      fingerprint: finding.fingerprint,
    },
    location: {
      file_path: finding.file_path,
      start_line: finding.start_line,
      start_column: finding.start_column,
      end_line: finding.end_line,
      end_column: finding.end_column,
    },
    repo_context: {
      project: project.name,
      repo_path: project.repo_path,
      remote_url: project.remote_url || null,
      scan_id: scan.id,
      mode: scan.mode,
      base_ref: scan.base_ref,
      head_ref: scan.head_ref,
    },
    scanner_evidence: {
      code_snippet: finding.code_snippet,
      metadata: finding.metadata_json,
    },
  };
}

function advisorDisclosureConfirmation(provider, finding, packet = advisorFindingPacket(finding), authorizationId = randomBytes(16).toString('hex')) {
  const consent = fixture.advisorProviderConsents[provider.id];
  if (!consent) throw fixtureHttpError(409, 'remote Advisor consent is missing or stale');
  const prompt = 'You are reviewing a local application-security scanner finding. '
    + 'Return strict JSON with keys verdict, confidence, reasoning, fix. '
    + 'verdict must be one of true_positive, false_positive, needs_review. '
    + 'confidence must be a JSON number between 0 and 1. '
    + 'reasoning and fix must be JSON strings. Do not add any other keys. '
    + 'Do not include markdown.\n\n'
    + `Finding packet:\n${JSON.stringify(packet, null, 2)}`;
  const confirmation = {
    schema: 'lomo-advisor-run-confirmation/v1',
    authorization_id: authorizationId,
    provider_id: provider.id,
    provider_config_revision: provider.config_revision,
    provider_config_digest: provider.config_digest,
    transport: provider.transport,
    destination: advisorProviderDestination(provider),
    disclosure_mode: 'finding_evidence',
    payload_categories: [...advisorDisclosureCategories],
    model: provider.model,
    model_digest: provider.model_digest,
    consent_approved_at: consent.approved_at,
    finding_id: finding.id,
    finding_revision: finding.revision,
    prompt_sha256: createHash('sha256').update(prompt).digest('hex'),
  };
  return {
    ...confirmation,
    confirmation_digest: createHmac('sha256', advisorDisclosureSigningKey)
      .update(advisorDisclosureSigningPurpose)
      .update(canonicalJson(confirmation))
      .digest('hex'),
  };
}

function buildAdvisorDisclosurePreview(provider, finding) {
  const packet = advisorFindingPacket(finding);
  const confirmation = advisorDisclosureConfirmation(provider, finding, packet);
  fixture.advisorDisclosureAuthorizations[confirmation.authorization_id] = {
    confirmation,
    input: null,
    job: null,
  };
  return {
    confirmation,
    packet,
    packet_utf8_bytes: Buffer.byteLength(JSON.stringify(packet, null, 2), 'utf8'),
  };
}

function publicAdvisorProvider(provider) {
  const authorization = provider.transport === 'local'
    ? 'not_required'
    : advisorProviderAuthorized(provider) ? 'authorized' : 'required';
  const statusReady = ['available', 'active'].includes(provider.status);
  const receiptReady = advisorReceiptMatches(provider);
  const consentReady = advisorConsentMatches(provider);
  const eligible = Boolean(provider.enabled
    && advisorProviderAuthorized(provider)
    && statusReady
    && receiptReady
    && provider.transport === 'local');
  let reason = provider.reason;
  let reasonCode = provider.reason_code;
  let remediation = provider.remediation;
  if (provider.transport !== 'local' && authorization === 'required') {
    reason = 'Exact host authorization is required before testing this provider.';
    reasonCode = 'authorization_required';
    remediation = 'authorize';
  } else if (provider.transport !== 'local' && reasonCode === null) {
    if (provider.id === fixture.activeAdvisorProviderId && provider.status === 'active' && receiptReady && consentReady) {
      reason = 'Ready for an explicit one-finding Advisor review after its exact disclosure preview is confirmed. Automatic, scan-wide, and bulk remote routing remain disabled.';
      reasonCode = 'remote_single_finding_confirmation_required';
      remediation = 'none';
    } else {
      reason = 'Test and activate this exact provider before remote Advisor use.';
      reasonCode = 'activation_required';
      remediation = 'activate';
    }
  } else if (provider.transport === 'local' && !eligible && reasonCode === null) {
    reason = 'Test this exact local provider before Advisor use.';
    reasonCode = 'test_required';
    remediation = 'test';
  }
  return {
    id: provider.id,
    name: provider.name,
    transport: provider.transport,
    priority: provider.priority,
    enabled: provider.enabled,
    base_url: provider.base_url,
    model: provider.model,
    model_digest: provider.model_digest,
    ssh_host: provider.ssh_host,
    ssh_port: provider.ssh_port,
    ssh_user: provider.ssh_user,
    authorization,
    status: provider.status,
    reason,
    reason_code: reasonCode,
    remediation,
    last_activity_at: provider.last_activity_at,
    content_disclosure_approved: provider.content_disclosure_approved,
    config_revision: provider.config_revision,
    config_digest: provider.config_digest,
    eligible,
  };
}

function advisorProviderCollection() {
  const ordered = [...fixture.advisorProviders]
    .sort((left, right) => left.priority - right.priority || left.name.localeCompare(right.name))
    .map(publicAdvisorProvider);
  const routeOrder = { local: 0, direct: 1, ssh: 2 };
  const eligible = ordered.filter((provider) => provider.eligible)
    .sort((left, right) => routeOrder[left.transport] - routeOrder[right.transport]
      || (left.id === fixture.activeAdvisorProviderId ? 0 : 1) - (right.id === fixture.activeAdvisorProviderId ? 0 : 1)
      || left.priority - right.priority || left.id.localeCompare(right.id));
  const selected = eligible[0] || null;
  const active = ordered.find((provider) => provider.id === fixture.activeAdvisorProviderId) || null;
  const unavailableReason = active?.reason_code || (ordered.length ? 'no_executable_provider' : 'no_configured_provider');
  return {
    revision: fixture.advisorProviderRevision,
    active_provider_id: fixture.activeAdvisorProviderId,
    providers: ordered,
    resolution: {
      provider_id: selected?.id || null,
      transport: selected?.transport || 'unavailable',
      reason: selected ? null : unavailableReason,
      eligible_provider_ids: eligible.map((provider) => provider.id),
    },
  };
}

function advisorTriageProviderPin(provider, collectionRevision = fixture.advisorProviderRevision) {
  return {
    provider_collection_revision: collectionRevision,
    provider_id: provider.id,
    transport: provider.transport,
    provider_config_revision: provider.config_revision,
    provider_config_digest: provider.config_digest,
    model: provider.model,
    model_digest: provider.model_digest,
  };
}

function requirePinnedLocalAdvisor(response, input, { scanWide = false } = {}) {
  const requested = input?.advisor_provider_pin;
  if (!requested || typeof requested !== 'object' || Array.isArray(requested)) {
    json(response, 422, { detail: 'local Advisor triage requires one exact provider pin' });
    return null;
  }
  const expectedKeys = [
    'model',
    'model_digest',
    'provider_collection_revision',
    'provider_config_digest',
    'provider_config_revision',
    'provider_id',
    'transport',
  ];
  if (Object.keys(requested).sort().join(',') !== expectedKeys.join(',')) {
    json(response, 422, { detail: 'Advisor provider pin contains unexpected or missing fields.' });
    return null;
  }
  const collection = advisorProviderCollection();
  if (requested.provider_collection_revision !== collection.revision) {
    json(response, 409, { detail: {
      code: 'advisor_provider_selection_stale',
      message: 'Advisor provider configuration changed after selection; no Advisor job was queued.',
      action: 'refresh_advisor_providers',
      safe_details: {
        expected_revision: requested.provider_collection_revision,
        current_revision: collection.revision,
      },
    } });
    return null;
  }
  const provider = fixture.advisorProviders.find((candidate) => candidate.id === requested.provider_id);
  if (!provider) {
    json(response, 409, { detail: {
      code: 'advisor_provider_selection_stale',
      message: 'The selected Advisor provider no longer exists; no Advisor job was queued.',
      action: 'refresh_advisor_providers',
      safe_details: { provider_id: requested.provider_id },
    } });
    return null;
  }
  const livePin = advisorTriageProviderPin(provider, collection.revision);
  if (canonicalJson(requested) !== canonicalJson(livePin)) {
    json(response, 409, { detail: {
      code: 'advisor_provider_selection_stale',
      message: 'The selected Advisor provider no longer matches its exact configuration; no Advisor job was queued.',
      action: 'refresh_advisor_providers',
      safe_details: {
        provider_id: provider.id,
        current_revision: provider.config_revision,
      },
    } });
    return null;
  }
  if (provider.transport === 'direct' || provider.transport === 'ssh') {
    json(response, 409, { detail: {
      code: 'advisor_remote_single_finding_required',
      message: scanWide
        ? 'Scan-wide remote Advisor disclosure is forbidden; choose one finding and confirm its exact disclosure preview.'
        : 'Remote Advisor review requires one exact disclosure preview and confirmation.',
      action: 'preview_advisor_source_disclosure',
      safe_details: {
        provider_id: provider.id,
        transport: provider.transport,
        reason_code: 'single_finding_confirmation_required',
      },
    } });
    return null;
  }
  if (
    collection.resolution.provider_id !== provider.id
    || collection.resolution.transport !== 'local'
    || !provider.enabled
  ) {
    json(response, 409, { detail: {
      code: 'advisor_provider_not_executable',
      message: 'No tested and currently executable local Advisor provider matches the exact selection.',
      action: 'test_advisor_provider',
      safe_details: {
        provider_id: provider.id,
        reason_code: collection.resolution.reason || 'no_executable_provider',
      },
    } });
    return null;
  }
  if (input.model != null && input.model !== '' && input.model !== provider.model) {
    json(response, 409, { detail: {
      code: 'advisor_provider_selection_stale',
      message: 'Advisor command model does not match the exact selected provider.',
      action: 'refresh_advisor_providers',
      safe_details: { provider_id: provider.id },
    } });
    return null;
  }
  return provider;
}

function validateAdvisorProvider(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw fixtureHttpError(422, 'provider must be an object');
  const allowedKeys = ['id', 'name', 'transport', 'priority', 'enabled', 'base_url', 'model', 'model_digest', 'ssh_host', 'ssh_port', 'ssh_user'];
  if (Object.keys(input).sort().join(',') !== [...allowedKeys].sort().join(',')) {
    throw fixtureHttpError(422, 'provider contains unexpected fields');
  }
  if (typeof input.id !== 'string' || !/^[a-z][a-z0-9-]{0,39}$/.test(input.id)) throw fixtureHttpError(422, 'provider id is invalid');
  if (typeof input.name !== 'string' || !input.name.trim() || input.name.trim().length > 80 || /[\p{Cc}\p{Cf}]/u.test(input.name)) {
    throw fixtureHttpError(422, 'provider name is invalid');
  }
  if (!['local', 'direct', 'ssh'].includes(input.transport)) throw fixtureHttpError(422, 'provider transport is invalid');
  if (!Number.isInteger(input.priority) || input.priority < 0 || input.priority > 7) throw fixtureHttpError(422, 'provider priority is invalid');
  if (typeof input.enabled !== 'boolean') throw fixtureHttpError(422, 'provider enabled state is invalid');
  if (typeof input.model !== 'string' || !input.model.trim() || input.model.trim().length > 120 || /[\p{Cc}\p{Cf}]/u.test(input.model)
    || typeof input.model_digest !== 'string' || !/^[a-f0-9]{64}$/.test(input.model_digest)) {
    throw fixtureHttpError(422, 'provider model identity is invalid');
  }
  let normalizedBaseUrl = input.base_url;
  let normalizedSshHost = input.ssh_host;
  if (input.transport === 'direct') {
    normalizedBaseUrl = normalizeExactDirectAdvisorUrl(input.base_url);
    if (!normalizedBaseUrl) {
      throw fixtureHttpError(422, 'direct provider target is invalid');
    }
  } else if (input.base_url !== null) throw fixtureHttpError(422, 'non-direct provider base URL must be null');
  if (input.transport === 'ssh') {
    normalizedSshHost = normalizeSafeAdvisorIpv4(input.ssh_host);
    if (!normalizedSshHost || input.ssh_port !== 22
      || typeof input.ssh_user !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(input.ssh_user)) {
      throw fixtureHttpError(422, 'SSH provider fields are invalid');
    }
  } else if (input.ssh_host !== null || input.ssh_port !== null || input.ssh_user !== null) {
    throw fixtureHttpError(422, 'non-SSH provider fields must be null');
  }
  const normalized = {
    ...input,
    name: input.name.trim(),
    base_url: normalizedBaseUrl,
    model: input.model.trim(),
    ssh_host: normalizedSshHost,
    ssh_user: typeof input.ssh_user === 'string' ? input.ssh_user.trim() : input.ssh_user,
    status: 'idle',
    reason: input.transport === 'ssh' ? 'Exact SSH host authorization is required before connection.' : 'Provider has not been tested yet.',
    reason_code: null,
    remediation: 'test',
    last_activity_at: null,
    content_disclosure_approved: false,
    config_revision: 1,
    config_digest: '',
  };
  normalized.config_digest = advisorProviderConfigDigest(normalized);
  return normalized;
}

function completeAdvisorProviderJob(job) {
  if (!job.provider_id || !job.provider_action) return;
  const provider = fixture.advisorProviders.find((candidate) => candidate.id === job.provider_id);
  if (!provider) return;
  job.status = 'completed';
  job.stage = 'completed';
  job.progress = 100;
  job.attempt = Math.max(1, job.attempt || 0);
  job.revision += 1;
  job.can_cancel = false;
  job.can_retry = false;
  job.started_at ||= time.started;
  job.completed_at = time.completed;
  job.updated_at = time.completed;
  job.heartbeat_at = time.completed;
  job.activity = {
    component_id: 'model-digest-verification',
    component_index: 3,
    component_total: 3,
    bytes_completed: 4096,
    bytes_total: 4096,
    updated_at: time.completed,
  };
  if (job.provider_action !== 'disconnect') {
    fixture.advisorProviderReceipts[provider.id] = {
      schema: 'lomo-advisor-provider-receipt/v1',
      provider_id: provider.id,
      kind: provider.transport,
      route: provider.transport,
      model: provider.model,
      model_digest: provider.model_digest,
      status: 'ready',
      tested_at: time.completed,
      revision: provider.config_revision,
    };
  }
  if (job.provider_action === 'activate') {
    fixture.advisorProviders.forEach((candidate) => {
      if (candidate.id === provider.id || candidate.status !== 'active') return;
      candidate.status = 'available';
      candidate.reason = 'Another eligible Advisor provider was selected.';
      candidate.reason_code = 'provider_not_selected';
      candidate.remediation = 'activate';
      candidate.last_activity_at = time.completed;
    });
    fixture.activeAdvisorProviderId = provider.id;
    provider.status = 'active';
    provider.reason = null;
    provider.reason_code = null;
    provider.remediation = 'none';
    provider.content_disclosure_approved = provider.transport === 'local' || job.acknowledge_source_disclosure === true;
    if (provider.transport !== 'local') {
      fixture.advisorProviderConsents[provider.id] = {
        schema: 'lomo-advisor-source-consent/v1',
        provider_id: provider.id,
        provider_config_revision: provider.config_revision,
        provider_config_digest: provider.config_digest,
        transport: provider.transport,
        destination: advisorProviderDestination(provider),
        disclosure_mode: 'finding_evidence',
        payload_categories: [...advisorDisclosureCategories],
        model: provider.model,
        model_digest: provider.model_digest,
        approved_at: time.completed,
      };
    }
  } else if (job.provider_action === 'disconnect') {
    if (fixture.activeAdvisorProviderId === provider.id) fixture.activeAdvisorProviderId = null;
    provider.status = 'disconnected';
    provider.reason = 'Disconnected by the operator.';
    provider.reason_code = 'operator_disconnected';
    provider.remediation = 'activate';
    provider.content_disclosure_approved = false;
    delete fixture.advisorProviderConsents[provider.id];
    delete fixture.advisorProviderReceipts[provider.id];
  } else {
    const remainsActive = fixture.activeAdvisorProviderId === provider.id && provider.content_disclosure_approved;
    provider.status = remainsActive ? 'active' : 'available';
    provider.reason = null;
    provider.reason_code = null;
    provider.remediation = 'none';
  }
  provider.last_activity_at = time.completed;
}

function config() {
  const active = fixture.runtimeConfig;
  const componentApplyCommand = new Map([
    ['false,false,false', 'make apply-components COMPONENTS=core'],
    ['true,false,false', 'make apply-components COMPONENTS=monitoring'],
    ['false,true,false', 'make apply-components COMPONENTS=git-proxy'],
    ['false,false,true', 'make apply-components COMPONENTS=db-admin'],
    ['true,true,false', 'make apply-components COMPONENTS=monitoring-git-proxy'],
    ['true,false,true', 'make apply-components COMPONENTS=monitoring-db-admin'],
    ['false,true,true', 'make apply-components COMPONENTS=git-proxy-db-admin'],
    ['true,true,true', 'make apply-components COMPONENTS=all'],
  ]).get([
    active.component_monitoring_enabled,
    active.component_git_proxy_enabled,
    active.component_db_admin_enabled,
  ].join(','));
  if (!componentApplyCommand) throw new Error('Generated component selection has no apply command.');
  const optionalComponent = (id, profile, enabled) => ({
    id,
    required: false,
    desired_enabled: enabled,
    desired_state: enabled ? 'enabled' : 'disabled',
    observed_state: 'not_observed',
    reachable: false,
    healthy: false,
    url: '',
    profile,
    apply_command: componentApplyCommand,
    reason_code: 'not_observed',
    message: enabled
      ? 'Not observed; apply the selected host component profile.'
      : 'Not observed; optional component is desired off.',
  });
  const components = [
    { id: 'control', required: true, desired_enabled: true, desired_state: 'enabled', observed_state: 'running', reachable: true, healthy: true, url: `${origin}/`, profile: 'core', apply_command: componentApplyCommand, reason_code: 'health_response_accepted', message: 'Control API is running and healthy.' },
    { id: 'scanner', required: true, desired_enabled: true, desired_state: 'enabled', observed_state: 'running', reachable: true, healthy: true, url: `${origin}/fixture/scanner`, profile: 'core', apply_command: componentApplyCommand, reason_code: 'health_response_accepted', message: 'Scanner runtime is running and healthy.' },
    optionalComponent('grafana', 'monitoring', active.component_monitoring_enabled),
    optionalComponent('prometheus', 'monitoring', active.component_monitoring_enabled),
    optionalComponent('gitea', 'git-proxy', active.component_git_proxy_enabled),
    optionalComponent('adminer', 'db-admin', active.component_db_admin_enabled),
  ];
  if (fixture.profile === 'component-truth') {
    Object.assign(components.find((component) => component.id === 'control'), {
      observed_state: 'not_running', reachable: false, healthy: false,
      reason_code: 'not_reachable', message: 'Required core service is not reachable.',
    });
    Object.assign(components.find((component) => component.id === 'grafana'), {
      desired_enabled: true, desired_state: 'enabled', observed_state: 'not_running',
      reason_code: 'not_reachable', message: 'Not running; optional; scanning is unaffected.',
    });
    Object.assign(components.find((component) => component.id === 'prometheus'), {
      desired_enabled: true, desired_state: 'enabled', observed_state: 'unknown',
      reason_code: 'probe_timeout', message: 'Desired optional service state could not be determined because its health check timed out.',
    });
    Object.assign(components.find((component) => component.id === 'gitea'), {
      observed_state: 'running_undesired', reachable: true, healthy: true,
      reason_code: 'running_undesired', message: 'Running although desired off; apply the component selection to stop it without deleting data.',
    });
    for (const component of components) component.apply_command = 'make apply-components COMPONENTS=monitoring';
  }
  return {
    installation_id: '012345abcdef', allowed_roots: ['/workspace/generated'], scanner_url: `${origin}/fixture/scanner`,
    ...active,
    ollama_available: false, ollama_models: [], ollama_reason: 'Generated local advisor is intentionally unavailable.',
    component_apply_command: componentApplyCommand,
    components,
    schema_init: fixture.profile === 'schema-unverified'
      ? {
        id: 'schema-init', lifecycle: 'one-shot', startable: false, state: 'unverified',
        message: 'Schema is current, but no matching schema-init completion receipt is available.',
        schema_id: null, schema_fingerprint: null, initialized_at: null, evidence: null,
      }
      : {
        id: 'schema-init', lifecycle: 'one-shot', startable: false, state: 'completed',
        message: 'Completed successfully; expected to stop.',
        schema_id: 'lomo-kodesec-0.1.0-initial',
        schema_fingerprint: 'c46a2a6c140c7ea9151b6a7414164ce5c10a9e70d8973cc5b09be4007e537517',
        initialized_at: '2026-08-25T08:00:00Z', evidence: 'schema-identity-and-api-startup-verification',
      },
  };
}

function scannerPreflight() {
  const enabledTools = fixture.tools.filter((tool) => tool.enabled);
  const readyTools = enabledTools.filter((tool) => tool.runtime_ready === true);
  const blockedTools = enabledTools.filter((tool) => tool.runtime_ready !== true).map((tool) => {
    const facets = tool.readiness && typeof tool.readiness === 'object' ? Object.entries(tool.readiness) : [];
    const blockingFacets = facets.filter(([, facet]) => facet && !['ready', 'not_required'].includes(facet.state));
    const blockingReasons = [...new Set(blockingFacets
      .map(([, facet]) => facet.reason)
      .filter((reason) => typeof reason === 'string' && reason))];
    const requiredComponentIds = [...new Set(blockingFacets
      .flatMap(([name, facet]) => (
        ['data', 'rules'].includes(name) && Array.isArray(facet.component_ids)
          ? facet.component_ids
          : []
      )))].sort();
    const preparationBlockingReasons = [...new Set(blockingFacets
      .filter(([name, facet]) => !['data', 'rules'].includes(name) || !Array.isArray(facet.component_ids) || !facet.component_ids.length)
      .map(([, facet]) => facet.reason)
      .filter((reason) => typeof reason === 'string' && reason))];
    if (!blockingFacets.length) preparationBlockingReasons.push('Runtime readiness was not reported.');
    return {
      id: tool.id,
      name: tool.name,
      blocking_reasons: blockingReasons.length ? blockingReasons : ['Runtime readiness was not reported.'],
      required_component_ids: requiredComponentIds,
      preparation_blocking_reasons: preparationBlockingReasons,
    };
  });
  const requiredComponentIds = [...new Set(blockedTools.flatMap((tool) => tool.required_component_ids))].sort();
  const preparationAvailable = blockedTools.length > 0
    && requiredComponentIds.length > 0
    && blockedTools.every((tool) => tool.preparation_blocking_reasons.length === 0);
  const previousGeneration = fixture.scannerLifecycle.cache.previous_generation;
  const cacheRollback = fixture.profile === 'scanner-rollback-incompatible'
    ? {
      eligible: false,
      reason_code: 'different_reviewed_locks',
      reason: 'The previous cache generation was built from different reviewed scanner locks. Prepare a verified cache for the current scanner catalog instead.',
      target_generation: previousGeneration,
    }
    : previousGeneration
      ? {
        eligible: true,
        reason_code: 'eligible',
        reason: 'The previous verified cache generation is compatible and can be restored atomically.',
        target_generation: previousGeneration,
      }
      : {
        eligible: false,
        reason_code: 'no_previous_generation',
        reason: 'No previous-good scanner cache generation is available.',
        target_generation: null,
      };
  const body = {
    schema_version: 1,
    ready: enabledTools.length > 0 && blockedTools.length === 0,
    enabled_tool_ids: enabledTools.map((tool) => tool.id).sort(),
    ready_tool_ids: readyTools.map((tool) => tool.id).sort(),
    blocked_tools: blockedTools.sort((left, right) => left.id.localeCompare(right.id)),
    required_component_ids: requiredComponentIds,
    preparation_available: preparationAvailable,
    active_generation: fixture.scannerLifecycle.cache.active_generation,
    catalog_revision: fixture.scannerPreparationPending ? null : fixture.scannerLifecycle.catalog.revision,
    cache_revision: fixture.scannerPreparationPending ? null : fixture.scannerLifecycle.cache.revision,
    cache_rollback: cacheRollback,
    recommended_action: enabledTools.length === 0
      ? 'enable_scanner'
      : blockedTools.length === 0
        ? 'scan'
        : preparationAvailable
          ? 'prepare_scanners'
          : 'repair_scanner_runtime',
  };
  return {
    ...body,
    revision: createHash('sha256').update(JSON.stringify(body)).digest('hex'),
  };
}

function enabledFixtureToolStatus(tool) {
  // Availability/status is separate from strict runtime readiness. Enabling
  // an available scanner restores its configured status;
  // degraded or absent facets still block preflight through runtime_ready.
  return tool.available ? 'ready' : 'missing';
}

function summary() {
  const severityCounts = {};
  const scannerCounts = {};
  const scannerSeverityCounts = {};
  for (const finding of fixture.findings) {
    severityCounts[finding.severity || 'info'] = (severityCounts[finding.severity || 'info'] || 0) + 1;
    scannerCounts[finding.scanner || 'unknown'] = (scannerCounts[finding.scanner || 'unknown'] || 0) + 1;
    scannerSeverityCounts[finding.scanner || 'unknown'] ??= {};
    scannerSeverityCounts[finding.scanner || 'unknown'][finding.severity || 'info'] = (
      scannerSeverityCounts[finding.scanner || 'unknown'][finding.severity || 'info'] || 0
    ) + 1;
  }
  return {
    projects: fixture.projects.length,
    scans: fixture.scans.length,
    findings: fixture.findings.length,
    finding_occurrences: fixture.findings.reduce((total, finding) => total + (finding.occurrence_count || 1), 0),
    artifacts: fixture.artifacts.length,
    severity_counts: severityCounts,
    scanner_counts: scannerCounts,
    scanner_severity_counts: scannerSeverityCounts,
    top_rules: fixture.findings.length
      ? [{ scanner: 'opengrep', rule_id: 'javascript.lang.audit.dynamic-code', severity: 'high', count: 1 }]
      : [],
    recent_scans: fixture.scans,
  };
}

async function bodyJson(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 16_384) throw new Error('Fixture body exceeds 16 KiB.');
  }
  return body ? JSON.parse(body) : {};
}

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
  response.end(body);
}

function text(response, status, body, type = 'text/plain; charset=utf-8') {
  response.writeHead(status, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
  response.end(body);
}

function applyFixtureLifecycle(finding, action, reason) {
  if (!lifecycleActions.has(action)) throw fixtureHttpError(422, `unsupported finding lifecycle action: ${action}`);
  if (typeof reason === 'string' && reason.length > 500) {
    throw fixtureHttpError(422, 'finding lifecycle reason must be at most 500 characters');
  }
  const normalizedReason = typeof reason === 'string' ? reason.trim() : '';
  if (reasonRequiredActions.has(action) && !normalizedReason) {
    throw fixtureHttpError(422, `reason is required for finding lifecycle action: ${action}`);
  }
  finding.lifecycle_status = action;
  finding.revision += 1;
  finding.suppression_reason = null;
  finding.gate_exempt_reason = null;
  finding.lifecycle_reason = normalizedReason || null;
  finding.lifecycle_updated_at = time.updated;
  if (['ignore', 'false_positive', 'fixed'].includes(action)) {
    finding.suppressed = true;
    finding.gate_exempt = false;
    finding.suppression_reason = normalizedReason;
  } else {
    finding.suppressed = false;
    finding.gate_exempt = ['gate_exempt', 'accepted_risk'].includes(action);
    if (finding.gate_exempt) finding.gate_exempt_reason = normalizedReason;
  }
  finding.gate_effect = finding.suppressed ? 'excluded' : finding.gate_exempt ? 'non_blocking' : 'blocking';
}

const mime = new Map([['.css', 'text/css; charset=utf-8'], ['.html', 'text/html; charset=utf-8'], ['.js', 'text/javascript; charset=utf-8'], ['.json', 'application/json; charset=utf-8'], ['.png', 'image/png']]);

function staticFile(response, pathname) {
  const relative = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  let file = resolve(dist, relative);
  if (file !== dist && !file.startsWith(`${dist}${sep}`)) return text(response, 400, 'Invalid path.');
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html');
  const stat = statSync(file);
  response.writeHead(200, { 'Content-Type': mime.get(extname(file)) || 'application/octet-stream', 'Content-Length': stat.size, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  createReadStream(file).pipe(response);
}

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url || '/', origin);
    const pathname = requestUrl.pathname;
    if (request.method === 'POST' && pathname === '/__test/reset') {
      const input = await bodyJson(request);
      const profile = ['persistent', 'focus', 'durable', 'worker-unavailable', 'advisor-evidence', 'advisor-failure', 'advisor-remote-disabled', 'advisor-local-empty', 'evidence-edges', 'advisor-running', 'scan-state-edges', 'scanner-lifecycle-failures', 'scanner-lock-refresh', 'scanner-rollback-incompatible', 'scanner-readiness-missing', 'scanner-preparation', 'first-run', 'limited-evidence', 'job-activity', 'component-truth', 'schema-unverified', 'finding-revision-advance', 'finding-immutable-evidence-change', 'large-findings', 'paginated-findings', 'findings-scale-1000', 'findings-scale-5000', 'findings-scale-10000', 'quiescent', 'auth-required', 'responsive-long-content', 'findings-first-viewport'].includes(input.profile) ? input.profile : 'fresh';
      fixture = buildFixture(profile, Number.isInteger(input.generation) ? input.generation : fixture.generation + 1);
      requestCounts = {
        findings: 0,
        findingDetails: 0,
        scanSummaries: 0,
        artifacts: 0,
        projects: 0,
        advisorProviderResolutions: 0,
        advisorPreviews: 0,
        advisorSubmissions: 0,
      };
      commandRequests = [];
      advisorProviderJobsByIdempotencyKey = new Map();
      return json(response, 200, { profile: fixture.profile, generation: fixture.generation });
    }
    if (request.method === 'GET' && pathname === '/__test/state') return json(response, 200, { profile: fixture.profile, generation: fixture.generation });
    if (request.method === 'GET' && pathname === '/__test/requests') return json(response, 200, requestCounts);
    if (request.method === 'GET' && pathname === '/__test/commands') return json(response, 200, commandRequests);
    if (request.method === 'GET' && pathname === '/__test/auth-state') {
      return json(response, 200, {
        authenticated: fixture.authSessionAuthenticated,
        bootstrap_attempts: fixture.authBootstrapAttempts,
      });
    }
    if (request.method === 'POST' && pathname === '/__test/auth-revoke') {
      fixture.authRequired = true;
      fixture.authSessionAuthenticated = false;
      return json(response, 200, { authenticated: false });
    }
    if (request.method === 'POST' && pathname === '/__test/advisor-provider-authorize') {
      const input = await bodyJson(request);
      const provider = fixture.advisorProviders.find((candidate) => candidate.id === input.provider_id);
      if (!provider || provider.transport === 'local') return json(response, 404, { detail: 'Remote Advisor provider not found.' });
      if (provider.transport === 'direct') {
        const host = new URL(provider.base_url).hostname.toLowerCase();
        if (!fixture.advisorAuthorizedDirectHosts.includes(host)) fixture.advisorAuthorizedDirectHosts.push(host);
      } else if (!fixture.advisorAuthorizedSshProviderIds.includes(provider.id)) {
        fixture.advisorAuthorizedSshProviderIds.push(provider.id);
      }
      return json(response, 200, advisorProviderCollection());
    }
    if (request.method === 'POST' && pathname === '/__test/first-run/core-ready') {
      if (fixture.profile !== 'first-run') return json(response, 409, { detail: 'first-run fixture is not active' });
      fixture.firstRunCoreReady = true;
      fixture.generation += 1;
      return json(response, 200, { ready: true, generation: fixture.generation });
    }
    if (request.method === 'POST' && pathname === '/__test/first-run/scanners-ready') {
      if (fixture.profile !== 'first-run') return json(response, 409, { detail: 'first-run fixture is not active' });
      const opengrep = fixture.tools.find((tool) => tool.id === 'opengrep');
      if (!opengrep?.readiness) return json(response, 500, { detail: 'first-run OpenGrep fixture is unavailable' });
      opengrep.runtime_ready = true;
      opengrep.readiness.rules = {
        state: 'ready',
        reason: null,
        component_ids: ['opengrep-reviewed-rules'],
      };
      fixture.scannerLifecycle.cache.active_generation = createHash('sha256')
        .update('generated-first-run-ready-cache')
        .digest('hex');
      fixture.scannerPreparationPending = false;
      fixture.generation += 1;
      return json(response, 200, scannerPreflight());
    }
    if (request.method === 'POST' && pathname === '/__test/scanner-preflight-change') {
      fixture.generation += 1;
      const blockedTool = fixture.tools.find((tool) => tool.runtime_ready === false);
      if (blockedTool?.readiness?.rules) {
        blockedTool.readiness.rules.reason = `Scanner rules readiness changed in generation ${fixture.generation}.`;
      }
      return json(response, 200, scannerPreflight());
    }
    if (request.method === 'GET' && pathname === '/v1/auth/session') {
      return fixture.authRequired && !fixture.authSessionAuthenticated
        ? json(response, 401, { detail: { code: 'authentication_required', message: 'Pair this browser with a current one-time browser pairing key.' } })
        : json(response, 200, { authenticated: true, csrf_token: 'fixture-csrf-token', expires_in: 3600 });
    }
    if (request.method === 'POST' && pathname === '/v1/auth/bootstrap') {
      const input = await bodyJson(request);
      const candidate = typeof input.bootstrap_token === 'string' ? input.bootstrap_token : '';
      fixture.authBootstrapAttempts.push(candidate);
      if (candidate === 'expired-bootstrap') {
        return json(response, 401, { detail: { code: 'bootstrap_expired', message: 'That one-time browser pairing key expired. Generate a new key in Settings or use owner recovery.' } });
      }
      if (!['valid-bootstrap', 'repair-bootstrap'].includes(candidate)) {
        return json(response, 401, { detail: { code: 'bootstrap_invalid', message: 'That one-time browser pairing key is invalid.' } });
      }
      fixture.authRequired = true;
      fixture.authSessionAuthenticated = true;
      return json(response, 200, { authenticated: true, csrf_token: 'fixture-csrf-token', expires_in: 3600 });
    }
    if (fixture.authRequired && !fixture.authSessionAuthenticated && pathname.startsWith('/v1/')) {
      return json(response, 401, { detail: { code: 'authentication_required', message: 'This browser member is missing or revoked, or its local cookie was removed.' } });
    }
    if (request.method === 'GET' && pathname === '/v1/git/push-protection') {
      // Synthetic fixtures do not register repository push-protection policies.
      return json(response, 200, { repositories: [] });
    }
    if (request.method === 'GET' && pathname === '/healthz') {
      const worker = fixture.profile !== 'worker-unavailable' && fixture.firstRunCoreReady !== false;
      const runtime = fixture.runtimeConfig;
      return json(response, 200, {
        ok: worker,
        version: 'fixture-1',
        db: true,
        scanner: true,
        worker,
        ai: {
          mode: runtime.ai_mode,
          available: false,
          base_url: runtime.ollama_base_url,
          model: runtime.ollama_model,
          thinking: runtime.ollama_thinking,
          models: [],
          reason: runtime.ai_mode === 'off'
            ? 'Generated local advisor is disabled by the saved runtime setting.'
            : 'Generated local advisor is intentionally unavailable.',
        },
      });
    }
    if (request.method === 'GET' && pathname === '/v1/dashboard/summary') return json(response, 200, summary());
    if (request.method === 'GET' && pathname === '/v1/auth/browser/sessions') {
      return json(response, 200, fixture.browserMembers);
    }
    if (request.method === 'DELETE' && pathname.startsWith('/v1/auth/browser/sessions/')) {
      const memberId = decodeURIComponent(pathname.slice('/v1/auth/browser/sessions/'.length));
      const member = fixture.browserMembers.find((candidate) => candidate.id === memberId);
      if (!member) return json(response, 404, { detail: 'browser member not found' });
      const input = await bodyJson(request);
      if (input.expected_created_at !== member.created_at) {
        return json(response, 409, { detail: {
          code: 'browser_member_revision_conflict',
          message: 'The browser member changed before this revocation was applied.',
          action: 'refresh_browser_members',
        } });
      }
      fixture.browserMembers = fixture.browserMembers.filter((candidate) => candidate.id !== memberId);
      if (member.current) fixture.authSessionAuthenticated = false;
      return json(response, 200, { revoked: true, current: member.current });
    }
    if (request.method === 'GET' && pathname === '/v1/auth/ide/capabilities') return json(response, 200, []);
    if (request.method === 'GET' && pathname === '/v1/auth/ide/enrollments') return json(response, 200, []);
    if (request.method === 'POST' && pathname === '/v1/projects') {
      requestCounts.projects += 1;
      const input = await bodyJson(request);
      if (!String(input.repo_path || '').startsWith('/workspace/generated/')) {
        return json(response, 422, { detail: {
          code: 'source_outside_allowed_root',
          message: 'Choose a repository inside an authorized source root.',
          action: 'authorize_source',
          context: {
            selected_path: String(input.repo_path || '').slice(0, 512),
            allowed_roots: ['/workspace/generated'],
          },
        } });
      }
      const project = {
        id: Math.max(0, ...fixture.projects.map((item) => item.id)) + 1,
        name: String(input.name || ''),
        repo_path: String(input.repo_path || ''),
        remote_url: String(input.remote_url || ''),
        default_branch: String(input.default_branch || 'main'),
        revision: 1,
        created_at: time.created,
      };
      fixture.projects.push(project);
      fixture.projectGatePolicies[project.id] = {
        active: fixture.runtimeConfig.gate_active,
        max_critical: fixture.runtimeConfig.gate_max_critical,
        max_high: fixture.runtimeConfig.gate_max_high,
        block_secrets: fixture.runtimeConfig.gate_block_secrets,
      };
      return json(response, 201, project);
    }
    if (request.method === 'GET' && pathname === '/v1/projects') {
      return json(response, 200, [...fixture.projects].sort((left, right) => right.id - left.id));
    }
    const projectGateRoute = pathname.match(/^\/v1\/gate-policies\/(\d+)$/);
    if (projectGateRoute && ['GET', 'PUT'].includes(request.method)) {
      const projectId = Number(projectGateRoute[1]);
      if (!fixture.projects.some(project => project.id === projectId)) {
        return json(response, 404, { detail: 'gate policy not found' });
      }
      const current = fixtureProjectGate(projectId);
      if (request.method === 'GET') return json(response, 200, { project_id: projectId, ...current });
      const input = await bodyJson(request);
      if (!input || Array.isArray(input) || typeof input !== 'object') return json(response, 422, { detail: 'Invalid project gate policy.' });
      const keys = ['active', 'max_critical', 'max_high', 'block_secrets'];
      const parseValues = value => {
        if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).some(key => !keys.includes(key))) return null;
        const parsed = { active: true, max_critical: 0, max_high: -1, block_secrets: true, ...value };
        return typeof parsed.active === 'boolean' && typeof parsed.block_secrets === 'boolean'
          && [parsed.max_critical, parsed.max_high].every(number => Number.isInteger(number) && number >= -1 && number <= 999) ? parsed : null;
      };
      const { expected_policy: expectedInput, ...values } = input;
      const saved = parseValues(values);
      const expected = parseValues(expectedInput);
      if (!saved || !expected) return json(response, 422, { detail: 'Invalid project gate policy.' });
      if (!keys.every(key => current[key] === expected[key])) {
        return json(response, 409, { detail: "This project's gate policy changed. Reload the policy and review your draft before saving." });
      }
      fixture.projectGatePolicies[projectId] = saved;
      for (const scan of fixture.scans) {
        if (scan.project_id !== projectId || !['completed', 'partial', 'failed', 'cancelled'].includes(scan.status)) continue;
        evaluateFixtureScanGate(scan);
        scan.revision += 1;
      }
      return json(response, 200, { project_id: projectId, ...saved });
    }
    const projectDeleteRoute = pathname.match(/^\/v1\/projects\/(\d+)$/);
    if (request.method === 'DELETE' && projectDeleteRoute) {
      const projectId = Number(projectDeleteRoute[1]);
      const projectIndex = fixture.projects.findIndex((project) => project.id === projectId);
      if (projectIndex < 0) return json(response, 404, { detail: 'project not found' });
      const projectScanIds = new Set(fixture.scans.filter((scan) => scan.project_id === projectId).map((scan) => scan.id));
      const activeJob = activeJobForScanIds(projectScanIds);
      if (activeJob) return json(response, 409, { detail: `resource has active durable job #${activeJob.id}; cancel and wait for terminal cleanup first` });
      fixture.projects.splice(projectIndex, 1);
      delete fixture.projectGatePolicies[projectId];
      fixture.scans = fixture.scans.filter((scan) => scan.project_id !== projectId);
      const retainedScanIds = new Set(fixture.scans.map((scan) => scan.id));
      fixture.findings = fixture.findings.filter((finding) => retainedScanIds.has(finding.scan_id));
      fixture.artifacts = fixture.artifacts.filter((artifact) => retainedScanIds.has(artifact.scan_id));
      fixture.jobs = fixture.jobs.filter((job) => !job.scan_id || retainedScanIds.has(job.scan_id));
      return json(response, 200, { deleted: true });
    }
    if (request.method === 'POST' && pathname === '/v1/scans') {
      const input = await bodyJson(request);
      const projectId = Number(input.project_id);
      if (!fixture.projects.some((project) => project.id === projectId)) {
        return json(response, 404, { detail: 'project not found' });
      }
      const preflight = scannerPreflight();
      const coverage = input.coverage || 'complete';
      if (input.preflight_revision !== preflight.revision) {
        return json(response, 409, { detail: {
          code: 'scanner_preflight_changed',
          message: 'Scanner readiness changed after it was reviewed. Review the current preflight before starting a scan.',
          action: 'review_scanner_preflight',
          context: { preflight_revision: preflight.revision },
        } });
      }
      if (coverage === 'complete' && !preflight.ready) {
        return json(response, 409, { detail: {
          code: preflight.recommended_action === 'enable_scanner' ? 'no_scanner_tools_enabled' : 'scanner_preparation_required',
          message: preflight.recommended_action === 'enable_scanner'
            ? 'Enable at least one scanner before starting a scan.'
            : 'Prepare every enabled scanner before starting a complete scan.',
          action: preflight.recommended_action,
          context: {
            preflight_revision: preflight.revision,
            blocked_tool_ids: preflight.blocked_tools.map((tool) => tool.id),
            required_component_ids: preflight.required_component_ids,
          },
        } });
      }
      if (coverage === 'limited' && (input.acknowledge_limited_coverage !== true || preflight.ready_tool_ids.length === 0)) {
        return json(response, 422, { detail: {
          code: 'limited_coverage_acknowledgement_required',
          message: 'A limited scan requires an explicit acknowledgement and at least one ready scanner.',
          action: 'review_limited_coverage',
          context: { preflight_revision: preflight.revision },
        } });
      }
      if (!durableCommand(request, response, 'scan', input)) return;
      const scan = {
        id: Math.max(0, ...fixture.scans.map((item) => item.id)) + 1,
        project_id: projectId,
        mode: String(input.mode || 'full'),
        base_ref: input.base_ref || null,
        head_ref: input.head_ref || null,
        status: 'pending',
        gate_decision: 'pending',
        gate_reasons: [],
        scanner_summary: { findings_total: 0 },
        error: null,
        started_at: null,
        completed_at: null,
        duration_ms: null,
        revision: 1,
        findings_revision: 1,
        created_at: time.created,
      };
      const job = queuedJob({ kind: 'scan', title: `Scan #${scan.id}`, scan_id: scan.id });
      scan.job_id = job.id;
      scan.job_revision = job.revision;
      fixture.scans.unshift(scan);
      return json(response, 202, scan);
    }
    if (request.method === 'GET' && pathname === '/v1/scans') return json(response, 200, fixture.scans);
    const scanSummaryRoute = pathname.match(/^\/v1\/scans\/(\d+)\/summary$/);
    if (request.method === 'GET' && scanSummaryRoute) {
      requestCounts.scanSummaries += 1;
      const scan = requireScan(Number(scanSummaryRoute[1]));
      return json(response, 200, scanSummary(scan));
    }
    const scanDetailRoute = pathname.match(/^\/v1\/scans\/(\d+)$/);
    if (request.method === 'DELETE' && scanDetailRoute) {
      const scanId = Number(scanDetailRoute[1]);
      if (!fixture.scans.some((scan) => scan.id === scanId)) return json(response, 404, { detail: 'scan not found' });
      const activeJob = activeJobForScanIds(new Set([scanId]));
      if (activeJob) return json(response, 409, { detail: `resource has active durable job #${activeJob.id}; cancel and wait for terminal cleanup first` });
      fixture.scans = fixture.scans.filter((scan) => scan.id !== scanId);
      fixture.findings = fixture.findings.filter((finding) => finding.scan_id !== scanId);
      fixture.artifacts = fixture.artifacts.filter((artifact) => artifact.scan_id !== scanId);
      fixture.jobs = fixture.jobs.filter((job) => job.scan_id !== scanId);
      return json(response, 200, { deleted: true });
    }
    if (request.method === 'GET' && scanDetailRoute) {
      return json(response, 200, requireScan(Number(scanDetailRoute[1])));
    }
    const jobDetailRoute = pathname.match(/^\/v1\/jobs\/(\d+)$/);
    if (request.method === 'GET' && jobDetailRoute) {
      const job = fixture.jobs.find((item) => item.id === Number(jobDetailRoute[1]));
      if (job?.kind === 'advisor_provider' && job.status === 'cancelling') {
        job.status = 'cancelled';
        job.stage = 'cancelled';
        job.detail = 'Cancellation confirmed; connector temporary state was cleaned.';
        job.completed_at = time.completed;
        job.updated_at = time.completed;
        job.revision += 1;
      }
      if (job?.kind === 'advisor_provider' && ['queued', 'leased', 'pending', 'running'].includes(job.status)) {
        const provider = fixture.advisorProviders.find((candidate) => candidate.id === job.provider_id);
        if (!provider?.name.startsWith('Stalled') || job.fixture_retried) completeAdvisorProviderJob(job);
      }
      return job ? json(response, 200, job) : json(response, 404, { detail: 'job not found' });
    }
    if (request.method === 'GET' && pathname === '/v1/jobs') {
      const status = requestUrl.searchParams.get('status');
      const requestedLimit = Number(requestUrl.searchParams.get('limit') || '100');
      const limit = Number.isSafeInteger(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 500)) : 100;
      const activeStatuses = new Set(['queued', 'leased', 'running', 'cancelling']);
      const jobs = status === 'active'
        ? fixture.jobs.filter((job) => activeStatuses.has(job.status))
        : status
          ? fixture.jobs.filter((job) => job.status === status)
          : fixture.jobs;
      return json(response, 200, jobs.slice(0, limit));
    }
    if (request.method === 'GET' && pathname === '/v1/scanner/tools') return json(response, 200, fixture.tools);
    if (request.method === 'GET' && pathname === '/v1/scanner/preflight') return json(response, 200, scannerPreflight());
    if (request.method === 'GET' && pathname === '/v1/scanner/lifecycle') return json(response, 200, fixture.scannerLifecycle);
    if (request.method === 'POST' && pathname === '/v1/scanner/prepare') {
      const input = await bodyJson(request);
      if (!durableCommand(request, response, 'scanner-prepare', input)) return;
      const preflight = scannerPreflight();
      if (preflight.ready) {
        return json(response, 409, { detail: {
          code: 'scanners_already_ready',
          message: 'All enabled scanners already have verified binaries, data, rules, and offline execution.',
          action: 'scan',
        } });
      }
      if (!preflight.preparation_available || !preflight.required_component_ids.length) {
        return json(response, 409, { detail: {
          code: 'scanner_runtime_prerequisite_missing',
          message: 'Scanner preparation cannot repair a missing scanner binary or offline execution prerequisite.',
          action: 'repair_scanner_runtime',
          context: {
            tool_ids: preflight.blocked_tools
              .filter((tool) => tool.preparation_blocking_reasons.length)
              .map((tool) => tool.id),
            blocking_reasons: preflight.blocked_tools
              .flatMap((tool) => tool.preparation_blocking_reasons)
              .slice(0, 8),
          },
          safe_details: { reason_code: 'runtime_prerequisite_missing' },
        } });
      }
      const catalogJob = queuedJob({
        kind: 'scanner_catalog_check',
        title: 'Check curated scanner catalog',
        detail: 'Persisted the catalog stage for scanner preparation.',
        component_ids: [],
      });
      const catalogLifecycle = bindLifecycleJob('catalog', catalogJob, {
        active_generation: null,
        previous_generation: null,
      });
      return json(response, 202, {
        catalog: { job: catalogJob, lifecycle: catalogLifecycle },
        cache: null,
        required_component_ids: preflight.required_component_ids,
      });
    }
    if (request.method === 'POST' && pathname === '/v1/scanner/tools/check-latest') {
      const input = await bodyJson(request);
      if (!durableCommand(request, response, 'scanner-catalog-check', input)) return;
      const job = queuedJob({ kind: 'scanner_catalog_check', title: 'Check curated scanner catalog' });
      const lifecycle = bindLifecycleJob('catalog', job, { active_generation: null, previous_generation: null });
      return json(response, 202, { job, lifecycle });
    }
    if (request.method === 'POST' && pathname === '/v1/scanner/cache/update') {
      const input = await bodyJson(request);
      if (!durableCommand(request, response, 'scanner-cache-update', input)) return;
      const componentIds = Array.isArray(input.component_ids) ? input.component_ids : [];
      const allowed = new Set(['trivy-db', 'trivy-java-db', 'trivy-checks', 'opengrep-reviewed-rules', 'bearer-rules', 'grype-db']);
      if (!componentIds.length || componentIds.some((item) => !allowed.has(item))) return json(response, 422, { error: 'Generated cache component selection is invalid.' });
      const job = queuedJob({ kind: 'scanner_cache_update', title: 'Update verified offline scanner cache', detail: `Persisted ${componentIds.length} selected cache components.` });
      const lifecycle = bindLifecycleJob('cache', job);
      return json(response, 202, { job, lifecycle });
    }
    if (request.method === 'POST' && pathname === '/v1/scanner/cache/rollback') {
      const input = await bodyJson(request);
      if (!durableCommand(request, response, 'scanner-cache-rollback', input)) return;
      if (!fixture.scannerLifecycle.cache.previous_generation) return json(response, 409, { error: 'Generated previous-good cache generation is unavailable.' });
      if (fixture.profile === 'scanner-rollback-incompatible') {
        return json(response, 409, {
          detail: {
            code: 'scanner_cache_rollback_unavailable',
            message: 'The previous cache generation was built from different reviewed scanner locks. Prepare a verified cache for the current scanner catalog instead.',
            action: 'prepare_scanners',
            context: {
              reason_code: 'different_reviewed_locks',
              target_generation: fixture.scannerLifecycle.cache.previous_generation,
            },
          },
        });
      }
      const job = queuedJob({ kind: 'scanner_cache_rollback', title: 'Roll back verified offline scanner cache', detail: 'Persisted one previous-good rollback command.' });
      const lifecycle = bindLifecycleJob('cache', job);
      return json(response, 202, { job, lifecycle });
    }
    const toolUpdate = pathname.match(/^\/v1\/scanner\/tools\/([a-z0-9-]+)\/update$/);
    if (request.method === 'POST' && toolUpdate) {
      const tool = fixture.tools.find((item) => item.id === toolUpdate[1]);
      if (!tool) return json(response, 404, { error: 'Generated tool not found.' });
      if (!tool.candidate_manifest_sha256) return json(response, 409, { error: 'Generated candidate has no admitted manifest attestation.' });
      tool.pinned_version = tool.latest_version;
      tool.status = 'host_confirmation_required';
      return json(response, 200, tool);
    }
    const toolPatch = pathname.match(/^\/v1\/scanner\/tools\/([a-z0-9-]+)$/);
    if (request.method === 'PATCH' && toolPatch) {
      const input = await bodyJson(request);
      const tool = fixture.tools.find((item) => item.id === toolPatch[1]);
      if (!tool) return json(response, 404, { error: 'Generated tool not found.' });
      if (typeof input.enabled !== 'boolean') return json(response, 422, { error: 'Generated tool enabled state must be boolean.' });
      tool.enabled = input.enabled;
      tool.status = tool.enabled ? enabledFixtureToolStatus(tool) : 'disabled';
      tool.updated_at = time.updated;
      return json(response, 200, tool);
    }
    if (request.method === 'GET' && pathname === '/v1/config') return json(response, 200, config());
    if (request.method === 'GET' && pathname === '/v1/advisor/local-models') {
      return json(response, 200, {
        schema: 'lomo-advisor-local-catalog/v1',
        source: 'dedicated_local_connector',
        models: [
          { name: 'qwen3:8b', digest: 'e'.repeat(64), size_bytes: 5_200_000_000, storage: 'local_weights' },
          { name: 'minimax-m3:cloud', digest: 'f'.repeat(64), size_bytes: 301, storage: 'cloud_stub' },
          { name: 'kimi-k3:cloud', digest: '1'.repeat(64), size_bytes: 302, storage: 'cloud_stub' },
          { name: 'glm-5.2:cloud', digest: '2'.repeat(64), size_bytes: 303, storage: 'cloud_stub' },
          { name: 'kimi-k2.7-code:cloud', digest: '3'.repeat(64), size_bytes: 304, storage: 'cloud_stub' },
          { name: 'kimi-k2.6:cloud', digest: '4'.repeat(64), size_bytes: 305, storage: 'cloud_stub' },
          { name: 'glm-5.1:cloud', digest: '5'.repeat(64), size_bytes: 306, storage: 'cloud_stub' },
        ],
        recommended_model: 'qwen3:8b',
      });
    }
    if (request.method === 'GET' && pathname === '/v1/advisor/providers') {
      requestCounts.advisorProviderResolutions += 1;
      return json(response, 200, advisorProviderCollection());
    }
    const advisorProviderReceiptRoute = pathname.match(/^\/v1\/advisor\/providers\/([a-zA-Z0-9-]+)\/receipt$/);
    if (advisorProviderReceiptRoute && request.method === 'GET') {
      const provider = fixture.advisorProviders.find((candidate) => candidate.id === advisorProviderReceiptRoute[1]);
      if (!provider) return json(response, 404, { detail: 'advisor provider not found' });
      const receipt = fixture.advisorProviderReceipts[provider.id];
      if (!advisorReceiptMatches(provider)) return json(response, 404, { detail: 'no current verified receipt exists for this provider' });
      return json(response, 200, receipt);
    }
    if (request.method === 'POST' && pathname === '/v1/advisor/providers') {
      const input = await bodyJson(request);
      if (input.expected_revision !== fixture.advisorProviderRevision) {
        return json(response, 409, { detail: 'Advisor provider configuration changed; reload before adding a provider.' });
      }
      if (fixture.advisorProviders.length >= 8) return json(response, 409, { detail: 'The bounded provider chain already contains eight profiles.' });
      const provider = validateAdvisorProvider(input.provider);
      if (fixture.advisorProviders.some((candidate) => candidate.id === provider.id)) return json(response, 422, { detail: 'advisor provider id already exists' });
      if (fixture.advisorProviders.some((candidate) => candidate.priority === provider.priority)) return json(response, 422, { detail: 'Advisor provider priority already exists.' });
      fixture.advisorProviders.push(provider);
      fixture.advisorProviderRevision += 1;
      return json(response, 201, advisorProviderCollection());
    }
    const advisorProviderRoute = pathname.match(/^\/v1\/advisor\/providers\/([a-zA-Z0-9-]+)$/);
    if (advisorProviderRoute && request.method === 'PUT') {
      const input = await bodyJson(request);
      const providerId = advisorProviderRoute[1];
      if (input.expected_revision !== fixture.advisorProviderRevision) return json(response, 409, { detail: 'Advisor provider configuration changed; reload before editing.' });
      const index = fixture.advisorProviders.findIndex((provider) => provider.id === providerId);
      if (index < 0) return json(response, 404, { detail: 'Advisor provider not found.' });
      if (input.provider?.id !== providerId) return json(response, 422, { detail: 'Advisor provider id cannot change.' });
      const provider = validateAdvisorProvider(input.provider);
      const previous = fixture.advisorProviders[index];
      const previousPriority = previous.priority;
      const swapped = fixture.advisorProviders.find((candidate) => candidate.id !== providerId && candidate.priority === provider.priority);
      const changedIds = [providerId];
      if (swapped) {
        swapped.priority = previousPriority;
        swapped.config_revision += 1;
        swapped.config_digest = advisorProviderConfigDigest(swapped);
        swapped.content_disclosure_approved = false;
        swapped.status = 'available';
        swapped.reason = 'Provider order changed; test and activate this exact configuration again.';
        swapped.reason_code = 'provider_configuration_changed';
        swapped.remediation = 'activate';
        changedIds.push(swapped.id);
      }
      provider.config_revision = previous.config_revision + 1;
      provider.config_digest = advisorProviderConfigDigest(provider);
      fixture.advisorProviders[index] = provider;
      if (changedIds.includes(fixture.activeAdvisorProviderId)) fixture.activeAdvisorProviderId = null;
      changedIds.forEach((changedId) => {
        delete fixture.advisorProviderReceipts[changedId];
        delete fixture.advisorProviderConsents[changedId];
      });
      fixture.advisorProviderRevision += 1;
      return json(response, 200, advisorProviderCollection());
    }
    if (advisorProviderRoute && request.method === 'DELETE') {
      const input = await bodyJson(request);
      const providerId = advisorProviderRoute[1];
      if (input.expected_revision !== fixture.advisorProviderRevision) return json(response, 409, { detail: 'Advisor provider configuration changed; reload before removing it.' });
      const index = fixture.advisorProviders.findIndex((provider) => provider.id === providerId);
      if (index < 0) return json(response, 404, { detail: 'Advisor provider not found.' });
      fixture.advisorProviders.splice(index, 1);
      if (fixture.activeAdvisorProviderId === providerId) fixture.activeAdvisorProviderId = null;
      delete fixture.advisorProviderReceipts[providerId];
      delete fixture.advisorProviderConsents[providerId];
      fixture.advisorProviderRevision += 1;
      return json(response, 200, advisorProviderCollection());
    }
    const advisorProviderCommandRoute = pathname.match(/^\/v1\/advisor\/providers\/([a-zA-Z0-9-]+)\/commands$/);
    if (advisorProviderCommandRoute && request.method === 'POST') {
      const input = await bodyJson(request);
      const provider = fixture.advisorProviders.find((candidate) => candidate.id === advisorProviderCommandRoute[1]);
      if (!provider) return json(response, 404, { detail: 'Advisor provider not found.' });
      if (input.expected_revision !== fixture.advisorProviderRevision) return json(response, 409, { detail: 'Advisor provider configuration changed; reload before starting this operation.' });
      if (Object.keys(input).sort().join(',') !== ['acknowledge_source_disclosure', 'action', 'expected_revision', 'source_disclosure_approval'].sort().join(',')
        || !['test', 'activate', 'disconnect'].includes(input.action)
        || typeof input.acknowledge_source_disclosure !== 'boolean') {
        return json(response, 422, { detail: 'Advisor provider command is invalid.' });
      }
      if (!provider.enabled && input.action !== 'disconnect') return json(response, 409, { detail: 'Enable the provider before testing or activating it.' });
      if (input.action !== 'disconnect' && !advisorProviderAuthorized(provider)) {
        return json(response, 409, { detail: {
          code: 'advisor_provider_authorization_required',
          message: 'This provider requires explicit host authorization before use.',
          action: 'authorize_advisor_provider',
          context: { provider_id: provider.id, transport: provider.transport },
        } });
      }
      if (input.action === 'activate' && provider.transport !== 'local') {
        const expectedApproval = advisorProviderActivationApproval(provider);
        if (input.acknowledge_source_disclosure !== true
          || canonicalJson(input.source_disclosure_approval) !== canonicalJson(expectedApproval)) {
          return json(response, 422, { detail: 'Activation requires approval bound to this exact provider configuration.' });
        }
      } else if (input.acknowledge_source_disclosure || input.source_disclosure_approval !== null) {
        return json(response, 422, { detail: 'Source disclosure approval is accepted only for remote activation.' });
      }
      if (!durableCommand(request, response, `advisor-provider-${input.action}`, input)) return;
      const idempotencyKey = request.headers['idempotency-key'];
      const replayBinding = advisorProviderJobsByIdempotencyKey.get(idempotencyKey);
      if (replayBinding && replayBinding.input !== canonicalJson(input)) {
        return json(response, 409, { detail: 'Idempotency key is already bound to a different Advisor provider command.' });
      }
      const replay = fixture.jobs.find((candidate) => candidate.id === replayBinding?.job_id);
      if (replay) return json(response, 202, replay);
      const activeProviderJob = fixture.jobs.find((candidate) => candidate.kind === 'advisor_provider'
        && ['queued', 'leased', 'pending', 'running', 'analyzing', 'cancelling'].includes(candidate.status));
      if (activeProviderJob) return json(response, 409, { detail: `advisor provider command already active as job ${activeProviderJob.id}` });
      const failing = provider.name.startsWith('Failing') && ['test', 'activate'].includes(input.action);
      const stalled = provider.name.startsWith('Stalled') && ['test', 'activate'].includes(input.action);
      const job = queuedJob({
        kind: 'advisor_provider',
        title: `${input.action} Advisor provider ${provider.name}`,
        provider_id: provider.id,
        provider_action: input.action,
        acknowledge_source_disclosure: input.acknowledge_source_disclosure,
        source_disclosure_approval: input.source_disclosure_approval,
        provider_config_revision: provider.config_revision,
        provider_config_digest: provider.config_digest,
      });
      advisorProviderJobsByIdempotencyKey.set(idempotencyKey, {
        job_id: job.id,
        input: canonicalJson(input),
      });
      if (failing) {
        Object.assign(job, {
          status: 'failed', stage: 'connect', progress: 35, attempt: 1, revision: 2,
          can_cancel: false, can_retry: true, started_at: time.started, completed_at: time.completed,
          heartbeat_at: time.updated, error_code: 'provider_unavailable',
          error_detail: 'Connection refused; token=fixture-secret /Users/generated/.ssh/id_ed25519 known_hosts=/private/generated/known_hosts',
        });
        provider.status = 'unavailable';
        provider.reason = 'Exact provider verification failed; review authorization, availability, and model pin.';
        provider.reason_code = 'advisor_provider_unavailable';
        provider.remediation = 'retry';
        provider.last_activity_at = time.completed;
        provider.content_disclosure_approved = false;
        if (fixture.activeAdvisorProviderId === provider.id) fixture.activeAdvisorProviderId = null;
        delete fixture.advisorProviderReceipts[provider.id];
        delete fixture.advisorProviderConsents[provider.id];
      } else if (stalled) {
        Object.assign(job, {
          status: 'running', stage: 'verify-model-digest', progress: 35, attempt: 1,
          started_at: time.started, heartbeat_at: time.started,
          activity: { component_id: 'model-digest-verification', component_index: 2, component_total: 3, updated_at: time.started },
        });
      }
      return json(response, 202, job);
    }
    const scopedConfigUpdate = pathname.match(/^\/v1\/config\/(advisor|gate|components)$/);
    if (request.method === 'PATCH' && scopedConfigUpdate) {
      const input = await bodyJson(request);
      const scope = scopedConfigUpdate[1];
      const allowedKeys = {
        advisor: ['ai_mode', 'ollama_base_url', 'ollama_model', 'ollama_thinking', 'auto_triage_limit'],
        gate: ['gate_preset', 'gate_active', 'gate_max_critical', 'gate_max_high', 'gate_block_secrets', 'gate_apply_to_existing'],
        components: ['component_monitoring_enabled', 'component_git_proxy_enabled', 'component_db_admin_enabled'],
      }[scope];
      const submittedKeys = input && typeof input === 'object' && !Array.isArray(input)
        ? Object.keys(input).sort()
        : [];
      if (submittedKeys.length !== allowedKeys.length || submittedKeys.some((key, index) => key !== [...allowedKeys].sort()[index])) {
        return json(response, 422, { detail: `Generated ${scope} runtime configuration must contain only its scoped fields.` });
      }
      if (scope === 'advisor') {
        if (
          !new Set(['auto', 'on', 'off']).has(input.ai_mode)
          || typeof input.ollama_base_url !== 'string'
          || !input.ollama_base_url
          || typeof input.ollama_model !== 'string'
          || !input.ollama_model
          || typeof input.ollama_thinking !== 'boolean'
          || !Number.isInteger(input.auto_triage_limit)
          || input.auto_triage_limit < 0
          || input.auto_triage_limit > 50
        ) return json(response, 422, { detail: 'Generated advisor runtime configuration is invalid.' });
        fixture.runtimeConfig = {
          ...fixture.runtimeConfig,
          ai_mode: input.ai_mode,
          ollama_base_url: input.ollama_base_url,
          ollama_model: input.ollama_model,
          ollama_thinking: input.ollama_thinking,
          auto_triage_limit: input.auto_triage_limit,
        };
      } else if (scope === 'gate') {
        if (
          !new Set(['observe', 'baseline', 'strict', 'custom']).has(input.gate_preset)
          || typeof input.gate_active !== 'boolean'
          || !Number.isInteger(input.gate_max_critical)
          || input.gate_max_critical < -1
          || input.gate_max_critical > 999
          || !Number.isInteger(input.gate_max_high)
          || input.gate_max_high < -1
          || input.gate_max_high > 999
          || typeof input.gate_block_secrets !== 'boolean'
          || typeof input.gate_apply_to_existing !== 'boolean'
        ) return json(response, 422, { detail: 'Generated gate runtime configuration is invalid.' });
        fixture.runtimeConfig = {
          ...fixture.runtimeConfig,
          gate_preset: input.gate_preset,
          gate_active: input.gate_active,
          gate_max_critical: input.gate_max_critical,
          gate_max_high: input.gate_max_high,
          gate_block_secrets: input.gate_block_secrets,
        };
        if (input.gate_apply_to_existing) {
          fixture.gatePolicy = {
            active: input.gate_active,
            max_critical: input.gate_max_critical,
            max_high: input.gate_max_high,
            block_secrets: input.gate_block_secrets,
          };
          applyFixtureGatePolicyToExistingScans();
        }
      } else {
        if (
          typeof input.component_monitoring_enabled !== 'boolean'
          || typeof input.component_git_proxy_enabled !== 'boolean'
          || typeof input.component_db_admin_enabled !== 'boolean'
        ) return json(response, 422, { detail: 'Generated component runtime configuration is invalid.' });
        fixture.runtimeConfig = {
          ...fixture.runtimeConfig,
          component_monitoring_enabled: input.component_monitoring_enabled,
          component_git_proxy_enabled: input.component_git_proxy_enabled,
          component_db_admin_enabled: input.component_db_admin_enabled,
        };
      }
      return json(response, 200, config());
    }
    if (request.method === 'PUT' && pathname === '/v1/config') {
      const input = await bodyJson(request);
      const allowedModes = new Set(['auto', 'on', 'off']);
      const allowedPresets = new Set(['observe', 'baseline', 'strict', 'custom']);
      if (!allowedModes.has(input.ai_mode) || !allowedPresets.has(input.gate_preset)) {
        return json(response, 422, { detail: 'Generated runtime configuration is invalid.' });
      }
      const next = {
        ai_mode: input.ai_mode,
        ollama_base_url: String(input.ollama_base_url || ''),
        ollama_model: String(input.ollama_model || ''),
        ollama_thinking: input.ollama_thinking === true,
        auto_triage_limit: Number(input.auto_triage_limit),
        component_monitoring_enabled: input.component_monitoring_enabled === true,
        component_git_proxy_enabled: input.component_git_proxy_enabled === true,
        component_db_admin_enabled: input.component_db_admin_enabled === true,
        gate_preset: input.gate_preset,
        gate_active: input.gate_active === true,
        gate_max_critical: Number(input.gate_max_critical),
        gate_max_high: Number(input.gate_max_high),
        gate_block_secrets: input.gate_block_secrets === true,
      };
      if (
        !next.ollama_base_url
        || !next.ollama_model
        || !Number.isInteger(next.auto_triage_limit)
        || next.auto_triage_limit < 0
        || next.auto_triage_limit > 50
        || !Number.isInteger(next.gate_max_critical)
        || !Number.isInteger(next.gate_max_high)
      ) return json(response, 422, { detail: 'Generated runtime configuration fields are invalid.' });
      fixture.runtimeConfig = next;
      if (input.gate_apply_to_existing === true) {
        fixture.gatePolicy = {
          active: next.gate_active,
          max_critical: next.gate_max_critical,
          max_high: next.gate_max_high,
          block_secrets: next.gate_block_secrets,
        };
        applyFixtureGatePolicyToExistingScans();
      }
      return json(response, 200, config());
    }
    const findingDetail = pathname.match(/^\/v1\/scans\/(\d+)\/findings\/(\d+)$/);
    if (request.method === 'GET' && findingDetail) {
      requestCounts.findingDetails += 1;
      const scan = requireScan(Number(findingDetail[1]));
      const item = fixture.findings.find((finding) => (
        finding.scan_id === Number(findingDetail[1])
        && finding.scan_finding_number === Number(findingDetail[2])
      ));
      if (!item) return json(response, 404, { detail: 'finding not found' });
      if (fixture.profile === 'finding-revision-advance' && requestCounts.findingDetails === 1) {
        item.revision += 1;
        item.ai_verdict = 'needs_review';
        item.ai_confidence = 0.91;
        item.ai_reasoning = 'A generated Advisor update advanced this finding while its detail was loading.';
        refreshScanFindingState(scan);
      }
      if (fixture.profile === 'finding-immutable-evidence-change' && requestCounts.findingDetails === 1) {
        item.revision += 1;
        item.severity = item.severity === 'critical' ? 'high' : 'critical';
        item.message = 'Hostile same-identity evidence replacement must not reconcile.';
        refreshScanFindingState(scan);
      }
      const expectedRevision = Number(requestUrl.searchParams.get('expected_revision'));
      const expectedFindingsRevision = Number(requestUrl.searchParams.get('expected_findings_revision'));
      if (
        !Number.isSafeInteger(expectedRevision)
        || expectedRevision < 1
        || !Number.isSafeInteger(expectedFindingsRevision)
        || expectedFindingsRevision < 1
      ) {
        return json(response, 422, { detail: {
          code: 'invalid_revision_fence',
          message: 'Finding detail requires positive item and collection revisions.',
          action: 'Refresh the finding collection before retrying.',
          context: {},
        } });
      }
      if (expectedRevision !== item.revision || expectedFindingsRevision !== scan.findings_revision) {
        return json(response, 409, { detail: {
          code: 'revision_conflict',
          message: 'The finding changed after it was loaded.',
          action: 'Reconcile the current finding collection and retry once.',
          context: { finding_revision: item.revision, findings_revision: scan.findings_revision },
        } });
      }
      return json(response, 200, { ...boundedFindingDetail(item), findings_revision: scan.findings_revision });
    }
    const findings = pathname.match(/^\/v1\/scans\/(\d+)\/findings$/);
    if (request.method === 'GET' && findings) {
      requestCounts.findings += 1;
      const scanId = Number(findings[1]);
      const scan = requireScan(scanId);
      checkFindingExpectedRevision(requestUrl.searchParams.get('expected_revision'), scan.findings_revision);
      const rawLimitParameter = requestUrl.searchParams.get('limit');
      const rawLimit = rawLimitParameter === null ? 100 : Number(rawLimitParameter);
      if (!Number.isSafeInteger(rawLimit) || rawLimit < 1 || rawLimit > 200) {
        return json(response, 422, { detail: 'limit must be between 1 and 200' });
      }
      const cursor = requestUrl.searchParams.get('cursor');
      const rawAnchor = requestUrl.searchParams.get('anchor_scan_finding_number');
      if (cursor !== null && rawAnchor !== null) {
        return json(response, 422, { detail: 'cursor and anchor_scan_finding_number are mutually exclusive' });
      }
      const filters = findingFilters(requestUrl);
      const digest = findingFilterDigest(filters);
      const all = filterFindings(findingsForScan(scanId), filters);
      let after = 0;
      if (cursor !== null) {
        const decoded = decodeFindingCursor(cursor);
        if (decoded.s !== scanId || decoded.f !== digest) {
          throw invalidFindingCursor('finding cursor does not match this scan and filter set');
        }
        if (decoded.r !== scan.findings_revision) {
          throw fixtureHttpError(409, {
            code: 'cursor_stale',
            message: 'findings changed after this cursor was issued; restart pagination',
            revision: scan.findings_revision,
          });
        }
        after = decoded.a;
      } else if (rawAnchor !== null) {
        const anchor = Number(rawAnchor);
        if (!Number.isSafeInteger(anchor) || anchor < 1) {
          return json(response, 422, { detail: 'anchor_scan_finding_number must be a positive integer' });
        }
        const anchorPosition = all.findIndex((finding) => finding.scan_finding_number === anchor);
        if (anchorPosition < 0) {
          return json(response, 404, { detail: 'anchor finding is not present under the active filters' });
        }
        const pageMemberCount = (anchorPosition % rawLimit) + 1;
        after = all[anchorPosition - pageMemberCount + 1].scan_finding_number - 1;
      }
      const fetched = all.filter((item) => item.scan_finding_number > after).slice(0, rawLimit + 1);
      const hasMore = fetched.length > rawLimit;
      const pageItems = fetched.slice(0, rawLimit);
      const nextCursor = hasMore && pageItems.length
        ? encodeFindingCursor({
          scanId,
          revision: scan.findings_revision,
          after: pageItems.at(-1).scan_finding_number,
          filterDigest: digest,
        })
        : null;
      return json(response, 200, {
        items: pageItems.map(findingListItem),
        total: all.length,
        truncated: hasMore,
        next_cursor: nextCursor,
        revision: scan.findings_revision,
      });
    }
    const artifacts = pathname.match(/^\/v1\/scans\/(\d+)\/artifacts$/);
    if (request.method === 'GET' && artifacts) {
      requestCounts.artifacts += 1;
      const scanId = Number(artifacts[1]);
      requireScan(scanId);
      return json(response, 200, fixture.artifacts.filter((item) => item.scan_id === scanId));
    }
    const artifactContent = pathname.match(/^\/v1\/artifacts\/(\d+)\/(open|download)$/);
    if (request.method === 'GET' && artifactContent) {
      const artifact = fixture.artifacts.find((item) => item.id === Number(artifactContent[1]));
      if (!artifact) return json(response, 404, { detail: 'artifact not found' });
      const disposition = artifactContent[2] === 'open' ? 'inline' : 'attachment';
      const body = `${JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        serialNumber: `urn:uuid:generated-playwright-artifact-${artifact.id}`,
        version: 1,
        components: [],
      }, null, 2)}\n`;
      response.writeHead(200, {
        'Content-Disposition': `${disposition}; filename="scan-${artifact.scan_id}-${artifact.scanner}.cyclonedx.json"`,
        'Content-Length': Buffer.byteLength(body),
        'Content-Type': 'application/vnd.cyclonedx+json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      response.end(body);
      return;
    }
    const scanAdvisor = pathname.match(/^\/v1\/scans\/(\d+)\/triage$/);
    if (request.method === 'POST' && scanAdvisor) {
      const input = await bodyJson(request);
      const scanId = Number(scanAdvisor[1]);
      requireScan(scanId);
      const provider = requirePinnedLocalAdvisor(response, input, { scanWide: true });
      if (!provider) return;
      if (!durableCommand(request, response, 'scan-advisor', input)) return;
      return json(response, 202, queuedJob({ title: `Advisor triage for scan #${scanId}`, scan_id: scanId }));
    }
    const advisorDisclosurePreview = pathname.match(/^\/v1\/findings\/(\d+)\/advisor-disclosure-preview$/);
    if (request.method === 'POST' && advisorDisclosurePreview) {
      requestCounts.advisorPreviews += 1;
      const input = await bodyJson(request);
      const allowedKeys = input.provider_id === undefined ? ['expected_revision'] : ['expected_revision', 'provider_id'];
      if (Object.keys(input).sort().join(',') !== allowedKeys.sort().join(',')) {
        return json(response, 422, { detail: 'Advisor disclosure preview request contains unexpected fields.' });
      }
      const findingId = Number(advisorDisclosurePreview[1]);
      const finding = fixture.findings.find((item) => item.id === findingId);
      if (!finding) return json(response, 404, { detail: 'finding not found' });
      if (input.expected_revision !== finding.revision) return json(response, 409, { detail: {
        code: 'revision_conflict',
        message: 'The selected finding changed before disclosure preview.',
        action: 'refresh_findings',
        context: {
          finding_id: finding.id,
          expected_revision: input.expected_revision,
          current_revision: finding.revision,
        },
        safe_details: {
          expected_revision: input.expected_revision,
          current_revision: finding.revision,
        },
      } });
      const scan = fixture.scans.find((item) => item.id === finding.scan_id);
      if (finding.suppressed || !scan || !['completed', 'partial', 'failed'].includes(scan.status)) {
        return json(response, 409, { detail: 'Advisor disclosure preview requires one active terminal finding' });
      }
      const providerId = input.provider_id ?? fixture.activeAdvisorProviderId;
      if (!providerId) return json(response, 409, { detail: 'no remote Advisor provider is active' });
      const provider = fixture.advisorProviders.find((candidate) => candidate.id === providerId);
      if (!provider) return json(response, 404, { detail: 'advisor provider not found' });
      if (provider.transport === 'local') return json(response, 409, { detail: 'the active Advisor route is local and needs no remote disclosure' });
      if (fixture.activeAdvisorProviderId !== provider.id || provider.status !== 'active') {
        return json(response, 409, { detail: 'the remote Advisor provider is not currently active' });
      }
      if (!advisorProviderAuthorized(provider)) return json(response, 409, { detail: 'the remote Advisor provider is not authorized' });
      if (!advisorReceiptMatches(provider)) return json(response, 409, { detail: 'the remote Advisor provider has no current exact test receipt' });
      const consent = fixture.advisorProviderConsents[provider.id];
      if (!advisorConsentMatches(provider) || !consent) return json(response, 409, { detail: 'remote Advisor consent is missing or stale' });
      return json(response, 200, buildAdvisorDisclosurePreview(provider, finding));
    }
    const findingAdvisor = pathname.match(/^\/v1\/findings\/(\d+)\/triage$/);
    if (request.method === 'POST' && findingAdvisor) {
      requestCounts.advisorSubmissions += 1;
      const input = await bodyJson(request);
      const findingId = Number(findingAdvisor[1]);
      const finding = fixture.findings.find((item) => item.id === findingId);
      if (!finding) return json(response, 404, { detail: 'finding not found' });
      const remoteConfirmation = input.remote_advisor_confirmation;
      const remote = remoteConfirmation !== undefined && remoteConfirmation !== null;
      const allowedKeys = remote
        ? ['acknowledge_remote_source_disclosure', 'expected_revision', 'model', 'remote_advisor_confirmation']
        : ['advisor_provider_pin', 'expected_revision', 'model'];
      if (Object.keys(input).some((key) => !allowedKeys.includes(key))) {
        return json(response, 422, { detail: 'Advisor finding request contains unexpected fields.' });
      }
      if (!Number.isSafeInteger(input.expected_revision) || input.expected_revision < 1) {
        return json(response, 422, { detail: {
          code: 'invalid_revision_fence',
          message: 'Advisor requires the current positive finding revision.',
          action: 'refresh_findings',
          context: {},
        } });
      }
      if (input.expected_revision !== finding.revision) {
        return json(response, 409, { detail: {
          code: 'revision_conflict',
          message: 'The finding changed before Advisor could be queued.',
          action: 'refresh_findings',
          context: { finding_revision: finding.revision },
        } });
      }
      if (remote) {
        if (input.acknowledge_remote_source_disclosure !== true) {
          return json(response, 422, { detail: 'remote Advisor acknowledgement requires one exact preview confirmation' });
        }
        const providerId = remoteConfirmation && typeof remoteConfirmation === 'object' && !Array.isArray(remoteConfirmation)
          ? remoteConfirmation.provider_id
          : null;
        const confirmedProvider = typeof providerId === 'string'
          ? fixture.advisorProviders.find((candidate) => candidate.id === providerId)
          : null;
        const confirmationCurrent = Boolean(confirmedProvider
          && ['direct', 'ssh'].includes(confirmedProvider.transport)
          && confirmedProvider.status === 'active'
          && fixture.activeAdvisorProviderId === confirmedProvider.id
          && advisorProviderAuthorized(confirmedProvider)
          && advisorReceiptMatches(confirmedProvider)
          && advisorConsentMatches(confirmedProvider));
        const authorizationId = remoteConfirmation && typeof remoteConfirmation === 'object' && !Array.isArray(remoteConfirmation)
          ? remoteConfirmation.authorization_id
          : null;
        const authorization = typeof authorizationId === 'string'
          ? fixture.advisorDisclosureAuthorizations[authorizationId]
          : null;
        const expectedConfirmation = confirmationCurrent && authorization
          ? authorization.confirmation
          : null;
        if (!confirmedProvider || !expectedConfirmation || canonicalJson(remoteConfirmation) !== canonicalJson(expectedConfirmation)) {
          return json(response, 409, { detail: {
            code: 'advisor_source_disclosure_confirmation_stale',
            message: 'The remote Advisor preview no longer matches the exact provider, receipt, consent, or finding revision.',
            action: 'preview_advisor_source_disclosure',
            context: { finding_id: finding.id, ...(typeof providerId === 'string' ? { provider_id: providerId } : {}) },
            safe_details: { current_revision: finding.revision, ...(typeof providerId === 'string' ? { provider_id: providerId } : {}) },
          } });
        }
        if (input.model != null && input.model !== '' && input.model !== confirmedProvider.model) {
          return json(response, 409, { detail: 'Advisor command model does not match the confirmed provider pin' });
        }
        if (authorization.job) {
          if (canonicalJson(input) !== canonicalJson(authorization.input)) {
            return json(response, 409, { detail: 'Remote Advisor authorization is already bound to a different command.' });
          }
          return json(response, 202, authorization.job);
        }
        if (!durableCommand(request, response, 'finding-advisor-remote', input)) return;
        const job = queuedJob({
          title: `Remote Advisor triage for ${finding.display_id || `finding #${findingId}`}`,
          detail: `Disclosure-bound ${confirmedProvider.transport} Advisor job persisted for one finding.`,
          scan_id: finding.scan_id,
          finding_id: findingId,
          finding_display_id: finding.display_id,
          finding_scan_number: finding.scan_finding_number,
          finding_rule_id: finding.rule_id,
        });
        authorization.input = structuredClone(input);
        authorization.job = structuredClone(job);
        return json(response, 202, job);
      } else if (input.acknowledge_remote_source_disclosure !== undefined || input.remote_advisor_confirmation !== undefined) {
        return json(response, 422, { detail: 'local Advisor requests do not accept remote disclosure confirmation fields' });
      }
      const provider = requirePinnedLocalAdvisor(response, input);
      if (!provider) return;
      if (!durableCommand(request, response, 'finding-advisor', input)) return;
      return json(response, 202, queuedJob({
        title: `Advisor triage for ${finding?.display_id || `finding #${findingId}`}`,
        scan_id: finding?.scan_id,
        finding_id: findingId,
        finding_display_id: finding?.display_id,
        finding_scan_number: finding?.scan_finding_number,
        finding_rule_id: finding?.rule_id,
      }));
    }
    const findingLifecycle = pathname.match(/^\/v1\/findings\/(\d+)\/lifecycle$/);
    if (request.method === 'PATCH' && findingLifecycle) {
      const input = await bodyJson(request);
      const finding = fixture.findings.find((item) => item.id === Number(findingLifecycle[1]));
      if (!finding) return json(response, 404, { detail: 'finding not found' });
      if (!Number.isSafeInteger(input.expected_revision) || input.expected_revision < 1) {
        return json(response, 422, { detail: 'expected_revision must be a positive integer' });
      }
      if (input.expected_revision !== finding.revision) {
        return json(response, 409, { detail: {
          code: 'revision_conflict',
          message: 'finding changed after it was loaded; refresh before retrying',
          revision: finding.revision,
        } });
      }
      applyFixtureLifecycle(finding, input.action, input.reason);
      refreshScanFindingState(requireScan(finding.scan_id));
      return json(response, 200, boundedFindingDetail(finding));
    }
    const findingDelete = pathname.match(/^\/v1\/findings\/(\d+)$/);
    if (request.method === 'DELETE' && findingDelete) {
      const index = fixture.findings.findIndex((item) => item.id === Number(findingDelete[1]));
      if (index < 0) return json(response, 404, { detail: 'finding not found' });
      const finding = fixture.findings[index];
      const expectedRevision = Number(requestUrl.searchParams.get('expected_revision'));
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
        return json(response, 422, { detail: 'expected_revision must be a positive integer' });
      }
      if (expectedRevision !== finding.revision) {
        return json(response, 409, { detail: {
          code: 'revision_conflict',
          message: 'finding changed after it was loaded; refresh before retrying',
          revision: finding.revision,
        } });
      }
      fixture.findings.splice(index, 1);
      refreshScanFindingState(requireScan(finding.scan_id));
      return json(response, 200, { deleted: true, finding_id: finding.id, scan_id: finding.scan_id });
    }
    if (request.method === 'POST' && pathname === '/v1/findings/bulk') {
      const input = await bodyJson(request);
      if (!Array.isArray(input.finding_ids) || input.finding_ids.length < 1 || input.finding_ids.length > 200) {
        return json(response, 422, { detail: 'finding_ids must contain between 1 and 200 finding IDs' });
      }
      if (!['triage', 'delete', ...lifecycleActions].includes(input.action)) {
        return json(response, 422, { detail: 'bulk finding action is invalid' });
      }
      const findingIds = [...new Set(input.finding_ids)].sort((left, right) => left - right);
      if (findingIds.some((findingId) => !Number.isSafeInteger(findingId) || findingId < 1)) {
        return json(response, 422, { detail: 'finding_ids must contain positive integers' });
      }
      const selected = fixture.findings.filter((item) => findingIds.includes(item.id));
      if (selected.length !== findingIds.length) {
        const found = new Set(selected.map((finding) => finding.id));
        return json(response, 404, { detail: `findings not found: ${JSON.stringify(findingIds.filter((findingId) => !found.has(findingId)).slice(0, 10))}` });
      }
      const scanIds = [...new Set(selected.map((item) => item.scan_id))];
      const expectedRevisions = input.expected_revisions;
      const expectedKeys = expectedRevisions && typeof expectedRevisions === 'object' && !Array.isArray(expectedRevisions)
        ? Object.keys(expectedRevisions).sort((left, right) => Number(left) - Number(right))
        : [];
      if (JSON.stringify(expectedKeys) !== JSON.stringify(findingIds.map(String))) {
        return json(response, 422, { detail: 'expected_revisions must contain exactly one revision for every selected finding' });
      }
      if (Object.values(expectedRevisions).some((revision) => !Number.isSafeInteger(revision) || revision < 1)) {
        return json(response, 422, { detail: 'expected_revisions must map finding IDs to positive integer revisions' });
      }
      const staleRevisions = Object.fromEntries(selected
        .filter((item) => Number(expectedRevisions[item.id]) !== item.revision)
        .map((item) => [item.id, item.revision]));
      if (Object.keys(staleRevisions).length) return json(response, 409, { detail: {
        code: 'revision_conflict',
        message: 'one or more findings changed after they were loaded; refresh before retrying',
        revisions: staleRevisions,
      } });
      if (input.action !== 'triage') {
        if (input.advisor_provider_pin !== undefined) {
          return json(response, 422, { detail: 'advisor provider pin is accepted only for bulk triage' });
        }
        if (reasonRequiredActions.has(input.action) && !String(input.reason || '').trim()) {
          return json(response, 422, { detail: `reason is required for finding lifecycle action: ${input.action}` });
        }
        if (input.action === 'delete') {
          fixture.findings = fixture.findings.filter((item) => !findingIds.includes(item.id));
          scanIds.forEach((scanId) => refreshScanFindingState(requireScan(scanId)));
          return json(response, 200, { updated: 0, deleted: selected.length, scan_ids: scanIds });
        }
        selected.forEach((finding) => applyFixtureLifecycle(finding, input.action, input.reason));
        scanIds.forEach((scanId) => refreshScanFindingState(requireScan(scanId)));
        return json(response, 200, { updated: selected.length, deleted: 0, scan_ids: scanIds });
      }
      const provider = requirePinnedLocalAdvisor(response, input, { scanWide: true });
      if (!provider) return;
      if (scanIds.length !== 1) return json(response, 422, { detail: 'bulk advisor triage requires findings from one scan' });
      if (selected.some((finding) => finding.suppressed)) return json(response, 409, { detail: 'bulk advisor triage accepts active findings only' });
      if (!durableCommand(request, response, 'bulk-advisor', input)) return;
      const job = queuedJob({ title: `Advisor triage for ${selected.length} selected findings`, scan_id: scanIds[0] });
      return json(response, 202, { updated: 0, deleted: 0, scan_ids: scanIds, job });
    }
    const cancelJob = pathname.match(/^\/v1\/jobs\/(\d+)\/cancel$/);
    if (request.method === 'POST' && cancelJob) {
      const job = fixture.jobs.find((item) => item.id === Number(cancelJob[1]));
      if (!job) return json(response, 404, { error: 'Generated job not found.' });
      if (!job.can_cancel) return json(response, 200, job);
      job.status = job.status === 'queued' ? 'cancelled' : 'cancelling';
      job.stage = job.status;
      job.detail = job.status === 'cancelled'
        ? 'Cancellation complete; no worker-owned temporary output existed.'
        : 'Cancellation persisted; waiting for worker cleanup confirmation.';
      job.can_cancel = false;
      job.cancel_requested_at = time.updated;
      job.revision += 1;
      if (job.status === 'cancelled') {
        job.completed_at = time.updated;
      }
      syncLifecycleJob(job);
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 180));
      return json(response, 200, job);
    }
    const retryJob = pathname.match(/^\/v1\/jobs\/(\d+)\/retry$/);
    if (request.method === 'POST' && retryJob) {
      const input = await bodyJson(request);
      const job = fixture.jobs.find((item) => item.id === Number(retryJob[1]));
      if (!job) return json(response, 404, { error: 'Generated job not found.' });
      if (job.status !== 'failed' || !job.can_retry) return json(response, 409, { error: 'Only a retryable failed job can be retried.' });
      if (input.expected_revision !== job.revision) return json(response, 409, { error: 'Job revision changed; reload before retrying.' });
      if (job.attempt >= job.max_attempts) job.max_attempts += 1;
      job.status = 'queued';
      job.stage = 'queued';
      job.detail = 'Operator retry queued with the original command snapshot.';
      job.progress = 0;
      job.completed_at = undefined;
      job.error = undefined;
      job.error_code = undefined;
      job.error_detail = undefined;
      job.can_cancel = true;
      job.can_retry = false;
      job.revision += 1;
      if (job.kind === 'advisor_provider') job.fixture_retried = true;
      syncLifecycleJob(job);
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 180));
      return json(response, 200, job);
    }
    if (request.method === 'GET' && pathname.startsWith('/fixture/')) return json(response, 200, { ok: true, fixture: true });
    if (request.method === 'GET' || request.method === 'HEAD') return staticFile(response, pathname);
    return json(response, 405, { error: 'Unsupported fixture method.' });
  } catch (error) {
    if (error && Number.isInteger(error.fixtureStatus)) {
      return json(response, error.fixtureStatus, { detail: error.fixtureDetail });
    }
    return json(response, 500, { error: error instanceof Error ? error.message : 'Fixture server failure.' });
  }
});

server.listen(port, '127.0.0.1', () => process.stdout.write(`Lomo Playwright fixture server listening on ${origin}\n`));
const close = () => server.close(() => process.exit(0));
process.on('SIGINT', close);
process.on('SIGTERM', close);
