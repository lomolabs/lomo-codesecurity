const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const http = require('node:http');
const { isDeepStrictEqual } = require('node:util');

const IDE_CAPABILITY_SCOPES = [
  'browser:invite',
  'event:read',
  'finding:advisor',
  'finding:delete',
  'finding:lifecycle',
  'finding:read',
  'job:cancel',
  'job:read',
  'project:create',
  'project:resolve',
  'scan:create',
  'scan:read',
  'source:open-ack',
  'source:open-context',
  'source:snapshot',
];
const RICH_LIMIT_FINDING_TOTAL = 5_001;
const SOURCE_SNAPSHOT_LIMITS = Object.freeze({
  schema_version: 1, max_file_bytes: 8_388_608, max_total_bytes: 67_108_864,
  max_files: 5_000, max_encoded_request_bytes: 117_440_512,
  eligible_source_max_file_bytes: 1_048_576,
});
const LOCAL_ADVISOR_PIN = Object.freeze({
  provider_collection_revision: 5,
  provider_id: 'local-default',
  transport: 'local',
  provider_config_revision: 3,
  provider_config_digest: 'b'.repeat(64),
  model: 'qwen3:8b',
  model_digest: 'a'.repeat(64),
});
const LOCAL_ADVISOR_COLLECTION = Object.freeze({
  revision: 5,
  active_provider_id: null,
  providers: [{
    id: 'local-default', name: 'This device', transport: 'local', priority: 0, enabled: true,
    base_url: null, model: 'qwen3:8b', model_digest: 'a'.repeat(64), ssh_host: null,
    ssh_port: null, ssh_user: null, authorization: 'not_required', status: 'available',
    reason: null, reason_code: null, remediation: 'none', last_activity_at: '2026-08-25T00:00:00Z',
    content_disclosure_approved: false, config_revision: 3, config_digest: 'b'.repeat(64),
    eligible: true,
  }],
  resolution: {
    provider_id: 'local-default', transport: 'local', reason: null,
    eligible_provider_ids: ['local-default'],
  },
});

function finding(number, filePath, location = {}) {
  return {
    id: 500 + number,
    scan_id: 71,
    scan_finding_number: number,
    display_id: `S71-F${String(number).padStart(3, '0')}`,
    scanner: number === 2 ? 'trivy' : 'semgrep',
    rule_id: `fixture.rule.${number}`,
    severity: number === 1 ? 'high' : 'medium',
    file_path: filePath,
    start_line: 1,
    start_column: null,
    end_line: 1,
    end_column: null,
    message: `Deterministic scanner finding ${number}`,
    fingerprint: `fixture-fingerprint-${number}`,
    lifecycle_status: 'open',
    gate_exempt: false,
    gate_effect: 'blocking',
    suppressed: false,
    occurrence_count: 1,
    is_repeat: false,
    first_seen_display_id: null,
    first_seen_scan_id: null,
    advisor_verdict: null,
    advisor_confidence: null,
    revision: number === 1 ? 3 : 1,
    ...location,
  };
}

function findingFromDefinition(definition, scanId = 71) {
  assert(definition, 'semantic fixture finding definition must exist');
  return finding(definition.number, definition.file_path, {
    scan_id: scanId,
    display_id: `S${scanId}-F${String(definition.number).padStart(3, '0')}`,
    scanner: definition.scanner,
    severity: definition.severity,
    start_line: definition.start_line,
    start_column: definition.start_column,
    end_line: definition.end_line,
    end_column: definition.end_column,
    message: definition.message,
    lifecycle_status: definition.lifecycle_status,
  });
}

function findingDetail(summary, lifecycle = {}, findingsRevision) {
  // Mirror FindingOut exactly. Advisor aliases belong only to the lightweight
  // projection; the detail endpoint exposes their canonical ai_* fields.
  return {
    id: summary.id,
    scan_id: summary.scan_id,
    scan_finding_number: summary.scan_finding_number,
    findings_revision: findingsRevision,
    display_id: summary.display_id,
    scanner: summary.scanner,
    rule_id: summary.rule_id,
    severity: summary.severity,
    file_path: summary.file_path,
    start_line: summary.start_line,
    start_column: summary.start_column,
    end_line: summary.end_line,
    end_column: summary.end_column,
    message: summary.message,
    code_snippet: 'export const generatedFixture = true;',
    fingerprint: summary.fingerprint,
    metadata_json: { fixture: 'isolated-extension-host' },
    ai_verdict: null,
    ai_confidence: null,
    ai_reasoning: null,
    ai_fix: null,
    suppressed: summary.suppressed,
    suppression_reason: lifecycle.suppressionReason ?? null,
    lifecycle_status: summary.lifecycle_status,
    gate_exempt: summary.gate_exempt,
    gate_exempt_reason: lifecycle.gateExemptReason ?? null,
    lifecycle_reason: lifecycle.reason ?? null,
    lifecycle_updated_at: lifecycle.updatedAt ?? null,
    occurrence_count: summary.occurrence_count,
    is_repeat: summary.is_repeat,
    first_seen_display_id: summary.first_seen_display_id,
    first_seen_scan_id: summary.first_seen_scan_id,
    revision: summary.revision,
    gate_effect: summary.gate_effect,
    created_at: '2026-08-13T00:00:00Z',
  };
}

function findingFileAggregate(filePath, values) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const lifecycleCounts = {
    open: 0,
    needs_review: 0,
    gate_exempt: 0,
    accepted_risk: 0,
    ignore: 0,
    false_positive: 0,
    fixed: 0,
  };
  for (const value of values) {
    severityCounts[value.severity] += 1;
    lifecycleCounts[value.lifecycle_status] += 1;
  }
  return {
    file_path: filePath,
    first_scan_finding_number: Math.min(...values.map(({ scan_finding_number: number }) => number)),
    total: values.length,
    active: values.filter(({ suppressed }) => !suppressed).length,
    suppressed: values.filter(({ suppressed }) => suppressed).length,
    gate_exempt: values.filter((value) => !value.suppressed && value.gate_exempt).length,
    blocking: values.filter((value) => !value.suppressed && value.gate_effect === 'blocking').length,
    severity_counts: severityCounts,
    lifecycle_counts: lifecycleCounts,
  };
}

function richLimitAggregate(value, total, severity) {
  assert(total > value.total, 'rich-limit aggregate must increase one existing file');
  assert.equal(value.suppressed, 0, 'rich-limit fixture file must remain active');
  assert.equal(value.gate_exempt, 0, 'rich-limit fixture file must remain gate blocking');
  assert(Object.hasOwn(value.severity_counts, severity), 'rich-limit fixture severity must be supported');
  const additional = total - value.total;
  return {
    ...value,
    total,
    active: value.active + additional,
    blocking: value.blocking + additional,
    severity_counts: {
      ...value.severity_counts,
      [severity]: value.severity_counts[severity] + additional,
    },
    lifecycle_counts: {
      ...value.lifecycle_counts,
      open: value.lifecycle_counts.open + additional,
    },
  };
}

function diagnosticFinding(value) {
  return {
    id: value.id,
    scan_finding_number: value.scan_finding_number,
    display_id: value.display_id,
    scanner: value.scanner,
    severity: value.severity,
    file_path: value.file_path,
    start_line: value.start_line,
    start_column: value.start_column,
    end_line: value.end_line,
    end_column: value.end_column,
    message: value.message,
    revision: value.revision,
  };
}

function findingIdentityReceipt(value) {
  return Object.freeze({
    id: value.id,
    revision: value.revision,
    scan_finding_number: value.scan_finding_number,
  });
}

function freezeFindingSnapshot(values) {
  return Object.freeze(values.map((value) => Object.freeze({ ...value })));
}

function gateDecision(values) {
  return values.some((value) => (
    !value.suppressed
    && !value.gate_exempt
    && ['critical', 'high'].includes(value.severity)
  )) ? 'fail' : 'pass';
}

// Synthetic browser boundary only, not the production Web UI or authentication
// implementation. Exercise the public one-use exchange rather than assigning an
// active membership merely because the editor opened a URL.
const BROWSER_FIXTURE_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Lomo CodeSecurity fixture</title></head>
<body><h1>Lomo CodeSecurity browser fixture</h1><p id="status" role="status">Connecting…</p>
<script>
(async () => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const bootstrap = fragment.get('bootstrap');
  if (fragment.has('bootstrap')) history.replaceState(null, '', location.pathname + location.search);
  let response = await fetch(bootstrap ? '/v1/auth/bootstrap' : '/v1/auth/session', bootstrap ? {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ bootstrap_token: bootstrap }),
  } : undefined);
  let result = await response.json();
  if (bootstrap && response.ok && result.authenticated === true) {
    response = await fetch('/v1/auth/session');
    result = await response.json();
  }
  document.getElementById('status').textContent = response.ok && result.authenticated === true
    ? 'Browser paired. Synthetic fixture only.' : 'Browser is not paired.';
})();
</script></body></html>`;

async function fakeApi({
  primaryRepoPath,
  secondaryRepoPath,
  sourceBoundaryRepoPath,
  semanticFixture,
  nativeSnapshotSource,
  onRequest = () => {},
}) {
  assert.equal(typeof onRequest, 'function', 'fake API request observer must be a function');
  const requests = [];
  // Explicit synthetic source allowlist, never a filesystem reader or real
  // scanner. Admission witnesses contain hashes/paths only, not uploaded bytes.
  const nativeSourceFiles = new Map();
  const admittedSnapshots = new Map();
  if (nativeSnapshotSource) {
    assert.match(nativeSnapshotSource.source_id, /^[0-9a-f]{64}$/u);
    assert.equal(primaryRepoPath, `/source-snapshots/native-windows/${nativeSnapshotSource.source_id}`);
    assert(Array.isArray(nativeSnapshotSource.files) && nativeSnapshotSource.files.length > 0
      && nativeSnapshotSource.files.length <= SOURCE_SNAPSHOT_LIMITS.max_files);
    for (const file of nativeSnapshotSource.files) {
      assert(!nativeSourceFiles.has(file.path));
      assert.match(file.path, /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u);
      assert(file.path.split('/').every((part) => part && part !== '.'));
      assert.match(file.sha256, /^[0-9a-f]{64}$/u);
      assert(Number.isSafeInteger(file.size_bytes) && file.size_bytes >= 0
        && file.size_bytes <= SOURCE_SNAPSHOT_LIMITS.max_file_bytes);
      nativeSourceFiles.set(file.path, Object.freeze({ path: file.path, sha256: file.sha256, size_bytes: file.size_bytes }));
    }
    assert(nativeSnapshotSource.files.reduce((total, file) => total + file.size_bytes, 0)
      <= SOURCE_SNAPSHOT_LIMITS.max_total_bytes);
  }
  const sockets = new Set();
  const eventResponses = new Set();
  let capabilityRevoked = false;
  let latestCapabilityGeneration = 0;
  let activeCapabilityGeneration = 0;
  let activeCapability;
  let pendingCapability;
  let pendingEnrollment;
  const browserInvitations = new Map();
  const browserSessions = new Map();
  const browserMembershipWaiters = new Map();
  const browserSession = (request) => {
    const cookie = String(request.headers.cookie || '').split(';').map((part) => part.trim())
      .find((part) => part.startsWith('kodesec_session='));
    return cookie ? browserSessions.get(cookie.slice('kodesec_session='.length)) : undefined;
  };
  const enrollmentWaiters = new Set();
  const enrollmentStatus = () => ({
    request_id: pendingEnrollment.request_id,
    state: pendingEnrollment.state,
    revision: pendingEnrollment.revision,
    decision_at: pendingEnrollment.decision_at,
    activation_expires_at: pendingEnrollment.activation_expires_at,
  });
  const flushEnrollmentWaiters = () => {
    for (const waiter of enrollmentWaiters) {
      enrollmentWaiters.delete(waiter);
      send(waiter, 200, enrollmentStatus());
    }
  };
  const primaryDefinitions = semanticFixture.findings.filter(({ repository }) => repository === 'primary');
  const primary = findingFromDefinition(primaryDefinitions.find(({ number }) => number === 1));
  const otherPrimaryFindings = primaryDefinitions
    .filter(({ number }) => number !== 1)
    .map((definition) => findingFromDefinition(definition));
  const largeFindings = Array.from({ length: semanticFixture.large_set.count }, (_, index) => finding(
    semanticFixture.large_set.first_number + index,
    semanticFixture.large_set.file_path,
    {
      message: `${semanticFixture.large_set.message_prefix} ${index + 1}`,
      scanner: semanticFixture.large_set.scanner,
      severity: semanticFixture.large_set.severity,
      start_column: 1,
      end_column: 7,
    },
  ));
  const initialPrimaryFindings = [primary, ...otherPrimaryFindings, ...largeFindings];
  const initialPrimaryScan = {
    id: 71,
    project_id: 17,
    status: 'completed',
    gate_decision: 'fail',
    findings_revision: 9,
    revision: 6,
  };
  const secondaryFindingTemplate = findingFromDefinition(
    semanticFixture.findings.find(({ repository }) => repository === 'secondary'),
    72,
  );
  const initialPrimaryIds = new Set(initialPrimaryFindings.map(({ id }) => id));
  const secondaryFinding = initialPrimaryIds.has(secondaryFindingTemplate.id)
    ? {
      ...secondaryFindingTemplate,
      id: Math.max(...initialPrimaryIds) + 1,
    }
    : secondaryFindingTemplate;
  const secondaryScan = {
    id: 72,
    project_id: 18,
    status: 'completed',
    gate_decision: 'pass',
    findings_revision: 3,
    revision: 2,
  };
  const initialFindingsByProject = new Map([
    [17, freezeFindingSnapshot(initialPrimaryFindings)],
    [18, freezeFindingSnapshot([secondaryFinding])],
  ]);
  const registeredSourceBoundaries = new Map([
    [17, Object.freeze({ project_id: 17, repo_path: primaryRepoPath })],
    [18, Object.freeze({ project_id: 18, repo_path: secondaryRepoPath })],
  ]);
  const scans = new Map();
  const latestScans = new Map();
  const findingsByScan = new Map();
  const findingLocations = new Map();
  const findingLifecycles = new Map();
  const richLimitManifests = new Map();
  const storeFindingSnapshot = (scanId, values) => {
    const snapshot = freezeFindingSnapshot(values);
    findingsByScan.set(scanId, snapshot);
    for (const value of snapshot) {
      findingLocations.set(value.id, Object.freeze({
        scanFindingNumber: value.scan_finding_number,
        scanId,
      }));
    }
    return snapshot;
  };
  const storeScan = (value, { latest = false } = {}) => {
    const selectedScan = Object.freeze({ ...value });
    scans.set(selectedScan.id, selectedScan);
    if (latest) latestScans.set(selectedScan.project_id, selectedScan);
    else if (latestScans.get(selectedScan.project_id)?.id === selectedScan.id) {
      latestScans.set(selectedScan.project_id, selectedScan);
    }
    return selectedScan;
  };
  const initialPrimary = storeScan(initialPrimaryScan, { latest: true });
  const initialSecondary = storeScan(secondaryScan, { latest: true });
  storeFindingSnapshot(initialPrimary.id, initialFindingsByProject.get(initialPrimary.project_id));
  storeFindingSnapshot(initialSecondary.id, initialFindingsByProject.get(initialSecondary.project_id));
  let nextScanId = Math.max(...scans.keys());
  let nextFindingId = Math.max(...findingLocations.keys());
  let nextScanJobId = 90;
  const scanJobs = new Map();
  const scanRequestsByIdempotencyKey = new Map();
  const findingsForScan = (selectedScan) => findingsByScan.get(selectedScan.id) || Object.freeze([]);
  const freshFindingSnapshot = (projectId, scanId, targetPath, targetKind) => storeFindingSnapshot(
    scanId,
    initialFindingsByProject.get(projectId)
      .filter((value) => (
        targetPath === undefined
        || targetKind === 'file' && value.file_path === targetPath
        || targetKind === 'directory' && value.file_path.startsWith(`${targetPath}/`)
      ))
      .map((value) => ({
        ...value,
        id: ++nextFindingId,
        scan_id: scanId,
        display_id: `S${scanId}-F${String(value.scan_finding_number).padStart(3, '0')}`,
        gate_exempt: false,
        gate_effect: 'blocking',
        suppressed: false,
        revision: 1,
      })),
  );
  const findingById = (findingId) => {
    const location = findingLocations.get(findingId);
    if (!location) return null;
    const selectedScan = scans.get(location.scanId);
    const value = findingsForScan(selectedScan).find(({ id }) => id === findingId);
    return value ? Object.freeze({ location, selectedScan, value }) : null;
  };
  const replaceFinding = (selectedScan, findingId, replacement) => {
    const values = findingsForScan(selectedScan);
    assert.equal(values.filter(({ id }) => id === findingId).length, 1);
    return storeFindingSnapshot(selectedScan.id, values.map((value) => (
      value.id === findingId ? replacement : value
    )));
  };
  const deleteFinding = (selectedScan, findingId) => {
    const values = findingsForScan(selectedScan);
    assert.equal(values.filter(({ id }) => id === findingId).length, 1);
    const snapshot = freezeFindingSnapshot(values.filter(({ id }) => id !== findingId));
    findingsByScan.set(selectedScan.id, snapshot);
    findingLocations.delete(findingId);
    findingLifecycles.delete(findingId);
    return snapshot;
  };

  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const url = new URL(request.url, 'http://127.0.0.1');
      const rawBody = Buffer.concat(chunks).toString('utf8');
      const body = rawBody ? JSON.parse(rawBody) : undefined;
      const scanResourceMatch = url.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)$/u);
      const scanFindingFilesMatch = url.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)\/finding-files$/u);
      const scanDiagnosticsMatch = url.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)\/finding-diagnostics$/u);
      const scanFindingsMatch = url.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)\/findings$/u);
      const scanLocalFindingMatch = url.pathname.match(
        /^\/v1\/scans\/([1-9][0-9]*)\/findings\/([1-9][0-9]*)$/u,
      );
      const findingLifecycleMatch = url.pathname.match(/^\/v1\/findings\/([1-9][0-9]*)\/lifecycle$/u);
      const findingTriageMatch = url.pathname.match(/^\/v1\/findings\/([1-9][0-9]*)\/triage$/u);
      const findingDeleteMatch = url.pathname.match(/^\/v1\/findings\/([1-9][0-9]*)$/u);
      const browserMembershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/u,
      );
      const recordedRequest = {
        authorization: request.headers.authorization,
        body: ['/v1/source-snapshots', '/v1/auth/bootstrap'].includes(url.pathname) ? undefined : body,
        idempotencyKey: request.headers['idempotency-key'],
        method: request.method,
        pathname: url.pathname,
        search: url.search,
      };
      requests.push(recordedRequest);
      process.stdout.write(`[smoke] api ${recordedRequest.method} ${recordedRequest.pathname}${recordedRequest.search}\n`);

      try {
        if (request.method === 'GET' && url.pathname === '/healthz') {
          assert.equal(request.headers.authorization, undefined);
          send(response, 200, { ok: true, source_snapshot_limits: SOURCE_SNAPSHOT_LIMITS });
      } else if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        response.end(BROWSER_FIXTURE_PAGE);
      } else if (request.method === 'POST' && url.pathname === '/v1/auth/bootstrap') {
        assert.deepEqual(Object.keys(body).sort(), ['bootstrap_token']);
        const match = typeof body.bootstrap_token === 'string'
          ? body.bootstrap_token.match(/^kbi1\.([A-Za-z0-9_-]{24})\.[A-Za-z0-9_-]{43}$/u) : null;
        const invitation = match ? browserInvitations.get(match[1]) : undefined;
        if (!invitation || invitation.membership.status !== 'pending') {
          send(response, 409, { detail: { code: 'ide_browser_invitation_unavailable' } });
          return;
        }
        if (body.bootstrap_token !== invitation.token) {
          send(response, 401, { detail: { code: 'ide_browser_invitation_invalid' } });
          return;
        }
        if (capabilityRevoked || invitation.issuer !== activeCapability) {
          send(response, 409, { detail: { code: 'ide_browser_invitation_issuer_revoked' } });
          return;
        }
        const retained = browserSession(request);
        if (retained && invitation.membership.purpose === 'extra_browser') {
          send(response, 409, { detail: { code: 'browser_already_paired' } });
          return;
        }
        // Fixed, recognizable fixture credentials never leave this loopback
        // server. They are not production credential generation or validation.
        const session = retained || Object.freeze({
          token: `fixture-browser-session-${browserSessions.size + 1}`,
          member_id: `kbm1_${String(browserSessions.size + 1).padStart(32, '0')}`,
          created_at: '2099-01-01T00:01:00Z',
          csrf_token: 'fixture-browser-csrf',
        });
        browserSessions.set(session.token, session);
        invitation.membership = Object.freeze({
          invitation_id: invitation.membership.invitation_id,
          purpose: invitation.membership.purpose,
          status: 'active',
          member_id: session.member_id,
          created_at: session.created_at,
        });
        for (const waiter of browserMembershipWaiters.get(match[1]) || []) {
          send(waiter, 200, invitation.membership);
        }
        browserMembershipWaiters.delete(match[1]);
        response.setHeader('Set-Cookie', `kodesec_session=${session.token}; Path=/; HttpOnly; SameSite=Strict`);
        response.setHeader('Cache-Control', 'no-store');
        send(response, 200, { authenticated: true, csrf_token: session.csrf_token, expires_in: 86400 });
      } else if (request.method === 'GET' && url.pathname === '/v1/auth/session') {
        const session = browserSession(request);
        recordedRequest.responseAuthenticated = Boolean(session);
        response.setHeader('Cache-Control', 'no-store');
        send(response, session ? 200 : 401, session
          ? { authenticated: true, csrf_token: session.csrf_token, expires_in: 86400 }
          : { detail: 'fixture browser session required' });
      } else if (request.method === 'POST' && url.pathname === '/v1/auth/ide/enrollments') {
        assert.deepEqual(Object.keys(body).sort(), [
          'client_name',
          'client_slot',
          'expected_active_generation',
        ]);
        assert.match(body.client_slot, /^ks1_[A-Za-z0-9_-]{43}$/u);
        assert.equal(body.expected_active_generation, activeCapabilityGeneration);
        if (pendingCapability) {
          send(response, 409, { detail: {
            code: 'ide_enrollment_pending',
            message: 'The fixture profile already has a pending IDE enrollment.',
            action: 'review_ide_enrollment',
          } });
          return;
        }
        latestCapabilityGeneration += 1;
        pendingCapability = Object.freeze({
          client_slot: body.client_slot,
          generation: latestCapabilityGeneration,
          capability: `kc1.${body.client_slot}.${latestCapabilityGeneration}.${'A'.repeat(43)}`,
        });
        pendingEnrollment = {
          client_name: body.client_name,
          request_id: `ker1_${String(latestCapabilityGeneration).padStart(24, '0')}`,
          state: 'awaiting_approval',
          revision: 1,
          verification_code: 'ABCD-EF23',
          decision_at: null,
          activation_expires_at: '2099-01-01T00:10:00Z',
        };
        send(response, 201, {
          request_id: pendingEnrollment.request_id,
          state: pendingEnrollment.state,
          revision: pendingEnrollment.revision,
          verification_code: pendingEnrollment.verification_code,
          capability: pendingCapability.capability,
          scopes: IDE_CAPABILITY_SCOPES,
          client_slot: pendingCapability.client_slot,
          generation: pendingCapability.generation,
          requested_at: '2099-01-01T00:00:00Z',
          activation_expires_at: pendingEnrollment.activation_expires_at,
        });
      } else if (request.method === 'GET' && url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        const presented = String(request.headers.authorization || '').replace(/^Bearer /u, '');
        if (pendingCapability?.capability !== presented || !pendingEnrollment) {
          send(response, 401, { detail: 'fixture pending capability required' });
          return;
        }
        const afterRevision = Number(url.searchParams.get('after_revision'));
        assert(Number.isSafeInteger(afterRevision) && afterRevision >= 0);
        if (pendingEnrollment.revision > afterRevision) {
          send(response, 200, enrollmentStatus());
          return;
        }
        enrollmentWaiters.add(response);
        response.once('close', () => enrollmentWaiters.delete(response));
      } else if (request.method === 'POST' && url.pathname === '/v1/auth/ide/activate') {
        const presented = String(request.headers.authorization || '').replace(/^Bearer /u, '');
        const candidate = pendingCapability?.capability === presented
          ? pendingCapability
          : activeCapability === presented
            ? Object.freeze({
                client_slot: presented.split('.')[1],
                generation: activeCapabilityGeneration,
                capability: presented,
              })
            : undefined;
        if (!candidate || pendingEnrollment?.state !== 'approved') {
          send(response, 401, { detail: 'fixture pending capability required' });
          return;
        }
        activeCapability = candidate.capability;
        activeCapabilityGeneration = candidate.generation;
        pendingCapability = undefined;
        pendingEnrollment = undefined;
        send(response, 200, {
          client_slot: candidate.client_slot,
          generation: candidate.generation,
          scopes: IDE_CAPABILITY_SCOPES,
        });
      } else if (request.method === 'DELETE' && url.pathname === '/v1/auth/ide/pending') {
        const presented = String(request.headers.authorization || '').replace(/^Bearer /u, '');
        if (pendingCapability?.capability !== presented) {
          send(response, 401, { detail: 'fixture pending capability required' });
          return;
        }
        pendingCapability = undefined;
        pendingEnrollment = undefined;
        for (const waiter of enrollmentWaiters) {
          enrollmentWaiters.delete(waiter);
          send(waiter, 410, { detail: 'fixture IDE enrollment was cancelled' });
        }
        send(response, 200, { cancelled: true });
      } else if (request.method === 'POST' && url.pathname === '/v1/auth/ide/browser-invitations') {
        const presented = String(request.headers.authorization || '').replace(/^Bearer /u, '');
        if (capabilityRevoked || activeCapability !== presented) {
          send(response, 401, { detail: 'fixture active capability required' });
          return;
        }
        assert.deepEqual(Object.keys(body).sort(), ['purpose']);
        assert.ok(
          body.purpose === 'integrated_dashboard' || body.purpose === 'extra_browser',
          'fixture browser invitation purpose must use the product enum',
        );
        const invitationId = String(browserInvitations.size + 1).padStart(24, 'b');
        const token = `kbi1.${invitationId}.${'c'.repeat(43)}`;
        browserInvitations.set(invitationId, {
          token,
          issuer: activeCapability,
          membership: Object.freeze({
            invitation_id: invitationId,
            purpose: body.purpose,
            status: 'pending',
            expires_at: '2099-01-01T00:10:00Z',
          }),
        });
        send(response, 201, {
          bootstrap_token: token,
          invitation_id: invitationId,
          issued_at: '2099-01-01T00:00:00Z',
          expires_at: '2099-01-01T00:10:00Z',
          expires_in: 600,
          purpose: body.purpose,
        });
      } else if (request.method === 'GET' && browserMembershipMatch) {
        const presented = String(request.headers.authorization || '').replace(/^Bearer /u, '');
        if (capabilityRevoked || !activeCapability || activeCapability !== presented) {
          send(response, 401, { detail: 'fixture active capability required' });
          return;
        }
        const invitationId = browserMembershipMatch[1];
        const invitation = browserInvitations.get(invitationId);
        if (!invitation) {
          send(response, 200, { invitation_id: invitationId, status: 'missing_or_revoked' });
        } else if (invitation.issuer !== presented) {
          send(response, 404, { detail: 'browser invitation not found' });
        } else if (invitation.membership.status === 'active') {
          send(response, 200, invitation.membership);
        } else {
          // Mirror the public long-poll boundary without a timing-dependent
          // fake acknowledgement. Consumption or fixture teardown settles it.
          const waiters = browserMembershipWaiters.get(invitationId) || new Set();
          browserMembershipWaiters.set(invitationId, waiters);
          waiters.add(response);
          response.once('close', () => waiters.delete(response));
        }
      } else if (capabilityRevoked) {
        send(response, 401, { detail: 'fixture capability revoked' });
      } else if (request.method === 'GET' && url.pathname === '/v1/events') {
        assert.equal(request.headers.accept, 'text/event-stream');
        assert.equal(request.headers['last-event-id'], '0');
        response.writeHead(200, {
          'Cache-Control': 'no-store',
          'Content-Type': 'text/event-stream',
        });
        response.write(
          'event: stream.ready\n'
          + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
        );
        eventResponses.add(response);
        // Match the production idle SSE protocol (events.py KEEPALIVE_SECONDS).
        // Silence would make the real editor correctly reconnect after 45s.
        const keepalive = setInterval(() => {
          if (capabilityRevoked) response.end();
          else response.write(': keepalive\n\n');
        }, 15_000);
        response.once('close', () => {
          clearInterval(keepalive);
          eventResponses.delete(response);
        });
      } else if (request.method === 'GET' && url.pathname === '/v1/advisor/providers') {
        send(response, 200, LOCAL_ADVISOR_COLLECTION);
      } else if (request.method === 'POST' && url.pathname === '/v1/source-snapshots') {
        const rejectSnapshot = () => send(response, 422, { detail: {
          code: 'source_snapshot_invalid', message: 'Snapshot differs from the exact synthetic source fixture.',
          action: 'choose_approved_source',
        } });
        if (!nativeSnapshotSource || !body || !isDeepStrictEqual(Object.keys(body).sort(),
          ['directory_scope', 'files', 'name', 'source_id'])
          || body.source_id !== nativeSnapshotSource.source_id
          || typeof body.name !== 'string' || !/^[A-Za-z0-9_.-]{1,120}$/u.test(body.name)
          || !Array.isArray(body.files) || body.files.length > nativeSourceFiles.size
          || body.directory_scope !== null && (typeof body.directory_scope !== 'string'
            || ![...nativeSourceFiles.keys()].some((path) => path.startsWith(`${body.directory_scope}/`)))) {
          rejectSnapshot(); return;
        }
        const files = [];
        let previous = '';
        for (const item of body.files) {
          const expected = nativeSourceFiles.get(item?.path);
          if (!expected || !isDeepStrictEqual(Object.keys(item).sort(), ['content_base64', 'path', 'sha256', 'size_bytes'])
            || typeof item.content_base64 !== 'string'
            || item.content_base64.length > Math.ceil(SOURCE_SNAPSHOT_LIMITS.max_file_bytes / 3) * 4
            || item.path <= previous || item.sha256 !== expected.sha256 || item.size_bytes !== expected.size_bytes) {
            rejectSnapshot(); return;
          }
          const content = Buffer.from(item.content_base64, 'base64');
          if (content.toString('base64') !== item.content_base64 || content.length !== expected.size_bytes
            || createHash('sha256').update(content).digest('hex') !== expected.sha256) {
            rejectSnapshot(); return;
          }
          previous = item.path;
          files.push(expected);
        }
        if (body.directory_scope !== null && !isDeepStrictEqual(files.map(({ path }) => path),
          [...nativeSourceFiles.keys()].filter((path) => path.startsWith(`${body.directory_scope}/`)).sort())) {
          rejectSnapshot(); return;
        }
        // Canonical production manifest field order (source_snapshots.py), not
        // a public ScanOut extension. This mocked route performs no disk write.
        const manifest = { directory_scope: body.directory_scope, file_count: files.length, files,
          schema: 'lomo-source-snapshot/v1', source_id: body.source_id,
          total_bytes: files.reduce((total, file) => total + file.size_bytes, 0) };
        const snapshotDigest = createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
        const admitted = Object.freeze({
          project: Object.freeze({ id: 17, name: body.name, repo_path: primaryRepoPath, revision: 2 }),
          snapshot_digest: snapshotDigest, directory_scope: manifest.directory_scope,
          file_count: manifest.file_count, total_bytes: manifest.total_bytes,
        });
        admittedSnapshots.set(snapshotDigest, Object.freeze({ admitted, files: Object.freeze(files) }));
        recordedRequest.responseSnapshot = Object.freeze({ ...admitted, files: Object.freeze(files) });
        send(response, 201, admitted);
      } else if (request.method === 'POST' && url.pathname === '/v1/sources/preview') {
        const presented = String(request.headers.authorization || '').replace(/^Bearer /u, '');
        if (!activeCapability || activeCapability !== presented) {
          send(response, 401, { detail: 'fixture active capability required' }); return;
        }
        assert.deepEqual(Object.keys(body).sort(), ['repo_path']);
        const permitted = [primaryRepoPath, secondaryRepoPath];
        assert.equal(typeof body.repo_path, 'string');
        assert(body.repo_path.startsWith('/') && !/[\\\p{Cc}\p{Cf}]/u.test(body.repo_path)
          && body.repo_path.length <= 4096 && body.repo_path.slice(1).split('/').every(part => part && part !== '.' && part !== '..'));
        const authorized = permitted.some(root => body.repo_path === root || body.repo_path.startsWith(`${root}/`));
        send(response, 200, { installation_id: '012345abcdef', repo_path: body.repo_path,
          authorization_mode: 'mounted', authorized, configured_roots: permitted,
          reason_code: authorized ? null : 'source_outside_allowed_root' });
      } else if (request.method === 'POST' && url.pathname === '/v1/projects/resolve') {
        if (body.repo_path === primaryRepoPath) {
          send(response, 200, { id: 17, name: 'fixture', repo_path: primaryRepoPath, revision: 2 });
        } else if (body.repo_path === sourceBoundaryRepoPath) {
          send(response, 422, { detail: {
            code: 'source_outside_allowed_root',
            message: 'The selected directory is outside the authorized source root.',
            action: 'authorize_source',
            context: {
              source_target: { kind: 'mounted_directory', display_path: sourceBoundaryRepoPath },
              authorization_boundary: { kind: 'allowed_roots', display_paths: [primaryRepoPath] },
            },
          } });
        } else if (body.repo_path === secondaryRepoPath) {
          send(response, 200, { id: 18, name: 'secondary-root', repo_path: secondaryRepoPath, revision: 1 });
        } else {
          send(response, 404, { detail: 'fixture repository is not registered' });
        }
      } else if (request.method === 'POST' && url.pathname === '/v1/scans') {
        const idempotencyKey = String(recordedRequest.idempotencyKey);
        assert.match(idempotencyKey, /^vscode-[0-9a-f-]{36}$/u);
        const expectedScanKeys = ['mode', 'project_id', 'use_ai'];
        if (body.target_path !== undefined) expectedScanKeys.push('target_path', 'target_kind');
        if (body.source_snapshot_digest !== undefined) expectedScanKeys.push('source_snapshot_digest');
        assert.deepEqual(
          Object.keys(body).sort(),
          expectedScanKeys.sort(),
          'scan command accepts only the production request fields',
        );
        assert.equal(body.mode, 'full');
        assert.equal(body.use_ai, false);
        if (body.target_path !== undefined) {
          assert.match(body.target_path, /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,4096}$/u);
          assert(body.target_path.split('/').every((segment) => segment && segment !== '.' && segment !== '..'));
          assert.match(body.target_kind, /^(?:file|directory)$/u);
        } else {
          assert.equal(body.target_kind, undefined);
        }
        if (nativeSnapshotSource && body.project_id === 17) {
          const snapshot = admittedSnapshots.get(body.source_snapshot_digest);
          const paths = snapshot?.files.map(({ path }) => path);
          const exactScope = snapshot && (body.target_path === undefined
            ? snapshot.admitted.directory_scope === null
              && isDeepStrictEqual(paths, [...nativeSourceFiles.keys()].sort())
            : body.target_kind === 'directory'
              ? snapshot.admitted.directory_scope === body.target_path
              : snapshot.admitted.directory_scope === null && isDeepStrictEqual(paths, [body.target_path]));
          if (!exactScope) {
            send(response, 422, { detail: { code: 'source_snapshot_invalid',
              message: 'Scan does not match its admitted exact snapshot and scope.' } });
            return;
          }
          recordedRequest.sourceSnapshotAdmission = snapshot.admitted;
        } else if (body.source_snapshot_digest !== undefined) {
          send(response, 422, { detail: { code: 'source_snapshot_invalid',
            message: 'Mounted fixture projects cannot use a native snapshot.' } });
          return;
        }
        const replay = scanRequestsByIdempotencyKey.get(idempotencyKey);
        if (replay) {
          if (!isDeepStrictEqual(replay.command, body)) {
            send(response, 409, { detail: 'idempotency key was already used for a different scan command' });
          } else {
            recordedRequest.idempotentReplay = true;
            recordedRequest.responseScanId = replay.response.id;
            recordedRequest.responseJobId = replay.response.job_id;
            send(response, 202, replay.response);
          }
          return;
        }
        if (!initialFindingsByProject.has(body.project_id)) {
          send(response, 404, { detail: 'fixture project is not registered' });
        } else {
          const sourceScan = latestScans.get(body.project_id) || null;
          const registeredSourceBoundary = registeredSourceBoundaries.get(body.project_id) || null;
          recordedRequest.sourceScanBefore = sourceScan ? { ...sourceScan } : null;
          recordedRequest.registeredSourceBoundaryBefore = registeredSourceBoundary
            ? { ...registeredSourceBoundary }
            : null;
          const scanId = ++nextScanId;
          const findings = freshFindingSnapshot(
            body.project_id,
            scanId,
            body.target_path,
            body.target_kind,
          );
          const selectedScan = storeScan({
            project_id: body.project_id,
            gate_decision: gateDecision(findings),
            findings_revision: 2,
            revision: 4,
            id: scanId,
            status: 'completed',
          }, { latest: true });
          nextScanJobId += 1;
          scanJobs.set(nextScanJobId, selectedScan.id);
          const pendingResponse = Object.freeze({
            ...selectedScan,
            findings_revision: 1,
            gate_decision: null,
            revision: 1,
            status: 'pending',
            job_id: nextScanJobId,
            job_revision: 1,
          });
          scanRequestsByIdempotencyKey.set(idempotencyKey, {
            command: Object.freeze({ ...body }),
            response: pendingResponse,
          });
          recordedRequest.idempotentReplay = false;
          recordedRequest.responseScanId = selectedScan.id;
          recordedRequest.responseJobId = nextScanJobId;
          recordedRequest.responseScan = {
            findings_revision: pendingResponse.findings_revision,
            gate_decision: pendingResponse.gate_decision,
            id: selectedScan.id,
            revision: pendingResponse.revision,
          };
          recordedRequest.sourceScanAfter = sourceScan ? { ...scans.get(sourceScan.id) } : null;
          const registeredSourceBoundaryAfter = registeredSourceBoundaries.get(body.project_id) || null;
          recordedRequest.registeredSourceBoundaryAfter = registeredSourceBoundaryAfter
            ? { ...registeredSourceBoundaryAfter }
            : null;
          send(response, 202, pendingResponse);
        }
      } else if (request.method === 'GET' && /^\/v1\/jobs\/[1-9][0-9]*$/u.test(url.pathname)) {
        const jobId = Number(url.pathname.split('/').at(-1));
        const scanId = scanJobs.get(jobId);
        if (!scanId) {
          send(response, 404, { detail: 'fixture scan job is not registered' });
        } else {
          send(response, 200, {
            id: jobId,
            kind: 'scan',
            title: `Scan #${scanId}`,
            status: 'completed',
            stage: 'completed',
            detail: 'Persisted fixture scan completed.',
            progress: 100,
            scan_id: scanId,
            attempt: 1,
            max_attempts: 3,
            revision: 2,
            can_cancel: false,
            can_retry: false,
          });
        }
      } else if (request.method === 'GET' && url.pathname === '/v1/projects/17/scans/latest') {
        send(response, 200, latestScans.get(17));
      } else if (request.method === 'GET' && url.pathname === '/v1/projects/18/scans/latest') {
        send(response, 200, latestScans.get(18));
      } else if (request.method === 'GET' && scanFindingFilesMatch) {
        const selectedScan = scans.get(Number(scanFindingFilesMatch[1]));
        if (!selectedScan) {
          send(response, 404, { detail: 'fixture scan is not registered' });
          return;
        }
        recordedRequest.findingsRevision = selectedScan.findings_revision;
        const values = findingsForScan(selectedScan);
        const richLimit = richLimitManifests.get(selectedScan.id);
        const actualRichFileTotal = richLimit
          ? values.filter(({ file_path: filePath }) => filePath === richLimit.filePath).length
          : 0;
        const totalFindings = richLimit
          ? values.length + richLimit.total - actualRichFileTotal
          : values.length;
        const filePaths = [...new Set(values.map(({ file_path: filePath }) => filePath))];
        recordedRequest.responseScan = {
          file_paths: filePaths,
          findings_revision: selectedScan.findings_revision,
          gate_decision: selectedScan.gate_decision,
          id: selectedScan.id,
          revision: selectedScan.revision,
          total_files: filePaths.length,
          total_findings: totalFindings,
        };
        const grouped = new Map();
        for (const value of values) {
          const fileValues = grouped.get(value.file_path) || [];
          fileValues.push(value);
          grouped.set(value.file_path, fileValues);
        }
        let items = [...grouped.entries()]
          .map(([filePath, fileValues]) => findingFileAggregate(filePath, fileValues))
          .sort((left, right) => left.first_scan_finding_number - right.first_scan_finding_number);
        if (richLimit) {
          const richIndex = items.findIndex(({ file_path: filePath }) => filePath === richLimit.filePath);
          assert.notEqual(richIndex, -1, 'rich-limit fixture file must exist in the manifest');
          items = items.with(
            richIndex,
            richLimitAggregate(items[richIndex], richLimit.total, semanticFixture.large_set.severity),
          );
        }
        send(response, 200, {
          scan: {
            ...selectedScan,
            gate_decision: selectedScan.gate_decision ?? null,
            gate_reasons: [],
            error: null,
          },
          total_findings: totalFindings,
          total_files: items.length,
          items,
          truncated: false,
          next_cursor: null,
        });
      } else if (request.method === 'GET' && scanDiagnosticsMatch) {
        const selectedScan = scans.get(Number(scanDiagnosticsMatch[1]));
        if (!selectedScan) {
          send(response, 404, { detail: 'fixture scan is not registered' });
          return;
        }
        recordedRequest.findingsRevision = selectedScan.findings_revision;
        assert.equal(url.searchParams.get('expected_revision'), String(selectedScan.findings_revision));
        const values = findingsForScan(selectedScan);
        const offset = Number(url.searchParams.get('cursor') || '0');
        const items = values.slice(offset, offset + 200);
        recordedRequest.responseFindings = items.map(findingIdentityReceipt);
        const nextOffset = offset + items.length;
        send(response, 200, {
          scan_id: selectedScan.id,
          items: items.map(diagnosticFinding),
          total: values.length,
          truncated: nextOffset < values.length,
          next_cursor: nextOffset < values.length ? String(nextOffset) : null,
          revision: selectedScan.findings_revision,
        });
      } else if (request.method === 'GET' && scanFindingsMatch) {
        const selectedScan = scans.get(Number(scanFindingsMatch[1]));
        if (!selectedScan) {
          send(response, 404, { detail: 'fixture scan is not registered' });
          return;
        }
        const requestedRevision = Number(url.searchParams.get('expected_revision'));
        recordedRequest.findingsRevision = requestedRevision;
        if (requestedRevision !== selectedScan.findings_revision) {
          send(response, 409, { detail: 'fixture rich revision changed' });
          return;
        }
        const filePath = url.searchParams.get('file_path');
        assert(filePath, 'rich findings are fetched only for an exact manifest file');
        const values = findingsForScan(selectedScan).filter((value) => value.file_path === filePath);
        const offset = Number(url.searchParams.get('cursor') || '0');
        const items = values.slice(offset, offset + 200);
        recordedRequest.responseFindings = items.map(findingIdentityReceipt);
        const nextOffset = offset + items.length;
        send(response, 200, {
          items,
          total: values.length,
          truncated: nextOffset < values.length,
          next_cursor: nextOffset < values.length ? String(nextOffset) : null,
          revision: selectedScan.findings_revision,
        });
      } else if (request.method === 'GET' && scanLocalFindingMatch) {
        const selectedScan = scans.get(Number(scanLocalFindingMatch[1]));
        if (!selectedScan) {
          send(response, 404, { detail: 'fixture scan is not registered' });
          return;
        }
        assert.deepEqual(
          [...url.searchParams.keys()].sort(),
          ['expected_findings_revision', 'expected_revision'],
          'scan-local finding detail requires both and only the real API revision fences',
        );
        assert.equal(
          url.searchParams.get('expected_findings_revision'),
          String(selectedScan.findings_revision),
        );
        const scanFindingNumber = Number(scanLocalFindingMatch[2]);
        const summary = findingsForScan(selectedScan).find(
          ({ scan_finding_number: number }) => number === scanFindingNumber,
        );
        if (!summary) {
          send(response, 404, { detail: 'finding no longer exists' });
        } else {
          assert.equal(url.searchParams.get('expected_revision'), String(summary.revision));
          recordedRequest.responseFinding = findingIdentityReceipt(summary);
          send(response, 200, findingDetail(
            summary,
            findingLifecycles.get(summary.id) || {},
            selectedScan.findings_revision,
          ));
        }
      } else if (request.method === 'PATCH' && findingLifecycleMatch) {
        const target = findingById(Number(findingLifecycleMatch[1]));
        if (!target) {
          send(response, 404, { detail: 'fixture finding is not registered' });
          return;
        }
        assert.ok(
          ['accepted_risk', 'gate_exempt'].includes(body.action),
          'the shared fixture supports the extension-host and real-surface lifecycle scenarios',
        );
        assert.equal(body.expected_revision, target.value.revision);
        assert.equal(typeof body.reason, 'string');
        assert.ok(body.reason.trim().length > 0);
        const updatedFinding = {
          ...target.value,
          lifecycle_status: body.action,
          gate_exempt: true,
          gate_effect: 'non_blocking',
          suppressed: false,
          revision: target.value.revision + 1,
        };
        const lifecycle = Object.freeze({
          gateExemptReason: body.reason,
          reason: body.reason,
          updatedAt: '2026-08-13T00:01:00Z',
        });
        findingLifecycles.set(updatedFinding.id, lifecycle);
        const updatedFindings = replaceFinding(target.selectedScan, updatedFinding.id, updatedFinding);
        const selectedScan = storeScan({
          ...target.selectedScan,
          findings_revision: target.selectedScan.findings_revision + 1,
          gate_decision: gateDecision(updatedFindings),
          revision: target.selectedScan.revision + 1,
        });
        recordedRequest.responseFinding = findingIdentityReceipt(updatedFinding);
        recordedRequest.responseScan = {
          findings_revision: selectedScan.findings_revision,
          gate_decision: selectedScan.gate_decision,
          id: selectedScan.id,
          revision: selectedScan.revision,
          total_findings: updatedFindings.length,
        };
        send(response, 200, findingDetail(
          updatedFinding,
          lifecycle,
          selectedScan.findings_revision,
        ));
      } else if (request.method === 'GET' && scanResourceMatch) {
        const selectedScan = scans.get(Number(scanResourceMatch[1]));
        if (selectedScan) send(response, 200, selectedScan);
        else send(response, 404, { detail: 'fixture scan is not registered' });
      } else if (request.method === 'POST' && findingTriageMatch) {
        const target = findingById(Number(findingTriageMatch[1]));
        if (!target) {
          send(response, 404, { detail: 'fixture finding is not registered' });
          return;
        }
        assert.deepEqual(body, {
          model: null,
          expected_revision: target.value.revision,
          advisor_provider_pin: LOCAL_ADVISOR_PIN,
        });
        assert.match(String(recordedRequest.idempotencyKey), /^vscode-[0-9a-f-]{36}$/u);
        recordedRequest.responseFinding = findingIdentityReceipt(target.value);
        send(response, 202, {
          id: 88,
          kind: 'advisor',
          finding_id: target.value.id,
          status: 'queued',
          progress: 0,
          revision: 1,
        });
      } else if (request.method === 'DELETE' && findingDeleteMatch) {
        const target = findingById(Number(findingDeleteMatch[1]));
        if (!target) {
          send(response, 404, { detail: 'fixture finding is not registered' });
          return;
        }
        assert.deepEqual([...url.searchParams.keys()], ['expected_revision']);
        assert.equal(url.searchParams.get('expected_revision'), String(target.value.revision));
        assert.equal(body, undefined);
        const updatedFindings = deleteFinding(target.selectedScan, target.value.id);
        const selectedScan = storeScan({
          ...target.selectedScan,
          gate_decision: gateDecision(updatedFindings),
          findings_revision: target.selectedScan.findings_revision + 1,
          revision: target.selectedScan.revision + 1,
        });
        recordedRequest.responseFinding = findingIdentityReceipt(target.value);
        recordedRequest.responseScan = {
          findings_revision: selectedScan.findings_revision,
          gate_decision: selectedScan.gate_decision,
          id: selectedScan.id,
          revision: selectedScan.revision,
          total_findings: updatedFindings.length,
        };
        send(response, 200, { deleted: true, finding_id: target.value.id, scan_id: selectedScan.id });
      } else {
        send(response, 404, { detail: `unhandled fake API route: ${request.method} ${url.pathname}` });
      }
      } finally {
        // The Remote WSL ledger must persist the completed handler's exact
        // response identity metadata, not an early mutable request snapshot.
        onRequest(recordedRequest);
      }
    });
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  assert(address && typeof address === 'object');
  return {
    approveIdeEnrollment(requestId, verificationCode) {
      assert(pendingEnrollment, 'fixture has no pending IDE enrollment to approve');
      assert.equal(requestId, pendingEnrollment.request_id);
      if (verificationCode !== undefined) {
        assert.equal(verificationCode, pendingEnrollment.verification_code);
      }
      assert.equal(pendingEnrollment.state, 'awaiting_approval');
      pendingEnrollment = {
        ...pendingEnrollment,
        state: 'approved',
        revision: pendingEnrollment.revision + 1,
        decision_at: '2099-01-01T00:01:00Z',
      };
      flushEnrollmentWaiters();
      return Object.freeze({ ...pendingEnrollment });
    },
    async close() {
      // Stop accepting work first, then terminate the deliberately long-lived
      // SSE stream and any keep-alive sockets before awaiting server closure.
      const closed = new Promise((resolveClose, rejectClose) => {
        server.close((error) => error ? rejectClose(error) : resolveClose());
      });
      for (const response of eventResponses) {
        response.destroy();
      }
      eventResponses.clear();
      server.closeAllConnections?.();
      for (const socket of sockets) {
        socket.destroy();
      }
      sockets.clear();
      await closed;
    },
    isListening() { return server.listening; },
    currentIdeEnrollment() {
      return pendingEnrollment ? Object.freeze({ ...pendingEnrollment }) : undefined;
    },
    currentBrowserMemberships() {
      return Object.freeze([...browserInvitations.values()].map(({ membership }) => membership));
    },
    enableRichLimitManifest() {
      const selectedScan = latestScans.get(17);
      assert(selectedScan, 'primary fixture scan must exist before enabling the rich limit');
      assert(!richLimitManifests.has(selectedScan.id), 'rich-limit fixture may be enabled only once per scan');
      const filePath = semanticFixture.large_set.file_path;
      const actual = findingsForScan(selectedScan).filter(({ file_path: findingPath }) => (
        findingPath === filePath
      )).length;
      assert(actual > 0 && actual < RICH_LIMIT_FINDING_TOTAL);
      const updatedScan = storeScan({
        ...selectedScan,
        findings_revision: selectedScan.findings_revision + 1,
        revision: selectedScan.revision + 1,
      }, { latest: true });
      richLimitManifests.set(updatedScan.id, Object.freeze({
        filePath,
        total: RICH_LIMIT_FINDING_TOTAL,
      }));
      return Object.freeze({
        actual_findings: actual,
        file_path: filePath,
        findings_revision: updatedScan.findings_revision,
        rich_findings: RICH_LIMIT_FINDING_TOTAL,
        scan_id: updatedScan.id,
        total_findings: findingsForScan(updatedScan).length + RICH_LIMIT_FINDING_TOTAL - actual,
      });
    },
    origin: `http://127.0.0.1:${address.port}`,
    recentRequestSummary() {
      const recent = requests.slice(-12).map(({ method, pathname, search }) => (
        `${method} ${pathname}${search}`
      ));
      return `Recent fake API requests (${requests.length} total, last ${recent.length}):\n${recent.join('\n')}`;
    },
    requests,
    revokeCapability() { capabilityRevoked = true; },
  };
}

function send(response, status, payload) {
  response.writeHead(status, {
    'Connection': 'close',
    'Content-Type': 'application/json',
  });
  response.end(JSON.stringify(payload));
}

module.exports = { fakeApi };
