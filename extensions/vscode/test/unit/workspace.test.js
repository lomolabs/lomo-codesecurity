const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { CodeSecurityRequestError } = require('../../dist/client.js');
const {
  canonicalWorkspaceSourcePath,
  classifyWorkspaceSourceUri,
  ensureWorkspaceProject,
  findingManifestPriorityPaths,
  MAX_DIAGNOSTIC_FILES,
  MAX_DIAGNOSTIC_FINDINGS,
  MAX_DIAGNOSTICS_PER_FILE,
  MAX_DIAGNOSTIC_BATCH,
  MAX_SCAN_FINDINGS,
  loadFindingDetail,
  loadFindingFileManifest,
  loadFindingPages,
  loadSourceOpenProjectContext,
  loadScanFindings,
  loadWorkspaceFindings,
  loadWorkspaceState,
  registeredProjectPrefix,
  rebaseRegisteredProjectFindingPath,
  safeFindingRelativePath,
  streamFindingDiagnosticPages,
  workspaceRelativeUriPath,
  workspaceSourcePath,
} = require('../../dist/workspace.js');

function item(id, overrides = {}) {
  return {
    id,
    scan_id: 41,
    scan_finding_number: id,
    display_id: `S41-F${String(id).padStart(3, '0')}`,
    scanner: 'fixture',
    rule_id: `fixture.${id}`,
    severity: 'high',
    file_path: `src/${id}.ts`,
    start_line: id,
    start_column: 2,
    end_line: id,
    end_column: 5,
    message: `finding ${id}`,
    fingerprint: `fingerprint-${id}`,
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
    revision: 1,
    ...overrides,
  };
}

function findingDetail(id, overrides = {}) {
  return {
    ...item(id),
    findings_revision: 1,
    code_snippet: null,
    metadata_json: {},
    ai_verdict: null,
    ai_confidence: null,
    ai_reasoning: null,
    ai_fix: null,
    suppression_reason: null,
    gate_exempt_reason: null,
    lifecycle_reason: null,
    lifecycle_updated_at: null,
    created_at: '2026-08-13T00:00:00Z',
    ...overrides,
  };
}

function diagnostic(id, overrides = {}) {
  const value = item(id, overrides);
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

function manifestItem(path, first, overrides = {}) {
  return {
    file_path: path,
    first_scan_finding_number: first,
    total: 1,
    active: 1,
    suppressed: 0,
    gate_exempt: 0,
    blocking: 1,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    lifecycle_counts: {
      open: 1,
      needs_review: 0,
      gate_exempt: 0,
      accepted_risk: 0,
      ignore: 0,
      false_positive: 0,
      fixed: 0,
    },
    ...overrides,
  };
}

function manifestScan(overrides = {}) {
  return {
    id: 41,
    project_id: 7,
    status: 'completed',
    gate_decision: 'fail',
    gate_reasons: [],
    error: null,
    revision: 4,
    findings_revision: 8,
    ...overrides,
  };
}

test('workspace project resolution is server-side and exact-path bound', async () => {
  const calls = [];
  const project = await ensureWorkspaceProject(async (path, init) => {
    calls.push({ path, init });
    return { id: 7, name: 'current', repo_path: '/workspace/current' };
  }, 'current', '/workspace/current');

  assert.equal(project.id, 7);
  assert.deepEqual(calls.map(({ path }) => path), ['/v1/projects/resolve']);
  assert.deepEqual(JSON.parse(calls[0].init.body), { repo_path: '/workspace/current' });
});

test('workspace project responses reject malformed authoritative revisions', async () => {
  await assert.rejects(
    ensureWorkspaceProject(
      async () => ({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 0 }),
      'current',
      '/workspace/current',
    ),
    /outside the selected workspace source root/,
  );
});

test('workspace binding canonicalizes paths and derives stable basename names', async () => {
  const creates = [];
  const bind = async (repoPath, id) => ensureWorkspaceProject(async (path, init) => {
    if (path === '/v1/projects/resolve') {
      throw new CodeSecurityRequestError('absent', 404);
    }
    const payload = JSON.parse(init.body);
    creates.push(payload);
    return { id, name: payload.name, repo_path: payload.repo_path };
  }, 'custom workspace label', repoPath);

  const first = await bind('/workspace/team-a//service/.', 7);
  const second = await bind('/workspace/team-b/service/', 8);
  assert.deepEqual(creates, [
    { name: 'service', repo_path: '/workspace/team-a/service', default_branch: 'main' },
    { name: 'service', repo_path: '/workspace/team-b/service', default_branch: 'main' },
  ]);
  assert.equal(first.id, 7);
  assert.equal(second.id, 8);
  assert.equal(canonicalWorkspaceSourcePath('/workspace//nested/./root/'), '/workspace/nested/root');
});

test('registered nested projects use segment boundaries and safe workspace-relative finding paths', () => {
  assert.equal(registeredProjectPrefix('/workspace/current', '/workspace/current'), '');
  assert.equal(registeredProjectPrefix('/workspace/current', '/workspace/current/k8s'), 'k8s');
  assert.equal(registeredProjectPrefix('/workspace/current', '/workspace/currentish/k8s'), undefined);
  assert.equal(rebaseRegisteredProjectFindingPath('k8s', 'deployment.yaml'), 'k8s/deployment.yaml');
  assert.throws(
    () => rebaseRegisteredProjectFindingPath('k8s', '../outside.yaml'),
    /unsafe retained-finding source path/,
  );
});

test('targeted source-open project context rejects mismatched and unsafe source identities', async () => {
  const commandId = 'a'.repeat(32);
  const expectedPath = `/v1/ide/source-open-commands/${commandId}/context`;
  const valid = {
    v: 1,
    command_id: commandId,
    project_id: 9,
    project_repo_path: '/workspace/current/k8s',
  };
  const calls = [];
  const loaded = await loadSourceOpenProjectContext(async (path) => {
    calls.push(path);
    return valid;
  }, commandId, 9);
  assert.deepEqual(loaded, {
    commandId,
    projectId: 9,
    repoPath: '/workspace/current/k8s',
  });
  assert.deepEqual(calls, [expectedPath]);
  const exactUtf8Boundary = `/${'é'.repeat(2_047)}a`;
  assert.equal(new TextEncoder().encode(exactUtf8Boundary).byteLength, 4_096);
  assert.equal((await loadSourceOpenProjectContext(async () => ({
    ...valid,
    project_repo_path: exactUtf8Boundary,
  }), commandId, 9)).repoPath, exactUtf8Boundary);

  const rejected = [
    { ...valid, command_id: 'b'.repeat(32) },
    { ...valid, project_id: 10 },
    { ...valid, project_repo_path: '/workspace/current//k8s' },
    { ...valid, project_repo_path: '/workspace/current/../outside' },
    { ...valid, project_repo_path: '/workspace/current\\k8s' },
    { ...valid, project_repo_path: '/workspace/current/\u0001k8s' },
    { ...valid, project_repo_path: '/workspace/current/\ud800' },
    { ...valid, project_repo_path: `/${'é'.repeat(2_048)}` },
  ];
  for (const candidate of rejected) {
    await assert.rejects(
      loadSourceOpenProjectContext(async (path) => {
        assert.equal(path, expectedPath);
        return candidate;
      }, commandId, 9),
      /targeted source-open project identity|safe absolute POSIX source path|non-canonical registered project source path/u,
    );
  }
});

test('workspace binding bounds hostile or unusable basenames before project creation', async () => {
  const names = [];
  const bind = async (label, repoPath, id) => ensureWorkspaceProject(async (path, init) => {
    if (path === '/v1/projects/resolve') throw new CodeSecurityRequestError('absent', 404);
    const payload = JSON.parse(init.body);
    names.push(payload.name);
    return { id, name: payload.name, repo_path: payload.repo_path };
  }, label, repoPath);

  await bind('   ', '/workspace/   ', 7);
  await bind('ignored', `/workspace/${'x'.repeat(121)}`, 8);
  await bind('ignored', `/workspace/${'😀'.repeat(121)}`, 9);

  assert.deepEqual(names, ['workspace', 'x'.repeat(120), '😀'.repeat(120)]);
  assert.deepEqual(names.map((name) => Array.from(name).length), [9, 120, 120]);
});

test('absent workspace is created once and a concurrent creation is reconciled by exact resolve', async () => {
  const calls = [];
  let resolveReads = 0;
  const project = await ensureWorkspaceProject(async (path, init) => {
    calls.push(path);
    if (path === '/v1/projects/resolve') {
      resolveReads += 1;
      if (resolveReads === 1) throw new CodeSecurityRequestError('absent', 404);
      return { id: 9, name: 'current', repo_path: '/workspace/current' };
    }
    assert.deepEqual(JSON.parse(init.body), {
      name: 'current', repo_path: '/workspace/current', default_branch: 'main',
    });
    throw new CodeSecurityRequestError('concurrent', 409);
  }, 'current', '/workspace/current');

  assert.equal(project.id, 9);
  assert.deepEqual(calls, ['/v1/projects/resolve', '/v1/projects', '/v1/projects/resolve']);
});

test('ambiguous project resolution and cross-path responses fail closed', async () => {
  await assert.rejects(
    ensureWorkspaceProject(async () => { throw new CodeSecurityRequestError('ambiguous', 409); }, 'x', '/workspace/x'),
    (error) => error.status === 409,
  );
  await assert.rejects(
    ensureWorkspaceProject(async () => ({ id: 7, name: 'other', repo_path: '/workspace/other' }), 'x', '/workspace/x'),
    /outside the selected workspace source root/,
  );
});

test('latest server-resolved active scan never substitutes older evidence', async () => {
  const calls = [];
  const snapshot = await loadWorkspaceFindings(async (path) => {
    calls.push(path);
    if (path === '/v1/projects/resolve') return { id: 7, name: 'current', repo_path: '/workspace/current' };
    if (path === '/v1/projects/7/scans/latest') return { id: 104, project_id: 7, status: 'running' };
    throw new Error(`unexpected ${path}`);
  }, '/workspace/current');

  assert.equal(snapshot.scan.id, 104);
  assert.deepEqual(snapshot.findings, []);
  assert.deepEqual(calls, ['/v1/projects/resolve', '/v1/projects/7/scans/latest']);
});

test('workspace metadata loads revisions without hydrating finding pages', async () => {
  const calls = [];
  const controller = new AbortController();
  const state = await loadWorkspaceState(async (path, init) => {
    calls.push({ path, init });
    if (path === '/v1/projects/resolve') {
      return { id: 7, name: 'current', repo_path: '/workspace/current', revision: 4 };
    }
    if (path === '/v1/projects/7/scans/latest') {
      return {
        id: 41,
        project_id: 7,
        status: 'completed',
        revision: 9,
        findings_revision: 12,
        job_id: 71,
        job_revision: 6,
      };
    }
    throw new Error(`unexpected ${path}`);
  }, '/workspace/current', controller.signal);

  assert.deepEqual(state, {
    project: { id: 7, name: 'current', repo_path: '/workspace/current', revision: 4 },
    scan: {
      id: 41,
      project_id: 7,
      status: 'completed',
      revision: 9,
      findings_revision: 12,
      job_id: 71,
      job_revision: 6,
    },
  });
  assert.deepEqual(calls.map(({ path }) => path), [
    '/v1/projects/resolve',
    '/v1/projects/7/scans/latest',
  ]);
  assert(calls.every(({ init }) => init.signal === controller.signal));
});

test('workspace metadata treats missing resources explicitly and rejects malformed scan revisions', async () => {
  assert.deepEqual(await loadWorkspaceState(async () => {
    throw new CodeSecurityRequestError('absent', 404);
  }, '/workspace/current'), {});

  const projectOnly = await loadWorkspaceState(async (path) => {
    if (path === '/v1/projects/resolve') {
      return { id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 };
    }
    throw new CodeSecurityRequestError('no scans', 404);
  }, '/workspace/current');
  assert.deepEqual(projectOnly, {
    project: { id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 },
  });

  await assert.rejects(loadWorkspaceState(async (path) => (
    path === '/v1/projects/resolve'
      ? { id: 7, name: 'current', repo_path: '/workspace/current' }
      : { id: 41, project_id: 7, status: 'completed', revision: 0, findings_revision: 1 }
  ), '/workspace/current'), /outside the requested workspace project/);
});

test('finding-file manifest is revision-stable, bounded, and retained as an exact ReadonlyMap', async () => {
  const calls = [];
  let yields = 0;
  const manifest = await loadFindingFileManifest(async (path) => {
    calls.push(path);
    if (path === '/v1/scans/41/finding-files?limit=200') {
      return {
        scan: manifestScan(),
        total_findings: 2,
        total_files: 2,
        items: [manifestItem('src/a.ts', 1)],
        truncated: true,
        next_cursor: 'opaque+manifest',
      };
    }
    if (path === '/v1/scans/41/finding-files?limit=200&cursor=opaque%2Bmanifest') {
      return {
        scan: manifestScan(),
        total_findings: 2,
        total_files: 2,
        items: [manifestItem('src/b.ts', 2)],
        truncated: false,
        next_cursor: null,
      };
    }
    throw new Error(`unexpected ${path}`);
  }, 41, undefined, async () => { yields += 1; });

  assert.equal(manifest.totalFindings, 2);
  assert.equal(manifest.files.size, 2);
  assert.deepEqual([...manifest.files.keys()], ['src/a.ts', 'src/b.ts']);
  assert.deepEqual(manifest.files.get('src/b.ts'), {
    file_path: 'src/b.ts',
    first_scan_finding_number: 2,
    total: 1,
    active: 1,
    suppressed: 0,
    gate_exempt: 0,
    blocking: 1,
  });
  assert.equal(yields, 1);
  assert.deepEqual(calls, [
    '/v1/scans/41/finding-files?limit=200',
    '/v1/scans/41/finding-files?limit=200&cursor=opaque%2Bmanifest',
  ]);

  await assert.rejects(loadFindingFileManifest(async () => ({
    scan: manifestScan(),
    total_findings: 50_000,
    total_files: 50_001,
    items: [],
    truncated: true,
    next_cursor: 'next',
  }), 41), /50000-file safety bound/);

  for (const hostile of [
    {
      total_findings: 50_001,
      total_files: 1,
      items: [manifestItem('src/too-many.ts', 1)],
    },
    {
      total_findings: 50_000,
      total_files: 1,
      items: [manifestItem('src/too-dense.ts', 1, {
        total: 50_001,
        active: 50_001,
        blocking: 50_001,
        severity_counts: { critical: 0, high: 50_001, medium: 0, low: 0, info: 0 },
        lifecycle_counts: {
          open: 50_001,
          needs_review: 0,
          gate_exempt: 0,
          accepted_risk: 0,
          ignore: 0,
          false_positive: 0,
          fixed: 0,
        },
      })],
    },
    {
      total_findings: 1,
      total_files: 1,
      items: [manifestItem('src/high-ordinal.ts', 50_001)],
    },
  ]) {
    await assert.rejects(loadFindingFileManifest(async () => ({
      scan: manifestScan(),
      ...hostile,
      truncated: false,
      next_cursor: null,
    }), 41), /invalid finding-file manifest|inconsistent finding-file manifest/);
  }
});

test('compact diagnostic stream fences revision/count/order and releases pages to a callback', async () => {
  const calls = [];
  const accepted = [];
  const result = await streamFindingDiagnosticPages(async (path) => {
    calls.push(path);
    if (!path.includes('cursor=')) {
      return {
        scan_id: 41,
        items: [diagnostic(1)],
        total: 2,
        truncated: true,
        next_cursor: 'opaque+diagnostic',
        revision: 8,
      };
    }
    return {
      scan_id: 41,
      items: [diagnostic(2)],
      total: 2,
      truncated: false,
      next_cursor: null,
      revision: 8,
    };
  }, 41, 8, async (page, progress) => {
    accepted.push({ ids: page.map(({ id }) => id), ...progress });
  }, { maximumFindings: 2, yieldControl: async () => {} });

  assert.deepEqual(result, { total: 2, revision: 8 });
  assert.deepEqual(accepted, [
    { ids: [1], processed: 1, total: 2, revision: 8, page: 1 },
    { ids: [2], processed: 2, total: 2, revision: 8, page: 2 },
  ]);
  assert.deepEqual(calls, [
    '/v1/scans/41/finding-diagnostics?limit=200&expected_revision=8',
    '/v1/scans/41/finding-diagnostics?limit=200&expected_revision=8&cursor=opaque%2Bdiagnostic',
  ]);

  await assert.rejects(streamFindingDiagnosticPages(async () => ({
    scan_id: 41,
    items: [diagnostic(1)],
    total: 1,
    truncated: false,
    next_cursor: null,
    revision: 9,
  }), 41, 8, async () => {}), (error) => error.status === 409);
  await assert.rejects(streamFindingDiagnosticPages(async () => ({
    scan_id: 41,
    items: [diagnostic(1), diagnostic(1, { scan_finding_number: 2, display_id: 'S41-F002' })],
    total: 2,
    truncated: false,
    next_cursor: null,
    revision: 8,
  }), 41, 8, async () => {}), /duplicate or out-of-order/);
});

test('Problems projection and transport have separate bounds while sparse ordinals retain the 50k identity range', async () => {
  assert.equal(MAX_DIAGNOSTIC_FINDINGS, 10_000);
  assert.equal(MAX_DIAGNOSTIC_FILES, 10_000);
  assert.equal(MAX_DIAGNOSTICS_PER_FILE, 1_000);
  assert.equal(MAX_DIAGNOSTIC_BATCH, 1_000);
  assert.equal(MAX_SCAN_FINDINGS, 50_000);
  const accepted = [];
  const result = await streamFindingDiagnosticPages(async () => ({
    scan_id: 41,
    items: [diagnostic(50_000)],
    total: 1,
    truncated: false,
    next_cursor: null,
    revision: 8,
  }), 41, 8, async (items) => accepted.push(...items), { maximumFindings: 1 });
  assert.deepEqual(result, { total: 1, revision: 8 });
  assert.equal(accepted[0].scan_finding_number, 50_000);
});

test('terminal findings load every keyset page with one stable revision and yielding', async () => {
  const calls = [];
  let yields = 0;
  const snapshot = await loadWorkspaceFindings(async (path) => {
    calls.push(path);
    if (path === '/v1/projects/resolve') return { id: 7, name: 'current', repo_path: '/workspace/current' };
    if (path === '/v1/projects/7/scans/latest') {
      return { id: 41, project_id: 7, status: 'failed', findings_revision: 8 };
    }
    if (path === '/v1/scans/41/findings?limit=200') {
      return { items: [item(1)], total: 2, truncated: true, next_cursor: 'opaque+cursor', revision: 8 };
    }
    if (path === '/v1/scans/41/findings?limit=200&cursor=opaque%2Bcursor') {
      return { items: [item(2)], total: 2, truncated: false, next_cursor: null, revision: 8 };
    }
    throw new Error(`unexpected ${path}`);
  }, '/workspace/current', undefined, async () => { yields += 1; });

  assert.deepEqual(snapshot.findings.map(({ id }) => id), [1, 2]);
  assert.equal(snapshot.total, 2);
  assert.equal(snapshot.revision, 8);
  assert.equal(yields, 1);
  assert.equal(calls.some((path) => path.includes('limit=500')), false);
});

test('latest workspace refresh retries when lifecycle state advances findings before gate metadata', async () => {
  let scanReads = 0;
  let pageReads = 0;
  let yields = 0;
  const snapshot = await loadWorkspaceFindings(async (path) => {
    if (path === '/v1/projects/resolve') {
      return { id: 7, name: 'current', repo_path: '/workspace/current' };
    }
    if (path === '/v1/projects/7/scans/latest') {
      scanReads += 1;
      return scanReads === 1
        ? { id: 41, project_id: 7, status: 'completed', gate_decision: 'fail', findings_revision: 8 }
        : { id: 41, project_id: 7, status: 'completed', gate_decision: 'pass', findings_revision: 9 };
    }
    if (path === '/v1/scans/41/findings?limit=200') {
      pageReads += 1;
      return {
        items: [item(1, {
          lifecycle_status: 'gate_exempt', gate_exempt: true, gate_effect: 'non_blocking', revision: 9,
        })],
        total: 1,
        truncated: false,
        next_cursor: null,
        revision: 9,
      };
    }
    throw new Error(`unexpected ${path}`);
  }, '/workspace/current', undefined, async () => { yields += 1; });

  assert.equal(scanReads, 2);
  assert.equal(pageReads, 2);
  assert.equal(yields, 1);
  assert.equal(snapshot.scan.gate_decision, 'pass');
  assert.equal(snapshot.scan.findings_revision, 9);
  assert.equal(snapshot.revision, 9);
  assert.equal(snapshot.findings[0].revision, 9);
});

test('per-file query encodes exact filters without client-side truncation', async () => {
  const calls = [];
  const result = await loadFindingPages(async (path) => {
    calls.push(path);
    return { items: [item(1)], total: 1, truncated: false, next_cursor: null, revision: 3 };
  }, 41, undefined, {
    filePath: 'src/a file.ts', severity: 'high', scanner: 'OpenGrep', lifecycleStatus: 'needs_review',
  });
  assert.equal(result.total, 1);
  assert.equal(calls[0], '/v1/scans/41/findings?limit=200&file_path=src%2Fa+file.ts&severity=high&scanner=OpenGrep&lifecycle_status=needs_review');
});

test('pagination rejects revision drift, repeated cursors, and false completion', async () => {
  let read = 0;
  await assert.rejects(loadFindingPages(async () => {
    read += 1;
    return read === 1
      ? { items: [item(1)], total: 2, truncated: true, next_cursor: 'next', revision: 4 }
      : { items: [item(2)], total: 2, truncated: false, next_cursor: null, revision: 5 };
  }, 41, undefined, {}, async () => {}), (error) => error.status === 409);

  await assert.rejects(loadFindingPages(async () => ({
    items: [], total: 1, truncated: true, next_cursor: 'same', revision: 4,
  }), 41, undefined, {}, async () => {}), /repeated findings cursor/);

  await assert.rejects(loadFindingPages(async () => ({
    items: [], total: 1, truncated: false, next_cursor: null, revision: 4,
  }), 41), /before the complete result/);
});

test('hostile finding pages reject oversized, cross-scan, malformed-range, and duplicate items', async () => {
  const invalidItems = [
    item(1, { scan_id: 99 }),
    item(1, { file_path: '../outside.ts' }),
    item(1, { start_column: null, end_column: 9 }),
    item(1, { start_line: 2, end_line: 2, start_column: 9, end_column: 4 }),
    item(1, { message: 'x'.repeat(4001) }),
    item(1, { display_id: 'S99-F001' }),
    item(1, { first_seen_scan_id: 0 }),
    item(1, { advisor_confidence: 2 }),
    item(1, { lifecycle_status: 'silently_suppressed' }),
    item(1, { gate_effect: 'advisor_pass' }),
    item(1, { lifecycle_status: 'open', suppressed: true, gate_effect: 'excluded' }),
    item(1, { lifecycle_status: 'gate_exempt', gate_exempt: false, gate_effect: 'blocking' }),
    item(1, { lifecycle_status: 'fixed', suppressed: false, gate_effect: 'blocking' }),
    item(1, { revision: 0 }),
    item(1, { scan_finding_number: 50_001, display_id: 'S41-F50001' }),
  ];
  for (const hostile of invalidItems) {
    await assert.rejects(loadFindingPages(async () => ({
      items: [hostile], total: 1, truncated: false, next_cursor: null, revision: 4,
    }), 41), /invalid lightweight finding item/);
  }

  const missingRequiredField = item(1);
  delete missingRequiredField.gate_effect;
  await assert.rejects(loadFindingPages(async () => ({
    items: [missingRequiredField], total: 1, truncated: false, next_cursor: null, revision: 4,
  }), 41), /invalid lightweight finding item/);

  const sanitized = await loadFindingPages(async () => ({
    items: [{ ...item(1), code_snippet: 'must not enter the lightweight cache' }],
    total: 1,
    truncated: false,
    next_cursor: null,
    revision: 4,
  }), 41);
  assert.equal(Object.hasOwn(sanitized.findings[0], 'code_snippet'), false);

  const insertionPoint = await loadFindingPages(async () => ({
    items: [item(1, {
      start_line: 9, start_column: 1, end_line: 9, end_column: 1,
    })],
    total: 1,
    truncated: false,
    next_cursor: null,
    revision: 4,
  }), 41);
  assert.equal(insertionPoint.findings[0].start_column, 1);
  assert.equal(insertionPoint.findings[0].end_column, 1);

  await assert.rejects(loadFindingPages(async () => ({
    items: Array.from({ length: 201 }, (_, index) => item(index + 1)),
    total: 201, truncated: false, next_cursor: null, revision: 4,
  }), 41), /invalid findings page/);

  let read = 0;
  await assert.rejects(loadFindingPages(async () => {
    read += 1;
    return read === 1
      ? { items: [item(1)], total: 2, truncated: true, next_cursor: 'next', revision: 4 }
      : {
        items: [item(1, { scan_finding_number: 2, display_id: 'S41-F002' })],
        total: 2,
        truncated: false,
        next_cursor: null,
        revision: 4,
      };
  }, 41, undefined, {}, async () => {}), /duplicate finding/);

  await assert.rejects(loadFindingPages(async () => ({
    items: [item(1), item(2)], total: 1, truncated: false, next_cursor: null, revision: 4,
  }), 41), /total is smaller/);
});

test('exact scan and scan-local finding detail reject identity substitution', async () => {
  const calls = [];
  await assert.rejects(loadScanFindings(async (path) => {
    calls.push(path);
    return { id: 41, project_id: 8, status: 'completed' };
  }, 7, 41), /outside the requested workspace project/);
  assert.deepEqual(calls, ['/v1/scans/41']);

  await assert.rejects(loadFindingDetail(async () => findingDetail(9, {
    scan_id: 42, scan_finding_number: 9,
  }), 41, 9, 1, 1), /invalid lightweight finding item/);
  const detail = await loadFindingDetail(async (path) => {
    assert.equal(path, '/v1/scans/41/findings/9?expected_revision=1&expected_findings_revision=1');
    return findingDetail(9, { ai_reasoning: 'local only' });
  }, 41, 9, 1, 1);
  assert.equal(detail.ai_reasoning, 'local only');
});

test('the Python FindingDetailOut contract fixture is accepted with both revision fences', async () => {
  const fixture = JSON.parse(fs.readFileSync(
    path.join(__dirname, '..', 'fixtures', 'contracts', 'finding-detail.json'),
    'utf8',
  ));
  const detail = await loadFindingDetail(async (requestPath) => {
    assert.equal(
      requestPath,
      '/v1/scans/41/findings/7?expected_revision=3&expected_findings_revision=9',
    );
    return fixture;
  }, 41, 7, 3, 9);
  assert.equal(detail.id, 501);
  assert.equal(detail.findings_revision, 9);
  assert.equal(detail.code_snippet, 'RUN adduser --disabled-password app\n\tUSER app');
});

test('finding detail accepts canonical multiline evidence while rejecting unsafe controls', async () => {
  const detail = await loadFindingDetail(async () => findingDetail(9, {
    code_snippet: 'line one\r\n\tline two\rline three',
    ai_reasoning: 'first\r\nsecond · café 😀',
    ai_fix: 'replace\tvalue\nthen verify',
  }), 41, 9, 1, 1);
  assert.equal(detail.code_snippet, 'line one\n\tline two\nline three');
  assert.equal(detail.ai_reasoning, 'first\nsecond · café 😀');
  assert.equal(detail.ai_fix, 'replace\tvalue\nthen verify');

  for (const [field, value] of [
    ['code_snippet', 'safe\u0000unsafe'],
    ['ai_reasoning', 'safe\u001bunsafe'],
    ['ai_fix', 'safe\u202eunsafe'],
    ['code_snippet', 'safe\u2028unsafe'],
  ]) {
    await assert.rejects(
      loadFindingDetail(async () => findingDetail(9, { [field]: value }), 41, 9, 1, 1),
      /invalid multiline finding evidence/,
    );
  }
});

test('finding paths reject absolute, traversal, URI, backslash, and control forms', () => {
  assert.equal(safeFindingRelativePath('src/app.ts'), 'src/app.ts');
  for (const path of [
    '', '/etc/passwd', '../outside.ts', 'src/../outside.ts', './src/app.ts', 'src//app.ts',
    'C:/Windows/system.ini', 'file:///etc/passwd', 'src\\outside.ts', 'src/evil\u0000.ts', 'src/evil\u202e.ts',
    `src/${'😀'.repeat(3000)}.ts`,
  ]) {
    assert.equal(safeFindingRelativePath(path), undefined, JSON.stringify(path));
  }
});

test('manifest priority selection honors required/visible order within the rich-summary budget', () => {
  const files = new Map([
    ['src/required.ts', { file_path: 'src/required.ts', total: 2 }],
    ['src/visible.ts', { file_path: 'src/visible.ts', total: 3 }],
    ['src/background.ts', { file_path: 'src/background.ts', total: 1 }],
  ]);
  const selected = findingManifestPriorityPaths(
    files,
    { scheme: 'file', authority: '', path: '/fixture' },
    [
      { scheme: 'file', authority: '', path: '/fixture/src/visible.ts' },
      { scheme: 'file', authority: '', path: '/fixture/src/background.ts' },
    ],
    ['src/required.ts'],
    5,
  );
  assert.deepEqual(selected, ['src/required.ts', 'src/visible.ts']);
});

test('native Windows URI ownership survives VS Code drive-letter serialization casing', () => {
  const folder = { scheme: 'file', authority: '', path: '/C:/Users/Developer/project' };
  const serializedDocument = {
    scheme: 'file', authority: '', path: '/c:/Users/Developer/project/infra/main.tf',
  };
  assert.equal(workspaceRelativeUriPath(folder, serializedDocument), 'infra/main.tf');
  assert.equal(workspaceRelativeUriPath(folder, {
    scheme: 'file', authority: '', path: '/D:/Users/Developer/project/infra/main.tf',
  }), undefined);
  assert.equal(workspaceRelativeUriPath(folder, {
    scheme: 'file', authority: '', path: '/c:/Users/Developer/project-sibling/main.tf',
  }), undefined);
  assert.equal(workspaceRelativeUriPath(folder, {
    scheme: 'file', authority: '', path: '/c:/Users/Developer/project/../outside/main.tf',
  }), undefined);
  assert.equal(workspaceRelativeUriPath(
    { scheme: 'file', authority: '', path: '/C:/Sensitive/Repo' },
    { scheme: 'file', authority: '', path: '/c:/sensitive/repo/infra/main.tf' },
  ), undefined, 'only the drive letter may be case-normalized');
  assert.equal(workspaceRelativeUriPath(folder, {
    scheme: 'file', authority: 'server', path: '/c:/Users/Developer/project/infra/main.tf',
  }), undefined);

  const files = new Map([['infra/main.tf', { file_path: 'infra/main.tf', total: 5 }]]);
  assert.deepEqual(
    findingManifestPriorityPaths(files, folder, [serializedDocument]),
    ['infra/main.tf'],
  );
});

test('workspace sources use mounted POSIX paths and opaque native Windows snapshot identities', () => {
  const folder = (uri) => ({ name: 'fixture', uri });
  const localWindows = {
    scheme: 'file', authority: '', path: '/C:/work/project', fsPath: 'C:\\work\\project',
  };
  const remoteWsl = {
    scheme: 'vscode-remote', authority: 'wsl+Ubuntu', path: '/home/user/project', fsPath: '/home/user/project',
  };
  const wslUnc = {
    scheme: 'file', authority: 'wsl.localhost', path: '/Ubuntu/home/user/project',
    fsPath: '\\\\wsl.localhost\\Ubuntu\\home\\user\\project',
  };
  assert.equal(classifyWorkspaceSourceUri(localWindows, 'win32'), 'native-local-drive');
  assert.equal(classifyWorkspaceSourceUri({
    scheme: 'file', authority: '', path: '/workspace/local', fsPath: '/workspace/local',
  }, 'linux'), 'local-posix');
  assert.equal(classifyWorkspaceSourceUri(remoteWsl, 'win32'), 'remote-wsl');
  assert.equal(classifyWorkspaceSourceUri(wslUnc, 'win32'), 'wsl-unc');
  assert.equal(classifyWorkspaceSourceUri({
    scheme: 'file', authority: 'server', path: '/share/project', fsPath: '\\\\server\\share\\project',
  }, 'win32'), 'unsupported');
  assert.equal(workspaceSourcePath(folder({
    scheme: 'file', authority: '', path: '/workspace/local', fsPath: '/workspace/local',
  }), 'linux'), '/workspace/local');
  assert.equal(workspaceSourcePath(folder(remoteWsl), 'win32'), '/home/user/project');
  assert.match(workspaceSourcePath(folder(localWindows), 'win32'), /^\/source-snapshots\/native-windows\/[0-9a-f]{64}$/);
  assert.throws(
    () => workspaceSourcePath(folder(wslUnc), 'win32'),
    (error) => error instanceof CodeSecurityRequestError
      && error.code === 'native_windows_unc_requires_remote_wsl'
      && error.action === 'reopen_in_remote_wsl',
  );
  assert.throws(() => workspaceSourcePath(folder({
    scheme: 'file', authority: '', path: '/C:/', fsPath: 'C:\\',
  }), 'win32'), /canonical non-root local drive folder/);
  assert.throws(() => workspaceSourcePath(folder({
    scheme: 'file', authority: 'server', path: '/share/project', fsPath: '\\\\server\\share\\project',
  }), 'win32'), /UNC and virtual filesystem roots are not supported/);
  assert.throws(() => workspaceSourcePath(folder({
    scheme: 'vscode-remote', authority: 'ssh-remote+host', path: '/srv/project', fsPath: '/srv/project',
  }), 'linux'), /not supported yet/);
});
