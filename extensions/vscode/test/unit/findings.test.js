const assert = require('node:assert/strict');
const test = require('node:test');

const {
  FindingStore,
  compareFindingPresentation,
  compareFindingSeverity,
  findingGateEffectLabel,
  findingInlineAnnotation,
  findingLifecycleLabel,
  findingRange,
  findingRangeForDocument,
  rangeContains,
} = require('../../dist/findings.js');

test('finding lifecycle and gate labels stay human-readable across native surfaces', () => {
  assert.deepEqual(
    ['open', 'needs_review', 'gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed']
      .map((value) => findingLifecycleLabel(value)),
    ['Open and blocking', 'Needs review', 'Non-blocking for gate', 'Accepted risk', 'Ignored and not counted', 'False positive', 'Fixed'],
  );
  assert.deepEqual(
    ['blocking', 'non_blocking', 'excluded'].map((value) => findingGateEffectLabel(value)),
    ['Blocking', 'Non-blocking for gate', 'Not counted'],
  );
});

function finding(index, overrides = {}) {
  return {
    id: index,
    scan_id: 41,
    scan_finding_number: index,
    display_id: `S41-F${String(index).padStart(3, '0')}`,
    scanner: 'fixture',
    rule_id: `fixture.${index}`,
    severity: 'high',
    file_path: `src/file-${index % 25}.ts`,
    start_line: index + 1,
    start_column: 3,
    end_line: index + 1,
    end_column: 8,
    message: `finding ${index}`,
    fingerprint: `fingerprint-${index}`,
    lifecycle_status: 'open',
    gate_exempt: false,
    gate_effect: 'blocking',
    suppressed: false,
    occurrence_count: 1,
    is_repeat: false,
    revision: 1,
    ...overrides,
  };
}

test('shared finding presentation aggregates four Checkov and Trivy entries exactly', () => {
  const members = [
    finding(4, { scanner: 'trivy', start_line: 2 }),
    finding(3, { scanner: 'checkov', start_line: 2 }),
    finding(2, { scanner: 'trivy', start_line: 2 }),
    finding(1, { scanner: 'checkov', start_line: 2 }),
  ];
  const ordered = [...members].sort(compareFindingPresentation);
  assert.deepEqual(ordered.map(({ id }) => id), [1, 3, 2, 4]);
  assert.deepEqual(members.map(({ id }) => id), [4, 3, 2, 1]);
  assert.equal(findingInlineAnnotation(ordered[0], ordered.length - 1), '  [HIGH · checkov +3 reports]');
  assert.equal(findingInlineAnnotation(ordered[0], 0), '  [HIGH · checkov]');
  assert.equal(findingInlineAnnotation(ordered[0], 1), '  [HIGH · checkov +1 report]');
  assert.equal(findingInlineAnnotation(ordered[0], 3, 'detailed'), '  [S41-F001 · HIGH · checkov +3 reports]');
});

test('shared finding presentation preserves severity and deterministic identity tie breaks', () => {
  assert.deepEqual(
    ['info', 'medium', 'high', 'low', 'critical'].sort(compareFindingSeverity),
    ['critical', 'high', 'medium', 'low', 'info'],
  );
  const primary = finding(1, { scanner: 'zeta', severity: 'critical' });
  assert(compareFindingPresentation(primary, finding(2, { scanner: 'alpha', severity: 'high' })) < 0);
  const left = finding(1);
  for (const changed of [
    { scanner: 'zeta' }, { display_id: 'S41-F002' }, { scan_id: 42 },
    { scan_finding_number: 2 }, { id: 2 },
  ]) assert(compareFindingPresentation(left, { ...left, ...changed }) < 0);
  assert.equal(compareFindingPresentation(left, { ...left }), 0);
});

test('shared finding presentation keeps single-line sanitization and Unicode bounds unchanged', () => {
  const dirty = finding(1, { scanner: '  checkov\r\n\u0000\u202etrivy  ' });
  assert.equal(findingInlineAnnotation(dirty, 0), '  [HIGH · checkov trivy]');
  const long = finding(2, { scanner: '🛡'.repeat(81), severity: 'info' });
  assert.equal(findingInlineAnnotation(long, 1), `  [INFO · ${'🛡'.repeat(79)}… +1 report]`);
  assert.equal(findingInlineAnnotation(long, 0, 'detailed'), `  [S41-F002 · INFO · ${'🛡'.repeat(79)}…]`);
});

function input(key = 'file:///workspace', overrides = {}) {
  return {
    key,
    label: 'workspace',
    rootUri: key,
    projectId: 7,
    scanId: 41,
    scanStatus: 'completed',
    gateDecision: 'fail',
    revision: 3,
    ...overrides,
  };
}

function aggregate(filePath, first) {
  return {
    file_path: filePath,
    first_scan_finding_number: first,
    total: 1,
    active: 1,
    suppressed: 0,
    gate_exempt: 0,
    blocking: 1,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    lifecycle_counts: {
      open: 1, needs_review: 0, gate_exempt: 0, accepted_risk: 0,
      ignore: 0, false_positive: 0, fixed: 0,
    },
  };
}

test('normalized SARIF columns convert to exact bounded VS Code positions', () => {
  assert.deepEqual(findingRange(finding(1, {
    start_line: 9, start_column: 5, end_line: 9, end_column: 11,
  })), { startLine: 8, startCharacter: 4, endLine: 8, endCharacter: 10 });

  assert.deepEqual(findingRange(finding(2, {
    start_line: 9, start_column: 5, end_line: 9, end_column: null,
  })), { startLine: 8, startCharacter: 4, endLine: 8, endCharacter: 5 });

  assert.deepEqual(findingRange(finding(3, {
    start_line: 9, start_column: null, end_line: 10, end_column: null,
  })), { startLine: 8, startCharacter: 0, endLine: 9, endCharacter: 0 });

  assert.deepEqual(findingRange(finding(30, {
    start_line: 9, start_column: 5, end_line: 10, end_column: null,
  })), { startLine: 8, startCharacter: 4, endLine: 9, endCharacter: 0 });

  const insertionPoint = finding(31, {
    start_line: 9, start_column: 5, end_line: 9, end_column: 5,
  });
  assert.deepEqual(
    findingRangeForDocument(insertionPoint, 10, () => 20),
    { startLine: 8, startCharacter: 4, endLine: 8, endCharacter: 4 },
  );
  assert.equal(rangeContains(findingRange(insertionPoint), 8, 4), true);

  const malformed = findingRange(finding(4, {
    start_line: 3, start_column: 8, end_line: 3, end_column: 2,
  }));
  assert.deepEqual(malformed, { startLine: 2, startCharacter: 7, endLine: 2, endCharacter: 8 });
  assert.equal(Object.values(malformed).includes(Number.MAX_SAFE_INTEGER), false);
  assert.equal(rangeContains(malformed, 2, 7), true);
  assert.equal(rangeContains(malformed, 2, 8), false);
});

test('document-aware ranges expand line-only evidence and clamp final and empty lines', () => {
  const lineOnly = finding(1, {
    start_line: 2, start_column: null, end_line: 2, end_column: null,
  });
  assert.deepEqual(
    findingRangeForDocument(lineOnly, 2, (line) => [8, 5][line]),
    { startLine: 1, startCharacter: 0, endLine: 1, endCharacter: 5 },
  );

  const beyondFinalLine = finding(2, {
    start_line: 900, start_column: 500, end_line: 901, end_column: null,
  });
  assert.deepEqual(
    findingRangeForDocument(beyondFinalLine, 2, (line) => [8, 5][line]),
    { startLine: 1, startCharacter: 4, endLine: 1, endCharacter: 5 },
  );

  const emptyDocument = finding(3, {
    start_line: 1, start_column: null, end_line: 1, end_column: null,
  });
  assert.deepEqual(
    findingRangeForDocument(emptyDocument, 1, () => 0),
    { startLine: 0, startCharacter: 0, endLine: 0, endCharacter: 0 },
  );
});

test('10,000 findings index in bounded chunks with deterministic file grouping', async () => {
  const store = new FindingStore(10_000, 4, 250);
  const findings = Array.from({ length: 10_000 }, (_, index) => finding(index + 1));
  let yields = 0;
  const workspace = await store.replaceWorkspace(input(), findings, async () => { yields += 1; });

  assert.equal(store.size, 10_000);
  assert.equal(yields, 39);
  assert.equal(workspace.files.size, 25);
  assert.equal(workspace.files.get('src/file-1.ts').length, 400);
  assert.deepEqual(store.workspaceEntries().map((entry) => entry.key), ['file:///workspace']);
  await assert.rejects(
    store.replaceWorkspace(input('file:///second'), [finding(10_001)], async () => {}),
    /10000-item safety bound/,
  );
});

test('exact file hydration uses a true bounded LRU without retaining global scan summaries', async () => {
  const store = new FindingStore(2, 4, 2);
  const manifest = new Map([
    ['src/a.ts', aggregate('src/a.ts', 1)],
    ['src/b.ts', aggregate('src/b.ts', 2)],
    ['src/c.ts', aggregate('src/c.ts', 3)],
  ]);
  await store.replaceWorkspace(input('file:///workspace', {
    totalFindings: 3,
    totalFiles: 3,
    fileManifest: manifest,
    diagnosticProjection: 'complete',
  }), [], async () => {});

  assert.equal(store.replaceFileFindings('file:///workspace', 'src/a.ts', [finding(1, {
    file_path: 'src/a.ts', scan_finding_number: 1,
  })], 3), true);
  assert.equal(store.replaceFileFindings('file:///workspace', 'src/b.ts', [finding(2, {
    file_path: 'src/b.ts', scan_finding_number: 2,
  })], 3), true);
  assert.equal(store.touchFile('file:///workspace', 'src/a.ts'), true);
  assert.equal(store.replaceFileFindings('file:///workspace', 'src/c.ts', [finding(3, {
    file_path: 'src/c.ts', scan_finding_number: 3,
  })], 3), true);

  const workspace = store.workspace('file:///workspace');
  assert.equal(store.size, 2);
  assert.deepEqual([...workspace.files.keys()], ['src/a.ts', 'src/c.ts']);
  assert.deepEqual(workspace.findings.map(({ file_path }) => file_path), ['src/a.ts', 'src/c.ts']);
  assert.equal(workspace.totalFindings, 3);
});

test('exact file hydration must match the manifest first ordinal and retained gate aggregates', async () => {
  const store = new FindingStore(20, 4, 2);
  const path = 'src/fenced.ts';
  const fileAggregate = {
    ...aggregate(path, 1),
    total: 2,
    active: 2,
    blocking: 2,
    severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 },
    lifecycle_counts: {
      open: 2, needs_review: 0, gate_exempt: 0, accepted_risk: 0,
      ignore: 0, false_positive: 0, fixed: 0,
    },
  };
  await store.replaceWorkspace(input('file:///workspace', {
    revision: 1,
    totalFindings: 2,
    totalFiles: 1,
    fileManifest: new Map([[path, fileAggregate]]),
    diagnosticProjection: 'complete',
  }), [], async () => {});

  assert.equal(store.replaceFileFindings('file:///workspace', path, [
    finding(2, { file_path: path }),
    finding(3, { file_path: path }),
  ], 1), false);
  assert.equal(store.replaceFileFindings('file:///workspace', path, [
    finding(1, { file_path: path }),
    finding(2, {
      file_path: path,
      lifecycle_status: 'fixed',
      suppressed: true,
      gate_effect: 'excluded',
    }),
  ], 1), false);

  const workspace = store.workspace('file:///workspace');
  assert.equal(workspace.files.size, 0);
  assert.equal(workspace.findings.length, 0);
});

test('removing one root invalidates its delayed 10,000-finding build while another root remains', async () => {
  const store = new FindingStore(20_000, 4, 250);
  await store.replaceWorkspace(
    input('file:///workspace-b', { label: 'workspace-b', projectId: 8, scanId: 42 }),
    [finding(20_001, { scan_id: 42, scan_finding_number: 1, display_id: 'S42-F001' })],
    async () => {},
  );
  const findings = Array.from({ length: 10_000 }, (_, index) => finding(index + 1));
  let releaseFirstYield;
  let startedFirstYield;
  const firstYield = new Promise((resolve) => { startedFirstYield = resolve; });
  const release = new Promise((resolve) => { releaseFirstYield = resolve; });
  let yields = 0;
  const pending = store.replaceWorkspace(input('file:///workspace-a'), findings, async () => {
    yields += 1;
    if (yields === 1) {
      startedFirstYield();
      await release;
    }
  });

  await firstYield;
  store.removeWorkspace('file:///workspace-a');
  releaseFirstYield();
  assert.equal(await pending, undefined);

  assert.equal(yields, 39);
  assert.equal(store.workspace('file:///workspace-a'), undefined);
  assert.equal(store.workspace('file:///workspace-b').findings.length, 1);
  assert.deepEqual(store.workspaceEntries().map(({ key }) => key), ['file:///workspace-b']);
  assert.equal(store.size, 1);
});

test('detail cache is deterministic LRU and workspace teardown releases all indexed state', async () => {
  const store = new FindingStore(20, 2, 2);
  await store.replaceWorkspace(input(), [finding(1), finding(2), finding(3)], async () => {});
  store.putDetail({ ...finding(1), ai_reasoning: 'one' });
  store.putDetail({ ...finding(2), ai_reasoning: 'two' });
  assert.equal(store.detail(41, 1).ai_reasoning, 'one');
  store.putDetail({ ...finding(3), ai_reasoning: 'three' });
  assert.equal(store.detail(41, 2), undefined);
  assert.equal(store.detailSize, 2);

  assert.equal(store.markFileStale('file:///workspace', 'src/file-1.ts'), true);
  assert.deepEqual([...store.workspace('file:///workspace').staleFiles], ['src/file-1.ts']);
  assert.equal(store.replaceFinding('file:///workspace', {
    ...finding(1, { revision: 2, lifecycle_status: 'needs_review' }),
    code_snippet: 'detail-only evidence',
    ai_reasoning: 'large Advisor detail',
  }), true);
  assert.equal(store.workspace('file:///workspace').findings[0].revision, 2);
  assert.equal(Object.hasOwn(store.workspace('file:///workspace').findings[0], 'code_snippet'), false);
  assert.equal(Object.hasOwn(store.workspace('file:///workspace').findings[0], 'ai_reasoning'), false);

  store.removeWorkspace('file:///workspace');
  assert.equal(store.size, 0);
  assert.equal(store.detailSize, 0);
  assert.deepEqual(store.workspaceEntries(), []);
});

test('marking one indexed file stale is an idempotent transition across 1,000 changes', async () => {
  const store = new FindingStore(20, 2, 2);
  await store.replaceWorkspace(input(), [finding(1)], async () => {});

  let transitions = 0;
  for (let change = 0; change < 1_000; change += 1) {
    if (store.markFileStale('file:///workspace', 'src/file-1.ts')) transitions += 1;
  }

  const staleWorkspace = store.workspace('file:///workspace');
  assert.equal(transitions, 1);
  assert.deepEqual([...staleWorkspace.staleFiles], ['src/file-1.ts']);
  assert.equal(store.markFileStale('file:///workspace', 'src/file-1.ts'), false);
  assert.equal(store.workspace('file:///workspace'), staleWorkspace);
});

test('same-scan manifest revisions preserve stale paths while a genuinely different scan clears them', async () => {
  const store = new FindingStore(20, 2, 2);
  const manifest = new Map([['src/stale.ts', aggregate('src/stale.ts', 1)]]);
  await store.replaceWorkspace(input('file:///workspace', {
    revision: 3, totalFindings: 1, totalFiles: 1, fileManifest: manifest,
  }), [], async () => {});
  assert.equal(store.markFileStale('file:///workspace', 'src/stale.ts'), true);

  await store.replaceWorkspace(input('file:///workspace', {
    revision: 4, totalFindings: 1, totalFiles: 1, fileManifest: manifest,
  }), [], async () => {});
  assert.deepEqual([...store.workspace('file:///workspace').staleFiles], ['src/stale.ts']);

  await store.replaceWorkspace(input('file:///workspace', {
    scanId: 42, revision: 1, totalFindings: 1, totalFiles: 1, fileManifest: manifest,
  }), [], async () => {});
  assert.deepEqual([...store.workspace('file:///workspace').staleFiles], []);
});

test('replacing a workspace scan purges detail records for both old and newly loaded scans', async () => {
  const store = new FindingStore(20, 8, 2);
  await store.replaceWorkspace(input(), [finding(1)], async () => {});
  store.putDetail({ ...finding(1), ai_reasoning: 'old scan detail' });
  store.putDetail({
    ...finding(2, {
      scan_id: 42,
      scan_finding_number: 1,
      display_id: 'S42-F001',
    }),
    ai_reasoning: 'pre-refresh new scan detail',
  });

  await store.replaceWorkspace(
    input('file:///workspace', { scanId: 42, revision: 1 }),
    [finding(2, { scan_id: 42, scan_finding_number: 1, display_id: 'S42-F001' })],
    async () => {},
  );

  assert.equal(store.detail(41, 1), undefined);
  assert.equal(store.detail(42, 1), undefined);
  assert.equal(store.detailSize, 0);
});
