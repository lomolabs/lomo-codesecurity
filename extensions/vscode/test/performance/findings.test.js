const assert = require('node:assert/strict');
const Module = require('node:module');
const { performance } = require('node:perf_hooks');
const test = require('node:test');

const { FindingStore, MAX_HYDRATED_FINDINGS } = require('../../dist/findings.js');
const { WorkspaceRefreshCoordinator } = require('../../dist/sync.js');
const {
  findingManifestPriorityPaths,
  loadFindingFileManifest,
  streamFindingDiagnosticPages,
} = require('../../dist/workspace.js');
const originalLoad = Module._load;
let nativeProjection;
let capturedTree;
class PerformanceUri {
  constructor(value, path) {
    this.value = value;
    this.path = path;
    this.scheme = 'file';
    this.authority = '';
    this.fsPath = path;
  }
  toString() { return this.value; }
}
const performanceVscode = {
  workspace: {
    workspaceFolders: [],
    textDocuments: [],
    getConfiguration: () => ({ get: (_key, fallback) => fallback }),
  },
  window: {
    visibleTextEditors: [],
    registerTreeDataProvider: (_name, provider) => {
      capturedTree = provider;
      return { dispose() {} };
    },
    createStatusBarItem: () => ({ show() {}, dispose() {}, text: '', tooltip: '' }),
  },
  languages: {},
  commands: { registerCommand: () => ({ dispose() {} }) },
  Uri: {
    joinPath: (base, path) => new PerformanceUri(
      `${base.toString().replace(/\/$/, '')}/${path}`,
      `${base.path.replace(/\/$/, '')}/${path}`,
    ),
    parse: (value) => new PerformanceUri(value, new URL(value).pathname),
  },
  Diagnostic: class Diagnostic {
    constructor(range, message, severity) { this.range = range; this.message = message; this.severity = severity; }
  },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Range: class Range {
    constructor(startLine, startCharacter, endLine, endCharacter) {
      this.start = { line: startLine, character: startCharacter };
      this.end = { line: endLine, character: endCharacter };
    }
  },
  StatusBarAlignment: { Left: 1 },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  TreeItem: class TreeItem { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
  ThemeIcon: class ThemeIcon { constructor(id) { this.id = id; } },
  EventEmitter: class EventEmitter {
    constructor() { this.event = () => ({ dispose() {} }); }
    fire() {}
    dispose() {}
  },
};
try {
  Module._load = function load(request, parent, isMain) {
    return request === 'vscode' ? performanceVscode : originalLoad.call(this, request, parent, isMain);
  };
  nativeProjection = require('../../dist/native.js');
} finally {
  Module._load = originalLoad;
}
const {
  FindingPositionIntervalIndex,
  indexFindingStartLines,
  projectVisibleFindingLines,
  visibleLineWindows,
  NativeFindingController,
} = nativeProjection;

function finding(index) {
  const fileNumber = index % 250;
  return {
    id: index + 1,
    scan_id: 71,
    scan_finding_number: index + 1,
    display_id: `S71-F${String(index + 1).padStart(5, '0')}`,
    scanner: index % 2 === 0 ? 'semgrep' : 'trivy',
    rule_id: `rule-${index % 40}`,
    severity: index % 10 === 0 ? 'high' : 'medium',
    file_path: `src/area-${fileNumber % 10}/file-${fileNumber}.ts`,
    start_line: (index % 400) + 1,
    start_column: 2,
    end_line: (index % 400) + 1,
    end_column: 8,
    message: `Deterministic finding ${index + 1}`,
    fingerprint: `fingerprint-${index + 1}`,
    lifecycle_status: 'open',
    gate_exempt: false,
    gate_effect: 'blocking',
    suppressed: false,
    occurrence_count: 1,
    is_repeat: false,
    revision: 1,
  };
}

test('10,000 lightweight findings stay within the heap budget and yield below 50 ms', async (context) => {
  assert.equal(typeof global.gc, 'function', 'run performance tests with --expose-gc');
  global.gc();
  const heapBefore = process.memoryUsage().heapUsed;
  const findings = Array.from({ length: 10_000 }, (_, index) => finding(index));
  const store = new FindingStore(10_000, 128, 250);
  const sliceDurations = [];
  let sliceStarted = performance.now();
  let yields = 0;

  await store.replaceWorkspace({
    key: 'file:///fixture',
    label: 'fixture',
    rootUri: 'file:///fixture',
    projectId: 17,
    projectRevision: 3,
    scanId: 71,
    scanRevision: 5,
    scanStatus: 'completed',
    gateDecision: 'fail',
    revision: 1,
  }, findings, async () => {
    sliceDurations.push(performance.now() - sliceStarted);
    yields += 1;
    await new Promise((resolve) => setImmediate(resolve));
    sliceStarted = performance.now();
  });
  sliceDurations.push(performance.now() - sliceStarted);

  const intervalBuildStarted = performance.now();
  const intervalIndex = new FindingPositionIntervalIndex(findings, (item) => ({
    start: { line: (item.start_line || 1) - 1, character: (item.start_column || 1) - 1 },
    end: { line: (item.end_line || 1) - 1, character: (item.end_column || 1) - 1 },
  }));
  const intervalBuildDuration = performance.now() - intervalBuildStarted;

  global.gc();
  const heapDelta = Math.max(process.memoryUsage().heapUsed - heapBefore, 0);
  context.diagnostic(`10,000-finding heap delta: ${(heapDelta / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(`slowest 250-finding slice: ${Math.max(...sliceDurations).toFixed(2)} ms`);
  context.diagnostic(`10,000-finding position-index cold build: ${intervalBuildDuration.toFixed(2)} ms`);
  assert.equal(store.size, 10_000);
  assert.equal(intervalIndex.size, 10_000);
  assert.equal(store.workspace('file:///fixture').files.size, 250);
  assert.equal(yields, 39, '10,000 findings in 250-item chunks should yield 39 times');
  assert(
    Math.max(...sliceDurations) <= 50,
    `a finding-index chunk blocked for ${Math.max(...sliceDurations).toFixed(2)} ms`,
  );
  assert(
    heapDelta <= 75 * 1024 * 1024,
    `10,000-finding index consumed ${(heapDelta / 1024 / 1024).toFixed(2)} MiB`,
  );

  store.removeWorkspace('file:///fixture');
  assert.equal(store.size, 0);
});

test('10,000-file batched Problems commit and 50,000-file limited manifest stay within budgets', async (context) => {
  assert.equal(typeof global.gc, 'function', 'run performance tests with --expose-gc');
  const total = 10_000;
  const folderUri = new PerformanceUri('file:///fixture', '/fixture');
  const folder = { name: 'fixture', uri: folderUri };
  const openDocument = {
    uri: new PerformanceUri('file:///fixture/src/file-800.ts', '/fixture/src/file-800.ts'),
    version: 1,
    lineCount: 1,
    lineAt: () => ({ text: 'fixture();' }),
    isDirty: false,
  };
  performanceVscode.workspace.workspaceFolders = [folder];
  performanceVscode.workspace.textDocuments = [openDocument];
  performanceVscode.window.visibleTextEditors = [{
    document: openDocument,
    visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 10 } }],
    setDecorations() {},
  }];
  const diagnosticEntries = new Map();
  let observeSecondCommit = false;
  let secondCommitAt;
  const collection = {
    set(batch) {
      assert(batch.length <= 1_000, 'one outbound URI batch must remain bounded');
      assert(
        batch.reduce((sum, [, items]) => sum + (items?.length || 0), 0) <= 1_000,
        'one outbound Problems batch must remain host-safe',
      );
      for (const [uri, items] of batch) {
        if (items === undefined) diagnosticEntries.delete(uri.toString());
        else diagnosticEntries.set(uri.toString(), items);
      }
      if (observeSecondCommit) secondCommitAt = performance.now();
    },
    delete(uri) { diagnosticEntries.delete(uri.toString()); },
    clear() { diagnosticEntries.clear(); },
    dispose() {},
  };
  const actions = Object.fromEntries([
    'openFinding', 'setLifecycle', 'runAdvisor', 'rescanFile', 'deleteFinding', 'hydrateFile',
  ].map((name) => [name, async () => {}]));
  const controller = new NativeFindingController(
    collection,
    actions,
  );
  const manifestRequest = (revision, manifestTotal = total) => async (path) => {
    const url = new URL(path, 'http://fixture');
    const offset = Number(url.searchParams.get('cursor') || 0);
    const count = Math.min(200, manifestTotal - offset);
    const items = Array.from({ length: count }, (_, index) => {
      const ordinal = offset + index + 1;
      return {
        file_path: `src/file-${ordinal}.ts`,
        first_scan_finding_number: ordinal,
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
    });
    const next = offset + count;
    return {
      scan: {
        id: 71,
        project_id: 17,
        status: 'completed',
        gate_decision: 'fail',
        gate_reasons: [],
        error: null,
        revision,
        findings_revision: revision,
      },
      total_findings: manifestTotal,
      total_files: manifestTotal,
      items,
      truncated: next < manifestTotal,
      next_cursor: next < manifestTotal ? String(next) : null,
    };
  };
  const diagnosticRequest = (revision) => async (path) => {
    const url = new URL(path, 'http://fixture');
    const offset = Number(url.searchParams.get('cursor') || 0);
    const count = Math.min(200, total - offset);
    const items = Array.from({ length: count }, (_, index) => {
      const ordinal = offset + index + 1;
      return {
        id: ordinal,
        scan_finding_number: ordinal,
        display_id: `S71-F${String(ordinal).padStart(3, '0')}`,
        scanner: 'fixture',
        severity: 'high',
        file_path: `src/file-${ordinal}.ts`,
        start_line: 1,
        start_column: null,
        end_line: 1,
        end_column: null,
        message: `finding ${ordinal}`,
        revision,
      };
    });
    const next = offset + count;
    return {
      scan_id: 71,
      items,
      total,
      truncated: next < total,
      next_cursor: next < total ? String(next) : null,
      revision,
    };
  };
  const project = { id: 17, name: 'fixture', repo_path: '/fixture', revision: 1 };
  const memory = () => {
    const usage = process.memoryUsage();
    return usage.heapUsed + usage.arrayBuffers;
  };
  const slices = [];
  const sliceTracker = (label) => {
    let started = performance.now();
    return {
      yield: async () => {
        slices.push({ label, duration: performance.now() - started });
        await new Promise((resolve) => setImmediate(resolve));
        started = performance.now();
      },
      finish: () => slices.push({ label, duration: performance.now() - started }),
    };
  };

  global.gc();
  const before = memory();
  const initialStarted = performance.now();
  let tracker = sliceTracker('manifest-r1');
  let manifest = await loadFindingFileManifest(manifestRequest(1), 71, undefined, tracker.yield);
  tracker.finish();
  await controller.replaceWorkspaceManifest(
    folder, project, manifest.scan, manifest.files, total, 1, 'loading',
  );
  await controller.projectWorkspaceDiagnostics(folder, 1, async (accept) => {
    tracker = sliceTracker('diagnostics-r1');
    await streamFindingDiagnosticPages(diagnosticRequest(1), 71, 1, accept, {
      maximumFindings: total,
      yieldControl: tracker.yield,
    });
    tracker.finish();
  });
  const initialDuration = performance.now() - initialStarted;

  let hydrated = Array.from({ length: MAX_HYDRATED_FINDINGS }, (_, index) => ({
    ...finding(index),
    scan_id: 71,
    file_path: `src/file-${index + 1}.ts`,
  }));
  let current = controller.store.workspace(folderUri.toString());
  await controller.store.replaceWorkspace({
    key: current.key,
    label: current.label,
    rootUri: current.rootUri,
    projectId: current.projectId,
    projectRevision: current.projectRevision,
    scanId: current.scanId,
    scanRevision: current.scanRevision,
    scanStatus: current.scanStatus,
    gateDecision: current.gateDecision,
    revision: current.revision,
    totalFindings: current.totalFindings,
    totalFiles: current.totalFiles,
    fileManifest: current.fileManifest,
    diagnosticProjection: current.diagnosticProjection,
    diagnosticProcessed: current.diagnosticProcessed,
  }, hydrated, async () => {});
  hydrated = null;
  manifest = null;
  global.gc();
  const steadyDelta = Math.max(memory() - before, 0);

  tracker = sliceTracker('manifest-r2');
  manifest = await loadFindingFileManifest(manifestRequest(2), 71, undefined, tracker.yield);
  tracker.finish();
  await controller.replaceWorkspaceManifest(
    folder, project, manifest.scan, manifest.files, total, 2, 'loading',
  );
  hydrated = Array.from({ length: MAX_HYDRATED_FINDINGS }, (_, index) => ({
    ...finding(index),
    scan_id: 71,
    file_path: `src/file-${index + 1}.ts`,
    revision: 2,
  }));
  current = controller.store.workspace(folderUri.toString());
  await controller.store.replaceWorkspace({
    key: current.key,
    label: current.label,
    rootUri: current.rootUri,
    projectId: current.projectId,
    projectRevision: current.projectRevision,
    scanId: current.scanId,
    scanRevision: current.scanRevision,
    scanStatus: current.scanStatus,
    gateDecision: current.gateDecision,
    revision: current.revision,
    totalFindings: current.totalFindings,
    totalFiles: current.totalFiles,
    fileManifest: current.fileManifest,
    diagnosticProjection: current.diagnosticProjection,
    diagnosticProcessed: current.diagnosticProcessed,
  }, hydrated, async () => {});
  hydrated = null;

  let releaseSecond;
  let markSecondBuilt;
  const secondBuilt = new Promise((resolve) => { markSecondBuilt = resolve; });
  const release = new Promise((resolve) => { releaseSecond = resolve; });
  const secondProjection = controller.projectWorkspaceDiagnostics(folder, 2, async (accept) => {
    tracker = sliceTracker('diagnostics-r2');
    await streamFindingDiagnosticPages(diagnosticRequest(2), 71, 2, accept, {
      maximumFindings: total,
      yieldControl: tracker.yield,
    });
    tracker.finish();
    markSecondBuilt();
    await release;
  });
  await secondBuilt;
  assert.equal(
    [...diagnosticEntries.values()].reduce((sum, items) => sum + items.length, 0),
    total,
    'the prior 10k Problems projection remains published while the new revision is fully built',
  );

  const treeStarted = performance.now();
  const workspaceNode = capturedTree.getChildren()[0];
  const children = capturedTree.getChildren(workspaceNode);
  assert.equal(children.filter(node => node.kind === 'scan_scope').length, 1,
    'the compact manifest alone must retain one unknown-scope history action');
  const pageNodes = children.filter(node => node.kind === 'file_page');
  const firstPageNodes = capturedTree.getChildren(pageNodes[0]);
  const treeDuration = performance.now() - treeStarted;
  global.gc();
  const doubleBufferDelta = Math.max(memory() - before, 0);
  const slowestSlice = Math.max(...slices.map(({ duration }) => duration));

  context.diagnostic(`10k-file initial manifest+Problems: ${initialDuration.toFixed(1)} ms`);
  context.diagnostic(`10k-file steady heap+buffers delta: ${(steadyDelta / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(`10k-file second-revision double-buffer delta: ${(doubleBufferDelta / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(`slowest manifest/diagnostic page slice: ${slowestSlice.toFixed(2)} ms`);
  context.diagnostic(`Tree root+one 200-file page: ${treeDuration.toFixed(2)} ms (${pageNodes.length}+${firstPageNodes.length} nodes)`);
  assert.equal(pageNodes.length, 50);
  assert.equal(firstPageNodes.length, 200);
  assert.equal(controller.store.workspace(folderUri.toString()).findings.length, MAX_HYDRATED_FINDINGS);
  assert(initialDuration <= 5_000, `initial 10k projection took ${initialDuration.toFixed(1)} ms`);
  assert(treeDuration <= 100, `expanded Tree page took ${treeDuration.toFixed(2)} ms`);
  assert(slowestSlice <= 50, `manifest/diagnostic page slice blocked for ${slowestSlice.toFixed(2)} ms`);
  assert(
    doubleBufferDelta <= 75 * 1024 * 1024,
    `second-revision atomic double buffer consumed ${(doubleBufferDelta / 1024 / 1024).toFixed(2)} MiB`,
  );

  const commitReleaseStarted = performance.now();
  let zeroDelayTimerAt;
  const zeroDelayTimer = new Promise((resolve) => setTimeout(() => {
    zeroDelayTimerAt = performance.now();
    resolve();
  }, 0));
  observeSecondCommit = true;
  releaseSecond();
  await secondProjection;
  const secondSettledAt = performance.now();
  observeSecondCommit = false;
  await zeroDelayTimer;
  const finalCommitDuration = (secondCommitAt || secondSettledAt) - commitReleaseStarted;
  const releaseToSettlement = secondSettledAt - commitReleaseStarted;
  const eventLoopDelay = zeroDelayTimerAt - commitReleaseStarted;
  context.diagnostic(
    `10k-file final atomic commit/set/0ms-delay: ${releaseToSettlement.toFixed(2)}`
    + `/${finalCommitDuration.toFixed(2)}/${eventLoopDelay.toFixed(2)} ms`,
  );
  assert(finalCommitDuration <= 50, `final DiagnosticCollection commit took ${finalCommitDuration.toFixed(2)} ms`);
  assert(releaseToSettlement <= 50, `release-to-projection settlement took ${releaseToSettlement.toFixed(2)} ms`);
  assert(eventLoopDelay <= 50, `final projection delayed the event loop ${eventLoopDelay.toFixed(2)} ms`);
  global.gc();
  const secondSteadyDelta = Math.max(memory() - before, 0);
  context.diagnostic(`10k-file second-revision committed delta: ${(secondSteadyDelta / 1024 / 1024).toFixed(2)} MiB`);
  assert(secondSteadyDelta <= 75 * 1024 * 1024);
  assert.equal([...diagnosticEntries.values()].reduce((sum, items) => sum + items.length, 0), total);

  // The exact manifest is allowed to reach 50k distinct files, but Problems is
  // deliberately limited above the aggregate retained projection budget.
  // Exercise the transition with prior Problems and bounded rich rows live.
  manifest = null;
  tracker = sliceTracker('manifest-r3-50k');
  let largeManifest = await loadFindingFileManifest(
    manifestRequest(3, 50_000), 71, undefined, tracker.yield,
  );
  tracker.finish();
  global.gc();
  const largeTransitionPeak = Math.max(memory() - before, 0);
  const limitedCommitStarted = performance.now();
  let limitedTimerAt;
  const limitedTimer = new Promise((resolve) => setTimeout(() => {
    limitedTimerAt = performance.now();
    resolve();
  }, 0));
  assert.equal(await controller.replaceWorkspaceManifest(
    folder, project, largeManifest.scan, largeManifest.files, 50_000, 3, 'limited',
  ), true);
  assert.equal(controller.limitWorkspaceDiagnostics(folder, 3), true);
  const limitedSettledAt = performance.now();
  await limitedTimer;
  const limitedCommitDuration = limitedSettledAt - limitedCommitStarted;
  const limitedEventLoopDelay = limitedTimerAt - limitedCommitStarted;
  current = controller.store.workspace(folderUri.toString());
  assert.equal(current.totalFiles, 50_000);
  assert.equal(current.totalFindings, 50_000);
  assert.equal(current.diagnosticProjection, 'limited');
  assert.equal(diagnosticEntries.size, 0, 'limited projection removes the prior Problems revision');

  hydrated = Array.from({ length: MAX_HYDRATED_FINDINGS }, (_, index) => ({
    ...finding(index),
    scan_id: 71,
    file_path: `src/file-${index + 1}.ts`,
    revision: 3,
  }));
  await controller.store.replaceWorkspace({
    key: current.key,
    label: current.label,
    rootUri: current.rootUri,
    projectId: current.projectId,
    projectRevision: current.projectRevision,
    scanId: current.scanId,
    scanRevision: current.scanRevision,
    scanStatus: current.scanStatus,
    gateDecision: current.gateDecision,
    revision: current.revision,
    totalFindings: current.totalFindings,
    totalFiles: current.totalFiles,
    fileManifest: current.fileManifest,
    diagnosticProjection: current.diagnosticProjection,
    diagnosticProcessed: current.diagnosticProcessed,
  }, hydrated, async () => {});
  hydrated = null;
  largeManifest = null;
  global.gc();
  const largeSteadyDelta = Math.max(memory() - before, 0);

  tracker = sliceTracker('manifest-r4-50k');
  largeManifest = await loadFindingFileManifest(
    manifestRequest(4, 50_000), 71, undefined, tracker.yield,
  );
  tracker.finish();
  global.gc();
  const largeDoubleManifestDelta = Math.max(memory() - before, 0);
  assert.equal(await controller.replaceWorkspaceManifest(
    folder, project, largeManifest.scan, largeManifest.files, 50_000, 4, 'limited',
  ), true);
  controller.limitWorkspaceDiagnostics(folder, 4);
  largeManifest = null;
  global.gc();
  const largeCommittedDelta = Math.max(memory() - before, 0);
  const largeWorkspaceNode = capturedTree.getChildren()[0];
  const largeChildren = capturedTree.getChildren(largeWorkspaceNode);
  assert.equal(largeChildren.filter(node => node.kind === 'scan_scope').length, 1);
  const largePages = largeChildren.filter(node => node.kind === 'file_page');
  const largeFirstPage = capturedTree.getChildren(largePages[0]);

  context.diagnostic(`50k manifest + prior 10k Problems/rich peak: ${(largeTransitionPeak / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(`50k manifest + 5k rich steady: ${(largeSteadyDelta / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(`second 50k manifest double-buffer peak: ${(largeDoubleManifestDelta / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(`second 50k manifest committed delta: ${(largeCommittedDelta / 1024 / 1024).toFixed(2)} MiB`);
  context.diagnostic(
    `50k limited transition settle/0ms-delay: ${limitedCommitDuration.toFixed(2)}`
    + `/${limitedEventLoopDelay.toFixed(2)} ms`,
  );
  assert.equal(largePages.length, 250);
  assert.equal(largeFirstPage.length, 200);
  assert(limitedCommitDuration <= 50, `limited transition took ${limitedCommitDuration.toFixed(2)} ms`);
  assert(limitedEventLoopDelay <= 50, `limited transition delayed the event loop ${limitedEventLoopDelay.toFixed(2)} ms`);
  assert(largeTransitionPeak <= 75 * 1024 * 1024);
  assert(largeSteadyDelta <= 75 * 1024 * 1024);
  assert(largeDoubleManifestDelta <= 75 * 1024 * 1024);
  assert(largeCommittedDelta <= 75 * 1024 * 1024);
  controller.dispose();
  performanceVscode.workspace.workspaceFolders = [];
  performanceVscode.workspace.textDocuments = [];
  performanceVscode.window.visibleTextEditors = [];
});

test('50,000-file priority lookup with one open editor does not iterate or materialize manifest URIs', (context) => {
  const total = 50_000;
  const files = new Map(Array.from({ length: total }, (_, index) => {
    const ordinal = index + 1;
    const filePath = `src/file-${ordinal}.ts`;
    return [filePath, {
      file_path: filePath,
      first_scan_finding_number: ordinal,
      total: 1,
      active: 1,
      suppressed: 0,
      gate_exempt: 0,
      blocking: 1,
    }];
  }));
  let iterations = 0;
  const guardedFiles = {
    get size() { return files.size; },
    get: (key) => files.get(key),
    has: (key) => files.has(key),
    entries() { iterations += 1; return files.entries(); },
    keys() { iterations += 1; return files.keys(); },
    values() { iterations += 1; return files.values(); },
    [Symbol.iterator]() { iterations += 1; return files[Symbol.iterator](); },
  };
  const started = performance.now();
  const selected = findingManifestPriorityPaths(
    guardedFiles,
    { scheme: 'file', authority: '', path: '/fixture' },
    [{ scheme: 'file', authority: '', path: '/fixture/src/file-40000.ts' }],
  );
  const duration = performance.now() - started;

  context.diagnostic(`50k manifest + one open editor priority lookup: ${duration.toFixed(3)} ms`);
  assert.deepEqual(selected, ['src/file-40000.ts']);
  assert.equal(iterations, 0, 'priority lookup must not scan the 50k manifest');
  assert(duration <= 50, `one-editor priority lookup took ${duration.toFixed(2)} ms`);
});

test('10,000 refresh requests coalesce to one transport operation within the scheduling budget', async (context) => {
  const coordinator = new WorkspaceRefreshCoordinator();
  let starts = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const started = performance.now();
  const refreshes = Array.from({ length: 10_000 }, () => coordinator.run(
    'file:///fixture',
    { key: 'manual', proof: 'workspace', supersedes: false },
    async () => {
      starts += 1;
      await gate;
      return 19;
    },
  ));
  const enqueueDuration = performance.now() - started;
  release();
  const values = await Promise.all(refreshes);
  const totalDuration = performance.now() - started;

  context.diagnostic(`10,000 coalesced refreshes enqueue/settle: ${enqueueDuration.toFixed(2)}/${totalDuration.toFixed(2)} ms`);
  assert.equal(starts, 1);
  assert(values.every((value) => value === 19));
  assert.equal(coordinator.activeCount, 0);
  assert(enqueueDuration <= 100, `refresh coalescing enqueue took ${enqueueDuration.toFixed(2)} ms`);
  assert(totalDuration <= 250, `refresh coalescing settlement took ${totalDuration.toFixed(2)} ms`);
});

test('10,000 dense same-line position lookups stay within hover/action latency and operation budgets', (context) => {
  const findings = Array.from({ length: 10_000 }, (_, index) => ({
    ...finding(index),
    file_path: 'src/dense.ts',
    start_line: 1,
    end_line: 1,
    start_column: (9_999 - index) * 2 + 1,
    end_column: (9_999 - index) * 2 + 2,
  }));
  let rangeBuilds = 0;
  const index = new FindingPositionIntervalIndex(findings, (item) => {
    rangeBuilds += 1;
    return {
      start: { line: 0, character: item.start_column - 1 },
      end: { line: 0, character: item.end_column - 1 },
    };
  });
  assert.equal(rangeBuilds, 10_000, 'document ranges are projected once when the cache is built');

  const durations = [];
  let exactTests = 0;
  for (let sample = 0; sample < 1_000; sample += 1) {
    const spatialIndex = sample * 9 % 10_000;
    const position = { line: 0, character: spatialIndex * 2 };
    const started = performance.now();
    const hit = index.first(position, position, (item) => {
      exactTests += 1;
      return item;
    });
    durations.push(performance.now() - started);
    assert.equal(hit.start_column - 1, position.character);
  }
  durations.sort((left, right) => left - right);
  const p95 = durations[Math.ceil(durations.length * 0.95) - 1];
  const p99 = durations[Math.ceil(durations.length * 0.99) - 1];
  context.diagnostic(`1,000 dense position lookups p95/p99: ${p95.toFixed(3)}/${p99.toFixed(3)} ms`);
  assert.equal(exactTests, 1_000, 'each disjoint warm query performs one exact candidate test');
  assert(p95 <= 2, `dense position lookup p95 ${p95.toFixed(3)} ms exceeds 2 ms`);
  assert(p99 <= 5, `dense position lookup p99 ${p99.toFixed(3)} ms exceeds 5 ms`);
});

test('detail cache uses deterministic bounded LRU eviction', () => {
  const store = new FindingStore(10, 2, 2);
  for (let index = 1; index <= 3; index += 1) {
    store.putDetail({ ...finding(index), scan_id: 4, scan_finding_number: index });
  }
  assert.equal(store.detailSize, 2);
  assert.equal(store.detail(4, 1), undefined);
  assert.equal(store.detail(4, 2).scan_finding_number, 2);
  store.putDetail({ ...finding(4), scan_id: 4, scan_finding_number: 4 });
  assert.equal(store.detail(4, 3), undefined, 'reading item 2 should make item 3 the LRU entry');
});

test('cached 10,000-finding viewport projection stays within the 8 ms p95 frame budget', (context) => {
  const findings = Array.from({ length: 10_000 }, (_, index) => ({
    ...finding(index),
    file_path: 'src/large.ts',
    start_line: index + 1,
    end_line: index + 1,
  }));
  const indexed = indexFindingStartLines(findings);
  const windows = visibleLineWindows([{
    start: { line: 5_000, character: 0 },
    end: { line: 5_199, character: 0 },
  }], 10_000);
  const durations = [];
  let finalProjection;
  for (let sample = 0; sample < 100; sample += 1) {
    const started = performance.now();
    finalProjection = projectVisibleFindingLines([{
      workspaceKey: 'file:///fixture',
      workspaceRevision: 1,
      findings: indexed,
    }], windows, 9_999);
    durations.push(performance.now() - started);
  }
  durations.sort((left, right) => left - right);
  const p95 = durations[Math.ceil(durations.length * 0.95) - 1];
  context.diagnostic(`100-sample cached visible projection p95: ${p95.toFixed(2)} ms`);
  assert.equal(finalProjection.length, 240);
  assert.deepEqual([finalProjection[0].line, finalProjection.at(-1).line], [4_980, 5_219]);
  assert(p95 <= 8, `cached visible projection p95 ${p95.toFixed(2)} ms exceeds 8 ms`);
});
