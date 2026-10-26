const assert = require('node:assert/strict');
const Module = require('node:module');
const test = require('node:test');
const {
  loadFindingFileManifest, streamFindingDiagnosticPages, MAX_DIAGNOSTIC_RETAINED_BYTES,
  findingScanScope,
  withFindingScanScope,
} = require('../../dist/workspace.js');

const uri = (value) => {
  const parsed = new URL(value);
  return {
    scheme: parsed.protocol.slice(0, -1), authority: parsed.host, path: parsed.pathname,
    fsPath: parsed.pathname, toString: () => value,
  };
};
const mock = {
  EventEmitter: class {
    event() { return { dispose() {} }; }
    fire() {}
    dispose() {}
  },
  StatusBarAlignment: { Left: 1 },
  TreeItem: class { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
  ThemeIcon: class { constructor(id) { this.id = id; } },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1 },
  CancellationError: class extends Error {},
  workspace: { workspaceFolders: [], textDocuments: [], getConfiguration: () => ({ get: (_key, value) => value }) },
  window: { visibleTextEditors: [] },
  languages: {},
  commands: { registerCommand: () => ({ dispose() {} }) },
  Uri: { parse: uri, joinPath: (root, path) => uri(`${root.toString()}/${path}`) },
  Diagnostic: class { constructor(range, message, severity) { Object.assign(this, { range, message, severity }); } },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Range: class {
    constructor(line, character, endLine, endCharacter) {
      this.start = { line, character }; this.end = { line: endLine, character: endCharacter };
    }
  },
  Selection: class { constructor(start, end) { Object.assign(this, { start, end }); } },
  TextEditorRevealType: { InCenterIfOutsideViewport: 2 },
};
const originalLoad = Module._load;
let NativeFindingController;
try {
  Module._load = function (request, parent, isMain) {
    return request === 'vscode' ? mock : originalLoad.call(this, request, parent, isMain);
  };
  ({ NativeFindingController } = require('../../dist/native.js'));
} finally { Module._load = originalLoad; }

function fixture(paths = ['/fixture', '/sibling']) {
  const folders = paths.map((path) => ({ name: path, uri: uri(`file://${path}`) }));
  mock.workspace.workspaceFolders = folders;
  mock.workspace.textDocuments = [];
  const entries = new Map();
  const batches = [];
  let controller;
  const collection = {
    set(batch) {
      assert(batch.length <= 1000);
      assert(batch.reduce((sum, [, items]) => sum + (items?.length || 0), 0) <= 1000);
      for (const [target, items] of batch) {
        assert((items?.length || 0) <= 1000);
        if (items === undefined) entries.delete(target.toString());
        else entries.set(target.toString(), items);
      }
      batches.push(batch.map(([target, items]) => [target.toString(), items?.length || 0]));
    },
    clear() { entries.clear(); }, delete(target) { entries.delete(target.toString()); }, dispose() {},
  };
  controller = new NativeFindingController(collection, { hydrateFile: async () => {} });
  return { controller, folders, entries, batches };
}

function row(ordinal, path = `src/file-${ordinal}.ts`, message = `finding ${ordinal}`) {
  return {
    id: ordinal, scan_finding_number: ordinal, display_id: `S71-F${String(ordinal).padStart(3, '0')}`,
    scanner: 'fixture', severity: 'high', file_path: path,
    start_line: 1, start_column: 1, end_line: 1, end_column: 2, message, revision: 1,
  };
}
function source(rows, revision = 1, scope = { kind: 'workspace', target_path: null }) {
  const aggregates = new Map();
  for (const item of rows) {
    const existing = aggregates.get(item.file_path);
    if (existing) {
      existing.total++; existing.active++; existing.blocking++;
      existing.severity_counts.high++; existing.lifecycle_counts.open++;
    } else aggregates.set(item.file_path, {
      file_path: item.file_path, first_scan_finding_number: item.scan_finding_number,
      total: 1, active: 1, suppressed: 0, gate_exempt: 0, blocking: 1,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      lifecycle_counts: { open: 1, needs_review: 0, gate_exempt: 0, accepted_risk: 0, ignore: 0, false_positive: 0, fixed: 0 },
    });
  }
  const files = [...aggregates.values()];
  const request = async (path) => {
    const url = new URL(path, 'http://fixture');
    const isManifest = url.pathname.endsWith('/finding-files');
    const all = isManifest ? files : rows.map((item) => ({ ...item, revision }));
    const offset = Number(url.searchParams.get('cursor') || 0);
    const next = Math.min(offset + 200, all.length);
    return {
      ...(isManifest ? {
        scan: { id: 71, project_id: 17, status: 'completed', gate_decision: 'fail', gate_reasons: [], error: null, revision, findings_revision: revision },
        total_findings: rows.length, total_files: files.length,
      } : { scan_id: 71, revision, total: rows.length }),
      items: all.slice(offset, next), truncated: next < all.length,
      next_cursor: next < all.length ? String(next) : null,
    };
  };
  return { request, rows, revision, scope };
}
async function manifest(controller, folder, input) {
  const value = await loadFindingFileManifest(input.request, 71);
  assert.equal(await controller.replaceWorkspaceManifest(folder, {
    id: 17, name: folder.name, repo_path: folder.uri.path, revision: 1,
  }, withFindingScanScope(value.scan, { ...value.scan, scanner_summary: { scope: input.scope } }),
  value.files, value.totalFindings, input.revision), true);
}
async function project(controller, folder, input, onPage = async () => {}) {
  return controller.projectWorkspaceDiagnostics(folder, input.revision, (accept) => streamFindingDiagnosticPages(
    input.request, 71, input.revision, async (items) => { await accept(items); await onPage(items); },
  ));
}
const count = (entries) => [...entries.values()].reduce((sum, items) => sum + items.length, 0);

test('live clearing refreshes findings, but disposal clears ownership without asking a closing host to refresh', async () => {
  const originalEmitter = mock.EventEmitter;
  const originalRegistration = mock.window.registerTreeDataProvider;
  let closing = false, refreshes = 0, registrationsDisposed = 0, controller;
  mock.EventEmitter = class {
    event() { return { dispose() {} }; }
    fire() {
      assert.equal(closing, false, 'the closing host cannot refresh a tree');
      refreshes++;
    }
    dispose() {}
  };
  mock.window.registerTreeDataProvider = () => ({ dispose() { registrationsDisposed++; } });
  try {
    const state = fixture(['/fixture']); controller = state.controller;
    const input = source([row(1)]);
    await manifest(controller, state.folders[0], input);
    await project(controller, state.folders[0], input);
    assert.equal(count(state.entries), 1);
    const beforeClear = refreshes;
    controller.clearAll();
    assert.equal(refreshes, beforeClear + 1);
    assert.equal(count(state.entries), 0);
    await manifest(controller, state.folders[0], input);
    await project(controller, state.folders[0], input);
    assert.equal(count(state.entries), 1);
    const beforeDispose = refreshes;
    closing = true;
    controller.dispose();
    controller.dispose();
    assert.equal(refreshes, beforeDispose);
    assert.equal(count(state.entries), 0);
    assert.deepEqual(controller.testSnapshot().treeWorkspaceLabels, []);
    assert.equal(registrationsDisposed, 1);
  } finally {
    closing = false;
    controller?.dispose();
    mock.EventEmitter = originalEmitter;
    if (originalRegistration === undefined) delete mock.window.registerTreeDataProvider;
    else mock.window.registerTreeDataProvider = originalRegistration;
  }
});

test('scope comes from persisted execution and never from finding count or an unsafe path', () => {
  for (const scope of [undefined, {}, [], { kind: 'workspace', target_path: 'src/a.js' },
    { kind: 'file', target_path: '../outside' }, { kind: 'directory', target_path: '/outside' },
    { kind: 'file', target_path: 'a\u0000.js' }]) {
    assert.deepEqual(findingScanScope({ scanner_summary: { scope } }), { kind: 'unknown' });
  }
  for (const kind of ['file', 'directory']) {
    assert.deepEqual(findingScanScope({ scanner_summary: { scope: { kind, target_path: 'src/café.ts' } } }),
      { kind, targetPath: 'src/café.ts' });
  }
});

test('a changed scan or revision cannot supply scope for another manifest', () => {
  const scan = { id: 71, project_id: 17, revision: 2, findings_revision: 3 };
  for (const key of ['id', 'project_id', 'revision', 'findings_revision']) {
    assert.throws(() => withFindingScanScope(scan, { ...scan, [key]: scan[key] + 1 }),
      error => error.status === 409);
  }
  assert.deepEqual(findingScanScope(withFindingScanScope(scan, scan)), { kind: 'unknown' });
  const detail = { ...scan, scanner_summary: { scope: { kind: 'workspace' } } };
  for (const missing of ['revision', 'findings_revision']) {
    const partial = { ...detail };
    delete partial[missing];
    assert.deepEqual(findingScanScope(withFindingScanScope(scan, partial)), { kind: 'unknown' });
    const present = missing === 'revision' ? 'findings_revision' : 'revision';
    partial[present] += 1;
    assert.throws(() => withFindingScanScope(scan, partial), error => error.status === 409);
  }
});

test('zero-finding scoped scans retain a history action and cannot look like full coverage', async () => {
  let provider, controller;
  const status = { show() {}, dispose() {} };
  const original = { TreeItem: mock.TreeItem, ThemeIcon: mock.ThemeIcon, TreeItemCollapsibleState: mock.TreeItemCollapsibleState };
  mock.TreeItem = class { constructor(label, state) { this.label = label; this.collapsibleState = state; } };
  mock.ThemeIcon = class { constructor(id) { this.id = id; } };
  mock.TreeItemCollapsibleState = { None: 0, Collapsed: 1 };
  mock.window.registerTreeDataProvider = (_id, tree) => { provider = tree; return { dispose() {} }; };
  mock.window.createStatusBarItem = () => status;
  try {
    const state = fixture(['/fixture']); controller = state.controller;
    await manifest(controller, state.folders[0], source([], 1, { kind: 'file', target_path: 'src/a.js' }));
    const root = provider.getChildren()[0], rootItem = provider.getTreeItem(root);
    assert.match(rootItem.description, /0 · file only/);
    assert.match(rootItem.tooltip, /Only src\/a.js is assessed/);
    const children = provider.getChildren(root);
    assert.equal(children.length, 1);
    const history = provider.getTreeItem(children[0]);
    assert.equal(history.label, 'Open scan history');
    assert.deepEqual(history.command.arguments, [71]);
    assert.equal(history.command.command, 'lomoCodeSecurity.openDashboard');
    assert.match(status.text, /1 scoped/);
    assert.match(status.accessibilityInformation.label, /1 scoped/);
    assert.match(status.tooltip, /do not represent whole-repository coverage/);
    await manifest(controller, state.folders[0], source([], 2));
    assert.equal(provider.getChildren(provider.getChildren()[0]).length, 0);
    assert.doesNotMatch(status.text, /scoped/);
    await manifest(controller, state.folders[0], source([], 3, { kind: 'directory', target_path: 'src' }));
    assert.match(provider.getTreeItem(provider.getChildren()[0]).description, /folder only/);
    await manifest(controller, state.folders[0], source([], 4, null));
    assert.match(provider.getTreeItem(provider.getChildren()[0]).description, /scope unavailable/);
    assert.equal(provider.getChildren(provider.getChildren()[0]).length, 1);
    delete provider.getChildren()[0].workspace.scanScope;
    assert.match(provider.getTreeItem(provider.getChildren()[0]).description, /scope unavailable/);
    assert.equal(provider.getChildren(provider.getChildren()[0]).length, 1);
    controller.setServiceHealth('connected');
    assert.match(status.text, /1 scoped/);
  } finally {
    controller?.dispose(); Object.assign(mock, original);
    delete mock.window.registerTreeDataProvider; delete mock.window.createStatusBarItem;
  }
});

test('compact Problems show readable Trivy titles without merging same-location findings', async () => {
  const { controller, folders: [root], entries } = fixture(['/fixture']);
  try {
    const cases = require('../fixtures/finding-titles.json');
    const rows = cases.map(({ message }, index) => ({
      ...row(index + 1, 'src/shared.ts', message.replaceAll('\n', ' ')), scanner: 'trivy',
    }));
    const input = source(rows);
    await manifest(controller, root, input);
    await project(controller, root, input);
    const diagnostics = entries.get('file:///fixture/src/shared.ts');
    assert.equal(diagnostics.length, 3);
    assert.deepEqual(diagnostics.map(item => item.code), ['S71-F001', 'S71-F002', 'S71-F003']);
    assert.deepEqual(diagnostics.map(item => item.message), cases.map(({ title }) =>
      title.length > 48 ? title.slice(0, 47) + '…' : title));
    assert.deepEqual(rows.map(item => item.message), cases.map(item => item.message.replaceAll('\n', ' ')));
  } finally { controller.dispose(); }
});

test('finding source reveals reuse exact visible editor groups without replacing a split sibling', async (t) => {
  for (const targeted of [false, true]) {
    for (const scenario of ['existing', 'active-match', 'not-visible', 'remote-existing', 'remote-other-only', 'wrong-result']) {
      await t.test(`${targeted ? 'targeted' : 'tree'} ${scenario}`, async () => {
        const { controller, folders: [folder] } = fixture(['/fixture']);
        const remote = scenario.startsWith('remote-');
        if (remote) folder.uri = uri('vscode-remote://wsl+Ubuntu-26.04/fixture');
        const finding = {
          ...row(1, 'src/file.ts'), scan_id: 71, rule_id: 'fixture.rule',
          gate_effect: 'blocking', lifecycle_status: 'open', suppressed: false, gate_exempt: false,
          start_column: 2, end_column: 5,
        };
        const document = {
          uri: mock.Uri.joinPath(folder.uri, finding.file_path),
          version: 1, isDirty: false, lineCount: 1, lineAt: () => ({ text: 'target source' }),
        };
        const siblingDocument = {
          ...document,
          uri: uri(remote
            ? 'vscode-remote://wsl+Other/fixture/src/file.ts'
            : 'file:///fixture/src/other.ts'),
        };
        const editor = (sourceDocument, viewColumn) => ({
          document: sourceDocument, viewColumn, selection: undefined, revealed: [],
          revealRange(range, kind) { this.revealed.push({ range, kind }); },
        });
        const left = editor(document, 1);
        const right = editor(scenario === 'active-match' ? document : siblingDocument, 2);
        const absent = ['not-visible', 'remote-other-only'].includes(scenario);
        const visible = absent ? [right] : [left, right];
        const calls = [];
        try {
          await manifest(controller, folder, source([finding]));
          assert.equal(controller.replaceHydratedFile(folder, finding.file_path, [finding], 1), true);
          mock.workspace.textDocuments = [document, siblingDocument];
          mock.window.visibleTextEditors = visible;
          mock.window.activeTextEditor = right;
          mock.workspace.openTextDocument = async (requested) => {
            assert.equal(requested.toString(), document.uri.toString());
            return document;
          };
          mock.window.showTextDocument = async (requested, options) => {
            assert.equal(requested, document);
            calls.push(options);
            const column = options.viewColumn ?? mock.window.activeTextEditor.viewColumn;
            const selected = visible.find((candidate) => candidate.viewColumn === column);
            assert(selected, 'the requested group must exist');
            selected.document = scenario === 'wrong-result' ? siblingDocument : requested;
            mock.window.activeTextEditor = selected;
            return selected;
          };
          const context = {
            workspaceKey: folder.uri.toString(), findingId: 1, scanId: 71,
            scanFindingNumber: 1, findingRevision: 1, findingsRevision: 1,
          };
          const reveal = () => targeted
            ? controller.revealTargetedFinding(folder, finding, () => {}, context)
            : controller.revealFinding(context);
          if (scenario === 'wrong-result') {
            await assert.rejects(reveal(), /VS Code did not (?:open|show).*finding file/u);
            assert.equal(left.selection, undefined);
            assert.deepEqual(left.revealed, []);
          } else {
            await reveal();
            const expected = absent || scenario === 'active-match' ? right : left;
            assert.equal(mock.window.activeTextEditor, expected);
            assert.equal(expected.document, document);
            assert.deepEqual(expected.selection.start, { line: 0, character: 1 });
            assert.deepEqual(expected.selection.end, { line: 0, character: 4 });
            assert.equal(expected.revealed.length, 1);
            if (!absent) {
              const untouched = expected === left ? right : left;
              assert.equal(untouched.document, expected === left ? siblingDocument : document);
              assert.equal(untouched.selection, undefined);
              assert.deepEqual(untouched.revealed, []);
            }
          }
          assert.deepEqual(calls, [{
            preview: false, preserveFocus: false,
            viewColumn: absent ? undefined : scenario === 'active-match' ? 2 : 1,
          }]);
        } finally {
          controller.dispose();
          mock.window.visibleTextEditors = [];
          delete mock.window.activeTextEditor;
          delete mock.window.showTextDocument;
          delete mock.workspace.openTextDocument;
        }
      });
    }
  }
});

test('connection and enrollment status preserve the finding Tree until its data changes', async () => {
  let provider;
  let refreshes = 0;
  const status = { show() {}, dispose() {} };
  const originalEmitter = mock.EventEmitter;
  mock.EventEmitter = class {
    event() { return { dispose() {} }; }
    fire() { refreshes++; }
    dispose() {}
  };
  mock.window.registerTreeDataProvider = (_id, tree) => {
    provider = tree;
    return { dispose() {} };
  };
  mock.window.createStatusBarItem = () => status;
  let controller;
  try {
    const state = fixture();
    controller = state.controller;
    const root = state.folders[0];
    const input = source([row(1)]);
    await manifest(controller, root, input);
    await project(controller, root, input);
    const roots = provider.getChildren();
    const file = provider.getChildren(roots[0])[0];
    const diagnostics = state.entries.get('file:///fixture/src/file-1.ts');
    const before = refreshes;
    for (const health of ['reconnecting', 'unavailable', 'pair required', 'connected']) {
      controller.setServiceHealth(health);
      assert.equal(refreshes, before, 'connection health is not a finding-data invalidation');
      assert.equal(provider.getChildren(), roots);
      assert.equal(provider.getParent(file), roots[0]);
      assert.equal(state.entries.get('file:///fixture/src/file-1.ts'), diagnostics);
      assert.equal(status.command, health === 'connected' ? 'lomoCodeSecurity.openDashboard'
        : health === 'pair required' ? 'lomoCodeSecurity.pair' : 'lomoCodeSecurity.reconnect');
      assert.match(status.text, /fail · 1/u);
      assert.equal(status.text.includes('cached'), ['reconnecting', 'unavailable'].includes(health));
      assert(status.accessibilityInformation.label.includes(health === 'pair required' ? 'IDE access required' : health));
    }
    controller.setIdeEnrollmentReview({ verificationCode: 'ABCD-EF23', state: 'awaiting_approval' });
    assert.equal(status.command, 'lomoCodeSecurity.pair');
    assert.match(status.text, /Approval needed/u);
    controller.setIdeEnrollmentReview(undefined);
    assert.equal(status.command, 'lomoCodeSecurity.openDashboard');
    assert.equal(refreshes, before);
    assert.equal(provider.getChildren(), roots);
    await manifest(controller, root, source([row(1), row(2)], 2));
    assert(refreshes > before, 'new finding data must still invalidate the Tree');
    assert.notEqual(provider.getChildren(), roots);
    assert.equal(provider.getChildren()[0].workspace.totalFindings, 2);
    assert.match(status.text, /fail · 2/u);
  } finally {
    controller?.dispose();
    mock.EventEmitter = originalEmitter;
    delete mock.window.registerTreeDataProvider;
    delete mock.window.createStatusBarItem;
  }
});

function delayedTreeView() {
  let provider, visibility;
  const reveals=[];
  mock.window.createTreeView=(_id,options)=>{
    provider=options.treeDataProvider;
    return {visible:true,dispose(){},onDidChangeVisibility(listener){visibility=listener;return {dispose(){}};},
      reveal(element,options){return new Promise((resolve,reject)=>reveals.push({element,options,
        revision:element.workspace.revision,resolve,reject}));}};
  };
  return {reveals,get provider(){return provider;},show:()=>visibility({visible:true}),
    dispose(){delete mock.window.createTreeView;}};
}

test('progressive manifests retain root identity across sibling arrivals and own revisions',async()=>{
  const view=delayedTreeView();let controller;
  try {
    const state=fixture(['/fixture','/sibling']);controller=state.controller;
    const [root,sibling]=state.folders;
    await manifest(controller,root,source([row(1)]));
    const first=view.provider.getChildren()[0], id=view.provider.getTreeItem(first).id;
    assert.equal(typeof id,'string');assert(id.length>0);
    await manifest(controller,sibling,source([row(2)]));
    assert.equal(view.provider.getChildren().find(x=>x.workspace.key===root.uri.toString()),first);
    assert.notEqual(view.provider.getTreeItem(view.provider.getChildren().find(x=>x!==first)).id,id);
    await manifest(controller,root,source([row(1),row(3)],2));
    assert.equal(view.provider.getChildren().find(x=>x.workspace.key===root.uri.toString()),first);
    assert.equal(first.workspace.revision,2);assert.equal(first.workspace.totalFindings,2);
    assert.equal(view.provider.getTreeItem(first).id,id);
    const files=view.provider.getChildren(first);assert.equal(files.length,2);
    assert(files.every(file=>view.provider.getParent(file)===first));
  } finally {controller?.dispose();for(const pending of view.reveals)pending.resolve();view.dispose();}
});

test('overlapping viewport reveals coalesce to the newest manifest without losing same-key updates',async()=>{
  const view=delayedTreeView();let controller;
  const settle=()=>new Promise(resolve=>setImmediate(resolve));
  try {
    const state=fixture(['/fixture','/sibling']);controller=state.controller;
    const [root,sibling]=state.folders;
    await manifest(controller,root,source([row(1)]));assert.equal(view.reveals.length,1);
    await manifest(controller,sibling,source([row(2)]));
    await manifest(controller,root,source([row(1),row(3)],2));
    assert.equal(view.reveals.length,1,'only one native reveal may be in flight');
    view.reveals[0].resolve();await settle();assert.equal(view.reveals.length,2);
    assert.equal(view.reveals[1].element.workspace.key,root.uri.toString());assert.equal(view.reveals[1].revision,2);
    await manifest(controller,root,source([row(1),row(3),row(4)],3));
    assert.equal(view.reveals.length,2);
    view.reveals[1].resolve();await settle();assert.equal(view.reveals.length,3);
    assert.equal(view.reveals[2].revision,3);
    view.reveals[2].resolve();await settle();view.show();await settle();assert.equal(view.reveals.length,3);
  } finally {controller?.dispose();for(const pending of view.reveals)pending.resolve();await settle();view.dispose();}
});

test('held viewport requests cannot resurrect a removed root or erase its new incarnation',async()=>{
  const view=delayedTreeView();let controller;
  const settle=()=>new Promise(resolve=>setImmediate(resolve));
  try {
    const state=fixture(['/fixture']);controller=state.controller;const root=state.folders[0];
    await manifest(controller,root,source([row(1)]));const oldRoot=view.provider.getChildren()[0];
    await manifest(controller,root,source([row(1),row(2)],2));
    controller.clearWorkspace(root);
    assert.deepEqual(view.provider.getChildren(oldRoot),[]);assert.deepEqual(view.provider.getChildren(),[]);
    await manifest(controller,root,source([row(3)],3));const newRoot=view.provider.getChildren()[0];
    assert.notEqual(newRoot,oldRoot);assert.deepEqual(view.provider.getChildren(oldRoot),[]);
    assert.equal(view.reveals.length,1);
    view.reveals[0].resolve();await settle();assert.equal(view.reveals.length,2);
    assert.equal(view.reveals[1].element,newRoot);assert.equal(view.reveals[1].revision,3);
    controller.clearWorkspace(root);view.reveals[1].resolve();await settle();view.show();await settle();
    assert.equal(view.reveals.length,2);assert.deepEqual(view.provider.getChildren(newRoot),[]);
  } finally {controller?.dispose();for(const pending of view.reveals)pending.resolve();await settle();view.dispose();}
});

test('failed viewport requests do not spin and retry only on a later visible-view event',async()=>{
  const view=delayedTreeView();let controller;const failures=[],original=console.error;
  const settle=()=>new Promise(resolve=>setImmediate(resolve));console.error=(...args)=>failures.push(args);
  try {
    const state=fixture(['/fixture']);controller=state.controller;
    await manifest(controller,state.folders[0],source([row(1)]));
    view.reveals[0].reject(Error('native view temporarily unavailable'));await settle();await settle();
    assert.equal(view.reveals.length,1);assert.equal(failures.length,1);
    view.show();assert.equal(view.reveals.length,2);
    view.reveals[1].resolve();await settle();view.show();assert.equal(view.reveals.length,2);
  } finally {controller?.dispose();for(const pending of view.reveals)pending.resolve();await settle();view.dispose();console.error=original;}
});

test('disposing during a held reveal suppresses queued work and late native errors',async()=>{
  const view=delayedTreeView();let controller;const failures=[],original=console.error;
  const settle=()=>new Promise(resolve=>setImmediate(resolve));console.error=(...args)=>failures.push(args);
  try {
    const state=fixture(['/fixture']);controller=state.controller;
    await manifest(controller,state.folders[0],source([row(1)]));
    await manifest(controller,state.folders[0],source([row(1),row(2)],2));
    controller.dispose();controller=undefined;
    view.reveals[0].reject(Error('view closed'));await settle();view.show();await settle();
    assert.equal(view.reveals.length,1);assert.deepEqual(failures,[]);
  } finally {controller?.dispose();for(const pending of view.reveals)pending.resolve();await settle();view.dispose();console.error=original;}
});

test('Problems publishes 2,219 files completely, retains a duplicate-name sibling and suppresses the unsaved file', async () => {
  const { controller, folders: [root, sibling], entries, batches } = fixture();
  const other = source([row(1)]);
  await manifest(controller, sibling, other); await project(controller, sibling, other);
  const siblingItems = entries.get('file:///sibling/src/file-1.ts');
  const dirty = { uri: uri('file:///fixture/src/file-1.ts'), isDirty: true, version: 1, lineCount: 1, lineAt: () => ({ text: 'edited' }) };
  mock.workspace.textDocuments = [dirty];
  const input = source(Array.from({ length: 2219 }, (_, index) => row(index + 1)));
  await manifest(controller, root, input);
  await project(controller, root, input);
  assert.equal(count(entries), 2219);
  assert.equal(entries.has(dirty.uri.toString()), false);
  assert.equal(entries.get('file:///sibling/src/file-1.ts'), siblingItems);
  assert.equal(entries.get('file:///fixture/src/file-2219.ts')[0].code, 'S71-F2219');
  assert.equal(controller.store.workspace(root.uri.toString()).diagnosticProjection, 'complete');
  assert.equal(batches.length, 4);
  controller.clearWorkspace(root);
  assert.equal(count(entries), 1);
  assert.equal(entries.get('file:///sibling/src/file-1.ts'), siblingItems);
  controller.dispose();
});

test('Problems refuses one oversized file before reading compact pages and preserves siblings', async () => {
  const { controller, folders: [root, sibling], entries } = fixture();
  const other = source([row(1)]);
  await manifest(controller, sibling, other); await project(controller, sibling, other);
  const input = source(Array.from({ length: 1001 }, (_, index) => row(index + 1, 'src/dense.ts')));
  await manifest(controller, root, input);
  let reads = 0;
  const result = await controller.projectWorkspaceDiagnostics(root, 1, async () => { reads++; });
  assert.equal(result.limited, true); assert.equal(reads, 0); assert.equal(count(entries), 1);
  assert.equal(controller.store.workspace(root.uri.toString()).diagnosticProjection, 'limited');
  controller.dispose();
});

test('Problems reservations bound concurrent roots and release after a cancelled page source', async () => {
  const { controller, folders: [root, sibling], entries } = fixture();
  const input = source(Array.from({ length: 6000 }, (_, index) => row(index + 1)));
  const other = source(Array.from({ length: 4001 }, (_, index) => row(index + 1)));
  await manifest(controller, root, input); await manifest(controller, sibling, other);
  let release;
  let entered;
  const ready = new Promise((resolve) => { entered = resolve; });
  const hold = new Promise((resolve) => { release = resolve; });
  const cancelled = Object.assign(new Error('cancelled'), { name: 'AbortError' });
  const pending = controller.projectWorkspaceDiagnostics(root, 1, async () => { entered(); await hold; throw cancelled; });
  await ready;
  const limited = await controller.projectWorkspaceDiagnostics(sibling, 1, async () => assert.fail('budget must refuse before page reads'));
  assert.equal(limited.limited, true); assert.equal(entries.size, 0);
  release(); await assert.rejects(pending, (error) => error === cancelled);
  await project(controller, sibling, other);
  assert.equal(count(entries), 4001);
  controller.dispose();
});

test('Problems rejects a superseded page build without replacing the newer root or sibling', async () => {
  const { controller, folders: [root, sibling], entries } = fixture();
  const prior = source([row(1)]);
  await manifest(controller, sibling, prior); await project(controller, sibling, prior);
  const input = source(Array.from({ length: 2219 }, (_, index) => row(index + 1)));
  await manifest(controller, root, input);
  let replaced = false;
  await assert.rejects(project(controller, root, input, async () => {
    if (replaced) return; replaced = true;
    const next = source([row(9, 'src/new.ts')], 2);
    await manifest(controller, root, next); await project(controller, root, next);
  }), (error) => error.name === 'AbortError');
  assert.equal(count(entries), 2);
  assert.equal(entries.get('file:///fixture/src/new.ts')[0].code, 'S71-F009');
  assert.equal(controller.store.workspace(root.uri.toString()).revision, 2);
  controller.dispose();
});

test('Problems removal during a page yield publishes no removed-root diagnostics', async () => {
  const { controller, folders: [root, sibling], entries } = fixture();
  const other = source([row(1)]);
  await manifest(controller, sibling, other); await project(controller, sibling, other);
  const input = source(Array.from({ length: 2219 }, (_, index) => row(index + 1)));
  await manifest(controller, root, input);
  await assert.rejects(project(controller, root, input, async () => {
    mock.workspace.workspaceFolders = [sibling]; controller.clearWorkspace(root);
  }), (error) => error.name === 'AbortError');
  assert.equal(count(entries), 1); assert.equal(controller.store.workspace(root.uri.toString()), undefined);
  controller.dispose();
});

test('Problems enforces the retained-string budget without partial publication', async () => {
  const { controller, folders: [root, sibling], entries } = fixture();
  const other = source([row(1)]);
  await manifest(controller, sibling, other); await project(controller, sibling, other);
  const input = source(Array.from({ length: 5000 }, (_, index) => row(index + 1, `src/file-${index + 1}.ts`, 'x'.repeat(4000))));
  assert(5000 * (1024 + 2 * 4000) > MAX_DIAGNOSTIC_RETAINED_BYTES);
  await manifest(controller, root, input);
  const result = await project(controller, root, input);
  assert.equal(result.limited, true); assert.equal(count(entries), 1);
  assert.equal(controller.store.workspace(root.uri.toString()).diagnosticProjection, 'limited');
  controller.dispose();
});

test('Problems replacement removes all trailing old URI batches and preserves nested-root authority', async () => {
  const { controller, folders: [root, nested], entries } = fixture(['/fixture', '/fixture/child']);
  const old = source(Array.from({ length: 2219 }, (_, index) => row(index + 1, `child/src/file-${index + 1}.ts`)));
  await manifest(controller, root, old); await project(controller, root, old);
  const child = source([row(7, 'src/file-1.ts')]);
  await manifest(controller, nested, child); await project(controller, nested, child);
  const nestedItems = entries.get('file:///fixture/child/src/file-1.ts');
  const next = source([row(3, 'src/replacement.ts')], 2);
  await manifest(controller, root, next); await project(controller, root, next);
  assert.equal(count(entries), 2);
  assert.equal(entries.get('file:///fixture/child/src/file-1.ts'), nestedItems);
  controller.clearWorkspace(nested);
  assert.equal(count(entries), 1);
  controller.dispose();
});
