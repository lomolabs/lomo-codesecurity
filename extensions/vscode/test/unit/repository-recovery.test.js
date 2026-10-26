const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { RepositoryRecoveryStore } = require('../../dist/repository-recovery-store.js');
const { createHash } = require('node:crypto');
const { createRepositoryRecoveryState, repositoryRecoveryFailure } = require('../../dist/repository-recovery.js');
const { REPOSITORY_CONTEXT_STATE_KEY: KEY, newRepositoryContext,
  bindRepositoryProject } = require('../../dist/repository-context.js');

const SESSION = 'c23172b2-77a6-45ec-a570-779f20a58dd01792350634333';
function store(initial = new Map(), write = async () => {}) {
  return { values: initial, get(key) { return initial.get(key); }, async update(key, value) {
    await write(key, value); initial.set(key, JSON.parse(JSON.stringify(value)));
  } };
}
async function fixture(run) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-recovery-')));
  const parent = path.join(root, 'parent'); fs.mkdirSync(parent);
  const uri = pathToFileURL(parent).href;
  const metadata = { schema_version: 1, managed_parents: [uri], roots: [] };
  for (let i = 0; i < 15; i++) {
    fs.mkdirSync(path.join(parent, `repo-${i}`, '.git'), { recursive: true });
    metadata.roots.push(bindRepositoryProject(newRepositoryContext(uri, parent, `repo-${i}`), i + 1));
  }
  const folder = { uri, path: parent };
  const original = { session: SESSION, workspace_uri: null, untitled: false, folders: [folder] };
  const added = path.join(parent, 'added-qa'); fs.mkdirSync(added);
  const converted = { session: SESSION, workspace_uri: 'untitled:1792350634333', untitled: true,
    folders: [folder, { uri: pathToFileURL(added).href, path: added }] };
  const profile = store(new Map([['unrelated.credentials', 'do-not-copy-or-delete']]));
  const profilePath = path.join(root, 'profile');
  const offers = [], failures = [];
  const start = (workspace, scope = converted, more = {}) => createRepositoryRecoveryState({ workspace, recovery: new RepositoryRecoveryStore(profilePath),
    scope: () => scope, active: () => true, offer: (count, restore) => offers.push({ count, restore }),
    failure: () => failures.push(true), ...more });
  const old = store(new Map([[KEY, metadata]]));
  await start(old, original).ready;
  try { await run({ root, parent, uri, metadata, original, converted, profile, profilePath, old, offers, failures, start }); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('ordinary single-folder conversion preserves all fifteen exact associations without copying authority', () => fixture(async f => {
  const workspace = store(), recovery = f.start(workspace);
  await recovery.ready;
  assert.deepEqual(workspace.get(KEY), f.metadata);
  assert.deepEqual(recovery.state.get(KEY), f.metadata);
  assert.deepEqual(f.old.get(KEY), f.metadata);
  assert.equal(f.profile.get('unrelated.credentials'), 'do-not-copy-or-delete');
  assert.deepEqual([...workspace.values.keys()], [KEY]);
  assert.equal(f.offers.length, 0); assert.equal(f.failures.length, 0);
}));

test('failed optional startup backup reports its stage without changing fifteen authoritative selections', () => fixture(async f => {
  const failures = [], privateError = Object.assign(new Error('/private/source?token=must-not-log'), { code: 'EACCES' });
  const recovery = f.start(f.old, f.original, {
    recovery: { write: async () => { throw privateError; } },
    failure: value => failures.push(value),
  });
  await recovery.ready;
  assert.deepEqual(recovery.state.get(KEY), f.metadata);
  assert.deepEqual(f.old.get(KEY), f.metadata);
  assert.deepEqual(failures, [{ schema: 'lomo-repository-recovery-failure/v1', phase: 'seed-write',
    category: 'filesystem', errno: 'EACCES', workspace_kind: 'folder', folder_count: 1 }]);
}));

test('recovery diagnostics exclude arbitrary exception and scope content', () => {
  const error = Object.assign(new Error('private source and credentials'), { code: 'ENOSPC', secret: 'not-for-logs' });
  const scope = { session: 'private', workspace_uri: 'untitled:private', untitled: true, folders: Array(50).fill({ uri: 'secret' }) };
  assert.deepEqual(repositoryRecoveryFailure(error, 'selection-backup', scope), {
    schema: 'lomo-repository-recovery-failure/v1', phase: 'selection-backup', category: 'filesystem',
    errno: 'ENOSPC', workspace_kind: 'untitled', folder_count: 33,
  });
  for (const message of ['__proto__', 'constructor', 'toString'])
    assert.equal(repositoryRecoveryFailure(new Error(message), 'restore').category, 'unknown');
  Object.defineProperty(error, 'code', { get() { throw new Error('private getter'); } });
  assert.equal(repositoryRecoveryFailure(error, 'restore').category, 'unknown');
});

test('diagnostic reporting failure does not reject startup or change authoritative selections', () => fixture(async f => {
  let reports = 0;
  const recovery = f.start(f.old, f.original, {
    recovery: { write: async () => { throw Object.assign(new Error('backup unavailable'), { code: 'EACCES' }); } },
    failure: () => { reports++; throw new Error('reporting failed'); },
  });
  await recovery.ready;
  assert.equal(reports, 1);
  assert.deepEqual(f.old.get(KEY), f.metadata);
  assert.deepEqual(recovery.state.get(KEY), f.metadata);
}));

test('an explicit current empty selection and its parent tombstone beat old positive recovery data', () => fixture(async f => {
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  const workspace = store(new Map([[KEY, empty]])), recovery = f.start(workspace);
  await recovery.ready; assert.deepEqual(recovery.state.get(KEY), empty);
  assert.deepEqual(workspace.get(KEY), empty); assert.equal(f.offers.length, 0);
  const original = f.start(f.old, f.original); await original.ready;
  await original.state.update(KEY, empty);
  const reopened = store(), returning = f.start(reopened); await returning.ready;
  assert.deepEqual(reopened.get(KEY), empty);
}));

test('missing renderer identity still invalidates a positive checkpoint before deselection', () => fixture(async f => {
  const anonymous = f.start(f.old, { ...f.original, session: undefined });
  await anonymous.ready;
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  await anonymous.state.update(KEY, empty);
  assert.deepEqual(f.old.get(KEY), empty);
  const returning = store(); await f.start(returning).ready;
  assert.deepEqual(returning.get(KEY), empty);
  assert.equal(f.offers.length, 0); assert.equal(f.failures.length, 0);
}));

test('missing renderer identity cannot bypass failed checkpoint invalidation', () => fixture(async f => {
  let authoritativeWrites = 0;
  const workspace = store(new Map([[KEY, f.metadata]]), async () => { authoritativeWrites++; });
  const unavailable = { write: async () => {}, change: async () => { throw new Error('checkpoint unavailable'); } };
  const original = f.start(workspace, { ...f.original, session: undefined }, { recovery: unavailable });
  await original.ready;
  await assert.rejects(original.state.update(KEY,
    { schema_version: 1, managed_parents: [f.uri], roots: [] }), /checkpoint unavailable/);
  assert.equal(authoritativeWrites, 0); assert.deepEqual(workspace.get(KEY), f.metadata);
}));

test('other windows and null telemetry placeholders require an explicit restore; saved workspaces never inherit', () => fixture(async f => {
  for (const session of ['e93172b2-77a6-45ec-a570-779f20a58dd01792350634334', 'someValue.sessionId', undefined]) {
    const workspace = store(), recovery = f.start(workspace, { ...f.converted, session });
    await recovery.ready; assert.equal(workspace.get(KEY), undefined);
    assert.deepEqual(recovery.state.get(KEY), { schema_version: 1, managed_parents: [f.uri], roots: [] });
    const offer = f.offers.at(-1); assert.equal(offer.count, 15);
    await offer.restore(); await offer.restore();
    assert.deepEqual(workspace.get(KEY), f.metadata);
  }
  const saved = store(), count = f.offers.length;
  await f.start(saved, { ...f.converted, workspace_uri: 'file:///independent.code-workspace', untitled: false }).ready;
  assert.equal(saved.get(KEY), undefined); assert.equal(f.offers.length, count);
}));

test('replaced clone or parent cannot acquire recovered project associations', () => fixture(async f => {
  fs.renameSync(path.join(f.parent, 'repo-0/.git'), path.join(f.parent, 'repo-0/.old-git'));
  fs.mkdirSync(path.join(f.parent, 'repo-0/.git'));
  const workspace = store(), recovery = f.start(workspace); await recovery.ready;
  assert.deepEqual(recovery.state.get(KEY), { schema_version: 1, managed_parents: [f.uri], roots: [] });
  assert.equal(workspace.get(KEY), undefined); assert.equal(f.failures.length, 1);
}));

test('pending restore serializes an explicit removal without resurrecting the old children', () => fixture(async f => {
  let release; const pending = new Promise(resolve => { release = resolve; });
  let first = true;
  const workspace = store(new Map(), async () => { if (first) { first = false; await pending; } });
  const recovery = f.start(workspace); const ready = recovery.ready;
  assert.deepEqual(recovery.state.get(KEY), { schema_version: 1, managed_parents: [f.uri], roots: [] });
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  const removal = recovery.state.update(KEY, empty); release(); await ready; await removal;
  assert.deepEqual(workspace.get(KEY), empty);
}));

test('an old ambiguous offer cannot overwrite a later explicit choice', () => fixture(async f => {
  const workspace = store(), recovery = f.start(workspace, { ...f.converted, session: 'someValue.sessionId' });
  await recovery.ready; const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  await recovery.state.update(KEY, empty); await f.offers[0].restore();
  assert.deepEqual(workspace.get(KEY), empty); assert.deepEqual(recovery.state.get(KEY), empty);
}));

test('Restricted Mode performs no recovery until trusted and no stale activation may publish', () => fixture(async f => {
  let scope, active = true;
  const workspace = store(), recovery = f.start(workspace, f.converted, { scope: () => scope, active: () => active });
  await recovery.ready; assert.equal(workspace.get(KEY), undefined); assert.equal(f.offers.length, 0);
  scope = f.converted; active = false;
  await recovery.ready; assert.equal(workspace.get(KEY), undefined);
  assert.throws(() => recovery.state.get(KEY));
}));

test('optional recovery failure cannot disable an existing authoritative selection or a fresh explicit choice', () => fixture(async f => {
  const unavailable = { candidates: async () => { throw new Error('corrupt optional hint'); },
    write: async () => { throw new Error('unavailable hint storage'); } };
  const original = f.start(f.old, f.original, { recovery: unavailable }); await original.ready;
  assert.deepEqual(original.state.get(KEY), f.metadata);
  const workspace = store(), recovery = f.start(workspace, f.converted, { recovery: unavailable });
  await recovery.ready;
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  assert.deepEqual(recovery.state.get(KEY), empty);
  await recovery.state.update(KEY, empty);
  assert.deepEqual(workspace.get(KEY), empty);
  assert.deepEqual(recovery.state.get(KEY), empty);
  assert.equal(f.failures.length, 2);
}));

test('manual restoration rejects uncertain persistence and does not run its refresh continuation', () => fixture(async f => {
  const workspace = store(new Map(), async () => { throw new Error('write outcome unavailable'); });
  const recovery = f.start(workspace, { ...f.converted, session: 'someValue.sessionId' });
  await recovery.ready;
  let refreshes = 0;
  await assert.rejects(f.offers[0].restore().then(() => { refreshes++; }), /write outcome unavailable/);
  assert.equal(refreshes, 0);
  assert.equal(workspace.get(KEY), undefined);
  assert.deepEqual(recovery.state.get(KEY), { schema_version: 1, managed_parents: [f.uri], roots: [] });
}));

test('two overlapping parents cannot overwrite each other in shared profile storage', () => fixture(async f => {
  const parent = path.join(f.root, 'second-parent'); fs.mkdirSync(parent);
  const uri = pathToFileURL(parent).href, added = path.join(parent, 'extra'); fs.mkdirSync(added);
  const metadata = { schema_version: 1, managed_parents: [uri], roots: [] };
  const other = { ...f.original, session: 'e93172b2-77a6-45ec-a570-779f20a58dd01792350634334', folders: [{ uri, path: parent }] };
  await Promise.all([f.start(f.old, f.original).ready, f.start(store(new Map([[KEY, metadata]])), other).ready]);
  const firstWorkspace = store(), secondWorkspace = store();
  await Promise.all([f.start(firstWorkspace).ready, f.start(secondWorkspace, { ...other,
    workspace_uri: 'untitled:1792350634334', untitled: true,
    folders: [...other.folders, { uri: pathToFileURL(added).href, path: added }] }).ready]);
  assert.deepEqual(firstWorkspace.get(KEY), f.metadata); assert.deepEqual(secondWorkspace.get(KEY), metadata);
  const files = fs.readdirSync(path.join(f.profilePath, 'repository-recovery-v1'));
  assert.equal(files.length, 2); assert(files.every(name => name.endsWith('.json')));
  assert.equal(f.offers.length, 0); assert.equal(f.failures.length, 0);
}));

test('exact renderer recovery bypasses unrelated corrupt files; linked and oversized matching records refuse safely', () => fixture(async f => {
  const directory = path.join(f.profilePath, 'repository-recovery-v1');
  const hash = value => createHash('sha256').update(value).digest('hex');
  const name = `${hash(f.uri)}.json`;
  fs.writeFileSync(path.join(directory, `${hash('unrelated-parent')}.json`), 'invalid');
  const good = store(); await f.start(good).ready; assert.deepEqual(good.get(KEY), f.metadata);
  fs.renameSync(path.join(directory, name), path.join(f.root, 'record.json'));
  fs.symlinkSync(path.join(f.root, 'record.json'), path.join(directory, name));
  const linked = store(); await f.start(linked).ready; assert.equal(linked.get(KEY), undefined);
  fs.unlinkSync(path.join(directory, name)); fs.writeFileSync(path.join(directory, name), 'x'.repeat(262145));
  const oversized = store(); await f.start(oversized).ready; assert.equal(oversized.get(KEY), undefined);
  assert.equal(f.failures.length, 2);
}));

test('failed final backup after deselection cannot resurrect an older positive selection', () => fixture(async f => {
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  const cache = new RepositoryRecoveryStore(f.profilePath);
  const publish = cache.publish.bind(cache);
  cache.publish = async (name, record, fence) => {
    if (!record.pending && record.entry.metadata.roots.length === 0) throw new Error('final hint write unavailable');
    await publish(name, record, fence);
  };
  const original = f.start(f.old, f.original, { recovery: cache });
  await original.ready;
  await original.state.update(KEY, empty);
  assert.deepEqual(f.old.get(KEY), empty);
  const converted = storeFixture();
  await f.start(converted).ready;
  assert.equal(converted.get(KEY), undefined);
  assert.equal(f.offers.length, 0);
  assert.equal(f.failures.length, 1);
  function storeFixture() { return { get: () => undefined, async update() { throw new Error('must not restore'); } }; }
}));

test('unconfirmed hint invalidation refuses the original-folder mutation before its authoritative write', () => fixture(async f => {
  const original = f.start(f.old, f.original, { recovery: {
    candidates: async () => [], write: async () => { throw new Error('storage unavailable'); },
    change: async () => { throw new Error('storage unavailable'); },
  } });
  await original.ready;
  await assert.rejects(original.state.update(KEY, { schema_version: 1, managed_parents: [f.uri], roots: [] }), /storage unavailable/);
  assert.deepEqual(f.old.get(KEY), f.metadata);
}));

test('an unresolved mutation tombstone survives startup seeding with an older authoritative snapshot', () => fixture(async f => {
  const workspace = store(new Map([[KEY, f.metadata]]), async () => { throw new Error('workspace write failed'); });
  const original = f.start(workspace, f.original); await original.ready;
  await assert.rejects(original.state.update(KEY, { schema_version: 1, managed_parents: [f.uri], roots: [] }), /workspace write failed/);
  assert.deepEqual(workspace.get(KEY), f.metadata);
  await f.start(workspace, f.original).ready;
  const converted = store(); await f.start(converted).ready;
  assert.equal(converted.get(KEY), undefined); assert.equal(f.offers.length, 0);
}));

test('recovery capacity preserves live and recent records, retiring only an old positively ended writer', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-recovery-capacity-')));
  try {
    const cache = new RepositoryRecoveryStore(root), session = 'b'.repeat(64);
    for (let i = 0; i < 128; i++) await cache.write(`parent-${i}`, session, { i }, () => {});
    const directory = path.join(root, 'repository-recovery-v1');
    assert.equal(fs.readdirSync(directory).length, 128);
    await assert.rejects(cache.write('one-more', session, {}, () => {}), /storage is full/);
    assert.equal(fs.readdirSync(directory).length, 128, 'capacity refusal cleans owned temporary files and locks');
    const endedPid = Number(require('node:child_process').execFileSync(process.execPath,
      ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' }));
    assert.throws(() => process.kill(endedPid, 0), error => error.code === 'ESRCH');
    const name = fs.readdirSync(directory).sort()[0], target = path.join(directory, name);
    const ended = JSON.parse(fs.readFileSync(target, 'utf8'));
    ended.windows = ended.windows.map(window => ({ ...window, pid: endedPid })); ended.updated_at = Date.now() - 2 * 86400000;
    fs.writeFileSync(target, JSON.stringify(ended));
    await cache.write('one-more', session, { accepted: true }, () => {});
    assert.equal(fs.existsSync(target), false);
    assert.equal(fs.readdirSync(directory).length, 128);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('fresh authoritative state always wins over a captured recovery value', () => fixture(async f => {
  const original = f.start(f.old, f.original); await original.ready;
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  f.old.values.set(KEY, empty);
  assert.deepEqual(original.state.get(KEY), empty);
}));

test('inactive parent history is retained and never bypasses deselection invalidation', () => fixture(async f => {
  const closedPath = path.join(f.root, 'closed'); fs.mkdirSync(path.join(closedPath, 'repo', '.git'), { recursive: true });
  const closedUri = pathToFileURL(closedPath).href;
  const retained = newRepositoryContext(closedUri, closedPath, 'repo');
  const value = { schema_version: 1, managed_parents: [f.uri, closedUri], roots: [...f.metadata.roots, retained] };
  fs.rmSync(closedPath, { recursive: true }); // A closed source must not be touched by selection of the open parent.
  const original = f.start(f.old, f.original); await original.ready;
  await original.state.update(KEY, value);
  assert.deepEqual(f.old.get(KEY), value);
  const restored = store(); await f.start(restored).ready; assert.deepEqual(restored.get(KEY), value);
  const empty = { ...value, roots: [] }; await original.state.update(KEY, empty);
  const reopened = store(); await f.start(reopened).ready; assert.deepEqual(reopened.get(KEY), empty);
}));

test('a stale Restore offer cannot resurrect children after the originating window deselects them', () => fixture(async f => {
  const converted = store(), recovery = f.start(converted, { ...f.converted, session: 'someValue.sessionId' });
  await recovery.ready; const offer = f.offers[0];
  const original = f.start(f.old, f.original); await original.ready;
  await original.state.update(KEY, { schema_version: 1, managed_parents: [f.uri], roots: [] });
  await assert.rejects(offer.restore(), /selection changed/);
  assert.equal(converted.get(KEY), undefined);
}));

test('windows of the same original folder restore its latest committed shared selection', () => fixture(async f => {
  const session = 'e93172b2-77a6-45ec-a570-779f20a58dd01792350634334';
  const otherState = store(new Map([[KEY, f.metadata]])), other = f.start(otherState, { ...f.original, session });
  await other.ready;
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  await other.state.update(KEY, empty);
  await f.start(f.old, f.original).ready; // Its deliberately stale Memento snapshot cannot overwrite the current checkpoint.
  const converted = store(); await f.start(converted).ready;
  assert.deepEqual(converted.get(KEY), empty);
  assert.equal(f.offers.length, 0);
}));

test('startup cannot publish a snapshot whose authoritative key changes before publication', () => fixture(async f => {
  const freshProfile = path.join(f.root, 'new-profile'), cache = new RepositoryRecoveryStore(freshProfile);
  const workspace = store(new Map([[KEY, f.metadata]]));
  const write = cache.write.bind(cache);
  cache.write = async (...args) => {
    workspace.values.set(KEY, { schema_version: 1, managed_parents: [f.uri], roots: [] });
    await write(...args);
  };
  await f.start(workspace, f.original, { recovery: cache }).ready;
  assert.deepEqual(await cache.candidates(f.uri, createHash('sha256').update(SESSION).digest('hex')), []);
}));

test('a stale original-window selection cannot overwrite a newer committed sibling choice', () => fixture(async f => {
  const original = f.start(f.old, f.original); await original.ready;
  const session = 'e93172b2-77a6-45ec-a570-779f20a58dd01792350634334';
  const otherState = store(new Map([[KEY, f.metadata]])), other = f.start(otherState, { ...f.original, session });
  await other.ready;
  const empty = { schema_version: 1, managed_parents: [f.uri], roots: [] };
  await other.state.update(KEY, empty);
  await assert.rejects(original.state.update(KEY, f.metadata), /changed in another window/);
  assert.deepEqual(otherState.get(KEY), empty);
  const restored = store(); await f.start(restored).ready; assert.deepEqual(restored.get(KEY), empty);
}));

test('removing children cannot drop the managed-parent fence or bypass hint invalidation', () => fixture(async f => {
  const original = f.start(f.old, f.original); await original.ready;
  await assert.rejects(original.state.update(KEY, { schema_version: 1, roots: [] }), /managed parent excluded/);
  assert.deepEqual(f.old.get(KEY), f.metadata);
}));
