const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { newRepositoryContext, verifyRepositoryContext, readRepositoryContexts,
  discoverImmediateRepositories, bindRepositoryProject, managedRepositoryParents } = require('../../dist/repository-context.js');

function fixture(run) {
  const parent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-context-')));
  return Promise.resolve().then(() => run(parent)).finally(() => fs.rmSync(parent, { recursive: true, force: true }));
}
function repo(parent, name) { fs.mkdirSync(path.join(parent, name, '.git'), { recursive: true }); }

test('ten child repository selections survive workspace metadata round-trip independently of authority', () => fixture(async parent => {
  for (let index = 0; index < 10; index++) repo(parent, `repo-${index}`);
  const discovered = await discoverImmediateRepositories(`file://${parent}`, parent);
  assert.equal(discovered.roots.length, 10);
  assert.equal(discovered.truncated, false);
  const retained = readRepositoryContexts(JSON.parse(JSON.stringify({ schema_version: 1, roots: discovered.roots })));
  assert(retained.every(record => record.project_id === null));
  for (const record of retained) assert.equal(verifyRepositoryContext(record, parent), path.join(parent, record.relative_path));
  const bound = bindRepositoryProject(retained[0], 27);
  assert.equal(bound.project_id, 27);
  assert.equal(bindRepositoryProject(bound, 27).project_id, 27);
  assert.equal(bindRepositoryProject(bound, 28).project_id, 28, 'a recreated exact-root project may replace a metadata hint');
  assert.equal(discovered.roots[0].project_id, null);
}));

test('immediate discovery bounds metadata and requires explicit nested selection', () => fixture(async parent => {
  for (let index = 0; index < 33; index++) repo(parent, `repo-${index}`);
  const discovered = await discoverImmediateRepositories(`file://${parent}`, parent);
  assert.equal(discovered.examined, 32);
  assert.equal(discovered.truncated, true);
  assert.equal(discovered.roots.length, 32);
  repo(parent, 'nested/deeper');
  assert.equal(newRepositoryContext(`file://${parent}`, parent, 'nested/deeper').relative_path, 'nested/deeper');
}));

test('linked, escaped, replaced, and malformed contexts cannot inherit a project binding', () => fixture(async parent => {
  repo(parent, 'repo');
  const record = bindRepositoryProject(newRepositoryContext(`file://${parent}`, parent, 'repo'), 7);
  fs.renameSync(path.join(parent, 'repo'), path.join(parent, 'old'));
  repo(parent, 'repo');
  assert.throws(() => verifyRepositoryContext(record, parent), /context changed/);
  fs.symlinkSync(path.join(parent, 'old'), path.join(parent, 'linked'));
  assert.throws(() => newRepositoryContext(`file://${parent}`, parent, 'linked'), /context changed/);
  const valid = newRepositoryContext(`file://${parent}`, parent, 'repo');
  for (const roots of [[{ ...valid, relative_path: '../outside' }], [{ ...valid, relative_path: '/repo' }],
    [{ ...valid, project_id: -1 }], [{ ...valid, extra: true }], [valid, valid], Array(33).fill(valid)]) {
    assert.throws(() => readRepositoryContexts({ schema_version: 1, roots }), /context changed/);
  }
  assert.throws(() => readRepositoryContexts({ schema_version: 2, roots: [] }), /context changed/);
}));

test('managed parent marker survives explicit removal of every child without source authority', () => {
  const state = { schema_version: 1, managed_parents: ['file:///workspace/parent'], roots: [] };
  assert.deepEqual(readRepositoryContexts(state), []);
  assert.deepEqual(managedRepositoryParents(state), ['file:///workspace/parent']);
  assert.throws(() => readRepositoryContexts({ ...state, managed_parents: ['same', 'same'] }), /context changed/);
});
