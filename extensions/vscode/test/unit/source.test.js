const assert = require('node:assert/strict');
const test = require('node:test');

const {
  sourceTargetForFileUri,
  sourceTargetForUri,
  supportedSourceFileName,
  workspaceOwnerForFileUri,
  workspaceScanTargets,
  validateMountedSourcePreview,
  repositorySourceTarget,
} = require('../../dist/source.js');

test('workspace batch freezes exact selected roots and rejects drift, duplicates and more than 32 roots', () => {
  const roots = Array.from({ length: 33 }, (_, index) => ({ name: `root${index}`, uri: uri(`/workspace/root${index}`) }));
  const targets = workspaceScanTargets([roots[2], roots[0]], roots);
  assert.deepEqual(targets.map((item) => item.repoPath), ['/workspace/root2', '/workspace/root0']);
  assert(targets.every((item) => item.kind === 'workspace' && item.targetPath === undefined));
  assert(Object.isFrozen(targets));
  assert.throws(() => workspaceScanTargets([], roots), /between 1 and 32/);
  assert.throws(() => workspaceScanTargets(roots, roots), /between 1 and 32/);
  assert.throws(() => workspaceScanTargets([roots[0]], roots.slice(1)), /no longer open/);
  assert.throws(() => workspaceScanTargets([roots[0], roots[0]], roots), /more than once/);
  assert.equal(workspaceScanTargets(roots.slice(0, 32), roots).length, 32);
});

test('selected repository source identity is the child while its editor lifecycle remains the parent', () => {
  const parent = { name: 'parent', uri: uri('/workspace') };
  const child = { name: 'repo', uri: uri('/workspace/repo') };
  const target = repositorySourceTarget(child, parent, [parent]);
  assert.equal(target.kind, 'workspace');
  assert.equal(target.repoPath, '/workspace/repo');
  assert.equal(target.owner, child);
  assert.equal(target.folder, child);
  assert.equal(target.workspaceOwner, parent);
  assert.throws(() => repositorySourceTarget(child, parent, []), /currently open/);
  assert.throws(() => repositorySourceTarget(parent, parent, [parent]), /currently open/);
  assert.throws(() => repositorySourceTarget({ name: 'other', uri: uri('/outside') }, parent, [parent]), /currently open/);
});

test('native child repository has an independent snapshot identity while its parent remains only the editor owner', () => {
  const parent = { name: 'parent', uri: windowsUri(String.raw`C:\work\parent`) };
  const child = { name: 'repo', uri: windowsUri(String.raw`C:\work\parent\repo`) };
  const target = repositorySourceTarget(child, parent, [parent], 'win32');
  assert.equal(target.authorizationMode, 'snapshot');
  assert.equal(target.owner, child);
  assert.equal(target.workspaceOwner, parent);
  assert.notEqual(target.sourceId, sourceTargetForUri(parent.uri, [parent], 'win32').sourceId);
  assert.equal(target.repoPath, `/source-snapshots/native-windows/${target.sourceId}`);
});

test('workspace batch source preview validates the exact typed current boundary without inferring admission', () => {
  const value = { installation_id: '0123456789ab', repo_path: '/workspace/current', authorization_mode: 'mounted', authorized: true,
    configured_roots: ['/workspace'], reason_code: null };
  assert.deepEqual(validateMountedSourcePreview(value, value.repo_path), value);
  assert.equal(validateMountedSourcePreview({ ...value, authorized: false,
    reason_code: 'source_outside_allowed_root' }, value.repo_path).authorized, false);
  for (const bad of [null, [], { ...value, repo_path: '/wrong' }, { ...value, unexpected: true },
    { ...value, configured_roots: [] }, { ...value, configured_roots: ['/a', '/a'] },
    { ...value, configured_roots: ['/a/../b'] }, { ...value, configured_roots: ['/a\u0000'] },
    { ...value, configured_roots: Array.from({ length: 33 }, (_, index) => `/root${index}`) },
    { ...value, authorized: false }, { ...value, reason_code: 'other' },
    { ...value, authorization_mode: 'snapshot' }]) {
    assert.throws(() => validateMountedSourcePreview(bad, value.repo_path), /invalid source-boundary preview/);
  }
});

function uri(path, authority = '') {
  return {
    scheme: authority ? 'vscode-remote' : 'file',
    authority,
    path,
    fsPath: path,
    toString: () => authority ? `vscode-remote://${authority}${path}` : `file://${path}`,
  };
}

function windowsUri(fsPath) {
  const path = `/${fsPath.replaceAll('\\', '/')}`;
  return {
    scheme: 'file', authority: '', path, fsPath,
    toString: () => `file://${path}`,
  };
}

test('source target chooses the longest owning root and preserves the exact nested directory', () => {
  const parent = { name: 'parent', index: 0, uri: uri('/workspace') };
  const child = { name: 'child', index: 1, uri: uri('/workspace/nested') };
  const target = sourceTargetForUri(uri('/workspace/nested/service'), [parent, child]);
  assert.equal(target.kind, 'directory');
  assert.equal(target.owner, child);
  assert.equal(target.key, 'file:///workspace/nested');
  assert.equal(target.label, 'service');
  assert.equal(target.uri.toString(), 'file:///workspace/nested/service');
  assert.equal(target.repoPath, '/workspace/nested');
  assert.equal(target.targetPath, 'service');
  assert.equal(target.folder, child);
  assert.equal(target.authorizationMode, 'mounted');
});

test('source target rejects folders outside every open root and mismatched authorities', () => {
  const local = { name: 'local', index: 0, uri: uri('/workspace') };
  const duplicate = { name: 'duplicate', index: 2, uri: uri('/workspace') };
  const remote = { name: 'remote', index: 1, uri: uri('/workspace', 'wsl+Ubuntu') };
  assert.throws(() => sourceTargetForUri(uri('/outside'), [local]), /not inside an open workspace/);
  assert.throws(
    () => sourceTargetForUri(uri('/workspace/nested'), [local, duplicate]),
    /more than one equally specific workspace root/,
  );
  assert.throws(
    () => sourceTargetForUri(uri('/workspace/project', 'wsl+Debian'), [remote]),
    /not inside an open workspace/,
  );
});

test('file context resolves exactly one deepest owning workspace root', () => {
  const parent = { name: 'parent', index: 0, uri: uri('/workspace') };
  const child = { name: 'child', index: 1, uri: uri('/workspace/nested') };
  assert.equal(
    workspaceOwnerForFileUri(uri('/workspace/nested/src/index.ts'), [parent, child]),
    child,
  );
});

test('file source target preserves the exact relative file under its deepest owner', () => {
  const parent = { name: 'parent', index: 0, uri: uri('/workspace') };
  const child = { name: 'child', index: 1, uri: uri('/workspace/nested') };
  const target = sourceTargetForFileUri(
    uri('/workspace/nested/k8s/deployment.yaml'),
    [parent, child],
  );
  assert.equal(target.kind, 'file');
  assert.equal(target.owner, child);
  assert.equal(target.folder, child);
  assert.equal(target.repoPath, '/workspace/nested');
  assert.equal(target.targetPath, 'k8s/deployment.yaml');
  assert.equal(target.key, 'file:///workspace/nested');
  assert.equal(target.label, 'deployment.yaml');
});

test('file source target accepts product languages and rejects unsupported files', () => {
  for (const name of ['app.py', 'frontend.js', 'Dockerfile', 'service.Dockerfile', 'main.tf', 'deployment.yaml']) {
    assert.equal(supportedSourceFileName(name), true, name);
  }
  for (const name of ['binary.png', 'README.md']) {
    assert.equal(supportedSourceFileName(name), false, name);
  }
  const root = { name: 'root', index: 0, uri: uri('/workspace') };
  assert.throws(
    () => sourceTargetForFileUri(uri('/workspace/image.png'), [root]),
    /file type is not supported/,
  );
});

test('file context fails closed outside roots and for duplicate equally specific roots', () => {
  const local = { name: 'local', index: 0, uri: uri('/workspace') };
  const duplicate = { name: 'duplicate', index: 1, uri: uri('/workspace') };
  assert.throws(
    () => workspaceOwnerForFileUri(uri('/outside/index.ts'), [local]),
    /not inside an open workspace/,
  );
  assert.throws(
    () => workspaceOwnerForFileUri(uri('/workspace/index.ts'), [local, duplicate]),
    /more than one equally specific workspace root/,
  );
});

test('native Windows nested folder and exact file targets use bounded snapshot identities', () => {
  const root = { name: 'project', index: 0, uri: windowsUri(String.raw`C:\work\project`) };
  const nested = windowsUri(String.raw`C:\work\project\services\api`);
  const folderTarget = sourceTargetForUri(nested, [root], 'win32');
  assert.equal(folderTarget.kind, 'directory');
  assert.equal(folderTarget.authorizationMode, 'snapshot');
  assert.match(folderTarget.sourceId, /^[0-9a-f]{64}$/);
  assert.equal(folderTarget.sourceId, sourceTargetForUri(root.uri, [root], 'win32').sourceId);
  assert.equal(folderTarget.repoPath, `/source-snapshots/native-windows/${folderTarget.sourceId}`);
  assert.equal(folderTarget.folder, root);
  assert.equal(folderTarget.targetPath, 'services/api');

  const fileTarget = sourceTargetForFileUri(
    windowsUri(String.raw`C:\work\project\k8s\deployment.yaml`),
    [root],
    'win32',
  );
  assert.equal(fileTarget.kind, 'file');
  assert.equal(fileTarget.authorizationMode, 'snapshot');
  assert.equal(fileTarget.targetPath, 'k8s/deployment.yaml');
  assert.equal(fileTarget.repoPath, `/source-snapshots/native-windows/${fileTarget.sourceId}`);
});

test('Remote WSL nested folder and exact file targets stay mounted and project-relative', () => {
  const root = { name: 'project', index: 0, uri: uri('/home/qa/project', 'wsl+Ubuntu') };
  const folderTarget = sourceTargetForUri(
    uri('/home/qa/project/services/api', 'wsl+Ubuntu'),
    [root],
    'win32',
  );
  assert.equal(folderTarget.authorizationMode, 'mounted');
  assert.equal(folderTarget.repoPath, '/home/qa/project');
  assert.equal(folderTarget.folder, root);
  assert.equal(folderTarget.targetPath, 'services/api');
  const fileTarget = sourceTargetForFileUri(
    uri('/home/qa/project/k8s/deployment.yaml', 'wsl+Ubuntu'),
    [root],
    'win32',
  );
  assert.equal(fileTarget.authorizationMode, 'mounted');
  assert.equal(fileTarget.repoPath, '/home/qa/project');
  assert.equal(fileTarget.targetPath, 'k8s/deployment.yaml');
});


test('SCM repository context binds one exact current Git root and rejects ambiguity before any source access', () => {
  const { sourceControlRepositoryRoot } = require('../../dist/source.js');
  const first = { name: 'first', uri: uri('/workspace/first') };
  const second = { name: 'second', uri: uri('/workspace/second') };
  assert.equal(sourceControlRepositoryRoot([], [first, second]), undefined, 'palette keeps chooser');
  assert.equal(sourceControlRepositoryRoot([undefined], [first, second]), undefined);
  assert.equal(sourceControlRepositoryRoot([{ id: 'git', rootUri: second.uri }], [first, second]), second);
  for (const args of [[null], [[{ id: 'git', rootUri: first.uri }]], [{ id: 'svn', rootUri: first.uri }],
    [{ id: 'git' }], [{ id: 'git', rootUri: uri('/workspace') }], [{ id: 'git', rootUri: uri('/outside') }],
    [{ id: 'git', rootUri: first.uri }, { id: 'git', rootUri: second.uri }],
    [{ id: 'git', rootUri: { ...first.uri, fsPath: '/workspace/second' } }],
    [{ id: 'git', rootUri: { ...first.uri, query: 'other=1' } }]]) {
    assert.throws(() => sourceControlRepositoryRoot(args, [first, second]), /one current Git repository/);
  }
  assert.throws(() => sourceControlRepositoryRoot([{ id: 'git', rootUri: first.uri }], [first, first]), /one current Git repository/);
  assert.throws(() => sourceControlRepositoryRoot([{ id: 'git', rootUri: first.uri }], []), /one current Git repository/);
});
