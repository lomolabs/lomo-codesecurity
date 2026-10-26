const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath, stat, chmod } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  inspectGitRepository, parseGitPushInput, planGitPush, exportGitTree, readGitRemoteAdvertisement,
} = require('../../dist/git-push-objects.js');
const {
  previewGitHook, installGitHook, observeGitHook, removeGitHook, gitHookScript,
} = require('../../dist/git-push-hook.js');

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, GIT_AUTHOR_NAME: 'Lomo fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Lomo fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  }).trimEnd();
}

async function fixture(t, format = 'sha1') {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lomo-git-push-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source space');
  const remote = path.join(root, 'remote.git');
  await mkdir(source);
  git(root, 'init', '--initial-branch=main', '--object-format=' + format, source);
  git(root, 'init', '--bare', '--object-format=' + format, remote);
  git(source, 'remote', 'add', 'origin', remote);
  return { root, source, remote };
}

async function commit(source, text, name = 'app.py') {
  await writeFile(path.join(source, name), text);
  git(source, 'add', '--', name);
  git(source, 'commit', '-m', 'synthetic fixture');
  return git(source, 'rev-parse', 'HEAD');
}

test('native Windows drive spelling preserves Git identity without admitting directory aliases',
  { skip: process.platform !== 'win32' }, async t => {
    const { source, root } = await fixture(t);
    await commit(source, 'SAFE = True\n');
    const canonical = await realpath(source);
    assert.match(canonical, /^[A-Za-z]:\\/u);
    const lower = canonical[0].toLowerCase() + canonical.slice(1);
    const upper = canonical[0].toUpperCase() + canonical.slice(1);
    const first = await inspectGitRepository(lower);
    assert.deepEqual(await inspectGitRepository(upper), first);
    assert.equal(first.root, canonical);
    assert.equal(first.gitDirectory, await realpath(path.join(source, '.git')));
    assert.equal(first.commonDirectory, first.gitDirectory);
    const nested = path.join(source, 'nested');
    await mkdir(nested);
    await assert.rejects(inspectGitRepository(nested), { code: 'git_root_incomplete' });
    const alias = path.join(root, 'junction');
    await symlink(source, alias, 'junction');
    await assert.rejects(inspectGitRepository(alias), { code: 'git_root_invalid' });
    // NTFS commonly resolves different directory casing to the same inode;
    // only drive-letter case is accepted by the product boundary.
    const directoryCase = canonical.slice(0, -1) + canonical.at(-1).toUpperCase();
    assert.notEqual(directoryCase, canonical);
    await assert.rejects(inspectGitRepository(directoryCase), { code: 'git_root_invalid' });
  });

test('native Windows hooks execute without POSIX mode bits and reject changed bytes',
  { skip: process.platform !== 'win32' }, async t => {
    const {source,remote,root} = await fixture(t);
    await commit(source,'SAFE = True\n');
    const helper=path.join(root,'native-hook.cjs'), configuration=path.join(root,'native-hook.json');
    const observation=path.join(root,'native-hook-input.txt');
    await writeFile(helper,"const fs=require('node:fs');const c=JSON.parse(fs.readFileSync(process.argv[3]));fs.writeFileSync(c.observation,fs.readFileSync(0));process.exit(c.result);\n");
    await writeFile(configuration,JSON.stringify({observation,result:1}));
    const preview=await previewGitHook(source);
    const installed=await installGitHook(preview,gitHookScript(process.execPath,helper,configuration));
    assert.equal((await stat(installed.hookPath)).mode & 0o111,0,'native filesystem must exhibit the reported Windows mode');
    assert.equal(await observeGitHook(preview.repository,installed),'installed');
    assert.throws(()=>git(source,'push','origin','main'));
    assert.equal(git(remote,'for-each-ref','--format=%(refname)'),'');
    assert.match(await readFile(observation,'utf8'),/refs\/heads\/main/);
    await writeFile(configuration,JSON.stringify({observation,result:0}));
    git(source,'push','origin','main');
    assert.equal(git(remote,'rev-parse','refs/heads/main'),git(source,'rev-parse','HEAD'));
    await writeFile(installed.hookPath,'#!/bin/sh\n# changed owned hook\n');
    assert.equal(await observeGitHook(preview.repository,installed),'needs_repair');
    await assert.rejects(removeGitHook(preview.repository,installed),{code:'git_hook_changed'});
    assert.equal(await readFile(installed.hookPath,'utf8'),'#!/bin/sh\n# changed owned hook\n');
  });

test('POSIX hook observation still requires the executable bit',
  { skip: process.platform === 'win32' }, async t => {
    const {source,root}=await fixture(t);await commit(source,'SAFE = True\n');
    const preview=await previewGitHook(source);
    const installed=await installGitHook(preview,gitHookScript(process.execPath,path.join(root,'helper.cjs'),path.join(root,'config.json')));
    await chmod(installed.hookPath,0o600);
    assert.equal(await observeGitHook(preview.repository,installed),'needs_repair');
    await assert.rejects(removeGitHook(preview.repository,installed),{code:'git_hook_changed'});
  });

test('immutable Git export retains documentation assets and refuses the 8 MiB successor', async t => {
  const { source } = await fixture(t);
  const content = Buffer.alloc(5_800_000, 0x89);
  await commit(source, content, 'documentation.png');
  const repository = await inspectGitRepository(source);
  const tree = git(source, 'rev-parse', 'HEAD^{tree}');
  const files = await exportGitTree(repository, tree);
  assert.equal(files.length, 1);
  assert.deepEqual(Buffer.from(files[0].content_base64, 'base64'), content);
  assert.equal(files[0].size_bytes, content.length);
  await commit(source, Buffer.alloc(8 * 1024 * 1024 + 1), 'documentation.png');
  await assert.rejects(exportGitTree(repository, git(source, 'rev-parse', 'HEAD^{tree}')), { code: 'git_blob_limit' });
});

test('owned hook inspection refuses oversized data without replacing it', async t => {
  const { source, root } = await fixture(t);
  await commit(source, 'safe\n');
  const preview = await previewGitHook(source);
  const installed = await installGitHook(preview, gitHookScript(process.execPath,
    path.join(root, 'helper.cjs'), path.join(root, 'settings.json')));
  const replacement = '#!/bin/sh\n' + 'x'.repeat(64 * 1024);
  await writeFile(installed.hookPath, replacement);
  await assert.rejects(observeGitHook(preview.repository, installed), { code: 'git_hook_conflict' });
  assert.equal(await readFile(installed.hookPath, 'utf8'), replacement);
});

test('sha256 immutable metadata and linked-worktree hook refusal are explicit', async t => {
  const { source, root } = await fixture(t, 'sha256');
  const tip = await commit(source, 'synthetic sha256 source\n');
  const repository = await inspectGitRepository(source);
  assert.equal(repository.format, 'sha256');
  const outgoing = await planGitPush(repository, `HEAD ${tip} refs/heads/main ${'0'.repeat(64)}\n`);
  const files = await exportGitTree(repository, outgoing.trees[0]);
  assert.equal(files[0].oid.length, 64);
  assert.equal(Buffer.from(files[0].content_base64, 'base64').toString(), 'synthetic sha256 source\n');
  const worktree = path.join(root, 'linked-worktree');
  git(source, 'worktree', 'add', '-b', 'qa-worktree', worktree);
  await assert.rejects(previewGitHook(worktree), { code: 'git_shared_hook_conflict' });
});

test('immutable outgoing Git coverage and repository-local hook effects', async t => {
  await t.test('parses exact refs without treating display tokens as commands', () => {
    const oid = 'a'.repeat(40), zero = '0'.repeat(40);
    const refs = parseGitPushInput(`HEAD~ ${oid} refs/heads/ünicode ${zero}\n`, 'sha1');
    assert.equal(refs[0].local_ref, 'HEAD~');
    assert.equal(refs[0].remote_ref, 'refs/heads/ünicode');
    assert.throws(() => parseGitPushInput(`HEAD ${oid} refs/heads/main ${zero}\nHEAD ${oid} refs/heads/main ${zero}\n`, 'sha1'), { code: 'push_input_invalid' });
    assert.throws(() => parseGitPushInput(`HEAD ${oid} refs/heads/main ${'b'.repeat(64)}\n`, 'sha1'), { code: 'push_input_invalid' });
    assert.throws(() => parseGitPushInput(`HEAD ${oid} refs/heads/main ${zero}\n\n`, 'sha1'), { code: 'push_input_invalid' });
    assert.deepEqual(parseGitPushInput('', 'sha1'), []);
  });

  await t.test('covers secret-then-removal history, dirty tree isolation, multiple refs and raw blobs', async t => {
    const { source } = await fixture(t);
    const first = await commit(source, 'SAFE = True\n');
    git(source, 'push', 'origin', 'main');
    const secret = await commit(source, 'TOKEN = "bounded-synthetic-history-finding"\n');
    const clean = await commit(source, 'SAFE = True\n');
    await writeFile(path.join(source, 'app.py'), 'DIRTY WORKTREE MUST NOT BE SCANNED\n');
    const repository = await inspectGitRepository(source);
    const plan = await planGitPush(repository, `HEAD ${clean} refs/heads/main ${first}\n`);
    assert.deepEqual(new Set(plan.commits.map(item => item.commit_oid)), new Set([secret, clean]));
    const exports = await Promise.all(plan.trees.map(tree => exportGitTree(repository, tree)));
    const contents = exports.flat().map(file => Buffer.from(file.content_base64, 'base64').toString());
    assert.ok(contents.includes('TOKEN = "bounded-synthetic-history-finding"\n'));
    assert.ok(!contents.some(value => value.includes('DIRTY WORKTREE')));
    const all = await planGitPush(repository, `refs/heads/main ${clean} refs/heads/one ${'0'.repeat(40)}\nrefs/heads/main ${clean} refs/heads/two ${'0'.repeat(40)}\n`);
    assert.equal(all.refs.length, 2);
    assert.equal(all.commits.length, 3);
    assert.equal(all.trees.length, 2, 'identical committed content is deduplicated');
    const deletion = await planGitPush(repository, `(delete) ${'0'.repeat(40)} refs/heads/main ${first}\n`);
    assert.equal(deletion.trees.length, 0);
    assert.notEqual(plan.digest, deletion.digest);
    const forced = await planGitPush(repository, `HEAD ${first} refs/heads/main ${clean}\n`);
    assert.equal(forced.trees.length, 1, 'a rewind still checks the exact new target tree');
    git(source, 'tag', '-a', 'annotated', '-m', 'fixture annotation');
    const tag = git(source, 'rev-parse', 'refs/tags/annotated');
    const tagPlan = await planGitPush(repository, `refs/tags/annotated ${tag} refs/tags/annotated ${'0'.repeat(40)}\n`);
    assert.equal(tagPlan.commits.length, 3);
  });

  await t.test('ignores export-ignore and filters, refuses linked or incomplete source', async t => {
    const { source, root } = await fixture(t);
    await commit(source, 'payload', 'secret.txt');
    await commit(source, 'secret.txt export-ignore\n*.txt filter=danger\n', '.gitattributes');
    git(source, 'config', 'filter.danger.smudge', 'touch SHOULD_NOT_EXECUTE');
    const repository = await inspectGitRepository(source);
    const tree = git(source, 'rev-parse', 'HEAD^{tree}');
    const files = await exportGitTree(repository, tree);
    assert.ok(files.some(file => file.path === 'secret.txt'));
    await assert.rejects(readFile(path.join(source, 'SHOULD_NOT_EXECUTE')), { code: 'ENOENT' });
    await symlink(source, path.join(root, 'linked-source'));
    await assert.rejects(inspectGitRepository(path.join(root, 'linked-source')), { code: 'git_root_invalid' });
    git(source, 'config', 'remote.origin.promisor', 'true');
    await assert.rejects(inspectGitRepository(source), { code: 'git_history_incomplete' });
    git(source, 'config', '--unset', 'remote.origin.promisor');
    await symlink('secret.txt', path.join(source, 'linked-file'));
    git(source, 'add', '--', 'linked-file');
    git(source, 'commit', '-m', 'link fixture');
    await assert.rejects(exportGitTree(repository, git(source, 'rev-parse', 'HEAD^{tree}')), { code: 'git_tree_unsupported' });
    await writeFile(path.join(source, '.git', 'shallow'), git(source, 'rev-parse', 'HEAD') + '\n');
    await assert.rejects(inspectGitRepository(source), { code: 'git_history_incomplete' });
  });

  await t.test('new feature branch bounds full history and ignores unrelated second advertisements', async t => {
    const { source, remote } = await fixture(t);
    await commit(source, 'main\n');
    for (let index = 0; index < 260; index++) git(source, 'commit', '--allow-empty', '-m', 'bounded metadata fixture');
    git(source, 'push', 'origin', 'main');
    git(source, 'checkout', '-b', 'feature');
    const feature = await commit(source, 'feature\n');
    const repository = await inspectGitRepository(source);
    const advertisement = await readGitRemoteAdvertisement(repository, remote);
    await assert.rejects(planGitPush(repository, `refs/heads/feature ${feature} refs/heads/feature ${'0'.repeat(40)}\n`, advertisement), { code: 'git_history_limit' });
    // A stale local tracking ref pretending the new commit is already remote
    // cannot suppress the actual outgoing commit.
    git(source, 'update-ref', 'refs/remotes/origin/main', feature);
    await assert.rejects(planGitPush(repository, `HEAD ${feature} refs/heads/feature ${'0'.repeat(40)}\n`, await readGitRemoteAdvertisement(repository, remote)), { code: 'git_history_limit' });
    await assert.rejects(planGitPush(repository, `HEAD ${feature} refs/heads/main ${'a'.repeat(40)}\n`, advertisement), { code: 'git_remote_changed' });
    git(source, 'config', `url.ext::touch ${path.join(source, 'HELPER_MUST_NOT_EXECUTE')}.insteadOf`, 'https://rewrite.invalid/');
    await assert.rejects(readGitRemoteAdvertisement(repository, 'https://rewrite.invalid/repo'), { code: 'git_remote_unavailable' });
    await assert.rejects(readFile(path.join(source, 'HELPER_MUST_NOT_EXECUTE')), { code: 'ENOENT' });
  });

  await t.test('a newly advertised unrelated branch cannot hide historical secret content', async t => {
    const { source, remote } = await fixture(t);
    const initial = await commit(source, 'safe\n');
    git(source, 'push', 'origin', 'main');
    const secret = await commit(source, 'bounded synthetic history token\n');
    const clean = await commit(source, 'safe\n');
    // Simulate unrelated remote branch appearing only in the second exchange.
    git(source, 'push', 'origin', `${secret}:refs/heads/unrelated`);
    const repository = await inspectGitRepository(source);
    const checked = await planGitPush(repository, `HEAD ${clean} refs/heads/main ${initial}\n`, await readGitRemoteAdvertisement(repository, remote));
    assert.deepEqual(new Set(checked.commits.map(item => item.commit_oid)), new Set([secret, clean]));
    const newBranch = await planGitPush(repository, `HEAD ${clean} refs/heads/new ${'0'.repeat(40)}\n`, await readGitRemoteAdvertisement(repository, remote));
    assert.equal(newBranch.commits.length, 3, 'bounded new branches are supported without trusting a second advertisement');
  });

  await t.test('normal Git invokes the owned hook; rejection preserves remote refs, OFF and explicit bypass do not block', async t => {
    const { source, remote, root } = await fixture(t);
    await commit(source, 'safe\n');
    const helper = path.join(root, 'mechanics-only-fixture.cjs');
    const configuration = path.join(root, 'mechanics-state.json');
    // This fixture is deliberately NOT product gate authority. It proves Git's
    // actual hook/remote-ref effect while the real verifier has separate tests.
    await writeFile(helper, `const fs=require('node:fs'); const args=process.argv.slice(2); const config=JSON.parse(fs.readFileSync(args[1])); const input=fs.readFileSync(0,'utf8'); fs.writeFileSync(config.observation,input); process.exit(config.result);\n`);
    const observation = path.join(root, 'push-input.txt');
    await writeFile(configuration, JSON.stringify({ result: 1, observation }));
    const preview = await previewGitHook(source);
    const installed = await installGitHook(preview, gitHookScript(process.execPath, helper, configuration));
    assert.equal(await observeGitHook(preview.repository, installed), 'installed');
    assert.throws(() => git(source, 'push', 'origin', 'main'));
    assert.equal(git(remote, 'for-each-ref', '--format=%(refname)'), '');
    assert.match(await readFile(observation, 'utf8'), /refs\/heads\/main/);
    await writeFile(configuration, JSON.stringify({ result: 0, observation }));
    git(source, 'push', 'origin', 'main');
    assert.equal(git(remote, 'rev-parse', 'refs/heads/main'), git(source, 'rev-parse', 'HEAD'));
    await commit(source, 'second\n');
    await writeFile(configuration, JSON.stringify({ result: 1, observation }));
    git(source, 'push', '--no-verify', 'origin', 'main');
    assert.equal(git(remote, 'rev-parse', 'refs/heads/main'), git(source, 'rev-parse', 'HEAD'));
    await removeGitHook(preview.repository, installed);
    await assert.rejects(readFile(installed.hookPath), { code: 'ENOENT' });
  });

  await t.test('preserves existing hooks, refuses stale consent and custom hook managers', async t => {
    const { source, root } = await fixture(t);
    await commit(source, 'safe\n');
    const hook = path.join(source, '.git', 'hooks', 'pre-push');
    const preview = await previewGitHook(source);
    await writeFile(hook, '#!/bin/sh\nexit 42\n', { mode: 0o700 });
    const script = gitHookScript(process.execPath, path.join(root, 'helper.cjs'), path.join(root, 'state.json'));
    await assert.rejects(installGitHook(preview, script), { code: 'git_hook_conflict' });
    assert.equal(await readFile(hook, 'utf8'), '#!/bin/sh\nexit 42\n');
    await assert.rejects(previewGitHook(source), { code: 'git_hook_conflict' });
    git(source, 'config', 'core.hooksPath', path.join(root, 'custom'));
    await assert.rejects(previewGitHook(source), { code: 'git_hook_path_conflict' });
    assert.equal(await readFile(hook, 'utf8'), '#!/bin/sh\nexit 42\n');
  });
});
