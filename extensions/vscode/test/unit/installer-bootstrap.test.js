const assert = require('node:assert/strict');
const { mkdtemp, chmod, link, lstat, mkdir, writeFile } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  FIRST_OWNER_BOOTSTRAP_FILE_NAME,
  FirstOwnerBootstrapError,
  consumeFirstOwnerBrowserBootstrap,
  firstOwnerBootstrapPath,
  readFirstOwnerBrowserBootstrap,
} = require('../../dist/installer-bootstrap.js');

const ENDPOINT = 'http://127.0.0.1:8080';
const TOKEN = 'a'.repeat(43);

test('native first-owner state uses exact LOCALAPPDATA or USERPROFILE without WSL path guessing', () => {
  const filename = FIRST_OWNER_BOOTSTRAP_FILE_NAME;
  assert.equal(firstOwnerBootstrapPath({ LOCALAPPDATA: String.raw`C:\Users\qa\AppData\Local`, HOME: '/home/qa',
    XDG_STATE_HOME: '/home/qa/.state' }, 'win32'), String.raw`C:\Users\qa\AppData\Local\lomo-kodesec` + '\\' + filename);
  assert.equal(firstOwnerBootstrapPath({ USERPROFILE: String.raw`D:\Users\qa` }, 'win32'),
    String.raw`D:\Users\qa\AppData\Local\lomo-kodesec` + '\\' + filename);
  assert.equal(firstOwnerBootstrapPath({ KODESEC_STATE_DIR: String.raw`D:\Lomo\state`, LOCALAPPDATA: String.raw`C:\Users\qa` }, 'win32'),
    String.raw`D:\Lomo\state` + '\\' + filename);
  for (const invalid of ['/home/qa', String.raw`\\wsl.localhost\Ubuntu\home\qa`, String.raw`C:state`,
    String.raw`C:\qa\..\state`, String.raw`C:\qa\state.`, String.raw`C:\qa\state:stream`, String.raw`\\?\C:\qa\state`]) {
    assert.equal(firstOwnerBootstrapPath({ KODESEC_STATE_DIR: invalid, LOCALAPPDATA: String.raw`C:\Users\qa` }, 'win32'), undefined);
    assert.equal(firstOwnerBootstrapPath({ LOCALAPPDATA: invalid, USERPROFILE: String.raw`C:\Users\qa` }, 'win32'), undefined);
  }
  assert.equal(firstOwnerBootstrapPath({ HOME: '/home/qa', XDG_STATE_HOME: '/home/qa/.state', LOCALAPPDATA: String.raw`C:\Users\qa` }, 'linux'),
    `/home/qa/.state/lomo-kodesec/${filename}`);
  assert.equal(firstOwnerBootstrapPath({ HOME: '/home/qa' }, 'win32'), undefined);
});

async function fixture() {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'lomo-first-owner-parent-'));
  const state = path.join(parent, 'lomo-kodesec');
  await mkdir(state, { mode: 0o700 });
  await chmod(state, 0o700);
  const artifact = path.join(state, FIRST_OWNER_BOOTSTRAP_FILE_NAME);
  const payload = JSON.stringify({
    bootstrap_token: TOKEN,
    control_origin: ENDPOINT,
    installation_id: '123456abcdef',
    v: 1,
  }) + '\n';
  await writeFile(artifact, payload, { encoding: 'utf8', mode: 0o600 });
  await chmod(artifact, 0o600);
  return { artifact, parent, state };
}

test('first-owner handoff is exact-loopback, owner-private, single-use, and compare-before-delete', async () => {
  const { artifact, state } = await fixture();
  assert.equal(firstOwnerBootstrapPath({ KODESEC_STATE_DIR: state }), artifact);
  assert.equal(firstOwnerBootstrapPath({ KODESEC_STATE_DIR: 'relative/state' }), undefined);

  const claim = await readFirstOwnerBrowserBootstrap(ENDPOINT, artifact);
  assert(claim);
  assert.equal(claim.bootstrapToken, TOKEN);
  assert.equal(claim.controlOrigin, ENDPOINT);
  assert.equal(claim.installationId, '123456abcdef');
  assert.doesNotMatch(JSON.stringify(claim.identity), new RegExp(TOKEN));

  await consumeFirstOwnerBrowserBootstrap(claim);
  await assert.rejects(lstat(artifact), (error) => error.code === 'ENOENT');
  await consumeFirstOwnerBrowserBootstrap(claim);
});

test('first-owner handoff rejects endpoint mismatch, insecure mode, hard links, and changed content', async () => {
  const mismatched = await fixture();
  await assert.rejects(
    readFirstOwnerBrowserBootstrap('http://127.0.0.1:8081', mismatched.artifact),
    FirstOwnerBootstrapError,
  );

  const insecure = await fixture();
  if (process.platform !== 'win32') {
    await chmod(insecure.artifact, 0o644);
    await assert.rejects(readFirstOwnerBrowserBootstrap(ENDPOINT, insecure.artifact), FirstOwnerBootstrapError);
  }

  const linked = await fixture();
  await link(linked.artifact, `${linked.artifact}.copy`);
  await assert.rejects(readFirstOwnerBrowserBootstrap(ENDPOINT, linked.artifact), FirstOwnerBootstrapError);

  const changed = await fixture();
  const claim = await readFirstOwnerBrowserBootstrap(ENDPOINT, changed.artifact);
  assert(claim);
  await writeFile(changed.artifact, JSON.stringify({
    bootstrap_token: 'b'.repeat(43),
    control_origin: ENDPOINT,
    installation_id: '123456abcdef',
    v: 1,
  }) + '\n', { encoding: 'utf8', mode: 0o600 });
  await chmod(changed.artifact, 0o600);
  await assert.rejects(consumeFirstOwnerBrowserBootstrap(claim), FirstOwnerBootstrapError);
  assert.equal((await lstat(changed.artifact)).isFile(), true);
});
