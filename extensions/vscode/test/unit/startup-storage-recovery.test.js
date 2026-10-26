const assert = require('node:assert/strict');
const test = require('node:test');
const { CodeSecurityRequestError } = require('../../dist/client.js');
const { restoreStartupStorage } = require('../../dist/startup-storage-recovery.js');

const failure = code => new CodeSecurityRequestError('Storage unavailable', undefined, false, { code });

test('normal startup reads once on every platform', async () => {
  for (const platform of ['win32', 'darwin', 'linux']) {
    let reads = 0;
    assert.equal(await restoreStartupStorage(async () => ++reads, new AbortController().signal, () => true, platform), 1);
    assert.equal(reads, 1);
  }
});

test('Windows retries a transient read once and returns the fresh result', async () => {
  let reads = 0;
  const value = await restoreStartupStorage(async () => {
    if (++reads === 1) throw failure('profile_credential_store_unavailable');
    return 'fresh permission-checked result';
  }, new AbortController().signal, () => true, 'win32');
  assert.equal(reads, 2);
  assert.equal(value, 'fresh permission-checked result');
});

test('insecure, corrupt, unconfirmed and other-platform failures never retry', async () => {
  for (const [platform, code] of [
    ['win32', 'profile_credential_store_insecure'], ['win32', 'profile_credential_store_corrupt'],
    ['win32', 'profile_credential_store_write_unconfirmed'],
    ['linux', 'profile_credential_store_unavailable'], ['darwin', 'profile_credential_store_unavailable'],
  ]) {
    let reads = 0;
    const error = failure(code);
    await assert.rejects(restoreStartupStorage(async () => { reads++; throw error; },
      new AbortController().signal, () => true, platform), value => value === error);
    assert.equal(reads, 1);
  }
});

test('a second temporary failure terminates with its actual error', async () => {
  let reads = 0;
  const final = failure('profile_credential_store_unavailable');
  await assert.rejects(restoreStartupStorage(async () => {
    if (++reads === 1) throw failure('profile_credential_store_unavailable');
    throw final;
  }, new AbortController().signal, () => true, 'win32'), value => value === final);
  assert.equal(reads, 2);
});

test('authority cancellation during backoff prevents the second read', async () => {
  const controller = new AbortController();
  let reads = 0;
  const result = restoreStartupStorage(async () => {
    reads++;
    throw failure('profile_credential_store_unavailable');
  }, controller.signal, () => { queueMicrotask(() => controller.abort()); return true; }, 'win32');
  await assert.rejects(result, { name: 'AbortError' });
  assert.equal(reads, 1);
});

test('a changed repository or authority scope prevents the second read', async () => {
  let reads = 0, checks = 0;
  await assert.rejects(restoreStartupStorage(async () => {
    reads++;
    throw failure('profile_credential_store_unavailable');
  }, new AbortController().signal, () => ++checks === 1, 'win32'), { name: 'AbortError' });
  assert.equal(reads, 1);
});
