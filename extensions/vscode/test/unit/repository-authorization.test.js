const assert = require('node:assert/strict');
const test = require('node:test');
const { reviewedRepositoryAuthorizationCommand } = require('../../dist/repository-authorization.js');

test('reviewed batch command preserves exact Unicode child paths without authorizing their parent', () => {
  const roots = Array.from({ length: 10 }, (_, index) => `/workspace/team 日本語/repo ${index}`);
  const command = reviewedRepositoryAuthorizationCommand(roots, '012345abcdef');
  const match = /^KODESEC_EXPECT_INSTALLATION_ID=012345abcdef KODESEC_SOURCE_ROOTS_B64=([A-Za-z0-9_-]+) make apply-source$/u.exec(command);
  assert.ok(match);
  assert.deepEqual(JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8')), roots);
  assert.ok(!command.includes('/workspace') && !roots.includes('/workspace/team 日本語'));
});

test('batch review refuses ambiguous scope, shell interpolation and unbound installation', () => {
  for (const roots of [[], ['/'], ['/home'], ['/System/Volumes/Data/home'], ['/app/config'],
    ['/work/repo', '/work/repo'], ['/work/repo', '/work/repo/sub'], ['/work/../root'],
    ['/work/$(touch sentinel)'], ['/work/quote"'], ['/work/repo\nnext'], ['/work/\ud800'],
    Array.from({ length: 33 }, (_, index) => `/work/repo${index}`), ['/work/' + 'x'.repeat(4096)]]) {
    assert.equal(reviewedRepositoryAuthorizationCommand(roots, '012345abcdef'), null);
  }
  for (const identity of [undefined, null, '', 'ABCDEF012345', '012345abcdef;touch x']) {
    assert.equal(reviewedRepositoryAuthorizationCommand(['/work/repo'], identity), null);
  }
});
