const assert = require('node:assert/strict');
const test = require('node:test');
const { sameCanonicalLocalPath } = require('../../dist/canonical-local-path.js');

test('Windows file URI drive-letter case preserves the same canonical path', () => {
  for (const drive of ['C', 'D', 'Z']) {
    const upper = `${drive}:\\Users\\QA\\repository\\.git`;
    const lower = `${drive.toLowerCase()}:\\Users\\QA\\repository\\.git`;
    assert(sameCanonicalLocalPath(upper, lower, 'win32'));
    assert(sameCanonicalLocalPath(lower, upper, 'win32'));
    assert(sameCanonicalLocalPath(upper, upper, 'win32'));
  }
});

test('drive-letter tolerance does not accept changed directories or path aliases', () => {
  const canonical = 'C:\\Users\\QA\\repository';
  for (const requested of ['c:\\users\\QA\\repository', 'c:\\Users\\qa\\repository',
    'D:\\Users\\QA\\repository', 'c:\\Users\\QA\\other', 'c:\\Users\\QA\\.\\repository',
    'c:\\Users\\QA\\other\\..\\repository', 'c:/Users/QA/repository',
    '\\\\?\\C:\\Users\\QA\\repository', 'C:Users\\QA\\repository',
    '\\\\server\\Users\\QA\\repository']) {
    assert.equal(sameCanonicalLocalPath(canonical, requested, 'win32'), false, requested);
  }
  assert.equal(sameCanonicalLocalPath('\\\\server\\Share', '\\\\server\\share', 'win32'), false);
});

test('other platforms retain exact canonical comparison', () => {
  for (const platform of ['darwin', 'linux']) {
    assert(sameCanonicalLocalPath('/home/qa/repo', '/home/qa/repo', platform));
    assert.equal(sameCanonicalLocalPath('/home/qa/repo', '/home/QA/repo', platform), false);
    assert.equal(sameCanonicalLocalPath('/home/qa/repo', '/home/qa/link', platform), false);
    assert.equal(sameCanonicalLocalPath('C:\\QA', 'c:\\QA', platform), false);
  }
});
