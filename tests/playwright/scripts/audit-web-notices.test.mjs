import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { auditWebNotices } from './audit-web-notices.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const names = ['highlight.js', 'lucide-react', 'react-dom', 'react', 'scheduler'];
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'lomo-web-notices-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const lock = { lockfileVersion: 3, packages: {} };
  let notices = '# Licenses\n';
  for (const name of names) {
    const dir = join(root, 'node_modules', name);
    mkdirSync(dir, { recursive: true });
    const metadata = { name, version: '1.0.0', license: 'MIT' };
    lock.packages[`node_modules/${name}`] = { ...metadata, integrity: `sha512-${'a'.repeat(86)}==` };
    // Two notices in one LICENSE exercise the Lucide/Feather preservation case.
    const license = `Copyright ${name}\n${'Permission and warranty text. '.repeat(6)}\n\nAdditional derived-work attribution.\n`;
    writeFileSync(join(dir, 'package.json'), JSON.stringify(metadata));
    writeFileSync(join(dir, 'LICENSE'), license);
    notices += `\n## ${name} - 1.0.0 (MIT)\n\n${license}`;
  }
  const notice = join(root, 'THIRD_PARTY_LICENSES.md');
  writeFileSync(notice, notices); writeFileSync(join(root, 'package-lock.json'), JSON.stringify(lock));
  return { root, notice, audit: () => auditWebNotices({ webRoot: root, notice,
    expectedNoticeSha256: hash(readFileSync(notice)),
    expectedLockSha256: hash(readFileSync(join(root, 'package-lock.json'))) }) };
}

test('compares every full license including derived-work attribution, with scoped evidence', t => {
  const f = fixture(t), result = f.audit();
  assert.equal(result.passed, true); assert.equal(result.legal_clearance, false);
  assert.equal(result.platform_qualified, false); assert.equal(result.module_inclusion_verified, false);
  assert.deepEqual(result.packages.map(row => row.name), names);
  assert(result.packages.every(row => /^[a-f0-9]{64}$/u.test(row.license_sha256)));
});

for (const [name, change] of [
  ['missing package', text => text.slice(0, text.indexOf('\n## scheduler'))],
  ['duplicate package', text => text + '\n## react - 1.0.0 (MIT)\n'],
  ['unknown package', text => text + '\n## unexpected - 1.0.0 (MIT)\n'],
  ['wrong version', text => text.replace('highlight.js - 1.0.0', 'highlight.js - 2.0.0')],
  ['wrong identifier', text => text.replace('(MIT)', '(ISC)')],
  ['missing derived notice', text => text.replace('Additional derived-work attribution.', '')],
  ['altered license clause', text => text.replace('Permission and warranty', 'No warranty')],
]) test(`refuses ${name} even when the notice digest is deliberately rebound`, t => {
  const f = fixture(t); writeFileSync(f.notice, change(readFileSync(f.notice, 'utf8')));
  assert.throws(f.audit);
});

test('rejects installation metadata that differs from the lock', t => {
  const f = fixture(t), path = join(f.root, 'node_modules', 'react', 'package.json');
  writeFileSync(path, JSON.stringify({ name: 'react', version: '2.0.0', license: 'MIT' }));
  assert.throws(f.audit);
});
test('rejects missing and linked license texts', t => {
  const f = fixture(t), path = join(f.root, 'node_modules', 'react', 'LICENSE');
  rmSync(path); assert.throws(f.audit);
  symlinkSync(join(f.root, 'node_modules', 'react-dom', 'LICENSE'), path); assert.throws(f.audit);
});
test('rejects linked package directories', t => {
  const f = fixture(t), path = join(f.root, 'node_modules', 'react');
  rmSync(path, { recursive: true }); symlinkSync(join(f.root, 'node_modules', 'react-dom'), path);
  assert.throws(f.audit);
});
test('requires the reviewed artifact and lock digests', t => {
  const f = fixture(t), args = { webRoot: f.root, notice: f.notice,
    expectedNoticeSha256: hash(readFileSync(f.notice)),
    expectedLockSha256: hash(readFileSync(join(f.root, 'package-lock.json'))) };
  assert.throws(() => auditWebNotices({ ...args, expectedNoticeSha256: '0'.repeat(64) }));
  assert.throws(() => auditWebNotices({ ...args, expectedLockSha256: '0'.repeat(64) }));
});
test('rejects oversized notice and license inputs', t => {
  const f = fixture(t); writeFileSync(join(f.root, 'node_modules', 'react', 'LICENSE'), 'a'.repeat(256 * 1024 + 1));
  assert.throws(f.audit); writeFileSync(f.notice, 'a'.repeat(1024 * 1024 + 1)); assert.throws(f.audit);
});
