import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

// Reviewed runtime notices, not the complete build dependency tree or a legal
// clearance decision. A changed emitted package set requires explicit review.
const PACKAGES = ['highlight.js', 'lucide-react', 'react-dom', 'react', 'scheduler'];
const SHA256 = /^[a-f0-9]{64}$/u;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const decode = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);

function readStable(path, maximum) {
  const before = lstatSync(path);
  assert(before.isFile() && before.nlink === 1 && before.size > 0 && before.size <= maximum,
    'expected a bounded regular input');
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd);
    for (const key of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(opened[key], before[key]);
    const buffer = Buffer.alloc(before.size + 1);
    let length = 0, count;
    while (length < buffer.length && (count = readSync(fd, buffer, length, buffer.length - length, null)) > 0) length += count;
    assert.equal(length, before.size, 'input changed while reading');
    const after = fstatSync(fd), named = lstatSync(path);
    for (const key of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']) {
      assert.equal(after[key], opened[key]); assert.equal(named[key], opened[key]);
    }
    assert(named.isFile() && named.nlink === 1);
    return buffer.subarray(0, length);
  } finally { closeSync(fd); }
}

/** Audit already-built notice bytes without invoking a build, network or editor.
 * Installed package texts are comparison inputs; npm integrity/rebuild proof and
 * the bundler's complete module inclusion graph remain separate obligations. */
export function auditWebNotices({ webRoot, notice, expectedNoticeSha256, expectedLockSha256 }) {
  assert(isAbsolute(webRoot) && isAbsolute(notice), 'use absolute input paths');
  assert(SHA256.test(expectedNoticeSha256) && SHA256.test(expectedLockSha256), 'reviewed digests required');
  const noticeBytes = readStable(notice, 1024 * 1024);
  assert.equal(hash(noticeBytes), expectedNoticeSha256, 'notice digest mismatch');
  const lockBytes = readStable(resolve(webRoot, 'package-lock.json'), 4 * 1024 * 1024);
  assert.equal(hash(lockBytes), expectedLockSha256, 'lock digest mismatch');
  const lock = JSON.parse(decode(lockBytes));
  assert.equal(lock.lockfileVersion, 3);
  const actual = decode(noticeBytes);
  const headings = [...actual.matchAll(/^## (.+) - (.+) \((.+)\)$/gmu)];
  assert.deepEqual(headings.map(match => match[1]), PACKAGES, 'emitted notice package set changed');
  const records = [];
  for (const [index, name] of PACKAGES.entries()) {
    for (const directory of [webRoot, resolve(webRoot, 'node_modules'), resolve(webRoot, 'node_modules', name)]) {
      assert(lstatSync(directory).isDirectory(), 'linked package directories are not audit inputs');
    }
    const packageBytes = readStable(resolve(webRoot, 'node_modules', name, 'package.json'), 128 * 1024);
    const metadata = JSON.parse(decode(packageBytes)), pinned = lock.packages?.[`node_modules/${name}`];
    assert(pinned && !pinned.link && typeof pinned.integrity === 'string' && pinned.integrity.startsWith('sha512-'));
    assert.equal(metadata.name, name); assert.equal(metadata.version, pinned.version);
    assert.equal(metadata.license, pinned.license);
    assert.equal(headings[index][2], pinned.version); assert.equal(headings[index][3], pinned.license);
    const licenseBytes = readStable(resolve(webRoot, 'node_modules', name, 'LICENSE'), 256 * 1024);
    const text = decode(licenseBytes).trim();
    assert(text.length > 100, 'license text missing or implausibly short');
    const start = headings[index].index + headings[index][0].length;
    const end = headings[index + 1]?.index ?? actual.length;
    // Vite trims outer whitespace. No internal text, clauses or attribution may
    // be dropped, even when the package's short identifier names just one license.
    assert.equal(actual.slice(start, end).trim(), text, `incomplete or changed ${name} license text`);
    records.push({ name, version: pinned.version, identifier: pinned.license,
      npm_integrity: pinned.integrity, package_sha256: hash(packageBytes),
      license_sha256: hash(licenseBytes), license_bytes: licenseBytes.length });
  }
  return { schema: 'lomo-web-notice-audit/v1', passed: true, platform_qualified: false,
    legal_clearance: false, module_inclusion_verified: false,
    notice_sha256: hash(noticeBytes), notice_bytes: noticeBytes.length,
    lock_sha256: hash(lockBytes), packages: records };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({ options: {
      'web-root': { type: 'string' }, notice: { type: 'string' },
      'expected-notice-sha256': { type: 'string' }, 'expected-lock-sha256': { type: 'string' },
    }, allowPositionals: false });
    const result = auditWebNotices({ webRoot: values['web-root'], notice: values.notice,
      expectedNoticeSha256: values['expected-notice-sha256'], expectedLockSha256: values['expected-lock-sha256'] });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch {
    // Do not print compared license/archive contents through assertion errors.
    process.stderr.write('Web notice audit failed: check exact input paths, digests, package versions and complete license texts.\n');
    process.exitCode = 1;
  }
}
