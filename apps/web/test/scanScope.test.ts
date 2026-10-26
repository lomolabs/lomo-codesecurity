import assert from 'node:assert/strict';
import test from 'node:test';

import { scanCoverageTarget, sourceCoverageFailures } from '../src/scanScope.ts';


function scanWithScope(scope: unknown) {
  return { scanner_summary: { scope } };
}


test('scan coverage renders the exact workspace, folder, and file target', () => {
  assert.deepEqual(scanCoverageTarget(scanWithScope({ kind: 'workspace', target_path: null })), {
    kind: 'workspace', label: 'Entire registered codebase', path: null,
  });
  assert.deepEqual(scanCoverageTarget(scanWithScope({ kind: 'directory', target_path: 'infra' })), {
    kind: 'directory', label: 'Folder · infra', path: 'infra',
  });
  assert.deepEqual(scanCoverageTarget(scanWithScope({ kind: 'file', target_path: 'app.py' })), {
    kind: 'file', label: 'File · app.py', path: 'app.py',
  });
});


test('scan coverage fails closed for malformed or unsafe target evidence', () => {
  for (const scope of [
    null,
    { kind: 'directory' },
    { kind: 'file', target_path: 'app.py\u0000forged' },
    { kind: 'unexpected', target_path: 'infra' },
  ]) {
    assert.deepEqual(scanCoverageTarget(scanWithScope(scope)), {
      kind: 'unavailable', label: 'Coverage target unavailable', path: null,
    });
  }
});


test('source coverage explains limits without exposing raw diagnostic paths', () => {
  const coverage = (source_coverage: unknown) => sourceCoverageFailures({ scanner_summary: { source_coverage } });
  assert.deepEqual(coverage({ complete: false, max_file_bytes: 1_048_576,
    reason_counts: { eligible_file_too_large: 1 } }), ['1 code file exceeds the 1 MiB per-file analysis limit.']);
  assert.deepEqual(coverage({ complete: false, max_file_bytes: 128,
    reason_counts: { eligible_file_too_large: 2, eligible_file_unreadable: 1 } }),
    ['2 code files exceed the 128 bytes per-file analysis limit.', '1 eligible file could not be read.']);
  assert.deepEqual(coverage({ complete: true, reason_counts: { eligible_file_too_large: 1 } }), []);
  const malformed = coverage({ complete: false, max_file_bytes: '/private/hidden.py',
    reason_counts: { '/private/hidden.py': 1, eligible_file_too_large: '1', eligible_file_unreadable: -1 } });
  assert.deepEqual(malformed, ['Source coverage is incomplete; its detailed reason is unavailable.']);
  assert.doesNotMatch(malformed.join(''), /private|hidden/);
  assert.deepEqual(coverage(null), []);
});
