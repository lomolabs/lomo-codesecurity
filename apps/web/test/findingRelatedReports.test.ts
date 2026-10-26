import assert from 'node:assert/strict';
import test from 'node:test';

import type { Finding } from '../src/api';
import { otherReportsAtLocation } from '../src/findingRelatedReports.ts';

function finding(id: number, overrides: Partial<Finding> = {}): Finding {
  return {
    id, scan_id: 41, scan_finding_number: id, display_id: `S41-F${id}`,
    scanner: 'opengrep', rule_id: `rule-${id}`, severity: 'high',
    file_path: 'src/app.py', start_line: 4, end_line: 4, start_column: 2, end_column: 8,
    message: `Report ${id}`, fingerprint: `fingerprint-${id}`, suppressed: false,
    lifecycle_status: 'open', gate_exempt: false, gate_effect: 'blocking',
    occurrence_count: 1, is_repeat: false, revision: 1, ...overrides,
  };
}

const view = (items: readonly Finding[]) => ({ projectId: 7, scanId: 41, findingsRevision: 3, items });

test('overlapping reports preserve every independent identity, severity and lifecycle in page order', () => {
  const selected = finding(1, { findings_revision: 3, occurrence_count: 9, is_repeat: true });
  const critical = finding(2, { scanner: 'bearer', severity: 'critical' });
  const excluded = finding(3, { severity: 'low', lifecycle_status: 'ignore', suppressed: true, gate_effect: 'excluded' });
  const page = Object.freeze([excluded, selected, critical]);
  const related = otherReportsAtLocation(view(page), selected, 7);
  assert.deepEqual(related, [excluded, critical]);
  assert.equal(related[0], excluded);
  assert.equal(related[1], critical);
  assert.equal(page.length, 3);
  assert.equal(selected.occurrence_count, 9); // Historical repeats are not location peers.
});

test('repository, run, collection and finding revision boundaries refuse stale or mixed views', () => {
  const selected = finding(1, { findings_revision: 3 });
  const peer = finding(2);
  assert.deepEqual(otherReportsAtLocation(view([selected, peer]), selected, 8), []);
  for (const overrides of [{ scan_id: 42 }, { findings_revision: 4 }, { revision: 2 },
    { fingerprint: 'changed' }, { scanner: 'changed' }, { rule_id: 'changed' }, { file_path: 'other.py' }]) {
    assert.deepEqual(otherReportsAtLocation(view([selected, peer]), { ...selected, ...overrides }, 7), []);
  }
  assert.deepEqual(otherReportsAtLocation(view([peer]), selected, 7), []);
  assert.deepEqual(otherReportsAtLocation(view([selected, { ...peer, scan_id: 42 }]), selected, 7), []);
  assert.deepEqual(otherReportsAtLocation(view([selected, { ...peer, findings_revision: 4 }]), selected, 7), []);
});

test('same line alone, unknown coordinates and differently cased paths do not imply identical location', () => {
  const selected = finding(1);
  for (const file_path of ['', ' ']) {
    const missing = finding(1, { file_path });
    assert.deepEqual(otherReportsAtLocation(view([missing, finding(2, { file_path })]), missing, 7), []);
  }
  for (const overrides of [{ start_column: 3 }, { end_column: 9 }, { end_line: 5 },
    { file_path: 'src/App.py' }, { file_path: './src/app.py' }, { start_line: undefined },
    { end_line: undefined }, { start_column: undefined }, { start_column: 0 }]) {
    assert.deepEqual(otherReportsAtLocation(view([selected, finding(2, overrides)]), selected, 7), []);
  }
  const lineOnly = finding(1, { start_column: undefined, end_column: undefined });
  const linePeer = finding(2, { start_column: undefined, end_column: undefined });
  assert.deepEqual(otherReportsAtLocation(view([lineOnly, linePeer]), lineOnly, 7), [linePeer]);
  assert.deepEqual(otherReportsAtLocation(view([finding(1, { end_line: undefined }), linePeer]),
    finding(1, { end_line: undefined }), 7), []);
});
