import assert from 'node:assert/strict';
import test from 'node:test';

import {
  advisorDisclosurePacketFields,
  claimRemoteAdvisorSubmission,
  releaseRemoteAdvisorSubmission,
} from '../src/advisorDisclosure.ts';
import type { AdvisorDisclosurePacket } from '../src/api.ts';


test('remote Advisor preview exposes every exact packet field with LF-normalized multiline evidence', () => {
  const packet: AdvisorDisclosurePacket = {
    schema_version: 1,
    finding: {
      id: 41,
      display_id: 'S7-F1',
      scanner: 'fixture',
      rule_id: 'FIXTURE-1',
      severity: 'high',
      message: 'line one\r\nline two\rline three',
      fingerprint: 'fixture-fingerprint',
    },
    location: {
      file_path: 'src/demo.py',
      start_line: 2,
      start_column: 3,
      end_line: 4,
      end_column: 5,
    },
    repo_context: {
      project: 'vulnerable-demo',
      repo_path: '/workspace/vulnerable-demo',
      remote_url: 'ssh://git@example.test/dark/vulnerable-demo.git',
      scan_id: 7,
      mode: 'full',
      base_ref: 'main~1',
      head_ref: 'main',
    },
    scanner_evidence: {
      code_snippet: 'eval(\r\n  user_input\r\n)',
      metadata: { confidence: 'high', nested: { line: 9 } },
    },
  };

  const fields = advisorDisclosurePacketFields(packet);
  assert.deepEqual(fields.map((field) => field.key), [
    'schema_version',
    'finding.id',
    'finding.display_id',
    'finding.scanner',
    'finding.rule_id',
    'finding.severity',
    'finding.message',
    'finding.fingerprint',
    'location.file_path',
    'location.start_line',
    'location.start_column',
    'location.end_line',
    'location.end_column',
    'repo_context.project',
    'repo_context.repo_path',
    'repo_context.remote_url',
    'repo_context.scan_id',
    'repo_context.mode',
    'repo_context.base_ref',
    'repo_context.head_ref',
    'scanner_evidence.code_snippet',
    'scanner_evidence.metadata',
  ]);
  assert.equal(fields.find((field) => field.key === 'finding.message')?.value, 'line one\nline two\nline three');
  assert.equal(fields.find((field) => field.key === 'scanner_evidence.code_snippet')?.value, 'eval(\n  user_input\n)');
  assert.match(fields.find((field) => field.key === 'scanner_evidence.metadata')?.value || '', /"confidence": "high"/u);
  assert.equal(fields.some((field) => field.value.includes('\r')), false);
});


test('remote Advisor submission ownership is synchronous and admits only one dispatch', () => {
  const ownership = { current: false };

  assert.equal(claimRemoteAdvisorSubmission(ownership), true);
  assert.equal(ownership.current, true);
  assert.equal(claimRemoteAdvisorSubmission(ownership), false);

  releaseRemoteAdvisorSubmission(ownership);
  assert.equal(ownership.current, false);
  assert.equal(claimRemoteAdvisorSubmission(ownership), true);
});
