const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const test = require('node:test');
const { trivyMessagePresentation } = require('../../dist/findingMessage.js');
const cases = require('../fixtures/finding-titles.json');

test('Web and IDE use the same bounded message projection', () => {
  const native = readFileSync(resolve(__dirname, '../../src/findingMessage.ts'), 'utf8').trim();
  const web = readFileSync(resolve(__dirname, '../../../../apps/web/src/findingEvidence.ts'), 'utf8');
  assert(web.includes(native), 'independently bundled projections must stay identical');
});

test('actual Trivy formats retain useful labels through compact and multiline transport', () => {
  for (const { message, kind, title } of cases) {
    for (const input of [message, message.replaceAll('\n', ' '), message.replaceAll('\n', '\r\n')]) {
      assert.deepEqual(trivyMessagePresentation('trivy', input), { kind, title });
      assert.equal(trivyMessagePresentation('other', input), undefined);
    }
  }
});

test('unknown and oversized messages are not interpreted as structured evidence', () => {
  for (const message of ['Artifact: unsupported layout', 'Package: unsupported layout',
    cases[0].message.replace('Severity: CRITICAL', 'Severity: maybe'),
    cases[0].message.replace('Secret AWS Access Key ID', 'Secret '),
    cases[1].message.replace('Message:', 'Explanation:'),
    cases[2].message.replace('CVE-2024-34069', 'unrecognized-id'),
    cases[0].message + 'x'.repeat(20000)]) {
    assert.equal(trivyMessagePresentation('trivy', message), undefined);
  }
});
