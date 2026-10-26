import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import type { Finding } from '../src/api.ts';

test('rendered evidence retains source text, safe overlays and honest captured origins', async (context) => {
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  context.after(async () => { await vite.close(); });
  const { FindingEvidence, sameFindingEvidence } = await vite.ssrLoadModule('/src/FindingEvidencePane.tsx');
  const finding: Finding = { id: 1, scan_id: 3, scan_finding_number: 1, display_id: 'S3-F001',
    scanner: 'opengrep', rule_id: 'dynamic-code', severity: 'high', file_path: 'src/app.ts',
    message: 'Dynamic code execution.', fingerprint: 'fixture', suppressed: false,
    lifecycle_status: 'open', gate_exempt: false, gate_effect: 'blocking', occurrence_count: 1,
    is_repeat: false, revision: 1, code_snippet: 'eval("<script>")', start_line: 20,
    end_line: 20, start_column: 900, end_column: 904, metadata_json: { snippet_start_line: 20,
      snippet_truncated: true, snippet_line_truncated: true, snippet_column_start: 900 } };
  const render = (value: Finding) => renderToStaticMarkup(createElement(FindingEvidence,
    { finding: value, snippetHeight: 300, setSnippetHeight() {} }));
  const html = render(finding);
  assert.match(html, /starting at source column 900/u);
  assert.match(html, /this is not the complete source file/u);
  assert.match(html, /class="code-column-ranges" aria-hidden="true"/u);
  assert.match(html, /<mark>eval<\/mark>/u);
  assert.match(html, /Offender line 20, column 900 through column 904/u);
  assert.doesNotMatch(html, /<script>/u);
  assert.match(html, /&lt;script&gt;/u);
  const missingOrigin = render({ ...finding, metadata_json: { snippet_start_line: 20, snippet_line_truncated: true } });
  assert.doesNotMatch(missingOrigin, /code-column-ranges/u);
  assert.match(missingOrigin, /class="code-row offender"/u);
  const noSnippet = render({ ...finding, scanner: 'grype', code_snippet: undefined, metadata_json: {} });
  assert.match(noSnippet, /No source snippet was captured for this dependency vulnerability/u);
  assert.match(noSnippet, /disabled=""/u);
  const props = { finding, snippetHeight: 300, setSnippetHeight() {} };
  assert.equal(sameFindingEvidence(props, props), true);
  for (const update of [{ scanner: 'grype' }, { rule_id: 'CVE-2026-1234' }, { message: 'Updated scanner explanation.' },
    { metadata_json: { ...finding.metadata_json, snippet_column_start: 901 } }]) {
    assert.equal(sameFindingEvidence(props, { ...props, finding: { ...finding, ...update } }), false);
  }
  assert.equal(sameFindingEvidence(props, { ...props, finding: { ...finding, ai_verdict: 'fixed' } }), true,
    'independent Advisor updates do not remount immutable source evidence');
});
