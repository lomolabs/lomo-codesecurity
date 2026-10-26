import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import type { Health, Summary } from '../src/api.ts';

test('Overview distinguishes missing counts from real zero and preserves retained summary on health loss', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { Overview } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const health: Health = { ok: true, version: '0.1.0', db: true, scanner: true, worker: true,
    ai: { mode: 'off', available: false, base_url: '', model: '', thinking: false, models: [] } };
  const empty: Summary = { projects: 0, scans: 0, findings: 0, finding_occurrences: 0, artifacts: 0,
    severity_counts: {}, scanner_counts: {}, scanner_severity_counts: {}, top_rules: [], recent_scans: [] };
  const render = (summary: Summary | null, observedHealth: Health | null = health) => renderToStaticMarkup(createElement(Overview, {
    surface: { 'data-route-surface': 'overview', inert: false }, health: observedHealth, summary, scans: [],
    advisorPresentation: { label: 'Off', detail: 'Advisor is optional.', model: null, pill: 'pending' },
    setView() {},
    openFindings() {},
  }));
  const assertCounters = (html: string, values: Array<string | number>) => {
    for (const [index, label] of ['Projects', 'Scans', 'Unique Findings', 'Artifacts'].entries()) {
      assert.ok(html.includes(`<dt>${label}</dt><dd>${values[index]}</dd>`), `${label} must show its observed value`);
    }
  };
  for (const observedHealth of [health, null]) {
    const pending = render(null, observedHealth);
    assertCounters(pending, Array(4).fill('Not loaded'));
    assert.match(pending, /role="status">Overview counts have not loaded yet\./u);
    assert.equal((pending.match(/<(?:dd|strong)>Not loaded<\/(?:dd|strong)>/gu) || []).length, 9,
      'four summary values and five nonduplicated severity counts retain the unknown distinction');
    assert.match(pending, /Scanner findings have not loaded yet\./u);
    assert.match(pending, /Scan history has not loaded yet\./u);
    assert.doesNotMatch(pending, /<strong>0<\/strong>|No scanner findings have been recorded yet\./u);
  }
  const zero = render(empty);
  assertCounters(zero, [0, 0, 0, 0]);
  assert.equal((zero.match(/<(?:dd|strong)>0<\/(?:dd|strong)>/gu) || []).length, 9);
  assert.match(zero, /No scanner findings have been recorded yet\./u);
  assert.doesNotMatch(zero, /Not loaded|have not loaded yet/u);

  const populated: Summary = { ...empty, projects: 3, scans: 11, findings: 54, artifacts: 10,
    severity_counts: { high: 54 }, scanner_counts: { bearer: 54 } };
  for (const observedHealth of [health, null]) {
    const html = render(populated, observedHealth);
    assertCounters(html, [3, 11, 54, 10]);
    assert.match(html, /<span>bearer<\/span><strong>54<\/strong>/u);
    assert.doesNotMatch(html, /Not loaded|have not loaded yet/u,
      'health loss must not erase the last loaded summary; the existing global stale-data notice owns freshness');
  }
});
