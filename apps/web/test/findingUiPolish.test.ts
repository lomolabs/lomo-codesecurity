import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

import type { Finding, Scan } from '../src/api.ts';

import { evidenceHeightControl, isEvidenceHeightStepAligned } from '../src/evidenceHeight.ts';
import {
  findingAdvisorVerdictLabel,
  findingBulkActionLimit,
  findingBulkSelectionDisabledReason,
  findingGateEffectLabel,
  findingLifecycleActionDisabledReason,
  findingLifecycleActionLabel,
} from '../src/findingLifecycle.ts';

test('scan evidence notices distinguish live execution, incomplete evidence, and policy failures', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { scanEvidenceNotice } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const scan: Scan = {
    id: 39, project_id: 1, mode: 'full', status: 'partial', gate_decision: 'incomplete',
    gate_reasons: ['Required scanner evidence is incomplete.'], created_at: '2026-09-26T00:00:00Z',
    revision: 1, findings_revision: 1,
    scanner_summary: { tools: [{ id: 'bearer', name: 'Bearer', enabled: true, status: 'failed',
      error: 'bearer_analysis_incomplete:analysis_error,file_timeout' }] },
  };
  const partial = scanEvidenceNotice(scan, 247, 1)!;
  assert.equal(partial.title, 'Scanner evidence is incomplete');
  assert.deepEqual(partial.scannerFailures, ['Bearer (failed): analysis error; file processing timed out. Bearer findings were not published.']);
  assert.match(partial.detail, /247 findings and 1 publishable artifact are preserved for review\./u);
  assert.equal(partial.nextAction, 'Review these scanner failures before starting a new scan. A new scan must finish all required scanners before its gate can pass.');
  assert.doesNotMatch(JSON.stringify(partial), /scanner job|Jobs|retrying/u);
  for (const [status, title] of [
    ['pending', 'Scan is waiting to start'], ['running', 'Scanner execution is in progress'],
    ['analyzing', 'Scan analysis is still in progress'],
  ]) {
    const notice = scanEvidenceNotice({ ...scan, status, gate_decision: 'pending' }, 0, 0)!;
    assert.equal(notice.title, title);
    assert.equal(notice.tone, 'warning');
    assert.deepEqual(notice.scannerFailures, []);
    assert.match(notice.detail, /Wait for a terminal scan/u);
    assert.equal(notice.nextAction, '');
  }
  const cancelled = scanEvidenceNotice({ ...scan, status: 'cancelled' }, 1, 0)!;
  assert.equal(cancelled.title, 'Scan was cancelled');
  assert.match(cancelled.detail, /1 finding is preserved for review/u);
  assert.match(cancelled.nextAction, /^Start a new scan when ready\./u);
  const failed = scanEvidenceNotice({ ...scan, status: 'failed', scanner_summary: {} }, 0, 0)!;
  assert.equal(failed.title, 'Scan execution failed');
  assert.deepEqual(failed.scannerFailures, []);
  assert.match(failed.detail, /No findings or publishable artifacts were preserved/u);
  assert.equal(scanEvidenceNotice({ ...scan, status: 'completed', gate_decision: 'fail' }, 247, 1), null);
  assert.equal(scanEvidenceNotice(undefined, 0, 0), null);
  assert.equal(scan.gate_decision, 'incomplete');
  const oversized = scanEvidenceNotice({ ...scan, scanner_summary: { source_coverage: {
    complete: false, max_file_bytes: 1_048_576, reason_counts: { eligible_file_too_large: 1 },
  }, tools: [{ id: 'opengrep', enabled: true, status: 'completed' }] } }, 0, 1)!;
  assert.deepEqual(oversized.sourceFailures, ['1 code file exceeds the 1 MiB per-file analysis limit.']);
  assert.deepEqual(oversized.scannerFailures, []);
  assert.match(oversized.nextAction, /Repeating unchanged source will not fix them/);
  assert.equal(scan.gate_decision, 'incomplete');
  const limited = scanEvidenceNotice({ ...scan, scanner_summary: { coverage: {
    mode: 'limited', complete: false, requested_tool_ids: ['trivy', 'opengrep'], ready_tool_ids: ['trivy'],
    omitted_tools: [{ id: 'opengrep', name: 'OpenGrep', blocking_reasons: ['Rules unavailable.'] }],
  } } }, 0, 0)!;
  assert.match(limited.detail, /Its deterministic gate is permanently incomplete\./u);
  assert.match(limited.nextAction, /^Review omitted scanners in Tools/u);
});

test('scanner failure copy admits only supported categories and bounds persisted diagnostics', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { scanEvidenceNotice } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const scan: Scan = {
    id: 1, project_id: 1, mode: 'full', status: 'partial', gate_reasons: [], scanner_summary: {},
    created_at: '2026-09-26T00:00:00Z', revision: 1, findings_revision: 1,
  };
  const reasons = (tools: unknown) => scanEvidenceNotice({ ...scan, scanner_summary: { tools } }, 0, 0)!.scannerFailures;
  const tool = { id: 'bearer', name: 'Bearer', enabled: true, status: 'failed' };
  assert.deepEqual(reasons([{ ...tool, error: 'bearer_analysis_incomplete:analysis_error,file_timeout,memory_limit,unknown,worker_failure' }]),
    ['Bearer (failed): analysis error; file processing timed out; memory limit reached; unclassified analysis error; scanner worker failed. Bearer findings were not published.']);
  for (const [letters, label] of [
    ['d', 'directory admission failed'],
    ['e', 'dependency classification failed'],
    ['f', 'framework classification failed'],
    ['p', 'recovered analysis panic'],
    ['s', 'source analysis failed'],
    ['t', 'detector processing failed'],
  ]) {
    assert.deepEqual(reasons([{ ...tool, error: `bearer_analysis_incomplete:aerr_${letters}` }]),
      [`Bearer (failed): ${label}. Bearer findings were not published.`]);
  }
  assert.deepEqual(reasons([{ ...tool, error: 'bearer_analysis_incomplete:aerr_su,file_timeout' }]),
    ['Bearer (failed): source analysis failed; unclassified analysis error; file processing timed out. Bearer findings were not published.']);
  assert.deepEqual(reasons([{ ...tool, error: 'bearer_analysis_incomplete:aerr_defpstu,file_timeout,memory_limit,unknown,worker_failure' }]),
    ['Bearer (failed): directory admission failed; dependency classification failed; framework classification failed; recovered analysis panic; source analysis failed; detector processing failed; unclassified analysis error; file processing timed out; memory limit reached; scanner worker failed. Bearer findings were not published.']);
  // Native canonical subtypes are sorted and unique. An unmatched-only report
  // uses legacy analysis_error, not aerr_u. Unknown inputs retain bounded text.
  for (const category of ['aerr_', 'aerr_u', 'aerr_ss', 'aerr_us', 'aerr_sd', 'aerr_sx',
    'aerr_S', 'aerr_s ', ' aerr_s', 'aerr_constructor', 'aerr_defpstuu']) {
    const error = `bearer_analysis_incomplete:${category},file_timeout`;
    assert.deepEqual(reasons([{ ...tool, error }]), [`Bearer (failed): ${error}`]);
  }
  const overlongSubtype = `bearer_analysis_incomplete:aerr_${'s'.repeat(600)},file_timeout`;
  assert.deepEqual(reasons([{ ...tool, error: overlongSubtype }]), [`Bearer (failed): ${overlongSubtype.slice(0, 400)}`]);
  assert.deepEqual(reasons([{ ...tool, error: 'timeout' }]), ['Bearer (failed): The scanner command exceeded its time limit.']);
  assert.match(reasons([{ ...tool, error: 'bearer_native_report_invalid' }])[0], /required format\. Bearer findings were not published\./u);
  const unknown = 'bearer_analysis_incomplete:future_category';
  assert.deepEqual(reasons([{ ...tool, error: unknown }]), [`Bearer (failed): ${unknown}`]);
  assert.deepEqual(reasons([{ ...tool, error: 'bearer_analysis_incomplete:constructor' }]), ['Bearer (failed): bearer_analysis_incomplete:constructor']);
  const persisted = '<img src=x onerror=alert(1)> [REDACTED] ' + 'x'.repeat(600);
  assert.deepEqual(reasons([{ ...tool, error: persisted }]), [`Bearer (failed): ${persisted.slice(0, 400)}`]);
  assert.deepEqual(reasons([null, [], 'invalid', { ...tool, enabled: false }, { ...tool, status: 'completed' }, { ...tool, status: 'skipped' }]), []);
  assert.deepEqual(reasons(null), []);
  assert.deepEqual(reasons([{ ...tool, error: null }, { ...tool, error: null }]), ['Bearer (failed): No additional failure reason was recorded.']);
  for (const status of ['unavailable', 'partial', 'cancelled']) assert.match(reasons([{ ...tool, status }])[0], new RegExp(`\\(${status}\\)`));
  const many = Array.from({ length: 35 }, (_, index) => ({ ...tool, name: `Scanner ${index}`, error: 'Synthetic persisted diagnostic.' }));
  const bounded = reasons(many);
  assert.equal(bounded.length, 10);
  assert.equal(bounded[8], '24 additional scanner failure reasons are not shown.');
  assert.equal(bounded[9], 'Additional scanner records are not shown.');
  assert.equal(reasons([{ ...tool, name: 'x'.repeat(121), id: 'x'.repeat(81) }])[0], 'Scanner (failed): No additional failure reason was recorded.');
});

test('cross-page bulk selection respects the production limit and allows explicit recovery', async (context) => {
  const schema = await readFile(fileURLToPath(new URL('../../api/kodesec_api/schemas.py', import.meta.url)), 'utf8');
  const bulkSchema = schema.split('class FindingBulkAction(BaseModel):')[1]?.split('\nclass ')[0];
  assert.ok(bulkSchema);
  for (const field of ['finding_ids', 'expected_revisions']) {
    assert.match(bulkSchema, new RegExp(`${field}: [^\\n]+max_length=${findingBulkActionLimit}\\)`));
  }
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { FindingListPane } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  for (const count of [0, 200, 201, 225, 200, 0]) {
    const reason = findingBulkSelectionDisabledReason(count);
    assert.equal(Boolean(reason), count === 0 || count > 200);
    const html = renderToStaticMarkup(createElement(FindingListPane, {
      activeFindingId: null, activeFindingsCount: 460, allVisibleSelected: false,
      busy: false, filteredFindings: [], renderedFindingCount: 0, findingsLoading: false,
      emptyMessage: 'No findings match the current filters. Clear filters to review this scan.',
      gateExemptCount: 0, ignoredCount: 0, page: 9, pageSize: 25,
      onOpen() {}, onRunBulk() {}, onToggleSelected() {}, onToggleVisibleSelection() {},
      onClearSelection() {}, registerRef() {}, visible: true, selectedFindingIds: new Set(),
      selectedIdsCount: count, setPage() {}, totalFilteredCount: 460, triageSelectionValid: count > 0,
    }));
    assert.doesNotMatch(html, /role="list"/u);
    assert.doesNotMatch(html, /aria-label="Findings in the current page"/u);
    assert.match(html, /No findings match the current filters/u);
    const actions = html.match(/<div[^>]*aria-label="Bulk finding actions"[^>]*>([\s\S]*?)<\/div>/u)?.[1];
    assert.ok(actions);
    const buttons = [...actions.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/gu)];
    const clear = buttons.filter((button) => button[2] === 'Clear selection');
    assert.equal(clear.length, count > 0 ? 1 : 0);
    if (clear[0]) assert.doesNotMatch(clear[0][1], /disabled/u);
    const mutations = buttons.filter((button) => button[2] !== 'Clear selection');
    assert.equal(mutations.length, 9);
    for (const [, attributes] of mutations) {
      assert.equal(attributes.includes('disabled=""'), Boolean(reason));
      if (reason) assert.match(attributes, /aria-describedby="bulk-lifecycle-disabled-reason"/u);
    }
    if (reason) assert.ok(actions.includes(reason));
    assert.match(actions, count ? new RegExp(`${count} selected`) : /No findings selected/u);
  }
  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  const handler = appSource.split('async function bulkFindingAction(')[1]?.split('async function checkTools(')[0];
  assert.ok(handler);
  const guard = handler.indexOf('findingBulkSelectionDisabledReason(findingIds.length)');
  assert.ok(guard >= 0 && guard < handler.indexOf('await confirmAction('));
  assert.ok(guard < handler.indexOf('await collectLifecycleReason('));
  assert.ok(guard < handler.indexOf('await currentAdvisorRoute('));
  assert.ok(guard < handler.indexOf('await api.bulkFindings('));
  assert.match(handler, /if \(selectionDisabledReason\) \{[^}]*return null;/u);
  assert.match(appSource, /const clearFindingSelection = useCallback\(\(\) => setSelectedFindingIds\(new Set\(\)\), \[\]\)/u);
});

test('bulk selection checkboxes name the exact scan-local finding', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { FindingListRow } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  for (const ordinal of [2, 4]) {
    const finding: Finding = {
      id: 100 + ordinal, scan_id: 1, scan_finding_number: ordinal,
      display_id: `S1-F${String(ordinal).padStart(3, '0')}`,
      scanner: 'synthetic', rule_id: 'synthetic-rule', severity: 'high',
      file_path: 'fixture.py', message: 'Synthetic test finding', fingerprint: `synthetic-${ordinal}`,
      suppressed: false, lifecycle_status: 'open', gate_exempt: false,
      gate_effect: 'blocking', occurrence_count: 1, is_repeat: false, revision: 1,
    };
    const html = renderToStaticMarkup(createElement(FindingListRow, {
      finding, active: false, index: ordinal - 1, setSize: 4, selected: ordinal === 2,
      fullPath: '/approved/fixture.py', onOpen() {}, onToggleSelected() {}, registerRef() {},
    }));
    const checkbox = html.match(/<input\b[^>]*type="checkbox"[^>]*>/u)?.[0];
    assert.ok(checkbox, 'the actual row renders its bulk-selection control');
    assert.ok(checkbox.includes(`aria-label="Select ${finding.display_id}"`));
    assert.equal(checkbox.includes('checked=""'), ordinal === 2);
    assert.equal((html.match(/type="checkbox"/gu) || []).length, 1);
  }
});


test('finding lifecycle actions use the visible product wording', async () => {
  assert.equal(findingLifecycleActionLabel('gate_exempt'), 'non-blocking for gate');
  assert.equal(findingLifecycleActionLabel('accepted_risk'), 'accepted risk');
  assert.equal(findingLifecycleActionLabel('ignore'), 'ignored and not counted');
  assert.equal(findingLifecycleActionLabel('false_positive'), 'a false positive');
  assert.equal(findingLifecycleActionLabel('fixed'), 'fixed');
  assert.equal(findingLifecycleActionLabel('needs_review'), 'needs review');
  assert.equal(findingLifecycleActionLabel('open'), 'open and blocking');
  assert.equal(findingLifecycleActionDisabledReason('open', 'open'), 'This finding is already open and blocking.');
  assert.equal(findingLifecycleActionDisabledReason('fixed', 'open'), null);
  assert.equal(findingLifecycleActionDisabledReason('unknown', 'unknown'), null);
  assert.equal(findingGateEffectLabel('blocking'), 'Blocking');
  assert.equal(findingGateEffectLabel('non_blocking'), 'Non-blocking for gate');
  assert.equal(findingGateEffectLabel('excluded'), 'Not counted');
  assert.equal(findingAdvisorVerdictLabel('true_positive'), 'Likely valid finding');
  assert.equal(findingAdvisorVerdictLabel('false_positive'), 'Likely false positive');
  assert.equal(findingAdvisorVerdictLabel('needs_review'), 'Needs review');

  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  assert.doesNotMatch(appSource, /Lifecycle set to \$\{action\.replace/u);
  assert.match(appSource, /Lifecycle set to \$\{findingLifecycleActionLabel\(action\)\}/u);
  assert.match(appSource, /disabled=\{busy \|\| Boolean\(currentReason\)\}/u);
  assert.match(appSource, /aria-describedby=\{currentReason \? lifecycleCurrentReasonId : undefined\}/u);
  assert.ok(appSource.includes('title={currentReason || `Set this finding to ${findingLifecycleActionLabel(action)}.`}'));
  assert.doesNotMatch(appSource, /<span aria-label=\{`Verdict \$\{verdict\}`\}>\{verdict\}<\/span>/u);
  assert.match(appSource, /<span><span className="visually-hidden">Verdict: <\/span>\{verdictLabel\}<\/span>/u);
});

test('evidence height starts on the exact keyboard step sequence', () => {
  assert.equal(isEvidenceHeightStepAligned(evidenceHeightControl.initial), true);
  assert.equal(isEvidenceHeightStepAligned(evidenceHeightControl.min), true);
  assert.equal(isEvidenceHeightStepAligned(evidenceHeightControl.max), true);
  assert.equal(isEvidenceHeightStepAligned(520), false);
  assert.equal(isEvidenceHeightStepAligned(evidenceHeightControl.min - evidenceHeightControl.step), false);
  assert.equal(isEvidenceHeightStepAligned(evidenceHeightControl.max + evidenceHeightControl.step), false);
});

test('scan scope values wrap instead of clipping required context', async () => {
  const styles = await readFile(fileURLToPath(new URL('../src/styles.css', import.meta.url)), 'utf8');
  const declaration = [...styles.matchAll(/\.scope-grid strong\s*\{(?<body>[^}]*)\}/gu)]
    .map((match) => match.groups?.body || '')
    .find((body) => body.includes('overflow-wrap'));
  assert.ok(declaration, 'scan scope value styles must remain explicit');
  assert.match(declaration, /overflow-wrap:\s*anywhere/u);
  assert.match(declaration, /white-space:\s*normal/u);
  assert.doesNotMatch(declaration, /overflow:\s*hidden|text-overflow:\s*ellipsis/u);
});

test('findings keep selected detail reachable at integrated dashboard widths', async () => {
  const styles = await readFile(fileURLToPath(new URL('../src/styles.css', import.meta.url)), 'utf8');
  const boundedList = styles.match(/\.finding-list-scroll\s*\{(?<body>[^}]*)\}/u)?.groups?.body;
  assert.ok(boundedList, 'the virtual findings list must have an explicit scroll owner');
  assert.match(boundedList, /max-height:\s*min\(calc\(100vh - 180px\), 414px\)/u);
  assert.match(boundedList, /overflow-y:\s*auto/u);

  const compactDesktop = styles.match(
    /@media \(min-width: 861px\) and \(max-width: 1264px\)\s*\{(?<body>[\s\S]*?)\n\}/u,
  )?.groups?.body;

  assert.ok(compactDesktop, 'compact desktop findings layout must remain explicit');
  assert.match(
    compactDesktop,
    /\.finding-workspace\s*\{[^}]*grid-template-columns:\s*minmax\(270px, 36%\) minmax\(0, 1fr\)/u,
  );
  assert.match(
    compactDesktop,
    /\.finding-detail\s*\{[^}]*position:\s*sticky[^}]*max-height:\s*calc\(100vh - 36px\)/u,
  );

  const narrow = styles.match(/@media \(max-width: 980px\)\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
  assert.ok(narrow, 'narrow findings layout must remain explicit');
  assert.doesNotMatch(
    narrow,
    /\.finding-list-scroll\s*\{[^}]*(?:max-height:\s*none|overflow:\s*visible)/u,
    'the findings list must stay bounded so selected detail is not buried below every row',
  );
});
