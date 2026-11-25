import { readFileSync } from 'node:fs';
import { chromium, expect } from '@playwright/test';

const { origin, key, scan, filterScan } = JSON.parse(readFileSync(0, 'utf8'));
async function checkFilterMatrix(page, scanId) {
  // The seed fixes these identities independently of the API's classifier.
  const expected = [[30, ['critical']], [201, ['secret']], [224, ['critical', 'secret']]];
  const base = origin + '/v1/scans/' + scanId;
  const review = async () => {
    const response = await page.request.get(base + '/summary');
    expect(response.ok()).toBe(true);
    return (await response.json()).gate_review;
  };
  const before = await review();
  expect(before).toMatchObject({ decision: 'fail', contributors: 3 });
  const pageOfFindings = async cursor => {
    const params = new URLSearchParams({ limit: '200' });
    if (cursor) params.set('cursor', cursor);
    const response = await page.request.get(base + '/findings?' + params);
    expect(response.ok()).toBe(true);
    return response.json();
  };
  const first = await pageOfFindings();
  expect(first.items).toHaveLength(200);
  expect(first.next_cursor).toBeTruthy();
  const last = await pageOfFindings(first.next_cursor);
  expect(last.items).toHaveLength(24);
  expect(last.next_cursor).toBeNull();
  const items = [...first.items, ...last.items];
  expect(items.filter(item => item.gate_contribution.length)
    .map(item => [item.scan_finding_number, item.gate_contribution])).toEqual(expected);

  await page.goto(origin + '/?view=findings&scan=' + scanId + '&gate=contributing');
  const list = page.locator('.finding-list');
  const search = page.getByRole('textbox', { name: 'Search findings' });
  const id = number => 'S' + scanId + '-F' + String(number).padStart(3, '0');
  const exactRows = async numbers => {
    await expect(list.locator('.list-head strong').first()).toHaveText(
      numbers.length + (numbers.length === 1 ? ' finding' : ' findings'));
    await expect(list.locator('.finding-number')).toHaveText(numbers.map(id));
  };
  const blockers = expected.map(([number]) => number);
  await exactRows(blockers);
  await expect(list.locator('.finding-blocker-label')).toHaveCount(3);
  await page.locator('.finding-filter-details summary').click();
  const lifecycle = page.getByLabel('Lifecycle', { exact: true });
  const severity = page.getByLabel('Severity', { exact: true });
  const scanner = page.getByLabel('Scanner', { exact: true });
  await expect(lifecycle).toHaveValue('contributing');
  for (const [query, matches] of [
    ['  CoNNeCtIon ToKeN  ', [30, 201]], ['SHARED/config', [30, 224]],
    [id(224).toLowerCase(), [224]], ['fixture.rule.201', [201]],
    ['fixture.rule.005', []], [' CRITICAL ', [30, 224]], ['gate blocker', blockers],
    ['no-such-finding', []], ['', blockers],
  ]) {
    await search.fill(query);
    await exactRows(matches);
    await expect(list.locator('.finding-blocker-label')).toHaveCount(matches.length);
  }
  await severity.selectOption('critical');
  await exactRows([30, 224]);
  await scanner.selectOption('gitleaks');
  await exactRows([224]);
  await search.fill('connection token');
  await exactRows([]);
  await severity.selectOption('low');
  await exactRows([201]);
  await severity.selectOption('all');
  await scanner.selectOption('all');
  await lifecycle.selectOption({ label: 'gate-eligible' });
  await exactRows([5, 30, 201]);
  await expect(page.locator('.finding-filter-details summary small')).toHaveText('gate-eligible');
  await search.fill('shared/config');
  await lifecycle.selectOption('active');
  await exactRows([4, 5, 30, 224]);
  await lifecycle.selectOption('non_blocking');
  await exactRows([4]);
  await search.fill('');
  await lifecycle.selectOption('ignored');
  await exactRows([2]);
  await scanner.selectOption('checkov');
  await exactRows([2]);
  await lifecycle.selectOption('active');
  await exactRows([]);
  await scanner.selectOption('all');
  await lifecycle.selectOption('all');
  await expect(list.locator('.list-head strong').first()).toHaveText('224 findings');
  await expect(list.locator('.finding-number').first()).toHaveText(id(1));
  await page.getByTitle('Next page', { exact: true }).click();
  await expect(list.locator('.finding-number').first()).toHaveText(id(26));
  // Filtering on a later page must reset pagination and must see the entire scan.
  await search.fill('fixture.rule.224');
  await exactRows([224]);
  await page.getByRole('button', { name: 'Show gate blockers' }).click();
  await expect(search).toHaveValue('');
  await exactRows(blockers);
  expect(await review()).toEqual(before);
  console.log('Filter matrix passed: 224 findings, 2 API pages, 3 exact blocker IDs, 1 two-reason blocker. Search, severity, scanner, lifecycle and pagination matched their expected IDs.');
}

const browser = await chromium.launch({ executablePath: process.env.KODESEC_TEST_CHROMIUM_EXECUTABLE || undefined });
try {
  const page = await browser.newPage();
  const errors = [];
  if (process.env.KODESEC_GATE_TEST_DIAGNOSTICS === '1') {
    page.on('response', response => {
      const path = new URL(response.url()).pathname;
      if (path.startsWith('/v1/')) console.log(response.status(), path);
    });
  }
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin + '/?view=findings&scan=' + scan);
  await page.getByLabel('One-time browser pairing key').fill(key);
  await page.getByRole('button', { name: 'Add this browser' }).click();
  const snapshot = async () => {
    const response = await page.request.get(origin + '/v1/scans/' + scan + '/summary');
    expect(response.ok()).toBe(true);
    return (await response.json()).gate_review;
  };
  const rows = page.locator('.finding-list-item');
  const detail = page.locator('.finding-detail');
  const openAction = async (id, action) => {
    await rows.getByRole('button', { name: new RegExp(id) }).click();
    const lifecycle = detail.locator('details').filter({ has: page.locator('summary', { hasText: /^\s*Lifecycle\s*$/ }) });
    if (await lifecycle.getAttribute('open') === null) await lifecycle.locator('summary').click();
    await lifecycle.getByRole('button', { name: action, exact: true }).click();
  };
  await expect(page.getByLabel('One-time browser pairing key')).toHaveCount(0);
  await page.goto(origin + '/?view=findings&project=1&scan=' + scan);
  const show = page.getByRole('button', { name: 'Show gate blockers' });
  try {
    await expect(show).toBeVisible({ timeout: 10000 });
  } catch (error) {
    console.error('Headings:', await page.getByRole('heading').allTextContents());
    console.error('Alerts:', await page.getByRole('alert').allTextContents());
    console.error('Gate:', await snapshot());
    throw error;
  }
  await show.click();
  await expect(rows).toHaveCount(2);
  const prefix = 'S' + scan + '-F';
  await openAction(prefix + '001', 'Mark fixed');
  await page.getByRole('button', { name: 'Keep unchanged' }).click();
  await expect(rows).toHaveCount(2);
  expect((await snapshot()).contributors).toBe(2);
  for (const [ordinal, action, remaining] of [['001', 'Mark fixed', 1], ['002', 'Accept risk', 0]]) {
    await openAction(prefix + ordinal, action);
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Local audit reason').fill('Reviewed this synthetic finding in the isolated test.');
    await dialog.getByRole('button', { name: /^Mark / }).click();
    await expect(rows).toHaveCount(remaining);
    const review = await snapshot();
    expect(review.contributors).toBe(remaining);
    expect(review.decision).toBe(remaining ? 'fail' : 'pass');
  }
  await expect(page.getByText(/No current failure set/)).toBeVisible();
  await page.getByRole('button', { name: 'Show all findings' }).click();
  await expect(rows).toHaveCount(3);
  await expect(rows.getByText('Gate blocker')).toHaveCount(0);
  await page.reload();
  const review = await snapshot();
  expect(review.decision).toBe('pass');
  expect(review.contributors).toBe(0);
  await checkFilterMatrix(page, filterScan);
  expect(errors).toEqual([]);
  console.log('Browser verified: 3 findings, 2 blockers, cancel kept both, independent reviews left 1 then 0.');
} finally {
  await browser.close();
}
