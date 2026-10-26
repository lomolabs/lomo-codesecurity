import { inspectControlLayout, inspectRenderedControls } from './support/control-layout.mjs';
import { inspectEvidenceContrast } from './support/evidence-contrast.mjs';
import { referenceTest } from './support/reference-viewport.js';
import { waitForRouteReady } from './support/route-ready.js';
import { captureRenderEnvironment } from './support/render-environment.js';
import { expect, Frame, Locator, Page, Request, TestInfo, test } from '@playwright/test';
import { availableParallelism, cpus, release, totalmem } from 'node:os';
import { writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';

import {
  axeBuilder,
  assertRequiredQualityObservers,
  assertStableSurface,
  installQualityObservers,
  installRuntimeGuards,
  qualitySnapshot,
  resetQualityWindow,
} from './support/quality.js';
import {
  qualificationMilliseconds,
  qualificationPerformanceBudgetMode,
  qualificationPerformanceBudgetsAreBlocking,
} from '../timing.js';

referenceTest('scan selector reserves readable label space at enlarged text sizes', async ({ page }, testInfo) => {
  await openRoute(page, 'Findings');
  const select = page.getByRole('combobox', { name: 'Scan', exact: true });
  for (const width of [320, 390, 768, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1024 });
    for (const scale of [1, 2]) {
      const originals = await page.evaluateHandle(scale => {
        const items = [...document.querySelectorAll<HTMLElement>('*')].map(element => ({
          element, font: element.style.fontSize, line: element.style.lineHeight,
          size: parseFloat(getComputedStyle(element).fontSize), leading: parseFloat(getComputedStyle(element).lineHeight),
        }));
        for (const item of items) {
          item.element.style.fontSize = `${item.size * scale}px`;
          if (Number.isFinite(item.leading)) item.element.style.lineHeight = `${item.leading * scale}px`;
        }
        return items;
      }, scale);
      try {
        const observed = await select.evaluate(element => {
          const control = element as HTMLSelectElement, style = getComputedStyle(control), box = control.getBoundingClientRect();
          const context = document.createElement('canvas').getContext('2d')!;
          context.font = style.font;
          return { width: box.width, font: style.fontSize, label: control.selectedOptions[0].textContent,
            text: context.measureText(control.selectedOptions[0].textContent || '').width,
            available: control.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight) - 16,
            left: box.left, right: box.right };
        });
        await testInfo.attach(`scan-selector-${width}-${scale}x.json`, {
          body: JSON.stringify(observed), contentType: 'application/json',
        });
        expect(observed.text, `${width}px / ${scale}x native select label`).toBeLessThanOrEqual(observed.available);
        expect(observed.left).toBeGreaterThanOrEqual(0);
        expect(observed.right).toBeLessThanOrEqual(width);
        await testInfo.attach(`scan-selector-${width}-${scale}x.png`, { body: await select.screenshot(), contentType: 'image/png' });
      } finally {
        await originals.evaluate(items => { for (const item of items) {
          item.element.style.fontSize = item.font; item.element.style.lineHeight = item.line;
        } });
        await originals.dispose();
      }
    }
  }
});

referenceTest('control layout includes textarea boundaries', async ({ page }) => {
  await page.setContent('<main><textarea aria-label="Host command" readonly style="position:absolute;left:-300px;width:200px">fixture command</textarea></main>');
  const geometry = await page.evaluate(inspectControlLayout);
  expect(geometry.offscreenControls.map(control => control.name)).toContain('Host command');
});

referenceTest('rendered control inventory retains fields without collecting values', async ({ page }) => {
  await page.setContent(`<main><section data-route-surface="settings">
    <label for="command">Host command</label><textarea id="command" readonly>DO-NOT-COLLECT-TEXTAREA</textarea>
    <input aria-label="Password" type="password" value="DO-NOT-COLLECT-PASSWORD">
    <input type="hidden" value="DO-NOT-COLLECT-HIDDEN">
    <textarea>DO-NOT-COLLECT-UNLABELLED</textarea>
    <label>Notes<textarea style="position:absolute;left:-300px;width:200px">DO-NOT-COLLECT-NESTED</textarea></label>
    <fieldset disabled><label><input type="checkbox">Protection</label></fieldset>
    <span id="size-label">Code preview height</span><input type="range" aria-labelledby="size-label">
    <details><summary>Advanced controls</summary><button>Hidden action</button></details>
    <button style="visibility:hidden">Invisible action</button>
    <button style="opacity:0">Transparent action</button>
    <a href="#fixture">Open details</a>
  </section></main>`);
  const inventory = await page.evaluate(inspectRenderedControls, 'settings');
  expect(inventory.execution_evidence).toBe(false);
  expect(inventory.controls.map(control => control.name)).toEqual([
    'Host command', 'Password', '', 'Notes', 'Protection', 'Code preview height', 'Advanced controls', 'Open details',
  ]);
  expect(inventory.controls[0]).toMatchObject({ tag: 'TEXTAREA', readonly: true });
  expect(inventory.controls[4]).toMatchObject({ type: 'checkbox', disabled: true });
  expect(inventory.controls[5]).toMatchObject({ type: 'range' });
  expect(JSON.stringify(inventory)).not.toContain('DO-NOT-COLLECT');
  expect(JSON.stringify(await page.evaluate(inspectControlLayout))).not.toContain('DO-NOT-COLLECT');
});

referenceTest('rendered control inventory rejects absent routes and excessive controls', async ({ page }) => {
  await page.setContent('<main><section data-route-surface="settings"></section></main>');
  await expect(page.evaluate(inspectRenderedControls, 'unknown')).rejects.toThrow('Unknown control inventory route');
  await expect(page.evaluate(inspectRenderedControls, 'findings')).rejects.toThrow('not mounted');
  await page.locator('section').evaluate(section => {
    for (let index = 0; index < 301; index++) section.append(document.createElement('button'));
  });
  await expect(page.evaluate(inspectRenderedControls, 'settings')).rejects.toThrow('exceeds bounded review');
});

const routes = [
  { name: 'Overview', slug: 'overview', evidence: 'Scanner Coverage' },
  { name: 'Projects', slug: 'projects', evidence: 'Generated Demo Service' },
  { name: 'Jobs', slug: 'jobs', evidence: 'Task Manager' },
  { name: 'Scans', slug: 'scans', evidence: 'Scan History' },
  { name: 'Findings', slug: 'findings', evidence: 'S41-F001' },
  { name: 'Tools', slug: 'tools', evidence: 'OpenGrep' },
  { name: 'Settings', slug: 'settings', evidence: 'Gate Defaults' },
] as const;

referenceTest('render diagnostics retain fonts and geometry without page content', async ({ page }, testInfo) => {
  await page.setContent(`<h1>DO-NOT-COLLECT-HEADING</h1>
    <nav><button>DO-NOT-COLLECT-ACTION</button></nav>
    <dl class="workbench-summary"><dd>DO-NOT-COLLECT-SUMMARY</dd></dl>
    <div class="finding-evidence"><code class="code-source">DO-NOT-COLLECT-CODE</code></div>
    <input type="password" value="DO-NOT-COLLECT-PASSWORD">
    <textarea>DO-NOT-COLLECT-NOTES</textarea>`);
  const evidence = await captureRenderEnvironment(page);
  expect(evidence.platformFonts.filter(item => item.present)).toHaveLength(4);
  expect(evidence.platformFonts[0].fonts?.some(font => font.glyphCount > 0)).toBe(true);
  expect(evidence.document.viewport).toMatchObject({ width: 1440, height: 900, scale: 1 });
  expect(JSON.stringify(evidence)).not.toContain('DO-NOT-COLLECT');
  await attachRenderEnvironment(testInfo, evidence);
});

async function attachRenderEnvironment(
  testInfo: TestInfo,
  evidence: Awaited<ReturnType<typeof captureRenderEnvironment>>,
) {
  const path = testInfo.outputPath('render-environment.json');
  await writeFile(path, JSON.stringify(evidence, null, 2), { mode: 0o600 });
  await testInfo.attach('render-environment.json', { path, contentType: 'application/json' });
}

type FindingDisclosure = '.finding-filter-details' | '.bulk-action-disclosure' | '.finding-scan-details';

async function expandFindingDisclosure(owner: Page | Locator, selector: FindingDisclosure) {
  const disclosure = owner.locator(selector);
  await expect(disclosure).toHaveCount(1);
  if (!await disclosure.evaluate((element: HTMLDetailsElement) => element.open)) {
    await disclosure.locator(':scope > summary').click();
  }
  await expect(disclosure).toHaveAttribute('open', '');
  return disclosure;
}

async function openRoute(page: Page, name: string) {
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.goto('/?view=overview');
  await waitForRouteReady(page, 'Overview');
  if (name !== 'Overview') {
    await page.getByRole('navigation').getByRole('button', { name, exact: true }).click();
    await waitForRouteReady(page, name);
  }
  await page.evaluate(() => window.scrollTo(0, 0));
}

async function reloadAfterReads(page: Page) {
  // Deliberate document replacement must not abort the reads under test.
  await page.waitForLoadState('networkidle');
  await page.reload();
}

for (const delayedPath of ['/v1/dashboard/summary', '/v1/jobs']) {
  referenceTest(`Overview readiness waits for the initial ${delayedPath} response`, async ({ page, request }) => {
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let observed!: () => void;
    const intercepted = new Promise<void>((resolve) => { observed = resolve; });
    await page.route((url) => url.pathname === delayedPath && !url.searchParams.has('status'), async route => {
      observed();
      await held;
      await route.fallback();
    });
    let readiness: ReturnType<typeof waitForRouteReady> | undefined;
    try {
      await page.goto('/?view=overview');
      await intercepted;
      await expect(page.getByText('Overview counts have not loaded yet.', { exact: true })).toBeVisible();
      readiness = waitForRouteReady(page, 'Overview');
      // This short negative-observation window tests premature completion; it
      // is not a readiness delay or a relaxed product performance budget.
      const outcome = await Promise.race([
        readiness.then(() => 'premature'),
        new Promise<string>((resolve) => setTimeout(() => resolve('pending'), 250)),
      ]);
      expect(outcome).toBe('pending');
    } finally {
      release();
      await readiness;
    }
    await waitForRouteReady(page, 'Overview');
    await expect(page.getByText('Overview counts have not loaded yet.', { exact: true })).toHaveCount(0);
  });
}

for (const route of routes) {
  test(`${route.name} has a deterministic foundation surface`, async ({ page, request, baseURL }, testInfo) => {
    if (!baseURL) throw new Error('Playwright baseURL is required.');
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    // Match the fixture's latest timestamp without freezing timers, polling,
    // animation frames, or performance measurements in these seven snapshots.
    await page.clock.setFixedTime('2026-08-12T08:00:04Z');
    await installQualityObservers(page);
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    await openRoute(page, route.name);
    // Foundation images use pointer interaction. Chromium can retain keyboard
    // modality between native windows, making programmatic route focus paint
    // an intermittent ring. Keyboard focus has its own explicit assertions.
    await page.getByRole('heading', { level: 1, name: route.name, exact: true }).click();
    const evidence = route.name === 'Projects'
      ? page.locator('.project-row strong', { hasText: route.evidence })
      : route.name === 'Tools'
        ? page.locator('.tool-card .tool-head').getByText(route.evidence, { exact: true })
        : page.getByText(route.evidence, { exact: false }).first();
    await expect(evidence).toBeVisible();

    if (route.name === 'Overview') {
      const board = page.locator('.risk-board');
      for (const severity of ['critical', 'low']) {
        const row = board.getByText(severity, { exact: true }).locator('..');
        await expect(row.locator('strong'), `${severity} fixture count is zero`).toHaveText('0');
        await expect.poll(() => row.locator('.risk-fill').evaluate((element) => element.getBoundingClientRect().width),
          { message: `${severity} zero count has no colored risk bar` }).toBe(0);
      }
      const high = board.getByText('high', { exact: true }).locator('..');
      await expect(high.locator('strong')).toHaveText('1');
      await expect.poll(() => high.locator('.risk-fill').evaluate((element) => element.getBoundingClientRect().width),
        { message: 'the nonzero high finding retains a visible risk bar' }).toBeGreaterThan(0);
    }

    if (route.name === 'Findings') {
      const surface = page.locator('section[data-route-surface="findings"]');
      for (const selector of ['.finding-filter-details', '.bulk-action-disclosure', '.finding-scan-details']) {
        await expect(surface.locator(selector), `${selector} starts deliberately collapsed`).not.toHaveAttribute('open', '');
      }
      if (testInfo.project.name === 'desktop-1440' || testInfo.project.name === 'desktop-1920') {
        const initialGeometry = await surface.evaluate((element) => {
          const main = element.closest('main')!;
          const row = element.querySelector('.finding-list-item')!.getBoundingClientRect();
          const workspace = element.querySelector('.finding-workspace')!.getBoundingClientRect();
          return {
            mainScrollTop: main.scrollTop, windowScrollY: window.scrollY,
            row: { top: row.top, bottom: row.bottom },
            workspace: { top: workspace.top, bottom: workspace.bottom },
            viewportHeight: window.innerHeight,
          };
        });
        await testInfo.attach('findings-initial-review-geometry.json', {
          body: Buffer.from(JSON.stringify(initialGeometry, null, 2)), contentType: 'application/json',
        });
        expect(initialGeometry.mainScrollTop, 'review is reachable without first scrolling main').toBe(0);
        expect(initialGeometry.windowScrollY, 'review is reachable without first scrolling the page').toBe(0);
        await expect(surface.locator('.finding-list-item').first(), 'first complete finding row fits the initial desktop viewport').toBeInViewport({ ratio: 1 });
        await expect(surface.locator('.finding-detail h2'), 'selected finding identity appears beside the list').toBeInViewport();
        await expect(surface.getByLabel('Code evidence for src/handler.ts', { exact: true }), 'code evidence starts in the initial desktop viewport').toBeInViewport();
      }
    }

    const accessibility = await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze();
    const prohibitedNames = accessibility.incomplete.filter(rule => rule.id === 'aria-prohibited-attr');
    expect(prohibitedNames.map(rule => ({ id: rule.id, targets: rule.nodes.map(node => node.target) })),
      'labels must use roles that permit accessible names, including axe manual-review results').toEqual([]);
    await testInfo.attach('accessibility.json', { body: Buffer.from(JSON.stringify(accessibility.violations, null, 2)), contentType: 'application/json' });
    const seriousOrCritical = accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact || ''));
    expect(
      seriousOrCritical.map((violation) => ({ id: violation.id, impact: violation.impact, nodes: violation.nodes.length })),
      'serious or critical WCAG A/AA violations',
    ).toEqual([]);

    // Use an interior, non-interactive target. A move to the viewport edge can
    // leave a stale native hover in a newly activated foreground window.
    await page.getByRole('heading', { level: 1, name: route.name, exact: true }).hover();
    await expect(page.locator('nav button:hover'), 'no incidental navigation hover in the baseline').toHaveCount(0);
    await resetQualityWindow(page);
    await assertStableSurface(page, testInfo);
    await attachRenderEnvironment(testInfo, await captureRenderEnvironment(page));
    await expect(page).toHaveScreenshot(`${route.slug}.png`);
    guards.assertClean();
  });
}

referenceTest('[WEB-START-001] an unqualified returning dashboard opens exact Findings from one initial refresh', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const reads: string[] = [];
  page.on('request', (request) => { if (request.method() === 'GET') reads.push(new URL(request.url()).pathname); });
  await page.goto('/?lomo_browser=vscode');
  const findings = page.locator('section[data-route-surface="findings"]');
  await expect(findings).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(findings.locator('.finding-detail h2')).toHaveText('S41-F001');
  await expect(findings).not.toHaveAttribute('inert', '');
  await page.waitForLoadState('networkidle');
  expect(reads.filter((path) => path === '/healthz')).toHaveLength(1);
  expect(reads.filter((path) => path === '/v1/scans')).toHaveLength(1);
  expect(new URL(page.url()).searchParams.get('lomo_browser')).toBe('vscode');
  expect(new URL(page.url()).searchParams.get('view')).toBe('findings');
  expect(new URL(page.url()).searchParams.get('scan')).toBe('41');
  await expect(page.locator('section[data-route-surface="overview"]')).toHaveCount(0);
  // The existing URL remains the context owner across reload, without storage.
  const location = page.url();
  await page.reload();
  await expect(findings).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(findings.locator('.finding-detail h2')).toHaveText('S41-F001');
  expect(page.url()).toBe(location);
  guards.assertClean();
});

referenceTest('[WEB-START-002] an unqualified installation with no scan history opens current source and scanner setup', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'first-run', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations: string[] = [];
  page.on('request', (request) => {
    if (request.method() !== 'GET' && new URL(request.url()).pathname.startsWith('/v1/')) mutations.push(request.url());
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toBeVisible();
  await expect(page.locator('section[data-route-surface="projects"]')).toHaveAttribute('data-projects-render-stage', 'ready');
  await expect(page.locator('details.first-run-checklist')).toHaveAttribute('open', '');
  await expect(page.getByLabel('Step 1: Core services')).toHaveAttribute('data-complete', 'false');
  await expect(page.getByLabel('Step 2: Source authorization and registration')).toHaveAttribute('data-complete', 'false');
  await expect(page.getByLabel('Step 3: Scanner data and readiness')).toHaveAttribute('data-complete', 'false');
  await expect(page.getByRole('button', { name: 'Scan', exact: true })).toHaveCount(0);
  expect(new URL(page.url()).searchParams.get('view')).toBe('projects');
  expect(mutations).toEqual([]);
  guards.assertClean();
});

referenceTest('[WEB-START-003] explicit navigation owns the route when a late initial scan response is empty', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'first-run', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let release!: () => void;
  let entered!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const seen = new Promise<void>((resolve) => { entered = resolve; });
  await page.route(`${new URL(baseURL).origin}/v1/scans?view=history`, async (route) => {
    const response = await route.fetch();
    entered();
    await released;
    await route.fulfill({ response });
  });
  try {
    await page.goto('/');
    await seen;
    await expect(page.getByRole('heading', { name: 'Opening workspace', exact: true })).toBeVisible();
    await expect(page.locator('main')).toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('section[data-route-surface]')).toHaveCount(0);
    // Choosing even the provisional route is user intent. This same-view case
    // also proves ownership without deliberately aborting any in-flight read.
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    release();
    await page.waitForLoadState('networkidle');
    await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
    await expect(page.locator('section[data-route-surface="projects"]')).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get('view')).toBe('findings');
    guards.assertClean();
  } finally { release(); }
});

referenceTest('[WEB-START-004] failed initial validation never infers first-run setup or overrides a subsequent route', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'first-run', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.route(`${new URL(baseURL).origin}/v1/scanner/preflight`, (route) => route.fulfill({ status: 200, json: {} }), { times: 1 });
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('invalid scanner readiness preflight');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page.locator('section[data-route-surface="projects"]')).toHaveCount(0);
  await page.waitForLoadState('networkidle');
  await page.getByRole('navigation').getByRole('button', { name: 'Projects', exact: true }).click();
  await expect(page.locator('section[data-route-surface="projects"]')).toHaveAttribute('data-projects-render-stage', 'ready');
  await page.waitForLoadState('networkidle');
  expect(new URL(page.url()).searchParams.get('view')).toBe('projects');
  await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  guards.assertClean();
});

referenceTest('[WEB-SETUP-001] verified scan prerequisites recede, reopen for recovery, and preserve an expanded focused summary', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let healthy = true;
  await page.route(`${new URL(baseURL).origin}/healthz`, async (route) => {
    const response = await route.fetch();
    const health = await response.json();
    await route.fulfill({ response, json: healthy ? health : { ...health, db: false, ok: false } });
  });
  await openRoute(page, 'Projects');
  const checklist = page.locator('details.first-run-checklist');
  const summary = checklist.locator(':scope > summary');
  await expect(checklist).not.toHaveAttribute('open', '');
  await expect(summary).toContainText('Scan prerequisites are ready');
  await expect(page.getByRole('button', { name: 'Scan', exact: true })).toBeEnabled();
  await summary.focus();
  await summary.press('Enter');
  await expect(checklist).toHaveAttribute('open', '');
  await expect(page.getByLabel('Step 2: Source authorization and registration')).toBeVisible();
  await expect(summary).toBeFocused();
  await summary.press('Enter');
  await expect(checklist).not.toHaveAttribute('open', '');
  healthy = false;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByLabel('Step 1: Core services')).toHaveAttribute('data-complete', 'false');
  await expect(checklist).toHaveAttribute('open', '');
  await expect(page.getByRole('button', { name: 'Review core services', exact: true })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await summary.focus();
  healthy = true;
  // Deliver a controlled refresh without moving focus away from the summary.
  // The real reads and native keyboard disclosure are independently asserted.
  await page.getByRole('button', { name: 'Refresh', exact: true }).evaluate((button: HTMLButtonElement) => button.click());
  await expect(page.getByLabel('Step 1: Core services')).toHaveAttribute('data-complete', 'true');
  await expect(summary).toContainText('Scan prerequisites are ready');
  await expect(summary).toBeFocused();
  await expect(checklist).toHaveAttribute('open', '');
  await page.waitForLoadState('networkidle');
  guards.assertClean();
});

referenceTest('primary navigation keeps the visible route reload-stable and preserves the retained browser member', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Overview');
  await page.evaluate(() => {
    window.history.replaceState(window.history.state, '', '/?view=overview&lomo_browser=vscode');
  });
  await reloadAfterReads(page);
  await expect(page).toHaveTitle('Lomo CodeSecurity · VS Code');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible();

  const navigation = page.getByRole('navigation', { name: 'Workbench views' });
  for (const route of routes) {
    await navigation.getByRole('button', { name: route.name, exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: route.name, exact: true })).toBeVisible();
    const location = new URL(page.url());
    expect(location.searchParams.get('view')).toBe(route.slug);
    expect(location.searchParams.get('lomo_browser')).toBe('vscode');
    if (route.slug !== 'findings') {
      expect(location.searchParams.has('scan')).toBe(false);
      expect(location.searchParams.has('finding')).toBe(false);
    }
  }

  await reloadAfterReads(page);
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  await expect(page).toHaveTitle('Lomo CodeSecurity · VS Code');
  await expect(navigation.getByRole('button', { name: 'Settings', exact: true })).toHaveAttribute('aria-current', 'page');
  expect(new URL(page.url()).searchParams.get('lomo_browser')).toBe('vscode');
  guards.assertClean();
});

referenceTest('idle dashboard discovers another client job on navigation and window focus', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'quiescent', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let externalRevision = 0;
  let historyReads = 0;
  await page.route('**/v1/jobs*', async (route) => {
    if (new URL(route.request().url()).searchParams.get('status') === 'active') {
      await route.fulfill({ status: 200, contentType: 'application/json', json: [] });
      return;
    }
    const response = await route.fetch();
    const rows = await response.json() as Array<Record<string, unknown>>;
    historyReads += 1;
    if (externalRevision > 0) rows.unshift({
      ...rows[0], id: 900, title: `Other editor completed job revision ${externalRevision}`,
      status: 'completed', stage: 'completed', revision: externalRevision,
      can_cancel: false, can_retry: false,
    });
    await route.fulfill({ response, json: rows });
  });

  await openRoute(page, 'Overview');
  const initialReads = historyReads;
  expect(initialReads).toBeGreaterThan(0);
  externalRevision = 1;
  await page.getByRole('navigation').getByRole('button', { name: 'Jobs', exact: true }).click();
  await expect(page.getByText('Other editor completed job revision 1', { exact: true })).toBeVisible();
  expect(historyReads).toBeGreaterThan(initialReads);
  await page.waitForLoadState('networkidle');

  const readsBeforeFocus = historyReads;
  externalRevision = 2;
  // This controlled regression represents an OS application switch, not an
  // end-to-end native foreground acceptance claim. The tab remains visible.
  await page.evaluate(() => {
    if (document.visibilityState !== 'visible') throw new Error('The dashboard must remain visible.');
    window.dispatchEvent(new Event('focus'));
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(page.getByText('Other editor completed job revision 2', { exact: true })).toBeVisible();
  await expect(page.getByText('Other editor completed job revision 1', { exact: true })).toHaveCount(0);
  await page.waitForLoadState('networkidle');
  expect(historyReads - readsBeforeFocus).toBe(1);
  await expect(page.getByText('job #900', { exact: true })).toHaveCount(1);
  expect(new URL(page.url()).searchParams.get('view')).toBe('jobs');

  // A focus event must not be lost when another endpoint is keeping an old
  // dashboard read in flight after its Jobs response has already completed.
  let releaseTools!: () => void;
  let reportToolsHeld!: () => void;
  const toolsReleased = new Promise<void>((resolve) => { releaseTools = resolve; });
  const toolsHeld = new Promise<void>((resolve) => { reportToolsHeld = resolve; });
  await page.route('**/v1/scanner/tools', async (route) => {
    const response = await route.fetch();
    reportToolsHeld();
    await toolsReleased;
    await route.fulfill({ response });
  }, { times: 1 });
  const readsBeforeHeldRefresh = historyReads;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await toolsHeld;
  await expect.poll(() => historyReads).toBe(readsBeforeHeldRefresh + 1);
  externalRevision = 3;
  await page.evaluate(() => {
    window.dispatchEvent(new Event('focus'));
    document.dispatchEvent(new Event('visibilitychange'));
  });
  releaseTools();
  await expect(page.getByText('Other editor completed job revision 3', { exact: true })).toBeVisible();
  await page.waitForLoadState('networkidle');
  expect(historyReads - readsBeforeHeldRefresh).toBe(2);
  await expect(page.getByText('job #900', { exact: true })).toHaveCount(1);
  expect(new URL(page.url()).searchParams.get('view')).toBe('jobs');
  guards.assertClean();
});

for (const scenario of [
  { route: 'Overview', profile: 'advisor-local-empty', summary: 'Overview summary', labels: ['Projects', 'Scans', 'Unique Findings', 'Artifacts', 'Advisor'] },
  { route: 'Tools', profile: 'scanner-preparation', summary: 'Scanner summary', labels: ['Scanners', 'Enabled', 'Updates', 'Real Tools', 'Artifacts'] },
] as const) {
  referenceTest(`${scenario.route} preserves summary text and primary actions with actual 200% text enlargement`, async ({ page, request, baseURL }, testInfo) => {
    test.setTimeout(qualificationMilliseconds(60_000));
    if (!baseURL) throw new Error('Playwright baseURL is required.');
    await request.post('/__test/reset', { data: { profile: scenario.profile, generation: 1 } });
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    await openRoute(page, scenario.route);
    const surface = page.locator(`section[data-route-surface="${scenario.route.toLowerCase()}"]`);
    const summary = surface.locator(`dl[aria-label="${scenario.summary}"]`);
    const readSummary = () => summary.locator(':scope > div').evaluateAll((items) => items.map((item) => [
      item.querySelector('dt')!.textContent, item.querySelector('dd')!.textContent,
    ]));
    await expect(summary.locator('dt')).toHaveText([...scenario.labels]);
    const initialSummary = await readSummary();
    expect(initialSummary.every(([, value]) => Boolean(value?.trim())), 'Every named count or observed status remains explicit').toBe(true);
    const primary = scenario.route === 'Overview'
      ? surface.locator('.risk-board').getByRole('button', { name: 'Findings', exact: true })
      : surface.getByRole('button', { name: 'Prepare all scanners', exact: true });
    const controls = scenario.route === 'Overview'
      ? [primary, surface.getByRole('button', { name: 'Set up Advisor', exact: true })]
      : [primary, surface.locator('.scanner-maintenance > summary')];
    if (scenario.route === 'Overview') {
      await expect(surface.locator('.risk-board h2')).toHaveText('Findings by severity');
      await expect(surface.locator('.risk-line > span')).toHaveText(['critical', 'high', 'medium', 'low', 'info']);
      await expect(surface.locator('.risk-line > strong')).toHaveText(['0', '1', '1', '0', '1']);
      await expect(summary.locator('dd').last()).toHaveText('Setup required');
      await expect(surface.locator('.advisor-card')).toContainText('Open Settings, choose one installed Ollama model, and use it locally once.');
    } else {
      await expect(surface.getByRole('heading', { name: 'Prepare Scanners', exact: true })).toBeVisible();
      await expect(surface.locator('.preflight-blocked-tools')).toContainText('OpenGrep');
      await expect(surface.locator('.tool-card').filter({ hasText: 'OpenGrep' }).getByLabel('OpenGrep runtime readiness'))
        .toContainText('No validated active or previous-good OpenGrep rules generation exists.');
    }
    await expect(primary).toBeEnabled();
    const textSelector = scenario.route === 'Overview'
      ? '.workbench-summary dt, .workbench-summary dd, .risk-board h2, .risk-line > span, .risk-line > strong, .risk-board button, .advisor-meter strong, .advisor-card > .helper-text'
      : '.workbench-summary dt, .workbench-summary dd, .scanner-preflight > .helper-text, .preparation-steps strong, .preparation-steps span, .preflight-blocked-tools li > strong, .preflight-blocked-tools li > span, .tool-card > p, .tool-head strong, .tool-head span, .tool-card .kv dt, .tool-card .kv dd, .tool-card .readiness-head span, .tool-card .readiness-head strong, .readiness-facet dt, .readiness-facet strong, .readiness-facet span, .readiness-facet small, .tool-actions button';
    const initialText = await surface.locator(textSelector).allTextContents();
    // Reuse the maintained Findings/Projects/Jobs method: snapshot computed
    // sizes before changing ancestors. Pixel-sized glyphs and finite leading
    // double exactly once; this is not native browser zoom evidence.
    const textScale = await page.evaluate(() => {
      const before = Array.from(document.querySelectorAll<HTMLElement>('*'))
        .filter((element) => element instanceof HTMLElement)
        .map((element) => ({ element, size: Number.parseFloat(getComputedStyle(element).fontSize), leading: Number.parseFloat(getComputedStyle(element).lineHeight) }));
      for (const { element, size, leading } of before) {
        element.style.fontSize = `${size * 2}px`;
        if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
      }
      const glyphs = before.filter(({ element }) => Array.from(element.childNodes)
        .some((node) => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent?.trim())));
      return { count: glyphs.length, mismatches: glyphs.flatMap(({ element, size }) => {
        const after = Number.parseFloat(getComputedStyle(element).fontSize);
        return Math.abs(after - size * 2) < 0.01 ? [] : [{ tag: element.tagName, before: size, after }];
      }) };
    });
    expect(textScale.count).toBeGreaterThan(30);
    expect(textScale.mismatches, 'Every existing glyph-bearing element actually doubles').toEqual([]);
    await testInfo.attach(`${scenario.route}-actual-text-enlargement.json`, { body: Buffer.from(JSON.stringify(textScale, null, 2)), contentType: 'application/json' });
    for (const width of [1440, 768, 390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await summary.scrollIntoViewIfNeeded();
      await expect.poll(readSummary).toEqual(initialSummary);
      await expect(surface.locator(textSelector)).toHaveText(initialText);
      const geometry = await surface.evaluate((element, selector) => ({
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        items: Array.from(element.querySelectorAll<HTMLElement>(selector)).map((item) => {
          const bounds = item.getBoundingClientRect();
          const range = document.createRange();
          range.selectNodeContents(item);
          return { text: item.textContent, left: bounds.left, right: bounds.right, top: bounds.top, bottom: bounds.bottom,
            width: bounds.width, height: bounds.height, clientWidth: item.clientWidth, scrollWidth: item.scrollWidth,
            clientHeight: item.clientHeight, scrollHeight: item.scrollHeight,
            glyphs: Array.from(range.getClientRects()).map((rect) => ({ left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom })) };
        }),
      }), textSelector);
      await testInfo.attach(`${scenario.route}-${width}-text-200-geometry.json`, { body: Buffer.from(JSON.stringify(geometry, null, 2)), contentType: 'application/json' });
      expect(geometry.overflow, `${width}px enlarged ${scenario.route} page has no horizontal overflow`).toBeLessThanOrEqual(1);
      for (const item of geometry.items) {
        expect(item.width, item.text || 'Visible text').toBeGreaterThan(0);
        expect(item.height, item.text || 'Visible text').toBeGreaterThan(0);
        expect(item.left).toBeGreaterThanOrEqual(-0.5);
        expect(item.right).toBeLessThanOrEqual(width + 0.5);
        expect(item.scrollWidth, `${item.text} horizontal clipping`).toBeLessThanOrEqual(item.clientWidth + 1);
        expect(item.scrollHeight, `${item.text} vertical clipping`).toBeLessThanOrEqual(item.clientHeight + 1);
        for (const glyph of item.glyphs) {
          expect(glyph.left, `${item.text} glyph left containment`).toBeGreaterThanOrEqual(item.left - 1);
          expect(glyph.right, `${item.text} glyph right containment`).toBeLessThanOrEqual(item.right + 1);
          expect(glyph.top, `${item.text} glyph top containment`).toBeGreaterThanOrEqual(item.top - 1);
          expect(glyph.bottom, `${item.text} glyph bottom containment`).toBeLessThanOrEqual(item.bottom + 1);
        }
      }
      for (const control of controls) {
        await control.focus();
        await expect(control).toBeFocused();
        // Center the target instead of relying on nearest-edge scroll rounding.
        await control.evaluate((element) => element.scrollIntoView({ block: 'center', inline: 'nearest' }));
        await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
        await expect(control).toBeInViewport({ ratio: 1 });
        const hit = await control.evaluate((element) => {
          const bounds = element.getBoundingClientRect();
          const target = document.elementFromPoint((bounds.left + bounds.right) / 2, (bounds.top + bounds.bottom) / 2);
          return { left: bounds.left, right: bounds.right, scrollWidth: element.scrollWidth, clientWidth: element.clientWidth,
            matches: target !== null && element.contains(target) };
        });
        expect(hit.left).toBeGreaterThanOrEqual(-0.5);
        expect(hit.right).toBeLessThanOrEqual(width + 0.5);
        expect(hit.scrollWidth).toBeLessThanOrEqual(hit.clientWidth + 1);
        expect(hit.matches, `${scenario.route} primary control owns its painted target at ${width}px`).toBe(true);
      }
      if (width <= 390) await testInfo.attach(`${scenario.route}-summary-${width}-text-200.png`, { body: await summary.screenshot(), contentType: 'image/png' });
    }
    if (scenario.route === 'Overview') {
      await primary.focus();
      await primary.press('Enter');
      await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
    } else {
      const maintenance = surface.locator('.scanner-maintenance');
      await maintenance.locator(':scope > summary').press('Enter');
      await expect(maintenance).toHaveAttribute('open', '');
      await expect(maintenance.getByRole('button', { name: 'Check curated catalog', exact: true })).toBeVisible();
      await expect(primary).toBeEnabled();
    }
    expect(await (await request.get('/__test/commands')).json()).toEqual([]);
    guards.assertClean();
  });
}

test('Overview gives a human setup path when no Advisor provider is configured', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'advisor-local-empty', generation: 1 } });
  const detectedModels = [
    'qwen3:8b',
    'minimax-m3:cloud',
    'kimi-k3:cloud',
    'glm-5.2:cloud',
    'kimi-k2.7-code:cloud',
    'kimi-k2.6:cloud',
    'glm-5.1:cloud',
  ];
  await page.route('**/healthz', async (route) => {
    const response = await route.fetch();
    const health = await response.json() as { ai?: { models?: string[]; reason?: string } };
    health.ai = { ...(health.ai || {}), models: detectedModels, reason: 'no_provider_configured' };
    await route.fulfill({ response, json: health });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Overview');

  const advisor = page.locator('.advisor-card');
  await expect(advisor.locator('.advisor-meter strong')).toHaveText('Setup required');
  await expect(page.locator('.top-actions')).toContainText('Advisor setup required');
  await expect(page.locator('.top-actions')).toContainText('Control plane healthy');
  await expect(advisor).toContainText('Open Settings, choose one installed Ollama model, and use it locally once.');
  await expect(advisor.getByRole('button', { name: 'Set up Advisor', exact: true })).toBeVisible();
  await expect(advisor).not.toContainText('no_provider_configured');
  await expect(page.getByRole('status', { name: 'Control plane healthy', exact: true })).toBeVisible();

  await advisor.getByRole('button', { name: 'Set up Advisor', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  await expect(page.locator('#advisor-providers')).toBeVisible();
  const advisorRoute = page.getByRole('heading', { level: 2, name: 'Advisor Route', exact: true }).locator('xpath=../..');
  await expect(advisorRoute).toContainText('No local Advisor provider is configured yet.');
  await expect(advisorRoute).not.toContainText('no_configured_provider');
  const transportModels = advisorRoute.getByRole('list', { name: 'Detected local transport models', exact: true });
  const modelItems = transportModels.getByRole('listitem');
  await expect(modelItems).toHaveCount(detectedModels.length);
  await expect(modelItems).toHaveText(detectedModels);
  for (let index = 0; index < detectedModels.length; index += 1) await expect(modelItems.nth(index)).toBeVisible();
  guards.assertClean();
});

test('Overview Recent Scans keeps the exact Open findings control visible within every supported viewport', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.clock.setFixedTime('2026-08-12T08:00:04Z');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Overview');

  const overview = page.locator('section[data-route-surface="overview"]');
  const recentScans = overview.locator('.band').filter({
    has: page.getByRole('heading', { level: 2, name: 'Recent Scans', exact: true }),
  });
  await expect(recentScans).toHaveCount(1);
  const scan = recentScans.getByRole('row', { name: 'Open findings for scan #40', exact: true });
  const open = scan.getByRole('button', { name: 'Open findings', exact: true });
  await expect(open).toHaveCount(1);
  await expect(open).toHaveAccessibleName('Open findings');
  await expect(open).toBeEnabled();
  await expect(recentScans.getByRole('button', { name: /^Delete scan #/u })).toHaveCount(0);
  // This panel is below the ordinary route screenshot's fold. Capture the
  // actual responsive row and visible action, without changing any baseline.
  await scan.scrollIntoViewIfNeeded();
  await open.scrollIntoViewIfNeeded();
  await open.focus();
  await expect(open).toBeFocused();
  await expect(open).toBeVisible();
  const controlGeometry = () => open.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    return {
      left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
      width: rect.width, height: rect.height,
      viewportWidth: document.documentElement.clientWidth, viewportHeight: window.innerHeight,
      documentScrollWidth: document.documentElement.scrollWidth,
      controlScrollWidth: element.scrollWidth, controlClientWidth: element.clientWidth,
    };
  });
  await expect.poll(async () => {
    const geometry = await controlGeometry();
    return geometry.width > 0 && geometry.height > 0
      && geometry.left >= -0.5 && geometry.top >= -0.5
      && geometry.right <= geometry.viewportWidth + 0.5
      && geometry.bottom <= geometry.viewportHeight + 0.5;
  }, { message: 'The complete scan 40 action must be inside the viewport.' }).toBe(true);
  await expect(open).toBeInViewport({ ratio: 1 });
  const geometry = await controlGeometry();
  expect(geometry.documentScrollWidth, 'Recent Scans must not cause horizontal page overflow.').toBeLessThanOrEqual(geometry.viewportWidth);
  expect(geometry.controlScrollWidth, 'The Open findings label must not be clipped.').toBeLessThanOrEqual(geometry.controlClientWidth + 1);
  await testInfo.attach('overview-recent-scan-40.png', { body: await scan.screenshot({ animations: 'disabled' }), contentType: 'image/png' });
  await expect(open).toBeInViewport({ ratio: 1 });
  await testInfo.attach('overview-recent-scan-40-geometry.json', { body: Buffer.from(JSON.stringify(geometry)), contentType: 'application/json' });

  // The operator journey separately proves pointer and native Enter activation
  // plus unchanged revisions/no mutations. Here each viewport proves the
  // visible responsive control still opens its non-default scan.
  await open.click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  const findings = page.locator('section[data-route-surface="findings"]');
  await expect(findings.getByLabel('Scan', { exact: true })).toHaveValue('40');
  await expect(findings).not.toHaveAttribute('aria-busy', 'true');
  await expect(findings).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(findings.locator('.finding-list-item')).toHaveCount(0);
  expect(new URL(page.url()).searchParams.toString()).toBe('view=findings&scan=40');
  await page.waitForLoadState('networkidle');
  guards.assertClean();
});

test('Scan History exposes an explicit Open findings action', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Scans');

  const scan = page.getByRole('row', { name: 'Open findings for scan #41', exact: true });
  const open = scan.getByRole('button', { name: 'Open findings', exact: true });
  const remove = scan.getByRole('button', { name: 'Delete scan #41', exact: true });
  await expect(open).toBeVisible();
  await remove.focus();
  await remove.press('Enter');
  await expect(page.getByRole('heading', { level: 1, name: 'Scans', exact: true })).toBeVisible();
  const confirmation = page.getByRole('dialog', { name: 'Delete scan #41?', exact: true });
  await expect(confirmation).toBeVisible();
  await confirmation.getByRole('button', { name: 'Keep scan', exact: true }).click();
  await expect(remove).toBeFocused();
  await open.click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F001');
  guards.assertClean();
});

referenceTest('Scan History keeps actions reachable at narrow widths with actual 200% text', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Scans');
  const scale = await page.evaluate(() => {
    const before = [...document.querySelectorAll<HTMLElement>('*')].filter(element => element instanceof HTMLElement)
      .map(element => ({ element, size: parseFloat(getComputedStyle(element).fontSize), leading: parseFloat(getComputedStyle(element).lineHeight) }));
    for (const { element, size, leading } of before) {
      element.style.fontSize = `${size * 2}px`;
      if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
    }
    return { count: before.length, mismatches: before.filter(({ element, size }) => Math.abs(parseFloat(getComputedStyle(element).fontSize) - size * 2) >= 0.01).length };
  });
  expect(scale.count).toBeGreaterThan(30);
  expect(scale.mismatches).toBe(0);
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    const controls = page.locator('.scan-row-actions button');
    expect(await controls.count()).toBeGreaterThan(1);
    for (const button of await controls.all()) {
      await button.scrollIntoViewIfNeeded();
      const bounds = await button.evaluate(element => {
        const rectangle = element.getBoundingClientRect();
        const target = document.elementFromPoint((rectangle.left + rectangle.right) / 2, (rectangle.top + rectangle.bottom) / 2);
        return { left: rectangle.left, right: rectangle.right, ownsTarget: target !== null && element.contains(target),
          horizontalClip: element.scrollWidth - element.clientWidth, verticalClip: element.scrollHeight - element.clientHeight };
      });
      expect(bounds.left).toBeGreaterThanOrEqual(0);
      expect(bounds.right).toBeLessThanOrEqual(width);
      expect(bounds.horizontalClip).toBeLessThanOrEqual(1);
      expect(bounds.verticalClip).toBeLessThanOrEqual(1);
      expect(bounds.ownsTarget).toBe(true);
    }
    const geometry = await page.evaluate(inspectControlLayout);
    expect(geometry.offscreenControls).toEqual([]);
    expect(geometry.overlaps).toEqual([]);
    await testInfo.attach(`scan-actions-${width}-text-200.png`, { body: await page.locator('.scan-table tr').last().screenshot(), contentType: 'image/png' });
  }
  const scan = page.getByRole('row', { name: 'Open findings for scan #41', exact: true });
  await scan.getByRole('button', { name: 'Open findings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F001');
  guards.assertClean();
});

test('navigation replaces the accessible route identity with the visible view', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  await page.getByRole('navigation').getByRole('button', { name: 'Projects', exact: true }).click();
  const main = page.locator('main[data-rendered-view="projects"]');
  await expect(main).toHaveAccessibleName('Projects');
  await expect(main.getByRole('heading', { level: 1 })).toHaveAccessibleName('Projects');
  await expect(main.getByRole('heading', { level: 1 })).toHaveText('Projects');
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Projects', exact: true }))
    .toHaveAttribute('aria-current', 'page');
  guards.assertClean();
});

test('Findings exposes the flagged source in the initial desktop review viewport', async ({ page, request, baseURL }, testInfo) => {
  test.skip(!['desktop-1440', 'desktop-1920'].includes(testInfo.project.name),
    'This contract concerns the initial normal desktop review viewport.');
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'findings-first-viewport', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');
  const detail = page.locator('.finding-detail');
  await expect(detail.locator('h2')).toHaveText('S41-F001');
  await expect(page.locator('section[data-route-surface="findings"]'))
    .toHaveAttribute('data-findings-render-stage', 'ready');
  expect(await page.locator('main').evaluate((element) => element.scrollTop)).toBe(0);
  expect(await detail.evaluate((element) => element.scrollTop)).toBe(0);
  await expect(detail.locator('.code-row.offender .code-gutter'),
    'The flagged line must be readable without first scrolling past IDE connection controls.').toBeInViewport({ ratio: 1 });
  await expect(detail.locator('.code-source')).toContainText('return eval(generatedInput);');
  await expect(detail.getByRole('button', { name: 'Open source in VS Code', exact: true })).toBeDisabled();
  await expect(detail.getByRole('button', { name: 'Open source in VS Code', exact: true })).toBeInViewport({ ratio: 1 });
  await expect(detail.getByRole('button', { name: 'Run Advisor', exact: true })).toBeInViewport({ ratio: 1 });
  await testInfo.attach('findings-initial-review-viewport.png', {
    body: await page.screenshot({ animations: 'disabled', caret: 'hide', fullPage: false }), contentType: 'image/png',
  });
  await expect(detail.getByRole('button', { name: 'Open source in VS Code', exact: true }))
    .toHaveAccessibleDescription(/No paired IDE has exactly one active CodeSecurity event-stream connection/);
  const description = detail.locator('.finding-description');
  await description.locator('summary').press('Enter');
  await expect(description.locator('.finding-summary')).toContainText('Review the highlighted source and the surrounding validation');
  await description.locator('summary').press('Enter');
  const ideConnection = detail.locator('.finding-ide-menu > summary');
  await ideConnection.focus();
  await ideConnection.press('Enter');
  await expect(detail.getByLabel('IDE target for source navigation')).toBeVisible();
  await detail.getByRole('button', { name: 'Refresh connected IDE clients', exact: true }).click();
  await ideConnection.click();
  await expect(detail.getByRole('button', { name: 'Run Advisor', exact: true })).toBeEnabled();
  await detail.locator('.finding-action-menu > summary').click();
  await expect(detail.getByRole('button', { name: 'Accept risk', exact: true })).toBeVisible();
  guards.assertClean();
});

referenceTest('Findings keeps review reachable in a short editor pane', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await page.setViewportSize({ width: 780, height: 465 });
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');
  const first = page.locator('.finding-list-item').first();
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
  await expect(page.getByPlaceholder('Search findings')).toBeInViewport({ ratio: 1 });
  await expect(page.getByLabel('Repository push protection', { exact: true })).toContainText('No matching protection record');
  const navigation = page.getByRole('navigation');
  for (const { name } of routes) {
    await expect(navigation.getByRole('button', { name, exact: true })).toBeInViewport({ ratio: 1 });
  }
  await testInfo.attach('findings-short-editor-pane.png', { body: await page.screenshot(), contentType: 'image/png' });
  // A short pane keeps source, unverified-protection guidance and search in
  // reach; one keyboard page reaches the evidence without hiding warnings.
  await page.locator('body').press('PageDown');
  await expect(first.locator('.finding-rule')).toBeInViewport({ ratio: 1 });
  await first.locator('.finding-list-main').focus();
  await first.locator('.finding-list-main').press('Enter');
  await expect(page.locator('.finding-detail-head')).toContainText('javascript.lang.audit.dynamic-code');
  await page.evaluate(() => {
    const sizes = Array.from(document.querySelectorAll<HTMLElement>('*')).map((element) => {
      const style = getComputedStyle(element);
      return { element, font: parseFloat(style.fontSize), line: parseFloat(style.lineHeight) };
    });
    for (const { element, font, line } of sizes) {
      if (Number.isFinite(font)) element.style.fontSize = `${font * 2}px`;
      if (Number.isFinite(line)) element.style.lineHeight = `${line * 2}px`;
    }
  });
  for (const width of [641, 780, 1024, 1264]) {
    await page.setViewportSize({ width, height: 465 });
    const geometry = await page.evaluate(inspectControlLayout);
    expect(geometry.documentOverflow, `${width}px with doubled text`).toBeLessThanOrEqual(1);
    expect(geometry.offscreenControls).toEqual([]);
    expect(geometry.selfClippedControls).toEqual([]);
    for (const button of await navigation.getByRole('button').all()) {
      expect(await button.evaluate(element => ({
        horizontal: element.scrollWidth - element.clientWidth,
        vertical: element.scrollHeight - element.clientHeight,
      }))).toEqual({ horizontal: 0, vertical: 0 });
    }
  }
  await navigation.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.locator('main')).toHaveAccessibleName('Settings');
  guards.assertClean();
});

test('Findings makes the first result readable in the initial mobile review viewport', async ({ page, request, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-390', 'This contract concerns initial 390px review reach.');
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');
  expect(await page.locator('main').evaluate((element) => element.scrollTop)).toBe(0);
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
  const first = page.locator('.finding-list-item').first();
  await expect(first).toBeInViewport({ ratio: 1 });
  await expect(first.locator('.finding-rule')).toBeInViewport({ ratio: 1 });
  const title = await first.locator('.finding-rule').evaluate((element) => ({
    text: element.textContent, whiteSpace: getComputedStyle(element).whiteSpace,
    height: element.clientHeight, scrollHeight: element.scrollHeight,
    width: element.clientWidth, scrollWidth: element.scrollWidth,
  }));
  expect(title.text).toBe('Dynamic code execution can consume untrusted input.');
  expect(title.whiteSpace).toBe('normal');
  expect(title.scrollHeight, 'The readable title must not be internally clipped.').toBeLessThanOrEqual(title.height + 1);
  expect(title.scrollWidth).toBeLessThanOrEqual(title.width + 1);
  expect(await first.evaluate((element) => element.getBoundingClientRect().bottom)).toBeLessThanOrEqual(836);
  await expect(first.locator('.finding-message')).toHaveAttribute('title', 'javascript.lang.audit.dynamic-code');
  await expect(first.locator('.finding-list-main')).toHaveAccessibleName(/javascript\.lang\.audit\.dynamic-code/);
  await expect(page.getByLabel('Repository push protection', { exact: true })).toContainText('No matching protection record');
  await testInfo.attach('findings-mobile-initial-review.png', { body: await page.screenshot(), contentType: 'image/png' });
  await first.locator('.finding-list-main').focus(); await first.locator('.finding-list-main').press('Enter');
  await expect(page.locator('.finding-detail-head')).toContainText('javascript.lang.audit.dynamic-code');
  await expect(page.locator('.finding-detail-head .finding-readable-title')).toHaveText(title.text!);
  const filters = page.locator('.finding-filter-details');
  await filters.locator('summary').focus(); await filters.locator('summary').press('Enter');
  await expect(page.getByLabel('Severity', { exact: true })).toBeVisible();
  await page.getByLabel('Severity', { exact: true }).selectOption('high');
  await expect(page.getByRole('button', { name: 'Clear filters', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
  await filters.locator('summary').press('Enter');
  const select = page.getByRole('button', { name: 'Select visible', exact: true });
  await select.focus(); await select.press('Enter');
  await expect(page.getByRole('region', { name: 'Bulk finding actions' })).toContainText('3 selected');
  guards.assertClean();
});

test('Findings detail controls stay readable and contained with the Lifecycle menu open', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  if (testInfo.project.name === 'desktop-1440') {
    await page.setViewportSize({ width: 1024, height: 900 });
  }
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const detail = page.locator('.finding-detail');
  await expect(detail.locator('h2')).toHaveText('S41-F001');
  const geometry = await detail.evaluate((element) => {
    const rectangle = (target: Element) => {
      const value = target.getBoundingClientRect();
      return { bottom: value.bottom, height: value.height, left: value.left, right: value.right, top: value.top, width: value.width };
    };
    const head = element.querySelector('.finding-detail-head');
    const identity = head?.firstElementChild;
    const actions = element.querySelector('.finding-detail-actions');
    if (!head || !identity || !actions) throw new Error('Finding detail header geometry is unavailable.');
    const actionItems = Array.from(actions.children).map(rectangle);
    return {
      actions: rectangle(actions),
      actionItems,
      detail: rectangle(element),
      documentClientWidth: document.documentElement.clientWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      identity: rectangle(identity),
      overlappingActionPairs: actionItems.flatMap((left, leftIndex) => actionItems.slice(leftIndex + 1).map((right, rightOffset) => ({
        leftIndex,
        rightIndex: leftIndex + rightOffset + 1,
        overlaps: Math.min(left.right, right.right) - Math.max(left.left, right.left) > 0.5
          && Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top) > 0.5,
      }))).filter((pair) => pair.overlaps),
    };
  });
  expect(geometry.documentScrollWidth, 'Findings must not create horizontal page overflow.').toBeLessThanOrEqual(geometry.documentClientWidth);
  expect(geometry.identity.width, 'The finding identity must retain a readable line width.').toBeGreaterThan(200);
  expect(geometry.identity.bottom, 'The action row must follow, not overlap, the finding identity.').toBeLessThanOrEqual(geometry.actions.top + 0.5);
  expect(geometry.overlappingActionPairs, 'Finding detail action controls must not overlap.').toEqual([]);
  for (const item of geometry.actionItems) {
    expect(item.left, 'Action control is clipped through the detail left edge.').toBeGreaterThanOrEqual(geometry.detail.left + 15);
    expect(item.right, 'Action control is clipped through the detail right edge.').toBeLessThanOrEqual(geometry.detail.right - 15);
  }

  const lifecycle = detail.locator('.finding-action-menu');
  await lifecycle.locator('summary').click();
  await expect(lifecycle).toHaveAttribute('open', '');
  await expect(lifecycle.getByRole('button', { name: 'Non-blocking for gate', exact: true })).toBeVisible();
  const menuGeometry = await lifecycle.locator(':scope > div').evaluate((element) => {
    const menu = element.getBoundingClientRect();
    const owner = element.closest('.finding-detail')?.getBoundingClientRect();
    if (!owner) throw new Error('Lifecycle menu lost its finding detail owner.');
    const buttons = Array.from(element.querySelectorAll('button')).map((button) => button.getBoundingClientRect());
    return {
      buttonsOverlap: buttons.some((button, index) => buttons.slice(index + 1).some((next) => (
        Math.min(button.right, next.right) - Math.max(button.left, next.left) > 0.5
        && Math.min(button.bottom, next.bottom) - Math.max(button.top, next.top) > 0.5
      ))),
      menu: { bottom: menu.bottom, left: menu.left, right: menu.right, top: menu.top },
      owner: { left: owner.left, right: owner.right },
      viewport: { height: window.innerHeight, width: window.innerWidth },
    };
  });
  expect(menuGeometry.menu.left, 'Lifecycle menu is clipped through the finding detail left edge.').toBeGreaterThanOrEqual(menuGeometry.owner.left + 15);
  expect(menuGeometry.menu.right, 'Lifecycle menu is clipped through the finding detail right edge.').toBeLessThanOrEqual(menuGeometry.owner.right - 15);
  expect(menuGeometry.menu.left).toBeGreaterThanOrEqual(0);
  expect(menuGeometry.menu.right).toBeLessThanOrEqual(menuGeometry.viewport.width);
  expect(menuGeometry.buttonsOverlap, 'Lifecycle actions must render as distinct rows.').toBe(false);

  const nextFinding = page.locator('.finding-list-item', { hasText: 'S41-F002' }).locator('.finding-list-main');
  await nextFinding.click();
  await expect(detail.locator('h2')).toHaveAccessibleName('S41-F002');
  await expect(detail.locator('h2')).toHaveText('S41-F002');
  await expect(detail.locator('.identity-strip span').filter({ hasText: 'Repeat status' }))
    .toHaveAttribute('title', 'Repeat finding. Same fingerprint appears 2 times across stored scans. First seen as S40-F001. Internal database ID #502.');
  await expect(detail.locator('.path-line')).toHaveAttribute('title', '/workspace/generated/demo-service/infra/service.yaml');
  await expect(detail.locator('.path-line small')).toHaveText('/workspace/generated/demo-service/infra/service.yaml');
  await expect(detail).not.toHaveAttribute('aria-busy', 'true');
  guards.assertClean();
});

referenceTest('Settings provider forms stay contained at an intermediate desktop width', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await page.setViewportSize({ width: 1100, height: 900 });
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');

  const providers = page.locator('#advisor-providers');
  await providers.getByRole('button', { name: 'Add provider', exact: true }).click();
  const forms = page.locator('.advisor-policy-form, .advisor-provider-fields');
  await expect(forms).toHaveCount(2);
  const geometry = await forms.evaluateAll((elements) => elements.map((element) => {
    const form = element.getBoundingClientRect();
    return {
      className: String(element.className),
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
      children: Array.from(element.children).map((child) => {
        const rectangle = child.getBoundingClientRect();
        return { left: rectangle.left, right: rectangle.right };
      }),
      form: { left: form.left, right: form.right },
    };
  }));
  const documentGeometry = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));

  expect(documentGeometry.scrollWidth, 'Settings must not create horizontal page overflow.').toBeLessThanOrEqual(documentGeometry.clientWidth);
  for (const form of geometry) {
    expect(form.scrollWidth, `${form.className} must not have clipped horizontal content.`).toBeLessThanOrEqual(form.clientWidth);
    for (const child of form.children) {
      expect(child.left, `${form.className} child is clipped through the left edge.`).toBeGreaterThanOrEqual(form.form.left - 0.5);
      expect(child.right, `${form.className} child is clipped through the right edge.`).toBeLessThanOrEqual(form.form.right + 0.5);
    }
  }
  guards.assertClean();
});

referenceTest('Settings browser pairing result stays contained at narrow and zoomed Mac geometry when copy is denied', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async () => { throw new Error('clipboard denied'); } },
    });
  });
  await page.route('**/v1/auth/browser/pairing-token', async (route) => {
    await route.fulfill({
      json: {
        bootstrap_token: `kb1.${'b'.repeat(43)}`,
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        expires_in: 600,
      },
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');

  for (const boundary of [
    { label: '390 narrow', width: 390, height: 844, fontScale: 1 },
    { label: '768 at 200% text', width: 768, height: 1024, fontScale: 2 },
    { label: 'short Mac window', width: 1458, height: 706, fontScale: 1 },
  ]) {
    await page.setViewportSize({ width: boundary.width, height: boundary.height });
    await page.evaluate((fontScale) => { document.documentElement.style.fontSize = `${fontScale * 100}%`; }, boundary.fontScale);
    const panel = page.locator('.browser-pairing-panel');
    await panel.getByRole('button', { name: /Generate (?:new|replacement) browser pairing key/u }).click();
    const result = panel.getByRole('region', { name: 'New browser pairing key', exact: true });
    await expect(result).toBeVisible();
    await result.getByRole('button', { name: 'Copy browser pairing key', exact: true }).click();
    await expect(result.getByRole('status').filter({ hasText: 'Automatic copy is unavailable.' })).toBeVisible();
    const geometry = await panel.evaluate((element) => {
      const owner = element.getBoundingClientRect();
      const visible = Array.from(element.querySelectorAll('input, button, [role="status"], ol')).filter((candidate) => {
        const style = getComputedStyle(candidate);
        const bounds = candidate.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && bounds.width > 0 && bounds.height > 0;
      });
      return {
        clientWidth: element.clientWidth,
        items: visible.map((candidate) => {
          const bounds = candidate.getBoundingClientRect();
          return { left: bounds.left, right: bounds.right, scrollWidth: candidate.scrollWidth, clientWidth: candidate.clientWidth, tagName: candidate.tagName };
        }),
        owner: { left: owner.left, right: owner.right },
        scrollWidth: element.scrollWidth,
      };
    });
    expect(geometry.scrollWidth, `${boundary.label} pairing panel overflow`).toBeLessThanOrEqual(geometry.clientWidth + 1);
    for (const item of geometry.items) {
      expect(item.left, `${boundary.label} pairing item left edge`).toBeGreaterThanOrEqual(geometry.owner.left - 0.5);
      expect(item.right, `${boundary.label} pairing item right edge`).toBeLessThanOrEqual(geometry.owner.right + 0.5);
      if (item.tagName !== 'INPUT') {
        expect(item.scrollWidth, `${boundary.label} pairing item clips content`).toBeLessThanOrEqual(item.clientWidth + 1);
      }
    }
  }
  guards.assertClean();
});

referenceTest('Web routes keep primary content and controls contained across responsive boundaries', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  test.setTimeout(qualificationMilliseconds(90_000));
  const longProjectName = `Project${'x'.repeat(113)}`;
  const longArtifactIdentity = 'syft-security-bom-generator-with-an-intentionally-long-operator-visible-identity';
  const longArtifactType = 'software-bill-of-materials-with-an-intentionally-long-type-identity';
  const longArtifactFormat = 'cyclonedx-json-with-an-intentionally-long-format-identity';
  const cases = [
    // A classic 15px scrollbar leaves 305px of content in a 320px window.
    // Exercise that usable width even on hosts with overlay scrollbars.
    { label: '305 available width after scrollbar', width: 305, height: 844, fontScale: 1 },
    { label: '320', width: 320, height: 844, fontScale: 1 },
    { label: '390', width: 390, height: 844, fontScale: 1 },
    { label: '768', width: 768, height: 1024, fontScale: 1 },
    { label: '981', width: 981, height: 900, fontScale: 1 },
    { label: '1147 short wide-screen', width: 1147, height: 534, fontScale: 1 },
    { label: '1180', width: 1180, height: 900, fontScale: 1 },
    { label: '1241', width: 1241, height: 900, fontScale: 1 },
    { label: '1264', width: 1264, height: 900, fontScale: 1 },
    { label: '1440', width: 1440, height: 900, fontScale: 1 },
    { label: '1440 at 125% text', width: 1440, height: 900, fontScale: 1.25 },
    { label: '1458 short Mac window', width: 1458, height: 706, fontScale: 1 },
    { label: '1530 short wide-screen', width: 1530, height: 712, fontScale: 1 },
    { label: '1835 wide-screen at 125% browser geometry', width: 1835, height: 854, fontScale: 1 },
    { label: '1920', width: 1920, height: 1080, fontScale: 1 },
    { label: '2048 user screenshot geometry', width: 2048, height: 953, fontScale: 1 },
    { label: '2294 user screenshot geometry', width: 2294, height: 1068, fontScale: 1 },
    { label: '2294 user screenshot geometry at 125% text', width: 2294, height: 1068, fontScale: 1.25 },
  ] as const;

  for (const boundary of cases) {
    await page.setViewportSize({ width: boundary.width, height: boundary.height });
    await request.post('/__test/reset', { data: { profile: 'responsive-long-content', generation: 1 } });
    await page.goto('/?view=overview');
    await page.evaluate((fontScale) => {
      document.documentElement.style.fontSize = `${fontScale * 100}%`;
    }, boundary.fontScale);
    await expect(page.locator('main')).toHaveAttribute('data-rendered-view', 'overview');

    for (const route of routes) {
      const routeName = route.name.toLowerCase();
      if (route.name !== 'Overview') {
        await page.getByRole('navigation').getByRole('button', { name: route.name, exact: true }).click();
      }
      const surface = page.locator(`main[data-rendered-view="${routeName}"] > section[data-route-surface="${routeName}"]`);
      await expect(surface, `${boundary.label} ${route.name} surface`).toHaveCount(1);
      await expect(surface).not.toHaveAttribute('aria-busy', 'true');
      await expect(surface).not.toHaveAttribute('inert', '');

      const inspectLayout = () => page.evaluate(inspectControlLayout);

      const issues = await inspectLayout();
      if (issues.clippedOverlapEvidence.length) {
        await testInfo.attach(`clipped-control-overlaps-${boundary.label}-${route.slug}.json`, {
          body: Buffer.from(JSON.stringify(issues.clippedOverlapEvidence, null, 2)), contentType: 'application/json',
        });
      }
      expect(issues.clippedOverlapEvidence.filter((entry) => entry.hitMatchesExpected === false), `${boundary.label} ${route.name} clipped-pair hit targets`).toEqual([]);
      expect(issues.documentOverflow, `${boundary.label} ${route.name} document overflow`).toBeLessThanOrEqual(1);
      expect(issues.offscreenControls, `${boundary.label} ${route.name} offscreen controls`).toEqual([]);
      expect(issues.overlaps, `${boundary.label} ${route.name} overlapping controls`).toEqual([]);
      expect(issues.crushedText, `${boundary.label} ${route.name} one-character text wrapping`).toEqual([]);
      expect(issues.selfClippedControls, `${boundary.label} ${route.name} controls clipping their own labels`).toEqual([]);

      if (route.name === 'Projects') {
        const registration = surface.locator('.project-registration');
        await registration.locator(':scope > summary').click();
        await expect(registration).toHaveAttribute('open', '');
        await expect(registration.getByLabel('Name', { exact: true })).toBeVisible();
        const expandedIssues = await inspectLayout();
        if (expandedIssues.clippedOverlapEvidence.length) {
          await testInfo.attach(`clipped-control-overlaps-${boundary.label}-projects-expanded.json`, {
            body: Buffer.from(JSON.stringify(expandedIssues.clippedOverlapEvidence, null, 2)), contentType: 'application/json',
          });
        }
        expect(expandedIssues.clippedOverlapEvidence.filter((entry) => entry.hitMatchesExpected === false), `${boundary.label} expanded Projects clipped-pair hit targets`).toEqual([]);
        expect(expandedIssues.documentOverflow, `${boundary.label} expanded Projects document overflow`).toBeLessThanOrEqual(1);
        expect(expandedIssues.offscreenControls, `${boundary.label} expanded Projects offscreen controls`).toEqual([]);
        expect(expandedIssues.overlaps, `${boundary.label} expanded Projects overlapping controls`).toEqual([]);
        expect(expandedIssues.crushedText, `${boundary.label} expanded Projects one-character text wrapping`).toEqual([]);
        expect(expandedIssues.selfClippedControls, `${boundary.label} expanded Projects controls clipping their own labels`).toEqual([]);
      }

      if (route.name === 'Settings') {
        const schemaStatus = surface.locator('[data-schema-init-state="completed"]');
        const schemaGeometry = await schemaStatus.evaluate((element) => {
          const bounds = element.getBoundingClientRect();
          const values = Array.from(element.querySelectorAll('code')).map((value) => {
            const valueBounds = value.getBoundingClientRect();
            return { left: valueBounds.left, right: valueBounds.right };
          });
          return {
            clientWidth: element.clientWidth,
            left: bounds.left,
            right: bounds.right,
            scrollWidth: element.scrollWidth,
            values,
          };
        });
        expect(schemaGeometry.scrollWidth, `${boundary.label} schema-init status horizontal overflow`).toBeLessThanOrEqual(schemaGeometry.clientWidth + 1);
        for (const value of schemaGeometry.values) {
          expect(value.left, `${boundary.label} schema-init value left edge`).toBeGreaterThanOrEqual(schemaGeometry.left - 0.5);
          expect(value.right, `${boundary.label} schema-init value right edge`).toBeLessThanOrEqual(schemaGeometry.right + 0.5);
        }
      }

      if (route.name === 'Findings') {
        const projectName = surface.locator('.finding-context-source > strong');
        await expect(projectName).toHaveText(longProjectName);
        await expect(projectName).toBeVisible();
        const projectGeometry = await projectName.evaluate((element) => ({
          clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
          clientHeight: element.clientHeight, scrollHeight: element.scrollHeight,
        }));
        expect(projectGeometry.scrollWidth, `${boundary.label} exact unbroken project name wraps`).toBeLessThanOrEqual(projectGeometry.clientWidth + 1);
        expect(projectGeometry.scrollHeight, `${boundary.label} exact unbroken project name is not clipped`).toBeLessThanOrEqual(projectGeometry.clientHeight + 1);
        await expandFindingDisclosure(surface, '.finding-filter-details');
        if (!await surface.locator('.bulk-action-disclosure').isVisible()) {
          await surface.getByRole('button', { name: 'Select visible', exact: true }).click();
        }
        await expandFindingDisclosure(surface, '.bulk-action-disclosure');
        await expandFindingDisclosure(surface, '.finding-scan-details');
        const expandedIssues = await inspectLayout();
        if (expandedIssues.clippedOverlapEvidence.length) {
          await testInfo.attach(`clipped-control-overlaps-${boundary.label}-findings-expanded.json`, {
            body: Buffer.from(JSON.stringify(expandedIssues.clippedOverlapEvidence, null, 2)), contentType: 'application/json',
          });
        }
        expect(expandedIssues.clippedOverlapEvidence.filter((entry) => entry.hitMatchesExpected === false), `${boundary.label} expanded Findings clipped-pair hit targets`).toEqual([]);
        expect(expandedIssues.documentOverflow, `${boundary.label} expanded Findings document overflow`).toBeLessThanOrEqual(1);
        expect(expandedIssues.offscreenControls, `${boundary.label} expanded Findings offscreen controls`).toEqual([]);
        expect(expandedIssues.overlaps, `${boundary.label} expanded Findings overlapping controls`).toEqual([]);
        expect(expandedIssues.crushedText, `${boundary.label} expanded Findings one-character text wrapping`).toEqual([]);
        expect(expandedIssues.selfClippedControls, `${boundary.label} expanded Findings controls clipping their own labels`).toEqual([]);
        const bulkActions = surface.getByRole('region', { name: 'Bulk finding actions', exact: true });
        const bulkGeometry = await bulkActions.evaluate((element) => ({
          clientWidth: element.clientWidth,
          scrollWidth: element.scrollWidth,
          buttons: Array.from(element.querySelectorAll('button')).map((button) => ({
            clientHeight: button.clientHeight,
            clientWidth: button.clientWidth,
            scrollHeight: button.scrollHeight,
            scrollWidth: button.scrollWidth,
          })),
        }));
        expect(bulkGeometry.scrollWidth, `${boundary.label} bulk actions horizontal overflow`).toBeLessThanOrEqual(bulkGeometry.clientWidth + 1);
        for (const button of bulkGeometry.buttons) {
          expect(button.scrollWidth, `${boundary.label} bulk action label horizontal clipping`).toBeLessThanOrEqual(button.clientWidth + 1);
          expect(button.scrollHeight, `${boundary.label} bulk action label vertical clipping`).toBeLessThanOrEqual(button.clientHeight + 1);
        }
        const detail = surface.locator('.finding-detail');
        const detailHeaderGeometry = await detail.locator('.finding-detail-head').evaluate((element) => {
          const identity = element.firstElementChild?.getBoundingClientRect();
          const actions = element.closest('.finding-detail')?.querySelector('.finding-primary-actions .finding-detail-actions')?.getBoundingClientRect();
          if (!identity || !actions) throw new Error('Finding detail header geometry is unavailable.');
          return {
            actions: { left: actions.left, top: actions.top },
            identity: { bottom: identity.bottom, left: identity.left, width: identity.width },
          };
        });
        expect(detailHeaderGeometry.identity.width, `${boundary.label} finding identity readable width`).toBeGreaterThan(200);
        expect(detailHeaderGeometry.identity.left, `${boundary.label} finding identity left edge`).toBeGreaterThanOrEqual(0);
        expect(detailHeaderGeometry.identity.bottom, `${boundary.label} finding actions follow the identity`).toBeLessThanOrEqual(detailHeaderGeometry.actions.top + 0.5);
        expect(detailHeaderGeometry.actions.left, `${boundary.label} finding actions align with the identity`).toBeGreaterThanOrEqual(detailHeaderGeometry.identity.left - 0.5);
        const lifecycle = detail.locator('.finding-action-menu');
        await lifecycle.locator('summary').click();
        const menu = lifecycle.locator(':scope > div');
        await expect(menu).toBeVisible();
        const readMenuGeometry = () => menu.evaluate((element) => {
          const menuBounds = element.getBoundingClientRect();
          const owner = element.closest('.finding-detail');
          if (!owner) throw new Error('Lifecycle menu lost its finding detail scroll owner.');
          const ownerBounds = owner.getBoundingClientRect();
          const buttons = Array.from(element.querySelectorAll('button')).map((button) => {
            const bounds = button.getBoundingClientRect();
            return {
              bottom: bounds.bottom,
              clientHeight: button.clientHeight,
              clientWidth: button.clientWidth,
              left: bounds.left,
              right: bounds.right,
              scrollHeight: button.scrollHeight,
              scrollWidth: button.scrollWidth,
              top: bounds.top,
            };
          });
          return {
            buttons,
            clientHeight: element.clientHeight,
            clientWidth: element.clientWidth,
            menu: { bottom: menuBounds.bottom, left: menuBounds.left, right: menuBounds.right, top: menuBounds.top },
            owner: { bottom: ownerBounds.bottom, left: ownerBounds.left, right: ownerBounds.right, top: ownerBounds.top },
            scrollHeight: element.scrollHeight,
            scrollWidth: element.scrollWidth,
            viewport: { height: window.innerHeight, width: window.innerWidth },
          };
        });
        // Opening the native details element reveals the menu before its
        // onToggle animation-frame scroll has settled. Await the same bounds
        // under the normal assertion budget, then retain every final check.
        await expect.poll(async () => {
          const geometry = await readMenuGeometry();
          return {
            left: geometry.menu.left >= geometry.owner.left - 0.5,
            right: geometry.menu.right <= geometry.owner.right + 0.5,
            top: geometry.menu.top >= Math.max(0, geometry.owner.top) - 0.5,
            bottom: geometry.menu.bottom <= Math.min(geometry.viewport.height, geometry.owner.bottom) + 0.5,
          };
        }, { message: `${boundary.label} Lifecycle settled within its visible scroll owner` }).toEqual({
          left: true, right: true, top: true, bottom: true,
        });
        const menuGeometry = await readMenuGeometry();
        const visibleOwnerTop = Math.max(0, menuGeometry.owner.top);
        const visibleOwnerBottom = Math.min(menuGeometry.viewport.height, menuGeometry.owner.bottom);
        expect(menuGeometry.menu.left, `${boundary.label} Lifecycle left edge`).toBeGreaterThanOrEqual(menuGeometry.owner.left - 0.5);
        expect(menuGeometry.menu.right, `${boundary.label} Lifecycle right edge`).toBeLessThanOrEqual(menuGeometry.owner.right + 0.5);
        expect(menuGeometry.menu.top, `${boundary.label} Lifecycle reachable top edge`).toBeGreaterThanOrEqual(visibleOwnerTop - 0.5);
        expect(menuGeometry.menu.bottom, `${boundary.label} Lifecycle reachable bottom edge`).toBeLessThanOrEqual(visibleOwnerBottom + 0.5);
        expect(menuGeometry.scrollWidth, `${boundary.label} Lifecycle internal horizontal overflow`).toBeLessThanOrEqual(menuGeometry.clientWidth + 1);
        expect(menuGeometry.scrollHeight, `${boundary.label} Lifecycle internal vertical overflow`).toBeLessThanOrEqual(menuGeometry.clientHeight + 1);
        for (const button of menuGeometry.buttons) {
          expect(button.left, `${boundary.label} Lifecycle action left edge`).toBeGreaterThanOrEqual(menuGeometry.menu.left - 0.5);
          expect(button.right, `${boundary.label} Lifecycle action right edge`).toBeLessThanOrEqual(menuGeometry.menu.right + 0.5);
          expect(button.scrollWidth, `${boundary.label} Lifecycle action label horizontal clipping`).toBeLessThanOrEqual(button.clientWidth + 1);
          expect(button.scrollHeight, `${boundary.label} Lifecycle action label vertical clipping`).toBeLessThanOrEqual(button.clientHeight + 1);
        }
        await lifecycle.locator('summary').click();

        const artifact = surface.locator('.artifact-card').filter({ hasText: longArtifactIdentity });
        await expect(artifact).toHaveCount(1);
        const scannerIdentity = artifact.locator('strong');
        await expect(scannerIdentity).toHaveText(longArtifactIdentity);
        await expect(artifact).toContainText(`${longArtifactType} · ${longArtifactFormat}`);
        expect.soft(
          await scannerIdentity.getAttribute('title'),
          `${boundary.label} long artifact identity needs a pointer-accessible full-value affordance`,
        ).toBe(longArtifactIdentity);
        const artifactGeometry = await artifact.evaluate((element) => {
          const bounds = element.getBoundingClientRect();
          const grid = element.parentElement?.getBoundingClientRect();
          const actions = element.querySelector('.artifact-actions')?.getBoundingClientRect();
          if (!actions || !grid) throw new Error('Artifact geometry is unavailable.');
          return {
            actions: { bottom: actions.bottom, left: actions.left, right: actions.right, top: actions.top },
            artifact: { bottom: bounds.bottom, left: bounds.left, right: bounds.right, top: bounds.top },
            clientWidth: element.clientWidth,
            grid: { left: grid.left, right: grid.right },
            scrollWidth: element.scrollWidth,
          };
        });
        expect(artifactGeometry.scrollWidth, `${boundary.label} long artifact card overflow`).toBeLessThanOrEqual(artifactGeometry.clientWidth + 1);
        expect(artifactGeometry.artifact.left, `${boundary.label} sparse artifact fills the grid left edge`).toBeGreaterThanOrEqual(artifactGeometry.grid.left - 0.5);
        expect(artifactGeometry.artifact.right, `${boundary.label} sparse artifact fills the available grid width`).toBeGreaterThanOrEqual(artifactGeometry.grid.right - 0.5);
        expect(artifactGeometry.artifact.right, `${boundary.label} sparse artifact stays inside the grid right edge`).toBeLessThanOrEqual(artifactGeometry.grid.right + 0.5);
        expect(artifactGeometry.actions.left, `${boundary.label} artifact actions left edge`).toBeGreaterThanOrEqual(artifactGeometry.artifact.left - 0.5);
        expect(artifactGeometry.actions.right, `${boundary.label} artifact actions right edge`).toBeLessThanOrEqual(artifactGeometry.artifact.right + 0.5);
      }
    }

    if (boundary.width === 390 || boundary.label === '1440 at 125% text' || boundary.width === 1835) {
      await request.post('/__test/reset', { data: { profile: 'advisor-remote-disabled', generation: 1 } });
      await page.goto('/?view=overview');
      await page.evaluate((fontScale) => {
        document.documentElement.style.fontSize = `${fontScale * 100}%`;
      }, boundary.fontScale);
      await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
      await page.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Review one Advisor disclosure', exact: true });
      await expect(dialog).toBeVisible();
      const cancel = dialog.getByRole('button', { name: 'Cancel — send nothing', exact: true });
      await cancel.scrollIntoViewIfNeeded();
      const dialogGeometry = await dialog.evaluate((element) => {
        const bounds = element.getBoundingClientRect();
        const actions = element.querySelector('.advisor-confirmation-actions')?.getBoundingClientRect();
        if (!actions) throw new Error('Advisor confirmation actions are unavailable.');
        return {
          actions: { bottom: actions.bottom, left: actions.left, right: actions.right, top: actions.top },
          clientHeight: element.clientHeight,
          clientWidth: element.clientWidth,
          dialog: { bottom: bounds.bottom, left: bounds.left, right: bounds.right, top: bounds.top },
          scrollHeight: element.scrollHeight,
          scrollWidth: element.scrollWidth,
          viewport: { height: window.innerHeight, width: window.innerWidth },
        };
      });
      expect(dialogGeometry.dialog.left, `${boundary.label} Advisor dialog left edge`).toBeGreaterThanOrEqual(0);
      expect(dialogGeometry.dialog.right, `${boundary.label} Advisor dialog right edge`).toBeLessThanOrEqual(dialogGeometry.viewport.width);
      expect(dialogGeometry.dialog.top, `${boundary.label} Advisor dialog top edge`).toBeGreaterThanOrEqual(0);
      expect(dialogGeometry.dialog.bottom, `${boundary.label} Advisor dialog bottom edge`).toBeLessThanOrEqual(dialogGeometry.viewport.height);
      expect(dialogGeometry.scrollWidth, `${boundary.label} Advisor dialog horizontal overflow`).toBeLessThanOrEqual(dialogGeometry.clientWidth + 1);
      expect(dialogGeometry.actions.left, `${boundary.label} Advisor action row left edge`).toBeGreaterThanOrEqual(dialogGeometry.dialog.left - 0.5);
      expect(dialogGeometry.actions.right, `${boundary.label} Advisor action row right edge`).toBeLessThanOrEqual(dialogGeometry.dialog.right + 0.5);
      expect(dialogGeometry.actions.top, `${boundary.label} Advisor actions reachable after scroll`).toBeGreaterThanOrEqual(dialogGeometry.dialog.top - 0.5);
      expect(dialogGeometry.actions.bottom, `${boundary.label} Advisor actions reachable after scroll`).toBeLessThanOrEqual(dialogGeometry.dialog.bottom + 0.5);
      expect(dialogGeometry.scrollHeight).toBeGreaterThan(0);
      await cancel.click();
      await expect(dialog).toHaveCount(0);
    }
  }
});

referenceTest('Findings keeps its virtual list bounded and selected detail reachable across the compact desktop breakpoint', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  test.setTimeout(qualificationMilliseconds(60_000));
  const boundaries = [
    { width: 320, height: 844, sideBySide: false },
    { width: 390, height: 844, sideBySide: false },
    { width: 768, height: 1024, sideBySide: false },
    { width: 860, height: 900, sideBySide: false },
    { width: 861, height: 900, sideBySide: true },
    { width: 980, height: 900, sideBySide: true },
    { width: 1264, height: 900, sideBySide: true },
    { width: 1440, height: 900, sideBySide: true },
  ] as const;

  for (const boundary of boundaries) {
    await page.setViewportSize({ width: boundary.width, height: boundary.height });
    await request.post('/__test/reset', { data: { profile: 'large-findings', generation: 1 } });
    await page.goto('/?view=overview');
    await openRoute(page, 'Findings');
    const surface = page.locator('section[data-route-surface="findings"]');
    const list = surface.locator('.finding-list-scroll');
    const detail = surface.locator('.finding-detail');
    await expect(detail.locator('h2')).toHaveText('S41-F001');

    const geometry = await surface.evaluate((element) => {
      const listElement = element.querySelector<HTMLElement>('.finding-list-scroll');
      const detailElement = element.querySelector<HTMLElement>('.finding-detail');
      if (!listElement || !detailElement) throw new Error('Findings workspace geometry is unavailable.');
      const listBounds = listElement.getBoundingClientRect();
      const detailBounds = detailElement.getBoundingClientRect();
      return {
        detail: { left: detailBounds.left, top: detailBounds.top },
        detailPosition: getComputedStyle(detailElement).position,
        documentOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        list: {
          bottom: listBounds.bottom,
          clientHeight: listElement.clientHeight,
          right: listBounds.right,
          scrollHeight: listElement.scrollHeight,
        },
      };
    });
    expect(geometry.documentOverflow, `${boundary.width}px document overflow`).toBeLessThanOrEqual(1);
    expect(geometry.list.clientHeight, `${boundary.width}px list remains bounded`).toBeLessThanOrEqual(414);
    expect(geometry.list.scrollHeight, `${boundary.width}px list owns overflow`).toBeGreaterThan(geometry.list.clientHeight + 1);
    if (boundary.sideBySide) {
      expect(geometry.detail.left, `${boundary.width}px selected detail stays beside the list`).toBeGreaterThanOrEqual(geometry.list.right - 0.5);
      expect(geometry.detailPosition, `${boundary.width}px selected detail remains sticky`).toBe('sticky');
    } else {
      expect(geometry.detail.top, `${boundary.width}px selected detail follows the bounded list`).toBeGreaterThanOrEqual(geometry.list.bottom - 0.5);
    }

    await detail.scrollIntoViewIfNeeded();
    await expect(detail.getByRole('button', { name: 'Run Advisor', exact: true })).toBeVisible();
    await expect(detail.getByRole('button', { name: 'Copy evidence', exact: true })).toBeVisible();
    const evidenceGeometry = await detail.evaluate((element) => {
      const controls = Array.from(element.querySelectorAll<HTMLElement>('.evidence-toolbar-actions > *, .highlighted-code'));
      return controls.map((control) => {
        const bounds = control.getBoundingClientRect();
        return { label: control.getAttribute('aria-label') || control.textContent?.slice(0, 40), left: bounds.left, right: bounds.right };
      });
    });
    for (const control of evidenceGeometry) {
      expect(control.left, `${boundary.width}px ${control.label} stays within the viewport`).toBeGreaterThanOrEqual(0);
      expect(control.right, `${boundary.width}px ${control.label} stays within the viewport`).toBeLessThanOrEqual(boundary.width);
    }
    if (boundary.width === 320) {
      await testInfo.attach('findings-320-evidence.png', { body: await detail.screenshot(), contentType: 'image/png' });
    }
  }
});

referenceTest('Finding rows preserve exact clipped-field affordances and virtual geometry with doubled root font sizing', async ({ page, request }, testInfo) => {
  await request.post('/__test/reset', { data: { profile: 'responsive-long-content', generation: 1 } });
  await openRoute(page, 'Findings');
  // This exercises rem-based row geometry. Pixel-sized labels do not enlarge
  // with the root size, so it is not a complete 200% text-resizing receipt.
  await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });

  const rows = page.locator('.finding-list-item');
  await expect(rows.first()).toBeVisible();
  await expect(rows.first()).not.toHaveAttribute('title');
  const scanner = rows.first().locator('.finding-scanner');
  await expect(scanner).toHaveAttribute('title', await scanner.textContent() || '');
  const rule = rows.first().locator('.finding-rule');
  expect(await rule.getAttribute('title')).toContain(await rule.textContent());
  const technical = rows.first().locator('.finding-message');
  const exactRule = await technical.getAttribute('title');
  expect(exactRule).toBeTruthy();
  expect(await technical.textContent()).toContain(exactRule);
  expect(await rows.first().locator('.finding-list-main').getAttribute('aria-label')).toContain(exactRule);

  const geometry = await rows.evaluateAll((elements) => elements.slice(0, 2).map((element) => {
    const bounds = element.getBoundingClientRect();
    return {
      bottom: bounds.bottom,
      clientHeight: element.clientHeight,
      scrollHeight: element.scrollHeight,
      top: bounds.top,
    };
  }));
  expect(geometry).toHaveLength(2);
  expect(geometry[0].scrollHeight, 'The first virtual row must not clip enlarged text.').toBeLessThanOrEqual(geometry[0].clientHeight + 1);
  expect(geometry[1].scrollHeight, 'The second virtual row must not clip enlarged text.').toBeLessThanOrEqual(geometry[1].clientHeight + 1);
  expect(geometry[1].top, 'Enlarged virtual rows must not overlap.').toBeGreaterThanOrEqual(geometry[0].bottom);

  await page.setViewportSize({ width: 1458, height: 706 });
  await page.evaluate(() => { document.documentElement.style.fontSize = '100%'; });
  const lifecycle = page.locator('.finding-detail .finding-action-menu');
  await lifecycle.locator('summary').click();
  const menu = lifecycle.locator(':scope > div');
  await expect(menu).toBeVisible();
  await expect.poll(async () => menu.evaluate((element) => (
    element.getBoundingClientRect().bottom <= window.innerHeight - 8
  )), { message: 'Lifecycle menu settles inside the short Mac window without a manual scroll.' }).toBe(true);
  const menuGeometry = await menu.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return {
      bottom: bounds.bottom,
      left: bounds.left,
      right: bounds.right,
      top: bounds.top,
      viewportHeight: window.innerHeight,
      viewportWidth: window.innerWidth,
    };
  });
  expect(menuGeometry.left, 'Lifecycle menu must stay inside the short Mac window left edge.').toBeGreaterThanOrEqual(0);
  expect(menuGeometry.right, 'Lifecycle menu must stay inside the short Mac window right edge.').toBeLessThanOrEqual(menuGeometry.viewportWidth);
  expect(menuGeometry.top, 'Lifecycle menu must stay inside the short Mac window top edge.').toBeGreaterThanOrEqual(0);
  expect(menuGeometry.bottom, 'Lifecycle menu must retain a visible margin above the short Mac window bottom edge.').toBeLessThanOrEqual(menuGeometry.viewportHeight - 8);
});

referenceTest('Findings keeps snippet text readable beneath offender highlights', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const code = '// Never place a secret in a log\nconst label = "review";\nfunction report(value: number) { return value + 42; }';
  await page.route('**/v1/scans/41/findings?*', async route => {
    const response = await route.fetch(), body = await response.json();
    await route.fulfill({ response, json: { ...body, items: body.items.map((finding: { id: number }) => finding.id === 514
      ? { ...finding, start_line: 44, end_line: 46, start_column: 1, end_column: 50 } : finding) } });
  });
  await page.route(/\/v1\/scans\/41\/findings\/14(?:\?|$)/, async route => {
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...await response.json(), code_snippet: code,
      start_line: 44, end_line: 46, start_column: 1, end_column: 50, metadata_json: { snippet_start_line: 44 } } });
  });
  await page.goto('/?view=findings&scan=41&finding=14');
  const evidence = page.getByRole('region', { name: 'Code evidence for src/generated-14.ts', exact: true });
  await expect(evidence.locator('.code-source')).toHaveText(code);
  await expect(evidence.locator('.hljs-comment')).toHaveCount(1);
  const result = await evidence.evaluate(inspectEvidenceContrast);
  await testInfo.attach('layered-snippet-contrast.json', { body: Buffer.from(JSON.stringify(result, null, 2)), contentType: 'application/json' });
  expect(result.palette_entries).toBeGreaterThanOrEqual(5);
  expect(result.samples.map(item => item.name)).toEqual(expect.arrayContaining(['code-line-number', 'code-marker']));
  expect(result.samples.filter(item => !item.passed), 'all plain and highlighted text must meet 4.5:1').toEqual([]);
  guards.assertClean();
});

referenceTest('Findings paints UTF-16 columns over tabs and emoji at captured origins', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const code = '\t🙂  unsafeSink(input);\n' + Array.from({ length: 40 }, (_, index) => `const context${index} = ${index};`).join('\n');
  let origin = 1;
  let startColumn = 6;
  await page.route('**/v1/scans/41/findings?*', async (route) => {
    const response = await route.fetch();
    const result = await response.json();
    await route.fulfill({ response, json: { ...result, items: result.items.map((finding: { id: number }) => finding.id === 514
      ? { ...finding, start_line: 44, end_line: 44, start_column: startColumn, end_column: origin + 15 }
      : finding) } });
  });
  await page.route(/\/v1\/scans\/41\/findings\/14(?:\?|$)/, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...await response.json(), code_snippet: code,
      start_line: 44, end_line: 44, start_column: startColumn, end_column: origin + 15,
      metadata_json: { snippet_start_line: 44, snippet_column_start: origin,
        snippet_line_truncated: origin > 1, snippet_truncated: origin > 1 } } });
  });
  const open = async () => {
    await page.goto('/?view=findings&scan=41&finding=14');
    const evidence = page.getByLabel('Code evidence for src/generated-14.ts', { exact: true });
    await expect(evidence.locator('.code-source')).toHaveText(code);
    return evidence;
  };
  const geometry = async () => page.locator('.finding-detail').evaluate((detail) => {
    const source = detail.querySelector('.code-source')!;
    const nodes: Text[] = [];
    const walker = document.createTreeWalker(source, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) nodes.push(walker.currentNode as Text);
    const endpoint = (offset: number) => {
      for (const node of nodes) {
        if (offset <= node.length) return { node, offset };
        offset -= node.length;
      }
      throw new Error('Source range is unavailable.');
    };
    const first = endpoint(5); const last = endpoint(15);
    const range = document.createRange();
    range.setStart(first.node, first.offset); range.setEnd(last.node, last.offset);
    const actual = range.getBoundingClientRect();
    const mark = detail.querySelector('.code-column-row mark')!.getBoundingClientRect();
    return { text: range.toString(), actual: { left: actual.left, right: actual.right, top: actual.top },
      mark: { left: mark.left, right: mark.right, top: mark.top },
      overflow: document.documentElement.scrollWidth - innerWidth };
  });
  for (origin of [1, 101]) {
    startColumn = origin + 5;
    const evidence = await open();
    await expect(evidence.locator('.code-column-row mark')).toHaveText('unsafeSink');
    if (origin > 1) await expect(page.locator('.evidence-boundary-note')).toContainText('starting at source column 101');
    for (const scale of [1, 2]) {
      if (scale === 2) await page.evaluate(() => {
        const sizes = Array.from(document.querySelectorAll<HTMLElement>('*')).map((element) => {
          const style = getComputedStyle(element);
          return { element, size: parseFloat(style.fontSize), leading: parseFloat(style.lineHeight) };
        });
        for (const { element, size, leading } of sizes) {
          element.style.fontSize = `${size * 2}px`;
          if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
        }
      });
      for (const width of [320, 390, 768, 1440, 1920]) {
        await page.setViewportSize({ width, height: 900 });
        await evidence.scrollIntoViewIfNeeded();
        await evidence.evaluate((element) => { element.scrollLeft = 0; element.scrollTop = 0; });
        const measured = await geometry();
        expect(measured.text).toBe('unsafeSink');
        expect(Math.abs(measured.mark.left - measured.actual.left), `${width}px ${scale}x column starts at the actual source glyph`).toBeLessThanOrEqual(1);
        expect(Math.abs(measured.mark.right - measured.actual.right), `${width}px ${scale}x column ends at the actual source glyph`).toBeLessThanOrEqual(1);
        expect(Math.abs(measured.mark.top - measured.actual.top)).toBeLessThanOrEqual(2);
        expect(measured.overflow).toBeLessThanOrEqual(1);
        await testInfo.attach(`columns-origin-${origin}-${width}-text-${scale}.png`, { body: await evidence.screenshot(), contentType: 'image/png' });
      }
    }
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true,
      value: { writeText: async (text: string) => { (window as Window & { __copiedEvidence?: string }).__copiedEvidence = text; } } }));
    const copy = page.getByRole('button', { name: 'Copy evidence', exact: true });
    await copy.focus(); await copy.press('Enter');
    expect(await page.evaluate(() => (window as Window & { __copiedEvidence?: string }).__copiedEvidence)).toBe(code);
    await evidence.focus(); await evidence.press('End');
    await expect.poll(() => evidence.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
  }
  origin = 1; startColumn = 3; // A hostile boundary through the emoji's surrogate pair.
  const evidence = await open();
  await expect(evidence.locator('.code-column-row mark')).toHaveCount(0);
  await expect(evidence.locator('.code-row.offender')).toHaveCount(1);
  guards.assertClean();
});

referenceTest('Findings protection context matches the exact source and opens Settings once ready', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const repositoryId = 'a'.repeat(64);
  const exact = { repository_id: repositoryId, project_id: 11, name: 'Generated exact clone',
    root_path: '/workspace/generated/demo-service', git_directory: '/workspace/generated/demo-service/.git',
    revision: 2, enabled: true, observed_state: 'installed', observed_revision: 2,
    observed_at: '2026-08-12T08:00:00Z', hook_digest: 'b'.repeat(64), reason_code: null, members: [] };
  let records = [exact];
  let hold = false;
  let release: (() => void) | undefined;
  await page.route('**/v1/git/push-protection', async (route) => {
    if (hold) await new Promise<void>((resolve) => { release = resolve; });
    await route.fulfill({ json: { repositories: records } });
  });
  await page.addInitScript((id) => {
    const original = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = function (...args) {
      if (this.id === `git-push-protection-${id}`) (window as Window & { __exactScrolls?: number }).__exactScrolls = ((window as Window & { __exactScrolls?: number }).__exactScrolls || 0) + 1;
      return original.apply(this, args);
    };
  }, repositoryId);
  await page.goto('/?view=findings&scan=41&finding=1');
  const context = page.getByLabel('Repository push protection', { exact: true });
  await expect(context.getByRole('status')).toContainText('On · last verified');
  await expect(context).toContainText('The next push still requires a check.');
  for (const width of [320, 390, 768, 1440, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await context.scrollIntoViewIfNeeded();
    await testInfo.attach(`exact-protection-${width}.png`, { body: await context.screenshot(), contentType: 'image/png' });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
  }
  records = [{ ...exact, root_path: '/workspace/generated/neighbor-clone' }];
  await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
  await expect(context.getByRole('status')).toContainText('No matching protection record');
  records = [exact, { ...exact, repository_id: 'c'.repeat(64) }];
  await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
  await expect(context.getByRole('status')).toContainText('Choose repository protection');
  records = [{ ...exact, observed_revision: 1 }];
  await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
  await expect(context.getByRole('status')).toContainText('Change pending · Apply in VS Code');
  records = [exact];
  await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
  await expect(context.getByRole('status')).toContainText('On · last verified');
  hold = true;
  await context.getByRole('button', { name: 'Manage push protection' }).click();
  await expect.poll(() => Boolean(release)).toBe(true);
  expect(await page.evaluate(() => (window as Window & { __exactScrolls?: number }).__exactScrolls || 0)).toBe(0);
  hold = false; release!();
  const repository = page.locator(`#git-push-protection-${repositoryId}`);
  await expect(repository).toBeFocused();
  await expect(page).toHaveURL(new RegExp(`#git-push-protection-${repositoryId}$`));
  expect(await page.evaluate(() => (window as Window & { __exactScrolls?: number }).__exactScrolls)).toBe(1);
  await page.getByRole('button', { name: 'Refresh protection', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Requested settings and last host observations refreshed.' })).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { __exactScrolls?: number }).__exactScrolls)).toBe(1);
  guards.assertClean();
});

referenceTest('Findings preserves complete evidence and reachable controls with actual 200% text enlargement', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=findings&scan=41&finding=14');
  const detail = page.locator('.finding-detail');
  await expect(detail.locator('h2')).toHaveText('S41-F014');
  await expect(detail).not.toHaveAttribute('aria-busy', 'true');
  const evidence = page.getByLabel('Code evidence for src/generated-14.ts', { exact: true });
  await expect(evidence).toHaveAttribute('data-line-count', '41');
  const navigation = page.getByRole('navigation', { name: 'Workbench views' });
  const assertNavigationGeometry = async (label: string) => {
    const iconSize = page.viewportSize()!.width > 640 ? 17 : 16;
    const buttons = await navigation.locator('button').evaluateAll((elements) => elements.map((element) => {
      const icon = element.querySelector('svg')!.getBoundingClientRect();
      return {
        name: element.textContent?.trim(), iconWidth: icon.width, iconHeight: icon.height,
        clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
      };
    }));
    await testInfo.attach(`navigation-${label}-geometry.json`, {
      body: Buffer.from(JSON.stringify(buttons, null, 2)), contentType: 'application/json',
    });
    expect(buttons).toHaveLength(7);
    for (const button of buttons) {
      expect(button.iconWidth, `${label} ${button.name} decorative icon remains visible at the compact header breakpoint`).toBe(iconSize);
      expect(button.iconHeight, `${label} ${button.name} decorative icon remains visible at the compact header breakpoint`).toBe(iconSize);
      expect(button.scrollWidth, `${label} ${button.name} label remains inside its button`).toBeLessThanOrEqual(button.clientWidth + 1);
    }
  };
  await page.setViewportSize({ width: 768, height: 900 });
  await assertNavigationGeometry('normal-768');
  await testInfo.attach('navigation-normal-768.png', { body: await navigation.screenshot(), contentType: 'image/png' });
  await page.setViewportSize({ width: 1440, height: 900 });
  const originalCode = await evidence.locator('.code-source').textContent();
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async (value: string) => { (window as Window & { __copiedEvidence?: string }).__copiedEvidence = value; } },
    });
  });
  const copy = detail.getByRole('button', { name: 'Copy evidence', exact: true });
  await copy.click();
  await expect(detail.getByRole('status').filter({ hasText: 'Sanitized code evidence copied.' })).toBeVisible();

  await expandFindingDisclosure(page, '.finding-filter-details');
  await expandFindingDisclosure(page, '.bulk-action-disclosure');
  await expandFindingDisclosure(page, '.finding-scan-details');

  // Freeze all existing computed sizes before changing any ancestor. This
  // doubles pixel-sized labels as well as inherited text, without compounding
  // nested elements. Leading doubles with the glyphs; layout dimensions remain
  // governed by the application. This is a synthetic text-only enlargement,
  // not a native browser zoom-menu receipt or just larger rem-based row boxes.
  const textScale = await page.evaluate(() => {
    const before = Array.from(document.querySelectorAll<HTMLElement>('*'))
      .filter((element) => element instanceof HTMLElement)
      .map((element) => {
        const style = getComputedStyle(element);
        return { element, size: Number.parseFloat(style.fontSize), leading: Number.parseFloat(style.lineHeight) };
      });
    for (const { element, size, leading } of before) {
      element.style.fontSize = `${size * 2}px`;
      if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
    }
    const glyphs = before.filter(({ element }) => Array.from(element.childNodes)
      .some((node) => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent?.trim())));
    return {
      elements: before.length,
      glyphElements: glyphs.length,
      mismatches: glyphs.flatMap(({ element, size }) => {
        const actual = Number.parseFloat(getComputedStyle(element).fontSize);
        return Math.abs(actual - size * 2) < 0.01 ? [] : [{ tag: element.tagName, before: size, after: actual }];
      }),
      ruleFont: getComputedStyle(document.querySelector('.finding-rule')!).fontSize,
      codeFont: getComputedStyle(document.querySelector('.code-source')!).fontSize,
    };
  });
  await testInfo.attach('actual-text-enlargement.json', { body: Buffer.from(JSON.stringify(textScale, null, 2)), contentType: 'application/json' });
  expect(textScale.glyphElements, 'the whole populated page supplies measured text').toBeGreaterThan(100);
  expect(textScale.mismatches, 'every existing glyph-bearing element actually doubles').toEqual([]);
  expect(textScale.ruleFont).toBe('28px');
  expect(textScale.codeFont).toBe('26px');

  for (const width of [1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await assertNavigationGeometry(`text-200-${width}`);
    if (width === 768) await testInfo.attach('navigation-text-200-768.png', { body: await navigation.screenshot(), contentType: 'image/png' });
    await detail.scrollIntoViewIfNeeded();
    const geometry = await page.evaluate(() => {
      const owner = document.querySelector('.finding-detail')!.getBoundingClientRect();
      const source = document.querySelector('.code-source')!;
      const overlay = document.querySelector('.code-row.offender')!;
      const code = document.querySelector('.highlighted-code')!;
      const controls = Array.from(document.querySelectorAll<HTMLElement>('.finding-detail-actions > button, .finding-action-menu summary, .evidence-toolbar-actions > *'));
      return {
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        outsideViewport: Array.from(document.querySelectorAll<HTMLElement>('button, input, select, label, strong'))
          .filter((element) => !element.closest('.highlighted-code, .visually-hidden') && element.getBoundingClientRect().width > 0)
          .filter((element) => element.getBoundingClientRect().right > innerWidth + 1)
          .map((element) => ({ tag: element.tagName, className: element.className, text: element.textContent?.trim().slice(0, 60), right: element.getBoundingClientRect().right })),
        disclosureControls: Array.from(document.querySelectorAll<HTMLElement>(
          '.finding-filter-details summary, .finding-filter-details select, .finding-filter-details button, .bulk-action-disclosure summary, .bulk-action-controls button, .finding-scan-details summary, .finding-scan-details a[href]',
        )).map((element) => {
          const bounds = element.getBoundingClientRect();
          return { name: element.getAttribute('aria-label') || element.textContent?.trim(), left: bounds.left, right: bounds.right, clientWidth: element.clientWidth, scrollWidth: element.scrollWidth, clientHeight: element.clientHeight, scrollHeight: element.scrollHeight };
        }),
        owner: { left: owner.left, right: owner.right },
        controls: controls.map((element) => {
          const bounds = element.getBoundingClientRect();
          return { name: element.textContent?.trim(), left: bounds.left, right: bounds.right, scrollWidth: element.scrollWidth, clientWidth: element.clientWidth };
        }),
        code: { clientWidth: code.clientWidth, scrollWidth: code.scrollWidth },
        lineHeight: Number.parseFloat(getComputedStyle(source).lineHeight),
        offenderTop: Number.parseFloat(getComputedStyle(overlay).top),
        offenderHeight: overlay.getBoundingClientRect().height,
        rows: Array.from(document.querySelectorAll<HTMLElement>('.finding-list-item')).slice(-2).map((element) => ({
          clientHeight: element.clientHeight, scrollHeight: element.scrollHeight, clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
        })),
      };
    });
    await testInfo.attach(`text-200-${width}-geometry.json`, { body: Buffer.from(JSON.stringify(geometry, null, 2)), contentType: 'application/json' });
    expect(geometry.lineHeight).toBe(44);
    expect(geometry.offenderTop, `${width}px highlight stays on actual offender line 44`).toBe(20 * geometry.lineHeight);
    expect(geometry.offenderHeight, `${width}px highlight covers one enlarged line`).toBe(geometry.lineHeight);
    expect.soft(geometry.overflow, `${width}px enlarged text causes no page overflow`).toBeLessThanOrEqual(1);
    for (const control of geometry.controls) {
      expect.soft(control.left, `${width}px ${control.name} stays inside detail`).toBeGreaterThanOrEqual(geometry.owner.left);
      expect.soft(control.right, `${width}px ${control.name} stays inside detail`).toBeLessThanOrEqual(geometry.owner.right);
      expect.soft(control.scrollWidth, `${width}px ${control.name} does not clip`).toBeLessThanOrEqual(control.clientWidth + 1);
    }
    expect(geometry.disclosureControls.length, `${width}px expanded controls remain present`).toBeGreaterThan(12);
    for (const control of geometry.disclosureControls) {
      expect.soft(control.left, `${width}px expanded ${control.name} stays inside viewport`).toBeGreaterThanOrEqual(0);
      expect.soft(control.right, `${width}px expanded ${control.name} stays inside viewport`).toBeLessThanOrEqual(width);
      expect.soft(control.scrollWidth, `${width}px expanded ${control.name} does not clip horizontally`).toBeLessThanOrEqual(control.clientWidth + 1);
      expect.soft(control.scrollHeight, `${width}px expanded ${control.name} does not clip vertically`).toBeLessThanOrEqual(control.clientHeight + 1);
    }
    for (const row of geometry.rows) {
      expect.soft(row.scrollHeight, `${width}px enlarged row text does not clip vertically`).toBeLessThanOrEqual(row.clientHeight + 1);
      expect.soft(row.scrollWidth, `${width}px enlarged row text stays inside its row`).toBeLessThanOrEqual(row.clientWidth + 1);
    }
    for (const row of await page.locator('.finding-list-item').all()) {
      await row.scrollIntoViewIfNeeded();
      await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      const painted = await row.evaluate(element => {
        const button = element.querySelector<HTMLButtonElement>('.finding-list-main')!;
        const bounds = element.getBoundingClientRect();
        const content = button.getBoundingClientRect();
        return { rendered: button.checkVisibility({ contentVisibilityAuto: true }),
          horizontalClip: button.scrollWidth - button.clientWidth, verticalClip: button.scrollHeight - button.clientHeight,
          rowBottom: bounds.bottom, contentBottom: content.bottom };
      });
      expect(painted.rendered).toBe(true);
      expect(painted.horizontalClip, 'enlarged metadata stays inside its button').toBeLessThanOrEqual(1);
      expect(painted.verticalClip, 'enlarged metadata is not clipped by its button').toBeLessThanOrEqual(1);
      expect(painted.contentBottom, 'metadata and evidence stay inside their fixed list row').toBeLessThanOrEqual(painted.rowBottom);
    }
    await copy.focus();
    await copy.press('Enter');
    expect(await page.evaluate(() => (window as Window & { __copiedEvidence?: string }).__copiedEvidence)).toBe(originalCode);
    await evidence.focus();
    // Each width reuses the same evidence pane. Reset with the real keyboard
    // before End so a retained bottom position cannot chain scrolling to the page.
    await evidence.press('Home');
    await expect.poll(() => evidence.evaluate((element) => element.scrollTop)).toBe(0);
    await evidence.press('End');
    await expect.poll(() => evidence.evaluate((element) =>
      Math.abs(element.scrollHeight - element.clientHeight - element.scrollTop))).toBeLessThanOrEqual(1);
    const lifecycle = detail.locator('.finding-action-menu');
    await lifecycle.locator('summary').focus();
    await lifecycle.locator('summary').press('Enter');
    await expect(lifecycle).toHaveAttribute('open', '');
    const lastAction = lifecycle.getByRole('button', { name: 'Needs review', exact: true });
    await lastAction.focus();
    await expect(lastAction).toBeFocused();
    await expect(lastAction).toBeInViewport();
    await lifecycle.locator('summary').press('Enter');
    await expect(lifecycle).not.toHaveAttribute('open', '');
    if (width === 390 || width === 320) {
      await testInfo.attach(`findings-expanded-filters-text-200-${width}.png`, { body: await page.locator('.finding-filter-details').screenshot(), contentType: 'image/png' });
    }
    await testInfo.attach(`findings-text-200-${width}.png`, { body: await detail.screenshot(), contentType: 'image/png' });
  }
  guards.assertClean();
});

referenceTest('reduced-motion preference disables running animations', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
  const animations = await page.evaluate(() => document.getAnimations().filter((animation) => animation.playState === 'running').length);
  expect(animations, 'active animations under reduced motion').toBe(0);
  guards.assertClean();
});

referenceTest('Jobs distinguishes unavailable history from an empty successful read and retains recovered rows', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  let responseMode: 'failed' | 'held' | 'ready' = 'failed';
  let failures = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/v1/jobs*', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname !== '/v1/jobs') return route.continue();
    if (url.searchParams.get('status') === 'active') return route.fulfill({ status: 200, json: [] });
    const mode = responseMode;
    if (mode === 'failed') {
      failures += 1;
      return route.fulfill({ status: 503, json: { detail: 'Generated job history unavailable.' } });
    }
    if (mode === 'held') await gate;
    return route.fulfill({ response: await route.fetch() });
  });
  try {
    await page.goto('/?view=jobs');
    const surface = page.locator('section[data-route-surface="jobs"]');
    await expect(surface.getByText('Job history is unavailable. Use Refresh to load dashboard data.', { exact: true })).toBeVisible();
    await expect(surface.locator('.job-count')).toHaveText('History unavailable');
    await expect(surface.locator('.job-summary dd')).toHaveText(['—', '—', '—', '—', '—']);
    await expect(surface.getByText(/^No jobs yet\./)).toHaveCount(0);
    await page.waitForLoadState('networkidle');
    responseMode = 'held';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(surface.getByText('Loading job history…', { exact: true })).toBeVisible();
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    await expect(surface.locator('.job-count')).toHaveText('Loading jobs…');
    responseMode = 'ready';
    release();
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface.locator('.job-list [data-job-id]').first()).toBeVisible();
    const count = await surface.locator('.job-count').textContent();
    const first = surface.locator('.job-list [data-job-id]').first();
    const retained = await first.elementHandle();
    responseMode = 'failed';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Generated job history unavailable.' })).toBeVisible();
    await expect(surface.locator('.job-count')).toHaveText(count!);
    expect(await retained!.evaluate((element) => element.isConnected)).toBe(true);
    await expect(surface.getByText(/^No jobs yet\./)).toHaveCount(0);
    await page.waitForLoadState('networkidle');
    expect(guards.failures.http).toEqual(Array.from({ length: failures }, () => `503 ${origin}/v1/jobs`));
    expect(guards.failures.console).toHaveLength(failures);
    for (const error of guards.failures.console) expect(error).toContain('503');
    expect(guards.failures.page).toEqual([]);
    expect(guards.failures.request).toEqual([]);
    expect(guards.failures.egress).toEqual([]);
    expect(guards.failures.credentialUrl).toEqual([]);
    expect(await request.get('/__test/commands').then((response) => response.json())).toEqual([]);
  } finally { release(); }
});

referenceTest('Jobs shows zero only after a successful empty history read', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'first-run', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=jobs');
  const surface = page.locator('section[data-route-surface="jobs"]');
  await expect(surface.getByText(/^No jobs yet\./)).toBeVisible();
  await expect(surface.locator('.job-count')).toHaveText('0 jobs');
  await expect(surface.locator('.job-summary dd')).toHaveText(['0', '0', '0', '0', '0']);
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await page.waitForLoadState('networkidle');
  guards.assertClean();
});

referenceTest('IDE access distinguishes loading and unavailable clients and supports independent refresh recovery', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let reads = 0;
  let enrollmentReads = 0;
  await page.route('**/v1/auth/ide/enrollments', (route) => {
    enrollmentReads += 1;
    return enrollmentReads === 2
      ? route.fulfill({ status: 503, json: { detail: 'Generated pending requests unavailable.' } })
      : route.fulfill({ status: 200, json: [] });
  });
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    reads += 1;
    if (reads === 1) {
      await gate;
      return route.fulfill({ status: 503, json: { detail: 'Generated IDE clients unavailable.' } });
    }
    return route.fulfill({ status: 200, json: [{
      state: 'valid',
      id: `ks1_${'S'.repeat(43)}`,
      client_name: 'Generated retained IDE',
      scopes: ['event:read', 'source:open-ack'],
      created_at: '2026-08-12T08:00:00Z',
      revoked: false,
      active: true,
      connected: true,
      active_generation: 2,
      latest_generation: 2,
      pending_activation: false,
      pending_generation: null,
      pending_client_name: null,
      pending_activation_expires_at: null,
      source_open_available: true,
      source_open_disabled_reason: null,
      invalid_recovery_token: null,
    }] });
  });
  try {
    await page.goto('/?view=settings#ide-access');
    const panel = page.locator('#ide-access');
    await expect(panel.getByText('Loading paired IDE clients…', { exact: true })).toBeVisible();
    await expect(panel.getByText(/^No paired IDE clients/)).toHaveCount(0);
    release();
    await expect(panel.getByText('Paired IDE clients could not be loaded. Use Refresh IDE access to try again.', { exact: true })).toBeVisible();
    await expect(panel.getByText(/^No paired IDE clients/)).toHaveCount(0);
    await panel.getByRole('button', { name: 'Refresh IDE access', exact: true }).click();
    await expect(panel.getByRole('list', { name: 'Paired IDE clients', exact: true })).toBeVisible();
    await expect(panel.getByText(/^No paired IDE clients/)).toHaveCount(0);
    await expect(panel.getByText(/^Paired IDE clients could not be loaded/)).toHaveCount(0);
    await expect(panel.getByRole('alert')).toHaveText('Generated pending requests unavailable.');
    await expect(panel.getByText('Paired IDE clients refreshed. Pending requests could not be refreshed.', { exact: true })).toBeVisible();
    await expect(panel.getByText(/^No IDE access requests are waiting/)).toHaveCount(0);
    await panel.getByRole('button', { name: 'Refresh IDE access', exact: true }).click();
    await expect(panel.getByRole('alert')).toHaveCount(0);
    await expect(panel.getByText(/^No IDE access requests are waiting/)).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(reads).toBe(3);
    expect(enrollmentReads).toBe(3);
    expect(guards.failures.http).toEqual([`503 ${origin}/v1/auth/ide/capabilities`, `503 ${origin}/v1/auth/ide/enrollments`]);
    expect(guards.failures.console).toHaveLength(2);
    for (const error of guards.failures.console) expect(error).toContain('503');
    expect(guards.failures.page).toEqual([]);
    expect(guards.failures.request).toEqual([]);
    expect(guards.failures.egress).toEqual([]);
    expect(guards.failures.credentialUrl).toEqual([]);
    expect(await request.get('/__test/commands').then((response) => response.json())).toEqual([]);
  } finally { release(); }
});

referenceTest('Jobs and Tools batch delayed collections and preserve ready rows across semantic refreshes', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(70_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');

  const scenarios = [
    { attribute: 'data-jobs-committed-count', batchSize: 6, replacementBatchSize: 8, blockingSelector: '.job-list', count: 18, path: '/v1/jobs', route: 'jobs', stage: 'data-jobs-render-stage' },
    { attribute: 'data-tools-committed-count', batchSize: 5, replacementBatchSize: 5, blockingSelector: null, count: 9, path: '/v1/scanner/tools', route: 'tools', stage: 'data-tools-render-stage' },
  ] as const;

  for (const scenario of scenarios) {
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    let releaseInitial!: () => void;
    const initialGate = new Promise<void>((resolve) => { releaseInitial = resolve; });
    let initialReleased = false;
    let semanticRevision = 1;
    let structuralRevision = 1;
    let findingProjection: 'current' | 'changed' | 'removed' = 'current';
    let collectionCount = scenario.count;
    const pattern = `**${scenario.path}*`;
    await page.route(pattern, async (route) => {
      const requestUrl = new URL(route.request().url());
      if (scenario.route === 'jobs' && requestUrl.searchParams.get('status') === 'active') {
        // Every synthetic job below is terminal. Keep the active-work endpoint
        // truthful instead of returning the history collection a second time.
        await route.fulfill({ status: 200, contentType: 'application/json', json: [] });
        return;
      }
      const response = await route.fetch();
      const original = await response.json() as Array<Record<string, unknown>>;
      if (!initialReleased) await initialGate;
      const expanded = Array.from({ length: collectionCount }, (_value, index) => {
        const source = original[index % original.length];
        if (scenario.route === 'jobs') {
          return {
            ...source,
            id: structuralRevision * 1_000 + index,
            title: index === collectionCount - 1 ? `Batched job revision ${semanticRevision}` : `Batched job ${index + 1}`,
            status: 'completed',
            stage: 'completed',
            progress: 100,
            scan_id: 41,
            finding_id: undefined,
            finding_display_id: undefined,
            finding_rule_id: undefined,
            revision: index === collectionCount - 1 ? semanticRevision : 1,
            can_cancel: false,
            can_retry: false,
            updated_at: semanticRevision === 1 || index !== collectionCount - 1 ? '2026-08-12T08:00:04Z' : '2026-08-12T08:00:05Z',
            // Synthetic equivalent of the API's live Advisor selection
            // projection. The job itself is unchanged when its finding changes.
            ...(index === 0 ? {
              kind: 'advisor',
              title: findingProjection === 'removed' ? 'Advisor selection' : 'Advisor triage for S41-F001',
              status: 'failed',
              stage: 'unavailable',
              finding_id: findingProjection === 'removed' ? null : 501,
              finding_display_id: findingProjection === 'removed' ? null : 'S41-F001',
              finding_scan_number: findingProjection === 'removed' ? null : 1,
              finding_rule_id: findingProjection === 'removed' ? null : 'javascript.lang.audit.dynamic-code',
              can_retry: findingProjection === 'current',
              retry_blocked_reason: findingProjection === 'current'
                ? null : 'The original selected finding is no longer current.',
            } : {}),
          };
        }
        return {
          ...source,
          id: `batched-tool-${structuralRevision}-${index + 1}`,
          name: `Batched Tool ${index + 1}`,
          description: index === collectionCount - 1
            ? `Batched tool semantic revision ${semanticRevision}.`
            : `Batched tool ${index + 1}.`,
          updated_at: semanticRevision === 1 || index !== collectionCount - 1 ? '2026-08-12T08:00:04Z' : '2026-08-12T08:00:05Z',
        };
      });
      await route.fulfill({ response, json: expanded });
    });

    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    await page.goto(`/?view=${scenario.route}`);
    const surface = page.locator(`section[data-route-surface="${scenario.route}"]`);
    const batchBoundary = scenario.blockingSelector ? surface.locator(scenario.blockingSelector) : surface;
    await expect(surface).toHaveCount(1);
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    if (scenario.blockingSelector) {
      await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
      await expect(surface).not.toHaveAttribute('inert', '');
    }
    await expect(batchBoundary).toHaveAttribute('aria-hidden', 'true');
    await expect(batchBoundary).toHaveAttribute('inert', '');
    await expect(surface).toHaveAttribute(scenario.attribute, '0');
    if (scenario.route === 'jobs') {
      await expect(surface.getByText('Loading job history…', { exact: true })).toBeVisible();
      await expect(surface.locator('.job-count')).toHaveText('Loading jobs…');
      await expect(surface.locator('.job-summary dd')).toHaveText(['—', '—', '—', '—', '—']);
      await expect(surface.getByText(/^No jobs yet\./)).toHaveCount(0);
    }
    await surface.evaluate((element, input) => {
      const target = element as HTMLElement;
      const blockingTarget = input.blockingSelector ? target.querySelector(input.blockingSelector) : target;
      if (!(blockingTarget instanceof HTMLElement)) throw new Error('Collection blocking boundary is missing.');
      const probeWindow = window as Window & {
        __kodesecBatchProbe?: Array<{ count: number; hidden: boolean; inert: boolean; stage: string | null }>;
      };
      const capture = () => probeWindow.__kodesecBatchProbe?.push({
        count: Number(target.getAttribute(input.attribute) || 0),
        hidden: blockingTarget.getAttribute('aria-hidden') === 'true',
        inert: blockingTarget.hasAttribute('inert'),
        stage: target.getAttribute(input.stage),
      });
      probeWindow.__kodesecBatchProbe = [];
      capture();
      new MutationObserver(capture).observe(target, {
        attributeFilter: [input.attribute, input.stage, 'aria-hidden', 'inert'],
        attributes: true,
      });
      if (blockingTarget !== target) {
        new MutationObserver(capture).observe(blockingTarget, {
          attributeFilter: ['aria-hidden', 'inert'],
          attributes: true,
        });
      }
    }, { attribute: scenario.attribute, blockingSelector: scenario.blockingSelector, stage: scenario.stage });

    initialReleased = true;
    releaseInitial();
    await expect(surface).toHaveAttribute(scenario.attribute, String(scenario.count));
    await expect(surface).toHaveAttribute(scenario.stage, 'ready');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface).not.toHaveAttribute('inert', '');
    await expect(batchBoundary).not.toHaveAttribute('aria-hidden', 'true');
    await expect(batchBoundary).not.toHaveAttribute('inert', '');

    const initialProbe = await page.evaluate(() => (
      window as Window & { __kodesecBatchProbe?: Array<{ count: number; hidden: boolean; inert: boolean; stage: string | null }> }
    ).__kodesecBatchProbe || []);
    const positiveCounts = [...new Set(initialProbe.map((sample) => sample.count).filter((count) => count > 0))];
    expect(
      initialProbe.some((sample) => sample.count === 0 && sample.hidden && sample.inert),
      `${scenario.route} blocks its collection ownership boundary before data is ready`,
    ).toBe(true);
    expect(positiveCounts[0], `${scenario.route} first committed batch`).toBeLessThanOrEqual(scenario.batchSize);
    expect(positiveCounts.at(-1), `${scenario.route} complete committed collection`).toBe(scenario.count);
    for (let index = 1; index < positiveCounts.length; index += 1) {
      expect(positiveCounts[index] - positiveCounts[index - 1], `${scenario.route} bounded batch delta`).toBeLessThanOrEqual(scenario.batchSize);
    }
    expect(
      initialProbe.some((sample) => sample.count === scenario.count && sample.stage !== 'ready'),
      `${scenario.route} complete collection crosses a paint before readiness`,
    ).toBe(true);

    const unchangedControl = scenario.route === 'jobs'
      ? page.getByLabel(/^Job #1000:/).getByRole('button', { name: 'Scan #41', exact: true })
      : page.locator('.tool-card').filter({ hasText: 'Batched Tool 1' }).getByRole('button', { name: 'Disable', exact: true });
    await unchangedControl.focus();
    await expect(unchangedControl).toBeFocused();
    await page.evaluate((routeName) => {
      const probeWindow = window as Window & { __kodesecUnchangedRow?: Element | null; __kodesecReadyOwnership?: string[] };
      probeWindow.__kodesecUnchangedRow = routeName === 'jobs'
        ? document.querySelector('[aria-label^="Job #1000:"]')
        : [...document.querySelectorAll('.tool-card')].find((card) => card.textContent?.includes('Batched Tool 1')) || null;
      probeWindow.__kodesecReadyOwnership = [];
      const surfaceElement = document.querySelector(`section[data-route-surface="${routeName}"]`);
      if (!surfaceElement) throw new Error('Ready surface missing.');
      const blockingElement = routeName === 'jobs' ? surfaceElement.querySelector('.job-list') : surfaceElement;
      if (!blockingElement) throw new Error('Ready collection blocking boundary missing.');
      new MutationObserver(() => {
        if (blockingElement.hasAttribute('inert')) probeWindow.__kodesecReadyOwnership?.push('inert');
        if (blockingElement.getAttribute('aria-hidden') === 'true') probeWindow.__kodesecReadyOwnership?.push('hidden');
      }).observe(blockingElement, { attributeFilter: ['aria-hidden', 'inert'], attributes: true });
    }, scenario.route);

    semanticRevision = 2;
    // Scan #39 remains active in the deterministic fixture, so the next
    // eight-second application poll—not a test-only state setter—delivers the
    // same-structure semantic update.
    const changedEvidence = scenario.route === 'jobs'
      ? page.getByText('Batched job revision 2', { exact: true })
      : page.getByText('Batched tool semantic revision 2.', { exact: true });
    await expect(changedEvidence).toBeVisible({ timeout: qualificationMilliseconds(12_000) });
    await page.waitForLoadState('networkidle');
    await expect(unchangedControl).toBeFocused();
    const readyOwnership = await page.evaluate((routeName) => {
      const probeWindow = window as Window & { __kodesecUnchangedRow?: Element | null; __kodesecReadyOwnership?: string[] };
      const current = routeName === 'jobs'
        ? document.querySelector('[aria-label^="Job #1000:"]')
        : [...document.querySelectorAll('.tool-card')].find((card) => card.textContent?.includes('Batched Tool 1')) || null;
      return {
        ownership: probeWindow.__kodesecReadyOwnership || [],
        rowPreserved: current === probeWindow.__kodesecUnchangedRow,
      };
    }, scenario.route);
    expect(readyOwnership).toEqual({ ownership: [], rowPreserved: true });

    if (scenario.route === 'jobs') {
      const projectedJob = page.getByLabel(/^Job #1000:/);
      const fixedJobIdentity = { id: 1000, revision: 1, updated_at: '2026-08-12T08:00:04Z' };
      const nextHistory = () => page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === 'GET' && url.pathname === '/v1/jobs'
          && url.searchParams.get('status') !== 'active';
      });
      await expect(projectedJob.getByRole('button', { name: 'Retry', exact: true })).toBeVisible();
      await expect(projectedJob.getByRole('button', { name: 'Open S41-F001', exact: true })).toBeVisible();

      // Only another finding's projection changes. No navigation, manual
      // refresh, timer override or job revision update can mask the poll key.
      const permissionResponse = nextHistory();
      findingProjection = 'changed';
      const permissionRows = await (await permissionResponse).json() as Array<Record<string, unknown>>;
      const permissionJob = permissionRows.find((job) => job.id === 1000);
      expect(permissionJob).toMatchObject({ ...fixedJobIdentity, can_retry: false, finding_id: 501 });
      await expect(projectedJob.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
      await expect(projectedJob.getByText('The original selected finding is no longer current.', { exact: true })).toBeVisible();
      await expect(projectedJob.getByRole('button', { name: 'Open S41-F001', exact: true })).toBeVisible();
      await expect(unchangedControl).toBeFocused();
      await page.waitForLoadState('networkidle');

      // Deleting the selected finding clears the server-derived identity while
      // the failed job, including its revision and timestamps, is retained.
      const deletionResponse = nextHistory();
      findingProjection = 'removed';
      const deletionRows = await (await deletionResponse).json() as Array<Record<string, unknown>>;
      const deletionJob = deletionRows.find((job) => job.id === 1000);
      expect(deletionJob).toMatchObject({
        ...fixedJobIdentity, can_retry: false, finding_id: null,
        finding_display_id: null, finding_scan_number: null, finding_rule_id: null,
      });
      await expect(projectedJob.getByRole('button', { name: 'Open S41-F001', exact: true })).toHaveCount(0);
      await expect(projectedJob.locator('.job-title-line strong')).toHaveText('Advisor selection');
      await expect(projectedJob.getByRole('button', { name: 'Scan #41', exact: true })).toBeVisible();
      await expect(unchangedControl).toBeFocused();
      await expect(surface).toHaveAttribute(scenario.stage, 'ready');
      await expect(batchBoundary).not.toHaveAttribute('inert', '');
      await page.waitForLoadState('networkidle');
      await testInfo.attach('job-derived-projection-polls.json', {
        body: Buffer.from(JSON.stringify({
          scope: 'Synthetic public Job projection changes through ordinary application polling; no native worker acceptance.',
          permissionJob, deletionJob,
        }, null, 2)), contentType: 'application/json',
      });
    }

    structuralRevision = 2;
    collectionCount = scenario.count + scenario.batchSize;
    await page.evaluate(() => {
      (window as Window & { __kodesecBatchProbe?: unknown[] }).__kodesecBatchProbe = [];
    });
    await page.getByRole('button', { name: 'Refresh', exact: true }).evaluate((button: HTMLButtonElement) => button.click());
    await expect(surface).toHaveAttribute(scenario.attribute, String(collectionCount));
    await expect(surface).toHaveAttribute(scenario.stage, 'ready');
    const structuralProbe = await page.evaluate(() => (
      window as Window & { __kodesecBatchProbe?: Array<{ count: number; hidden: boolean; inert: boolean; stage: string | null }> }
    ).__kodesecBatchProbe || []);
    const structuralCounts = [...new Set(structuralProbe.map((sample) => sample.count).filter((count) => count > 0))];
    expect(
      structuralProbe.some((sample) => sample.hidden && sample.inert && sample.stage !== 'ready'),
      `${scenario.route} blocks its collection ownership boundary while replacement rows paint`,
    ).toBe(true);
    expect(structuralCounts[0], `${scenario.route} replacement starts with one bounded batch`).toBeLessThanOrEqual(scenario.replacementBatchSize);
    expect(structuralCounts.at(-1), `${scenario.route} replacement completes`).toBe(collectionCount);
    for (let index = 1; index < structuralCounts.length; index += 1) {
      expect(structuralCounts[index] - structuralCounts[index - 1], `${scenario.route} replacement batch delta`).toBeLessThanOrEqual(scenario.replacementBatchSize);
    }
    expect(
      structuralProbe.some((sample) => sample.count === collectionCount && sample.stage !== 'ready'),
      `${scenario.route} replacement crosses a final paint before readiness`,
    ).toBe(true);
    guards.assertClean();
    await page.unroute(pattern);
  }
});

referenceTest('older active durable work remains visible and keeps bounded reconciliation armed', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let activeRequests = 0;
  let historyRequests = 0;
  let detailRequests = 0;
  let terminalTransition = false;
  const terminalHistory: Array<Record<string, unknown>> = Array.from({ length: 100 }, (_value, index) => ({
    id: 10_000 - index,
    kind: 'scan',
    title: `Terminal history ${index + 1}`,
    status: 'completed',
    stage: 'completed',
    detail: 'Completed fixture history.',
    progress: 100,
    scan_id: 41,
    error: null,
    attempt: 1,
    max_attempts: 1,
    revision: 2,
    can_cancel: false,
    can_retry: false,
    created_at: '2026-08-12T08:00:00Z',
    started_at: '2026-08-12T08:00:01Z',
    completed_at: '2026-08-12T08:00:02Z',
    updated_at: '2026-08-12T08:00:02Z',
  }));
  const olderActive = {
    ...terminalHistory[0],
    id: 1,
    title: 'Older durable scan still running',
    status: 'running',
    stage: 'scanner',
    detail: 'Running outside the newest history window.',
    progress: 45,
    completed_at: null,
    revision: 3,
    can_cancel: true,
    updated_at: '2026-08-12T08:00:03Z',
  };
  const olderCompleted = {
    ...olderActive,
    status: 'completed',
    stage: 'completed',
    detail: 'Completed after leaving the newest history window.',
    progress: 100,
    completed_at: '2026-08-12T08:00:12Z',
    revision: 4,
    can_cancel: false,
    updated_at: '2026-08-12T08:00:12Z',
  };
  await page.route('**/v1/jobs/1', async (route) => {
    detailRequests += 1;
    if (detailRequests === 1) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{' });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', json: olderCompleted });
  });
  await page.route('**/v1/jobs*', async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get('status') === 'active') {
      activeRequests += 1;
      await route.fulfill({ status: 200, contentType: 'application/json', json: terminalTransition ? [] : [olderActive] });
      return;
    }
    historyRequests += 1;
    await route.fulfill({ status: 200, contentType: 'application/json', json: terminalHistory });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=jobs');
  await expect(page.getByRole('heading', { level: 1, name: 'Jobs' })).toBeVisible();
  await expect(page.getByText('Older durable scan still running', { exact: true })).toBeVisible();
  const initialActiveRequests = activeRequests;
  terminalTransition = true;
  await expect.poll(() => activeRequests, { timeout: qualificationMilliseconds(10_000) }).toBeGreaterThan(initialActiveRequests);
  await expect.poll(() => detailRequests, { timeout: qualificationMilliseconds(5_000) }).toBeGreaterThan(0);
  const reconciled = page.getByLabel('Job #1: Older durable scan still running');
  await expect(reconciled.locator('.job-status-cell')).toHaveText('Running');
  await expect(reconciled.locator('.job-status-cell')).toBeVisible();
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect.poll(() => detailRequests, { timeout: qualificationMilliseconds(5_000) }).toBeGreaterThan(1);
  await expect(reconciled.locator('.job-status-cell')).toHaveText('Completed');
  await expect(reconciled.locator('.job-status-cell')).toBeVisible();
  await expect(reconciled.getByText('Completed after leaving the newest history window.', { exact: true })).toBeVisible();
  expect(historyRequests).toBeGreaterThanOrEqual(2);
  guards.assertClean();
});

referenceTest('deferred route handoff blocks stale pointer and keyboard actions', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.addInitScript(() => {
    const NativeMessageChannel = window.MessageChannel;
    class DeferredRouteTestMessageChannel extends NativeMessageChannel {
      constructor() {
        super();
        const postMessage = this.port2.postMessage.bind(this.port2);
        this.port2.postMessage = ((message: unknown, transfer?: StructuredSerializeOptions | Transferable[]) => {
          const deliver = () => {
            if (transfer === undefined) postMessage(message);
            else postMessage(message, transfer as Transferable[]);
          };
          if (document.documentElement.dataset.deferRouteTest === 'hold') window.setTimeout(deliver, 1_000);
          else deliver();
        }) as typeof this.port2.postMessage;
      }
    }
    Object.defineProperty(window, 'MessageChannel', {
      configurable: true,
      value: DeferredRouteTestMessageChannel,
      writable: true,
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Overview');

  const main = page.locator('main');
  const navigation = page.getByRole('navigation', { name: 'Workbench views' });
  const pendingRouteState = () => page.evaluate(() => {
    const workbench = document.querySelector('main');
    const surface = workbench?.querySelector<HTMLElement>(':scope > section[data-route-surface]');
    const current = document.querySelector<HTMLElement>('nav [aria-current="page"]');
    return {
      activeView: current?.dataset.viewTarget ?? null,
      ariaBusy: workbench?.getAttribute('aria-busy') ?? null,
      ariaHidden: surface?.getAttribute('aria-hidden') ?? null,
      focusedView: (document.activeElement as HTMLElement | null)?.dataset.viewTarget ?? null,
      inert: surface?.inert ?? false,
      renderedView: workbench?.getAttribute('data-rendered-view') ?? null,
      requestedView: workbench?.getAttribute('data-requested-view') ?? null,
      surfaceView: surface?.dataset.routeSurface ?? null,
      title: document.querySelector('h1')?.textContent?.trim() ?? null,
    };
  });

  const stalePointerAction = main.getByRole('button', { name: 'Findings', exact: true });
  const stalePointerHandle = await stalePointerAction.elementHandle();
  const pointerSurface = await main.locator(':scope > section[data-route-surface="overview"]').elementHandle();
  const settingsBox = await navigation.getByRole('button', { name: 'Settings', exact: true }).boundingBox();
  const stalePointerBox = await stalePointerAction.boundingBox();
  if (!stalePointerHandle || !pointerSurface || !settingsBox || !stalePointerBox) throw new Error('Pointer route controls must have layout boxes and an owned surface.');
  await stalePointerHandle.evaluate((button) => {
    button.dataset.staleActivations = '0';
    button.addEventListener('click', () => {
      button.dataset.staleActivations = String(Number(button.dataset.staleActivations || '0') + 1);
    });
  });

  await page.evaluate(() => { document.documentElement.dataset.deferRouteTest = 'hold'; });
  await page.mouse.click(settingsBox.x + settingsBox.width / 2, settingsBox.y + settingsBox.height / 2);
  expect(await pendingRouteState(), 'pointer navigation pending ownership').toEqual({
    activeView: 'settings',
    ariaBusy: 'true',
    ariaHidden: 'true',
    focusedView: 'settings',
    inert: true,
    renderedView: 'overview',
    requestedView: 'settings',
    surfaceView: 'overview',
    title: 'Settings',
  });
  expect(await pointerSurface.evaluate((surface) => surface instanceof HTMLElement && surface.isConnected
    && surface === document.querySelector('main > section[data-route-surface="overview"]')
    && surface.inert && surface.getAttribute('aria-hidden') === 'true'),
  'the original visible route becomes inert without replacing its DOM').toBe(true);
  expect(await stalePointerHandle.evaluate((button) => button.isConnected), 'the stale pointer target is still attached behind the inert fence').toBe(true);
  await page.mouse.click(stalePointerBox.x + stalePointerBox.width / 2, stalePointerBox.y + stalePointerBox.height / 2);
  expect(await stalePointerHandle.evaluate((button) => button.dataset.staleActivations), 'stale pointer activations').toBe('0');
  await page.evaluate(() => { delete document.documentElement.dataset.deferRouteTest; });
  await expect(main).toHaveAttribute('data-rendered-view', 'settings', { timeout: qualificationMilliseconds(3_000) });
  await expect(main.locator(':scope > section[data-route-surface="settings"]')).not.toHaveAttribute('inert', '');
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  await expect(navigation.getByRole('button', { name: 'Settings', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect(navigation.getByRole('button', { name: 'Settings', exact: true })).toBeFocused();
  expect(await pointerSurface.evaluate((surface) => surface.isConnected), 'the prior surface is removed only after route commit').toBe(false);

  await navigation.getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(main).toHaveAttribute('data-rendered-view', 'overview');
  const staleKeyboardAction = main.getByRole('button', { name: 'Tools', exact: true });
  const staleKeyboardHandle = await staleKeyboardAction.elementHandle();
  const keyboardSurface = await main.locator(':scope > section[data-route-surface="overview"]').elementHandle();
  if (!staleKeyboardHandle || !keyboardSurface) throw new Error('Keyboard route control and its owned surface must be attached.');
  await staleKeyboardHandle.evaluate((button) => {
    button.dataset.staleActivations = '0';
    button.addEventListener('click', () => {
      button.dataset.staleActivations = String(Number(button.dataset.staleActivations || '0') + 1);
    });
    button.focus();
  });

  await page.evaluate(() => { document.documentElement.dataset.deferRouteTest = 'hold'; });
  await page.keyboard.press('Enter');
  expect(await pendingRouteState(), 'keyboard navigation pending ownership').toEqual({
    activeView: 'tools',
    ariaBusy: 'true',
    ariaHidden: 'true',
    focusedView: 'tools',
    inert: true,
    renderedView: 'overview',
    requestedView: 'tools',
    surfaceView: 'overview',
    title: 'Tools',
  });
  expect(await keyboardSurface.evaluate((surface) => surface instanceof HTMLElement && surface.isConnected
    && surface === document.querySelector('main > section[data-route-surface="overview"]')
    && surface.inert && surface.getAttribute('aria-hidden') === 'true'),
  'keyboard navigation retains the original inert route until commit').toBe(true);
  expect(await staleKeyboardHandle.evaluate((button) => button.isConnected), 'the stale keyboard target is still attached behind the inert fence').toBe(true);
  await page.keyboard.press('Enter');
  expect(await staleKeyboardHandle.evaluate((button) => button.dataset.staleActivations), 'stale keyboard activations').toBe('1');
  await page.evaluate(() => { delete document.documentElement.dataset.deferRouteTest; });
  await expect(main).toHaveAttribute('data-rendered-view', 'tools', { timeout: qualificationMilliseconds(3_000) });
  await expect(main).toHaveAttribute('data-requested-view', 'tools');
  await expect(main).toHaveAttribute('aria-busy', 'false');
  await expect(main.locator(':scope > section[data-route-surface="tools"]')).not.toHaveAttribute('aria-hidden', 'true');
  await expect(page.getByRole('heading', { level: 1, name: 'Tools', exact: true })).toBeVisible();
  await expect(navigation.getByRole('button', { name: 'Tools', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect(navigation.getByRole('button', { name: 'Tools', exact: true })).toBeFocused();
  expect(await keyboardSurface.evaluate((surface) => surface.isConnected), 'the prior keyboard surface is removed after route commit').toBe(false);
  await page.waitForLoadState('networkidle');
  guards.assertClean();
});

referenceTest('quality diagnostics serialize within their bounded evidence budget', async ({ page, request }, testInfo) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await installQualityObservers(page);
  await openRoute(page, 'Overview');
  await page.evaluate(() => {
    const source = document.createElement('div');
    source.dataset.qualityDiagnostic = 'source';
    const destination = document.createElement('div');
    destination.dataset.qualityDiagnostic = 'destination';
    const movable = document.createElement('section');
    movable.append(document.createElement('span'));
    source.append(movable);
    document.body.append(source, destination);
  });
  await resetQualityWindow(page);
  const initialQuality = await qualitySnapshot(page);
  await page.evaluate(() => {
    const source = document.querySelector('[data-quality-diagnostic="source"]');
    const destination = document.querySelector('[data-quality-diagnostic="destination"]');
    const movable = source?.querySelector('section');
    if (!destination || !movable) throw new Error('DOM movement diagnostic missing.');
    destination.append(movable);
  });
  const movedQuality = await qualitySnapshot(page);
  expect(movedQuality.domCurrent).toBe(initialQuality.domCurrent);
  expect(movedQuality.domBoundaryPeak).toBe(initialQuality.domCurrent);
  await resetQualityWindow(page);
  const nestedAppendInitial = await qualitySnapshot(page);
  await page.evaluate(() => {
    const parent = document.createElement('section');
    parent.dataset.qualityDiagnostic = 'nested-append';
    document.body.append(parent);
    parent.append(document.createElement('span'));
  });
  const nestedAppendQuality = await qualitySnapshot(page);
  expect(nestedAppendQuality.domCurrent).toBe(nestedAppendInitial.domCurrent + 2);
  expect(nestedAppendQuality.domBoundaryPeak).toBe(nestedAppendInitial.domCurrent + 2);
  await page.evaluate(() => document.querySelector('[data-quality-diagnostic="nested-append"]')?.remove());
  await resetQualityWindow(page);
  const detachedMutationInitial = await qualitySnapshot(page);
  await page.evaluate(() => {
    const detached = document.createElement('section');
    const fragment = document.createDocumentFragment();
    const nested = document.createElement('div');
    for (let index = 0; index < 11; index += 1) nested.append(document.createElement('span'));
    fragment.append(document.createTextNode('ignored text'), nested, document.createComment('ignored comment'));
    document.body.append(detached);
    detached.remove();
    detached.append(fragment);
  });
  const diagnostics = await page.evaluate(() => {
    const quality = window.__kodesecQuality;
    const normalize = window.__kodesecNormalizeLoafScript;
    const markRoute = window.__kodesecMarkQualityRoute;
    const routeAt = window.__kodesecQualityRouteAt;
    if (!quality || !normalize || !markRoute || !routeAt) throw new Error('Quality diagnostics missing.');
    const marker = performance.now();
    markRoute('projects', marker);
    markRoute('settings', marker + 1);
    return {
      internal: normalize({
        duration: 7,
        sourceURL: `${window.location.origin}/assets/generated.js?token=raw-private#fragment`,
        sourceFunctionName: 'generatedFixture',
      }),
      external: normalize({
        duration: 8,
        sourceURL: 'https://user:raw-private@example.invalid/private.js?token=raw-private',
        sourceFunctionName: 'externalFixture',
      }),
      unsafeFunction: normalize({ sourceFunctionName: 'fixture\nraw-private' }),
      routes: [routeAt(marker - 1), routeAt(marker + 0.5), routeAt(marker + 2)],
    };
  });
  const quality = await qualitySnapshot(page);
  assertRequiredQualityObservers(quality);
  expect(diagnostics.internal).toEqual({
    duration: 7,
    sourceURL: '/assets/generated.js',
    functionName: 'generatedFixture',
  });
  expect(diagnostics.external).toEqual({ duration: 8, sourceURL: '<external>', functionName: 'externalFixture' });
  expect(diagnostics.unsafeFunction.functionName).toBe('<redacted>');
  expect(diagnostics.routes).toEqual(['overview', 'projects', 'settings']);
  expect(JSON.stringify(diagnostics)).not.toContain('raw-private');
  expect(quality.domBoundaryPeak).toBe(detachedMutationInitial.domCurrent);
  expect(quality.domCurrent).toBe(detachedMutationInitial.domCurrent);
  expect(quality.longFrames.length).toBeLessThanOrEqual(24);
  expect(quality.routeTransitions.length).toBeLessThanOrEqual(32);
});

referenceTest('Projects keeps source registration and scan controls reachable with actual 200% text enlargement', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'responsive-long-content', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations: string[] = [];
  page.on('request', (candidate) => {
    const url = new URL(candidate.url());
    if (url.origin === new URL(baseURL).origin && url.pathname.startsWith('/v1/')
      && !['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) mutations.push(`${candidate.method()} ${url.pathname}`);
  });
  await openRoute(page, 'Projects');
  const surface = page.locator('section[data-route-surface="projects"]');
  const registration = surface.locator('.project-registration');
  const summary = registration.locator(':scope > summary');
  for (const disclosure of [surface.locator('.first-run-checklist'), registration]) {
    if (!await disclosure.evaluate((element: HTMLDetailsElement) => element.open)) {
      await disclosure.locator(':scope > summary').click();
    }
    await expect(disclosure).toHaveAttribute('open', '');
  }
  await registration.getByRole('button', { name: 'Authorize another source root', exact: true }).click();
  const name = registration.getByLabel('Name', { exact: true });
  const path = registration.getByLabel('Repository Path', { exact: true });
  const source = registration.getByLabel('Exact source root', { exact: true });
  await name.fill('Enlarged unsubmitted project');
  await path.fill('/workspace/generated/enlarged-project');
  await source.fill('/workspace/generated/narrow-team');
  const hostCommand = registration.getByLabel('Source authorization host command', { exact: true });
  const expectedHostCommand = `KODESEC_EXPECT_INSTALLATION_ID=012345abcdef KODESEC_SOURCE_ROOT_B64=${Buffer.from('/workspace/generated/narrow-team', 'utf8').toString('base64url')} make apply-source`;
  await expect(hostCommand).toHaveValue(expectedHostCommand);
  await expect(hostCommand).toHaveAttribute('readonly', '');
  const selectedProject = await surface.locator('select[name="project_id"]').inputValue();

  // Reuse the existing Findings/Jobs computed-size method: snapshot before
  // changing any ancestor, then double glyphs and finite leading once.
  // This is synthetic text enlargement, not CSS zoom or native browser zoom.
  const textScale = await page.evaluate(() => {
    const before = Array.from(document.querySelectorAll<HTMLElement>('*'))
      .filter((element) => element instanceof HTMLElement)
      .map((element) => {
        const style = getComputedStyle(element);
        return { element, size: Number.parseFloat(style.fontSize), leading: Number.parseFloat(style.lineHeight) };
      });
    for (const { element, size, leading } of before) {
      element.style.fontSize = `${size * 2}px`;
      if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
    }
    const checked = before.filter(({ element }) => element.matches('input, select, textarea, button, summary')
      || Array.from(element.childNodes).some((node) => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent?.trim())));
    return {
      elements: checked.length,
      mismatches: checked.flatMap(({ element, size }) => {
        const after = Number.parseFloat(getComputedStyle(element).fontSize);
        return Math.abs(after - size * 2) < 0.01 ? [] : [{ tag: element.tagName, before: size, after }];
      }),
    };
  });
  expect(textScale.elements, 'populated Projects text and native form controls are measured').toBeGreaterThan(40);
  expect(textScale.mismatches, 'all existing glyphs and native form-control fonts actually double').toEqual([]);
  await testInfo.attach('projects-actual-text-enlargement.json', { body: Buffer.from(JSON.stringify(textScale, null, 2)), contentType: 'application/json' });

  for (const width of [1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await summary.focus();
    await summary.press('Space');
    await expect(registration).not.toHaveAttribute('open', '');
    await expect(name).not.toBeVisible();
    await expect(summary).toBeFocused();
    await summary.press('Enter');
    await expect(registration).toHaveAttribute('open', '');
    await expect(name).toHaveValue('Enlarged unsubmitted project');
    await expect(path).toHaveValue('/workspace/generated/enlarged-project');
    await expect(source).toHaveValue('/workspace/generated/narrow-team');
    await expect(surface.locator('select[name="project_id"]')).toHaveValue(selectedProject);
    await expect(surface.getByRole('button', { name: 'Scan', exact: true })).toBeEnabled();
    // Registered rows use content-visibility:auto. Materialize the exact row
    // at this width before measuring its children; cached offscreen geometry
    // from an earlier width is not evidence of painted control clipping.
    const registeredRow = surface.locator('.project-row');
    await expect(registeredRow).toHaveCount(1);
    await registeredRow.scrollIntoViewIfNeeded();
    await expect(registeredRow).toBeInViewport();
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    const geometry = await surface.evaluate((element) => {
      const heading = element.querySelector('.project-registration > summary h2')!.getBoundingClientRect();
      const chevron = element.querySelector('.project-registration > summary > svg')!.getBoundingClientRect();
      const command = element.querySelector('.source-authorization-command')!;
      const commandBounds = command.getBoundingClientRect();
      const textareaBounds = command.querySelector('textarea')!.getBoundingClientRect();
      const copyBounds = command.querySelector('button')!.getBoundingClientRect();
      return {
      authorizationCommand: {
        left: commandBounds.left, right: commandBounds.right,
        textareaLeft: textareaBounds.left, textareaRight: textareaBounds.right, textareaBottom: textareaBounds.bottom,
        copyLeft: copyBounds.left, copyRight: copyBounds.right, copyTop: copyBounds.top,
      },
      disclosure: { headingRight: heading.right, headingTop: heading.top, headingBottom: heading.bottom,
        chevronLeft: chevron.left, chevronCenterY: (chevron.top + chevron.bottom) / 2 },
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      text: Array.from(element.querySelectorAll<HTMLElement>('h2, label, .helper-text, .project-row strong, button, summary'))
        .filter((item) => item.getBoundingClientRect().width > 0 && !item.closest('details:not([open])'))
        .map((item) => {
          const bounds = item.getBoundingClientRect();
          return { tag: item.tagName, selfClipping: item.matches('button, summary, .project-row strong'), left: bounds.left, right: bounds.right, clientWidth: item.clientWidth,
            scrollWidth: item.scrollWidth, clientHeight: item.clientHeight, scrollHeight: item.scrollHeight };
        }),
    }; });
    expect(geometry.disclosure.chevronLeft, `${width}px disclosure indicator follows the heading`).toBeGreaterThanOrEqual(geometry.disclosure.headingRight - 0.5);
    expect(geometry.disclosure.chevronCenterY, `${width}px disclosure indicator is beside the heading`).toBeGreaterThanOrEqual(geometry.disclosure.headingTop - 0.5);
    expect(geometry.disclosure.chevronCenterY, `${width}px disclosure indicator does not wrap below`).toBeLessThanOrEqual(geometry.disclosure.headingBottom + 0.5);
    expect(geometry.overflow, `${width}px enlarged Projects page does not overflow`).toBeLessThanOrEqual(1);
    await expect(hostCommand).toHaveValue(expectedHostCommand);
    if (width <= 640) {
      const command = geometry.authorizationCommand;
      expect(Math.abs(command.textareaLeft - command.left), `${width}px command starts at its available row edge`).toBeLessThanOrEqual(0.5);
      expect(Math.abs(command.textareaRight - command.right), `${width}px command retains the full readable row width`).toBeLessThanOrEqual(0.5);
      expect(command.copyTop, `${width}px Copy follows the readable command without overlap`).toBeGreaterThanOrEqual(command.textareaBottom - 0.5);
      expect(Math.abs(command.copyLeft - command.left), `${width}px Copy starts at its available row edge`).toBeLessThanOrEqual(0.5);
      expect(Math.abs(command.copyRight - command.right), `${width}px Copy retains the full row width`).toBeLessThanOrEqual(0.5);
    }
    expect(geometry.text.length, `${width}px expanded Projects content is present`).toBeGreaterThan(15);
    for (const item of geometry.text) {
      expect(item.left, `${width}px ${item.tag} left edge`).toBeGreaterThanOrEqual(-0.5);
      expect(item.right, `${width}px ${item.tag} right edge`).toBeLessThanOrEqual(width + 0.5);
      // Match the hostile-content owner: hidden absolute InfoTip descendants
      // do not define painted heading/label clipping. Controls and row names do.
      if (item.selfClipping) {
        expect(item.scrollWidth, `${width}px ${item.tag} text horizontal clipping`).toBeLessThanOrEqual(item.clientWidth + 1);
        expect(item.scrollHeight, `${width}px ${item.tag} text vertical clipping`).toBeLessThanOrEqual(item.clientHeight + 1);
      }
    }
    // Check painted targets after individually bringing controls into view;
    // tall 200% forms need not fit one viewport to remain usable.
    const controls = registration.locator('summary, input, textarea, button');
    expect(await controls.count()).toBeGreaterThan(7);
    for (const control of await controls.all()) {
      await control.scrollIntoViewIfNeeded();
      const hit = await control.evaluate((element) => {
        const bounds = element.getBoundingClientRect();
        const target = document.elementFromPoint((bounds.left + bounds.right) / 2, (bounds.top + bounds.bottom) / 2);
        return { left: bounds.left, right: bounds.right, matches: target !== null && element.contains(target) };
      });
      expect(hit.left).toBeGreaterThanOrEqual(-0.5);
      expect(hit.right).toBeLessThanOrEqual(width + 0.5);
      expect(hit.matches, `${width}px an enlarged registration control owns its painted target`).toBe(true);
    }
    await name.focus();
    await expect(name).toBeFocused();
    await name.press('Tab');
    await expect(path).toBeFocused();
    await testInfo.attach(`projects-text-200-${width}-geometry.json`, { body: Buffer.from(JSON.stringify(geometry, null, 2)), contentType: 'application/json' });
    // Deferred rows must be painted before measuring them. A name can wrap
    // without clipping yet still be unusable when actions consume its column.
    const rows = surface.locator('.project-row');
    expect(await rows.count()).toBeGreaterThan(0);
    for (const row of await rows.all()) {
      await row.scrollIntoViewIfNeeded();
      await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      const identity = await row.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const name = element.querySelector('strong')!.getBoundingClientRect();
        const branch = element.querySelector('small')!.getBoundingClientRect();
        const buttons = Array.from(element.querySelectorAll('button')).map(button => {
          const rectangle = button.getBoundingClientRect();
          return { top: rectangle.top, left: rectangle.left, right: rectangle.right, bottom: rectangle.bottom };
        });
        return { width: bounds.width, nameWidth: name.width, nameBottom: name.bottom,
          branchRight: branch.right, buttons };
      });
      if (width <= 640) {
        expect(identity.nameWidth, 'repository identity retains most of its row').toBeGreaterThan(identity.width * 0.65);
        expect(identity.buttons[0].top, 'actions follow the complete repository name').toBeGreaterThanOrEqual(identity.nameBottom);
        expect(identity.branchRight, 'branch and Open have separate columns').toBeLessThanOrEqual(identity.buttons[0].left);
        expect(Math.abs((identity.buttons[0].top + identity.buttons[0].bottom) / 2
          - (identity.buttons[1].top + identity.buttons[1].bottom) / 2), 'row action centers align').toBeLessThanOrEqual(1);
      }
      for (const button of await row.getByRole('button').all()) {
        await button.scrollIntoViewIfNeeded();
        expect(await button.evaluate(element => {
          const bounds = element.getBoundingClientRect();
          const target = document.elementFromPoint((bounds.left + bounds.right) / 2, (bounds.top + bounds.bottom) / 2);
          return element.checkVisibility({ contentVisibilityAuto: true }) && target !== null && element.contains(target);
        }), 'project action owns its painted target').toBe(true);
      }
    }
    if (width <= 390) {
      await testInfo.attach(`projects-registration-text-200-${width}.png`, { body: await registration.screenshot(), contentType: 'image/png' });
    }
  }
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('Projects keeps existing scan controls primary and preserves a registration draft across disclosure and refresh', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations: string[] = [];
  page.on('request', (candidate) => {
    const url = new URL(candidate.url());
    if (url.origin === new URL(baseURL).origin && url.pathname.startsWith('/v1/')
      && !['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) mutations.push(`${candidate.method()} ${url.pathname}`);
  });
  await openRoute(page, 'Projects');
  const registration = page.locator('.project-registration');
  const summary = registration.locator(':scope > summary');
  const name = registration.getByLabel('Name', { exact: true });
  await expect(registration).not.toHaveAttribute('open', '');
  await expect(summary.getByRole('heading', { name: 'Register Project', exact: true })).toBeVisible();
  const indicator = await summary.evaluate((element) => {
    const heading = element.querySelector('h2')!.getBoundingClientRect();
    const chevron = element.querySelector('svg')!.getBoundingClientRect();
    return { headingRight: heading.right, headingTop: heading.top, headingBottom: heading.bottom,
      chevronLeft: chevron.left, chevronCenterY: (chevron.top + chevron.bottom) / 2 };
  });
  expect(indicator.chevronLeft, 'Registration indicator follows its heading').toBeGreaterThanOrEqual(indicator.headingRight - 0.5);
  expect(indicator.chevronCenterY, 'Registration indicator stays beside its heading').toBeGreaterThanOrEqual(indicator.headingTop - 0.5);
  expect(indicator.chevronCenterY, 'Registration indicator never stacks below its heading').toBeLessThanOrEqual(indicator.headingBottom + 0.5);
  await expect(summary.getByRole('button')).toHaveCount(0);
  await expect(name).toHaveCount(1);
  await expect(name).not.toBeVisible();
  await expect(page.getByRole('heading', { name: 'Start Scan', exact: false })).toBeInViewport();
  await expect(page.getByRole('button', { name: 'Scan', exact: true })).toBeEnabled();
  if ((page.viewportSize()?.width ?? 0) > 980) {
    await expect(page.locator('.project-registered').getByRole('heading', { name: 'Registered', exact: false })).toBeInViewport();
    await expect(page.locator('.project-row').getByRole('button', { name: 'Open', exact: true })).toBeInViewport();
  }
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await testInfo.attach('projects-existing-registration-collapsed.png', {
    body: await page.screenshot({ animations: 'disabled', caret: 'hide', fullPage: false }), contentType: 'image/png',
  });
  await summary.focus();
  await summary.press('Enter');
  await expect(registration).toHaveAttribute('open', '');
  await expect(summary).toBeFocused();
  await summary.press('Tab');
  await expect(registration.getByRole('button', { name: 'More information', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(name).toBeFocused();
  await name.fill('Unsubmitted draft');
  await registration.getByLabel('Repository Path', { exact: true }).fill('/workspace/generated/draft');
  await registration.getByLabel('Remote URL', { exact: true }).fill('https://example.invalid/draft.git');
  await registration.getByLabel('Default Branch', { exact: true }).fill('draft-branch');
  const originalInput = await name.elementHandle();
  if (!originalInput) throw new Error('The registration input is unavailable.');
  try {
    await summary.focus();
    await summary.press('Space');
    await expect(registration).not.toHaveAttribute('open', '');
    await expect(summary).toBeFocused();
    await summary.press('Enter');
    await expect(registration).toHaveAttribute('open', '');
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.waitForLoadState('networkidle');
    await expect(registration).toHaveAttribute('open', '');
    expect(await originalInput.evaluate((element) => element === document.querySelector('.project-registration input[name="name"]'))).toBe(true);
    await expect(name).toHaveValue('Unsubmitted draft');
    await expect(registration.getByLabel('Repository Path', { exact: true })).toHaveValue('/workspace/generated/draft');
    await expect(registration.getByLabel('Remote URL', { exact: true })).toHaveValue('https://example.invalid/draft.git');
    await expect(registration.getByLabel('Default Branch', { exact: true })).toHaveValue('draft-branch');
    expect(mutations).toEqual([]);
    guards.assertClean();
  } finally { await originalInput.dispose(); }
});

referenceTest('project registration acknowledges once, refreshes persisted state, and resets the form', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let release!: () => void;
  let markEntered!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const entered = new Promise<void>((resolve) => { markEntered = resolve; });
  await page.route(`${new URL(baseURL).origin}/v1/projects`, async (route) => {
    if (route.request().method() !== 'POST') { await route.continue(); return; }
    markEntered();
    await released;
    await route.continue();
  });
  try {
    await openRoute(page, 'Projects');

    await page.locator('.project-registration > summary').click();
    await page.getByLabel('Name').fill('Async Form Fixture');
    await page.getByLabel('Repository Path').fill('/workspace/generated/async-form-fixture');
    await page.getByRole('button', { name: 'Add Project' }).click();
    await entered;
    const registration = page.locator('.project-registration');
    const summary = registration.locator(':scope > summary');
    await expect(registration).toHaveAttribute('open', '');
    await expect(page.getByRole('button', { name: 'Add Project' })).toBeDisabled();
    await summary.focus();
    await summary.press('Space');
    await expect(registration).not.toHaveAttribute('open', '');
    await summary.press('Enter');
    await expect(registration).toHaveAttribute('open', '');
    await expect(page.getByLabel('Name')).toHaveValue('Async Form Fixture');
    release();

    await expect(page.getByText('Project registered', { exact: true })).toBeVisible();
    await expect(page.getByText('Project registration failed', { exact: true })).toHaveCount(0);
    await expect(page.locator('.project-row strong', { hasText: 'Async Form Fixture' })).toBeVisible();
    await expect(page.getByLabel('Name')).toHaveValue('');
    await expect(page.getByLabel('Repository Path')).toHaveValue('');
    await expect(page.getByLabel('Default Branch')).toHaveValue('main');
    const counts = await (await request.get('/__test/requests')).json() as { projects: number };
    expect(counts.projects, 'project registration requests').toBe(1);
    await expect(registration).toHaveAttribute('open', '');
    guards.assertClean();
  } finally { release(); }
});

referenceTest('late project registration preserves the user’s Tools navigation', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const origin = new URL(baseURL).origin;
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, origin);
  let release!: () => void;
  let entered!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const seen = new Promise<void>((resolve) => { entered = resolve; });
  await page.route(`${origin}/v1/projects`, async (route) => {
    if (route.request().method() !== 'POST') { await route.continue(); return; }
    entered();
    await released;
    await route.continue();
  });
  try {
    await openRoute(page, 'Projects');
    await page.locator('.project-registration > summary').click();
    await page.getByLabel('Name').fill('Route Ownership Fixture');
    await page.getByLabel('Repository Path').fill('/workspace/generated/route-ownership');
    await page.getByRole('button', { name: 'Add Project', exact: true }).click();
    await seen;
    await page.getByRole('navigation').getByRole('button', { name: 'Tools', exact: true }).click();
    await expect(page.locator('main')).toHaveAttribute('data-rendered-view', 'tools');
    release();
    await expect(page.getByText('Project registered', { exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('main')).toHaveAttribute('data-requested-view', 'tools');
    await expect(page.locator('main')).toHaveAttribute('data-rendered-view', 'tools');
    const card = page.locator('article.tool-card-internal').filter({ hasText: 'iac-lite ·' });
    await expect(card.getByRole('button', { name: 'Enable', exact: true })).toBeEnabled();
    expect(new URL(page.url()).searchParams.get('view')).toBe('tools');
    const counts = await (await request.get('/__test/requests')).json() as { projects: number };
    expect(counts.projects).toBe(1);
    guards.assertClean();
  } finally { release(); }
});

referenceTest('[WEB-ACT-001] project registration renders a structured source-root error as bounded human guidance', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.addInitScript(() => {
    (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization = undefined;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization = value;
        },
      },
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.setViewportSize({ width: 600, height: 432 });
  await openRoute(page, 'Projects');
  const projectsBefore = await (await request.get('/v1/projects')).json();

  await page.locator('.project-registration > summary').click();
  await page.getByLabel('Name').fill('Refused broad root');
  await page.getByLabel('Repository Path').fill('/Users');
  await page.getByLabel('Remote URL').fill('https://example.test/unchanged');
  await page.getByLabel('Default Branch').fill('unchanged-branch');
  await page.getByRole('button', { name: 'Add Project' }).focus();
  await page.keyboard.press('Enter');
  const inlineError = page.locator('form [role="alert"]');
  await expect(inlineError).toBeFocused();
  await expect(inlineError).toContainText('Choose a folder inside an existing authorized root.');
  await expect(inlineError).toContainText('broad parent folders cannot be authorized');
  await expect(inlineError).not.toContainText('explicitly authorize this exact source root');
  await expect(page.getByLabel('Repository Path')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByLabel('Repository Path')).toHaveAttribute('aria-describedby', await inlineError.getAttribute('id') || 'missing-error-id');
  const errorBounds = await inlineError.boundingBox();
  expect(errorBounds).not.toBeNull();
  expect(errorBounds!.y).toBeGreaterThanOrEqual(0);
  expect(errorBounds!.y + errorBounds!.height).toBeLessThanOrEqual(432);
  await expect(page.getByLabel('Source authorization host command')).toHaveCount(0);
  await expect(page.getByLabel('Name')).toHaveValue('Refused broad root');
  await expect(page.getByLabel('Repository Path')).toHaveValue('/Users');
  await expect(page.getByLabel('Remote URL')).toHaveValue('https://example.test/unchanged');
  await expect(page.getByLabel('Default Branch')).toHaveValue('unchanged-branch');
  expect(await (await request.get('/v1/projects')).json()).toEqual(projectsBefore);

  await page.getByLabel('Name').fill('Outside Root Fixture');
  await page.getByLabel('Repository Path').fill('/private/generated/outside-root');
  await page.getByRole('button', { name: 'Add Project' }).click();

  const toast = page.locator('.toast').filter({ hasText: 'Project registration failed' }).last();
  await expect(toast).toContainText('Choose a repository inside an authorized source root.');
  await expect(toast).toContainText('Selected folder: /private/generated/outside-root.');
  await expect(toast).toContainText('Authorized source roots: /workspace/generated.');
  await expect(toast).toContainText('review one narrow source root in local setup');
  await expect(toast).not.toContainText('source_outside_allowed_root');
  await expect(toast).not.toContainText('authorize_source');
  await expect(page.getByLabel('Repository Path')).toHaveValue('/private/generated/outside-root');
  const exactCommand = `KODESEC_EXPECT_INSTALLATION_ID=012345abcdef KODESEC_SOURCE_ROOT_B64=${Buffer.from('/private/generated/outside-root', 'utf8').toString('base64url')} make apply-source`;
  await expect(page.getByText('Authorize one narrow read-only source root')).toBeVisible();
  await expect(page.getByLabel('Exact source root')).toHaveValue('/private/generated/outside-root');
  await expect(page.getByText(
    'The rejected registration response reported this root as guidance: /workspace/generated. This retained response is never used for scan admission; only a fresh successful configuration load is authoritative.',
    { exact: true },
  )).toBeVisible();
  await expect(page.getByLabel('Source authorization host command')).toHaveValue(exactCommand);
  await expect(page.getByText('Database and scanner-cache volumes are preserved; no image is rebuilt.')).toBeVisible();
  await page.getByRole('button', { name: 'Copy host command' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Host command copied.' })).toBeVisible();
  expect(await page.evaluate(
    () => (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization,
  )).toBe(exactCommand);
  for (const broadRoot of [
    '/Users', '/Users/', '/Users/.', '/Users//', '/home/.', '/home///', '/srv/../Users', '/Users/..',
    '/private/tmp', '/private/tmp/', '/private/tmp/.', '/private//tmp', '/private/var/../tmp',
    '/private/var/tmp', '/var/tmp',
    '/System/Volumes/Data', '/System/Volumes/Data/Users', '/System/Volumes/Data/Volumes',
    '/System/Volumes/Data/private', '/System/Volumes/Data/private/tmp',
    '/System/Volumes/Data/private/var/tmp', '/System/Volumes/Data/var', '/System/Volumes/Data/var/tmp',
  ]) {
    await page.getByLabel('Exact source root').fill(broadRoot);
    await expect(page.getByLabel('Source authorization host command')).toHaveCount(0);
    await expect(page.getByRole('status').filter({ hasText: 'No command is offered for an unsafe root or unknown installation.' })).toBeVisible();
  }
  const narrowTemporaryRoot = '/private/tmp/lomo-qa/run/worktree';
  const narrowTemporaryCommand = `KODESEC_EXPECT_INSTALLATION_ID=012345abcdef KODESEC_SOURCE_ROOT_B64=${Buffer.from(narrowTemporaryRoot, 'utf8').toString('base64url')} make apply-source`;
  await page.getByLabel('Exact source root').fill(narrowTemporaryRoot);
  await expect(page.getByLabel('Source authorization host command')).toHaveValue(narrowTemporaryCommand);
  const narrowTrailingRoot = '/srv/project/';
  const narrowTrailingCommand = `KODESEC_EXPECT_INSTALLATION_ID=012345abcdef KODESEC_SOURCE_ROOT_B64=${Buffer.from(narrowTrailingRoot, 'utf8').toString('base64url')} make apply-source`;
  await page.getByLabel('Exact source root').fill(narrowTrailingRoot);
  await expect(page.getByLabel('Source authorization host command')).toHaveValue(narrowTrailingCommand);
  await page.getByRole('button', { name: 'Copy host command' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Host command copied.' })).toBeVisible();
  expect(await page.evaluate(
    () => (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization,
  )).toBe(narrowTrailingCommand);
  await page.getByLabel('Exact source root').fill('/private/generated/$HOME/service');
  await expect(page.getByLabel('Source authorization host command')).toHaveCount(0);
  await expect(page.getByRole('status').filter({ hasText: 'No command is offered for an unsafe root or unknown installation.' })).toBeVisible();
  expect(guards.failures.http).toHaveLength(2);
  expect(guards.failures.http[0]).toContain('422');
  expect(guards.failures.console).toHaveLength(2);
  expect(guards.failures.console[0]).toContain('422');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);

  await expect(page.locator('main > .notice')).toContainText('Choose a repository inside an authorized source root.');
  await page.getByRole('navigation').getByRole('button', { name: 'Tools', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Tools', exact: true })).toBeVisible();
  await expect(page.locator('main > .notice')).toHaveCount(0);
});

referenceTest('[WEB-ACT-001] late project failures stay owned by the route that submitted them', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let releaseRequest: (() => void) | undefined;
  let markIntercepted: (() => void) | undefined;
  const intercepted = new Promise<void>((resolve) => { markIntercepted = resolve; });
  const release = new Promise<void>((resolve) => { releaseRequest = resolve; });
  await page.route('**/v1/projects', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }
    markIntercepted?.();
    await release;
    await route.continue();
  });
  await openRoute(page, 'Projects');

  await page.locator('.project-registration > summary').click();
  await page.getByLabel('Name').fill('Late Outside Root Fixture');
  await page.getByLabel('Repository Path').fill('/private/generated/outside-root');
  await page.getByRole('button', { name: 'Add Project' }).click();
  await intercepted;
  await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  const settingsButton = page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true });
  await settingsButton.focus();
  releaseRequest?.();
  await expect(page.getByText('Project registration failed', { exact: true })).toBeVisible();
  await expect(settingsButton).toBeFocused();
  await expect(page.locator('main > .notice')).toHaveCount(0);
  await page.getByRole('navigation').getByRole('button', { name: 'Projects', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toBeVisible();
  await expect(page.locator('main > .notice')).toHaveCount(0);
  await expect(page.locator('form [role="alert"]')).toHaveCount(0);
});

referenceTest('[WEB-ACT-009] source-boundary recovery deep link exposes typed roots and a copy-only host workflow', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const initialConfigResponse = await request.get('/v1/config');
  expect(initialConfigResponse.status()).toBe(200);
  const initialConfig = await initialConfigResponse.json() as { installation_id: string; allowed_roots: string[] };
  expect(initialConfig).toMatchObject({ installation_id: '012345abcdef', allowed_roots: ['/workspace/generated'] });
  const mutations: string[] = [];
  page.on('request', (candidate) => {
    const target = new URL(candidate.url());
    if (target.origin === new URL(baseURL).origin && target.pathname.startsWith('/v1/')
      && !['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) {
      mutations.push(`${candidate.method()} ${target.pathname}`);
    }
  });
  await page.addInitScript(() => {
    (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization = undefined;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization = value;
        },
      },
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=settings#source-boundary');
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  const settingsSurface = page.locator('section[data-route-surface="settings"]');
  await expect(settingsSurface).not.toHaveAttribute('aria-busy', 'true');
  await expect(settingsSurface).not.toHaveAttribute('inert', '');

  const panel = page.locator('#source-boundary');
  await expect(panel).toBeVisible();
  await expect(panel).toBeFocused();
  await expect(panel.getByText('It never broadens a host mount automatically.')).toBeVisible();
  const configuredRoots = panel.getByRole('list', { name: 'Configured allowed source roots' });
  await expect(configuredRoots.getByText('/workspace/generated', { exact: true })).toBeVisible();
  await expect(panel.getByText('These exact paths come from the authenticated runtime configuration.')).toBeVisible();

  await expect(panel.getByRole('combobox', { name: 'Source authorization action', exact: true })).toHaveValue('add');
  const additionalRoot = '/private/generated/outside-root';
  const exactCommand = `KODESEC_EXPECT_INSTALLATION_ID=${initialConfig.installation_id} KODESEC_SOURCE_ROOT_B64=${Buffer.from(additionalRoot, 'utf8').toString('base64url')} make apply-source`;
  await panel.getByLabel('Additional source root', { exact: true }).fill(additionalRoot);
  await expect(panel.getByLabel('Source authorization host command')).toHaveValue(exactCommand);
  await expect(panel.getByText('Database and scanner-cache volumes are preserved; no image is rebuilt.')).toBeVisible();
  await panel.getByRole('button', { name: 'Copy host command', exact: true }).click();
  await expect(panel.getByRole('status')).toHaveText('Guarded host command copied. Run it from the checkout with this installation’s STATE_DIR when using custom runtime state, then reload Settings.');
  expect(await page.evaluate(
    () => (window as Window & { __copiedSourceAuthorization?: string }).__copiedSourceAuthorization,
  )).toBe(exactCommand);

  for (const broadRoot of [
    '/Users', '/private/tmp', '/private/tmp/.', '/System/Volumes/Data',
    '/System/Volumes/Data/Users', '/System/Volumes/Data/private/tmp',
  ]) {
    await panel.getByLabel('Additional source root', { exact: true }).fill(broadRoot);
    await expect(panel.getByLabel('Source authorization host command')).toHaveCount(0);
    await expect(panel.getByRole('status').filter({ hasText: 'unsafe or broad root' })).toBeVisible();
  }
  await panel.getByRole('button', { name: 'Choose or register an approved folder', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toBeVisible();
  expect(mutations).toEqual([]);
  const finalConfigResponse = await request.get('/v1/config');
  expect(finalConfigResponse.status()).toBe(200);
  expect(await finalConfigResponse.json()).toMatchObject({
    installation_id: initialConfig.installation_id,
    allowed_roots: initialConfig.allowed_roots,
  });

  guards.assertClean();
});

referenceTest('[WEB-SETUP-002] first-run setup preserves readable guidance and keyboard recovery across widths and 200% text', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(90_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  for (const scale of [1, 2]) {
    for (const width of [320, 390, 768, 1440, 1920]) {
      await page.setViewportSize({ width, height: width <= 390 ? 844 : 900 });
      await request.post('/__test/reset', { data: { profile: 'first-run', generation: 1 } });
      await openRoute(page, 'Projects');
      const setup = page.locator('.first-run-checklist');
      const registration = page.locator('.project-registration');
      await expect(setup).toHaveAttribute('open', '');
      await expect(registration).toHaveAttribute('open', '');
      await expect(page.getByRole('button', { name: 'Scan', exact: true })).toHaveCount(0);
      const text = await setup.innerText();
      const enlargement = await page.evaluate((factor) => {
        const before = Array.from(document.querySelectorAll<HTMLElement>('*')).map((element) => ({
          element, size: Number.parseFloat(getComputedStyle(element).fontSize),
          leading: Number.parseFloat(getComputedStyle(element).lineHeight),
        }));
        for (const { element, size, leading } of before) {
          element.style.fontSize = `${size * factor}px`;
          if (Number.isFinite(leading)) element.style.lineHeight = `${leading * factor}px`;
        }
        return before.filter(({ element }) => Array.from(element.childNodes)
          .some((node) => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent?.trim())))
          .flatMap(({ element, size }) => Math.abs(Number.parseFloat(getComputedStyle(element).fontSize) - size * factor) < 0.01
            ? [] : [{ tag: element.tagName, before: size }]);
      }, scale);
      expect(enlargement, 'Computed glyph sizes use exact text enlargement, not browser zoom').toEqual([]);
      expect(await setup.innerText()).toBe(text);
      await testInfo.attach(`first-run-setup-${width}-text-${scale * 100}.png`, {
        body: await setup.screenshot(), contentType: 'image/png',
      });
      const geometry = await page.locator('section[data-route-surface="projects"]').evaluate((surface) => ({
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        items: Array.from(surface.querySelectorAll<HTMLElement>(
          '.first-run-checklist h2, .first-run-checklist .helper-text, .first-run-steps li > div > strong, .first-run-steps li > div > span, .first-run-steps button, .project-registration > .helper-text, .project-registration label, .project-registration button',
        )).map((element) => {
          const bounds = element.getBoundingClientRect();
          return { text: element.textContent, left: bounds.left, right: bounds.right,
            hasHiddenTooltip: Boolean(element.querySelector('.info-tip-content')),
            glyphs: Array.from(element.childNodes).filter((node) => node.nodeType === Node.TEXT_NODE && node.textContent?.trim())
              .flatMap((node) => { const range = document.createRange(); range.selectNode(node);
                return Array.from(range.getClientRects()).map((rect) => ({ left: rect.left, right: rect.right })); }),
            clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
            clientHeight: element.clientHeight, scrollHeight: element.scrollHeight };
        }),
      }));
      await testInfo.attach(`first-run-setup-${width}-text-${scale * 100}-geometry.json`, {
        body: Buffer.from(JSON.stringify(geometry, null, 2)), contentType: 'application/json',
      });
      expect(geometry.overflow, 'First-run guidance causes no document overflow').toBeLessThanOrEqual(1);
      for (const item of geometry.items) {
        expect(item.left, item.text || 'setup guidance').toBeGreaterThanOrEqual(-0.5);
        expect(item.right, item.text || 'setup guidance').toBeLessThanOrEqual(width + 0.5);
        // A hidden positioned InfoTip contributes to its paragraph's scroll
        // dimensions. Validate the painted prose, not that hidden descendant.
        if (!item.hasHiddenTooltip) {
          expect(item.scrollWidth, item.text || 'setup guidance').toBeLessThanOrEqual(item.clientWidth + 1);
          expect(item.scrollHeight, item.text || 'setup guidance').toBeLessThanOrEqual(item.clientHeight + 1);
        }
        for (const glyph of item.glyphs) {
          expect(glyph.left, item.text || 'setup glyph').toBeGreaterThanOrEqual(item.left - 1);
          expect(glyph.right, item.text || 'setup glyph').toBeLessThanOrEqual(item.right + 1);
        }
      }
      const sourceAction = setup.getByRole('button', { name: 'Register source', exact: true });
      await sourceAction.focus();
      await sourceAction.evaluate((element) => element.scrollIntoView({ block: 'center' }));
      await expect(sourceAction).toBeInViewport({ ratio: 1 });
      await sourceAction.press('Enter');
      await expect(page.getByLabel('Name', { exact: true })).toBeFocused();
      await expect(registration).toHaveAttribute('open', '');
      expect(await (await request.get('/__test/commands')).json()).toEqual([]);
      expect(await (await request.get('/v1/projects')).json()).toEqual([]);
    }
  }
  guards.assertClean();
});

referenceTest('[WEB-ACT-004] Projects first-run checklist proves core, source, and scanner readiness before a normal scan', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'first-run', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Projects');

  const registration = page.locator('.project-registration');
  await expect(registration).toHaveAttribute('open', '');
  await expect(registration.locator(':scope > .helper-text')).toContainText(
    'This adds a scan target; it does not add a folder to your editor workspace or start a scan.',
  );
  await expect(registration.getByRole('button', { name: 'Authorize another source root', exact: true })).toBeVisible();
  const checklist = page.getByRole('list', { name: 'First-run setup checklist' });
  await expect(page.getByRole('heading', { level: 2, name: 'Scan setup', exact: true })).toBeVisible();
  const coreStep = checklist.getByLabel('Step 1: Core services');
  const sourceStep = checklist.getByLabel('Step 2: Source authorization and registration');
  const scannerStep = checklist.getByLabel('Step 3: Scanner data and readiness');
  const stepNumberLayout = await checklist.locator('.first-run-step-number').evaluateAll((badges) => badges.map((badge) => {
    const style = getComputedStyle(badge);
    const bounds = badge.getBoundingClientRect();
    return {
      alignItems: style.alignItems,
      display: style.display,
      flexBasis: style.flexBasis,
      flexShrink: style.flexShrink,
      height: bounds.height,
      justifyItems: style.justifyItems,
      placeItems: style.placeItems,
      width: bounds.width,
    };
  }));
  expect(stepNumberLayout).toEqual(Array.from({ length: 3 }, () => ({
    alignItems: 'center',
    // The authored inline-grid is blockified because the badge is a grid item.
    display: 'grid',
    flexBasis: '24px',
    flexShrink: '0',
    height: 24,
    justifyItems: 'center',
    placeItems: 'center',
    width: 24,
  })));
  const infoTip = page.getByRole('button', { name: 'More information', exact: true }).first();
  await expect(infoTip).toHaveAttribute('aria-expanded', 'false');
  const infoTipTarget = await infoTip.boundingBox();
  expect(infoTipTarget?.width).toBeGreaterThanOrEqual(24);
  expect(infoTipTarget?.height).toBeGreaterThanOrEqual(24);
  await infoTip.click();
  await expect(infoTip).toHaveAttribute('aria-expanded', 'true');
  const tooltip = page.getByRole('tooltip').first();
  await expect(tooltip).toBeVisible();
  const tooltipBounds = await tooltip.boundingBox();
  const viewport = page.viewportSize();
  expect(tooltipBounds?.x).toBeGreaterThanOrEqual(24);
  expect((tooltipBounds?.x || 0) + (tooltipBounds?.width || 0)).toBeLessThanOrEqual((viewport?.width || 1440) - 24);
  expect(tooltipBounds?.y).toBeGreaterThanOrEqual(24);
  expect((tooltipBounds?.y || 0) + (tooltipBounds?.height || 0)).toBeLessThanOrEqual((viewport?.height || 900) - 24);
  expect(await tooltip.evaluate((element) => getComputedStyle(element).pointerEvents)).toBe('auto');
  await tooltip.evaluate((element) => { element.style.maxHeight = '20px'; });
  expect(await tooltip.evaluate((element) => element.scrollHeight)).toBeGreaterThan(await tooltip.evaluate((element) => element.clientHeight));
  await infoTip.press('ArrowDown');
  expect(await tooltip.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
  await infoTip.click();
  await expect(infoTip).toHaveAttribute('aria-expanded', 'false');
  // Clicking closed leaves the trigger focused; leave and return to exercise
  // the keyboard focus entry rather than requesting focus on the same node.
  await infoTip.press('Tab');
  await page.keyboard.press('Shift+Tab');
  await expect(infoTip).toBeFocused();
  await expect(infoTip).toHaveAttribute('aria-expanded', 'true');
  await infoTip.press('Escape');
  await expect(infoTip).toHaveAttribute('aria-expanded', 'false');
  await expect(infoTip).toBeFocused();
  await expect(coreStep).toHaveAttribute('data-complete', 'false');
  await expect(sourceStep).toHaveAttribute('data-complete', 'false');
  await expect(sourceStep).toContainText('Authorized root: /workspace/generated');
  await expect(scannerStep).toHaveAttribute('data-complete', 'false');
  await expect(page.getByRole('button', { name: 'Scan', exact: true })).toHaveCount(0);

  const settingsRead = page.waitForResponse(response => response.request().method() === 'GET'
    && new URL(response.url()).pathname === '/v1/config');
  await coreStep.getByRole('button', { name: 'Review core services', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  // Chromium can retain the previous document-idle state while the new route's
  // intercepted reads are starting. Observe this navigation's actual read first.
  expect(await (await settingsRead).finished()).toBeNull();
  await page.waitForLoadState('networkidle');
  await request.post('/__test/first-run/core-ready');
  await openRoute(page, 'Projects');
  await expect(page.getByLabel('Step 1: Core services')).toHaveAttribute('data-complete', 'true');

  const registerSource = page.getByLabel('Step 2: Source authorization and registration');
  await registerSource.getByRole('button', { name: 'Register source', exact: true }).click();
  await expect(page.getByLabel('Name', { exact: true })).toBeFocused();
  await page.getByLabel('Name', { exact: true }).fill('First-run Service');
  await page.getByLabel('Repository Path', { exact: true }).fill('/workspace/generated/first-run-service');
  await page.getByRole('button', { name: 'Add Project', exact: true }).click();
  await expect(page.getByLabel('Step 2: Source authorization and registration')).toHaveAttribute('data-complete', 'true');
  await expect(page.locator('.project-row').getByText('First-run Service', { exact: true })).toBeVisible();
  const blockedCompleteScan = page.getByRole('button', { name: 'Scan', exact: true });
  await expect(blockedCompleteScan).toBeVisible();
  await expect(blockedCompleteScan).toBeDisabled();
  await expect(blockedCompleteScan).toHaveAttribute('aria-describedby', 'complete-scan-disabled-reason');
  await expect(page.locator('#complete-scan-disabled-reason')).toContainText('Prepare the required data or rules for OpenGrep');
  await expect(page.locator('.scan-readiness').getByRole('button', { name: 'Prepare scanners', exact: true })).toBeEnabled();

  const preflightRead = page.waitForResponse(response => response.request().method() === 'GET'
    && new URL(response.url()).pathname === '/v1/scanner/preflight');
  await page.getByLabel('Step 3: Scanner data and readiness').getByRole('button', { name: 'Prepare scanners', exact: true }).click();

  const tools = page.locator('section[data-route-surface="tools"]');
  await expect(tools).toHaveAttribute('data-tools-render-stage', 'ready');
  await expect(tools.getByRole('heading', { name: 'Prepare Scanners', exact: true })).toBeVisible();
  await expect(tools.locator('.preflight-blocked-tools').getByText('No validated active or previous-good OpenGrep rules generation exists.', { exact: true })).toBeVisible();
  await expect(tools.getByText('Requires: opengrep-reviewed-rules', { exact: true })).toBeVisible();
  await expect(tools.getByRole('button', { name: 'Prepare all scanners', exact: true })).toBeEnabled();

  expect(await (await preflightRead).finished()).toBeNull();
  await page.waitForLoadState('networkidle');
  const preparation = await request.post('/__test/first-run/scanners-ready');
  expect(preparation.ok()).toBe(true);
  const prepared = await preparation.json() as {
    ready: boolean; active_generation: string; enabled_tool_ids: string[];
    ready_tool_ids: string[]; blocked_tools: unknown[];
  };
  const externalTools = ['bearer', 'checkov', 'gitleaks', 'grype', 'opengrep', 'syft', 'trivy', 'trufflehog'];
  expect(prepared.ready).toBe(true);
  expect(prepared.active_generation).toMatch(/^[a-f0-9]{64}$/u);
  expect(prepared.enabled_tool_ids).toEqual(externalTools);
  expect(prepared.ready_tool_ids).toEqual(externalTools);
  expect(prepared.blocked_tools).toEqual([]);
  await testInfo.attach('first-run-prepared-scanner-preflight.json', {
    body: Buffer.from(JSON.stringify(prepared, null, 2)), contentType: 'application/json',
  });
  await openRoute(page, 'Projects');
  const completedSetup = page.locator('details.first-run-checklist');
  await expect(completedSetup).not.toHaveAttribute('open', '');
  await expect(completedSetup.locator(':scope > summary')).toContainText('Scan prerequisites are ready');
  await completedSetup.locator(':scope > summary').click();
  await expect(page.getByLabel('Step 3: Scanner data and readiness')).toHaveAttribute('data-complete', 'true');
  await expect(page.getByLabel('All scan prerequisites ready')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Start Scan', exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Scan', exact: true })).toBeEnabled();
  guards.assertClean();
});

referenceTest('[WEB-ACT-003] Projects requires explicit confirmation before a limited scan and binds its admission evidence', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-preparation', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Projects');

  await expect(page.getByRole('group', { name: 'Advanced choice: limited coverage', exact: true })).toContainText('Omitted evidence keeps the deterministic gate incomplete.');
  await expect(page.getByRole('button', { name: 'Scan', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Review Advanced Limited Scan', exact: true }).click();
  await page.locator('dialog.confirmation-dialog').getByRole('button', { name: 'Use limited coverage', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Advanced limited coverage acknowledged.' })).toContainText('OpenGrep');
  await page.getByRole('button', { name: 'Run Advanced Limited Scan', exact: true }).click();
  await expect(page.getByText('Scan #42 queued', { exact: true })).toBeVisible();

  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands.filter((command) => command.route === 'scan')).toHaveLength(1);
  expect(commands.find((command) => command.route === 'scan')?.input).toMatchObject({
    coverage: 'limited',
    acknowledge_limited_coverage: true,
  });
  guards.assertClean();
});

referenceTest('Projects rejects a limited scan when readiness changes after acknowledgement', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-preparation', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Projects');

  await page.getByRole('button', { name: 'Review Advanced Limited Scan', exact: true }).click();
  await page.locator('dialog.confirmation-dialog').getByRole('button', { name: 'Use limited coverage', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Advanced limited coverage acknowledged.' })).toBeVisible();
  const reviewed = await request.get('/v1/scanner/preflight').then((response) => response.json()) as { revision: string };
  const changed = await request.post('/__test/scanner-preflight-change').then((response) => response.json()) as { revision: string };
  expect(changed.revision).not.toBe(reviewed.revision);

  await page.getByRole('button', { name: 'Run Advanced Limited Scan', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Tools', exact: true })).toBeVisible();
  await expect(page.getByText('Scanner readiness changed after it was reviewed. Review the current preflight before starting a scan.', { exact: true })).toBeVisible();
  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string }>;
  expect(commands.filter((command) => command.route === 'scan')).toHaveLength(0);
  expect(guards.failures.http).toHaveLength(1);
  expect(guards.failures.http[0]).toContain('409');
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

referenceTest('non-Findings routes perform only one bounded terminal-scan prefetch', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Projects');

  await expect.poll(async () => {
    const counts = await (await request.get('/__test/requests')).json() as {
      findings: number;
      findingDetails: number;
      scanSummaries: number;
      artifacts: number;
    };
    return counts;
  }).toMatchObject({ findings: 1, findingDetails: 0, scanSummaries: 2, artifacts: 1 });
  guards.assertClean();
});

referenceTest('cold Findings publishes no selection and empty terminal evidence without a stuck loading state', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  for (const entry of [
    { profile: 'first-run', location: '/?view=findings', message: 'Select a scan to review its findings.', name: 'no-selection' },
    { profile: 'limited-evidence', location: '/?view=findings&scan=40', message: 'No findings are available to display for this scan.', name: 'empty-terminal' },
  ]) {
    expect((await request.post('/__test/reset', { data: { profile: entry.profile, generation: 1 } })).status()).toBe(200);
    await page.goto(entry.location);
    const surface = page.locator('section[data-route-surface="findings"]');
    await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface.locator('.finding-detail')).toHaveCount(0);
    await expect(surface.getByText(entry.message, { exact: true })).toHaveCount(1);
    await expect(surface.locator('.finding-list').getByText(entry.message, { exact: true })).toBeVisible();
    const widths = await surface.locator('.finding-workspace').evaluate(element => ({
      workspace: element.getBoundingClientRect().width,
      list: element.querySelector('.finding-list')!.getBoundingClientRect().width,
    }));
    expect(Math.abs(widths.workspace - widths.list), 'Empty results should use the available workspace width.').toBeLessThanOrEqual(1);
    await expect(surface.locator('.finding-list-item')).toHaveCount(0);
    await expect(page.getByText('Loading finding evidence…', { exact: true })).toHaveCount(0);
    const scan = surface.getByLabel('Scan', { exact: true });
    await expect(scan).toBeVisible();
    await expect(scan).toBeEnabled();
    if (entry.name === 'empty-terminal') {
      await expect(scan).toHaveValue('40');
      await expect(surface.getByRole('status').filter({ hasText: 'Scanner evidence is incomplete' })).toBeVisible();
      await expect(surface.locator('.finding-gate-metric strong')).toHaveText('incomplete');
      await expect(surface.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeDisabled();
    }
    await testInfo.attach(`cold-findings-${entry.name}.png`, { contentType: 'image/png', body: await page.screenshot() });
  }
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  await page.goto('/?view=findings&scan=41&finding=14');
  await expect(page.locator('.finding-detail[data-finding-id="514"]')).toBeVisible();
  await page.getByRole('textbox', { name: 'Search findings', exact: true }).fill('no-matching-finding-qualification');
  await expect(page.getByRole('textbox', { name: 'Search findings', exact: true })).toHaveValue('no-matching-finding-qualification');
  await expect(page.getByText('No findings match the current filters. Clear filters to review this scan.', { exact: true })).toHaveCount(1);
  await expect(page.locator('.finding-detail')).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
  await expect(page.locator('.finding-detail[data-finding-id]')).toBeVisible();
  await expect(page.locator('.finding-list-item')).not.toHaveCount(0);
  guards.assertClean();
});

referenceTest('Findings exposes readiness only after complete detail crosses a paint', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  // Start with the ordinary validated collection prefetch already settled.
  await openRoute(page, 'Overview');
  const exactDetail = new URL('/v1/scans/41/findings/1?expected_revision=1&expected_findings_revision=1', baseURL).href;
  const pendingNavigation = new Set<Request>();
  const collectionPaths = ['/v1/scans/41/summary', '/v1/scans/41/findings', '/v1/scans/41/artifacts'];
  const completedCollectionReads = new Map<string, number>();
  const detailReads: string[] = [];
  const observeRequest = (entry: Request) => {
    const url = new URL(entry.url());
    if (url.origin === origin && url.pathname === '/v1/scans/41/findings/1') {
      expect(entry.method()).toBe('GET');
      detailReads.push(entry.url());
    } else pendingNavigation.add(entry);
  };
  const observeCompletion = (entry: Request) => {
    pendingNavigation.delete(entry);
    const url = new URL(entry.url());
    if (url.origin === origin && collectionPaths.includes(url.pathname)) {
      completedCollectionReads.set(url.pathname, (completedCollectionReads.get(url.pathname) || 0) + 1);
    }
  };
  const observeFailure = (entry: Request) => { pendingNavigation.delete(entry); };
  page.on('request', observeRequest);
  page.on('requestfinished', observeCompletion);
  page.on('requestfailed', observeFailure);
  let releaseDetail!: () => void;
  let detailHeld = false;
  const detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
  await page.route('**/v1/scans/41/findings/1?**', async (route) => {
    detailHeld = true;
    await detailGate;
    await route.fallback();
  }, { times: 1 });
  const surface = page.locator('section[data-route-surface="findings"]');
  const scanSelect = surface.getByLabel('Scan', { exact: true });
  await page.evaluate(() => {
    const probe = window as Window & {
      __kodesecSmallFindingBatches?: Array<{ busy: boolean; count: number; stage: string | null }>;
      __kodesecSmallFindingBatchOverflow?: boolean;
      __kodesecStopSmallFindingBatches?: () => void;
    };
    probe.__kodesecSmallFindingBatches = [];
    probe.__kodesecSmallFindingBatchOverflow = false;
    const sample = () => {
      const current = document.querySelector('main > section[data-route-surface="findings"]');
      if (!current) return;
      const next = {
        busy: current.getAttribute('aria-busy') === 'true',
        count: Number(current.getAttribute('data-findings-committed-count') || 0),
        stage: current.getAttribute('data-findings-render-stage'),
      };
      const last = probe.__kodesecSmallFindingBatches!.at(-1);
      if (last?.count === next.count && last.busy === next.busy && last.stage === next.stage) return;
      if (probe.__kodesecSmallFindingBatches!.length >= 32) {
        probe.__kodesecSmallFindingBatchOverflow = true;
        return;
      }
      probe.__kodesecSmallFindingBatches!.push(next);
    };
    const observer = new MutationObserver(sample);
    observer.observe(document.querySelector('main')!.parentElement!, {
      subtree: true, childList: true, attributes: true,
      attributeFilter: ['aria-busy', 'data-findings-committed-count', 'data-findings-render-stage'],
    });
    probe.__kodesecStopSmallFindingBatches = () => { observer.disconnect(); };
  });
  try {
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    await expect.poll(() => detailHeld).toBe(true);
    await expect(page.getByRole('status').filter({ hasText: 'Loading finding evidence…' })).toHaveCount(1);
    await expect(page.locator('.finding-initial-loading')).toBeVisible();
    await expect.poll(() => Object.fromEntries(completedCollectionReads)).toEqual({
      '/v1/scans/41/summary': 1,
    });
    await expect.poll(() => pendingNavigation.size).toBe(0);
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    expect(detailReads).toEqual([exactDetail]);
    const batchProbe = await page.evaluate(() => {
      const probe = window as Window & {
        __kodesecSmallFindingBatches?: Array<{ busy: boolean; count: number; stage: string | null }>;
        __kodesecSmallFindingBatchOverflow?: boolean;
        __kodesecStopSmallFindingBatches?: () => void;
      };
      probe.__kodesecStopSmallFindingBatches?.();
      return {
        observations: probe.__kodesecSmallFindingBatches || [],
        overflow: probe.__kodesecSmallFindingBatchOverflow || false,
      };
    });
    // These observations prove bounded DOM commits, not that pixels painted.
    // The held exact detail must still prevent route readiness independently.
    expect(batchProbe.overflow, 'bounded Findings commit observations').toBe(false);
    const positiveBatches = batchProbe.observations.filter(({ count }) => count > 0);
    expect(positiveBatches.length).toBeGreaterThan(0);
    expect(positiveBatches[0].count, 'three findings fit the existing ten-row batch ceiling').toBe(3);
    expect(positiveBatches.every(({ count }) => count === 3), 'small collections need no partial row commit').toBe(true);
    expect(positiveBatches.every(({ busy, stage }) => busy && stage !== 'ready'), 'complete rows do not finish the held exact detail').toBe(true);
    await scanSelect.focus();
    await expect(scanSelect).toBeFocused();
    await expect(scanSelect).toBeEnabled();
    await expect(surface).not.toHaveAttribute('inert', '');
    await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
    await expect(surface.locator('.finding-detail')).toHaveAttribute('aria-busy', 'true');
    await expect(surface, 'a complete collection does not finish the pending selected detail').toHaveAttribute('aria-busy', 'true');

    releaseDetail();
    await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
    await expect(surface).toHaveAttribute('data-findings-committed-count', '3');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface.locator('.finding-workspace')).not.toHaveAttribute('inert', '');
    await expect(surface.locator('.finding-detail')).toHaveAttribute('aria-busy', 'false');
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
    await expect(surface.getByLabel('Code evidence for src/handler.ts', { exact: true })).toBeVisible();
    await expect(surface.locator('.finding-list-item')).toHaveCount(3);
    await expect(surface.locator('.finding-list-item.active')).toContainText('S41-F001');
    await expect(scanSelect).toBeFocused();
    await expect(page.getByText('Loading finding evidence…', { exact: true })).toHaveCount(0);
    expect(detailReads).toEqual([exactDetail]);
  } finally {
    releaseDetail();
    await page.evaluate(() => {
      (window as Window & { __kodesecStopSmallFindingBatches?: () => void }).__kodesecStopSmallFindingBatches?.();
    });
    page.off('request', observeRequest);
    page.off('requestfinished', observeCompletion);
    page.off('requestfailed', observeFailure);
  }
  guards.assertClean();
});

referenceTest('Findings keeps navigation reconciliation busy and reuses only a current revision-bound snapshot', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  const exactDetail = `${origin}/v1/scans/41/findings/1?expected_revision=1&expected_findings_revision=1`;
  const acceptedDetail = page.waitForResponse((response) => response.request().method() === 'GET' && response.url() === exactDetail);
  await openRoute(page, 'Findings');
  const response = await acceptedDetail;
  expect(response.status()).toBe(200);
  expect(await response.json()).toMatchObject({ id: 501, scan_id: 41, scan_finding_number: 1, revision: 1, findings_revision: 1 });
  expect(await response.finished()).toBeNull();
  const surface = page.locator('section[data-route-surface="findings"]');
  const scanSelect = surface.getByLabel('Scan', { exact: true });
  await expect(surface.locator('.finding-list-item.active')).toContainText('S41-F001');
  const retainedArtifact = surface.locator(`a[href="${origin}/v1/artifacts/301/open"]`);
  await expandFindingDisclosure(surface, '.finding-scan-details');
  await expect(retainedArtifact).toHaveCount(1);
  await expect(retainedArtifact).toHaveJSProperty('href', `${origin}/v1/artifacts/301/open`);
  const collectionPaths = ['/v1/scans/41/summary', '/v1/scans/41/findings', '/v1/scans/41/artifacts'];
  const completedCollectionReads = new Map<string, number>();
  const detailReads: string[] = [];
  const pendingIndependentReads = new Set<Request>();
  const observeRequest = (entry: Request) => {
    const url = new URL(entry.url());
    if (url.origin === origin && url.pathname.startsWith('/v1/') && url.pathname !== '/v1/scans') pendingIndependentReads.add(entry);
    if (url.origin === origin && url.pathname === '/v1/scans/41/findings/1') {
      expect(entry.method()).toBe('GET');
      detailReads.push(entry.url());
    }
  };
  const observeCompletion = (entry: Request) => {
    pendingIndependentReads.delete(entry);
    const url = new URL(entry.url());
    if (url.origin === origin && collectionPaths.includes(url.pathname)) {
      completedCollectionReads.set(url.pathname, (completedCollectionReads.get(url.pathname) || 0) + 1);
    }
  };
  const observeFailure = (entry: Request) => { pendingIndependentReads.delete(entry); };
  page.on('requestfailed', observeFailure);
  page.on('request', observeRequest);
  page.on('requestfinished', observeCompletion);
  // Returning with retained evidence still needs the new navigation owner's
  // global scan read. Its independent exact detail must not announce ready first.
  await page.getByRole('navigation').getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(page.locator('main')).toHaveAttribute('data-rendered-view', 'overview');
  await page.waitForLoadState('networkidle');
  let releaseGlobal!: () => void;
  let releaseChangedGlobal = () => {};
  const globalGate = new Promise<void>((resolve) => { releaseGlobal = resolve; });
  let globalHeld = false;
  await page.route(`${origin}/v1/scans?view=history`, async (route) => {
    const response = await route.fetch();
    globalHeld = true;
    await globalGate;
    await route.fulfill({ response });
  }, { times: 1 });
  await page.evaluate(() => {
    const probe = window as Window & {
      __kodesecHeldFindingsReadiness?: Array<{ busy: boolean; scan: string | null }>;
      __kodesecStopHeldFindingsReadiness?: () => void;
    };
    probe.__kodesecHeldFindingsReadiness = [];
    const sample = () => {
      const current = document.querySelector('main > section[data-route-surface="findings"]');
      if (!current) return;
      const state = {
        busy: current.getAttribute('aria-busy') === 'true',
        scan: current.querySelector<HTMLSelectElement>('select[aria-label="Scan"]')?.value ?? null,
      };
      const last = probe.__kodesecHeldFindingsReadiness!.at(-1);
      if (last?.busy === state.busy && last.scan === state.scan) return;
      if (probe.__kodesecHeldFindingsReadiness!.length >= 100) throw new Error('Held Findings readiness observation exceeded its bound.');
      probe.__kodesecHeldFindingsReadiness!.push(state);
    };
    const observer = new MutationObserver(sample);
    observer.observe(document.querySelector('main')!.parentElement!, {
      subtree: true, childList: true, attributes: true, attributeFilter: ['aria-busy'],
    });
    probe.__kodesecStopHeldFindingsReadiness = () => { observer.disconnect(); };
  });
  try {
    const returnedDetail = page.waitForResponse((response) => response.request().method() === 'GET' && response.url() === exactDetail);
    const independentRead = page.waitForResponse((response) => (
      response.request().method() === 'GET' && response.url() === `${origin}/healthz`
    ));
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    await expect.poll(() => globalHeld).toBe(true);
    expect(await (await independentRead).finished()).toBeNull();
    const refreshedDetail = await returnedDetail;
    expect(refreshedDetail.status()).toBe(200);
    expect(await refreshedDetail.json()).toMatchObject({ id: 501, scan_id: 41, scan_finding_number: 1, revision: 1, findings_revision: 1 });
    expect(await refreshedDetail.finished()).toBeNull();
    await expect.poll(() => pendingIndependentReads.size).toBe(0);
    await expect(scanSelect).toHaveValue('41');
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
    await scanSelect.focus();
    await expect(scanSelect).toBeFocused();
    await expect(scanSelect).toBeEnabled();
    await expect(surface).not.toHaveAttribute('inert', '');
    await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    const heldReadiness = await page.evaluate(() => {
      const probe = window as Window & {
        __kodesecHeldFindingsReadiness?: Array<{ busy: boolean; scan: string | null }>;
        __kodesecStopHeldFindingsReadiness?: () => void;
      };
      probe.__kodesecStopHeldFindingsReadiness?.();
      return probe.__kodesecHeldFindingsReadiness || [];
    });
    await testInfo.attach('held-global-findings-readiness.json', {
      body: Buffer.from(JSON.stringify({
        scope: 'Synthetic held global read with retained revision-bound evidence; no performance qualification.',
        globalHeld, heldReadiness, exactDetailReads: detailReads,
        collectionReads: Object.fromEntries(completedCollectionReads),
      }, null, 2)), contentType: 'application/json',
    });
    expect(heldReadiness.length).toBeGreaterThan(0);
    expect(heldReadiness.filter(({ busy }) => !busy), 'retained evidence cannot announce ready while its navigation collection is held').toEqual([]);
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    releaseGlobal();
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
    await expect(surface).toHaveAttribute('data-findings-committed-count', '3');
    await expect(surface.locator('.finding-list-item.active')).toContainText('S41-F001');
    await expect(surface.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
    await expect(surface.getByLabel('Code evidence for src/handler.ts', { exact: true })).toBeVisible();
    await expect(scanSelect).toBeFocused();
    await page.waitForLoadState('networkidle');
    expect(detailReads, 'one exact detail returns independently of the held global read').toEqual([exactDetail]);
    expect(Object.fromEntries(completedCollectionReads), 'unchanged navigation verifies the snapshot without downloading it again').toEqual({
      '/v1/scans/41/summary': 1,
    });
    guards.assertClean();

    // Another client changes a finding while this browser is on another view.
    // The return must replace the old rows and gate rather than reuse them.
    await page.getByRole('navigation').getByRole('button', { name: 'Overview', exact: true }).click();
    await page.waitForLoadState('networkidle');
    const changed = await request.patch('/v1/findings/501/lifecycle', {
      data: { action: 'accepted_risk', reason: 'Reviewed by another fixture client.', expected_revision: 1 },
    });
    expect(changed.status()).toBe(200);
    completedCollectionReads.clear();
    // Synthetic startup-removal overlay at the newly advanced scan revision.
    // The backend transaction/revision contract is tested separately in Python.
    await page.route(`${origin}/v1/scans/41/artifacts`, (route) => route.fulfill({ json: [] }));
    const changedGlobalGate = new Promise<void>((resolve) => { releaseChangedGlobal = resolve; });
    let changedGlobalHeld = false;
    await page.route(`${origin}/v1/scans?view=history`, async (route) => {
      const response = await route.fetch();
      changedGlobalHeld = true;
      await changedGlobalGate;
      await route.fulfill({ response });
    }, { times: 1 });
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    await expect.poll(() => changedGlobalHeld).toBe(true);
    await expect(surface.locator('.finding-detail')).toContainText('accepted risk');
    await expect.poll(() => pendingIndependentReads.size).toBe(0);
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    await expect(retainedArtifact).toHaveCount(1);
    expect(Object.fromEntries(completedCollectionReads), 'exact-detail reconciliation reads rows but has not refreshed artifacts').toEqual({
      '/v1/scans/41/summary': 3, '/v1/scans/41/findings': 1,
    });
    // The finding owner must not promote its partial refresh into a complete
    // snapshot. Navigation still owes an artifact read at the newer revision.
    completedCollectionReads.clear();
    releaseChangedGlobal();
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(retainedArtifact).toHaveCount(0);
    await expandFindingDisclosure(surface, '.finding-scan-details');
    await expect(surface.getByText('No publishable derived artifacts are stored for this scan.', { exact: true })).toBeVisible();
    await expect(surface.locator('.scan-metrics .stat').filter({ hasText: 'Gate' }).locator('strong')).toHaveText('pass');
    await page.waitForLoadState('networkidle');
    expect(Object.fromEntries(completedCollectionReads), 'changed revision requires a complete replacement snapshot').toEqual({
      '/v1/scans/41/summary': 1, '/v1/scans/41/findings': 1, '/v1/scans/41/artifacts': 1,
    });
  } finally {
    releaseGlobal();
    releaseChangedGlobal();
    page.off('request', observeRequest);
    page.off('requestfinished', observeCompletion);
    page.off('requestfailed', observeFailure);
    await page.evaluate(() => {
      const probe = window as Window & {
        __kodesecHeldFindingsReadiness?: unknown;
        __kodesecStopHeldFindingsReadiness?: () => void;
      };
      probe.__kodesecStopHeldFindingsReadiness?.();
      delete probe.__kodesecStopHeldFindingsReadiness;
      delete probe.__kodesecHeldFindingsReadiness;
    });
  }
  // The old exact detail receives one typed conflict before the single bounded
  // reconciliation above. Every other runtime guard remains strict.
  expect(guards.failures.http).toHaveLength(1);
  expect(guards.failures.http[0]).toContain('409');
  expect(guards.failures.http[0]).toContain('/v1/scans/41/findings/1');
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

referenceTest('[WEB-ACT-007] Findings reconciles one legitimate finding revision advance without losing selection', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'finding-revision-advance', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Overview');

  // The fixture advances the revision on its first exact-detail read. Let
  // navigation finish its independent collection refresh before that advance,
  // so this scenario isolates one detail owner's bounded reconciliation.
  // Every request remains covered by the strict guards, including cancellations.
  const isSelectedDetail = (url: string) => new URL(url).pathname === '/v1/scans/41/findings/1';
  const pendingNavigation = new Set<Request>();
  const observeNavigationRequest = (entry: Request) => {
    if (!isSelectedDetail(entry.url())) pendingNavigation.add(entry);
  };
  const observeNavigationCompletion = (entry: Request) => { pendingNavigation.delete(entry); };
  page.on('request', observeNavigationRequest);
  page.on('requestfinished', observeNavigationCompletion);
  page.on('requestfailed', observeNavigationCompletion);
  const detailReads: Array<{ itemRevision: string | null; collectionRevision: string | null; status: number }> = [];
  page.on('response', (response) => {
    if (!isSelectedDetail(response.url())) return;
    const url = new URL(response.url());
    detailReads.push({
      itemRevision: url.searchParams.get('expected_revision'),
      collectionRevision: url.searchParams.get('expected_findings_revision'),
      status: response.status(),
    });
  });
  let releaseDetail!: () => void;
  let detailHeld = false;
  const detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
  await page.route('**/v1/scans/41/findings/1?**', async (route) => {
    detailHeld = true;
    await detailGate;
    await route.fallback();
  }, { times: 1 });
  try {
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    await expect.poll(() => detailHeld).toBe(true);
    await expect.poll(() => pendingNavigation.size).toBe(0);
    await page.evaluate(() => new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()));
    }));
  } finally {
    releaseDetail();
    page.off('request', observeNavigationRequest);
    page.off('requestfinished', observeNavigationCompletion);
    page.off('requestfailed', observeNavigationCompletion);
  }

  await expect(page.getByRole('alert').filter({ hasText: 'Finding detail is unavailable' })).toHaveCount(0);
  await expect(page.locator('.finding-list-item.active')).toContainText('S41-F001');
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F001');
  await expect(page.getByLabel('Code evidence for src/handler.ts')).toBeVisible();
  await expect(page.locator('.advisor-panel')).toContainText('A generated Advisor update advanced this finding while its detail was loading.');
  const counts = await request.get('/__test/requests').then((response) => response.json()) as { findingDetails: number };
  expect(counts.findingDetails).toBe(2);
  expect(detailReads).toEqual([
    { itemRevision: '1', collectionRevision: '1', status: 409 },
    { itemRevision: '2', collectionRevision: '2', status: 200 },
  ]);
  await testInfo.attach('finding-revision-reconciliation-reads.json', {
    body: Buffer.from(JSON.stringify(detailReads, null, 2)), contentType: 'application/json',
  });
  expect(guards.failures.http).toHaveLength(1);
  expect(guards.failures.http[0]).toContain('409');
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

referenceTest('Findings retries a failed same-revision detail only after explicit Refresh', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(30_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  // Retain bounded input evidence when a native foreground run changes
  // selection while this test is deliberately waiting for the ordinary poll.
  await page.addInitScript(() => {
    const inputs: Array<{ type: string; trusted: boolean; finding: string | null; key: string | null }> = [];
    Object.assign(window, { findingRetryInputs: inputs });
    for (const type of ['click', 'keydown']) document.addEventListener(type, (event) => {
      if (inputs.length >= 20) return;
      const target = event.target instanceof Element ? event.target : null;
      const finding = target?.closest('[data-finding-id]')?.getAttribute('data-finding-id') ?? null;
      const key = event instanceof KeyboardEvent && ['Enter', ' ', 'ArrowUp', 'ArrowDown'].includes(event.key)
        ? event.key : null;
      inputs.push({ type, trusted: event.isTrusted, finding, key });
    }, true);
  });
  await openRoute(page, 'Overview');
  const exactDetail = new URL('/v1/scans/41/findings/1?expected_revision=1&expected_findings_revision=1', baseURL).href;
  const detailReads: string[] = [];
  const detailStatuses: number[] = [];
  const pendingNavigation = new Set<Request>();
  const observeRequest = (entry: Request) => {
    if (new URL(entry.url()).pathname !== '/v1/scans/41/findings/1') pendingNavigation.add(entry);
  };
  const observeCompletion = (entry: Request) => { pendingNavigation.delete(entry); };
  page.on('request', observeRequest);
  page.on('requestfinished', observeCompletion);
  page.on('requestfailed', observeCompletion);
  let releaseFailure!: () => void;
  let releaseSuccess!: () => void;
  const failureGate = new Promise<void>((resolve) => { releaseFailure = resolve; });
  const successGate = new Promise<void>((resolve) => { releaseSuccess = resolve; });
  await page.route('**/v1/scans/41/findings/1?**', async (route) => {
    expect(route.request().method()).toBe('GET');
    expect(route.request().url()).toBe(exactDetail);
    detailReads.push(route.request().url());
    expect(detailReads.length, 'one initial read and one explicitly requested retry').toBeLessThanOrEqual(2);
    if (detailReads.length === 1) {
      await failureGate;
      detailStatuses.push(503);
      await route.fulfill({ status: 503, json: { detail: 'Generated finding detail temporarily unavailable.' } });
      return;
    }
    await successGate;
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({ id: 501, scan_id: 41, scan_finding_number: 1, revision: 1, findings_revision: 1 });
    detailStatuses.push(response.status());
    await route.fulfill({ response });
  });
  const surface = page.locator('section[data-route-surface="findings"]');
  const detail = page.locator('.finding-detail[data-finding-id="501"]');
  const selected = page.locator('.finding-list-item', { hasText: 'S41-F001' }).locator('.finding-list-main');
  const alert = detail.getByRole('alert');
  try {
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    await expect.poll(() => detailReads.length).toBe(1);
    await expect.poll(() => pendingNavigation.size).toBe(0);
    await expect(detail).toHaveAttribute('aria-busy', 'true');
    releaseFailure();
    await expect(alert).toContainText('Finding detail is unavailable: Generated finding detail temporarily unavailable.');
    await expect(alert).toBeVisible();
    await expect(page.getByText('Loading finding evidence…', { exact: true })).toHaveCount(0);
    await expect(detail).toHaveAttribute('aria-busy', 'false');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(detail.locator('.advisor-panel')).toHaveCount(0);
    await expect(selected).toHaveAttribute('aria-pressed', 'true');
    await page.waitForLoadState('networkidle');

    // Active scan #39 schedules the ordinary eight-second application poll.
    // A settled, unchanged collection must retain the error without retrying.
    const pollSummary = await page.waitForResponse((response) => {
      const url = new URL(response.url());
      return response.request().method() === 'GET' && url.origin === origin
        && url.pathname === '/v1/scans/41/summary';
    }, { timeout: qualificationMilliseconds(15_000) });
    expect(pollSummary.status()).toBe(200);
    expect(await pollSummary.json()).toMatchObject({ scan: { id: 41 }, revision: 1, findings_revision: 1 });
    await page.waitForLoadState('networkidle');
    expect(detailReads).toEqual([exactDetail]);
    await expect(alert).toContainText('Generated finding detail temporarily unavailable.');
    await expect(detail).toHaveAttribute('aria-busy', 'false');

    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect.poll(() => detailReads.length).toBe(2);
    await expect(detail).toHaveAttribute('aria-busy', 'true');
    await expect(alert).toHaveCount(0);
    await expect(detail.getByRole('button', { name: 'Run Advisor', exact: true })).toBeDisabled();
    await expect(selected).toHaveAttribute('aria-pressed', 'true');
    releaseSuccess();
    await expect(detail).toHaveAttribute('aria-busy', 'false');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(detail.getByText('Generated local review preserves scanner evidence and does not change the gate.', { exact: true })).toBeVisible();
    await expect(detail.getByRole('button', { name: 'Run Advisor', exact: true })).toBeEnabled();
    await expect(selected).toHaveAttribute('aria-pressed', 'true');
    await page.waitForLoadState('networkidle');
    expect(detailReads).toEqual([exactDetail, exactDetail]);
    expect(detailStatuses).toEqual([503, 200]);
    expect(await request.get('/__test/commands').then((response) => response.json())).toEqual([]);
    await testInfo.attach('findings-explicit-detail-retry.json', {
      body: Buffer.from(JSON.stringify({ detailReads, detailStatuses, unchangedPollObserved: true, userRefreshes: 1 })),
      contentType: 'application/json',
    });
    expect(guards.failures.http).toEqual([`503 ${origin}/v1/scans/41/findings/1`]);
    expect(guards.failures.console).toHaveLength(1);
    expect(guards.failures.console[0]).toContain('503');
    expect(guards.failures.page).toEqual([]);
    expect(guards.failures.request).toEqual([]);
    expect(guards.failures.egress).toEqual([]);
    expect(guards.failures.credentialUrl).toEqual([]);
  } finally {
    releaseFailure();
    releaseSuccess();
    page.off('request', observeRequest);
    page.off('requestfinished', observeCompletion);
    page.off('requestfailed', observeCompletion);
    await testInfo.attach('findings-detail-retry-inputs.json', {
      body: Buffer.from(JSON.stringify(await page.evaluate(() => (
        (window as Window & { findingRetryInputs?: unknown }).findingRetryInputs ?? []
      )))),
      contentType: 'application/json',
    });
  }
});

referenceTest('Findings rejects same-identity immutable message or severity replacement', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'finding-immutable-evidence-change', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Overview');

  // As in WEB-ACT-007, finish navigation's independent collection refresh
  // before the first detail read mutates the fixture. This isolates the
  // selected detail owner's immutable-evidence rejection.
  const isSelectedDetail = (url: string) => new URL(url).pathname === '/v1/scans/41/findings/1';
  const pendingNavigation = new Set<Request>();
  const observeNavigationRequest = (entry: Request) => {
    if (!isSelectedDetail(entry.url())) pendingNavigation.add(entry);
  };
  const observeNavigationCompletion = (entry: Request) => { pendingNavigation.delete(entry); };
  page.on('request', observeNavigationRequest);
  page.on('requestfinished', observeNavigationCompletion);
  page.on('requestfailed', observeNavigationCompletion);
  const detailReads: Array<{ itemRevision: string | null; collectionRevision: string | null; status: number }> = [];
  page.on('response', (response) => {
    if (!isSelectedDetail(response.url())) return;
    const url = new URL(response.url());
    detailReads.push({
      itemRevision: url.searchParams.get('expected_revision'),
      collectionRevision: url.searchParams.get('expected_findings_revision'),
      status: response.status(),
    });
  });
  let releaseDetail!: () => void;
  let detailHeld = false;
  const detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
  await page.route('**/v1/scans/41/findings/1?**', async (route) => {
    detailHeld = true;
    await detailGate;
    await route.fallback();
  }, { times: 1 });
  try {
    await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    await expect.poll(() => detailHeld).toBe(true);
    await expect.poll(() => pendingNavigation.size).toBe(0);
    await page.evaluate(() => new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()));
    }));
  } finally {
    releaseDetail();
    page.off('request', observeNavigationRequest);
    page.off('requestfinished', observeNavigationCompletion);
    page.off('requestfailed', observeNavigationCompletion);
  }

  const alert = page.getByRole('alert').filter({ hasText: 'Finding detail is unavailable' });
  await expect(alert).toContainText('different immutable identity or evidence binding');
  await expect(page.locator('section[data-route-surface="findings"]')).not.toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('.advisor-panel')).toHaveCount(0);
  const counts = await request.get('/__test/requests').then((response) => response.json()) as { findingDetails: number };
  expect(counts.findingDetails).toBe(1);
  expect(detailReads).toEqual([{ itemRevision: '1', collectionRevision: '1', status: 409 }]);
  expect(guards.failures.http).toEqual([`409 ${new URL(baseURL).origin}/v1/scans/41/findings/1`]);
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

referenceTest('Findings renders hostile bounded advisor text and exact multiline evidence as inert text', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'advisor-evidence', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const surface = page.locator('section[data-route-surface="findings"]');
  const advisor = surface.locator('.advisor-panel');
  await expect(advisor.getByText('Verdict: Needs review', { exact: true })).toBeVisible();
  await expect(advisor.getByText('Confidence 88%', { exact: true })).toBeVisible();
  await expect(advisor.getByText('Reasoning', { exact: true })).toBeVisible();
  await expect(advisor.getByText('The advisor returned no remediation suggestion.', { exact: true })).toBeVisible();
  await expect(advisor.getByText('Advisory only. This review does not change finding lifecycle or the deterministic gate.', { exact: true })).toBeVisible();
  await expect(advisor.locator('img, script')).toHaveCount(0);
  expect(await page.evaluate(() => Boolean((window as Window & { __advisorXss?: boolean }).__advisorXss))).toBe(false);
  expect((await advisor.locator('.advisor-explanation p').textContent())?.startsWith('<img src=x onerror="globalThis.__advisorXss=true">')).toBe(true);
  expect((await advisor.locator('.advisor-explanation p').textContent())?.length).toBeLessThanOrEqual(4_000);

  const evidence = surface.getByLabel('Code evidence for src/<hostile>&evidence.ts');
  await expect(evidence).toHaveAttribute('data-line-count', '5');
  await expect(evidence).toHaveAttribute('aria-describedby', /.+/);
  const descriptionId = await evidence.getAttribute('aria-describedby');
  if (!descriptionId) throw new Error('Multiline offender description is missing.');
  await expect(page.locator(`[id=${JSON.stringify(descriptionId)}]`)).toHaveText('Offender lines 12 through 14.');
  await expect(evidence.locator('.code-row.offender .code-line-number')).toHaveText('12');
  expect(await evidence.locator('.code-row.offender').evaluate((element) => element.getBoundingClientRect().height)).toBe(66);
  await expect(evidence.locator('script')).toHaveCount(0);
  expect((await evidence.locator('.code-source').textContent())?.includes('<script>not markup</script>')).toBe(true);

  await page.evaluate(() => {
    (window as Window & { __copiedEvidence?: string }).__copiedEvidence = undefined;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          (window as Window & { __copiedEvidence?: string }).__copiedEvidence = value;
        },
      },
    });
  });
  const copy = surface.getByRole('button', { name: 'Copy evidence', exact: true });
  await copy.focus();
  await copy.press('Enter');
  await expect(surface.getByRole('status').filter({ hasText: 'Sanitized code evidence copied.' })).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { __copiedEvidence?: string }).__copiedEvidence)).toBe(
    'const before = "<script>not markup</script>";\nunsafeSink(first);\n\nunsafeSink(last);\n',
  );

  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async () => { throw new Error('denied'); } },
    });
  });
  await copy.click();
  await expect(surface.getByRole('status').filter({ hasText: 'Code evidence could not be copied. Select the text manually.' })).toBeVisible();

  const accessibility = await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact || '')).map((violation) => violation.id)).toEqual([]);
  guards.assertClean();
});

referenceTest('Findings distinguishes advisor failure from preserved scanner evidence and gate state', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'advisor-failure', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const status = page.getByRole('status').filter({ hasText: 'Advisor did not complete · advisor_unavailable' });
  await expect(status).toBeVisible();
  await expect(status).toContainText('Scanner evidence, finding lifecycle, and the deterministic gate are unchanged.');
  await expect(page.getByLabel('Code evidence for src/handler.ts')).toBeVisible();
  await expect(page.locator('.stat').filter({ hasText: 'Gate' }).locator('strong')).toHaveText('fail');
  await expect(page.locator('.stat').filter({ hasText: 'Status' }).locator('strong')).toHaveText('completed');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeEnabled();
  guards.assertClean();
});

referenceTest('Findings exposes partial scanner evidence without presenting an advisor or policy success', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'limited-evidence', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const scanSelect = page.getByLabel('Scan', { exact: true });
  await scanSelect.selectOption('40');
  const status = page.getByRole('status').filter({ hasText: 'Scanner evidence is incomplete' });
  await expect(status).toBeVisible();
  await expect(status).toContainText('This was an explicitly limited scan: 1 of 2 requested scanners ran.');
  await expect(status).toContainText('Omitted scanners: OpenGrep (Reviewed offline rules were unavailable.).');
  await expect(status).toContainText('Its deterministic gate is permanently incomplete.');
  await expect(status).toContainText('No findings or publishable artifacts were preserved for this scan.');
  await expect(status).toContainText('Review omitted scanners in Tools');
  await expect(status).not.toContainText('Review the scanner job');
  await expect(status).not.toContainText('findings are preserved for review');
  await expect(page.locator('.stat').filter({ hasText: 'Gate' }).locator('strong')).toHaveText('incomplete');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeDisabled();
  await expect(page.getByText('No findings are available to display for this scan.', { exact: true })).toHaveCount(1);
  await expect(page.locator('.finding-list').getByText('No findings are available to display for this scan.', { exact: true })).toBeVisible();
  await expect(page.locator('.finding-detail')).toHaveCount(0);
  guards.assertClean();
});

referenceTest('Findings explains bounded scanner failures with readable mobile and enlarged text', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scan-state-edges', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const publicDiagnostic = '<img src=x onerror=alert(1)> [REDACTED] ' + 'x'.repeat(500);
  // Synthetic public-summary data only; no native scanner payload or real source paths.
  await page.route('**/v1/scans**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (!['/v1/scans', '/v1/scans/40', '/v1/scans/40/summary'].includes(path)) {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    const payload = await response.json();
    for (const scan of Array.isArray(payload) ? payload : [payload.scan || payload]) {
      if (scan.id !== 40) continue;
      scan.status = 'partial';
      scan.error = null;
      scan.gate_reasons = ['Required scanner evidence is incomplete; the deterministic policy gate was not passed.'];
      scan.scanner_summary ||= {};
      scan.scanner_summary.tools = [
        { id: 'bearer', name: 'Bearer', enabled: true, status: 'failed', error: 'bearer_analysis_incomplete:aerr_defpstu,file_timeout,memory_limit,unknown,worker_failure' },
        { id: 'grype', name: 'Grype', enabled: true, status: 'unavailable', error: publicDiagnostic },
        { id: 'trivy', name: 'Trivy', enabled: true, status: 'completed', error: 'Completed sentinel must not render.' },
        { id: 'secrets-lite', name: 'Internal Secrets Lite', enabled: false, status: 'failed', error: 'Disabled sentinel must not render.' },
      ];
    }
    await route.fulfill({ response, json: payload });
  });
  await openRoute(page, 'Findings');
  await page.getByLabel('Scan', { exact: true }).selectOption('40');
  const status = page.getByRole('status').filter({ hasText: 'Scanner evidence is incomplete' });
  const bearerFailure = status.locator('span').filter({ hasText: 'Bearer (failed)' });
  await expect(bearerFailure).toHaveCount(1);
  // Canonical subtype u and file category unknown share one readable label;
  // the exact text also retains one explicit findings-withheld explanation.
  await expect(bearerFailure).toHaveText(
    'Bearer (failed): directory admission failed; dependency classification failed; framework classification failed; recovered analysis panic; source analysis failed; detector processing failed; unclassified analysis error; file processing timed out; memory limit reached; scanner worker failed. Bearer findings were not published.',
  );
  await expect(status).toContainText('1 finding and 1 publishable artifact are preserved for review.');
  await expect(status.locator('span').filter({ hasText: 'Grype (unavailable)' })).toHaveText(`Grype (unavailable): ${publicDiagnostic.slice(0, 400)}`);
  await expect(status.locator('img, script')).toHaveCount(0);
  await expect(status).not.toContainText('sentinel');
  await expect(status).not.toContainText('Review the scanner job');
  await expect(status).toContainText('A new scan must finish all required scanners before its gate can pass.');
  await expect(page.locator('.stat').filter({ hasText: 'Gate' }).locator('strong')).toHaveText('incomplete');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeEnabled();

  for (const scale of [1, 2]) {
    if (scale === 2) {
      const mismatches = await page.evaluate(() => {
        const before = Array.from(document.querySelectorAll<HTMLElement>('*'))
          .filter((element) => element instanceof HTMLElement)
          .map((element) => ({ element, size: Number.parseFloat(getComputedStyle(element).fontSize), leading: Number.parseFloat(getComputedStyle(element).lineHeight) }));
        for (const { element, size, leading } of before) {
          element.style.fontSize = `${size * 2}px`;
          if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
        }
        return before.filter(({ element, size }) => Math.abs(Number.parseFloat(getComputedStyle(element).fontSize) - size * 2) > 0.01).length;
      });
      expect(mismatches, 'computed glyph sizes double once without compounding').toBe(0);
      await expect(status.locator('span').first()).toHaveCSS('font-size', '26px');
    }
    for (const width of [390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await status.scrollIntoViewIfNeeded();
      const geometry = await status.evaluate((notice) => ({
        pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        spans: Array.from(notice.querySelectorAll('span')).map((span) => ({
          left: span.getBoundingClientRect().left, right: span.getBoundingClientRect().right,
          clientWidth: span.clientWidth, scrollWidth: span.scrollWidth,
          clientHeight: span.clientHeight, scrollHeight: span.scrollHeight,
        })),
      }));
      expect(geometry.pageOverflow, `${width}px at ${scale}x text has no page overflow`).toBeLessThanOrEqual(1);
      for (const span of geometry.spans) {
        expect(span.left).toBeGreaterThanOrEqual(0);
        expect(span.right).toBeLessThanOrEqual(width);
        expect(span.scrollWidth).toBeLessThanOrEqual(span.clientWidth + 1);
        expect(span.scrollHeight).toBeLessThanOrEqual(span.clientHeight + 1);
      }
      await testInfo.attach(`scanner-failures-${width}-${scale}x.png`, { body: await status.screenshot(), contentType: 'image/png' });
    }
  }
  const accessibility = await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact || '')).map((violation) => violation.id)).toEqual([]);
  guards.assertClean();
});

referenceTest('Findings distinguishes cancelled evidence from analysis that is still changing', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scan-state-edges', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const scanSelect = page.getByLabel('Scan', { exact: true });
  await scanSelect.selectOption('40');
  const cancelled = page.getByRole('status').filter({ hasText: 'Scan was cancelled' });
  await expect(cancelled).toContainText('1 finding and 1 publishable artifact are preserved for review.');
  await expect(cancelled).toContainText('Start a new scan when ready.');
  await expect(page.locator('.finding-context-source .scan-mode-warning')).toBeVisible();
  await expect(page.locator('.finding-context-source .scan-mode-warning')).toHaveText('incremental-diff-fallback-full');
  await expandFindingDisclosure(page, '.finding-scan-details');
  await expect(page.locator('.scan-mode-scope .scan-mode-label')).toHaveText('#40 · incremental_diff → full');
  await expect(page.locator('.scan-mode-scope .scan-mode-warning')).toHaveText('incremental-diff-fallback-full');
  await expect(page.locator('.stat').filter({ hasText: 'Gate' }).locator('strong')).toHaveText('incomplete');
  await expect(page.locator('.finding-detail h2')).toHaveText('S40-F001');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeDisabled();

  await scanSelect.selectOption('38');
  const failed = page.getByRole('status').filter({ hasText: 'Scan execution failed' });
  await expect(failed).toContainText('No findings or publishable artifacts were preserved for this scan.');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeDisabled();

  await scanSelect.selectOption('39');
  const analyzing = page.getByRole('status').filter({ hasText: 'Scan analysis is still in progress' });
  await expect(analyzing).toContainText('Scanner evidence and advisor output may still change.');
  await expect(page.locator('.finding-detail h2')).toHaveText('S39-F001');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeDisabled();
  await expect(page.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true })).toBeDisabled();
  guards.assertClean();
});

referenceTest('Scan History exposes effective scan mode and fail-closed incomplete gates', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scan-state-edges', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Scans');

  const cancelled = page.getByRole('row').filter({ hasText: '#40' });
  await expect(cancelled.locator('.scan-mode-label')).toHaveText('incremental_diff → full');
  await expect(cancelled.locator('.scan-mode-warning')).toHaveText('incremental-diff-fallback-full');
  await expect(cancelled.locator('.pill-incomplete')).toHaveText('incomplete');
  const failed = page.getByRole('row').filter({ hasText: '#38' });
  await expect(failed.locator('.pill-incomplete')).toHaveText('incomplete');
  guards.assertClean();
});

referenceTest('Findings disables advisor actions for suppressed evidence until it is reopened', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const suppressed = page.locator('.finding-list-item', { hasText: 'S41-F003' });
  await suppressed.locator('.finding-list-main').click();
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F003');
  const detailAdvisor = page.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true });
  await expect(detailAdvisor).toBeDisabled();
  await expect(detailAdvisor).toHaveAttribute('aria-describedby', 'finding-advisor-disabled-reason');
  await expect(page.locator('#finding-advisor-disabled-reason')).toHaveText('Reopen this finding before requesting Advisor review.');
  await suppressed.getByRole('checkbox').check();
  await expandFindingDisclosure(page, '.bulk-action-disclosure');
  await expect(page.locator('.bulk-actions').getByRole('button', { name: 'Advisor', exact: true })).toBeDisabled();
  await suppressed.getByRole('checkbox').uncheck();
  const active = page.locator('.finding-list-item', { hasText: 'S41-F001' });
  await active.getByRole('checkbox').check();
  await expect(page.locator('.bulk-actions').getByRole('button', { name: 'Advisor', exact: true })).toBeEnabled();
  guards.assertClean();
});

referenceTest('Findings disables single, bulk, and scan advisor admission while scan evidence is changing', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await page.setViewportSize({ width: 390, height: 844 });
  await request.post('/__test/reset', { data: { profile: 'advisor-running', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  // Narrow review reveals bulk controls only after selection. Keep the
  // disclosure open while clearing that selection to exercise disabled guards.
  const firstSelection = page.locator('.finding-list-item').first().getByRole('checkbox');
  await firstSelection.check();
  await expandFindingDisclosure(page, '.bulk-action-disclosure');
  await firstSelection.uncheck();
  const noSelectionLifecycle = page.locator('.bulk-actions').getByRole('button', { name: 'Non-blocking', exact: true });
  await expect(noSelectionLifecycle).toBeDisabled();
  await expect(noSelectionLifecycle).toHaveAttribute('aria-describedby', 'bulk-lifecycle-disabled-reason');
  await expect(page.locator('#bulk-lifecycle-disabled-reason')).toHaveText('Select one or more findings to use lifecycle actions.');
  const disabledReasonGeometry = await page.locator('.bulk-actions').evaluate((element) => {
    const owner = element.getBoundingClientRect();
    const reason = element.querySelector('.disabled-action-reason')?.getBoundingClientRect();
    if (!reason) throw new Error('Bulk lifecycle disabled reason is missing.');
    return {
      owner: { left: owner.left, right: owner.right, width: owner.width },
      reason: { left: reason.left, right: reason.right, width: reason.width },
      documentClientWidth: document.documentElement.clientWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
    };
  });
  expect(disabledReasonGeometry.documentScrollWidth).toBeLessThanOrEqual(disabledReasonGeometry.documentClientWidth);
  expect(disabledReasonGeometry.reason.left).toBeGreaterThanOrEqual(disabledReasonGeometry.owner.left);
  expect(disabledReasonGeometry.reason.right).toBeLessThanOrEqual(disabledReasonGeometry.owner.right);
  expect(disabledReasonGeometry.reason.width).toBeGreaterThan(disabledReasonGeometry.owner.width * 0.8);

  await page.getByLabel('Scan', { exact: true }).selectOption('39');
  await expect(page.locator('.finding-detail h2')).toHaveText('S39-F001');
  await expect(page.getByRole('button', { name: 'Scan Advisor', exact: true })).toBeDisabled();
  await expect(page.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true })).toBeDisabled();
  await page.locator('.finding-list-item', { hasText: 'S39-F001' }).getByRole('checkbox').check();
  await expandFindingDisclosure(page, '.bulk-action-disclosure');
  await expect(page.locator('.bulk-actions').getByRole('button', { name: 'Advisor', exact: true })).toBeDisabled();
  guards.assertClean();
});

referenceTest('Findings keeps evidence steady while action guidance refreshes at narrow and enlarged widths', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let updateArmed = false;
  let heldReads = 0;
  let globalRefreshSettled = false;
  let releaseDetail!: () => void;
  let currentScanId = 41;
  let currentNumber = 1;
  let currentFindingId = '501';
  let detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
  await page.route('**/v1/scans/*/summary', async (route) => {
    const response = await route.fetch();
    const summary = await response.json();
    const advancing = updateArmed && new URL(route.request().url()).pathname.split('/')[3] === String(currentScanId);
    await route.fulfill({ response, json: advancing
      ? { ...summary, revision: summary.revision + 1, findings_revision: summary.findings_revision + 1 }
      : summary });
  });
  await page.route('**/v1/scans/*/findings?*', async (route) => {
    const url = new URL(route.request().url());
    const advancing = updateArmed && url.pathname.split('/')[3] === String(currentScanId);
    url.searchParams.set('expected_revision', '1');
    const response = await route.fetch({ url: url.toString() });
    const collection = await response.json();
    await route.fulfill({ response, json: advancing ? {
      ...collection, revision: collection.revision + 1,
      items: collection.items.map((finding: { revision: number }) => ({ ...finding, revision: finding.revision + 1 })),
    } : collection });
  });
  await page.route(/\/v1\/scans\/(?:41|39)\/findings\/(?:1|3)(?:\?|$)/u, async (route) => {
    const url = new URL(route.request().url());
    const advancing = updateArmed && url.pathname.split('/')[3] === String(currentScanId)
      && url.pathname.split('/')[5] === String(currentNumber);
    url.searchParams.set('expected_revision', '1');
    url.searchParams.set('expected_findings_revision', '1');
    const response = await route.fetch({ url: url.toString() });
    const finding = await response.json();
    if (advancing) { heldReads += 1; await detailGate; }
    await route.fulfill({ response, json: advancing
      ? { ...finding, revision: finding.revision + 1, findings_revision: finding.findings_revision + 1 }
      : finding });
  });
  await page.route('**/v1/scans?view=history', async (route) => {
    const response = await route.fetch();
    const hold = updateArmed && currentScanId === 39;
    if (hold) { heldReads += 1; await detailGate; }
    await route.fulfill({ response });
    if (hold) globalRefreshSettled = true;
  });
  await openRoute(page, 'Findings');
  const originalFontSize = await page.evaluate(() => Number.parseFloat(getComputedStyle(document.documentElement).fontSize));
  const variants = [{ width: 1440, enlarged: false }, { width: 390, enlarged: false }, { width: 320, enlarged: false },
    { width: 390, enlarged: true }, { width: 320, enlarged: true }];
  const sample = async (phase: string) => {
    const rows = [];
    for (const { width, enlarged } of variants) {
      await page.setViewportSize({ width, height: width === 1440 ? 900 : 844 });
      await page.evaluate((fontSize) => { document.documentElement.style.fontSize = `${fontSize}px`; }, originalFontSize * (enlarged ? 2 : 1));
      await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      const detail = page.locator('.finding-detail');
      await expect(detail).toHaveAttribute('data-finding-id', currentFindingId);
      const geometry = await detail.evaluate((element) => {
        const actions = element.querySelector('.finding-primary-actions')!.getBoundingClientRect();
        const evidence = element.querySelector('.finding-evidence')!.getBoundingClientRect();
        const reservation = element.querySelector('.finding-advisor-guidance-reserve')!;
        return {
          evidenceOffset: evidence.top - actions.top,
          actionsHeight: actions.height,
          actionsClientWidth: (element.querySelector('.finding-primary-actions') as HTMLElement).clientWidth,
          actionsScrollWidth: (element.querySelector('.finding-primary-actions') as HTMLElement).scrollWidth,
          reservationHidden: reservation.getAttribute('aria-hidden') === 'true' && getComputedStyle(reservation).visibility === 'hidden',
          reservationFocusable: reservation.matches('a, button, input, select, textarea, [tabindex]'),
        };
      });
      expect(geometry.actionsScrollWidth).toBeLessThanOrEqual(geometry.actionsClientWidth);
      expect(geometry.reservationHidden).toBe(true);
      expect(geometry.reservationFocusable).toBe(false);
      rows.push({ width, enlarged, ...geometry });
      if (phase === 'before' || phase === 'held' || phase === 'settled') {
        await detail.scrollIntoViewIfNeeded();
        const name = `finding-guidance-${currentScanId}-${currentNumber}-${phase}-${width}-${enlarged ? 'text-200' : 'normal'}.png`;
        const screenshotPath = testInfo.outputPath(name);
        await page.screenshot({ path: screenshotPath });
        await testInfo.attach(name, { path: screenshotPath, contentType: 'image/png' });
      }
    }
    return rows;
  };
  try {
    for (const [scanId, number, reason] of [[41, 1, 'Updating finding…'],
      [41, 3, 'Reopen this finding before requesting Advisor review.'],
      [39, 1, 'Advisor review requires a terminal scan with persisted findings.']] as const) {
      updateArmed = false;
      currentScanId = scanId;
      currentNumber = number;
      heldReads = 0;
      globalRefreshSettled = false;
      detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
      await request.post('/__test/reset', { data: { profile: scanId === 39 ? 'advisor-running' : 'fresh', generation: 1 } });
      if (scanId === 39) {
        // Active scans intentionally skip initial and polling detail hydration.
        // Reuse the maintained explicit selector to load its current findings;
        // hold a real global poll below rather than invent a detail poll.
        await openRoute(page, 'Findings');
        await page.getByLabel('Scan', { exact: true }).selectOption('39');
      } else await page.goto(`/?view=findings&scan=${scanId}&finding=${number}`);
      const detail = page.locator('.finding-detail');
      await expect(detail.locator('h2')).toHaveText(`S${scanId}-F${String(number).padStart(3, '0')}`);
      await expect(detail).toHaveAttribute('aria-busy', 'false');
      currentFindingId = (await detail.getAttribute('data-finding-id'))!;
      await page.evaluate(() => document.fonts.ready.then(() => undefined));
      const before = await sample('before');
      updateArmed = true;
      await expect.poll(() => heldReads, { timeout: qualificationMilliseconds(15_000) }).toBe(1);
      await expect(detail).toHaveAttribute('aria-busy', scanId === 39 ? 'false' : 'true');
      await expect(page.locator('#finding-advisor-disabled-reason')).toBeVisible();
      const advisor = detail.getByRole('button', { name: 'Run Advisor', exact: true });
      await expect(advisor).toBeDisabled();
      await expect(advisor).toHaveAccessibleDescription(reason);
      await expect(page.locator('.finding-primary-actions > .source-open-status')).toBeVisible();
      if (scanId === 41 && number === 3) {
        const lifecycleReservation = detail.locator('.finding-layout-reserve');
        await expect(lifecycleReservation).toHaveAttribute('aria-hidden', 'true');
        await expect(lifecycleReservation).toHaveText('Lifecycle reason: Generated false-positive fixture.');
        await expect(lifecycleReservation).not.toBeVisible();
        expect(await lifecycleReservation.evaluate((element) => element.matches('a, button, input, select, textarea, [tabindex]'))).toBe(false);
      }
      const held = await sample('held');
      releaseDetail();
      if (scanId === 39) await expect.poll(() => globalRefreshSettled).toBe(true);
      await expect(detail).toHaveAttribute('aria-busy', 'false');
      await expect(detail.locator('.finding-layout-reserve')).toHaveCount(0);
      const settled = await sample('settled');
      await testInfo.attach(`finding-guidance-${scanId}-${number}-revision-geometry.json`, {
        body: Buffer.from(JSON.stringify({ scope: scanId === 39
          ? 'Held actual global poll for active-scan HTTP fixture; no detail poll or backend lifecycle qualification.'
          : 'Held detail poll HTTP fixture; not backend lifecycle or performance qualification.', before, held, settled })),
        contentType: 'application/json',
      });
      for (let index = 0; index < before.length; index += 1) {
        expect(held[index].evidenceOffset).toBe(before[index].evidenceOffset);
        expect(settled[index].evidenceOffset).toBe(before[index].evidenceOffset);
        expect(held[index].actionsHeight).toBe(before[index].actionsHeight);
        expect(settled[index].actionsHeight).toBe(before[index].actionsHeight);
      }
    }
    guards.assertClean();
  } finally { releaseDetail(); }
});

referenceTest('Findings handles empty snippets and offender ranges outside captured context', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'evidence-edges', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const outOfWindow = page.getByLabel('Code evidence for src/handler.ts');
  await expect(outOfWindow).toHaveAttribute('data-line-count', '2');
  await expect(outOfWindow.locator('.code-row.offender')).toHaveCount(0);
  const descriptionId = await outOfWindow.getAttribute('aria-describedby');
  if (!descriptionId) throw new Error('Out-of-window offender description is missing.');
  await expect(page.locator(`[id=${JSON.stringify(descriptionId)}]`)).toHaveText('Offender line 900.');

  await page.locator('.finding-list-item', { hasText: 'S41-F002' }).locator('.finding-list-main').click();
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F002');
  await expect(page.locator('.finding-detail').getByText('No source snippet was captured. The scanner message and location remain available.', { exact: true })).toBeVisible();
  const copyEvidence = page.locator('.finding-detail').getByRole('button', { name: 'Copy evidence', exact: true });
  await expect(copyEvidence).toBeDisabled();
  await expect(copyEvidence).toHaveAttribute('aria-describedby', 'finding-copy-evidence-disabled-reason');
  await expect(page.locator('#finding-copy-evidence-disabled-reason')).toHaveText('No code evidence is available to copy.');
  guards.assertClean();
});

referenceTest('Findings loads 10,005 keyset findings, focuses a non-boundary anchor, and keeps the visible DOM bounded', async ({ browser, page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'large-findings', generation: 1 } });

  type FindingListItem = { id: number; scan_finding_number: number; file_path: string } & Record<string, unknown>;
  type FindingPage = {
    items: FindingListItem[];
    total: number;
    truncated: boolean;
    next_cursor: string | null;
    revision: number;
  };
  const firstResponse = await request.get('/v1/scans/41/findings?limit=200');
  expect(firstResponse.status()).toBe(200);
  const firstPage = await firstResponse.json() as FindingPage;
  expect(firstPage).toMatchObject({ total: 10_005, truncated: true, revision: 1 });
  expect(firstPage.items).toHaveLength(200);
  expect(firstPage.next_cursor).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(firstPage.next_cursor).not.toMatch(/^\d+$/);
  const listItemKeys = new Set(Object.keys(firstPage.items[0]));
  expect([
    'code_snippet',
    'metadata_json',
    'ai_verdict',
    'ai_confidence',
    'ai_reasoning',
    'ai_fix',
    'suppression_reason',
    'gate_exempt_reason',
    'lifecycle_reason',
  ].every((field) => !listItemKeys.has(field))).toBe(true);

  const filteredResponse = await request.get('/v1/scans/41/findings?limit=2&file_path=src%2Fgenerated%2Fbatch-1.ts');
  const filteredPage = await filteredResponse.json() as FindingPage;
  expect(filteredPage.total).toBe(100);
  expect(Buffer.from(filteredPage.next_cursor || '', 'base64url').toString('ascii')).not.toContain('src/generated/batch-1.ts');
  const mismatchedCursor = await request.get(`/v1/scans/41/findings?limit=2&cursor=${filteredPage.next_cursor}`);
  expect(mismatchedCursor.status()).toBe(400);
  expect((await mismatchedCursor.json()).detail.code).toBe('cursor_invalid');

  const seenIds = new Set<number>();
  const seenNumbers = new Set<number>();
  let currentPage = firstPage;
  for (;;) {
    for (const finding of currentPage.items) {
      expect(seenIds.has(finding.id), `duplicate database finding ID ${finding.id}`).toBe(false);
      expect(seenNumbers.has(finding.scan_finding_number), `duplicate scan-local finding ${finding.scan_finding_number}`).toBe(false);
      seenIds.add(finding.id);
      seenNumbers.add(finding.scan_finding_number);
    }
    if (!currentPage.next_cursor) break;
    const response = await request.get(`/v1/scans/41/findings?limit=200&cursor=${currentPage.next_cursor}`);
    expect(response.status()).toBe(200);
    currentPage = await response.json() as FindingPage;
    expect(currentPage.total).toBe(10_005);
    expect(currentPage.revision).toBe(1);
  }
  expect(seenIds.size).toBe(10_005);
  expect(seenNumbers.size).toBe(10_005);
  expect(Math.min(...seenNumbers)).toBe(1);
  expect(Math.max(...seenNumbers)).toBe(10_005);

  const nonBoundaryAnchorResponse = await request.get('/v1/scans/41/findings?limit=200&anchor_scan_finding_number=250');
  const nonBoundaryAnchorPage = await nonBoundaryAnchorResponse.json() as FindingPage;
  expect(nonBoundaryAnchorResponse.status()).toBe(200);
  expect(nonBoundaryAnchorPage.items[0].scan_finding_number).toBe(201);
  expect(nonBoundaryAnchorPage.items.at(-1)?.scan_finding_number).toBe(400);
  expect(nonBoundaryAnchorPage.items.some((finding) => finding.scan_finding_number === 250)).toBe(true);

  const anchoredResponse = await request.get('/v1/scans/41/findings?limit=200&anchor_scan_finding_number=10000');
  const anchoredPage = await anchoredResponse.json() as FindingPage;
  expect(anchoredPage.items[0].scan_finding_number).toBe(9_801);
  expect(anchoredPage.items.at(-1)?.scan_finding_number).toBe(10_000);
  const terminalResponse = await request.get(`/v1/scans/41/findings?limit=200&cursor=${anchoredPage.next_cursor}`);
  const terminalPage = await terminalResponse.json() as FindingPage;
  expect(terminalPage.items.map((finding) => finding.scan_finding_number)).toEqual([10_001, 10_002, 10_003, 10_004, 10_005]);
  expect(terminalPage).toMatchObject({ total: 10_005, truncated: false, next_cursor: null, revision: 1 });

  // Rebuild the same deterministic profile so request accounting below covers
  // only the browser's revision-fenced snapshot and on-demand detail work.
  await request.post('/__test/reset', { data: { profile: 'large-findings', generation: 1 } });
  await installQualityObservers(page);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const coldLoadStarted = performance.now();
  await page.goto('/?view=findings&scan=41&finding=250');

  const surface = page.locator('section[data-route-surface="findings"]');
  await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  const coldLoadToReadyMs = performance.now() - coldLoadStarted;
  await expect(surface.locator('.list-head strong')).toHaveText('10005 findings');
  await expect(surface.locator('.finding-list-track')).toHaveAttribute('aria-label', 'Findings in the current page');
  expect(await surface.locator('.finding-list-item').count(), 'bounded rendered 25-row page').toBe(25);
  await expect(surface.locator('.finding-list .pager span')).toHaveText('10 / 401');
  const target = surface.locator('.finding-list-item', { hasText: 'S41-F250' });
  await expect(target).toHaveClass(/active/);
  await expect(target).toHaveAttribute('aria-posinset', '25');
  await expect(target).toHaveAttribute('aria-setsize', '25');
  await expect(target.locator('.finding-list-main')).toBeFocused();
  await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F250');
  await expect(surface.getByLabel('Code evidence for src/generated/batch-3.ts', { exact: true })).toBeVisible();
  const requestCounts = await (await request.get('/__test/requests')).json() as {
    findings: number;
    findingDetails: number;
    scanSummaries: number;
    artifacts: number;
  };
  expect(requestCounts).toMatchObject({
    findings: 52,
    findingDetails: 1,
    scanSummaries: 2,
    artifacts: 1,
  });

  const coldLoadQuality = await qualitySnapshot(page);
  assertRequiredQualityObservers(coldLoadQuality);
  expect(coldLoadQuality.domCurrent, 'large-result cold-load current DOM bound').toBeLessThanOrEqual(2_500);
  expect(coldLoadQuality.domBoundaryPeak, 'large-result cold-load peak DOM bound').toBeLessThanOrEqual(2_750);

  // Cold startup includes bundle parsing/JIT and hydration of the complete
  // revision-fenced snapshot. Preserve that functional and bounded-DOM
  // evidence above, then measure the operator interaction in its own window so
  // cold runtime work cannot be misreported as a visible-page algorithm stall.
  // Reveal the same controls before the measured selection, preserving its original scope and budget.
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  await resetQualityWindow(page);
  const selectionStarted = performance.now();
  await surface.getByRole('button', { name: 'Select visible', exact: true }).click();
  await expect(surface.locator('.bulk-actions strong')).toHaveText('25 selected');
  await expect(surface.locator('.finding-list-item.selected')).toHaveCount(await surface.locator('.finding-list-item').count());
  await expect(surface.locator('.bulk-actions').getByRole('button', { name: 'Advisor', exact: true })).toBeEnabled();
  const selectVisibleToReadyMs = performance.now() - selectionStarted;
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.setTimeout(() => {
      window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()));
    }, 0);
  }));

  const interactionQuality = await qualitySnapshot(page);
  await testInfo.attach('large-findings-quality.json', {
    body: Buffer.from(JSON.stringify({
      scope: 'synthetic rendered Findings collection; not scanner throughput or live product acceptance',
      performanceBudgetMode: qualificationPerformanceBudgetMode,
      fixture: {
        profile: 'large-findings', generation: 1, scanId: 41,
        findingsTotal: seenIds.size, apiPageLimit: 200,
        renderedRows: await surface.locator('.finding-list-item').count(),
        visiblePageSize: 25, visiblePageCount: 401, anchor: 250,
      },
      environment: {
        platform: process.platform, architecture: process.arch, node: process.version,
        osRelease: release(), cpu: cpus()[0]?.model ?? null,
        availableCpus: availableParallelism(), totalMemoryBytes: totalmem(),
        browser: browser.browserType().name(), browserVersion: browser.version(),
        headed: testInfo.project.use.headless === false, viewport: page.viewportSize(),
      },
      observations: {
        coldLoadToReadyMs, selectVisibleToReadyMs,
        timingBasis: 'Controller monotonic wall time through ready-state assertions, including browser transport and actionability; one sample, not renderer-only latency or a percentile.',
        memoryBasis: 'No process RSS, peak memory or JavaScript heap measurement in this scenario.',
      },
      requests: requestCounts,
      coldLoad: coldLoadQuality,
      interaction: interactionQuality,
    }, null, 2)),
    contentType: 'application/json',
  });
  assertRequiredQualityObservers(interactionQuality);
  expect(interactionQuality.domCurrent, 'large-result interaction current DOM bound').toBeLessThanOrEqual(2_500);
  expect(interactionQuality.domBoundaryPeak, 'large-result interaction peak DOM bound').toBeLessThanOrEqual(2_750);
  if (qualificationPerformanceBudgetsAreBlocking) {
    expect(
      interactionQuality.longTasks.filter(({ duration }) => duration > qualificationMilliseconds(50)),
      'large-result interaction long tasks',
    ).toEqual([]);
  }
  guards.assertClean();
});

referenceTest('[WEB-FINDINGS-REFRESH-001] unchanged refresh retains all pages and the selected finding beyond page one', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'paginated-findings', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=findings&scan=41&finding=250');
  const surface = page.locator('section[data-route-surface="findings"]');
  const assertCompleteSelection = async (visiblePage = 10) => {
    await expect(surface.locator('.list-head strong')).toHaveText('460 findings');
    await expect(surface.locator('.finding-list .pager span')).toHaveText(`${visiblePage} / 19`);
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F250');
    if (visiblePage === 10) {
      await expect(surface.locator('.finding-list-item', { hasText: 'S41-F250' })).toHaveClass(/active/);
    }
    expect(new URL(page.url()).searchParams.get('finding')).toBe('250');
  };
  await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await assertCompleteSelection();

  // Hold the second API page at a real response boundary. The first-page
  // preview must not replace an already committed collection or its selection.
  let releaseContinuation!: () => void;
  let reportContinuationHeld!: () => void;
  const continuationReleased = new Promise<void>((resolve) => { releaseContinuation = resolve; });
  const continuationHeld = new Promise<void>((resolve) => { reportContinuationHeld = resolve; });
  let held = false;
  await page.route('**/v1/scans/41/findings?*', async (route) => {
    const response = await route.fetch();
    const body = await response.json() as { items: Array<{ scan_finding_number: number }> };
    if (!held && (body.items[0]?.scan_finding_number ?? 0) > 200) {
      held = true;
      reportContinuationHeld();
      await continuationReleased;
    }
    await route.fulfill({ response });
  });
  try {
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await continuationHeld;
    await assertCompleteSelection();
  } finally {
    releaseContinuation();
  }
  await page.waitForLoadState('networkidle');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await assertCompleteSelection();

  for (const trigger of ['window-focus', 'navigation'] as const) {
    const summaryResponse = page.waitForResponse((response) => (
      new URL(response.url()).pathname === '/v1/scans/41/summary'
    ));
    if (trigger === 'window-focus') {
      // Controlled regression for returning from VS Code; the main desktop
      // acceptance separately proves the actual application-switch action.
      await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    } else {
      await page.getByRole('navigation').getByRole('button', { name: 'Overview', exact: true }).click();
      await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
    }
    await summaryResponse;
    await page.waitForLoadState('networkidle');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    // Route remount currently resets view-local pagination to page one, but
    // must preserve the complete collection, detail selection and exact URL.
    await assertCompleteSelection(trigger === 'navigation' ? 1 : 10);
  }
  guards.assertClean();
});

referenceTest('[WEB-FINDINGS-REFRESH-002] navigation owns missing details and visibility preserves a newer scan selection', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  await openRoute(page, 'Scans');

  let releaseCollection!: () => void;
  let collectionGate = new Promise<void>((resolve) => { releaseCollection = resolve; });
  let holdNextCollection = true;
  let heldCollections = 0;
  let collectionReleased = false;
  let releaseFirstSummary!: () => void;
  const firstSummaryGate = new Promise<void>((resolve) => { releaseFirstSummary = resolve; });
  let summary40Reads = 0;
  let overlappedSummary40Reads = 0;
  const reads: string[] = [];
  page.on('request', (browserRequest) => {
    const url = new URL(browserRequest.url());
    if (url.origin === origin && browserRequest.method() === 'GET'
      && /^\/v1\/scans\/(40|41)\/(summary|findings|artifacts)(\/|$)/u.test(url.pathname)) {
      reads.push(`${url.pathname}${url.search}`);
    }
  });
  await page.route(`${origin}/v1/scans?view=history`, async (route) => {
    if (!holdNextCollection) return route.fallback();
    holdNextCollection = false;
    const gate = collectionGate;
    heldCollections += 1;
    const response = await route.fetch();
    await gate;
    await route.fulfill({ response });
  });
  await page.route(`${origin}/v1/scans/40/summary`, async (route) => {
    summary40Reads += 1;
    if (!collectionReleased) overlappedSummary40Reads += 1;
    if (summary40Reads !== 1) return route.fallback();
    const response = await route.fetch();
    await firstSummaryGate;
    await route.fulfill({ response });
  });
  const surface = page.locator('section[data-route-surface="findings"]');
  try {
    const independentRead = page.waitForResponse((response) => (
      response.request().method() === 'GET' && response.url() === `${origin}/healthz`
    ));
    const row = page.getByLabel('Open findings for scan #40', { exact: true });
    await row.focus();
    await expect(row).toBeFocused();
    await page.keyboard.press(' ');
    await expect.poll(() => heldCollections).toBe(1);
    expect(await (await independentRead).finished()).toBeNull();
    await expect(page.getByLabel('Scan', { exact: true })).toHaveValue('40');
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    // Let the existing navigation effects run while their collection remains held.
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    expect(reads.filter((path) => path.startsWith('/v1/scans/40/findings')
      || path === '/v1/scans/40/artifacts'), 'history must settle before missing evidence is fetched').toEqual([]);
    collectionReleased = true;
    releaseCollection();
    await expect.poll(() => summary40Reads).toBeGreaterThanOrEqual(1);
    // The first detail summary remains held through collection reconciliation.
    // Before the fix, the competing refresh aborts it and starts another read.
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    releaseFirstSummary();
    await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await page.waitForLoadState('networkidle');
    await testInfo.attach('navigation-detail-owner.json', {
      body: Buffer.from(JSON.stringify({
        scope: 'Synthetic held-response ownership regression; not live scanner or performance acceptance.',
        heldCollections, overlappedSummary40Reads, summary40Reads, reads,
        requestFailures: guards.failures.request,
      }, null, 2)), contentType: 'application/json',
    });
    expect(overlappedSummary40Reads, 'one exact summary overlaps the history read').toBe(1);
    expect(summary40Reads, 'one revision-fenced summary/list/summary snapshot').toBe(2);
    expect(reads.filter((path) => path === '/v1/scans/40/findings?limit=200')).toHaveLength(1);
    expect(reads.filter((path) => path === '/v1/scans/40/artifacts')).toHaveLength(1);
    await expect(surface.locator('.finding-list-item')).toHaveCount(0);
    guards.assertClean();

    // A same-view selection made during a visibility refresh owns its own read;
    // the older collection must not cancel it, strand it, or restore scan40.
    collectionGate = new Promise<void>((resolve) => { releaseCollection = resolve; });
    holdNextCollection = true;
    const visibilityCollection = page.waitForResponse((response) => (
      response.request().method() === 'GET' && response.url() === `${origin}/v1/scans?view=history`
    ));
    const selectedDetail = page.waitForResponse((response) => (
      response.request().method() === 'GET'
      && response.url() === `${origin}/v1/scans/41/findings/1?expected_revision=1&expected_findings_revision=1`
    ));
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect.poll(() => heldCollections).toBe(2);
    await page.getByLabel('Scan', { exact: true }).selectOption('41');
    const detail = await selectedDetail;
    expect(detail.status()).toBe(200);
    expect(await detail.json()).toMatchObject({
      id: 501, scan_id: 41, scan_finding_number: 1, revision: 1, findings_revision: 1,
    });
    expect(await detail.finished()).toBeNull();
    await expect(surface.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
    releaseCollection();
    expect(await (await visibilityCollection).finished()).toBeNull();
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    await expect(page.getByLabel('Scan', { exact: true })).toHaveValue('41');
    await expect(surface.locator('.finding-detail')).toHaveAttribute('aria-busy', 'false');
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
    // Selecting a scan requests its default finding; only an explicit finding
    // selection or a stale deep-link fallback adds the scan-local ordinal.
    expect(new URL(page.url()).searchParams.toString()).toBe('view=findings&scan=41');
    expect(reads.filter((path) => path === '/v1/scans/41/summary')).toHaveLength(2);
    expect(reads.filter((path) => path === '/v1/scans/41/findings?limit=200')).toHaveLength(1);
    expect(reads.filter((path) => path === '/v1/scans/41/artifacts')).toHaveLength(1);
    guards.assertClean();
  } finally {
    releaseCollection();
    releaseFirstSummary();
  }
});

referenceTest('finding queries and mutations enforce scan, reason, revision, and atomic bulk boundaries', async ({ request }, testInfo) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });

  const exactScan = await request.get('/v1/scans/41');
  expect(exactScan.status()).toBe(200);
  expect(await exactScan.json()).toMatchObject({ id: 41, revision: 1, findings_revision: 1, gate_decision: 'fail' });
  const initialSummary = await request.get('/v1/scans/41/summary');
  expect(initialSummary.status()).toBe(200);
  expect(await initialSummary.json()).toMatchObject({
    scan: { id: 41, gate_decision: 'fail' },
    findings: {
      total: 3,
      active: 2,
      suppressed: 1,
      gate_exempt: 1,
      severity_counts: { high: 1, medium: 1 },
      scanner_counts: { opengrep: 1, checkov: 1 },
    },
    revision: 1,
    findings_revision: 1,
  });
  for (const path of ['/v1/scans/999999', '/v1/scans/999999/summary', '/v1/scans/999999/findings', '/v1/scans/999999/findings/1?expected_revision=1&expected_findings_revision=1']) {
    expect((await request.get(path)).status(), path).toBe(404);
  }

  const firstPageResponse = await request.get('/v1/scans/41/findings?limit=2');
  const firstPage = await firstPageResponse.json() as { next_cursor: string; items: Array<Record<string, unknown>> };
  expect(firstPage.next_cursor).toBeTruthy();
  expect(['code_snippet', 'metadata_json', 'ai_verdict', 'ai_reasoning', 'ai_fix', 'lifecycle_reason']
    .every((field) => !(field in firstPage.items[0]))).toBe(true);
  const unfencedDetail = await request.get('/v1/scans/41/findings/1');
  expect(unfencedDetail.status()).toBe(422);
  expect((await unfencedDetail.json()).detail).toMatchObject({ code: 'invalid_revision_fence' });

  const missingReason = await request.patch('/v1/findings/501/lifecycle', {
    data: { action: 'accepted_risk', expected_revision: 1 },
  });
  expect(missingReason.status()).toBe(422);
  const unchangedFirst = await request.get('/v1/scans/41/findings/1?expected_revision=1&expected_findings_revision=1');
  expect(unchangedFirst.status()).toBe(200);
  expect(await unchangedFirst.json()).toMatchObject({ revision: 1, findings_revision: 1, lifecycle_status: 'open' });

  const acceptedRisk = await request.patch('/v1/findings/501/lifecycle', {
    data: { action: 'accepted_risk', reason: 'Reviewed through the deterministic fixture.', expected_revision: 1 },
  });
  expect(acceptedRisk.status()).toBe(200);
  expect(await acceptedRisk.json()).toMatchObject({
    revision: 2,
    lifecycle_status: 'accepted_risk',
    lifecycle_reason: 'Reviewed through the deterministic fixture.',
    gate_exempt: true,
    gate_effect: 'non_blocking',
  });
  expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({ revision: 2, findings_revision: 2, gate_decision: 'pass' });
  expect(await (await request.get('/v1/scans/41/summary')).json()).toMatchObject({
    scan: { gate_decision: 'pass' },
    findings: { total: 3, active: 2, suppressed: 1, gate_exempt: 2 },
    revision: 2,
    findings_revision: 2,
  });

  const staleCursor = await request.get(`/v1/scans/41/findings?limit=2&cursor=${firstPage.next_cursor}`);
  expect(staleCursor.status()).toBe(409);
  expect((await staleCursor.json()).detail).toMatchObject({ code: 'cursor_stale', revision: 2 });
  const staleSingle = await request.patch('/v1/findings/501/lifecycle', {
    data: { action: 'open', expected_revision: 1 },
  });
  expect(staleSingle.status()).toBe(409);
  expect((await staleSingle.json()).detail).toMatchObject({ code: 'revision_conflict', revision: 2 });

  const staleBulk = await request.post('/v1/findings/bulk', {
    data: {
      action: 'needs_review',
      finding_ids: [501, 502],
      expected_revisions: { 501: 1, 502: 1 },
    },
  });
  expect(staleBulk.status()).toBe(409);
  expect((await staleBulk.json()).detail).toMatchObject({ code: 'revision_conflict', revisions: { 501: 2 } });
  const unchangedSecond = await request.get('/v1/scans/41/findings/2?expected_revision=1&expected_findings_revision=2');
  expect(unchangedSecond.status()).toBe(200);
  expect(await unchangedSecond.json()).toMatchObject({ revision: 1, findings_revision: 2, lifecycle_status: 'gate_exempt' });
  expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({ revision: 2, findings_revision: 2, gate_decision: 'pass' });

  const updatedBulk = await request.post('/v1/findings/bulk', {
    data: {
      action: 'needs_review',
      finding_ids: [501, 502],
      expected_revisions: { 501: 2, 502: 1 },
    },
  });
  expect(updatedBulk.status()).toBe(200);
  expect(await updatedBulk.json()).toMatchObject({ updated: 2, deleted: 0, scan_ids: [41] });
  expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({ revision: 3, findings_revision: 3, gate_decision: 'fail' });

  const deletedBulk = await request.post('/v1/findings/bulk', {
    data: {
      action: 'delete',
      finding_ids: [501, 502],
      expected_revisions: { 501: 3, 502: 2 },
    },
  });
  expect(deletedBulk.status()).toBe(200);
  expect(await deletedBulk.json()).toMatchObject({ updated: 0, deleted: 2, scan_ids: [41] });
  expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({
    revision: 4,
    findings_revision: 4,
    gate_decision: 'pass',
    scanner_summary: { findings_total: 0, ignored_count: 1, gate_exempt_count: 0 },
  });
  expect(await (await request.get('/v1/scans/41/summary')).json()).toMatchObject({
    scan: { gate_decision: 'pass' },
    findings: { total: 1, active: 0, suppressed: 1, gate_exempt: 0 },
    revision: 4,
    findings_revision: 4,
  });
});

referenceTest('Findings keeps the authoritative gate unchanged until a lifecycle revision is confirmed', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let releaseMutation!: () => void;
  const mutationGate = new Promise<void>((resolve) => { releaseMutation = resolve; });
  let mutationInput: Record<string, unknown> | null = null;
  let mutationCount = 0;
  await page.route('**/v1/findings/501/lifecycle', async (route) => {
    expect(route.request().method()).toBe('PATCH');
    mutationCount += 1;
    mutationInput = route.request().postDataJSON() as Record<string, unknown>;
    await mutationGate;
    const response = await route.fetch();
    await route.fulfill({ response });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const gate = page.locator('.stat').filter({ hasText: 'Gate' }).locator('strong');
  await expect(gate).toHaveText('fail');
  await page.locator('.finding-action-menu summary').click();
  await page.locator('.finding-detail').getByRole('button', { name: 'Non-blocking for gate', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Reason required: non-blocking for gate', exact: true });
  await expect(dialog).toBeVisible();
  const auditReason = 'Reviewed locally for the browser lifecycle fixture.';
  await dialog.getByLabel('Local audit reason', { exact: true }).fill(auditReason);
  expect(mutationCount).toBe(0);
  expect(mutationInput).toBeNull();
  await expect(gate).toHaveText('fail');
  await dialog.getByRole('button', { name: 'Mark non-blocking for gate', exact: true }).click();
  await expect.poll(() => mutationInput).not.toBeNull();
  await expect(gate, 'the client does not optimistically alter the deterministic gate').toHaveText('fail');
  const capturedMutation = mutationInput as unknown as Record<string, unknown>;
  expect(mutationCount).toBe(1);
  expect(capturedMutation).toEqual({ action: 'gate_exempt', reason: auditReason, expected_revision: 1 });

  releaseMutation();
  await expect(page.getByText('S41-F001 updated', { exact: true })).toBeVisible();
  await expect(gate).toHaveText('pass');
  await expect(page.locator('.finding-detail').getByText('non-blocking', { exact: true })).toBeVisible();
  expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({ revision: 2, findings_revision: 2, gate_decision: 'pass' });
  expect(mutationCount).toBe(1);
  guards.assertClean();
});

referenceTest('Findings keeps the scan toolbar focused while replacement evidence is pending and inert', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let releaseReplacement!: () => void;
  const replacementGate = new Promise<void>((resolve) => { releaseReplacement = resolve; });
  for (const path of ['findings', 'artifacts'] as const) {
    const pattern = path === 'findings' ? '**/v1/scans/40/findings?*' : '**/v1/scans/40/artifacts';
    await page.route(pattern, async (route) => {
      await replacementGate;
      await route.fulfill({
        json: path === 'findings'
          ? { items: [], total: 0, truncated: false, next_cursor: null, revision: 1 }
          : [],
        status: 200,
      });
    });
  }
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const surface = page.locator('section[data-route-surface="findings"]');
  const workspace = surface.locator('.finding-workspace');
  const scanSelect = surface.getByLabel('Scan', { exact: true });
  await scanSelect.focus();
  await expect(scanSelect).toBeFocused();
  await scanSelect.selectOption('40');
  await expect(scanSelect).toHaveValue('40');
  await expect(surface).toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
  await expect(workspace).toHaveAttribute('aria-busy', 'true');
  await expect(workspace).toHaveAttribute('inert', '');
  await expect(scanSelect).toBeFocused();
  expect(await scanSelect.evaluate((element) => Boolean(element.closest('[inert], [aria-hidden="true"]')))).toBe(false);
  await expect(workspace.getByRole('button', { name: 'Run Advisor', exact: true })).toHaveCount(0);

  releaseReplacement();
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(workspace).not.toHaveAttribute('inert', '');
  await expect(scanSelect).toBeFocused();
  await expect(scanSelect).toHaveValue('40');

  await scanSelect.selectOption('41');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(scanSelect).toBeFocused();
  await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
  guards.assertClean();
});

referenceTest('Findings hands detail focus to the replacement before stale evidence is hidden', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  let releaseDeletion!: () => void;
  let deletionHeld = false;
  let deletionCount = 0;
  const deletionGate = new Promise<void>((resolve) => { releaseDeletion = resolve; });
  await page.route('**/v1/findings/501?expected_revision=1', async (route) => {
    expect(route.request().method()).toBe('DELETE');
    deletionCount += 1;
    deletionHeld = true;
    await deletionGate;
    await route.fallback();
  });

  const deleteButton = page.getByTitle('Delete this finding from the selected scan');
  await deleteButton.focus();
  await expect(deleteButton).toBeFocused();
  await deleteButton.press('Enter');
  const deleteDialog = page.locator('dialog.confirmation-dialog');
  await expect(deleteDialog.getByText('Delete S41-F001 (javascript.lang.audit.dynamic-code) from this scan?', { exact: true })).toBeVisible();
  try {
    expect(deletionCount).toBe(0);
    await deleteDialog.getByRole('button', { name: 'Delete finding', exact: true }).click();
    await expect.poll(() => deletionHeld).toBe(true);
    await expect(deleteDialog).toHaveCount(0);
    await expect(page.locator('.finding-detail h2')).toHaveText('S41-F001');
    await expect(page.locator('.finding-list-item', { hasText: 'S41-F001' }).locator('.finding-list-main')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.finding-list-main:focus'), 'no row takes detail focus before the authoritative deletion acknowledgement').toHaveCount(0);
    expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({ revision: 1, findings_revision: 1 });
  } finally {
    releaseDeletion();
  }

  const replacement = page.locator('.finding-list-item', { hasText: 'S41-F002' }).locator('.finding-list-main');
  await expect(replacement).toBeFocused();
  await expect(page.locator('.finding-detail')).not.toHaveAttribute('inert', '');
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F002');
  expect(deletionCount).toBe(1);
  expect(await (await request.get('/v1/scans/41')).json()).toMatchObject({ revision: 2, findings_revision: 2 });
  guards.assertClean();
});

referenceTest('Findings preserves keyboard focus when refreshed evidence removes the active finding', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Findings');

  const triageButton = page.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true });
  await triageButton.focus();
  await expect(triageButton).toBeFocused();
  const deletion = await request.delete('/v1/findings/501?expected_revision=1');
  expect(deletion.ok(), 'authoritative external finding deletion').toBe(true);
  // Trigger the same refresh path as polling without moving focus to the
  // header control; this isolates the external evidence-replacement boundary.
  await page.getByRole('button', { name: 'Refresh', exact: true }).evaluate((button: HTMLButtonElement) => button.click());

  const replacement = page.locator('.finding-list-item', { hasText: 'S41-F002' }).locator('.finding-list-main');
  await expect(replacement).toBeFocused();
  await expect(page.locator('.finding-detail')).not.toHaveAttribute('inert', '');
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F002');
  guards.assertClean();
});

referenceTest('Findings replaces a removed deep-link route with its actual fallback without history growth', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=findings&scan=41&finding=1');
  const surface = page.locator('section[data-route-surface="findings"]');
  const detail = surface.locator('.finding-detail');
  await expect(surface).toHaveCount(1);
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(detail.locator('h2')).toHaveText('S41-F001');
  await expect(detail).toHaveAttribute('aria-busy', 'false');
  const deleteCurrentFinding = async () => {
    await detail.getByTitle('Delete this finding from the selected scan').click();
    const confirmation = page.locator('dialog.confirmation-dialog');
    await expect(confirmation).toBeVisible();
    await confirmation.getByRole('button', { name: 'Delete finding', exact: true }).click();
  };

  const historyLength = await page.evaluate(() => window.history.length);
  await page.evaluate(() => {
    const observed = window as Window & { __findingRouteReplacements?: number };
    const replaceState = window.history.replaceState.bind(window.history);
    observed.__findingRouteReplacements = 0;
    window.history.replaceState = ((data: unknown, unused: string, url?: string | URL | null) => {
      observed.__findingRouteReplacements = (observed.__findingRouteReplacements || 0) + 1;
      replaceState(data, unused, url);
    }) as History['replaceState'];
  });

  await deleteCurrentFinding();
  await expect(page.getByText('S41-F001 deleted', { exact: true })).toBeVisible();
  await expect(detail.locator('h2')).toHaveText('S41-F002');
  await expect(detail).toHaveAttribute('aria-busy', 'false');
  await expect(page).toHaveURL(/\?view=findings&scan=41&finding=2$/u);
  expect(await page.evaluate(() => window.history.length)).toBe(historyLength);
  expect(await page.evaluate(() => (window as Window & { __findingRouteReplacements?: number }).__findingRouteReplacements)).toBe(1);

  await deleteCurrentFinding();
  await expect(page.getByText('S41-F002 deleted', { exact: true })).toBeVisible();
  await expect(detail.locator('h2')).toHaveText('S41-F003');
  await expect(detail).toHaveAttribute('aria-busy', 'false');
  await expect(page).toHaveURL(/\?view=findings&scan=41&finding=3$/u);
  expect(await page.evaluate(() => window.history.length)).toBe(historyLength);
  expect(await page.evaluate(() => (window as Window & { __findingRouteReplacements?: number }).__findingRouteReplacements)).toBe(2);

  await deleteCurrentFinding();
  await expect(page.getByText('S41-F003 deleted', { exact: true })).toBeVisible();
  await expect(surface.locator('.finding-list-item')).toHaveCount(0);
  await expect(page).toHaveURL(/\?view=findings&scan=41$/u);
  expect(await page.evaluate(() => window.history.length)).toBe(historyLength);
  expect(await page.evaluate(() => (window as Window & { __findingRouteReplacements?: number }).__findingRouteReplacements)).toBe(3);
  guards.assertClean();
});

referenceTest('durable scan and advisor commands send unique idempotency keys', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const providersResponse = await request.get('/v1/advisor/providers');
  expect(providersResponse.status()).toBe(200);
  const providers = await providersResponse.json() as {
    revision: number;
    providers: Array<{
      id: string; transport: string; eligible: boolean; config_revision: number;
      config_digest: string; model: string; model_digest: string;
    }>;
    resolution: { provider_id: string | null; transport: string; eligible_provider_ids: string[] };
  };
  expect(providers.revision).toBe(1);
  expect(providers.resolution).toMatchObject({ provider_id: 'local-default', transport: 'local' });
  const provider = providers.providers.find((candidate) => candidate.id === providers.resolution.provider_id);
  if (!provider) throw new Error('The fixture must resolve one current local Advisor provider.');
  expect(provider).toMatchObject({ transport: 'local', eligible: true });
  expect(providers.resolution.eligible_provider_ids).toContain(provider.id);
  const expectedAdvisorPin = {
    provider_collection_revision: providers.revision,
    provider_id: provider.id,
    transport: provider.transport,
    provider_config_revision: provider.config_revision,
    provider_config_digest: provider.config_digest,
    model: provider.model,
    model_digest: provider.model_digest,
  };
  await installQualityObservers(page);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Projects');

  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  await expect(page.getByText('Scan #42 queued', { exact: true })).toBeVisible();
  const queuedScans = await (await request.get('/v1/scans')).json() as Array<{
    id: number;
    job_id?: number;
    job_revision?: number;
  }>;
  expect(queuedScans.find((scan) => scan.id === 42)).toMatchObject({
    id: 42,
    job_id: 84,
    job_revision: 1,
  });

  await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
  await page.getByLabel('Scan', { exact: true }).selectOption('41');
  await expect(page.getByText('S41-F001', { exact: true }).first()).toBeVisible();
  const scanAdvisorResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).origin === new URL(baseURL).origin
    && new URL(response.url()).pathname === '/v1/scans/41/triage'
  ));
  await page.getByRole('button', { name: 'Scan Advisor', exact: true }).click();
  const scanAdvisorResponse = await scanAdvisorResponsePromise;
  expect(scanAdvisorResponse.status()).toBe(202);
  const scanAdvisorJob = await scanAdvisorResponse.json() as { id: number };
  expect(scanAdvisorJob).toMatchObject({ kind: 'advisor', status: 'queued', revision: 1, scan_id: 41 });
  await expect(page.getByText(`Advisor job #${scanAdvisorJob.id} queued`, { exact: true })).toBeVisible();

  await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Run Advisor', exact: true })).toBeVisible();
  const findingAdvisorResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).origin === new URL(baseURL).origin
    && new URL(response.url()).pathname === '/v1/findings/501/triage'
  ));
  await page.getByRole('button', { name: 'Run Advisor', exact: true }).click();
  const findingAdvisorResponse = await findingAdvisorResponsePromise;
  expect(findingAdvisorResponse.status()).toBe(202);
  const findingAdvisorJob = await findingAdvisorResponse.json() as { id: number };
  expect(findingAdvisorJob).toMatchObject({ kind: 'advisor', status: 'queued', revision: 1, scan_id: 41, finding_id: 501 });
  await expect(page.getByText(`Advisor job #${findingAdvisorJob.id} queued`, { exact: true })).toBeVisible();

  await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
  await page.locator('.finding-list-item', { hasText: 'S41-F001' }).getByRole('checkbox').check();
  await page.locator('.finding-list-item', { hasText: 'S41-F002' }).getByRole('checkbox').check();
  await expandFindingDisclosure(page, '.bulk-action-disclosure');
  const bulkAdvisorResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).origin === new URL(baseURL).origin
    && new URL(response.url()).pathname === '/v1/findings/bulk'
  ));
  await page.locator('.bulk-actions').getByRole('button', { name: 'Advisor', exact: true }).click();
  const bulkAdvisorResponse = await bulkAdvisorResponsePromise;
  expect(bulkAdvisorResponse.status()).toBe(202);
  const bulkAdvisorResult = await bulkAdvisorResponse.json() as { job: { id: number } };
  expect(bulkAdvisorResult).toMatchObject({
    updated: 0, deleted: 0, scan_ids: [41],
    job: { kind: 'advisor', status: 'queued', revision: 1, scan_id: 41 },
  });
  await expect(page.getByText(`Advisor job #${bulkAdvisorResult.job.id} queued`, { exact: true })).toBeVisible();
  const advisorJobIds = [scanAdvisorJob.id, findingAdvisorJob.id, bulkAdvisorResult.job.id];
  for (const id of advisorJobIds) {
    expect(Number.isSafeInteger(id)).toBe(true);
    expect(id).toBeGreaterThan(0);
  }
  expect(new Set([84, ...advisorJobIds]).size, 'each action acknowledges a fresh durable job').toBe(4);

  const commands = await (await request.get('/__test/commands')).json() as Array<{
    method: string;
    route: string;
    idempotency_key: string;
    input: Record<string, unknown>;
  }>;
  expect(commands.map((command) => command.route)).toEqual([
    'scan',
    'scan-advisor',
    'finding-advisor',
    'bulk-advisor',
  ]);
  expect(commands.every((command) => command.method === 'POST')).toBe(true);
  for (const command of commands) expect(command.idempotency_key).toMatch(/^web-[0-9a-f-]{36}$/);
  expect(new Set(commands.map((command) => command.idempotency_key)).size).toBe(commands.length);
  expect(commands[0].input).toMatchObject({ project_id: 11, mode: 'full', use_ai: false });
  expect(commands[1].input).toMatchObject({ include_existing: false });
  expect(commands[2].input).toEqual({ expected_revision: 1, advisor_provider_pin: expectedAdvisorPin });
  expect(commands[3].input).toMatchObject({
    action: 'triage',
    finding_ids: [501, 502],
    expected_revisions: { 501: 1, 502: 1 },
  });
  for (const command of commands.slice(1)) expect(command.input.advisor_provider_pin).toEqual(expectedAdvisorPin);

  // The queue acknowledgement intentionally precedes the subsequent state
  // refresh. Measure the stable surface only after that persisted refresh and
  // route transition have completed.
  await expect(page.getByRole('heading', { level: 1, name: 'Jobs', exact: true })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await resetQualityWindow(page);
  await assertStableSurface(page, testInfo);
  guards.assertClean();
});

referenceTest('Jobs keeps grouped counts and current actions readable at narrow widths and 200% text', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'durable', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');
  const surface = page.locator('section[data-route-surface="jobs"]');
  const summary = surface.getByRole('group', { name: 'Job summary', exact: true });
  const expectedCounts = [['Active', '4'], ['Completed', '1'], ['Failed', '1'], ['Scans', '4'], ['Advisor', '3']];
  const readCounts = () => summary.locator('dl > div').evaluateAll((elements) => elements.map((element) => [
    element.querySelector('dt')!.textContent, element.querySelector('dd')!.textContent,
  ]));
  await expect(summary.getByRole('group', { name: 'Job status counts', exact: true })).toBeVisible();
  await expect(summary.getByRole('group', { name: 'Job kind counts', exact: true })).toBeVisible();
  await expect.poll(readCounts).toEqual(expectedCounts);
  await expect(surface.locator('.work-processing-status')).toHaveText('Work processing healthyQueued work can start.');

  const search = page.getByRole('textbox', { name: 'Search jobs', exact: true });
  const status = page.getByRole('combobox', { name: 'Job status', exact: true });
  const kind = page.getByRole('combobox', { name: 'Job kind', exact: true });
  await search.fill('92');
  await status.selectOption('active');
  const row = page.getByLabel(/^Job #92:/);
  await expect(surface.locator('.job-row')).toHaveCount(1);
  await expect(row.locator('.job-status-cell')).toHaveText('Running');
  await expect.poll(readCounts, { message: 'Filtering work does not hide or recompute the overall summary' }).toEqual(expectedCounts);
  const cancel = row.getByRole('button', { name: 'Cancel', exact: true });
  const scan = row.getByRole('button', { name: 'Scan #39', exact: true });

  for (const scale of [1, 2]) {
    if (scale === 2) {
      // Measure existing computed glyph sizes first so pixel-sized labels also
      // double without compounding inherited sizes. This is synthetic text
      // enlargement, not a native browser zoom-menu receipt.
      const mismatches = await page.evaluate(() => {
        const before = Array.from(document.querySelectorAll<HTMLElement>('*'))
          .filter((element) => element instanceof HTMLElement)
          .map((element) => ({ element, size: Number.parseFloat(getComputedStyle(element).fontSize), leading: Number.parseFloat(getComputedStyle(element).lineHeight) }));
        for (const { element, size, leading } of before) {
          element.style.fontSize = `${size * 2}px`;
          if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
        }
        return before.filter(({ element }) => Array.from(element.childNodes).some((node) => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent?.trim())))
          .flatMap(({ element, size }) => Math.abs(Number.parseFloat(getComputedStyle(element).fontSize) - size * 2) < 0.01 ? [] : [element.tagName]);
      });
      expect(mismatches, 'Every existing glyph-bearing element doubles').toEqual([]);
    }
    for (const width of [390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await summary.scrollIntoViewIfNeeded();
      const geometry = await surface.evaluate((element) => {
        const summaryElement = element.querySelector('.job-summary')!;
        const summaryBounds = summaryElement.getBoundingClientRect();
        const toolbarBounds = element.querySelector('.job-toolbar')!.getBoundingClientRect();
        return {
          pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          summaryBottom: summaryBounds.bottom, toolbarTop: toolbarBounds.top,
          items: Array.from(element.querySelectorAll<HTMLElement>('.job-summary-label, .job-summary dt, .job-summary dd, .job-toolbar input, .job-toolbar select, .job-actions button')).map((item) => {
            const bounds = item.getBoundingClientRect();
            return { text: item.textContent?.trim() || item.getAttribute('aria-label'), left: bounds.left, right: bounds.right,
              width: bounds.width, height: bounds.height, clientWidth: item.clientWidth, scrollWidth: item.scrollWidth,
              clientHeight: item.clientHeight, scrollHeight: item.scrollHeight, fontSize: Number.parseFloat(getComputedStyle(item).fontSize) };
          }),
        };
      });
      await testInfo.attach(`jobs-${width}-text-${scale * 100}-geometry.json`, { body: Buffer.from(JSON.stringify(geometry, null, 2)), contentType: 'application/json' });
      expect(geometry.pageOverflow, `${width}px/${scale}x page overflow`).toBeLessThanOrEqual(1);
      expect(geometry.summaryBottom, 'Summary and job controls do not overlap').toBeLessThanOrEqual(geometry.toolbarTop);
      expect(geometry.items).toHaveLength(17);
      for (const item of geometry.items) {
        expect(item.width, item.text || 'Job content').toBeGreaterThan(0);
        expect(item.height, item.text || 'Job content').toBeGreaterThan(0);
        expect(item.left, `${item.text} left containment`).toBeGreaterThanOrEqual(0);
        expect(item.right, `${item.text} right containment`).toBeLessThanOrEqual(width);
        expect(item.scrollWidth, `${item.text} horizontal clipping`).toBeLessThanOrEqual(item.clientWidth + 1);
        expect(item.scrollHeight, `${item.text} vertical clipping`).toBeLessThanOrEqual(item.clientHeight + 1);
        expect(item.fontSize, `${item.text} readable size`).toBeGreaterThanOrEqual(14 * scale);
      }
      await expect.poll(readCounts).toEqual(expectedCounts);
      await search.focus();
      await search.press('Tab');
      await expect(status).toBeFocused();
      await status.press('Tab');
      await expect(kind).toBeFocused();
      await kind.press('Tab');
      await expect(cancel).toBeFocused();
      await expect(cancel).toBeInViewport();
      await cancel.press('Tab');
      await expect(scan).toBeFocused();
      await expect(scan).toBeInViewport();
      await testInfo.attach(`jobs-summary-${width}-text-${scale * 100}.png`, { body: await summary.screenshot(), contentType: 'image/png' });
    }
  }
  // Reaching the exact action by keyboard must still open its existing review;
  // declining it must leave the job and command ledger unchanged.
  await cancel.focus();
  await cancel.press('Enter');
  const confirmation = page.locator('dialog.confirmation-dialog');
  await expect(confirmation.getByRole('heading', { name: 'Cancel job #92?', exact: true })).toBeVisible();
  await confirmation.getByRole('button', { name: 'Keep job running', exact: true }).press('Enter');
  await expect(confirmation).not.toBeVisible();
  await expect(row.locator('.job-status-cell')).toHaveText('Running');
  expect(await (await request.get('/__test/commands')).json()).toEqual([]);
  await page.waitForLoadState('networkidle');
  guards.assertClean();
});

referenceTest('Jobs finding actions wrap at narrow widths with actual 200% text and retain exact navigation', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'durable', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');
  await page.getByRole('textbox', { name: 'Search jobs', exact: true }).fill('91');
  const row = page.getByLabel(/^Job #91:/);
  const finding = row.getByRole('button', { name: 'Open S41-F001', exact: true });
  await expect(finding).toBeVisible();

  const enlargement = await page.evaluate(() => {
    const items = Array.from(document.querySelectorAll<HTMLElement>('*')).map(element => ({
      element, font: parseFloat(getComputedStyle(element).fontSize),
      leading: parseFloat(getComputedStyle(element).lineHeight),
    }));
    for (const { element, font, leading } of items) {
      element.style.fontSize = `${font * 2}px`;
      if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
    }
    return items.filter(({ element, font }) =>
      Math.abs(parseFloat(getComputedStyle(element).fontSize) - font * 2) > 0.01).length;
  });
  expect(enlargement, 'Every existing text size actually doubles').toBe(0);
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await finding.scrollIntoViewIfNeeded();
    const geometry = await row.locator('.job-actions button').evaluateAll(elements => elements.map(element => {
      const box = element.getBoundingClientRect();
      return { label: element.textContent, left: box.left, right: box.right,
        overflow: element.scrollWidth - element.clientWidth };
    }));
    expect(geometry).toHaveLength(3);
    for (const action of geometry) {
      expect(action.left, action.label || '').toBeGreaterThanOrEqual(0);
      expect(action.right, action.label || '').toBeLessThanOrEqual(width);
      expect(action.overflow, action.label || '').toBeLessThanOrEqual(1);
    }
    await testInfo.attach(`jobs-finding-${width}-text-200.png`, { body: await row.screenshot(), contentType: 'image/png' });
  }
  await finding.focus();
  await finding.press('Enter');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page.getByLabel('Scan', { exact: true })).toHaveValue('41');
  await expect(page.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
  expect(await (await request.get('/__test/commands')).json()).toEqual([]);
  guards.assertClean();
});

referenceTest('durable job lifecycle exposes only valid cancellation and acknowledges immediately', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'durable', generation: 1 } });
  await installQualityObservers(page);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');

  for (const [jobId, status] of [[90, 'Waiting'], [91, 'Assigned'], [92, 'Running'], [93, 'Cancelling'], [94, 'Cancelled']] as const) {
    const row = page.getByLabel(new RegExp(`^Job #${jobId}:`));
    await expect(row.locator('.job-status-cell')).toHaveText(status);
    await expect(row.locator('.job-status-cell')).toBeVisible();
  }
  await expect(page.getByRole('group', { name: 'Job status counts', exact: true }).locator('dl > div').filter({ hasText: 'Active' }).locator('dd')).toHaveText('4');
  await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(3);
  await expect(page.getByLabel(/^Job #93:/).getByText('Stopping this Advisor request and confirming cleanup. Completed reviews remain available.', { exact: true })).toBeVisible();
  await expect(page.getByLabel(/^Job #94:/).getByText('Scanner cancellation is complete. Findings and sanitized artifacts published by completed stages remain available.', { exact: true })).toBeVisible();
  await expect(page.getByLabel(/^Job #94:/).getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);

  const runningRow = page.getByLabel(/^Job #92:/);
  await runningRow.getByRole('button', { name: 'Cancel', exact: true }).click();
  const cancellation = page.locator('dialog.confirmation-dialog');
  await expect(cancellation).toBeVisible();
  await page.evaluate(() => {
    window.__kodesecCancelAck = { duration: null };
    const message = document.querySelector('dialog.confirmation-dialog > p')?.textContent || '';
    document.body.dataset.cancelConfirmation = message;
    const confirm = [...document.querySelectorAll('dialog.confirmation-dialog button')]
      .find((button) => button.textContent?.trim() === 'Cancel job');
    if (!confirm) throw new Error('Exact cancellation confirmation is missing.');
    confirm.addEventListener('click', () => {
      const started = performance.now();
      const observer = new MutationObserver(() => {
        const acknowledged = [...document.querySelectorAll('.toast strong')]
          .some((node) => node.textContent?.trim() === 'Cancelling job #92');
        if (acknowledged) {
          observer.disconnect();
          if (window.__kodesecCancelAck) window.__kodesecCancelAck.duration = performance.now() - started;
        }
      });
      observer.observe(document.querySelector('.toast-stack') || document.body, { childList: true, subtree: true });
    }, { capture: true, once: true });
  });
  await cancellation.getByRole('button', { name: 'Cancel job', exact: true }).click();
  await expect(page.getByText('Cancelling job #92', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.body.dataset.cancelConfirmation)).toContain('The exact scanner run will stop.');
  await expect(page.getByText('The durable worker will stop the exact scanner run and confirm temporary-output cleanup before marking it cancelled.', { exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__kodesecCancelAck?.duration ?? null)).not.toBeNull();
  const acknowledgement = await page.evaluate(() => window.__kodesecCancelAck?.duration ?? Number.POSITIVE_INFINITY);
  await testInfo.attach('cancel-acknowledgement.json', { body: Buffer.from(JSON.stringify({ duration_ms: acknowledgement }, null, 2)), contentType: 'application/json' });
  expect(acknowledgement, 'cancellation acknowledgement').toBeLessThanOrEqual(qualificationMilliseconds(100));

  await expect(runningRow.locator('.job-status-cell')).toHaveText('Cancelling');
  await expect(runningRow.locator('.job-status-cell')).toBeVisible();
  await expect(runningRow.getByText("Scanner cancellation is persisted; waiting for temporary-output cleanup and the worker's terminal receipt.", { exact: true })).toBeVisible();
  await expect(runningRow.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);

  const advisorRow = page.getByLabel(/^Job #91:/);
  let advisorCancellationRequests = 0;
  page.on('request', (outgoing) => {
    if (outgoing.method() === 'POST' && new URL(outgoing.url()).pathname === '/v1/jobs/91/cancel') advisorCancellationRequests += 1;
  });
  await advisorRow.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(cancellation).toBeVisible();
  await expect(cancellation.locator(':scope > p')).toHaveText('Cancel job #91? This Advisor request will stop and its connection will close. Completed reviews remain available. Cancellation cannot undo processing or disclosure that already occurred.');
  expect(advisorCancellationRequests, 'opening Advisor confirmation sends no cancellation').toBe(0);
  const advisorCancellationResponse = page.waitForResponse((response) => response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/jobs/91/cancel');
  await cancellation.getByRole('button', { name: 'Cancel job', exact: true }).click();
  await expect(page.getByText('Cancelling job #91', { exact: true })).toBeVisible();
  await expect(page.getByText('Cancellation requested. Waiting for this Advisor connection to close and cleanup to finish.', { exact: true })).toBeVisible();
  const advisorCancelled = await advisorCancellationResponse;
  expect(advisorCancelled.status()).toBe(200);
  expect(await advisorCancelled.json()).toMatchObject({ id: 91, kind: 'advisor', scan_id: 41, finding_id: 501, revision: 3, status: 'cancelling', can_cancel: false });
  expect(advisorCancellationRequests, 'one confirmed exact Advisor cancellation').toBe(1);
  await expect(advisorRow.getByText('Stopping this Advisor request and confirming cleanup. Completed reviews remain available.', { exact: true })).toBeVisible();
  await expect(advisorRow.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);

  const failedRow = page.getByLabel(/^Job #82:/);
  await expect(failedRow.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(1);
  await expect(page.getByLabel(/^Job #81:/).getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
  await page.evaluate(() => {
    window.__kodesecRetryAck = { duration: null };
    const retry = [...document.querySelectorAll('button')]
      .find((node) => node.textContent?.trim() === 'Retry');
    retry?.addEventListener('click', () => {
      const started = performance.now();
      const observer = new MutationObserver(() => {
        const acknowledged = [...document.querySelectorAll('.toast strong')]
          .some((node) => node.textContent?.trim() === 'Retrying job #82');
        if (acknowledged) {
          observer.disconnect();
          if (window.__kodesecRetryAck) window.__kodesecRetryAck.duration = performance.now() - started;
        }
      });
      observer.observe(document.querySelector('.toast-stack') || document.body, { childList: true, subtree: true });
    }, { capture: true, once: true });
  });
  await failedRow.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByText('Retrying job #82', { exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__kodesecRetryAck?.duration ?? null)).not.toBeNull();
  const retryAcknowledgement = await page.evaluate(() => window.__kodesecRetryAck?.duration ?? Number.POSITIVE_INFINITY);
  await testInfo.attach('retry-acknowledgement.json', { body: Buffer.from(JSON.stringify({ duration_ms: retryAcknowledgement }, null, 2)), contentType: 'application/json' });
  expect(retryAcknowledgement, 'retry acknowledgement').toBeLessThanOrEqual(qualificationMilliseconds(100));
  await expect(failedRow.locator('.job-status-cell')).toHaveText('Waiting');
  await expect(failedRow.locator('.job-status-cell')).toBeVisible();
  await expect(failedRow.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
  await expect(failedRow.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(1);

  // Both commands intentionally trigger a full persisted-state refresh. Wait
  // for that refresh to settle before asserting transport cleanliness so
  // context teardown cannot turn owned, in-flight requests into false aborts.
  await page.waitForLoadState('networkidle');

  const accessibility = await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze();
  const seriousOrCritical = accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact || ''));
  expect(seriousOrCritical.map((violation) => violation.id)).toEqual([]);
  await resetQualityWindow(page);
  await assertStableSurface(page, testInfo);
  guards.assertClean();
});

referenceTest('Jobs distinguishes healthy slow work from a stale worker heartbeat', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'job-activity', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');

  const job = page.getByLabel(/^Job #83:/);
  await expect(job).toContainText('phase Checking current scanner data');
  await expect(job.getByText('Validating active bearer-rules', { exact: true })).toBeVisible();
  await expect(job.getByText(/Current component 1 of 6 · 5\.0 MB of 10\.0 MB · last updater activity/)).toBeVisible();
  await expect(job.getByText(/Worker heartbeat active · last received/)).toBeVisible();
  const elapsed = job.locator('.job-elapsed');
  await expect(elapsed).toContainText(/Since first start (?:\d+d )?(?:\d+h )?(?:\d+m )?\d+s/u);
  const initialElapsed = await elapsed.textContent();
  await expect.poll(() => elapsed.textContent(), { timeout: 3_000 }).not.toBe(initialElapsed);
  await expect(job.locator('.progress-label strong')).toHaveText('Running');
  await expect(job.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow');
  await expect(job).not.toContainText('18%');
  await expect(job.locator('.job-slow-status')).toHaveText('Worker heartbeat is active. No updater activity has been reported for more than 45 seconds. This can be normal during a long-running step. Keep waiting, or cancel the job if you no longer need its result.');
  await expect(job.getByRole('alert')).toHaveCount(0);
  await expect(job.locator('.job-heartbeat-stale')).toHaveCount(0);
  await expect(job).not.toContainText('Check worker health');
  const componentless = page.getByLabel(/^Job #85:/);
  await expect(componentless.getByText('Phase Checking scanner data lock', { exact: true })).toBeVisible();
  await expect(componentless.getByText(/last updater activity/)).toBeVisible();
  await expect(componentless.getByText(/Worker heartbeat active · last received/)).toBeVisible();
  await expect(componentless.locator('.job-slow-status')).toHaveText('Worker heartbeat is active. No updater activity has been reported for more than 45 seconds. This can be normal during a long-running step. Keep waiting; cancellation is unavailable during this phase.');
  await expect(componentless.getByRole('alert')).toHaveCount(0);
  await expect(componentless).not.toContainText('cancel the job');
  await expect(componentless.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);
  const scanner = page.getByLabel(/^Job #86:/);
  await expect(scanner.getByText('Phase Running scanners', { exact: true })).toBeVisible();
  await expect(scanner.getByText(/last scanner state change/)).toBeVisible();
  await expect(scanner.getByText(/Worker heartbeat active · last received/)).toBeVisible();
  await expect(scanner.locator('.job-slow-status')).toContainText('Worker heartbeat is active. No scanner state change has been reported for more than 45 seconds.');
  await expect(scanner.getByRole('alert')).toHaveCount(0);
  await expect(scanner.locator('.progress-label strong')).toHaveText('Running');
  await expect(scanner.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow');
  await expect(scanner).not.toContainText('15%');
  await expect(scanner.locator('.job-elapsed')).toContainText(/Since first start (?:\d+d )?(?:\d+h )?(?:\d+m )?\d+s/u);
  const completed = page.getByLabel(/^Job #84:/);
  await expect(completed.locator('.job-status-cell')).toHaveText('Completed');
  await expect(completed.locator('.job-status-cell')).toBeVisible();
  await expect(completed).not.toContainText('Preparing grype-db');
  await expect(completed.locator('.job-activity')).toHaveCount(0);

  const staleJob = page.getByLabel(/^Job #87:/);
  await expect(staleJob.getByText(/Worker heartbeat stale · last received/)).toBeVisible();
  await expect(staleJob.locator('.job-heartbeat-stale')).toHaveCount(1);
  await expect(staleJob.getByRole('alert')).toHaveText('No scanner state change or fresh worker heartbeat has been reported for more than 45 seconds. The job remains safely recorded. Check worker health before retrying or cancelling it.');
  await expect(staleJob.locator('.job-slow-status')).toHaveCount(0);
  guards.assertClean();
});

referenceTest('[WEB-ACT-008] Settings treats unobserved desired-off components and schema verification truthfully', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const expectedSchemaReceipt = {
    id: 'schema-init', lifecycle: 'one-shot', startable: false, state: 'completed',
    message: 'Completed successfully; expected to stop.',
    schema_id: 'lomo-kodesec-0.1.0-initial',
    schema_fingerprint: 'c46a2a6c140c7ea9151b6a7414164ce5c10a9e70d8973cc5b09be4007e537517',
    initialized_at: '2026-08-25T08:00:00Z',
    evidence: 'schema-identity-and-api-startup-verification',
  };
  const configResponse = await request.get('/v1/config');
  expect(configResponse.status()).toBe(200);
  const { schema_init: schemaReceipt } = await configResponse.json() as { schema_init: typeof expectedSchemaReceipt };
  expect(schemaReceipt).toEqual(expectedSchemaReceipt);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');

  await expect(page.locator('.component-card', { hasText: 'cAdvisor' })).toHaveCount(0);
  const schemaStatus = page.locator('[data-schema-init-state="completed"]');
  await expect(schemaStatus).toContainText('schema-init Completed successfully; expected to stop.');
  await expect(schemaStatus.locator('code')).toHaveText([schemaReceipt.schema_id, schemaReceipt.schema_fingerprint]);
  await expect(schemaStatus.locator('time')).toHaveText(schemaReceipt.initialized_at);
  await expect(schemaStatus.locator('time')).toHaveAttribute('datetime', schemaReceipt.initialized_at);
  await expect(schemaStatus).toContainText('and verified at API startup.');
  await expect(page.locator('[data-schema-init-state="unverified"]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /schema-init/u })).toHaveCount(0);
  const links = page.locator('.links');
  for (const label of ['Grafana', 'Gitea', 'Prometheus']) {
    await expect(links.getByText(`${label} · disabled`, { exact: true })).toHaveAttribute('aria-disabled', 'true');
    await expect(links.getByRole('link', { name: label, exact: true })).toHaveCount(0);
  }
  await expect(page.getByRole('button', { name: 'Save Desired Components', exact: true })).toBeVisible();
  guards.assertClean();
});

referenceTest('Settings never claims schema-init completion without a matching runtime receipt', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'schema-unverified', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');

  const schemaStatus = page.locator('[data-schema-init-state="unverified"]');
  await expect(schemaStatus).toContainText('schema-init status is unverified.');
  await expect(schemaStatus).toContainText('no matching schema-init completion receipt');
  await expect(page.getByText('Completed successfully; expected to stop.', { exact: false })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /schema-init/u })).toHaveCount(0);
  guards.assertClean();
});

referenceTest('Settings distinguishes ready, absent, unknown, and running-unhealthy components', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'component-truth', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');

  const control = page.locator('.component-card', { hasText: 'control' });
  await expect(control).toHaveClass(/component-failure/);
  await expect(control).toContainText('Required core service is not reachable.');

  const scanner = page.locator('.component-card', { hasText: 'scanner' });
  await expect(scanner).toHaveClass(/component-ready/);
  await expect(scanner).toContainText('Scanner runtime is running and healthy.');

  await expect(page.locator('.component-card', { hasText: 'cAdvisor' })).toHaveCount(0);

  const grafana = page.locator('.component-card', { hasText: 'grafana' });
  await expect(grafana).toHaveClass(/component-warning/);
  await expect(grafana).toContainText('desired on · observed not running');
  await expect(grafana).toContainText('Not running; optional; scanning is unaffected.');

  const prometheus = page.locator('.component-card', { hasText: 'prometheus' });
  await expect(prometheus).toHaveClass(/component-warning/);
  await expect(prometheus).toContainText('desired on · observed unknown');

  const gitea = page.locator('.component-card', { hasText: 'gitea' });
  await expect(gitea).toHaveClass(/component-warning/);
  await expect(gitea).toContainText('desired off · observed running undesired');
  await expect(gitea).toContainText('stop it without deleting data');

  const adminer = page.locator('.component-card', { hasText: 'adminer' });
  await expect(adminer).toHaveClass(/component-disabled/);
  await expect(adminer).toContainText('desired off · observed not observed');
  await expect(page.locator('.command-box')).toContainText('make apply-components COMPONENTS=monitoring');
  guards.assertClean();
});

referenceTest('[WEB-HEALTH-001] failed health observations preserve cached work without claiming current readiness and recover on an unchanged poll', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const healthy = await (await request.get('/healthz')).json();
  healthy.ai.available = true;
  healthy.ai.reason = 'connected';
  let failHealth = false;
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.route('**/healthz', (route) => failHealth
    ? route.abort('failed')
    : route.fulfill({ status: 200, json: healthy }));
  // Persisted configuration is deliberately positive: it must not substitute
  // for the unavailable health observation in Settings.
  await page.route('**/v1/config', async (route) => {
    const response = await route.fetch();
    const config = await response.json();
    await route.fulfill({ response, json: { ...config, ollama_available: true, ollama_reason: 'connected' } });
  });
  await openRoute(page, 'Findings');
  await expect(page.getByRole('status', { name: 'Control plane healthy', exact: true })).toBeVisible();
  // Findings keeps Advisor guidance beside its actions, not in the global header.
  await expect(page.locator('.top-actions').getByText(/^Advisor /u)).toHaveCount(0);
  const selected = page.locator('.finding-list-item.active');
  await expect(selected).toHaveCount(1);
  const selectedBefore = await selected.textContent();
  const findingCount = await page.locator('.finding-list-item').count();
  expect(findingCount).toBeGreaterThan(0);

  failHealth = true;
  await page.getByTitle('Refresh', { exact: true }).click();
  await expect(page.getByRole('status', { name: 'Control plane status unknown', exact: true })).toBeVisible();
  await expect(page.locator('.top-actions').getByText(/^Advisor /u)).toHaveCount(0);
  await expect(page.getByRole('status', { name: 'Control plane healthy', exact: true })).toHaveCount(0);
  await expect(page.getByText(/Displayed findings, jobs and settings are the last loaded data/u)).toBeVisible();
  await expect(selected).toHaveText(selectedBefore || 'missing selection');
  await expect(page.locator('.finding-list-item')).toHaveCount(findingCount);

  const navigation = page.getByRole('navigation', { name: 'Workbench views' });
  await navigation.getByRole('button', { name: 'Jobs', exact: true }).click();
  await expect(page.locator('.top-actions')).toContainText('Advisor unknown');
  await expect(page.locator('.top-actions')).not.toContainText('Advisor ready');
  await expect(page.getByText('Work processing status unknown', { exact: true })).toBeVisible();
  await expect(page.getByText('Work processing healthy', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Task Manager More information', exact: true })).toBeVisible();
  await navigation.getByRole('button', { name: 'Settings', exact: true }).click();
  const settings = page.locator('section[data-route-surface="settings"]');
  await expect(settings).toHaveAttribute('data-settings-config-state', 'success');
  await expect(settings).not.toHaveAttribute('inert', '');
  const runtime = page.locator('.band').filter({ has: page.getByRole('heading', { name: 'Runtime', exact: true }) });
  await expect(runtime.locator('dd').filter({ hasText: /^unknown$/u })).toHaveCount(2);
  await expect(runtime.locator('dd').filter({ hasText: /^(ok|down)$/u })).toHaveCount(0);
  const advisor = page.locator('.band').filter({ has: page.getByRole('heading', { name: 'Advisor Route', exact: true }) });
  await expect(advisor.getByText('unknown', { exact: true })).toBeVisible();
  await expect(advisor).toContainText('last loaded configuration, not a current connection test');
  await expect(page.locator('.component-card.component-ready')).toHaveCount(0);
  await expect(page.locator('.component-card').filter({ hasText: /^control/u })).toContainText('observed unknown');
  const mode = page.getByRole('combobox', { name: 'Mode', exact: true });
  await mode.selectOption('off');

  failHealth = false;
  // Existing active fixture work schedules the application poll. Its unchanged
  // health payload must restore readiness even though the collection key did
  // not change. No user refresh or Settings reload may discard the draft.
  await expect(page.getByRole('status', { name: 'Control plane healthy', exact: true }))
    .toBeVisible({ timeout: qualificationMilliseconds(15_000) });
  await expect(page.locator('.top-actions')).toContainText('Advisor ready');
  await expect(runtime.getByText('Work processing healthy', { exact: true })).toBeVisible();
  await expect(runtime.locator('dd').filter({ hasText: /^ok$/u })).toHaveCount(2);
  await expect(mode).toHaveValue('off');
  await expect(advisor.getByText('yes', { exact: true })).toBeVisible();

  // A later outage invalidates configuration that this Settings instance read
  // before the outage. Restored health must not re-label those component cards
  // as current or silently replace the user's still-unsaved policy draft.
  failHealth = true;
  await page.getByTitle('Refresh', { exact: true }).click();
  await expect(page.getByRole('status', { name: 'Control plane status unknown', exact: true })).toBeVisible();
  failHealth = false;
  await page.getByTitle('Refresh', { exact: true }).click();
  await expect(page.getByRole('status', { name: 'Control plane healthy', exact: true })).toBeVisible();
  await expect(page.locator('.component-card.component-ready')).toHaveCount(0);
  await expect(mode).toHaveValue('off');
  await expect(advisor).toContainText('Reload Settings to verify the retained provider selection');
  await page.getByRole('button', { name: 'Reload Settings', exact: true }).click();
  await expect(page.locator('.component-card.component-ready')).toHaveCount(2);
  await expect(mode).toHaveValue('off');
  expect((await (await request.get('/v1/config')).json()).ai_mode).toBe('auto');
  await navigation.getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(selected).toHaveText(selectedBefore || 'missing selection');
  await expect(page.locator('.finding-list-item')).toHaveCount(findingCount);
  expect(guards.failures.request.length).toBeGreaterThan(0);
  expect(guards.failures.request.every((failure) => failure.includes('/healthz: net::ERR_FAILED') || failure.endsWith('net::ERR_ABORTED'))).toBe(true);
  expect(guards.failures.console.every((failure) => failure.includes('net::ERR_FAILED'))).toBe(true);
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.http).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

referenceTest('[WEB-HEALTH-001] superseded health successes and failures cannot replace a newer route observation', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'quiescent', generation: 1 } });
  const healthy = await (await request.get('/healthz')).json();
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let failHealth = false;
  let held: { entered: () => void; release: Promise<void>; finished: () => void } | null = null;
  await page.route('**/healthz', async (route) => {
    const failThisRequest = failHealth;
    const owner = held;
    held = null;
    owner?.entered();
    if (owner) await owner.release;
    try {
      if (failThisRequest) await route.abort('failed');
      else await route.fulfill({ status: 200, json: healthy });
    } finally {
      owner?.finished();
    }
  });
  await openRoute(page, 'Overview');
  const navigation = page.getByRole('navigation', { name: 'Workbench views' });
  for (const [oldFailure, nextRoute, expectedLabel] of [
    [false, 'Jobs', 'Control plane status unknown'],
    [true, 'Overview', 'Control plane healthy'],
  ] as const) {
    failHealth = oldFailure;
    let markEntered!: () => void;
    let release!: () => void;
    let markFinished!: () => void;
    const entered = new Promise<void>((resolve) => { markEntered = resolve; });
    const released = new Promise<void>((resolve) => { release = resolve; });
    const finished = new Promise<void>((resolve) => { markFinished = resolve; });
    held = { entered: markEntered, release: released, finished: markFinished };
    await page.getByTitle('Refresh', { exact: true }).click();
    await entered;
    failHealth = !oldFailure;
    await navigation.getByRole('button', { name: nextRoute, exact: true }).click();
    await expect(page.getByRole('status', { name: expectedLabel, exact: true })).toBeVisible();
    release();
    await finished;
    await page.waitForLoadState('networkidle');
    await expect(page.getByRole('status', { name: expectedLabel, exact: true })).toBeVisible();
    await expect(navigation.getByRole('button', { name: nextRoute, exact: true })).toBeFocused();
  }
  expect(guards.failures.request.every((failure) => failure.includes('/healthz: net::ERR_') || failure.endsWith('net::ERR_ABORTED'))).toBe(true);
  expect(guards.failures.console.every((failure) => failure.includes('net::ERR_FAILED'))).toBe(true);
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.http).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

referenceTest('worker loss is explicit and actionable in Jobs and Settings', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'worker-unavailable', generation: 1 } });
  await installQualityObservers(page);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');

  const unavailable = page.getByRole('status').filter({ hasText: 'Work processing unavailable' });
  await expect(unavailable).toBeVisible();
  await expect(unavailable).toContainText('Queued work is safe, but it will not start.');
  await expect(unavailable).toContainText('Run make up');
  await expect(unavailable).toContainText('Refresh');

  await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Work processing unavailable' })).toBeVisible();

  const accessibility = await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze();
  const seriousOrCritical = accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact || ''));
  expect(seriousOrCritical.map((violation) => violation.id)).toEqual([]);
  guards.assertClean();
});

referenceTest('Findings keeps revised selected detail busy before its request effect and until exact response', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(30_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let revised = false;
  let heldRequests = 0;
  let releaseDetail!: () => void;
  const detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
  await page.route('**/v1/scans/41/summary', async (route) => {
    const response = await route.fetch();
    const summary = await response.json();
    await route.fulfill({ response, json: revised ? {
      ...summary, revision: summary.revision + 1, findings_revision: summary.findings_revision + 1,
    } : summary });
  });
  await page.route('**/v1/scans/41/findings?*', async (route) => {
    const response = await route.fetch();
    const collection = await response.json();
    await route.fulfill({ response, json: {
      ...collection,
      revision: revised ? collection.revision + 1 : collection.revision,
      items: collection.items.map((finding: { id: number }) => finding.id === 514 ? {
        ...finding, advisor_verdict: 'generated_review', advisor_confidence: revised ? 0.6 : 0.5,
        revision: revised ? 2 : 1,
      } : finding),
    } });
  });
  await page.route(/\/v1\/scans\/41\/findings\/14(?:\?|$)/, async (route) => {
    const url = new URL(route.request().url());
    const revision = url.searchParams.get('expected_revision');
    expect(revision).toBe(revised ? '2' : '1');
    expect(url.searchParams.get('expected_findings_revision')).toBe(revision);
    if (revision === '2') { heldRequests += 1; await detailGate; }
    url.searchParams.set('expected_revision', '1');
    url.searchParams.set('expected_findings_revision', '1');
    const response = await route.fetch({ url: url.toString() });
    expect(response.status()).toBe(200);
    const finding = await response.json();
    await route.fulfill({ response, json: {
      ...finding, revision: Number(revision), findings_revision: Number(revision),
      ai_verdict: 'generated_review', ai_confidence: revision === '2' ? 0.6 : 0.5,
      ai_reasoning: `Generated focus evidence at revision ${revision === '2' ? 'two' : 'one'} remains local and deterministic.`,
      ai_fix: 'Validate the generated input before it reaches the sink.',
    } });
  });
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.goto('/?view=findings&scan=41&finding=14');
  const surface = page.locator('section[data-route-surface="findings"]');
  const detail = page.locator('.finding-detail[data-finding-id="514"]');
  const target = page.locator('.finding-list-item', { hasText: 'S41-F014' }).locator('.finding-list-main');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(detail).toHaveAttribute('aria-busy', 'false');
  await expect(target).toBeFocused();
  await page.waitForLoadState('networkidle');
  const before = await page.evaluate(() => {
    const section = document.querySelector<HTMLElement>('section[data-route-surface="findings"]')!;
    const detail = document.querySelector<HTMLElement>('.finding-detail[data-finding-id="514"]')!;
    const list = document.querySelector<HTMLElement>('.finding-list-scroll')!;
    const track = document.querySelector<HTMLElement>('.finding-list-track')!;
    const target = document.querySelector<HTMLButtonElement>('.finding-list-item.active .finding-list-main')!;
    const evidence = document.querySelector<HTMLElement>('[aria-label="Code evidence for src/generated-14.ts"]')!;
    const main = document.querySelector<HTMLElement>('main')!;
    const rows: Array<Record<string, unknown>> = [];
    let dropped = 0;
    let responseReleased = false;
    const capture = (cause: 'initial' | 'mutation' | 'scroll' | 'release' | 'final') => {
      const targetRect = target.getBoundingClientRect();
      const listRect = list.getBoundingClientRect();
      const row = {
        cause, responseReleased, revised: detail.querySelector('.advisor-verdict small')?.textContent === 'Confidence 60%',
        busy: detail.getAttribute('aria-busy') === 'true',
        detailError: detail.querySelector('[role="alert"]') !== null,
        rowsCommitted: Number(section.dataset.findingsCommittedCount),
        rowCount: track.querySelectorAll('.finding-list-item').length,
        scroll: { main: main.scrollTop, list: list.scrollTop, detail: detail.scrollTop, evidence: evidence.scrollTop },
        listHeight: list.clientHeight, listScrollHeight: list.scrollHeight,
        trackHeight: track.getBoundingClientRect().height,
        targetRect: { top: targetRect.top, bottom: targetRect.bottom },
        listRect: { top: listRect.top, bottom: listRect.bottom },
        targetPreserved: document.querySelector('.finding-list-item.active .finding-list-main') === target,
        evidencePreserved: document.querySelector('[aria-label="Code evidence for src/generated-14.ts"]') === evidence,
        targetFocused: document.activeElement === target,
      };
      if (rows.length < 128) rows.push(row); else dropped += 1;
      return row;
    };
    const initial = capture('initial');
    const observer = new MutationObserver(() => capture('mutation'));
    observer.observe(section, { attributes: true, childList: true, characterData: true, subtree: true });
    const onScroll = () => capture('scroll');
    for (const element of [main, list, detail, evidence]) element.addEventListener('scroll', onScroll);
    (window as Window & { __findingsRevisionProbe?: unknown }).__findingsRevisionProbe = {
      sample: () => ({ current: capture('final'), rows, dropped }),
      release: () => { responseReleased = true; capture('release'); },
      stop: () => { observer.disconnect(); for (const element of [main, list, detail, evidence]) element.removeEventListener('scroll', onScroll); },
    };
    return initial;
  });
  revised = true;
  const sample = () => page.evaluate(() => (window as Window & {
    __findingsRevisionProbe?: { sample: () => { current: Record<string, unknown>; rows: Array<{ responseReleased: boolean; revised: boolean; busy: boolean; detailError: boolean }>; dropped: number } };
  }).__findingsRevisionProbe!.sample());
  try {
    await expect.poll(() => heldRequests, { timeout: qualificationMilliseconds(15_000) }).toBe(1);
    await expect(detail.locator('.advisor-verdict small')).toHaveText('Confidence 60%');
    const held = await sample();
    await testInfo.attach('findings-held-revision-readiness.json', { body: Buffer.from(JSON.stringify({ before, held }, null, 2)), contentType: 'application/json' });
    expect(held.dropped).toBe(0);
    expect(held.rows.filter((row) => row.revised && !row.responseReleased && !row.busy && !row.detailError), 'no current-detail readiness before exact revision response').toEqual([]);
    expect(held.current).toMatchObject({ busy: true, targetPreserved: true, evidencePreserved: true, targetFocused: true });
    await expect(detail.getByRole('button', { name: 'Run Advisor', exact: true })).toBeDisabled();
    await page.evaluate(() => (window as Window & {
      __findingsRevisionProbe?: { release: () => void };
    }).__findingsRevisionProbe!.release());
    releaseDetail();
    await expect(detail).toHaveAttribute('aria-busy', 'false');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(detail.getByText('Generated focus evidence at revision two remains local and deterministic.', { exact: true })).toBeVisible();
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    const after = await sample();
    await testInfo.attach('findings-released-revision-readiness.json', { body: Buffer.from(JSON.stringify({ before, after }, null, 2)), contentType: 'application/json' });
    expect(after.dropped).toBe(0);
    expect(after.rows.filter((row) => row.revised && !row.responseReleased && !row.busy && !row.detailError), 'only post-release current detail may become ready').toEqual([]);
    expect(after.current).toMatchObject({ busy: false, revised: true, responseReleased: true, detailError: false, targetPreserved: true, evidencePreserved: true, targetFocused: true });
    expect(after.current.scroll, 'the revision update preserves all recorded scroll owners').toEqual(before.scroll);
    expect(heldRequests).toBe(1);
    guards.assertClean();
  } finally {
    releaseDetail();
    await page.evaluate(() => {
      const state = window as Window & { __findingsRevisionProbe?: { stop: () => void } };
      state.__findingsRevisionProbe?.stop(); delete state.__findingsRevisionProbe;
    });
  }
});

referenceTest('finding navigation waits for the exact staged detail before claiming focus', async ({ page }) => {
  const { readFileSync } = await import('node:fs');
  const { transpileModule, ModuleKind, ScriptTarget } = await import('typescript');
  const helper = transpileModule(readFileSync(new URL('../../../apps/web/src/findingNavigation.ts', import.meta.url), 'utf8'),
    { compilerOptions: { module: ModuleKind.ESNext, target: ScriptTarget.ES2022 } }).outputText;
  await page.setContent(`<main><div class="finding-workspace" style="width:320px">
    <div class="finding-list-scroll" style="height:180px;overflow:auto">
      <div style="height:400px"></div><div class="finding-list-item"><button class="finding-list-main">S41-F014</button></div>
    </div>
    <article class="finding-detail" data-finding-id="1" aria-busy="true" inert>
      <div class="finding-detail-identity"><h2 tabindex="-1">S41-F014</h2></div>
    </article>
  </div></main>`);
  await page.addScriptTag({ type: 'module', content: `${helper}
    window.focusedCount = 0;
    window.stopFindingNavigation = revealFindingNavigation(document.querySelector('.finding-list-item'), 14,
      () => true, () => { window.focusedCount += 1; });` });
  const frames = () => page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await frames();
  await expect(page.locator('.finding-list-main')).not.toBeFocused();
  await page.locator('.finding-detail').evaluate((element) => {
    (element as HTMLElement).dataset.findingId = '14';
    element.setAttribute('aria-busy', 'false');
  });
  await frames();
  await expect(page.locator('.finding-detail h2')).not.toBeFocused();
  await page.locator('.finding-detail').evaluate((element) => element.removeAttribute('inert'));
  await expect(page.locator('.finding-detail h2')).toBeFocused();
  await expect(page.locator('.finding-detail h2')).toBeInViewport({ ratio: 1 });
  expect(await page.evaluate(() => (window as unknown as { focusedCount: number }).focusedCount)).toBe(1);
  await page.evaluate(() => (window as unknown as { stopFindingNavigation: () => void }).stopFindingNavigation());
});

for (const width of [320, 390, 768]) {
  referenceTest(`narrow finding deep links reveal the selected detail at ${width}px`, async ({ page, request, baseURL }, testInfo) => {
    if (!baseURL) throw new Error('Playwright baseURL is required.');
    await page.setViewportSize({ width, height: 900 });
    await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    await page.goto('/?view=findings&scan=41&finding=14');
    const heading = page.locator('.finding-detail h2');
    const row = page.locator('.finding-list-item', { hasText: 'S41-F014' });
    await expect(heading).toHaveText('S41-F014');
    await expect(heading).toBeFocused();
    await expect(heading).toBeInViewport({ ratio: 1 });
    await expect(row).toHaveClass(/active/);
    const listOffset = await page.locator('.finding-list-scroll').evaluate((element) => element.scrollTop);
    expect(listOffset, 'the selected row remains reachable when returning to the list').toBeGreaterThan(0);
    await testInfo.attach(`narrow-finding-${width}.png`, { body: await page.screenshot(), contentType: 'image/png' });

    // An ordinary background refresh must not pull a reader back to the list
    // or steal focus after the explicit navigation has been fulfilled.
    const control = page.getByLabel('Max height');
    await control.focus();
    const position = await page.locator('main').evaluate((element) => element.scrollTop);
    await page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/scans/41/summary',
      { timeout: qualificationMilliseconds(15_000) });
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await expect(control).toBeFocused();
    expect(await page.locator('main').evaluate((element) => element.scrollTop)).toBe(position);
    expect(await page.locator('.finding-list-scroll').evaluate((element) => element.scrollTop)).toBe(listOffset);
    guards.assertClean();
  });
}

referenceTest('job and deep-link navigation focus the exact offender without polling reset', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Jobs');

  await page.getByRole('button', { name: /Open S41-F014/ }).click();
  await expect(page).toHaveURL(/\?view=findings&scan=41&finding=14$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Findings' })).toBeVisible();

  const target = page.locator('.finding-list-item', { hasText: 'S41-F014' });
  const targetButton = target.locator('.finding-list-main');
  await expect(target).toHaveClass(/active/);
  await expect(targetButton).toBeFocused();
  await expect(page.locator('.code-row.offender .code-line-number')).toHaveText('44');
  expect(await page.locator('.finding-list-scroll').evaluate((element) => element.scrollTop), 'job navigation scroll offset').toBeGreaterThan(0);

  const evidence = page.getByLabel('Code evidence for src/generated-14.ts');
  const resizeControl = page.getByLabel('Max height');
  const initialEvidenceHeight = await evidence.evaluate((element) => element.clientHeight);
  expect(await evidence.evaluate((element) => element.scrollHeight), 'evidence is initially bounded').toBeGreaterThan(initialEvidenceHeight);
  await resizeControl.focus();
  await resizeControl.press('End');
  await expect(resizeControl).toHaveValue('900');
  const enlargedEvidenceHeight = await evidence.evaluate((element) => element.clientHeight);
  expect(enlargedEvidenceHeight, 'keyboard enlargement reveals more evidence').toBeGreaterThan(initialEvidenceHeight);
  await resizeControl.press('Home');
  await expect(resizeControl).toHaveValue('180');
  expect(await evidence.evaluate((element) => element.clientHeight), 'keyboard contraction restores a bounded pane').toBeLessThan(enlargedEvidenceHeight);

  type RefreshCycle = {
    artifacts: number;
    findings: number;
    summaryRequests: number;
    summaryResponses: number;
  };
  const refreshCycles: RefreshCycle[] = [];
  const summaryRequestCycles = new WeakMap<Request, RefreshCycle>();
  let trackReload = false;
  const observeReloadCommit = (frame: Frame) => {
    if (frame !== page.mainFrame()) return;
    // Commit is the clean boundary: old-document polling can no longer race
    // into the new document's refresh-cycle evidence.
    trackReload = true;
    refreshCycles.length = 0;
  };
  const observeRefreshRequest = (browserRequest: Request) => {
    const url = new URL(browserRequest.url());
    if (!trackReload || browserRequest.method() !== 'GET') return;
    if (url.pathname === '/v1/jobs' && !url.searchParams.has('status')) {
      refreshCycles.push({ artifacts: 0, findings: 0, summaryRequests: 0, summaryResponses: 0 });
    }
    const activeCycle = refreshCycles.at(-1);
    if (!activeCycle) return;
    if (/^\/v1\/scans\/\d+\/findings$/.test(url.pathname)) activeCycle.findings += 1;
    if (/^\/v1\/scans\/\d+\/artifacts$/.test(url.pathname)) activeCycle.artifacts += 1;
    if (/^\/v1\/scans\/\d+\/summary$/.test(url.pathname)) {
      activeCycle.summaryRequests += 1;
      summaryRequestCycles.set(browserRequest, activeCycle);
    }
  };
  const observeRefreshCompletion = (browserRequest: Request) => {
    const cycle = summaryRequestCycles.get(browserRequest);
    if (cycle) cycle.summaryResponses += 1;
  };
  page.on('framenavigated', observeReloadCommit);
  page.on('request', observeRefreshRequest);
  page.on('requestfinished', observeRefreshCompletion);
  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings' })).toBeVisible();
  await expect(target).toHaveClass(/active/);
  await expect(targetButton).toBeFocused();
  await expect(page.locator('.code-row.offender .code-line-number')).toHaveText('44');
  await expect.poll(() => refreshCycles[0]?.findings ?? 0, { timeout: qualificationMilliseconds(5_000) }).toBeGreaterThanOrEqual(1);
  await expect.poll(() => refreshCycles[0]?.artifacts ?? 0, { timeout: qualificationMilliseconds(5_000) }).toBeGreaterThanOrEqual(1);
  await expect.poll(() => refreshCycles[0]?.summaryResponses ?? 0, { timeout: qualificationMilliseconds(5_000) }).toBeGreaterThanOrEqual(2);
  expect(refreshCycles[0], 'reload revision-fenced detail requests').toEqual({
    artifacts: 1,
    findings: 1,
    summaryRequests: 2,
    summaryResponses: 2,
  });

  const scrollBeforePoll = await page.locator('.finding-list-scroll').evaluate((element) => element.scrollTop);
  // Always observe a complete refresh that starts after the scroll sample. An
  // unchanged authoritative summary must end the poll without reloading the
  // finding pages or artifacts.
  const pollCycleIndex = refreshCycles.length;
  await expect.poll(() => refreshCycles[pollCycleIndex]?.summaryResponses ?? 0, { timeout: qualificationMilliseconds(15_000) }).toBeGreaterThanOrEqual(1);
  // Cross the fetch continuation and two paints before proving the absence of
  // a late detail reload after the unchanged summary response.
  await page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
  expect(refreshCycles[pollCycleIndex], 'unchanged summary-only poll').toEqual({
    artifacts: 0,
    findings: 0,
    summaryRequests: 1,
    summaryResponses: 1,
  });
  await expect(target).toHaveClass(/active/);
  await expect(targetButton).toBeFocused();
  expect(await page.locator('.finding-list-scroll').evaluate((element) => element.scrollTop), 'poll preserves list scroll').toBe(scrollBeforePoll);
  await testInfo.attach('deep-link-refresh-cycles.json', {
    body: Buffer.from(JSON.stringify(refreshCycles, null, 2)),
    contentType: 'application/json',
  });
  page.off('framenavigated', observeReloadCommit);
  page.off('request', observeRefreshRequest);
  page.off('requestfinished', observeRefreshCompletion);
  guards.assertClean();
});

for (const kind of ['native-windows', 'git-commit'] as const) {
  referenceTest(`Projects keeps ${kind} guidance stable during source-boundary reconciliation`, async ({ page, request }) => {
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    await page.route('**/v1/projects', async route => {
      const response = await route.fetch();
      const projects = await response.json();
      await route.fulfill({ response, json: [{ ...projects[0],
        repo_path: `/source-snapshots/${kind}/${'a'.repeat(64)}` }] });
    });
    await openRoute(page, 'Overview');
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    let observed!: () => void;
    const intercepted = new Promise<void>(resolve => { observed = resolve; });
    await page.route('**/v1/config', async route => {
      observed();
      await held;
      await route.fallback();
    });
    const sourceStep = page.getByLabel('Step 2: Source authorization and registration');
    let before: Awaited<ReturnType<typeof sourceStep.boundingBox>>;
    let text: string;
    try {
      await page.getByRole('navigation').getByRole('button', { name: 'Projects', exact: true }).click();
      await intercepted;
      // The snapshot workflow is already known from its project identity. A
      // delayed host-mount check cannot turn it into a different source kind.
      await expect(sourceStep.getByText('VS Code required', { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Scan', exact: true })).toBeDisabled();
      before = await sourceStep.boundingBox();
      text = await sourceStep.innerText();
    } finally { release(); }
    await page.waitForLoadState('networkidle');
    await expect(sourceStep).toHaveText(text!, { useInnerText: true });
    expect(await sourceStep.boundingBox()).toEqual(before!);
    await expect(sourceStep).toHaveAttribute('data-complete', 'false');
    await expect(page.getByRole('button', { name: 'Scan', exact: true })).toBeDisabled();
    expect(await (await request.get('/__test/commands')).json()).toEqual([]);
  });

  referenceTest(`Findings exact ${kind} snapshot protection binding`, async ({ page, request, baseURL }, testInfo) => {
    if (!baseURL) throw new Error('Playwright baseURL is required.');
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    const repositoryId = 'a'.repeat(64);
    const sourceId = kind === 'native-windows'
      ? '7766a19c7506e6c256c14c9ed23f90a6436d719aee5f1454824c44e67301abcf' : repositoryId;
    const sourcePath = `/source-snapshots/${kind}/${sourceId}`;
    const root = kind === 'native-windows' ? 'C:\\Users\\Café\\repo' : '/workspace/generated/demo-service';
    const exact = { repository_id: repositoryId, project_id: 11, name: 'Exact snapshot source', root_path: root,
      git_directory: `${root}${kind === 'native-windows' ? '\\' : '/'}.git`, revision: 2, enabled: true,
      observed_state: 'installed', observed_revision: 2, observed_at: '2026-08-12T08:00:00Z',
      hook_digest: 'b'.repeat(64), reason_code: null, members: [] };
    let records = [exact];
    await page.route('**/v1/projects', async (route) => {
      const response = await route.fetch();
      const projects = await response.json();
      await route.fulfill({ response, json: projects.map((project: { id: number }) => project.id === 11
        ? { ...project, repo_path: sourcePath } : project) });
    });
    await page.route('**/v1/git/push-protection', (route) => route.fulfill({ json: { repositories: records } }));
    await page.goto('/?view=findings&scan=41&finding=1');
    const context = page.getByLabel('Repository push protection', { exact: true });
    await expect(context.getByRole('status')).toContainText('On · last verified');
    await testInfo.attach(`${kind}-exact-protection.png`, { body: await context.screenshot(), contentType: 'image/png' });
    records = [{ ...exact, project_id: 12 }];
    await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
    await expect(context.getByRole('status')).toContainText('No matching protection record');
    records = [kind === 'native-windows' ? { ...exact, root_path: 'C:\\Users\\Café\\neighbor' }
      : { ...exact, repository_id: 'c'.repeat(64) }];
    await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
    await expect(context.getByRole('status')).toContainText('No matching protection record');
    records = [exact, exact];
    await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
    await expect(context.getByRole('status')).toContainText('Choose repository protection');
    records = [exact];
    await context.getByRole('button', { name: 'Refresh repository push protection' }).click();
    await expect(context.getByRole('status')).toContainText('On · last verified');
    await context.getByRole('button', { name: 'Manage push protection' }).click();
    await expect(page).toHaveURL(new RegExp(`#git-push-protection-${repositoryId}$`));
    await expect(page.locator(`#git-push-protection-${repositoryId}`)).toBeFocused();
    guards.assertClean();
  });
}

referenceTest('Findings rejects an obsolete native digest after focus refresh', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.addInitScript(() => {
    const original = crypto.subtle.digest.bind(crypto.subtle);
    let held = false;
    crypto.subtle.digest = async (algorithm, bytes) => {
      const raw = ArrayBuffer.isView(bytes) ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength) : new Uint8Array(bytes);
      if (!held && new TextDecoder().decode(raw).startsWith('native-windows\0')) {
        held = true;
        await new Promise<void>((resolve) => {
          (window as Window & { __releaseSourceDigest?: () => void }).__releaseSourceDigest = resolve;
        });
      }
      return original(algorithm, bytes);
    };
  });
  await page.route('**/v1/projects', async (route) => {
    const response = await route.fetch(); const projects = await response.json();
    await route.fulfill({ response, json: projects.map((project: { id: number }) => project.id === 11
      ? { ...project, repo_path: '/source-snapshots/native-windows/7766a19c7506e6c256c14c9ed23f90a6436d719aee5f1454824c44e67301abcf' } : project) });
  });
  const exact = { repository_id: 'a'.repeat(64), project_id: 11, name: 'Held native source',
    root_path: 'C:\\Users\\Café\\repo', git_directory: 'C:\\Users\\Café\\repo\\.git',
    revision: 2, enabled: true, observed_state: 'installed', observed_revision: 2,
    observed_at: '2026-08-12T08:00:00Z', hook_digest: 'b'.repeat(64), reason_code: null, members: [] };
  let records = [exact];
  await page.route('**/v1/git/push-protection', (route) => route.fulfill({ json: { repositories: records } }));
  await page.goto('/?view=findings&scan=41&finding=1');
  const context = page.getByLabel('Repository push protection', { exact: true });
  await expect.poll(() => page.evaluate(() => Boolean((window as Window & { __releaseSourceDigest?: () => void }).__releaseSourceDigest))).toBe(true);
  await expect(context.getByRole('status')).toContainText('Checking protection…');
  records = [{ ...exact, root_path: 'C:\\Users\\Café\\neighbor' }];
  await page.evaluate(() => dispatchEvent(new Event('focus')));
  await expect(context.getByRole('status')).toContainText('No matching protection record');
  await page.evaluate(() => (window as Window & { __releaseSourceDigest?: () => void }).__releaseSourceDigest!());
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(context.getByRole('status')).toContainText('No matching protection record');
  guards.assertClean();
});

referenceTest('WEB-JOBS-RECOVERY-001 checks uncertain cache outcome without retrying preparation', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.clock.setFixedTime('2026-09-30T00:16:00Z');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  // Source-bound supporting fixture only: these responses exercise the real
  // Web handler, not a native updater, real database or published cache proof.
  const original = { id: 42, kind: 'scanner_cache_update', title: 'Prepare scanner data', status: 'failed',
    stage: 'committing', revision: 7, attempt: 1, max_attempts: 1, can_retry: false, can_cancel: false,
    error_code: 'scanner_preparation_commit_uncertain', error_detail: 'Publication outcome remains uncertain after the preparation deadline.',
    created_at: '2026-09-30T00:00:00Z', updated_at: '2026-09-30T00:15:00Z' };
  const before = structuredClone(original);
  const jobs: Array<Record<string, unknown>> = [original];
  const lifecycle = await (await request.get('/v1/scanner/lifecycle')).json();
  lifecycle.cache = { ...lifecycle.cache, status: 'failed', revision: 2, job_id: original.id,
    error_code: original.error_code, error_detail: original.error_detail };
  const commands: { body: unknown; csrf_present: boolean; key: string }[] = [];
  await page.route(/\/v1\/jobs(?:\?.*)?$/u, route => {
    const active = new URL(route.request().url()).searchParams.get('status') === 'active';
    return route.fulfill({ json: jobs.filter(job => !active || ['queued', 'leased', 'running', 'cancelling'].includes(String(job.status))) });
  });
  await page.route(/\/v1\/jobs\/(42|43)$/u, route => route.fulfill({ json: jobs.find(job => job.id === Number(new URL(route.request().url()).pathname.split('/').at(-1))) }));
  await page.route('**/v1/scanner/lifecycle', route => route.fulfill({ json: lifecycle }));
  await page.route('**/v1/jobs/42/reconcile', async route => {
    const outgoing = route.request();
    commands.push({ body: outgoing.postDataJSON(), csrf_present: Boolean(outgoing.headers()['x-csrf-token']), key: outgoing.headers()['idempotency-key'] });
    const job = { id: 43, original_job_id: 42, kind: 'scanner_cache_reconcile', title: 'Reconcile cache outcome', status: 'queued', stage: 'queued',
      revision: 1, attempt: 0, max_attempts: 1, can_retry: false, can_cancel: true, created_at: '2026-09-30T00:16:00Z', updated_at: '2026-09-30T00:16:00Z' };
    jobs.unshift(job);
    lifecycle.cache = { ...lifecycle.cache, status: 'queued', revision: 3, job_id: 43, error_code: null, error_detail: null };
    await route.fulfill({ status: 202, json: { job, lifecycle: lifecycle.cache, original_job_id: 42 } });
  });
  await openRoute(page, 'Jobs');
  const row = page.getByLabel(/^Job #42:/);
  const check = row.getByRole('button', { name: 'Check cache outcome', exact: true });
  await expect(row.locator('.job-status-cell')).toHaveText('Failed');
  await expect(row.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
  await expect(check).toHaveAttribute('aria-describedby', 'job-42-cache-outcome');
  for (const scale of [1, 2]) {
    if (scale === 2) await page.evaluate(() => {
      const sizes = [...document.querySelectorAll<HTMLElement>('*')].filter(element => element instanceof HTMLElement)
        .map(element => ({ element, size: parseFloat(getComputedStyle(element).fontSize), leading: parseFloat(getComputedStyle(element).lineHeight) }));
      for (const { element, size, leading } of sizes) {
        element.style.fontSize = `${size * 2}px`;
        if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
      }
    });
    for (const width of [320, 390, 768, 1440, 1920]) {
      await page.setViewportSize({ width, height: 844 });
      const search = page.getByRole('textbox', { name: 'Search jobs', exact: true });
      await search.focus(); await search.press('Tab');
      const status = page.getByRole('combobox', { name: 'Job status', exact: true });
      await expect(status).toBeFocused(); await status.press('Tab');
      const kind = page.getByRole('combobox', { name: 'Job kind', exact: true });
      await expect(kind).toBeFocused(); await kind.press('Tab');
      await expect(check).toBeFocused(); await expect(check).toBeInViewport();
      const geometry = await check.evaluate(button => {
        const box = button.getBoundingClientRect();
        const range = document.createRange(); range.selectNodeContents(button);
        const glyphs = range.getBoundingClientRect();
        return { left: box.left, right: box.right, glyphLeft: glyphs.left, glyphRight: glyphs.right,
          scroll: button.scrollWidth, client: button.clientWidth, viewport: innerWidth, pageWidth: document.documentElement.scrollWidth };
      });
      expect(geometry.left).toBeGreaterThanOrEqual(0);
      expect(geometry.right).toBeLessThanOrEqual(width + 1);
      expect(geometry.glyphLeft).toBeGreaterThanOrEqual(geometry.left - 1);
      expect(geometry.glyphRight).toBeLessThanOrEqual(geometry.right + 1);
      expect(geometry.scroll).toBeLessThanOrEqual(geometry.client + 1);
      expect(geometry.pageWidth).toBeLessThanOrEqual(width + 1);
      await testInfo.attach(`cache-outcome-${width}-text-${scale * 100}.png`, { body: await row.screenshot(), contentType: 'image/png' });
      expect(commands).toEqual([]);
    }
  }
  // Reset fixture text enlargement before creating new DOM nodes.
  await reloadAfterReads(page);
  await check.press('Enter');
  await expect.poll(() => commands.length).toBe(1);
  expect(commands[0].body).toEqual({ expected_revision: 7 });
  expect(commands[0].csrf_present).toBe(true);
  expect(commands[0].key).toMatch(/^web-[a-f0-9-]{36}$/u);
  await expect(row.locator('.job-status-cell')).toHaveText('Failed');
  expect(original).toEqual(before);
  const recovery = page.getByLabel(/^Job #43:/);
  await expect(recovery).toHaveAttribute('data-job-id', '43');
  await expect(recovery.locator('.job-meta')).toContainText('Cache outcome check');
  await expect(recovery.getByText(/The original preparation remains failed\./u)).toBeVisible();
  await expect(recovery.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
  await expect(check).toHaveCount(0);
  await expect(row.getByRole('button', { name: 'View outcome check #43', exact: true })).toBeVisible();
  await expect(recovery.getByRole('button', { name: 'Preparation #42', exact: true })).toBeVisible();
  const captureOutcomeState = async (state: string) => {
    for (const [width, scale] of [[1440, 1], [390, 1], [320, 2]] as const) {
      await page.setViewportSize({ width, height: 844 });
      await reloadAfterReads(page);
      await expect(recovery.locator('.job-meta')).toContainText('Cache outcome check');
      if (scale === 2) await page.evaluate(() => {
        const sizes = [...document.querySelectorAll<HTMLElement>('*')].filter(element => element instanceof HTMLElement)
          .map(element => ({ element, size: parseFloat(getComputedStyle(element).fontSize), leading: parseFloat(getComputedStyle(element).lineHeight) }));
        for (const { element, size, leading } of sizes) {
          element.style.fontSize = `${size * 2}px`;
          if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
        }
      });
      await recovery.scrollIntoViewIfNeeded();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1);
      const link = recovery.getByRole('button', { name: 'Preparation #42', exact: true });
      const geometry = await link.evaluate(button => ({ right: button.getBoundingClientRect().right, width: button.clientWidth, scroll: button.scrollWidth }));
      expect(geometry.right).toBeLessThanOrEqual(width + 1);
      expect(geometry.scroll).toBeLessThanOrEqual(geometry.width + 1);
      expect(await link.locator('svg').evaluate(icon => icon.getBoundingClientRect().width)).toBeGreaterThanOrEqual(14);
      await testInfo.attach(`cache-check-${state}-${width}-text-${scale * 100}.png`, { body: await recovery.screenshot(), contentType: 'image/png' });
    }
  };
  await captureOutcomeState('queued');
  await recovery.getByRole('button', { name: 'Preparation #42', exact: true }).click();
  await expect(row).toHaveAttribute('aria-current', 'true');
  await row.getByRole('button', { name: 'View outcome check #43', exact: true }).click();
  await expect(recovery).toHaveAttribute('aria-current', 'true');
  jobs[0] = { ...jobs[0], status: 'completed', stage: 'completed', revision: 2, can_cancel: false };
  lifecycle.cache = { ...lifecycle.cache, status: 'completed', revision: 4, receipt: { kind: 'reconciliation' } };
  await reloadAfterReads(page);
  await expect(recovery.locator('.job-status-cell')).toHaveText('Completed');
  await expect(recovery.locator('#job-43-cache-outcome')).toHaveClass('helper-text');
  await expect(recovery.locator('#job-43-cache-outcome')).toContainText('Cache outcome verified.');
  await expect(row.locator('.job-status-cell')).toHaveText('Failed');
  await expect(recovery.getByText(/The original preparation remains failed\./u)).toBeVisible();
  await expect(check).toHaveCount(0);
  await expect(row.getByRole('button', { name: 'View outcome check #43', exact: true })).toBeVisible();
  await captureOutcomeState('completed');
  expect(commands).toHaveLength(1);
  expect(await (await request.get('/__test/commands')).json()).toEqual([]);
  await testInfo.attach('source-fixture-cache-check-command.json', { body: Buffer.from(JSON.stringify({ classification: 'source-bound supporting Web fixture', commands, original_unchanged: original })), contentType: 'application/json' });
  await page.waitForLoadState('networkidle'); guards.assertClean();
});


referenceTest('Settings sections preserve drafts and reflow without clipped controls', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(60_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');
  const directory = page.getByRole('navigation', { name: 'Settings sections', exact: true });
  await expect(directory.getByRole('link')).toHaveCount(5);
  const gateForm = page.locator('[data-settings-form="gate"]');
  const draft = gateForm.locator('input[type="number"]').last();
  await draft.fill('9');
  for (const name of ['Workspace access', 'Advisor', 'Trusted access', 'Installation', 'Protection']) {
    await directory.getByRole('link', { name, exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toHaveCount(1);
    await expect(draft, `${name} navigation preserves unsaved gate input`).toHaveValue('9');
  }
  for (const width of [1920, 1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const geometry = await page.locator('.settings-workbench').evaluate((workbench) => {
      const controls = Array.from(workbench.querySelectorAll<HTMLElement>('button, input, select, nav a, .settings-section-heading'))
        .filter((item) => item.getClientRects().length > 0);
      return { documentOverflow: document.documentElement.scrollWidth - innerWidth,
        controls: controls.map((item) => { const rect = item.getBoundingClientRect(); return {
          label: item.getAttribute('aria-label') || item.textContent?.slice(0, 80) || item.tagName,
          left: rect.left, right: rect.right, overflow: item.scrollWidth - item.clientWidth,
          tag: item.tagName,
        }; }) };
    });
    expect(geometry.documentOverflow, `${width}px document reflow`).toBeLessThanOrEqual(1);
    for (const control of geometry.controls) {
      expect(control.left, `${width}px ${control.label} left`).toBeGreaterThanOrEqual(-0.5);
      expect(control.right, `${width}px ${control.label} right`).toBeLessThanOrEqual(width + 0.5);
      if (!['INPUT', 'SELECT'].includes(control.tag)) expect(control.overflow, `${width}px ${control.label} clipping`).toBeLessThanOrEqual(1);
    }
    if ([1440, 390].includes(width)) {
      await page.locator('main').evaluate((element) => { element.scrollTop = 0; });
      await page.evaluate(() => window.scrollTo(0, 0));
      await testInfo.attach(`settings-sections-${width}.png`, { body: await page.screenshot(), contentType: 'image/png' });
    }
  }
  await page.setViewportSize({ width: 768, height: 1024 });
  await page.evaluate(() => {
    const sizes = Array.from(document.querySelectorAll<HTMLElement>('*')).map((element) => {
      const style = getComputedStyle(element);
      return { element, font: parseFloat(style.fontSize), line: parseFloat(style.lineHeight) };
    });
    for (const { element, font, line } of sizes) {
      if (Number.isFinite(font)) element.style.fontSize = `${font * 2}px`;
      if (Number.isFinite(line)) element.style.lineHeight = `${line * 2}px`;
    }
  });
  for (const width of [768, 390, 320]) {
    await page.setViewportSize({ width, height: 1024 });
    const geometry = await page.evaluate(inspectControlLayout);
    expect(geometry.documentOverflow, `${width}px actual 200% text enlargement`).toBeLessThanOrEqual(1);
    expect(geometry.offscreenControls, `${width}px all Settings controls remain within the viewport`).toEqual([]);
    expect(geometry.selfClippedControls, `${width}px Settings action labels wrap without clipping`).toEqual([]);
    const panel = page.locator('#source-boundary');
    const controls = panel.locator('button, input, select');
    expect(await controls.count()).toBeGreaterThan(2);
    for (const control of await controls.all()) {
      await control.scrollIntoViewIfNeeded();
      expect(await control.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const target = document.elementFromPoint((bounds.left + bounds.right) / 2, (bounds.top + bounds.bottom) / 2);
        return target !== null && element.contains(target);
      }), 'enlarged source-boundary control owns its target').toBe(true);
    }
    await testInfo.attach(`settings-source-text-200-${width}.png`, { body: await panel.screenshot(), contentType: 'image/png' });
  }
  const violations = (await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze()).violations
    .filter((item) => ['serious', 'critical'].includes(item.impact || ''));
  expect(violations.map((item) => ({ id: item.id, impact: item.impact }))).toEqual([]);
  guards.assertClean();
});

referenceTest('compact code evidence starts at the offender and expands without losing captured code', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=findings&scan=41&finding=14');
  const evidence = page.getByLabel('Code evidence for src/generated-14.ts', { exact: true });
  await expect(evidence).toBeVisible();
  await expect(page.getByLabel('Max height')).toHaveValue('220');
  const source = await evidence.locator('.code-source').textContent();
  const initial = await evidence.evaluate((element) => {
    const viewport = element.getBoundingClientRect();
    const offender = element.querySelector('.offender')!.getBoundingClientRect();
    return { height: element.clientHeight, scrollTop: element.scrollTop, visible: offender.top >= viewport.top && offender.bottom <= viewport.bottom };
  });
  expect(initial.height).toBeLessThanOrEqual(220);
  expect(initial.scrollTop).toBeGreaterThan(0);
  expect(initial.visible, 'offender visible in initial compact context').toBe(true);
  await page.getByRole('button', { name: 'More code', exact: true }).click();
  expect(await evidence.evaluate((element) => element.clientHeight)).toBeGreaterThan(initial.height);
  await expect(evidence.locator('.code-source')).toHaveText(source!);
  await page.getByRole('button', { name: 'Compact code', exact: true }).click();
  expect(await evidence.evaluate((element) => element.clientHeight)).toBe(initial.height);
  await testInfo.attach('compact-finding.png', { body: await page.screenshot(), contentType: 'image/png' });
  guards.assertClean();
});

referenceTest('related location reports navigate independently without merging findings', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const location = { file_path: 'src/generated-14.ts', start_line: 44, end_line: 44, start_column: 1, end_column: 12 };
  await page.route('**/v1/scans/41/findings?*', async (route) => {
    const response = await route.fetch();
    const result = await response.json();
    await route.fulfill({ response, json: { ...result, items: result.items.map((finding: { id: number }) => [514, 513].includes(finding.id)
      ? { ...finding, ...location } : finding) } });
  });
  await page.route(/\/v1\/scans\/41\/findings\/(14|13)(?:\?|$)/, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...await response.json(), ...location } });
  });
  await page.goto('/?view=findings&scan=41&finding=14');
  const reports = page.getByRole('region', { name: 'Other reports at this location in this view', exact: true });
  await expect(reports).toContainText('reports may describe different issues');
  await expect(reports.getByRole('button')).toHaveCount(1);
  await reports.getByRole('button', { name: /S41-F013/ }).click();
  await expect(page).toHaveURL(/finding=13$/);
  await expect(page.locator('.finding-detail h2')).toHaveText('S41-F013');
  await expect(reports.getByRole('button', { name: /S41-F014/ })).toBeVisible();
  await expect(page.locator('.finding-list-item', { hasText: 'S41-F014' })).toHaveCount(1);
  await expect(page.locator('.finding-list-item', { hasText: 'S41-F013' })).toHaveCount(1);
  guards.assertClean();
});

referenceTest('compact navigation retains icons and wraps without clipping', async ({ page }, testInfo) => {
  await openRoute(page, 'Overview');
  const navigation = page.getByRole('navigation', { name: 'Workbench views', exact: true });
  for (const scale of [1, 2]) {
    if (scale === 2) await page.evaluate(() => {
      const metrics = [...document.querySelectorAll<HTMLElement>('.side, .side *')]
        .map(element => ({ element, size: parseFloat(getComputedStyle(element).fontSize),
          leading: parseFloat(getComputedStyle(element).lineHeight) }));
      for (const { element, size, leading } of metrics) {
        element.style.fontSize = `${size * 2}px`;
        if (Number.isFinite(leading)) element.style.lineHeight = `${leading * 2}px`;
      }
    });
    for (const width of [320, 390, 768, 1024, 1264, 1440, 1920]) {
      await page.setViewportSize({ width, height: 600 });
      const buttons = navigation.getByRole('button');
      await expect(buttons).toHaveCount(7);
      for (const button of await buttons.all()) {
        await expect(button.locator('svg')).toBeVisible();
        const size = await button.evaluate(element => {
          const box = element.getBoundingClientRect();
          return { left: box.left, right: box.right, scroll: element.scrollWidth,
            client: element.clientWidth, height: box.height };
        });
        expect(size.left).toBeGreaterThanOrEqual(0);
        expect(size.right).toBeLessThanOrEqual(width + 1);
        expect(size.scroll).toBeLessThanOrEqual(size.client + 1);
        expect(size.height).toBeGreaterThanOrEqual(36);
      }
      const boxes = await buttons.evaluateAll(elements => elements.map(element => {
        const r = element.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom };
      }));
      for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i], b = boxes[j];
        expect(a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top).toBe(true);
      }
      await testInfo.attach(`navigation-${width}-text-${scale * 100}.png`, {
        body: await page.locator('.side').screenshot(), contentType: 'image/png',
      });
    }
  }
});
