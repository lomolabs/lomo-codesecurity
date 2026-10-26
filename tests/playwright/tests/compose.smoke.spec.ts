import { expect, Page, test } from '@playwright/test';

import {
  axeBuilder,
  assertStableSurface,
  installQualityObservers,
  installRuntimeGuards,
  resetQualityWindow,
} from './support/quality.js';
import {
  LiveWebActionError,
  runLiveWebActionLedger,
} from './support/live-action-ledger.mjs';

const routes = ['Overview', 'Projects', 'Jobs', 'Scans', 'Findings', 'Tools', 'Settings'] as const;

async function openRoute(page: Page, route: typeof routes[number]) {
  const renderedView = route.toLowerCase();
  await page.getByRole('navigation').getByRole('button', { name: route, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: route, exact: true })).toBeVisible();
  await expect(page.locator('main')).toHaveAttribute('data-rendered-view', renderedView);
  const surface = page.locator(`main > section[data-route-surface="${renderedView}"]`);
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  if (route === 'Findings') {
    await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
  }
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => window.scrollTo(0, 0));
}

test('isolated Compose control plane survives restart and serves every authenticated route', async ({ page, request, baseURL }, testInfo) => {
  test.setTimeout(90_000);
  if (!baseURL) throw new Error('Compose smoke baseURL is required.');
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await installQualityObservers(page);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);

  const session = await request.get('/v1/auth/session');
  expect(session.status()).toBe(200);
  expect(await session.json()).toMatchObject({ authenticated: true });

  await page.goto('/?view=overview');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { level: 1, name: 'Pair this browser', exact: true })).toHaveCount(0);

  const accessibilityResults: Record<string, unknown>[] = [];
  for (const route of routes) {
    await openRoute(page, route);
    if (route === 'Projects') {
      await expect(page.locator('.project-row strong', { hasText: 'Generated Compose Smoke Project' })).toBeVisible();
    }
    await resetQualityWindow(page);
    await assertStableSurface(page, testInfo);

    const accessibility = await axeBuilder(page).withTags(['wcag2a', 'wcag2aa']).analyze();
    const seriousOrCritical = accessibility.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact || ''));
    accessibilityResults.push({
      route,
      violations: accessibility.violations.map((violation) => ({ id: violation.id, impact: violation.impact, nodes: violation.nodes.length })),
    });
    expect(seriousOrCritical, `${route} serious or critical WCAG A/AA violations`).toEqual([]);

    await testInfo.attach(`compose-${route.toLowerCase()}.png`, {
      body: await page.screenshot({ animations: 'disabled', caret: 'hide', fullPage: false }),
      contentType: 'image/png',
    });
  }
  await testInfo.attach('compose-accessibility.json', {
    body: Buffer.from(JSON.stringify(accessibilityResults, null, 2)),
    contentType: 'application/json',
  });
  guards.assertClean();
});

test('[WEB-LIVE] real Compose foreground journey records visible and backend effects', async ({ page, request, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'Mutating real-Compose operator actions run once.');
  test.setTimeout(180_000);
  if (!baseURL) throw new Error('Compose smoke baseURL is required.');
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.goto('/?view=overview');
  await openRoute(page, 'Projects');

  const projects = page.locator('section[data-route-surface="projects"]');
  const existingProjects = await request.get('/v1/projects').then((response) => response.json()) as Array<{
    id: number;
    name: string;
    repo_path: string;
  }>;
  const seededProject = existingProjects.find((project) => project.name === 'Generated Compose Smoke Project');
  if (!seededProject) throw new Error('The generated Compose project is missing.');
  const disposablePath = `${seededProject.repo_path}/ledger-disposable`;

  await projects.locator('.project-registration > summary').click();
  await projects.getByLabel('Name', { exact: true }).fill('Outside Compose Boundary');
  await projects.getByLabel('Repository Path', { exact: true }).fill('/private/generated/outside-compose-boundary');
  const denied = page.waitForResponse((response) => response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/projects');
  await projects.getByRole('button', { name: 'Add Project', exact: true }).click();
  expect((await denied).status()).toBe(422);
  await expect(page.locator('.toast').filter({ hasText: 'Project registration failed' })).toContainText('Choose a repository inside an authorized source root.');
  await expect(page.getByLabel('Exact source root')).toHaveValue('/private/generated/outside-compose-boundary');

  let disposableProject: { id: number; name: string; repo_path: string } | null = null;
  let completeScan: { id: number; job_id: number | null; status: string; scanner_summary: Record<string, unknown>; findings_revision: number } | null = null;
  let limitedScan: { id: number; status: string; scanner_summary: Record<string, unknown> } | null = null;
  let selectedFinding: { id: number; scan_finding_number: number; display_id: string; rule_id: string; scanner: string; severity: string; revision: number } | null = null;
  let findingCollectionRevision: number | null = null;
  let tools = page.locator('section[data-route-surface="tools"]');
  let settings = page.locator('section[data-route-surface="settings"]');
  let components = settings.locator('.band').filter({ has: settings.getByRole('heading', { name: 'Components', exact: true }) });

  const visibleProof = async (id: string, summary: string, evidence: Record<string, unknown>) => {
    await testInfo.attach(`compose-${id.toLowerCase()}.png`, {
      body: await page.screenshot({ animations: 'disabled', caret: 'hide', fullPage: false }),
      contentType: 'image/png',
    });
    return { ok: true as const, summary, evidence };
  };

  const evidencePointer = (id: string) => `compose-${id.toLowerCase()}.png`;
  let primaryFailure: unknown = null;
  let cleanupFailure: unknown = null;
  const cleanupEvidence: string[] = [];
  try {
    const ledger = await runLiveWebActionLedger({
      platform: 'isolated-real-compose-desktop-1440',
      runId: 'compose-live-foreground',
      steps: [
        {
          id: 'WEB-LIVE-001',
          action: 'Entered the exact disposable source and clicked Add Project.',
          evidencePointer: evidencePointer('WEB-LIVE-001'),
          act: async () => {
            await projects.getByLabel('Name', { exact: true }).fill('Compose Live Ledger Project');
            await projects.getByLabel('Repository Path', { exact: true }).fill(disposablePath);
            const response = page.waitForResponse((candidate) => candidate.request().method() === 'POST'
              && new URL(candidate.url()).pathname === '/v1/projects');
            await projects.getByRole('button', { name: 'Add Project', exact: true }).click();
            disposableProject = await (await response).json() as typeof disposableProject;
          },
          verifyVisible: async () => {
            await expect(projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' })).toBeVisible();
            return visibleProof('WEB-LIVE-001', 'The disposable project row is visible.', { row_count: 1 });
          },
          verifyBackend: async () => {
            const stored = await request.get('/v1/projects').then((response) => response.json()) as Array<{ id: number; name: string }>;
            expect(stored).toContainEqual(expect.objectContaining({ id: disposableProject?.id, name: 'Compose Live Ledger Project' }));
            return { ok: true, summary: `Project ${disposableProject?.id} is durable.`, evidence: { project_id: disposableProject?.id ?? 0 } };
          },
        },
        {
          id: 'WEB-LIVE-002',
          action: 'Clicked Open on the exact disposable project.',
          evidencePointer: evidencePointer('WEB-LIVE-002'),
          act: async () => projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' }).getByRole('button', { name: 'Open', exact: true }).click(),
          verifyVisible: async () => {
            const row = projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' });
            await expect(row).toHaveAttribute('data-project-selected', 'true');
            return visibleProof('WEB-LIVE-002', 'The disposable project is visibly selected.', { selected: true });
          },
          verifyBackend: async () => ({ ok: true, summary: `Project ${disposableProject?.id} remains authoritative.`, evidence: { project_id: disposableProject?.id ?? 0 } }),
        },
        {
          id: 'WEB-LIVE-004',
          action: 'Clicked the normal Scan action for the selected disposable project.',
          evidencePointer: evidencePointer('WEB-LIVE-004'),
          act: async () => {
            const response = page.waitForResponse((candidate) => candidate.request().method() === 'POST'
              && new URL(candidate.url()).pathname === '/v1/scans');
            await projects.getByRole('button', { name: 'Scan', exact: true }).click();
            const admitted = await (await response).json() as { id: number };
            await expect.poll(async () => {
              completeScan = await request.get(`/v1/scans/${admitted.id}`).then((candidate) => candidate.json()) as typeof completeScan;
              return completeScan?.status;
            }, { timeout: 60_000 }).toBe('completed');
          },
          verifyVisible: async () => {
            await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
            await expect(page.getByLabel('Scan', { exact: true })).toHaveValue(String(completeScan?.id));
            return visibleProof('WEB-LIVE-004', `Scan ${completeScan?.id} is visibly selected after completion.`, { scan_id: completeScan?.id ?? 0 });
          },
          verifyBackend: async () => {
            expect(completeScan).toMatchObject({ status: 'completed', scanner_summary: { coverage: 'complete' } });
            return { ok: true, summary: `Scan ${completeScan?.id} completed with complete coverage.`, evidence: { scan_id: completeScan?.id ?? 0, status: 'completed' } };
          },
        },
        {
          id: 'WEB-LIVE-005',
          action: 'Enabled one deliberately unprepared scanner, acknowledged the advanced warning, and clicked Run Advanced Limited Scan.',
          evidencePointer: evidencePointer('WEB-LIVE-005'),
          act: async () => {
            await openRoute(page, 'Tools');
            tools = page.locator('section[data-route-surface="tools"]');
            const openGrep = tools.locator('.tool-card', { hasText: 'OpenGrep' });
            await openGrep.getByRole('button', { name: 'Enable', exact: true }).click();
            await expect(openGrep.locator('.pill')).toHaveText('enabled');
            await openRoute(page, 'Projects');
            await projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' }).getByRole('button', { name: 'Open', exact: true }).click();
            await projects.getByRole('button', { name: 'Review Advanced Limited Scan', exact: true }).click();
            await page.locator('dialog.confirmation-dialog').getByRole('button', { name: 'Use limited coverage', exact: true }).click();
            const response = page.waitForResponse((candidate) => candidate.request().method() === 'POST'
              && new URL(candidate.url()).pathname === '/v1/scans');
            await projects.getByRole('button', { name: 'Run Advanced Limited Scan', exact: true }).click();
            const admittedResponse = await response;
            expect(admittedResponse.request().postDataJSON()).toMatchObject({ coverage: 'limited', acknowledge_limited_coverage: true });
            const admitted = await admittedResponse.json() as { id: number };
            await expect.poll(async () => {
              limitedScan = await request.get(`/v1/scans/${admitted.id}`).then((candidate) => candidate.json()) as typeof limitedScan;
              return limitedScan?.status;
            }, { timeout: 60_000 }).toBe('partial');
          },
          verifyVisible: async () => {
            await expect(page.getByLabel('Scan', { exact: true })).toHaveValue(String(limitedScan?.id));
            return visibleProof('WEB-LIVE-005', `Limited scan ${limitedScan?.id} is visibly selected and partial.`, { scan_id: limitedScan?.id ?? 0 });
          },
          verifyBackend: async () => {
            expect(limitedScan).toMatchObject({ status: 'partial', scanner_summary: { coverage: 'limited' } });
            return { ok: true, summary: `Scan ${limitedScan?.id} persisted explicit limited coverage.`, evidence: { scan_id: limitedScan?.id ?? 0, status: 'partial' } };
          },
        },
        {
          id: 'WEB-LIVE-006',
          action: 'Selected the complete scan and applied an exact finding search filter.',
          evidencePointer: evidencePointer('WEB-LIVE-006'),
          act: async () => {
            await openRoute(page, 'Findings');
            await page.getByLabel('Scan', { exact: true }).selectOption(String(completeScan?.id));
            const result = await request.get(`/v1/scans/${completeScan?.id}/findings?limit=200`).then((response) => response.json()) as { items: Array<typeof selectedFinding>; revision: number };
            findingCollectionRevision = result.revision;
            selectedFinding = result.items[0];
            if (!selectedFinding) throw new Error('The complete disposable scan produced no finding for the live filter journey.');
            await page.getByLabel('Search findings', { exact: true }).fill(selectedFinding.rule_id);
          },
          verifyVisible: async () => {
            await expect(page.locator('.finding-list-item')).toHaveCount(1);
            await expect(page.locator('.finding-list-item')).toContainText(selectedFinding?.display_id ?? 'missing');
            return visibleProof('WEB-LIVE-006', 'The exact search filter leaves one matching finding visible.', { finding_count: 1 });
          },
          verifyBackend: async () => ({ ok: true, summary: `Finding ${selectedFinding?.id} remains in scan ${completeScan?.id}.`, evidence: { finding_id: selectedFinding?.id ?? 0, scan_id: completeScan?.id ?? 0 } }),
        },
        {
          id: 'WEB-LIVE-007',
          action: 'Clicked the exact filtered finding row.',
          evidencePointer: evidencePointer('WEB-LIVE-007'),
          act: async () => page.locator('.finding-list-item', { hasText: selectedFinding?.display_id }).click(),
          verifyVisible: async () => {
            const detail = page.locator('.finding-detail');
            await expect(detail).toHaveAttribute('data-finding-id', String(selectedFinding?.id));
            await expect(detail).toContainText(selectedFinding?.rule_id ?? 'missing');
            return visibleProof('WEB-LIVE-007', `Finding ${selectedFinding?.display_id} detail is visibly hydrated.`, { finding_id: selectedFinding?.id ?? 0 });
          },
          verifyBackend: async () => {
            if (!completeScan || !selectedFinding || findingCollectionRevision === null) {
              throw new Error('Exact finding identity and revisions are required for detail verification.');
            }
            const parameters = new URLSearchParams({
              expected_revision: String(selectedFinding.revision),
              expected_findings_revision: String(findingCollectionRevision),
            });
            const detail = await request.get(
              `/v1/scans/${completeScan.id}/findings/${selectedFinding.scan_finding_number}?${parameters}`,
            ).then((response) => response.json()) as { id: number; revision: number; scan_finding_number: number };
            expect(detail).toMatchObject({
              id: selectedFinding.id,
              revision: selectedFinding.revision,
              scan_finding_number: selectedFinding.scan_finding_number,
            });
            expect(completeScan.findings_revision).toBe(findingCollectionRevision);
            return { ok: true, summary: `Finding ${detail.id} detail matches revision ${detail.revision}.`, evidence: { finding_id: detail.id, revision: detail.revision, findings_revision: findingCollectionRevision } };
          },
        },
        {
          id: 'WEB-LIVE-008',
          action: 'Opened Jobs and refreshed the exact completed scan job.',
          evidencePointer: evidencePointer('WEB-LIVE-008'),
          act: async () => {
            await openRoute(page, 'Jobs');
            await page.getByTitle('Refresh', { exact: true }).click();
          },
          verifyVisible: async () => {
            const row = page.locator('.job-row', { hasText: `Scan #${completeScan?.id}` });
            await expect(row).toBeVisible();
            await expect(row).toContainText('Completed');
            return visibleProof('WEB-LIVE-008', `Completed job for scan ${completeScan?.id} is visible.`, { job_id: completeScan?.job_id ?? 0 });
          },
          verifyBackend: async () => {
            const job = await request.get(`/v1/jobs/${completeScan?.job_id}`).then((response) => response.json()) as { id: number; status: string };
            expect(job.status).toBe('completed');
            return { ok: true, summary: `Job ${job.id} is durably completed.`, evidence: { job_id: job.id, status: job.status } };
          },
        },
        {
          id: 'WEB-LIVE-019',
          action: 'Saved all optional component preferences, then restored lean core.',
          evidencePointer: evidencePointer('WEB-LIVE-019'),
          act: async () => {
            await openRoute(page, 'Settings');
            settings = page.locator('section[data-route-surface="settings"]');
            components = settings.locator('.band').filter({ has: settings.getByRole('heading', { name: 'Components', exact: true }) });
            const toggles = [
              components.getByLabel('Monitoring: Grafana and Prometheus', { exact: true }),
              components.getByLabel('Git proxy: Gitea', { exact: true }),
              components.getByLabel('Database UI: Adminer', { exact: true }),
            ];
            for (const toggle of toggles) await toggle.check();
            await components.getByRole('button', { name: 'Save Desired Components', exact: true }).click();
            await expect(components.locator('.command-box code')).toHaveText('make apply-components COMPONENTS=all');
            for (const toggle of toggles) await toggle.uncheck();
            await components.getByRole('button', { name: 'Save Desired Components', exact: true }).click();
          },
          verifyVisible: async () => {
            await expect(components.locator('.command-box code')).toHaveText('make apply-components COMPONENTS=core');
            return visibleProof('WEB-LIVE-019', 'The restored lean-core host command is visible.', { desired_profile: 'core' });
          },
          verifyBackend: async () => {
            const config = await request.get('/v1/config').then((response) => response.json()) as Record<string, unknown>;
            expect(config).toMatchObject({ component_monitoring_enabled: false, component_git_proxy_enabled: false, component_db_admin_enabled: false, component_apply_command: 'make apply-components COMPONENTS=core' });
            return { ok: true, summary: 'Lean-core desired component state is durable.', evidence: { desired_profile: 'core' } };
          },
        },
        {
          id: 'WEB-LIVE-020',
          action: 'Reloaded Settings to reconcile optional desired and observed state.',
          evidencePointer: evidencePointer('WEB-LIVE-020'),
          act: async () => settings.getByRole('button', { name: 'Reload Settings', exact: true }).click(),
          verifyVisible: async () => {
            await expect(settings).toContainText('Not observed; optional component is desired off.');
            return visibleProof('WEB-LIVE-020', 'Desired-off optional services are visibly neutral.', { unsafe_dns_error_count: 0 });
          },
          verifyBackend: async () => {
            const config = await request.get('/v1/config').then((response) => response.json()) as { components: Array<{ required: boolean; desired_state: string; message: string }> };
            const optional = config.components.filter((component) => !component.required);
            expect(optional.length).toBeGreaterThan(0);
            expect(optional.every((component) => component.desired_state === 'disabled' && !/errno|name or service not known/iu.test(component.message))).toBe(true);
            return { ok: true, summary: `${optional.length} optional services have safe desired-off projections.`, evidence: { optional_count: optional.length } };
          },
        },
        {
          id: 'WEB-LIVE-021',
          action: 'Focused the truthful schema-init status in Settings.',
          evidencePointer: evidencePointer('WEB-LIVE-021'),
          act: async () => components.locator('[data-schema-init-state="completed"]').scrollIntoViewIfNeeded(),
          verifyVisible: async () => {
            await expect(components.getByText(/schema-init Completed successfully; expected to stop\./u)).toBeVisible();
            await expect(components.getByRole('button', { name: /schema-init/u })).toHaveCount(0);
            return visibleProof('WEB-LIVE-021', 'schema-init is visibly successful, expected stopped, and not startable.', { start_button_count: 0 });
          },
          verifyBackend: async () => {
            const config = await request.get('/v1/config').then((response) => response.json()) as { schema_init: { state: string; startable: boolean } };
            expect(config.schema_init).toMatchObject({ state: 'completed', startable: false });
            return { ok: true, summary: 'Startup verification reports completed non-startable schema-init.', evidence: { state: config.schema_init.state, startable: config.schema_init.startable } };
          },
        },
        {
          id: 'WEB-LIVE-003',
          action: 'Confirmed deletion of the exact disposable project and its run-owned evidence.',
          evidencePointer: evidencePointer('WEB-LIVE-003'),
          act: async () => {
            await openRoute(page, 'Projects');
            const row = projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' });
            await row.getByTitle('Delete project and scan data').click();
            await page.locator('dialog.confirmation-dialog').getByRole('button', { name: 'Delete project and data', exact: true }).click();
          },
          verifyVisible: async () => {
            await expect(projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' })).toHaveCount(0);
            return visibleProof('WEB-LIVE-003', 'The exact disposable project row is gone.', { row_count: 0 });
          },
          verifyBackend: async () => {
            expect((await request.get(`/v1/projects/${disposableProject?.id}`)).status()).toBe(404);
            return { ok: true, summary: `Project ${disposableProject?.id} and its run-owned evidence were removed.`, evidence: { project_id: disposableProject?.id ?? 0, http_status: 404 } };
          },
        },
      ],
    });
    // This journey covers a deliberate subset. It cannot clear the complete
    // live-control catalog or replace the separate release lifecycle journeys.
    expect(ledger.status).toBe('partial');
    expect(ledger.coverage.complete).toBe(false);
    expect(ledger.coverage.passed_ids).toHaveLength(11);
    expect(ledger.coverage.unexecuted_ids).toContain('WEB-LIVE-022');
    await testInfo.attach('compose-live-action-ledger.json', {
      body: Buffer.from(JSON.stringify(ledger, null, 2)),
      contentType: 'application/json',
    });
  } catch (error) {
    primaryFailure = error;
    if (error instanceof LiveWebActionError) {
      await testInfo.attach('compose-live-action-ledger-failed.json', {
        body: Buffer.from(JSON.stringify(error.ledger, null, 2)),
        contentType: 'application/json',
      });
    }
  } finally {
    try {
      await openRoute(page, 'Tools');
      tools = page.locator('section[data-route-surface="tools"]');
      const openGrep = tools.locator('.tool-card', { hasText: 'OpenGrep' });
      if (await openGrep.getByRole('button', { name: 'Disable', exact: true }).count()) {
        await openGrep.getByRole('button', { name: 'Disable', exact: true }).click();
        await expect(openGrep.locator('.pill')).toHaveText('disabled');
        cleanupEvidence.push('OpenGrep restored to disabled.');
      } else {
        cleanupEvidence.push('OpenGrep was already disabled.');
      }

      const cleanupProject = disposableProject as { id: number; name: string; repo_path: string } | null;
      if (cleanupProject) {
        const projectResponse = await request.get(`/v1/projects/${cleanupProject.id}`);
        if (projectResponse.status() === 200) {
          await openRoute(page, 'Projects');
          const row = projects.locator('.project-row', { hasText: 'Compose Live Ledger Project' });
          await expect(row).toBeVisible();
          await row.getByTitle('Delete project and scan data').click();
          await page.locator('dialog.confirmation-dialog').getByRole('button', { name: 'Delete project and data', exact: true }).click();
          await expect(row).toHaveCount(0);
          expect((await request.get(`/v1/projects/${cleanupProject.id}`)).status()).toBe(404);
          cleanupEvidence.push(`Disposable project ${cleanupProject.id} removed by exact identity.`);
        } else if (projectResponse.status() === 404) {
          cleanupEvidence.push(`Disposable project ${cleanupProject.id} was already absent.`);
        } else {
          throw new Error(`Disposable project cleanup received unexpected HTTP ${projectResponse.status()}.`);
        }
      }
    } catch (error) {
      cleanupFailure = error;
    }
    await testInfo.attach('compose-live-action-cleanup.json', {
      body: Buffer.from(JSON.stringify({
        status: cleanupFailure ? 'failed' : 'passed',
        actions: cleanupEvidence,
        error: cleanupFailure instanceof Error ? cleanupFailure.message : cleanupFailure ? 'Unknown cleanup failure.' : null,
      }, null, 2)),
      contentType: 'application/json',
    });
  }
  if (primaryFailure) throw primaryFailure;
  if (cleanupFailure) throw cleanupFailure;
});
