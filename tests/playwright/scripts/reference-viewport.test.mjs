import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

// This file will live in tests/playwright/scripts/ after review.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
test('reference viewport admission skips before page-dependent hooks and fixtures', () => {
  const work = mkdtempSync(join(tmpdir(), 'lomo-reference-viewport-'));
  try {
    const report = join(work, 'report.json');
    writeFileSync(join(work, 'playwright.config.mjs'), `export default ${JSON.stringify({
      testDir: work, testMatch: 'admission.spec.mjs', outputDir: join(work, 'results'),
      workers: 1, retries: 0, timeout: 5000,
      reporter: [['json', { outputFile: report }]],
      projects: ['desktop-1440', 'desktop-1920', 'tablet-768', 'mobile-390'].map(name => ({ name })),
    })};\n`);
    const helper = pathToFileURL(join(root, 'tests/support/reference-viewport.ts')).href;
    const playwright = pathToFileURL(join(root, 'node_modules/@playwright/test/index.mjs')).href;
    writeFileSync(join(work, 'admission.spec.mjs'), `
      import { referenceTest } from ${JSON.stringify(helper)};
      import { test as ordinary, expect } from ${JSON.stringify(playwright)};
      const reference = referenceTest.extend({ page: async ({}, use, info) => {
        if (info.project.name !== 'desktop-1440') throw new Error('Skipped case constructed a page');
        await use({ constructed: true });
      }});
      reference('reference-only fixture', async ({ page }) => { expect(page.constructed).toBe(true); });
      reference.describe('page-dependent hook', () => {
        reference.beforeEach(async ({ page }) => { expect(page.constructed).toBe(true); });
        reference('reference-only hook', async ({ page }) => { expect(page.constructed).toBe(true); });
      });
      ordinary.describe('mixed base hooks and options', () => {
        ordinary.use({ locale: 'fr-FR' });
        ordinary.beforeEach(async ({ page }) => { expect(page.constructed).toBe(true); });
        reference('base options are preserved', async ({ page, locale }) => {
          expect(page.constructed).toBe(true); expect(locale).toBe('fr-FR');
        });
      });
      ordinary('responsive coverage preserved', async ({}, info) => {
        expect(['desktop-1440','desktop-1920','tablet-768','mobile-390']).toContain(info.project.name);
      });
    `);
    const run = spawnSync(process.execPath, [join(root, 'node_modules/playwright/cli.js'), 'test',
      '--config', join(work, 'playwright.config.mjs')], { cwd: work, encoding: 'utf8', timeout: 20_000 });
    assert.equal(run.error, undefined);
    assert.equal(run.status, 0, run.stderr + run.stdout);
    const result = JSON.parse(readFileSync(report, 'utf8'));
    assert.equal(result.stats.expected, 7);
    assert.equal(result.stats.skipped, 9);
    assert.equal(result.stats.unexpected, 0);
    assert.equal(result.stats.flaky, 0);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
