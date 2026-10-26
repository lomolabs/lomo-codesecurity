import { defineConfig } from '@playwright/test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { qualificationMilliseconds } from './timing.js';

const configDirectory = dirname(fileURLToPath(import.meta.url));
const composeMode = process.env.KODESEC_PLAYWRIGHT_MODE === 'compose';
const configuredWSEndpoint = process.env.KODESEC_PLAYWRIGHT_WS_ENDPOINT;
const headedValue = process.env.KODESEC_PLAYWRIGHT_HEADED;
if (headedValue !== undefined && headedValue !== '0' && headedValue !== '1') {
  throw new Error('KODESEC_PLAYWRIGHT_HEADED must be exactly 0 or 1.');
}
const headed = headedValue === '1';

function exactPlaywrightWSEndpoint(value: string): string {
  const parsed = new URL(value);
  const endpointPort = Number.parseInt(parsed.port, 10);
  if (
    parsed.protocol !== 'ws:'
    || parsed.hostname !== '127.0.0.1'
    || !parsed.port
    || !Number.isInteger(endpointPort)
    || endpointPort < 1024
    || endpointPort > 65535
    || parsed.username
    || parsed.password
    || !/^\/[a-f0-9]{12}$/.test(parsed.pathname)
    || parsed.search
    || parsed.hash
    || value !== `ws://127.0.0.1:${endpointPort}${parsed.pathname}`
  ) {
    throw new Error('KODESEC_PLAYWRIGHT_WS_ENDPOINT must be an exact ws://127.0.0.1:<port>/<generated-id> URL.');
  }
  return value;
}

if (composeMode && configuredWSEndpoint) {
  throw new Error('KODESEC_PLAYWRIGHT_WS_ENDPOINT is not accepted by the existing Compose smoke mode.');
}
const wsEndpoint = configuredWSEndpoint ? exactPlaywrightWSEndpoint(configuredWSEndpoint) : undefined;
const configuredPort = process.env.KODESEC_PLAYWRIGHT_PORT || '41783';
const port = Number(configuredPort);
if (!composeMode && (!/^\d{4,5}$/.test(configuredPort) || !Number.isInteger(port) || port < 1024 || port > 65535)) {
  throw new Error(`Invalid KODESEC_PLAYWRIGHT_PORT: ${process.env.KODESEC_PLAYWRIGHT_PORT}`);
}
const fixtureBaseURL = `http://127.0.0.1:${port}`;
const composeBaseURL = process.env.KODESEC_COMPOSE_BASE_URL;
if (composeMode) {
  if (!composeBaseURL) throw new Error('KODESEC_COMPOSE_BASE_URL is required in Compose mode.');
  const parsed = new URL(composeBaseURL);
  const composePort = Number.parseInt(parsed.port, 10);
  if (
    parsed.protocol !== 'http:'
    || parsed.hostname !== '127.0.0.1'
    || !Number.isInteger(composePort)
    || composePort < 1024
    || composePort > 65535
    || parsed.username
    || parsed.password
    || composeBaseURL !== parsed.origin
  ) {
    throw new Error('KODESEC_COMPOSE_BASE_URL must be an exact 127.0.0.1 HTTP origin.');
  }
  if (!process.env.KODESEC_COMPOSE_STORAGE_STATE) throw new Error('KODESEC_COMPOSE_STORAGE_STATE is required in Compose mode.');
}
const baseURL = composeMode ? composeBaseURL! : fixtureBaseURL;
const resultDirectory = process.env.KODESEC_PLAYWRIGHT_RESULT_DIR || resolve(configDirectory, '.results');
const rawExecutionReport = resolve(resultDirectory, 'execution-report.raw.json');
// Explicit targeted diagnostic only; never add it to ordinary qualification.
const networkConformance = process.argv.includes('tests/network-isolation.conformance.spec.ts');
const proxyConformance = process.argv.includes('tests/proxy-isolation.conformance.spec.ts');
const findingsScale = process.argv.includes('tests/findings.scale.spec.ts');

export default defineConfig({
  testDir: './tests',
  testMatch: composeMode
    ? '**/compose.smoke.spec.ts'
    : networkConformance ? '**/network-isolation.conformance.spec.ts'
    : proxyConformance ? '**/proxy-isolation.conformance.spec.ts'
    : findingsScale ? '**/findings.scale.spec.ts' : [
        '**/foundation.spec.ts',
        '**/findings.performance.spec.ts',
        '**/navigation.performance.spec.ts',
        '**/operator-actions.spec.ts',
        '**/scanner-lifecycle.spec.ts',
      ],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: qualificationMilliseconds(30_000),
  expect: {
    timeout: qualificationMilliseconds(5_000),
    toHaveScreenshot: { animations: 'disabled', caret: 'hide', maxDiffPixels: 0 },
  },
  outputDir: resolve(resultDirectory, 'artifacts'),
  // macOS native Chrome and its headless shell resolve system fonts differently.
  // Keep independently reviewed references rather than replacing either mode.
  snapshotPathTemplate: `{testDir}/__screenshots__/{testFilePath}/{arg}-{projectName}-{platform}${process.platform === 'darwin' && !headed ? '-headless' : ''}{ext}`,
  reporter: [
    ['line'],
    ['html', { outputFolder: resolve(resultDirectory, 'report'), open: 'never' }],
    ['json', { outputFile: rawExecutionReport }],
  ],
  use: {
    baseURL,
    browserName: 'chromium',
    headless: !headed,
    locale: 'en-US',
    timezoneId: 'UTC',
    colorScheme: 'dark',
    contextOptions: { reducedMotion: 'reduce' },
    serviceWorkers: 'block',
    connectOptions: wsEndpoint ? { wsEndpoint } : undefined,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    storageState: composeMode ? process.env.KODESEC_COMPOSE_STORAGE_STATE : undefined,
  },
  webServer: composeMode ? undefined : {
    command: 'node ./scripts/server-launcher.mjs',
    cwd: configDirectory,
    url: `${baseURL}/healthz`,
    timeout: qualificationMilliseconds(15_000),
    reuseExistingServer: false,
    env: { KODESEC_PLAYWRIGHT_PORT: String(port) },
  },
  projects: [
    { name: 'desktop-1440', use: { viewport: { width: 1440, height: 900 } } },
    { name: 'desktop-1920', use: { viewport: { width: 1920, height: 1080 } } },
    { name: 'tablet-768', use: { viewport: { width: 768, height: 1024 } } },
    { name: 'mobile-390', use: { viewport: { width: 390, height: 844 } } },
  ],
});
