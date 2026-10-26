import assert from 'node:assert/strict';
import test from 'node:test';

import {
  LIVE_WEB_ACTION_CATALOG,
  LIVE_WEB_ACTION_LEDGER_SCHEMA,
  LiveWebActionError,
  REQUIRED_LIVE_WEB_ACTION_IDS,
  openLiveWebRoute,
  runLiveWebActionLedger,
} from '../tests/support/live-action-ledger.mjs';

test('live Web action inventory is stable, unique and covers every required real-product area', () => {
  assert.equal(new Set(REQUIRED_LIVE_WEB_ACTION_IDS).size, REQUIRED_LIVE_WEB_ACTION_IDS.length);
  assert.deepEqual(REQUIRED_LIVE_WEB_ACTION_IDS, LIVE_WEB_ACTION_CATALOG.map((item) => item.id));
  assert.deepEqual(new Set(LIVE_WEB_ACTION_CATALOG.map((item) => item.screen)), new Set([
    'Projects', 'Findings', 'Jobs', 'Tools', 'Settings',
  ]));
  for (const item of LIVE_WEB_ACTION_CATALOG) {
    assert.match(item.id, /^WEB-LIVE-\d{3}$/u);
    assert.ok(item.control);
    assert.ok(item.precondition);
    assert.ok(item.expected_visible);
    assert.ok(item.expected_backend);
    assert.ok(Object.isFrozen(item));
  }
});

test('live Web action ledger requires one visible proof and one backend proof for each foreground click', async () => {
  const calls = [];
  let tick = 0;
  const ledger = await runLiveWebActionLedger({
    platform: 'ubuntu',
    runId: 'ubuntu-live-ledger-test',
    clock: () => `2026-09-02T12:00:${String(tick++).padStart(2, '0')}Z`,
    steps: [
      {
        id: 'WEB-LIVE-001',
        action: 'Filled the exact disposable name and path, then clicked Add Project.',
        evidencePointer: 'screenshots/projects-after-create.png',
        act: async () => calls.push('create-click'),
        verifyVisible: async () => ({ ok: true, summary: 'Disposable project row is visible.', evidence: { row_count: 1 } }),
        verifyBackend: async () => ({ ok: true, summary: 'Project 71 exists at revision 1.', evidence: { project_id: 71, revision: 1 } }),
      },
      {
        id: 'WEB-LIVE-004',
        action: 'Clicked the normal Scan action for project 71.',
        evidencePointer: 'screenshots/projects-scan-72.png',
        act: async () => calls.push('scan-click'),
        verifyVisible: async () => ({ ok: true, summary: 'Scan 72 is visibly completed with complete coverage.', evidence: { scan_id: 72 } }),
        verifyBackend: async () => ({ ok: true, summary: 'Scan 72 is completed and full.', evidence: { scan_id: 72, status: 'completed', coverage: 'full' } }),
      },
    ],
  });

  assert.deepEqual(calls, ['create-click', 'scan-click']);
  assert.equal(ledger.schema, LIVE_WEB_ACTION_LEDGER_SCHEMA);
  assert.equal(ledger.status, 'partial');
  assert.equal(ledger.coverage.complete, false);
  assert.deepEqual(ledger.coverage.passed_ids, ['WEB-LIVE-001', 'WEB-LIVE-004']);
  assert.deepEqual(ledger.coverage.failed_ids, []);
  assert.deepEqual(ledger.coverage.unexecuted_ids, REQUIRED_LIVE_WEB_ACTION_IDS.filter((id) => !['WEB-LIVE-001', 'WEB-LIVE-004'].includes(id)));
  assert.equal(ledger.entries.length, 2);
  assert.deepEqual(ledger.entries.map((entry) => entry.result), ['pass', 'pass']);
  assert.deepEqual(ledger.entries[1].evidence.backend, {
    scan_id: 72,
    status: 'completed',
    coverage: 'full',
  });
  assert.ok(Object.isFrozen(ledger));
});

test('live Web action ledger stops on missing backend proof and retains a bounded failing receipt', async () => {
  await assert.rejects(
    runLiveWebActionLedger({
      platform: 'fedora',
      runId: 'fedora-live-ledger-test',
      steps: [{
        id: 'WEB-LIVE-010',
        action: 'Clicked Retry on the exact failed job.',
        evidencePointer: 'screenshots/jobs-retry.png',
        act: async () => {},
        verifyVisible: async () => ({ ok: true, summary: 'The original job row resumed.', evidence: { row_count: 1 } }),
        verifyBackend: async () => ({ ok: false, summary: 'Original job identity was not verified.', evidence: {} }),
      }],
    }),
    (error) => {
      assert.ok(error instanceof LiveWebActionError);
      assert.equal(error.actionId, 'WEB-LIVE-010');
      assert.equal(error.ledger.status, 'failed');
      assert.equal(error.ledger.coverage.complete, false);
      assert.deepEqual(error.ledger.coverage.failed_ids, ['WEB-LIVE-010']);
      assert.equal(error.ledger.coverage.unexecuted_ids.includes('WEB-LIVE-010'), false);
      assert.equal(error.ledger.entries[0].result, 'fail');
      assert.match(error.ledger.entries[0].error, /must return/u);
      return true;
    },
  );
});

test('only the complete catalog with both proofs can pass the full action ledger', async () => {
  const steps = REQUIRED_LIVE_WEB_ACTION_IDS.map((id) => ({
    id,
    action: `Fixture action ${id}.`,
    evidencePointer: `fixture/${id}.json`,
    act: async () => {},
    verifyVisible: async () => ({ ok: true, summary: 'Synthetic visible proof.', evidence: {} }),
    verifyBackend: async () => ({ ok: true, summary: 'Synthetic backend proof.', evidence: {} }),
  }));
  const ledger = await runLiveWebActionLedger({ platform: 'synthetic', runId: 'catalog-contract', steps });
  assert.equal(ledger.status, 'passed');
  assert.equal(ledger.coverage.complete, true);
  assert.deepEqual(ledger.coverage.passed_ids, REQUIRED_LIVE_WEB_ACTION_IDS);
  assert.deepEqual(ledger.coverage.failed_ids, []);
  assert.deepEqual(ledger.coverage.unexecuted_ids, []);
  assert.ok(ledger.coverage.passed_ids.includes('WEB-LIVE-022'));
});

test('live Web action ledger rejects authority-shaped receipt text', async () => {
  await assert.rejects(
    runLiveWebActionLedger({
      platform: 'windows',
      runId: 'windows-live-ledger-test',
      steps: [{
        id: 'WEB-LIVE-017',
        action: 'Clicked Add browser.',
        evidencePointer: 'screenshots/settings-add-browser.png',
        act: async () => {},
        verifyVisible: async () => ({ ok: true, summary: 'Invitation kc1.secret appeared.', evidence: {} }),
        verifyBackend: async () => ({ ok: true, summary: 'Pending member exists.', evidence: {} }),
      }],
    }),
    LiveWebActionError,
  );
});

test('live Web action ledger normalizes multiline failures and redacts authority material', async () => {
  await assert.rejects(
    runLiveWebActionLedger({
      platform: 'macos',
      runId: 'mac-live-ledger-test',
      steps: [{
        id: 'WEB-LIVE-018',
        action: 'Confirmed revocation for the exact disposable browser member.',
        evidencePointer: 'screenshots/settings-revoke-browser.png',
        act: async () => { throw new Error('request failed\nAuthorization: Bearer kc1.secret'); },
        verifyVisible: async () => ({ ok: true, summary: 'Unused.', evidence: {} }),
        verifyBackend: async () => ({ ok: true, summary: 'Unused.', evidence: {} }),
      }],
    }),
    (error) => {
      assert.ok(error instanceof LiveWebActionError);
      assert.equal(
        error.ledger.entries[0].error,
        'Action failed with protected authority material in the underlying error; detail was redacted.',
      );
      assert.doesNotMatch(JSON.stringify(error.ledger), /kc1\.secret/u);
      return true;
    },
  );
});

for (const [kind, token] of Object.entries({
  invitation: `kbi1.${'i'.repeat(24)}.${'s'.repeat(43)}`,
  session: `${'s'.repeat(32)}.${'b'.repeat(64)}`,
  'session-url-safe': `-${'_'.repeat(31)}.${'c'.repeat(64)}`,
})) {
  test(`live ledger rejects ${kind} authority in proofs and redacts it in failures`, async () => {
    for (const location of ['summary', 'nested-evidence', 'failure', 'long-failure']) {
      await assert.rejects(runLiveWebActionLedger({
        platform: 'synthetic',
        runId: `authority-${kind}-${location}`,
        steps: [{
          id: 'WEB-LIVE-017',
          action: 'Exercise a disposable invitation fixture.',
          evidencePointer: 'fixture/invitation.json',
          act: async () => {
            if (location === 'failure') throw new Error(`Invitation failed: ${token}`);
            if (location === 'long-failure') throw new Error(`${'context '.repeat(60)}${token}`);
          },
          verifyVisible: async () => ({
            ok: true,
            summary: location === 'summary' ? `Shown: ${token}` : 'Invitation state is visible.',
            evidence: location === 'nested-evidence' ? { nested: [{ text: token }] } : {},
          }),
          verifyBackend: async () => ({ ok: true, summary: 'Fixture only.', evidence: {} }),
        }],
      }), error => {
        assert.ok(error instanceof LiveWebActionError);
        assert.equal(error.ledger.status, 'failed');
        assert.equal(JSON.stringify(error.ledger).includes(token), false);
        assert.equal(error.message.includes(token), false);
        if (location.endsWith('failure')) {
          assert.equal(error.ledger.entries[0].error,
            'Action failed with protected authority material in the underlying error; detail was redacted.');
        }
        return true;
      });
    }
  });
}

test('live ledger retains non-secret member identities and content digests', async () => {
  const evidence = {
    ide_member: `ks1_${'m'.repeat(43)}`,
    browser_member: `kbm1_${'m'.repeat(32)}`,
    enrollment_id: `ker1_${'m'.repeat(24)}`,
    invalid_record_cas: `kir1_${'a'.repeat(64)}`,
    sha256: 'd'.repeat(64),
  };
  const ledger = await runLiveWebActionLedger({
    platform: 'synthetic', runId: 'public-identity-proof',
    steps: [{
      id: 'WEB-LIVE-017', action: 'Check unchanged member identities.',
      evidencePointer: 'fixture/identities.json', act: async () => {},
      verifyVisible: async () => ({ ok: true, summary: 'Members shown.', evidence }),
      verifyBackend: async () => ({ ok: true, summary: 'Identity proof.', evidence }),
    }],
  });
  assert.equal(ledger.status, 'partial');
  assert.deepEqual(ledger.entries[0].evidence.backend, evidence);
});

test('openLiveWebRoute waits for painted readiness after the visible heading', async () => {
  const calls = [];
  let ready = false;
  const surface = {
    waitFor: async (options) => calls.push(['surface-wait', options]),
    getAttribute: async (name) => (name === 'aria-busy' ? String(!ready) : null),
  };
  const navigation = {
    getByRole: (role, options) => {
      calls.push(['navigation-role', role, options]);
      return { click: async () => calls.push(['click']) };
    },
  };
  const heading = { waitFor: async (options) => calls.push(['heading-wait', options]) };
  const page = {
    getByRole: (role, options) => {
      calls.push(['page-role', role, options]);
      if (role === 'navigation') return navigation;
      return heading;
    },
    locator: (selector) => {
      calls.push(['locator', selector]);
      if (selector.includes(':not(')) return { waitFor: async options => {
        assert.deepEqual(options, { state: 'visible', timeout: 10000 });
        assert.match(selector, /:not\(\[aria-busy="true"\]\):not\(\[inert\]\)/);
        ready = true;
      } };
      return surface;
    },
  };
  assert.equal(await openLiveWebRoute(page, 'Tools'), surface);
  assert.ok(calls.some((item) => item[0] === 'navigation-role' && item[2].name === 'Tools'));
  assert.ok(calls.some((item) => item[0] === 'locator' && item[1].includes('tools')));
  ready = false;
  const locator = page.locator;
  page.locator = selector => selector.includes(':not(')
    ? { waitFor: async () => { throw new Error('readiness deadline'); } } : locator(selector);
  await assert.rejects(openLiveWebRoute(page, 'Tools'), /readiness deadline/);
});

test('explicit VM readiness waits remain finite and refuse invalid budgets before UI actions', async () => {
  let actions = 0, observed;
  const surface = { waitFor: async () => {}, getAttribute: async () => null };
  const page = { getByRole: () => ({ getByRole: () => ({ click: async () => { actions++; } }), waitFor: async () => {} }),
    locator: selector => selector.includes(':not(') ? { waitFor: async options => { observed = options.timeout; } } : surface };
  await openLiveWebRoute(page, 'Tools', { timeoutMs: 156000 }); assert(observed > 0 && observed <= 156000); assert.equal(actions, 1);
  for (const timeoutMs of [0, -1, Infinity, NaN, 234001]) await assert.rejects(openLiveWebRoute(page, 'Tools', { timeoutMs }));
  assert.equal(actions, 1);
});

test('explicit route clock clips every awaited action and cannot renew between stages', async () => {
  const originalNow = Date.now, waits = []; let now = 1000;
  Date.now = () => now;
  const wait = async options => { waits.push(options.timeout); now += 25; };
  const surface = { waitFor: wait, getAttribute: async () => null };
  const page = { getByRole: () => ({ getByRole: () => ({ click: wait }), waitFor: wait }),
    locator: selector => selector.includes(':not(') ? { waitFor: wait } : surface };
  try {
    await openLiveWebRoute(page, 'Tools', { timeoutMs: 200 }); assert.deepEqual(waits, [200, 175, 150, 125]);
    now = 1000; waits.length = 0;
    await assert.rejects(openLiveWebRoute(page, 'Tools', { timeoutMs: 40 }), /Original route deadline expired/);
    assert.deepEqual(waits, [40, 15], 'exhausted original clock must prevent the next UI action');
  } finally { Date.now = originalNow; }
});

test('a polling readiness race reobserves without reclicking or renewing the route clock', async () => {
  const originalNow = Date.now;
  let now = 1000, clicks = 0, reads = 0;
  const waits = [];
  Date.now = () => now;
  const surface = { waitFor: async () => {}, getAttribute: async name =>
    name === 'aria-busy' && ++reads === 1 ? 'true' : null };
  const page = {
    getByRole: role => role === 'navigation'
      ? { getByRole: () => ({ click: async () => { clicks++; } }) }
      : { waitFor: async () => {} },
    locator: selector => selector.includes(':not(')
      ? { waitFor: async ({ timeout }) => { waits.push(timeout); now += 25; } } : surface,
  };
  try {
    assert.equal(await openLiveWebRoute(page, 'Jobs', { timeoutMs: 100 }), surface);
    assert.equal(clicks, 1);
    assert.deepEqual(waits, [100, 75]);
    now = 1000; reads = 0; clicks = 0; waits.length = 0;
    surface.getAttribute = async name => name === 'aria-busy' ? 'true' : null;
    await assert.rejects(openLiveWebRoute(page, 'Jobs', { timeoutMs: 40 }), /Original route deadline expired/);
    assert.equal(clicks, 1);
    assert.deepEqual(waits, [40, 15]);
  } finally { Date.now = originalNow; }
});
