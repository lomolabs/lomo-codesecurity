import assert from 'node:assert/strict';
import test from 'node:test';

import type { ScannerCacheVerification, ScannerLifecycleScope, ScannerPreflight } from '../src/api.ts';
import {
  requiredLockRefreshComponents,
  scannerPreparationDisabledReason,
  scannerPreparationCommandCopy,
  scannerVerificationCopy,
  scannerVerificationDisabledReason,
  scannerVerificationPollRequired,
  validScannerCacheVerification,
  validScannerVerificationPreflight,
} from '../src/scannerPreparation.ts';

const preflight = {
  required_component_ids: ['grype-db', 'trivy-db'],
} as ScannerPreflight;

const verification: ScannerCacheVerification = {
  state: 'verifying', target: 'active', generation_id: 'a'.repeat(64),
  phase: 'validating', component_id: 'grype-db',
  started_at: '2026-09-07T12:00:00Z', last_activity_at: '2026-09-07T12:00:01.123456+00:00',
  bytes_verified: null, bytes_total: null,
};

test('scanner verification validates exact typed states, identities, UTC activity and bounded bytes', () => {
  assert.equal(validScannerCacheVerification(verification), true);
  assert.equal(validScannerCacheVerification({ ...verification, phase: 'hashing', bytes_verified: 1024, bytes_total: 8 * 1024 ** 3 }), true);
  for (const invalid of [
    null, [], {}, { ...verification, unknown: true },
    { ...verification, state: ['verifying'] }, { ...verification, target: ['active'] },
    { ...verification, phase: ['hashing'] }, { ...verification, phase: 'downloading' },
    { ...verification, generation_id: 'a'.repeat(63) }, { ...verification, generation_id: 'A'.repeat(64) },
    { ...verification, component_id: 'untrusted scanner name' },
    { ...verification, started_at: '2026-09-07T12:00:00+02:00' },
    { ...verification, started_at: '2026-02-30T12:00:00Z' },
    { ...verification, last_activity_at: '2026-09-07T11:59:59Z' },
    { ...verification, bytes_verified: true, bytes_total: 1 },
    { ...verification, bytes_verified: 0, bytes_total: null },
    { ...verification, bytes_verified: 2, bytes_total: 1 },
    { ...verification, bytes_verified: -1, bytes_total: 1 },
    { ...verification, bytes_verified: 0.5, bytes_total: 1 },
    { ...verification, bytes_verified: 0, bytes_total: 8 * 1024 ** 3 + 1 },
  ]) assert.equal(validScannerCacheVerification(invalid), false);
});

test('scanner verification blocks preparation and complete scanning without polling terminal failures', () => {
  for (const state of ['verifying', 'timed_out', 'failed'] as const) {
    const current = { ...preflight, cache_verification: { ...verification, state },
      ready: false, preparation_available: false,
      recommended_action: state === 'verifying' ? 'wait_for_scanner_verification' : 'retry_scanner_verification',
    } as ScannerPreflight;
    assert.equal(validScannerVerificationPreflight(current), true);
    assert.equal(validScannerVerificationPreflight({ ...current, ready: true }), false);
    assert.equal(validScannerVerificationPreflight({ ...current, preparation_available: true }), false);
    assert.equal(validScannerVerificationPreflight({ ...current, recommended_action: 'prepare_scanners' }), false);
    assert.match(scannerVerificationDisabledReason(current) || '', /before complete scanning/u);
    assert.equal(scannerVerificationPollRequired(current), state === 'verifying');
    assert.equal(scannerVerificationCopy(current.cache_verification!).canRetry, state !== 'verifying');
  }
});

test('scanner verification of previous-good is exact and leaves active scan readiness independent', () => {
  const previous = { ...verification, target: 'previous_good' as const };
  const current = { ...preflight, ready: true, preparation_available: false, recommended_action: 'scan',
    cache_rollback: { eligible: false, reason_code: 'previous_generation_verifying',
      reason: 'Checking previous-good data.', target_generation: previous.generation_id, verification: previous },
  } as ScannerPreflight;
  assert.equal(validScannerVerificationPreflight(current), true);
  assert.equal(scannerVerificationDisabledReason(current), null);
  assert.equal(scannerVerificationPollRequired(current), true);
  assert.match(scannerVerificationCopy(previous).detail, /already-verified active cache remains available/u);
  for (const rollback of [
    { ...current.cache_rollback, target_generation: 'b'.repeat(64) },
    { ...current.cache_rollback, eligible: true },
    { ...current.cache_rollback, verification: { ...previous, target: 'active' as const } },
    { ...current.cache_rollback, verification: { ...previous, state: 'failed' as const } },
    { ...current.cache_rollback, verification: undefined },
  ]) assert.equal(validScannerVerificationPreflight({ ...current, cache_rollback: rollback }), false);
});

function catalog(status: ScannerLifecycleScope['status'], components: unknown): ScannerLifecycleScope {
  return {
    status,
    receipt: { result: { components } },
  } as ScannerLifecycleScope;
}

test('required lock refresh guidance accepts only completed bounded catalog evidence', () => {
  const required = requiredLockRefreshComponents(preflight, catalog('completed', [
    { component_id: 'trivy-java-db', state: 'requires_lock_refresh' },
    { component_id: 'grype-db', state: 'requires_lock_refresh' },
    { component_id: 'trivy-db', state: 'requires_lock_refresh' },
  ]));
  assert.deepEqual(required.map(({ id }) => id), ['trivy-db', 'grype-db']);
  assert.deepEqual(requiredLockRefreshComponents(preflight, catalog('cancelled', [
    { component_id: 'grype-db', state: 'requires_lock_refresh' },
  ])), []);
  assert.deepEqual(requiredLockRefreshComponents(preflight, catalog('completed', [
    { component_id: 'grype-db', state: 'requires_lock_refresh' },
    { component_id: 'grype-db', state: 'requires_lock_refresh' },
  ])), []);
});

test('scanner preparation blocks concurrent work but permits an explicit current-source recheck', () => {
  assert.equal(
    scannerPreparationDisabledReason(true),
    'Scanner preparation is already processing or reconciling durable work.',
  );
  assert.equal(scannerPreparationDisabledReason(false), null);
});

test('scanner preparation copy does not invent cache work before catalog success', () => {
  const catalogCommand = {
    catalog: { job: { id: 17, status: 'queued' }, lifecycle: { status: 'queued' } },
    required_component_ids: ['trivy-db'],
  } as Parameters<typeof scannerPreparationCommandCopy>[0];
  assert.deepEqual(scannerPreparationCommandCopy(catalogCommand), {
    title: 'Scanner catalog job #17 queued',
    detail: 'CodeSecurity is checking the reviewed scanner locks. Verified cache work will be created only if that catalog check passes.',
  });

  const continued = {
    ...catalogCommand,
    cache: { job: { id: 18, status: 'running' }, lifecycle: { status: 'running' } },
  } as Parameters<typeof scannerPreparationCommandCopy>[0];
  assert.equal(
    scannerPreparationCommandCopy(continued).title,
    'Scanner cache job #18 in progress',
  );
});

test('scanner preparation replay copy is terminal-truthful without a cache child', () => {
  const command = (status: 'completed' | 'failed' | 'cancelled') => ({
    catalog: { job: { id: 21, status }, lifecycle: { status } },
    required_component_ids: ['trivy-db'],
  }) as Parameters<typeof scannerPreparationCommandCopy>[0];

  assert.deepEqual(scannerPreparationCommandCopy(command('completed')), {
    title: 'Scanner catalog job #21 completed',
    detail: 'The reviewed-lock check completed without creating cache work. Refreshed readiness will show whether preparation is complete or an exact lock/runtime blocker needs attention.',
  });
  assert.match(scannerPreparationCommandCopy(command('failed')).detail, /failed; no verified cache job was created/u);
  assert.match(scannerPreparationCommandCopy(command('cancelled')).detail, /cancelled; no verified cache job was created/u);
});

test('scanner preparation replay copy reports the actual cache terminal state', () => {
  const command = (status: 'completed' | 'failed') => ({
    catalog: { job: { id: 21, status: 'completed' }, lifecycle: { status: 'completed' } },
    cache: { job: { id: 22, status }, lifecycle: { status } },
    required_component_ids: ['trivy-db'],
  }) as Parameters<typeof scannerPreparationCommandCopy>[0];

  assert.deepEqual(scannerPreparationCommandCopy(command('completed')), {
    title: 'Scanner cache job #22 completed',
    detail: 'Catalog job #21 is completed; verified cache job #22 is completed. Track the exact durable stages from Tools or Jobs.',
  });
  assert.equal(scannerPreparationCommandCopy(command('failed')).title, 'Scanner cache job #22 failed');
});

test('scanner preparation replay copy binds exact jobs over newer singleton lifecycles', () => {
  const catalogCompleted = {
    catalog: { job: { id: 31, status: 'completed' }, lifecycle: { status: 'running', job_id: 99 } },
    required_component_ids: ['trivy-db'],
  } as Parameters<typeof scannerPreparationCommandCopy>[0];
  assert.equal(scannerPreparationCommandCopy(catalogCompleted).title, 'Scanner catalog job #31 completed');

  const catalogFailed = {
    catalog: { job: { id: 32, status: 'failed' }, lifecycle: { status: 'completed', job_id: 99 } },
    required_component_ids: ['trivy-db'],
  } as Parameters<typeof scannerPreparationCommandCopy>[0];
  assert.equal(scannerPreparationCommandCopy(catalogFailed).title, 'Scanner catalog job #32 failed');

  const cacheFailed = {
    catalog: { job: { id: 31, status: 'completed' }, lifecycle: { status: 'running', job_id: 99 } },
    cache: { job: { id: 33, status: 'failed' }, lifecycle: { status: 'completed', job_id: 100 } },
    required_component_ids: ['trivy-db'],
  } as Parameters<typeof scannerPreparationCommandCopy>[0];
  assert.equal(scannerPreparationCommandCopy(cacheFailed).title, 'Scanner cache job #33 failed');

  const cacheCompleted = {
    ...cacheFailed,
    cache: { job: { id: 34, status: 'completed' }, lifecycle: { status: 'running', job_id: 100 } },
  } as Parameters<typeof scannerPreparationCommandCopy>[0];
  assert.equal(scannerPreparationCommandCopy(cacheCompleted).title, 'Scanner cache job #34 completed');
});

test('scanner preparation copy treats an unknown exact job state as neutral', () => {
  const command = {
    catalog: { job: { id: 41, status: 'future-state' }, lifecycle: { status: 'running', job_id: 41 } },
    required_component_ids: ['trivy-db'],
  } as Parameters<typeof scannerPreparationCommandCopy>[0];

  assert.deepEqual(scannerPreparationCommandCopy(command), {
    title: 'Scanner catalog job #41 recorded',
    detail: 'The exact durable job state is not recognized. Review this job or refresh readiness before taking another action.',
  });
});
