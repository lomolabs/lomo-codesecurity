import assert from 'node:assert/strict';
import test from 'node:test';

import type { AdvisorTriageProviderPin, Finding, Job } from '../src/api';
import {
  AdvisorFindingReconciliationError,
  retryLocalAdvisorAfterRevisionConflict,
} from '../src/advisorFindingReconciliation.ts';
import type { ResolvedAdvisorRoute } from '../src/advisorRouting';

const pin: AdvisorTriageProviderPin = {
  provider_collection_revision: 7,
  provider_id: 'local-ollama',
  transport: 'local',
  provider_config_revision: 4,
  provider_config_digest: 'a'.repeat(64),
  model: 'qwen3:8b',
  model_digest: 'b'.repeat(64),
};

function finding(revision: number, overrides: Partial<Finding> = {}): Finding {
  return {
    id: 501,
    scan_id: 41,
    scan_finding_number: 1,
    display_id: 'S41-F001',
    scanner: 'sast-lite',
    rule_id: 'shell-true',
    severity: 'high',
    file_path: 'app.py',
    start_line: 25,
    start_column: 14,
    end_line: 25,
    end_column: 58,
    message: 'Unsafe shell invocation',
    code_snippet: 'subprocess.run(command, shell=True)',
    fingerprint: 'immutable-fingerprint',
    suppressed: false,
    lifecycle_status: 'open',
    gate_exempt: false,
    gate_effect: 'blocking',
    occurrence_count: 1,
    is_repeat: false,
    revision,
    findings_revision: revision,
    ...overrides,
  };
}

function localRoute(): Extract<ResolvedAdvisorRoute, { kind: 'local' }> {
  return {
    kind: 'local',
    provider: {
      id: 'local-ollama',
      name: 'Local Ollama',
      transport: 'local',
      priority: 0,
      enabled: true,
      base_url: null,
      model: 'qwen3:8b',
      model_digest: 'b'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
      config_revision: 4,
      config_digest: 'a'.repeat(64),
      status: 'active',
      eligible: true,
      authorization: 'not_required',
      content_disclosure_approved: false,
      reason: null,
      last_tested_at: null,
    },
    pin,
  };
}

const queuedJob = { id: 91, status: 'queued' } as Job;
const conflict = Object.assign(new Error('revision conflict'), { name: 'ApiError', code: 'revision_conflict' });
const isConflict = (error: unknown) => error instanceof Error && 'code' in error && error.code === 'revision_conflict';

test('one reconciliation preserves identity, commits current state, refreshes the provider pin, and retries once', async () => {
  const original = finding(2);
  const current = finding(3, { ai_verdict: 'true_positive' });
  const calls: string[] = [];
  const result = await retryLocalAdvisorAfterRevisionConflict(original, {
    reconcileOnce: async () => {
      calls.push('reconcile');
      return { finding: current, detail: current, commit: () => calls.push('commit') };
    },
    resolveRoute: async () => {
      calls.push('provider');
      return localRoute();
    },
    queue: async (target, refreshedPin) => {
      calls.push('queue');
      assert.equal(target.revision, 3);
      assert.equal(refreshedPin.provider_collection_revision, 7);
      return queuedJob;
    },
    isRevisionConflict: isConflict,
    isFindingRemoved: () => false,
  });

  assert.deepEqual(calls, ['reconcile', 'commit', 'provider', 'queue']);
  assert.equal(result.job, queuedJob);
  assert.equal(result.finding, current);
  assert.equal(result.providerName, 'Local Ollama');
});

test('removal and immutable substitution are terminal before provider refresh or retry', async () => {
  for (const [reconciled, expectedCode] of [
    [null, 'finding_removed'],
    [{ finding: finding(3, { fingerprint: 'replacement' }), detail: finding(3, { fingerprint: 'replacement' }), commit: () => assert.fail('must not commit') }, 'finding_substituted'],
  ] as const) {
    let downstreamCalls = 0;
    await assert.rejects(
      retryLocalAdvisorAfterRevisionConflict(finding(2), {
        reconcileOnce: async () => reconciled,
        resolveRoute: async () => { downstreamCalls += 1; return localRoute(); },
        queue: async () => { downstreamCalls += 1; return queuedJob; },
        isRevisionConflict: isConflict,
        isFindingRemoved: () => false,
      }),
      (error: unknown) => error instanceof AdvisorFindingReconciliationError && error.code === expectedCode,
    );
    assert.equal(downstreamCalls, 0);
  }
});

test('a second conflict is terminal and never loops', async () => {
  let reconciliations = 0;
  let queueAttempts = 0;
  await assert.rejects(
    retryLocalAdvisorAfterRevisionConflict(finding(2), {
      reconcileOnce: async () => {
        reconciliations += 1;
        const current = finding(3);
        return { finding: current, detail: current, commit: () => undefined };
      },
      resolveRoute: async () => localRoute(),
      queue: async () => { queueAttempts += 1; throw conflict; },
      isRevisionConflict: isConflict,
      isFindingRemoved: () => false,
    }),
    (error: unknown) => error instanceof AdvisorFindingReconciliationError && error.code === 'second_revision_conflict',
  );
  assert.equal(reconciliations, 1);
  assert.equal(queueAttempts, 1);
});
