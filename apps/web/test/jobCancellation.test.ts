import assert from 'node:assert/strict';
import test from 'node:test';

import { cancellationOutcome } from '../src/jobCancellation.ts';

const copy = {
  completed: 'Cancellation complete.',
  pending: 'Cancellation persisted.',
};

test('terminal completion racing cancellation never claims cancellation was persisted', () => {
  assert.deepEqual(cancellationOutcome({ status: 'completed' }, copy), {
    detail: 'The job finished as completed before cancellation was persisted. No cancellation was recorded.',
    tone: 'info',
  });
  assert.deepEqual(
    cancellationOutcome(
      { status: 'completed', cancel_requested_at: '2026-08-31T16:00:00Z' },
      copy,
    ),
    {
      detail: 'The job finished as completed before cancellation could take effect. Its terminal result is authoritative; no cancellation remains pending.',
      tone: 'info',
    },
  );
  assert.deepEqual(
    cancellationOutcome(
      { status: 'running', cancel_requested_at: '2026-08-31T16:00:00Z' },
      copy,
    ),
    { detail: 'Cancellation persisted.', tone: 'success' },
  );
  assert.deepEqual(cancellationOutcome({ status: 'cancelled' }, copy), {
    detail: 'Cancellation complete.',
    tone: 'success',
  });
});
