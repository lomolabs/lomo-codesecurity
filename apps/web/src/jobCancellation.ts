export type CancellationResponse = Readonly<{
  status: string;
  cancel_requested_at?: string | null;
}>;

export type CancellationOutcome = Readonly<{
  detail: string;
  tone: 'info' | 'success';
}>;

export function cancellationOutcome(
  response: CancellationResponse,
  copy: Readonly<{ completed: string; pending: string }>,
): CancellationOutcome {
  if (response.status === 'cancelled') {
    return { detail: copy.completed, tone: 'success' };
  }
  if (['completed', 'failed'].includes(response.status)) {
    return {
      detail: response.cancel_requested_at
        ? `The job finished as ${response.status} before cancellation could take effect. Its terminal result is authoritative; no cancellation remains pending.`
        : `The job finished as ${response.status} before cancellation was persisted. No cancellation was recorded.`,
      tone: 'info',
    };
  }
  if (response.cancel_requested_at || response.status === 'cancelling') {
    return { detail: copy.pending, tone: 'success' };
  }
  return {
    detail: `Cancellation was not recorded; the job remains ${response.status}. Refresh its status before trying again.`,
    tone: 'info',
  };
}
