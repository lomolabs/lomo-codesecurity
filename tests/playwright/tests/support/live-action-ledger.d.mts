export type LiveWebActionProof = {
  ok: true;
  summary: string;
  evidence: unknown;
};

export type LiveWebActionStep = {
  id: string;
  action: string;
  evidencePointer: string;
  act: () => Promise<unknown>;
  verifyVisible: () => Promise<LiveWebActionProof>;
  verifyBackend: () => Promise<LiveWebActionProof>;
};

export type LiveWebActionLedger = Readonly<{
  schema: string;
  platform: string;
  run_id: string;
  started_at: string;
  completed_at: string | null;
  status: 'running' | 'passed' | 'partial' | 'failed';
  coverage: Readonly<{
    complete: boolean;
    required_ids: readonly string[];
    passed_ids: readonly string[];
    failed_ids: readonly string[];
    unexecuted_ids: readonly string[];
  }>;
  entries: readonly Readonly<Record<string, unknown>>[];
}>;

export class LiveWebActionError extends Error {
  actionId: string | undefined;
  ledger: LiveWebActionLedger | undefined;
}

export function runLiveWebActionLedger(input: {
  platform: string;
  runId: string;
  steps: LiveWebActionStep[];
  clock?: () => string;
}): Promise<LiveWebActionLedger>;
