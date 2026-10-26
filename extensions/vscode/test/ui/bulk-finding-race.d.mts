import type { Page } from 'playwright-core';
export function armBulkFindingRace(input: {
  page: Page; endpoint: string; selected: Array<{ id: number; revision: number }>;
  assertCurrent?: () => Promise<void>; remaining?: () => number; timeout?: number;
  observeCompeting: (fault: { kind: string; mutation_requests: number; finding_id: number; expected_revision: number }) => Promise<{ status: 'PASS' }>;
}): Promise<{ observed(): { status: 'PASS' }; close(): Promise<void> }>;
