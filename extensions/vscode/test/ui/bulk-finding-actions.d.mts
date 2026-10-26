import type { Page, Locator } from 'playwright-core';

type Lifecycle = 'open' | 'needs_review' | 'gate_exempt' | 'accepted_risk' | 'ignore' | 'false_positive' | 'fixed';
type Selection = { id: number; display_id: string; revision?: number; status?: Lifecycle };
type Fence = () => Promise<void>;
export const BULK_LIFECYCLE_ACTIONS: ReadonlyArray<readonly [string, Lifecycle, string | null]>;
export function prepareBulkFindingSelection(input: {
  page: Page; surface: Locator; selected: Selection[]; assertCurrent: Fence; timeout?: number;
  remaining?: () => number;
}): Promise<Locator>;
export function waitForBulkSelection(input: {
  page: Page; selected: Selection[]; timeout?: number; status?: Lifecycle | null;
  assertCurrent?: Fence; remaining?: () => number;
}): Promise<void>;
type Observation = { action: string; cancelled: boolean; status?: number; request?: unknown; response?: unknown };
export function performBulkFindingAction(input: {
  page: Page; surface: Locator; endpoint: string; action: Lifecycle | 'delete'; reason?: string | null;
  cancel?: boolean; assertCurrent: Fence; timeout?: number;
  remaining?: () => number;
}): Promise<Observation>;
export function verifyBulkFindingRequest(observed: Observation, input: {
  selected: Array<{ id: number; revision: number }>; action: Lifecycle | 'delete'; reason?: string | null; scanId: number;
  conflict?: Record<string, number> | null;
}): { status: 'PASS' };
