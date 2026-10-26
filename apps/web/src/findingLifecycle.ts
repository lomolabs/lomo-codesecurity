const actionLabels: Readonly<Record<string, string>> = Object.freeze({
  accepted_risk: 'accepted risk',
  false_positive: 'a false positive',
  fixed: 'fixed',
  gate_exempt: 'non-blocking for gate',
  ignore: 'ignored and not counted',
  needs_review: 'needs review',
  open: 'open and blocking',
});

// Matches the production FindingBulkAction request bound. Keep the selection
// intact above this limit; never split one confirmed mutation into hidden jobs.
export const findingBulkActionLimit = 200;

export function findingBulkSelectionDisabledReason(selectedCount: number): string | null {
  if (selectedCount === 0) return 'Select one or more findings to use lifecycle actions.';
  if (selectedCount > findingBulkActionLimit) {
    return `Select at most ${findingBulkActionLimit} findings per action. ${selectedCount} are selected across pages; deselect findings or clear the selection to continue.`;
  }
  return null;
}

export function findingLifecycleActionLabel(action: string): string {
  return actionLabels[action] || action.replace(/_/g, ' ');
}

export function findingLifecycleActionDisabledReason(
  action: string,
  currentStatus: string,
): string | null {
  if (!(action in actionLabels) || action !== currentStatus) return null;
  return `This finding is already ${findingLifecycleActionLabel(action)}.`;
}

const gateEffectLabels: Readonly<Record<string, string>> = Object.freeze({
  blocking: 'Blocking',
  non_blocking: 'Non-blocking for gate',
  excluded: 'Not counted',
});

const advisorVerdictLabels: Readonly<Record<string, string>> = Object.freeze({
  true_positive: 'Likely valid finding',
  false_positive: 'Likely false positive',
  needs_review: 'Needs review',
});

export function findingGateEffectLabel(effect: string): string {
  return gateEffectLabels[effect] || 'Unknown gate effect';
}

export function findingAdvisorVerdictLabel(verdict: string | null | undefined): string {
  if (!verdict) return '';
  return advisorVerdictLabels[verdict] || 'Advisor result available';
}
