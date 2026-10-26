import type { AdvisorTriageProviderPin, Finding, Job } from './api';
import type { ResolvedAdvisorRoute } from './advisorRouting';

export type AdvisorFindingReconciliationFailure =
  | 'finding_removed'
  | 'finding_substituted'
  | 'provider_changed'
  | 'second_revision_conflict';

export class AdvisorFindingReconciliationError extends Error {
  readonly code: AdvisorFindingReconciliationFailure;

  constructor(
    code: AdvisorFindingReconciliationFailure,
    message: string,
  ) {
    super(message);
    this.name = 'AdvisorFindingReconciliationError';
    this.code = code;
  }
}

export function findingIdentityAndEvidenceMatches(left: Finding, right: Finding): boolean {
  return (
    left.id === right.id
    && left.scan_id === right.scan_id
    && left.scan_finding_number === right.scan_finding_number
    && left.display_id === right.display_id
    && left.fingerprint === right.fingerprint
    && left.scanner === right.scanner
    && left.rule_id === right.rule_id
    && left.severity === right.severity
    && left.file_path === right.file_path
    && left.start_line === right.start_line
    && left.start_column === right.start_column
    && left.end_line === right.end_line
    && left.end_column === right.end_column
    && left.message === right.message
  );
}

export type ReconciledAdvisorFinding = Readonly<{
  finding: Finding;
  detail: Finding;
  commit: () => void;
}>;

type RetryLocalAdvisorDependencies = Readonly<{
  reconcileOnce: (original: Finding) => Promise<ReconciledAdvisorFinding | null>;
  resolveRoute: () => Promise<ResolvedAdvisorRoute>;
  queue: (finding: Finding, pin: AdvisorTriageProviderPin) => Promise<Job>;
  isRevisionConflict: (error: unknown) => boolean;
  isFindingRemoved: (error: unknown) => boolean;
}>;

export async function retryLocalAdvisorAfterRevisionConflict(
  original: Finding,
  dependencies: RetryLocalAdvisorDependencies,
): Promise<Readonly<{
  job: Job;
  finding: Finding;
  providerName: string;
}>> {
  let reconciled: ReconciledAdvisorFinding | null;
  try {
    reconciled = await dependencies.reconcileOnce(original);
  } catch (error) {
    if (dependencies.isFindingRemoved(error)) {
      throw new AdvisorFindingReconciliationError(
        'finding_removed',
        'The selected finding was removed during Advisor reconciliation.',
      );
    }
    if (dependencies.isRevisionConflict(error)) {
      throw new AdvisorFindingReconciliationError(
        'second_revision_conflict',
        'The finding changed again during the single authoritative Advisor reconciliation.',
      );
    }
    throw error;
  }
  if (!reconciled) {
    throw new AdvisorFindingReconciliationError(
      'finding_removed',
      'The selected finding was removed during Advisor reconciliation.',
    );
  }
  if (
    !findingIdentityAndEvidenceMatches(reconciled.finding, original)
    || !findingIdentityAndEvidenceMatches(reconciled.detail, reconciled.finding)
  ) {
    throw new AdvisorFindingReconciliationError(
      'finding_substituted',
      'The selected finding no longer has the same immutable identity and evidence binding.',
    );
  }

  // Commit the one authoritative snapshot before retrying. A terminal provider
  // change or second conflict must still leave the user's logical selection on
  // the current finding rather than restoring stale UI state.
  reconciled.commit();
  const route = await dependencies.resolveRoute();
  if (route.kind !== 'local') {
    throw new AdvisorFindingReconciliationError(
      'provider_changed',
      'Advisor routing changed away from the local provider during reconciliation.',
    );
  }
  try {
    const job = await dependencies.queue(reconciled.detail, route.pin);
    return { job, finding: reconciled.detail, providerName: route.provider.name };
  } catch (error) {
    if (dependencies.isFindingRemoved(error)) {
      throw new AdvisorFindingReconciliationError(
        'finding_removed',
        'The selected finding was removed before the single Advisor retry completed.',
      );
    }
    if (dependencies.isRevisionConflict(error)) {
      throw new AdvisorFindingReconciliationError(
        'second_revision_conflict',
        'The finding changed again when CodeSecurity retried Advisor once.',
      );
    }
    throw error;
  }
}
