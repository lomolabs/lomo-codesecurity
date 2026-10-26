/** Dependency-free typed request failure shared by pure source adapters and the client. */
export class CodeSecurityRequestError extends Error {
  readonly status?: number;
  readonly retryable: boolean;
  readonly code?: string;
  readonly action?: string;
  readonly correlationId?: string;
  readonly sourceBoundary?: Readonly<{
    selectedTarget?: string;
    authorizedRoots: readonly string[];
  }>;

  constructor(
    message: string,
    status?: number,
    retryable = false,
    problem?: Readonly<{
      code?: string;
      action?: string;
      correlationId?: string;
      sourceBoundary?: Readonly<{ selectedTarget?: string; authorizedRoots: readonly string[] }>;
    }>,
  ) {
    super(message);
    this.name = 'CodeSecurityRequestError';
    this.status = status;
    this.retryable = retryable;
    this.code = problem?.code;
    this.action = problem?.action;
    this.correlationId = problem?.correlationId;
    this.sourceBoundary = problem?.sourceBoundary;
  }
}
