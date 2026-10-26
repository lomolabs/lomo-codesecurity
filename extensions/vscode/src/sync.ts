import { CodeSecurityRequestError } from './client';

export type RefreshIntent = Readonly<{
  key: string;
  proof: string;
  supersedes: boolean;
}>;

type Waiter<T> = {
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
  signal?: AbortSignal;
  stop?: () => void;
};

type Operation<T> = {
  intent: RefreshIntent;
  controller: AbortController;
  waiters: Set<Waiter<T>>;
};


function abortError(message = 'The CodeSecurity refresh was stopped.'): DOMException {
  return new DOMException(message, 'AbortError');
}


export class RefreshProofSupersededError extends CodeSecurityRequestError {
  constructor() {
    super(
      'A different authoritative refresh proof superseded this reconciliation; retry after replay.',
      409,
      true,
    );
    this.name = 'RefreshProofSupersededError';
  }
}


/**
 * Coalesces one authoritative refresh per workspace without weakening cursor
 * acknowledgement. A newer event/reset may abort the transport work of an
 * older refresh, but the older caller is transferred to the replacement and
 * settles only after that replacement succeeds. A manual refresh joins any
 * work already proving the latest state instead of starting another page walk.
 */
export class WorkspaceRefreshCoordinator<T> {
  private readonly operations = new Map<string, Operation<T>>();
  private disposed = false;

  run(
    workspaceKey: string,
    intent: RefreshIntent,
    operation: (signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    if (this.disposed) return Promise.reject(abortError());
    if (signal?.aborted) return Promise.reject(abortError());

    let current = this.operations.get(workspaceKey);
    const joinsCurrent = current
      && current.intent.proof === intent.proof
      && (current.intent.key === intent.key || !intent.supersedes);
    if (!joinsCurrent) {
      const transfersProof = current?.intent.proof === intent.proof;
      const waiters = transfersProof ? current!.waiters : new Set<Waiter<T>>();
      if (current && !transfersProof) {
        this.reject(current.waiters, new RefreshProofSupersededError());
      }
      current?.controller.abort();
      current = {
        intent,
        controller: new AbortController(),
        waiters,
      };
      this.operations.set(workspaceKey, current);
      this.start(workspaceKey, current, operation);
    }

    const active = current as Operation<T>;
    return new Promise<T>((resolve, reject) => {
      const waiter: Waiter<T> = { resolve, reject, signal };
      const stop = () => {
        const latest = this.operations.get(workspaceKey);
        latest?.waiters.delete(waiter);
        signal?.removeEventListener('abort', stop);
        reject(abortError());
        if (latest?.waiters.size === 0) {
          this.operations.delete(workspaceKey);
          latest.controller.abort();
        }
      };
      waiter.stop = stop;
      active.waiters.add(waiter);
      signal?.addEventListener('abort', stop, { once: true });
      // The signal can become aborted between the initial check and listener
      // registration. Settle it synchronously rather than retaining a waiter.
      if (signal?.aborted) stop();
    });
  }

  cancel(workspaceKey: string, error: unknown = abortError()): void {
    const current = this.operations.get(workspaceKey);
    if (!current) return;
    this.operations.delete(workspaceKey);
    current.controller.abort();
    this.reject(current.waiters, error);
  }

  cancelAll(error: unknown = abortError()): void {
    for (const key of [...this.operations.keys()]) this.cancel(key, error);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.cancelAll();
  }

  get activeCount(): number {
    return this.operations.size;
  }

  private start(
    workspaceKey: string,
    current: Operation<T>,
    operation: (signal: AbortSignal) => Promise<T>,
  ): void {
    void Promise.resolve()
      .then(() => operation(current.controller.signal))
      .then(
        (value) => {
          if (this.operations.get(workspaceKey) !== current) return;
          this.operations.delete(workspaceKey);
          this.resolve(current.waiters, value);
        },
        (error) => {
          // Superseding work inherits these waiters. The aborted operation is
          // intentionally silent; only the replacement may settle them.
          if (this.operations.get(workspaceKey) !== current) return;
          this.operations.delete(workspaceKey);
          this.reject(current.waiters, error);
        },
      );
  }

  private resolve(waiters: Set<Waiter<T>>, value: T): void {
    for (const waiter of waiters) {
      waiter.signal?.removeEventListener('abort', waiter.stop!);
      waiter.resolve(value);
    }
    waiters.clear();
  }

  private reject(waiters: Set<Waiter<T>>, error: unknown): void {
    for (const waiter of waiters) {
      waiter.signal?.removeEventListener('abort', waiter.stop!);
      waiter.reject(error);
    }
    waiters.clear();
  }
}
