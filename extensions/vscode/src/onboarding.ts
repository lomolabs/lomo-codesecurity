export const SETUP_CONTEXT_PREFIX = 'lomoCodeSecurity.setup.';
export type SetupStep = 'backend' | 'connection' | 'repositories' | 'scan' | 'review' | 'protection';
const steps: readonly SetupStep[] = ['backend', 'connection', 'repositories', 'scan', 'review', 'protection'];
type RepositoryObservation = Readonly<{ projectId: number; complete: boolean }>;

/** Current session observations only. Command clicks and saved flags are not evidence. */
export class SetupProgress {
  private readonly values = new Map<SetupStep, boolean>();
  private roots = new Set<string>();
  private readonly repositories = new Map<string, RepositoryObservation>();
  private readonly reviews = new Set<string>();
  private readonly protections = new Set<string>();
  constructor(private readonly publish: (key: string, complete: boolean) => void) { this.invalidate(); }

  private set(step: SetupStep, value: boolean): void {
    if (this.values.get(step) === value) return;
    this.values.set(step, value);
    this.publish(`${SETUP_CONTEXT_PREFIX}${step}`, value);
  }

  invalidate(): void {
    this.roots.clear(); this.repositories.clear(); this.reviews.clear(); this.protections.clear();
    for (const step of steps) this.set(step, false);
  }
  backend(value: unknown): void { this.set('backend', value === true); }
  connection(trusted: boolean, activeIde: boolean, verifiedBrowser: boolean): void {
    this.set('connection', trusted === true && activeIde === true && verifiedBrowser === true);
  }
  selectRoots(keys: readonly string[]): void {
    const next = new Set(keys);
    for (const key of this.roots) if (!next.has(key)) this.drop(key);
    this.roots = next;
    this.updateRepositories();
  }
  drop(key: string): void {
    this.roots.delete(key); this.repositories.delete(key); this.reviews.delete(key); this.protections.delete(key);
    this.updateRepositories();
  }
  observeRepository(key: string, projectId: number, scan: unknown): void {
    if (!this.roots.has(key)) return;
    if (!Number.isSafeInteger(projectId) || projectId < 1) {
      this.repositories.delete(key); this.reviews.delete(key); this.protections.delete(key); this.updateRepositories(); return;
    }
    const previous = this.repositories.get(key);
    if (previous && previous.projectId !== projectId) { this.reviews.delete(key); this.protections.delete(key); }
    const item = scan && typeof scan === 'object' && !Array.isArray(scan) ? scan as Record<string, unknown> : undefined;
    const summary = item?.scanner_summary as Record<string, unknown> | undefined;
    const coverage = summary?.source_coverage as Record<string, unknown> | undefined;
    const capture = summary?.source_capture as Record<string, unknown> | undefined;
    const complete = item?.project_id === projectId && item.status === 'completed' && coverage?.complete === true
      && (capture === undefined || capture.complete === true);
    this.repositories.set(key, { projectId, complete });
    this.updateRepositories();
  }
  reviewed(key: string): void {
    if (this.roots.has(key) && this.repositories.has(key)) { this.reviews.add(key); this.updateRepositories(); }
  }
  observedProtection(key: string, host: unknown): void {
    const item = host && typeof host === 'object' && !Array.isArray(host) ? host as Record<string, unknown> : undefined;
    if (this.roots.has(key) && item?.state === 'installed' && typeof item.enabled === 'boolean'
      && Number.isSafeInteger(item.revision) && (item.revision as number) > 0
      && typeof item.hookDigest === 'string' && /^[a-f0-9]{64}$/u.test(item.hookDigest)) this.protections.add(key);
    else this.protections.delete(key);
    this.updateRepositories();
  }
  private updateRepositories(): void {
    const registered = this.roots.size > 0 && [...this.roots].every(key => this.repositories.has(key));
    this.set('repositories', registered);
    this.set('scan', registered && [...this.roots].every(key => this.repositories.get(key)?.complete === true));
    this.set('review', this.reviews.size > 0);
    this.set('protection', this.protections.size > 0);
  }
}
