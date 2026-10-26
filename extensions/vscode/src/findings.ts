import findingLabels = require('./finding-labels.json');

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingLifecycle =
  | 'open'
  | 'needs_review'
  | 'gate_exempt'
  | 'accepted_risk'
  | 'ignore'
  | 'false_positive'
  | 'fixed';
export type FindingGateEffect = 'blocking' | 'non_blocking' | 'excluded';

export function findingLifecycleLabel(value: FindingLifecycle): string {
  return findingLabels.lifecycle[value];
}

export function findingGateEffectLabel(value: FindingGateEffect): string {
  return findingLabels.gate_effect[value];
}

export type FindingFileAggregate = {
  file_path: string;
  first_scan_finding_number: number;
  total: number;
  active: number;
  suppressed: number;
  gate_exempt: number;
  blocking: number;
  severity_counts: Readonly<Record<FindingSeverity, number>>;
  lifecycle_counts: Readonly<Record<FindingLifecycle, number>>;
};

export type FindingFileIndex = Pick<FindingFileAggregate,
  | 'file_path'
  | 'first_scan_finding_number'
  | 'total'
  | 'active'
  | 'suppressed'
  | 'gate_exempt'
  | 'blocking'
>;

export interface FindingFileIndexMap extends Iterable<[string, FindingFileIndex]> {
  readonly size: number;
  has(path: string): boolean;
  get(path: string): FindingFileIndex | undefined;
  entries(): IterableIterator<[string, FindingFileIndex]>;
  keys(): IterableIterator<string>;
  values(): IterableIterator<FindingFileIndex>;
  forEach(
    callback: (value: FindingFileIndex, key: string, map: FindingFileIndexMap) => void,
    thisArg?: unknown,
  ): void;
}

export type DiagnosticProjectionState = 'loading' | 'complete' | 'limited';

export type FindingSummary = {
  id: number;
  scan_id: number;
  scan_finding_number: number;
  display_id: string;
  scanner: string;
  rule_id: string;
  severity: FindingSeverity;
  file_path: string;
  start_line?: number | null;
  start_column?: number | null;
  end_line?: number | null;
  end_column?: number | null;
  message: string;
  fingerprint: string;
  lifecycle_status: FindingLifecycle;
  gate_exempt: boolean;
  gate_effect: FindingGateEffect;
  suppressed: boolean;
  occurrence_count: number;
  is_repeat: boolean;
  first_seen_display_id?: string | null;
  first_seen_scan_id?: number | null;
  advisor_verdict?: string | null;
  advisor_confidence?: number | null;
  revision: number;
};

const SEVERITY_ORDER = new Map(['critical', 'high', 'medium', 'low', 'info'].map((value, index) => [value, index]));

export function compareFindingSeverity(left: string, right: string): number {
  return (SEVERITY_ORDER.get(left) ?? 99) - (SEVERITY_ORDER.get(right) ?? 99);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function compareFindingPresentation(
  left: Pick<FindingSummary, 'severity' | 'scanner' | 'display_id' | 'scan_id' | 'scan_finding_number' | 'id'>,
  right: Pick<FindingSummary, 'severity' | 'scanner' | 'display_id' | 'scan_id' | 'scan_finding_number' | 'id'>,
): number {
  return compareFindingSeverity(left.severity, right.severity)
    || compareText(left.scanner, right.scanner)
    || compareText(left.display_id, right.display_id)
    || left.scan_id - right.scan_id
    || left.scan_finding_number - right.scan_finding_number
    || left.id - right.id;
}

export function unicodeBoundedText(value: string, length: number): string {
  const points = Array.from(value);
  if (points.length <= length) return value;
  if (length <= 1) return '…'.slice(0, Math.max(length, 0));
  return `${points.slice(0, length - 1).join('')}…`;
}

export function boundedSingleLineText(value: string, length = 180): string {
  const normalized = value
    .replace(/\r\n?/gu, '\n')
    .replace(/[\p{Cc}\p{Cf}\p{Cs}]+/gu, ' ')
    .trim();
  return unicodeBoundedText(normalized, length);
}

/** Format an already ordered, current line aggregate without changing its membership. */
export function findingInlineAnnotation(
  primary: Pick<FindingSummary, 'display_id' | 'severity' | 'scanner'>,
  extra: number,
  mode: 'compact' | 'detailed' = 'compact',
): string {
  const suffix = extra > 0 ? ` +${extra} report${extra === 1 ? '' : 's'}` : '';
  const scanner = boundedSingleLineText(primary.scanner, 80);
  return mode === 'detailed'
    ? `  [${primary.display_id} · ${primary.severity.toUpperCase()} · ${scanner}${suffix}]`
    : `  [${primary.severity.toUpperCase()} · ${scanner}${suffix}]`;
}

/**
 * The compact, immutable subset needed to project VS Code Problems. Keeping
 * this separate from FindingSummary prevents the background projection from
 * retaining lifecycle, occurrence, Advisor, and fingerprint data for every
 * finding in a large scan.
 */
export type FindingDiagnostic = {
  id: number;
  scan_finding_number: number;
  display_id: string;
  scanner: string;
  severity: FindingSeverity;
  file_path: string;
  start_line?: number | null;
  start_column?: number | null;
  end_line?: number | null;
  end_column?: number | null;
  message: string;
  revision: number;
};

export type FindingDetail = FindingSummary & {
  findings_revision?: number;
  code_snippet?: string | null;
  metadata_json?: Record<string, unknown>;
  ai_verdict?: string | null;
  ai_confidence?: number | null;
  ai_reasoning?: string | null;
  ai_fix?: string | null;
  suppression_reason?: string | null;
  gate_exempt_reason?: string | null;
  lifecycle_reason?: string | null;
  lifecycle_updated_at?: string | null;
  created_at?: string;
};

export type FindingRange = {
  startLine: number;
  startCharacter: number;
  endLine: number;
  endCharacter: number;
};

export type FindingScanScope = Readonly<
  { kind: 'workspace' | 'unknown' } | { kind: 'file' | 'directory'; targetPath: string }
>;

export type IndexedWorkspace = {
  key: string;
  label: string;
  rootUri: string;
  projectId: number;
  projectRevision: number;
  scanId: number;
  scanRevision: number;
  scanStatus: string;
  scanScope?: FindingScanScope;
  gateDecision?: string | null;
  revision: number;
  totalFindings: number;
  totalFiles: number;
  fileManifest: FindingFileIndexMap;
  diagnosticProjection: DiagnosticProjectionState;
  diagnosticProcessed: number;
  findings: readonly FindingSummary[];
  files: ReadonlyMap<string, readonly FindingSummary[]>;
  staleFiles: ReadonlySet<string>;
  allFilesStale: boolean;
};

type InvalidatedWorkspace = Pick<IndexedWorkspace,
  'projectId' | 'scanId' | 'staleFiles' | 'allFilesStale'>;

export type WorkspaceIndexInput = Omit<IndexedWorkspace,
  'findings' | 'files' | 'staleFiles' | 'allFilesStale' | 'totalFindings' | 'totalFiles' | 'fileManifest'
  | 'diagnosticProjection' | 'diagnosticProcessed'> & {
    totalFindings?: number;
    totalFiles?: number;
    fileManifest?: FindingFileIndexMap;
    diagnosticProjection?: DiagnosticProjectionState;
    diagnosticProcessed?: number;
    allFilesStale?: boolean;
  };
export type YieldControl = () => Promise<void>;
export const MAX_HYDRATED_FINDINGS = 5_000;
export const MAX_AUTOMATIC_HYDRATION_FILES = 64;

const integerAtLeast = (value: unknown, minimum: number, fallback: number): number => (
  Number.isSafeInteger(value) && (value as number) >= minimum ? value as number : fallback
);

/** Keep detail-only evidence out of the high-cardinality lightweight index. */
export function findingSummary(value: FindingSummary): FindingSummary {
  return {
    id: value.id,
    scan_id: value.scan_id,
    scan_finding_number: value.scan_finding_number,
    display_id: value.display_id,
    scanner: value.scanner,
    rule_id: value.rule_id,
    severity: value.severity,
    file_path: value.file_path,
    start_line: value.start_line,
    start_column: value.start_column,
    end_line: value.end_line,
    end_column: value.end_column,
    message: value.message,
    fingerprint: value.fingerprint,
    lifecycle_status: value.lifecycle_status,
    gate_exempt: value.gate_exempt,
    gate_effect: value.gate_effect,
    suppressed: value.suppressed,
    occurrence_count: value.occurrence_count,
    is_repeat: value.is_repeat,
    first_seen_display_id: value.first_seen_display_id,
    first_seen_scan_id: value.first_seen_scan_id,
    advisor_verdict: value.advisor_verdict,
    advisor_confidence: value.advisor_confidence,
    revision: value.revision,
  };
}

/**
 * Convert one-based normalized SARIF coordinates to a bounded VS Code range.
 * API columns use SARIF semantics: one-based with an exclusive end. VS Code
 * uses zero-based positions with an exclusive end, so both subtract one.
 * A line-only result uses a zero column on its normalized end line. The native
 * document-aware layer expands that to the actual line length. Keeping the
 * transport-level range bounded avoids an unbounded character sentinel and an
 * invalid synthetic line after the final document line.
 */
export function findingRange(finding: Pick<FindingSummary,
  'start_line' | 'start_column' | 'end_line' | 'end_column'>): FindingRange {
  const startLine = integerAtLeast(finding.start_line, 1, 1) - 1;
  const endLine = Math.max(integerAtLeast(finding.end_line, 1, startLine + 1) - 1, startLine);
  const hasStartColumn = Number.isSafeInteger(finding.start_column) && (finding.start_column as number) >= 1;
  const hasEndColumn = Number.isSafeInteger(finding.end_column) && (finding.end_column as number) >= 1;
  if (!hasStartColumn) {
    return { startLine, startCharacter: 0, endLine, endCharacter: 0 };
  }

  const startCharacter = (finding.start_column as number) - 1;
  if (!hasEndColumn) {
    if (endLine > startLine) {
      return { startLine, startCharacter, endLine, endCharacter: 0 };
    }
    return { startLine, startCharacter, endLine: startLine, endCharacter: startCharacter + 1 };
  }
  const endCharacter = (finding.end_column as number) - 1;
  if (endLine === startLine && endCharacter < startCharacter) {
    return { startLine, startCharacter, endLine, endCharacter: startCharacter + 1 };
  }
  return { startLine, startCharacter, endLine, endCharacter };
}

/**
 * Clamp a normalized finding to a concrete document without enumerating or
 * retaining the document. This is the range used by visible-editor surfaces.
 */
export function findingRangeForDocument(
  finding: Pick<FindingSummary, 'start_line' | 'start_column' | 'end_line' | 'end_column'>,
  lineCount: number,
  lineLength: (line: number) => number,
): FindingRange {
  const raw = findingRange(finding);
  const lastLine = Math.max((Number.isSafeInteger(lineCount) && lineCount > 0 ? lineCount : 1) - 1, 0);
  const startLine = Math.min(Math.max(raw.startLine, 0), lastLine);
  const endLine = Math.min(Math.max(raw.endLine, startLine), lastLine);
  const boundedLength = (line: number): number => {
    const length = lineLength(line);
    return Number.isSafeInteger(length) && length >= 0 ? length : 0;
  };
  const startLength = boundedLength(startLine);
  let startCharacter = Math.min(Math.max(raw.startCharacter, 0), startLength);
  const endLength = boundedLength(endLine);
  const hasStartColumn = Number.isSafeInteger(finding.start_column) && (finding.start_column as number) >= 1;
  const hasEndColumn = Number.isSafeInteger(finding.end_column) && (finding.end_column as number) >= 1;
  let endCharacter = Math.min(Math.max(raw.endCharacter, 0), endLength);

  // Missing columns mean the complete normalized line span. A multiline
  // start-only range likewise ends at the actual end of its final line.
  if (!hasStartColumn || !hasEndColumn && endLine > startLine) {
    endCharacter = endLength;
  }
  if (endLine === startLine && endCharacter < startCharacter) {
    if (startCharacter >= startLength && startLength > 0) startCharacter = startLength - 1;
    endCharacter = Math.min(startCharacter + 1, startLength);
  }
  return { startLine, startCharacter, endLine, endCharacter };
}

export function rangeContains(range: FindingRange, line: number, character: number): boolean {
  if (
    range.startLine === range.endLine
    && range.startCharacter === range.endCharacter
  ) {
    return line === range.startLine && character === range.startCharacter;
  }
  if (line < range.startLine || line > range.endLine) return false;
  if (line === range.startLine && character < range.startCharacter) return false;
  if (line === range.endLine && character >= range.endCharacter) return false;
  return true;
}

function defaultYield(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function aggregateFiles(findings: readonly FindingSummary[]): ReadonlyMap<string, FindingFileAggregate> {
  const files = new Map<string, FindingSummary[]>();
  for (const finding of findings) {
    const values = files.get(finding.file_path) || [];
    values.push(finding);
    files.set(finding.file_path, values);
  }
  return new Map([...files.entries()].map(([filePath, values]) => {
    const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const lifecycle = {
      open: 0,
      needs_review: 0,
      gate_exempt: 0,
      accepted_risk: 0,
      ignore: 0,
      false_positive: 0,
      fixed: 0,
    };
    for (const finding of values) {
      severity[finding.severity] += 1;
      lifecycle[finding.lifecycle_status] += 1;
    }
    const active = values.filter((finding) => !finding.suppressed).length;
    return [filePath, {
      file_path: filePath,
      first_scan_finding_number: Math.min(...values.map((finding) => finding.scan_finding_number)),
      total: values.length,
      active,
      suppressed: values.length - active,
      gate_exempt: values.filter((finding) => !finding.suppressed && finding.gate_exempt).length,
      blocking: values.filter((finding) => !finding.suppressed && finding.gate_effect === 'blocking').length,
      severity_counts: severity,
      lifecycle_counts: lifecycle,
    }];
  }));
}

/**
 * A bounded in-process index of lightweight finding summaries. It is not a
 * source of truth: every mutation is replaced only with an authoritative API
 * response. Detail records use deterministic LRU eviction.
 */
export class FindingStore {
  private readonly workspaces = new Map<string, IndexedWorkspace>();
  private readonly invalidatedWorkspaces = new Map<string, InvalidatedWorkspace>();
  private readonly details = new Map<string, FindingDetail>();
  private readonly workspaceGenerations = new Map<string, number>();
  private readonly hydratedFileUsage = new Map<string, Readonly<{
    workspaceKey: string;
    filePath: string;
  }>>();
  private nextWorkspaceGeneration = 0;
  private findingCount = 0;

  constructor(
    readonly maxFindings = 50_000,
    readonly maxDetails = 128,
    readonly chunkSize = 250,
  ) {
    if (![maxFindings, maxDetails, chunkSize].every((value) => Number.isSafeInteger(value) && value > 0)) {
      throw new RangeError('FindingStore bounds must be positive safe integers.');
    }
  }

  get size(): number {
    return this.findingCount;
  }

  get detailSize(): number {
    return this.details.size;
  }

  workspaceEntries(): readonly IndexedWorkspace[] {
    return [...this.workspaces.values()].sort((left, right) => (
      left.label.localeCompare(right.label) || left.key.localeCompare(right.key)
    ));
  }

  workspace(key: string): IndexedWorkspace | undefined {
    return this.workspaces.get(key);
  }

  private purgeDetailsForScans(scanIds: ReadonlySet<number>): void {
    if (scanIds.size === 0) return;
    for (const key of [...this.details.keys()]) {
      const separator = key.indexOf(':');
      const scanId = separator > 0 ? Number(key.slice(0, separator)) : Number.NaN;
      if (scanIds.has(scanId)) this.details.delete(key);
    }
  }

  async replaceWorkspace(
    input: WorkspaceIndexInput,
    findings: readonly FindingSummary[],
    yieldControl: YieldControl = defaultYield,
  ): Promise<IndexedWorkspace | undefined> {
    const generation = ++this.nextWorkspaceGeneration;
    this.workspaceGenerations.set(input.key, generation);
    const previous = this.workspaces.get(input.key);
    const invalidated = this.invalidatedWorkspaces.get(input.key);
    const projected = this.findingCount - (previous?.findings.length || 0) + findings.length;
    if (projected > this.maxFindings) {
      throw new RangeError(
        `The local finding index would exceed its explicit ${this.maxFindings}-item safety bound.`,
      );
    }

    const indexed: FindingSummary[] = [];
    const files = new Map<string, FindingSummary[]>();
    for (let offset = 0; offset < findings.length; offset += this.chunkSize) {
      const end = Math.min(offset + this.chunkSize, findings.length);
      for (let index = offset; index < end; index += 1) {
        const finding = findings[index];
        indexed.push(finding);
        const fileItems = files.get(finding.file_path) || [];
        fileItems.push(finding);
        files.set(finding.file_path, fileItems);
      }
      if (end < findings.length) await yieldControl();
    }

    // Workspace removal and a newer refresh both invalidate an in-flight
    // chunked build. Commit only the latest generation so a yielded 10k load
    // cannot resurrect a root after VS Code has removed it.
    if (this.workspaceGenerations.get(input.key) !== generation) return undefined;

    const current = this.workspaces.get(input.key);
    const commitCount = this.findingCount - (current?.findings.length || 0) + findings.length;
    if (commitCount > this.maxFindings) {
      throw new RangeError(
        `The local finding index would exceed its explicit ${this.maxFindings}-item safety bound.`,
      );
    }

    const fileManifest = input.fileManifest || aggregateFiles(findings);
    // Deleting the latest scan can reveal an older retained scan. Its disk
    // evidence cannot make an edit observed under the deleted scan trustworthy;
    // only a genuinely newer scan identity may clear session-local stale state.
    const staleAuthority = previous || invalidated;
    const carriesStaleState = staleAuthority
      && staleAuthority.projectId === input.projectId
      && input.scanId <= staleAuthority.scanId;
    const staleFiles = carriesStaleState
      ? new Set([...staleAuthority.staleFiles].filter((filePath) => fileManifest.has(filePath)))
      : new Set<string>();
    const workspace: IndexedWorkspace = {
      ...input,
      totalFindings: input.totalFindings ?? findings.length,
      totalFiles: input.totalFiles ?? fileManifest.size,
      fileManifest,
      diagnosticProjection: input.diagnosticProjection || 'complete',
      diagnosticProcessed: input.diagnosticProcessed
        ?? (input.diagnosticProjection === 'loading' ? 0 : input.totalFindings ?? findings.length),
      findings: indexed,
      files,
      staleFiles,
      allFilesStale: input.allFilesStale ?? (carriesStaleState ? staleAuthority.allFilesStale : false),
    };
    this.removeHydratedUsageForWorkspace(input.key);
    for (const filePath of files.keys()) this.touchHydratedUsage(input.key, filePath);
    this.workspaces.set(input.key, workspace);
    this.invalidatedWorkspaces.delete(input.key);
    this.findingCount = commitCount;
    // A refresh invalidates detail from both the replaced scan and the new
    // scan. The former must not survive when a workspace advances to another
    // scan; the latter may have changed at the collection revision just loaded.
    this.purgeDetailsForScans(new Set([input.scanId, ...(previous ? [previous.scanId] : [])]));
    return workspace;
  }

  replaceFinding(workspaceKey: string, replacement: FindingSummary): boolean {
    const current = this.workspaces.get(workspaceKey);
    if (!current) return false;
    const index = current.findings.findIndex((finding) => (
      finding.scan_id === replacement.scan_id
      && finding.scan_finding_number === replacement.scan_finding_number
    ));
    if (index < 0) return false;
    const findings = [...current.findings];
    findings[index] = findingSummary(replacement);
    const files = new Map<string, FindingSummary[]>();
    for (const finding of findings) {
      const values = files.get(finding.file_path) || [];
      values.push(finding);
      files.set(finding.file_path, values);
    }
    this.workspaces.set(workspaceKey, { ...current, findings, files });
    return true;
  }

  replaceFileFindings(
    workspaceKey: string,
    filePath: string,
    findings: readonly FindingSummary[],
    expectedRevision: number,
  ): boolean {
    const current = this.workspaces.get(workspaceKey);
    const aggregate = current?.fileManifest.get(filePath);
    let active = 0;
    let suppressed = 0;
    let gateExempt = 0;
    let blocking = 0;
    let rowsMatchIdentity = true;
    for (const finding of findings) {
      if (finding.scan_id !== current?.scanId || finding.file_path !== filePath) {
        rowsMatchIdentity = false;
      }
      if (finding.suppressed) {
        suppressed += 1;
        continue;
      }
      active += 1;
      if (finding.gate_exempt) gateExempt += 1;
      if (finding.gate_effect === 'blocking') blocking += 1;
    }
    if (
      !current
      || current.revision !== expectedRevision
      || !aggregate
      || current.allFilesStale
      || current.staleFiles.has(filePath)
      || findings.length !== aggregate.total
      || findings[0]?.scan_finding_number !== aggregate.first_scan_finding_number
      || !rowsMatchIdentity
      || active !== aggregate.active
      || suppressed !== aggregate.suppressed
      || gateExempt !== aggregate.gate_exempt
      || blocking !== aggregate.blocking
    ) return false;
    if (findings.length > this.maxFindings) {
      throw new RangeError(
        `Exact file hydration would exceed the explicit ${this.maxFindings}-summary local safety bound.`,
      );
    }
    const previous = current.files.get(filePath) || [];
    let projected = this.findingCount - previous.length + findings.length;
    while (projected > this.maxFindings) {
      if (!this.evictHydratedFile(workspaceKey, filePath)) {
        throw new RangeError(
          `Exact file hydration would exceed the explicit ${this.maxFindings}-summary local safety bound.`,
        );
      }
      projected = this.findingCount - previous.length + findings.length;
    }
    const latest = this.workspaces.get(workspaceKey);
    if (!latest || latest.revision !== expectedRevision) return false;
    const summaries = findings.map(findingSummary);
    const latestPrevious = latest.files.get(filePath) || [];
    const files = new Map(latest.files);
    files.delete(filePath);
    files.set(filePath, summaries);
    const retained = latest.findings
      .filter((finding) => finding.file_path !== filePath)
      .concat(summaries)
      .sort((left, right) => left.scan_finding_number - right.scan_finding_number);
    this.workspaces.set(workspaceKey, { ...latest, findings: retained, files });
    this.findingCount = this.findingCount - latestPrevious.length + summaries.length;
    this.touchHydratedUsage(workspaceKey, filePath);
    this.purgeDetailsForScans(new Set([latest.scanId]));
    return true;
  }

  touchFile(workspaceKey: string, filePath: string): boolean {
    const current = this.workspaces.get(workspaceKey);
    const findings = current?.files.get(filePath);
    if (!current || !findings) return false;
    const files = new Map(current.files);
    files.delete(filePath);
    files.set(filePath, findings);
    this.workspaces.set(workspaceKey, { ...current, files });
    this.touchHydratedUsage(workspaceKey, filePath);
    return true;
  }

  reserveHydratedCapacity(
    additionalFindings: number,
    excludedWorkspaceKey: string,
    excludedFilePath: string,
  ): Readonly<{ available: boolean; evicted: boolean }> {
    if (!Number.isSafeInteger(additionalFindings) || additionalFindings < 0) {
      throw new RangeError('Hydration capacity reservations must be non-negative safe integers.');
    }
    let evicted = false;
    while (this.findingCount + additionalFindings > this.maxFindings) {
      if (!this.evictHydratedFile(excludedWorkspaceKey, excludedFilePath)) {
        return { available: false, evicted };
      }
      evicted = true;
    }
    return { available: true, evicted };
  }

  private evictHydratedFile(excludedWorkspaceKey: string, excludedFilePath: string): boolean {
    for (const [usageKey, usage] of this.hydratedFileUsage) {
      if (usage.workspaceKey === excludedWorkspaceKey && usage.filePath === excludedFilePath) continue;
      this.hydratedFileUsage.delete(usageKey);
      const workspace = this.workspaces.get(usage.workspaceKey);
      const findings = workspace?.files.get(usage.filePath);
      if (!workspace || !findings) continue;
      const files = new Map(workspace.files);
      files.delete(usage.filePath);
      this.workspaces.set(usage.workspaceKey, {
        ...workspace,
        files,
        findings: workspace.findings.filter((finding) => finding.file_path !== usage.filePath),
      });
      this.findingCount -= findings.length;
      return true;
    }
    return false;
  }

  private hydratedUsageKey(workspaceKey: string, filePath: string): string {
    return JSON.stringify([workspaceKey, filePath]);
  }

  private touchHydratedUsage(workspaceKey: string, filePath: string): void {
    const key = this.hydratedUsageKey(workspaceKey, filePath);
    this.hydratedFileUsage.delete(key);
    this.hydratedFileUsage.set(key, { workspaceKey, filePath });
  }

  private removeHydratedUsageForWorkspace(workspaceKey: string): void {
    for (const [key, usage] of this.hydratedFileUsage) {
      if (usage.workspaceKey === workspaceKey) this.hydratedFileUsage.delete(key);
    }
  }

  updateWorkspaceState(
    workspaceKey: string,
    values: Partial<Pick<IndexedWorkspace,
      'projectRevision' | 'scanRevision' | 'scanStatus' | 'gateDecision' | 'revision'
      | 'diagnosticProjection' | 'diagnosticProcessed'>>,
  ): boolean {
    const current = this.workspaces.get(workspaceKey);
    if (!current) return false;
    const changed = Object.entries(values).some(([key, value]) => (
      current[key as keyof IndexedWorkspace] !== value
    ));
    if (!changed) return false;
    this.workspaces.set(workspaceKey, { ...current, ...values });
    return true;
  }

  markFileStale(workspaceKey: string, filePath: string): boolean {
    const current = this.workspaces.get(workspaceKey);
    if (
      !current
      || current.allFilesStale
      || !current.fileManifest.has(filePath)
      || current.staleFiles.has(filePath)
    ) return false;
    const staleFiles = new Set(current.staleFiles);
    staleFiles.add(filePath);
    this.workspaces.set(workspaceKey, { ...current, staleFiles });
    return true;
  }

  markAllFilesStale(workspaceKey: string): boolean {
    const current = this.workspaces.get(workspaceKey);
    if (!current || current.allFilesStale) return false;
    this.findingCount -= current.findings.length;
    this.removeHydratedUsageForWorkspace(workspaceKey);
    this.workspaces.set(workspaceKey, {
      ...current,
      findings: [],
      files: new Map(),
      allFilesStale: true,
    });
    return true;
  }

  removeWorkspace(key: string): void {
    this.workspaceGenerations.delete(key);
    this.invalidatedWorkspaces.delete(key);
    this.removeHydratedUsageForWorkspace(key);
    const current = this.workspaces.get(key);
    if (!current) return;
    this.findingCount -= current.findings.length;
    this.workspaces.delete(key);
    this.purgeDetailsForScans(new Set([current.scanId]));
  }

  invalidateWorkspace(key: string): boolean {
    const current = this.workspaces.get(key);
    if (!current) return false;
    this.workspaceGenerations.delete(key);
    this.removeHydratedUsageForWorkspace(key);
    this.invalidatedWorkspaces.set(key, {
      projectId: current.projectId,
      scanId: current.scanId,
      staleFiles: new Set(current.staleFiles),
      allFilesStale: current.allFilesStale,
    });
    this.findingCount -= current.findings.length;
    this.workspaces.delete(key);
    this.purgeDetailsForScans(new Set([current.scanId]));
    return true;
  }

  putDetail(detail: FindingDetail): void {
    const key = `${detail.scan_id}:${detail.scan_finding_number}`;
    this.details.delete(key);
    this.details.set(key, detail);
    while (this.details.size > this.maxDetails) {
      const oldest = this.details.keys().next().value as string | undefined;
      if (!oldest) break;
      this.details.delete(oldest);
    }
  }

  detail(scanId: number, scanFindingNumber: number): FindingDetail | undefined {
    const key = `${scanId}:${scanFindingNumber}`;
    const detail = this.details.get(key);
    if (!detail) return undefined;
    this.details.delete(key);
    this.details.set(key, detail);
    return detail;
  }

  clear(): void {
    this.workspaceGenerations.clear();
    this.hydratedFileUsage.clear();
    this.invalidatedWorkspaces.clear();
    this.workspaces.clear();
    this.details.clear();
    this.findingCount = 0;
  }
}
