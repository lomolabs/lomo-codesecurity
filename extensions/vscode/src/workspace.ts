import { createHash } from 'node:crypto';
import { win32 } from 'node:path';

import { CodeSecurityRequestError } from './request-error';
import {
  FindingDetail,
  FindingDiagnostic,
  FindingFileAggregate,
  FindingFileIndex,
  FindingFileIndexMap,
  FindingLifecycle,
  FindingSeverity,
  FindingScanScope,
  FindingSummary,
  YieldControl,
  findingSummary,
} from './findings';

export type { FindingDetail, FindingSummary } from './findings';
export type Finding = FindingSummary;

export type Project = {
  id: number;
  name: string;
  repo_path: string;
  revision?: number;
};

export type Scan = {
  id: number;
  project_id: number;
  status: string;
  gate_decision?: string | null;
  gate_reasons?: string[];
  scanner_summary?: Record<string, unknown>;
  findings_revision?: number;
  revision?: number;
  error?: string | null;
  job_id?: number | null;
  job_revision?: number | null;
};

/** The persisted execution scope, never inferred from how many findings remain. */
export function findingScanScope(scan: Scan): FindingScanScope {
  const value = scan.scanner_summary?.scope;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: 'unknown' };
  const { kind, target_path: path } = value as Record<string, unknown>;
  if (kind === 'workspace' && path == null) return { kind: 'workspace' };
  if ((kind === 'file' || kind === 'directory') && typeof path === 'string'
    && path.length <= 4096 && safeFindingRelativePath(path) === path) {
    return { kind, targetPath: path };
  }
  return { kind: 'unknown' };
}

/** The compact file manifest deliberately omits scanner details. Join scope from
 * the existing scan resource only at the same identity and revisions. */
export function withFindingScanScope(manifest: Scan, detail: Scan): Scan {
  if (!detail || manifest.id !== detail.id || manifest.project_id !== detail.project_id
    || detail.revision !== undefined && manifest.revision !== detail.revision
    || detail.findings_revision !== undefined && manifest.findings_revision !== detail.findings_revision) {
    throw new CodeSecurityRequestError('The scan changed while loading its scope. Refresh findings.', 409);
  }
  // Older/incomplete metadata may still supply an authoritative compact manifest,
  // but it cannot establish a matching execution scope.
  const scope: FindingScanScope = detail.revision === undefined || detail.findings_revision === undefined
    ? { kind: 'unknown' } : findingScanScope(detail);
  return { ...manifest, scanner_summary: { scope: {
    kind: scope.kind, target_path: 'targetPath' in scope ? scope.targetPath : null,
  } } };
}

export type FindingPage = {
  items: FindingSummary[];
  total: number;
  truncated: boolean;
  next_cursor: string | null;
  revision: number;
};

export type FindingDiagnosticPage = {
  scan_id: number;
  items: FindingDiagnostic[];
  total: number;
  truncated: boolean;
  next_cursor: string | null;
  revision: number;
};

export type ApiRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export type WorkspaceFindings = {
  project?: Project;
  scan?: Scan;
  findings: FindingSummary[];
  total: number;
  revision?: number;
};

export type WorkspaceState = {
  project?: Project;
  scan?: Scan;
};

export type FindingFileManifest = {
  scan: Scan;
  totalFindings: number;
  totalFiles: number;
  files: FindingFileIndexMap;
};

export type FindingFilters = {
  filePath?: string;
  severity?: string;
  scanner?: string;
  lifecycleStatus?: string;
};

const FINDING_SCAN_STATUSES = new Set(['completed', 'partial', 'failed', 'cancelled']);
const CONTROL_FORMAT_OR_SURROGATE_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}]/u;
const UNSAFE_MULTILINE_CHARACTER = /[\p{Cf}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/u;
const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
const WINDOWS_DRIVE = /^[A-Za-z]:($|\/)/;
const WINDOWS_NATIVE_PATH = /^(?:[A-Za-z]:[\\/]|\\\\)/;
const WINDOWS_DRIVE_PATH = /^[A-Za-z]:\\/;
const WINDOWS_UNC_PATH = /^\\\\([^\\]+)\\/;
const WSL_UNC_AUTHORITY = 'wsl.localhost';
const NATIVE_WINDOWS_SNAPSHOT_PREFIX = '/source-snapshots/native-windows';
const PAGE_LIMIT = 200;
const MAX_PAGES = 500;
const MAX_MANIFEST_PAGES = 250;
const MAX_SNAPSHOT_ATTEMPTS = 3;
const MAX_CURSOR_LENGTH = 512;
const MAX_FINDING_PATH_UTF8_BYTES = 4096;
// The host limits an outbound set(), not the retained collection. A file must
// fit in one replacement; independent files can be sent in bounded batches.
export const MAX_SCAN_FINDINGS = 50_000;
export const MAX_DIAGNOSTIC_FINDINGS = 10_000;
export const MAX_DIAGNOSTIC_FILES = 10_000;
export const MAX_DIAGNOSTICS_PER_FILE = 1_000;
export const MAX_DIAGNOSTIC_BATCH = 1_000;
export const MAX_DIAGNOSTIC_RETAINED_BYTES = 32 * 1024 * 1024;
export const DIAGNOSTIC_PROJECTION_LIMIT_DESCRIPTION =
  '10,000 findings/files across workspace roots, 1,000 findings per file, or the bounded Problems memory budget';
export const MAX_MANIFEST_FILES = PAGE_LIMIT * MAX_MANIFEST_PAGES;
const SEVERITIES: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const LIFECYCLES: readonly FindingLifecycle[] = [
  'open', 'needs_review', 'gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed',
];
const MANIFEST_METRIC_WIDTH = 6;
const FINDING_ITEM_FIELDS = [
  'id', 'scan_id', 'scan_finding_number', 'display_id', 'scanner', 'rule_id', 'severity',
  'file_path', 'start_line', 'start_column', 'end_line', 'end_column', 'message', 'fingerprint',
  'lifecycle_status', 'gate_exempt', 'gate_effect', 'suppressed', 'occurrence_count', 'is_repeat',
  'first_seen_display_id', 'first_seen_scan_id', 'advisor_verdict', 'advisor_confidence', 'revision',
] as const;
const FINDING_DIAGNOSTIC_FIELDS = [
  'id', 'scan_finding_number', 'display_id', 'scanner', 'severity', 'file_path',
  'start_line', 'start_column', 'end_line', 'end_column', 'message', 'revision',
] as const;
const FINDING_DETAIL_FIELDS = [
  'code_snippet', 'metadata_json', 'ai_verdict', 'ai_confidence', 'ai_reasoning', 'ai_fix',
  'suppression_reason', 'gate_exempt_reason', 'lifecycle_reason', 'lifecycle_updated_at', 'created_at',
] as const;

/**
 * Columnar immutable manifest storage. API pages expose descriptive nested
 * count records, but retaining 50,000 of those object graphs would dominate
 * the extension heap. Values are reconstructed only for the file currently
 * requested by Tree/hydration code.
 */
class CompactFindingFileManifest implements FindingFileIndexMap {
  readonly [Symbol.toStringTag] = 'CompactFindingFileManifest';

  constructor(
    private readonly paths: readonly string[],
    private readonly positions: ReadonlyMap<string, number>,
    private readonly metrics: Float64Array,
  ) {}

  get size(): number {
    return this.paths.length;
  }

  has(path: string): boolean {
    return this.positions.has(path);
  }

  get(path: string): FindingFileIndex | undefined {
    const index = this.positions.get(path);
    return index === undefined ? undefined : this.valueAt(index);
  }

  *entries(): IterableIterator<[string, FindingFileIndex]> {
    for (let index = 0; index < this.paths.length; index += 1) {
      yield [this.paths[index], this.valueAt(index)];
    }
  }

  *keys(): IterableIterator<string> {
    yield* this.paths;
  }

  *values(): IterableIterator<FindingFileIndex> {
    for (let index = 0; index < this.paths.length; index += 1) yield this.valueAt(index);
  }

  forEach(
    callback: (value: FindingFileIndex, key: string, map: FindingFileIndexMap) => void,
    thisArg?: unknown,
  ): void {
    for (const [path, value] of this.entries()) callback.call(thisArg, value, path, this);
  }

  [Symbol.iterator](): IterableIterator<[string, FindingFileIndex]> {
    return this.entries();
  }

  private valueAt(index: number): FindingFileIndex {
    const offset = index * MANIFEST_METRIC_WIDTH;
    return {
      file_path: this.paths[index],
      first_scan_finding_number: this.metrics[offset],
      total: this.metrics[offset + 1],
      active: this.metrics[offset + 2],
      suppressed: this.metrics[offset + 3],
      gate_exempt: this.metrics[offset + 4],
      blocking: this.metrics[offset + 5],
    };
  }
}


class FindingFileManifestBuilder {
  private readonly paths: string[] = [];
  private readonly positions = new Map<string, number>();
  private readonly metrics: Float64Array;

  constructor(private readonly expectedSize: number) {
    this.metrics = new Float64Array(expectedSize * MANIFEST_METRIC_WIDTH);
  }

  get size(): number {
    return this.paths.length;
  }

  has(path: string): boolean {
    return this.positions.has(path);
  }

  append(item: FindingFileAggregate): void {
    if (this.paths.length >= this.expectedSize || this.positions.has(item.file_path)) {
      throw new CodeSecurityRequestError('CodeSecurity returned duplicate or excessive manifest file identities.');
    }
    const index = this.paths.length;
    const offset = index * MANIFEST_METRIC_WIDTH;
    this.paths.push(item.file_path);
    this.positions.set(item.file_path, index);
    this.metrics.set([
      item.first_scan_finding_number,
      item.total,
      item.active,
      item.suppressed,
      item.gate_exempt,
      item.blocking,
    ], offset);
  }

  finish(): FindingFileIndexMap {
    if (this.paths.length !== this.expectedSize) {
      throw new CodeSecurityRequestError('CodeSecurity ended the finding-file manifest before it was complete.');
    }
    return new CompactFindingFileManifest(this.paths, this.positions, this.metrics);
  }
}

type WorkspaceSourceUriLike = {
  scheme: string;
  authority: string;
  path: string;
  fsPath: string;
};

type WorkspaceFolderLike = {
  name: string;
  uri: WorkspaceSourceUriLike;
};

export type WorkspaceSourceUriKind =
  | 'native-local-drive'
  | 'local-posix'
  | 'remote-wsl'
  | 'wsl-unc'
  | 'unsupported';

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

const defaultYield: YieldControl = () => new Promise((resolve) => setTimeout(resolve, 0));

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (const character of value) {
    const codePoint = character.codePointAt(0) as number;
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) return MAX_FINDING_PATH_UTF8_BYTES + 1;
    bytes += codePoint <= 0x7f ? 1 : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
    if (bytes > MAX_FINDING_PATH_UTF8_BYTES) return bytes;
  }
  return bytes;
}

function exactWorkspaceProject(value: Project, repoPath: string, projectId?: number): Project {
  if (
    !value
    || !Number.isSafeInteger(value.id)
    || value.id < 1
    || (projectId !== undefined && value.id !== projectId)
    || typeof value.name !== 'string'
    || value.repo_path !== repoPath
    || (value.revision !== undefined
      && (!Number.isSafeInteger(value.revision) || value.revision < 1))
  ) {
    throw new CodeSecurityRequestError(projectId === undefined
      ? 'CodeSecurity returned a project outside the selected workspace source root.'
      : 'CodeSecurity returned a different registered project identity.');
  }
  return value;
}

export type SourceOpenProjectContext = Readonly<{
  commandId: string;
  projectId: number;
  repoPath: string;
}>;

export async function loadSourceOpenProjectContext(
  request: ApiRequest,
  commandId: string,
  projectId: number,
  signal?: AbortSignal,
): Promise<SourceOpenProjectContext> {
  if (!/^[0-9a-f]{32}$/.test(commandId) || !Number.isSafeInteger(projectId) || projectId < 1) {
    throw new CodeSecurityRequestError('CodeSecurity requested an invalid targeted source-open identity.');
  }
  const context = await request<unknown>(
    `/v1/ide/source-open-commands/${commandId}/context`,
    { signal },
  );
  if (
    !exactRecord(context, ['v', 'command_id', 'project_id', 'project_repo_path'])
    || context.v !== 1
    || context.command_id !== commandId
    || context.project_id !== projectId
    || typeof context.project_repo_path !== 'string'
    || utf8ByteLength(context.project_repo_path) > MAX_FINDING_PATH_UTF8_BYTES
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned a different targeted source-open project identity.');
  }
  const canonicalRepoPath = canonicalWorkspaceSourcePath(context.project_repo_path);
  if (canonicalRepoPath !== context.project_repo_path) {
    throw new CodeSecurityRequestError('CodeSecurity returned a non-canonical registered project source path.');
  }
  return Object.freeze({ commandId, projectId, repoPath: canonicalRepoPath });
}

/**
 * Return the canonical project prefix below one open workspace source root.
 * Undefined means that the registered project is outside that root. Both
 * inputs remain POSIX source identities, including Remote WSL workspaces.
 */
export function registeredProjectPrefix(
  workspaceRoot: string,
  projectRoot: string,
): string | undefined {
  const canonicalWorkspaceRoot = canonicalWorkspaceSourcePath(workspaceRoot);
  const canonicalProjectRoot = canonicalWorkspaceSourcePath(projectRoot);
  if (
    canonicalWorkspaceRoot !== workspaceRoot
    || canonicalProjectRoot !== projectRoot
  ) {
    throw new CodeSecurityRequestError('CodeSecurity cannot map a non-canonical project source path.');
  }
  if (canonicalWorkspaceRoot === canonicalProjectRoot) return '';
  const boundary = canonicalWorkspaceRoot === '/' ? '/' : `${canonicalWorkspaceRoot}/`;
  if (!canonicalProjectRoot.startsWith(boundary)) return undefined;
  const relative = canonicalProjectRoot.slice(boundary.length);
  if (!safeFindingRelativePath(relative)) {
    throw new CodeSecurityRequestError('CodeSecurity cannot map the registered project below this workspace.');
  }
  return relative;
}

export function rebaseRegisteredProjectFindingPath(
  projectPrefix: string,
  findingPath: string,
): string {
  const safeFindingPath = safeFindingRelativePath(findingPath);
  if (!safeFindingPath) {
    throw new CodeSecurityRequestError('CodeSecurity rejected an unsafe retained-finding source path.');
  }
  if (!projectPrefix) return safeFindingPath;
  if (!safeFindingRelativePath(projectPrefix)) {
    throw new CodeSecurityRequestError('CodeSecurity rejected an unsafe registered-project source prefix.');
  }
  const rebased = `${projectPrefix}/${safeFindingPath}`;
  if (!safeFindingRelativePath(rebased)) {
    throw new CodeSecurityRequestError('CodeSecurity rejected an unsafe workspace-relative finding path.');
  }
  return rebased;
}

export function canonicalWorkspaceSourcePath(value: string): string {
  if (
    !value.startsWith('/')
    || value.includes('\\')
    || CONTROL_FORMAT_OR_SURROGATE_CHARACTER.test(value)
  ) {
    throw new CodeSecurityRequestError('The selected workspace does not expose a safe absolute POSIX source path.');
  }
  const segments: string[] = [];
  for (const segment of value.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      throw new CodeSecurityRequestError('The selected workspace does not expose a safe absolute POSIX source path.');
    }
    segments.push(segment);
  }
  return segments.length ? `/${segments.join('/')}` : '/';
}

async function resolveWorkspaceProject(
  request: ApiRequest,
  repoPath: string,
  signal?: AbortSignal,
): Promise<Project | undefined> {
  const canonicalRepoPath = canonicalWorkspaceSourcePath(repoPath);
  try {
    const project = await request<Project>('/v1/projects/resolve', {
      method: 'POST',
      body: JSON.stringify({ repo_path: canonicalRepoPath }),
      signal,
    });
    return exactWorkspaceProject(project, canonicalRepoPath);
  } catch (error) {
    if (error instanceof CodeSecurityRequestError && error.status === 404) return undefined;
    throw error;
  }
}

export async function ensureWorkspaceProject(
  request: ApiRequest,
  name: string,
  repoPath: string,
  signal?: AbortSignal,
): Promise<Project> {
  const canonicalRepoPath = canonicalWorkspaceSourcePath(repoPath);
  const resolved = await resolveWorkspaceProject(request, canonicalRepoPath, signal);
  if (resolved) return resolved;
  const basename = canonicalRepoPath.split('/').filter(Boolean).at(-1);
  const requestedName = (basename || name).trim();
  const deterministicName = Array.from(requestedName || 'workspace').slice(0, 120).join('');
  try {
    const project = await request<Project>('/v1/projects', {
      method: 'POST',
      body: JSON.stringify({ name: deterministicName, repo_path: canonicalRepoPath, default_branch: 'main' }),
      signal,
    });
    return exactWorkspaceProject(project, canonicalRepoPath);
  } catch (error) {
    if (!(error instanceof CodeSecurityRequestError) || error.status !== 409) throw error;
    const concurrent = await resolveWorkspaceProject(request, canonicalRepoPath, signal);
    if (concurrent) return concurrent;
    throw error;
  }
}

function validateScan(value: Scan, projectId: number, scanId?: number): Scan {
  if (
    !value
    || !Number.isSafeInteger(value.id)
    || value.id < 1
    || value.project_id !== projectId
    || scanId !== undefined && value.id !== scanId
    || typeof value.status !== 'string'
    || value.revision !== undefined
      && (!Number.isSafeInteger(value.revision) || value.revision < 1)
    || value.findings_revision !== undefined
      && (!Number.isSafeInteger(value.findings_revision) || value.findings_revision < 1)
    || value.job_id !== undefined && value.job_id !== null
      && (!Number.isSafeInteger(value.job_id) || value.job_id < 1)
    || value.job_revision !== undefined && value.job_revision !== null
      && (!Number.isSafeInteger(value.job_revision) || value.job_revision < 1)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned a scan outside the requested workspace project.');
  }
  return value;
}

export async function loadWorkspaceState(
  request: ApiRequest,
  repoPath: string,
  signal?: AbortSignal,
): Promise<WorkspaceState> {
  const project = await resolveWorkspaceProject(request, repoPath, signal);
  if (!project) return {};
  try {
    const scan = validateScan(
      await request<Scan>(`/v1/projects/${project.id}/scans/latest`, { signal }),
      project.id,
    );
    return { project, scan };
  } catch (error) {
    if (error instanceof CodeSecurityRequestError && error.status === 404) return { project };
    throw error;
  }
}

function isBoundedText(value: unknown, maxLength: number, allowEmpty = false): value is string {
  return typeof value === 'string'
    && value.length <= maxLength
    && (allowEmpty || value.length > 0)
    && !CONTROL_FORMAT_OR_SURROGATE_CHARACTER.test(value);
}

function isNullableBoundedText(value: unknown, maxLength: number): boolean {
  return value === null || isBoundedText(value, maxLength, true);
}

function normalizeNullableMultilineText(
  value: unknown,
  maxLength: number,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string') {
    throw new CodeSecurityRequestError('CodeSecurity returned invalid multiline finding evidence.');
  }
  const normalized = value.replace(/\r\n?/g, '\n');
  if (normalized.length > maxLength || UNSAFE_MULTILINE_CHARACTER.test(normalized)) {
    throw new CodeSecurityRequestError('CodeSecurity returned invalid multiline finding evidence.');
  }
  return normalized;
}

function isNullablePositiveIdentity(value: unknown): boolean {
  return value === null || Number.isSafeInteger(value) && (value as number) >= 1;
}

function isNullableConfidence(value: unknown): boolean {
  return value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
}

function findingLifecycleIsConsistent(value: FindingSummary): boolean {
  if (value.lifecycle_status === 'open' || value.lifecycle_status === 'needs_review') {
    return !value.suppressed && !value.gate_exempt && value.gate_effect === 'blocking';
  }
  if (value.lifecycle_status === 'gate_exempt' || value.lifecycle_status === 'accepted_risk') {
    return !value.suppressed && value.gate_exempt && value.gate_effect === 'non_blocking';
  }
  return value.suppressed && !value.gate_exempt && value.gate_effect === 'excluded';
}

function validateFindingItem(value: FindingSummary, scanId: number): FindingSummary {
  if (!value || typeof value !== 'object') {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid lightweight finding item.');
  }
  const record = value as unknown as Record<string, unknown>;
  const hasEveryField = FINDING_ITEM_FIELDS.every((field) => Object.hasOwn(record, field));
  const validStartLine = value.start_line === null
    || Number.isSafeInteger(value.start_line) && (value.start_line as number) >= 1;
  const validEndLine = value.end_line === null
    || Number.isSafeInteger(value.end_line) && (value.end_line as number) >= (value.start_line || 1);
  const validStartColumn = value.start_column === null
    || Number.isSafeInteger(value.start_column) && (value.start_column as number) >= 1;
  const validEndColumn = value.end_column === null
    || Number.isSafeInteger(value.end_column) && (value.end_column as number) >= 1;
  const hasStartLine = Number.isSafeInteger(value.start_line);
  const hasEndLine = Number.isSafeInteger(value.end_line);
  const hasStartColumn = Number.isSafeInteger(value.start_column);
  const hasEndColumn = Number.isSafeInteger(value.end_column);
  const invalidSameLineEnd = hasStartColumn && hasEndColumn
    && (value.end_line || value.start_line) === value.start_line
    && (value.end_column as number) < (value.start_column as number);
  const expectedDisplayId = Number.isSafeInteger(value.scan_finding_number)
    ? `S${scanId}-F${String(value.scan_finding_number).padStart(3, '0')}`
    : '';
  if (
    !hasEveryField
    || !Number.isSafeInteger(value.id) || value.id < 1
    || value.scan_id !== scanId
    || !Number.isSafeInteger(value.scan_finding_number) || value.scan_finding_number < 1
      || value.scan_finding_number > MAX_SCAN_FINDINGS
    || !Number.isSafeInteger(value.revision) || value.revision < 1
    || !isBoundedText(value.display_id, 80)
    || value.display_id !== expectedDisplayId
    || !isBoundedText(value.scanner, 80)
    || !isBoundedText(value.rule_id, 160)
    || !['critical', 'high', 'medium', 'low', 'info'].includes(value.severity)
    || !isBoundedText(value.file_path, 4096)
    || !safeFindingRelativePath(value.file_path)
    || !validStartLine || !validEndLine || !validStartColumn || !validEndColumn
    || hasStartLine !== hasEndLine
    || !hasStartLine && (hasStartColumn || hasEndColumn)
    || hasEndColumn && !hasStartColumn || invalidSameLineEnd
    || !isBoundedText(value.message, 4000)
    || !isBoundedText(value.fingerprint, 128)
    || !['open', 'needs_review', 'gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed']
      .includes(value.lifecycle_status)
    || typeof value.gate_exempt !== 'boolean'
    || !['blocking', 'non_blocking', 'excluded'].includes(value.gate_effect)
    || typeof value.suppressed !== 'boolean'
    || !findingLifecycleIsConsistent(value)
    || !Number.isSafeInteger(value.occurrence_count) || value.occurrence_count < 1
    || typeof value.is_repeat !== 'boolean'
    || !isNullablePositiveIdentity(value.first_seen_scan_id)
    || !isNullableBoundedText(value.first_seen_display_id, 80)
    || !isNullableBoundedText(value.advisor_verdict, 40)
    || !isNullableConfidence(value.advisor_confidence)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid lightweight finding item.');
  }
  // Return only the documented lightweight representation so unexpected
  // response properties (especially detail-sized strings/objects) cannot be
  // retained in the bounded extension index.
  return findingSummary(value);
}

function validateFindingPage(value: FindingPage, scanId: number): FindingPage {
  if (
    !value
    || !Array.isArray(value.items)
    || !Number.isSafeInteger(value.total)
    || value.total < 0
    || typeof value.truncated !== 'boolean'
    || value.next_cursor !== null && !isBoundedText(value.next_cursor, MAX_CURSOR_LENGTH)
    || !Number.isSafeInteger(value.revision)
    || value.revision < 1
    || value.items.length > PAGE_LIMIT
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid findings page.');
  }
  return {
    items: value.items.map((item) => validateFindingItem(item, scanId)),
    total: value.total,
    truncated: value.truncated,
    next_cursor: value.next_cursor,
    revision: value.revision,
  };
}

function validateFindingDiagnostic(value: unknown, scanId: number): FindingDiagnostic {
  if (!exactRecord(value, FINDING_DIAGNOSTIC_FIELDS)) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid compact diagnostic item.');
  }
  const startLine = value.start_line;
  const endLine = value.end_line;
  const startColumn = value.start_column;
  const endColumn = value.end_column;
  const hasStartLine = Number.isSafeInteger(startLine);
  const hasEndLine = Number.isSafeInteger(endLine);
  const hasStartColumn = Number.isSafeInteger(startColumn);
  const hasEndColumn = Number.isSafeInteger(endColumn);
  const ordinal = value.scan_finding_number;
  const expectedDisplayId = Number.isSafeInteger(ordinal)
    ? `S${scanId}-F${String(ordinal).padStart(3, '0')}`
    : '';
  if (
    !Number.isSafeInteger(value.id) || (value.id as number) < 1 || (value.id as number) > 2_147_483_647
    || !Number.isSafeInteger(ordinal) || (ordinal as number) < 1 || (ordinal as number) > MAX_SCAN_FINDINGS
    || !isBoundedText(value.display_id, 64) || value.display_id !== expectedDisplayId
    || !isBoundedText(value.scanner, 80)
    || !SEVERITIES.includes(value.severity as FindingSeverity)
    || !isBoundedText(value.file_path, 4096) || !safeFindingRelativePath(value.file_path)
    || startLine !== null && (!hasStartLine || (startLine as number) < 1 || (startLine as number) > 2_147_483_647)
    || endLine !== null && (!hasEndLine || (endLine as number) < (startLine as number || 1)
      || (endLine as number) > 2_147_483_647)
    || startColumn !== null && (!hasStartColumn || (startColumn as number) < 1
      || (startColumn as number) > 2_147_483_647)
    || endColumn !== null && (!hasEndColumn || (endColumn as number) < 1
      || (endColumn as number) > 2_147_483_647)
    || hasStartLine !== hasEndLine
    || !hasStartLine && (hasStartColumn || hasEndColumn)
    || hasEndColumn && !hasStartColumn
    || hasStartColumn && hasEndColumn
      && (endLine || startLine) === startLine
      && (endColumn as number) < (startColumn as number)
    || !isBoundedText(value.message, 4000, true)
    || !Number.isSafeInteger(value.revision) || (value.revision as number) < 1
      || (value.revision as number) > 2_147_483_647
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid compact diagnostic item.');
  }
  return {
    id: value.id as number,
    scan_finding_number: ordinal as number,
    display_id: value.display_id,
    scanner: value.scanner,
    severity: value.severity as FindingSeverity,
    file_path: value.file_path,
    start_line: startLine as number | null,
    start_column: startColumn as number | null,
    end_line: endLine as number | null,
    end_column: endColumn as number | null,
    message: value.message,
    revision: value.revision as number,
  };
}

function validateFindingDiagnosticPage(value: unknown, scanId: number): FindingDiagnosticPage {
  const keys = ['scan_id', 'items', 'total', 'truncated', 'next_cursor', 'revision'];
  if (
    !exactRecord(value, keys)
    || value.scan_id !== scanId
    || !Array.isArray(value.items) || value.items.length > PAGE_LIMIT
    || !Number.isSafeInteger(value.total) || (value.total as number) < 0
      || (value.total as number) > MAX_DIAGNOSTIC_FINDINGS
    || typeof value.truncated !== 'boolean'
    || value.next_cursor !== null && !isBoundedText(value.next_cursor, MAX_CURSOR_LENGTH)
    || !Number.isSafeInteger(value.revision) || (value.revision as number) < 1
      || (value.revision as number) > 2_147_483_647
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid compact diagnostic page.');
  }
  return {
    scan_id: scanId,
    items: value.items.map((item) => validateFindingDiagnostic(item, scanId)),
    total: value.total as number,
    truncated: value.truncated,
    next_cursor: value.next_cursor,
    revision: value.revision as number,
  };
}

export function validateFindingDetailResponse(
  value: FindingDetail,
  scanId: number,
  scanFindingNumber: number,
  findingId?: number,
  expectedFindingsRevision?: number,
): FindingDetail {
  if (!value || typeof value !== 'object') {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid scan-local finding detail.');
  }
  const record = value as unknown as Record<string, unknown>;
  const compactShape = validateFindingItem({
    ...value,
    advisor_verdict: value.ai_verdict ?? null,
    advisor_confidence: value.ai_confidence ?? null,
  }, scanId);
  const metadata = value.metadata_json;
  const codeSnippet = normalizeNullableMultilineText(value.code_snippet, 20_000);
  const aiReasoning = normalizeNullableMultilineText(value.ai_reasoning, 4000);
  const aiFix = normalizeNullableMultilineText(value.ai_fix, 4000);
  let metadataLength = 0;
  try {
    metadataLength = metadata === undefined ? 0 : JSON.stringify(metadata).length;
  } catch {
    metadataLength = Number.POSITIVE_INFINITY;
  }
  if (
    !FINDING_DETAIL_FIELDS.every((field) => Object.hasOwn(record, field))
    || value.scan_finding_number !== scanFindingNumber
    || findingId !== undefined && value.id !== findingId
    || value.findings_revision !== undefined && (
      !Number.isSafeInteger(value.findings_revision) || value.findings_revision < 1
    )
    || expectedFindingsRevision !== undefined && value.findings_revision !== expectedFindingsRevision
    || metadata !== undefined && (
      metadata === null || typeof metadata !== 'object' || Array.isArray(metadata) || metadataLength > 100_000
    )
    || value.ai_verdict !== undefined && !isNullableBoundedText(value.ai_verdict, 40)
    || value.ai_confidence !== undefined && !isNullableConfidence(value.ai_confidence)
    || value.suppression_reason !== undefined && !isNullableBoundedText(value.suppression_reason, 500)
    || value.gate_exempt_reason !== undefined && !isNullableBoundedText(value.gate_exempt_reason, 500)
    || value.lifecycle_reason !== undefined && !isNullableBoundedText(value.lifecycle_reason, 500)
    || value.lifecycle_updated_at !== undefined && !isNullableBoundedText(value.lifecycle_updated_at, 80)
    || !isBoundedText(value.created_at, 80)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid scan-local finding detail.');
  }
  return {
    ...compactShape,
    findings_revision: value.findings_revision,
    code_snippet: codeSnippet,
    metadata_json: metadata,
    ai_verdict: value.ai_verdict,
    ai_confidence: value.ai_confidence,
    ai_reasoning: aiReasoning,
    ai_fix: aiFix,
    suppression_reason: value.suppression_reason,
    gate_exempt_reason: value.gate_exempt_reason,
    lifecycle_reason: value.lifecycle_reason,
    lifecycle_updated_at: value.lifecycle_updated_at,
    created_at: value.created_at,
  };
}

function countRecord<T extends string>(
  value: unknown,
  keys: readonly T[],
): Readonly<Record<T, number>> | undefined {
  if (!exactRecord(value, keys)) return undefined;
  const counts = value as Record<T, unknown>;
  if (keys.some((key) => !Number.isSafeInteger(counts[key]) || (counts[key] as number) < 0)) {
    return undefined;
  }
  return counts as Readonly<Record<T, number>>;
}

function validateFindingFileAggregate(value: unknown): FindingFileAggregate {
  const keys = [
    'file_path', 'first_scan_finding_number', 'total', 'active', 'suppressed', 'gate_exempt',
    'blocking', 'severity_counts', 'lifecycle_counts',
  ];
  if (!exactRecord(value, keys)) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid finding-file manifest item.');
  }
  const severityCounts = countRecord(value.severity_counts, SEVERITIES);
  const lifecycleCounts = countRecord(value.lifecycle_counts, LIFECYCLES);
  const total = value.total;
  const active = value.active;
  const suppressed = value.suppressed;
  const gateExempt = value.gate_exempt;
  const blocking = value.blocking;
  if (
    typeof value.file_path !== 'string'
    || value.file_path.length > 4096
    || !safeFindingRelativePath(value.file_path)
    || !Number.isSafeInteger(value.first_scan_finding_number)
    || (value.first_scan_finding_number as number) < 1
    || (value.first_scan_finding_number as number) > MAX_SCAN_FINDINGS
    || !Number.isSafeInteger(total) || (total as number) < 1
    || (total as number) > MAX_SCAN_FINDINGS
    || !Number.isSafeInteger(active) || (active as number) < 0
    || !Number.isSafeInteger(suppressed) || (suppressed as number) < 0
    || !Number.isSafeInteger(gateExempt) || (gateExempt as number) < 0
    || !Number.isSafeInteger(blocking) || (blocking as number) < 0
    || !severityCounts
    || !lifecycleCounts
    || (active as number) + (suppressed as number) !== total
    || (gateExempt as number) + (blocking as number) !== active
    || SEVERITIES.reduce((sum, key) => sum + severityCounts[key], 0) !== total
    || LIFECYCLES.reduce((sum, key) => sum + lifecycleCounts[key], 0) !== total
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned inconsistent finding-file manifest counts.');
  }
  return {
    file_path: value.file_path,
    first_scan_finding_number: value.first_scan_finding_number as number,
    total: total as number,
    active: active as number,
    suppressed: suppressed as number,
    gate_exempt: gateExempt as number,
    blocking: blocking as number,
    severity_counts: severityCounts,
    lifecycle_counts: lifecycleCounts,
  };
}

function validateManifestScan(value: unknown, scanId: number): Scan {
  const keys = [
    'id', 'project_id', 'status', 'gate_decision', 'gate_reasons', 'error', 'revision',
    'findings_revision',
  ];
  if (!exactRecord(value, keys)) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid finding-file manifest scan.');
  }
  const scan = validateScan(value as unknown as Scan, value.project_id as number, scanId);
  if (
    !Array.isArray(value.gate_reasons)
    || value.gate_reasons.length > 200
    || value.gate_reasons.some((reason) => !isBoundedText(reason, 500, true))
    || value.gate_decision !== null && !isBoundedText(value.gate_decision, 40)
    || value.error !== null && !isBoundedText(value.error, 4000, true)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned invalid finding-file manifest scan metadata.');
  }
  return scan;
}

function sameManifestScan(left: Scan, right: Scan): boolean {
  return left.id === right.id
    && left.project_id === right.project_id
    && left.status === right.status
    && left.revision === right.revision
    && left.findings_revision === right.findings_revision
    && left.gate_decision === right.gate_decision
    && left.error === right.error
    && JSON.stringify(left.gate_reasons || []) === JSON.stringify(right.gate_reasons || []);
}

export async function loadFindingFileManifest(
  request: ApiRequest,
  scanId: number,
  signal?: AbortSignal,
  yieldControl: YieldControl = defaultYield,
): Promise<FindingFileManifest> {
  if (!Number.isSafeInteger(scanId) || scanId < 1) {
    throw new CodeSecurityRequestError('CodeSecurity requires a valid scan identity.');
  }
  let files: FindingFileManifestBuilder | undefined;
  const cursors = new Set<string>();
  let cursor: string | null = null;
  let scan: Scan | undefined;
  let totalFindings: number | undefined;
  let totalFiles: number | undefined;
  let lastOrdinal = 0;
  let aggregateTotal = 0;
  for (let pageNumber = 0; pageNumber < MAX_MANIFEST_PAGES; pageNumber += 1) {
    const parameters = new URLSearchParams({ limit: String(PAGE_LIMIT) });
    if (cursor) parameters.set('cursor', cursor);
    const value = await request<unknown>(
      `/v1/scans/${scanId}/finding-files?${parameters.toString()}`,
      { signal },
    );
    const keys = ['scan', 'total_findings', 'total_files', 'items', 'truncated', 'next_cursor'];
    if (
      !exactRecord(value, keys)
      || !Number.isSafeInteger(value.total_findings) || (value.total_findings as number) < 0
      || (value.total_findings as number) > MAX_SCAN_FINDINGS
      || !Number.isSafeInteger(value.total_files) || (value.total_files as number) < 0
      || !Array.isArray(value.items) || value.items.length > PAGE_LIMIT
      || typeof value.truncated !== 'boolean'
      || value.next_cursor !== null && !isBoundedText(value.next_cursor, MAX_CURSOR_LENGTH)
    ) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid finding-file manifest page.');
    }
    const pageScan = validateManifestScan(value.scan, scanId);
    if (scan === undefined) scan = pageScan;
    if (totalFindings === undefined) totalFindings = value.total_findings as number;
    if (totalFiles === undefined) {
      totalFiles = value.total_files as number;
      if (totalFiles > MAX_MANIFEST_FILES) {
        throw new RangeError(
          `The finding-file manifest exceeds its explicit ${MAX_MANIFEST_FILES}-file safety bound.`,
        );
      }
      files = new FindingFileManifestBuilder(totalFiles);
    }
    if (
      !sameManifestScan(scan, pageScan)
      || value.total_findings !== totalFindings
      || value.total_files !== totalFiles
    ) {
      throw new CodeSecurityRequestError(
        'The finding-file manifest changed during pagination. Refresh the authoritative revision.',
        409,
      );
    }
    if (!files) throw new CodeSecurityRequestError('CodeSecurity returned an invalid finding-file manifest size.');
    const items = value.items.map(validateFindingFileAggregate);
    for (const item of items) {
      if (files.has(item.file_path) || item.first_scan_finding_number <= lastOrdinal) {
        throw new CodeSecurityRequestError(
          'CodeSecurity returned duplicate or out-of-order finding-file manifest identities.',
        );
      }
      lastOrdinal = item.first_scan_finding_number;
      aggregateTotal += item.total;
      if (!Number.isSafeInteger(aggregateTotal) || aggregateTotal > totalFindings) {
        throw new CodeSecurityRequestError('CodeSecurity returned excessive finding-file aggregate counts.');
      }
      files.append(item);
    }
    if (value.next_cursor === null) {
      if (
        value.truncated
        || files.size !== totalFiles
        || aggregateTotal !== totalFindings
        || (totalFindings === 0) !== (totalFiles === 0)
      ) {
        throw new CodeSecurityRequestError('CodeSecurity ended the finding-file manifest before it was complete.');
      }
      return { scan, totalFindings, totalFiles, files: files.finish() };
    }
    if (!value.truncated || items.length === 0 || cursors.has(value.next_cursor)) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid finding-file manifest cursor.');
    }
    cursors.add(value.next_cursor);
    cursor = value.next_cursor;
    await yieldControl();
  }
  throw new CodeSecurityRequestError(
    `The finding-file manifest exceeded its explicit ${MAX_MANIFEST_FILES}-file safety bound.`,
  );
}

export type FindingPageProgress = Readonly<{
  processed: number;
  total: number;
  revision: number;
  page: number;
}>;

export type FindingPageStreamOptions = Readonly<{
  signal?: AbortSignal;
  filters?: FindingFilters;
  expectedRevision?: number;
  maximumFindings?: number;
  yieldControl?: YieldControl;
}>;

export async function streamFindingPages(
  request: ApiRequest,
  scanId: number,
  accept: (items: readonly FindingSummary[], progress: FindingPageProgress) => PromiseLike<void> | void,
  options: FindingPageStreamOptions = {},
): Promise<{ total: number; revision: number }> {
  const {
    signal,
    filters = {},
    expectedRevision,
    maximumFindings = MAX_PAGES * PAGE_LIMIT,
    yieldControl = defaultYield,
  } = options;
  if (!Number.isSafeInteger(scanId) || scanId < 1) {
    throw new CodeSecurityRequestError('CodeSecurity requires a valid scan identity.');
  }
  if (
    expectedRevision !== undefined
    && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
    || !Number.isSafeInteger(maximumFindings)
    || maximumFindings < 1
    || maximumFindings > MAX_PAGES * PAGE_LIMIT
  ) {
    throw new CodeSecurityRequestError('CodeSecurity requires valid findings projection bounds.');
  }
  const seenCursors = new Set<string>();
  const seenIds = new Set<number>();
  let cursor: string | null = null;
  let total: number | undefined;
  let revision: number | undefined;
  let processed = 0;
  let lastOrdinal = 0;

  for (let pageNumber = 0; pageNumber < MAX_PAGES; pageNumber += 1) {
    const parameters = new URLSearchParams({ limit: String(PAGE_LIMIT) });
    if (cursor) parameters.set('cursor', cursor);
    if (filters.filePath) parameters.set('file_path', filters.filePath);
    if (filters.severity) parameters.set('severity', filters.severity);
    if (filters.scanner) parameters.set('scanner', filters.scanner);
    if (filters.lifecycleStatus) parameters.set('lifecycle_status', filters.lifecycleStatus);
    if (expectedRevision !== undefined) parameters.set('expected_revision', String(expectedRevision));
    const page = validateFindingPage(await request<FindingPage>(
      `/v1/scans/${scanId}/findings?${parameters.toString()}`,
      { signal },
    ), scanId);
    if (total === undefined) total = page.total;
    if (revision === undefined) revision = page.revision;
    if (page.total > maximumFindings) {
      throw new RangeError(
        `The findings query exceeds its explicit ${maximumFindings}-item local safety bound.`,
      );
    }
    if (page.total !== total || page.revision !== revision) {
      throw new CodeSecurityRequestError(
        'Findings changed while they were loading. Refresh to reconcile the authoritative revision.',
        409,
      );
    }
    for (const item of page.items) {
      if (seenIds.has(item.id) || item.scan_finding_number <= lastOrdinal) {
        throw new CodeSecurityRequestError(
          'CodeSecurity returned a duplicate finding or out-of-order ordinal across cursor pages.',
        );
      }
      seenIds.add(item.id);
      lastOrdinal = item.scan_finding_number;
    }
    processed += page.items.length;
    if ((total as number) < processed) {
      throw new CodeSecurityRequestError('CodeSecurity findings total is smaller than the accumulated cursor result.');
    }
    await accept(page.items, {
      processed,
      total: total as number,
      revision: revision as number,
      page: pageNumber + 1,
    });
    if (page.next_cursor === null) {
      if (page.truncated || processed !== total) {
        throw new CodeSecurityRequestError('CodeSecurity ended a findings page before the complete result was loaded.');
      }
      return { total, revision } as { total: number; revision: number };
    }
    if (!page.truncated || page.items.length === 0 || seenCursors.has(page.next_cursor)) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid or repeated findings cursor.');
    }
    seenCursors.add(page.next_cursor);
    cursor = page.next_cursor;
    await yieldControl();
  }
  throw new CodeSecurityRequestError(
    `The findings query exceeded its explicit ${MAX_PAGES * PAGE_LIMIT}-item safety bound.`,
  );
}

export async function streamFindingDiagnosticPages(
  request: ApiRequest,
  scanId: number,
  expectedRevision: number,
  accept: (items: readonly FindingDiagnostic[], progress: FindingPageProgress) => PromiseLike<void> | void,
  options: Readonly<{
    signal?: AbortSignal;
    maximumFindings?: number;
    yieldControl?: YieldControl;
  }> = {},
): Promise<{ total: number; revision: number }> {
  const {
    signal,
    maximumFindings = MAX_DIAGNOSTIC_FINDINGS,
    yieldControl = defaultYield,
  } = options;
  if (
    !Number.isSafeInteger(scanId) || scanId < 1
    || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1
      || expectedRevision > 2_147_483_647
    || !Number.isSafeInteger(maximumFindings) || maximumFindings < 1
      || maximumFindings > MAX_DIAGNOSTIC_FINDINGS
  ) {
    throw new CodeSecurityRequestError('CodeSecurity requires valid compact diagnostic projection bounds.');
  }
  const seenCursors = new Set<string>();
  const seenIds = new Set<number>();
  let cursor: string | null = null;
  let total: number | undefined;
  let processed = 0;
  let lastOrdinal = 0;
  const maximumPages = Math.ceil(MAX_DIAGNOSTIC_FINDINGS / PAGE_LIMIT);

  for (let pageNumber = 0; pageNumber < maximumPages; pageNumber += 1) {
    const parameters = new URLSearchParams({
      limit: String(PAGE_LIMIT),
      expected_revision: String(expectedRevision),
    });
    if (cursor) parameters.set('cursor', cursor);
    const page = validateFindingDiagnosticPage(await request<unknown>(
      `/v1/scans/${scanId}/finding-diagnostics?${parameters.toString()}`,
      { signal },
    ), scanId);
    if (page.revision !== expectedRevision) {
      throw new CodeSecurityRequestError(
        'Compact diagnostic pages did not match the expected manifest revision.',
        409,
      );
    }
    if (total === undefined) total = page.total;
    if (page.total !== total) {
      throw new CodeSecurityRequestError(
        'Compact diagnostic totals changed during pagination.',
        409,
      );
    }
    if (page.total > maximumFindings) {
      throw new RangeError(
        `The compact diagnostic query exceeds its explicit ${maximumFindings}-item local safety bound.`,
      );
    }
    for (const item of page.items) {
      if (seenIds.has(item.id) || item.scan_finding_number <= lastOrdinal) {
        throw new CodeSecurityRequestError(
          'CodeSecurity returned a duplicate or out-of-order compact diagnostic identity.',
        );
      }
      seenIds.add(item.id);
      lastOrdinal = item.scan_finding_number;
    }
    processed += page.items.length;
    if (processed > (total as number)) {
      throw new CodeSecurityRequestError('Compact diagnostic total is smaller than its cursor result.');
    }
    await accept(page.items, {
      processed,
      total: total as number,
      revision: expectedRevision,
      page: pageNumber + 1,
    });
    if (page.next_cursor === null) {
      if (page.truncated || processed !== total) {
        throw new CodeSecurityRequestError(
          'CodeSecurity ended compact diagnostic pagination before the complete result was loaded.',
        );
      }
      return { total, revision: expectedRevision } as { total: number; revision: number };
    }
    if (!page.truncated || page.items.length === 0 || seenCursors.has(page.next_cursor)) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid compact diagnostic cursor.');
    }
    seenCursors.add(page.next_cursor);
    cursor = page.next_cursor;
    await yieldControl();
  }
  throw new CodeSecurityRequestError(
    `The compact diagnostic query exceeded its explicit ${MAX_DIAGNOSTIC_FINDINGS}-item safety bound.`,
  );
}

export async function loadFindingPages(
  request: ApiRequest,
  scanId: number,
  signal?: AbortSignal,
  filters: FindingFilters = {},
  yieldControl: YieldControl = defaultYield,
  expectedRevision?: number,
  maximumFindings = MAX_PAGES * PAGE_LIMIT,
): Promise<{ findings: FindingSummary[]; total: number; revision: number }> {
  const findings: FindingSummary[] = [];
  const result = await streamFindingPages(
    request,
    scanId,
    (items) => { findings.push(...items); },
    { signal, filters, expectedRevision, maximumFindings, yieldControl },
  );
  return { findings, ...result };
}

export async function loadWorkspaceFindings(
  request: ApiRequest,
  repoPath: string,
  signal?: AbortSignal,
  yieldControl: YieldControl = defaultYield,
): Promise<WorkspaceFindings> {
  const project = await resolveWorkspaceProject(request, repoPath, signal);
  if (!project) return { findings: [], total: 0 };

  let lastScanRevision: number | undefined;
  let lastPageRevision: number | undefined;
  for (let attempt = 1; attempt <= MAX_SNAPSHOT_ATTEMPTS; attempt += 1) {
    let scan: Scan;
    try {
      scan = validateScan(
        await request<Scan>(`/v1/projects/${project.id}/scans/latest`, { signal }),
        project.id,
      );
    } catch (error) {
      if (error instanceof CodeSecurityRequestError && error.status === 404) {
        return { project, findings: [], total: 0 };
      }
      throw error;
    }
    if (!FINDING_SCAN_STATUSES.has(scan.status)) {
      return { project, scan, findings: [], total: 0 };
    }
    try {
      const page = await loadFindingPages(request, scan.id, signal, {}, yieldControl);
      lastScanRevision = scan.findings_revision;
      lastPageRevision = page.revision;
      if (
        Number.isSafeInteger(lastScanRevision)
        && (lastScanRevision as number) >= 1
        && lastScanRevision === lastPageRevision
      ) {
        return { project, scan, ...page };
      }
    } catch (error) {
      if (!(error instanceof CodeSecurityRequestError) || error.status !== 409) throw error;
      if (attempt === MAX_SNAPSHOT_ATTEMPTS) throw error;
    }
    if (attempt < MAX_SNAPSHOT_ATTEMPTS) {
      await yieldControl();
    }
  }
  throw new CodeSecurityRequestError(
    `CodeSecurity latest scan changed during reconciliation `
    + `(scan revision ${lastScanRevision ?? 'missing'}, findings revision ${lastPageRevision ?? 'missing'}). `
    + 'Refresh again to load one authoritative revision.',
    409,
  );
}

export async function loadScanFindings(
  request: ApiRequest,
  projectId: number,
  scanId: number,
  signal?: AbortSignal,
  yieldControl: YieldControl = defaultYield,
): Promise<WorkspaceFindings> {
  const scan = await loadExactScan(request, projectId, scanId, signal);
  if (!FINDING_SCAN_STATUSES.has(scan.status)) return { scan, findings: [], total: 0 };
  const page = await loadFindingPages(request, scan.id, signal, {}, yieldControl);
  return { scan, ...page };
}

export async function loadExactScan(
  request: ApiRequest,
  projectId: number,
  scanId: number,
  signal?: AbortSignal,
): Promise<Scan> {
  if (!Number.isSafeInteger(projectId) || projectId < 1 || !Number.isSafeInteger(scanId) || scanId < 1) {
    throw new CodeSecurityRequestError('CodeSecurity requires valid project and scan identities.');
  }
  return validateScan(await request<Scan>(`/v1/scans/${scanId}`, { signal }), projectId, scanId);
}

export async function loadFindingDetail(
  request: ApiRequest,
  scanId: number,
  scanFindingNumber: number,
  expectedRevision: number,
  expectedFindingsRevision: number,
  signal?: AbortSignal,
): Promise<FindingDetail> {
  if (![scanId, scanFindingNumber, expectedRevision, expectedFindingsRevision]
    .every((value) => Number.isSafeInteger(value) && value > 0)) {
    throw new CodeSecurityRequestError('CodeSecurity requires a valid scan-local finding identity.');
  }
  const detail = await request<FindingDetail>(
    `/v1/scans/${scanId}/findings/${scanFindingNumber}`
      + `?expected_revision=${expectedRevision}&expected_findings_revision=${expectedFindingsRevision}`,
    { signal },
  );
  return validateFindingDetailResponse(
    detail,
    scanId,
    scanFindingNumber,
    undefined,
    expectedFindingsRevision,
  );
}

function assertPosixWorkspacePath(value: string): string {
  return canonicalWorkspaceSourcePath(value);
}

/**
 * Classify every supported local/Remote-WSL source shape before filesystem
 * access. This function never rewrites a native path into another authority.
 */
export function classifyWorkspaceSourceUri(
  uri: WorkspaceSourceUriLike,
  platform = '',
): WorkspaceSourceUriKind {
  if (uri.scheme === 'vscode-remote') {
    return uri.authority.toLowerCase().startsWith('wsl+') ? 'remote-wsl' : 'unsupported';
  }
  if (uri.scheme !== 'file') return 'unsupported';
  const uncHost = WINDOWS_UNC_PATH.exec(uri.fsPath)?.[1]?.toLowerCase();
  if (
    uri.authority.toLowerCase() === WSL_UNC_AUTHORITY
    || uncHost === WSL_UNC_AUTHORITY
  ) return 'wsl-unc';
  if (
    !uri.authority
    && WINDOWS_DRIVE_PATH.test(uri.fsPath)
    && !/[\p{Cc}\p{Cf}]/u.test(uri.fsPath)
  ) return 'native-local-drive';
  if (platform === 'win32' || WINDOWS_NATIVE_PATH.test(uri.fsPath)) return 'unsupported';
  if (
    !uri.authority
    && uri.fsPath.startsWith('/')
    && !/[\p{Cc}\p{Cf}]/u.test(uri.fsPath)
  ) return 'local-posix';
  return 'unsupported';
}

function nativeWindowsUncRequiresRemoteWsl(): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    'This workspace is open through \\\\wsl.localhost as a native Windows UNC path. '
      + 'Reopen the workspace in VS Code Remote WSL so CodeSecurity runs against its mounted POSIX source.',
    undefined,
    false,
    {
      code: 'native_windows_unc_requires_remote_wsl',
      action: 'reopen_in_remote_wsl',
    },
  );
}

function assertNoNativeWindowsUnc(uri: WorkspaceSourceUriLike, platform = ''): void {
  const kind = classifyWorkspaceSourceUri(uri, platform);
  if (kind === 'wsl-unc') throw nativeWindowsUncRequiresRemoteWsl();
  if (
    uri.scheme === 'file'
    && (
      uri.authority
      || WINDOWS_UNC_PATH.test(uri.fsPath)
      || platform === 'win32' && !WINDOWS_DRIVE_PATH.test(uri.fsPath)
    )
  ) {
    throw new CodeSecurityRequestError(
      'Native Windows snapshot scanning requires an absolute local drive workspace. UNC and virtual filesystem roots are not supported.',
    );
  }
}

export function isNativeWindowsWorkspace(folder: WorkspaceFolderLike, platform = ''): boolean {
  return classifyWorkspaceSourceUri(folder.uri, platform) === 'native-local-drive';
}

export function nativeWindowsWorkspaceSourceId(folder: WorkspaceFolderLike): string {
  assertNoNativeWindowsUnc(folder.uri, 'win32');
  if (
    classifyWorkspaceSourceUri(folder.uri, 'win32') !== 'native-local-drive'
  ) {
    throw new CodeSecurityRequestError(
      'Native Windows snapshot scanning requires an absolute local drive workspace. UNC and virtual filesystem roots are not supported.',
    );
  }
  const normalized = win32.normalize(folder.uri.fsPath);
  if (
    !win32.isAbsolute(normalized)
    || normalized === win32.parse(normalized).root
    || normalized.split('\\').some((part) => part === '..')
  ) {
    throw new CodeSecurityRequestError(
      'The selected native Windows workspace must be a canonical non-root local drive folder.',
    );
  }
  const identity = normalized.replace(/\\+$/u, '').normalize('NFC').toLocaleLowerCase('en-US');
  return createHash('sha256').update(`native-windows\0${identity}`, 'utf8').digest('hex');
}

export function workspaceSourceAuthorizationMode(
  folder: WorkspaceFolderLike,
  platform = '',
): 'mounted' | 'snapshot' {
  assertNoNativeWindowsUnc(folder.uri, platform);
  const kind = classifyWorkspaceSourceUri(folder.uri, platform);
  if (kind === 'native-local-drive') return 'snapshot';
  if (kind === 'local-posix' || kind === 'remote-wsl') return 'mounted';
  if (folder.uri.scheme === 'vscode-remote') {
    throw new CodeSecurityRequestError(
      'This remote workspace is not supported yet. Open the source locally or with VS Code Remote WSL.',
    );
  }
  throw new CodeSecurityRequestError(
    `Workspace scheme "${folder.uri.scheme}" is not supported. Use a local folder or VS Code Remote WSL.`,
  );
}

export function workspaceSourcePath(folder: WorkspaceFolderLike, platform = ''): string {
  const kind = classifyWorkspaceSourceUri(folder.uri, platform);
  if (folder.uri.scheme === 'vscode-remote') {
    if (kind !== 'remote-wsl') {
      throw new CodeSecurityRequestError(
        'This remote workspace is not supported yet. Open the source locally or with VS Code Remote WSL.',
      );
    }
    return assertPosixWorkspacePath(folder.uri.path);
  }
  if (folder.uri.scheme !== 'file') {
    throw new CodeSecurityRequestError(
      `Workspace scheme "${folder.uri.scheme}" is not supported. Use a local folder or VS Code Remote WSL.`,
    );
  }
  assertNoNativeWindowsUnc(folder.uri, platform);
  if (kind === 'native-local-drive') {
    return `${NATIVE_WINDOWS_SNAPSHOT_PREFIX}/${nativeWindowsWorkspaceSourceId(folder)}`;
  }
  if (kind !== 'local-posix') {
    throw new CodeSecurityRequestError(
      'This local workspace path is not supported. Use a canonical local folder or VS Code Remote WSL.',
    );
  }
  return assertPosixWorkspacePath(folder.uri.fsPath);
}

export function safeFindingRelativePath(value: string): string | undefined {
  if (
    !value
    || utf8ByteLength(value) > MAX_FINDING_PATH_UTF8_BYTES
    || value.startsWith('/')
    || value.includes('\\')
    || CONTROL_FORMAT_OR_SURROGATE_CHARACTER.test(value)
    || URI_SCHEME.test(value)
    || WINDOWS_DRIVE.test(value)
  ) {
    return undefined;
  }
  const segments = value.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) return undefined;
  return value;
}

export type FindingUriIdentity = Readonly<{
  scheme?: string;
  authority?: string;
  path: string;
}>;

const WINDOWS_FILE_URI_PATH = /^\/[A-Za-z]:(?:\/|$)/u;

/**
 * Resolve one URI below a workspace URI without changing its authority.
 * VS Code may preserve an upper-case native Windows drive letter in Uri.path
 * and serialize it lower-case. Every path component remains case-sensitive.
 */
export function workspaceRelativeUriPath(
  folderUri: FindingUriIdentity,
  uri: FindingUriIdentity,
): string | undefined {
  if (
    (uri.scheme ?? folderUri.scheme) !== folderUri.scheme
    || (uri.authority ?? folderUri.authority) !== folderUri.authority
  ) return undefined;
  if (
    folderUri.scheme === 'file'
    && !folderUri.authority
    && WINDOWS_FILE_URI_PATH.test(folderUri.path)
    && WINDOWS_FILE_URI_PATH.test(uri.path)
  ) {
    const rootPath = `/${folderUri.path[1].toLowerCase()}${folderUri.path.slice(2)}`
      .replace(/\/+$/u, '');
    const candidatePath = `/${uri.path[1].toLowerCase()}${uri.path.slice(2)}`;
    if (candidatePath === rootPath) return '';
    const prefix = `${rootPath}/`;
    if (!candidatePath.startsWith(prefix)) return undefined;
    return safeFindingRelativePath(candidatePath.slice(prefix.length));
  }
  const rootPath = folderUri.path === '/'
    ? '/'
    : folderUri.path.replace(/\/+$/u, '');
  if (uri.path === rootPath) return '';
  const prefix = rootPath === '/' ? '/' : `${rootPath}/`;
  return uri.path.startsWith(prefix)
    ? safeFindingRelativePath(uri.path.slice(prefix.length))
    : undefined;
}

/**
 * Select exact-file hydration priorities by the bounded editor/document set.
 * This deliberately performs Map.has/get lookups instead of walking every
 * manifest path and constructing up to 50,000 VS Code Uri objects.
 */
export function findingManifestPriorityPaths(
  files: FindingFileIndexMap,
  folderUri: FindingUriIdentity,
  documentUris: readonly FindingUriIdentity[],
  requiredFilePaths: readonly string[] = [],
  maximumFindings = Number.MAX_SAFE_INTEGER,
  maximumAutomaticFiles = Number.MAX_SAFE_INTEGER,
): readonly string[] {
  const selected = new Set<string>();
  let selectedFindings = 0;
  const select = (candidate: string): void => {
    const path = safeFindingRelativePath(candidate);
    const aggregate = path ? files.get(path) : undefined;
    const canonical = aggregate?.file_path;
    if (
      !canonical
      || selected.has(canonical)
      || !Number.isSafeInteger(maximumFindings)
      || maximumFindings < 0
      || selectedFindings + aggregate.total > maximumFindings
    ) return;
    selected.add(canonical);
    selectedFindings += aggregate.total;
  };
  for (const path of requiredFilePaths) select(path);
  const requiredCount = selected.size;

  for (const uri of documentUris) {
    if (selected.size - requiredCount >= maximumAutomaticFiles) break;
    const relativePath = workspaceRelativeUriPath(folderUri, uri);
    if (relativePath === undefined) continue;
    select(relativePath);
  }
  return [...selected];
}
