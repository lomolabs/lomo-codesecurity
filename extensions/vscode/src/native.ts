import { createHash } from 'node:crypto';

import * as vscode from 'vscode';

import { CodeSecurityRequestError } from './client';
import {
  FindingDetail,
  FindingDiagnostic,
  FindingFileIndex,
  FindingFileIndexMap,
  FindingLifecycle,
  FindingStore,
  FindingSummary,
  IndexedWorkspace,
  MAX_AUTOMATIC_HYDRATION_FILES,
  MAX_HYDRATED_FINDINGS,
  boundedSingleLineText,
  compareFindingPresentation,
  compareFindingSeverity,
  findingGateEffectLabel,
  findingInlineAnnotation,
  findingLifecycleLabel,
  findingRange,
  findingRangeForDocument,
  rangeContains,
  unicodeBoundedText,
} from './findings';
import { isAbortError } from './jobs';
import { trivyMessagePresentation } from './findingMessage';
import {
  MAX_DIAGNOSTIC_FILES,
  MAX_DIAGNOSTIC_FINDINGS,
  MAX_DIAGNOSTICS_PER_FILE,
  MAX_DIAGNOSTIC_BATCH,
  MAX_DIAGNOSTIC_RETAINED_BYTES,
  DIAGNOSTIC_PROJECTION_LIMIT_DESCRIPTION,
  Project,
  Scan,
  findingScanScope,
  safeFindingRelativePath,
  workspaceRelativeUriPath,
} from './workspace';

export type FindingCommandContext = {
  workspaceKey: string;
  findingId: number;
  scanId: number;
  scanFindingNumber: number;
  findingRevision: number;
  findingsRevision: number;
};

export type FindingContextResolution =
  | Readonly<{ status: 'current'; context: FindingCommandContext }>
  | Readonly<{ status: 'ambiguous' | 'stale' | 'invalid' }>;

export type NativeFindingActions = {
  openFinding(context: FindingCommandContext): Promise<void>;
  setLifecycle(context: FindingCommandContext): Promise<void>;
  runAdvisor(context: FindingCommandContext): Promise<void>;
  rescanFile(context: FindingCommandContext): Promise<void>;
  deleteFinding(context: FindingCommandContext): Promise<void>;
  hydrateFile(
    workspaceKey: string,
    filePath: string,
    scanId: number,
    revision: number,
    priority?: boolean,
    automaticCandidates?: ReadonlySet<string>,
  ): Promise<void>;
};

export type LocalServiceHealth =
  | 'not checked'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'unavailable'
  | 'pair required';

type OwnedDiagnostics = {
  scanId: number;
  revision: number;
  items: vscode.Diagnostic[];
  document?: vscode.TextDocument;
  documentVersion?: number;
};
type OwnedFileProjection = { workspaceKey: string; filePath: string };
type OwnedFindingEntry = {
  workspace: IndexedWorkspace;
  filePath: string;
  findings: readonly FindingSummary[];
};
type BoundCodeActionContext = Readonly<{
  context: FindingCommandContext;
  document: vscode.TextDocument;
  documentVersion: number;
  filePath: string;
  range: vscode.Range;
  findingRange: vscode.Range;
}>;
type QuickFixAction = 'open' | 'lifecycle' | 'advisor' | 'rescan' | 'delete';
type QuickFixCommand = Readonly<{
  title: string;
  action: QuickFixAction;
  command: string;
  dispatchCommand: string;
}>;

function workspaceFileIsStale(workspace: IndexedWorkspace, filePath: string): boolean {
  return workspace.allFilesStale || workspace.staleFiles.has(filePath);
}
type FindingHit = { finding: FindingSummary; range: vscode.Range };
type WorkspaceTreeNode = { kind: 'workspace'; workspace: IndexedWorkspace };
type TreeViewportRequest = Readonly<{ workspaceKey: string }>;
type ScanScopeTreeNode = { kind: 'scan_scope'; workspace: IndexedWorkspace };
type FilePageTreeNode = {
  kind: 'file_page';
  workspace: IndexedWorkspace;
  offset: number;
  count: number;
};
type FileTreeNode = {
  kind: 'file';
  workspace: IndexedWorkspace;
  filePath: string;
  total: number;
};
type RichLimitTreeNode = Omit<FileTreeNode, 'kind'> & { kind: 'rich_limit' };
type SeverityTreeNode = Omit<FileTreeNode, 'kind'> & {
  kind: 'severity';
  severity: string;
  findings: readonly FindingSummary[];
};
type LifecycleTreeNode = Omit<SeverityTreeNode, 'kind'> & { kind: 'lifecycle'; lifecycle: FindingLifecycle };
type FindingTreeNode = Omit<LifecycleTreeNode, 'kind'> & { kind: 'finding'; finding: FindingSummary };
type FindingTreeNodeUnion = WorkspaceTreeNode | FilePageTreeNode | FileTreeNode
  | ScanScopeTreeNode | RichLimitTreeNode | SeverityTreeNode | LifecycleTreeNode | FindingTreeNode;
type AnnotationMode = 'off' | 'compact' | 'detailed';
export type VisibleLineWindow = { start: number; end: number };
export type IndexedLineFinding = { startLine: number; finding: FindingSummary };
type FindingPositionInterval = {
  range: vscode.Range;
  ordinal: number;
  finding: FindingSummary;
};
type FindingPositionIntervalNode = {
  interval: FindingPositionInterval;
  left?: FindingPositionIntervalNode;
  right?: FindingPositionIntervalNode;
  minStart: vscode.Position;
  maxEnd: vscode.Position;
  minOrdinal: number;
};
export type ProjectedLineFinding = {
  workspaceKey: string;
  workspaceRevision: number;
  finding: FindingSummary;
};
export type ProjectedFindingLine = { line: number; findings: readonly ProjectedLineFinding[] };
type DecorationProjection = {
  signature: string;
  inline: vscode.DecorationOptions[];
};

function comparePosition(left: Pick<vscode.Position, 'line' | 'character'>, right: Pick<vscode.Position, 'line' | 'character'>): number {
  return left.line - right.line || left.character - right.character;
}

function sameRange(left: vscode.Range, right: vscode.Range): boolean {
  return comparePosition(left.start, right.start) === 0
    && comparePosition(left.end, right.end) === 0;
}

function sameFindingCommandContext(left: FindingCommandContext, right: FindingCommandContext): boolean {
  return left.workspaceKey === right.workspaceKey
    && left.findingId === right.findingId
    && left.scanId === right.scanId
    && left.scanFindingNumber === right.scanFindingNumber
    && left.findingRevision === right.findingRevision
    && left.findingsRevision === right.findingsRevision;
}

function sameBoundCodeActionContext(left: BoundCodeActionContext, right: BoundCodeActionContext): boolean {
  return left.document === right.document
    && left.documentVersion === right.documentVersion
    && left.filePath === right.filePath
    && sameRange(left.range, right.range)
    && sameRange(left.findingRange, right.findingRange)
    && sameFindingCommandContext(left.context, right.context);
}

function codeActionActivationRange(
  document: vscode.TextDocument,
  providerRange: vscode.Range,
  findingRange: vscode.Range,
  selectedDiagnostic: vscode.Diagnostic | undefined,
): vscode.Range {
  const boundProviderRange = new vscode.Range(providerRange.start, providerRange.end);
  if (
    !selectedDiagnostic
    || comparePosition(findingRange.start, findingRange.end) !== 0
    || !sameRange(boundProviderRange, findingRange)
  ) return boundProviderRange;

  const editor = vscode.window.activeTextEditor;
  const selection = editor?.document === document
    && editor.document.version === document.version
    && editor.selection
    ? new vscode.Range(editor.selection.start, editor.selection.end)
    : undefined;
  if (
    !selection
    || comparePosition(selection.start, selection.end) !== 0
    || selection.start.line !== findingRange.start.line
  ) return boundProviderRange;

  // VS Code can ask for a Quick Fix at the exact zero-width diagnostic while
  // retaining the visible source cursor elsewhere on that same line. The
  // selected diagnostic has already been validated against our owned
  // projection, so bind the argument-free dispatcher to that provider-time
  // cursor instead of requiring the cursor to jump to an invisible point.
  return selection;
}

function diagnosticCodeText(code: vscode.Diagnostic['code']): string | undefined {
  if (typeof code === 'string') return code;
  if (code && typeof code === 'object' && typeof code.value === 'string') return code.value;
  return undefined;
}

function sameDiagnostic(left: vscode.Diagnostic, right: vscode.Diagnostic): boolean {
  return diagnosticCodeText(left.code) === diagnosticCodeText(right.code)
    && left.source === right.source
    && left.message === right.message
    && left.severity === right.severity
    && sameRange(left.range, right.range);
}

function sameRevealFindingEvidence(left: FindingSummary, right: FindingSummary): boolean {
  return left.id === right.id
    && left.scan_id === right.scan_id
    && left.scan_finding_number === right.scan_finding_number
    && left.revision === right.revision
    && left.display_id === right.display_id
    && left.scanner === right.scanner
    && left.rule_id === right.rule_id
    && left.severity === right.severity
    && left.file_path === right.file_path
    && (left.start_line ?? null) === (right.start_line ?? null)
    && (left.start_column ?? null) === (right.start_column ?? null)
    && (left.end_line ?? null) === (right.end_line ?? null)
    && (left.end_column ?? null) === (right.end_column ?? null)
    && left.message === right.message
    && left.fingerprint === right.fingerprint;
}

function minimumPosition(left: vscode.Position, right: vscode.Position): vscode.Position {
  return comparePosition(left, right) <= 0 ? left : right;
}

function maximumPosition(left: vscode.Position, right: vscode.Position): vscode.Position {
  return comparePosition(left, right) >= 0 ? left : right;
}

/**
 * Document-aware interval lookup for hover and Code Actions. Ranges are
 * projected and clamped once when the index is built; warm lookups therefore
 * do not call TextDocument.lineAt, even for a dense single-line result set.
 */
export class FindingPositionIntervalIndex {
  private readonly root?: FindingPositionIntervalNode;
  private readonly rangesByOrdinal: readonly vscode.Range[];
  readonly size: number;

  constructor(
    findings: readonly FindingSummary[],
    rangeForFinding: (finding: FindingSummary, ordinal: number) => vscode.Range,
  ) {
    const intervals = findings.map((finding, ordinal) => {
      const range = rangeForFinding(finding, ordinal);
      return { range, ordinal, finding };
    }).sort((left, right) => (
      comparePosition(left.range.start, right.range.start)
      || comparePosition(left.range.end, right.range.end)
      || left.ordinal - right.ordinal
    ));
    this.size = intervals.length;
    const rangesByOrdinal = new Array<vscode.Range>(findings.length);
    for (const interval of intervals) rangesByOrdinal[interval.ordinal] = interval.range;
    this.rangesByOrdinal = rangesByOrdinal;
    this.root = FindingPositionIntervalIndex.build(intervals, 0, intervals.length);
  }

  private static build(
    intervals: readonly FindingPositionInterval[],
    start: number,
    end: number,
  ): FindingPositionIntervalNode | undefined {
    if (start >= end) return undefined;
    const middle = start + Math.floor((end - start) / 2);
    const left = FindingPositionIntervalIndex.build(intervals, start, middle);
    const right = FindingPositionIntervalIndex.build(intervals, middle + 1, end);
    const interval = intervals[middle];
    return {
      interval,
      left,
      right,
      minStart: left ? minimumPosition(left.minStart, interval.range.start) : interval.range.start,
      maxEnd: maximumPosition(
        maximumPosition(interval.range.end, left?.maxEnd || interval.range.end),
        right?.maxEnd || interval.range.end,
      ),
      minOrdinal: Math.min(interval.ordinal, left?.minOrdinal ?? interval.ordinal, right?.minOrdinal ?? interval.ordinal),
    };
  }

  rangeAt(ordinal: number): vscode.Range | undefined {
    return this.rangesByOrdinal[ordinal];
  }

  first<T>(
    queryStart: vscode.Position,
    queryEnd: vscode.Position,
    project: (finding: FindingSummary, range: vscode.Range, ordinal: number) => T | undefined,
  ): T | undefined {
    const start = comparePosition(queryStart, queryEnd) <= 0 ? queryStart : queryEnd;
    const end = start === queryStart ? queryEnd : queryStart;
    let bestOrdinal = Number.POSITIVE_INFINITY;
    let best: T | undefined;
    const eligible = (node?: FindingPositionIntervalNode): node is FindingPositionIntervalNode => Boolean(
      node
      && node.minOrdinal < bestOrdinal
      && comparePosition(node.maxEnd, start) >= 0
      && comparePosition(node.minStart, end) <= 0,
    );
    const visit = (node?: FindingPositionIntervalNode): void => {
      if (
        !eligible(node)
      ) return;
      const { interval } = node;
      const candidates: Array<{ ordinal: number; run: () => void }> = [];
      if (eligible(node.left)) candidates.push({ ordinal: node.left.minOrdinal, run: () => visit(node.left) });
      if (
        interval.ordinal < bestOrdinal
        && comparePosition(interval.range.start, end) <= 0
        && comparePosition(interval.range.end, start) >= 0
      ) {
        candidates.push({
          ordinal: interval.ordinal,
          run: () => {
            const projected = project(interval.finding, interval.range, interval.ordinal);
            if (projected !== undefined) {
              bestOrdinal = interval.ordinal;
              best = projected;
            }
          },
        });
      }
      if (eligible(node.right)) candidates.push({ ordinal: node.right.minOrdinal, run: () => visit(node.right) });
      candidates.sort((left, right) => left.ordinal - right.ordinal);
      for (const candidate of candidates) {
        if (candidate.ordinal < bestOrdinal) {
          candidate.run();
        }
      }
    };
    visit(this.root);
    return best;
  }

  all<T>(
    queryStart: vscode.Position,
    queryEnd: vscode.Position,
    project: (finding: FindingSummary, range: vscode.Range, ordinal: number) => T | undefined,
  ): T[] {
    const start = comparePosition(queryStart, queryEnd) <= 0 ? queryStart : queryEnd;
    const end = start === queryStart ? queryEnd : queryStart;
    const projected: Array<{ ordinal: number; value: T }> = [];
    const visit = (node?: FindingPositionIntervalNode): void => {
      if (
        !node
        || comparePosition(node.maxEnd, start) < 0
        || comparePosition(node.minStart, end) > 0
      ) return;
      visit(node.left);
      const { interval } = node;
      if (
        comparePosition(interval.range.start, end) <= 0
        && comparePosition(interval.range.end, start) >= 0
      ) {
        const value = project(interval.finding, interval.range, interval.ordinal);
        if (value !== undefined) projected.push({ ordinal: interval.ordinal, value });
      }
      visit(node.right);
    };
    visit(this.root);
    projected.sort((left, right) => left.ordinal - right.ordinal);
    return projected.map(({ value }) => value);
  }
}

const INLINE_DECORATION_OVERSCAN_LINES = 20;
const VISIBLE_RANGE_DEBOUNCE_MS = 16;
const MAX_AUTOMATIC_HYDRATION_ATTEMPTS = 512;
const MAX_RECENT_DOCUMENT_CHANGES = 512;
const MAX_CODE_ACTION_CONTEXTS = 512;
const QUICK_FIX_COMMANDS: readonly QuickFixCommand[] = Object.freeze([
  Object.freeze({
    title: 'Open Finding in Web',
    action: 'open',
    command: 'lomoCodeSecurity.openFinding',
    dispatchCommand: 'lomoCodeSecurity.quickFix.open',
  }),
  Object.freeze({
    title: 'Change CodeSecurity lifecycle…',
    action: 'lifecycle',
    command: 'lomoCodeSecurity.setLifecycle',
    dispatchCommand: 'lomoCodeSecurity.quickFix.lifecycle',
  }),
  Object.freeze({
    title: 'Run CodeSecurity Advisor',
    action: 'advisor',
    command: 'lomoCodeSecurity.runAdvisor',
    dispatchCommand: 'lomoCodeSecurity.quickFix.advisor',
  }),
  Object.freeze({
    title: 'Rescan exact finding file',
    action: 'rescan',
    command: 'lomoCodeSecurity.rescanFile',
    dispatchCommand: 'lomoCodeSecurity.quickFix.rescan',
  }),
  Object.freeze({
    title: 'Delete CodeSecurity finding…',
    action: 'delete',
    command: 'lomoCodeSecurity.deleteFinding',
    dispatchCommand: 'lomoCodeSecurity.quickFix.delete',
  }),
]);
const TREE_FILE_PAGE_SIZE = 200;
const SUPPRESSIVE_LIFECYCLES = new Set<FindingLifecycle>([
  'gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed',
]);

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareProjectedFindings(left: ProjectedLineFinding, right: ProjectedLineFinding): number {
  return compareFindingPresentation(left.finding, right.finding)
    || compareText(left.workspaceKey, right.workspaceKey);
}

export function indexFindingStartLines(findings: readonly FindingSummary[]): readonly IndexedLineFinding[] {
  return findings.map((finding) => ({
    startLine: findingRange(finding).startLine,
    finding,
  })).sort((left, right) => left.startLine - right.startLine || compareFindingPresentation(left.finding, right.finding));
}

function lowerBoundFindings(findings: readonly IndexedLineFinding[], line: number): number {
  let low = 0;
  let high = findings.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (findings[middle].startLine < line) low = middle + 1;
    else high = middle;
  }
  return low;
}

function upperBoundFindings(findings: readonly IndexedLineFinding[], line: number): number {
  let low = 0;
  let high = findings.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (findings[middle].startLine <= line) low = middle + 1;
    else high = middle;
  }
  return low;
}

export function visibleLineWindows(
  ranges: readonly vscode.Range[],
  lineCount: number,
  overscan = INLINE_DECORATION_OVERSCAN_LINES,
): VisibleLineWindow[] {
  if (ranges.length === 0) return [];
  const lastLine = Math.max(lineCount - 1, 0);
  const windows = ranges.map((range) => ({
    start: Math.max(Math.min(range.start.line, lastLine) - overscan, 0),
    end: Math.min(Math.max(range.end.line, 0) + overscan, lastLine),
  })).sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: VisibleLineWindow[] = [];
  for (const window of windows) {
    const previous = merged.at(-1);
    if (!previous || window.start > previous.end + 1) {
      merged.push({ ...window });
    } else {
      previous.end = Math.max(previous.end, window.end);
    }
  }
  return merged;
}

function lineIsProjected(line: number, windows: readonly VisibleLineWindow[]): boolean {
  return windows.some((window) => line >= window.start && line <= window.end);
}

export function projectVisibleFindingLines(
  entries: readonly {
    workspaceKey: string;
    workspaceRevision: number;
    findings: readonly IndexedLineFinding[];
  }[],
  windows: readonly VisibleLineWindow[],
  lastLine: number,
): readonly ProjectedFindingLine[] {
  const grouped = new Map<number, ProjectedLineFinding[]>();
  for (const entry of entries) {
    for (const window of windows) {
      const first = lowerBoundFindings(entry.findings, window.start);
      const after = window.end === lastLine
        ? entry.findings.length
        : upperBoundFindings(entry.findings, window.end);
      for (const indexed of entry.findings.slice(first, after)) {
        const lineNumber = Math.min(Math.max(indexed.startLine, 0), lastLine);
        if (!lineIsProjected(lineNumber, windows)) continue;
        const line = grouped.get(lineNumber) || [];
        line.push({
          workspaceKey: entry.workspaceKey,
          workspaceRevision: entry.workspaceRevision,
          finding: indexed.finding,
        });
        grouped.set(lineNumber, line);
      }
    }
  }
  return [...grouped.entries()]
    .sort(([left], [right]) => left - right)
    .map(([line, findings]) => ({ line, findings: findings.sort(compareProjectedFindings) }));
}

function commandContext(
  workspaceKey: string,
  findingsRevision: number,
  finding: FindingSummary,
): FindingCommandContext {
  return Object.freeze({
    workspaceKey,
    findingId: finding.id,
    scanId: finding.scan_id,
    scanFindingNumber: finding.scan_finding_number,
    findingRevision: finding.revision,
    findingsRevision,
  });
}

function explicitFindingCommandContext(value: unknown): FindingCommandContext | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const required = [
    'workspaceKey', 'findingId', 'scanId', 'scanFindingNumber', 'findingRevision', 'findingsRevision',
  ];
  const allowed = new Set(required);
  if (Object.keys(record).some((key) => !allowed.has(key)) || required.some((key) => !Object.hasOwn(record, key))) {
    return undefined;
  }
  if (typeof record.workspaceKey !== 'string' || !record.workspaceKey) return undefined;
  if (![record.findingId, record.scanId, record.scanFindingNumber]
    .every((item) => Number.isSafeInteger(item) && (item as number) > 0)) return undefined;
  if (!Number.isSafeInteger(record.findingRevision) || (record.findingRevision as number) < 1) return undefined;
  if (!Number.isSafeInteger(record.findingsRevision) || (record.findingsRevision as number) < 1) return undefined;
  return record as FindingCommandContext;
}

function diagnosticSeverity(value: FindingDiagnostic['severity']): vscode.DiagnosticSeverity {
  if (value === 'critical' || value === 'high') return vscode.DiagnosticSeverity.Error;
  if (value === 'medium') return vscode.DiagnosticSeverity.Warning;
  // VS Code's Problems model indexes Error, Warning, and Information. Hint is
  // an editor-only severity and is intentionally excluded from that surface,
  // so projecting CodeSecurity `info` as Hint makes persisted findings vanish
  // from Problems while their inline text and rich hover still render.
  return vscode.DiagnosticSeverity.Information;
}

function toVscodeRange(finding: FindingDiagnostic): vscode.Range {
  const range = findingRange(finding);
  return new vscode.Range(range.startLine, range.startCharacter, range.endLine, range.endCharacter);
}

function documentRange(document: vscode.TextDocument, finding: FindingDiagnostic): vscode.Range {
  const range = findingRangeForDocument(
    finding,
    document.lineCount,
    (line) => document.lineAt(line).text.length,
  );
  return new vscode.Range(range.startLine, range.startCharacter, range.endLine, range.endCharacter);
}

function sourceRevealOptions(uri: vscode.Uri): vscode.TextDocumentShowOptions {
  const target = uri.toString();
  const visible = vscode.window.visibleTextEditors;
  const matches = (editor: vscode.TextEditor): boolean => (
    editor.viewColumn !== undefined && editor.document.uri.toString() === target
  );
  const active = vscode.window.activeTextEditor;
  const existing = active && visible.includes(active) && matches(active)
    ? active
    : visible.find(matches);
  return { preview: false, preserveFocus: false, viewColumn: existing?.viewColumn };
}

const UNSAFE_MULTILINE_DISPLAY_CHARACTER = /[\p{Cf}\p{Cs}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/u;

function findingTitle(finding: Pick<FindingSummary, 'scanner' | 'message'>): string {
  return trivyMessagePresentation(finding.scanner, finding.message)?.title || finding.message;
}

function diagnosticFindingMessage(finding: Pick<FindingSummary, 'scanner' | 'message'>): string {
  // VS Code renders Diagnostic.message in its own compact hover, outside the
  // extension's Markdown layout. Keep that native surface bounded; the full
  // validated evidence remains available in CodeSecurity's rich hover, tree,
  // and dashboard detail.
  return boundedSingleLineText(findingTitle(finding), 48);
}

function boundedMultilineText(value: string, length = 500): string {
  const normalized = value.replace(/\r\n?/gu, '\n');
  if (UNSAFE_MULTILINE_DISPLAY_CHARACTER.test(normalized)) {
    throw new CodeSecurityRequestError(
      'CodeSecurity refused unsafe control or formatting characters in multiline finding text.',
    );
  }
  return unicodeBoundedText(normalized.trim(), length);
}

function appendMultilineText(markdown: vscode.MarkdownString, value: string, length = 500): void {
  const lines = boundedMultilineText(value, length).split('\n');
  lines.forEach((line, index) => {
    markdown.appendText(line);
    if (index < lines.length - 1) markdown.appendMarkdown('  \n');
  });
}

function decorationFindingSignature(projected: ProjectedLineFinding): readonly unknown[] {
  const finding = projected.finding;
  return [
    projected.workspaceKey,
    projected.workspaceRevision,
    finding.id,
    finding.scan_id,
    finding.scan_finding_number,
    finding.revision,
    boundedSingleLineText(finding.fingerprint, 128),
    boundedSingleLineText(finding.display_id, 80),
    boundedSingleLineText(finding.scanner, 80),
    boundedSingleLineText(finding.rule_id, 160),
    finding.severity,
    finding.lifecycle_status,
    finding.gate_effect,
    finding.occurrence_count,
    finding.first_seen_scan_id || null,
    boundedSingleLineText(finding.first_seen_display_id || '', 80),
    boundedMultilineText(finding.message, 500),
  ];
}

function encodedCommandArguments(context: FindingCommandContext): string {
  return encodeURIComponent(JSON.stringify([context])).replace(/[!'()*]/g, (character) => (
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  ));
}

function appendFindingHover(
  markdown: vscode.MarkdownString,
  workspaceKey: string,
  findingsRevision: number,
  finding: FindingSummary,
  dirty: boolean,
  interactivity: 'commands' | 'read_only',
): void {
  markdown.appendMarkdown('**');
  markdown.appendText(`${boundedSingleLineText(finding.display_id, 80)} · ${finding.severity.toUpperCase()}`);
  markdown.appendMarkdown('**\n\n**Scanner:** ');
  markdown.appendText(boundedSingleLineText(finding.scanner, 80));
  markdown.appendMarkdown('  \n**Rule:** ');
  markdown.appendText(boundedSingleLineText(finding.rule_id, 160));
  markdown.appendMarkdown('  \n**Lifecycle:** ');
  markdown.appendText(findingLifecycleLabel(finding.lifecycle_status));
  markdown.appendMarkdown('  \n**Gate effect:** ');
  markdown.appendText(findingGateEffectLabel(finding.gate_effect));
  markdown.appendMarkdown('  \n**Repeat history:** ');
  markdown.appendText(`${Math.max(finding.occurrence_count, 1)} occurrence(s)`);
  if (finding.first_seen_display_id) {
    markdown.appendMarkdown('; first seen as ');
    markdown.appendText(boundedSingleLineText(finding.first_seen_display_id, 80));
  }
  markdown.appendMarkdown('\n\n');
  appendMultilineText(markdown, finding.message, 500);
  markdown.appendMarkdown('\n\n');
  if (dirty) {
    markdown.appendMarkdown('**Warning:** Unsaved editor content was not included in this disk-based scan.\n\n');
  }
  if (interactivity === 'commands') {
    const context = encodedCommandArguments(commandContext(workspaceKey, findingsRevision, finding));
    markdown.appendMarkdown(
      `[Open Finding in Web](command:lomoCodeSecurity.openFinding?${context}) · `
      + `[Run Advisor](command:lomoCodeSecurity.runAdvisor?${context})`,
    );
  } else {
    markdown.appendText('Actions are available from the current source-range hover or CodeSecurity Findings tree.');
  }
}

function hoverMarkdown(
  workspaceKey: string,
  findingsRevision: number,
  finding: FindingSummary,
  dirty: boolean,
  interactivity: 'commands' | 'read_only',
): vscode.MarkdownString {
  const markdown = new vscode.MarkdownString();
  markdown.supportHtml = false;
  markdown.isTrusted = interactivity === 'commands'
    ? { enabledCommands: ['lomoCodeSecurity.openFinding', 'lomoCodeSecurity.runAdvisor'] }
    : false;
  appendFindingHover(markdown, workspaceKey, findingsRevision, finding, dirty, interactivity);
  return markdown;
}

type FindingHoverTarget = Readonly<{
  workspaceKey: string;
  findingsRevision: number;
  filePath: string;
  finding: FindingSummary;
  range: vscode.Range;
}>;

const MAX_INTERACTIVE_HOVER_FINDINGS = 8;

function interactiveHoverMarkdown(
  targets: readonly FindingHoverTarget[],
  dirty: boolean,
  interactivity: 'commands' | 'read_only' = 'commands',
): vscode.MarkdownString {
  const markdown = new vscode.MarkdownString();
  markdown.supportHtml = false;
  markdown.isTrusted = interactivity === 'commands'
    ? { enabledCommands: ['lomoCodeSecurity.openFinding', 'lomoCodeSecurity.runAdvisor'] }
    : false;
  const rendered = targets.slice(0, MAX_INTERACTIVE_HOVER_FINDINGS);
  rendered.forEach((target, index) => {
    if (index > 0) markdown.appendMarkdown('\n\n---\n\n');
    appendFindingHover(
      markdown,
      target.workspaceKey,
      target.findingsRevision,
      target.finding,
      dirty,
      interactivity,
    );
  });
  const omitted = targets.length - rendered.length;
  if (omitted > 0) {
    markdown.appendMarkdown('\n\n---\n\n');
    markdown.appendText(
      `${omitted.toLocaleString()} more current finding${omitted === 1 ? '' : 's'} overlap this source position. `
      + 'Choose one in CodeSecurity Findings for its exact actions.',
    );
  }
  return markdown;
}

class FindingTreeProvider implements vscode.TreeDataProvider<FindingTreeNodeUnion>, vscode.Disposable {
  private readonly changes = new vscode.EventEmitter<FindingTreeNodeUnion | undefined | null | void>();
  private readonly findingCommandContexts = new WeakMap<object, FindingCommandContext>();
  private readonly parents = new WeakMap<object, FindingTreeNodeUnion>();
  private roots: WorkspaceTreeNode[] = [];
  readonly onDidChangeTreeData = this.changes.event;

  constructor(
    private readonly store: FindingStore,
    private readonly hydrateFile: (
      workspaceKey: string,
      filePath: string,
      scanId: number,
      revision: number,
    ) => Promise<void>,
    private readonly onRootAccess: () => void = () => undefined,
  ) {
    this.synchronizeRoots();
  }

  refresh(): void {
    this.synchronizeRoots();
    this.changes.fire();
  }

  workspaceNode(workspaceKey: string): WorkspaceTreeNode | undefined {
    return this.roots.find(({ workspace }) => workspace.key === workspaceKey);
  }

  getParent(node: FindingTreeNodeUnion): FindingTreeNodeUnion | undefined {
    return this.parents.get(node);
  }

  dispose(): void {
    this.changes.dispose();
  }

  getTreeItem(node: FindingTreeNodeUnion): vscode.TreeItem {
    if (node.kind === 'workspace') {
      const item = new vscode.TreeItem(node.workspace.label, vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `workspace:${createHash('sha256').update(node.workspace.key).digest('hex')}`;
      const projection = node.workspace.diagnosticProjection === 'loading'
        ? ` · Problems ${node.workspace.diagnosticProcessed}/${node.workspace.totalFindings}`
        : node.workspace.diagnosticProjection === 'limited'
          ? ' · Problems unavailable'
          : '';
      const scope = node.workspace.scanScope || { kind: 'unknown' };
      const scopeLabel = scope?.kind === 'file' ? ' · file only'
        : scope?.kind === 'directory' ? ' · folder only'
          : scope?.kind === 'unknown' ? ' · scope unavailable' : '';
      item.description = `${node.workspace.totalFindings}${scopeLabel} · gate ${node.workspace.gateDecision || 'pending'}${projection}`;
      item.tooltip = `Scan #${node.workspace.scanId}. ` + (
        scope?.kind === 'file' || scope?.kind === 'directory'
          ? `Only ${scope.targetPath} is assessed. Findings and gate apply to this scan, not the entire repository. `
            + 'Open scan history below to review earlier scans; scan the workspace to assess all files.'
          : scope?.kind === 'unknown'
            ? 'The executed scope is unavailable. Do not treat this result as whole-repository coverage.'
            : 'Entire registered codebase. Findings and gate apply to this scan.');
      item.contextValue = 'lomoCodeSecurity.workspace';
      item.iconPath = new vscode.ThemeIcon('root-folder');
      return item;
    }
    if (node.kind === 'scan_scope') {
      const scope = node.workspace.scanScope || { kind: 'unknown' };
      const item = new vscode.TreeItem('Open scan history', vscode.TreeItemCollapsibleState.None);
      item.description = scope?.kind === 'file' ? 'file-only results'
        : scope?.kind === 'directory' ? 'folder-only results' : 'scope unavailable';
      item.tooltip = (scope.kind === 'unknown' ? 'The executed scope is unavailable for this scan. '
        : 'Other files are not assessed by this scan. ')
        + 'Earlier findings remain in scan history. '
        + 'Open the workbench and use its scan selector to review a previous full scan.';
      item.iconPath = new vscode.ThemeIcon('history');
      item.contextValue = 'lomoCodeSecurity.scanScope';
      item.command = { command: 'lomoCodeSecurity.openDashboard', title: 'Open scan history',
        arguments: [node.workspace.scanId] };
      return item;
    }
    if (node.kind === 'file_page') {
      const first = node.offset + 1;
      const last = node.offset + node.count;
      const item = new vscode.TreeItem(
        `Files ${first.toLocaleString()}–${last.toLocaleString()}`,
        vscode.TreeItemCollapsibleState.Collapsed,
      );
      item.description = `${node.count} files`;
      item.contextValue = 'lomoCodeSecurity.filePage';
      item.iconPath = new vscode.ThemeIcon('files');
      return item;
    }
    if (node.kind === 'file') {
      const stale = workspaceFileIsStale(node.workspace, node.filePath);
      const item = new vscode.TreeItem(node.filePath, vscode.TreeItemCollapsibleState.Collapsed);
      item.description = `${node.total}${stale ? ' · stale after edit' : ''}`;
      item.contextValue = stale ? 'lomoCodeSecurity.file.stale' : 'lomoCodeSecurity.file';
      item.iconPath = new vscode.ThemeIcon(stale ? 'warning' : 'file-code');
      return item;
    }
    if (node.kind === 'rich_limit') {
      const item = new vscode.TreeItem(
        'Open full file findings in the local workbench',
        vscode.TreeItemCollapsibleState.None,
      );
      item.description = `${node.total.toLocaleString()} exact findings · VS Code rich limit ${MAX_HYDRATED_FINDINGS.toLocaleString()}`;
      item.tooltip = `The exact aggregate is available, but this file exceeds the bounded `
        + `${MAX_HYDRATED_FINDINGS.toLocaleString()}-summary in-process rich index. `
        + 'Open its exact scan in the local workbench for full finding identities and lifecycle actions.';
      item.contextValue = 'lomoCodeSecurity.file.richLimited';
      item.iconPath = new vscode.ThemeIcon('link-external');
      item.command = {
        command: 'lomoCodeSecurity.openDashboard',
        title: 'Open exact scan findings',
        arguments: [node.workspace.scanId],
      };
      return item;
    }
    if (node.kind === 'severity') {
      const item = new vscode.TreeItem(node.severity.toUpperCase(), vscode.TreeItemCollapsibleState.Collapsed);
      item.description = String(node.findings.length);
      item.contextValue = 'lomoCodeSecurity.severity';
      return item;
    }
    if (node.kind === 'lifecycle') {
      const item = new vscode.TreeItem(findingLifecycleLabel(node.lifecycle), vscode.TreeItemCollapsibleState.Collapsed);
      item.description = String(node.findings.length);
      item.contextValue = 'lomoCodeSecurity.lifecycle';
      return item;
    }
    const item = new vscode.TreeItem(
      `${node.finding.display_id} · ${boundedSingleLineText(findingTitle(node.finding), 100)}`,
      vscode.TreeItemCollapsibleState.None,
    );
    item.description = `${node.finding.scanner} · ${node.finding.rule_id}`;
    item.tooltip = `${node.finding.file_path}:${node.finding.start_line || 1}`;
    item.contextValue = 'lomoCodeSecurity.finding';
    item.iconPath = new vscode.ThemeIcon(node.finding.gate_effect === 'blocking' ? 'error' : 'shield');
    const context = commandContext(node.workspace.key, node.workspace.revision, node.finding);
    this.findingCommandContexts.set(node, context);
    item.command = {
      command: 'lomoCodeSecurity.revealFinding',
      title: 'Reveal finding in editor',
      arguments: [context],
    };
    return item;
  }

  commandContextFor(value: unknown): Readonly<{
    context?: FindingCommandContext;
    ambiguous: boolean;
  }> {
    if (value === null || typeof value !== 'object') return { ambiguous: false };
    const remembered = this.findingCommandContexts.get(value);
    if (remembered) return { context: remembered, ambiguous: false };
    return { ambiguous: false };
  }

  getChildren(node?: FindingTreeNodeUnion): vscode.ProviderResult<FindingTreeNodeUnion[]> {
    if (!node) {
      this.onRootAccess();
      return this.roots;
    }
    if (node.kind === 'workspace') {
      if (this.workspaceNode(node.workspace.key) !== node) return [];
      const scope = node.workspace.scanScope || { kind: 'unknown' };
      const notice: ScanScopeTreeNode[] = scope.kind !== 'workspace'
        ? [this.child(node, { kind: 'scan_scope', workspace: node.workspace })] : [];
      if (node.workspace.totalFiles <= TREE_FILE_PAGE_SIZE) {
        return [...notice, ...this.fileNodes(node, node.workspace, 0, node.workspace.totalFiles)];
      }
      return [...notice, ...Array.from(
        { length: Math.ceil(node.workspace.totalFiles / TREE_FILE_PAGE_SIZE) },
        (_, page) => this.child(node, {
          kind: 'file_page' as const,
          workspace: node.workspace,
          offset: page * TREE_FILE_PAGE_SIZE,
          count: Math.min(TREE_FILE_PAGE_SIZE, node.workspace.totalFiles - page * TREE_FILE_PAGE_SIZE),
        }),
      )];
    }
    if (node.kind === 'scan_scope') return [];
    if (node.kind === 'file_page') return this.fileNodes(node, node.workspace, node.offset, node.count);
    if (node.kind === 'file') {
      if (node.total > MAX_HYDRATED_FINDINGS) {
        return [this.child(node, { ...node, kind: 'rich_limit' })];
      }
      const current = this.store.workspace(node.workspace.key);
      if (
        !current
        || current.projectId !== node.workspace.projectId
        || current.scanId !== node.workspace.scanId
        || current.revision !== node.workspace.revision
        || !current.fileManifest.has(node.filePath)
      ) return [];
      const findings = current?.files.get(node.filePath);
      if (!findings) {
        return this.hydrateFile(
          node.workspace.key,
          node.filePath,
          node.workspace.scanId,
          node.workspace.revision,
        ).then(() => this.hydratedFileChildren(node)).catch((error: unknown) => {
          if (!isAbortError(error)) throw error;
          return this.hydratedFileChildren(node);
        });
      }
      this.store.touchFile(node.workspace.key, node.filePath);
      return this.fileChildren(node, node, findings);
    }
    if (node.kind === 'rich_limit') return [];
    if (node.kind === 'severity') {
      return [...new Set(node.findings.map((finding) => finding.lifecycle_status))]
        .sort()
        .map((lifecycle) => this.child(node, {
          ...node,
          kind: 'lifecycle',
          lifecycle,
          findings: node.findings.filter((finding) => finding.lifecycle_status === lifecycle),
        }));
    }
    if (node.kind === 'lifecycle') {
      return node.findings.map((finding) => this.child(node, { ...node, kind: 'finding', finding }));
    }
    return [];
  }

  private fileChildren(
    parent: FileTreeNode,
    node: FileTreeNode,
    findings: readonly FindingSummary[],
  ): SeverityTreeNode[] {
    const severities = [...new Set(findings.map((finding) => finding.severity))]
      .sort(compareFindingSeverity);
    return severities.map((severity) => this.child(parent, {
      ...node,
      kind: 'severity',
      severity,
      findings: findings.filter((finding) => finding.severity === severity),
    }));
  }

  private hydratedFileChildren(node: FileTreeNode): SeverityTreeNode[] {
    const updated = this.store.workspace(node.workspace.key);
    const hydrated = updated?.files.get(node.filePath);
    if (!updated || !hydrated) return [];
    return this.fileChildren(node, { ...node, workspace: updated }, hydrated);
  }

  private fileNodes(
    parent: WorkspaceTreeNode | FilePageTreeNode,
    workspace: IndexedWorkspace,
    offset: number,
    count: number,
  ): FileTreeNode[] {
    const nodes: FileTreeNode[] = [];
    let index = 0;
    for (const filePath of workspace.fileManifest.keys()) {
      if (index >= offset && nodes.length < count) {
        nodes.push(this.child(parent, {
          kind: 'file',
          workspace,
          filePath,
          total: workspace.fileManifest.get(filePath)?.total || 0,
        }));
      }
      index += 1;
      if (nodes.length === count) break;
    }
    return nodes;
  }

  private child<T extends FindingTreeNodeUnion>(parent: FindingTreeNodeUnion, node: T): T {
    this.parents.set(node, parent);
    return node;
  }

  private synchronizeRoots(): void {
    const previous = new Map(this.roots.map((node) => [node.workspace.key, node]));
    this.roots = this.store.workspaceEntries().map((workspace) => {
      const node = previous.get(workspace.key) || { kind: 'workspace' as const, workspace };
      // Native reveals can outlive a sibling's manifest refresh. Keep their
      // root identity stable; descendant finding contexts retain their revision.
      node.workspace = workspace;
      return node;
    });
  }
}

export class NativeFindingController implements vscode.Disposable {
  readonly store: FindingStore;
  private readonly diagnosticsByWorkspace = new Map<string, Map<string, OwnedDiagnostics>>();
  private readonly diagnosticCosts = new Map<string, { total: number; bytes: number }>();
  private readonly diagnosticBuilds = new Map<symbol, { key: string; total: number; bytes: number }>();
  private readonly folders = new Map<string, vscode.WorkspaceFolder>();
  private readonly sourceTargetOwners = new Map<string, string>();
  private readonly workspaceGenerations = new Map<string, number>();
  private readonly lineIndexes = new WeakMap<readonly FindingSummary[], readonly IndexedLineFinding[]>();
  private readonly documentIntervalIndexes = new WeakMap<
    vscode.TextDocument,
    WeakMap<readonly FindingSummary[], { version: number; lineCount: number; index: FindingPositionIntervalIndex }>
  >();
  private readonly documentChangeGenerations = new WeakMap<vscode.TextDocument, number>();
  private readonly recentDocumentChanges = new Map<string, number>();
  private readonly renderSignatures = new WeakMap<vscode.TextEditor, string>();
  private readonly pendingVisibleRangeEditors = new Set<vscode.TextEditor>();
  private readonly automaticHydrationAttempts = new Map<string, string>();
  private readonly automaticHydrationsInFlight = new Map<string, string>();
  private readonly codeActionContexts = new Map<string, BoundCodeActionContext>();
  private revealedFindingContext?: BoundCodeActionContext;
  private nextWorkspaceGeneration = 0;
  private nextDocumentChangeGeneration = 0;
  private documentChangeHistoryFloor = 0;
  private readonly disposables: vscode.Disposable[] = [];
  private readonly inline?: vscode.TextEditorDecorationType;
  private readonly tree?: FindingTreeProvider;
  private readonly treeView?: vscode.TreeView<FindingTreeNodeUnion>;
  private readonly status?: vscode.StatusBarItem;
  private pendingTreeViewportReset?: TreeViewportRequest;
  private treeViewportResetInFlight = false;
  private visibleRangeTimer?: ReturnType<typeof setTimeout>;
  private serviceHealth: LocalServiceHealth = 'not checked';
  private ideEnrollmentReview?: Readonly<{
    verificationCode: string;
    state: 'awaiting_approval' | 'rejected' | 'expired' | 'unavailable';
  }>;
  private disposed = false;

  constructor(
    private readonly diagnostics: vscode.DiagnosticCollection,
    private readonly actions: NativeFindingActions,
    store = new FindingStore(MAX_HYDRATED_FINDINGS),
    private readonly isWorkspaceTrusted: () => boolean = () => true,
    onFindingsViewAccess: () => void = () => undefined,
  ) {
    this.store = store;
    if (typeof vscode.window.createTextEditorDecorationType === 'function') {
      this.inline = vscode.window.createTextEditorDecorationType({
        after: { margin: '0 0 0 1.5em', color: new vscode.ThemeColor('editor.foreground') },
        rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
      });
      this.disposables.push(this.inline);
    }
    if (typeof vscode.window.onDidChangeTextEditorVisibleRanges === 'function') {
      this.disposables.push(vscode.window.onDidChangeTextEditorVisibleRanges(({ textEditor }) => {
        if (this.isWorkspaceTrusted()) this.scheduleVisibleRangeUpdate(textEditor);
      }));
    }
    if (typeof vscode.window.createStatusBarItem === 'function') {
      this.status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
      this.status.name = 'Lomo CodeSecurity';
      this.status.command = 'lomoCodeSecurity.openDashboard';
      this.status.text = '$(shield) CodeSecurity local · not checked';
      const workspaceTrust = this.workspaceTrustSummary();
      this.status.tooltip = `${workspaceTrust} Local-only CodeSecurity control plane. No API request has been made in this session.`;
      this.status.accessibilityInformation = { label: this.statusAccessibilityLabel(workspaceTrust) };
      this.status.show();
      this.disposables.push(this.status);
    }
    if (
      typeof vscode.EventEmitter === 'function'
      && (
        typeof vscode.window.createTreeView === 'function'
        || typeof vscode.window.registerTreeDataProvider === 'function'
      )
    ) {
      this.tree = new FindingTreeProvider(
        this.store,
        (workspaceKey, filePath, scanId, revision) => this.isWorkspaceTrusted()
          ? this.actions.hydrateFile(workspaceKey, filePath, scanId, revision, true)
          : Promise.resolve(),
        onFindingsViewAccess,
      );
      this.disposables.push(this.tree);
      if (typeof vscode.window.createTreeView === 'function') {
        this.treeView = vscode.window.createTreeView('lomoCodeSecurity.findings', {
          treeDataProvider: this.tree,
        });
        this.disposables.push(
          this.treeView,
          this.treeView.onDidChangeVisibility(({ visible }) => {
            if (visible) this.resetPendingTreeViewport();
          }),
        );
      } else {
        this.disposables.push(vscode.window.registerTreeDataProvider('lomoCodeSecurity.findings', this.tree));
      }
    }
    if (typeof vscode.languages.registerHoverProvider === 'function') {
      this.disposables.push(vscode.languages.registerHoverProvider({ scheme: '*' }, {
        provideHover: (document, position) => this.isWorkspaceTrusted()
          ? this.provideHover(document, position)
          : undefined,
      }));
    }
    for (const command of QUICK_FIX_COMMANDS) {
      this.disposables.push(vscode.commands.registerCommand(
        command.dispatchCommand,
        () => this.dispatchQuickFix(command.action),
      ));
    }
    if (typeof vscode.languages.registerCodeActionsProvider === 'function') {
      this.disposables.push(vscode.languages.registerCodeActionsProvider({ scheme: '*' }, {
        provideCodeActions: (document, range, actionContext) => this.isWorkspaceTrusted()
          ? this.provideCodeActions(document, range, actionContext)
          : [],
      }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
    }
  }

  workspaceTrustChanged(): void {
    if (this.disposed) return;
    this.refreshNativeSurfaces();
  }

  private workspaceTrustSummary(): string {
    return this.isWorkspaceTrusted()
      ? 'Workspace source access: trusted.'
      : 'Workspace source access: restricted until Workspace Trust is granted.';
  }

  private statusAccessibilityLabel(workspaceTrust: string): string {
    const visibleStatus = this.status?.text.replace(/\$\([^)]+\)\s*/gu, '').trim() || 'CodeSecurity local';
    const folders = vscode.workspace.workspaceFolders || [];
    const workspaceIdentity = folders.length === 1
      ? createHash('sha256').update(folders[0].uri.toString(), 'utf8').digest('hex')
      : 'unavailable';
    return `Lomo CodeSecurity. ${workspaceTrust} Workspace source URI SHA-256: ${workspaceIdentity}. ${visibleStatus}.`;
  }

  private scheduleVisibleRangeUpdate(editor: vscode.TextEditor): void {
    if (this.disposed || !this.isWorkspaceTrusted()) return;
    this.pendingVisibleRangeEditors.add(editor);
    if (this.visibleRangeTimer !== undefined) return;
    this.visibleRangeTimer = setTimeout(() => {
      this.visibleRangeTimer = undefined;
      const visibleEditors = new Set(vscode.window.visibleTextEditors || []);
      const pending = [...this.pendingVisibleRangeEditors].filter((candidate) => visibleEditors.has(candidate));
      this.pendingVisibleRangeEditors.clear();
      if (!this.isWorkspaceTrusted()) return;
      for (const editor of pending) this.clearAutomaticHydrationAttemptForUri(editor.document.uri);
      this.updateVisibleEditors(pending);
    }, VISIBLE_RANGE_DEBOUNCE_MS);
  }

  private indexedFindings(findings: readonly FindingSummary[]): readonly IndexedLineFinding[] {
    const cached = this.lineIndexes.get(findings);
    if (cached) return cached;
    const indexed = indexFindingStartLines(findings);
    this.lineIndexes.set(findings, indexed);
    return indexed;
  }

  private documentIntervalIndex(
    document: vscode.TextDocument,
    findings: readonly FindingSummary[],
    ranges?: readonly vscode.Range[],
  ): FindingPositionIntervalIndex {
    let indexes = this.documentIntervalIndexes.get(document);
    if (!indexes) {
      indexes = new WeakMap();
      this.documentIntervalIndexes.set(document, indexes);
    }
    const cached = indexes.get(findings);
    if (
      cached
      && cached.version === document.version
      && cached.lineCount === document.lineCount
    ) return cached.index;
    const index = new FindingPositionIntervalIndex(
      findings,
      (finding, ordinal) => ranges?.[ordinal] || documentRange(document, finding),
    );
    indexes.set(findings, { version: document.version, lineCount: document.lineCount, index });
    return index;
  }

  private markPreexistingDirtyDocuments(workspace: IndexedWorkspace): void {
    for (const document of vscode.workspace.textDocuments || []) {
      if (!document.isDirty) continue;
      for (const owner of this.allManifestOwnersForUri(document.uri)) {
        if (owner.workspaceKey === workspace.key) this.store.markFileStale(workspace.key, owner.filePath);
      }
    }
  }

  documentChangeCheckpoint(): number {
    return this.nextDocumentChangeGeneration;
  }

  private markDocumentsChangedSince(
    workspace: IndexedWorkspace,
    checkpoint: number,
  ): void {
    if (checkpoint < this.documentChangeHistoryFloor) {
      const prior = this.diagnosticsByWorkspace.get(workspace.key);
      const priorUris = prior ? this.diagnosticUriKeys(workspace.key, prior.keys()) : [];
      this.diagnosticsByWorkspace.set(workspace.key, new Map());
      this.diagnosticCosts.delete(workspace.key);
      this.store.markAllFilesStale(workspace.key);
      // History overflow is a terminal, fail-closed projection for this scan,
      // not an indefinitely running Problems build. A same-scan refresh
      // carries allFilesStale forward; only a genuinely newer scan clears it.
      this.store.updateWorkspaceState(workspace.key, {
        diagnosticProjection: 'complete',
        diagnosticProcessed: workspace.totalFindings,
      });
      this.reconcileUris(priorUris.filter(
        (uriKey) => this.surfaceWorkspaceKeyForUri(vscode.Uri.parse(uriKey)) === workspace.key,
      ));
      this.refreshNativeSurfaces();
      throw new CodeSecurityRequestError(
        'Too many documents changed while CodeSecurity was reconciling; refresh again before trusting the projection.',
        409,
      );
    }
    for (const [uriKey, generation] of this.recentDocumentChanges) {
      if (generation <= checkpoint) continue;
      const uri = vscode.Uri.parse(uriKey);
      for (const owner of this.allManifestOwnersForUri(uri)) {
        if (owner.workspaceKey === workspace.key) this.store.markFileStale(workspace.key, owner.filePath);
      }
    }
  }

  private workspaceRootsForUri(uri: vscode.Uri): {
    rootSpecificity: number;
    key: string;
    filePath: string;
  }[] {
    const rootsByKey = new Map<string, { rootSpecificity: number; key: string; filePath: string }>();
    for (const folder of vscode.workspace.workspaceFolders || []) {
      const filePath = workspaceRelativeUriPath(folder.uri, uri);
      if (filePath === undefined) continue;
      const key = folder.uri.toString();
      rootsByKey.set(key, { rootSpecificity: folder.uri.path.length, key, filePath });
    }
    for (const [key, ownerKey] of this.sourceTargetOwners) {
      const folder = this.folders.get(key);
      if (!folder || !this.openWorkspaceKeys().has(ownerKey)) continue;
      const filePath = workspaceRelativeUriPath(folder.uri, uri);
      if (filePath === undefined) continue;
      rootsByKey.set(key, { rootSpecificity: folder.uri.path.length, key, filePath });
    }
    return [...rootsByKey.values()].sort((left, right) => (
      right.rootSpecificity - left.rootSpecificity || compareText(left.key, right.key)
    ));
  }

  private surfaceWorkspaceKeyForUri(uri: vscode.Uri): string | undefined {
    return this.workspaceRootsForUri(uri)[0]?.key;
  }

  private manifestOwnersForUri(uri: vscode.Uri): OwnedFileProjection[] {
    const authority = this.workspaceRootsForUri(uri)[0];
    if (!authority) return [];
    const filePath = safeFindingRelativePath(authority.filePath);
    const workspace = this.store.workspace(authority.key);
    return filePath && workspace?.fileManifest.has(filePath)
      ? [{ workspaceKey: authority.key, filePath }]
      : [];
  }

  private allManifestOwnersForUri(uri: vscode.Uri): OwnedFileProjection[] {
    const owners: (OwnedFileProjection & { rootSpecificity: number })[] = [];
    for (const workspace of this.store.workspaceEntries()) {
      const folder = this.folders.get(workspace.key);
      if (!folder) continue;
      const relativePath = workspaceRelativeUriPath(folder.uri, uri);
      const filePath = relativePath === undefined ? undefined : safeFindingRelativePath(relativePath);
      if (filePath && workspace.fileManifest.has(filePath)) {
        owners.push({ workspaceKey: workspace.key, filePath, rootSpecificity: folder.uri.path.length });
      }
    }
    return owners
      .sort((left, right) => (
        right.rootSpecificity - left.rootSpecificity
        || compareText(left.workspaceKey, right.workspaceKey)
      ))
      .map(({ workspaceKey, filePath }) => ({ workspaceKey, filePath }));
  }

  private entriesForUri(uri: vscode.Uri): OwnedFindingEntry[] {
    const entries: OwnedFindingEntry[] = [];
    for (const owner of this.manifestOwnersForUri(uri)) {
      const workspace = this.store.workspace(owner.workspaceKey);
      const findings = workspace?.files.get(owner.filePath);
      if (workspace && findings) entries.push({ workspace, filePath: owner.filePath, findings });
    }
    return entries;
  }

  private automaticHydrationKey(
    workspaceKey: string,
    scanId: number,
    revision: number,
    filePath: string,
  ): string {
    return JSON.stringify([workspaceKey, scanId, revision, filePath]);
  }

  private automaticHydrationSelection(): Readonly<{
    keys: ReadonlySet<string>;
    uris: ReadonlySet<string>;
  }> {
    const keys = new Set<string>();
    const uris = new Set<string>();
    const seenUris = new Set<string>();
    const documents = [
      ...(vscode.window.visibleTextEditors || []).map((editor) => editor.document),
      ...(vscode.workspace.textDocuments || []),
    ];
    let selectedFindings = 0;
    for (const document of documents) {
      const uriKey = document.uri.toString();
      if (seenUris.has(uriKey)) continue;
      seenUris.add(uriKey);
      const owner = this.manifestOwnersForUri(document.uri)[0];
      if (!owner) continue;
      const workspace = this.store.workspace(owner.workspaceKey);
      const aggregate = workspace?.fileManifest.get(owner.filePath);
      if (!workspace || !aggregate || workspaceFileIsStale(workspace, owner.filePath)) continue;
      const key = this.automaticHydrationKey(
        owner.workspaceKey,
        workspace.scanId,
        workspace.revision,
        owner.filePath,
      );
      if (keys.has(key)) {
        uris.add(uriKey);
        continue;
      }
      if (keys.size >= MAX_AUTOMATIC_HYDRATION_FILES) break;
      if (selectedFindings + aggregate.total > this.store.maxFindings) continue;
      selectedFindings += aggregate.total;
      keys.add(key);
      uris.add(uriKey);
    }
    return { keys, uris };
  }

  automaticHydrationCandidate(
    workspaceKey: string,
    filePath: string,
    scanId: number,
    revision: number,
    candidates: ReadonlySet<string> = this.automaticHydrationSelection().keys,
  ): boolean {
    return candidates.has(
      this.automaticHydrationKey(workspaceKey, scanId, revision, filePath),
    );
  }

  automaticHydrationCandidates(): ReadonlySet<string> {
    return this.automaticHydrationSelection().keys;
  }

  releaseAutomaticHydrationAttempt(
    workspaceKey: string,
    filePath: string,
    scanId: number,
    revision: number,
  ): void {
    this.automaticHydrationAttempts.delete(
      this.automaticHydrationKey(workspaceKey, scanId, revision, filePath),
    );
  }

  reserveHydrationCapacity(
    additionalFindings: number,
    workspaceKey: string,
    filePath: string,
  ): boolean {
    const reservation = this.store.reserveHydratedCapacity(
      additionalFindings,
      workspaceKey,
      filePath,
    );
    if (reservation.evicted) this.refreshNativeSurfaces();
    return reservation.available;
  }

  private clearAutomaticHydrationAttemptsForWorkspace(workspaceKey: string): void {
    for (const [key, owner] of this.automaticHydrationAttempts) {
      if (owner === workspaceKey) this.automaticHydrationAttempts.delete(key);
    }
    for (const [key, owner] of this.automaticHydrationsInFlight) {
      if (owner === workspaceKey) this.automaticHydrationsInFlight.delete(key);
    }
  }

  private clearAutomaticHydrationAttemptForUri(uri: vscode.Uri): void {
    for (const owner of this.manifestOwnersForUri(uri)) {
      const workspace = this.store.workspace(owner.workspaceKey);
      if (!workspace) continue;
      this.automaticHydrationAttempts.delete(this.automaticHydrationKey(
        owner.workspaceKey,
        workspace.scanId,
        workspace.revision,
        owner.filePath,
      ));
    }
  }

  private rememberAutomaticHydrationAttempt(key: string, workspaceKey: string): void {
    this.automaticHydrationAttempts.delete(key);
    this.automaticHydrationAttempts.set(key, workspaceKey);
    while (this.automaticHydrationAttempts.size > MAX_AUTOMATIC_HYDRATION_ATTEMPTS) {
      const oldest = this.automaticHydrationAttempts.keys().next().value as string | undefined;
      if (!oldest) break;
      this.automaticHydrationAttempts.delete(oldest);
    }
  }

  private automaticHydrationWasSuperseded(
    workspaceKey: string,
    projectId: number,
    filePath: string,
    scanId: number,
    revision: number,
  ): boolean {
    const current = this.store.workspace(workspaceKey);
    return this.disposed
      || !current
      || current.projectId !== projectId
      || current.scanId !== scanId
      || current.revision !== revision
      || !current.fileManifest.has(filePath)
      || current.files.has(filePath)
      || workspaceFileIsStale(current, filePath);
  }

  private requestHydrationForUri(
    uri: vscode.Uri,
    automatic?: ReadonlySet<string>,
  ): void {
    const owners = this.manifestOwnersForUri(uri);
    if (owners.length === 0) return;
    const selected = automatic || this.automaticHydrationSelection().keys;
    for (const owner of owners) {
      const workspace = this.store.workspace(owner.workspaceKey);
      if (!workspace || workspaceFileIsStale(workspace, owner.filePath)) continue;
      if (workspace.files.has(owner.filePath)) {
        this.store.touchFile(owner.workspaceKey, owner.filePath);
        continue;
      }
      const attemptKey = this.automaticHydrationKey(
        owner.workspaceKey,
        workspace.scanId,
        workspace.revision,
        owner.filePath,
      );
      if (!selected.has(attemptKey)) continue;
      if (this.automaticHydrationAttempts.has(attemptKey)) continue;
      this.rememberAutomaticHydrationAttempt(attemptKey, owner.workspaceKey);
      this.automaticHydrationsInFlight.set(attemptKey, owner.workspaceKey);
      let retryOnNextEditorSignal = false;
      void this.actions.hydrateFile(
        owner.workspaceKey,
        owner.filePath,
        workspace.scanId,
        workspace.revision,
        false,
        selected,
      ).catch((error: unknown) => {
        if (
          isAbortError(error)
          || this.automaticHydrationWasSuperseded(
            owner.workspaceKey,
            workspace.projectId,
            owner.filePath,
            workspace.scanId,
            workspace.revision,
          )
        ) return;
        retryOnNextEditorSignal = true;
        this.automaticHydrationAttempts.delete(attemptKey);
        vscode.window.setStatusBarMessage(
          `$(warning) CodeSecurity could not load rich findings for `
          + `${boundedSingleLineText(owner.filePath, 72)}. Scroll or reopen the file to retry.`,
          5_000,
        );
      }).finally(() => {
        if (this.automaticHydrationsInFlight.get(attemptKey) === owner.workspaceKey) {
          this.automaticHydrationsInFlight.delete(attemptKey);
        }
        // A real failure releases its reservation for the next editor event,
        // but must not use this completion frame to start an immediate loop.
        if (retryOnNextEditorSignal) return;
        const visible = (vscode.window.visibleTextEditors || [])
          .filter((editor) => editor.document.uri.toString() === uri.toString());
        if (visible.length > 0) this.updateVisibleEditors(visible, false);
      });
    }
  }

  private boundedAutomaticHydrationUris(
    editors: readonly vscode.TextEditor[],
    selected: ReadonlySet<string>,
  ): ReadonlySet<string> {
    return new Set(editors
      .map((editor) => editor.document.uri.toString())
      .filter((uriKey) => selected.has(uriKey)));
  }

  private provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const editor = vscode.window.activeTextEditor;
    const selection = editor?.document === document && editor.selection
      ? new vscode.Range(editor.selection.start, editor.selection.end)
      : undefined;
    const exactSelection = selection;
    const retained = this.revealedFindingContext;
    const retainedResolution = retained
      && exactSelection
      && retained.document === document
      && sameRange(retained.range, exactSelection)
      ? this.resolveBoundCodeActionContext(retained)
      : undefined;
    if (retained && retainedResolution?.status !== 'current') {
      this.revealedFindingContext = undefined;
    }
    // Keyboard Show Hover queries the active caret, which is the exclusive
    // end of a forward selection. Only its still-current explicit owner may
    // use that endpoint; stored ranges and unrelated pointer hits stay exact.
    const selectedEndpointOwner = retainedResolution?.status === 'current'
      && exactSelection
      && comparePosition(exactSelection.start, exactSelection.end) < 0
      && editor?.selection?.active
      && comparePosition(editor.selection.active, position) === 0
      && comparePosition(exactSelection.end, position) === 0
      ? retainedResolution.context
      : undefined;
    const targets: FindingHoverTarget[] = [];
    for (const entry of this.entriesForUri(document.uri)) {
      if (workspaceFileIsStale(entry.workspace, entry.filePath)) continue;
      targets.push(...this.documentIntervalIndex(document, entry.findings).all(
        position,
        position,
        (finding, range) => (rangeContains({
          startLine: range.start.line,
          startCharacter: range.start.character,
          endLine: range.end.line,
          endCharacter: range.end.character,
        }, position.line, position.character) || (
          selectedEndpointOwner
          && exactSelection
          && sameRange(range, exactSelection)
          && sameFindingCommandContext(
            commandContext(entry.workspace.key, entry.workspace.revision, finding),
            selectedEndpointOwner,
          )
        )) ? {
            workspaceKey: entry.workspace.key,
            findingsRevision: entry.workspace.revision,
            filePath: entry.filePath,
            finding,
            range,
          } : undefined,
      ));
    }
    if (targets.length === 0) return undefined;

    const exactTargets = exactSelection
      ? targets.filter((target) => sameRange(target.range, exactSelection))
      : [];
    let selectedIndex = -1;
    if (exactTargets.length === 1) {
      const [selected] = exactTargets;
      selectedIndex = targets.indexOf(selected);
      this.rememberRevealedFinding(
        commandContext(selected.workspaceKey, selected.findingsRevision, selected.finding),
        document,
        selected.filePath,
        selected.range,
      );
    } else if (retainedResolution?.status === 'current') {
      selectedIndex = targets.findIndex((target) => sameFindingCommandContext(
        commandContext(target.workspaceKey, target.findingsRevision, target.finding),
        retainedResolution.context,
      ));
    }
    // A tree reveal supplies exact identity even when scanners report the same
    // point range. A bare caret (or stale reveal) does not supply that authority.
    const ambiguousCollapsedSelection = Boolean(
      exactSelection
      && comparePosition(exactSelection.start, exactSelection.end) === 0
      && exactTargets.length > 1
      && selectedIndex < 0
    );
    if (selectedIndex > 0) targets.unshift(...targets.splice(selectedIndex, 1));
    return new vscode.Hover(
      interactiveHoverMarkdown(
        targets,
        document.isDirty,
        ambiguousCollapsedSelection ? 'read_only' : 'commands',
      ),
      targets[0].range,
    );
  }

  private findingForDiagnostic(
    document: vscode.TextDocument,
    entry: OwnedFindingEntry,
    diagnostic: vscode.Diagnostic,
  ): FindingHit | undefined {
    const owner = this.diagnosticsByWorkspace.get(entry.workspace.key)?.get(entry.filePath);
    if (
      !owner
      || owner.scanId !== entry.workspace.scanId
      || owner.revision !== entry.workspace.revision
    ) return undefined;
    const ownedDiagnostic = owner.items.find((candidate) => sameDiagnostic(candidate, diagnostic));
    const displayId = diagnosticCodeText(ownedDiagnostic?.code);
    if (!ownedDiagnostic || !displayId) return undefined;
    const ordinal = entry.findings.findIndex((finding) => (
      finding.display_id === displayId
      && finding.scanner === ownedDiagnostic.source
      && diagnosticFindingMessage(finding) === ownedDiagnostic.message
    ));
    if (ordinal < 0) return undefined;
    const findingRange = this.documentIntervalIndex(document, entry.findings).rangeAt(ordinal);
    if (!findingRange || !sameRange(findingRange, ownedDiagnostic.range)) return undefined;
    return { finding: entry.findings[ordinal], range: findingRange };
  }

  private provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    actionContext?: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const relevantDiagnostics: vscode.Diagnostic[] = [];
    const pending: BoundCodeActionContext[] = [];
    let refusal: string | undefined;
    entries: for (const entry of this.entriesForUri(document.uri)) {
      if (workspaceFileIsStale(entry.workspace, entry.filePath)) continue;
      const hits: Array<FindingHit & { diagnostic?: vscode.Diagnostic }> = [];
      const findingIds = new Set<number>();
      // VS Code can supply every diagnostic intersecting the editor selection,
      // even when Problems shows one filtered row. Array order is not authority.
      for (const diagnostic of actionContext?.diagnostics || []) {
        const candidate = this.findingForDiagnostic(document, entry, diagnostic);
        if (candidate?.range.intersection(range) === undefined) continue;
        if (findingIds.has(candidate.finding.id)) continue;
        findingIds.add(candidate.finding.id);
        hits.push({ ...candidate, diagnostic });
      }
      if (hits.length === 0) {
        hits.push(...this.documentIntervalIndex(document, entry.findings).all(
          range.start,
          range.end,
          (finding, candidateRange) => candidateRange.intersection(range) !== undefined
            ? { finding, range: candidateRange } : undefined,
        ));
      }
      for (const hit of hits) {
        if (pending.length === MAX_CODE_ACTION_CONTEXTS) {
          refusal = 'Too many overlapping CodeSecurity findings. Narrow the source selection or use the Findings tree to choose one exact finding.';
          break entries;
        }
        const context = commandContext(entry.workspace.key, entry.workspace.revision, hit.finding);
        if (hit.diagnostic) relevantDiagnostics.push(hit.diagnostic);
        pending.push(Object.freeze({
          context,
          document,
          documentVersion: document.version,
          filePath: entry.filePath,
          range: codeActionActivationRange(document, range, hit.range, hit.diagnostic),
          findingRange: hit.range,
        }));
      }
    }
    if (refusal) {
      // A partial registry would turn a large ambiguous selection into false
      // authority. Refuse the whole provider result, including cached actions.
      this.clearCodeActionContexts();
    } else {
      const retained = [...this.codeActionContexts.values()];
      const additional = pending.filter((bound) => (
        !retained.some((candidate) => sameBoundCodeActionContext(candidate, bound))
      )).length;
      if (retained.length + additional > MAX_CODE_ACTION_CONTEXTS) {
        // Evict whole provider histories, not individual findings: retaining
        // only half of an ambiguous pair would manufacture a unique owner.
        this.clearCodeActionContexts();
      }
      for (const bound of pending) {
        let token: string | undefined;
        for (const [candidateToken, candidate] of this.codeActionContexts) {
          if (!sameBoundCodeActionContext(candidate, bound)) continue;
          token = candidateToken;
          // Repeated provider calls for one cached action are use, not churn.
          // Refresh its LRU position without replacing its immutable token.
          this.codeActionContexts.delete(candidateToken);
          this.codeActionContexts.set(candidateToken, candidate);
          break;
        }
        if (token === undefined) {
          token = globalThis.crypto?.randomUUID?.();
          if (!token || this.codeActionContexts.has(token)) {
            throw new CodeSecurityRequestError(
              'VS Code could not create a unique CodeSecurity Quick Fix identity.',
            );
          }
          this.codeActionContexts.set(token, bound);
        }
      }
    }
    if (pending.length === 0 && !refusal) return [];
    const diagnostics = relevantDiagnostics.length > 0
      ? relevantDiagnostics : this.diagnosticsIntersecting(document, range);
    return QUICK_FIX_COMMANDS.map((command) => {
      const action = new vscode.CodeAction(command.title, vscode.CodeActionKind.QuickFix);
      // VS Code 1.134 wraps every Code Action command with a non-empty
      // arguments array in a disposable renderer command. Problems retains
      // action lists longer than that wrapper in some cache/reload paths.
      // Keep these five command identities stable and argument-free; the
      // exact context stays in this bounded extension-host registry and is
      // resolved from the document/range that Problems opens before run.
      action.command = {
        command: command.dispatchCommand,
        title: command.title,
      };
      action.diagnostics = diagnostics;
      if (refusal) action.disabled = { reason: refusal };
      return action;
    });
  }

  private diagnosticsIntersecting(
    document: vscode.TextDocument,
    range: vscode.Range,
  ): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    for (const ownerEntry of this.manifestOwnersForUri(document.uri)) {
      const entry = this.diagnosticsByWorkspace.get(ownerEntry.workspaceKey)?.get(ownerEntry.filePath);
      const workspace = this.store.workspace(ownerEntry.workspaceKey);
      const findings = workspace?.files.get(ownerEntry.filePath);
      if (
        !entry
        || !workspace
        || entry.scanId !== workspace.scanId
        || entry.revision !== workspace.revision
        || !findings
        || workspaceFileIsStale(workspace, ownerEntry.filePath)
      ) continue;
      diagnostics.push(...this.documentIntervalIndex(document, findings).all(
        range.start,
        range.end,
        (_finding, candidateRange, ordinal) => (
          candidateRange.intersection(range) !== undefined ? entry.items[ordinal] : undefined
        ),
      ));
    }
    return diagnostics;
  }

  private reconcileBuiltDiagnosticsWithCurrentDocuments(
    workspaceKey: string,
    grouped: Map<string, OwnedDiagnostics>,
    changeGenerationAtStart: number,
  ): void {
    const workspace = this.store.workspace(workspaceKey);
    const folder = this.folders.get(workspaceKey);
    if (!workspace || !folder) {
      grouped.clear();
      return;
    }
    const openDocuments = new Map<string, vscode.TextDocument>();
    for (const document of vscode.workspace.textDocuments || []) {
      const uriKey = document.uri.toString();
      if (!openDocuments.has(uriKey)) openDocuments.set(uriKey, document);
    }
    for (const [filePath, entry] of grouped) {
      const uriKey = vscode.Uri.joinPath(folder.uri, filePath).toString();
      const document = openDocuments.get(uriKey);
      if (
        workspaceFileIsStale(workspace, filePath)
        || (document && (this.documentChangeGenerations.get(document) || 0) > changeGenerationAtStart)
      ) {
        this.store.markFileStale(workspaceKey, filePath);
        grouped.delete(filePath);
        continue;
      }
      if (document === entry.document && document?.version === entry.documentVersion) continue;
      const findings = workspace.files.get(filePath);
      if (!findings) {
        // Closed-file Problems are already complete diagnostics and do not
        // retain FindingSummary rows. If this file opened during the paged
        // build, exact hydration will shortly reproject its document ranges.
        entry.document = document;
        entry.documentVersion = document?.version;
        continue;
      }
      entry.items = findings.map((finding) => {
        const diagnostic = new vscode.Diagnostic(
          document ? documentRange(document, finding) : toVscodeRange(finding),
          diagnosticFindingMessage(finding),
          diagnosticSeverity(finding.severity),
        );
        diagnostic.source = finding.scanner;
        diagnostic.code = finding.display_id;
        return diagnostic;
      });
      entry.document = document;
      entry.documentVersion = document?.version;
      if (document) {
        this.documentIntervalIndex(document, findings, entry.items.map((diagnostic) => diagnostic.range));
      }
    }
  }

  private reconcileUris(uriKeys: Iterable<string>): void {
    let replacements: [vscode.Uri, readonly vscode.Diagnostic[] | undefined][] = [];
    let count = 0;
    for (const uriKey of new Set(uriKeys)) {
      const uri = vscode.Uri.parse(uriKey);
      const owners = this.manifestOwnersForUri(uri)
        .map((owner) => this.diagnosticsByWorkspace.get(owner.workspaceKey)?.get(owner.filePath))
        .filter((entry): entry is OwnedDiagnostics => entry !== undefined);
      const owner = owners[0];
      const size = owner?.items.length || 0;
      if (size > MAX_DIAGNOSTICS_PER_FILE) {
        throw new CodeSecurityRequestError('A Problems file exceeds the explicit host replacement bound.');
      }
      if (replacements.length >= MAX_DIAGNOSTIC_BATCH || count + size > MAX_DIAGNOSTIC_BATCH) {
        this.diagnostics.set(replacements);
        replacements = [];
        count = 0;
      }
      if (!owner) {
        replacements.push([uri, undefined]);
      } else {
        replacements.push([uri, owner.items]);
      }
      count += size;
    }
    if (replacements.length > 0) this.diagnostics.set(replacements);
  }

  private reconcileWorkspaceRootTopology(uriKeys: Iterable<string>): void {
    const positiveByAuthority = new Map<string, string[]>();
    const removals: string[] = [];
    for (const uriKey of new Set(uriKeys)) {
      const uri = vscode.Uri.parse(uriKey);
      const owner = this.manifestOwnersForUri(uri)[0];
      const diagnostics = owner
        ? this.diagnosticsByWorkspace.get(owner.workspaceKey)?.get(owner.filePath)
        : undefined;
      if (!owner || !diagnostics) {
        removals.push(uriKey);
        continue;
      }
      const group = positiveByAuthority.get(owner.workspaceKey) || [];
      group.push(uriKey);
      positiveByAuthority.set(owner.workspaceKey, group);
    }
    // Resolve topology before the shared writer partitions transport updates.
    // Each complete file replacement is sent exactly once; never split a file.
    for (const group of positiveByAuthority.values()) this.reconcileUris(group);
    this.reconcileUris(removals);
  }

  private diagnosticUriKeys(workspaceKey: string, filePaths: Iterable<string>): string[] {
    const folder = this.folders.get(workspaceKey);
    if (!folder) return [];
    return [...filePaths].map((filePath) => vscode.Uri.joinPath(folder.uri, filePath).toString());
  }

  async replaceWorkspaceManifest(
    folder: vscode.WorkspaceFolder,
    project: Project,
    scan: Scan,
    manifest: FindingFileIndexMap,
    totalFindings: number,
    revision: number,
    diagnosticProjection: 'loading' | 'complete' | 'limited' = 'loading',
    allowOlderScanIdentity = false,
    documentChangeCheckpoint = this.nextDocumentChangeGeneration,
  ): Promise<boolean> {
    if (this.disposed || !this.isWorkspaceTrusted()) return false;
    const key = folder.uri.toString();
    if (!this.sourceTargetIsOpen(folder)) return false;
    const current = this.store.workspace(key);
    if (current && (
      current.projectId > project.id
      || !allowOlderScanIdentity && current.projectId === project.id && current.scanId > scan.id
      || current.projectId === project.id
        && current.scanId === scan.id
        && current.revision > revision
      || current.projectId === project.id
        && current.scanId === scan.id
        && current.revision === revision
        && current.scanRevision > (scan.revision || 0)
    )) return false;
    const treeProjectionChanged = !current
      || current.scanId !== scan.id
      || current.revision !== revision
      || current.fileManifest.size !== manifest.size
      || [...manifest.keys()].some((filePath) => !current.fileManifest.has(filePath));
    const generation = ++this.nextWorkspaceGeneration;
    this.workspaceGenerations.set(key, generation);
    const workspace = await this.store.replaceWorkspace({
      key,
      label: folder.name,
      rootUri: key,
      projectId: project.id,
      projectRevision: project.revision || 0,
      scanId: scan.id,
      scanRevision: scan.revision || 0,
      scanStatus: scan.status,
      scanScope: findingScanScope(scan),
      gateDecision: scan.gate_decision,
      revision,
      totalFindings,
      totalFiles: manifest.size,
      fileManifest: manifest,
      diagnosticProjection,
      diagnosticProcessed: diagnosticProjection === 'complete' ? totalFindings : 0,
    }, []);
    if (!workspace || !this.workspaceLoadIsCurrent(key, generation, folder)) return false;
    if (this.revealedFindingContext?.context.workspaceKey === key) {
      this.revealedFindingContext = undefined;
    }
    this.clearAutomaticHydrationAttemptsForWorkspace(key);
    this.folders.set(key, folder);
    this.markPreexistingDirtyDocuments(workspace);
    this.markDocumentsChangedSince(workspace, documentChangeCheckpoint);
    // Keep the prior rendered editor decorations stable until visible/open
    // files have either hydrated at this revision or been proven absent/stale.
    // Tree/status can publish the exact manifest immediately.
    if (treeProjectionChanged) this.pendingTreeViewportReset = { workspaceKey: key };
    this.refreshNativeSurfaces(false);
    this.resetPendingTreeViewport();
    return true;
  }

  async projectWorkspaceDiagnostics(
    folder: vscode.WorkspaceFolder,
    revision: number,
    produce: (
      accept: (findings: readonly FindingDiagnostic[]) => Promise<void>,
    ) => Promise<void>,
  ): Promise<{ loaded: number; skipped: number; limited?: boolean }> {
    if (this.disposed || !this.isWorkspaceTrusted()) return { loaded: 0, skipped: 0 };
    const key = folder.uri.toString();
    const generation = this.workspaceGenerations.get(key);
    const workspace = this.store.workspace(key);
    if (!generation || !workspace || workspace.revision !== revision) return { loaded: 0, skipped: 0 };
    const token = Symbol('diagnostic-build');
    const reservation = { key, total: workspace.totalFindings, bytes: 0 };
    const projectedTotals = new Map([...this.diagnosticCosts].map(([owner, cost]) => [owner, cost.total]));
    for (const build of this.diagnosticBuilds.values()) {
      projectedTotals.set(build.key, Math.max(projectedTotals.get(build.key) || 0, build.total));
    }
    projectedTotals.set(key, Math.max(projectedTotals.get(key) || 0, workspace.totalFindings));
    if (
      workspace.totalFindings > MAX_DIAGNOSTIC_FINDINGS
      || workspace.totalFiles > MAX_DIAGNOSTIC_FILES
      || [...workspace.fileManifest.values()].some((file) => file.total > MAX_DIAGNOSTICS_PER_FILE)
      || [...projectedTotals.values()].reduce((total, count) => total + count, 0) > MAX_DIAGNOSTIC_FINDINGS
      || [...this.diagnosticBuilds.values()].reduce((total, build) => total + build.total, 0)
        + workspace.totalFindings > MAX_DIAGNOSTIC_FINDINGS
    ) {
      this.limitWorkspaceDiagnostics(folder, revision);
      return { loaded: 0, skipped: 0, limited: true };
    }
    this.diagnosticBuilds.set(token, reservation);
    const budgetExceeded = new Error('Problems memory budget exceeded');
    try {
      const changeGenerationAtStart = this.nextDocumentChangeGeneration;
      const grouped = new Map<string, OwnedDiagnostics>();
      const observedCounts = new Map<string, number>();
      const openDocuments = new Map<string, vscode.TextDocument>();
      for (const document of vscode.workspace.textDocuments || []) {
        const uriKey = document.uri.toString();
        if (!openDocuments.has(uriKey)) openDocuments.set(uriKey, document);
      }
      let processed = 0;
      let skipped = 0;
      await produce(async (findings) => {
        if (!this.isWorkspaceTrusted()) return;
        if (!this.workspaceLoadIsCurrent(key, generation, folder)) {
          const error = new Error('Problems projection was superseded.');
          error.name = 'AbortError';
          throw error;
        }
        let reservedBytes = [...this.diagnosticCosts.values()].reduce((total, cost) => total + cost.bytes, 0)
          + [...this.diagnosticBuilds.values()].reduce((total, build) => total + build.bytes, 0);
        for (const finding of findings) {
          processed += 1;
          const path = safeFindingRelativePath(finding.file_path);
          const manifestPath = path ? workspace.fileManifest.get(path)?.file_path : undefined;
          if (!path) {
            throw new CodeSecurityRequestError(
              'CodeSecurity returned an unsafe compact diagnostic path.',
            );
          }
          if (!manifestPath) {
            throw new CodeSecurityRequestError(
              'CodeSecurity compact diagnostics referenced a file outside the exact manifest.',
              409,
            );
          }
          observedCounts.set(manifestPath, (observedCounts.get(manifestPath) || 0) + 1);
          const uri = vscode.Uri.joinPath(folder.uri, manifestPath);
          const uriKey = uri.toString();
          if (workspaceFileIsStale(workspace, manifestPath)) continue;
          // Conservative object allowance plus UTF-16 retained strings. Both
          // current projections and in-flight replacements share this budget.
          const bytes = 1024 + 2 * (
            finding.message.length + manifestPath.length + finding.scanner.length + finding.display_id.length
          );
          reservation.bytes += bytes;
          reservedBytes += bytes;
          if (reservedBytes > MAX_DIAGNOSTIC_RETAINED_BYTES) throw budgetExceeded;
          const document = openDocuments.get(uriKey);
          const diagnostic = new vscode.Diagnostic(
            document ? documentRange(document, finding) : toVscodeRange(finding),
            diagnosticFindingMessage(finding),
            diagnosticSeverity(finding.severity),
          );
          diagnostic.source = finding.scanner;
          diagnostic.code = finding.display_id;
          const entry = grouped.get(manifestPath) || {
            scanId: workspace.scanId,
            revision,
            items: [],
            document,
            documentVersion: document?.version,
          };
          entry.items.push(diagnostic);
          grouped.set(manifestPath, entry);
        }
        if (processed % 1000 === 0 || processed === workspace.totalFindings) {
          const progressWorkspace = this.store.workspace(key);
          if (
            progressWorkspace
            && progressWorkspace.revision === revision
            && this.workspaceLoadIsCurrent(key, generation, folder)
          ) {
            this.store.updateWorkspaceState(key, { diagnosticProcessed: processed });
            this.refreshNativeSurfaces(false);
          }
        }
      });
      const current = this.store.workspace(key);
      if (!this.isWorkspaceTrusted()) return { loaded: 0, skipped: 0 };
      if (
        !this.workspaceLoadIsCurrent(key, generation, folder)
        || !current
        || current.revision !== revision
      ) return { loaded: 0, skipped: 0 };
      if (processed !== current.totalFindings) {
        throw new CodeSecurityRequestError(
          'CodeSecurity diagnostic pages did not match the exact manifest finding count.',
          409,
        );
      }
      this.reconcileBuiltDiagnosticsWithCurrentDocuments(key, grouped, changeGenerationAtStart);
      const reconciled = this.store.workspace(key);
      if (!reconciled || reconciled.revision !== revision) return { loaded: 0, skipped: 0 };
      for (const [filePath, aggregate] of reconciled.fileManifest) {
        const observed = observedCounts.get(filePath) || 0;
        const retained = grouped.get(filePath)?.items.length || 0;
        if (
          observed !== aggregate.total
          || (workspaceFileIsStale(reconciled, filePath) ? retained !== 0 : retained !== aggregate.total)
        ) {
          throw new CodeSecurityRequestError(
            'CodeSecurity compact diagnostics did not match the exact per-file manifest counts.',
            409,
          );
        }
      }
      const affected = new Set([
        ...this.diagnosticUriKeys(key, this.diagnosticsByWorkspace.get(key)?.keys() || []),
        ...this.diagnosticUriKeys(key, grouped.keys()),
      ].filter((uriKey) => this.surfaceWorkspaceKeyForUri(vscode.Uri.parse(uriKey)) === key));
      this.diagnosticsByWorkspace.set(key, grouped);
      this.diagnosticCosts.set(key, { total: processed, bytes: reservation.bytes });
      // The map swap and bounded transport replacements run in the same task:
      // edits/removals cannot interleave a partially published root. Paged build
      // work yields above; the complete writer slice has its own measured gate.
      this.reconcileUris(affected);
      this.store.updateWorkspaceState(key, {
        diagnosticProjection: 'complete',
        diagnosticProcessed: processed,
      });
      // Exact rich hydration can finish immediately before the atomic Problems
      // map swap, when openDocument still sees only the prior projection. Run
      // the current documents through the now-published map once; if hydration
      // finishes later, replaceHydratedFile performs the same re-projection.
      for (const document of vscode.workspace.textDocuments || []) this.reprojectDocument(document, false);
      this.refreshNativeSurfaces();
      return { loaded: processed - skipped, skipped };
    } catch (error) {
      if (error !== budgetExceeded) throw error;
      if (this.workspaceLoadIsCurrent(key, generation, folder)) {
        this.limitWorkspaceDiagnostics(folder, revision);
      }
      return { loaded: 0, skipped: 0, limited: true };
    } finally {
      this.diagnosticBuilds.delete(token);
    }
  }

  limitWorkspaceDiagnostics(folder: vscode.WorkspaceFolder, revision: number): boolean {
    if (!this.isWorkspaceTrusted()) return false;
    const key = folder.uri.toString();
    const workspace = this.store.workspace(key);
    if (!workspace || workspace.revision !== revision) return false;
    const prior = this.diagnosticsByWorkspace.get(key);
    this.diagnosticsByWorkspace.set(key, new Map());
    this.diagnosticCosts.delete(key);
    this.store.updateWorkspaceState(key, { diagnosticProjection: 'limited', diagnosticProcessed: 0 });
    if (prior) this.reconcileUris(this.diagnosticUriKeys(key, prior.keys()).filter(
      (uriKey) => this.surfaceWorkspaceKeyForUri(vscode.Uri.parse(uriKey)) === key,
    ));
    // The caller starts optional visible/open rich hydration only after the
    // exact limited projection and any explicit required paths are settled.
    this.refreshNativeSurfaces(false);
    return true;
  }

  replaceHydratedFile(
    folder: vscode.WorkspaceFolder,
    filePath: string,
    findings: readonly FindingSummary[],
    revision: number,
  ): boolean {
    if (!this.isWorkspaceTrusted()) return false;
    const key = folder.uri.toString();
    if (!this.store.replaceFileFindings(key, filePath, findings, revision)) return false;
    if (
      this.revealedFindingContext?.context.workspaceKey === key
      && this.revealedFindingContext.filePath === filePath
    ) this.revealedFindingContext = undefined;
    const uri = vscode.Uri.joinPath(folder.uri, filePath);
    const document = (vscode.workspace.textDocuments || [])
      .find((candidate) => candidate.uri.toString() === uri.toString());
    if (document) this.reprojectDocument(document, false);
    // A rich-file completion changes one editor surface. Recomputing the
    // global open/visible hydration selection here would rescan thousands of
    // documents once per file in a bounded 64-file batch. Refresh Tree/status,
    // then render only matching visible editors without admitting more work;
    // the caller performs one global selection at the next real surface cycle.
    this.refreshNativeSurfaces(false);
    const visible = (vscode.window.visibleTextEditors || [])
      .filter((editor) => editor.document.uri.toString() === uri.toString());
    if (visible.length > 0) this.updateVisibleEditors(visible, false);
    return true;
  }

  updateWorkspaceMetadata(
    folder: vscode.WorkspaceFolder,
    project: Project,
    scan: Scan,
  ): boolean {
    if (this.disposed) return false;
    const key = folder.uri.toString();
    const current = this.store.workspace(key);
    if (
      !current
      || current.projectId !== project.id
      || current.scanId !== scan.id
      || !this.workspaceLoadIsCurrent(key, this.workspaceGenerations.get(key) || 0, folder)
    ) return false;
    const projectRevision = project.revision || current.projectRevision;
    const scanRevision = scan.revision || current.scanRevision;
    if (projectRevision < current.projectRevision || scanRevision < current.scanRevision) return false;
    const changed = this.store.updateWorkspaceState(key, {
      projectRevision,
      scanRevision,
      scanStatus: scan.status,
      gateDecision: scan.gate_decision,
    });
    if (changed) this.refreshNativeSurfaces();
    return true;
  }

  finding(context: FindingCommandContext): FindingSummary | undefined {
    const workspace = this.store.workspace(context.workspaceKey);
    if (!workspace || workspace.revision !== context.findingsRevision) return undefined;
    return workspace.findings.find((finding) => (
      finding.id === context.findingId
      && finding.scan_id === context.scanId
      && finding.scan_finding_number === context.scanFindingNumber
      && finding.revision === context.findingRevision
    ));
  }

  private currentLogicalFindingContext(context: FindingCommandContext): FindingCommandContext | undefined {
    const workspace = this.store.workspace(context.workspaceKey);
    if (
      !workspace
      || workspace.scanId !== context.scanId
      || workspace.revision < context.findingsRevision
    ) return undefined;
    const finding = workspace.findings.find((candidate) => (
      candidate.id === context.findingId
      && candidate.scan_id === context.scanId
      && candidate.scan_finding_number === context.scanFindingNumber
      && candidate.revision >= context.findingRevision
    ));
    if (!finding) return undefined;
    // The database identity plus the scan-local ordinal is immutable for the
    // lifetime of a scan. Native surfaces can outlive one collection revision,
    // so normalize their retained command payload to the current projection
    // before an action performs its server-side revision fence.
    return commandContext(workspace.key, workspace.revision, finding);
  }

  registerSourceTarget(folder: vscode.WorkspaceFolder, owner: vscode.WorkspaceFolder): void {
    const key = folder.uri.toString();
    this.sourceTargetOwners.set(key, owner.uri.toString());
    this.folders.set(key, folder);
    this.workspaceRootsChanged();
  }

  resolveFindingContext(value: unknown): FindingContextResolution {
    const fromTree = this.tree?.commandContextFor(value);
    if (fromTree?.ambiguous) return { status: 'ambiguous' };
    if (fromTree?.context) {
      const current = this.finding(fromTree.context)
        ? fromTree.context
        : this.currentLogicalFindingContext(fromTree.context);
      return current ? { status: 'current', context: current } : { status: 'stale' };
    }
    const candidate = explicitFindingCommandContext(value);
    if (!candidate) return { status: 'invalid' };
    const current = this.finding(candidate)
      ? candidate
      : this.currentLogicalFindingContext(candidate);
    return current ? { status: 'current', context: current } : { status: 'stale' };
  }

  private resolveBoundCodeActionContext(bound: BoundCodeActionContext): FindingContextResolution {
    const editor = vscode.window.activeTextEditor;
    const selection = editor?.selection
      ? new vscode.Range(editor.selection.start, editor.selection.end)
      : undefined;
    let selectionMatches = false;
    if (selection && comparePosition(selection.start, selection.end) === 0) {
      selectionMatches = rangeContains({
        startLine: bound.range.start.line,
        startCharacter: bound.range.start.character,
        endLine: bound.range.end.line,
        endCharacter: bound.range.end.character,
      }, selection.start.line, selection.start.character);
    } else if (selection) {
      const overlap = selection.intersection(bound.range);
      selectionMatches = Boolean(overlap && comparePosition(overlap.start, overlap.end) < 0);
    }
    if (
      !editor
      || editor.document !== bound.document
      || editor.document.version !== bound.documentVersion
      || !selectionMatches
    ) return { status: 'invalid' };
    const workspace = this.store.workspace(bound.context.workspaceKey);
    const owner = this.entriesForUri(editor.document.uri).find((entry) => (
      entry.workspace.key === bound.context.workspaceKey
      && entry.filePath === bound.filePath
    ));
    if (!workspace || !owner || workspaceFileIsStale(workspace, bound.filePath)) {
      return { status: 'stale' };
    }
    const current = this.finding(bound.context)
      ? bound.context
      : this.currentLogicalFindingContext(bound.context);
    return current ? { status: 'current', context: current } : { status: 'stale' };
  }

  private async dispatchQuickFix(action: QuickFixAction): Promise<void> {
    if (!this.isWorkspaceTrusted()) return;
    const command = QUICK_FIX_COMMANDS.find((candidate) => candidate.action === action);
    if (!command) return;
    const editorSelection = vscode.window.activeTextEditor?.selection;
    const selection = editorSelection
      ? new vscode.Range(editorSelection.start, editorSelection.end)
      : undefined;
    const candidates: Array<{
      token: string;
      context: FindingCommandContext;
      exactRange: boolean;
      exactFindingRange: boolean;
    }> = [];
    for (const [token, bound] of this.codeActionContexts) {
      const resolution = this.resolveBoundCodeActionContext(bound);
      if (resolution.status !== 'current') continue;
      candidates.push({
        token,
        context: resolution.context,
        exactRange: Boolean(selection && sameRange(selection, bound.range)),
        exactFindingRange: Boolean(selection && sameRange(selection, bound.findingRange)),
      });
    }
    // The provider range can span several diagnostics. It is not the selected
    // finding's identity: prefer an exact finding range, never array order.
    const preferred = candidates.some((candidate) => candidate.exactFindingRange)
      ? candidates.filter((candidate) => candidate.exactFindingRange)
      : candidates.some((candidate) => candidate.exactRange)
        ? candidates.filter((candidate) => candidate.exactRange)
        : candidates;
    const matches: Array<{ token: string; context: FindingCommandContext }> = [];
    for (const candidate of preferred) {
      if (matches.some((match) => sameFindingCommandContext(match.context, candidate.context))) continue;
      matches.push(candidate);
    }
    if (matches.length === 0) {
      await vscode.window.showWarningMessage(
        'This CodeSecurity Quick Fix is no longer current. Reopen Quick Fixes for the visible finding and try again.',
      );
      return;
    }
    let match = matches[0];
    if (matches.length > 1) {
      const choices = matches.map((candidate) => {
        const finding = this.finding(candidate.context)!;
        return {
          label: finding.display_id,
          description: boundedSingleLineText(`${finding.scanner} · ${finding.rule_id}`, 160),
          detail: boundedSingleLineText(`${finding.file_path}:${finding.start_line ?? 1}:${finding.start_column ?? 1} · ${finding.message}`, 240),
          candidate,
        };
      });
      const choice = await vscode.window.showQuickPick(choices, {
        title: `Choose finding · ${command.title}`,
        placeHolder: 'Several findings overlap this selection. Choose the exact finding to continue.',
        matchOnDescription: true,
        matchOnDetail: true,
      });
      if (!choice || !choices.includes(choice)) return;
      match = choice.candidate;
    }
    const bound = this.codeActionContexts.get(match.token);
    const current = bound && this.resolveBoundCodeActionContext(bound);
    const currentSelection = vscode.window.activeTextEditor?.selection;
    if (
      !bound || current?.status !== 'current'
      || !sameFindingCommandContext(current.context, match.context)
      || !selection || !currentSelection || !sameRange(selection, currentSelection)
    ) {
      await vscode.window.showWarningMessage(
        'This CodeSecurity Quick Fix is no longer current. Reopen Quick Fixes for the visible finding and try again.',
      );
      return;
    }
    this.codeActionContexts.delete(match.token);
    this.codeActionContexts.set(match.token, bound);
    await vscode.commands.executeCommand(command.command, match.context);
  }

  private clearCodeActionContexts(): void {
    this.codeActionContexts.clear();
  }

  private assertCurrentRevealProjection(
    context: FindingCommandContext,
    expectedWorkspace: IndexedWorkspace,
    expectedFinding: FindingSummary,
    requestedPath: string,
    manifestPath: string,
    phase: 'opening' | 'showing',
  ): void {
    const currentWorkspace = this.store.workspace(context.workspaceKey);
    const currentFinding = this.finding(context);
    const currentManifestPath = currentWorkspace
      ? safeFindingRelativePath(currentWorkspace.fileManifest.get(requestedPath)?.file_path || '')
      : undefined;
    if (
      !currentWorkspace
      || currentWorkspace.projectId !== expectedWorkspace.projectId
      || currentWorkspace.scanId !== expectedWorkspace.scanId
      || currentWorkspace.revision !== expectedWorkspace.revision
    ) {
      throw new CodeSecurityRequestError(
        `CodeSecurity scan revision changed while its file was ${phase}. Refresh and try again.`,
        409,
        false,
        { code: 'revision_conflict' },
      );
    }
    if (
      currentManifestPath !== manifestPath
      || !currentFinding
      || !sameRevealFindingEvidence(currentFinding, expectedFinding)
    ) {
      throw new CodeSecurityRequestError(
        `CodeSecurity finding changed while its file was ${phase}. Refresh and try again.`,
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
    if (workspaceFileIsStale(currentWorkspace, manifestPath)) {
      throw new CodeSecurityRequestError(
        `CodeSecurity finding became stale while its file was ${phase}. Save and rescan before revealing it.`,
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
  }

  private rememberRevealedFinding(
    context: FindingCommandContext,
    document: vscode.TextDocument,
    filePath: string,
    range: vscode.Range,
  ): void {
    this.revealedFindingContext = {
      context,
      document,
      documentVersion: document.version,
      filePath,
      range,
      findingRange: range,
    };
  }

  async revealFinding(context: FindingCommandContext): Promise<void> {
    const workspace = this.store.workspace(context.workspaceKey);
    const folder = this.folders.get(context.workspaceKey);
    const finding = this.finding(context);
    if (!workspace || !folder || !finding) {
      throw new CodeSecurityRequestError(
        'CodeSecurity finding is no longer current. Refresh before revealing it.',
        409,
      );
    }
    const requestedPath = safeFindingRelativePath(finding.file_path);
    const manifestPath = requestedPath
      ? safeFindingRelativePath(workspace.fileManifest.get(requestedPath)?.file_path || '')
      : undefined;
    if (!requestedPath || !manifestPath) {
      throw new CodeSecurityRequestError(
        'CodeSecurity finding does not belong to the current workspace manifest.',
        409,
      );
    }
    if (workspaceFileIsStale(workspace, manifestPath)) {
      throw new CodeSecurityRequestError(
        'CodeSecurity finding is stale after an editor change. Save and rescan before revealing it.',
        409,
      );
    }

    const uri = vscode.Uri.joinPath(folder.uri, manifestPath);
    const document = await vscode.workspace.openTextDocument(uri);
    this.assertCurrentRevealProjection(context, workspace, finding, requestedPath, manifestPath, 'opening');
    const editor = await vscode.window.showTextDocument(document, sourceRevealOptions(uri));
    if (editor.document.uri.toString() !== uri.toString()) {
      throw new CodeSecurityRequestError('VS Code did not open the requested CodeSecurity finding file.');
    }
    this.assertCurrentRevealProjection(context, workspace, finding, requestedPath, manifestPath, 'showing');
    const range = documentRange(document, finding);
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    this.rememberRevealedFinding(context, document, manifestPath, range);
  }

  /**
   * Reveal one recipient-bound, API-validated finding in an exact trusted
   * open workspace without creating or replacing any native projection.
   */
  async revealTargetedFinding(
    folder: vscode.WorkspaceFolder,
    finding: FindingDetail,
    assertWorkspaceOwner: () => void,
    projectionContext?: FindingCommandContext,
  ): Promise<vscode.TextEditor> {
    assertWorkspaceOwner();
    if (!this.sourceTargetIsOpen(folder)) {
      throw new CodeSecurityRequestError(
        'The selected IDE workspace is no longer open for this CodeSecurity project.',
        409,
        false,
        { code: 'workspace_not_open' },
      );
    }
    const requestedPath = safeFindingRelativePath(finding.file_path);
    if (!requestedPath) {
      throw new CodeSecurityRequestError(
        'CodeSecurity rejected an unsafe targeted-finding source path.',
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
    const uri = vscode.Uri.joinPath(folder.uri, requestedPath);
    const alreadyOpenDocument = vscode.workspace.textDocuments.find(
      (document) => document.uri.toString() === uri.toString(),
    );
    if (alreadyOpenDocument?.isDirty) {
      throw new CodeSecurityRequestError(
        'The targeted CodeSecurity finding cannot be opened over unsaved editor text.',
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
    const projectedWorkspace = projectionContext
      ? this.store.workspace(projectionContext.workspaceKey)
      : undefined;
    const projectedFinding = projectionContext ? this.finding(projectionContext) : undefined;
    const manifestPath = projectedWorkspace
      ? safeFindingRelativePath(projectedWorkspace.fileManifest.get(requestedPath)?.file_path || '')
      : undefined;
    if (projectionContext && (
      projectionContext.workspaceKey !== folder.uri.toString()
      || !projectedWorkspace
      || projectedWorkspace.scanId !== projectionContext.scanId
      || projectedWorkspace.revision !== projectionContext.findingsRevision
    )) {
      throw new CodeSecurityRequestError(
        'The selected CodeSecurity scan changed before its targeted finding could be revealed.',
        409,
        false,
        { code: 'revision_conflict' },
      );
    }
    if (projectionContext && (
      !projectedFinding
      || !manifestPath
      || manifestPath !== requestedPath
      || !sameRevealFindingEvidence(projectedFinding, finding)
      || workspaceFileIsStale(projectedWorkspace!, manifestPath)
    )) {
      throw new CodeSecurityRequestError(
        'The selected CodeSecurity finding no longer matches the current native projection.',
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
    const assertProjection = (phase: 'opening' | 'showing'): void => {
      if (!projectionContext || !projectedWorkspace || !projectedFinding || !manifestPath) return;
      this.assertCurrentRevealProjection(
        projectionContext,
        projectedWorkspace,
        projectedFinding,
        requestedPath,
        manifestPath,
        phase,
      );
    };
    assertProjection('opening');
    const expectedRootUri = folder.uri.toString();
    const assertWorkspaceOpen = (phase: 'opening' | 'showing'): void => {
      if (
        folder.uri.toString() !== expectedRootUri
        || !this.sourceTargetIsOpen(folder)
      ) {
        throw new CodeSecurityRequestError(
          `The selected CodeSecurity workspace changed while its targeted finding was ${phase}.`,
          409,
          false,
          { code: 'workspace_not_open' },
        );
      }
    };
    const document = await vscode.workspace.openTextDocument(uri);
    assertWorkspaceOwner();
    assertWorkspaceOpen('opening');
    assertProjection('opening');
    if (document.uri.toString() !== uri.toString()) {
      throw new CodeSecurityRequestError('VS Code did not open the targeted finding file requested by CodeSecurity.');
    }
    const documentVersion = document.version;
    if (document.isDirty) {
      throw new CodeSecurityRequestError(
        'The targeted CodeSecurity finding cannot be opened over unsaved editor text.',
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
    const editor = await vscode.window.showTextDocument(document, sourceRevealOptions(uri));
    assertWorkspaceOwner();
    assertWorkspaceOpen('showing');
    assertProjection('showing');
    if (editor.document.uri.toString() !== uri.toString()) {
      throw new CodeSecurityRequestError('VS Code did not show the targeted finding file requested by CodeSecurity.');
    }
    if (
      editor.document !== document
      || editor.document.version !== documentVersion
      || editor.document.isDirty
    ) {
      throw new CodeSecurityRequestError(
        'The targeted CodeSecurity finding source changed while VS Code opened it.',
        409,
        false,
        { code: 'finding_not_current' },
      );
    }
    const range = documentRange(document, finding);
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    if (projectionContext && manifestPath) {
      this.rememberRevealedFinding(projectionContext, document, manifestPath, range);
    } else {
      // A source-only target has no current native projection to authorize
      // hover ownership, even if its range matches a previously revealed item.
      this.revealedFindingContext = undefined;
    }
    return editor;
  }

  workspaceFolder(key: string): vscode.WorkspaceFolder | undefined {
    return this.folders.get(key);
  }

  markDocumentChanged(document: vscode.TextDocument): boolean {
    if (!this.isWorkspaceTrusted()) return false;
    this.nextDocumentChangeGeneration += 1;
    this.documentChangeGenerations.set(document, this.nextDocumentChangeGeneration);
    if (this.revealedFindingContext?.document === document) {
      this.revealedFindingContext = undefined;
    }
    const uriKey = document.uri.toString();
    this.recentDocumentChanges.delete(uriKey);
    this.recentDocumentChanges.set(uriKey, this.nextDocumentChangeGeneration);
    while (this.recentDocumentChanges.size > MAX_RECENT_DOCUMENT_CHANGES) {
      const oldest = this.recentDocumentChanges.entries().next().value as [string, number] | undefined;
      if (!oldest) break;
      this.recentDocumentChanges.delete(oldest[0]);
      this.documentChangeHistoryFloor = Math.max(this.documentChangeHistoryFloor, oldest[1]);
    }
    let changed = false;
    const affected = new Set<string>();
    for (const ownerEntry of this.allManifestOwnersForUri(document.uri)) {
      if (!this.store.markFileStale(ownerEntry.workspaceKey, ownerEntry.filePath)) continue;
      changed = true;
      const owner = this.diagnosticsByWorkspace.get(ownerEntry.workspaceKey);
      if (owner?.delete(ownerEntry.filePath)) affected.add(document.uri.toString());
    }
    if (changed) {
      this.reconcileUris(affected);
      this.refreshNativeSurfaces();
    }
    return changed;
  }

  markFilesChanged(uris: readonly vscode.Uri[]): number {
    if (!this.isWorkspaceTrusted()) return 0;
    let changed = 0;
    const affected = new Set<string>();
    for (const uri of uris) {
      this.clearAutomaticHydrationAttemptForUri(uri);
      for (const ownerEntry of this.allManifestOwnersForUri(uri)) {
        if (!this.store.markFileStale(ownerEntry.workspaceKey, ownerEntry.filePath)) continue;
        changed += 1;
        const owner = this.diagnosticsByWorkspace.get(ownerEntry.workspaceKey);
        if (owner?.delete(ownerEntry.filePath)) affected.add(uri.toString());
      }
    }
    if (changed > 0) {
      this.reconcileUris(affected);
      this.refreshNativeSurfaces();
    }
    return changed;
  }

  openDocument(document: vscode.TextDocument): void {
    if (!this.isWorkspaceTrusted()) return;
    this.clearAutomaticHydrationAttemptForUri(document.uri);
    this.reprojectDocument(document, true);
  }

  private reprojectDocument(document: vscode.TextDocument, requestHydration: boolean): void {
    if (this.disposed || !this.isWorkspaceTrusted()) return;
    if (requestHydration) this.requestHydrationForUri(document.uri);
    const uriKey = document.uri.toString();
    let changed = false;
    for (const entry of this.entriesForUri(document.uri)) {
      if (workspaceFileIsStale(entry.workspace, entry.filePath)) continue;
      const owner = this.diagnosticsByWorkspace.get(entry.workspace.key);
      const prior = owner?.get(entry.filePath);
      if (
        !owner
        || !prior
        || prior.scanId !== entry.workspace.scanId
        || prior.revision !== entry.workspace.revision
      ) continue;
      const items = entry.findings.map((finding) => {
        const diagnostic = new vscode.Diagnostic(
          documentRange(document, finding),
          diagnosticFindingMessage(finding),
          diagnosticSeverity(finding.severity),
        );
        diagnostic.source = finding.scanner;
        diagnostic.code = finding.display_id;
        return diagnostic;
      });
      owner.set(entry.filePath, {
        scanId: entry.workspace.scanId,
        revision: entry.workspace.revision,
        items,
        document,
        documentVersion: document.version,
      });
      this.documentIntervalIndex(document, entry.findings, items.map((diagnostic) => diagnostic.range));
      changed = true;
    }
    if (!changed) return;
    this.reconcileUris([uriKey]);
    // This method recalculates Problems for any opened document; decorations
    // remain constrained to VS Code's visible editor list.
    this.updateVisibleEditors();
  }

  closeDocument(document: vscode.TextDocument): void {
    if (this.disposed) return;
    if (this.revealedFindingContext?.document === document) {
      this.revealedFindingContext = undefined;
    }
    for (const workspace of this.diagnosticsByWorkspace.values()) {
      for (const entry of workspace.values()) {
        if (entry.document !== document) continue;
        // Problems owns only immutable diagnostic ranges after close. Drop the
        // last strong TextDocument reference so the document-keyed interval
        // cache can be released, and a later reopen builds against its own
        // document identity/version.
        entry.document = undefined;
        entry.documentVersion = undefined;
      }
    }
    this.documentIntervalIndexes.delete(document);
    this.documentChangeGenerations.delete(document);
  }

  invalidateWorkspaceProjection(folder: vscode.WorkspaceFolder): boolean {
    if (!this.isWorkspaceTrusted()) return false;
    const key = folder.uri.toString();
    const current = this.store.workspace(key);
    if (!current) return false;
    if (this.revealedFindingContext?.context.workspaceKey === key) {
      this.revealedFindingContext = undefined;
    }
    const generation = ++this.nextWorkspaceGeneration;
    this.workspaceGenerations.set(key, generation);
    this.clearAutomaticHydrationAttemptsForWorkspace(key);
    const prior = this.diagnosticsByWorkspace.get(key);
    const priorUris = prior ? this.diagnosticUriKeys(key, prior.keys()) : [];
    this.diagnosticsByWorkspace.set(key, new Map());
    this.diagnosticCosts.delete(key);
    // A committed lifecycle/deletion mutation advances both the finding
    // collection and the gate. Do not retain the old manifest as a loading
    // projection: VS Code may re-expand one of its file nodes after the
    // cancellation boundary and start a brand-new request at that obsolete
    // revision. Remove the old authority until the exact refresh publishes
    // its replacement; stale Tree nodes are rejected by getChildren above.
    this.store.invalidateWorkspace(key);
    if (prior) this.reconcileUris(priorUris.filter(
      (uriKey) => this.surfaceWorkspaceKeyForUri(vscode.Uri.parse(uriKey)) === key,
    ));
    this.refreshNativeSurfaces();
    return true;
  }

  clearWorkspace(
    folder: vscode.WorkspaceFolder,
    { preserveSourceTarget = false }: { preserveSourceTarget?: boolean } = {},
  ): void {
    const key = folder.uri.toString();
    if (this.revealedFindingContext?.context.workspaceKey === key) {
      this.revealedFindingContext = undefined;
    }
    this.clearAutomaticHydrationAttemptsForWorkspace(key);
    this.workspaceGenerations.delete(key);
    const prior = this.diagnosticsByWorkspace.get(key);
    const priorUris = prior ? this.diagnosticUriKeys(key, prior.keys()) : [];
    this.diagnosticsByWorkspace.delete(key);
    this.diagnosticCosts.delete(key);
    // Empty or unavailable findings do not remove a selected repository from
    // its open parent. Explicit context removal still forgets both identities.
    if (!preserveSourceTarget) {
      this.folders.delete(key);
      this.sourceTargetOwners.delete(key);
    }
    this.store.removeWorkspace(key);
    if (prior) this.reconcileWorkspaceRootTopology(priorUris);
    this.refreshNativeSurfaces();
  }

  workspaceRootsChanged(): void {
    // Root topology changes redefine surface authority. Prior automatic
    // attempts are no longer meaningful even when scan identity is unchanged;
    // clear the bounded ledger so the newly authoritative visible root gets
    // one deterministic hydration opportunity without an editor transition.
    this.automaticHydrationAttempts.clear();
    this.automaticHydrationsInFlight.clear();
    this.revealedFindingContext = undefined;
    const affected = new Set<string>();
    for (const [workspaceKey, workspace] of this.diagnosticsByWorkspace) {
      for (const uriKey of this.diagnosticUriKeys(workspaceKey, workspace.keys())) affected.add(uriKey);
    }
    this.reconcileWorkspaceRootTopology(affected);
    this.refreshNativeSurfaces();
  }

  clearAll(): void {
    this.clearCodeActionContexts();
    this.revealedFindingContext = undefined;
    this.diagnosticsByWorkspace.clear();
    this.diagnosticCosts.clear();
    this.folders.clear();
    this.sourceTargetOwners.clear();
    this.workspaceGenerations.clear();
    this.automaticHydrationAttempts.clear();
    this.automaticHydrationsInFlight.clear();
    this.recentDocumentChanges.clear();
    this.store.clear();
    // DiagnosticCollection.clear uses VS Code's dedicated collection-clear
    // host call, so a multi-root authority reset cannot hit the outbound
    // per-update diagnostic envelope or leave a suffix of stale Problems.
    this.diagnostics.clear();
    this.refreshNativeSurfaces();
  }

  private workspaceLoadIsCurrent(
    key: string,
    generation: number,
    folder: vscode.WorkspaceFolder,
  ): boolean {
    return !this.disposed
      && this.workspaceGenerations.get(key) === generation
      && this.sourceTargetIsOpen(folder);
  }

  private openWorkspaceKeys(): ReadonlySet<string> {
    return new Set((vscode.workspace.workspaceFolders || []).map((folder) => folder.uri.toString()));
  }

  private sourceTargetIsOpen(folder: vscode.WorkspaceFolder): boolean {
    const key = folder.uri.toString();
    const ownerKey = this.sourceTargetOwners.get(key) || key;
    return this.openWorkspaceKeys().has(ownerKey);
  }

  setServiceHealth(health: LocalServiceHealth): void {
    if (this.disposed || this.serviceHealth === health) return;
    this.serviceHealth = health;
    this.refreshStatusAndEditors();
  }

  setIdeEnrollmentReview(
    review?: Readonly<{
      verificationCode: string;
      state: 'awaiting_approval' | 'rejected' | 'expired' | 'unavailable';
    }>,
  ): void {
    if (
      this.disposed
      || this.ideEnrollmentReview?.verificationCode === review?.verificationCode
        && this.ideEnrollmentReview?.state === review?.state
    ) return;
    this.ideEnrollmentReview = review;
    this.refreshStatusAndEditors(false);
  }

  private refreshNativeSurfaces(updateEditors = true): void {
    if (this.disposed) return;
    this.tree?.refresh();
    this.refreshStatusAndEditors(updateEditors);
  }

  private refreshStatusAndEditors(updateEditors = true): void {
    const entries = this.store.workspaceEntries();
    const count = entries.reduce((total, workspace) => total + workspace.totalFindings, 0);
    const scoped = entries.filter(workspace => workspace.scanScope?.kind !== 'workspace').length;
    const stale = entries.reduce((total, workspace) => (
      total + (workspace.allFilesStale ? workspace.totalFiles : workspace.staleFiles.size)
    ), 0);
    const gates = [...new Set(entries.map((workspace) => workspace.gateDecision).filter(Boolean))];
    const projections = new Set(entries.map((workspace) => workspace.diagnosticProjection));
    const diagnosticProcessed = entries.reduce((total, workspace) => (
      total + (workspace.diagnosticProjection === 'loading' ? workspace.diagnosticProcessed : 0)
    ), 0);
    const diagnosticTotal = entries.reduce((total, workspace) => (
      total + (workspace.diagnosticProjection === 'loading' ? workspace.totalFindings : 0)
    ), 0);
    const problems = projections.has('limited')
      ? ' · Problems unavailable'
      : projections.has('loading')
        ? ` · Problems ${diagnosticProcessed}/${diagnosticTotal}`
        : '';
    const connectionStale = ['connecting', 'reconnecting', 'unavailable'].includes(this.serviceHealth);
    if (this.status) {
      if (this.ideEnrollmentReview) {
        const review = this.ideEnrollmentReview;
        this.status.text = review.state === 'awaiting_approval'
          ? `$(key) Approval needed · ${review.verificationCode}`
          : `$(key) IDE access ${review.state} · ${review.verificationCode}`;
        this.status.command = 'lomoCodeSecurity.pair';
        this.status.tooltip = review.state === 'awaiting_approval'
          ? `Approve IDE access ${review.verificationCode} in CodeSecurity Settings from an already-authenticated owner browser opened in the system browser. Select this status to review or cancel the request.`
          : `IDE access ${review.verificationCode} was ${review.state}. Select this status to review or cancel the retained request.`;
      } else {
        this.status.command = connectionStale
          ? 'lomoCodeSecurity.reconnect'
          : this.serviceHealth === 'pair required'
            ? 'lomoCodeSecurity.pair'
            : 'lomoCodeSecurity.openDashboard';
        const visibleHealth = this.serviceHealth === 'pair required' ? 'IDE access required' : this.serviceHealth;
        this.status.text = entries.length === 0
          ? `$(shield) CodeSecurity local · ${visibleHealth}`
          : `$(shield) ${visibleHealth} · ${gates.join('/') || 'pending'} · ${count}`
            + `${connectionStale ? ' cached' : ''}${scoped ? ` · ${scoped} scoped` : ''}${stale ? ` · ${stale} stale` : ''}${problems}`;
        this.status.tooltip = projections.has('limited')
          ? `The exact Tree and visible-file annotations remain available. A root exceeds `
            + `${DIAGNOSTIC_PROJECTION_LIMIT_DESCRIPTION}. Unchanged sibling Problems are retained.`
          : projections.has('loading')
            ? 'The exact Tree manifest is available. The complete Problems projection is loading in bounded pages.'
            : stale
              ? 'Disk-based findings changed locally. Rescan before relying on stale files.'
              : connectionStale
                ? `Local service: ${this.serviceHealth}. Retained findings are cached and may be stale. Select this status to reconnect the exact retained IDE profile.`
                : this.serviceHealth === 'pair required'
                  ? 'IDE access is required. Select this status to connect this exact VS Code profile.'
                : `Local service: ${this.serviceHealth}. Authoritative cached gate and indexed finding count.`;
        if (scoped) this.status.tooltip += ` ${scoped} repository result${scoped === 1 ? '' : 's'} `
          + 'cover a file, folder or unknown scope. These totals do not represent whole-repository coverage. '
          + 'Use Open scan history in the Findings tree to review earlier scans.';
      }
      const workspaceTrust = this.workspaceTrustSummary();
      this.status.tooltip = `${workspaceTrust} ${String(this.status.tooltip)}`;
      this.status.accessibilityInformation = { label: this.statusAccessibilityLabel(workspaceTrust) };
    }
    if (updateEditors && this.isWorkspaceTrusted()) this.updateVisibleEditors();
  }

  private resetPendingTreeViewport(): void {
    const pending = this.pendingTreeViewportReset;
    if (this.disposed || this.treeViewportResetInFlight || !pending || !this.treeView?.visible) return;
    const root = this.tree?.workspaceNode(pending.workspaceKey);
    if (!root) {
      this.pendingTreeViewportReset = undefined;
      return;
    }
    this.treeViewportResetInFlight = true;
    void this.revealPendingTreeViewport(root, pending);
  }

  private async revealPendingTreeViewport(root: WorkspaceTreeNode, pending: TreeViewportRequest): Promise<void> {
    try {
      await this.treeView!.reveal(root, { select: false, focus: false, expand: 1 });
      if (this.pendingTreeViewportReset === pending) this.pendingTreeViewportReset = undefined;
    } catch (error: unknown) {
      if (!this.disposed && this.treeView?.visible && !(error instanceof vscode.CancellationError)) {
        console.error('CodeSecurity could not restore the visible Findings tree viewport.', error);
      }
    } finally {
      this.treeViewportResetInFlight = false;
      // Coalesce to the latest request, including a newer revision of the same
      // repository. A failed unchanged request waits for a later visibility event.
      if (this.pendingTreeViewportReset !== pending) this.resetPendingTreeViewport();
    }
  }

  private decorationProjection(editor: vscode.TextEditor, mode: AnnotationMode): DecorationProjection {
    if (mode === 'off') {
      return { signature: JSON.stringify([mode, editor.document.version]), inline: [] };
    }
    const ranges = Array.isArray(editor.visibleRanges) ? editor.visibleRanges : [];
    const windows = visibleLineWindows(ranges, editor.document.lineCount);
    if (windows.length === 0) {
      return { signature: JSON.stringify([mode, editor.document.version, []]), inline: [] };
    }

    const lastLine = Math.max(editor.document.lineCount - 1, 0);
    const sources: {
      workspaceKey: string;
      workspaceRevision: number;
      findings: readonly IndexedLineFinding[];
    }[] = [];
    for (const entry of this.entriesForUri(editor.document.uri)) {
      if (workspaceFileIsStale(entry.workspace, entry.filePath)) continue;
      sources.push({
        workspaceKey: entry.workspace.key,
        workspaceRevision: entry.workspace.revision,
        findings: this.indexedFindings(entry.findings),
      });
    }

    const inline: vscode.DecorationOptions[] = [];
    const signatureLines: unknown[] = [];
    for (const { line, findings } of projectVisibleFindingLines(sources, windows, lastLine)) {
      const primary = findings[0];
      const finding = primary.finding;
      const extra = findings.length - 1;
      const lineEnd = new vscode.Position(line, editor.document.lineAt(line).text.length);
      // Keep the informational annotation hover at the line end, outside the
      // exclusive source range owned by the richer actionable HoverProvider.
      const inlineRange = new vscode.Range(lineEnd, lineEnd);
      const hoverMessage = hoverMarkdown(
        primary.workspaceKey,
        primary.workspaceRevision,
        finding,
        editor.document.isDirty,
        'read_only',
      );
      if (extra > 0) {
        hoverMessage.appendMarkdown('\n\n');
        hoverMessage.appendText(`${extra} other report${extra === 1 ? '' : 's'} on this line. These may describe different issues; each report keeps its own severity and actions.`);
      }
      const label = findingInlineAnnotation(finding, extra, mode);
      inline.push({
        range: inlineRange,
        hoverMessage,
        renderOptions: { after: { contentText: label } },
      });
      signatureLines.push([
        line,
        lineEnd.character,
        label,
        findings.map(decorationFindingSignature),
      ]);
    }
    return {
      signature: JSON.stringify([mode, editor.document.version, editor.document.isDirty, signatureLines]),
      inline,
    };
  }

  updateVisibleEditors(
    editors?: readonly vscode.TextEditor[],
    hydrateMissing = true,
  ): void {
    if (
      this.disposed
      || !this.isWorkspaceTrusted()
      || !this.inline
      || !Array.isArray(vscode.window.visibleTextEditors)
    ) return;
    const mode = vscode.workspace.getConfiguration('lomoCodeSecurity').get<AnnotationMode>(
      'inlineAnnotations', 'compact',
    );
    const candidates = editors || vscode.window.visibleTextEditors;
    const automatic = hydrateMissing
      ? this.automaticHydrationSelection()
      : { keys: new Set<string>(), uris: new Set<string>() };
    const hydrationUris = hydrateMissing
      ? this.boundedAutomaticHydrationUris(candidates, automatic.uris)
      : automatic.uris;
    for (const editor of candidates) {
      if (hydrationUris.has(editor.document.uri.toString())) {
        this.requestHydrationForUri(editor.document.uri, automatic.keys);
      }
      // A new compact Problems projection can become visible before its rich
      // file hydration completes. Clear the prior decoration frame during
      // that gap so the new diagnostic is never mixed with previous-scan
      // decoration detail. Commands are exposed only by the current provider.
      const projection = this.decorationProjection(editor, mode);
      if (this.renderSignatures.get(editor) === projection.signature) continue;
      editor.setDecorations(this.inline, projection.inline);
      this.renderSignatures.set(editor, projection.signature);
    }
    if (hydrateMissing) {
      // automatic.uris is already globally capped by finding count and 64
      // files, with visible editors ordered before other open documents.
      // Admit the bounded non-visible suffix without rendering it.
      for (const uriKey of automatic.uris) {
        if (hydrationUris.has(uriKey)) continue;
        this.requestHydrationForUri(vscode.Uri.parse(uriKey), automatic.keys);
      }
    }
  }

  visibleEditorsChanged(editors: readonly vscode.TextEditor[] = vscode.window.visibleTextEditors || []): void {
    if (!this.isWorkspaceTrusted()) return;
    for (const editor of editors) this.clearAutomaticHydrationAttemptForUri(editor.document.uri);
    this.updateVisibleEditors(editors);
  }

  testSnapshot(): Readonly<{ statusText: string; treeWorkspaceLabels: readonly string[] }> {
    return Object.freeze({
      statusText: this.status?.text || '',
      treeWorkspaceLabels: Object.freeze(this.store.workspaceEntries().map((workspace) => workspace.label)),
    });
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.pendingTreeViewportReset = undefined;
    if (this.visibleRangeTimer !== undefined) {
      clearTimeout(this.visibleRangeTimer);
      this.visibleRangeTimer = undefined;
    }
    this.pendingVisibleRangeEditors.clear();
    this.automaticHydrationAttempts.clear();
    this.clearAll();
    for (const disposable of this.disposables.splice(0)) disposable.dispose();
  }
}

export { SUPPRESSIVE_LIFECYCLES };
