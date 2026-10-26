import type { Finding } from './api';

/** Presentation only: never replace the scanner message or finding identity.
 * Kept identical in the independently packaged Web and IDE clients by a parity test.
 */
export function trivyMessagePresentation(scanner: string, message: string): {
  kind: 'secret' | 'configuration' | 'dependency'; title: string;
} | undefined {
  if (scanner !== 'trivy' || message.length > 20000) return undefined;
  // SARIF uses newlines; compact API summaries flatten those separators.
  const text = message.trim().replace(/\r?\n/gu, ' ');
  const secret = /^Artifact: [^\r\n]+ Type:  Secret ([^\r\n]{1,180}?) Severity: (?:CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN) Match: [^\r\n]*$/u.exec(text);
  if (secret) return { kind: 'secret', title: secret[1].trim() };
  const configuration = /^Artifact: [^\r\n]+ Type: \S+ Vulnerability \S+ Severity: (?:CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN) Message: ([^\r\n]{1,180}?) Link: [^\r\n]+$/u.exec(text);
  if (configuration) return { kind: 'configuration', title: configuration[1].trim() };
  const dependency = /^Package: (\S{1,120}) Installed Version: \S+ Vulnerability ((?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)) Severity: (?:CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN) Fixed Version: [^\r\n]* Link: [^\r\n]+$/u.exec(text);
  if (dependency) return { kind: 'dependency', title: `${dependency[1]} · ${dependency[2]}` };
  return undefined;
}

export type FindingEvidenceKind = 'code' | 'secret' | 'dependency' | 'configuration' | 'license' | 'unknown';
const kindLabels: Record<FindingEvidenceKind, string> = {
  code: 'Code issue', secret: 'Secret exposure', dependency: 'Dependency vulnerability',
  configuration: 'Configuration issue', license: 'License signal', unknown: 'Scanner finding',
};

// Only these already-redacted, admitted metadata fields participate in review.
// Unknown/native payload fields are never promoted into the interface.
const metadataKeys = ['rule_name', 'tags', 'verified', 'snippet_start_line', 'snippet_column_start',
  'snippet_truncated', 'snippet_line_truncated', 'message_truncated'] as const;

export function findingEvidenceMetadata(finding: Pick<Finding, 'metadata_json'>): Record<string, unknown> {
  const metadata = finding.metadata_json || {};
  const result: Record<string, unknown> = {};
  for (const key of metadataKeys) {
    const value = metadata[key];
    if (key === 'tags') {
      if (Array.isArray(value) && value.length <= 64 && value.every((tag) => typeof tag === 'string' && tag.length <= 160)) {
        result.tags = [...value];
      }
    } else if (key === 'rule_name') {
      if (typeof value === 'string' && value.trim() && value.length <= 240) result[key] = value;
    } else if (key.endsWith('_line') || key === 'snippet_column_start') {
      if (typeof value === 'number' && Number.isFinite(value)) result[key] = value;
    } else if (typeof value === 'boolean') result[key] = value;
  }
  return result;
}

export function findingEvidenceMetadataKey(finding: Pick<Finding, 'metadata_json'>): string {
  return JSON.stringify(findingEvidenceMetadata(finding));
}

export function preserveFindingEvidence(summary: Finding, detail: Finding): Finding {
  return { ...summary, code_snippet: detail.code_snippet,
    metadata_json: { ...findingEvidenceMetadata(summary), ...findingEvidenceMetadata(detail) } };
}

export function findingEvidencePresentation(finding: Pick<Finding, 'scanner' | 'rule_id' | 'message' | 'metadata_json'>) {
  const metadata = findingEvidenceMetadata(finding);
  const tags = (metadata.tags as string[] | undefined)?.map((tag) => tag.toLowerCase()) || [];
  const structured = trivyMessagePresentation(finding.scanner, finding.message);
  let kind: FindingEvidenceKind = 'unknown';
  if (['gitleaks', 'trufflehog', 'secrets-lite'].includes(finding.scanner)) kind = 'secret';
  else if (['opengrep', 'bearer', 'sast-lite'].includes(finding.scanner)) kind = 'code';
  else if (['checkov', 'iac-lite'].includes(finding.scanner)) kind = 'configuration';
  else if (finding.scanner === 'grype') kind = 'dependency';
  else if (finding.scanner === 'trivy') {
    // Trivy emits several result kinds. Its scanner identity alone is insufficient.
    if (/^(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)$/iu.test(finding.rule_id)) kind = 'dependency';
    else if (tags.includes('secret')) kind = 'secret';
    else if (tags.includes('misconfiguration')) kind = 'configuration';
    else if (tags.includes('license')) kind = 'license';
    else if (structured) kind = structured.kind;
  }
  const label = kindLabels[kind];
  const ruleName = typeof metadata.rule_name === 'string' ? metadata.rule_name.trim() : '';
  const namedRule = ruleName !== finding.rule_id && /\s/u.test(ruleName) ? ruleName : '';
  const message = finding.message.trim();
  const structuredTrivy = finding.scanner === 'trivy' && /^(Artifact|Package):/u.test(message);
  const firstSentence = structuredTrivy ? structured?.title : message.split(/(?<=[.!?])\s/u)[0];
  const title = namedRule || (firstSentence && firstSentence.length <= 180 ? firstSentence : label);
  return { kind, label, title, verifiedSecret: kind === 'secret' && metadata.verified === true };
}

export type OffenderColumnSegment = { lineIndex: number; prefix: string; text: string };

/** Coordinates admitted by source_io are one-based UTF-16, end-exclusive. */
export function offenderColumnSegments(input: {
  lines: string[]; firstLine: number; startLine?: number; endLine?: number;
  startColumn?: number; endColumn?: number; columnOrigin?: number;
}): OffenderColumnSegment[] {
  const { lines, firstLine, startLine, endLine = startLine, startColumn, endColumn, columnOrigin = 1 } = input;
  const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
  if (![firstLine, startLine, endLine, startColumn, endColumn, columnOrigin].every(positive)
    || endLine! < startLine! || endLine === startLine && endColumn! < startColumn!) return [];
  const result: OffenderColumnSegment[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const sourceLine = firstLine + index;
    if (sourceLine < startLine! || sourceLine > endLine!) continue;
    const line = lines[index];
    const origin = index === 0 ? columnOrigin : 1;
    const from = Math.max(0, sourceLine === startLine ? startColumn! - origin : 0);
    const to = Math.min(line.length, sourceLine === endLine ? endColumn! - origin : line.length);
    if (from >= to || from >= line.length || to <= 0) continue;
    // Never paint half a surrogate pair when hostile or inconsistent coordinates arrive.
    const splitsPair = (offset: number) => offset > 0 && offset < line.length
      && /[\uD800-\uDBFF]/u.test(line[offset - 1]) && /[\uDC00-\uDFFF]/u.test(line[offset]);
    if (splitsPair(from) || splitsPair(to)) continue;
    result.push({ lineIndex: index, prefix: line.slice(0, from), text: line.slice(from, to) });
  }
  return result;
}

export function findingLocation(finding: Finding) {
  if (!finding.start_line) return finding.file_path;
  const start = `${finding.start_line}${finding.start_column ? `:${finding.start_column}` : ''}`;
  const hasDistinctEnd = Boolean(
    finding.end_line
    && (finding.end_line !== finding.start_line || finding.end_column !== finding.start_column),
  );
  if (!hasDistinctEnd) return `${finding.file_path}:${start}`;
  const end = `${finding.end_line}${finding.end_column ? `:${finding.end_column}` : ''}`;
  return `${finding.file_path}:${start}-${end}`;
}
