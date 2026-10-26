import type { Finding } from './api';

export type FindingReportView = {
  projectId: number;
  scanId: number;
  findingsRevision: number;
  items: readonly Finding[];
};

function sourceRange(finding: Finding): string | undefined {
  const { start_line: start, end_line: end, start_column: left, end_column: right } = finding;
  if (typeof finding.file_path !== 'string' || !finding.file_path.trim()
    || !Number.isSafeInteger(start) || start! < 1
    || !Number.isSafeInteger(end) || end! < start!) return undefined;
  const hasLeft = left != null;
  const hasRight = right != null;
  if (hasLeft !== hasRight) return undefined;
  if (hasLeft && (!Number.isSafeInteger(left) || left! < 1
    || !Number.isSafeInteger(right) || right! < 1
    || start === end && right! < left!)) return undefined;
  // These are reported coordinates, never an inferred range or case-folded path.
  return JSON.stringify([finding.file_path, start, left ?? null, end, right ?? null]);
}

/** Related location reports in one loaded page; this does not establish duplicate issues. */
export function otherReportsAtLocation(
  view: FindingReportView,
  selected: Finding,
  selectedProjectId: number,
): readonly Finding[] {
  if (selectedProjectId !== view.projectId || selected.scan_id !== view.scanId
    || !Number.isSafeInteger(view.findingsRevision) || view.findingsRevision < 1
    || selected.findings_revision != null && selected.findings_revision !== view.findingsRevision
    || view.items.some((item) => item.scan_id !== view.scanId
      || item.findings_revision != null && item.findings_revision !== view.findingsRevision)) return [];
  const member = view.items.find((item) => item.id === selected.id);
  if (!member || member.revision !== selected.revision
    || member.fingerprint !== selected.fingerprint || member.scanner !== selected.scanner
    || member.rule_id !== selected.rule_id || member.display_id !== selected.display_id) return [];
  const range = sourceRange(selected);
  if (range === undefined || sourceRange(member) !== range) return [];
  return view.items.filter((item) => item.id !== selected.id && sourceRange(item) === range);
}
