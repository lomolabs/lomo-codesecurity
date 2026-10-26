import type { Scan } from './api.ts';


export type ScanCoverageTarget = Readonly<{
  kind: 'workspace' | 'directory' | 'file' | 'unavailable';
  label: string;
  path: string | null;
}>;


const UNSAFE_TARGET_TEXT = /[\p{Cc}\p{Cf}\p{Cs}]/u;


function safeTargetPath(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const path = value.trim();
  if (!path || path.length > 500 || UNSAFE_TARGET_TEXT.test(path)) return null;
  return path;
}


export function scanCoverageTarget(scan: Pick<Scan, 'scanner_summary'> | null | undefined): ScanCoverageTarget {
  const scope = scan?.scanner_summary?.scope;
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    return { kind: 'unavailable', label: 'Coverage target unavailable', path: null };
  }
  const kind = 'kind' in scope ? scope.kind : undefined;
  if (kind === 'workspace') {
    return { kind, label: 'Entire registered codebase', path: null };
  }
  const path = safeTargetPath('target_path' in scope ? scope.target_path : undefined);
  if (kind === 'directory' && path) return { kind, label: `Folder · ${path}`, path };
  if (kind === 'file' && path) return { kind, label: `File · ${path}`, path };
  return { kind: 'unavailable', label: 'Coverage target unavailable', path: null };
}


/** Render known, path-free coverage reasons; never echo arbitrary diagnostic keys. */
export function sourceCoverageFailures(scan: Pick<Scan, 'scanner_summary'>): string[] {
  const raw = scan.scanner_summary?.source_coverage;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [];
  const coverage = raw as Record<string, unknown>;
  if (coverage.complete !== false) return [];
  const counts = coverage.reason_counts;
  if (!counts || typeof counts !== 'object' || Array.isArray(counts)) {
    return ['Source coverage is incomplete; its detailed reason is unavailable.'];
  }
  const limit = coverage.max_file_bytes;
  const limitLabel = typeof limit === 'number' && Number.isSafeInteger(limit) && limit > 0
    ? limit % 1_048_576 === 0 ? `${limit / 1_048_576} MiB` : `${limit.toLocaleString('en-US')} bytes`
    : null;
  const reasons: Readonly<Record<string, (count: number) => string>> = {
    eligible_file_too_large: (n) => `${n} code ${n === 1 ? 'file exceeds' : 'files exceed'} ${limitLabel ? `the ${limitLabel}` : 'the recorded'} per-file analysis limit.`,
    eligible_file_limit_exceeded: (n) => `${n} eligible ${n === 1 ? 'file is' : 'files are'} outside the analysis file-count limit.`,
    eligible_file_binary: (n) => `${n} eligible ${n === 1 ? 'file contains' : 'files contain'} binary data that could not be analyzed as code.`,
    eligible_file_invalid_utf8: (n) => `${n} eligible ${n === 1 ? 'file is' : 'files are'} not valid UTF-8 text.`,
    eligible_file_unreadable: (n) => `${n} eligible ${n === 1 ? 'file could' : 'files could'} not be read.`,
    eligible_file_unsupported_type: (n) => `${n} eligible ${n === 1 ? 'entry has' : 'entries have'} an unsupported filesystem type.`,
    eligible_file_capture_total_bytes_exceeded: (n) => `${n} eligible ${n === 1 ? 'file exceeds' : 'files exceed'} the total source capture limit.`,
  };
  const result = Object.entries(reasons).flatMap(([reason, describe]) => {
    const count = (counts as Record<string, unknown>)[reason];
    return typeof count === 'number' && Number.isSafeInteger(count) && count > 0 ? [describe(count)] : [];
  });
  return result.length ? result : ['Source coverage is incomplete; its detailed reason is unavailable.'];
}
