import type { AdvisorDisclosurePacket } from './api.ts';


export type AdvisorDisclosurePacketField = Readonly<{
  key: string;
  label: string;
  value: string;
  multiline: boolean;
}>;

export type RemoteAdvisorSubmissionOwnership = {
  current: boolean;
};

export function claimRemoteAdvisorSubmission(
  ownership: RemoteAdvisorSubmissionOwnership,
): boolean {
  if (ownership.current) return false;
  ownership.current = true;
  return true;
}

export function releaseRemoteAdvisorSubmission(
  ownership: RemoteAdvisorSubmissionOwnership,
): void {
  ownership.current = false;
}

function scalar(value: string | number | null): string {
  return value === null ? 'null' : String(value);
}

export function normalizeAdvisorDisclosureMultiline(value: string): string {
  return value.replace(/\r\n?/gu, '\n');
}

export function advisorDisclosurePacketFields(
  packet: AdvisorDisclosurePacket,
): readonly AdvisorDisclosurePacketField[] {
  const fields = [
    ['schema_version', 'Packet schema', scalar(packet.schema_version), false],
    ['finding.id', 'Finding database ID', scalar(packet.finding.id), false],
    ['finding.display_id', 'Finding display ID', packet.finding.display_id, false],
    ['finding.scanner', 'Scanner', packet.finding.scanner, false],
    ['finding.rule_id', 'Rule', packet.finding.rule_id, false],
    ['finding.severity', 'Severity', packet.finding.severity, false],
    ['finding.message', 'Finding message', packet.finding.message, true],
    ['finding.fingerprint', 'Finding fingerprint', packet.finding.fingerprint, false],
    ['location.file_path', 'Project-relative file', packet.location.file_path, false],
    ['location.start_line', 'Start line', scalar(packet.location.start_line), false],
    ['location.start_column', 'Start column', scalar(packet.location.start_column), false],
    ['location.end_line', 'End line', scalar(packet.location.end_line), false],
    ['location.end_column', 'End column', scalar(packet.location.end_column), false],
    ['repo_context.project', 'Project identity', packet.repo_context.project, false],
    ['repo_context.repo_path', 'Authorized repository path', packet.repo_context.repo_path, false],
    ['repo_context.remote_url', 'Redacted remote URL', scalar(packet.repo_context.remote_url), false],
    ['repo_context.scan_id', 'Scan ID', scalar(packet.repo_context.scan_id), false],
    ['repo_context.mode', 'Scan mode', packet.repo_context.mode, false],
    ['repo_context.base_ref', 'Base revision', scalar(packet.repo_context.base_ref), false],
    ['repo_context.head_ref', 'Head revision', scalar(packet.repo_context.head_ref), false],
    ['scanner_evidence.code_snippet', 'Redacted code snippet', packet.scanner_evidence.code_snippet ?? 'null', true],
    ['scanner_evidence.metadata', 'Bounded scanner metadata', JSON.stringify(packet.scanner_evidence.metadata, null, 2), true],
  ] as const;
  return fields.map(([key, label, value, multiline]) => ({
    key,
    label,
    value: normalizeAdvisorDisclosureMultiline(value),
    multiline,
  }));
}
