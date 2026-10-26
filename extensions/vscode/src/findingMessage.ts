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
