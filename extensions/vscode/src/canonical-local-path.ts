/** Compare an already-resolved path with its filesystem canonical path.
 * VS Code file URIs can lowercase a Windows drive letter. No other spelling
 * difference is accepted: directory case, links and path aliases still fail. */
export function sameCanonicalLocalPath(actual: string, requested: string,
  platform: NodeJS.Platform = process.platform): boolean {
  if (actual === requested) return true;
  return platform === 'win32' && /^[A-Za-z]:\\/u.test(actual) && /^[A-Za-z]:\\/u.test(requested)
    && actual[0].toUpperCase() === requested[0].toUpperCase() && actual.slice(1) === requested.slice(1);
}
