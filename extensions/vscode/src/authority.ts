export const MAX_IDE_AUTHORITY_GENERATION = 2_147_483_647;

/** Return the one canonical local control-plane origin, or undefined. */
export function canonicalLoopbackOrigin(value: string): string | undefined {
  const match = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\]):([0-9]+)\/?$/iu.exec(value.trim());
  const port = match ? Number(match[2]) : Number.NaN;
  if (!match || !Number.isSafeInteger(port) || port < 1 || port > 65_535) return undefined;
  return `http://${match[1].toLowerCase()}:${port}`;
}
