export type TextEntryNormalization =
  | Readonly<{ ok: true; value: string }>
  | Readonly<{ ok: false; reason: 'required' | 'too-long' }>;

export function normalizeTextEntryValue(
  value: string,
  maxLength: number,
  required = true,
): TextEntryNormalization {
  const normalized = value.trim();
  if (required && !normalized) return { ok: false, reason: 'required' };
  if (normalized.length > maxLength) return { ok: false, reason: 'too-long' };
  return { ok: true, value: normalized };
}
