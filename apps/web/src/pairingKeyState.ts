export function pairingKeyIsExpired(expiresAt: string, now = Date.now()): boolean {
  const expiry = Date.parse(expiresAt);
  return !Number.isFinite(expiry) || expiry <= now;
}

export function pairingKeyExpiryDelay(expiresAt: string, now = Date.now()): number {
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry)) return 0;
  return Math.max(0, Math.min(expiry - now, 2_147_483_647));
}

export function ideEnrollmentPresentation(
  enrollment: Readonly<{ activation_expires_at: string }>,
  now = Date.now(),
): Readonly<{
  expired: boolean;
  label: 'Approval required' | 'Expired';
  tone: 'pending' | 'unavailable';
  decisionDisabledReason: string | null;
}> {
  const expired = pairingKeyIsExpired(enrollment.activation_expires_at, now);
  return expired
    ? {
      expired: true,
      label: 'Expired',
      tone: 'unavailable',
      decisionDisabledReason: 'This request expired. CodeSecurity is refreshing the authoritative pending list.',
    }
    : {
      expired: false,
      label: 'Approval required',
      tone: 'pending',
      decisionDisabledReason: null,
    };
}
