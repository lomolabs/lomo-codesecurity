const MAX_TIMER_DELAY_MILLISECONDS = 2_147_483_647;


export function browserSessionRenewalDelayMilliseconds(expiresInSeconds: number): number {
  if (!Number.isSafeInteger(expiresInSeconds) || expiresInSeconds <= 0) {
    throw new Error('CodeSecurity returned an invalid browser-session lifetime.');
  }
  return Math.min(
    Math.max(250, Math.floor(expiresInSeconds * 500)),
    MAX_TIMER_DELAY_MILLISECONDS,
  );
}


export function sessionFailureRequiresPairing(status: number | undefined): boolean {
  return status === 401;
}
