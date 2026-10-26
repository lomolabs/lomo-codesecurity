import { setTimeout as delay } from 'node:timers/promises';
import { CodeSecurityRequestError } from './client';

/** Retry only a transient read of retained Windows authority during startup.
 * Each attempt still verifies fresh permissions. No enrollment or write belongs
 * in this operation, and its original authority signal owns both attempts. */
export async function restoreStartupStorage<T>(
  read: () => Promise<T>,
  signal: AbortSignal,
  isCurrent: () => boolean,
  platform: NodeJS.Platform = process.platform,
): Promise<T> {
  try {
    return await read();
  } catch (error) {
    if (platform !== 'win32' || signal.aborted || !isCurrent()
      || !(error instanceof CodeSecurityRequestError)
      || error.code !== 'profile_credential_store_unavailable') throw error;
    // Busy Windows startup can outlast one owned metadata helper. Wait before
    // a single fresh read; insecure/corrupt/unconfirmed authority never retries.
    await delay(1_000, undefined, { signal });
    signal.throwIfAborted();
    if (!isCurrent()) throw new DOMException('Startup repository context changed.', 'AbortError');
    return read();
  }
}
