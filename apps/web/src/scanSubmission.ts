export type ScanSubmissionOwnership = { current: boolean };

export async function submitScanOnce<T>(
  ownership: ScanSubmissionOwnership,
  submit: () => Promise<T>,
): Promise<T | undefined> {
  if (ownership.current) return undefined;
  ownership.current = true;
  try {
    return await submit();
  } finally {
    ownership.current = false;
  }
}
