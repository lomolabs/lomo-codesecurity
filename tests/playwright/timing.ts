const rawQualificationTimingFactor = process.env.KODESEC_PLAYWRIGHT_TIMING_FACTOR ?? '1';

const currentPolicy = process.env.KODESEC_PLAYWRIGHT_TIMING_POLICY === 'D-020';
const laneFactors: Record<string, string> = { mac: '1', linux: '2.6', windows: '3.9' };
const laneFactor = laneFactors[process.env.KODESEC_PLAYWRIGHT_PERFORMANCE_PLATFORM || ''];
if (currentPolicy ? rawQualificationTimingFactor !== laneFactor
  : process.env.KODESEC_PLAYWRIGHT_TIMING_POLICY !== undefined || !['1', '2'].includes(rawQualificationTimingFactor)) {
  throw new Error('KODESEC_PLAYWRIGHT_TIMING_FACTOR must be exactly 1 or2 historically, or match the explicit D020 lane1/2.6/3.9.');
}

export const qualificationTimingFactor = Number(rawQualificationTimingFactor);
export const qualificationPerformanceBudgetMode = qualificationTimingFactor === 1
  ? 'blocking'
  : 'advisory';
export const qualificationPerformanceBudgetsAreBlocking =
  qualificationPerformanceBudgetMode === 'blocking';

export function qualificationMilliseconds(nativeLinuxMilliseconds: number): number {
  if (!Number.isSafeInteger(nativeLinuxMilliseconds) || nativeLinuxMilliseconds <= 0) {
    throw new Error('Qualification timing inputs must be positive safe integer milliseconds.');
  }
  const scaled = Math.ceil(nativeLinuxMilliseconds * qualificationTimingFactor);
  if (!Number.isSafeInteger(scaled)) throw new Error('Scaled qualification timing exceeds the safe integer range.');
  return scaled;
}
