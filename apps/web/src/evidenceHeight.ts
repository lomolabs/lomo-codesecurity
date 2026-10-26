export const evidenceHeightControl = Object.freeze({
  initial: 220,
  max: 900,
  min: 180,
  step: 40,
});

export function isEvidenceHeightStepAligned(value: number): boolean {
  return Number.isSafeInteger(value)
    && value >= evidenceHeightControl.min
    && value <= evidenceHeightControl.max
    && (value - evidenceHeightControl.min) % evidenceHeightControl.step === 0;
}
