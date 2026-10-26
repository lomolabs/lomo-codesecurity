export function inspectControlLayout(): {
  clippedOverlapEvidence: Array<Record<string, unknown>>;
  crushedText: Array<{ name: string; width: number; height: number }>;
  deferredControls: Array<{ name: string }>;
  documentOverflow: number;
  offscreenControls: Array<{ name: string; left: number; right: number }>;
  overlaps: Array<{ left: string; right: string }>;
  selfClippedControls: Array<{
    name: string; clientHeight: number; clientWidth: number; scrollHeight: number; scrollWidth: number;
  }>;
};

export function inspectRenderedControls(view: string): {
  width: number;
  height: number;
  route: string | null;
  execution_evidence: false;
  controls: Array<{ tag: string; name: string; type: string | null; disabled: boolean; readonly: boolean }>;
};
