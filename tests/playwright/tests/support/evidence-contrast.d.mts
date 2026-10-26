export function inspectEvidenceContrast(pre: Element, options?: {
  columnHighlight?: 'required' | 'absent';
} | void): {
  samples: Array<{ name: string; foreground: number[]; background: number[]; ratio: number; minimum: number; passed: boolean }>;
  palette_entries: number;
  column_highlight: 'required' | 'absent';
  background: number[];
  rowColor: number[];
  columnColor: number[] | null;
  minimum_ratio: number;
  passed: boolean;
};
