/** Read the actual snippet palette, including highlights painted over text.
 * WCAG 2.2 relative luminance, without rounding the acceptance threshold.
 * Evaluate on one rendered evidence <pre>; never changes its presentation. */
export function inspectEvidenceContrast(pre, { columnHighlight = 'required' } = {}) {
  const require = (value, message) => { if (!value) throw Error(`Evidence contrast: ${message}`); };
  require(['required', 'absent'].includes(columnHighlight), 'explicit column highlight mode required');
  const color = value => {
    const match = value.match(/^rgba?\((\d+(?:\.\d+)?),\s*(\d+(?:\.\d+)?),\s*(\d+(?:\.\d+)?)(?:,\s*([\d.]+))?\)$/);
    require(match, `unsupported computed color ${value}`);
    return [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4] ?? 1)];
  };
  const over = (front, back) => front.slice(0, 3).map((value, i) => value * front[3] + back[i] * (1 - front[3]));
  const luminance = rgb => rgb.slice(0, 3).map(value => value / 255)
    .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, i) => sum + value * [0.2126, 0.7152, 0.0722][i], 0);
  const contrast = (front, back) => {
    const values = [luminance(front), luminance(back)].sort((a, b) => a - b);
    return (values[1] + 0.05) / (values[0] + 0.05);
  };
  const source = pre.querySelector('.code-source'), row = pre.querySelector('.code-row.offender');
  const columns = pre.querySelector('.code-column-ranges'), mark = columns?.querySelector('mark');
  const gutter = pre.querySelector('.code-line-numbers');
  require(source && row && gutter, 'source, gutter and offender line required');
  require(columnHighlight === 'required' ? columns && mark : !columns,
    columnHighlight === 'required' ? 'both highlight layers required' : 'unexpected column highlight');
  for (let item = source; item; item = item.parentElement) {
    const style = getComputedStyle(item);
    require(style.opacity === '1' && style.filter === 'none' && style.mixBlendMode === 'normal', 'unsupported ancestor compositing');
  }
  const background = color(getComputedStyle(pre).backgroundColor);
  require(background[3] === 1, 'opaque snippet background required');
  for (const item of [pre, source, row, columns, mark, gutter].filter(Boolean)) {
    require(getComputedStyle(item).backgroundImage === 'none', 'background image needs separate review');
  }
  require(Number(getComputedStyle(source).zIndex) < Number(getComputedStyle(row).zIndex), 'paint order changed');
  if (columns) {
    require(Number(getComputedStyle(row).zIndex) < Number(getComputedStyle(columns).zIndex), 'paint order changed');
    require(color(getComputedStyle(mark).color)[3] === 0 && columns.getAttribute('aria-hidden') === 'true',
      'column text must be decorative and transparent');
  }
  const rowColor = color(getComputedStyle(row).backgroundColor);
  const columnColor = mark ? color(getComputedStyle(mark).backgroundColor) : null;
  const samples = [], palette = new Map();
  for (const element of [source, ...source.querySelectorAll('[class]')]) {
    if (!element.textContent.trim()) continue;
    const style = getComputedStyle(element);
    require(style.opacity === '1', 'token opacity needs separate review');
    palette.set(`${element.className}:${style.color}`, { name: element.className, color: color(style.color) });
  }
  const sample = (name, foreground, base, overlays) => {
    let front = over(foreground, base), back = base.slice(0, 3);
    for (const overlay of overlays) { front = over(overlay, front); back = over(overlay, back); }
    const ratio = contrast(front, back);
    samples.push({ name, foreground: front, background: back, ratio, minimum: 4.5, passed: ratio >= 4.5 });
  };
  for (const entry of palette.values()) {
    sample(`${entry.name}:plain`, entry.color, background, []);
    sample(`${entry.name}:offender-row`, entry.color, background, [rowColor]);
    if (columnColor) sample(`${entry.name}:offender-columns`, entry.color, background, [rowColor, columnColor]);
  }
  const gutterStyle = getComputedStyle(gutter), gutterBackground = over(color(gutterStyle.backgroundColor), background);
  sample('line-numbers:plain', color(gutterStyle.color), gutterBackground, []);
  sample('line-numbers:offender-row', color(gutterStyle.color), gutterBackground, [rowColor]);
  // These labels are children of the overlay: their text paints above its
  // background, unlike the regular line numbers underneath it.
  for (const selector of ['.code-line-number', '.code-marker']) {
    const label = row.querySelector(selector);
    require(label && getComputedStyle(label).opacity === '1', 'offender label required');
    sample(selector.slice(1), color(getComputedStyle(label).color), over(rowColor, gutterBackground), []);
  }
  return { samples, palette_entries: palette.size, column_highlight: columnHighlight, background, rowColor, columnColor,
    minimum_ratio: Math.min(...samples.map(item => item.ratio)), passed: samples.every(item => item.passed) };
}
