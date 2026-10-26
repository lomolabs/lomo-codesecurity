/** Resolve the severity dot's axe ambiguity without changing the painted UI.
 * Refuse unsupported compositing or a dot over text instead of guessing. */
export function inspectSeverityContrast(box) {
  const require = (value, reason) => { if (!value) throw Error(`Severity contrast: ${reason}`); };
  const color = value => {
    const match = value.match(/^rgba?\((\d+(?:\.\d+)?),\s*(\d+(?:\.\d+)?),\s*(\d+(?:\.\d+)?)(?:,\s*([\d.]+))?\)$/);
    require(match, 'unsupported computed color');
    return [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4] ?? 1)];
  };
  const over = (front, back) => [...front.slice(0, 3).map((v, i) => v * front[3] + back[i] * (1 - front[3])), 1];
  const luminance = rgb => rgb.slice(0, 3).map(v => v / 255)
    .map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
  const ratio = (front, back) => {
    const values = [luminance(front), luminance(back)].sort((a, b) => a - b);
    return (values[1] + 0.05) / (values[0] + 0.05);
  };
  const ancestors = [];
  let opaque = false;
  for (let element = box; element; element = element.parentElement) {
    const style = getComputedStyle(element);
    require(style.opacity === '1' && style.filter === 'none' && style.mixBlendMode === 'normal'
      && style.backgroundImage === 'none' && style.transform === 'none', 'unsupported ancestor compositing');
    if (!opaque) {
      ancestors.push(color(style.backgroundColor));
      opaque = ancestors.at(-1)[3] === 1;
    }
  }
  require(ancestors.at(-1)?.[3] === 1, 'opaque background required');
  const background = ancestors.reverse().reduce((back, front) => over(front, back));
  const style = getComputedStyle(box), pseudo = getComputedStyle(box, '::before');
  require(pseudo.opacity === '1' && pseudo.filter === 'none' && pseudo.mixBlendMode === 'normal'
    && pseudo.backgroundImage === 'none' && pseudo.transform === 'none', 'unsupported dot compositing');
  const bounds = box.getBoundingClientRect();
  const dot = pseudo.display === 'none' || pseudo.content === 'none' ? null : {
    x: bounds.x + parseFloat(style.borderLeftWidth) + parseFloat(pseudo.left),
    y: bounds.y + parseFloat(style.borderTopWidth) + parseFloat(pseudo.top),
    width: parseFloat(pseudo.width), height: parseFloat(pseudo.height),
  };
  require(!dot || Object.values(dot).every(Number.isFinite), 'unresolved dot geometry');
  const samples = [...box.querySelectorAll('span, strong')].map(element => {
    const textStyle = getComputedStyle(element);
    require(textStyle.opacity === '1' && textStyle.backgroundImage === 'none'
      && textStyle.filter === 'none' && textStyle.mixBlendMode === 'normal' && textStyle.transform === 'none'
      && color(textStyle.backgroundColor)[3] === 0, 'unsupported text compositing');
    require(element.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true }),
      'visible severity text required');
    const range = document.createRange(); range.selectNodeContents(element);
    const rects = [...range.getClientRects()].map(r => ({ x: r.x, y: r.y, width: r.width, height: r.height }));
    require(rects.length > 0 && rects.every(r => r.width > 0 && r.height > 0
      && r.x >= 0 && r.y >= 0 && r.x + r.width <= innerWidth && r.y + r.height <= innerHeight)
      && element.textContent.trim(), 'painted severity text required');
    const dotOverlaps = dot && rects.some(r => r.x < dot.x + dot.width && r.x + r.width > dot.x
      && r.y < dot.y + dot.height && r.y + r.height > dot.y);
    require(!dotOverlaps, 'severity dot overlaps text');
    const contrast = ratio(over(color(textStyle.color), background), background);
    return { text: element.textContent.trim(), rects, contrast, minimum: 4.5, passed: contrast >= 4.5 };
  });
  require(samples.length === 2, 'one severity label and count required');
  const dotContrast = dot ? ratio(over(color(pseudo.backgroundColor), background), background) : null;
  return { background, dot, dot_contrast: dotContrast, samples,
    passed: samples.every(s => s.passed) && (dotContrast === null || dotContrast >= 3) };
}
