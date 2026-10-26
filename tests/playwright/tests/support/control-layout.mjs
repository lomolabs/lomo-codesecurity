/** Shared DOM geometry witness for synthetic and real retained-backend journeys.
 * Read-only; evaluate inside the current visible document. */
export function inspectControlLayout() {
    const visible = (element) => {
        if (element.closest('details:not([open])') && !element.matches('summary'))
            return false;
        // content-visibility:auto retains stale child geometry while skipped.
        // Report those controls separately; callers must scroll their rows into
        // view before claiming coverage of their painted layout.
        if (!element.checkVisibility({ contentVisibilityAuto: true }))
            return false;
        const style = getComputedStyle(element);
        const rectangle = element.getBoundingClientRect();
        return style.display !== 'none'
            && style.visibility !== 'hidden'
            && Number(style.opacity) > 0
            && rectangle.width > 0
            && rectangle.height > 0;
    };
    const withinHorizontalScroller = (element) => {
        let ancestor = element.parentElement;
        while (ancestor) {
            const style = getComputedStyle(ancestor);
            if ((style.overflowX === 'auto' || style.overflowX === 'scroll') && ancestor.scrollWidth > ancestor.clientWidth)
                return true;
            ancestor = ancestor.parentElement;
        }
        return false;
    };
    const intersect = (left, right) => ({
        left: Math.max(left.left, right.left), right: Math.min(left.right, right.right),
        top: Math.max(left.top, right.top), bottom: Math.min(left.bottom, right.bottom),
    });
    const paintedBounds = (element, rectangle) => {
        const bounds = { left: rectangle.left, right: rectangle.right, top: rectangle.top, bottom: rectangle.bottom };
        for (let ancestor = element.parentElement; ancestor; ancestor = ancestor.parentElement) {
            const style = getComputedStyle(ancestor);
            const clipsX = ['auto', 'scroll', 'hidden', 'clip'].includes(style.overflowX);
            const clipsY = ['auto', 'scroll', 'hidden', 'clip'].includes(style.overflowY);
            if (!clipsX && !clipsY)
                continue;
            const owner = ancestor.getBoundingClientRect();
            const left = owner.left + ancestor.clientLeft;
            const top = owner.top + ancestor.clientTop;
            if (clipsX) {
                bounds.left = Math.max(bounds.left, left);
                bounds.right = Math.min(bounds.right, left + ancestor.clientWidth);
            }
            if (clipsY) {
                bounds.top = Math.max(bounds.top, top);
                bounds.bottom = Math.min(bounds.bottom, top + ancestor.clientHeight);
            }
        }
        return bounds;
    };
    const labelText = (element) => {
        if (!element || element.matches('input, select, textarea')) return '';
        const copy = element.cloneNode(true);
        for (const field of copy.querySelectorAll('input, select, textarea')) field.remove();
        return copy.textContent || '';
    };
    const controlName = (element) => (element.getAttribute('aria-label')
        || [...(element.labels || [])].map(labelText).join(' ')
        || labelText(element)
        || element.tagName).trim().replace(/\s+/g, ' ').slice(0, 80);
    const clippedOverlapEvidence = [];
    const candidates = Array.from(document.querySelectorAll('main button, main input, main select, main textarea, main a[href], main summary'));
    const deferredControls = candidates
        .filter(element => element.checkVisibility() && !element.checkVisibility({ contentVisibilityAuto: true }))
        .map(element => ({ name: controlName(element) }));
    const controls = candidates
        .filter(visible)
        .map((element) => {
        const rectangle = element.getBoundingClientRect();
        return { element, rectangle, painted: paintedBounds(element, rectangle) };
    });
    const selfClippedControls = controls.flatMap(({ element }) => {
        if (!element.matches('button, a[href], summary'))
            return [];
        const text = element.textContent?.trim().replace(/\s+/g, ' ') || '';
        if (!text)
            return [];
        const style = getComputedStyle(element);
        const scrollableX = style.overflowX === 'auto' || style.overflowX === 'scroll';
        const scrollableY = style.overflowY === 'auto' || style.overflowY === 'scroll';
        const clippedX = !scrollableX && element.scrollWidth > element.clientWidth + 1;
        const clippedY = !scrollableY && element.scrollHeight > element.clientHeight + 1;
        return clippedX || clippedY ? [{
                name: element.getAttribute('aria-label') || text.slice(0, 100),
                clientHeight: element.clientHeight,
                clientWidth: element.clientWidth,
                scrollHeight: element.scrollHeight,
                scrollWidth: element.scrollWidth,
            }] : [];
    });
    const offscreenControls = controls
        .filter(({ element, rectangle }) => !withinHorizontalScroller(element) && (rectangle.left < -0.5 || rectangle.right > window.innerWidth + 0.5))
        .map(({ element, rectangle }) => ({
        name: controlName(element),
        left: rectangle.left,
        right: rectangle.right,
    }));
    const overlaps = controls.flatMap((left, index) => controls.slice(index + 1).flatMap((right) => {
        if (left.element.contains(right.element) || right.element.contains(left.element))
            return [];
        const raw = intersect(left.rectangle, right.rectangle);
        if (raw.right - raw.left <= 1 || raw.bottom - raw.top <= 1)
            return [];
        const painted = intersect(left.painted, right.painted);
        if (painted.right - painted.left <= 1 || painted.bottom - painted.top <= 1) {
            // Retain the excluded raw overlap and independently check an actual
            // hit target when its intersection is currently in the viewport.
            const probe = intersect(raw, { left: 0, top: 0, right: innerWidth, bottom: innerHeight });
            const point = probe.right > probe.left && probe.bottom > probe.top
                ? { x: (probe.left + probe.right) / 2, y: (probe.top + probe.bottom) / 2 } : null;
            const containsPoint = (bounds) => point !== null
                && point.x >= bounds.left && point.x < bounds.right && point.y >= bounds.top && point.y < bounds.bottom;
            const expected = containsPoint(left.painted) ? left.element : containsPoint(right.painted) ? right.element : null;
            const hit = point ? document.elementFromPoint(point.x, point.y) : null;
            clippedOverlapEvidence.push({
                left: controlName(left.element), right: controlName(right.element), raw,
                leftPainted: left.painted, rightPainted: right.painted, point,
                expectedTarget: expected ? controlName(expected) : null,
                hitTarget: hit ? controlName(hit) : null,
                hitMatchesExpected: expected ? hit !== null && expected.contains(hit) : null,
            });
            return [];
        }
        return [{
                left: controlName(left.element),
                right: controlName(right.element),
            }];
    }));
    const crushedText = Array.from(document.querySelectorAll('main h1, main h2, main h3, main button, .finding-detail-head > :first-child, .project-row strong, .job-title-line strong'))
        .filter(visible)
        .flatMap((element) => {
        const rectangle = element.getBoundingClientRect();
        const text = element.textContent?.trim().replace(/\s+/g, ' ') || '';
        if (text.length < 3 || rectangle.width >= 28 || rectangle.height <= 48)
            return [];
        return [{ name: text.slice(0, 100), width: rectangle.width, height: rectangle.height }];
    });
    return {
        clippedOverlapEvidence,
        crushedText,
        deferredControls,
        documentOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        offscreenControls,
        overlaps,
        selfClippedControls,
    };
}

/** Rendered native controls only: labels and state, never field values. This
 * inventory does not establish action/effect or accessibility acceptance. */
export function inspectRenderedControls(view) {
    if (!['overview', 'projects', 'jobs', 'scans', 'findings', 'tools', 'settings'].includes(view))
        throw new Error('Unknown control inventory route.');
    const surface = document.querySelector(`section[data-route-surface="${view}"]`);
    if (!surface) throw new Error('Control inventory route is not mounted.');
    const labelText = (element) => {
        if (!element || element.matches('input, select, textarea')) return '';
        const copy = element.cloneNode(true);
        for (const field of copy.querySelectorAll('input, select, textarea')) field.remove();
        return copy.textContent || '';
    };
    const controls = [...surface.querySelectorAll('button, input, select, textarea, summary, a[href]')]
        .filter(element => element.checkVisibility({ contentVisibilityAuto: true, opacityProperty: true, visibilityProperty: true }))
        .map(element => {
            const field = element.matches('input, select, textarea');
            const referencedLabel = (element.getAttribute('aria-labelledby') || '').split(/\s+/u)
                .map(id => labelText(document.getElementById(id))).join(' ').trim();
            const name = referencedLabel || element.getAttribute('aria-label')
                || [...(element.labels || [])].map(labelText).join(' ')
                || labelText(element) || element.getAttribute('title') || element.getAttribute('name') || '';
            return {
                tag: element.tagName, name: name.trim().replace(/\s+/gu, ' ').slice(0, 160),
                type: element.matches('input') ? element.type : null,
                disabled: element.matches(':disabled') || element.getAttribute('aria-disabled') === 'true',
                readonly: field && element.readOnly === true,
            };
        });
    if (controls.length > 300) throw new Error('Rendered control inventory exceeds bounded review.');
    return { width: innerWidth, height: innerHeight, route: new URL(location.href).searchParams.get('view'),
        execution_evidence: false, controls };
}
