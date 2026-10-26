/** Reveal one explicit navigation; ordinary refreshes do not call this helper. */
export function revealFindingNavigation(
  item: HTMLElement,
  findingId: number,
  isCurrent: () => boolean,
  onFocused: () => void,
) {
  const workspace = item.closest<HTMLElement>('.finding-workspace');
  const detail = workspace?.querySelector<HTMLElement>('.finding-detail');
  if (!workspace || !detail) return;
  let visibilityObserver: IntersectionObserver | undefined;
  let focusFrame: number | undefined;
  let paintedFrame: number | undefined;
  let revealing = false;
  const ready = () => isCurrent() && detail.isConnected
    && detail.dataset.findingId === String(findingId)
    && detail.getAttribute('aria-busy') !== 'true'
    && !detail.closest('[inert], [aria-hidden="true"]');

  const reveal = () => {
    if (revealing || !ready()) return;
    revealing = true;
    const heading = detail.querySelector<HTMLHeadingElement>('.finding-detail-identity h2');
    const itemRect = item.getBoundingClientRect();
    const detailRect = detail.getBoundingClientRect();
    // Follow the rendered layout rather than duplicating its CSS breakpoint.
    const stacked = detailRect.left < itemRect.right && detailRect.right > itemRect.left;
    const target = stacked && heading ? heading : item.querySelector<HTMLButtonElement>('.finding-list-main');
    if (!target) return;
    visibilityObserver = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.target === target && entry.isIntersecting)) return;
      visibilityObserver?.disconnect();
      // Observe visibility through clipping ancestors, then allow two paints.
      focusFrame = window.requestAnimationFrame(() => {
        paintedFrame = window.requestAnimationFrame(() => {
          if (!ready() || !target.isConnected) {
            revealing = false;
            reveal();
            return;
          }
          target.focus({ preventScroll: true });
          if (document.activeElement === target) {
            readinessObserver.disconnect();
            onFocused();
          }
        });
      });
    }, { threshold: 0 });
    visibilityObserver.observe(target);

    // Retain the selected row's position for returning from the detail.
    const list = item.closest<HTMLElement>('.finding-list-scroll');
    if (list && window.getComputedStyle(list).overflowY !== 'visible') {
      const listRect = list.getBoundingClientRect();
      const centered = itemRect.top - listRect.top - Math.max(0, (list.clientHeight - itemRect.height) / 2);
      list.scrollTo({ top: Math.max(0, list.scrollTop + centered), behavior: 'auto' });
    } else {
      item.scrollIntoView({ block: 'center', behavior: 'auto' });
    }
    if (stacked && heading) {
      detail.scrollTop = 0;
      heading.scrollIntoView({ block: 'start', inline: 'nearest', behavior: 'auto' });
    } else {
      const main = item.closest('main');
      if (main && /(auto|scroll)/.test(window.getComputedStyle(main).overflowY)) {
        const workspaceTop = main.scrollTop + workspace.getBoundingClientRect().top - main.getBoundingClientRect().top;
        main.scrollTo({ top: Math.min(Math.max(0, main.scrollHeight - main.clientHeight), Math.max(0, workspaceTop - 18)), behavior: 'auto' });
      } else {
        const rect = item.getBoundingClientRect();
        if (rect.top < 96 || rect.bottom > window.innerHeight - 24) {
          window.scrollTo({ top: Math.max(0, window.scrollY + rect.top - Math.max(96, (window.innerHeight - rect.height) / 2)), behavior: 'auto' });
        }
      }
    }
  };
  // A cached selection still paints in stages inside the child pane. Parent
  // readiness alone cannot prove the exact heading is mounted and focusable.
  const readinessObserver = new MutationObserver(reveal);
  readinessObserver.observe(detail, { attributes: true, attributeFilter: ['data-finding-id', 'aria-busy', 'inert', 'aria-hidden'] });
  reveal();
  return () => {
    readinessObserver.disconnect();
    visibilityObserver?.disconnect();
    if (focusFrame !== undefined) window.cancelAnimationFrame(focusFrame);
    if (paintedFrame !== undefined) window.cancelAnimationFrame(paintedFrame);
  };
}
