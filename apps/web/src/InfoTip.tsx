import { Info } from 'lucide-react';
import { useId, useLayoutEffect, useRef, useState } from 'react';
import type { CSSProperties } from 'react';

export function InfoTip({ text }: { text: string }) {
  const descriptionId = useId();
  const [open, setOpen] = useState(false);
  const [horizontalOffset, setHorizontalOffset] = useState(0);
  const [verticalPlacement, setVerticalPlacement] = useState<'above' | 'below'>('below');
  const [verticalMaxHeight, setVerticalMaxHeight] = useState(320);
  const tipRef = useRef<HTMLSpanElement>(null);
  const contentRef = useRef<HTMLSpanElement>(null);
  const pointerFocusRef = useRef(false);

  useLayoutEffect(() => {
    if (!open) return undefined;
    const position = () => {
      const bounds = tipRef.current?.getBoundingClientRect();
      const contentBounds = contentRef.current?.getBoundingClientRect();
      if (!bounds || !contentBounds) return;
      const width = Math.min(320, window.innerWidth - 48);
      const left = Math.min(Math.max(bounds.left, 24), window.innerWidth - width - 24);
      setHorizontalOffset(left - bounds.left);
      const belowSpace = Math.max(0, window.innerHeight - bounds.bottom - 29);
      const aboveSpace = Math.max(0, bounds.top - 29);
      const placement = contentBounds.height <= belowSpace || belowSpace >= aboveSpace ? 'below' : 'above';
      setVerticalPlacement(placement);
      setVerticalMaxHeight(placement === 'below' ? belowSpace : aboveSpace);
    };
    position();
    window.addEventListener('resize', position);
    window.addEventListener('scroll', position, true);
    return () => {
      window.removeEventListener('resize', position);
      window.removeEventListener('scroll', position, true);
    };
  }, [open]);

  return (
    <span
      ref={tipRef}
      className="info-tip"
      data-open={open}
      data-placement={verticalPlacement}
      style={{
        '--info-tip-max-height': `${verticalMaxHeight}px`,
        '--info-tip-offset': `${horizontalOffset}px`,
      } as CSSProperties}
    >
      <button
        type="button"
        className="info-tip-trigger"
        aria-label="More information"
        aria-describedby={descriptionId}
        aria-expanded={open}
        onClick={() => {
          pointerFocusRef.current = false;
          setOpen((current) => !current);
        }}
        onBlur={() => {
          pointerFocusRef.current = false;
          setOpen(false);
        }}
        onFocus={() => {
          if (!pointerFocusRef.current) setOpen(true);
        }}
        onPointerDown={() => { pointerFocusRef.current = true; }}
        onPointerCancel={() => { pointerFocusRef.current = false; }}
        onPointerUp={() => { pointerFocusRef.current = false; }}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            setOpen(false);
            return;
          }
          const content = contentRef.current;
          if (!open || !content || content.scrollHeight <= content.clientHeight) return;
          const direction = ['ArrowDown', 'PageDown'].includes(event.key)
            ? 1
            : ['ArrowUp', 'PageUp'].includes(event.key)
              ? -1
              : 0;
          if (!direction) return;
          event.preventDefault();
          content.scrollBy({
            top: direction * (event.key.startsWith('Page') ? content.clientHeight : 24),
            behavior: 'auto',
          });
        }}
      >
        <Info size={14} aria-hidden="true" />
      </button>
      <span
        ref={contentRef}
        className="info-tip-content"
        id={descriptionId}
        role="tooltip"
        onPointerDown={(event) => event.preventDefault()}
      >
        {text}
      </span>
    </span>
  );
}
