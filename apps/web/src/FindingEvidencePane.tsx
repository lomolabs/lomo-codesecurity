import { Copy, TerminalSquare } from 'lucide-react';
import { memo, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import type { Finding } from './api';
import { evidenceHeightControl } from './evidenceHeight';
import { findingEvidenceMetadata, findingEvidenceMetadataKey, findingEvidencePresentation, findingLocation, offenderColumnSegments } from './findingEvidence';
import hljs from 'highlight.js/lib/core';
import bash from 'highlight.js/lib/languages/bash';
import dockerfile from 'highlight.js/lib/languages/dockerfile';
import ini from 'highlight.js/lib/languages/ini';
import javascript from 'highlight.js/lib/languages/javascript';
import json from 'highlight.js/lib/languages/json';
import python from 'highlight.js/lib/languages/python';
import typescript from 'highlight.js/lib/languages/typescript';
import yaml from 'highlight.js/lib/languages/yaml';

const snippetContextLines = 40;
const snippetHighlightCacheEntries = 16;
const snippetHighlightCacheCharacters = 512 * 1024;
const snippetHighlightCache = new Map<string, { html: string; size: number }>();
let snippetHighlightCacheSize = 0;
function DisabledReason({ id, reason }: { id: string; reason: string | null }) {
  return reason ? <p className="disabled-action-reason" id={id} role="status">{reason}</p> : null;
}

hljs.registerLanguage('bash', bash);
hljs.registerLanguage('dockerfile', dockerfile);
hljs.registerLanguage('ini', ini);
hljs.registerLanguage('javascript', javascript);
hljs.registerLanguage('json', json);
hljs.registerLanguage('python', python);
hljs.registerLanguage('typescript', typescript);
hljs.registerLanguage('yaml', yaml);

function languageForPath(path: string) {
  const lower = path.toLowerCase();
  if (lower.endsWith('.py')) return 'python';
  if (lower.endsWith('.js') || lower.endsWith('.jsx')) return 'javascript';
  if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'typescript';
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml';
  if (lower.endsWith('.tf')) return 'ini';
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.toml')) return 'toml';
  if (lower.endsWith('.sh') || lower.endsWith('.bash') || lower.endsWith('.zsh')) return 'bash';
  if (lower.includes('dockerfile')) return 'dockerfile';
  return '';
}

function highlightedHtml(code: string, filePath: string) {
  const language = languageForPath(filePath);
  const cacheKey = `${language}\u0000${code}`;
  const cached = snippetHighlightCache.get(cacheKey);
  if (cached) {
    snippetHighlightCache.delete(cacheKey);
    snippetHighlightCache.set(cacheKey, cached);
    return cached.html;
  }
  let html: string;
  try {
    if (language && hljs.getLanguage(language)) {
      html = hljs.highlight(code, { language }).value;
    } else {
      html = hljs.highlightAuto(code).value;
    }
  } catch {
    html = code.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char] || char);
  }
  const size = cacheKey.length + html.length;
  if (size <= snippetHighlightCacheCharacters) {
    while (
      snippetHighlightCache.size >= snippetHighlightCacheEntries
      || snippetHighlightCacheSize + size > snippetHighlightCacheCharacters
    ) {
      const oldestKey = snippetHighlightCache.keys().next().value;
      if (typeof oldestKey !== 'string') break;
      const oldest = snippetHighlightCache.get(oldestKey);
      snippetHighlightCache.delete(oldestKey);
      snippetHighlightCacheSize -= oldest?.size || 0;
    }
    snippetHighlightCache.set(cacheKey, { html, size });
    snippetHighlightCacheSize += size;
  }
  return html;
}

function positiveSafeLineNumber(value: unknown) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return undefined;
  const integer = Math.floor(value);
  if (integer < 1) return undefined;
  return Math.min(integer, Number.MAX_SAFE_INTEGER);
}

const CodeSnippet = memo(function CodeSnippet({
  code,
  filePath,
  height,
  startLine,
  startColumn,
  endLine,
  endColumn,
  snippetStartLine,
  columnOrigin,
}: {
  code: string;
  filePath: string;
  height: number;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippetStartLine?: number;
  columnOrigin?: number;
}) {
  const normalizedCode = useMemo(() => code.replace(/\r\n?/g, '\n'), [code]);
  const rawLines = useMemo(() => normalizedCode.split('\n'), [normalizedCode]);
  const normalizedStartLine = positiveSafeLineNumber(startLine);
  const normalizedEndCandidate = positiveSafeLineNumber(endLine);
  const normalizedEndLine = normalizedStartLine === undefined
    ? normalizedEndCandidate
    : Math.max(normalizedStartLine, normalizedEndCandidate ?? normalizedStartLine);
  const normalizedSnippetStartLine = positiveSafeLineNumber(snippetStartLine);
  const offenderLineSpan = normalizedStartLine !== undefined && normalizedEndLine !== undefined
    ? normalizedEndLine - normalizedStartLine + 1
    : 1;
  const fallbackContextLines = Math.min(snippetContextLines, Math.floor(Math.max(rawLines.length - offenderLineSpan, 0) / 2));
  const maximumFirstLine = Math.max(1, Number.MAX_SAFE_INTEGER - Math.max(0, rawLines.length - 1));
  const contextualFirstLine = Math.max(1, (normalizedStartLine ?? 1) - fallbackContextLines);
  const firstLine = Math.min(normalizedSnippetStartLine ?? contextualFirstLine, maximumFirstLine);
  const highlightedSource = useMemo(() => highlightedHtml(normalizedCode, filePath), [filePath, normalizedCode]);
  const lineNumbers = useMemo(() => rawLines.map((_line, index) => firstLine + index).join('\n'), [firstLine, rawLines]);
  const rowHeight = 22;
  const naturalHeight = rawLines.length * rowHeight + 18;
  const renderedHeight = Math.min(height, Math.max(68, naturalHeight));
  const rawOffenderFirstIndex = normalizedStartLine === undefined ? -1 : normalizedStartLine - firstLine;
  const rawOffenderLastIndex = normalizedStartLine === undefined || normalizedEndLine === undefined ? -1 : normalizedEndLine - firstLine;
  const offenderFirstIndex = Math.max(0, rawOffenderFirstIndex);
  const offenderLastIndex = Math.min(rawLines.length - 1, rawOffenderLastIndex);
  const offenderVisible = normalizedStartLine !== undefined
    && offenderFirstIndex <= offenderLastIndex
    && rawOffenderFirstIndex < rawLines.length
    && rawOffenderLastIndex >= 0;
  const firstVisibleOffenderLine = Math.max(firstLine, normalizedStartLine ?? firstLine);
  const offenderDescription = normalizedStartLine === undefined || normalizedEndLine === undefined
    ? undefined
    : normalizedStartLine === normalizedEndLine
      ? `Offender line ${normalizedStartLine}${startColumn ? `, column ${startColumn}${endColumn && endColumn !== startColumn ? ` through column ${endColumn}` : ''}` : ''}.`
      : `Offender lines ${normalizedStartLine}${startColumn ? `, column ${startColumn}` : ''} through ${normalizedEndLine}${endColumn ? `, column ${endColumn}` : ''}.`;
  const columnSegments = useMemo(() => offenderColumnSegments({
    lines: rawLines, firstLine, startLine, endLine: endLine ?? startLine,
    startColumn, endColumn, columnOrigin,
  }), [rawLines, firstLine, startLine, endLine, startColumn, endColumn, columnOrigin]);
  const descriptionId = useId();
  const codeViewport = useRef<HTMLPreElement>(null);
  useLayoutEffect(() => {
    const viewport = codeViewport.current;
    const source = viewport?.querySelector('.code-source');
    if (!viewport || !source) return;
    const lineHeight = Number.parseFloat(getComputedStyle(source).lineHeight);
    if (!Number.isFinite(lineHeight) || lineHeight <= 0) return;
    // Start near the evidence, leaving a little context. A refresh of the same
    // evidence or a height adjustment preserves the reader's scroll position.
    viewport.scrollTop = offenderVisible ? Math.max(0, offenderFirstIndex - 2) * lineHeight : 0;
  }, [normalizedCode, filePath, firstLine, offenderFirstIndex, offenderVisible]);
  return (
    <pre
      ref={codeViewport}
      role="region"
      aria-describedby={offenderDescription ? descriptionId : undefined}
      aria-label={`Code evidence for ${filePath || 'the selected finding'}`}
      className="code-block highlighted-code"
      data-line-count={rawLines.length}
      style={{
        height: `${renderedHeight}px`,
        maxHeight: `${height}px`,
        '--code-line-digits': String(firstLine + rawLines.length - 1).length,
      } as CSSProperties}
      tabIndex={0}
    >
      {offenderDescription ? <span className="visually-hidden" id={descriptionId}>{offenderDescription}</span> : null}
      <code>
        <span aria-hidden="true" className="code-line-numbers">{lineNumbers}</span>
        <span className="code-source" dangerouslySetInnerHTML={{ __html: highlightedSource }} />
        {columnSegments.length ? <span className="code-column-ranges" aria-hidden="true">
          {columnSegments.map((segment) => <span className="code-column-row" key={segment.lineIndex} style={{ top: `${segment.lineIndex}lh` }}>
            <span>{segment.prefix}</span><mark>{segment.text}</mark>
          </span>)}
        </span> : null}
        {offenderVisible ? (
          <span
            aria-hidden="true"
            className="code-row offender"
            style={{
              height: `${offenderLastIndex - offenderFirstIndex + 1}lh`,
              top: `${offenderFirstIndex}lh`,
            }}
          >
            <span className="code-gutter">
              <span className="code-marker">&gt;</span>
              <span className="code-line-number">{firstVisibleOffenderLine}</span>
            </span>
          </span>
        ) : null}
      </code>
    </pre>
  );
});

type FindingEvidenceProps = {
  finding: Finding;
  setSnippetHeight: (height: number) => void;
  snippetHeight: number;
};

export function sameFindingEvidence(left: FindingEvidenceProps, right: FindingEvidenceProps) {
  const previous = left.finding;
  const next = right.finding;
  return (
    left.snippetHeight === right.snippetHeight
    && left.setSnippetHeight === right.setSnippetHeight
    && previous.id === next.id
    && previous.scan_id === next.scan_id
    && previous.scanner === next.scanner
    && previous.rule_id === next.rule_id
    && previous.message === next.message
    && previous.file_path === next.file_path
    && previous.start_line === next.start_line
    && previous.start_column === next.start_column
    && previous.end_line === next.end_line
    && previous.end_column === next.end_column
    && previous.code_snippet === next.code_snippet
    && findingEvidenceMetadataKey(previous) === findingEvidenceMetadataKey(next)
  );
}

export const FindingEvidence = memo(function FindingEvidence({ finding, setSnippetHeight, snippetHeight }: FindingEvidenceProps) {
  const [copyStatus, setCopyStatus] = useState('');
  const metadata = findingEvidenceMetadata(finding);
  const presentation = findingEvidencePresentation(finding);
  const normalizedCode = useMemo(() => (finding.code_snippet || '').replace(/\r\n?/g, '\n'), [finding.code_snippet]);
  const copyDisabledReason = finding.code_snippet ? null : 'No code evidence is available to copy.';
  const copyDisabledReasonId = 'finding-copy-evidence-disabled-reason';

  useEffect(() => setCopyStatus(''), [finding.id, normalizedCode]);

  async function copyEvidence() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(normalizedCode);
      setCopyStatus('Sanitized code evidence copied.');
    } catch {
      setCopyStatus('Code evidence could not be copied. Select the text manually.');
    }
  }

  return (
    <div className="detail-section finding-evidence">
      <div className="detail-section-head">
        <TerminalSquare size={16} />
        <strong>Evidence</strong>
        <span className="finding-evidence-location">{findingLocation(finding)}</span>
        <div className="evidence-toolbar-actions">
          <button
            aria-describedby={copyDisabledReason ? copyDisabledReasonId : undefined}
            className="secondary-action"
            type="button"
            disabled={Boolean(copyDisabledReason)}
            onClick={() => void copyEvidence()}
            title={finding.code_snippet ? 'Copy the displayed sanitized evidence.' : 'No code evidence is available to copy.'}
          >
            <Copy size={14} /> Copy evidence
          </button>
        </div>
      </div>
      <DisabledReason id={copyDisabledReasonId} reason={copyDisabledReason} />
      {copyStatus ? (
        <p aria-live="polite" className="status-note" role="status">{copyStatus}</p>
      ) : null}
      {metadata.snippet_truncated === true || metadata.snippet_line_truncated === true ? (
        <p className="evidence-boundary-note">Captured context is bounded; this is not the complete source file.
          {metadata.snippet_line_truncated === true ? ` The displayed line is a captured window${typeof metadata.snippet_column_start === 'number' && Number.isSafeInteger(metadata.snippet_column_start) && metadata.snippet_column_start > 0 ? ` starting at source column ${metadata.snippet_column_start}` : ''}.` : ''}
        </p>
      ) : null}
      {finding.code_snippet ? (
        <CodeSnippet
          code={normalizedCode}
          filePath={finding.file_path}
          height={snippetHeight}
          startLine={finding.start_line}
          startColumn={finding.start_column}
          endLine={finding.end_line}
          endColumn={finding.end_column}
          snippetStartLine={typeof metadata.snippet_start_line === 'number' ? metadata.snippet_start_line : undefined}
          columnOrigin={metadata.snippet_line_truncated === true
            ? typeof metadata.snippet_column_start === 'number' ? metadata.snippet_column_start : 0
            : undefined}
        />
      ) : (
        <div className="empty-state">{presentation.kind === 'dependency' ? 'No source snippet was captured for this dependency vulnerability. Review the scanner message and exact manifest location.' : 'No source snippet was captured. The scanner message and location remain available.'}</div>
      )}
      <div className="evidence-display-options">
        {normalizedCode.split('\n').length * 22 + 18 > evidenceHeightControl.initial ? (
          <button className="secondary-action" type="button"
            onClick={() => setSnippetHeight(snippetHeight > evidenceHeightControl.initial ? evidenceHeightControl.initial : 500)}>
            {snippetHeight > evidenceHeightControl.initial ? 'Compact code' : 'More code'}
          </button>
        ) : null}
        <label className="snippet-slider">
          Max height
          <input
            type="range"
            min={evidenceHeightControl.min}
            max={evidenceHeightControl.max}
            step={evidenceHeightControl.step}
            value={snippetHeight}
            onChange={(event) => setSnippetHeight(Number(event.target.value))}
          />
        </label>
      </div>
    </div>
  );
}, sameFindingEvidence);
