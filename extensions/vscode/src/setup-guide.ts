import { randomBytes } from 'node:crypto';
import type * as vscode from 'vscode';
import { SETUP_CONTEXT_PREFIX, SetupStep } from './onboarding';

const steps: readonly SetupStep[] = ['backend', 'connection', 'repositories', 'scan', 'review', 'protection'];
const commands = new Set([
  'lomoCodeSecurity.gettingStarted', 'lomoCodeSecurity.pair', 'workbench.trust.manage',
  'lomoCodeSecurity.selectRepositories', 'lomoCodeSecurity.openDashboard',
  'lomoCodeSecurity.scanWorkspaceFolders', 'lomoCodeSecurity.refreshFindings', 'lomoCodeSecurity.protectPushes',
]);
type Action = Readonly<{ command: string }> | Readonly<{ notes: SetupStep }>;
type Step = Readonly<{ id: SetupStep; title: string; description: string; actions: readonly { label: string; command: string }[] }>;
type Host = Readonly<{
  create(): vscode.WebviewPanel;
  run(command: string): Thenable<unknown>;
  notes(step: SetupStep): Thenable<unknown>;
  error(): void;
}>;

/** Setup prose and action labels have one source: the packaged contribution. */
export function setupGuideSteps(manifest: unknown): readonly Step[] {
  const source = manifest as { contributes?: { walkthroughs?: { id?: string; steps?: unknown[] }[] } } | undefined;
  const rows = source?.contributes?.walkthroughs?.find(row => row.id === 'setup')?.steps;
  if (!Array.isArray(rows) || rows.length !== steps.length) throw new Error('CodeSecurity setup instructions are unavailable.');
  return rows.map((value, index) => {
    const row = value as Record<string, unknown>;
    if (row.id !== steps[index] || typeof row.title !== 'string' || row.title.length > 120
      || typeof row.description !== 'string' || row.description.length > 6000
      || (row.media as { markdown?: unknown } | undefined)?.markdown !== `media/setup-${steps[index]}.md`)
      throw new Error('CodeSecurity setup instructions are invalid.');
    const actions: { label: string; command: string }[] = [];
    const description = row.description.replace(/\[([^\]\n]{1,120})\]\(command:([A-Za-z0-9.]+)\)/gu, (_match, label: string, command: string) => {
      if (!commands.has(command)) throw new Error('CodeSecurity setup action is invalid.');
      actions.push({ label, command }); return '';
    }).trim();
    if (!actions.length || actions.length > 4 || /command:/u.test(description)) throw new Error('CodeSecurity setup action is invalid.');
    return { id: steps[index], title: row.title, description, actions };
  });
}

const escape = (value: string): string => value.replace(/[&<>"']/gu, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);

function guideHtml(rows: readonly Step[], nonce: string): string {
  const sections = rows.map((row, index) => `<section aria-labelledby="title-${row.id}">
    <span class="number" aria-hidden="true">${index + 1}</span><div class="step">
    <h2 id="title-${row.id}">${escape(row.title)}</h2><p>${escape(row.description)}</p>
    <div class="actions">${row.actions.map((action, actionIndex) => `<button data-action="${row.id}:${actionIndex}">${escape(action.label)}</button>`).join('')}
    <button class="notes" data-action="${row.id}:notes" aria-label="Detailed instructions: ${escape(row.title)}">Detailed instructions</button></div>
    <p class="status" role="status" id="status-${row.id}">Not observed this session</p></div></section>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'">
    <title>Start with useful findings</title><style nonce="${nonce}">
    body{color:var(--vscode-foreground);background:var(--vscode-editor-background);font-family:var(--vscode-font-family);font-size:var(--vscode-font-size);line-height:1.55;margin:28px auto;padding:0 24px;max-width:860px}
    h1{font-size:1.8em;font-weight:600;line-height:1.25;margin:0 0 12px}header>p{color:var(--vscode-descriptionForeground);max-width:72ch;margin:8px 0 24px}
    section{display:grid;grid-template-columns:32px minmax(0,1fr);gap:16px;border-top:1px solid var(--vscode-panel-border);padding:20px 0}
    .number{font-variant-numeric:tabular-nums;color:var(--vscode-descriptionForeground);padding-top:2px}h2{font-size:1.12em;line-height:1.4;margin:0 0 6px;font-weight:600}
    p{margin:0 0 12px;overflow-wrap:anywhere}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
    button{font:inherit;line-height:1.4;white-space:normal;text-align:start;border:1px solid var(--vscode-button-border,transparent);border-radius:3px;padding:5px 10px;cursor:pointer;color:var(--vscode-button-secondaryForeground);background:var(--vscode-button-secondaryBackground)}
    button:hover{background:var(--vscode-button-secondaryHoverBackground)}button:focus-visible{outline:2px solid var(--vscode-focusBorder);outline-offset:3px}
    button:disabled{opacity:.6;cursor:wait}.notes{color:var(--vscode-textLink-foreground);background:transparent;border-color:transparent}.notes:hover{text-decoration:underline;background:transparent}
    .status{font-size:.9em;color:var(--vscode-descriptionForeground);margin:10px 0 0}.status[data-complete="true"]{color:var(--vscode-foreground);font-weight:600}
    @media(max-width:480px){body{margin:20px auto;padding:0 14px}section{grid-template-columns:20px minmax(0,1fr);gap:10px}}
    </style></head><body><header><h1>Start with useful findings</h1><p>Six steps from a local backend to reviewed findings and deliberate push protection. Progress reflects results observed in this session. Current access and readiness are checked again when you act.</p></header>
    <main aria-label="CodeSecurity setup">${sections}</main><script nonce="${nonce}">
    const api=acquireVsCodeApi();
    document.addEventListener('click',event=>{const button=event.target instanceof Element?event.target.closest('button[data-action]'):null;if(button&&!button.disabled)api.postMessage({type:'action',id:button.dataset.action});});
    window.addEventListener('message',event=>{const message=event.data;if(message?.type!=='progress')return;
      for(const [step,complete]of Object.entries(message.steps??{})){const element=document.getElementById('status-'+step);if(element){element.textContent=complete===true?'Observed this session':'Not observed this session';element.dataset.complete=String(complete===true);}}
      for(const button of document.querySelectorAll('button'))button.disabled=message.busy===true;
    });api.postMessage({type:'ready'});
    </script></body></html>`;
}

/** A user-opened guide; it never enrolls, grants access or starts work on open. */
export class SetupGuide implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private listeners: vscode.Disposable[] = [];
  private readonly progress = Object.fromEntries(steps.map(step => [step, false])) as Record<SetupStep, boolean>;
  private disposed = false;
  private busy = false;
  constructor(private readonly manifest: () => unknown, private readonly host: Host) {}

  show(): void {
    if (this.disposed) return;
    if (this.panel) { this.panel.reveal(); this.publish(); return; }
    const rows = setupGuideSteps(this.manifest()), actions = new Map<string, Action>();
    for (const row of rows) {
      row.actions.forEach((action, index) => actions.set(`${row.id}:${index}`, { command: action.command }));
      actions.set(`${row.id}:notes`, { notes: row.id });
    }
    const panel = this.host.create(); this.panel = panel;
    this.listeners = [panel.onDidDispose(() => this.closed(panel)), panel.onDidChangeViewState(() => this.publish()),
      panel.webview.onDidReceiveMessage((message: unknown) => {
        if (this.disposed || this.panel !== panel || !panel.visible || !message || typeof message !== 'object' || Array.isArray(message)) return;
        const value = message as Record<string, unknown>, keys = Object.keys(value).sort().join(',');
        if (keys === 'type' && value.type === 'ready') { this.publish(); return; }
        if (keys !== 'id,type' || value.type !== 'action' || typeof value.id !== 'string' || value.id.length > 32 || this.busy) return;
        const action = actions.get(value.id); if (!action) return;
        this.busy = true; this.publish();
        void Promise.resolve().then(() => {
          if (this.disposed || this.panel !== panel) return;
          return 'command' in action ? this.host.run(action.command) : this.host.notes(action.notes);
        }).catch(() => { if (!this.disposed && this.panel === panel) this.host.error(); })
          .finally(() => { this.busy = false; this.publish(); });
      })];
    panel.webview.html = guideHtml(rows, randomBytes(16).toString('hex'));
  }
  update(key: string, complete: boolean): void {
    const step = key.slice(SETUP_CONTEXT_PREFIX.length) as SetupStep;
    if (!key.startsWith(SETUP_CONTEXT_PREFIX) || !steps.includes(step) || this.disposed) return;
    this.progress[step] = complete === true; this.publish();
  }
  private publish(): void {
    if (this.disposed || !this.panel) return;
    try { void Promise.resolve(this.panel.webview.postMessage({ type: 'progress', steps: { ...this.progress }, busy: this.busy })).catch(() => undefined); }
    catch { /* The native panel may close between its disposal event and delivery. */ }
  }
  private closed(panel: vscode.WebviewPanel): void {
    if (this.panel !== panel) return;
    this.panel = undefined;
    for (const listener of this.listeners.splice(0)) listener.dispose();
  }
  dispose(): void { this.disposed = true; const panel = this.panel; if (panel) { this.closed(panel); panel.dispose(); } }
}
