import { useEffect, useRef, useState, type FormEvent } from 'react';
import { RefreshCw, Save, Shield } from 'lucide-react';
import { api, type GatePolicyValues, type Project } from './api';
import { projectGateReadFence, projectGateValues, sameGate } from './projectGatePolicy';

type Entry = { saved: GatePolicyValues; draft: GatePolicyValues; status: string };

/** One policy read for the selected project; drafts stay scoped when switching. */
export function ProjectGate({ project, disabled, onSaved }: {
  project: Project; disabled: boolean; onSaved: () => Promise<void>;
}) {
  const [entries, setEntries] = useState<Record<number, Entry>>({});
  const [loading, setLoading] = useState<number | null>(null);
  const [saving, setSaving] = useState<number | null>(null);
  const [errors, setErrors] = useState<Record<number, string>>({});
  const controller = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const readFence = useRef(projectGateReadFence());
  const id = project.id;
  const entry = entries[id];
  const blocked = disabled || loading === id || saving !== null;

  async function load(projectId: number) {
    controller.current?.abort();
    const operation = new AbortController();
    const current = readFence.current.capture(projectId);
    controller.current = operation;
    setLoading(projectId);
    setErrors(current => ({ ...current, [projectId]: '' }));
    try {
      const saved = projectGateValues(await api.projectGate(projectId, operation.signal), projectId);
      if (operation.signal.aborted || !current()) return;
      setEntries(current => {
        const previous = current[projectId];
        const dirty = previous && !sameGate(previous.saved, previous.draft);
        return { ...current, [projectId]: { saved, draft: dirty ? previous.draft : saved,
          status: dirty ? 'Policy refreshed. Your unsaved changes are retained; review them before saving.' : '' } };
      });
    } catch (error) {
      if (!operation.signal.aborted && current()) setErrors(current => ({ ...current, [projectId]: String(error instanceof Error ? error.message : error) }));
    } finally {
      if (!operation.signal.aborted) setLoading(null);
    }
  }

  useEffect(() => {
    mounted.current = true;
    void load(id);
    return () => { mounted.current = false; controller.current?.abort(); };
  }, [id]);

  function edit(update: Partial<GatePolicyValues>) {
    setEntries(current => ({ ...current, [id]: { ...current[id], draft: { ...current[id].draft, ...update }, status: '' } }));
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!entry || blocked || errors[id]) return;
    const submitted = { ...entry.draft };
    readFence.current.invalidate(id);
    setSaving(id);
    setErrors(current => ({ ...current, [id]: '' }));
    try {
      const saved = projectGateValues(await api.saveProjectGate(id, submitted, entry.saved), id);
      readFence.current.invalidate(id);
      if (!mounted.current) return;
      setEntries(current => ({ ...current, [id]: { saved, draft: saved,
        status: `Policy saved for ${project.name}. Existing scan gates were recalculated; other projects are unchanged.` } }));
      await onSaved();
    } catch (error) {
      readFence.current.invalidate(id);
      if (mounted.current) setErrors(current => ({ ...current, [id]: String(error instanceof Error ? error.message : error) }));
    } finally {
      if (mounted.current) setSaving(null);
    }
  }

  return <section className="project-gate" data-project-id={id} aria-label={`Scan gate for ${project.name}`} aria-busy={loading === id || saving === id}>
    <div className="band-head">
      <div><h3><Shield size={16} aria-hidden="true" /> Repository scan gate</h3><p className="helper-text">{project.name}</p></div>
      <button type="button" className="secondary-action" disabled={blocked} onClick={() => void load(id)}><RefreshCw size={15} /> Reload policy</button>
    </div>
    <p className="helper-text">Applies only to this project and its scan results. Push blocking requires separate protection setup in VS Code.</p>
    {entry ? <form className="form" onSubmit={save}>
      <label className="check"><input type="checkbox" checked={entry.draft.active} disabled={blocked} onChange={event => edit({ active: event.target.checked })} /><span>Evaluate this project’s gate</span></label>
      <label>Maximum critical findings<input type="number" min="-1" max="999" required disabled={blocked} value={entry.draft.max_critical} onChange={event => edit({ max_critical: Number(event.target.value) })} /></label>
      <label>Maximum high findings<input type="number" min="-1" max="999" required disabled={blocked} value={entry.draft.max_high} onChange={event => edit({ max_high: Number(event.target.value) })} /></label>
      <label className="check"><input type="checkbox" checked={entry.draft.block_secrets} disabled={blocked} onChange={event => edit({ block_secrets: event.target.checked })} /><span>Block secrets in this project</span></label>
      <p className="helper-text">−1 leaves a severity unbounded. Incomplete scans cannot pass. A disabled gate cannot approve a protected push.</p>
      <div className="project-gate-actions">
        <button disabled={blocked || Boolean(errors[id]) || sameGate(entry.saved, entry.draft)}><Save size={15} /> {saving === id ? 'Saving…' : 'Save project gate'}</button>
        <button type="button" className="secondary-action" disabled={blocked || sameGate(entry.saved, entry.draft)} onClick={() => setEntries(current => ({ ...current, [id]: { ...current[id], draft: current[id].saved, status: '' } }))}>Reset draft</button>
      </div>
    </form> : !errors[id] ? <p role="status">Loading this project’s gate…</p> : null}
    {errors[id] ? <p className="status-note error" role="alert">{errors[id]} Use Reload policy to check the current values.</p> : null}
    {entry?.status ? <p className="status-note" role="status">{entry.status}</p> : null}
  </section>;
}
