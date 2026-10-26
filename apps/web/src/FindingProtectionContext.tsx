import { RefreshCw, Shield } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from './api';
import type { Project } from './api';
import { pushProtectionPresentation } from './GitPushProtection';
import { exactProjectProtection, type ProtectionMatch } from './findingProtection';

type Observation = { identity: string; status: 'loading' | 'ready' | 'error'; exact: ProtectionMatch | null };

export function FindingProtectionContext({ project, scanRevision, onOpen }: {
  project?: Project; scanRevision?: number; onOpen: (repositoryId?: string) => void;
}) {
  const identity = project ? `${project.id}\u0000${project.repo_path}` : '';
  const [refresh, setRefresh] = useState(0);
  const [observation, setObservation] = useState<Observation>({ identity: '', status: 'loading', exact: null });
  useEffect(() => {
    if (!identity) return;
    const controller = new AbortController();
    setObservation({ identity, status: 'loading', exact: null });
    void api.gitPushPolicies(controller.signal).then(async (result) => {
      if (controller.signal.aborted || !project) return;
      const exact = await exactProjectProtection(project, result.repositories, { signal: controller.signal });
      if (!controller.signal.aborted) setObservation({ identity, status: 'ready', exact });
    }).catch(() => {
      if (!controller.signal.aborted) setObservation({ identity, status: 'error', exact: null });
    });
    return () => controller.abort();
  }, [identity, refresh, scanRevision]);
  useEffect(() => {
    const reload = () => { if (document.visibilityState === 'visible') setRefresh((value) => value + 1); };
    window.addEventListener('focus', reload);
    return () => window.removeEventListener('focus', reload);
  }, []);

  const current = observation.identity === identity ? observation : null;
  const exact = current?.status === 'ready' ? current.exact : null;
  const presentation = exact?.policy ? pushProtectionPresentation(exact.policy) : null;
  const label = !project ? 'Select a scan' : !current || current.status === 'loading' ? 'Checking protection…'
    : current.status === 'error' ? 'Protection status unavailable' : exact?.ambiguous ? 'Choose repository protection'
      : presentation?.label || 'No matching protection record';
  return <div className="finding-context-protection" role="group" aria-label="Repository push protection">
    <span className="finding-protection-state" role="status">Push protection <strong>{label}</strong></span>
    <div className="finding-protection-actions">
      <button type="button" className="secondary-action" onClick={() => onOpen(exact?.policy?.repository_id)}>
        <Shield size={16} aria-hidden="true" /> Manage push protection
      </button>
      <button type="button" className="icon-button secondary-action" aria-label="Refresh repository push protection"
        disabled={!project || !current || current.status === 'loading'} onClick={() => setRefresh((value) => value + 1)}>
        <RefreshCw size={14} aria-hidden="true" />
      </button>
    </div>
    {current?.status === 'error' ? <p className="helper-text finding-protection-note">Refresh to verify this source’s protection, or review its repository setup.</p>
      : exact?.ambiguous ? <p className="helper-text finding-protection-note">Several repository records match this source. Review the exact clone in Settings.</p>
        : presentation?.verifiedAt ? <p className="helper-text finding-protection-note">Last host observation: {presentation.verifiedAt}. The next push still requires a check.</p>
          : presentation ? <p className="helper-text finding-protection-note">{presentation.detail}</p>
            : <p className="helper-text finding-protection-note">A passing scan gate does not verify installed push protection.</p>}
  </div>;
}
