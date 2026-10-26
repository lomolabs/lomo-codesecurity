import { Laptop, RefreshCw, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';

import { useConfirmation } from './ConfirmationDialog';
import { BrowserMember, api } from './api';


function memberKindLabel(kind: BrowserMember['member_kind']): string {
  if (kind === 'owner') return 'Owner browser';
  if (kind === 'ide_dashboard') return 'VS Code dashboard';
  return 'Additional browser';
}


function localTime(value: string): string {
  const instant = new Date(value);
  return Number.isFinite(instant.getTime())
    ? instant.toLocaleString()
    : 'Invalid timestamp';
}


export function SettingsBrowserMembers() {
  const confirmAction = useConfirmation();
  const [members, setMembers] = useState<BrowserMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyMemberId, setBusyMemberId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const ordered = useMemo(() => [...members].sort((left, right) => (
    Number(right.current) - Number(left.current)
    || right.last_seen_at.localeCompare(left.last_seen_at)
    || left.id.localeCompare(right.id)
  )), [members]);

  async function loadMembers(announce: boolean, signal?: AbortSignal) {
    setLoading(true);
    setError(null);
    if (announce) setStatus(null);
    try {
      const next = await api.browserMembers(signal);
      setMembers(next);
      if (announce) setStatus(`Browser members refreshed. ${next.length} authorized.`);
    } catch (loadError) {
      if (signal?.aborted) return;
      setError(loadError instanceof Error ? loadError.message : String(loadError));
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    void loadMembers(false, controller.signal);
    return () => controller.abort();
  }, []);

  async function revoke(member: BrowserMember) {
    const currentEffect = member.current
      ? 'This Settings page will return to Pair this browser. Other browsers and every IDE profile remain authorized.'
      : 'Only this browser member will lose access. Other browsers and every IDE profile remain authorized.';
    if (!await confirmAction({
      title: member.current ? 'Sign out this browser?' : `Revoke ${member.member_name}?`,
      message: `${currentEffect} Stored projects, scans, findings, and settings remain.`,
      confirmLabel: member.current ? 'Sign out this browser' : 'Revoke browser',
      cancelLabel: 'Keep browser authorized',
      tone: 'danger',
    })) return;
    setBusyMemberId(member.id);
    setError(null);
    setStatus(null);
    try {
      const result = await api.revokeBrowserMember(member);
      if (result.current) {
        window.location.reload();
        return;
      }
      setMembers((current) => current.filter((candidate) => candidate.id !== member.id));
      setStatus(`${member.member_name} was revoked. Every other browser and IDE member remains authorized.`);
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : String(revokeError));
    } finally {
      setBusyMemberId(null);
    }
  }

  return (
    <div className="band span-2 browser-member-management" aria-busy={loading || busyMemberId !== null}>
      <div className="band-head ide-client-management-head">
        <div>
          <h2>Browsers in this installation</h2>
          <p>
            Each browser profile has its own durable, revocable member. CodeSecurity does not expire server
            authority on a schedule; a browser or operating system may still remove its local cookie.
          </p>
        </div>
        <button
          type="button"
          className="secondary-action"
          disabled={loading || busyMemberId !== null}
          onClick={() => void loadMembers(true)}
        >
          <RefreshCw size={15} /> {loading ? 'Refreshing browsers…' : 'Refresh browsers'}
        </button>
      </div>
      {error ? <p className="status-note error" role="alert">{error}</p> : null}
      {status ? <p className="status-note" role="status">{status}</p> : null}
      {!loading && ordered.length === 0 ? (
        <p className="status-note">No valid browser members were returned.</p>
      ) : null}
      {ordered.length > 0 ? (
        <ul className="ide-client-list" aria-label="Authorized browser members">
          {ordered.map((member) => (
            <li className="ide-client-row" key={member.id}>
              <div className="ide-client-main">
                <strong><Laptop size={15} /> {member.member_name}</strong>
                <span className={`badge ${member.current ? 'badge-pass' : ''}`}>
                  {member.current ? 'Current browser' : memberKindLabel(member.member_kind)}
                </span>
                <code title={member.id}>Member …{member.id.slice(-8)}</code>
                <span className="ide-client-detail">
                  {memberKindLabel(member.member_kind)} · Added {localTime(member.created_at)} · Last successful authorization {localTime(member.last_seen_at)}
                </span>
              </div>
              <div className="ide-client-actions">
                <button
                  type="button"
                  className="danger"
                  disabled={busyMemberId !== null}
                  onClick={() => void revoke(member)}
                  aria-label={member.current
                    ? `Sign out current browser member ${member.member_name}`
                    : `Revoke browser member ${member.member_name}`}
                >
                  <Trash2 size={14} /> {busyMemberId === member.id
                    ? 'Revoking…'
                    : member.current
                      ? 'Sign out'
                      : 'Revoke'}
                </button>
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
