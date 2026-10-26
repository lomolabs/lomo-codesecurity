import { FormEvent, ReactNode, Ref, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { RefreshCw, Shield, UnlockKeyhole, X } from 'lucide-react';

import { api, isApiError, onAuthRequired, setCsrfToken } from './api';
import {
  browserSessionRenewalDelayMilliseconds,
  sessionFailureRequiresPairing,
} from './authSession';
import { consumeBootstrapFragment, subscribeToBootstrapFragments } from './browserBootstrap';


type AuthState = 'checking' | 'ready' | 'recovering' | 'required' | 'error';
type AuthAttempt = 'initial' | 'renewal' | 'retry' | 'bootstrap';

const pairingRequiredMessage = 'No active local browser session. Enter a current one-time browser pairing key.';
const authenticationLostMessage = 'This browser member is missing or revoked, or its local cookie was removed. Pair this browser again.';
const reconnectingMessage = 'CodeSecurity is temporarily unavailable. Your local browser session was not discarded.';


export function BrowserPairingForm({
  token,
  inputRef,
  onTokenChange,
  onSubmit,
}: {
  token: string;
  inputRef?: Ref<HTMLInputElement>;
  onTokenChange: (token: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form onSubmit={onSubmit} className="auth-form" autoComplete="off">
      <label htmlFor="bootstrap-token">One-time browser pairing key</label>
      <input
        id="bootstrap-token"
        name="one-time-code"
        type="password"
        autoComplete="one-time-code"
        autoCapitalize="none"
        spellCheck={false}
        value={token}
        onChange={(event) => onTokenChange(event.target.value)}
        ref={inputRef}
        autoFocus
        required
      />
      <button type="submit" disabled={!token.trim()}><UnlockKeyhole size={16} /> Add this browser</button>
    </form>
  );
}


export default function AuthGate({ children }: { children: ReactNode }) {
  const started = useRef(false);
  const mounted = useRef(false);
  const inFlight = useRef<Promise<void> | null>(null);
  const inFlightCandidate = useRef<string | undefined>(undefined);
  const queuedCandidate = useRef<{ candidate: string; attempt?: AuthAttempt } | null>(null);
  const authorityEpoch = useRef(0);
  const renewalTimer = useRef<number | undefined>(undefined);
  const tokenInput = useRef<HTMLInputElement>(null);
  const [state, setState] = useState<AuthState>('checking');
  const [activeAttempt, setActiveAttempt] = useState<AuthAttempt>('initial');
  const [token, setToken] = useState('');
  const [message, setMessage] = useState('Checking the local browser session…');
  const [inviteWarning, setInviteWarning] = useState<string | null>(null);

  function clearRenewalTimer() {
    if (renewalTimer.current !== undefined) {
      window.clearTimeout(renewalTimer.current);
      renewalTimer.current = undefined;
    }
  }

  function scheduleRenewal(delay: number, epoch: number) {
    clearRenewalTimer();
    renewalTimer.current = window.setTimeout(() => {
      renewalTimer.current = undefined;
      if (mounted.current && authorityEpoch.current === epoch) {
        void establish(undefined, 'renewal');
      }
    }, delay);
  }

  async function establish(candidate?: string, requestedAttempt?: AuthAttempt) {
    if (inFlight.current) {
      if (candidate && candidate !== inFlightCandidate.current) {
        queuedCandidate.current = { candidate, attempt: requestedAttempt };
      }
      await inFlight.current;
      return;
    }

    const attemptKind = requestedAttempt || (candidate ? 'bootstrap' : 'initial');
    const attemptEpoch = authorityEpoch.current;
    inFlightCandidate.current = candidate;
    const attempt = (async () => {
      if (attemptKind !== 'renewal') {
        setActiveAttempt(attemptKind);
        setState(attemptKind === 'retry' ? 'recovering' : 'checking');
        setMessage(
          attemptKind === 'bootstrap'
            ? 'Creating the one-time local session…'
            : attemptKind === 'retry'
              ? 'Retrying the local browser session…'
              : 'Checking the local browser session…',
        );
      }
      try {
        const result = candidate ? await api.bootstrap(candidate) : await api.authSession();
        const renewalDelay = browserSessionRenewalDelayMilliseconds(result.expires_in);
        if (!mounted.current || authorityEpoch.current !== attemptEpoch) return;
        setCsrfToken(result.csrf_token);
        if (candidate) setToken('');
        setInviteWarning(null);
        setState('ready');
        scheduleRenewal(renewalDelay, attemptEpoch);
      } catch (error) {
        if (!mounted.current) return;
        const detail = error instanceof Error ? error.message : String(error);
        if (candidate) {
          try {
            const retained = await api.authSession();
            const renewalDelay = browserSessionRenewalDelayMilliseconds(retained.expires_in);
            if (!mounted.current || authorityEpoch.current !== attemptEpoch) return;
            setCsrfToken(retained.csrf_token);
            setToken('');
            setInviteWarning(
              'The one-time browser invitation could not be used. This browser kept its existing authorized member; generate a new invitation only if you meant to add another browser.',
            );
            setState('ready');
            scheduleRenewal(renewalDelay, attemptEpoch);
            return;
          } catch {
            // No retained browser authority exists. Preserve the typed
            // invitation failure below so the user can pair deliberately.
          }
        }
        const status = isApiError(error) ? error.status : undefined;
        const pairingRequired = sessionFailureRequiresPairing(status);
        if (authorityEpoch.current !== attemptEpoch && !pairingRequired) return;
        if (candidate) {
          setToken('');
          setMessage(detail);
          setState('error');
        } else if (pairingRequired) {
          clearRenewalTimer();
          setMessage(attemptKind === 'initial' ? pairingRequiredMessage : authenticationLostMessage);
          setState('required');
        } else {
          setMessage(`${reconnectingMessage} ${detail}`);
          setState('recovering');
        }
      }
    })();

    inFlight.current = attempt;
    try {
      await attempt;
    } finally {
      if (inFlight.current === attempt) {
        inFlight.current = null;
        inFlightCandidate.current = undefined;
        const queued = queuedCandidate.current;
        queuedCandidate.current = null;
        if (queued && mounted.current) {
          await establish(queued.candidate, queued.attempt);
        }
      }
    }
  }

  useEffect(() => {
    mounted.current = true;
    const unsubscribe = onAuthRequired(() => {
      authorityEpoch.current += 1;
      clearRenewalTimer();
      setCsrfToken('');
      setInviteWarning(null);
      setMessage(authenticationLostMessage);
      setState('required');
    });
    if (!started.current) {
      started.current = true;
      const candidate = consumeBootstrapFragment(window.location, window.history);
      void establish(candidate || undefined, candidate ? 'bootstrap' : 'initial');
    }
    const unsubscribeBootstrapFragments = subscribeToBootstrapFragments(window, (candidate) => {
      authorityEpoch.current += 1;
      clearRenewalTimer();
      void establish(candidate, 'bootstrap');
    });
    return () => {
      mounted.current = false;
      clearRenewalTimer();
      unsubscribe();
      unsubscribeBootstrapFragments();
    };
  }, []);

  useLayoutEffect(() => {
    if (state === 'required' || state === 'error') {
      tokenInput.current?.focus({ preventScroll: true });
    }
  }, [state]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (token.trim()) {
      await establish(token.trim());
    }
  }

  if (state === 'ready') {
    return (
      <>
        {inviteWarning ? (
          <div className="auth-invite-warning" role="status">
            <span>{inviteWarning}</span>
            <button
              type="button"
              aria-label="Dismiss browser invitation warning"
              onClick={() => setInviteWarning(null)}
            >
              <X size={16} />
            </button>
          </div>
        ) : null}
        {children}
      </>
    );
  }

  if (state === 'checking') {
    return (
      <main className="auth-shell">
        <section className="auth-panel" aria-live="polite" aria-busy="true">
          <div className="auth-mark" aria-hidden="true"><Shield size={28} /></div>
          <p className="eyebrow">LOCAL CONTROL PLANE</p>
          <h1>{activeAttempt === 'bootstrap' ? 'Connecting this browser' : 'Checking this browser'}</h1>
          <p className="auth-status" role="status">{message}</p>
        </section>
      </main>
    );
  }

  if (state === 'recovering') {
    return (
      <main className="auth-shell">
        <section className="auth-panel" aria-live="polite">
          <div className="auth-mark" aria-hidden="true"><Shield size={28} /></div>
          <p className="eyebrow">LOCAL CONTROL PLANE</p>
          <h1>Reconnecting to CodeSecurity</h1>
          <p className="auth-status" role="status">{message}</p>
          <button type="button" onClick={() => void establish(undefined, 'retry')}>
            <RefreshCw size={16} /> Retry connection
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="auth-shell">
      <section className="auth-panel" aria-live="polite">
        <div className="auth-mark" aria-hidden="true"><Shield size={28} /></div>
        <p className="eyebrow">LOCAL CONTROL PLANE</p>
        <h1>Pair this browser</h1>
        <p>Generate a one-time browser pairing key from CodeSecurity Settings in an already paired browser. It never belongs in a query string, log, or saved browser profile.</p>
        {state === 'required' ? <p className="auth-status" role="status">{message}</p> : null}
        <BrowserPairingForm
          token={token}
          inputRef={tokenInput}
          onTokenChange={setToken}
          onSubmit={submit}
        />
        {state === 'error' ? <p className="auth-status error" role="alert">{message}</p> : null}
        <details className="auth-help">
          <summary>Installation-owner recovery</summary>
          <p>
            If no paired browser remains, recover access from the CodeSecurity checkout with <code>make auth-info</code>.
            If that one-time owner value was consumed or exposed, run <code>make auth-reset</code>, then <code>make up</code> and <code>make auth-info</code>.
          </p>
        </details>
      </section>
    </main>
  );
}
