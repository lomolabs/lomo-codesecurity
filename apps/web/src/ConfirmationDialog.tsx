import { AlertTriangle } from 'lucide-react';
import {
  ReactNode,
  createContext,
  useCallback,
  useContext,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';
import './confirmation-dialog.css';
import { normalizeTextEntryValue } from './textEntry';

export type ConfirmationRequest = Readonly<{
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
  tone?: 'danger' | 'warning';
}>;

export type RequestConfirmation = (request: ConfirmationRequest) => Promise<boolean>;

export type TextEntryRequest = Readonly<{
  title: string;
  message: string;
  label: string;
  submitLabel: string;
  cancelLabel: string;
  maxLength: number;
  required?: boolean;
  initialValue?: string;
  tone?: 'danger' | 'warning';
}>;

export type RequestTextEntry = (request: TextEntryRequest) => Promise<string | null>;

type PendingConfirmation = ConfirmationRequest & Readonly<{ id: number }>;
export type PendingTextEntry = TextEntryRequest & Readonly<{ id: number }>;

const ConfirmationContext = createContext<RequestConfirmation | null>(null);
const TextEntryContext = createContext<RequestTextEntry | null>(null);

export function ConfirmationProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirmation | null>(null);
  const [pendingTextEntry, setPendingTextEntry] = useState<PendingTextEntry | null>(null);
  const sequenceRef = useRef(0);
  const resolverRef = useRef<((confirmed: boolean) => void) | null>(null);
  const textEntryResolverRef = useRef<((value: string | null) => void) | null>(null);

  const interactionOpen = useCallback(() => (
    Boolean(resolverRef.current) || Boolean(textEntryResolverRef.current)
  ), []);

  const settle = useCallback((confirmed: boolean) => {
    const resolve = resolverRef.current;
    if (!resolve) return;
    resolverRef.current = null;
    setPending(null);
    resolve(confirmed);
  }, []);

  const requestConfirmation = useCallback<RequestConfirmation>((request) => {
    if (interactionOpen()) {
      return Promise.reject(new Error('A confirmation or text entry is already open. Finish it before starting another action.'));
    }
    return new Promise<boolean>((resolve) => {
      resolverRef.current = resolve;
      sequenceRef.current += 1;
      setPending({ ...request, id: sequenceRef.current });
    });
  }, [interactionOpen]);

  const settleTextEntry = useCallback((value: string | null) => {
    const resolve = textEntryResolverRef.current;
    if (!resolve) return;
    textEntryResolverRef.current = null;
    setPendingTextEntry(null);
    resolve(value);
  }, []);

  const requestTextEntry = useCallback<RequestTextEntry>((request) => {
    if (interactionOpen()) {
      return Promise.reject(new Error('A confirmation or text entry is already open. Finish it before starting another action.'));
    }
    return new Promise<string | null>((resolve) => {
      textEntryResolverRef.current = resolve;
      sequenceRef.current += 1;
      setPendingTextEntry({ ...request, id: sequenceRef.current });
    });
  }, [interactionOpen]);

  useLayoutEffect(() => {
    return () => {
      resolverRef.current?.(false);
      resolverRef.current = null;
      textEntryResolverRef.current?.(null);
      textEntryResolverRef.current = null;
    };
  }, []);

  return (
    <ConfirmationContext.Provider value={requestConfirmation}>
      <TextEntryContext.Provider value={requestTextEntry}>
        {children}
        {pending ? (
          <ConfirmationDialog
            confirmation={pending}
            onCancel={() => settle(false)}
            onConfirm={() => settle(true)}
          />
        ) : null}
        {pendingTextEntry ? (
          <TextEntryDialog
            request={pendingTextEntry}
            onCancel={() => settleTextEntry(null)}
            onSubmit={settleTextEntry}
          />
        ) : null}
      </TextEntryContext.Provider>
    </ConfirmationContext.Provider>
  );
}

export function useConfirmation(): RequestConfirmation {
  const confirmation = useContext(ConfirmationContext);
  if (!confirmation) throw new Error('useConfirmation must be used inside ConfirmationProvider.');
  return confirmation;
}

export function useTextEntry(): RequestTextEntry {
  const textEntry = useContext(TextEntryContext);
  if (!textEntry) throw new Error('useTextEntry must be used inside ConfirmationProvider.');
  return textEntry;
}

function ConfirmationDialog({
  confirmation,
  onCancel,
  onConfirm,
}: {
  confirmation: PendingConfirmation;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!dialog) return undefined;
    dialog.showModal();
    cancelRef.current?.focus({ preventScroll: true });
    return () => {
      if (dialog.open) dialog.close();
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [confirmation.id]);

  return (
    <dialog
      ref={dialogRef}
      aria-describedby={descriptionId}
      aria-labelledby={titleId}
      className={`confirmation-dialog confirmation-dialog-${confirmation.tone || 'warning'}`}
      onKeyDown={(event) => {
        if (event.key !== 'Escape' || event.nativeEvent.isComposing) return;
        event.preventDefault();
        event.stopPropagation();
        onCancel();
      }}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <div className="confirmation-dialog-head">
        <div>
          <span className="section-subtitle">Review consequence</span>
          <h2 id={titleId}>{confirmation.title}</h2>
        </div>
        <AlertTriangle size={24} aria-hidden="true" />
      </div>
      <p id={descriptionId}>{confirmation.message}</p>
      <div className="confirmation-dialog-actions">
        <button
          ref={cancelRef}
          type="button"
          className="secondary-action"
          onClick={onCancel}
        >
          {confirmation.cancelLabel}
        </button>
        <button
          type="button"
          className={confirmation.tone === 'danger' ? 'danger-action' : undefined}
          onClick={onConfirm}
        >
          {confirmation.confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

export function TextEntryDialog({
  request,
  onCancel,
  onSubmit,
}: {
  request: PendingTextEntry;
  onCancel: () => void;
  onSubmit: (value: string) => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const fieldRef = useRef<HTMLTextAreaElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  const fieldId = useId();
  const countId = useId();
  const errorId = useId();
  const [value, setValue] = useState(request.initialValue || '');
  const [validationError, setValidationError] = useState<string | null>(null);

  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!dialog) return undefined;
    dialog.showModal();
    fieldRef.current?.focus({ preventScroll: true });
    return () => {
      if (dialog.open) dialog.close();
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [request.id]);

  useLayoutEffect(() => {
    if (!validationError) return;
    const focused = document.activeElement;
    if (focused instanceof HTMLElement && dialogRef.current?.contains(focused)) {
      focused.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
    }
  }, [validationError]);

  const submit = () => {
    const normalized = normalizeTextEntryValue(value, request.maxLength, request.required !== false);
    if (!normalized.ok) {
      setValidationError(normalized.reason === 'required'
        ? `${request.label} is required. No change was made.`
        : `${request.label} must be at most ${request.maxLength} characters. No change was made.`);
      return;
    }
    onSubmit(normalized.value);
  };

  const describedBy = [descriptionId, countId, validationError ? errorId : null]
    .filter(Boolean)
    .join(' ');

  return (
    <dialog
      ref={dialogRef}
      aria-describedby={descriptionId}
      aria-labelledby={titleId}
      className={`confirmation-dialog confirmation-dialog-${request.tone || 'warning'}`}
      onKeyDown={(event) => {
        if (event.key !== 'Escape' || event.nativeEvent.isComposing) return;
        event.preventDefault();
        event.stopPropagation();
        onCancel();
      }}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <div className="confirmation-dialog-head">
        <div>
          <span className="section-subtitle">Local audit record</span>
          <h2 id={titleId}>{request.title}</h2>
        </div>
        <AlertTriangle size={24} aria-hidden="true" />
      </div>
      <p id={descriptionId}>{request.message}</p>
      <form
        className="confirmation-dialog-form"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <label htmlFor={fieldId}>{request.label}</label>
        <textarea
          ref={fieldRef}
          id={fieldId}
          aria-describedby={describedBy}
          aria-invalid={validationError ? true : undefined}
          maxLength={request.maxLength}
          rows={4}
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            if (validationError) setValidationError(null);
          }}
        />
        <div id={countId} className="confirmation-dialog-count">
          {value.length} / {request.maxLength} characters
        </div>
        {validationError ? (
          <div id={errorId} className="confirmation-dialog-error" role="alert">
            {validationError}
          </div>
        ) : null}
        <div className="confirmation-dialog-actions">
          <button type="button" className="secondary-action" onClick={onCancel}>
            {request.cancelLabel}
          </button>
          <button type="submit" className={request.tone === 'danger' ? 'danger-action' : undefined}>
            {request.submitLabel}
          </button>
        </div>
      </form>
    </dialog>
  );
}
