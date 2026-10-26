export interface BrowserBootstrapLocation {
  hash: string;
  pathname: string;
  search: string;
}


export interface BrowserBootstrapHistory {
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}


export interface BrowserBootstrapWindow {
  location: BrowserBootstrapLocation;
  history: BrowserBootstrapHistory;
  addEventListener(type: 'hashchange', listener: () => void): void;
  removeEventListener(type: 'hashchange', listener: () => void): void;
}


function sourceSetupDestination(location: BrowserBootstrapLocation, destination: string | null): string {
  const route = new URLSearchParams(location.search);
  if (location.pathname !== '/'
    || route.getAll('view').length !== 1 || route.get('view') !== 'projects'
    || route.getAll('setup').length !== 1 || route.get('setup') !== 'source'
    || route.has('scan') || route.has('finding') || route.has('source')) return '';
  const match = /^source=([A-Za-z0-9_-]{1,683})$/u.exec(destination || '');
  if (!match) return '';
  const encoded = match[1];
  try {
    const padded = `${encoded}${'='.repeat((4 - encoded.length % 4) % 4)}`;
    const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    if (!binary.length || binary.length > 512
      || btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '') !== encoded) return '';
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const path = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (!path.startsWith('/') || path.startsWith('//') || path !== path.trim()
      || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(path)) return '';
    // Retain only a bounded suggestion on the exact setup route. The host
    // command and fresh source boundary still own authorization and admission.
    return `#source=${encoded}`;
  } catch {
    return '';
  }
}


export function consumeBootstrapFragment(
  location: BrowserBootstrapLocation,
  history: BrowserBootstrapHistory,
): string {
  const fragment = new URLSearchParams(location.hash.replace(/^#/u, ''));
  const token = fragment.get('bootstrap') || '';
  if (token) {
    const destination = fragment.get('destination');
    const retainedDestination = destination === 'source-boundary'
      || destination === 'advisor-providers'
      || destination === 'ide-access'
      ? `#${destination}`
      : fragment.getAll('destination').length === 1
        ? sourceSetupDestination(location, destination)
        : '';
    history.replaceState(
      null,
      '',
      `${location.pathname}${location.search}${retainedDestination}`,
    );
  }
  return token;
}


export function subscribeToBootstrapFragments(
  browser: BrowserBootstrapWindow,
  accept: (token: string) => void,
): () => void {
  const handleHashChange = () => {
    const token = consumeBootstrapFragment(browser.location, browser.history);
    if (token) accept(token);
  };
  browser.addEventListener('hashchange', handleHashChange);
  return () => browser.removeEventListener('hashchange', handleHashChange);
}
