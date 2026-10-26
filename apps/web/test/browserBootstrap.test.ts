import assert from 'node:assert/strict';
import test from 'node:test';

import {
  consumeBootstrapFragment,
  type BrowserBootstrapWindow,
  subscribeToBootstrapFragments,
} from '../src/browserBootstrap.ts';


function fakeBrowser() {
  const listeners = new Set<() => void>();
  const replacements: string[] = [];
  const browser: BrowserBootstrapWindow = {
    location: {
      hash: '',
      pathname: '/settings',
      search: '?screen=pairing',
    },
    history: {
      replaceState: (_data, _unused, url) => replacements.push(String(url)),
    },
    addEventListener: (_type, listener) => listeners.add(listener),
    removeEventListener: (_type, listener) => listeners.delete(listener),
  };
  return {
    browser,
    replacements,
    dispatchHashChange: () => listeners.forEach((listener) => listener()),
    listenerCount: () => listeners.size,
  };
}


test('a bootstrap fragment is consumed and removed from browser history', () => {
  const fixture = fakeBrowser();
  const browserPairingKey = `kb1.${'a'.repeat(43)}`;
  fixture.browser.location.hash = `#bootstrap=${browserPairingKey}`;

  assert.equal(
    consumeBootstrapFragment(fixture.browser.location, fixture.browser.history),
    browserPairingKey,
  );
  assert.deepEqual(fixture.replacements, ['/settings?screen=pairing']);
});


test('a safe dashboard destination survives while the invitation secret is removed', () => {
  const fixture = fakeBrowser();
  const browserPairingKey = `kbi1.${'a'.repeat(24)}.${'b'.repeat(43)}`;
  fixture.browser.location.hash = `#bootstrap=${browserPairingKey}&destination=advisor-providers`;

  assert.equal(
    consumeBootstrapFragment(fixture.browser.location, fixture.browser.history),
    browserPairingKey,
  );
  assert.deepEqual(fixture.replacements, ['/settings?screen=pairing#advisor-providers']);
  assert.doesNotMatch(fixture.replacements[0], /kbi1|bootstrap/u);
});


test('the IDE approval destination survives while the invitation secret is removed', () => {
  const fixture = fakeBrowser();
  const browserPairingKey = `kbi1.${'a'.repeat(24)}.${'b'.repeat(43)}`;
  fixture.browser.location.hash = `#bootstrap=${browserPairingKey}&destination=ide-access`;

  assert.equal(
    consumeBootstrapFragment(fixture.browser.location, fixture.browser.history),
    browserPairingKey,
  );
  assert.deepEqual(fixture.replacements, ['/settings?screen=pairing#ide-access']);
  assert.doesNotMatch(fixture.replacements[0], /kbi1|bootstrap/u);
});


test('an exact Projects source suggestion survives first pairing without retaining the invitation', () => {
  for (const path of ['/private/my service/Žluťoučký', `/${'a'.repeat(511)}`]) {
    const fixture = fakeBrowser();
    const token = `kbi1.${'a'.repeat(24)}.${'b'.repeat(43)}`;
    const encoded = Buffer.from(path, 'utf8').toString('base64url');
    fixture.browser.location.pathname = '/';
    fixture.browser.location.search = '?view=projects&setup=source&lomo_browser=vscode';
    fixture.browser.location.hash = `#${new URLSearchParams({ bootstrap: token, destination: `source=${encoded}` })}`;

    assert.equal(consumeBootstrapFragment(fixture.browser.location, fixture.browser.history), token);
    assert.deepEqual(fixture.replacements, [`/?view=projects&setup=source&lomo_browser=vscode#source=${encoded}`]);
    assert.doesNotMatch(fixture.replacements[0], /kbi1|bootstrap/u);
    const destination = new URL(fixture.replacements[0], 'http://127.0.0.1:8080');
    assert.equal(destination.searchParams.has('source'), false);
    assert.equal(Buffer.from(new URLSearchParams(destination.hash.slice(1)).get('source')!, 'base64url').toString('utf8'), path);
  }
});


test('source suggestions reject malformed payloads and ambiguous routes while still removing bootstrap', () => {
  const encoded = Buffer.from('/selected/service', 'utf8').toString('base64url');
  const exactSearch = '?view=projects&setup=source';
  const cases: Array<{
    label: string;
    search?: string;
    pathname?: string;
    destination?: string;
    duplicateDestination?: boolean;
  }> = [
    { label: 'wrong view', search: '?view=settings&setup=source' },
    { label: 'missing setup', search: '?view=projects' },
    { label: 'wrong setup', search: '?view=projects&setup=advisor' },
    { label: 'duplicate view', search: '?view=projects&view=projects&setup=source' },
    { label: 'duplicate setup', search: '?view=projects&setup=source&setup=source' },
    { label: 'conflicting scan', search: `${exactSearch}&scan=41` },
    { label: 'conflicting finding', search: `${exactSearch}&finding=1` },
    { label: 'query source', search: `${exactSearch}&source=${encoded}` },
    { label: 'wrong path', pathname: '/settings' },
    { label: 'duplicate destination', duplicateDestination: true },
    { label: 'duplicate source', destination: `source=${encoded}&source=${encoded}` },
    { label: 'extra destination field', destination: `source=${encoded}&view=settings` },
    { label: 'empty source', destination: 'source=' },
    { label: 'padded base64', destination: 'source=L2E=' },
    { label: 'noncanonical pad bits', destination: 'source=L2F' },
    { label: 'invalid base64 length', destination: 'source=a' },
    { label: 'invalid UTF-8', destination: `source=${Buffer.from([47, 255]).toString('base64url')}` },
    ...[
      ['relative path', 'selected/service'],
      ['Windows drive', 'C:\\selected\\service'],
      ['UNC path', '//server/share'],
      ['leading whitespace', ' /selected/service'],
      ['trailing whitespace', '/selected/service '],
      ['control', '/selected/unsafe\u0000path'],
      ['format character', '/selected/unsafe\u202epath'],
      ['byte order mark', '\ufeff/selected/service'],
      ['UTF-8 byte limit', `/${'é'.repeat(256)}`],
      ['encoded length limit', `/${'a'.repeat(512)}`],
    ].map(([label, path]) => ({ label, destination: `source=${Buffer.from(path, 'utf8').toString('base64url')}` })),
  ];
  for (const candidate of cases) {
    const fixture = fakeBrowser();
    const token = `kbi1.${'a'.repeat(24)}.${'b'.repeat(43)}`;
    fixture.browser.location.pathname = candidate.pathname ?? '/';
    fixture.browser.location.search = candidate.search ?? exactSearch;
    const fragment = new URLSearchParams({
      bootstrap: token,
      destination: candidate.destination ?? `source=${encoded}`,
    });
    if (candidate.duplicateDestination) fragment.append('destination', `source=${encoded}`);
    fixture.browser.location.hash = `#${fragment}`;

    assert.equal(consumeBootstrapFragment(fixture.browser.location, fixture.browser.history), token, candidate.label);
    assert.deepEqual(fixture.replacements, [fixture.browser.location.pathname + fixture.browser.location.search], candidate.label);
    assert.doesNotMatch(fixture.replacements[0], /kbi1|bootstrap/u, candidate.label);
  }
});


test('same-document bootstrap navigation is delivered once without retaining the secret URL', () => {
  const fixture = fakeBrowser();
  const accepted: string[] = [];
  const unsubscribe = subscribeToBootstrapFragments(fixture.browser, (token) => accepted.push(token));

  fixture.browser.location.hash = '#bootstrap=fresh-value';
  fixture.dispatchHashChange();

  assert.deepEqual(accepted, ['fresh-value']);
  assert.deepEqual(fixture.replacements, ['/settings?screen=pairing']);
  assert.equal(fixture.listenerCount(), 1);

  unsubscribe();
  assert.equal(fixture.listenerCount(), 0);
});


test('unrelated fragments are neither delivered nor removed', () => {
  const fixture = fakeBrowser();
  const accepted: string[] = [];
  const unsubscribe = subscribeToBootstrapFragments(fixture.browser, (token) => accepted.push(token));

  fixture.browser.location.hash = '#source-boundary';
  fixture.dispatchHashChange();

  assert.deepEqual(accepted, []);
  assert.deepEqual(fixture.replacements, []);
  unsubscribe();
});
