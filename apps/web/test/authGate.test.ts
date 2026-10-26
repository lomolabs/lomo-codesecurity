import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';


test('browser pairing is rendered as an obscured one-time code rather than a saved password', async (context) => {
  const webRoot = fileURLToPath(new URL('..', import.meta.url));
  const vite = await createServer({
    root: webRoot,
    configFile: false,
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true },
  });
  context.after(async () => {
    await vite.close();
  });

  const module = await vite.ssrLoadModule('/src/AuthGate.tsx') as typeof import('../src/AuthGate.tsx');
  const markup = renderToStaticMarkup(createElement(module.BrowserPairingForm, {
    token: '',
    onTokenChange: () => undefined,
    onSubmit: () => undefined,
  }));

  assert.match(markup, /<form[^>]*autoComplete="off"/u);
  assert.match(markup, /<input[^>]*name="one-time-code"/u);
  assert.match(markup, /<input[^>]*type="password"/u);
  assert.match(markup, /<input[^>]*autoComplete="one-time-code"/u);
  assert.match(markup, /Add this browser<\/button>/u);
  assert.doesNotMatch(markup, /autoComplete="(?:current-password|new-password)"/u);
});
