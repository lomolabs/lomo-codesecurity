import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

import { normalizeTextEntryValue } from '../src/textEntry.ts';


test('lifecycle reason normalization trims valid text and rejects unsafe bounds', () => {
  assert.deepEqual(normalizeTextEntryValue('  bounded QA reason  ', 500), {
    ok: true,
    value: 'bounded QA reason',
  });
  assert.deepEqual(normalizeTextEntryValue('   ', 500), {
    ok: false,
    reason: 'required',
  });
  assert.equal(normalizeTextEntryValue('x'.repeat(500), 500).ok, true);
  assert.deepEqual(normalizeTextEntryValue('x'.repeat(501), 500), {
    ok: false,
    reason: 'too-long',
  });
});

test('lifecycle reasons use the shared accessible in-app text-entry dialog', async (context) => {
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

  const module = await vite.ssrLoadModule('/src/ConfirmationDialog.tsx') as typeof import('../src/ConfirmationDialog.tsx');
  const markup = renderToStaticMarkup(createElement(module.TextEntryDialog, {
    request: {
      id: 1,
      title: 'Reason required: non-blocking for gate',
      message: 'This audit reason is stored only in the local CodeSecurity database.',
      label: 'Local audit reason',
      submitLabel: 'Mark non-blocking for gate',
      cancelLabel: 'Keep unchanged',
      maxLength: 500,
      required: true,
      tone: 'warning',
    },
    onCancel: () => undefined,
    onSubmit: () => undefined,
  }));

  assert.match(markup, /<dialog[^>]*aria-describedby=/u);
  assert.match(markup, /<dialog[^>]*aria-labelledby=/u);
  assert.match(markup, /<label[^>]*>Local audit reason<\/label>/u);
  assert.match(markup, /<textarea[^>]*maxLength="500"/u);
  assert.match(markup, />Keep unchanged<\/button>/u);
  assert.match(markup, />Mark non-blocking for gate<\/button>/u);
  assert.match(markup, /0 \/ 500 characters/u);

  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  assert.doesNotMatch(appSource, /window\.prompt\s*\(/u);
  assert.match(appSource, /await collectLifecycleReason\(/u);
});
