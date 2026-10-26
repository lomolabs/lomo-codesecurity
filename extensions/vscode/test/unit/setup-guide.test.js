const assert = require('node:assert/strict');
const test = require('node:test');
const { SetupGuide, setupGuideSteps } = require('../../dist/setup-guide.js');
const manifest = require('../../package.json');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture(run = async () => {}) {
  const panels = [], calls = [], notes = [], errors = [];
  const guide = new SetupGuide(() => manifest, {
    create() {
      const messages = [], listeners = new Map();
      const subscribe = (key, listener) => { listeners.set(key, listener); return { dispose: () => listeners.delete(key) }; };
      const panel = {
        visible: true, disposed: false, reveals: 0, messages, listeners,
        reveal() { this.reveals++; this.visible = true; },
        dispose() { this.disposed = true; listeners.get('dispose')?.(); },
        onDidDispose: listener => subscribe('dispose', listener),
        onDidChangeViewState: listener => subscribe('visible', listener),
        webview: { html: '', postMessage: async message => { messages.push(message); return true; },
          onDidReceiveMessage: listener => subscribe('message', listener) },
        message: value => listeners.get('message')?.(value),
      };
      panels.push(panel); return panel;
    },
    run: async command => { calls.push(command); return run(command); },
    notes: async step => { notes.push(step); }, error: () => errors.push('handled'),
  });
  return { guide, panels, calls, notes, errors };
}

test('six setup steps and permitted actions come from the shipped contribution', () => {
  const rows = setupGuideSteps(manifest);
  assert.deepEqual(rows.map(row => row.id), ['backend', 'connection', 'repositories', 'scan', 'review', 'protection']);
  assert(rows.every(row => row.actions.length > 0 && !row.description.includes('command:')));
  for (const change of [
    data => data.contributes.walkthroughs[0].steps.pop(),
    data => data.contributes.walkthroughs[0].steps[0].media.markdown = '../../credentials',
    data => data.contributes.walkthroughs[0].steps[0].description = '[Run](command:workbench.action.terminal.new)',
    data => data.contributes.walkthroughs[0].steps[0].description = '[Run](command:lomoCodeSecurity.pair?payload)',
  ]) {
    const data = structuredClone(manifest); change(data); assert.throws(() => setupGuideSteps(data));
  }
});

test('opening reuses one lazy panel and never executes an action or marks progress', () => {
  const f = fixture(); assert.equal(f.panels.length, 0);
  f.guide.show(); f.guide.show();
  assert.equal(f.panels.length, 1); assert.equal(f.panels[0].reveals, 1);
  assert.deepEqual(f.calls, []); assert.deepEqual(f.notes, []);
  f.panels[0].message({ type: 'ready' });
  assert(Object.values(f.panels[0].messages.at(-1).steps).every(value => value === false));
  const html = f.panels[0].webview.html;
  assert.equal((html.match(/<section /g) || []).length, 6);
  assert.match(html, /default-src 'none'/); assert.match(html, /base-uri 'none'/);
  assert.equal((html.match(/nonce="[a-f0-9]{32}"/g) || []).length, 2);
  assert(!html.includes('http://')); assert(!html.includes('https://')); assert(!html.includes('<iframe'));
  f.guide.dispose(); assert.equal(f.panels[0].disposed, true); assert.equal(f.panels[0].listeners.size, 0);
});

test('actions invoke only their guarded command and notes use an exact packaged step', async () => {
  const f = fixture(); f.guide.show(); const panel = f.panels[0];
  for (const row of setupGuideSteps(manifest)) {
    for (const [index, action] of row.actions.entries()) {
      panel.message({ type: 'action', id: `${row.id}:${index}` }); await tick();
      assert.equal(f.calls.at(-1), action.command);
      assert(Object.values(panel.messages.at(-1).steps).every(value => value === false), 'clicks are not completion');
    }
    panel.message({ type: 'action', id: `${row.id}:notes` }); await tick();
    assert.equal(f.notes.at(-1), row.id);
  }
  f.guide.dispose();
});

test('malformed, arbitrary-command, hidden and disposed messages cannot execute', async () => {
  const f = fixture(); f.guide.show(); const p = f.panels[0];
  for (const message of [null, [], 'backend:0', { type: 'action', id: 'terminal:0' },
    { type: 'action', id: 'backend:0', args: ['/private'] }, { type: 'command', command: 'workbench.action.terminal.new' }]) p.message(message);
  p.visible = false; p.message({ type: 'action', id: 'backend:0' });
  p.visible = true; p.message({ type: 'action', id: 'backend:0' }); f.guide.dispose(); await tick();
  assert.deepEqual(f.calls, []); assert.deepEqual(f.notes, []); assert.deepEqual(f.errors, []);
});

test('progress updates preserve the document and ignore unrelated context keys', () => {
  const f = fixture(); f.guide.show(); const p = f.panels[0], html = p.webview.html;
  f.guide.update('lomoCodeSecurity.setup.backend', true);
  f.guide.update('lomoCodeSecurity.setup.authority', true);
  f.guide.update('other.setup.scan', true);
  assert.equal(p.messages.at(-1).steps.backend, true); assert.equal(p.messages.at(-1).steps.scan, false);
  assert.equal(Object.keys(p.messages.at(-1).steps).length, 6); assert.equal(p.webview.html, html);
  f.guide.dispose();
});

test('busy commands reject double dispatch, handle failure and ignore late completion after close', async () => {
  let reject; const pending = new Promise((_resolve, fail) => { reject = fail; });
  const f = fixture(() => pending); f.guide.show(); const p = f.panels[0];
  p.message({ type: 'action', id: 'protection:0' }); p.message({ type: 'action', id: 'scan:1' });
  await tick(); assert.equal(f.calls.length, 1); assert.equal(p.messages.at(-1).busy, true);
  p.dispose(); const count = p.messages.length; reject(new Error('private error must not appear in the page')); await tick();
  assert.equal(p.messages.length, count); assert.deepEqual(f.errors, []);
  f.guide.show(); assert.equal(f.panels.length, 2); f.guide.dispose();
});

test('manifest prose is escaped and cannot introduce active markup', () => {
  const data = structuredClone(manifest); data.contributes.walkthroughs[0].steps[0].title = '<img src=x onerror=alert(1)>';
  const f = fixture(); const host = { create: () => { f.guide.show(); return f.panels[0]; }, run: async () => {}, notes: async () => {}, error() {} };
  const guide = new SetupGuide(() => data, host); guide.show();
  assert(f.panels[0].webview.html.includes('&lt;img')); assert(!f.panels[0].webview.html.includes('<img'));
  guide.dispose(); f.guide.dispose();
});

test('closing and reopening cannot duplicate a still-running setup action', async () => {
  let finish; const pending = new Promise(resolve => { finish = resolve; });
  const f = fixture(() => pending); f.guide.show();
  f.panels[0].message({ type: 'action', id: 'protection:0' }); await tick();
  f.panels[0].dispose(); f.guide.show(); const reopened = f.panels[1];
  reopened.message({ type: 'ready' }); assert.equal(reopened.messages.at(-1).busy, true);
  reopened.message({ type: 'action', id: 'scan:1' }); await tick(); assert.equal(f.calls.length, 1);
  finish(); await tick(); assert.equal(reopened.messages.at(-1).busy, false);
  reopened.message({ type: 'action', id: 'scan:1' }); await tick(); assert.equal(f.calls.length, 2);
  f.guide.dispose();
});
