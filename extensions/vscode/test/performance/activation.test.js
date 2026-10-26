const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const Module = require('node:module');
const { resolve } = require('node:path');
const { performance } = require('node:perf_hooks');
const test = require('node:test');

const manifest = JSON.parse(readFileSync(resolve(__dirname, '..', '..', 'package.json'), 'utf8'));
const contributedCommandIds = manifest.contributes.commands.map(({ command }) => command);
const contributedCommandSet = new Set(contributedCommandIds);

test('production activation stays below 100 ms p95 with no fetch or workspace file enumeration', async (context) => {
  const originalLoad = Module._load;
  const originalFetch = globalThis.fetch;
  const originalSetInterval = globalThis.setInterval;
  let fetches = 0;
  let intervals = 0;
  let workspaceFolderReads = 0;
  let workspaceFileReads = 0;
  let configurationReads = 0;
  const registrations = [];
  const registrationBatches = [];
  const ownedDisposables = [];
  const disposable = () => {
    const value = { disposed: false, dispose() { this.disposed = true; } };
    ownedDisposables.push(value);
    return value;
  };
  const fakeVscode = {
    ExtensionMode: { Production: 1, Development: 2, Test: 3 },
    env: { appName: 'VS Code', remoteName: undefined },
    languages: {
      createDiagnosticCollection: () => {
        const collection = disposable();
        collection.clear = () => {};
        return collection;
      },
    },
    commands: {
      async executeCommand(name, key, value) {
        assert.equal(name, 'setContext', 'activation only publishes onboarding context');
        assert.match(key, /^lomoCodeSecurity\.setup\./);
        assert.equal(typeof value, 'boolean');
      },
      registerCommand(name) {
        registrations.push(name);
        return disposable();
      },
    },
    window: {
      onDidChangeVisibleTextEditors: () => disposable(),
    },
    workspace: {
      get workspaceFolders() {
        workspaceFolderReads += 1;
        return [];
      },
      getConfiguration() {
        configurationReads += 1;
        return { get: () => undefined };
      },
      findFiles() {
        workspaceFileReads += 1;
        throw new Error('activation must not enumerate workspace files');
      },
      onDidChangeConfiguration: () => disposable(),
      onDidChangeTextDocument: () => disposable(),
      onDidRenameFiles: () => disposable(),
      onDidDeleteFiles: () => disposable(),
      onDidOpenTextDocument: () => disposable(),
      onDidCloseTextDocument: () => disposable(),
      onDidGrantWorkspaceTrust: () => disposable(),
      onDidChangeWorkspaceFolders: () => disposable(),
    },
  };
  Module._load = function load(request, parent, isMain) {
    return request === 'vscode' ? fakeVscode : originalLoad.call(this, request, parent, isMain);
  };
  globalThis.fetch = async () => {
    fetches += 1;
    throw new Error('activation must not fetch');
  };
  globalThis.setInterval = (...arguments_) => {
    intervals += 1;
    return originalSetInterval(...arguments_);
  };

  const extensionPath = require.resolve('../../dist/extension.js');
  const durations = [];
  try {
    for (let sample = 0; sample < 30; sample += 1) {
      delete require.cache[extensionPath];
      const started = performance.now();
      const extension = require(extensionPath);
      const subscriptions = [];
      const registrationStart = registrations.length;
      extension.activate({
        extensionMode: fakeVscode.ExtensionMode.Production,
        globalStorageUri: {
          fsPath: resolve(__dirname, '..', '..', '.activation-test-storage'),
          toString: () => 'file:///activation-test-storage',
        },
        secrets: { delete: async () => {}, get: async () => undefined, store: async () => {} },
        workspaceState: { get: () => undefined, update: async () => {} },
        subscriptions,
      });
      registrationBatches.push(registrations.slice(registrationStart));
      durations.push(performance.now() - started);
      extension.deactivate();
      await Promise.resolve(); // Settle the fenced repository-recovery continuation.
      for (const subscription of subscriptions) subscription.dispose();
    }
  } finally {
    delete require.cache[extensionPath];
    Module._load = originalLoad;
    globalThis.fetch = originalFetch;
    globalThis.setInterval = originalSetInterval;
  }

  durations.sort((left, right) => left - right);
  const p95 = durations[Math.ceil(durations.length * 0.95) - 1];
  context.diagnostic(`30-sample activation p95: ${p95.toFixed(2)} ms`);
  context.diagnostic(`30-sample configuration reads: ${configurationReads}`);
  context.diagnostic(`30-sample workspace-folder metadata reads: ${workspaceFolderReads}`);
  assert.equal(fetches, 0);
  assert.equal(intervals, 0, 'activation must not start fixed idle polling');
  assert.equal(workspaceFileReads, 0);
  assert.equal(workspaceFolderReads, 0, 'activation defers workspace metadata until repository recovery settles');
  assert.equal(configurationReads, 0, 'deactivation fences deferred startup endpoint reads');
  assert.equal(registrationBatches.length, 30);
  const firstRegistrationBatch = registrationBatches[0];
  for (const batch of registrationBatches) {
    assert.deepEqual(batch, firstRegistrationBatch, 'every activation must register the same command surface');
    assert.equal(new Set(batch).size, batch.length, 'one activation must not register a command twice');
    assert.deepEqual(
      batch.filter((command) => contributedCommandSet.has(command)).sort(),
      [...contributedCommandIds].sort(),
      'one activation must register every manifest-contributed command exactly once',
    );
    assert.equal(
      batch.every((command) => contributedCommandSet.has(command) || command.startsWith('lomoCodeSecurity.quickFix.')),
      true,
      'non-contributed activation commands are restricted to the bounded inline Quick Fix adapter',
    );
  }
  assert.equal(ownedDisposables.every(({ disposed }) => disposed), true);
  assert(p95 <= 100, `activation p95 ${p95.toFixed(2)} ms exceeds 100 ms`);
});
