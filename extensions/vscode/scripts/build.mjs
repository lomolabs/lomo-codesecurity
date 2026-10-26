import { rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build, context, formatMessages, stop } from 'esbuild-wasm';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDirectory, '..');
const outputDirectory = resolve(extensionRoot, 'dist');
const watch = process.argv.slice(2).includes('--watch');

await rm(outputDirectory, { force: true, recursive: true });

const options = {
  absWorkingDir: extensionRoot,
  bundle: true,
  format: 'cjs',
  legalComments: 'none',
  // The WASM executable rewrites fs.writeSync. When stderr is a regular
  // file, Node's SyncWriteStream calls that override recursively. Report
  // diagnostics from this parent process instead; warnings/errors still
  // reach redirected logs and failed builds retain their nonzero outcome.
  logLevel: 'silent',
  plugins: [{
    name: 'build-diagnostics',
    setup(builder) {
      builder.onEnd(async (result) => {
        for (const [kind, messages] of [['error', result.errors], ['warning', result.warnings]]) {
          if (messages.length === 0) continue;
          const formatted = await formatMessages(messages, {
            kind,
            color: Boolean(process.stderr.isTTY) && !('NO_COLOR' in process.env),
          });
          for (const message of formatted) process.stderr.write(message);
        }
        if (result.errors.length === 0) console.log(`Built ${builder.initialOptions.outfile}`);
      });
    },
  }],
  minify: true,
  platform: 'node',
  sourcemap: false,
  target: 'node20',
};

const targets = [
  { ...options, entryPoints: ['src/extension.ts'], external: ['vscode'], outfile: 'dist/extension.js' },
  // A Git hook must work without an editor process. No VS Code API import may
  // remain external here; esbuild must resolve everything except Node builtins.
  { ...options, entryPoints: ['src/git-push-cli.ts'], outfile: 'dist/git-push-cli.js' },
];

if (watch) {
  const buildContexts = await Promise.all(targets.map((target) => context(target)));
  await Promise.all(buildContexts.map((buildContext) => buildContext.watch()));
  process.on('SIGINT', async () => {
    await Promise.all(buildContexts.map((buildContext) => buildContext.dispose()));
    await stop();
    process.exit(130);
  });
} else {
  try {
    await Promise.all(targets.map((target) => build(target)));
  } finally {
    await stop();
  }
}
