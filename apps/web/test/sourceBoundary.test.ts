import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

import {
  authoritativeSourceRoots,
  commitCurrentSourceBoundaryLoad,
  mountedProjectIsAuthorized,
  projectSourceAdapter,
  projectSourceNavigationDisabledReason,
  resolveSourceBoundaryLoad,
  safeAllowedSourceRoots,
  snapshotProjectScanGuidance,
  sourceAuthorizationCommand,
  sourcePathIsAuthorized,
  summarizeSourceRegistrations,
} from '../src/sourceBoundary.ts';

const installationId = '012345abcdef';


test('source removal uses an exact encoded root without replacing sibling authorizations', () => {
  const root = '/workspace/日本語 space';
  const command = sourceAuthorizationCommand(root, installationId, 'remove');
  assert.equal(command, `KODESEC_EXPECT_INSTALLATION_ID=${installationId} KODESEC_SOURCE_OPERATION=remove KODESEC_SOURCE_ROOT_B64=${Buffer.from(root).toString('base64url')} make apply-source`);
  assert.equal(sourceAuthorizationCommand('/workspace/comma,root', installationId), null);
});

test('source commands require the exact observed installation and source controls have concise labels', () => {
  for (const identity of [undefined, null, '', '012345ABCDEf', 'a'.repeat(13), '$(whoami)', '012345abcdef\n']) {
    assert.equal(sourceAuthorizationCommand('/workspace/source', identity), null);
  }
  assert.match(sourceAuthorizationCommand('/workspace/source', installationId) || '', /^KODESEC_EXPECT_INSTALLATION_ID=012345abcdef /u);
  const component = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(component, /<select aria-label="Source authorization action"/u);
  assert.match(component, /<select aria-label="Source root to remove"/u);
  assert.match(component, /STATE_DIR="\/path\/to\/your\/state"/u);
});

test('source authorization rejects broad macOS aliases while allowing one narrow checkout', () => {
  const broadRoots = [
    '/',
    '/Users',
    '/private/tmp',
    '/System/Volumes/Data',
    '/System/Volumes/Data/Users',
    '/System/Volumes/Data/Volumes',
    '/System/Volumes/Data/private/tmp',
    '/System/Volumes/Data/private/var/tmp',
  ];
  for (const root of broadRoots) {
    assert.equal(sourceAuthorizationCommand(root, installationId), null, root);
  }
  const narrowRoot = '/System/Volumes/Data/Users/operator/src/lomo-demo';
  assert.match(sourceAuthorizationCommand(narrowRoot, installationId) || '', /^KODESEC_EXPECT_INSTALLATION_ID=012345abcdef KODESEC_SOURCE_ROOT_B64=/u);
  assert.deepEqual(
    safeAllowedSourceRoots([...broadRoots, narrowRoot, narrowRoot]),
    [narrowRoot],
  );
});


test('source registration summary distinguishes the authorized subset from every retained registration', () => {
  const summary = summarizeSourceRegistrations([
    { repo_path: '/previous/source/one' },
    { repo_path: '/current/source/project-7' },
    { repo_path: '/previous/source/two' },
    { repo_path: '/current/source/project-8' },
    { repo_path: '/previous/source/three' },
    { repo_path: '/previous/source/four' },
    { repo_path: '/previous/source/five' },
  ], ['/current/source']);

  assert.deepEqual(summary, {
    insideCount: 2,
    outsideCount: 5,
    snapshotCount: 0,
    message: '2 of 7 registered mounted projects are inside the current read-only source boundary. 5 registered mounted projects remain outside this boundary; they stay visible, but Web scanning requires re-authorizing that source or deleting the registration.',
  });
});

test('selected-project source checks do not borrow authorization from another retained project', () => {
  const roots = ['/current/source'];

  assert.equal(sourcePathIsAuthorized('/current/source/project-7', roots), true);
  assert.equal(sourcePathIsAuthorized('/current/source', roots), true);
  assert.equal(sourcePathIsAuthorized('/current/source-sibling/project-8', roots), false);
  assert.equal(sourcePathIsAuthorized('/previous/source/project-9', roots), false);
});

test('only a successfully loaded current configuration can authorize a mounted project', () => {
  const configured = { status: 'ready', roots: ['/current/source'] } as const;
  const loading = { status: 'loading' } as const;
  const failed = {
    status: 'error',
    reason: 'The current source boundary could not be loaded.',
  } as const;

  assert.deepEqual(authoritativeSourceRoots(configured), ['/current/source']);
  assert.deepEqual(authoritativeSourceRoots(loading), []);
  assert.deepEqual(authoritativeSourceRoots(failed), []);
  assert.equal(mountedProjectIsAuthorized('/current/source/project-7', configured), true);
  assert.equal(mountedProjectIsAuthorized('/current/source/project-7', loading), false);
  assert.equal(mountedProjectIsAuthorized('/current/source/project-7', failed), false);
  assert.equal(mountedProjectIsAuthorized('/reported/by/prior-422/project', failed), false);
});

test('native Windows snapshot identities use their reserved adapter and never mounted-root admission', () => {
  const digest = 'a'.repeat(64);
  const snapshot = `/source-snapshots/native-windows/${digest}`;

  assert.equal(projectSourceAdapter(snapshot), 'native_windows_snapshot');
  assert.equal(projectSourceAdapter(`/source-snapshots/native-windows/${'A'.repeat(64)}`), 'mounted_directory');
  assert.equal(projectSourceAdapter('/source-snapshots/native-windows/not-a-digest'), 'mounted_directory');
  assert.equal(mountedProjectIsAuthorized(snapshot, {
    status: 'ready',
    roots: ['/source-snapshots'],
  }), false);
  assert.deepEqual(summarizeSourceRegistrations([
    { repo_path: '/current/source/project-7' },
    { repo_path: snapshot },
  ], ['/current/source']), {
    insideCount: 1,
    outsideCount: 0,
    snapshotCount: 1,
    message: '1 of 1 registered mounted project is inside the current read-only source boundary. 1 native Windows snapshot remains available only through a fresh scan from the exact native VS Code workspace; it is not a mounted source path.',
  });
});

test('immutable Git snapshot projects stay distinct and cannot become mounted scan or authorization targets', () => {
  const snapshot = `/source-snapshots/git-commit/${'b'.repeat(64)}`;
  assert.equal(projectSourceAdapter(snapshot), 'git_commit_snapshot');
  for (const root of [snapshot, '/source-snapshots', '/source-snapshots/git-commit',
    '/source-snapshots/git-commit/not-a-digest', `/tmp/../${snapshot.slice(1)}`]) {
    assert.equal(sourceAuthorizationCommand(root, installationId), null);
    assert.equal(sourceAuthorizationCommand(root, installationId, 'remove'), null);
    assert.equal(sourcePathIsAuthorized(root, [root, '/']), false);
    assert.equal(mountedProjectIsAuthorized(root, { status: 'ready', roots: [root] }), false);
  }
  assert.deepEqual(safeAllowedSourceRoots([snapshot, '/source-snapshots', '/current/source']), ['/current/source']);
  const summary = summarizeSourceRegistrations([{ repo_path: snapshot }], []);
  assert.equal(summary.snapshotCount, 1);
  assert.equal(summary.outsideCount, 0);
  assert.match(summary.message, /immutable Git snapshot project requires Check Outgoing Commits/u);
  assert.doesNotMatch(summary.message, /native Windows|outside this boundary/u);
});

test('mixed Git, Windows and mounted registrations retain separate admission and truthful counts', () => {
  const summary = summarizeSourceRegistrations([
    { repo_path: '/current/source' }, { repo_path: '/outside/source' },
    { repo_path: `/source-snapshots/git-commit/${'b'.repeat(64)}` },
    { repo_path: `/source-snapshots/native-windows/${'c'.repeat(64)}` },
  ], ['/current/source']);
  assert.deepEqual({ inside: summary.insideCount, outside: summary.outsideCount, snapshots: summary.snapshotCount },
    { inside: 1, outside: 1, snapshots: 2 });
  assert.match(summary.message, /1 native Windows snapshot remains/u);
  assert.match(summary.message, /1 immutable Git snapshot project requires/u);
});

test('historical Git source navigation refuses current-file substitution before command admission without hiding evidence', () => {
  const identity = `/source-snapshots/git-commit/${'b'.repeat(64)}`;
  for (const root of [identity, `${identity}/`, `/tmp/../${identity.slice(1)}`, '/source-snapshots/git-commit/not-a-digest']) {
    const reason = projectSourceNavigationDisabledReason(root) || '';
    assert.match(reason, /immutable Git snapshot, not the current checkout/u);
    assert.match(reason, /matching filename could contain different code/u);
    assert.match(reason, /retained finding details and snippet/u);
  }
  assert.equal(projectSourceNavigationDisabledReason('/workspace/current'), null);
  assert.equal(projectSourceNavigationDisabledReason(`/source-snapshots/native-windows/${'c'.repeat(64)}`), null);
  assert.match(projectSourceNavigationDisabledReason(undefined) || '', /Refresh this scan and its project/u);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const admission = app.slice(app.indexOf('const openSourceInIde = useCallback'), app.indexOf('async function onCreateProject'));
  assert.match(admission, /selectedScanSummary\?\.scan.id === finding.scan_id/u);
  assert.match(admission, /project.id === selectedScanSummary.scan.project_id/u);
  assert.match(admission, /if \(sourceReason\) \{[\s\S]*?return;\s*\}/u);
  assert(admission.indexOf('if (sourceReason)') < admission.indexOf('await api.openSourceInIde'));
  assert.match(app, /const unavailableReason = sourceNavigationDisabledReason \|\|/u);
  assert.match(app, /sourceNavigationDisabledReason=\{projectSourceNavigationDisabledReason\(selectedProject\?\.repo_path\)\}/u);
  assert.match(app, /left.sourceNavigationDisabledReason === right.sourceNavigationDisabledReason/u);
  assert.match(app, /\{showEvidence \? \(\s*<FindingEvidence finding=\{finding\}/u);
});

test('snapshot scan guidance names the real contributed Git command and is used by the guarded Web form', () => {
  const manifest = JSON.parse(readFileSync(new URL('../../../extensions/vscode/package.json', import.meta.url), 'utf8'));
  const command = manifest.contributes.commands.find((entry: { command: string }) => entry.command === 'lomoCodeSecurity.checkOutgoingCommits');
  assert(command, 'guidance must name an actually contributed command');
  const guidance = snapshotProjectScanGuidance('git_commit_snapshot') || '';
  assert(guidance.includes(`${command.category}: ${command.title}`));
  assert.match(guidance, /not a mounted checkout/u);
  assert.doesNotMatch(guidance, /native Windows/u);
  assert.match(snapshotProjectScanGuidance('native_windows_snapshot') || '', /native VS Code workspace/u);
  assert.equal(snapshotProjectScanGuidance('mounted_directory'), null);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /const selectedSnapshotGuidance = snapshotProjectScanGuidance\(selectedSourceAdapter\)/u);
  assert.match(app, /if \(!coreServicesReady \|\| !selectedProjectSourceReady\) \{\s*event.preventDefault\(\)/u);
  assert.match(app, /if \(!selectedProject \|\| selectedSourceAdapter !== 'mounted_directory'\) return/u);
  assert.match(app, /selectedProject && selectedSnapshotGuidance \? \(/u);
});

test('source-boundary refresh commits only the latest generation and represents load failure explicitly', async () => {
  const stale = await resolveSourceBoundaryLoad(async () => ({ allowed_roots: ['/stale/root'], installation_id: 'abcdef012345' }));
  const current = await resolveSourceBoundaryLoad(async () => ({ allowed_roots: ['/current/root'], installation_id: installationId }));
  const failed = await resolveSourceBoundaryLoad(async () => { throw new Error('offline'); });
  const committed: unknown[] = [];

  assert.equal(commitCurrentSourceBoundaryLoad(4, 5, stale, (state) => committed.push(state)), false);
  assert.equal(commitCurrentSourceBoundaryLoad(5, 5, current, (state) => committed.push(state)), true);
  assert.deepEqual(committed, [{ status: 'ready', roots: ['/current/root'], installationId }]);
  assert.equal(failed.status, 'error');
  assert.match(failed.status === 'error' ? failed.reason : '', /could not be loaded/u);
  const missingIdentity = await resolveSourceBoundaryLoad(async () => ({ allowed_roots: ['/current/root'], installation_id: null }));
  assert.equal(missingIdentity.status, 'error');
});
