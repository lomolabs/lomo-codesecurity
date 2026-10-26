import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import type { GitPushPolicy } from '../src/api.ts';
import { exactProjectProtection, nativeWindowsSourceId, protectionSettingsHash } from '../src/findingProtection.ts';
import { subscribeToExactSettingsDeepLink } from '../src/settingsDeepLink.ts';

const policy: GitPushPolicy = { repository_id: 'a'.repeat(64), project_id: 7, name: 'Exact repository',
  root_path: '/workspace/team/repo', git_directory: '/workspace/team/repo/.git', revision: 2, enabled: true,
  observed_state: 'installed', observed_revision: 1, observed_at: '2026-09-29T00:00:00Z',
  hook_digest: 'b'.repeat(64), reason_code: 'policy_changed', members: [] };

test('protection context requires the exact project and source, never a neighboring clone', async () => {
  const project = { id: 7, repo_path: '/workspace/team/repo' };
  assert.equal((await exactProjectProtection(project, [policy])).policy, policy);
  assert.deepEqual(await exactProjectProtection(project, [{ ...policy, project_id: 8 },
    { ...policy, root_path: '/workspace/team/repo-other' }]), { policy: null, ambiguous: false });
  assert.deepEqual(await exactProjectProtection(project, [policy, { ...policy, repository_id: 'c'.repeat(64) }]),
    { policy: null, ambiguous: true });
  assert.equal(protectionSettingsHash(policy.repository_id), `#git-push-protection-${'a'.repeat(64)}`);
  assert.equal(protectionSettingsHash(), '#git-push-protection');
});

test('exact repository Settings entry waits for route and policy readiness and focuses only once', () => {
  const hash = protectionSettingsHash(policy.repository_id);
  const frames = new Map<number, FrameRequestCallback>();
  let nextFrame = 0;
  let scrolls = 0;
  let focuses = 0;
  let available = false;
  const browser = { location: { hash }, requestAnimationFrame(callback: FrameRequestCallback) {
    frames.set(++nextFrame, callback); return nextFrame;
  }, cancelAnimationFrame(id: number) { frames.delete(id); }, addEventListener() {}, removeEventListener() {} };
  const subscription = subscribeToExactSettingsDeepLink(browser, hash, () => available ? {
    scrollIntoView() { scrolls += 1; }, focus() { focuses += 1; },
  } : null);
  subscription.setReady(false);
  assert.equal(frames.size, 0, 'loading route and repository records cannot steal focus');
  available = true;
  subscription.setReady(true);
  for (const [id, frame] of frames) { frames.delete(id); frame(0); }
  assert.equal(scrolls, 1);
  assert.equal(focuses, 1);
  subscription.setReady(false);
  subscription.setReady(true);
  assert.equal(frames.size, 0, 'a policy refresh cannot scroll the same entry a second time');
  subscription.dispose();
});

const vectors = [
  {
    "root": "C:\\Users\\Café\\repo",
    "source_id": "7766a19c7506e6c256c14c9ed23f90a6436d719aee5f1454824c44e67301abcf"
  },
  {
    "root": "c:\\users\\CAFÉ\\REPO\\\\",
    "source_id": "7766a19c7506e6c256c14c9ed23f90a6436d719aee5f1454824c44e67301abcf"
  },
  {
    "root": "D:\\Emoji😀\\repo",
    "source_id": "2e65b089e33bfb30c9d9f78526c91c2a9b7f70899211b1864c85c86144b34190"
  },
  {
    "root": "C:\\Users\\Café\\neighbor",
    "source_id": "b11c07e0f41b362a64ed5b5239a659ee8ad923f84c2d6cf826b8a670f16d546b"
  }
];

test('native source matches Python NFC/lower/UTF8 vectors including emoji and trailing backslashes', async () => {
  for (const vector of vectors) assert.equal(await nativeWindowsSourceId(vector.root), vector.source_id);
  assert.equal(vectors[0].source_id, vectors[1].source_id);
});
test('native project requires exact source hash and project ID', async () => {
  const repo_path = `/source-snapshots/native-windows/${vectors[0].source_id}`;
  const native = { ...policy, root_path: vectors[0].root };
  assert.equal((await exactProjectProtection({ id: 7, repo_path }, [native])).policy, native);
  for (const wrong of [{ ...native, project_id: 8 }, { ...native, root_path: vectors[3].root }]) {
    assert.equal((await exactProjectProtection({ id: 7, repo_path }, [wrong])).policy, null);
  }
  assert.equal((await exactProjectProtection({ id: 7, repo_path: `${repo_path}/other` }, [native])).policy, null);
});
test('Git snapshot requires exact repository digest plus project ID', async () => {
  const project = { id: 7, repo_path: `/source-snapshots/git-commit/${policy.repository_id}` };
  assert.equal((await exactProjectProtection(project, [policy], { subtle: null })).policy, policy);
  assert.equal((await exactProjectProtection(project, [{ ...policy, project_id: 8 }])).policy, null);
  assert.equal((await exactProjectProtection(project, [{ ...policy, repository_id: 'c'.repeat(64) }])).policy, null);
});
test('snapshot namespace cannot fall through to a mounted root or project-only match', async () => {
  for (const repo_path of ['/source-snapshots/native-windows/not-a-digest', '/source-snapshots/git-commit/' + 'A'.repeat(64)]) {
    assert.equal((await exactProjectProtection({ id: 7, repo_path }, [{ ...policy, root_path: repo_path }])).policy, null);
  }
});
test('native missing crypto and digest rejection fail closed; mounted and Git need no crypto', async () => {
  const project = { id: 7, repo_path: `/source-snapshots/native-windows/${vectors[0].source_id}` };
  const native = { ...policy, root_path: vectors[0].root };
  await assert.rejects(exactProjectProtection(project, [native], { subtle: null }), /verification unavailable/);
  await assert.rejects(exactProjectProtection(project, [native], { subtle: { async digest() { throw new Error('unavailable'); } } }));
  assert.equal((await exactProjectProtection({ id: 7, repo_path: policy.root_path }, [policy], { subtle: null })).policy, policy);
});
test('ambiguous exact records never select one policy and same root hashes only once', async () => {
  const project = { id: 7, repo_path: `/source-snapshots/native-windows/${vectors[0].source_id}` };
  const native = { ...policy, root_path: vectors[0].root };
  let calls = 0;
  const match = await exactProjectProtection(project, [native, { ...native, repository_id: 'c'.repeat(64) }],
    { subtle: { digest(algorithm, data) { calls += 1; return webcrypto.subtle.digest(algorithm, data); } } });
  assert.deepEqual(match, { policy: null, ambiguous: true }); assert.equal(calls, 1);
});
test('abort during native digest rejects stale result after hash completes', async () => {
  const controller = new AbortController(); let release!: (value: ArrayBuffer) => void;
  const result = exactProjectProtection({ id: 7, repo_path: `/source-snapshots/native-windows/${vectors[0].source_id}` },
    [{ ...policy, root_path: vectors[0].root }], { signal: controller.signal,
      subtle: { digest() { return new Promise<ArrayBuffer>((resolve) => { release = resolve; }); } } });
  controller.abort(); release(new Uint8Array(32).buffer);
  await assert.rejects(result, { name: 'AbortError' });
});
test('already aborted work never hashes or produces a match', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(exactProjectProtection({ id: 7, repo_path: policy.root_path }, [policy], { signal: controller.signal }), { name: 'AbortError' });
});
