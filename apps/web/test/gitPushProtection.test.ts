import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import type { GitPushMember, GitPushPolicy, GitPushPolicyUpdate } from '../src/api.ts';
import type { ConfirmationRequest } from '../src/ConfirmationDialog.tsx';

const policy: GitPushPolicy = {
  repository_id: 'a'.repeat(64), project_id: 7, name: 'Disposable repository', revision: 2, enabled: true,
  root_path: '/qa/独立 repository', git_directory: '/qa/独立 repository/.git',
  observed_state: 'installed', observed_revision: 2, observed_at: '2026-09-12T20:00:00Z',
  hook_digest: 'b'.repeat(64), reason_code: null, members: [],
};

test('repository push settings preserve consent, exact revisions and honest host observations', async (context) => {
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  context.after(() => vite.close());
  const panel = await vite.ssrLoadModule('/src/GitPushProtection.tsx') as typeof import('../src/GitPushProtection.tsx');
  const apiModule = await vite.ssrLoadModule('/src/api.ts') as typeof import('../src/api.ts');

  await context.test('past matching host observation is not a timeless Protected claim', () => {
    assert.equal(panel.pushProtectionPresentation(policy).label, 'On · last verified');
    assert.match(panel.pushProtectionPresentation(policy).detail, /past observation/u);
    assert(panel.pushProtectionPresentation(policy).verifiedAt);
    for (const changed of [
      { observed_at: null }, { observed_at: 'invalid' },
      { hook_digest: null }, { observed_state: 'not_installed' as const },
    ]) assert.equal(panel.pushProtectionPresentation({ ...policy, ...changed }).label, 'Setup required');
    assert.equal(panel.pushProtectionPresentation({ ...policy, observed_state: 'needs_repair' }).label, 'Needs repair');
    assert.equal(panel.pushProtectionPresentation({ ...policy, enabled: false }).label, 'Off · last applied');
    for (const enabled of [true, false]) {
      for (const observed_revision of [1, null]) {
        const pending = panel.pushProtectionPresentation({ ...policy, enabled, observed_revision });
        assert.equal(pending.label, 'Change pending · Apply in VS Code');
        assert.match(pending.detail, /has not been applied on the host/u);
        assert.equal(pending.verifiedAt, null);
        assert.doesNotMatch(pending.detail, /will not check or block|checks were turned off/u);
      }
    }
  });

  await context.test('cancel and leaving the page while confirming submit no change', async () => {
    let requests = 0;
    let warning: ConfirmationRequest | undefined;
    const submit = async () => { requests += 1; return policy; };
    const cancelled = await panel.changePushProtection(policy, false, async (request) => {
      warning = request;
      return false;
    }, submit, () => true);
    assert.equal(cancelled, null);
    assert.equal(warning?.cancelLabel, 'Keep protection on');
    assert.equal(warning?.confirmLabel, 'Turn off protection');
    assert.match(warning?.message || '', /security findings or unscanned changes may be sent to your remote/u);
    assert.match(warning?.message || '', /Existing remote protections are not changed/u);
    assert(warning?.message.includes(`Source: ${policy.root_path}. Project ${policy.project_id}.`));
    assert.match(warning?.message || '', /requested Off; apply it in VS Code/u);
    assert.equal(await panel.changePushProtection(policy, false, async () => true, submit, () => false), null);
    assert.equal(requests, 0);
  });

  await context.test('ON and confirmed OFF submit exactly the selected repository revision', async () => {
    const requests: Array<{ id: string; update: GitPushPolicyUpdate }> = [];
    const submit = async (id: string, update: GitPushPolicyUpdate) => {
      requests.push({ id, update });
      return { ...policy, repository_id: id, revision: update.expected_revision + 1,
        enabled: update.enabled, reason_code: 'policy_changed' as const };
    };
    const off = await panel.changePushProtection(policy, false, async () => true, submit, () => true);
    const on = await panel.changePushProtection({ ...policy, enabled: false }, true,
      async () => { throw new Error('Enabling must not ask for bypass consent.'); }, submit, () => true);
    assert.deepEqual(requests, [
      { id: policy.repository_id, update: { expected_revision: 2, enabled: false, confirm_bypass: true } },
      { id: policy.repository_id, update: { expected_revision: 2, enabled: true, confirm_bypass: false } },
    ]);
    assert.equal(off?.enabled, false);
    assert.equal(on?.revision, 3);
    assert.equal(panel.pushProtectionPresentation(on!).label, 'Change pending · Apply in VS Code');
    assert.equal(policy.enabled, true, 'the previous snapshot must not be mutated');
  });

  await context.test('conflict is not retried and wrong response identity cannot replace a neighbour', async () => {
    const conflict = new Error('Push protection changed in another window.');
    let calls = 0;
    await assert.rejects(panel.changePushProtection(policy, false, async () => true, async () => {
      calls += 1;
      throw conflict;
    }, () => true), (error) => error === conflict);
    assert.equal(calls, 1);
    await assert.rejects(panel.changePushProtection(policy, false, async () => true, async () => ({
      ...policy, repository_id: 'c'.repeat(64), enabled: false, revision: 3,
    }), () => true), /could not be confirmed/u);
  });

  await context.test('editor grants require exact explicit consent and preserve cancellation, revocation and reapproval', async () => {
    const member: GitPushMember = { client_slot: `ks1_${'x'.repeat(43)}`, generation: 3,
      name: 'Owned QA profile', state: 'requested', requested_at: '2026-09-12T20:00:00Z', approved_at: null };
    const current = { ...policy, members: [member] };
    const requests: Array<{ id: string; slot: string; generation: number; update: { expected_revision: number; approve: boolean } }> = [];
    const submit = async (id: string, selected: Pick<GitPushMember, 'client_slot' | 'generation'>, update: { expected_revision: number; approve: boolean }) => {
      requests.push({ id, slot: selected.client_slot, generation: selected.generation, update });
      return { ...current, revision: update.expected_revision + 1, members: [{ ...member,
        state: update.approve ? 'approved' as const : 'revoked' as const }] };
    };
    let warning: ConfirmationRequest | undefined;
    assert.equal(await panel.changePushProtectionMember(current, member, true, async (request) => {
      warning = request; return false;
    }, submit, () => true), null);
    assert.equal(requests.length, 0);
    assert.match(warning?.title || '', /Owned QA profile for Disposable repository/u);
    assert.match(warning?.message || '', /does not change remotes or authorize external Advisor/u);
    assert(warning?.message.includes(`Source: ${policy.root_path}. Project ${policy.project_id}.`));
    assert.equal(await panel.changePushProtectionMember(current, member, true, async () => true, submit, () => false), null);
    assert.equal(requests.length, 0);
    await assert.rejects(panel.changePushProtectionMember(current, member, true, async () => true,
      async () => ({ ...current, root_path: '/qa/another repository', revision: 3,
        members: [{ ...member, state: 'approved' }] }), () => true), /could not be confirmed/u);
    const approved = await panel.changePushProtectionMember(current, member, true, async () => true, submit, () => true);
    const revoked = await panel.changePushProtectionMember(approved!, approved!.members[0], false, async () => true, submit, () => true);
    assert.equal(panel.pushProtectionPresentation(revoked!).label, 'Change pending · Apply in VS Code');
    await panel.changePushProtectionMember(revoked!, revoked!.members[0], true, async (request) => {
      assert.equal(request.cancelLabel, 'Keep access revoked'); return true;
    }, submit, () => true);
    assert.deepEqual(requests.map(({ update }) => update), [
      { expected_revision: 2, approve: true }, { expected_revision: 3, approve: false }, { expected_revision: 4, approve: true },
    ]);
    assert(requests.every((item) => item.id === policy.repository_id && item.slot === member.client_slot && item.generation === 3));
  });

  await context.test('Settings renders setup guidance, accessible toggles and unavailable state without optimistic authority', () => {
    const props = { repositories: [] as GitPushPolicy[], loading: false, busyId: null,
      error: null, status: null, onRefresh: () => {}, onChange: () => {}, onMemberChange: () => {} };
    const empty = renderToStaticMarkup(createElement(panel.GitPushProtectionPanel, props));
    assert.match(empty, /No repositories are set up yet/u);
    assert.match(empty, /VS Code and choose Protect Pushes/u);
    assert.match(empty, /saving here does not install a hook/u);
    assert.match(empty, /--no-verify/u);
    const observed = renderToStaticMarkup(createElement(panel.GitPushProtectionPanel, {
      ...props, repositories: [policy],
    }));
    assert.match(observed, /type="checkbox"[^>]*aria-label="Protect pushes from Disposable repository/u);
    assert.match(observed, /Last verified <time/u);
    assert.match(observed, /class="git-push-source-path">Source: \/qa\/独立 repository/u);
    assert.match(observed, /Project 7/u);
    assert.doesNotMatch(observed, />Protected</u);
    const unavailable = renderToStaticMarkup(createElement(panel.GitPushProtectionPanel, {
      ...props, repositories: [policy], error: 'Control plane unavailable.',
    }));
    assert.match(unavailable, /Status unavailable/u);
    assert.match(unavailable, /<input[^>]*disabled=""/u);
    assert.match(unavailable, /role="alert"/u);
    const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
    assert.match(app, /<SettingsGitPushProtection routeReady=\{routeReady && !surface\.inert\} \/>\s*<SettingsGatePanel/u);
    const styles = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8');
    const pathRule = styles.match(/#git-push-protection \.git-push-source-path\s*\{([^}]+)\}/u)?.[1] || '';
    for (const declaration of ['grid-column: 1 / -1', 'overflow: visible', 'overflow-wrap: anywhere', 'white-space: normal']) {
      assert(pathRule.includes(declaration), `exact source display requires ${declaration}`);
    }
  });

  await context.test('shared API preserves authenticated request transport and typed conflict without host operations', async () => {
    const originalFetch = globalThis.fetch;
    const requests: Array<{ path: string; init?: RequestInit }> = [];
    apiModule.setCsrfToken('synthetic-csrf');
    try {
      globalThis.fetch = async (url, init) => {
        requests.push({ path: String(url), init });
        return new Response(JSON.stringify(init?.method === 'PATCH'
          ? { ...policy, enabled: false, revision: 3 }
          : { repositories: [policy] }), { status: 200 });
      };
      const list = await apiModule.api.gitPushPolicies();
      assert.equal(list.repositories[0].repository_id, policy.repository_id);
      await apiModule.api.updateGitPushPolicy(policy.repository_id,
        { expected_revision: 2, enabled: false, confirm_bypass: true });
      await apiModule.api.decideGitPushMember(policy.repository_id,
        { client_slot: `ks1_${'x'.repeat(43)}`, generation: 3 }, { expected_revision: 2, approve: true });
      assert.deepEqual(requests.map(({ path }) => path), [
        '/v1/git/push-protection', `/v1/git/push-protection/${policy.repository_id}`,
        `/v1/git/push-protection/${policy.repository_id}/members/ks1_${'x'.repeat(43)}/3`,
      ]);
      assert.equal(requests[1].init?.credentials, 'same-origin');
      assert.equal((requests[1].init?.headers as Record<string, string>)['X-CSRF-Token'], 'synthetic-csrf');
      assert.deepEqual(JSON.parse(requests[1].init?.body as string),
        { expected_revision: 2, enabled: false, confirm_bypass: true });
      assert.equal(requests[2].init?.method, 'POST');
      assert.equal((requests[2].init?.headers as Record<string, string>)['X-CSRF-Token'], 'synthetic-csrf');
      assert.deepEqual(JSON.parse(requests[2].init?.body as string), { expected_revision: 2, approve: true });
      globalThis.fetch = async () => new Response(JSON.stringify({ detail: {
        code: 'push_policy_changed', message: 'Refresh before changing this repository.',
      } }), { status: 409 });
      await assert.rejects(apiModule.api.updateGitPushPolicy(policy.repository_id,
        { expected_revision: 2, enabled: false, confirm_bypass: true }),
      (error) => apiModule.isApiError(error, 'push_policy_changed') && error.status === 409);
    } finally {
      globalThis.fetch = originalFetch;
      apiModule.setCsrfToken('');
    }
  });
});
