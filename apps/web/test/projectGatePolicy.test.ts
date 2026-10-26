import assert from 'node:assert/strict';
import test from 'node:test';
import { projectGateReadFence, projectGateValues, sameGate } from '../src/projectGatePolicy.ts';

const policy = { project_id: 4, active: true, max_critical: 0, max_high: -1, block_secrets: true };
test('gate drafts contain only exact project-scoped settings', () => {
  assert.deepEqual(projectGateValues(policy, 4), { active: true, max_critical: 0, max_high: -1, block_secrets: true });
  assert.throws(() => projectGateValues(policy, 5), /does not match/);
  for (const max_high of [NaN, 1000, -2, 0.5]) assert.throws(() => projectGateValues({ ...policy, max_high }, 4));
});

test('late reads from before and during a deferred save cannot replace its result after a project switch', async () => {
  const fence = projectGateReadFence();
  const beforeSave = fence.capture(4);
  fence.invalidate(4);
  const neighboringRead = fence.capture(5);
  const returnedToProject = fence.capture(4);
  let release: () => void = () => {};
  const saving = new Promise<void>(resolve => { release = resolve; }).then(() => fence.invalidate(4));
  assert.equal(beforeSave(), false);
  release(); await saving;
  assert.equal(returnedToProject(), false);
  assert.equal(neighboringRead(), true);
  assert.equal(fence.capture(4)(), true);
});
test('a reload can distinguish an untouched policy from each editable field', () => {
  assert.equal(sameGate(policy, { ...policy }), true);
  for (const change of [{ active: false }, { max_critical: 1 }, { max_high: 0 }, { block_secrets: false }]) {
    assert.equal(sameGate(policy, { ...policy, ...change }), false);
  }
});
