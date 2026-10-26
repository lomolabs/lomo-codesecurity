import type { GatePolicyValues, ProjectGatePolicy } from './api';

export function projectGateValues(policy: ProjectGatePolicy, projectId: number): GatePolicyValues {
  if (policy.project_id !== projectId || typeof policy.active !== 'boolean' || typeof policy.block_secrets !== 'boolean'
    || ![policy.max_critical, policy.max_high].every(value => Number.isInteger(value) && value >= -1 && value <= 999)) {
    throw new Error('The gate response does not match this project. Reload its policy.');
  }
  return { active: policy.active, max_critical: policy.max_critical, max_high: policy.max_high, block_secrets: policy.block_secrets };
}

export function sameGate(left: GatePolicyValues, right: GatePolicyValues): boolean {
  return left.active === right.active && left.max_critical === right.max_critical
    && left.max_high === right.max_high && left.block_secrets === right.block_secrets;
}

/** A read begun before or during a save cannot replace its committed result. */
export function projectGateReadFence() {
  const generations = new Map<number, number>();
  return {
    invalidate(projectId: number) { generations.set(projectId, (generations.get(projectId) ?? 0) + 1); },
    capture(projectId: number) {
      const generation = generations.get(projectId) ?? 0;
      return () => generation === (generations.get(projectId) ?? 0);
    },
  };
}
