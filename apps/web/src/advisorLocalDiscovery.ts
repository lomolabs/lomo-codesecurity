import type {
  AdvisorLocalCatalog,
  AdvisorLocalModel,
  AdvisorProvider,
  AdvisorProviderAction,
  AdvisorProviderCollection,
  AdvisorProviderInput,
  Health,
  Job,
} from './api';

const digestPattern = /^[0-9a-f]{64}$/u;
const transientLocalAdvisorReceiptReasons = new Set([
  'not_checked_by_worker',
  'worker_advisor_catalog_owner_mismatch',
  'worker_advisor_catalog_stale',
]);
export const LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT = 6;

export function localAdvisorDiscoveryPollPending(health: Health | null): boolean {
  if (!health || !health.db) return false;
  if (health.worker) {
    return transientLocalAdvisorReceiptReasons.has(health.ai.reason || '');
  }
  return health.ai.reason === 'work_processing_unavailable';
}

export function localAdvisorDiscoveryPollAllowed(health: Health | null, attempts: number): boolean {
  return Number.isSafeInteger(attempts)
    && attempts >= 0
    && attempts < LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT
    && localAdvisorDiscoveryPollPending(health);
}

export function consumeLocalAdvisorDiscoveryPollAttempt(
  health: Health | null,
  attempts: number,
  visible: boolean,
): number {
  if (!visible || !localAdvisorDiscoveryPollPending(health)) return attempts;
  const current = Number.isSafeInteger(attempts) && attempts >= 0 ? attempts : 0;
  return Math.min(LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT, current + 1);
}

export function localAdvisorAutoDetectionKey(
  settingsGeneration: number,
  health: Health | null,
): string | null {
  if (!Number.isSafeInteger(settingsGeneration) || settingsGeneration < 1 || health?.worker !== true) {
    return null;
  }
  return JSON.stringify([
    settingsGeneration,
    health.ai.available,
    health.ai.reason || null,
    [...health.ai.models].sort(),
  ]);
}

function highestPriorityLocalProvider(
  providers: readonly AdvisorProvider[],
): AdvisorProvider | undefined {
  return providers
    .filter((provider) => provider.transport === 'local')
    .sort((left, right) => left.priority - right.priority || left.id.localeCompare(right.id))[0];
}

export function normalizeAdvisorLocalCatalog(value: AdvisorLocalCatalog): AdvisorLocalCatalog {
  if (
    value.schema !== 'lomo-advisor-local-catalog/v1'
    || value.source !== 'dedicated_local_connector'
    || !Array.isArray(value.models)
    || value.models.length > 200
  ) throw new Error('Local Ollama returned an invalid model catalog.');
  const names = new Set<string>();
  const models = value.models.map((model): AdvisorLocalModel => {
    if (
      !model
      || typeof model.name !== 'string'
      || model.name.length < 1
      || model.name.length > 120
      || /[\p{Cc}\p{Cf}]/u.test(model.name)
      || names.has(model.name)
      || typeof model.digest !== 'string'
      || !digestPattern.test(model.digest)
      || !Number.isSafeInteger(model.size_bytes)
      || model.size_bytes < 0
      || !['local_weights', 'cloud_stub'].includes(model.storage)
      || model.storage === 'local_weights' && model.size_bytes === 0
    ) throw new Error('Local Ollama returned an invalid model catalog.');
    names.add(model.name);
    return { ...model };
  });
  const recommended = value.recommended_model;
  if (recommended !== null && !models.some(
    (model) => model.name === recommended && model.storage === 'local_weights',
  )) throw new Error('Local Ollama returned an invalid recommended model.');
  return { ...value, models };
}

export function selectedLocalModel(
  catalog: AdvisorLocalCatalog,
  selectedName: string | null,
): AdvisorLocalModel | null {
  const localModels = catalog.models.filter((model) => model.storage === 'local_weights');
  return localModels.find((model) => model.name === selectedName)
    || localModels.find((model) => model.name === catalog.recommended_model)
    || localModels[0]
    || null;
}

export function advisorLocalCatalogSummary(catalog: AdvisorLocalCatalog): string {
  const localCount = catalog.models.filter((model) => model.storage === 'local_weights').length;
  const cloudCount = catalog.models.length - localCount;
  return `Detected model details · ${localCount} local · ${cloudCount} cloud-only`;
}

export function localModelSelectorDisabled(state: {
  mutationsEnabled: boolean;
  modelAvailable: boolean;
  saving: boolean;
  operationActive: boolean;
  editorOpen: boolean;
  detectionLoading: boolean;
}): boolean {
  return !state.mutationsEnabled
    || !state.modelAvailable
    || state.saving
    || state.operationActive
    || state.editorOpen
    || state.detectionLoading;
}

export function advisorProviderDisableReason(active: boolean): string | null {
  return active ? 'Disconnect the active provider before disabling it.' : null;
}

export function detectedLocalProviderInput(
  model: AdvisorLocalModel,
  providers: readonly AdvisorProvider[],
): AdvisorProviderInput {
  if (model.storage !== 'local_weights' || model.size_bytes <= 0 || !digestPattern.test(model.digest)) {
    throw new Error('Only a model with verified local weights can become a local provider.');
  }
  const existingLocal = highestPriorityLocalProvider(providers);
  if (existingLocal) {
    return {
      id: existingLocal.id,
      name: existingLocal.name,
      transport: 'local',
      priority: existingLocal.priority,
      enabled: true,
      base_url: null,
      model: model.name,
      model_digest: model.digest,
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
    };
  }
  const priorities = new Set(providers.map((provider) => provider.priority));
  const priority = Array.from({ length: 8 }, (_, index) => index)
    .find((index) => !priorities.has(index));
  if (priority === undefined) throw new Error('The bounded provider chain already contains eight profiles.');
  const ids = new Set(providers.map((provider) => provider.id));
  const id = ['local-ollama', ...Array.from({ length: 7 }, (_, index) => `local-ollama-${index + 2}`)]
    .find((candidate) => !ids.has(candidate));
  if (!id) throw new Error('No local provider identity is available in the bounded provider chain.');
  return {
    id,
    name: 'Local Ollama',
    transport: 'local',
    priority,
    enabled: true,
    base_url: null,
    model: model.name,
    model_digest: model.digest,
    ssh_host: null,
    ssh_port: null,
    ssh_user: null,
  };
}

export type DetectedLocalProviderAction = 'add' | 'update' | 'current';

export function detectedLocalProviderAction(
  model: AdvisorLocalModel,
  providers: readonly AdvisorProvider[],
): DetectedLocalProviderAction {
  const existingLocal = highestPriorityLocalProvider(providers);
  if (!existingLocal) return 'add';
  return existingLocal.model === model.name && existingLocal.model_digest === model.digest
    ? 'current'
    : 'update';
}

export function detectedLocalProviderIsReady(
  model: AdvisorLocalModel,
  collection: AdvisorProviderCollection,
): boolean {
  const provider = highestPriorityLocalProvider(collection.providers);
  return Boolean(
    provider
    && provider.model === model.name
    && provider.model_digest === model.digest
    && provider.enabled
    && provider.status === 'active'
    && provider.eligible
    && collection.active_provider_id === provider.id
    && collection.resolution.provider_id === provider.id
    && collection.resolution.transport === 'local',
  );
}

export type LocalProviderWriteReconciliationReason = 'authority_conflict' | 'transport_uncertain';

type ApiErrorShape = Error & { status: number; code: string };

function isApiErrorShape(error: unknown): error is ApiErrorShape {
  return error instanceof Error
    && error.name === 'ApiError'
    && Number.isSafeInteger((error as Partial<ApiErrorShape>).status)
    && typeof (error as Partial<ApiErrorShape>).code === 'string';
}

export function localProviderWriteReconciliationReason(
  error: unknown,
): LocalProviderWriteReconciliationReason | null {
  if (isApiErrorShape(error) && error.code === 'revision_conflict') {
    return 'authority_conflict';
  }
  if (
    error instanceof TypeError
    || typeof DOMException !== 'undefined'
      && error instanceof DOMException
      && ['AbortError', 'NetworkError'].includes(error.name)
  ) return 'transport_uncertain';
  return null;
}

export function exactEnabledLocalProvider(
  providerId: string,
  model: AdvisorLocalModel,
  providers: readonly AdvisorProvider[],
): AdvisorProvider | null {
  return providers.find((provider) => (
    provider.id === providerId
    && provider.transport === 'local'
    && provider.enabled
    && provider.model === model.name
    && provider.model_digest === model.digest
  )) || null;
}

export function advisorProviderOperationLabel(
  action: AdvisorProviderAction,
  status: Job['status'],
  active: boolean,
): string {
  if (status === 'cancelling') {
    if (action === 'test') return 'Cancelling connection test';
    if (action === 'activate') return 'Cancelling activation';
    return 'Cancelling disconnect';
  }
  if (active) {
    if (action === 'test') return 'Testing connection';
    if (action === 'activate') return 'Activating provider';
    return 'Disconnecting provider';
  }
  if (action === 'test') {
    if (status === 'completed') return 'Connection test completed';
    if (status === 'cancelled') return 'Connection test cancelled';
    return 'Connection test failed';
  }
  if (action === 'activate') {
    if (status === 'completed') return 'Provider activated';
    if (status === 'cancelled') return 'Activation cancelled';
    return 'Activation failed';
  }
  if (status === 'completed') return 'Provider disconnected';
  if (status === 'cancelled') return 'Disconnect cancelled';
  return 'Disconnect failed';
}
