import * as vscode from 'vscode';

import {
  AuthorityInvalidation,
  BrowserInvitation,
  BrowserInvitationMembership,
  CodeSecurityClient,
  IdeConnectionOutcome,
  CodeSecurityRequestOptions,
  CodeSecurityRequestError,
  IdeEnrollmentApprovalRequiredError,
  IdeEnrollmentReview,
  PairingRequiredError,
  durableCommandHeaders,
  normalizeEndpoint,
  profileCredentialStorageFailure,
  workspaceScanCommand,
} from './client';
import { ProfileCredentialStore, ProfileCredentialStoreError } from './credentials';
import { activateWindowsPrivatePathVerifier, disposeWindowsPrivatePathVerifier } from './windows-private-path';
import { restoreStartupStorage } from './startup-storage-recovery';
import { GitPushRepository, GitPushUiAdapters, runGitPushProtection } from './git-push-ui';
import { runGitPushScan } from './git-push-scan';
import { applyGitPushPolicy, inspectGitPushPolicy, removeGitPushPolicy } from './git-push-host';
import { GitPushBoundaryError, inspectGitRepository, parseGitPushInput, readGitLocalRefs, readGitPushDestinations } from './git-push-objects';
import {
  FirstOwnerBootstrapError,
  FirstOwnerBrowserBootstrap,
  consumeFirstOwnerBrowserBootstrap,
  readFirstOwnerBrowserBootstrap,
} from './installer-bootstrap';
import {
  FindingDiagnostic,
  FindingDetail,
  FindingLifecycle,
  FindingSummary,
  findingGateEffectLabel,
  findingLifecycleLabel,
} from './findings';
import { Job, abortableDelay, isAbortError, jobProgressMessage, observeJob } from './jobs';
import { DomainEvent, RealtimeState, RealtimeSync, SourceOpenCommand } from './realtime';
import { RefreshProofSupersededError, WorkspaceRefreshCoordinator } from './sync';
import {
  MAX_WORKSPACE_SCAN_ROOTS,
  SourceTarget,
  sourceTargetForFileUri,
  sourceTargetForUri,
  validateMountedSourcePreview,
  repositorySourceTarget,
  sourceControlRepositoryRoot,
} from './source';
import {
  REPOSITORY_CONTEXT_STATE_KEY, RepositoryContextRecord, readRepositoryContexts,
  discoverImmediateRepositories, newRepositoryContext, verifyRepositoryContext, bindRepositoryProject, managedRepositoryParents,
} from './repository-context';
import { createRepositoryRecoveryState } from './repository-recovery';
import { RepositoryRecoveryStore } from './repository-recovery-store';
import { reviewedRepositoryAuthorizationCommand } from './repository-authorization';
import { SetupProgress } from './onboarding';
import { SetupGuide } from './setup-guide';
import {
  admittedNativeWindowsSourceSnapshot,
  collectNativeWindowsSourceSnapshot,
  admittedSourceSnapshotLimits,
} from './snapshot';
import {
  FindingCommandContext,
  NativeFindingController,
  SUPPRESSIVE_LIFECYCLES,
} from './native';
import {
  Project,
  Scan,
  MAX_DIAGNOSTIC_FILES,
  MAX_DIAGNOSTIC_FINDINGS,
  MAX_DIAGNOSTICS_PER_FILE,
  DIAGNOSTIC_PROJECTION_LIMIT_DESCRIPTION,
  ensureWorkspaceProject,
  loadSourceOpenProjectContext,
  loadFindingDetail,
  loadExactScan,
  loadFindingFileManifest,
  withFindingScanScope,
  loadFindingPages,
  loadWorkspaceState,
  streamFindingDiagnosticPages,
  validateFindingDetailResponse,
  classifyWorkspaceSourceUri,
  isNativeWindowsWorkspace,
  workspaceSourcePath,
  registeredProjectPrefix,
  rebaseRegisteredProjectFindingPath,
} from './workspace';

let diagnostics: vscode.DiagnosticCollection | undefined;
let apiClient: CodeSecurityClient | undefined;
let profileCredentials: ProfileCredentialStore | undefined;
type ProfileState = Readonly<{
  get<T>(key: string): T | undefined;
  update(key: string, value: unknown): Thenable<void>;
}>;
let profileState: ProfileState | undefined;
let repositoryState: ProfileState | undefined;
let setupProgress: SetupProgress | undefined;
let setupGuide: SetupGuide | undefined;
let verifiedDashboardGeneration: number | undefined;
let repositoryContextGeneration = 0;
let repositoryStateWrites: Promise<void> = Promise.resolve();
let nativeFindings: NativeFindingController | undefined;
let realtime: RealtimeSync | undefined;
let realtimeFactory: (() => RealtimeSync) | undefined;
let refreshCoordinator: WorkspaceRefreshCoordinator<WorkspaceRefreshResult> | undefined;
let closeDocumentSubscription: vscode.Disposable | undefined;
const activeScanObservers = new Map<string, AbortController>();
const sourceTargets = new Map<string, SourceTarget>();
const activeAuthorityRequests = new Set<AbortController>();
type FileHydration = {
  key: string;
  workspaceKey: string;
  filePath: string;
  scanId: number;
  revision: number;
  controller: AbortController;
  promise: Promise<void>;
  findingCount: number;
  priority: boolean;
  automaticCandidates?: ReadonlySet<string>;
  started: boolean;
  cancelled: boolean;
  resolve: () => void;
  reject: (error: unknown) => void;
};
const activeFileHydrations = new Map<string, FileHydration>();
const queuedFileHydrations: FileHydration[] = [];
const MAX_CONCURRENT_FILE_HYDRATIONS = 4;
const MAX_FILE_HYDRATION_MILLISECONDS = 15_000;
let runningFileHydrations = 0;
let reservedHydrationFindings = 0;
let pumpingFileHydrations = false;
let hydrationCommitDepth = 0;
let hydrationPumpTimer: ReturnType<typeof setTimeout> | undefined;
let authorityGeneration = 0;
let extensionActive = false;
let activeIdeConnectionFlow: Promise<void> | undefined;
let activeIdeConnectionController: AbortController | undefined;
let currentIdeEnrollmentReview: IdeEnrollmentReview | undefined;
let startupDashboardWarningShown = false;
let refreshIntentSequence = 0;
let developmentContextHydrationEnabled = false;
let developmentReconnectRequests = 0;
const developmentPriorityPaths = new Map<string, Set<string>>();
let developmentOpenFindingReceipt: DevelopmentOpenFindingReceipt | null = null;
let lazyReconnectAttempt: {
  endpoint: string;
  generation: number;
  client: CodeSecurityClient;
  invalidation?: AuthorityInvalidation;
} | undefined;
type PairedProfileReconnectState = {
  passiveAttempted: boolean;
  inFlight?: Promise<void>;
};
let pendingPairedProfileReconnect: PairedProfileReconnectState | undefined;
let pendingStartupWorkspaceHydration: {
  generation: number;
  client: CodeSecurityClient;
} | undefined;
const acknowledgedSourceOpenCommands = new Map<string, Readonly<{
  status: 'opened' | 'failed';
  errorCode?: string;
}>>();

type DevelopmentOpenFindingReceipt = Readonly<{
  workspaceKey: string;
  findingId: number;
  scanId: number;
  scanFindingNumber: number;
  findingRevision: number;
  findingsRevision: number;
  uri: string;
  integratedBrowserOpened: boolean;
}>;

type DevelopmentTestApi = Readonly<{
  connectIde(clientName: string): Promise<void>;
  refresh(): Promise<void>;
  reconnectRequests(): number;
  snapshot(): Readonly<{
    statusText: string;
    treeWorkspaceLabels: readonly string[];
    lastOpenFinding: DevelopmentOpenFindingReceipt | null;
    workspaces: readonly Readonly<{
      workspaceKey: string;
      scanId: number;
      count: number;
      gateDecision: string | null;
      staleFiles: readonly string[];
      findings: readonly Readonly<FindingCommandContext & {
        displayId: string;
        lifecycleStatus: FindingLifecycle;
        gateEffect: string;
        revision: number;
      }>[];
    }>[];
  }>;
  applyLifecycle(context: FindingCommandContext, action: FindingLifecycle, reason?: string): Promise<void>;
  queueAdvisor(context: FindingCommandContext): Promise<Readonly<{ id: number | null; status: string }>>;
  deleteFinding(context: FindingCommandContext): Promise<void>;
  revealFinding(context: FindingCommandContext): Promise<void>;
  handleSourceOpen(command: SourceOpenCommand): Promise<void>;
}>;

type DiagnosticLoad = {
  loaded: number;
  skipped: number;
  scanStatus?: string;
  totalFindings?: number;
  problemsLimited?: boolean;
};

type WorkspaceRefreshResult = DiagnosticLoad & {
  kind: 'unregistered' | 'no_scan' | 'active' | 'loaded' | 'limited' | 'unchanged';
  scanId?: number;
};

type WorkspaceRefreshTrigger =
  | Readonly<{ kind: 'manual' }>
  | Readonly<{ kind: 'reset' }>
  | Readonly<{ kind: 'event'; event: DomainEvent }>;

const MAX_LIFECYCLE_REASON_CHARACTERS = 500;
const MAX_REVISION_RECONCILIATION_ATTEMPTS = 3;
const DEVELOPMENT_CONTEXT_TARGET = 3;
// Admission reads /tools and, when a previous-good cache generation exists,
// /cache/rollback-eligibility. The deployed scanner contract allows 45 seconds
// per call; the remaining 30 seconds cover local API, database, and response
// work. Windows and Remote WSL receive the required nested-virtualization
// multiplier in one shared timing adapter.
const SCAN_ADMISSION_LINUX_DEADLINE_MS = 120_000;
const FINDING_SCAN_STATUSES = new Set(['completed', 'partial', 'failed', 'cancelled']);
const REMOTE_WSL_EXTENSION_ID = 'ms-vscode-remote.remote-wsl';
const REMOTE_WSL_REOPEN_COMMAND = 'remote-wsl.reopenInWSL';
const INTEGRATED_DASHBOARD_MEMBERSHIPS_KEY = 'lomoCodeSecurity.integratedDashboardMemberships.v1';
const INTEGRATED_DASHBOARD_PENDING_KEY = 'lomoCodeSecurity.integratedDashboardPending.v1';
const INTEGRATED_DASHBOARD_MEMBERSHIP_INVALID_MESSAGE =
  'The saved integrated-browser membership record is invalid. Select Reset and pair integrated browser to clear only this local dashboard record and create one replacement browser member.';
type IntegratedDashboardMembership = Readonly<{
  endpoint: string;
  invitationId: string;
  memberId: string;
  createdAt: string;
}>;
type IntegratedDashboardMemberships = Readonly<{
  schema: 'lomo-integrated-dashboard-memberships/v1';
  memberships: readonly IntegratedDashboardMembership[];
}>;
type PendingIntegratedDashboardInvitation = Readonly<{
  endpoint: string;
  invitationId: string;
  issuedAt: string;
  expiresAt: string;
}>;
type PendingIntegratedDashboardInvitations = Readonly<{
  schema: 'lomo-integrated-dashboard-pending/v1';
  invitations: readonly PendingIntegratedDashboardInvitation[];
}>;
const MANAGE_WORKSPACE_TRUST_ACTION = 'Manage Workspace Trust';
const MANAGE_WORKSPACE_TRUST_COMMAND = 'workbench.trust.manage';
const ADVISOR_SETTINGS_ACTION = 'Open Advisor Settings';
const REMOTE_ADVISOR_PREVIEW_ACTION = 'Open exact finding for consent';
const ADVISOR_SETTINGS_PROBLEM_CODES = new Set([
  'advisor_provider_authorization_required',
  'advisor_provider_configuration_corrupt',
  'advisor_provider_not_executable',
  'advisor_provider_selection_stale',
  'advisor_remote_single_finding_required',
  'advisor_source_disclosure_confirmation_required',
  'advisor_source_disclosure_confirmation_stale',
  'advisor_source_disclosure_consent_required',
]);
const ADVISOR_SETTINGS_PROBLEM_ACTIONS = new Set([
  'activate_advisor_provider',
  'authorize_advisor_provider',
  'confirm_advisor_source_disclosure',
  'preview_advisor_source_disclosure',
  'refresh_advisor_providers',
  'test_advisor_provider',
]);

export function scanAdmissionDeadlineMs(
  authorizationMode: SourceTarget['authorizationMode'],
  remoteName: string | undefined,
): number {
  return authorizationMode === 'snapshot' || remoteName?.toLowerCase() === 'wsl'
    ? SCAN_ADMISSION_LINUX_DEADLINE_MS * 2
    : SCAN_ADMISSION_LINUX_DEADLINE_MS;
}

type AdvisorProviderPin = Readonly<{
  provider_collection_revision: number;
  provider_id: string;
  transport: 'local';
  provider_config_revision: number;
  provider_config_digest: string;
  model: string;
  model_digest: string;
}>;

type AdvisorProviderRoute =
  | Readonly<{ kind: 'local'; pin: AdvisorProviderPin }>
  | Readonly<{
      kind: 'remote_single_finding_confirmation';
      providerId: string;
      transport: 'direct' | 'ssh';
    }>;

const ADVISOR_PROVIDER_ID = /^[a-z][a-z0-9-]{0,39}$/u;
const ADVISOR_PROVIDER_DIGEST = /^[0-9a-f]{64}$/u;
const ADVISOR_PROVIDER_FIELDS = new Set([
  'id', 'name', 'transport', 'priority', 'enabled', 'base_url', 'model', 'model_digest',
  'ssh_host', 'ssh_port', 'ssh_user', 'authorization', 'status', 'reason', 'reason_code',
  'remediation', 'last_activity_at', 'content_disclosure_approved', 'config_revision',
  'config_digest', 'eligible',
]);

function advisorRecord(value: unknown, fields: ReadonlySet<string>): value is Record<string, unknown> {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function advisorVisibleText(value: unknown, maximum: number): value is string {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= maximum
    && !/[\p{Cc}\p{Cf}]/u.test(value);
}

function advisorAdmissionError(message: string): CodeSecurityRequestError {
  return new CodeSecurityRequestError(message, 409, false, {
    code: 'advisor_provider_not_executable',
    action: 'refresh_advisor_providers',
  });
}

function findingContextError(message: string): CodeSecurityRequestError {
  return new CodeSecurityRequestError(message, 409, false, {
    code: 'finding_not_current',
    action: 'refresh_findings',
  });
}

function advisorProviderRoute(value: unknown): AdvisorProviderRoute {
  const collectionFields = new Set(['revision', 'active_provider_id', 'providers', 'resolution']);
  const resolutionFields = new Set(['provider_id', 'transport', 'reason', 'eligible_provider_ids']);
  if (!advisorRecord(value, collectionFields)) {
    throw advisorAdmissionError(
      'CodeSecurity returned an invalid Advisor provider collection. Refresh Advisor Settings and retry; no finding data was sent.',
    );
  }
  const revision = value.revision;
  const providers = value.providers;
  const resolution = value.resolution;
  if (
    !Number.isSafeInteger(revision) || (revision as number) < 1
    || !Array.isArray(providers) || providers.length > 8
    || !advisorRecord(resolution, resolutionFields)
  ) {
    throw advisorAdmissionError(
      'CodeSecurity returned an invalid Advisor provider collection. Refresh Advisor Settings and retry; no finding data was sent.',
    );
  }

  const identities = new Set<string>();
  const priorities = new Set<number>();
  for (const provider of providers) {
    if (
      !advisorRecord(provider, ADVISOR_PROVIDER_FIELDS)
      || typeof provider.id !== 'string' || !ADVISOR_PROVIDER_ID.test(provider.id)
      || !['local', 'direct', 'ssh'].includes(String(provider.transport))
      || !Number.isSafeInteger(provider.priority) || (provider.priority as number) < 0
      || (provider.priority as number) > 7
      || typeof provider.enabled !== 'boolean'
      || !advisorVisibleText(provider.model, 120)
      || typeof provider.model_digest !== 'string' || !ADVISOR_PROVIDER_DIGEST.test(provider.model_digest)
      || !Number.isSafeInteger(provider.config_revision) || (provider.config_revision as number) < 1
      || typeof provider.config_digest !== 'string' || !ADVISOR_PROVIDER_DIGEST.test(provider.config_digest)
      || typeof provider.eligible !== 'boolean'
      || identities.has(provider.id)
      || priorities.has(provider.priority as number)
    ) {
      throw advisorAdmissionError(
        'CodeSecurity returned an invalid Advisor provider collection. Refresh Advisor Settings and retry; no finding data was sent.',
      );
    }
    identities.add(provider.id);
    priorities.add(provider.priority as number);
  }
  if (
    value.active_provider_id !== null
    && (typeof value.active_provider_id !== 'string' || !identities.has(value.active_provider_id))
  ) {
    throw advisorAdmissionError(
      'CodeSecurity returned an inconsistent Advisor provider selection. Refresh Advisor Settings and retry; no finding data was sent.',
    );
  }

  const eligibleIds = resolution.eligible_provider_ids;
  if (
    !Array.isArray(eligibleIds) || eligibleIds.length > 8
    || eligibleIds.some((id) => typeof id !== 'string' || !identities.has(id))
    || new Set(eligibleIds).size !== eligibleIds.length
    || providers.some((provider) => provider.eligible !== eligibleIds.includes(provider.id as string))
  ) {
    throw advisorAdmissionError(
      'CodeSecurity returned an inconsistent Advisor provider selection. Refresh Advisor Settings and retry; no finding data was sent.',
    );
  }

  if (
    resolution.provider_id === null
    && resolution.transport === 'unavailable'
    && resolution.reason === 'remote_single_finding_confirmation_required'
    && eligibleIds.length === 0
    && typeof value.active_provider_id === 'string'
  ) {
    const remote = providers.find((provider) => provider.id === value.active_provider_id);
    if (
      remote
      && (remote.transport === 'direct' || remote.transport === 'ssh')
      && remote.enabled === true
      && remote.eligible === false
      && remote.authorization === 'authorized'
      && remote.status === 'active'
      && remote.reason_code === 'remote_single_finding_confirmation_required'
      && remote.remediation === 'none'
      && remote.content_disclosure_approved === true
    ) {
      return Object.freeze({
        kind: 'remote_single_finding_confirmation',
        providerId: remote.id as string,
        transport: remote.transport,
      });
    }
  }

  if (resolution.transport === 'direct' || resolution.transport === 'ssh') {
    throw advisorAdmissionError(
      'CodeSecurity returned an unsupported automatic remote Advisor route. Remote review must start from one exact finding disclosure preview in the Web UI; no finding data was sent.',
    );
  }
  if (
    resolution.transport !== 'local'
    || typeof resolution.provider_id !== 'string'
    || resolution.provider_id !== eligibleIds[0]
  ) {
    throw advisorAdmissionError(
      'No tested and currently executable local Advisor provider is available; no finding data was sent.',
    );
  }
  const selected = providers.find((provider) => provider.id === resolution.provider_id);
  if (
    !selected
    || selected.transport !== 'local'
    || selected.enabled !== true
    || selected.eligible !== true
    || selected.authorization !== 'not_required'
    || !['available', 'active'].includes(String(selected.status))
  ) {
    throw advisorAdmissionError(
      'CodeSecurity returned an inconsistent local Advisor provider selection. Refresh Advisor Settings and retry; no finding data was sent.',
    );
  }
  return Object.freeze({
    kind: 'local',
    pin: Object.freeze({
      provider_collection_revision: revision as number,
      provider_id: selected.id as string,
      transport: 'local',
      provider_config_revision: selected.config_revision as number,
      provider_config_digest: selected.config_digest as string,
      model: selected.model as string,
      model_digest: selected.model_digest as string,
    }),
  });
}


export function activate(context: vscode.ExtensionContext): DevelopmentTestApi | undefined {
  activateWindowsPrivatePathVerifier();
  extensionActive = true;
  activeIdeConnectionFlow = undefined;
  activeIdeConnectionController?.abort();
  activeIdeConnectionController = undefined;
  currentIdeEnrollmentReview = undefined;
  startupDashboardWarningShown = false;
  authorityGeneration = 0;
  refreshIntentSequence = 0;
  developmentContextHydrationEnabled = [
    vscode.ExtensionMode.Development,
    vscode.ExtensionMode.Test,
  ].includes(context.extensionMode);
  developmentReconnectRequests = 0;
  developmentPriorityPaths.clear();
  developmentOpenFindingReceipt = null;
  lazyReconnectAttempt = undefined;
  pendingPairedProfileReconnect = { passiveAttempted: false };
  acknowledgedSourceOpenCommands.clear();
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('lomo-code-security');
  diagnostics = diagnosticCollection;
  refreshCoordinator = new WorkspaceRefreshCoordinator<WorkspaceRefreshResult>();
  const memoryState = new Map<string, unknown>();
  const cursorStorage = context.globalState && typeof context.globalState.update === 'function'
    ? context.globalState
    : {
      get: <T>(key: string): T | undefined => memoryState.get(key) as T | undefined,
      update: async (key: string, value: unknown): Promise<void> => { memoryState.set(key, value); },
    };
  profileState = cursorStorage;
  let repositoryStorage: ProfileState;
  const repositoryRecovery = createRepositoryRecoveryState({
    workspace: context.workspaceState,
    recovery: new RepositoryRecoveryStore(context.globalStorageUri.fsPath),
    scope: () => {
      if (!vscode.workspace.isTrusted) return undefined;
      try {
        return {
          session: vscode.env.sessionId,
          workspace_uri: vscode.workspace.workspaceFile?.toString() ?? null,
          untitled: vscode.workspace.workspaceFile?.scheme === 'untitled',
          folders: (vscode.workspace.workspaceFolders || []).map(folder => {
            const admitted = workspaceSourcePath(folder);
            return { uri: folder.uri.toString(), path: isNativeWindowsWorkspace(folder) ? folder.uri.fsPath : admitted };
          }),
        };
      } catch { return undefined; } // Unsupported roots keep their existing command-time explanation.
    },
    active: () => extensionActive && repositoryState === repositoryStorage,
    offer: (count, restore) => {
      void vscode.window.showInformationMessage(
        `This workspace can restore ${count} repository selection${count === 1 ? '' : 's'} from its original parent. Source access and protection are unchanged.`,
        'Restore selections', 'Choose repositories',
      ).then(async choice => {
        if (!extensionActive || repositoryState !== repositoryStorage) return;
        if (choice === 'Restore selections') {
          await restore();
          await vscode.commands.executeCommand('lomoCodeSecurity.refreshFindings');
        } else if (choice === 'Choose repositories') await vscode.commands.executeCommand('lomoCodeSecurity.selectRepositories');
      }).then(undefined, () => { /* The recovery state reports persistence failures. */ });
    },
    failure: failure => {
      if (!extensionActive || repositoryState !== repositoryStorage) return;
      try { console.warn('[Lomo CodeSecurity] Repository selection recovery failed:', JSON.stringify(failure)); }
      catch { /* Diagnostics cannot change the existing warning or recovery outcome. */ }
      void vscode.window.showWarningMessage(
        'CodeSecurity could not preserve repository selections across this workspace change. Reopen the original parent or choose its repositories again. No source access was granted.',
      ).then(undefined, () => {});
    },
  });
  repositoryStorage = repositoryRecovery.state;
  repositoryState = repositoryStorage;
  repositoryContextGeneration += 1;
  repositoryStateWrites = repositoryRecovery.ready;
  const startForWorkspace = () => {
    void repositoryRecovery.ready.then(() => {
      if (extensionActive && repositoryState === repositoryStorage) startIdeDashboardOnActivation();
    }).catch(reportReconnectFailure);
  };
  verifiedDashboardGeneration = undefined;
  setupGuide = new SetupGuide(() => context.extension.packageJSON, {
    create: () => vscode.window.createWebviewPanel('lomoCodeSecurity.setup', 'CodeSecurity · Get Started', vscode.ViewColumn.Active,
      { enableScripts: true, enableCommandUris: false, localResourceRoots: [] }),
    run: command => vscode.commands.executeCommand(command),
    notes: step => vscode.commands.executeCommand('markdown.showPreview', vscode.Uri.joinPath(context.extensionUri, 'media', `setup-${step}.md`)),
    error: () => { void vscode.window.showErrorMessage('CodeSecurity could not open this setup action. You can run it from the Command Palette.'); },
  });
  context.subscriptions.push(setupGuide);
  setupProgress = new SetupProgress((key, complete) => {
    void vscode.commands.executeCommand('setContext', key, complete);
    setupGuide?.update(key, complete);
  });
  profileCredentials = new ProfileCredentialStore(
    context.globalStorageUri.fsPath,
    context.globalStorageUri.toString(),
  );
  apiClient = new CodeSecurityClient(
    profileCredentials,
    () => config().apiBaseUrl,
    globalThis.fetch,
    handleAuthorityInvalidation,
  );
  realtimeFactory = () => new RealtimeSync(apiClient!, cursorStorage, {
    onState: applyRealtimeHealth,
    onSourceOpen: handleSourceOpenCommand,
  });
  realtime = realtimeFactory();
  nativeFindings = new NativeFindingController(diagnosticCollection, {
    openFinding,
    setLifecycle,
    runAdvisor,
    rescanFile,
    deleteFinding,
    hydrateFile: hydrateWorkspaceFile,
  }, undefined, () => vscode.workspace.isTrusted === true, requestPairedProfileReconnect);
  closeDocumentSubscription = vscode.workspace.onDidCloseTextDocument(
    (document) => nativeFindings?.closeDocument(document),
  );
  const workspaceTrustSubscription = vscode.workspace.onDidGrantWorkspaceTrust(
    () => {
      nativeFindings?.workspaceTrustChanged();
      startForWorkspace();
    },
  );
  context.subscriptions.push(
    diagnosticCollection,
    nativeFindings,
    workspaceTrustSubscription,
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'lomoCodeSecurity.pair',
      command(runPairingFlow),
    ),
    vscode.commands.registerCommand(
      'lomoCodeSecurity.reconnect',
      command(reconnectLocalService),
    ),
    vscode.commands.registerCommand(
      'lomoCodeSecurity.addBrowser',
      command(addBrowser),
    ),
    vscode.commands.registerCommand('lomoCodeSecurity.openDashboard', commandWithArgument(openDashboard)),
    vscode.commands.registerCommand(
      'lomoCodeSecurity.scanWorkspace',
      command(scanWorkspaceCommand),
    ),
    vscode.commands.registerCommand(
      'lomoCodeSecurity.scanWorkspaceFolders',
      command(scanWorkspaceFoldersCommand),
    ),
    vscode.commands.registerCommand(
      'lomoCodeSecurity.scanRootFolder',
      command(scanRootFolderCommand),
    ),
    vscode.commands.registerCommand('lomoCodeSecurity.scanFolder', commandWithArguments(scanFolder)),
    vscode.commands.registerCommand(
      'lomoCodeSecurity.scanFile',
      commandWithArguments(scanFile),
    ),
    vscode.commands.registerCommand('lomoCodeSecurity.refreshFindings', command(refreshFindings)),
    vscode.commands.registerCommand('lomoCodeSecurity.protectPushes', commandWithArguments((...arguments_: unknown[]) => protectPushes(context, false, arguments_))),
    vscode.commands.registerCommand('lomoCodeSecurity.checkOutgoingCommits', commandWithArguments((...arguments_: unknown[]) => protectPushes(context, true, arguments_))),
    vscode.commands.registerCommand('lomoCodeSecurity.openFinding', commandWithArgument(openFinding)),
    vscode.commands.registerCommand('lomoCodeSecurity.revealFinding', commandWithArgument(revealFinding)),
    vscode.commands.registerCommand('lomoCodeSecurity.setLifecycle', commandWithArgument(setLifecycle)),
    vscode.commands.registerCommand('lomoCodeSecurity.runAdvisor', commandWithArgument(runAdvisor)),
    vscode.commands.registerCommand('lomoCodeSecurity.rescanFile', commandWithArgument(rescanFile)),
    vscode.commands.registerCommand('lomoCodeSecurity.deleteFinding', commandWithArgument(deleteFinding)),
    vscode.commands.registerCommand('lomoCodeSecurity.reopenInRemoteWsl', command(reopenWorkspaceInRemoteWsl)),
    vscode.commands.registerCommand('lomoCodeSecurity.selectRepositories', command(selectRepositoryContexts)),
    vscode.commands.registerCommand('lomoCodeSecurity.gettingStarted', command(async () => {
      setupGuide?.show();
      if (vscode.workspace.isTrusted !== true) { setupProgress?.invalidate(); return; }
      const client = apiClient;
      if (!client) return;
      const endpoint = client.endpointIdentity();
      const generation = authorityGeneration;
      const contextGeneration = repositoryContextGeneration;
      const current = () => extensionActive && apiClient === client && authorityGeneration === generation
        && repositoryContextGeneration === contextGeneration && client.endpointIdentity() === endpoint && vscode.workspace.isTrusted === true;
      // Public health only: opening help never requests an IDE credential or source permission.
      try {
        const health = await client.publicHealth();
        if (current()) setupProgress?.backend(health && typeof health === 'object' ? (health as Record<string, unknown>).ok : false);
      } catch { if (current()) setupProgress?.backend(false); }
    })),
    vscode.workspace.onDidChangeWorkspaceFolders((event) => {
      for (const folder of event.removed) {
        clearSourceTargetsOwnedBy(folder);
      }
      nativeFindings?.workspaceRootsChanged();
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (
        vscode.workspace.isTrusted
        && event.contentChanges.length > 0
        && nativeFindings?.markDocumentChanged(event.document)
      ) {
        void vscode.window.showWarningMessage(
          'CodeSecurity removed stale annotations for this file. Unsaved editor content was not included in the disk-based scan; rescan after saving.',
        );
      }
    }),
    vscode.workspace.onDidRenameFiles((event) => {
      const changed = vscode.workspace.isTrusted
        ? nativeFindings?.markFilesChanged(event.files.flatMap(({ oldUri, newUri }) => [oldUri, newUri]))
        : 0;
      if (changed) {
        void vscode.window.showWarningMessage(
          'CodeSecurity removed stale annotations for renamed files. Rescan before relying on their findings.',
        );
      }
    }),
    vscode.workspace.onDidDeleteFiles((event) => {
      const changed = vscode.workspace.isTrusted ? nativeFindings?.markFilesChanged(event.files) : 0;
      if (changed) {
        void vscode.window.showWarningMessage(
          'CodeSecurity removed stale annotations for deleted files. Rescan before relying on their findings.',
        );
      }
    }),
    vscode.workspace.onDidOpenTextDocument((document) => {
      if (vscode.workspace.isTrusted) nativeFindings?.openDocument(document);
    }),
    closeDocumentSubscription,
    vscode.window.onDidChangeVisibleTextEditors(
      (editors) => {
        if (vscode.workspace.isTrusted) nativeFindings?.visibleEditorsChanged(editors);
      },
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('lomoCodeSecurity.inlineAnnotations')) {
        if (vscode.workspace.isTrusted) nativeFindings?.updateVisibleEditors();
      }
      if (event.affectsConfiguration('lomoCodeSecurity.apiBaseUrl')) {
        handleEndpointConfigurationChange();
      }
    }),
  );

  // A retained profile authority is the user's durable sign-in for this local
  // installation. Restore it after activation without delaying the extension
  // host, then give the IDE's contextual browser a fresh fragment-only member
  // invitation. Missing/revoked authority remains a quiet no-op; a retained
  // authority that cannot restore its dashboard gets one nonblocking recovery
  // action while explicit commands retain their full actionable UI.
  startForWorkspace();

  if (!developmentContextHydrationEnabled) {
    return undefined;
  }
  return Object.freeze({
    connectIde: async (clientName: string) => {
      await connectIdeAndStream(clientName);
    },
    refresh: async () => {
      const folders = sourceContextFolders();
      if (!folders.length) throw new CodeSecurityRequestError('The extension test window has no selected source context.');
      for (const folder of folders) {
        await refreshWorkspaceFolder(folder, false);
        await hydrateDevelopmentContexts(folder);
      }
    },
    reconnectRequests: () => developmentReconnectRequests,
    snapshot: () => {
      const nativeSnapshot = nativeFindings?.testSnapshot() || { statusText: '', treeWorkspaceLabels: [] };
      return Object.freeze({
        ...nativeSnapshot,
        lastOpenFinding: developmentOpenFindingReceipt
          ? Object.freeze({ ...developmentOpenFindingReceipt })
          : null,
        workspaces: Object.freeze((nativeFindings?.store.workspaceEntries() || []).map((workspace) => Object.freeze({
          workspaceKey: workspace.key,
          scanId: workspace.scanId,
          count: workspace.totalFindings,
          gateDecision: workspace.gateDecision || null,
          staleFiles: Object.freeze([...workspace.staleFiles].sort()),
          findings: Object.freeze(workspace.findings.map((finding) => Object.freeze({
            workspaceKey: workspace.key,
            findingId: finding.id,
            scanId: finding.scan_id,
            scanFindingNumber: finding.scan_finding_number,
            findingRevision: finding.revision,
            findingsRevision: workspace.revision,
            displayId: finding.display_id,
            lifecycleStatus: finding.lifecycle_status,
            gateEffect: finding.gate_effect,
            revision: finding.revision,
          }))),
        }))),
      });
    },
    applyLifecycle: async (findingContext, action, reason) => {
      const valid = validFindingContext(commandContextFields(findingContext));
      await applyFindingLifecycle(valid, action, reason);
      const folder = nativeFindings?.workspaceFolder(valid.workspaceKey);
      if (folder) await hydrateDevelopmentContexts(folder);
    },
    queueAdvisor: async (findingContext) => {
      const job = await queueAdvisor(validFindingContext(commandContextFields(findingContext)));
      if (job === null) {
        return Object.freeze({ id: null, status: 'remote_confirmation_required' });
      }
      return Object.freeze({ id: job.id, status: job.status });
    },
    deleteFinding: async (findingContext) => {
      const valid = validFindingContext(commandContextFields(findingContext));
      await deleteFindingAuthoritatively(valid);
      const folder = nativeFindings?.workspaceFolder(valid.workspaceKey);
      if (folder) await hydrateDevelopmentContexts(folder);
    },
    revealFinding: async (findingContext) => {
      requireTrustedWorkspaceSourceAccess();
      const valid = validFindingContext(commandContextFields(findingContext));
      if (!nativeFindings) throw new CodeSecurityRequestError('CodeSecurity findings are not ready.');
      await nativeFindings.revealFinding(valid);
    },
    handleSourceOpen: async (sourceOpenCommand) => {
      await handleSourceOpenCommand(sourceOpenCommand, new AbortController().signal);
    },
  });
}


async function hydrateDevelopmentContexts(folder: vscode.WorkspaceFolder): Promise<void> {
  const native = nativeFindings;
  let workspace = native?.store.workspace(workspaceKey(folder));
  if (!developmentContextHydrationEnabled || !native || !workspace) return;
  const priorities = developmentPriorityPaths.get(workspace.key) || new Set<string>();
  developmentPriorityPaths.set(workspace.key, priorities);
  for (const path of [...priorities]) {
    if (!workspace.fileManifest.has(path)) priorities.delete(path);
  }
  for (const path of workspace.files.keys()) {
    if (priorities.size >= DEVELOPMENT_CONTEXT_TARGET) break;
    priorities.add(path);
  }
  const target = Math.min(DEVELOPMENT_CONTEXT_TARGET, workspace.totalFindings);
  if (workspace.findings.length >= target) return;
  const identity = {
    scanId: workspace.scanId,
    revision: workspace.revision,
  };
  for (const [filePath, aggregate] of workspace.fileManifest) {
    if (workspace.findings.length >= target) return;
    if (priorities.size >= DEVELOPMENT_CONTEXT_TARGET && !priorities.has(filePath)) continue;
    if (
      aggregate.total > native.store.maxFindings
      || workspace.allFilesStale
      || workspace.staleFiles.has(filePath)
    ) continue;
    priorities.add(filePath);
    await hydrateWorkspaceFile(workspace.key, filePath, identity.scanId, identity.revision);
    workspace = nativeFindings?.store.workspace(workspace.key);
    if (
      !workspace
      || workspace.scanId !== identity.scanId
      || workspace.revision !== identity.revision
    ) return;
  }
}


function clearDevelopmentOpenFinding(workspaceKeyValue?: string): void {
  if (
    workspaceKeyValue === undefined
    || developmentOpenFindingReceipt?.workspaceKey === workspaceKeyValue
  ) {
    developmentOpenFindingReceipt = null;
  }
}


export function deactivate() {
  disposeWindowsPrivatePathVerifier();
  extensionActive = false;
  activeIdeConnectionController?.abort();
  activeIdeConnectionController = undefined;
  activeIdeConnectionFlow = undefined;
  currentIdeEnrollmentReview = undefined;
  startupDashboardWarningShown = false;
  developmentContextHydrationEnabled = false;
  developmentReconnectRequests = 0;
  developmentPriorityPaths.clear();
  developmentOpenFindingReceipt = null;
  lazyReconnectAttempt = undefined;
  pendingPairedProfileReconnect = undefined;
  pendingStartupWorkspaceHydration = undefined;
  authorityGeneration += 1;
  for (const controller of activeAuthorityRequests) controller.abort();
  activeAuthorityRequests.clear();
  cancelFileHydrations();
  if (hydrationPumpTimer !== undefined) {
    clearTimeout(hydrationPumpTimer);
    hydrationPumpTimer = undefined;
  }
  clearDevelopmentOpenFinding();
  for (const controller of activeScanObservers.values()) {
    controller.abort();
  }
  activeScanObservers.clear();
  sourceTargets.clear();
  const eventSubscription = realtime;
  realtime = undefined;
  eventSubscription?.dispose();
  realtimeFactory = undefined;
  const refreshes = refreshCoordinator;
  refreshCoordinator = undefined;
  refreshes?.dispose();
  const documentCloseSubscription = closeDocumentSubscription;
  closeDocumentSubscription = undefined;
  documentCloseSubscription?.dispose();
  const controller = nativeFindings;
  nativeFindings = undefined;
  controller?.dispose();
  const collection = diagnostics;
  diagnostics = undefined;
  collection?.clear();
  collection?.dispose();
  apiClient = undefined;
  profileCredentials = undefined;
  profileState = undefined;
  repositoryState = undefined;
  repositoryContextGeneration += 1;
  setupGuide?.dispose();
  setupGuide = undefined;
  setupProgress?.invalidate();
  setupProgress = undefined;
  verifiedDashboardGeneration = undefined;
}


function updateSetupConnection(state = realtime?.currentState): void {
  setupProgress?.connection(vscode.workspace.isTrusted === true, state === 'connected', verifiedDashboardGeneration === authorityGeneration);
}

function applyRealtimeHealth(state: RealtimeState): void {
  updateSetupConnection(state);
  if (state === 'connecting') nativeFindings?.setServiceHealth('connecting');
  if (state === 'connected') nativeFindings?.setServiceHealth('connected');
  if (state === 'reconnecting') nativeFindings?.setServiceHealth('reconnecting');
  if (state === 'unavailable') nativeFindings?.setServiceHealth('unavailable');
  if (state === 'pair required') nativeFindings?.setServiceHealth('pair required');
}


function ensureRealtime(): RealtimeSync {
  if (realtime) return realtime;
  if (!extensionActive || !realtimeFactory) {
    throw new CodeSecurityRequestError('CodeSecurity event synchronization is unavailable.');
  }
  realtime = realtimeFactory();
  return realtime;
}


function cancelFileHydrations(workspace?: string): void {
  for (const hydration of activeFileHydrations.values()) {
    if (workspace !== undefined && hydration.workspaceKey !== workspace) continue;
    hydration.cancelled = true;
    hydration.controller.abort();
    if (!hydration.started) settleQueuedHydration(hydration, authorityAbortError());
  }
}


function cancelInactiveAutomaticHydrations(
  native: NativeFindingController,
  candidates: ReadonlySet<string>,
): void {
  for (const hydration of activeFileHydrations.values()) {
    if (hydration.priority || native.automaticHydrationCandidate(
      hydration.workspaceKey,
      hydration.filePath,
      hydration.scanId,
      hydration.revision,
      candidates,
    )) continue;
    hydration.cancelled = true;
    hydration.controller.abort();
    if (!hydration.started) settleQueuedHydration(hydration, authorityAbortError());
  }
}


function removeQueuedHydration(hydration: FileHydration): void {
  const index = queuedFileHydrations.indexOf(hydration);
  if (index >= 0) queuedFileHydrations.splice(index, 1);
}


function settleQueuedHydration(hydration: FileHydration, error?: unknown): void {
  removeQueuedHydration(hydration);
  if (activeFileHydrations.get(hydration.key) === hydration) {
    activeFileHydrations.delete(hydration.key);
  }
  if (error === undefined) hydration.resolve();
  else hydration.reject(error);
}


function hydrationStillCurrent(hydration: FileHydration): Readonly<{
  native: NativeFindingController;
  folder: vscode.WorkspaceFolder;
}> | undefined {
  const native = nativeFindings;
  const workspace = native?.store.workspace(hydration.workspaceKey);
  const folder = native?.workspaceFolder(hydration.workspaceKey);
  const aggregate = workspace?.fileManifest.get(hydration.filePath);
  if (
    !native
    || !workspace
    || !folder
    || workspace.scanId !== hydration.scanId
    || workspace.revision !== hydration.revision
    || aggregate?.total !== hydration.findingCount
    || workspace.allFilesStale
    || workspace.staleFiles.has(hydration.filePath)
    || !hydration.priority && !native.automaticHydrationCandidate(
      hydration.workspaceKey,
      hydration.filePath,
      hydration.scanId,
      hydration.revision,
      hydration.automaticCandidates,
    )
  ) return undefined;
  if (workspace.files.has(hydration.filePath)) {
    native.store.touchFile(hydration.workspaceKey, hydration.filePath);
    return undefined;
  }
  return { native, folder };
}


async function runFileHydration(
  hydration: FileHydration,
  native: NativeFindingController,
  folder: vscode.WorkspaceFolder,
): Promise<void> {
  let timedOut = false;
  const deadline = setTimeout(() => {
    timedOut = true;
    hydration.controller.abort();
  }, MAX_FILE_HYDRATION_MILLISECONDS);
  try {
    requireTrustedWorkspaceSourceAccess();
    const snapshot = await loadFindingPages(
      request,
      hydration.scanId,
      hydration.controller.signal,
      { filePath: hydration.filePath },
      undefined,
      hydration.revision,
      hydration.findingCount,
    );
    requireTrustedWorkspaceSourceAccess();
    if (snapshot.revision !== hydration.revision || snapshot.total !== hydration.findingCount) {
      throw new CodeSecurityRequestError(
        `CodeSecurity file hydration did not match manifest revision ${hydration.revision} `
          + `and count ${hydration.findingCount}.`,
        409,
      );
    }
    if (hydration.cancelled || hydration.controller.signal.aborted) throw authorityAbortError();
    const current = nativeFindings?.store.workspace(hydration.workspaceKey);
    if (
      !current
      || current.scanId !== hydration.scanId
      || current.revision !== hydration.revision
      || current.allFilesStale
      || current.staleFiles.has(hydration.filePath)
      || current.fileManifest.get(hydration.filePath)?.total !== hydration.findingCount
    ) {
      throw authorityAbortError();
    }
    hydrationCommitDepth += 1;
    try {
      const replaced = nativeFindings?.replaceHydratedFile(
        folder,
        hydration.filePath,
        snapshot.findings,
        hydration.revision,
      );
      if (replaced !== true) {
        throw new CodeSecurityRequestError(
          'CodeSecurity exact-file findings did not match the current manifest file identity.',
          409,
          true,
        );
      }
    } finally {
      hydrationCommitDepth -= 1;
    }
    hydration.resolve();
  } catch (error) {
    const superseded = hydration.cancelled
      || hydration.controller.signal.aborted
      || !hydrationStillCurrent(hydration);
    hydration.reject(
      timedOut
        ? new CodeSecurityRequestError(
          `CodeSecurity exact-file hydration timed out after ${MAX_FILE_HYDRATION_MILLISECONDS}ms.`,
          408,
          true,
        )
        : superseded
          ? authorityAbortError()
          : error,
    );
  } finally {
    clearTimeout(deadline);
    if (activeFileHydrations.get(hydration.key) === hydration) {
      activeFileHydrations.delete(hydration.key);
    }
    reservedHydrationFindings -= hydration.findingCount;
    runningFileHydrations -= 1;
    // The public async hydrateWorkspaceFile adopts the inner promise, so a
    // microtask here can still run before the caller's reaction. Defer one
    // task: explicit Tree/lifecycle callers first observe the committed file,
    // and the next admission sees retained state after this reservation is
    // released exactly once.
    scheduleFileHydrationPump();
  }
}


function preemptAutomaticHydrationsForPriority(): void {
  for (const hydration of activeFileHydrations.values()) {
    if (!hydration.started || hydration.priority || hydration.cancelled) continue;
    hydration.cancelled = true;
    hydration.controller.abort();
    // The physical slot and finding reservation remain owned until the
    // adapter actually settles in runFileHydration.finally.
  }
}


function scheduleFileHydrationPump(): void {
  if (hydrationPumpTimer !== undefined || !extensionActive) return;
  hydrationPumpTimer = setTimeout(() => {
    hydrationPumpTimer = undefined;
    pumpFileHydrations();
  }, 0);
}


function pumpFileHydrations(): void {
  if (pumpingFileHydrations || hydrationCommitDepth > 0) return;
  pumpingFileHydrations = true;
  try {
    while (
      runningFileHydrations < MAX_CONCURRENT_FILE_HYDRATIONS
      && queuedFileHydrations.length > 0
    ) {
      const hydration = queuedFileHydrations.shift()!;
      if (hydration.cancelled || hydration.controller.signal.aborted) {
        settleQueuedHydration(hydration, authorityAbortError());
        continue;
      }
      const current = hydrationStillCurrent(hydration);
      if (!current) {
        settleQueuedHydration(hydration);
        continue;
      }
      if (reservedHydrationFindings + hydration.findingCount > current.native.store.maxFindings) {
        queuedFileHydrations.unshift(hydration);
        return;
      }
      if (!current.native.reserveHydrationCapacity(
        reservedHydrationFindings + hydration.findingCount,
        hydration.workspaceKey,
        hydration.filePath,
      )) {
        settleQueuedHydration(
          hydration,
          new RangeError('CodeSecurity could not free bounded exact-file hydration capacity.'),
        );
        continue;
      }
      hydration.started = true;
      reservedHydrationFindings += hydration.findingCount;
      runningFileHydrations += 1;
      void runFileHydration(hydration, current.native, current.folder);
    }
  } finally {
    pumpingFileHydrations = false;
  }
}


async function hydrateWorkspaceFile(
  workspaceKeyValue: string,
  filePath: string,
  scanId: number,
  revision: number,
  priority = true,
  automaticCandidates?: ReadonlySet<string>,
): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const native = nativeFindings;
  const workspace = native?.store.workspace(workspaceKeyValue);
  const folder = native?.workspaceFolder(workspaceKeyValue);
  const aggregate = workspace?.fileManifest.get(filePath);
  if (
    !native
    || !workspace
    || !folder
    || workspace.scanId !== scanId
    || workspace.revision !== revision
    || !aggregate
    || workspace.allFilesStale
    || workspace.staleFiles.has(filePath)
  ) return;
  if (workspace.files.has(filePath)) {
    native.store.touchFile(workspaceKeyValue, filePath);
    return;
  }
  if (aggregate.total > native.store.maxFindings) {
    throw new RangeError(
      `This file has ${aggregate.total} findings, exceeding the explicit `
      + `${native.store.maxFindings}-summary exact-file hydration bound.`,
    );
  }

  const key = JSON.stringify([workspaceKeyValue, scanId, revision, filePath]);
  const active = activeFileHydrations.get(key);
  if (active) {
    if (priority && !active.priority) {
      active.priority = true;
      active.automaticCandidates = undefined;
      preemptAutomaticHydrationsForPriority();
      if (!active.started) {
        removeQueuedHydration(active);
        queuedFileHydrations.unshift(active);
        pumpFileHydrations();
      }
    }
    if (!active.cancelled) return active.promise;
    await active.promise.catch(() => undefined);
    return hydrateWorkspaceFile(
      workspaceKeyValue, filePath, scanId, revision, priority, automaticCandidates,
    );
  }
  const candidates = automaticCandidates || native.automaticHydrationCandidates();
  if (!priority && !native.automaticHydrationCandidate(
    workspaceKeyValue,
    filePath,
    scanId,
    revision,
    candidates,
  )) return;
  if (!priority) cancelInactiveAutomaticHydrations(native, candidates);
  const controller = new AbortController();
  let resolve!: () => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  const hydration: FileHydration = {
    key,
    workspaceKey: workspaceKeyValue,
    filePath,
    scanId,
    revision,
    controller,
    promise,
    findingCount: aggregate.total,
    priority,
    automaticCandidates: priority ? undefined : candidates,
    started: false,
    cancelled: false,
    resolve,
    reject,
  };
  activeFileHydrations.set(key, hydration);
  if (priority) {
    preemptAutomaticHydrationsForPriority();
    const firstAutomatic = queuedFileHydrations.findIndex((candidate) => !candidate.priority);
    if (firstAutomatic < 0) queuedFileHydrations.push(hydration);
    else queuedFileHydrations.splice(firstAutomatic, 0, hydration);
  } else {
    queuedFileHydrations.push(hydration);
  }
  pumpFileHydrations();
  return promise;
}


function resetAuthorityProjection(
  health: 'pair required' | 'unavailable' = 'pair required',
  refreshError: unknown = authorityAbortError(),
): void {
  setupProgress?.invalidate();
  verifiedDashboardGeneration = undefined;
  activeIdeConnectionController?.abort();
  pendingStartupWorkspaceHydration = undefined;
  currentIdeEnrollmentReview = undefined;
  authorityGeneration += 1;
  for (const controller of activeAuthorityRequests) controller.abort();
  activeAuthorityRequests.clear();
  cancelFileHydrations();
  for (const controller of activeScanObservers.values()) controller.abort();
  activeScanObservers.clear();
  sourceTargets.clear();
  refreshCoordinator?.cancelAll(refreshError);
  const stream = realtime;
  realtime = undefined;
  stream?.dispose();
  if (extensionActive && realtimeFactory) {
    realtime = realtimeFactory();
    pendingPairedProfileReconnect = { passiveAttempted: false };
  }
  clearDevelopmentOpenFinding();
  nativeFindings?.clearAll();
  nativeFindings?.setIdeEnrollmentReview(undefined);
  nativeFindings?.setServiceHealth(health);
}


function handleAuthorityInvalidation(invalidation: AuthorityInvalidation): void {
  // CodeSecurityClient invokes this only after its serialized exact-record
  // check marks the matching authority unusable in this window. A late 401
  // for an older capability therefore cannot clear a newer capability.
  const reconnectAttempt = lazyReconnectAttempt;
  if (
    reconnectAttempt
    && reconnectAttempt.client === apiClient
    && reconnectAttempt.generation === authorityGeneration
    && (
      reconnectAttempt.endpoint === invalidation.endpoint
      || invalidation.reason === 'endpoint_changed'
    )
  ) {
    reconnectAttempt.invalidation = invalidation;
  }
  const message = invalidation.reason === 'endpoint_changed'
    ? 'The CodeSecurity API endpoint changed. Connect this VS Code profile again.'
    : invalidation.reason === 'unauthorized'
      ? 'The CodeSecurity capability is missing or explicitly revoked. Request IDE access again.'
      : undefined;
  resetAuthorityProjection('pair required', new PairingRequiredError(message));
}


function handleEndpointConfigurationChange(): void {
  // Project, scan, finding, and cursor identities belong to one exact origin.
  // Authorities are isolated by normalized endpoint hash, so switching the
  // setting cannot read or invalidate another origin's authority.
  resetAuthorityProjection('pair required');
}


function authorityAbortError(): DOMException {
  return new DOMException('CodeSecurity authority changed while the operation was active.', 'AbortError');
}


async function authorityOperation<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  parentSignal?: AbortSignal,
): Promise<T> {
  if (!extensionActive || parentSignal?.aborted) throw authorityAbortError();
  const generation = authorityGeneration;
  const controller = new AbortController();
  const stop = () => controller.abort();
  parentSignal?.addEventListener('abort', stop, { once: true });
  activeAuthorityRequests.add(controller);
  try {
    const value = await operation(controller.signal);
    if (generation !== authorityGeneration || controller.signal.aborted) throw authorityAbortError();
    return value;
  } finally {
    parentSignal?.removeEventListener('abort', stop);
    activeAuthorityRequests.delete(controller);
  }
}


function config() {
  const cfg = vscode.workspace.getConfiguration('lomoCodeSecurity');
  return {
    apiBaseUrl: cfg.get<string>('apiBaseUrl') || 'http://127.0.0.1:8080',
  };
}


async function request<T>(
  path: string,
  init?: RequestInit,
  requestOptions?: CodeSecurityRequestOptions,
): Promise<T> {
  if (!apiClient) {
    throw new PairingRequiredError();
  }
  try {
    const response = await authorityOperation(
      (signal) => apiClient!.request<T>(path, { ...init, signal }, requestOptions),
      init?.signal || undefined,
    );
    const streamState = realtime?.currentState;
    if (streamState && streamState !== 'idle') {
      applyRealtimeHealth(streamState);
    }
    return response;
  } catch (error) {
    if (error instanceof PairingRequiredError) {
      // The client invalidation callback already performed complete teardown
      // under its authority lock. This assignment covers the first unpaired
      // command without weakening that race boundary.
      nativeFindings?.setServiceHealth('pair required');
    } else if (
      error instanceof CodeSecurityRequestError
      && (error.retryable || error.status !== undefined && error.status >= 500)
    ) {
      nativeFindings?.setServiceHealth('unavailable');
    }
    throw error;
  }
}


function command(handler: () => Promise<void>): () => Promise<void> {
  return async () => {
    try {
      await handler();
    } catch (error) {
      await showCommandFailure(error);
    }
  };
}

function commandWithArgument<T>(
  handler: (argument: T) => Promise<void>,
): (argument: T) => Promise<void> {
  return async (argument: T) => {
    try {
      await handler(argument);
    } catch (error) {
      await showCommandFailure(error);
    }
  };
}

function commandWithArguments<T extends readonly unknown[]>(
  handler: (...arguments_: T) => Promise<void>,
): (...arguments_: T) => Promise<void> {
  return async (...arguments_: T) => {
    try {
      await handler(...arguments_);
    } catch (error) {
      await showCommandFailure(error);
    }
  };
}


async function showCommandFailure(error: unknown): Promise<void> {
  if (isAbortError(error)) return;
  if (error instanceof IdeEnrollmentApprovalRequiredError) {
    applyIdeEnrollmentReview(error.review);
    await reviewIdeEnrollment();
    return;
  }
  if (error instanceof PairingRequiredError) {
    const selection = await vscode.window.showWarningMessage(error.message, 'Connect IDE');
    if (selection === 'Connect IDE') await vscode.commands.executeCommand('lomoCodeSecurity.pair');
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.action === 'finish_integrated_browser_pairing'
  ) {
    const selection = await vscode.window.showWarningMessage(
      commandErrorMessage(error),
      'Check same browser pairing',
      'Replace pending invitation',
    );
    const endpoint = normalizeEndpoint(config().apiBaseUrl);
    const pending = pendingIntegratedDashboardInvitation(endpoint);
    if (!pending || !selection) return;
    if (selection === 'Replace pending invitation') {
      try {
        await forgetPendingIntegratedDashboardInvitation(pending);
        await openIntegratedBrowserMemberRoute(
          workbenchUri(),
          'CodeSecurity integrated dashboard recovery',
          { forceNewMembership: true },
        );
      } catch (recoveryError) {
        await vscode.window.showErrorMessage(commandErrorMessage(recoveryError));
      }
      return;
    }
    try {
      const reconciled = await reconcilePendingIntegratedDashboardInvitation(pending);
      if (reconciled) await navigateRetainedIntegratedBrowser(workbenchUri());
    } catch (recoveryError) {
      if (
        recoveryError instanceof CodeSecurityRequestError
        && recoveryError.action === 'finish_integrated_browser_pairing'
      ) {
        await vscode.window.showWarningMessage(commandErrorMessage(recoveryError));
        return;
      }
      await showCommandFailure(recoveryError);
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.action === 'pair_integrated_browser_again'
  ) {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Pair integrated browser again',
    );
    if (selection === 'Pair integrated browser again') {
      try {
        await openIntegratedBrowserMemberRoute(
          workbenchUri(),
          'CodeSecurity integrated dashboard recovery',
          { forceNewMembership: true },
        );
      } catch (recoveryError) {
        await vscode.window.showErrorMessage(commandErrorMessage(recoveryError));
      }
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.action === 'reset_integrated_dashboard_membership'
  ) {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Reset and pair integrated browser',
    );
    if (selection === 'Reset and pair integrated browser') {
      try {
        await clearIntegratedDashboardMembershipState();
        await openIntegratedBrowserMemberRoute(
          workbenchUri(),
          'CodeSecurity integrated dashboard recovery',
          { forceNewMembership: true },
        );
      } catch (recoveryError) {
        await vscode.window.showErrorMessage(commandErrorMessage(recoveryError));
      }
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.action === 'reset_rejected_profile_authority'
  ) {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Reset this profile connection',
      'Open owner review in system browser',
    );
    if (selection === 'Open owner review in system browser') {
      await openOwnerIdeAccessReview();
      return;
    }
    if (selection !== 'Reset this profile connection') return;
    const endpoint = normalizeEndpoint(config().apiBaseUrl);
    const confirmation = await vscode.window.showWarningMessage(
      `Reset the rejected CodeSecurity connection for this exact VS Code profile at ${endpoint}?`,
      {
        modal: true,
        detail: 'This removes only this profile\'s rejected local credential. It does not revoke another IDE or browser. This profile will request owner approval again.',
      },
      'Reset and request IDE access',
    );
    if (confirmation !== 'Reset and request IDE access') return;
    if (!apiClient) throw new PairingRequiredError();
    await apiClient.resetRejectedIdeAuthority();
    resetAuthorityProjection('pair required');
    await startIdeConnectionFlow();
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.action === 'add_browser_again'
  ) {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Add Browser again',
    );
    if (selection === 'Add Browser again') {
      await vscode.commands.executeCommand('lomoCodeSecurity.addBrowser');
    }
    return;
  }
  if (error instanceof CodeSecurityRequestError && error.action === 'retry_open_dashboard') {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Open Dashboard',
    );
    if (selection === 'Open Dashboard') {
      await vscode.commands.executeCommand('lomoCodeSecurity.openDashboard');
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.code === 'workspace_trust_required'
    && error.action === 'manage_workspace_trust'
  ) {
    const selection = await vscode.window.showErrorMessage(
      error.message,
      MANAGE_WORKSPACE_TRUST_ACTION,
    );
    if (selection === MANAGE_WORKSPACE_TRUST_ACTION) {
      await vscode.commands.executeCommand(MANAGE_WORKSPACE_TRUST_COMMAND);
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.code === 'native_windows_unc_requires_remote_wsl'
    && error.action === 'reopen_in_remote_wsl'
  ) {
    const selection = await vscode.window.showErrorMessage(
      error.message,
      'Reopen Workspace in Remote WSL',
    );
    if (selection === 'Reopen Workspace in Remote WSL') {
      await vscode.commands.executeCommand('lomoCodeSecurity.reopenInRemoteWsl');
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && (
      error.action === 'revoke_or_restore_profile_authority'
      || error.action === 'review_paired_ide_clients'
      || error.action === 'resume_pending_enrollment'
      || error.action === 'start_new_enrollment'
    )
  ) {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Open owner review in system browser',
      'Copy owner-review address',
    );
    if (selection === 'Open owner review in system browser') await openOwnerIdeAccessReview();
    if (selection === 'Copy owner-review address') await copyOwnerIdeAccessReviewAddress();
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.code === 'profile_credential_store_corrupt'
    && error.action === 'repair_profile_credential_store'
  ) {
    const selection = await vscode.window.showErrorMessage(
      commandErrorMessage(error),
      'Review and repair exact profile authority',
    );
    if (selection !== 'Review and repair exact profile authority') return;
    const confirmation = await vscode.window.showWarningMessage(
      'Repair only corrupt CodeSecurity authority records in this exact VS Code profile and configured loopback endpoint?',
      {
        modal: true,
        detail: 'Valid records are preserved. Symbolic links, hard links, non-regular files, insecure permissions, unknown files, and recent writes are refused rather than removed.',
      },
      'Repair exact profile authority records',
    );
    if (confirmation !== 'Repair exact profile authority records') return;
    const store = profileCredentials;
    if (!store) throw new CodeSecurityRequestError('The CodeSecurity profile authority store is unavailable.');
    const endpoint = normalizeEndpoint(config().apiBaseUrl);
    let result;
    try {
      result = await store.repairCorruptRecords(endpoint);
    } catch (repairError) {
      await vscode.window.showErrorMessage(commandErrorMessage(
        repairError instanceof ProfileCredentialStoreError
          ? profileCredentialStorageFailure(repairError)
          : repairError,
      ));
      return;
    }
    resetAuthorityProjection('pair required');
    await vscode.window.showInformationMessage(
      result.removed.length > 0
        ? `Removed ${result.removed.length} corrupt CodeSecurity profile authority record${result.removed.length === 1 ? '' : 's'} from ${endpoint}. Review IDE access before requesting access again.`
        : `No corrupt CodeSecurity profile authority records remained for ${endpoint}.`,
    );
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && (error.code === 'source_outside_allowed_root' || error.action === 'authorize_source')
  ) {
    const selectedTarget = error.sourceBoundary?.selectedTarget;
    const authorizedRoots = error.sourceBoundary?.authorizedRoots || [];
    const boundaryContext = [
      selectedTarget ? `Selected target: ${selectedTarget}.` : undefined,
      authorizedRoots.length > 0 ? `Authorized roots: ${authorizedRoots.join(', ')}.` : undefined,
    ].filter((part): part is string => part !== undefined).join(' ');
    const selection = await vscode.window.showErrorMessage(
      `${error.message} ${boundaryContext ? `${boundaryContext} ` : ''}`
        + 'The selected folder is outside the source boundary configured for the local stack. '
        + 'Open Source Setup to authorize a narrow source root with the exact reviewed host command, or choose an authorized folder.'
        + (error.correlationId ? ` Reference: ${error.correlationId}.` : ''),
      'Open Source Setup',
    );
    if (selection === 'Open Source Setup') {
      await openWorkbench('projects', undefined, undefined, 'source', selectedTarget);
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && (error.action === 'enable_scanner' || error.action === 'prepare_scanners')
  ) {
    const selection = await vscode.window.showErrorMessage(commandErrorMessage(error), 'Prepare scanners');
    if (selection === 'Prepare scanners') await openWorkbench('tools');
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.action === 'repair_scanner_runtime'
  ) {
    const selection = await vscode.window.showErrorMessage(commandErrorMessage(error), 'Review scanner runtime');
    if (selection === 'Review scanner runtime') await openWorkbench('tools');
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && (error.action === 'wait_for_scanner_verification' || error.action === 'retry_scanner_verification')
  ) {
    const selection = await vscode.window.showErrorMessage(commandErrorMessage(error), 'View scanner verification');
    if (selection === 'View scanner verification') await openWorkbench('tools');
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && (
      error.code !== undefined && ADVISOR_SETTINGS_PROBLEM_CODES.has(error.code)
      || error.action !== undefined && ADVISOR_SETTINGS_PROBLEM_ACTIONS.has(error.action)
    )
  ) {
    const reference = error.correlationId ? ` Reference: ${error.correlationId}.` : '';
    const selection = await vscode.window.showErrorMessage(
      `${error.message} Open Advisor Settings to review the authoritative provider state, complete the requested setup, and retry.${reference}`,
      ADVISOR_SETTINGS_ACTION,
    );
    if (selection === ADVISOR_SETTINGS_ACTION) {
      await openWorkbench('settings', undefined, undefined, 'advisor');
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && error.code === 'finding_mutation_committed_refresh_required'
    && error.action === 'refresh_findings'
  ) {
    const selection = await vscode.window.showWarningMessage(
      commandErrorMessage(error),
      'Refresh Findings',
    );
    if (selection === 'Refresh Findings') {
      await vscode.commands.executeCommand('lomoCodeSecurity.refreshFindings');
    }
    return;
  }
  if (
    error instanceof CodeSecurityRequestError
    && (error.action === 'refresh_findings' || error.action === 'refresh_scan')
  ) {
    const selection = await vscode.window.showErrorMessage(commandErrorMessage(error), 'Refresh Findings');
    if (selection === 'Refresh Findings') {
      await vscode.commands.executeCommand('lomoCodeSecurity.refreshFindings');
    }
    return;
  }
  await vscode.window.showErrorMessage(commandErrorMessage(error));
}

function committedFindingMutationRefreshError(
  error: CodeSecurityRequestError,
  message: string,
): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    message,
    error.status,
    error.retryable,
    {
      code: 'finding_mutation_committed_refresh_required',
      action: 'refresh_findings',
      correlationId: error.correlationId,
    },
  );
}

function problemActionGuidance(action: string | undefined): string | undefined {
  switch (action) {
    case 'authorize_source':
      return 'Authorize a narrow source root in CodeSecurity, then retry.';
    case 'enable_scanner':
      return 'Enable at least one scanner in CodeSecurity, then retry.';
    case 'prepare_scanners':
      return 'Finish scanner preparation in CodeSecurity, then retry.';
    case 'repair_scanner_runtime':
      return 'Review the shipped scanner runtime in CodeSecurity Tools, restore the reported binary or offline-execution prerequisite, then retry.';
    case 'wait_for_scanner_verification':
      return 'View verification progress in CodeSecurity Tools. Wait for the existing scanner cache to finish verification, then retry the scan.';
    case 'retry_scanner_verification':
      return 'Open CodeSecurity Tools to retry verification of the existing cache, then retry the scan. Retrying verification does not download scanner data.';
    case 'revoke_or_restore_profile_authority':
      return "Restore this profile's matching authority, or revoke its retained IDE access in CodeSecurity Settings before connecting again.";
    case 'resume_pending_enrollment':
      return 'Review the retained IDE access request in CodeSecurity Settings or cancel it from the CodeSecurity status action.';
    case 'start_new_enrollment':
      return 'Cancel the retained IDE access request, then connect this VS Code profile again.';
    case 'repair_profile_credential_store':
      return 'The dedicated profile authority record is corrupt. Do not request IDE access again until that exact profile storage record is safely repaired.';
    case 'review_profile_storage_security':
      return 'CodeSecurity refused insecure profile authority storage. Review the reported ownership, permissions, link, and path condition without weakening it.';
    case 'restore_profile_storage_access':
      return 'Restore access to this exact VS Code profile storage directory, then retry.';
    case 'review_paired_ide_clients':
      return 'Review current IDE access in CodeSecurity Settings before requesting access again.';
    case 'retry_open_dashboard':
      return 'The VS Code profile remains connected. Run Open Dashboard to retry the same fragment-only browser authorization.';
    case 'pair_integrated_browser_again':
      return 'The VS Code profile remains connected. Pair the integrated browser again only if you want to create one replacement browser member.';
    case 'finish_integrated_browser_pairing':
      return 'Return to the exact browser tab and finish pairing, then check the same invitation. Replacing it always requires an explicit choice.';
    case 'reset_integrated_dashboard_membership':
      return INTEGRATED_DASHBOARD_MEMBERSHIP_INVALID_MESSAGE;
    case 'reset_rejected_profile_authority':
      return 'Reset only this rejected profile connection, then review its new IDE access request. Other IDE and browser members remain unchanged.';
    case 'add_browser_again':
      return 'No additional browser was paired. Retry only when an unpaired browser or browser profile is ready.';
    case 'refresh_findings':
      return 'Refresh findings, choose the current finding, and retry.';
    case 'refresh_scan':
      return 'Refresh the current scan, then retry.';
    case 'retry_after_remote_generation_enablement':
      return 'Remote Advisor review must begin from one exact finding disclosure preview and explicit authorization; automatic, scan-wide, and bulk remote routing remain disabled. No prompt was transmitted.';
    default:
      return undefined;
  }
}


function commandErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) {
    return 'The CodeSecurity command failed.';
  }
  if (!(error instanceof CodeSecurityRequestError)) {
    return error.message;
  }
  const reference = error.correlationId ? ` Reference: ${error.correlationId}.` : '';
  const action = problemActionGuidance(error.action);
  if (action) return `${error.message} ${action}${reference}`;
  if (error.status === 404) {
    return `${error.message} The persisted resource no longer exists; refresh the matching workspace or Jobs view.${reference}`;
  }
  if (error.status === 409) {
    return `${error.message} Persisted state changed; refresh Jobs before acting again.${reference}`;
  }
  if (error.status !== undefined && error.status >= 500) {
    return `${error.message} Durable work remains persisted; restore the local stack and refresh Jobs.${reference}`;
  }
  return `${error.message}${reference}`;
}


function requireTrustedWorkspaceSourceAccess(): void {
  if (vscode.workspace.isTrusted === true) return;
  setupProgress?.invalidate();
  verifiedDashboardGeneration = undefined;
  throw new CodeSecurityRequestError(
    'CodeSecurity cannot read, scan, annotate, or open workspace source while VS Code is in Restricted Mode. '
      + 'Review this workspace and manage Workspace Trust before retrying.',
    undefined,
    false,
    {
      code: 'workspace_trust_required',
      action: 'manage_workspace_trust',
    },
  );
}


function requirePersistentIntegratedBrowser(): void {
  if (vscode.workspace.isTrusted !== true) {
    throw new CodeSecurityRequestError(
      'The IDE can stay connected in Restricted Mode, but VS Code would discard the integrated browser session when it closes. '
        + 'Review this workspace and manage Workspace Trust before pairing or opening the CodeSecurity dashboard.',
      undefined,
      false,
      { code: 'workspace_trust_required', action: 'manage_workspace_trust' },
    );
  }
  if (vscode.workspace.getConfiguration('workbench.browser').get<string>('dataStorage', 'default') === 'ephemeral') {
    throw new CodeSecurityRequestError(
      'CodeSecurity cannot retain an integrated browser session while workbench.browser.dataStorage is ephemeral. '
        + 'Choose a persistent VS Code browser storage mode, then retry Open Dashboard. No setting was changed.',
      undefined,
      false,
      { code: 'integrated_dashboard_ephemeral_storage' },
    );
  }
}


const MAX_IDE_CLIENT_NAME_CHARACTERS = 120;
const UNSAFE_IDE_CLIENT_NAME_CHARACTER = /[\p{Cc}\p{Cf}]/u;

function ideClientNameDefault(): string {
  const printable = (value: string | undefined, fallback: string) => (
    value
      ?.replace(/[\p{Cc}\p{Cf}]+/gu, ' ')
      .replace(/\s+/gu, ' ')
      .trim()
    || fallback
  );
  const folders = vscode.workspace.workspaceFolders || [];
  const workspaceName = printable(
    vscode.workspace.name
      || (folders.length === 1 ? folders[0].name : folders.length > 1 ? `${folders.length} folders` : undefined),
    'no workspace',
  );
  const label = [
    printable(vscode.env.appName, 'VS Code'),
    workspaceName,
    printable(vscode.env.remoteName, 'local'),
  ].join(' · ');
  return Array.from(label).slice(0, MAX_IDE_CLIENT_NAME_CHARACTERS).join('');
}

function ideClientNameValidation(value: string): string | undefined {
  const candidate = value.trim();
  if (!candidate) return 'CodeSecurity requires a recognizable name for this VS Code profile or remote environment.';
  if (Array.from(candidate).length > MAX_IDE_CLIENT_NAME_CHARACTERS) {
    return `Keep the IDE client name within ${MAX_IDE_CLIENT_NAME_CHARACTERS} characters.`;
  }
  if (UNSAFE_IDE_CLIENT_NAME_CHARACTER.test(candidate)) {
    return 'Use printable IDE client-name characters without control or formatting characters.';
  }
  return undefined;
}

function applyIdeEnrollmentReview(review: IdeEnrollmentReview): void {
  currentIdeEnrollmentReview = review;
  if (review.state === 'approved') {
    nativeFindings?.setIdeEnrollmentReview(undefined);
    nativeFindings?.setServiceHealth('connecting');
    return;
  }
  nativeFindings?.setIdeEnrollmentReview({
    verificationCode: review.verificationCode,
    state: review.state,
  });
}


async function connectIdeProfile(
  signal: AbortSignal,
  dashboardMode: BrowserInvitationOpenMode,
): Promise<void> {
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const endpoint = normalizeEndpoint(config().apiBaseUrl);
  const clientName = ideClientNameDefault();
  const clientNameError = ideClientNameValidation(clientName);
  if (clientNameError) throw new CodeSecurityRequestError(clientNameError);
  if (normalizeEndpoint(config().apiBaseUrl) !== endpoint) {
    throw new CodeSecurityRequestError(
      'The CodeSecurity API endpoint changed before IDE enrollment. No enrollment request was sent; review the configured local endpoint and retry.',
    );
  }
  const firstOwnerBootstrap = await readFirstOwnerBootstrap(endpoint);
  const connection = await connectIdeAndStream(
    clientName,
    signal,
    firstOwnerBootstrap?.bootstrapToken,
  );
  currentIdeEnrollmentReview = undefined;
  nativeFindings?.setIdeEnrollmentReview(undefined);
  hydrateStartupWorkspaceContextsWhenReady();
  // Automatic enrollment may finish in Restricted Mode. Keep the IDE connected
  // and preserve the installer handoff until the explicit trust event resumes
  // dashboard setup; an error toast here can pause the newly trusted browser.
  if (dashboardMode === 'silent' && vscode.workspace.isTrusted !== true) return;
  requirePersistentIntegratedBrowser();
  if (connection.finishFirstOwnerSetup && firstOwnerBootstrap) {
    await openFirstOwnerIntegratedDashboard(firstOwnerBootstrap, dashboardMode);
    return;
  }
  // Reconcile authority before workbench restore; reopening here would race it.
  if (await reconcileIntegratedDashboardState(endpoint)) return;
  if (connection.authority === 'retained') {
    throw integratedDashboardMembershipMissingError();
  }
  await openIntegratedDashboardAfterPair(dashboardMode);
}


async function readFirstOwnerBootstrap(endpoint: string): Promise<FirstOwnerBrowserBootstrap | undefined> {
  try {
    return await readFirstOwnerBrowserBootstrap(endpoint);
  } catch (error) {
    if (!(error instanceof FirstOwnerBootstrapError)) throw error;
    throw new CodeSecurityRequestError(
      error.message,
      undefined,
      false,
      { code: error.code, action: 'restore_first_owner_bootstrap' },
    );
  }
}


async function reviewIdeEnrollment(): Promise<void> {
  const review = currentIdeEnrollmentReview || await apiClient?.pendingIdeEnrollment();
  if (!review) return;
  applyIdeEnrollmentReview(review);
  const choices: Array<{
    label: string;
    description: string;
    action: 'retry' | 'review' | 'copy' | 'cancel';
  }> = [];
  if (review.state === 'approved') {
    choices.push({
      label: 'Retry connection',
      description: 'Activate the exact approved authority without creating another request.',
      action: 'retry',
    });
  }
  choices.push(
    {
      label: 'Open owner review in system browser',
      description: review.state === 'awaiting_approval'
        ? `Open CodeSecurity Settings in an already authenticated owner browser to approve ${review.verificationCode}.`
        : `Open the exact ${review.state} IDE access request in an already authenticated owner browser.`,
      action: 'review' as const,
    },
    {
      label: 'Copy owner-review address',
      description: 'Copy the non-secret CodeSecurity Settings address for an already authenticated owner browser.',
      action: 'copy' as const,
    },
    {
      label: 'Cancel this IDE access request',
      description: 'Cancel only this exact pending profile authority.',
      action: 'cancel' as const,
    },
  );
  const choice = await vscode.window.showQuickPick(choices, {
    title: `IDE access · ${review.verificationCode}`,
    placeHolder: review.state === 'awaiting_approval'
      ? 'Approval is required before this VS Code profile can connect.'
      : `This retained IDE access request is ${review.state}.`,
  });
  if (choice?.action === 'retry') {
    currentIdeEnrollmentReview = undefined;
    await startIdeConnectionFlow();
    return;
  }
  if (choice?.action === 'review') {
    await openOwnerIdeAccessReview();
    return;
  }
  if (choice?.action === 'copy') {
    await copyOwnerIdeAccessReviewAddress();
    return;
  }
  if (choice?.action !== 'cancel') return;
  const connectionFlow = activeIdeConnectionFlow;
  activeIdeConnectionController?.abort();
  if (connectionFlow) {
    const prior = await connectionFlow.then(
      () => Object.freeze({ settled: 'completed' as const }),
      (error: unknown) => Object.freeze({ settled: 'failed' as const, error }),
    );
    // The explicit cancel owns cleanup even when the preceding connect failed.
    // Preserve that outcome as bounded diagnostic context without allowing it
    // to veto cancellation of the exact durable pending authority.
    if (prior.settled === 'failed' && !isAbortError(prior.error)) {
      console.warn('CodeSecurity IDE connection had already failed before explicit cancellation.');
    }
  }
  await authorityOperation((signal) => apiClient!.cancelIdeEnrollment(signal));
  currentIdeEnrollmentReview = undefined;
  nativeFindings?.setIdeEnrollmentReview(undefined);
  nativeFindings?.setServiceHealth('pair required');
  await vscode.window.showInformationMessage('Cancelled this VS Code profile\'s pending CodeSecurity IDE access request.');
}


function startIdeConnectionFlow(
  dashboardMode: BrowserInvitationOpenMode = 'interactive',
): Promise<void> {
  const existing = activeIdeConnectionFlow;
  if (existing) return existing;
  const controller = new AbortController();
  activeIdeConnectionController = controller;
  const current = connectIdeProfile(controller.signal, dashboardMode);
  activeIdeConnectionFlow = current;
  const clear = () => {
    if (activeIdeConnectionFlow === current) activeIdeConnectionFlow = undefined;
    if (activeIdeConnectionController === controller) activeIdeConnectionController = undefined;
  };
  void current.then(clear, clear);
  return current;
}


async function runPairingFlow(): Promise<void> {
  if (realtime?.currentState === 'connected') {
    vscode.window.setStatusBarMessage(
      '$(check) This exact VS Code profile is already connected.',
      5_000,
    );
    return;
  }
  if (currentIdeEnrollmentReview) {
    if (currentIdeEnrollmentReview.state === 'approved') {
      currentIdeEnrollmentReview = undefined;
      await startIdeConnectionFlow();
      return;
    }
    await reviewIdeEnrollment();
    return;
  }
  const existing = activeIdeConnectionFlow;
  if (existing) {
    // connectIde owns the authority lock until it publishes the exact durable
    // review through applyIdeEnrollmentReview. A second command must not queue
    // a lock-taking status read behind that in-flight request.
    vscode.window.setStatusBarMessage(
      '$(loading~spin) CodeSecurity is requesting IDE access…',
      5_000,
    );
    return;
  }
  await startIdeConnectionFlow();
}


async function reconnectPairedProfileOnDemand(
  context: 'restore_open_workspaces' | 'workspace_refresh_complete' = 'restore_open_workspaces',
): Promise<void> {
  const endpoint = normalizeEndpoint(config().apiBaseUrl);
  const stream = ensureRealtime();
  if (stream.currentState === 'connected') return;
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const attempt: {
    endpoint: string;
    generation: number;
    client: CodeSecurityClient;
    invalidation?: AuthorityInvalidation;
  } = {
    endpoint,
    generation: authorityGeneration,
    client,
  };
  lazyReconnectAttempt = attempt;
  try {
    await authorityOperation(async (signal) => {
      // Keep an exact pair-required projection until the selected endpoint
      // proves a durable authority. RealtimeSync becomes the sole writer of
      // connecting/connected states once a binding or bootstrap stream starts.
      if (context === 'workspace_refresh_complete') {
        if (stream.currentState === 'idle') await stream.reconnectPairedCapability(signal);
        else await stream.ensureConnected(signal);
        return;
      }
      const bindings = await restoreOpenWorkspaceContextsBeforeReconnect(signal);
      for (const bind of bindings) bind();
      if (bindings.length > 0) await stream.ensureConnected(signal);
      else await stream.reconnectPairedCapability(signal);
    });
  } catch (error) {
    // Missing, malformed, or rejected credentials invalidate the authority
    // synchronously and dispose this stream. Own that typed outcome before
    // treating the resulting AbortError as an ordinary supersession.
    if (attempt.invalidation || error instanceof PairingRequiredError) {
      nativeFindings?.setServiceHealth('pair required');
      return;
    }
    if (isAbortError(error)) return;
    nativeFindings?.setServiceHealth('unavailable');
    throw error;
  } finally {
    if (lazyReconnectAttempt === attempt) lazyReconnectAttempt = undefined;
  }
}


async function reconnectLocalService(): Promise<void> {
  const pending = pendingPairedProfileReconnect;
  const attempt = beginPairedProfileReconnect(pending, 'explicit', 'workspace_refresh_complete');
  if (attempt) await attempt;
  if (realtime?.currentState === 'connected') {
    vscode.window.setStatusBarMessage(
      '$(check) CodeSecurity reconnected this exact VS Code profile.',
      5_000,
    );
    return;
  }
  if (realtime?.currentState === 'pair required' || currentIdeEnrollmentReview) {
    const selection = await vscode.window.showWarningMessage(
      'This VS Code profile no longer has active IDE access. Review the exact local access request before reconnecting.',
      'Connect / Review IDE Access',
    );
    if (selection === 'Connect / Review IDE Access') {
      await vscode.commands.executeCommand('lomoCodeSecurity.pair');
    }
    return;
  }
  throw new CodeSecurityRequestError(
    'CodeSecurity could not reconnect the retained IDE profile to the exact local service.',
    503,
    true,
    { code: 'ide_reconnect_unavailable', action: 'retry_ide_reconnect' },
  );
}


async function restoreOpenWorkspaceContextsBeforeReconnect(
  signal: AbortSignal,
): Promise<readonly (() => void)[]> {
  requireTrustedWorkspaceSourceAccess();
  const generation = authorityGeneration;
  const deferred = new Map<string, () => void>();
  const attempted: vscode.WorkspaceFolder[] = [];
  try {
    for (const folder of sourceContextFolders()) {
      attempted.push(folder);
      try {
        await refreshWorkspaceFolder(folder, false, signal, { kind: 'reset' }, deferred);
      } catch (error) {
        if (signal.aborted || generation !== authorityGeneration) throw authorityAbortError();
        if (!(error instanceof CodeSecurityRequestError)
          || error.status !== 422 || error.code !== 'source_outside_allowed_root') throw error;
        // Source authorization is root-specific. A denied sibling must not
        // cancel another root's admitted rich hydration or current projection.
        const key = workspaceKey(folder);
        deferred.delete(key);
        cancelFileHydrations(key);
        realtime?.unbindWorkspace(key);
        nativeFindings?.clearWorkspace(folder, { preserveSourceTarget: true });
        // Do not hold other roots or reconnect behind a notification dismissal.
        void showCommandFailure(error).catch(reportReconnectFailure);
      }
    }
    return Object.freeze([...deferred.values()]);
  } catch (error) {
    for (const folder of attempted) {
      cancelFileHydrations(workspaceKey(folder));
      nativeFindings?.clearWorkspace(folder, { preserveSourceTarget: true });
    }
    throw error;
  }
}


function requestPairedProfileReconnect(): void {
  if (developmentContextHydrationEnabled) developmentReconnectRequests += 1;
  const pending = pendingPairedProfileReconnect;
  const attempt = beginPairedProfileReconnect(pending, 'passive', 'restore_open_workspaces');
  if (attempt) void attempt.catch(reportReconnectFailure);
}

async function reportReconnectFailure(error: unknown): Promise<void> {
  // A newer exact REST or event proof owns the same workspace now. Its caller
  // will surface any terminal failure; the displaced reconnect must not add a
  // contradictory generic Jobs recovery prompt.
  if (error instanceof RefreshProofSupersededError) return;
  await showCommandFailure(error);
}


function hydrateStartupWorkspaceContextsWhenReady(): void {
  const request = pendingStartupWorkspaceHydration;
  if (!request) return;
  if (!extensionActive || request.generation !== authorityGeneration || request.client !== apiClient) {
    pendingStartupWorkspaceHydration = undefined;
    return;
  }
  if (!vscode.workspace.isTrusted || realtime?.currentState !== 'connected') return;
  pendingStartupWorkspaceHydration = undefined;
  // IDE readiness and browser recovery have separate authority. Consume this
  // startup request once even when its connection flow began interactively or
  // Workspace Trust arrived while browser reconciliation was still pending.
  void authorityOperation(async (signal) => {
    const repositoryGeneration = repositoryContextGeneration;
    const folderUris = sourceContextFolders().map(folder => folder.uri.toString());
    const bindings = await restoreStartupStorage(
      () => restoreOpenWorkspaceContextsBeforeReconnect(signal), signal,
      () => {
        try {
          return extensionActive && vscode.workspace.isTrusted
            && realtime?.currentState === 'connected'
            && request.generation === authorityGeneration && request.client === apiClient
            && repositoryGeneration === repositoryContextGeneration
            && JSON.stringify(sourceContextFolders().map(folder => folder.uri.toString())) === JSON.stringify(folderUris);
        } catch { return false; }
      },
    );
    for (const bind of bindings) bind();
    if (bindings.length > 0) await ensureRealtime().ensureConnected(signal);
  }).catch(reportReconnectFailure);
}


function startIdeDashboardOnActivation(): void {
  if (!apiClient || !realtime || !pendingPairedProfileReconnect) return;
  const hydration = { generation: authorityGeneration, client: apiClient };
  pendingStartupWorkspaceHydration = hydration;
  hydrateStartupWorkspaceContextsWhenReady();
  void startIdeConnectionFlow('silent').catch((error: unknown) => {
    if (pendingStartupWorkspaceHydration === hydration) pendingStartupWorkspaceHydration = undefined;
    if (error instanceof IdeEnrollmentApprovalRequiredError) {
      applyIdeEnrollmentReview(error.review);
      return;
    }
    if (isAbortError(error)) return;
    if (error instanceof StartupDashboardError) {
      showStartupDashboardWarning(error);
      return;
    }
    if (
      error instanceof CodeSecurityRequestError
      && (
        error.action === 'pair_integrated_browser_again'
        || error.action === 'finish_integrated_browser_pairing'
        || error.action === 'reset_integrated_dashboard_membership'
        || error.code === 'workspace_trust_required'
        || error.code === 'integrated_dashboard_ephemeral_storage'
      )
    ) {
      void showCommandFailure(error);
      return;
    }
    if (
      error instanceof CodeSecurityRequestError
      && (
        error.action === 'reset_rejected_profile_authority'
        || error.action === 'revoke_or_restore_profile_authority'
        || error.action === 'review_paired_ide_clients'
        || error.action === 'resume_pending_enrollment'
        || error.action === 'start_new_enrollment'
      )
    ) {
      showStartupIdeAccessWarning(error);
      return;
    }
    if (error instanceof CodeSecurityRequestError && error.retryable) {
      nativeFindings?.setServiceHealth('unavailable');
      return;
    }
    if (currentIdeEnrollmentReview) return;
    const failure = error instanceof StartupDashboardError
      ? error
      : error instanceof CodeSecurityRequestError
        ? new StartupDashboardError(
          `CodeSecurity could not restore its retained IDE session at startup. ${error.message}`,
          'startup_dashboard_reconnect_failed',
        )
        : new StartupDashboardError(
          'CodeSecurity restored no startup dashboard because the editor rejected an unexpected local operation.',
          'startup_dashboard_unexpected_failure',
        );
    showStartupDashboardWarning(failure);
  });
}


function showStartupIdeAccessWarning(error: CodeSecurityRequestError): void {
  if (startupDashboardWarningShown || !extensionActive) return;
  startupDashboardWarningShown = true;
  void vscode.window.showWarningMessage(
    `${commandErrorMessage(error)} Select Connect / Review IDE Access to recover only this VS Code profile.`,
    'Connect / Review IDE Access',
  ).then((selection) => {
    if (selection !== 'Connect / Review IDE Access' || !extensionActive) return undefined;
    return vscode.commands.executeCommand('lomoCodeSecurity.pair');
  }, (failure: unknown) => {
    console.error('CodeSecurity could not display its startup IDE access recovery action.', failure);
    return undefined;
  });
}


function showStartupDashboardWarning(error: StartupDashboardError): void {
  if (startupDashboardWarningShown || !extensionActive) return;
  startupDashboardWarningShown = true;
  void vscode.window.showWarningMessage(
    `${error.message} Select Open CodeSecurity Dashboard to retry with a fresh one-time browser invitation.`,
    'Open CodeSecurity Dashboard',
  ).then((selection) => {
    if (selection !== 'Open CodeSecurity Dashboard' || !extensionActive) return undefined;
    const pending = pendingIntegratedDashboardInvitation(normalizeEndpoint(config().apiBaseUrl));
    return (pending ? forgetPendingIntegratedDashboardInvitation(pending) : Promise.resolve())
      .then(() => openIntegratedBrowserMemberRoute(
        workbenchUri(),
        'CodeSecurity startup dashboard recovery',
      ))
      .then(() => undefined)
      .catch(showCommandFailure);
  }, (failure: unknown) => {
    console.error('CodeSecurity could not display its startup dashboard recovery action.', failure);
    return undefined;
  });
}


function beginPairedProfileReconnect(
  pending: PairedProfileReconnectState | undefined,
  demand: 'passive' | 'explicit',
  context: 'restore_open_workspaces' | 'workspace_refresh_complete',
): Promise<void> | undefined {
  if (!pending || pending !== pendingPairedProfileReconnect) return undefined;
  if (pending.inFlight) return pending.inFlight;
  if (demand === 'passive' && pending.passiveAttempted) return undefined;
  pending.passiveAttempted = true;
  const attempt = reconnectPairedProfileOnDemand(context);
  pending.inFlight = attempt;
  const clear = () => {
    if (pending === pendingPairedProfileReconnect && pending.inFlight === attempt) {
      pending.inFlight = undefined;
    }
  };
  void attempt.then(clear, clear);
  return attempt;
}


async function connectIdeAndStream(
  clientName: string,
  parentSignal?: AbortSignal,
  firstOwnerBootstrapToken?: string,
): Promise<IdeConnectionOutcome> {
  if (!apiClient) throw new PairingRequiredError();
  return authorityOperation(async (signal) => {
    const connection = await apiClient!.connectIde(
      clientName,
      applyIdeEnrollmentReview,
      signal,
      firstOwnerBootstrapToken,
    );
    pendingPairedProfileReconnect = { passiveAttempted: true };
    await ensureRealtime().reconnectPairedCapability(signal);
    return connection;
  }, parentSignal);
}


function workbenchUri(
  view?: 'projects' | 'jobs' | 'findings' | 'tools' | 'settings',
  scanId?: number,
  scanFindingNumber?: number,
  setup?: 'source' | 'advisor' | 'ide-access' | 'push-protection',
  sourceSetupPath?: string,
  pushProtectionRepositoryId?: string,
): vscode.Uri {
  const url = new URL(normalizeEndpoint(config().apiBaseUrl));
  if (view) {
    url.searchParams.set('view', view);
  }
  if (view === 'findings' && scanId) {
    url.searchParams.set('scan', String(scanId));
  }
  if (view === 'findings' && scanFindingNumber) {
    url.searchParams.set('finding', String(scanFindingNumber));
  }
  if (view === 'projects' && setup === 'source') {
    url.searchParams.set('setup', 'source');
    // This is an untrusted suggestion for the existing host-approval form,
    // never source admission. Keep exact POSIX paths out of request queries.
    if (sourceSetupPath?.startsWith('/') && !sourceSetupPath.startsWith('//')
      && sourceSetupPath === sourceSetupPath.trim()
      && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(sourceSetupPath)
      && Buffer.byteLength(sourceSetupPath, 'utf8') <= 512) {
      url.hash = `source=${Buffer.from(sourceSetupPath, 'utf8').toString('base64url')}`;
    }
  }
  if (view === 'settings' && setup === 'advisor') {
    url.hash = 'advisor-providers';
  }
  if (view === 'settings' && setup === 'push-protection') {
    if (!pushProtectionRepositoryId || !/^[0-9a-f]{64}$/u.test(pushProtectionRepositoryId)) {
      throw new CodeSecurityRequestError('Choose one exact repository before opening push protection Settings.', 409);
    }
    url.hash = `git-push-protection-${pushProtectionRepositoryId}`;
  }
  if (view === 'settings' && setup === 'ide-access') {
    url.hash = 'ide-access';
  }
  return vscode.Uri.parse(url.toString());
}

const INTEGRATED_BROWSER_OPEN_COMMAND = 'workbench.action.browser.open';
const FOCUS_EDITOR_GROUP_COMMANDS = Object.freeze([
  'workbench.action.focusFirstEditorGroup',
  'workbench.action.focusSecondEditorGroup',
  'workbench.action.focusThirdEditorGroup',
  'workbench.action.focusFourthEditorGroup',
  'workbench.action.focusFifthEditorGroup',
  'workbench.action.focusSixthEditorGroup',
  'workbench.action.focusSeventhEditorGroup',
  'workbench.action.focusEighthEditorGroup',
]);
const RETAINED_BROWSER_MEMBER_QUERY_KEY = 'lomo_browser';
const RETAINED_BROWSER_MEMBER_QUERY_VALUE = 'vscode';
const RETAINED_BROWSER_TAB_TITLE = 'Lomo CodeSecurity · VS Code';
const retainedBrowserNavigationTails = new Map<string, Promise<void>>();
const retainedBrowserTabs = new Map<string, vscode.Tab>();

type IntegratedBrowserOpenRequest = Readonly<{
  url: string;
  reuseUrlFilter?: string;
}>;

type BrowserInvitationOpenMode = 'interactive' | 'silent';

class IntegratedBrowserOpenError extends Error {
  constructor() {
    super('The VS Code integrated browser rejected the CodeSecurity navigation request.');
    this.name = 'IntegratedBrowserOpenError';
  }
}

class StartupDashboardError extends CodeSecurityRequestError {
  constructor(message: string, code: string) {
    super(message, 503, true, {
      code,
      action: 'retry_open_dashboard',
    });
    this.name = 'StartupDashboardError';
  }
}

function integratedBrowserOpenRequest(
  uri: vscode.Uri,
  reuseExisting: boolean,
): IntegratedBrowserOpenRequest {
  const url = new URL(uri.toString(true));
  url.searchParams.set(RETAINED_BROWSER_MEMBER_QUERY_KEY, RETAINED_BROWSER_MEMBER_QUERY_VALUE);
  if (!reuseExisting) return Object.freeze({ url: url.toString() });
  const filter = new URL(`${url.origin}/`);
  filter.searchParams.set(RETAINED_BROWSER_MEMBER_QUERY_KEY, RETAINED_BROWSER_MEMBER_QUERY_VALUE);
  return Object.freeze({
    url: url.toString(),
    reuseUrlFilter: filter.toString(),
  });
}

type RetainedBrowserTabLocation = Readonly<{
  group: vscode.TabGroup;
  tab: vscode.Tab;
}>;

function retainedBrowserTab(endpoint: string): RetainedBrowserTabLocation | undefined {
  const groups = vscode.window.tabGroups.all;
  const tracked = retainedBrowserTabs.get(endpoint);
  const hostQualifiedTitle = `${RETAINED_BROWSER_TAB_TITLE} (${new URL(endpoint).host})`;
  const restored = groups.flatMap((group) => group.tabs
    .filter((tab) => tab.label === RETAINED_BROWSER_TAB_TITLE || tab.label === hostQualifiedTitle)
    .map((tab) => ({ group, tab })),
  );
  if (restored.length > 1) {
    throw new CodeSecurityRequestError(
      'VS Code restored more than one retained CodeSecurity dashboard. Close the extra retained dashboard tab before opening another exact route.',
      409,
      false,
      { code: 'integrated_dashboard_tab_ambiguous' },
    );
  }
  if (restored.length === 1) {
    retainedBrowserTabs.set(endpoint, restored[0].tab);
    return restored[0];
  }
  if (tracked) {
    const location = groups.find((group) => group.tabs.includes(tracked));
    if (location) return { group: location, tab: tracked };
    retainedBrowserTabs.delete(endpoint);
  }
  return undefined;
}

function rememberOpenedRetainedBrowserTab(endpoint: string): void {
  const active = vscode.window.tabGroups.activeTabGroup.activeTab;
  if (active && active.label.startsWith('Lomo CodeSecurity')) {
    retainedBrowserTabs.set(endpoint, active);
  }
}

async function navigateRetainedIntegratedBrowser(uri: vscode.Uri): Promise<void> {
  const endpoint = normalizeEndpoint(new URL(uri.toString(true)).origin);
  const prior = retainedBrowserNavigationTails.get(endpoint) || Promise.resolve();
  // VS Code 1.135 atomically navigates and focuses the contextual Browser view
  // that matches reuseUrlFilter. Keep the title/remembered-object lookup only
  // as the duplicate-tab ambiguity guard and restart recovery identity. Drive
  // every route through the one supported Browser command so address-input
  // focus cannot acknowledge a stale URL. Serialize the lane so an older route
  // cannot settle after a newer finding.
  const current = prior
    .catch(() => undefined)
    .then(async () => {
      const retained = retainedBrowserTab(endpoint);
      await executeIntegratedBrowserOpen(uri, true);
      let replacement: vscode.Tab | undefined;
      if (retained && !(retained.group.isActive && retained.tab.isActive)) {
        replacement = vscode.window.tabGroups.activeTabGroup.activeTab;
        if (!replacement || replacement === retained.tab) throw new IntegratedBrowserOpenError();
        const closed = await vscode.window.tabGroups.close(retained.tab, true);
        if (!closed) throw new IntegratedBrowserOpenError();
      }
      if (replacement) retainedBrowserTabs.set(endpoint, replacement);
      else rememberOpenedRetainedBrowserTab(endpoint);
    });
  retainedBrowserNavigationTails.set(endpoint, current);
  try {
    await current;
  } finally {
    if (retainedBrowserNavigationTails.get(endpoint) === current) {
      retainedBrowserNavigationTails.delete(endpoint);
    }
  }
}

const COPY_OWNER_REVIEW_ADDRESS_ACTION = 'Copy owner-review address';

function ownerIdeAccessReviewUri(): vscode.Uri {
  return workbenchUri('settings', undefined, undefined, 'ide-access');
}

async function copyOwnerIdeAccessReviewAddress(): Promise<void> {
  await vscode.env.clipboard.writeText(ownerIdeAccessReviewUri().toString(true));
  await vscode.window.showInformationMessage(
    'Copied the non-secret CodeSecurity owner-review address. Open it in an already authenticated owner browser; the IDE approval code remains visible in VS Code.',
  );
}

async function openOwnerIdeAccessReview(): Promise<void> {
  const uri = ownerIdeAccessReviewUri();
  let opened = false;
  try {
    opened = await vscode.env.openExternal(uri);
  } catch {
    // VS Code exposes no typed host error for system-browser launch failures.
    // Normalize this one boundary to the same truthful manual recovery below.
  }
  if (opened) return;
  const selection = await vscode.window.showWarningMessage(
    'CodeSecurity could not open the system browser. Use an already authenticated owner browser to open CodeSecurity Settings > IDE access; the approval code remains visible in VS Code.',
    COPY_OWNER_REVIEW_ADDRESS_ACTION,
  );
  if (selection === COPY_OWNER_REVIEW_ADDRESS_ACTION) {
    await copyOwnerIdeAccessReviewAddress();
  }
}

async function executeIntegratedBrowserOpen(
  uri: vscode.Uri,
  reuseExisting = true,
): Promise<void> {
  requirePersistentIntegratedBrowser();
  try {
    const availableCommands = await vscode.commands.getCommands(true);
    if (!availableCommands.includes(INTEGRATED_BROWSER_OPEN_COMMAND)) {
      throw new IntegratedBrowserOpenError();
    }
    await vscode.commands.executeCommand(
      INTEGRATED_BROWSER_OPEN_COMMAND,
      integratedBrowserOpenRequest(uri, reuseExisting),
    );
  } catch (error) {
    if (error instanceof IntegratedBrowserOpenError) throw error;
    // VS Code commands are an untyped host boundary. Normalize their failure
    // before product code decides whether an explicit command should offer a
    // recovery action or passive startup should remain non-interrupting.
    throw new IntegratedBrowserOpenError();
  }
}

async function executeSystemBrowserOpen(uri: vscode.Uri): Promise<void> {
  try {
    if (!await vscode.env.openExternal(uri)) throw new IntegratedBrowserOpenError();
  } catch (error) {
    if (error instanceof IntegratedBrowserOpenError) throw error;
    // VS Code exposes no typed host error for system-browser launch failures.
    throw new IntegratedBrowserOpenError();
  }
}

function browserInvitationUri(uri: vscode.Uri, bootstrapToken: string): vscode.Uri {
  const url = new URL(uri.toString(true));
  const destination = url.hash.replace(/^#/u, '');
  const fragment = new URLSearchParams({ bootstrap: bootstrapToken });
  if (destination) fragment.set('destination', destination);
  url.hash = fragment.toString();
  return vscode.Uri.parse(url.toString());
}

function integratedDashboardMemberships(): readonly IntegratedDashboardMembership[] {
  const stored = profileState?.get<unknown>(INTEGRATED_DASHBOARD_MEMBERSHIPS_KEY);
  if (stored === undefined) return [];
  const candidate = stored as Record<string, unknown>;
  if (
    typeof stored !== 'object'
    || stored === null
    || candidate.schema !== 'lomo-integrated-dashboard-memberships/v1'
    || !Array.isArray(candidate.memberships)
  ) {
    throw new CodeSecurityRequestError(
      INTEGRATED_DASHBOARD_MEMBERSHIP_INVALID_MESSAGE,
      500,
      false,
      {
        code: 'integrated_dashboard_membership_invalid',
        action: 'reset_integrated_dashboard_membership',
      },
    );
  }
  const memberships: IntegratedDashboardMembership[] = [];
  const endpoints = new Set<string>();
  const invitationIds = new Set<string>();
  const memberIds = new Set<string>();
  for (const value of candidate.memberships) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new CodeSecurityRequestError(
        INTEGRATED_DASHBOARD_MEMBERSHIP_INVALID_MESSAGE,
        500,
        false,
        {
          code: 'integrated_dashboard_membership_invalid',
          action: 'reset_integrated_dashboard_membership',
        },
      );
    }
    const record = value as Record<string, unknown>;
    if (
      Object.keys(record).sort().join('\0') !== 'createdAt\0endpoint\0invitationId\0memberId'
      || typeof record.endpoint !== 'string'
      || normalizeEndpoint(record.endpoint) !== record.endpoint
      || typeof record.invitationId !== 'string'
      || !/^[A-Za-z0-9_-]{24}$/u.test(record.invitationId)
      || typeof record.memberId !== 'string'
      || !/^kbm1_[A-Za-z0-9_-]{32}$/u.test(record.memberId)
      || typeof record.createdAt !== 'string'
      || !Number.isFinite(Date.parse(record.createdAt))
      || endpoints.has(record.endpoint)
      || invitationIds.has(record.invitationId)
      || memberIds.has(record.memberId)
    ) {
      throw new CodeSecurityRequestError(
        INTEGRATED_DASHBOARD_MEMBERSHIP_INVALID_MESSAGE,
        500,
        false,
        {
          code: 'integrated_dashboard_membership_invalid',
          action: 'reset_integrated_dashboard_membership',
        },
      );
    }
    endpoints.add(record.endpoint);
    invitationIds.add(record.invitationId);
    memberIds.add(record.memberId);
    memberships.push(Object.freeze({
      endpoint: record.endpoint,
      invitationId: record.invitationId,
      memberId: record.memberId,
      createdAt: record.createdAt,
    }));
  }
  return Object.freeze(memberships);
}

function integratedDashboardMembership(endpoint: string): IntegratedDashboardMembership | undefined {
  return integratedDashboardMemberships().find((membership) => membership.endpoint === endpoint);
}

function pendingIntegratedDashboardInvitations(): readonly PendingIntegratedDashboardInvitation[] {
  const stored = profileState?.get<unknown>(INTEGRATED_DASHBOARD_PENDING_KEY);
  if (stored === undefined) return [];
  const candidate = stored as Record<string, unknown>;
  if (
    typeof stored !== 'object'
    || stored === null
    || candidate.schema !== 'lomo-integrated-dashboard-pending/v1'
    || !Array.isArray(candidate.invitations)
  ) {
    throw new CodeSecurityRequestError(
      'The saved pending integrated-browser acknowledgement is invalid. No browser invitation was issued.',
      500,
      false,
      { code: 'integrated_dashboard_pending_invalid', action: 'reset_integrated_dashboard_membership' },
    );
  }
  const invitations: PendingIntegratedDashboardInvitation[] = [];
  const endpoints = new Set<string>();
  const invitationIds = new Set<string>();
  for (const value of candidate.invitations) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new CodeSecurityRequestError(
        'The saved pending integrated-browser acknowledgement is invalid. No browser invitation was issued.',
        500,
        false,
        { code: 'integrated_dashboard_pending_invalid', action: 'reset_integrated_dashboard_membership' },
      );
    }
    const record = value as Record<string, unknown>;
    if (
      Object.keys(record).sort().join('\0') !== 'endpoint\0expiresAt\0invitationId\0issuedAt'
      || typeof record.endpoint !== 'string'
      || normalizeEndpoint(record.endpoint) !== record.endpoint
      || typeof record.invitationId !== 'string'
      || !/^[A-Za-z0-9_-]{24}$/u.test(record.invitationId)
      || typeof record.issuedAt !== 'string'
      || !Number.isFinite(Date.parse(record.issuedAt))
      || typeof record.expiresAt !== 'string'
      || !Number.isFinite(Date.parse(record.expiresAt))
      || Date.parse(record.expiresAt) <= Date.parse(record.issuedAt)
      || endpoints.has(record.endpoint)
      || invitationIds.has(record.invitationId)
    ) {
      throw new CodeSecurityRequestError(
        'The saved pending integrated-browser acknowledgement is invalid. No browser invitation was issued.',
        500,
        false,
        { code: 'integrated_dashboard_pending_invalid', action: 'reset_integrated_dashboard_membership' },
      );
    }
    endpoints.add(record.endpoint);
    invitationIds.add(record.invitationId);
    invitations.push(Object.freeze({
      endpoint: record.endpoint,
      invitationId: record.invitationId,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
    }));
  }
  return Object.freeze(invitations);
}

function pendingIntegratedDashboardInvitation(
  endpoint: string,
): PendingIntegratedDashboardInvitation | undefined {
  return pendingIntegratedDashboardInvitations().find((invitation) => invitation.endpoint === endpoint);
}

async function recordPendingIntegratedDashboardInvitation(
  endpoint: string,
  invitation: BrowserInvitation,
): Promise<void> {
  const state = profileState;
  if (!state) {
    throw new CodeSecurityRequestError(
      'The VS Code profile cannot persist its pending integrated-browser acknowledgement.',
      500,
      false,
      { code: 'integrated_dashboard_pending_storage_unavailable' },
    );
  }
  if (invitation.purpose !== 'integrated_dashboard') {
    throw new CodeSecurityRequestError('CodeSecurity refused to stage a non-dashboard browser invitation.');
  }
  const invitations = pendingIntegratedDashboardInvitations()
    .filter((current) => current.endpoint !== endpoint);
  await state.update(INTEGRATED_DASHBOARD_PENDING_KEY, Object.freeze({
    schema: 'lomo-integrated-dashboard-pending/v1',
    invitations: Object.freeze([...invitations, Object.freeze({
      endpoint,
      invitationId: invitation.invitationId,
      issuedAt: invitation.issuedAt,
      expiresAt: invitation.expiresAt,
    })]),
  }) satisfies PendingIntegratedDashboardInvitations);
}

async function forgetPendingIntegratedDashboardInvitation(
  pending: PendingIntegratedDashboardInvitation,
): Promise<void> {
  const state = profileState;
  if (!state) return;
  const invitations = pendingIntegratedDashboardInvitations();
  if (!invitations.some((current) => (
    current.endpoint === pending.endpoint && current.invitationId === pending.invitationId
  ))) return;
  await state.update(INTEGRATED_DASHBOARD_PENDING_KEY, Object.freeze({
    schema: 'lomo-integrated-dashboard-pending/v1',
    invitations: Object.freeze(invitations.filter((current) => !(
      current.endpoint === pending.endpoint && current.invitationId === pending.invitationId
    ))),
  }) satisfies PendingIntegratedDashboardInvitations);
}

async function recordIntegratedDashboardMembership(
  endpoint: string,
  membership: Extract<BrowserInvitationMembership, { status: 'active' }>,
): Promise<void> {
  const state = profileState;
  if (!state) {
    throw new CodeSecurityRequestError(
      'The VS Code profile cannot persist its integrated-dashboard membership.',
      500,
      false,
      { code: 'integrated_dashboard_membership_storage_unavailable' },
    );
  }
  if (membership.purpose !== 'integrated_dashboard') {
    throw new CodeSecurityRequestError(
      'CodeSecurity refused to retain an extra-browser invitation as the integrated dashboard.',
      409,
      false,
      { code: 'integrated_dashboard_membership_purpose_invalid' },
    );
  }
  const memberships = integratedDashboardMemberships()
    .filter((current) => current.endpoint !== endpoint);
  await state.update(INTEGRATED_DASHBOARD_MEMBERSHIPS_KEY, Object.freeze({
    schema: 'lomo-integrated-dashboard-memberships/v1',
    memberships: Object.freeze([...memberships, Object.freeze({
      endpoint,
      invitationId: membership.invitationId,
      memberId: membership.memberId,
      createdAt: membership.createdAt,
    })]),
  }) satisfies IntegratedDashboardMemberships);
  verifiedDashboardGeneration = authorityGeneration;
  updateSetupConnection();
}

async function clearIntegratedDashboardMembershipState(): Promise<void> {
  const state = profileState;
  if (!state) {
    throw new CodeSecurityRequestError(
      'The VS Code profile cannot update integrated-browser membership state.',
      500,
      false,
      { code: 'integrated_dashboard_membership_storage_unavailable' },
    );
  }
  await state.update(INTEGRATED_DASHBOARD_MEMBERSHIPS_KEY, undefined);
  await state.update(INTEGRATED_DASHBOARD_PENDING_KEY, undefined);
}

function pairedDashboardInvitationFailure(error: CodeSecurityRequestError): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    `The VS Code profile connected successfully, but CodeSecurity could not authorize its integrated dashboard. ${error.message}`,
    error.status,
    error.retryable,
    {
      code: error.code,
      action: 'retry_open_dashboard',
      correlationId: error.correlationId,
    },
  );
}

function integratedDashboardMembershipMissingError(): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    'The retained integrated-browser member is missing, revoked, or was never confirmed by CodeSecurity.',
    409,
    false,
    {
      code: 'integrated_dashboard_membership_missing',
      action: 'pair_integrated_browser_again',
    },
  );
}

function integratedDashboardMembershipPendingError(
  pending: PendingIntegratedDashboardInvitation,
): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    `The integrated browser invitation issued at ${pending.issuedAt} is still waiting for that exact browser to finish pairing.`,
    409,
    true,
    {
      code: 'integrated_dashboard_membership_pending',
      action: 'finish_integrated_browser_pairing',
    },
  );
}

async function reconcilePendingIntegratedDashboardInvitation(
  pending: PendingIntegratedDashboardInvitation,
): Promise<IntegratedDashboardMembership | undefined> {
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const authoritative = await client.waitForBrowserInvitationMembership(pending.invitationId);
  if (authoritative.status === 'active' && authoritative.purpose === 'integrated_dashboard') {
    await recordIntegratedDashboardMembership(pending.endpoint, authoritative);
    await forgetPendingIntegratedDashboardInvitation(pending);
    return integratedDashboardMembership(pending.endpoint);
  }
  if (
    authoritative.status === 'pending'
    && authoritative.purpose === 'integrated_dashboard'
    && Date.parse(authoritative.expiresAt) > Date.now()
  ) {
    throw integratedDashboardMembershipPendingError(pending);
  }
  // Retain recovery history until explicit replacement; absence would make a
  // later dashboard command look like the profile's first browser pairing.
  throw integratedDashboardMembershipMissingError();
}

async function reconcileIntegratedDashboardMembership(
  membership: IntegratedDashboardMembership,
): Promise<void> {
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const authoritative = await client.waitForBrowserInvitationMembership(membership.invitationId);
  if (
    authoritative.status === 'active'
    && authoritative.purpose === 'integrated_dashboard'
    && authoritative.memberId === membership.memberId
    && authoritative.createdAt === membership.createdAt
  ) { verifiedDashboardGeneration = authorityGeneration; updateSetupConnection(); return; }
  verifiedDashboardGeneration = undefined;
  updateSetupConnection();
  // This record is not authority. Retaining it keeps revocation explicit across
  // command retries and editor restarts instead of silently issuing a new grant.
  throw integratedDashboardMembershipMissingError();
}

async function reconcileIntegratedDashboardState(endpoint: string): Promise<boolean> {
  const retained = integratedDashboardMembership(endpoint);
  const pending = pendingIntegratedDashboardInvitation(endpoint);
  // Explicit replacement can consume its invitation before the local ACK is
  // saved. Reconcile that newer intent before the old revoked acknowledgement.
  if (pending && (!retained || pending.invitationId !== retained.invitationId)) {
    return Boolean(await reconcilePendingIntegratedDashboardInvitation(pending));
  }
  if (!retained) return false;
  await reconcileIntegratedDashboardMembership(retained);
  if (pending?.invitationId === retained.invitationId) {
    await forgetPendingIntegratedDashboardInvitation(pending);
  }
  return true;
}


async function openWithBrowserInvitation(
  uri: vscode.Uri,
  description: string,
  purpose: 'integrated_dashboard' | 'extra_browser',
  target: 'integrated' | 'system',
  mode: BrowserInvitationOpenMode = 'interactive',
  reuseExisting = true,
): Promise<Extract<BrowserInvitationMembership, { status: 'active' }> | undefined> {
  if (target === 'integrated') requirePersistentIntegratedBrowser();
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const invitation = await client.issueBrowserInvitation(purpose);
  const endpoint = normalizeEndpoint(config().apiBaseUrl);
  if (purpose === 'integrated_dashboard') {
    await recordPendingIntegratedDashboardInvitation(endpoint, invitation);
  }
  const invitationUri = browserInvitationUri(uri, invitation.bootstrapToken);
  try {
    if (target === 'integrated') {
      await executeIntegratedBrowserOpen(invitationUri, reuseExisting);
    } else {
      await executeSystemBrowserOpen(invitationUri);
    }
  } catch (error) {
    if (!(error instanceof IntegratedBrowserOpenError)) throw error;
    if (mode === 'silent') return undefined;
    const choice = await vscode.window.showErrorMessage(
      `The ${target === 'integrated' ? 'VS Code integrated browser' : 'system browser'} could not open ${description}. The one-time pairing code was not copied, stored, or included in this message.`,
      'Copy pairing code',
    );
    if (choice === 'Copy pairing code') {
      await vscode.env.clipboard.writeText(invitation.bootstrapToken);
      await vscode.window.showInformationMessage(
        'Copied the one-time browser pairing code. Open CodeSecurity on this machine and paste it into Pair this browser within 10 minutes.',
      );
    }
    return undefined;
  }
  const membership = await client.waitForBrowserInvitationMembership(invitation.invitationId);
  if (membership.status === 'active' && membership.purpose === purpose) {
    if (purpose === 'integrated_dashboard') {
      await recordIntegratedDashboardMembership(endpoint, membership);
      const pending = pendingIntegratedDashboardInvitation(endpoint);
      if (pending?.invitationId === invitation.invitationId) {
        await forgetPendingIntegratedDashboardInvitation(pending);
      }
    }
    return membership;
  }
  if (purpose === 'integrated_dashboard' && membership.status === 'pending') {
    const pending = pendingIntegratedDashboardInvitation(endpoint);
    if (pending?.invitationId === invitation.invitationId) {
      throw integratedDashboardMembershipPendingError(pending);
    }
  }
  throw new CodeSecurityRequestError(
    purpose === 'integrated_dashboard'
      ? 'VS Code opened the integrated browser, but CodeSecurity did not confirm its durable browser membership.'
      : 'VS Code opened the additional browser, but CodeSecurity did not confirm its durable browser membership.',
    409,
    false,
    {
      code: purpose === 'integrated_dashboard'
        ? 'integrated_dashboard_membership_unconfirmed'
        : 'extra_browser_membership_unconfirmed',
      action: purpose === 'integrated_dashboard'
        ? 'pair_integrated_browser_again'
        : 'add_browser_again',
    },
  );
}

async function openFirstOwnerIntegratedDashboard(
  bootstrap: FirstOwnerBrowserBootstrap,
  mode: BrowserInvitationOpenMode,
): Promise<void> {
  requirePersistentIntegratedBrowser();
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  // An interrupted setup may already have acknowledged its exact member.
  // Reconcile that proof before cleanup; never issue a replacement implicitly.
  if (await reconcileIntegratedDashboardState(bootstrap.controlOrigin)) {
    await consumeAcknowledgedFirstOwnerBootstrap(bootstrap);
    return;
  }
  // Keep the installer handoff until the independently revocable member is
  // acknowledged. Only the invitation crosses into the browser, in a fragment.
  const invitation = await client.issueBrowserInvitation('integrated_dashboard');
  await recordPendingIntegratedDashboardInvitation(bootstrap.controlOrigin, invitation);
  const uri = browserInvitationUri(workbenchUri(), invitation.bootstrapToken);
  try {
    await executeIntegratedBrowserOpen(uri);
    const membership = await client.waitForBrowserInvitationMembership(invitation.invitationId);
    if (membership.status !== 'active' || membership.purpose !== 'integrated_dashboard') {
      const pending = pendingIntegratedDashboardInvitation(bootstrap.controlOrigin);
      if (membership.status === 'pending' && pending?.invitationId === invitation.invitationId) {
        throw integratedDashboardMembershipPendingError(pending);
      }
      throw new CodeSecurityRequestError(
        'The first IDE connected, but CodeSecurity did not confirm its integrated-browser member.',
        409,
        false,
        {
          code: 'integrated_dashboard_membership_unconfirmed',
          action: 'pair_integrated_browser_again',
        },
      );
    }
    await recordIntegratedDashboardMembership(bootstrap.controlOrigin, membership);
    const pending = pendingIntegratedDashboardInvitation(bootstrap.controlOrigin);
    if (pending?.invitationId === invitation.invitationId) {
      await forgetPendingIntegratedDashboardInvitation(pending);
    }
    await consumeAcknowledgedFirstOwnerBootstrap(bootstrap);
  } catch (error) {
    if (!(error instanceof IntegratedBrowserOpenError)) throw error;
    if (mode === 'silent') {
      const choice = await vscode.window.showWarningMessage(
        'The first IDE connected, but VS Code could not open its integrated CodeSecurity dashboard. Select Open CodeSecurity Dashboard to retry with a fresh one-time browser invitation.',
        'Open CodeSecurity Dashboard',
      );
      if (choice === 'Open CodeSecurity Dashboard') {
        const pending = pendingIntegratedDashboardInvitation(bootstrap.controlOrigin);
        if (pending) await forgetPendingIntegratedDashboardInvitation(pending);
        const opened = await openIntegratedBrowserMemberRoute(
          workbenchUri(),
          'CodeSecurity after first-owner setup',
        );
        if (opened) await consumeAcknowledgedFirstOwnerBootstrap(bootstrap);
      }
      return;
    }
    const choice = await vscode.window.showErrorMessage(
      'The first IDE connected, but VS Code could not open its integrated CodeSecurity dashboard. The one-time browser invitation was not logged or placed in a query string.',
      'Copy pairing code',
    );
    if (choice === 'Copy pairing code') {
      await vscode.env.clipboard.writeText(invitation.bootstrapToken);
      await vscode.window.showInformationMessage(
        'Copied the one-time browser pairing code. Open CodeSecurity on this machine and use it within 10 minutes.',
      );
    }
  }
}

async function consumeAcknowledgedFirstOwnerBootstrap(bootstrap: FirstOwnerBrowserBootstrap): Promise<void> {
  try {
    await consumeFirstOwnerBrowserBootstrap(bootstrap);
  } catch (error) {
    if (!(error instanceof FirstOwnerBootstrapError)) throw error;
    throw new CodeSecurityRequestError(
      error.message,
      undefined,
      false,
      { code: error.code, action: 'restore_first_owner_bootstrap' },
    );
  }
}

async function finishFirstOwnerBeforeExplicitDashboard(): Promise<void> {
  requirePersistentIntegratedBrowser();
  if (await readFirstOwnerBootstrap(normalizeEndpoint(config().apiBaseUrl))) {
    await startIdeConnectionFlow();
  }
}

async function openIntegratedBrowserMemberRoute(
  uri: vscode.Uri,
  description: string,
  options: Readonly<{
    mode?: BrowserInvitationOpenMode;
    forceNewMembership?: boolean;
  }> = {},
): Promise<boolean> {
  requirePersistentIntegratedBrowser();
  const endpoint = normalizeEndpoint(config().apiBaseUrl);
  if (!options.forceNewMembership && await reconcileIntegratedDashboardState(endpoint)) {
    await navigateRetainedIntegratedBrowser(uri);
    return true;
  }
  const pending = pendingIntegratedDashboardInvitation(endpoint);
  if (options.forceNewMembership && pending) {
    await forgetPendingIntegratedDashboardInvitation(pending);
  }
  const membership = await openWithBrowserInvitation(
    uri,
    description,
    'integrated_dashboard',
    'integrated',
    options.mode,
    options.forceNewMembership !== true,
  );
  if (!membership) return false;
  await recordIntegratedDashboardMembership(endpoint, membership);
  return true;
}


async function openIntegratedDashboardAfterPair(
  mode: BrowserInvitationOpenMode = 'interactive',
): Promise<void> {
  try {
    const opened = await openIntegratedBrowserMemberRoute(
      workbenchUri(),
      'CodeSecurity after connecting',
      { mode },
    );
    if (!opened) {
      if (mode === 'silent') {
        throw new StartupDashboardError(
          'The IDE remains connected, but VS Code did not open its integrated CodeSecurity dashboard.',
          'startup_dashboard_open_failed',
        );
      }
      throw new CodeSecurityRequestError(
        'The extension remains connected, but VS Code did not open its integrated CodeSecurity dashboard. Run Open Dashboard to retry with a fresh fragment-only browser authorization.',
        503,
        true,
        {
          code: 'paired_dashboard_open_failed',
          action: 'retry_open_dashboard',
        },
      );
    }
  } catch (error) {
    if (error instanceof StartupDashboardError) throw error;
    if (error instanceof CodeSecurityRequestError) {
      if (error.code === 'paired_dashboard_open_failed') throw error;
      if (error.code === 'workspace_trust_required' || error.code === 'integrated_dashboard_ephemeral_storage') throw error;
      if (error.action === 'pair_integrated_browser_again') throw error;
      const failure = pairedDashboardInvitationFailure(error);
      if (mode === 'silent') {
        throw new StartupDashboardError(failure.message, 'startup_dashboard_invitation_failed');
      }
      throw failure;
    }
    if (error instanceof PairingRequiredError) {
      throw new CodeSecurityRequestError(
        'The VS Code profile connected successfully, but its retained IDE authority was unavailable before CodeSecurity could authorize the integrated dashboard.',
        401,
        false,
        {
          code: 'paired_ide_authority_unavailable',
          action: 'retry_open_dashboard',
        },
      );
    }
    throw error;
  }
}

async function addBrowser(): Promise<void> {
  const choice = await vscode.window.showQuickPick([
    {
      label: 'Copy pairing code for another browser',
      description: 'Recommended — paste the 10-minute one-time code only into an unpaired local browser profile.',
      action: 'copy' as const,
    },
    {
      label: 'Open pairing page in system browser',
      description: 'Use only when the system browser is an unpaired profile; an already-paired browser is rejected.',
      action: 'open' as const,
    },
  ], {
    title: 'Add Browser to Lomo CodeSecurity',
    placeHolder: 'Choose how to add one browser to this local installation.',
  });
  if (!choice) return;
  if (choice.action === 'open') {
    const membership = await openWithBrowserInvitation(
      workbenchUri(),
      'CodeSecurity',
      'extra_browser',
      'system',
      'interactive',
      false,
    );
    if (membership) {
      vscode.window.setStatusBarMessage(
        '$(check) CodeSecurity added one independently revocable browser.',
        5_000,
      );
    }
    return;
  }
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const invitation = await client.issueBrowserInvitation('extra_browser');
  await vscode.env.clipboard.writeText(invitation.bootstrapToken);
  await vscode.window.showInformationMessage(
    'Copied the one-time browser pairing code. Open CodeSecurity on this machine and paste it into Pair this browser within 10 minutes.',
  );
}


async function openDashboard(scanId?: number) {
  if (scanId !== undefined && (!Number.isSafeInteger(scanId) || scanId < 1)) {
    throw new CodeSecurityRequestError('CodeSecurity requires a valid scan identity for this dashboard link.');
  }
  const uri = scanId === undefined ? workbenchUri() : workbenchUri('findings', scanId);
  await finishFirstOwnerBeforeExplicitDashboard();
  await openIntegratedBrowserMemberRoute(uri, 'the CodeSecurity dashboard deep link');
}


async function openWorkbench(
  view: 'projects' | 'jobs' | 'findings' | 'tools' | 'settings',
  scanId?: number,
  scanFindingNumber?: number,
  setup?: 'source' | 'advisor' | 'push-protection',
  sourceSetupPath?: string,
  pushProtectionRepositoryId?: string,
) {
  const uri = workbenchUri(view, scanId, scanFindingNumber, setup, sourceSetupPath, pushProtectionRepositoryId);
  await finishFirstOwnerBeforeExplicitDashboard();
  await openIntegratedBrowserMemberRoute(uri, 'the CodeSecurity workbench deep link');
}

function validFindingContext(value: unknown): FindingCommandContext {
  const resolution = nativeFindings?.resolveFindingContext(value);
  if (resolution?.status === 'current') {
    const folder = nativeFindings?.workspaceFolder(resolution.context.workspaceKey);
    if (folder) assertRepositoryFolder(folder);
    return resolution.context;
  }
  if (resolution?.status === 'ambiguous') {
    throw new CodeSecurityRequestError(
      'This CodeSecurity group contains multiple findings. Expand it and choose one current finding before using this action.',
    );
  }
  if (resolution?.status === 'stale') {
    throw new CodeSecurityRequestError(
      'This CodeSecurity finding is no longer current. Refresh findings and choose it again before using this action.',
      409,
      false,
      { code: 'finding_not_current', action: 'refresh_findings' },
    );
  }
  throw new CodeSecurityRequestError('Choose a current CodeSecurity finding before using this action.');
}

function commandContextFields(context: FindingCommandContext): FindingCommandContext {
  return {
    workspaceKey: context.workspaceKey,
    findingId: context.findingId,
    scanId: context.scanId,
    scanFindingNumber: context.scanFindingNumber,
    findingRevision: context.findingRevision,
    findingsRevision: context.findingsRevision,
  };
}

async function openFinding(value: unknown): Promise<void> {
  const context = validFindingContext(value);
  const uri = workbenchUri('findings', context.scanId, context.scanFindingNumber);
  // Uri#toString() percent-encodes the complete query component and caches
  // that transport form. Keep the exact browser URL for the receipt without
  // populating VS Code's encoded URI cache before the integrated-browser
  // command receives the Uri object.
  const externalUrl = uri.toString(true);
  const receipt: DevelopmentOpenFindingReceipt = Object.freeze({
    workspaceKey: context.workspaceKey,
    findingId: context.findingId,
    scanId: context.scanId,
    scanFindingNumber: context.scanFindingNumber,
    findingRevision: context.findingRevision,
    findingsRevision: context.findingsRevision,
    uri: externalUrl,
    integratedBrowserOpened: false,
  });
  if (developmentContextHydrationEnabled) developmentOpenFindingReceipt = receipt;
  await finishFirstOwnerBeforeExplicitDashboard();
  const opened = await openIntegratedBrowserMemberRoute(uri, 'the exact CodeSecurity finding deep link');
  if (opened) setupProgress?.reviewed(context.workspaceKey);
  if (opened && developmentContextHydrationEnabled && developmentOpenFindingReceipt === receipt) {
    developmentOpenFindingReceipt = Object.freeze({
      ...receipt,
      integratedBrowserOpened: true,
    });
  }
}

async function revealFinding(value: unknown): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const context = validFindingContext(value);
  if (!nativeFindings) throw new CodeSecurityRequestError('CodeSecurity findings are not ready.');
  await nativeFindings.revealFinding(context);
  setupProgress?.reviewed(context.workspaceKey);
}

type AuthoritativeFinding = Readonly<{
  context: FindingCommandContext;
  detail: FindingDetail;
}>;

function sameImmutableFindingIdentity(
  finding: Pick<FindingDetail, 'id' | 'scan_id' | 'scan_finding_number'>,
  context: FindingCommandContext,
): boolean {
  return finding.id === context.findingId
    && finding.scan_id === context.scanId
    && finding.scan_finding_number === context.scanFindingNumber;
}

function sameImmutableFindingEvidence(
  left: FindingSummary,
  right: FindingSummary,
): boolean {
  return left.id === right.id
    && left.scan_id === right.scan_id
    && left.scan_finding_number === right.scan_finding_number
    && left.display_id === right.display_id
    && left.scanner === right.scanner
    && left.rule_id === right.rule_id
    && left.severity === right.severity
    && left.file_path === right.file_path
    && (left.start_line ?? null) === (right.start_line ?? null)
    && (left.start_column ?? null) === (right.start_column ?? null)
    && (left.end_line ?? null) === (right.end_line ?? null)
    && (left.end_column ?? null) === (right.end_column ?? null)
    && left.message === right.message
    && left.fingerprint === right.fingerprint;
}

async function readAuthoritativeFinding(
  context: FindingCommandContext,
  signal?: AbortSignal,
): Promise<AuthoritativeFinding> {
  const detail = await loadFindingDetail(
    request,
    context.scanId,
    context.scanFindingNumber,
    context.findingRevision,
    context.findingsRevision,
    signal,
  );
  if (!sameImmutableFindingIdentity(detail, context)) {
    throw findingContextError('CodeSecurity finding identity changed. Refresh before acting.');
  }
  const indexed = nativeFindings?.finding(context);
  if (!indexed || !sameImmutableFindingEvidence(indexed, detail)) {
    throw findingContextError(
      'CodeSecurity finding identity or immutable scanner evidence changed. Select it again before acting.',
    );
  }
  if (
    detail.revision !== context.findingRevision
    || detail.findings_revision !== context.findingsRevision
  ) {
    throw findingContextError('CodeSecurity returned a different finding revision. Refresh before acting.');
  }
  return Object.freeze({ context, detail });
}

function revisionConflictCanReconcile(error: unknown): boolean {
  return error instanceof CodeSecurityRequestError
    && error.status === 409
    && (error.code === 'revision_conflict' || error.code === 'finding_changed');
}

async function reconcileFindingContext(
  context: FindingCommandContext,
  signal?: AbortSignal,
): Promise<FindingCommandContext> {
  const native = nativeFindings;
  const workspace = native?.store.workspace(context.workspaceKey);
  const folder = native?.workspaceFolder(context.workspaceKey);
  if (!native || !workspace || !folder || workspace.scanId !== context.scanId) {
    throw findingContextError(
      'The finding workspace or scan is no longer current. Refresh before acting.',
    );
  }
  const prior = workspace.findings.find((finding) => (
    finding.id === context.findingId
    && finding.scan_id === context.scanId
    && finding.scan_finding_number === context.scanFindingNumber
  ));
  if (!prior) {
    throw findingContextError(
      'The selected finding is no longer present in the current workspace snapshot.',
    );
  }
  await refreshExactScanDiagnostics(
    folder,
    workspace.projectId,
    context.scanId,
    signal || new AbortController().signal,
    [prior.file_path],
    1,
  );
  const reloaded = native.store.workspace(context.workspaceKey);
  if (
    !reloaded
    || reloaded.projectId !== workspace.projectId
    || reloaded.scanId !== context.scanId
  ) {
    throw findingContextError(
      'The finding workspace advanced to another project or scan during reconciliation.',
    );
  }
  const replacement = reloaded.findings.find((finding) => (
    finding.scan_id === context.scanId
    && finding.scan_finding_number === context.scanFindingNumber
  ));
  if (!replacement) {
    throw findingContextError(
      'The selected finding no longer exists in the authoritative scan snapshot.',
    );
  }
  if (replacement.id !== context.findingId) {
    throw findingContextError(
      'The scan-local finding identity now belongs to a different finding. Select it again before acting.',
    );
  }
  if (!sameImmutableFindingEvidence(prior, replacement)) {
    throw findingContextError(
      'The finding retained its identifier but its immutable scanner evidence changed. Select it again before acting.',
    );
  }
  const reconciled: FindingCommandContext = {
    ...context,
    findingRevision: replacement.revision,
    findingsRevision: reloaded.revision,
  };
  if (!native.finding(reconciled)) {
    throw findingContextError(
      'CodeSecurity could not resolve the selected finding in the authoritative workspace snapshot.',
    );
  }
  return reconciled;
}

async function authoritativeFinding(
  context: FindingCommandContext,
  signal?: AbortSignal,
): Promise<AuthoritativeFinding> {
  try {
    return await readAuthoritativeFinding(context, signal);
  } catch (error) {
    if (!revisionConflictCanReconcile(error)) throw error;
    const reconciled = await reconcileFindingContext(context, signal);
    try {
      return await readAuthoritativeFinding(reconciled, signal);
    } catch (reconciledError) {
      if (!revisionConflictCanReconcile(reconciledError)) throw reconciledError;
      throw findingContextError(
        'The finding changed again during the one bounded reconciliation attempt. Refresh findings and choose it again before acting.',
      );
    }
  }
}

type SourceOpenAcknowledgement = Readonly<{
  id: string;
  status: 'opened' | 'failed' | 'expired';
  revision: number;
  error_code?: string | null;
}>;

export function sourceOpenErrorCode(error: unknown): string {
  if (
    error instanceof CodeSecurityRequestError
    && [
      'workspace_not_open',
      'revision_conflict',
      'finding_not_current',
      'workspace_trust_required',
      'source_editor_not_focused',
    ].includes(error.code || '')
  ) return error.code!;
  return 'source_open_failed';
}

function sourceOpenContextError(message: string, code: 'workspace_not_open' | 'revision_conflict' | 'finding_not_current') {
  return new CodeSecurityRequestError(message, 409, false, { code });
}

async function acknowledgeSourceOpenCommand(
  commandId: string,
  status: 'opened' | 'failed',
  errorCode?: string,
): Promise<void> {
  const acknowledgement = await request<SourceOpenAcknowledgement>(
    `/v1/ide/source-open-commands/${commandId}/ack`,
    {
      method: 'POST',
      body: JSON.stringify({
        status,
        error_code: status === 'failed' ? errorCode : null,
      }),
    },
  );
  if (
    acknowledgement.id !== commandId
    || acknowledgement.status !== status
    || !Number.isSafeInteger(acknowledgement.revision)
    || acknowledgement.revision < 2
  ) {
    throw new CodeSecurityRequestError(
      'CodeSecurity did not persist the exact source-open acknowledgement.',
    );
  }
}

function rememberSourceOpenAcknowledgement(
  commandId: string,
  acknowledgement: Readonly<{ status: 'opened' | 'failed'; errorCode?: string }>,
): void {
  acknowledgedSourceOpenCommands.delete(commandId);
  acknowledgedSourceOpenCommands.set(commandId, acknowledgement);
  while (acknowledgedSourceOpenCommands.size > 128) {
    const oldest = acknowledgedSourceOpenCommands.keys().next().value as string | undefined;
    if (!oldest) break;
    acknowledgedSourceOpenCommands.delete(oldest);
  }
}

export async function persistImmutableSourceOpenOutcome(
  ledger: Map<string, Readonly<{ status: 'opened' | 'failed'; errorCode?: string }>>,
  commandId: string,
  proposed: Readonly<{ status: 'opened' | 'failed'; errorCode?: string }>,
  acknowledge: (outcome: Readonly<{ status: 'opened' | 'failed'; errorCode?: string }>) => Promise<void>,
): Promise<Readonly<{ status: 'opened' | 'failed'; errorCode?: string }>> {
  if (!ledger.has(commandId)) ledger.set(commandId, proposed);
  const immutable = ledger.get(commandId)!;
  await acknowledge(immutable);
  return immutable;
}

async function sourceOpenFindingContext(
  command: SourceOpenCommand,
  signal: AbortSignal,
): Promise<Readonly<{
  folder: vscode.WorkspaceFolder;
  detail: FindingDetail;
  projectId: number;
  projectPrefix: string;
  assertWorkspaceOwner: () => void;
}>> {
  const project = await loadSourceOpenProjectContext(
    request,
    command.command_id,
    command.project_id,
    signal,
  );
  const scan = await loadExactScan(request, command.project_id, command.scan_id, signal);
  if (scan.findings_revision !== command.expected_findings_revision) {
    throw sourceOpenContextError(
      'The selected scan changed before the IDE opened its retained finding.',
      'revision_conflict',
    );
  }
  const detail = await loadFindingDetail(
    request,
    command.scan_id,
    command.scan_finding_number,
    command.expected_finding_revision,
    command.expected_findings_revision,
    signal,
  );
  if (
    detail.id !== command.finding_id
    || detail.revision !== command.expected_finding_revision
    || detail.findings_revision !== command.expected_findings_revision
  ) {
    throw sourceOpenContextError(
      'The source-open command resolved to a different finding identity.',
      'finding_not_current',
    );
  }
  const owner = sourceOpenWorkspaceOwner(project.repoPath);
  const expectedOwnerUri = owner.folder.uri.toString();
  const expectedWorkspaceRoot = owner.workspaceRoot;
  const assertWorkspaceOwner = (): void => {
    const current = sourceOpenWorkspaceOwner(project.repoPath);
    if (
      current.folder.uri.toString() !== expectedOwnerUri
      || current.workspaceRoot !== expectedWorkspaceRoot
    ) {
      throw sourceOpenContextError(
        'The unique open workspace containing this CodeSecurity project changed during source navigation.',
        'workspace_not_open',
      );
    }
  };
  const rebasedDetail = Object.freeze({
    ...detail,
    file_path: rebaseRegisteredProjectFindingPath(owner.projectPrefix, detail.file_path),
  });
  return Object.freeze({
    folder: owner.folder,
    detail: rebasedDetail,
    projectId: project.projectId,
    projectPrefix: owner.projectPrefix,
    assertWorkspaceOwner,
  });
}


function sourceOpenWorkspaceOwner(projectRepoPath: string): Readonly<{
  folder: vscode.WorkspaceFolder;
  workspaceRoot: string;
  projectPrefix: string;
}> {
  requireTrustedWorkspaceSourceAccess();
  const matches = sourceContextFolders().flatMap((folder) => {
    assertRepositoryFolder(folder);
    const workspaceRoot = workspaceSourcePath(folder);
    const projectPrefix = registeredProjectPrefix(workspaceRoot, projectRepoPath);
    return projectPrefix === undefined ? [] : [{ folder, workspaceRoot, projectPrefix }];
  });
  const maximumSpecificity = matches.reduce(
    (maximum, candidate) => Math.max(maximum, candidate.workspaceRoot.length),
    -1,
  );
  const owners = matches.filter((candidate) => candidate.workspaceRoot.length === maximumSpecificity);
  if (owners.length !== 1) {
    throw sourceOpenContextError(
      'The selected IDE does not have exactly one open workspace containing this CodeSecurity project.',
      'workspace_not_open',
    );
  }
  return Object.freeze(owners[0]);
}

async function handleSourceOpenCommand(
  command: SourceOpenCommand,
  signal: AbortSignal,
): Promise<void> {
  const prior = acknowledgedSourceOpenCommands.get(command.command_id);
  if (prior) {
    await persistImmutableSourceOpenOutcome(
      acknowledgedSourceOpenCommands,
      command.command_id,
      prior,
      (outcome) => acknowledgeSourceOpenCommand(command.command_id, outcome.status, outcome.errorCode),
    );
    return;
  }
  if (Date.parse(command.expires_at) <= Date.now()) return;
  let outcome: Readonly<{ status: 'opened' | 'failed'; errorCode?: string }>;
  let visibleFinding: FindingDetail | undefined;
  let failureMessage: string | undefined;
  try {
    requireTrustedWorkspaceSourceAccess();
    const current = await sourceOpenFindingContext(command, signal);
    if (!nativeFindings) throw new CodeSecurityRequestError('CodeSecurity findings are not ready.');
    // A source-open command is one explicit, recipient-bound Web action. Close
    // the REST snapshot-to-stream gap for its exact trusted open workspace
    // before acknowledging navigation, so a retained IDE cannot remain on a
    // zero/stale native projection until the operator clicks Reconnect.
    let projectionContext: FindingCommandContext | undefined;
    if (current.projectPrefix === '') {
      await refreshWorkspaceFolder(current.folder, false, signal, { kind: 'reset' });
      const workspace = nativeFindings.store.workspace(workspaceKey(current.folder));
      if (
        !workspace
        || workspace.projectId !== current.projectId
        || workspace.scanId !== command.scan_id
        || workspace.revision !== command.expected_findings_revision
      ) {
        throw sourceOpenContextError(
          'The selected scan changed while the IDE reconciled its current native projection.',
          'revision_conflict',
        );
      }
      await hydrateWorkspaceFile(
        workspace.key,
        current.detail.file_path,
        workspace.scanId,
        workspace.revision,
      );
      projectionContext = {
        workspaceKey: workspace.key,
        findingId: command.finding_id,
        scanId: command.scan_id,
        scanFindingNumber: command.scan_finding_number,
        findingRevision: command.expected_finding_revision,
        findingsRevision: command.expected_findings_revision,
      };
    }
    const editor = await nativeFindings.revealTargetedFinding(
      current.folder,
      current.detail,
      current.assertWorkspaceOwner,
      projectionContext,
    );
    await focusTargetedTextEditor(editor);
    visibleFinding = current.detail;
    setupProgress?.reviewed(workspaceKey(current.folder));
    outcome = { status: 'opened' };
  } catch (error) {
    if (isAbortError(error) || signal.aborted) throw error;
    const errorCode = sourceOpenErrorCode(error);
    outcome = { status: 'failed', errorCode };
    failureMessage = error instanceof Error ? error.message : String(error);
  }
  // The visible local result becomes immutable before transport. If the ACK
  // response is lost, reconnect replays only this same outcome; it can never
  // turn a file that already opened into a reported failure.
  rememberSourceOpenAcknowledgement(command.command_id, outcome);
  await persistImmutableSourceOpenOutcome(
    acknowledgedSourceOpenCommands,
    command.command_id,
    outcome,
    (remembered) => acknowledgeSourceOpenCommand(command.command_id, remembered.status, remembered.errorCode),
  );
  if (outcome.status === 'opened') {
    void vscode.window.showInformationMessage(
      `Opened ${visibleFinding?.display_id || 'the requested finding'} from the CodeSecurity Web workbench at its exact source range.`,
    );
  } else {
    void vscode.window.showErrorMessage(
      `CodeSecurity could not open the requested Web finding in this IDE: ${failureMessage || 'the source-open command failed'}`,
    );
  }
}

async function focusTargetedTextEditor(editor: vscode.TextEditor): Promise<void> {
  if (vscode.window.activeTextEditor === editor) return;
  const viewColumn = editor.viewColumn;
  const command = viewColumn === undefined ? undefined : FOCUS_EDITOR_GROUP_COMMANDS[viewColumn - 1];
  if (!command) {
    throw new CodeSecurityRequestError(
      'VS Code opened the requested CodeSecurity source but did not expose a focusable editor group.',
      409,
      false,
      { code: 'source_editor_not_focused' },
    );
  }
  const availableCommands = await vscode.commands.getCommands(true);
  if (!availableCommands.includes(command)) {
    throw new CodeSecurityRequestError(
      'VS Code opened the requested CodeSecurity source but cannot focus its exact editor group.',
      409,
      false,
      { code: 'source_editor_not_focused' },
    );
  }
  await vscode.commands.executeCommand(command);
  if (vscode.window.activeTextEditor !== editor) {
    throw new CodeSecurityRequestError(
      'VS Code opened the requested CodeSecurity source behind another editor instead of focusing it.',
      409,
      false,
      { code: 'source_editor_not_focused' },
    );
  }
}

async function setLifecycle(value: unknown): Promise<void> {
  const context = validFindingContext(value);
  const current = await authoritativeFinding(context);
  const choices: Array<{ label: string; action: FindingLifecycle; description: string }> = [
    { label: 'Needs review', action: 'needs_review', description: 'Keep active and blocking according to policy.' },
    { label: 'Non-blocking for gate', action: 'gate_exempt', description: 'Exclude from the gate; a reason is required.' },
    { label: 'Accepted risk', action: 'accepted_risk', description: 'Accept this risk; a reason is required.' },
    { label: 'Ignored', action: 'ignore', description: 'Suppress from active review; a reason is required.' },
    { label: 'False positive', action: 'false_positive', description: 'Suppress as incorrect; a reason is required.' },
    { label: 'Fixed', action: 'fixed', description: 'Mark remediated; a reason is required.' },
    { label: 'Open', action: 'open', description: 'Return to active review.' },
  ];
  const choice = await vscode.window.showQuickPick(choices, {
    title: `Change ${current.detail.display_id} lifecycle`,
    placeHolder: `Current: ${findingLifecycleLabel(current.detail.lifecycle_status)}. Gate remains authoritative until the server confirms.`,
    ignoreFocusOut: true,
  });
  if (!choice) {
    await vscode.window.showInformationMessage(
      `Lifecycle change for ${current.detail.display_id} was cancelled; no mutation request was sent.`,
    );
    return;
  }
  let reason: string | undefined;
  if (SUPPRESSIVE_LIFECYCLES.has(choice.action)) {
    reason = await vscode.window.showInputBox({
      title: `${choice.label} reason`,
      prompt: 'Required audit reason (stored locally by CodeSecurity).',
      validateInput: (value) => {
        const normalized = value.trim();
        if (!normalized) return 'A reason is required for this lifecycle action.';
        if (Array.from(normalized).length > MAX_LIFECYCLE_REASON_CHARACTERS) {
          return `The audit reason must be ${MAX_LIFECYCLE_REASON_CHARACTERS} characters or fewer.`;
        }
        return undefined;
      },
      ignoreFocusOut: true,
    });
    if (!reason?.trim()) {
      await vscode.window.showInformationMessage(
        `Lifecycle change for ${current.detail.display_id} was cancelled; no mutation request was sent.`,
      );
      return;
    }
  }
  await applyFindingLifecycle(current.context, choice.action, reason, current);
}

async function applyFindingLifecycle(
  context: FindingCommandContext,
  action: FindingLifecycle,
  reason?: string,
  knownCurrent?: AuthoritativeFinding,
): Promise<void> {
  const normalizedReason = reason?.trim();
  if (SUPPRESSIVE_LIFECYCLES.has(action) && !normalizedReason) {
    throw new CodeSecurityRequestError('A reason is required for this lifecycle action.');
  }
  if (normalizedReason && Array.from(normalizedReason).length > MAX_LIFECYCLE_REASON_CHARACTERS) {
    throw new CodeSecurityRequestError(
      `The lifecycle reason must be ${MAX_LIFECYCLE_REASON_CHARACTERS} characters or fewer.`,
    );
  }
  const currentResult = knownCurrent || await authoritativeFinding(context);
  const currentContext = currentResult.context;
  const current = currentResult.detail;
  const workspace = nativeFindings?.store.workspace(currentContext.workspaceKey);
  const folder = nativeFindings?.workspaceFolder(currentContext.workspaceKey);
  if (!workspace || !folder || workspace.scanId !== currentContext.scanId) {
    throw findingContextError('The finding workspace or scan is no longer current. Refresh before acting.');
  }
  requireTrustedWorkspaceSourceAccess();
  const response = await request<FindingDetail>(
    `/v1/findings/${current.id}/lifecycle`,
    {
      method: 'PATCH',
      body: JSON.stringify({ action, reason: normalizedReason || null, expected_revision: current.revision }),
    },
  );
  const replacement = validateFindingDetailResponse(
    response,
    currentContext.scanId,
    currentContext.scanFindingNumber,
    currentContext.findingId,
  );
  if (replacement.id !== current.id || replacement.revision <= current.revision) {
    throw findingContextError('CodeSecurity did not confirm a newer authoritative finding revision.');
  }
  const stillCurrent = nativeFindings?.store.workspace(currentContext.workspaceKey);
  const stillOpenFolder = nativeFindings?.workspaceFolder(currentContext.workspaceKey);
  if (
    !stillCurrent
    || !stillOpenFolder
    || stillCurrent.scanId !== currentContext.scanId
    || stillCurrent.projectId !== workspace.projectId
  ) {
    throw findingContextError(
      'CodeSecurity committed the lifecycle change, but this workspace advanced to another scan. Refresh before acting again.',
    );
  }

  // A finding mutation also revises the collection and gate. Never combine
  // the newer gate with an index in which another concurrently changed
  // finding is stale. Remove the old projection and accept only a complete,
  // exact-scan snapshot whose scan and finding-page revisions agree.
  requireTrustedWorkspaceSourceAccess();
  cancelFileHydrations(currentContext.workspaceKey);
  nativeFindings?.invalidateWorkspaceProjection(stillOpenFolder);
  try {
    await refreshTerminalScanDiagnostics(
      stillOpenFolder,
      workspace.projectId,
      currentContext.scanId,
      new AbortController().signal,
      [replacement.file_path],
    );
  } catch (error) {
    if (!(error instanceof CodeSecurityRequestError) || error.status !== 409) throw error;
    throw committedFindingMutationRefreshError(
      error,
      `${replacement.display_id} is now ${findingLifecycleLabel(replacement.lifecycle_status)} with gate effect `
      + `${findingGateEffectLabel(replacement.gate_effect)}. CodeSecurity committed the lifecycle change, but this VS Code profile could not `
      + 'settle the updated findings revision. Refresh Findings to load the authoritative scan; do not repeat the change.',
    );
  }
  const reloaded = nativeFindings?.store.workspace(currentContext.workspaceKey);
  if (!reloaded || reloaded.scanId !== currentContext.scanId) {
    throw findingContextError(
      'CodeSecurity committed the lifecycle change, but the workspace advanced to another scan.',
    );
  }
  const targetIsStale = reloaded.allFilesStale || reloaded.staleFiles.has(replacement.file_path);
  if (!targetIsStale) {
    await hydrateWorkspaceFile(
      currentContext.workspaceKey,
      replacement.file_path,
      reloaded.scanId,
      reloaded.revision,
    );
  }
  const authoritative = targetIsStale
    && reloaded.fileManifest.has(replacement.file_path)
    ? replacement
    : nativeFindings?.finding({
      ...currentContext,
      findingRevision: replacement.revision,
      findingsRevision: reloaded.revision,
    });
  if (!authoritative || authoritative.revision < replacement.revision) {
    throw findingContextError(
      'CodeSecurity committed the lifecycle change but the exact scan reload did not contain its authoritative revision.',
    );
  }
  const lifecycleLabel = findingLifecycleLabel(authoritative.lifecycle_status);
  const gateEffectLabel = findingGateEffectLabel(authoritative.gate_effect);
  vscode.window.setStatusBarMessage(
    `${authoritative.display_id} is now ${lifecycleLabel}.`
    + (lifecycleLabel === gateEffectLabel ? '' : ` Gate effect: ${gateEffectLabel}.`)
    + ' The complete scan revision was reloaded.',
    5_000,
  );
}

async function runAdvisor(value: unknown): Promise<void> {
  const context = validFindingContext(value);
  // validFindingContext resolves every native entry point through the same
  // current projection. Offer consent from that already-visible finding before
  // doing any REST reconciliation: a slow detail read must never make the
  // command appear inert, and cancellation must remain completely local.
  const visible = nativeFindings?.finding(context);
  if (!visible) {
    throw findingContextError(
      'This CodeSecurity finding is no longer current. Refresh findings and choose it again before using Advisor.',
    );
  }
  const confirmation = await vscode.window.showQuickPick([
    {
      label: 'Cancel',
      action: 'cancel' as const,
      description: 'Safe default — no request is sent and no finding data is disclosed.',
    },
    {
      label: 'Run Advisor',
      action: 'run' as const,
      description: 'Resolve the provider; remote review stays in the Web UI one-finding disclosure flow.',
    },
  ], {
    title: `Run Advisor for ${visible.display_id}?`,
    placeHolder: 'Scanner evidence remains authoritative; Advisor output cannot change the gate.',
    ignoreFocusOut: true,
  });
  if (confirmation?.action !== 'run') {
    await vscode.window.showInformationMessage(
      `Advisor for ${visible.display_id} was cancelled; no job request was sent.`,
    );
    return;
  }
  requestPairedProfileReconnect();
  const current = await authoritativeFinding(context);
  const job = await queueAdvisor(current.context, current);
  if (job === null) return;
  const selection = await vscode.window.showInformationMessage(
    `Advisor job #${job.id} is ${job.status}. Open Jobs for its authoritative persisted status; findings and gate remain unchanged until its result is available.`,
    'Open jobs',
  );
  if (selection === 'Open jobs') await openWorkbench('jobs');
}

async function queueAdvisor(
  context: FindingCommandContext,
  knownCurrent?: AuthoritativeFinding,
): Promise<Job | null> {
  const currentResult = knownCurrent || await authoritativeFinding(context);
  const current = currentResult.detail;
  // The provider collection is authoritative only for this admission attempt.
  // Pin its exact revision/configuration in the following POST; the server
  // locks and revalidates the same tuple before it queues any Advisor work.
  const providerRoute = advisorProviderRoute(
    await request<unknown>('/v1/advisor/providers'),
  );
  if (providerRoute.kind === 'remote_single_finding_confirmation') {
    const selection = await vscode.window.showInformationMessage(
      `${current.display_id} is configured for the active ${providerRoute.transport} Advisor provider ${providerRoute.providerId}. `
      + 'Remote review requires the Web UI to show and bind the exact one-finding disclosure preview before you explicitly authorize transmission. Open the exact finding, then choose Triage to review that preview. No prompt was sent.',
      REMOTE_ADVISOR_PREVIEW_ACTION,
    );
    if (selection === REMOTE_ADVISOR_PREVIEW_ACTION) {
      await openWorkbench('findings', current.scan_id, current.scan_finding_number);
    }
    return null;
  }
  const job = await request<Job>(`/v1/findings/${current.id}/triage`, {
    method: 'POST',
    headers: durableCommandHeaders(),
    body: JSON.stringify({
      model: null,
      expected_revision: current.revision,
      advisor_provider_pin: providerRoute.pin,
    }),
  });
  if (job.kind !== 'advisor' || job.finding_id !== current.id || !Number.isSafeInteger(job.id)) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid Advisor job acknowledgement.');
  }
  return job;
}

async function rescanFile(value: unknown): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const context = validFindingContext(value);
  const current = await authoritativeFinding(context);
  const folder = nativeFindings?.workspaceFolder(current.context.workspaceKey);
  const finding = current.detail;
  if (!folder || !finding) {
    throw findingContextError('The finding workspace or scan is no longer current. Refresh before rescanning.');
  }
  const fileUri = vscode.Uri.joinPath(folder.uri, ...finding.file_path.split('/'));
  const target = sourceContextTarget(fileUri, true);
  const selection = await vscode.window.showInformationMessage(
    `Scan only ${finding.file_path} for ${finding.display_id}? Save the file first so CodeSecurity reads its current contents.`,
    'Scan exact file',
  );
  if (selection !== 'Scan exact file') {
    await vscode.window.showInformationMessage(
      `Exact file scan for ${finding.display_id} was cancelled; no scan request was sent.`,
    );
    return;
  }
  validFindingContext(current.context);
  await scanWorkspace(target);
}

type DeleteFindingAcknowledgement = {
  deleted: boolean;
  finding_id: number;
  scan_id: number;
};

async function deleteFinding(value: unknown): Promise<void> {
  const context = validFindingContext(value);
  const current = await authoritativeFinding(context);
  const confirmation = await vscode.window.showQuickPick([
    {
      label: 'Cancel',
      action: 'cancel' as const,
      description: `Keep ${current.detail.display_id}; no request will be sent.`,
    },
    {
      label: 'Delete permanently',
      action: 'delete' as const,
      description: 'Recalculate the authoritative gate. This cannot be undone.',
    },
  ], {
    title: `Delete ${current.detail.display_id} from scan #${current.detail.scan_id}?`,
    placeHolder: `Rule ${current.detail.rule_id}. Cancel is the safe default.`,
    ignoreFocusOut: true,
  });
  if (confirmation?.action !== 'delete') {
    await vscode.window.showInformationMessage(
      `Deletion of ${current.detail.display_id} was cancelled; no delete request was sent.`,
    );
    return;
  }
  await deleteFindingAuthoritatively(current.context, current);
}

async function deleteFindingAuthoritatively(
  context: FindingCommandContext,
  knownCurrent?: AuthoritativeFinding,
): Promise<void> {
  const currentResult = knownCurrent || await authoritativeFinding(context);
  const currentContext = currentResult.context;
  const current = currentResult.detail;
  const workspace = nativeFindings?.store.workspace(currentContext.workspaceKey);
  const folder = nativeFindings?.workspaceFolder(currentContext.workspaceKey);
  if (!workspace || !folder || workspace.scanId !== currentContext.scanId) {
    throw findingContextError('The finding workspace or scan is no longer current. Refresh before deleting.');
  }
  requireTrustedWorkspaceSourceAccess();
  const acknowledgement = await request<DeleteFindingAcknowledgement>(
    `/v1/findings/${current.id}?expected_revision=${current.revision}`,
    { method: 'DELETE' },
  );
  if (
    !acknowledgement
    || acknowledgement.deleted !== true
    || acknowledgement.finding_id !== current.id
    || acknowledgement.scan_id !== currentContext.scanId
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid finding deletion acknowledgement.');
  }
  const stillCurrent = nativeFindings?.store.workspace(currentContext.workspaceKey);
  const stillOpenFolder = nativeFindings?.workspaceFolder(currentContext.workspaceKey);
  if (
    !stillCurrent
    || !stillOpenFolder
    || stillCurrent.scanId !== currentContext.scanId
    || stillCurrent.projectId !== workspace.projectId
  ) {
    throw findingContextError(
      'CodeSecurity committed the deletion, but this workspace advanced to another scan. Refresh before acting again.',
    );
  }

  // The mutation is committed, but the acknowledgement intentionally does not
  // carry a gate. Remove the now-stale local projection and accept a new gate
  // only from the exact authoritative scan resource and its complete pages.
  requireTrustedWorkspaceSourceAccess();
  cancelFileHydrations(currentContext.workspaceKey);
  nativeFindings?.invalidateWorkspaceProjection(stillOpenFolder);
  try {
    await refreshTerminalScanDiagnostics(
      stillOpenFolder,
      workspace.projectId,
      currentContext.scanId,
      new AbortController().signal,
    );
  } catch (error) {
    if (!(error instanceof CodeSecurityRequestError) || error.status !== 409) throw error;
    throw committedFindingMutationRefreshError(
      error,
      `${current.display_id} was deleted. CodeSecurity committed the deletion, but this VS Code profile could not settle `
      + 'the updated findings revision. Refresh Findings to load the authoritative scan; do not repeat the deletion.',
    );
  }
  await vscode.window.showInformationMessage(
    `${current.display_id} was deleted. CodeSecurity reloaded scan #${currentContext.scanId} and its authoritative gate.`,
  );
}


function repositoryRecords(): readonly RepositoryContextRecord[] {
  return readRepositoryContexts(repositoryState?.get(REPOSITORY_CONTEXT_STATE_KEY));
}

function managedParents(): readonly string[] {
  return managedRepositoryParents(repositoryState?.get(REPOSITORY_CONTEXT_STATE_KEY));
}

async function persistRepositoryMetadata(build: () => unknown, assertCurrent: () => void): Promise<void> {
  const write = repositoryStateWrites.catch(() => undefined).then(async () => {
    assertCurrent();
    const state = repositoryState;
    if (!state) throw authorityAbortError();
    await state.update(REPOSITORY_CONTEXT_STATE_KEY, build());
    assertCurrent();
  });
  repositoryStateWrites = write;
  await write;
}

function selectedRepositoryContexts(): readonly Readonly<{
  record: RepositoryContextRecord; parent: vscode.WorkspaceFolder; folder: vscode.WorkspaceFolder;
}>[] {
  const open = vscode.workspace.workspaceFolders || [];
  return repositoryRecords().flatMap(record => {
    const parent = open.find(folder => folder.uri.toString() === record.parent_uri);
    if (!parent) return [];
    // Classify before touching a filesystem: UNC and unsupported remotes stay fenced.
    workspaceSourcePath(parent);
    const uri = vscode.Uri.joinPath(parent.uri, ...record.relative_path.split('/'));
    return [{ record, parent, folder: { uri, name: record.relative_path, index: parent.index } }];
  });
}

function sourceContextFolders(): readonly vscode.WorkspaceFolder[] {
  const selected = selectedRepositoryContexts();
  const parents = new Set(managedParents());
  const folders = [...(vscode.workspace.workspaceFolders || []).filter(folder => !parents.has(folder.uri.toString())),
    ...selected.map(item => item.folder)];
  for (const item of selected) {
    const target = Object.freeze({ ...repositorySourceTarget(item.folder, item.parent, vscode.workspace.workspaceFolders || []), contextGeneration: repositoryContextGeneration });
    if (!sourceTargets.has(target.key)) rememberSourceTarget(target);
  }
  setupProgress?.selectRoots(folders.map(workspaceKey));
  return folders;
}

function assertRepositoryFolder(folder: vscode.WorkspaceFolder): void {
  const selected = selectedRepositoryContexts().find(item => item.folder.uri.toString() === folder.uri.toString());
  if (selected) {
    try { verifyRepositoryContext(selected.record, selected.parent.uri.fsPath); }
    catch (error) { setupProgress?.observeRepository(workspaceKey(folder), 0, undefined); throw error; }
  }
}

function sourceContextTarget(uri: vscode.Uri, file = false): SourceTarget {
  const folders = sourceContextFolders();
  const target = file ? sourceTargetForFileUri(uri, folders) : sourceTargetForUri(uri, folders);
  const selected = selectedRepositoryContexts().find(item => item.folder.uri.toString() === target.owner.uri.toString());
  if (!selected) return target;
  verifyRepositoryContext(selected.record, selected.parent.uri.fsPath);
  return Object.freeze({ ...target, workspaceOwner: selected.parent, contextGeneration: repositoryContextGeneration });
}

async function rememberRepositoryProject(folder: vscode.WorkspaceFolder, project: Project): Promise<void> {
  const contextGeneration = repositoryContextGeneration;
  const generation = authorityGeneration;
  const selected = selectedRepositoryContexts().find(item => item.folder.uri.toString() === folder.uri.toString());
  if (!selected) return;
  verifyRepositoryContext(selected.record, selected.parent.uri.fsPath);
  if (project.repo_path !== workspaceSourcePath(folder)) throw new CodeSecurityRequestError('The selected child project source identity changed.', 409);
  const bound = bindRepositoryProject(selected.record, project.id);
  if (bound.project_id !== selected.record.project_id) {
    if (!repositoryState) throw new CodeSecurityRequestError('Workspace-local repository selection storage is unavailable.');
    await persistRepositoryMetadata(() => ({ schema_version: 1, managed_parents: managedParents(),
      roots: repositoryRecords().map(record => record.parent_uri === bound.parent_uri && record.relative_path === bound.relative_path ? bindRepositoryProject(record, project.id) : record) }), () => {
      requireTrustedWorkspaceSourceAccess();
      if (!extensionActive || contextGeneration !== repositoryContextGeneration || generation !== authorityGeneration || !workspaceIsOpen(folder)) throw authorityAbortError();
      assertRepositoryFolder(folder);
    });
    assertRepositoryFolder(folder);
  }
}

async function requireSourceTransferCapability(signal?: AbortSignal): Promise<void> {
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  const health = await authorityOperation(operationSignal => client.publicHealth(operationSignal), signal);
  setupProgress?.backend(health && typeof health === 'object' ? (health as Record<string, unknown>).ok : false);
  admittedSourceSnapshotLimits(health && typeof health === 'object' && !Array.isArray(health)
    ? (health as Record<string, unknown>).source_snapshot_limits : undefined);
}

async function reviewRepositorySourceAuthorization(targets: readonly SourceTarget[]): Promise<void> {
  const mounted = targets.filter(target => target.authorizationMode === 'mounted');
  if (!mounted.length) return;
  const previews = [];
  for (const target of mounted) {
    assertCurrentSourceTarget(target);
    previews.push(validateMountedSourcePreview(await request<unknown>('/v1/sources/preview', {
      method: 'POST', body: JSON.stringify({ repo_path: target.repoPath }),
    }), target.repoPath));
    assertCurrentSourceTarget(target);
  }
  if (new Set(previews.map(preview => preview.installation_id)).size !== 1) {
    throw new CodeSecurityRequestError('Source previews belong to different installations. Review the repository selection again.');
  }
  const missing = previews.filter(preview => !preview.authorized).map(preview => preview.repo_path);
  if (!missing.length) return;
  const hostCommand = reviewedRepositoryAuthorizationCommand(missing, previews[0].installation_id);
  if (!hostCommand) throw new CodeSecurityRequestError('The exact repository source authorization command could not be prepared.');
  const action = 'Copy reviewed host command';
  if (await vscode.window.showWarningMessage('Authorize selected repository sources on the backend host', {
    modal: true, detail: missing.join('\n')
      + '\n\nThese exact narrow roots need mounted source authorization. Copy the reviewed command and run it from the backend source checkout on its host. It preserves existing roots and applies the reviewed batch once. The editor does not execute it or authorize the parent.',
  }, action) === action) {
    for (const target of targets) assertCurrentSourceTarget(target);
    await vscode.env.clipboard.writeText(hostCommand);
    void vscode.window.showInformationMessage('The reviewed host command was copied. Run it on the backend host, then refresh or explicitly scan the selected repositories. No scan was started.');
  }
}

async function selectRepositoryContexts(): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const open = [...(vscode.workspace.workspaceFolders || [])];
  if (!open.length) return offerWorkspaceFolder();
  if (!repositoryState) throw new CodeSecurityRequestError('Workspace-local repository selection storage is unavailable.');
  const parents = open.map(folder => ({ label: folder.name, description: folder.uri.fsPath, folder }));
  const picked = open.length === 1 ? parents[0] : await vscode.window.showQuickPick(parents, {
    title: 'Choose the open parent for repository discovery', placeHolder: 'The parent stays open; each selected repository retains its own source authorization.',
  });
  if (!picked) return;
  if (!parents.includes(picked)) throw new CodeSecurityRequestError('Choose one exact current open parent.');
  const parent = picked.folder;
  const contextGeneration = repositoryContextGeneration;
  const generation = authorityGeneration;
  const endpoint = normalizeEndpoint(config().apiBaseUrl);
  const assertSelectionCurrent = () => {
    requireTrustedWorkspaceSourceAccess();
    if (contextGeneration !== repositoryContextGeneration || generation !== authorityGeneration
      || endpoint !== normalizeEndpoint(config().apiBaseUrl)
      || !(vscode.workspace.workspaceFolders || []).some(folder => folder.uri.toString() === parent.uri.toString())) throw authorityAbortError();
  };
  workspaceSourcePath(parent);
  const mode = await vscode.window.showQuickPick([
    { label: 'Discover immediate child repositories', browse: false },
    { label: 'Browse one exact nested repository…', browse: true },
  ], { title: 'Select repositories inside the open parent', placeHolder: 'Discovery inspects at most 32 immediate entry names and .git metadata; nested browsing is explicit.' });
  if (!mode) return;
  let records: readonly RepositoryContextRecord[];
  if (mode.browse) {
    const selected = await vscode.window.showOpenDialog({ defaultUri: parent.uri, canSelectFiles: false,
      canSelectFolders: true, canSelectMany: false, title: 'Choose an exact repository below the open parent' });
    if (!selected?.length) return;
    const target = sourceTargetForUri(selected[0], [parent]);
    if (!target.targetPath) throw new CodeSecurityRequestError('Choose a repository below the parent; the parent is not selected.');
    records = [newRepositoryContext(parent.uri.toString(), parent.uri.fsPath, target.targetPath)];
  } else {
    const discovered = await discoverImmediateRepositories(parent.uri.toString(), parent.uri.fsPath);
    assertSelectionCurrent();
    const previous = repositoryRecords();
    const choices = discovered.roots.map(record => ({ label: record.relative_path,
      description: vscode.Uri.joinPath(parent.uri, ...record.relative_path.split('/')).fsPath, record }));
    for (const choice of choices) Object.assign(choice, { picked: previous.some(record => record.parent_uri === choice.record.parent_uri
      && record.relative_path === choice.record.relative_path && record.root_identity === choice.record.root_identity && record.git_identity === choice.record.git_identity) });
    const chosen = await vscode.window.showQuickPick(choices, { canPickMany: true,
      title: 'Choose exact child repository contexts', placeHolder: discovered.truncated
        ? 'Discovery reached its 32-entry bound. Browse an exact nested repository if it is not listed.'
        : 'Select individual repositories. No source files were read and no authority was granted.' });
    if (!chosen) return;
    if (chosen.some(choice => !choices.includes(choice))) throw new CodeSecurityRequestError('Choose only the exact discovered repositories.');
    records = chosen.map(choice => previous.find(record => record.parent_uri === choice.record.parent_uri
      && record.relative_path === choice.record.relative_path && record.root_identity === choice.record.root_identity && record.git_identity === choice.record.git_identity) || choice.record);
  }
  const previous = repositoryRecords();
  const retained = mode.browse ? previous.filter(record => !(record.parent_uri === parent.uri.toString()
    && record.relative_path === records[0].relative_path)) : previous.filter(record => record.parent_uri !== parent.uri.toString());
  assertSelectionCurrent();
  const nextParents = [...new Set([...managedParents(), parent.uri.toString()])];
  const next = readRepositoryContexts({ schema_version: 1, managed_parents: nextParents, roots: [...retained, ...records] });
  const confirm = `Use ${next.length} repository context${next.length === 1 ? '' : 's'}`;
  const detail = records.length ? records.map(record => verifyRepositoryContext(record, parent.uri.fsPath)).join('\n')
    : `No repositories will remain selected below ${parent.uri.fsPath}. The parent remains an editor container and will not be scanned or registered.`;
  if (await vscode.window.showWarningMessage('Review exact repository selection', { modal: true,
    detail: detail + '\n\nThe existing parent stays open. Selection is local workspace metadata and grants no source access. Existing projects, findings and Git settings are preserved; no scan starts.' }, confirm) !== confirm) return;
  assertSelectionCurrent();
  for (const record of records) verifyRepositoryContext(record, parent.uri.fsPath);
  const selectedGeneration = ++repositoryContextGeneration;
  const assertCommittedSelectionCurrent = () => {
    requireTrustedWorkspaceSourceAccess();
    if (!extensionActive || repositoryContextGeneration !== selectedGeneration || authorityGeneration !== generation || endpoint !== normalizeEndpoint(config().apiBaseUrl)
      || !(vscode.workspace.workspaceFolders || []).some(folder => folder.uri.toString() === parent.uri.toString())) throw authorityAbortError();
    for (const record of records) verifyRepositoryContext(record, parent.uri.fsPath);
  };
  await persistRepositoryMetadata(() => {
    const current = repositoryRecords();
    const retainedNow = mode.browse ? current.filter(record => !(record.parent_uri === parent.uri.toString()
      && record.relative_path === records[0].relative_path)) : current.filter(record => record.parent_uri !== parent.uri.toString());
    const selectedNow = records.map(record => current.find(candidate => candidate.parent_uri === record.parent_uri
      && candidate.relative_path === record.relative_path && candidate.root_identity === record.root_identity && candidate.git_identity === record.git_identity) || record);
    return { schema_version: 1, managed_parents: [...new Set([...managedParents(), parent.uri.toString()])], roots: [...retainedNow, ...selectedNow] };
  }, assertCommittedSelectionCurrent);
  clearSourceTargetsOwnedBy(parent);
  const targets = sourceContextFolders().filter(folder => records.some(record => folder.uri.toString()
    === vscode.Uri.joinPath(parent.uri, ...record.relative_path.split('/')).toString())).map(folder => sourceContextTarget(folder.uri));
  await reviewRepositorySourceAuthorization(targets);
  assertCommittedSelectionCurrent();
}

function workspaceKey(folder: vscode.WorkspaceFolder): string {
  return folder.uri.toString();
}

function sourceTargetFolder(target: SourceTarget): vscode.WorkspaceFolder {
  return target.folder as vscode.WorkspaceFolder;
}

function sourceTargetOwner(target: SourceTarget): vscode.WorkspaceFolder {
  return (target.workspaceOwner || target.owner) as vscode.WorkspaceFolder;
}

function assertCurrentSourceTarget(target: SourceTarget): void {
  requireTrustedWorkspaceSourceAccess();
  const current = sourceContextTarget(target.uri as vscode.Uri, target.kind === 'file');
  if (
    current.kind !== target.kind
    || current.key !== target.key
    || current.owner.uri.toString() !== target.owner.uri.toString()
    || current.folder.uri.toString() !== target.folder.uri.toString()
    || current.repoPath !== target.repoPath
    || current.targetPath !== target.targetPath
    || current.authorizationMode !== target.authorizationMode
    || current.sourceId !== target.sourceId
    || current.workspaceOwner?.uri.toString() !== target.workspaceOwner?.uri.toString()
    || current.contextGeneration !== target.contextGeneration
  ) {
    throw new CodeSecurityRequestError(
      'The selected source workspace changed. Choose the exact source again before scanning.',
    );
  }
}

function rememberSourceTarget(target: SourceTarget): vscode.WorkspaceFolder {
  sourceTargets.set(target.key, target);
  const folder = sourceTargetFolder(target);
  nativeFindings?.registerSourceTarget(folder, sourceTargetOwner(target));
  return folder;
}

function clearSourceTarget(folder: vscode.WorkspaceFolder): void {
  const key = workspaceKey(folder);
  setupProgress?.drop(key);
  activeScanObservers.get(key)?.abort();
  activeScanObservers.delete(key);
  cancelFileHydrations(key);
  developmentPriorityPaths.delete(key);
  clearDevelopmentOpenFinding(key);
  refreshCoordinator?.cancel(key);
  realtime?.unbindWorkspace(key);
  nativeFindings?.clearWorkspace(folder);
  sourceTargets.delete(key);
}

function clearSourceTargetsOwnedBy(owner: vscode.WorkspaceFolder): void {
  const ownerKey = workspaceKey(owner);
  const targets = [...sourceTargets.values()]
    .filter((target) => (target.workspaceOwner || target.owner).uri.toString() === ownerKey)
    .map(sourceTargetFolder);
  targets.push(owner);
  const unique = new Map(targets.map((target) => [workspaceKey(target), target]));
  for (const target of [...unique.values()].sort((left, right) => right.uri.path.length - left.uri.path.length)) {
    clearSourceTarget(target);
  }
}


async function offerWorkspaceFolder(): Promise<void> {
  if ((vscode.workspace.workspaceFolders || []).some(folder => managedParents().includes(folder.uri.toString()))) {
    const action = 'Select repositories';
    if (await vscode.window.showInformationMessage('No repository contexts are selected. The open parent remains an editor container and will not be scanned or registered.', action) === action) {
      await selectRepositoryContexts();
    }
    return;
  }
  const selected = await vscode.window.showWarningMessage(
    'Add a folder to this editor workspace first. Adding it does not authorize scanner access, register a project or start a scan.',
    'Add Folder to Workspace…',
  );
  if (selected === 'Add Folder to Workspace…') {
    await vscode.commands.executeCommand('workbench.action.addRootFolder');
  }
}

async function selectWorkspaceFolder(): Promise<vscode.WorkspaceFolder | undefined> {
  const folders = sourceContextFolders();
  if (folders.length === 0) {
    await offerWorkspaceFolder();
    return undefined;
  }
  if (folders.length === 1) {
    return folders[0];
  }
  const activeDocument = vscode.window.activeTextEditor?.document.uri;
  const activeFolder = activeDocument ? (() => {
    try { return sourceContextTarget(activeDocument, true).folder as vscode.WorkspaceFolder; } catch { return undefined; }
  })() : undefined;
  if (activeFolder) {
    return activeFolder;
  }
  const selected = await vscode.window.showQuickPick(
    folders.map((folder) => ({
      label: folder.name,
      description: folder.uri.path,
      folder,
    })),
    {
      title: 'Choose a workspace to scan',
      placeHolder: 'CodeSecurity scans one explicitly selected source root.',
      ignoreFocusOut: true,
    },
  );
  return selected?.folder;
}

async function protectPushes(context: vscode.ExtensionContext, checkOutgoing = false, arguments_: readonly unknown[] = []): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const scopedFolder = sourceControlRepositoryRoot(arguments_, sourceContextFolders());
  const client = apiClient;
  if (!client) throw new PairingRequiredError();
  let selectedFolder: vscode.WorkspaceFolder | undefined;
  let target: SourceTarget | undefined;
  let selected: GitPushRepository | undefined;
  let removed = false;
  const sourceAbort = new AbortController();
  const generation = authorityGeneration;
  const sourceGeneration = repositoryContextGeneration;
  const endpoint = client.endpointIdentity();
  const subscription = vscode.workspace.onDidChangeWorkspaceFolders((event) => {
    if (selectedFolder && event.removed.some((folder) => folder.uri.toString() === (target?.workspaceOwner?.uri.toString() || selectedFolder!.uri.toString()))) {
      removed = true; sourceAbort.abort();
    }
  });
  const assertCurrent = (repository?: GitPushRepository) => {
    requireTrustedWorkspaceSourceAccess();
    if (removed || generation !== authorityGeneration || sourceGeneration !== repositoryContextGeneration
      || client !== apiClient || client.endpointIdentity() !== endpoint
      || !selectedFolder || !target || !workspaceIsOpen(selectedFolder)
      || repository && selected && (repository.repositoryId !== selected.repositoryId || repository.clientSlot !== selected.clientSlot || repository.generation !== selected.generation)) {
      throw new CodeSecurityRequestError('The selected repository or IDE profile changed. Open Push Protection again before changing it.', 409);
    }
    assertCurrentSourceTarget(target);
  };
  const hostContext = Object.freeze({ endpoint, globalStoragePath: context.globalStorageUri.fsPath,
    globalStorageIdentity: context.globalStorageUri.toString(), extensionPath: context.extensionUri.fsPath, nodePath: process.execPath });
  try {
    const adapters: GitPushUiAdapters = {
      chooseRepository: async () => {
        const folders = [...sourceContextFolders()];
        if (!folders.length || folders.length > MAX_WORKSPACE_SCAN_ROOTS) {
          throw new CodeSecurityRequestError('Open between 1 and 32 exact repository roots before configuring push protection.');
        }
        const choices = folders.map((folder) => ({ label: folder.name, description: folder.uri.fsPath, folder }));
        const picked = scopedFolder ? choices.find(choice => choice.folder.uri.toString() === scopedFolder.uri.toString())
          : await vscode.window.showQuickPick(choices, {
            title: 'Choose repository for push protection', placeHolder: 'Select the exact clone. No hook or setting is changed by this selection.', ignoreFocusOut: true,
          });
        if (scopedFolder && !picked) throw new CodeSecurityRequestError('The Source Control repository selection changed. Choose its current root again.', 409);
        if (!picked) return undefined;
        if (!choices.includes(picked)) throw new CodeSecurityRequestError('Select one exact current repository from the list.');
        selectedFolder = picked.folder;
        target = sourceContextTarget(selectedFolder.uri);
        assertCurrent();
        const identity = await client.activeIdeIdentity(); assertCurrent();
        const repository = await inspectGitRepository(selectedFolder.uri.fsPath); assertCurrent();
        // Reuse an already-indexed source project when present. Otherwise the
        // owner-confirmed registration creates a Git-only snapshot project.
        const indexed = nativeFindings?.store.workspace(selectedFolder.uri.toString());
        selected = Object.freeze({ repositoryId: repository.repositoryId, root: repository.root,
          gitDirectory: repository.gitDirectory, projectId: indexed?.projectId || null,
          name: selectedFolder.name, clientSlot: identity.clientSlot, generation: identity.generation });
        return selected;
      },
      assertCurrent,
      request,
      inspectPolicy: async (repository, policy) => {
        const host = await inspectGitPushPolicy(repository, policy, hostContext);
        assertCurrent(repository);
        if (selectedFolder) setupProgress?.observedProtection(workspaceKey(selectedFolder), host);
        return host;
      },
      applyPolicy: async (repository, policy) => {
        const host = await applyGitPushPolicy(repository, policy, hostContext);
        assertCurrent(repository);
        if (selectedFolder) setupProgress?.observedProtection(workspaceKey(selectedFolder), host);
        return host;
      },
      removePolicy: (repository, policy) => removeGitPushPolicy(repository, policy, hostContext),
      choose: async (choices, title, placeHolder) => {
        const picked = await vscode.window.showQuickPick([...choices], { title, placeHolder, ignoreFocusOut: true });
        return picked && choices.includes(picked) ? picked.id : undefined;
      },
      confirm: async (title, detail, action) => await vscode.window.showWarningMessage(title, { modal: true, detail }, action) === action,
      // Informational notices resolve on dismissal, not when displayed. They
      // must not hold the next Settings navigation or keep this action open.
      showStatus: async (message) => { void vscode.window.showInformationMessage(message); },
      openSettings: async () => {
        assertCurrent();
        if (!selected) throw new CodeSecurityRequestError('Choose one exact repository before opening push protection Settings.', 409);
        await openWorkbench('settings', undefined, undefined, 'push-protection', undefined, selected.repositoryId);
      },
    };
    if (checkOutgoing) {
      await requireSourceTransferCapability(sourceAbort.signal);
      await runGitPushScan({ ...adapters,
        showBlocked: async (message, scanIds) => {
          const action = await vscode.window.showWarningMessage(message, 'Review blocking findings', 'Open protection settings');
          assertCurrent();
          if (action === 'Open protection settings') { await adapters.openSettings(); return; }
          if (action !== 'Review blocking findings') return;
          const choices = scanIds.map(scanId => ({ label: `Scan #${scanId}`, description: 'Blocked outgoing committed tree', scanId }));
          const chosen = choices.length === 1 ? choices[0] : await vscode.window.showQuickPick(choices, {
            title: 'Review blocking outgoing findings', placeHolder: 'Choose a failed committed-tree scan.', ignoreFocusOut: true,
          });
          assertCurrent();
          if (chosen && choices.includes(chosen)) await openWorkbench('findings', chosen.scanId);
        },
        showRecovery: async (message) => {
          if (await vscode.window.showWarningMessage(message, 'Open Jobs') === 'Open Jobs') {
            assertCurrent(); await openWorkbench('jobs');
          }
        },
        selectTarget: async (repository) => {
          const destinations = await readGitPushDestinations(repository); assertCurrent();
          if (!destinations.length) throw new CodeSecurityRequestError('Configure a push destination for this exact repository before checking outgoing commits.');
          const remoteChoices = destinations.map((item) => ({ label: item.name, description: item.destination, item }));
          const remote = await vscode.window.showQuickPick(remoteChoices, { title: 'Choose exact push destination',
            placeHolder: 'Only remote reference metadata will be read; no push occurs.', ignoreFocusOut: true });
          assertCurrent();
          if (!remote) return undefined;
          if (!remoteChoices.includes(remote)) throw new CodeSecurityRequestError('Select one exact offered push destination.');
          const refs = await readGitLocalRefs(repository); assertCurrent();
          const refChoices = refs.map((item) => ({ label: item.ref, description: item.oid, item }));
          const ref = await vscode.window.showQuickPick(refChoices, { title: 'Choose exact local reference',
            placeHolder: 'Select the committed branch or tag you intend to push.', ignoreFocusOut: true });
          assertCurrent();
          if (!ref) return undefined;
          if (!refChoices.includes(ref)) throw new CodeSecurityRequestError('Select one exact offered local reference.');
          const remoteRef = await vscode.window.showInputBox({ title: 'Exact destination reference',
            prompt: 'Enter the full remote reference, for example refs/heads/main. No default is assumed.', ignoreFocusOut: true,
            validateInput: (value) => {
              try { parseGitPushInput(`${ref.item.ref} ${ref.item.oid} ${value} ${'0'.repeat(ref.item.oid.length)}\n`, repository.format); return undefined; }
              catch (error) {
                if (!(error instanceof GitPushBoundaryError)) throw error;
                return 'Enter one valid full Git reference such as refs/heads/main.';
              }
            },
          });
          assertCurrent();
          return remoteRef === undefined ? undefined : { destination: remote.item.destination, localRef: ref.item.ref,
            localOid: ref.item.oid, remoteRef };
        },
        withProgress: async (task) => vscode.window.withProgress({ location: vscode.ProgressLocation.Notification,
          title: 'CodeSecurity: outgoing committed files', cancellable: true }, async (progress, token) => {
          // A user cancellation is not a server event. Wake the durable job
          // observer so it can submit cancellation without waiting for the
          // scanner's next revision, while retaining its cleanup observation.
          const cancellation = token.onCancellationRequested(() => realtime?.wakeAllJobs());
          try {
            return await task({
              signal: sourceAbort.signal, cancellationRequested: () => token.isCancellationRequested,
              report: (message) => progress.report({ message }),
              observe: (jobId, scanId) => observePersistedJob(jobId, scanId, sourceAbort.signal,
                () => token.isCancellationRequested, progress),
            });
          } finally { cancellation.dispose(); }
        }),
      });
    } else await runGitPushProtection(adapters);
  } finally { subscription.dispose(); }
}


async function reopenWorkspaceInRemoteWsl(): Promise<void> {
  const folder = await selectWorkspaceFolder();
  if (!folder) return;
  const sourceKind = classifyWorkspaceSourceUri(folder.uri);
  if (isNativeWindowsWorkspace(folder) || sourceKind === 'wsl-unc') {
    const remoteWsl = vscode.extensions.getExtension(REMOTE_WSL_EXTENSION_ID);
    if (!remoteWsl) {
      throw new CodeSecurityRequestError(
        'Install and enable the official Microsoft WSL extension (ms-vscode-remote.remote-wsl), then retry.',
      );
    }
    const commands = await vscode.commands.getCommands(true);
    if (!commands.includes(REMOTE_WSL_REOPEN_COMMAND)) {
      throw new CodeSecurityRequestError(
        'The official Microsoft WSL extension is installed, but its reopen command is unavailable. Enable it and retry.',
      );
    }
    await vscode.commands.executeCommand(REMOTE_WSL_REOPEN_COMMAND);
    return;
  }
  if (sourceKind === 'local-posix' || sourceKind === 'remote-wsl') {
    throw new CodeSecurityRequestError(
      'This workspace already uses a supported POSIX path; reopening it in Remote WSL is unnecessary.',
    );
  }
  // Reuse the source admission owner so generic UNC and unsupported remote
  // authorities remain fail-closed without receiving the WSL-specific action.
  workspaceSourcePath(folder);
  throw new CodeSecurityRequestError('This workspace source is not supported.');
}


async function ensureProject(folder: vscode.WorkspaceFolder, signal: AbortSignal): Promise<Project> {
  const name = folder.name.replace(/[^a-zA-Z0-9_.-]+/g, '-');
  const repoPath = workspaceSourcePath(folder);
  return ensureWorkspaceProject(request, name, repoPath, signal);
}

async function scanFolder(resourceUri?: vscode.Uri, selectedUris?: readonly vscode.Uri[]): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const selected = resourceUri
    ? [resourceUri]
    : selectedUris && selectedUris.length > 0
      ? [...new Map(selectedUris.map((uri) => [uri.toString(), uri])).values()]
      : [];
  if (selected.length !== 1) {
    throw new CodeSecurityRequestError('Select exactly one folder to scan with CodeSecurity.');
  }
  const target = sourceContextTarget(selected[0]);
  if (typeof vscode.workspace.fs?.stat === 'function') {
    const stat = await vscode.workspace.fs.stat(selected[0]);
    if ((stat.type & vscode.FileType.Directory) === 0) {
      throw new CodeSecurityRequestError('Select a folder, not a file, to start a CodeSecurity scan.');
    }
  }
  await scanWorkspace(target);
}


async function scanFile(
  resourceUri?: vscode.Uri,
  selectedUris?: readonly vscode.Uri[],
): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const selected = resourceUri
    ? [resourceUri]
    : selectedUris && selectedUris.length > 0
      ? [...new Map(selectedUris.map((uri) => [uri.toString(), uri])).values()]
      : [];
  if (selected.length !== 1) {
    throw new CodeSecurityRequestError(
      'Select exactly one supported file to scan with CodeSecurity.',
    );
  }
  // Classify and authorize the selected URI before asking the filesystem to
  // touch it. In particular, a native Windows `\\wsl.localhost` path must
  // fail into the explicit Remote WSL handoff without probing the share.
  const target = sourceContextTarget(selected[0], true);
  if (typeof vscode.workspace.fs?.stat === 'function') {
    const stat = await vscode.workspace.fs.stat(selected[0]);
    if ((stat.type & vscode.FileType.Directory) !== 0) {
      throw new CodeSecurityRequestError(
        'Select a file, not a folder, to start an exact CodeSecurity file scan.',
      );
    }
    if ((stat.type & vscode.FileType.File) === 0) {
      throw new CodeSecurityRequestError(
        'The selected Explorer resource is not a regular file and cannot be scanned.',
      );
    }
  }
  await scanWorkspace(target);
}


async function scanWorkspaceCommand(): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  // View-title commands receive view-owned arguments that are not resource
  // URIs. Workspace scanning deliberately resolves from the open workspace;
  // Explorer resource rows use the separate URI-consuming folder command.
  await scanWorkspace();
}


async function scanRootFolderCommand(): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const folders = sourceContextFolders();
  if (folders.length !== 1) return scanWorkspaceFoldersCommand();
  await scanWorkspace(folders[0]);
}

type WorkspaceScanOutcome = Readonly<{
  target: SourceTarget;
  status: 'completed' | 'partial' | 'failed' | 'cancelled' | 'not_started' | 'unconfirmed';
  scanId?: number;
  jobId?: number;
  detail: string;
  error?: unknown;
}>;

type BatchScanProgress = Readonly<{
  progress: vscode.Progress<{ message?: string; increment?: number }>;
  cancellationToken: vscode.CancellationToken;
}>;

async function showWorkspaceScanOutcomes(outcomes: readonly WorkspaceScanOutcome[]): Promise<void> {
  const selected = await vscode.window.showQuickPick(outcomes.map((outcome) => ({
    label: outcome.target.label,
    description: `${outcome.status.replace('_', ' ')}${outcome.scanId ? ` · scan #${outcome.scanId} · job #${outcome.jobId}` : ''}`,
    detail: `${outcome.target.repoPath} — ${outcome.detail}`,
    outcome,
  })), {
    title: 'CodeSecurity · workspace folder results',
    placeHolder: 'Each folder has its own result. Select a scan to open it, or a problem for guidance.',
    matchOnDescription: true,
    matchOnDetail: true,
  });
  if (selected?.outcome.status === 'unconfirmed') await openWorkbench('jobs');
  else if (selected?.outcome.error) await showCommandFailure(selected.outcome.error);
  else if (selected?.outcome.scanId) await openWorkbench('findings', selected.outcome.scanId);
}

async function scanWorkspaceFoldersCommand(): Promise<void> {
  requireTrustedWorkspaceSourceAccess();
  const open = [...sourceContextFolders()];
  if (!open.length) {
    await offerWorkspaceFolder();
    return;
  }
  const mode = await vscode.window.showQuickPick([
    { label: 'Choose folders…', all: false, discover: false },
    { label: `All ${open.length} workspace folders`, all: true, discover: false },
    { label: 'Choose repositories inside an open parent…', all: false, discover: true },
  ], { title: 'Scan Workspace Folders', placeHolder: `One scan and job per folder; up to ${MAX_WORKSPACE_SCAN_ROOTS} folders per batch.` });
  if (!mode) return;
  if (mode.discover) return selectRepositoryContexts();
  const chosen = mode.all ? open : (await vscode.window.showQuickPick(open.map((folder) => ({
    label: folder.name, description: folder.uri.path, folder,
  })), {
    title: 'Choose workspace folders to scan', canPickMany: true,
    placeHolder: 'Select the exact folders. No source will be read before confirmation.',
  }))?.map((item) => item.folder);
  if (!chosen?.length) return;
  if (chosen.length > MAX_WORKSPACE_SCAN_ROOTS || new Set(chosen.map(folder => folder.uri.toString())).size !== chosen.length
    || chosen.some(folder => !open.some(current => current.uri.toString() === folder.uri.toString()))) {
    throw new CodeSecurityRequestError('Choose between 1 and 32 exact current source contexts without duplicates.');
  }
  const targets = chosen.map(folder => sourceContextTarget(folder.uri));
  const preview: Array<{ target: SourceTarget; detail: string; error?: CodeSecurityRequestError }> = [];
  for (const target of targets) {
    if (target.authorizationMode === 'snapshot') {
      preview.push({ target, detail: 'Bounded native Windows snapshot; files and authorization are validated at scan admission.' });
      continue;
    }
    const boundary = validateMountedSourcePreview(await request<unknown>('/v1/sources/preview', {
      method: 'POST', body: JSON.stringify({ repo_path: target.repoPath }),
    }), target.repoPath);
    preview.push({ target, detail: boundary.authorized
      ? 'Inside a currently configured read-only boundary; admission checks still apply.'
      : `Not started: outside configured boundaries: ${boundary.configured_roots.join(', ')}`,
    ...(!boundary.authorized ? { error: new CodeSecurityRequestError(
      `Source ${target.repoPath} is outside the configured read-only source boundary.`, 422, false,
      { code: 'source_outside_allowed_root', action: 'configure_source_boundary', sourceBoundary: {
        selectedTarget: target.repoPath, authorizedRoots: boundary.configured_roots,
      } },
    ) } : {}), });
  }
  let allowed = preview.filter((item) => !item.error);
  const refused = preview.filter((item) => item.error).map((item): WorkspaceScanOutcome => ({
    target: item.target, status: 'not_started', detail: item.detail, error: item.error,
  }));
  if (!allowed.length) return showWorkspaceScanOutcomes(refused);
  // A native modal cannot scroll a long list of paths on every platform. Keep
  // exact roots in the editor's searchable, scrollable picker and the final
  // modal short enough to leave its actions reachable.
  const reviewed = await vscode.window.showQuickPick(allowed.map((item) => ({
    label: item.target.label, description: item.target.authorizationMode === 'snapshot'
      ? item.target.folder.uri.fsPath : item.target.repoPath,
    detail: item.detail, picked: true, target: item.target,
  })), {
    title: 'Review folders to scan', canPickMany: true,
    placeHolder: 'Review exact paths; uncheck folders to omit. Enter continues, Escape cancels.',
    matchOnDescription: true, matchOnDetail: true,
  });
  if (!reviewed?.length) return;
  if (new Set(reviewed.map(item => item.target.key)).size !== reviewed.length
    || reviewed.some(item => !allowed.some(candidate => candidate.target === item.target))) {
    throw new CodeSecurityRequestError('The reviewed scan selection changed. Choose the exact folders again.');
  }
  const selected = new Set(reviewed.map(item => item.target.key));
  refused.push(...allowed.filter(item => !selected.has(item.target.key)).map((item): WorkspaceScanOutcome => ({
    target: item.target, status: 'not_started', detail: 'Omitted in the final folder review.',
  })));
  allowed = allowed.filter(item => selected.has(item.target.key));
  const confirm = `Scan ${allowed.length} folder${allowed.length === 1 ? '' : 's'}`;
  const confirmation = await vscode.window.showWarningMessage('Review workspace folder scans', {
    modal: true,
    detail: `${allowed.length} reviewed folder${allowed.length === 1 ? '' : 's'} selected; ${refused.length} not started. Source admission checks still apply.`
      + '\n\nEach approved folder runs separately, in the reviewed order. Overlapping roots are not merged. '
      + 'Normal scans do not run Advisor. Cancel stops this batch’s current job and leaves later folders unstarted.',
  }, confirm);
  if (confirmation !== confirm) return;
  const outcomes = new Map(refused.map((outcome) => [outcome.target.key, outcome]));
  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification, title: 'CodeSecurity: workspace folders', cancellable: true,
  }, async (progress, cancellationToken) => {
    let stoppedByError = false;
    for (let index = 0; index < allowed.length; index += 1) {
      const { target } = allowed[index];
      if (cancellationToken.isCancellationRequested || stoppedByError) {
        outcomes.set(target.key, { target, status: 'not_started', detail: stoppedByError
          ? 'Batch stopped after a connection or unexpected failure. Review its result before starting again.'
          : 'Batch cancelled before this folder was started.' });
        continue;
      }
      if (!workspaceIsOpen(sourceTargetFolder(target))) {
        outcomes.set(target.key, { target, status: 'not_started', detail: 'This exact workspace folder was closed after preview.' });
        continue;
      }
      try {
        const outcome = await scanWorkspace(target, {
          cancellationToken,
          // Per-job percentages are not summed into invented batch progress.
          progress: { report: (value) => progress.report({ message: `${index + 1}/${allowed.length} · ${target.label} · ${value.message || ''}` }) },
        });
        if (outcome) {
          outcomes.set(target.key, outcome);
          if (outcome.status === 'unconfirmed') stoppedByError = true;
        }
      } catch (error) {
        // Keep every root represented; unknown errors stop later admission and
        // retain the original error for the ordinary, safe recovery surface.
        stoppedByError = !(error instanceof CodeSecurityRequestError) || error.retryable;
        outcomes.set(target.key, { target, status: 'failed',
          detail: isAbortError(error) ? 'Observation interrupted. Check Jobs before starting another scan.' : commandErrorMessage(error), error,
        });
      }
    }
  });
  await showWorkspaceScanOutcomes(targets.map((target) => outcomes.get(target.key)!));
}


type ScanProgressOutcome = Readonly<{
  kind: 'completed';
  project: Project;
  scan: Scan;
  job: Job;
}> | Readonly<{
  kind: 'failed';
  error: unknown;
  admission: 'not_submitted' | 'unconfirmed' | 'accepted';
  scan?: Scan;
}>;


async function scanWorkspace(
  selected?: vscode.WorkspaceFolder | SourceTarget,
  batch?: BatchScanProgress,
): Promise<WorkspaceScanOutcome | undefined> {
  requireTrustedWorkspaceSourceAccess();
  const explicitTarget = selected && 'authorizationMode' in selected ? selected : undefined;
  const selectedFolder = selected && !explicitTarget ? selected as vscode.WorkspaceFolder : undefined;
  const chosen = selectedFolder || (!selected ? await selectWorkspaceFolder() : undefined);
  if (!explicitTarget && !chosen) {
    return;
  }
  const target = explicitTarget || sourceContextTarget((chosen as vscode.WorkspaceFolder).uri);
  assertCurrentSourceTarget(target);
  const folder = sourceTargetFolder(target);
  workspaceSourcePath(folder);
  const key = workspaceKey(folder);
  if (activeScanObservers.has(key)) {
    if (batch) return { target, status: 'not_started', detail: 'Another scan is already being observed for this folder; this batch does not own or cancel it.' };
    await vscode.window.showInformationMessage(
      `CodeSecurity is already observing a scan for ${folder.name}. `
      + 'Use its progress notification to cancel or wait for the persisted result.',
    );
    return;
  }

  const controller = new AbortController();
  activeScanObservers.set(key, controller);
  try {
    const execute = async (
      progress: vscode.Progress<{ message?: string; increment?: number }>,
      cancellationToken: vscode.CancellationToken,
    ): Promise<ScanProgressOutcome> => {
        let stage: 'preparing' | 'submitting' | 'accepted' = 'preparing';
        let admittedScan: Scan | undefined;
        let cancellationRequested = cancellationToken.isCancellationRequested;
        const requestCancellation = () => {
          cancellationRequested = true;
          progress.report({ message: 'saving cancellation request' });
          if (stage === 'preparing') {
            // No durable job exists yet. Stop bounded snapshot collection,
            // upload, project registration, or stream setup locally without
            // inventing a job cancellation request.
            controller.abort();
          } else {
            // Submission may already have committed despite response loss.
            // Preserve the idempotent request/observation signal so the exact
            // durable job can be found and cancelled once its identity is
            // known.
            realtime?.wakeAllJobs();
          }
        };
        const cancellation = cancellationToken.onCancellationRequested(requestCancellation);
        if (cancellationRequested) requestCancellation();
        try {
          assertCurrentSourceTarget(target);
          let sourceSnapshotDigest: string | undefined;
          let project: Project;
          if (target.authorizationMode === 'snapshot') {
            await requireSourceTransferCapability(controller.signal);
            assertCurrentSourceTarget(target);
            progress.report({ message: 'collecting the selected native Windows source snapshot' });
            const upload = await collectNativeWindowsSourceSnapshot(
              target,
              controller.signal,
            );
            assertCurrentSourceTarget(target);
            progress.report({ message: `admitting ${upload.files.length} bounded source files locally` });
            const admitted = admittedNativeWindowsSourceSnapshot(
              await request<unknown>('/v1/source-snapshots', {
                method: 'POST',
                body: JSON.stringify(upload),
                signal: controller.signal,
              }),
              target,
              upload,
            );
            project = admitted.project as Project;
            sourceSnapshotDigest = admitted.snapshotDigest;
          } else {
            progress.report({ message: 'registering the selected source root' });
            project = await ensureProject(folder, controller.signal);
          }
          assertCurrentSourceTarget(target);
          if (selectedRepositoryContexts().some(item => item.folder.uri.toString() === folder.uri.toString())) await rememberRepositoryProject(folder, project);
          rememberSourceTarget(target);
          const indexed = nativeFindings?.store.workspace(key);
          bindRealtimeWorkspace(
            folder,
            project.id,
            indexed?.projectId === project.id ? indexed.scanId : undefined,
          );
          progress.report({ message: 'connecting authenticated local updates' });
          if (!realtime) throw new CodeSecurityRequestError('CodeSecurity event synchronization is unavailable.');
          await realtime.ensureConnected(controller.signal);
          assertCurrentSourceTarget(target);
          progress.report({
            message: target.kind === 'file'
              ? `persisting exact file scan for ${target.label}`
              : 'persisting scan command',
          });
          stage = 'submitting';
          const scan = await submitWorkspaceScan(
            project.id,
            target.targetPath,
            target.kind === 'workspace' ? undefined : target.kind,
            sourceSnapshotDigest,
            scanAdmissionDeadlineMs(target.authorizationMode, vscode.env.remoteName),
            controller.signal,
            progress,
          );
          stage = 'accepted';
          if (
            !Number.isSafeInteger(scan.id)
            || scan.id < 1
            || scan.project_id !== project.id
            || !Number.isSafeInteger(scan.job_id)
            || (scan.job_id as number) < 1
          ) {
            throw new CodeSecurityRequestError(
              'CodeSecurity accepted the scan without a valid durable job identity. Open Jobs before submitting again.',
            );
          }
          admittedScan = scan;
          setupProgress?.observeRepository(key, project.id, scan);
          realtime.updateWorkspaceScan(key, scan.id);
          const job = await observePersistedJob(
            scan.job_id as number,
            scan.id,
            controller.signal,
            () => cancellationRequested,
            progress,
          );
          return { kind: 'completed', project, scan, job };
        } catch (error) {
          // Resolve the cancellable progress owner before the outer command
          // boundary presents scanner preparation or source remediation.
          // No prompt is awaited from inside the progress callback.
          return { kind: 'failed', error, admission: stage === 'preparing' ? 'not_submitted'
            : stage === 'submitting' ? 'unconfirmed' : 'accepted', scan: admittedScan };
        } finally {
          cancellation.dispose();
        }
      };
    const result = batch ? await execute(batch.progress, batch.cancellationToken)
      : await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification, title: `CodeSecurity: ${target.label}`, cancellable: true,
      }, execute);
    if (result.kind === 'failed') {
      const submissionRefused = result.error instanceof CodeSecurityRequestError
        && result.error.status !== undefined && result.error.status >= 400 && result.error.status < 500;
      if (batch && (result.admission === 'accepted'
        || result.admission === 'unconfirmed' && !submissionRefused)) return {
        target, status: 'unconfirmed', scanId: result.scan?.id, jobId: result.scan?.job_id ?? undefined,
        detail: result.scan
          ? 'The exact scan was accepted, but its terminal result or cancellation could not be confirmed. Check Jobs before starting another scan.'
          : 'Scan submission could not be confirmed. Check Jobs before starting another scan.',
        error: result.error,
      };
      if (batch && isAbortError(result.error)) return {
        target, status: result.admission === 'not_submitted' ? 'not_started' : 'failed',
        scanId: result.scan?.id, jobId: result.scan?.job_id ?? undefined,
        detail: result.admission === 'not_submitted' ? 'Stopped before scan submission.'
          : 'Observation interrupted; cancellation is not confirmed. Check the exact job before starting again.',
      };
      throw result.error;
    }
    let loaded: DiagnosticLoad;
    try {
      loaded = await presentTerminalJob(
        folder, result.project, result.scan, result.job, controller.signal, target.targetPath, !batch,
      );
    } catch (error) {
      if (!batch) throw error;
      return { target, status: 'unconfirmed', scanId: result.scan.id, jobId: result.job.id,
        detail: `Job ${result.job.status}; its finding refresh could not be verified. ${commandErrorMessage(error)}`, error };
    }
    if (result.job.status === 'completed' && loaded.scanStatus === 'completed') {
      if (activeScanObservers.get(key) === controller) activeScanObservers.delete(key);
      // One exact read supplies coverage absent from the compact manifest. Help
      // status cannot change the already committed job or command outcome.
      const contextGeneration = repositoryContextGeneration;
      const generation = authorityGeneration;
      try {
        const scan = await loadExactScan(request, result.project.id, result.scan.id, controller.signal);
        assertCurrentSourceTarget(target);
        const current = nativeFindings?.store.workspace(key);
        if (generation !== authorityGeneration || contextGeneration !== repositoryContextGeneration
          || !current || current.projectId !== result.project.id || current.scanId !== scan.id
          || scan.revision !== current.scanRevision || scan.findings_revision !== current.revision) throw authorityAbortError();
        setupProgress?.observeRepository(key, result.project.id, scan);
      } catch {
        if (generation === authorityGeneration && contextGeneration === repositoryContextGeneration
          && nativeFindings?.store.workspace(key)?.scanId === result.scan.id) setupProgress?.observeRepository(key, result.project.id, undefined);
      }
    }
    return {
      target, scanId: result.scan.id, jobId: result.job.id,
      status: result.job.status === 'completed' ? (loaded.scanStatus === 'partial' ? 'partial' : 'completed')
        : result.job.status === 'cancelled' ? 'cancelled' : 'failed',
      detail: result.job.status === 'failed' ? safeJobDetail(result.job)
        : `${loaded.totalFindings ?? loaded.loaded} persisted findings${loaded.scanStatus === 'partial' ? '; required coverage is incomplete' : ''}.`,
    };
  } finally {
    controller.abort();
    if (activeScanObservers.get(key) === controller) activeScanObservers.delete(key);
  }
}


async function submitWorkspaceScan(
  projectId: number,
  targetPath: string | undefined,
  targetKind: 'file' | 'directory' | undefined,
  sourceSnapshotDigest: string | undefined,
  admissionDeadlineMs: number,
  signal: AbortSignal,
  progress: vscode.Progress<{ message?: string; increment?: number }>,
): Promise<Scan> {
  const command = workspaceScanCommand(projectId, targetPath, targetKind, sourceSnapshotDigest);
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await request<Scan>(
        command.path,
        { ...command.init, signal },
        { deadlineMs: admissionDeadlineMs },
      );
    } catch (error) {
      const retryable = error instanceof CodeSecurityRequestError
        && (error.retryable || error.status !== undefined && error.status >= 500);
      if (!retryable) {
        throw error;
      }
      if (attempt === 3) {
        throw new CodeSecurityRequestError(
          'Could not confirm whether the durable scan command was accepted. '
          + 'The client made three total confirmation attempts with one identity; '
          + 'open Jobs before submitting another scan.',
        );
      }
      progress.report({ message: `confirmation interrupted; replaying the same durable command (${attempt + 1}/3)` });
      await abortableDelay(attempt * 250, signal);
    }
  }
  throw new CodeSecurityRequestError('The durable scan command could not be confirmed.');
}


async function observePersistedJob(
  jobId: number,
  scanId: number,
  signal: AbortSignal,
  cancellationRequested: () => boolean,
  progress: vscode.Progress<{ message?: string; increment?: number }>,
): Promise<Job> {
  let priorProgress = 0;
  return observeJob({
    request,
    jobId,
    scanId,
    signal,
    cancellationRequested,
    onUpdate: (job) => {
      const current = Number.isFinite(job.progress)
        ? Math.min(Math.max(Math.round(job.progress as number), 0), 100)
        : priorProgress;
      progress.report({
        message: jobProgressMessage(job),
        increment: Math.max(current - priorProgress, 0),
      });
      priorProgress = Math.max(priorProgress, current);
    },
    onConnectionIssue: (attempt) => {
      progress.report({
        message: `local control plane unavailable; reconnecting (${attempt}/3), persisted work continues`,
      });
    },
    waitForChange: async (revision, operationSignal) => {
      if (!realtime) throw new CodeSecurityRequestError('CodeSecurity event synchronization is unavailable.');
      await realtime.waitForJob(jobId, scanId, revision, operationSignal);
    },
  });
}


function safeJobDetail(job: Job): string {
  const detail = (job.error_detail || job.detail || '')
    .replace(/[\p{Cc}\p{Cf}]+/gu, ' ')
    .trim()
    .slice(0, 240);
  const errorCode = (job.error_code || '').replace(/[^A-Za-z0-9_.:-]/g, '_').slice(0, 80);
  const code = errorCode ? ` (${errorCode})` : '';
  return detail ? `${detail}${code}` : `The durable worker reported ${job.status}${code}.`;
}


function reportDetachedTerminalActionFailure(error: unknown): void {
  void showCommandFailure(error).then(undefined, () => {
    // The ordinary visible error surface itself failed. Keep a bounded local
    // diagnostic rather than creating an unhandled rejection or exposing the
    // original error object, which may contain local path context.
    console.error('CodeSecurity could not report a terminal scan action failure.');
  });
}


function observeTerminalAction(
  selection: Thenable<string | undefined>,
  onSelection: (value: string | undefined) => Promise<void>,
): void {
  void Promise.resolve(selection)
    .then(onSelection)
    .then(undefined, reportDetachedTerminalActionFailure);
}


async function presentTerminalJob(
  folder: vscode.WorkspaceFolder,
  project: Project,
  scan: Scan,
  initialJob: Job,
  signal: AbortSignal,
  targetPath?: string,
  announce = true,
) {
  const job = initialJob;
  const loaded = await refreshTerminalScanDiagnostics(folder, project.id, scan.id, signal);
  if (!announce) return loaded;
  const evidence = loaded.problemsLimited
    ? `${loaded.totalFindings} persisted findings are indexed in the exact Tree; Problems exceeds `
      + DIAGNOSTIC_PROJECTION_LIMIT_DESCRIPTION
    : `${loaded.loaded} persisted finding${loaded.loaded === 1 ? '' : 's'}`;
  const scope = targetPath ? ` for ${targetPath}` : '';
  if (job.status === 'completed') {
    const outcome = loaded.scanStatus === 'partial'
      ? 'finished with partial evidence; required scanner coverage is incomplete'
      : 'completed';
    const unsafePaths = loaded.skipped
      ? ` and skipped ${loaded.skipped} unsafe path${loaded.skipped === 1 ? '' : 's'}`
      : '';
    observeTerminalAction(
      vscode.window.showInformationMessage(
        `CodeSecurity scan #${scan.id}${scope} ${outcome}; loaded ${evidence}${unsafePaths}.`,
        'Open scan',
      ),
      async (selection) => {
        if (selection === 'Open scan') await openWorkbench('findings', scan.id);
      },
    );
    return loaded;
  }
  if (job.status === 'cancelled') {
    observeTerminalAction(
      vscode.window.showInformationMessage(
        `CodeSecurity scan #${scan.id}${scope} is cancelled. Worker cleanup is confirmed; ${evidence} remain available.`,
        'Open jobs',
      ),
      async (selection) => {
        if (selection === 'Open jobs') await openWorkbench('jobs');
      },
    );
    return loaded;
  }

  // IDE capabilities are workspace/finding scoped. Generic persisted-job
  // retry is an operator-wide action, so this native surface deliberately
  // offers inspection only. A new workspace scan remains an explicit command.
  observeTerminalAction(
    vscode.window.showErrorMessage(
      `CodeSecurity scan #${scan.id}${scope} failed: ${safeJobDetail(job)} ${evidence} remain available.`,
      'Open scan',
      'Open jobs',
    ),
    async (selection) => {
      if (selection === 'Open scan') {
        await openWorkbench('findings', scan.id);
      } else if (selection === 'Open jobs') {
        await openWorkbench('jobs');
      }
    },
  );
  return loaded;
}


async function refreshTerminalScanDiagnostics(
  folder: vscode.WorkspaceFolder,
  projectId: number,
  scanId: number,
  signal: AbortSignal,
  requiredFilePaths: readonly string[] = [],
  // One finding mutation transaction publishes scan.changed and
  // findings.changed separately. Admit at most those two coordinator
  // handoffs before surfacing a genuinely unstable reconciliation.
  maximumCoordinatorReplays = MAX_REVISION_RECONCILIATION_ATTEMPTS - 1,
): Promise<DiagnosticLoad> {
  if (
    !Number.isSafeInteger(maximumCoordinatorReplays)
    || maximumCoordinatorReplays < 0
    || maximumCoordinatorReplays >= MAX_REVISION_RECONCILIATION_ATTEMPTS
  ) {
    throw new CodeSecurityRequestError('CodeSecurity requires a bounded coordinator replay count.');
  }
  for (let replay = 0; replay <= maximumCoordinatorReplays; replay += 1) {
    try {
      return await refreshExactScanDiagnostics(
        folder,
        projectId,
        scanId,
        signal,
        requiredFilePaths,
      );
    } catch (error) {
      if (!(error instanceof RefreshProofSupersededError) || replay === maximumCoordinatorReplays) throw error;
      // An SSE replacement owns the workspace proof until its REST replay is
      // complete. Its joined result is sufficient only when it proves this
      // exact terminal scan and every requested file is current; otherwise ask
      // for the exact scan again. The join can itself lose to an incompatible
      // foreground proof; consume only that typed coordinator conflict inside
      // this same bounded replay loop.
      try {
        const joined = await refreshWorkspaceFolder(folder, false, signal);
        const current = nativeFindings?.store.workspace(workspaceKey(folder));
        const joinedStatus = joined.scanStatus || current?.scanStatus;
        const joinedCoversRequiredFiles = requiredFilePaths.every((path) => (
          current?.files.has(path)
          && !current.allFilesStale
          && !current.staleFiles.has(path)
        ));
        const joinedRequestedTerminalScan = joined.scanId === scanId
          && current?.projectId === projectId
          && current.scanId === scanId
          && current.diagnosticProjection !== 'loading'
          && joinedStatus !== undefined
          && FINDING_SCAN_STATUSES.has(joinedStatus)
          && joinedCoversRequiredFiles;
        if (joinedRequestedTerminalScan) return joined;
      } catch (joinError) {
        if (!(joinError instanceof RefreshProofSupersededError)) throw joinError;
      }
    }
  }
  throw new CodeSecurityRequestError(
    `CodeSecurity scan #${scanId} could not settle after event reconciliation.`,
    409,
    true,
  );
}


type DiagnosticPageSource = (
  scanId: number,
  revision: number,
  maximumFindings: number,
  signal: AbortSignal,
  accept: (items: readonly FindingDiagnostic[]) => Promise<void>,
) => Promise<void>;

// Keep the compact transport behind one narrow adapter so native Problems
// remains independent of cursor and wire details.
const diagnosticPageSource: DiagnosticPageSource = async (
  scanId,
  revision,
  maximumFindings,
  signal,
  accept,
) => {
  const result = await streamFindingDiagnosticPages(request, scanId, revision, accept, {
    signal,
    maximumFindings: Math.max(maximumFindings, 1),
  });
  if (result.revision !== revision || result.total !== maximumFindings) {
    throw new CodeSecurityRequestError(
      `CodeSecurity diagnostic projection did not match revision ${revision} and count ${maximumFindings}.`,
      409,
    );
  }
};


function projectionPriorityPaths(
  folder: vscode.WorkspaceFolder,
  requiredFilePaths: readonly string[],
): readonly string[] {
  if (!developmentContextHydrationEnabled) return requiredFilePaths;
  return [...new Set([
    ...requiredFilePaths,
    ...(developmentPriorityPaths.get(workspaceKey(folder)) || []),
  ])];
}


async function hydrateRequiredFiles(
  folder: vscode.WorkspaceFolder,
  manifest: Awaited<ReturnType<typeof loadFindingFileManifest>>,
  signal: AbortSignal,
  requiredFilePaths: readonly string[] = [],
): Promise<void> {
  const paths = [...new Set(requiredFilePaths)]
    .filter((path) => manifest.files.has(path));
  let next = 0;
  const workers = Array.from({ length: Math.min(paths.length, 4) }, async () => {
    while (next < paths.length) {
      if (signal.aborted) throw authorityAbortError();
      const path = paths[next];
      next += 1;
      await hydrateWorkspaceFile(
        workspaceKey(folder),
        path,
        manifest.scan.id,
        manifest.scan.findings_revision || 0,
        true,
      );
    }
  });
  await Promise.all(workers);
  if (signal.aborted) throw authorityAbortError();
}


async function publishManifestProjection(
  folder: vscode.WorkspaceFolder,
  project: Project,
  manifest: Awaited<ReturnType<typeof loadFindingFileManifest>>,
  signal: AbortSignal,
  requiredFilePaths: readonly string[] = [],
  allowOlderScanIdentity = false,
  documentChangeCheckpoint?: number,
): Promise<DiagnosticLoad> {
  requireTrustedWorkspaceSourceAccess();
  const native = nativeFindings;
  const projectionDocumentChangeCheckpoint = documentChangeCheckpoint
    ?? native?.documentChangeCheckpoint()
    ?? 0;
  const revision = manifest.scan.findings_revision;
  if (!native || !Number.isSafeInteger(revision) || (revision as number) < 1) {
    throw new CodeSecurityRequestError('CodeSecurity returned a manifest without a valid findings revision.');
  }
  if (manifest.scan.project_id !== project.id) {
    throw new CodeSecurityRequestError('CodeSecurity returned a manifest for a different project.', 409);
  }
  if (!workspaceIsOpen(folder) || signal.aborted) throw authorityAbortError();
  const key = workspaceKey(folder);
  const current = native.store.workspace(key);
  const currentSupersedesManifest = current && (
    current.projectId > project.id
    || !allowOlderScanIdentity && current.scanId > manifest.scan.id
    || current.projectId === project.id
      && current.scanId === manifest.scan.id
      && current.revision > (revision as number)
  );
  if (currentSupersedesManifest) {
    if (current.diagnosticProjection === 'loading') {
      throw new CodeSecurityRequestError(
        'A newer CodeSecurity projection is still reconciling.',
        409,
      );
    }
    return {
      loaded: current.diagnosticProjection === 'limited' ? 0 : current.totalFindings,
      skipped: 0,
      scanStatus: current.scanStatus,
      totalFindings: current.totalFindings,
      problemsLimited: current.diagnosticProjection === 'limited',
    };
  }
  cancelFileHydrations(key);
  const limited = manifest.totalFindings > MAX_DIAGNOSTIC_FINDINGS
    || manifest.totalFiles > MAX_DIAGNOSTIC_FILES
    || [...manifest.files.values()].some((file) => file.total > MAX_DIAGNOSTICS_PER_FILE);
  const committed = await native.replaceWorkspaceManifest(
    folder,
    project,
    manifest.scan,
    manifest.files,
    manifest.totalFindings,
    revision as number,
    limited ? 'limited' : 'loading',
    allowOlderScanIdentity,
    projectionDocumentChangeCheckpoint,
  );
  if (!committed || signal.aborted) throw authorityAbortError();
  clearDevelopmentOpenFinding(key);
  if (limited) native.limitWorkspaceDiagnostics(folder, revision as number);
  await hydrateRequiredFiles(
    folder,
    manifest,
    signal,
    projectionPriorityPaths(folder, requiredFilePaths),
  );
  if (signal.aborted) throw authorityAbortError();
  if (limited) {
    // Limited Problems has no compact build whose final surface refresh would
    // launch best-effort editor hydration. Start it only after authoritative
    // state and explicit required paths are settled; it never gates the ACK.
    native.updateVisibleEditors();
    return {
      loaded: 0,
      skipped: 0,
      scanStatus: manifest.scan.status,
      totalFindings: manifest.totalFindings,
      problemsLimited: true,
    };
  }
  const loaded = await native.projectWorkspaceDiagnostics(
    folder,
    revision as number,
    (accept) => diagnosticPageSource(
      manifest.scan.id,
      revision as number,
      manifest.totalFindings,
      signal,
      accept,
    ),
  );
  return {
    ...loaded,
    scanStatus: manifest.scan.status,
    totalFindings: manifest.totalFindings,
    problemsLimited: loaded.limited === true,
  };
}


async function refreshExactScanDiagnostics(
  folder: vscode.WorkspaceFolder,
  projectId: number,
  scanId: number,
  signal: AbortSignal,
  requiredFilePaths: readonly string[] = [],
  maxAttempts = MAX_REVISION_RECONCILIATION_ATTEMPTS,
): Promise<DiagnosticLoad> {
  requireTrustedWorkspaceSourceAccess();
  const coordinator = refreshCoordinator;
  if (!coordinator) throw new CodeSecurityRequestError('CodeSecurity refresh coordination is unavailable.');
  return coordinator.run(
    workspaceKey(folder),
    {
      key: `exact:${scanId}:${++refreshIntentSequence}`,
      proof: `exact:${scanId}`,
      supersedes: true,
    },
    (operationSignal) => withWorkspaceHydrationCancellation(
      folder,
      operationSignal,
      () => refreshExactScanDiagnosticsNow(
        folder,
        projectId,
        scanId,
        operationSignal,
        requiredFilePaths,
        maxAttempts,
      ),
    ),
    signal,
  );
}


async function withWorkspaceHydrationCancellation<T>(
  folder: vscode.WorkspaceFolder,
  signal: AbortSignal,
  operation: () => Promise<T>,
): Promise<T> {
  const cancel = () => cancelFileHydrations(workspaceKey(folder));
  signal.addEventListener('abort', cancel, { once: true });
  try {
    if (signal.aborted) {
      cancel();
      throw authorityAbortError();
    }
    return await operation();
  } finally {
    signal.removeEventListener('abort', cancel);
  }
}


async function refreshExactScanDiagnosticsNow(
  folder: vscode.WorkspaceFolder,
  projectId: number,
  scanId: number,
  signal: AbortSignal,
  requiredFilePaths: readonly string[],
  maxAttempts: number,
): Promise<WorkspaceRefreshResult> {
  requireTrustedWorkspaceSourceAccess();
  const generation = authorityGeneration;
  const documentChangeCheckpoint = nativeFindings?.documentChangeCheckpoint() || 0;
  let lastRevision: number | undefined;
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > MAX_REVISION_RECONCILIATION_ATTEMPTS) {
    throw new CodeSecurityRequestError('CodeSecurity requires a bounded exact-scan reconciliation attempt count.');
  }
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const manifest = await loadFindingFileManifest(request, scanId, signal);
      lastRevision = manifest.scan.findings_revision;
      if (!workspaceIsOpen(folder) || signal.aborted || generation !== authorityGeneration) {
        throw authorityAbortError();
      }
      const project: Project = {
        id: projectId,
        name: folder.name,
        repo_path: workspaceSourcePath(folder),
        revision: nativeFindings?.store.workspace(workspaceKey(folder))?.projectId === projectId
          ? nativeFindings.store.workspace(workspaceKey(folder))?.projectRevision
          : undefined,
      };
      const current = nativeFindings?.store.workspace(workspaceKey(folder));
      const currentCoversRequiredFiles = requiredFilePaths.every((path) => (
        !manifest.files.has(path)
        || Boolean(
          current?.files.has(path)
          && !current.allFilesStale
          && !current.staleFiles.has(path),
        )
      ));
      if (
        current
        && current.projectId === projectId
        && current.scanId === scanId
        && current.revision === manifest.scan.findings_revision
        && (
          manifest.scan.revision === undefined
          || current.scanRevision >= manifest.scan.revision
        )
        && current.totalFindings === manifest.totalFindings
        && current.totalFiles === manifest.totalFiles
        && current.diagnosticProjection !== 'loading'
        && currentCoversRequiredFiles
      ) {
        return currentWorkspaceResult(
          folder,
          current.diagnosticProjection === 'limited' ? 'limited' : 'unchanged',
          manifest.scan.status,
          scanId,
        );
      }
      const scopedManifest = { ...manifest, scan: withFindingScanScope(
        manifest.scan, await request<Scan>(`/v1/scans/${scanId}`, { signal }),
      ) };
      const loaded = await publishManifestProjection(
        folder, project, scopedManifest, signal, requiredFilePaths, false, documentChangeCheckpoint,
      );
      if (generation !== authorityGeneration) throw authorityAbortError();
      bindRealtimeWorkspace(folder, projectId, scanId);
      return {
        kind: loaded.problemsLimited ? 'limited' : 'loaded',
        ...loaded,
        scanId,
      };
    } catch (error) {
      if (!(error instanceof CodeSecurityRequestError) || error.status !== 409) throw error;
      if (attempt === maxAttempts) throw error;
      await abortableDelay(0, signal);
    }
  }
  throw new CodeSecurityRequestError(
    `CodeSecurity scan #${scanId} kept changing during revision ${lastRevision ?? 'unknown'} reconciliation.`,
    409,
  );
}


async function refreshFindings() {
  requireTrustedWorkspaceSourceAccess();
  const folders = [...sourceContextFolders()];
  if (!folders.length) {
    await vscode.window.showInformationMessage((vscode.workspace.workspaceFolders || []).length
      ? 'Select repository contexts inside the open parent before refreshing findings. The parent will not be registered.'
      : 'Open a workspace folder to refresh CodeSecurity findings.');
    return;
  }
  const pending = pendingPairedProfileReconnect;
  if (folders.length === 1) await refreshWorkspaceFolder(folders[0], true);
  else {
    const outcomes: Array<{ label: string; description: string; detail: string; error?: unknown }> = [];
    for (const folder of folders) {
      if (!workspaceIsOpen(folder)) {
        outcomes.push({ label: folder.name, description: 'not refreshed', detail: 'This folder was closed during refresh.' });
        continue;
      }
      try {
        const result = await refreshWorkspaceFolder(folder, false);
        const indexed = result.totalFindings ?? result.loaded;
        outcomes.push({ label: folder.name, description: result.kind.replace('_', ' '),
          detail: `${folder.uri.path} · ${indexed} finding${indexed === 1 ? '' : 's'}`
            + `${result.scanId ? ` · scan #${result.scanId}` : ''}`
            + (result.problemsLimited ? ' · Problems unavailable; exact Findings tree remains available.' : '') });
      } catch (error) {
        // Each root owns its projection. A failed sibling refresh must not
        // erase or replace another root's findings or logical selection.
        outcomes.push({ label: folder.name, description: 'refresh failed', detail: commandErrorMessage(error), error });
      }
    }
    const selected = await vscode.window.showQuickPick(outcomes, {
      title: 'CodeSecurity · refreshed workspace folders',
      placeHolder: 'All open folders were checked without registering new projects. Select a problem for guidance.',
    });
    if (selected?.error) await showCommandFailure(selected.error);
  }
  const reconnect = beginPairedProfileReconnect(
    pending,
    'explicit',
    'workspace_refresh_complete',
  );
  // The authoritative REST refresh above is complete. Realtime recovery is a
  // follow-on health path and must not hold the user's Refresh command open
  // while an event stream is slow to publish its ready frame.
  if (reconnect) void reconnect.catch(reportReconnectFailure);
}

async function refreshWorkspaceFolder(
  folder: vscode.WorkspaceFolder,
  announce: boolean,
  signal?: AbortSignal,
  trigger: WorkspaceRefreshTrigger = { kind: 'manual' },
  deferredBindings?: Map<string, () => void>,
): Promise<WorkspaceRefreshResult> {
  const coordinator = refreshCoordinator;
  if (!coordinator) throw new CodeSecurityRequestError('CodeSecurity refresh coordination is unavailable.');
  const intent = trigger.kind === 'manual'
    ? { key: 'manual', proof: 'workspace', supersedes: false }
    : trigger.kind === 'event'
      ? { key: `event:${trigger.event.event_id}`, proof: 'workspace', supersedes: true }
      : { key: `reset:${++refreshIntentSequence}`, proof: 'workspace', supersedes: true };
  const result = await coordinator.run(
    workspaceKey(folder),
    intent,
    (operationSignal) => withWorkspaceHydrationCancellation(
      folder,
      operationSignal,
      () => refreshWorkspaceFolderNow(folder, trigger, operationSignal, deferredBindings),
    ),
    signal,
  );
  if (announce) await announceWorkspaceRefresh(folder, result);
  return result;
}


function currentWorkspaceResult(
  folder: vscode.WorkspaceFolder,
  kind: WorkspaceRefreshResult['kind'],
  scanStatus?: string,
  scanId?: number,
): WorkspaceRefreshResult {
  const current = nativeFindings?.store.workspace(workspaceKey(folder));
  return {
    kind,
    loaded: current?.diagnosticProjection === 'limited' ? 0 : current?.totalFindings || 0,
    skipped: 0,
    totalFindings: current?.totalFindings || 0,
    problemsLimited: current?.diagnosticProjection === 'limited',
    scanStatus: scanStatus ?? current?.scanStatus,
    scanId: scanId ?? current?.scanId,
  };
}


function projectionCoversEvent(
  folder: vscode.WorkspaceFolder,
  event: DomainEvent,
): WorkspaceRefreshResult | undefined {
  if (event.change === 'deleted') return undefined;
  const current = nativeFindings?.store.workspace(workspaceKey(folder));
  if (!current || current.diagnosticProjection === 'loading') return undefined;
  const revision = event.aggregate.revision;
  const covered = event.kind === 'project.changed'
    ? current.projectId === event.scope.project_id && current.projectRevision >= revision
    : event.kind === 'scan.changed'
      ? current.scanId === event.scope.scan_id && current.scanRevision >= revision
      : event.kind === 'findings.changed'
        ? current.scanId === event.scope.scan_id && current.revision >= revision
        : false;
  return covered ? currentWorkspaceResult(folder, 'unchanged') : undefined;
}


function workspaceStateCoversEvent(
  state: Awaited<ReturnType<typeof loadWorkspaceState>>,
  event: DomainEvent,
): boolean {
  const projectId = event.scope.project_id;
  if (projectId === undefined) return false;
  if (!state.project) {
    // A temporarily lagging resolve can legitimately return 404 immediately
    // after a create/update event. Only an authoritative identity deletion is
    // proven by absence; every positive change must remain replayable until
    // its project and revision become visible through REST.
    return event.change === 'deleted'
      && (event.kind === 'project.changed' || event.kind === 'scan.changed');
  }
  if (state.project.id !== projectId) {
    // Project identities come from a non-reusing PostgreSQL sequence. A later
    // project at the same repo path makes an event for the deleted/recreated
    // predecessor obsolete, while an older resolved identity is still lagging.
    return state.project.id > projectId;
  }
  if (event.kind === 'project.changed') {
    return event.change !== 'deleted'
      && (state.project.revision || 0) >= event.aggregate.revision;
  }

  const eventScanId = event.scope.scan_id;
  if (eventScanId === undefined) return true;
  if (!state.scan) return event.change === 'deleted';
  if (state.scan.id !== eventScanId) {
    if (event.kind === 'scan.changed' && event.change === 'deleted') return true;
    // Scan identities are monotonically allocated. A later latest scan makes
    // an event for an older, non-latest scan irrelevant. For non-deletion
    // changes, an older latest scan has not caught up and must not advance the
    // cursor; a deletion is proven by the exact deleted identity being absent.
    return state.scan.id > eventScanId;
  }
  if (event.change === 'deleted') return false;
  if (event.kind === 'scan.changed') {
    return (state.scan.revision || 0) >= event.aggregate.revision;
  }
  if (event.kind === 'findings.changed') {
    return (state.scan.findings_revision || 0) >= event.aggregate.revision;
  }
  return true;
}


async function loadRevisionAwareWorkspaceState(
  repoPath: string,
  trigger: WorkspaceRefreshTrigger,
  signal: AbortSignal,
) {
  let state: Awaited<ReturnType<typeof loadWorkspaceState>> = {};
  for (let attempt = 1; attempt <= MAX_REVISION_RECONCILIATION_ATTEMPTS; attempt += 1) {
    state = await loadWorkspaceState(request, repoPath, signal);
    if (trigger.kind !== 'event' || workspaceStateCoversEvent(state, trigger.event)) return state;
    if (attempt < MAX_REVISION_RECONCILIATION_ATTEMPTS) await abortableDelay(0, signal);
  }
  const event = trigger.kind === 'event' ? trigger.event : undefined;
  throw new CodeSecurityRequestError(
    event
      ? `CodeSecurity state has not reached ${event.kind} revision ${event.aggregate.revision}; `
        + 'the event will be replayed after reconnect.'
      : 'CodeSecurity state changed during refresh reconciliation.',
    409,
    true,
  );
}


async function loadAndPublishRevisionFencedWorkspace(
  folder: vscode.WorkspaceFolder,
  repoPath: string,
  initialState: Readonly<{ project: Project; scan: Scan }>,
  trigger: WorkspaceRefreshTrigger,
  signal: AbortSignal,
  documentChangeCheckpoint: number,
  deferredBindings?: Map<string, () => void>,
) {
  let state = initialState;
  let lastScanRevision: number | undefined;
  let lastManifestRevision: number | undefined;
  for (let attempt = 1; attempt <= MAX_REVISION_RECONCILIATION_ATTEMPTS; attempt += 1) {
    try {
      const manifest = await loadFindingFileManifest(request, state.scan.id, signal);
      lastScanRevision = state.scan.findings_revision;
      lastManifestRevision = manifest.scan.findings_revision;
      if (
        Number.isSafeInteger(lastScanRevision)
        && (lastScanRevision as number) >= 1
        && lastScanRevision === lastManifestRevision
        && manifest.scan.project_id === state.project.id
      ) {
        const indexed = nativeFindings?.store.workspace(workspaceKey(folder));
        const allowOlderScanIdentity = trigger.kind === 'event'
          && trigger.event.kind === 'scan.changed'
          && trigger.event.change === 'deleted'
          && indexed?.scanId === trigger.event.scope.scan_id
          && trigger.event.scope.scan_id !== state.scan.id;
        const loaded = await publishManifestProjection(
          folder,
          state.project,
          { ...manifest, scan: withFindingScanScope(manifest.scan, state.scan) },
          signal,
          [],
          allowOlderScanIdentity,
          documentChangeCheckpoint,
        );
        bindRealtimeWorkspace(folder, state.project.id, state.scan.id, deferredBindings);
        return { project: state.project, scan: manifest.scan, manifest, loaded };
      }
    } catch (error) {
      if (!(error instanceof CodeSecurityRequestError) || error.status !== 409) throw error;
      if (attempt === MAX_REVISION_RECONCILIATION_ATTEMPTS) throw error;
    }
    if (attempt < MAX_REVISION_RECONCILIATION_ATTEMPTS) {
      await abortableDelay(0, signal);
      const next = await loadRevisionAwareWorkspaceState(repoPath, trigger, signal);
      if (
        !next.project
        || !next.scan
        || next.project.id !== state.project.id
        || next.scan.id !== state.scan.id
        || !FINDING_SCAN_STATUSES.has(next.scan.status)
      ) {
        throw new CodeSecurityRequestError(
          'CodeSecurity selected a different latest scan during manifest reconciliation. Refresh again.',
          409,
          true,
        );
      }
      state = { project: next.project, scan: next.scan };
    }
  }
  throw new CodeSecurityRequestError(
    `CodeSecurity latest scan changed during reconciliation `
    + `(scan revision ${lastScanRevision ?? 'missing'}, manifest revision ${lastManifestRevision ?? 'missing'}). `
    + 'Refresh again to load one authoritative revision.',
    409,
    true,
  );
}


async function refreshWorkspaceFolderNow(
  folder: vscode.WorkspaceFolder,
  trigger: WorkspaceRefreshTrigger,
  signal: AbortSignal,
  deferredBindings?: Map<string, () => void>,
): Promise<WorkspaceRefreshResult> {
  requireTrustedWorkspaceSourceAccess();
  const contextGeneration = repositoryContextGeneration;
  if (trigger.kind === 'event') {
    const covered = projectionCoversEvent(folder, trigger.event);
    if (covered) return covered;
  }
  const generation = authorityGeneration;
  const documentChangeCheckpoint = nativeFindings?.documentChangeCheckpoint() || 0;
  assertRepositoryFolder(folder);
  const repoPath = workspaceSourcePath(folder);
  const state = await loadRevisionAwareWorkspaceState(repoPath, trigger, signal);
  if (contextGeneration !== repositoryContextGeneration) throw authorityAbortError();
  assertRepositoryFolder(folder);
  if (state.project && selectedRepositoryContexts().some(item => item.folder.uri.toString() === folder.uri.toString())) await rememberRepositoryProject(folder, state.project);
  setupProgress?.observeRepository(workspaceKey(folder), state.project?.id || 0, state.scan);
  // Folder-removal teardown may run while any REST page is awaited. Do not
  // recreate its realtime binding or native projection after that teardown.
  if (!workspaceIsOpen(folder) || signal.aborted || generation !== authorityGeneration) {
    throw authorityAbortError();
  }
  if (!state.project) {
    clearDevelopmentOpenFinding(workspaceKey(folder));
    realtime?.unbindWorkspace(workspaceKey(folder), trigger.kind !== 'manual');
    nativeFindings?.clearWorkspace(folder, { preserveSourceTarget: true });
    return { kind: 'unregistered', loaded: 0, skipped: 0 };
  }
  if (!state.scan) {
    clearDevelopmentOpenFinding(workspaceKey(folder));
    bindRealtimeWorkspace(folder, state.project.id, undefined, deferredBindings);
    nativeFindings?.clearWorkspace(folder, { preserveSourceTarget: true });
    return { kind: 'no_scan', loaded: 0, skipped: 0 };
  }
  const current = nativeFindings?.store.workspace(workspaceKey(folder));
  if (developmentOpenFindingReceipt?.workspaceKey === workspaceKey(folder)
    && developmentOpenFindingReceipt.scanId !== state.scan.id) {
    clearDevelopmentOpenFinding(workspaceKey(folder));
  }
  const sameIdentity = current?.projectId === state.project.id && current.scanId === state.scan.id;
  const metadataRegressed = sameIdentity && (
    state.project.revision !== undefined && state.project.revision < current.projectRevision
    || state.scan.revision !== undefined && state.scan.revision < current.scanRevision
    || state.scan.findings_revision !== undefined && state.scan.findings_revision < current.revision
  );
  if (metadataRegressed) {
    throw new CodeSecurityRequestError(
      `CodeSecurity returned metadata older than the indexed scan #${state.scan.id}.`,
      409,
      true,
    );
  }
  if (!FINDING_SCAN_STATUSES.has(state.scan.status)) {
    bindRealtimeWorkspace(folder, state.project.id, state.scan.id, deferredBindings);
    if (current?.projectId === state.project.id && current.scanId === state.scan.id) {
      nativeFindings?.updateWorkspaceMetadata(folder, state.project, state.scan);
    }
    return currentWorkspaceResult(folder, 'active', state.scan.status, state.scan.id);
  }
  if (
    current
    && current.projectId === state.project.id
    && current.scanId === state.scan.id
    && state.scan.findings_revision === current.revision
    && current.diagnosticProjection !== 'loading'
  ) {
    bindRealtimeWorkspace(folder, state.project.id, state.scan.id, deferredBindings);
    nativeFindings?.updateWorkspaceMetadata(folder, state.project, state.scan);
    return currentWorkspaceResult(folder, 'unchanged', state.scan.status, state.scan.id);
  }

  const snapshot = await loadAndPublishRevisionFencedWorkspace(
    folder,
    repoPath,
    { project: state.project, scan: state.scan },
    trigger,
    signal,
    documentChangeCheckpoint,
    deferredBindings,
  );
  if (!workspaceIsOpen(folder) || signal.aborted || generation !== authorityGeneration) {
    throw authorityAbortError();
  }
  if (generation !== authorityGeneration) throw authorityAbortError();
  return {
    kind: snapshot.loaded.problemsLimited ? 'limited' : 'loaded',
    ...snapshot.loaded,
    scanStatus: snapshot.scan.status,
    scanId: snapshot.scan.id,
  };
}


async function announceWorkspaceRefresh(
  folder: vscode.WorkspaceFolder,
  result: WorkspaceRefreshResult,
): Promise<void> {
  if (result.kind === 'unregistered') {
    await vscode.window.showInformationMessage(
      `Workspace ${folder.name} is not registered with CodeSecurity. Run Scan Workspace to register it.`,
    );
    return;
  }
  if (result.kind === 'no_scan') {
    await vscode.window.showInformationMessage(`No CodeSecurity scan exists for ${folder.name}.`);
    return;
  }
  if (result.kind === 'active') {
    await vscode.window.showInformationMessage(
      `CodeSecurity scan #${result.scanId} is ${result.scanStatus}; `
      + 'existing Problems remain unchanged until persisted evidence is ready.',
      'Open jobs',
    ).then(async (selection) => {
      if (selection === 'Open jobs') await openWorkbench('jobs');
    });
    return;
  }
  if (result.kind === 'unchanged') {
    const indexed = result.totalFindings ?? result.loaded;
    vscode.window.setStatusBarMessage(
      `CodeSecurity verified ${indexed} indexed finding${indexed === 1 ? '' : 's'} `
      + `at the current revision of ${result.scanStatus} scan #${result.scanId}.`
      + (result.problemsLimited ? ' Problems unavailable; exact Findings tree remains available.' : ''),
      5_000,
    );
    return;
  }
  if (result.kind === 'limited') {
    await vscode.window.showWarningMessage(
      `CodeSecurity indexed ${result.totalFindings} persisted findings from ${result.scanStatus} scan #${result.scanId}. `
      + `The exact Tree and status remain available, but Problems is unavailable above `
      + `${DIAGNOSTIC_PROJECTION_LIMIT_DESCRIPTION}.`,
      'Open scan',
    ).then(async (selection) => {
      if (selection === 'Open scan') await openWorkbench('findings', result.scanId);
    });
    return;
  }
  const unsafePaths = result.skipped
    ? `; ${result.skipped} unsafe path${result.skipped === 1 ? '' : 's'} skipped`
    : '';
  vscode.window.setStatusBarMessage(
    `CodeSecurity loaded ${result.loaded} persisted finding${result.loaded === 1 ? '' : 's'} `
    + `from ${result.scanStatus} scan #${result.scanId}${unsafePaths}.`,
    5_000,
  );
}


function workspaceIsOpen(folder: vscode.WorkspaceFolder): boolean {
  const folders = vscode.workspace.workspaceFolders;
  if (!Array.isArray(folders)) return false;
  if (managedParents().includes(workspaceKey(folder))) return false;
  const target = sourceTargets.get(workspaceKey(folder));
  const ownerKey = (target?.workspaceOwner || target?.owner)?.uri.toString() || workspaceKey(folder);
  if (!folders.some((candidate) => candidate.uri.toString() === ownerKey)) return false;
  try { assertRepositoryFolder(folder); return true; } catch { return false; }
}


function bindRealtimeWorkspace(
  folder: vscode.WorkspaceFolder,
  projectId: number,
  scanId?: number,
  deferredBindings?: Map<string, () => void>,
): void {
  if (!workspaceIsOpen(folder)) return;
  const key = workspaceKey(folder);
  const bind = () => ensureRealtime().bindWorkspace(key, {
    projectId,
    scanId,
    onEvent: async (event: DomainEvent, signal: AbortSignal) => {
      if (!workspaceIsOpen(folder)) return;
      await refreshWorkspaceFolder(folder, false, signal, { kind: 'event', event });
    },
    onReset: async (signal: AbortSignal) => {
      if (!workspaceIsOpen(folder)) return;
      await refreshWorkspaceFolder(folder, false, signal, { kind: 'reset' });
    },
  });
  if (deferredBindings) {
    deferredBindings.set(key, bind);
    return;
  }
  bind();
}
