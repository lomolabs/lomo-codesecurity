const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const Module = require('node:module');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { newRepositoryContext, REPOSITORY_CONTEXT_STATE_KEY } = require('../../dist/repository-context.js');

const {
  CodeSecurityRequestError,
  IDE_CAPABILITY_SCOPES,
} = require('../../dist/client.js');
const { ProfileCredentialStoreError } = require('../../dist/credentials.js');
const { RefreshProofSupersededError, WorkspaceRefreshCoordinator } = require('../../dist/sync.js');

const VALID_BROWSER_INVITATION = `kbi1.${'b'.repeat(24)}.${'c'.repeat(43)}`;
const RETAINED_BROWSER_REUSE_FILTER = 'http://127.0.0.1:8080/?lomo_browser=vscode';
const RETAINED_BROWSER_TAB_TITLE = 'Lomo CodeSecurity · VS Code';
const TEST_CLIENT_SLOT = `ks1_${'s'.repeat(43)}`;
const TEST_ENROLLMENT_REQUEST = `ker1_${'r'.repeat(24)}`;
const TEST_VERIFICATION_CODE = 'ABCD-EF23';

function retainedBrowserUrl(value) {
  const url = new URL(value);
  url.searchParams.set('lomo_browser', 'vscode');
  return url.toString();
}

function simulateBrowserReplacement(tabs, label = RETAINED_BROWSER_TAB_TITLE) {
  for (const tab of tabs) tab.isActive = false;
  const replacement = { label, isActive: true };
  tabs.push(replacement);
  return replacement;
}

function testCapability(generation, label = `generation-${generation}`) {
  const secret = createHash('sha256').update(label).digest('base64url');
  return `kc1.${TEST_CLIENT_SLOT}.${generation}.${secret}`;
}

function testAuthority(endpoint = 'http://127.0.0.1:8080', generation = 1, label) {
  return Object.freeze({
    v: 1,
    endpoint,
    client_slot: TEST_CLIENT_SLOT,
    generation,
    capability: testCapability(generation, label),
    activation_expires_at: '2099-08-29T23:59:59Z',
    enrollment_request_id: TEST_ENROLLMENT_REQUEST,
    enrollment_revision: 1,
    enrollment_verification_code: TEST_VERIFICATION_CODE,
  });
}

function testActiveAuthority(endpoint = 'http://127.0.0.1:8080', generation = 1, label) {
  return Object.freeze({
    v: 1,
    endpoint,
    client_slot: TEST_CLIENT_SLOT,
    generation,
    capability: testCapability(generation, label),
  });
}

function enrollmentEnvelope(record) {
  return {
    request_id: record.enrollment_request_id,
    state: 'awaiting_approval',
    revision: record.enrollment_revision,
    verification_code: record.enrollment_verification_code,
    capability: record.capability,
    scopes: [...IDE_CAPABILITY_SCOPES],
    client_slot: record.client_slot,
    generation: record.generation,
    requested_at: '2099-08-29T23:49:59Z',
    activation_expires_at: record.activation_expires_at,
  };
}

function approvedEnrollmentEnvelope(record) {
  return {
    request_id: record.enrollment_request_id,
    state: 'approved',
    revision: 2,
    decision_at: '2099-08-29T23:50:59Z',
    activation_expires_at: record.activation_expires_at,
  };
}

function activationEnvelope(record) {
  return {
    client_slot: record.client_slot,
    generation: record.generation,
    scopes: [...IDE_CAPABILITY_SCOPES],
  };
}

function browserInvitationEnvelope(token = VALID_BROWSER_INVITATION, purpose = 'integrated_dashboard') {
  const [, invitationId] = token.split('.');
  return {
    bootstrap_token: token,
    invitation_id: invitationId,
    purpose,
    issued_at: '2026-08-30T12:00:00Z',
    expires_at: '2026-08-30T12:10:00Z',
    expires_in: 600,
  };
}

function activeBrowserMembershipEnvelope(invitationId, purpose = 'integrated_dashboard') {
  return {
    invitation_id: invitationId,
    status: 'active',
    purpose,
    member_id: `kbm1_${invitationId}${'m'.repeat(8)}`,
    created_at: '2026-08-30T12:00:01Z',
  };
}

function integratedDashboardMembershipState(
  endpoint = 'http://127.0.0.1:8080',
  token = VALID_BROWSER_INVITATION,
) {
  const [, invitationId] = token.split('.');
  const membership = activeBrowserMembershipEnvelope(invitationId);
  return {
    schema: 'lomo-integrated-dashboard-memberships/v1',
    memberships: [{
      endpoint,
      invitationId,
      memberId: membership.member_id,
      createdAt: membership.created_at,
    }],
  };
}

function pendingIntegratedDashboardState(
  endpoint = 'http://127.0.0.1:8080',
  token = VALID_BROWSER_INVITATION,
) {
  const [, invitationId] = token.split('.');
  return {
    schema: 'lomo-integrated-dashboard-pending/v1',
    invitations: [{
      endpoint,
      invitationId,
      issuedAt: '2099-08-30T12:00:00Z',
      expiresAt: '2099-08-30T12:10:00Z',
    }],
  };
}

class FakeProfileCredentialStore {
  constructor(authorities = [testActiveAuthority()]) {
    this.clientSlot = TEST_CLIENT_SLOT;
    this.authorities = new Map(authorities.map((record) => [record.endpoint, record]));
    this.pending = new Map();
    this.rejected = new Set();
    this.rejectionReasons = new Map();
    this.operations = [];
    this.readAuthorityError = undefined;
    this.writePendingError = undefined;
    this.repairError = undefined;
    this.repairResult = Object.freeze({ removed: Object.freeze([]) });
    this.suppressNextAuthorityRead = false;
  }

  async readAuthority(endpoint) {
    if (this.suppressNextAuthorityRead) {
      this.suppressNextAuthorityRead = false;
      return undefined;
    }
    this.operations.push({ operation: 'readAuthority', endpoint });
    if (this.readAuthorityError) throw this.readAuthorityError;
    return this.authorities.get(endpoint);
  }

  async readPending(endpoint) {
    this.operations.push({ operation: 'readPending', endpoint });
    return this.pending.get(endpoint);
  }

  async writePending(endpoint, record) {
    this.operations.push({ operation: 'writePending', endpoint, record });
    if (this.writePendingError) throw this.writePendingError;
    this.pending.set(endpoint, record);
  }

  async promotePending(endpoint, record, active) {
    this.operations.push({ operation: 'promotePending', endpoint, record, active });
    assert.deepEqual(this.pending.get(endpoint), record);
    this.authorities.set(endpoint, active);
    this.pending.delete(endpoint);
  }

  async discardPending(endpoint, record) {
    this.operations.push({ operation: 'discardPending', endpoint, record });
    if (this.pending.get(endpoint)?.capability === record.capability) this.pending.delete(endpoint);
  }

  async discardRejectedAuthority(endpoint, record) {
    this.operations.push({ operation: 'discardRejectedAuthority', endpoint, record });
    assert.equal(this.rejected.has(record.capability), true);
    if (this.authorities.get(endpoint)?.capability === record.capability) {
      this.authorities.delete(endpoint);
    }
    this.rejected.delete(record.capability);
  }

  async markRejected(endpoint, record, reason = 'rejected') {
    this.operations.push({ operation: 'markRejected', endpoint, record });
    this.rejected.add(record.capability);
    this.rejectionReasons.set(record.capability, reason);
  }

  async rejectionReason(endpoint, record) {
    return this.rejected.has(record.capability) ? this.rejectionReasons.get(record.capability) ?? 'unavailable' : undefined;
  }

  async isRejected(endpoint, record) {
    this.operations.push({ operation: 'isRejected', endpoint, record });
    return this.rejected.has(record.capability);
  }

  async repairCorruptRecords(endpoint) {
    this.operations.push({ operation: 'repairCorruptRecords', endpoint });
    if (this.repairError) throw this.repairError;
    this.readAuthorityError = undefined;
    return this.repairResult;
  }
}

function observeMapWrite(storage, accepts) {
  const originalWrite = storage.set;
  const write = originalWrite.bind(storage);
  let resolveWrite;
  const observed = new Promise((resolve) => { resolveWrite = resolve; });
  storage.set = (key, value) => {
    const result = write(key, value);
    if (accepts(key, value)) {
      storage.set = originalWrite;
      resolveWrite({ key, value });
    }
    return result;
  };
  return observed;
}


function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function heldEventStream(signal, ready = true) {
  const encoder = new TextEncoder();
  let settled = false;
  const body = new ReadableStream({
    start(controller) {
      if (ready) {
        controller.enqueue(encoder.encode(
          'event: stream.ready\n'
          + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
        ));
      }
      const stop = () => {
        if (settled) return;
        settled = true;
        controller.error(new DOMException('stopped', 'AbortError'));
      };
      signal?.addEventListener('abort', stop, { once: true });
    },
    cancel() { settled = true; },
  });
  return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } });
}

function closedReadyEventStream() {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(
        'event: stream.ready\n'
        + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
      ));
      controller.close();
    },
  });
  return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } });
}

function controllableEventStream() {
  const encoder = new TextEncoder();
  let streamController;
  let stopped = false;
  return {
    response(signal) {
      return new Response(new ReadableStream({
        start(controller) {
          streamController = controller;
          signal?.addEventListener('abort', () => {
            if (stopped) return;
            stopped = true;
            controller.error(new DOMException('stopped', 'AbortError'));
          }, { once: true });
        },
        cancel() { stopped = true; },
      }), { headers: { 'Content-Type': 'text/event-stream' } });
    },
    send(value) {
      assert(streamController && !stopped, 'fixture event stream is not writable');
      streamController.enqueue(encoder.encode(value));
    },
  };
}

function domainEvent(id, kind, revision, change = 'updated') {
  const project = kind === 'project.changed';
  return `id: ${id}\nevent: ${kind}\ndata: ${JSON.stringify({
    v: 1,
    event_id: id,
    kind,
    aggregate: {
      type: project ? 'project' : kind === 'scan.changed' ? 'scan' : 'findings',
      id: project ? '7' : '41',
      revision,
    },
    occurred_at: '2026-08-14T12:00:00Z',
    scope: project ? { project_id: 7 } : { project_id: 7, scan_id: 41 },
    change,
    hint: {},
  })}\n\n`;
}

function projectDomainEvent(id, projectId, revision, change) {
  return `id: ${id}\nevent: project.changed\ndata: ${JSON.stringify({
    v: 1,
    event_id: id,
    kind: 'project.changed',
    aggregate: { type: 'project', id: String(projectId), revision },
    occurred_at: '2026-08-14T12:00:00Z',
    scope: { project_id: projectId },
    change,
    hint: {},
  })}\n\n`;
}

function scanDomainEvent(id, scanId, revision, change) {
  return `id: ${id}\nevent: scan.changed\ndata: ${JSON.stringify({
    v: 1,
    event_id: id,
    kind: 'scan.changed',
    aggregate: { type: 'scan', id: String(scanId), revision },
    occurred_at: '2026-08-14T12:00:00Z',
    scope: { project_id: 7, scan_id: scanId },
    change,
    hint: {},
  })}\n\n`;
}

function finding(id, overrides = {}) {
  const scanId = overrides.scan_id || 41;
  const ordinal = overrides.scan_finding_number || id;
  return {
    id,
    scan_id: scanId,
    scan_finding_number: ordinal,
    display_id: `S${scanId}-F${String(ordinal).padStart(3, '0')}`,
    scanner: 'fixture',
    rule_id: `fixture.${id}`,
    severity: 'high',
    file_path: `src/${id}.ts`,
    start_line: 1,
    start_column: null,
    end_line: 1,
    end_column: null,
    message: `finding ${id}`,
    fingerprint: `fingerprint-${id}`,
    lifecycle_status: 'open',
    gate_exempt: false,
    gate_effect: 'blocking',
    suppressed: false,
    occurrence_count: 1,
    is_repeat: false,
    first_seen_display_id: null,
    first_seen_scan_id: null,
    advisor_verdict: null,
    advisor_confidence: null,
    revision: 1,
    ...overrides,
  };
}

const QUICK_FIX_ACTIONS = Object.freeze(['open', 'lifecycle', 'advisor', 'rescan', 'delete']);
const QUICK_FIX_COMMANDS = Object.freeze(QUICK_FIX_ACTIONS.map(
  (action) => `lomoCodeSecurity.quickFix.${action}`,
));

function assertStableQuickFixCommands(actions) {
  assert.equal(actions.length, QUICK_FIX_ACTIONS.length);
  const commands = [];
  for (const [index, action] of actions.entries()) {
    assert.equal(action.command.command, QUICK_FIX_COMMANDS[index]);
    assert.equal(
      Object.hasOwn(action.command, 'arguments'),
      false,
      'Problems Quick Fix commands must not enter VS Code\'s disposable argument-wrapper cache',
    );
    commands.push(action.command.command);
  }
  assert.deepEqual(commands, QUICK_FIX_COMMANDS);
  return commands;
}

const LOCAL_ADVISOR_PIN = Object.freeze({
  provider_collection_revision: 5,
  provider_id: 'local-default',
  transport: 'local',
  provider_config_revision: 3,
  provider_config_digest: 'b'.repeat(64),
  model: 'qwen3:8b',
  model_digest: 'a'.repeat(64),
});

function advisorProvider(overrides = {}) {
  return {
    id: 'local-default',
    name: 'This device',
    transport: 'local',
    priority: 0,
    enabled: true,
    base_url: null,
    model: 'qwen3:8b',
    model_digest: 'a'.repeat(64),
    ssh_host: null,
    ssh_port: null,
    ssh_user: null,
    authorization: 'not_required',
    status: 'available',
    reason: null,
    reason_code: null,
    remediation: 'none',
    last_activity_at: '2026-08-25T00:00:00Z',
    content_disclosure_approved: false,
    config_revision: 3,
    config_digest: 'b'.repeat(64),
    eligible: true,
    ...overrides,
  };
}

function advisorProviderCollection(provider = advisorProvider(), overrides = {}) {
  const eligibleIds = provider.eligible ? [provider.id] : [];
  return {
    revision: 5,
    active_provider_id: null,
    providers: [provider],
    resolution: {
      provider_id: provider.eligible ? provider.id : null,
      transport: provider.eligible ? provider.transport : 'unavailable',
      reason: provider.eligible ? null : 'no_executable_provider',
      eligible_provider_ids: eligibleIds,
    },
    ...overrides,
  };
}

function findingPage(items, revision = 1) {
  return { items, total: items.length, truncated: false, next_cursor: null, revision };
}

function diagnosticItem(value) {
  return {
    id: value.id,
    scan_finding_number: value.scan_finding_number,
    display_id: value.display_id,
    scanner: value.scanner,
    severity: value.severity,
    file_path: value.file_path,
    start_line: value.start_line,
    start_column: value.start_column,
    end_line: value.end_line,
    end_column: value.end_column,
    message: value.message,
    revision: value.revision,
  };
}

function manifestAggregate(filePath, values) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const lifecycleCounts = {
    open: 0,
    needs_review: 0,
    gate_exempt: 0,
    accepted_risk: 0,
    ignore: 0,
    false_positive: 0,
    fixed: 0,
  };
  for (const value of values) {
    severityCounts[value.severity] += 1;
    lifecycleCounts[value.lifecycle_status] += 1;
  }
  const active = values.filter((value) => !value.suppressed).length;
  return {
    file_path: filePath,
    first_scan_finding_number: Math.min(...values.map((value) => value.scan_finding_number)),
    total: values.length,
    active,
    suppressed: values.length - active,
    gate_exempt: values.filter((value) => !value.suppressed && value.gate_exempt).length,
    blocking: values.filter((value) => !value.suppressed && value.gate_effect === 'blocking').length,
    severity_counts: severityCounts,
    lifecycle_counts: lifecycleCounts,
  };
}

function hybridManifest(values, revision = 1, scanOverrides = {}) {
  const grouped = new Map();
  for (const value of values) {
    const items = grouped.get(value.file_path) || [];
    items.push(value);
    grouped.set(value.file_path, items);
  }
  const items = [...grouped.entries()]
    .map(([path, findings]) => manifestAggregate(path, findings))
    .sort((left, right) => left.first_scan_finding_number - right.first_scan_finding_number);
  return {
    scan: {
      id: 41,
      project_id: 7,
      status: 'completed',
      gate_decision: 'fail',
      gate_reasons: [],
      error: null,
      revision,
      findings_revision: revision,
      ...scanOverrides,
    },
    total_findings: values.length,
    total_files: items.length,
    items,
    truncated: false,
    next_cursor: null,
  };
}

function hybridDiagnosticPage(values, revision = 1) {
  return {
    scan_id: 41,
    items: values.map(diagnosticItem),
    total: values.length,
    truncated: false,
    next_cursor: null,
    revision,
  };
}

function findingDetail(id, overrides = {}) {
  return {
    ...finding(id),
    findings_revision: 1,
    code_snippet: null,
    metadata_json: {},
    ai_verdict: null,
    ai_confidence: null,
    ai_reasoning: null,
    ai_fix: null,
    suppression_reason: null,
    gate_exempt_reason: null,
    lifecycle_reason: null,
    lifecycle_updated_at: null,
    created_at: '2026-08-13T00:00:00Z',
    ...overrides,
  };
}

async function hydrateTreePath(tree, filePath) {
  const workspaceNode = tree.getChildren()[0];
  assert(workspaceNode, 'expected one indexed workspace Tree node');
  const direct = tree.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope');
  const fileNodes = direct[0]?.kind === 'file_page' ? tree.getChildren(direct[0]) : direct;
  const fileNode = fileNodes.find((node) => node.filePath === filePath);
  assert(fileNode, `expected Tree file node ${filePath}`);
  return tree.getChildren(fileNode);
}


async function withExtensionFixture({
  route,
  apiBaseUrl = 'http://127.0.0.1:8080',
  availableCommands = [
    'workbench.action.browser.open',
    'workbench.action.focusFirstEditorGroup',
    'workbench.action.focusSecondEditorGroup',
    'workbench.action.focusThirdEditorGroup',
    'workbench.action.focusFourthEditorGroup',
    'workbench.action.focusFifthEditorGroup',
    'workbench.action.focusSixthEditorGroup',
    'workbench.action.focusSeventhEditorGroup',
    'workbench.action.focusEighthEditorGroup',
  ],
  availableExtensions = [],
  cancellationRequested = false,
  captureProgressCancellation,
  errorSelection,
  informationSelection,
  gitPushRepository,
  inputValue,
  inlineAnnotations = 'compact',
  eventStreamFactory,
  profileCredentialStore,
  realtimeOptions,
  streamReady = true,
  workspaceFolders,
  quickPick,
  warningSelection,
  extensionMode,
  strictHybridRoutes = false,
  strictBrowserInvitationRoute = false,
  strictBrowserMembershipRoute = false,
  integratedBrowserResult,
  externalOpenResult = true,
  modelOpenExternalUriCache = false,
  resourceStatType = 2,
  snapshotCollector,
  workspaceTrusted = true,
  browserDataStorage = 'default',
  progressLifecycle,
  onOpenTextDocument,
  onShowTextDocument,
  initialTextEditors = [],
  globalStateStorage,
  workspaceStateStorage,
  workspaceStateUpdate,
  workspaceFile,
  sessionId,
  profileStoragePath,
  workspaceSourcePathAdapter,
  nativeWindowsWorkspaceAdapter,
  captureRepositoryRecoveryScope,
  sourceTransferHealth = { source_snapshot_limits: require('../../dist/snapshot.js').SOURCE_SNAPSHOT_LIMITS },
  activeTabGroupTabs = [],
  otherTabGroupTabs = [],
  activeTabGroupIndex = 0,
  deferTextEditorFocus = false,
  textEditorViewColumn = 1,
  treeViewVisible = false,
  treeViewportOffset = 0,
  firstOwnerBootstrap,
  suppressStartupAuthority = true,
}, run) {
  const originalLoad = Module._load;
  const originalFetch = globalThis.fetch;
  const ownedProfilePath = profileStoragePath === undefined
    ? fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-extension-profile-'))) : undefined;
  profileStoragePath ??= ownedProfilePath;
  const repositoryRecoveries = [];
  const registrations = new Map();
  const reports = [];
  const information = [];
  const warnings = [];
  const warningCalls = [];
  const quickPickCalls = [];
  const errors = [];
  const executedCommands = [];
  const setupPanels = [];
  const setupContexts = new Map();
  let currentActiveTextEditor = initialTextEditors[0];
  let lastShownTextEditor;
  const resourceStats = [];
  const snapshotCollections = [];
  const opened = [];
  const closedTabs = [];
  const externalOpened = [];
  const clipboardWrites = [];
  const shownDocuments = [];
  const entries = new Map();
  let eventStreamCount = 0;
  let workspaceFolderListener;
  let textDocumentListener;
  let openDocumentListener;
  let closeDocumentListener;
  let closeDocumentListenerDisposed = false;
  let closeDocumentCallbackCount = 0;
  let configurationListener;
  let workspaceTrustListener;
  let visibleRangeListener;
  let visibleEditorsListener;
  let visibleRangeListenerDisposed = false;
  let hoverProvider;
  let codeActionsProvider;
  let commandsAtCodeActionProviderRegistration = [];
  let treeProvider;
  let treeRefreshes = 0;
  let treeVisibilityListener;
  let currentTreeViewVisible = treeViewVisible;
  let currentTreeViewportOffset = treeViewportOffset;
  const treeViewReveals = [];
  let currentWorkspaceTrusted = workspaceTrusted;
  let decorationTypeNumber = 0;
  const decorationTypes = [];
  const statusItems = [];
  const statusBarMessages = [];
  const eventStreamSignals = [];
  let configurationReads = 0;
  const globalStateValues = globalStateStorage || new Map();
  const workspaceStateValues = workspaceStateStorage || new Map();
  const globalStateUpdates = [];
  const consumedFirstOwnerBootstraps = [];
  const browserInvitationPurposes = new Map();
  const scanResources = new Map();
  const manifestScans = new Map();
  const derivedFindingSnapshots = new Map();
  const fixtureProfileCredentialStore = profileCredentialStore || new FakeProfileCredentialStore();
  fixtureProfileCredentialStore.suppressNextAuthorityRead = suppressStartupAuthority;
  let suppressOneStartupEnrollment = suppressStartupAuthority;
  let startupPairRequiredReady;
  let startupPairRequiredObserved;
  if (suppressStartupAuthority) {
    startupPairRequiredObserved = new Promise((resolve) => {
      startupPairRequiredReady = resolve;
    });
  }
  let configuredApiBaseUrl = apiBaseUrl;
  const folderUri = {
    scheme: 'file',
    authority: '',
    path: '/workspace/current',
    fsPath: '/workspace/current',
    toString: () => 'file:///workspace/current',
  };
  const folders = workspaceFolders === undefined
    ? [{ name: 'current', uri: folderUri }]
    : [...workspaceFolders];
  assert(Array.isArray(folders), 'extension fixture workspace roots must start as an explicit array');
  const collection = {
    batches: 0,
    deletes: 0,
    clear() { entries.clear(); },
    delete(uri) { this.deletes += 1; entries.delete(uri.toString()); },
    get(uri) { return entries.get(uri.toString()); },
    set(batch) {
      this.batches += 1;
      assert(
        batch.reduce((total, [, diagnostics]) => total + (diagnostics?.length || 0), 0) <= 1_000,
        'one outbound Problems batch must stay within the supported VS Code host cap',
      );
      for (const [uri, diagnostics] of batch) {
        if (diagnostics === undefined) entries.delete(uri.toString());
        else entries.set(uri.toString(), diagnostics);
      }
    },
    dispose() {},
  };
  let currentActiveTabGroupIndex = activeTabGroupIndex;
  const fixtureTabGroups = [activeTabGroupTabs, otherTabGroupTabs].map((tabs, index) => ({
    get activeTab() { return tabs.find((tab) => tab.isActive); },
    get isActive() { return currentActiveTabGroupIndex === index; },
    tabs,
    viewColumn: index + 1,
  }));
  const focusGroupCommands = [
    'workbench.action.focusFirstEditorGroup',
    'workbench.action.focusSecondEditorGroup',
    'workbench.action.focusThirdEditorGroup',
    'workbench.action.focusFourthEditorGroup',
    'workbench.action.focusFifthEditorGroup',
    'workbench.action.focusSixthEditorGroup',
    'workbench.action.focusSeventhEditorGroup',
    'workbench.action.focusEighthEditorGroup',
  ];
  const fakeVscode = {
    ExtensionMode: { Production: 1, Development: 2, Test: 3 },
    ViewColumn: { Active: -1 },
    ProgressLocation: { Notification: 15 },
    languages: {
      createDiagnosticCollection: () => collection,
      registerHoverProvider: (_selector, provider) => {
        hoverProvider = provider;
        return { dispose() {} };
      },
      registerCodeActionsProvider: (_selector, provider) => {
        commandsAtCodeActionProviderRegistration = [...registrations.keys()];
        codeActionsProvider = provider;
        return { dispose() {} };
      },
    },
    commands: {
      registerCommand: (name, handler) => {
        registrations.set(name, handler);
        return {
          dispose() {
            if (registrations.get(name) === handler) registrations.delete(name);
          },
        };
      },
      getCommands: async () => [...registrations.keys(), ...availableCommands],
      executeCommand: async (name, ...args) => {
        if (name === 'setContext') { setupContexts.set(args[0], args[1]); return; }
        executedCommands.push({ name, args });
        const focusGroupIndex = focusGroupCommands.indexOf(name);
        if (focusGroupIndex >= 0) {
          assert(fixtureTabGroups[focusGroupIndex], 'editor group focus target must exist');
          currentActiveTabGroupIndex = focusGroupIndex;
          if (lastShownTextEditor?.viewColumn === focusGroupIndex + 1) {
            currentActiveTextEditor = lastShownTextEditor;
          }
          return undefined;
        }
        if (name === 'workbench.action.browser.open') {
          const [request] = args;
          const url = typeof request === 'string' ? request : request?.url;
          assert.equal(typeof url, 'string', 'integrated browser command requires one exact URL');
          opened.push(url);
          if (typeof integratedBrowserResult === 'function') {
            return integratedBrowserResult(url, request);
          }
        }
      },
    },
    extensions: {
      getExtension: (id) => availableExtensions.includes(id) ? { id } : undefined,
    },
    workspace: {
      get isTrusted() { return currentWorkspaceTrusted; },
      workspaceFolders: folders,
      workspaceFile,
      textDocuments: [...new Set(initialTextEditors.map((editor) => editor.document))],
      fs: {
        stat: async (uri) => {
          resourceStats.push(uri.toString());
          return { type: resourceStatType };
        },
      },
      openTextDocument: async (uri) => {
        const document = fakeVscode.workspace.textDocuments.find(
          (candidate) => candidate.uri.toString() === uri.toString(),
        );
        if (!document) throw new Error(`fixture document is not open: ${uri.toString()}`);
        await onOpenTextDocument?.({ document, uri });
        return document;
      },
      getConfiguration: (section) => {
        configurationReads += 1;
        return {
          get: (key, fallback) => {
            if (section === 'lomoCodeSecurity' && key === 'apiBaseUrl') return configuredApiBaseUrl;
            if (section === 'lomoCodeSecurity' && key === 'inlineAnnotations') return inlineAnnotations;
            if (section === 'workbench.browser' && key === 'dataStorage') return browserDataStorage;
            return fallback;
          },
        };
      },
      getWorkspaceFolder: () => undefined,
      onDidChangeWorkspaceFolders: (listener) => {
        workspaceFolderListener = listener;
        return { dispose() {} };
      },
      onDidChangeTextDocument: (listener) => {
        textDocumentListener = listener;
        return { dispose() {} };
      },
      onDidRenameFiles: () => ({ dispose() {} }),
      onDidDeleteFiles: () => ({ dispose() {} }),
      onDidOpenTextDocument: (listener) => {
        openDocumentListener = listener;
        return { dispose() {} };
      },
      onDidCloseTextDocument: (listener) => {
        closeDocumentListener = listener;
        return { dispose() { closeDocumentListenerDisposed = true; } };
      },
      onDidChangeConfiguration: (listener) => {
        configurationListener = listener;
        return { dispose() {} };
      },
      onDidGrantWorkspaceTrust: (listener) => {
        workspaceTrustListener = listener;
        return { dispose() { if (workspaceTrustListener === listener) workspaceTrustListener = undefined; } };
      },
    },
    window: {
      tabGroups: {
        get all() { return fixtureTabGroups; },
        get activeTabGroup() { return fixtureTabGroups[currentActiveTabGroupIndex]; },
        close: async (target) => {
          const targets = Array.isArray(target) ? target : [target];
          for (const tab of targets) {
            closedTabs.push(tab);
            const group = fixtureTabGroups.find((candidate) => candidate.tabs.includes(tab));
            if (!group) return false;
            group.tabs.splice(group.tabs.indexOf(tab), 1);
          }
          return true;
        },
      },
      visibleTextEditors: [...initialTextEditors],
      get activeTextEditor() { return currentActiveTextEditor; },
      set activeTextEditor(value) { currentActiveTextEditor = value; },
      createWebviewPanel: (viewType, title, column, options) => {
        const panel = { viewType, title, column, options, visible: true, messages: [],
          reveal() {}, dispose() { this.visible = false; },
          onDidDispose: () => ({ dispose() {} }), onDidChangeViewState: () => ({ dispose() {} }) };
        panel.webview = { html: '', postMessage: async message => { panel.messages.push(message); return true; },
          onDidReceiveMessage: listener => { panel.message = listener; return { dispose() {} }; } };
        setupPanels.push(panel); return panel;
      },
      showQuickPick: async (items, options) => {
        quickPickCalls.push({ items, options });
        return quickPick ? quickPick(items, options) : items[0];
      },
      showInputBox: async (options) => typeof inputValue === 'function'
        ? inputValue(options, {
          changeApiBaseUrl: (value) => { configuredApiBaseUrl = value; },
        })
        : inputValue,
      withProgress: async (options, task) => {
        reports.push({ options });
        progressLifecycle?.('started');
        let requested = cancellationRequested;
        const listeners = new Set();
        const token = {
          get isCancellationRequested() { return requested; },
          onCancellationRequested: (listener) => {
            listeners.add(listener);
            return { dispose: () => listeners.delete(listener) };
          },
        };
        captureProgressCancellation?.({
          options,
          cancel: () => {
            if (requested) return;
            requested = true;
            progressLifecycle?.('cancel-requested');
            for (const listener of [...listeners]) listener();
          },
        });
        try {
          const value = await task({ report: (item) => reports.push(item) }, token);
          progressLifecycle?.('resolved');
          return value;
        } catch (error) {
          progressLifecycle?.('rejected');
          throw error;
        } finally {
          progressLifecycle?.('settled');
        }
      },
      showInformationMessage: async (message, ...actions) => {
        information.push(message);
        return typeof informationSelection === 'function'
          ? informationSelection(message, actions)
          : informationSelection;
      },
      showWarningMessage: async (message, ...actions) => {
        warnings.push(message);
        warningCalls.push({ message, actions });
        return typeof warningSelection === 'function' ? warningSelection(message, actions) : warningSelection;
      },
      showErrorMessage: async (message, ...actions) => {
        progressLifecycle?.('error-presented');
        errors.push({ message, actions });
        return errorSelection;
      },
      showTextDocument: async (document, options) => {
        const editor = {
          document,
          options,
          viewColumn: textEditorViewColumn,
          selection: undefined,
          revealed: [],
          revealRange(range, revealType) { this.revealed.push({ range, revealType }); },
        };
        shownDocuments.push(editor);
        lastShownTextEditor = editor;
        if (!deferTextEditorFocus) {
          currentActiveTextEditor = editor;
          currentActiveTabGroupIndex = Math.max(0, textEditorViewColumn - 1);
        }
        await onShowTextDocument?.({ document, editor });
        return editor;
      },
      onDidChangeVisibleTextEditors: (listener) => {
        visibleEditorsListener = listener;
        return { dispose() {} };
      },
      onDidChangeTextEditorVisibleRanges: (listener) => {
        visibleRangeListener = listener;
        return { dispose() { visibleRangeListenerDisposed = true; } };
      },
      createTextEditorDecorationType: (configuration) => {
        const decorationType = {
          id: ++decorationTypeNumber,
          configuration,
          disposed: false,
          dispose() { this.disposed = true; },
        };
        decorationTypes.push(decorationType);
        return decorationType;
      },
      createTreeView: (_view, options) => {
        treeProvider = options.treeDataProvider;
        return {
          get visible() { return currentTreeViewVisible; },
          onDidChangeVisibility: (listener) => {
            treeVisibilityListener = listener;
            return { dispose() { if (treeVisibilityListener === listener) treeVisibilityListener = undefined; } };
          },
          reveal: async (node, revealOptions) => {
            treeViewReveals.push({ node, options: revealOptions });
            currentTreeViewportOffset = 0;
          },
          dispose() {},
        };
      },
      registerTreeDataProvider: (_view, provider) => {
        treeProvider = provider;
        return { dispose() {} };
      },
      createStatusBarItem: () => {
        let text = '';
        const item = {
          show() {},
          dispose() {},
          get text() { return text; },
          set text(value) {
            text = value;
          },
          tooltip: '',
          name: '',
          command: '',
        };
        statusItems.push(item);
        return item;
      },
      setStatusBarMessage: (message, timeout) => {
        statusBarMessages.push({ message, timeout });
        return { dispose() {} };
      },
    },
    env: {
      appName: 'Fixture Code',
      sessionId,
      openExternal: async (uri) => {
        externalOpened.push(uri.toString(true));
        return typeof externalOpenResult === 'function'
          ? externalOpenResult(uri)
          : externalOpenResult;
      },
      clipboard: {
        writeText: async (value) => { clipboardWrites.push(value); },
      },
    },
    Uri: {
      joinPath: (base, ...segments) => {
        const value = `${base.toString().replace(/\/$/, '')}/${segments.join('/')}`;
        const path = new URL(value).pathname;
        return {
          scheme: base.scheme,
          authority: base.authority,
          path,
          fsPath: path,
          toString: () => value,
        };
      },
      parse: (value) => {
        const parsed = new URL(value);
        if (!modelOpenExternalUriCache) {
          return { path: parsed.pathname, fsPath: parsed.pathname, toString: () => value };
        }
        let cachedExternal;
        const raw = parsed.toString();
        const encoded = `${parsed.origin}${parsed.pathname}`
          + (parsed.search ? `?${encodeURIComponent(parsed.search.slice(1))}` : '')
          + (parsed.hash ? `#${encodeURIComponent(parsed.hash.slice(1))}` : '');
        return {
          path: parsed.pathname,
          fsPath: parsed.pathname,
          toString: (skipEncoding = false) => {
            if (skipEncoding) return raw;
            cachedExternal ||= encoded;
            return cachedExternal;
          },
          externalizeForOpen: () => cachedExternal || raw,
        };
      },
    },
    Position: class Position { constructor(line, character) { this.line = line; this.character = character; } },
    Selection: class Selection {
      constructor(start, end) { this.start = start; this.end = end; }
    },
    TextEditorRevealType: { InCenterIfOutsideViewport: 2 },
    FileType: { File: 1, Directory: 2 },
    Range: class Range {
      constructor(...values) {
        this.values = values;
        if (values.length === 4) {
          this.start = { line: values[0], character: values[1] };
          this.end = { line: values[2], character: values[3] };
        } else {
          this.start = values[0]; this.end = values[1];
        }
      }
      intersection(other) {
        const compare = (left, right) => left.line - right.line || left.character - right.character;
        const start = compare(this.start, other.start) >= 0 ? this.start : other.start;
        const end = compare(this.end, other.end) <= 0 ? this.end : other.end;
        return compare(start, end) <= 0 ? new this.constructor(start, end) : undefined;
      }
    },
    Diagnostic: class Diagnostic {
      constructor(range, message, severity) {
        this.range = range;
        this.message = message;
        this.severity = severity;
      }
    },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    StatusBarAlignment: { Left: 1 },
    OverviewRulerLane: { Right: 4 },
    DecorationRangeBehavior: { ClosedClosed: 3 },
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    TreeItem: class TreeItem { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
    ThemeIcon: class ThemeIcon { constructor(id) { this.id = id; } },
    ThemeColor: class ThemeColor { constructor(id) { this.id = id; } },
    MarkdownString: class MarkdownString {
      constructor(value = '', supportThemeIcons = false) {
        this.value = value;
        this.supportThemeIcons = supportThemeIcons;
        this.segments = value ? [{ kind: 'markdown', value }] : [];
      }
      appendMarkdown(value) {
        this.value += value;
        this.segments.push({ kind: 'markdown', value });
        return this;
      }
      appendText(value) {
        this.value += value;
        this.segments.push({ kind: 'text', value });
        return this;
      }
    },
    Hover: class Hover {
      constructor(contents, range) { this.contents = contents; this.range = range; }
    },
    EventEmitter: class EventEmitter {
      constructor() { this.event = () => ({ dispose() {} }); }
      fire() { treeRefreshes += 1; }
      dispose() {}
    },
    CodeActionKind: { QuickFix: { value: 'quickfix' } },
    CodeAction: class CodeAction { constructor(title, kind) { this.title = title; this.kind = kind; } },
    CancellationError: class CancellationError extends Error {},
  };
  Module._load = function load(request, parent, isMain) {
    if (request === 'vscode') return fakeVscode;
    if (request === './workspace' && parent?.filename === extensionPath
      && (workspaceSourcePathAdapter || nativeWindowsWorkspaceAdapter)) {
      return { ...originalLoad.call(this, request, parent, isMain),
        ...(workspaceSourcePathAdapter ? { workspaceSourcePath: workspaceSourcePathAdapter } : {}),
        ...(nativeWindowsWorkspaceAdapter ? { isNativeWindowsWorkspace: nativeWindowsWorkspaceAdapter } : {}) };
    }
    if (request === './repository-recovery' && parent?.filename === extensionPath) {
      const recovery = originalLoad.call(this, request, parent, isMain);
      return { ...recovery, createRepositoryRecoveryState: (options) => {
        captureRepositoryRecoveryScope?.(options.scope);
        const state = recovery.createRepositoryRecoveryState(options);
        repositoryRecoveries.push(state);
        return state;
      } };
    }
    if (gitPushRepository && parent?.filename === extensionPath && request === './git-push-objects') {
      return { ...originalLoad.call(this, request, parent, isMain), inspectGitRepository: async (root) => {
        assert.equal(root, gitPushRepository.root);
        return gitPushRepository;
      } };
    }
    if (gitPushRepository && parent?.filename === extensionPath && request === './git-push-host') {
      return { ...originalLoad.call(this, request, parent, isMain), inspectGitPushPolicy: async () => ({
        state: 'not_installed', enabled: null, revision: null, hookDigest: null,
      }) };
    }
    if (request === './credentials' && parent?.filename === extensionPath) {
      const credentials = originalLoad.call(this, request, parent, isMain);
      return {
        ...credentials,
        ProfileCredentialStore: class ProfileCredentialStoreFixture {
          constructor() { return fixtureProfileCredentialStore; }
        },
      };
    }
    if (request === './installer-bootstrap' && parent?.filename === extensionPath) {
      const installerBootstrap = originalLoad.call(this, request, parent, isMain);
      return {
        ...installerBootstrap,
        readFirstOwnerBrowserBootstrap: async () => consumedFirstOwnerBootstraps.includes(firstOwnerBootstrap)
          ? undefined : firstOwnerBootstrap,
        consumeFirstOwnerBrowserBootstrap: async (value) => {
          consumedFirstOwnerBootstraps.push(value);
        },
      };
    }
    if (request === './snapshot' && parent?.filename === extensionPath) {
      const snapshot = originalLoad.call(this, request, parent, isMain);
      return {
        ...snapshot,
        collectNativeWindowsSourceSnapshot: async (...arguments_) => {
          snapshotCollections.push(arguments_[0]);
          return snapshotCollector
            ? snapshotCollector(...arguments_)
            : snapshot.collectNativeWindowsSourceSnapshot(...arguments_);
        },
      };
    }
    if (request === './realtime' && parent?.filename === extensionPath && realtimeOptions) {
      const realtime = originalLoad.call(this, request, parent, isMain);
      return {
        ...realtime,
        RealtimeSync: class RealtimeSyncFixture extends realtime.RealtimeSync {
          constructor(client, storage, options) {
            super(client, storage, { ...options, ...realtimeOptions });
          }
        },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  const invokeRoute = async (parsed, init) => {
    const response = await route(parsed, init);
    if (response.ok) {
      const latest = /^\/v1\/projects\/[1-9][0-9]*\/scans\/latest$/.test(parsed.pathname);
      const exact = /^\/v1\/scans\/[1-9][0-9]*$/.test(parsed.pathname);
      const created = parsed.pathname === '/v1/scans' && init.method === 'POST';
      if (latest || exact || created) {
        const value = await response.clone().json();
        if (Number.isSafeInteger(value.id)) scanResources.set(value.id, value);
      }
    }
    if (response.ok && /^\/v1\/scans\/[1-9][0-9]*\/finding-files$/.test(parsed.pathname)) {
      const value = await response.clone().json();
      manifestScans.set(value.scan.id, value.scan);
    }
    return response;
  };
  const deriveFindingSnapshot = async (scanId, init) => {
    let scan = scanResources.get(scanId);
    if (!scan || !['completed', 'partial', 'failed', 'cancelled'].includes(scan.status)) {
      try {
        const exactUrl = new URL(`http://127.0.0.1/v1/scans/${scanId}`);
        const response = await invokeRoute(exactUrl, init);
        if (response.ok) scan = await response.clone().json();
      } catch (error) {
        if (!(error instanceof Error) || !/unexpected request/i.test(error.message)) throw error;
      }
    }
    const pages = [];
    const items = [];
    let cursor = null;
    let revision;
    let total;
    for (;;) {
      const pageUrl = new URL(`http://127.0.0.1/v1/scans/${scanId}/findings`);
      pageUrl.searchParams.set('limit', '200');
      if (cursor) pageUrl.searchParams.set('cursor', cursor);
      const response = await invokeRoute(pageUrl, init);
      if (!response.ok) return { errorResponse: response };
      const page = await response.clone().json();
      pages.push(page);
      items.push(...page.items);
      revision = revision === undefined ? page.revision : revision;
      total = total === undefined ? page.total : total;
      if (page.next_cursor === null) break;
      cursor = page.next_cursor;
    }
    scan = scan || { id: scanId, project_id: 7, status: 'completed' };
    const snapshot = { scan, pages, items, revision, total };
    derivedFindingSnapshots.set(scanId, snapshot);
    return snapshot;
  };
  const derivedManifestResponse = async (parsed, init, scanId) => {
    const encodedCursor = parsed.searchParams.get('cursor');
    const offset = encodedCursor ? Number(encodedCursor.replace('fixture-manifest-', '')) : 0;
    const snapshot = encodedCursor
      ? derivedFindingSnapshots.get(scanId)
      : await deriveFindingSnapshot(scanId, init);
    assert(snapshot, 'fixture manifest cursor has no source snapshot');
    if (snapshot.errorResponse) return snapshot.errorResponse;
    const grouped = new Map();
    for (const value of snapshot.items) {
      const values = grouped.get(value.file_path) || [];
      values.push(value);
      grouped.set(value.file_path, values);
    }
    const aggregates = [...grouped.entries()]
      .map(([path, values]) => manifestAggregate(path, values))
      .sort((left, right) => left.first_scan_finding_number - right.first_scan_finding_number);
    const pageItems = aggregates.slice(offset, offset + 200);
    const nextOffset = offset + pageItems.length;
    const hasMore = nextOffset < aggregates.length;
    const scan = snapshot.scan;
    const body = {
      scan: {
        id: scanId,
        project_id: scan.project_id,
        status: scan.status,
        gate_decision: scan.gate_decision ?? null,
        gate_reasons: scan.gate_reasons || [],
        error: scan.error ?? null,
        revision: scan.revision || snapshot.revision,
        findings_revision: snapshot.revision,
      },
      total_findings: snapshot.total,
      total_files: aggregates.length,
      items: pageItems,
      truncated: hasMore,
      next_cursor: hasMore ? `fixture-manifest-${nextOffset}` : null,
    };
    manifestScans.set(scanId, body.scan);
    return json(body);
  };
  const derivedDiagnosticResponse = (parsed, scanId) => {
    const snapshot = derivedFindingSnapshots.get(scanId);
    assert(snapshot, 'fixture diagnostics have no manifest source snapshot');
    const encodedCursor = parsed.searchParams.get('cursor');
    const offset = encodedCursor ? Number(encodedCursor.replace('fixture-diagnostic-', '')) : 0;
    const pageItems = snapshot.items.slice(offset, offset + 200).map(diagnosticItem);
    const nextOffset = offset + pageItems.length;
    const hasMore = nextOffset < snapshot.items.length;
    return json({
      scan_id: scanId,
      items: pageItems,
      total: snapshot.total,
      truncated: hasMore,
      next_cursor: hasMore ? `fixture-diagnostic-${nextOffset}` : null,
      revision: snapshot.revision,
    });
  };
  const derivedFileResponse = (parsed, scanId) => {
    const snapshot = derivedFindingSnapshots.get(scanId);
    assert(snapshot, 'fixture file hydration has no manifest source snapshot');
    const path = parsed.searchParams.get('file_path');
    const values = snapshot.items.filter((value) => value.file_path === path);
    const encodedCursor = parsed.searchParams.get('cursor');
    const offset = encodedCursor ? Number(encodedCursor.replace('fixture-file-', '')) : 0;
    const pageItems = values.slice(offset, offset + 200);
    const nextOffset = offset + pageItems.length;
    const hasMore = nextOffset < values.length;
    return json({
      items: pageItems,
      total: values.length,
      truncated: hasMore,
      next_cursor: hasMore ? `fixture-file-${nextOffset}` : null,
      revision: snapshot.revision,
    });
  };
  globalThis.fetch = async (url, init = {}) => {
    const parsed = new URL(String(url));
    if (parsed.pathname === '/healthz') return typeof sourceTransferHealth === 'function'
      ? sourceTransferHealth(parsed, init) : json(sourceTransferHealth);
    if (suppressOneStartupEnrollment && parsed.pathname === '/v1/auth/ide/enrollments') {
      suppressOneStartupEnrollment = false;
      startupPairRequiredReady?.();
      return json({
        detail: {
          code: 'fixture_startup_enrollment_suppressed',
          message: 'The focused fixture suppressed its unrelated automatic startup enrollment.',
          action: 'retry_ide_enrollment',
        },
      }, 503);
    }
    if (parsed.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
      const purpose = JSON.parse(String(init.body)).purpose;
      const response = strictBrowserInvitationRoute
        ? await invokeRoute(parsed, init)
        : json(browserInvitationEnvelope(VALID_BROWSER_INVITATION, purpose), 201);
      if (response.ok) {
        const invitation = await response.clone().json();
        browserInvitationPurposes.set(invitation.invitation_id, invitation.purpose);
      }
      return response;
    }
    const membershipMatch = parsed.pathname.match(
      /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
    );
    if (membershipMatch && !strictBrowserMembershipRoute) {
      const invitationId = membershipMatch[1];
      return json(activeBrowserMembershipEnvelope(
        invitationId,
        browserInvitationPurposes.get(invitationId) || 'integrated_dashboard',
      ));
    }
    if (parsed.pathname === '/v1/events') {
      eventStreamCount += 1;
      eventStreamSignals.push(init.signal);
      return eventStreamFactory
        ? eventStreamFactory(init.signal, eventStreamCount, init)
        : heldEventStream(init.signal, streamReady);
    }
    const manifestMatch = parsed.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)\/finding-files$/);
    if (!strictHybridRoutes && manifestMatch) {
      return derivedManifestResponse(parsed, init, Number(manifestMatch[1]));
    }
    const diagnosticMatch = parsed.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)\/finding-diagnostics$/);
    if (!strictHybridRoutes && diagnosticMatch) {
      return derivedDiagnosticResponse(parsed, Number(diagnosticMatch[1]));
    }
    const findingMatch = parsed.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)\/findings$/);
    if (!strictHybridRoutes && findingMatch && parsed.searchParams.has('file_path')) {
      return derivedFileResponse(parsed, Number(findingMatch[1]));
    }
    try {
      return await invokeRoute(parsed, init);
    } catch (error) {
      // Legacy action fixtures derive compact manifests. Expose that same scan
      // metadata for the new read-only scope join, without inventing a scope.
      const exactScan = parsed.pathname.match(/^\/v1\/scans\/([1-9][0-9]*)$/);
      if (!strictHybridRoutes && exactScan && (init.method || 'GET') === 'GET' && error instanceof Error
        && /unexpected request/i.test(error.message) && manifestScans.has(Number(exactScan[1]))) {
        return json(manifestScans.get(Number(exactScan[1])));
      }
      if (
        /^\/v1\/projects\/[1-9][0-9]*\/scans\/latest$/.test(parsed.pathname)
        && error instanceof Error
        && /unexpected request/i.test(error.message)
      ) {
        return json({ detail: 'no scan exists before this fixture command' }, 404);
      }
      throw error;
    }
  };

  const extensionPath = require.resolve('../../dist/extension.js');
  const nativePath = require.resolve('../../dist/native.js');
  delete require.cache[extensionPath];
  delete require.cache[nativePath];
  try {
    const extension = require(extensionPath);
    const testApi = extension.activate({
      extensionMode: extensionMode || fakeVscode.ExtensionMode.Production,
      extensionUri: folderUri,
      extension: { packageJSON: require('../../package.json') },
      globalStorageUri: {
        scheme: 'file',
        authority: '',
        path: profileStoragePath,
        fsPath: profileStoragePath,
        toString: () => `file://${profileStoragePath}`,
      },
      subscriptions: [],
      workspaceState: { get: (key) => workspaceStateValues.get(key), update: async (key, value) => {
        await workspaceStateUpdate?.(key, value);
        workspaceStateValues.set(key, value);
      } },
      globalState: {
        get: (key) => globalStateValues.get(key),
        update: async (key, value) => {
          globalStateUpdates.push({ key, value });
          globalStateValues.set(key, value);
        },
      },
    });
    if (startupPairRequiredObserved) {
      await startupPairRequiredObserved;
      await new Promise((resolve) => setImmediate(resolve));
    }
    let active = true;
    const deactivate = () => {
      if (active) {
        active = false;
        extension.deactivate();
      }
    };
    try {
      await run({
      registrations,
      reports,
      information,
      warnings,
      warningCalls,
      quickPickCalls,
      errors,
      executedCommands,
      setupPanels,
      setupContexts,
      resourceStats,
      snapshotCollections,
      opened,
      closedTabs,
      externalOpened,
      clipboardWrites,
      shownDocuments,
      entries,
      collection,
      statusItems,
      statusBarMessages,
      eventStreams: () => eventStreamCount,
      eventStreamSignals: () => eventStreamSignals,
      configurationReads: () => configurationReads,
      globalStateUpdates: () => globalStateUpdates,
      consumedFirstOwnerBootstraps: () => consumedFirstOwnerBootstraps,
      testApi,
      extensionModule: extension,
      treeProvider: () => treeProvider,
      treeRefreshes: () => treeRefreshes,
      treeViewReveals: () => treeViewReveals,
      treeViewportOffset: () => currentTreeViewportOffset,
      setTreeViewVisible: (visible) => {
        currentTreeViewVisible = visible;
        treeVisibilityListener?.({ visible });
      },
      decorationTypes: () => decorationTypes,
      visibleRangeListenerDisposed: () => visibleRangeListenerDisposed,
      closeDocumentListenerDisposed: () => closeDocumentListenerDisposed,
      closeDocumentCallbackCount: () => closeDocumentCallbackCount,
      changeApiBaseUrl: (value) => {
        configuredApiBaseUrl = value;
        configurationListener({
          affectsConfiguration: (section) => section === 'lomoCodeSecurity.apiBaseUrl',
        });
      },
      provideHover: (document, position) => hoverProvider?.provideHover(document, position),
      provideCodeActions: (document, range, context = { diagnostics: [] }) => (
        codeActionsProvider?.provideCodeActions(document, range, context)
      ),
      commandsAtCodeActionProviderRegistration: () => commandsAtCodeActionProviderRegistration,
      deactivate,
      removeFolder: () => {
        const removed = folders[0];
        assert(removed, 'extension fixture has no workspace folder to remove');
        folders.splice(0, 1);
        fakeVscode.workspace.workspaceFolders = folders.length > 0 ? folders : undefined;
        workspaceFolderListener({ added: [], removed: [removed] });
      },
      addFolder: (folder) => {
        folders.push(folder);
        fakeVscode.workspace.workspaceFolders = folders;
        workspaceFolderListener({ added: [folder], removed: [] });
      },
      removeFolderByName: (name) => {
        const index = folders.findIndex((folder) => folder.name === name);
        assert(index >= 0, `extension fixture has no workspace folder named ${name}`);
        const [removed] = folders.splice(index, 1);
        fakeVscode.workspace.workspaceFolders = folders.length > 0 ? folders : undefined;
        workspaceFolderListener({ added: [], removed: [removed] });
      },
      openWorkspaceFolders: () => fakeVscode.workspace.workspaceFolders,
      setWorkspaceTrusted: (value) => { currentWorkspaceTrusted = value; },
      setBrowserDataStorage: (value) => { browserDataStorage = value; },
      grantWorkspaceTrust: () => {
        currentWorkspaceTrusted = true;
        workspaceTrustListener?.();
      },
      setVisibleTextEditors: (editors) => {
        fakeVscode.window.visibleTextEditors = editors;
        fakeVscode.window.activeTextEditor = editors[0];
      },
      notifyVisibleTextEditorsChanged: () => visibleEditorsListener(fakeVscode.window.visibleTextEditors),
      changeVisibleRanges: (editor, ranges) => {
        editor.visibleRanges = ranges;
        visibleRangeListener({ textEditor: editor, visibleRanges: ranges });
      },
      openDocument: (document) => {
        fakeVscode.workspace.textDocuments.push(document);
        openDocumentListener(document);
      },
      closeDocument: (document) => {
        const index = fakeVscode.workspace.textDocuments.indexOf(document);
        if (index >= 0) fakeVscode.workspace.textDocuments.splice(index, 1);
        if (!closeDocumentListenerDisposed) {
          closeDocumentCallbackCount += 1;
          closeDocumentListener(document);
        }
      },
        changeDocument: (document) => textDocumentListener({ document, contentChanges: [{ text: 'changed' }] }),
      });
    } finally {
      deactivate();
    }
  } finally {
    try {
      // Use the actual recovery implementation and wait for its owned writes
      // before retiring this fixture's private profile directory.
      await Promise.all(repositoryRecoveries.map(recovery => recovery.ready));
      if (ownedProfilePath) fs.rmSync(ownedProfilePath, { recursive: true });
    } finally {
      delete require.cache[extensionPath];
      delete require.cache[nativePath];
      Module._load = originalLoad;
      globalThis.fetch = originalFetch;
    }
  }
}


test('empty-workspace scan offers the native add action without source, enrollment or scan requests', async () => {
  for (const name of ['lomoCodeSecurity.scanWorkspace', 'lomoCodeSecurity.scanWorkspaceFolders']) {
    for (const selection of [undefined, 'Add Folder to Workspace…']) {
      const requests = [];
      await withExtensionFixture({
        workspaceFolders: [], warningSelection: selection,
        route: async (url) => { requests.push(url.pathname); throw new Error(`unexpected request ${url.pathname}`); },
      }, async ({ registrations, warningCalls, executedCommands, information, opened, externalOpened, openWorkspaceFolders, errors }) => {
        await registrations.get(name)();
        assert.deepEqual(warningCalls.at(-1).actions, ['Add Folder to Workspace…']);
        assert.match(warningCalls.at(-1).message, /does not authorize scanner access, register a project or start a scan/u);
        assert.deepEqual(executedCommands.filter(({ name: command }) => command === 'workbench.action.addRootFolder'),
          selection ? [{ name: 'workbench.action.addRootFolder', args: [] }] : []);
        assert.deepEqual(requests, [], 'the source command returns after offering native workspace membership');
        assert.deepEqual(information, [], 'native action completion is not reported as an observed folder or scan');
        assert.deepEqual(opened, []);
        assert.deepEqual(externalOpened, []);
        assert.deepEqual(openWorkspaceFolders(), [], 'fixture does not pretend to execute VS Code workspace changes');
        assert.deepEqual(errors, []);
      });
    }
  }
});

test('Restricted Mode keeps empty-workspace scan from dispatching the native add action', async () => {
  await withExtensionFixture({
    workspaceFolders: [], workspaceTrusted: false, warningSelection: 'Add Folder to Workspace…',
    route: async () => { throw new Error('unexpected request'); },
  }, async ({ registrations, executedCommands, errors }) => {
    await registrations.get('lomoCodeSecurity.scanWorkspaceFolders')();
    assert.equal(executedCommands.some(({ name }) => name === 'workbench.action.addRootFolder'), false);
    assert.match(errors.at(-1).message, /Restricted Mode/u);
  });
});

test('push-protection setup opens Settings after approval without an obscuring informational toast', async () => {
  const repository = { repositoryId: 'a'.repeat(64), root: '/workspace/current', gitDirectory: '/workspace/current/.git' };
  let finishModal;
  let observeModal;
  const modalShown = new Promise((resolve) => { observeModal = resolve; });
  const modalChoice = { then(resolve) { finishModal = resolve; observeModal(); } };
  let dismissNotice;
  const notice = new Promise((resolve) => { dismissNotice = resolve; });
  const writes = [];
  await withExtensionFixture({
    gitPushRepository: repository,
    streamReady: false,
    warningSelection: modalChoice,
    informationSelection: (message) => /No hook was installed or setting enabled\./u.test(message) ? notice : undefined,
    quickPick: (items, options) => {
      if (options.title === 'Choose repository for push protection') return items[0];
      assert.equal(options.title, 'Protect pushes · current');
      return items.find((item) => item.id === 'setup');
    },
    route: async (url, init) => {
      if (url.pathname === `/v1/git/push-protection/${repository.repositoryId}`) {
        return json({ detail: { code: 'push_setup_required', message: 'Set up this exact clone.' } }, 404);
      }
      assert.equal(url.pathname, '/v1/git/push-protection');
      assert.equal(init.method, 'POST');
      writes.push(JSON.parse(init.body));
      return json({
        repository_id: repository.repositoryId, name: 'current', project_id: 7,
        root_path: repository.root, git_directory: repository.gitDirectory,
        revision: 1, enabled: false, observed_state: 'not_installed', observed_revision: null,
        observed_at: null, hook_digest: null, reason_code: 'host_setup_required',
        members: [{ client_slot: TEST_CLIENT_SLOT, generation: 1, name: 'Current editor', state: 'requested',
          requested_at: '2026-09-20T00:00:00Z', approved_at: null }],
      });
    },
  }, async ({ registrations, warningCalls, information, opened, errors }) => {
    const command = registrations.get('lomoCodeSecurity.protectPushes')();
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Push setup waited for an informational notice to close.')), 2_000);
    });
    try {
      await Promise.race([modalShown, deadline]);
      assert.equal(writes.length, 0, 'repository access must still await explicit modal approval');
      assert.equal(opened.length, 0);
      assert.equal(warningCalls[0].message, 'Request repository push protection access?');
      assert.equal(warningCalls[0].actions[0].modal, true);
      finishModal('Request access');
      await Promise.race([command, deadline]);
      assert.equal(writes.length, 1);
      assert.deepEqual(writes[0], { repository_id: repository.repositoryId, name: 'current',
        root_path: repository.root, git_directory: repository.gitDirectory, project_id: null });
      assert.deepEqual(errors, []);
      assert.deepEqual(information, [], 'a toast must not obscure the exact Settings approval panel');
      assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/?view=settings#bootstrap=${VALID_BROWSER_INVITATION}&destination=git-push-protection-${repository.repositoryId}`)]);
      assert.deepEqual(errors, []);
    } finally {
      clearTimeout(timer);
      finishModal?.(undefined);
      dismissNotice();
      await command;
    }
  });
});

test('fresh installer authority atomically connects the first IDE and opens one fragment-only integrated dashboard', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'first-owner');
  const store = new FakeProfileCredentialStore([]);
  const bootstrap = Object.freeze({
    artifactPath: '/fixture/private/first-owner-browser-v1.json',
    bootstrapToken: 'o'.repeat(43),
    controlOrigin: 'http://127.0.0.1:8080',
    installationId: '123456abcdef',
    identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
  });
  const requests = [];
  await withExtensionFixture({
    firstOwnerBootstrap: bootstrap,
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    strictBrowserInvitationRoute: true,
    workspaceFolders: [],
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({
        path: url.pathname,
        body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
        authorization: new Headers(init.headers).get('authorization'),
      });
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/claim-first-owner') {
        assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${pending.capability}`);
        assert.deepEqual(JSON.parse(String(init.body)), {
          bootstrap_token: bootstrap.bootstrapToken,
          expected_request_id: pending.enrollment_request_id,
          expected_revision: pending.enrollment_revision,
          expected_generation: pending.generation,
        });
        return json(approvedEnrollmentEnvelope(pending));
      }
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        return json(approvedEnrollmentEnvelope(pending));
      }
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
      throw new Error(`unexpected first-owner request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ opened, externalOpened, executedCommands, clipboardWrites, statusItems, consumedFirstOwnerBootstraps }) => {
    for (let turn = 0; turn < 30 && opened.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(requests.map(({ path }) => path), [
      '/v1/auth/ide/enrollments',
      '/v1/auth/ide/enrollments/current/claim-first-owner',
      '/v1/auth/ide/enrollments/current/wait',
      '/v1/auth/ide/activate',
      '/v1/auth/ide/browser-invitations',
    ]);
    assert.deepEqual(consumedFirstOwnerBootstraps(), [bootstrap]);
    assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`)]);
    assert.deepEqual(externalOpened, []);
    assert.deepEqual(clipboardWrites, []);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · connected');
    assert.equal(statusItems[0].command, 'lomoCodeSecurity.openDashboard');
    assert.deepEqual(executedCommands.filter(({ name }) => name === 'workbench.action.browser.open').length, 1);
  });
});

test('first-owner startup preserves installer authority until trust and then pairs exactly once', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'first-owner-await-trust');
  const store = new FakeProfileCredentialStore([]);
  const bootstrap = Object.freeze({
    artifactPath: '/fixture/private/first-owner-browser-v1.json',
    bootstrapToken: 'o'.repeat(43),
    controlOrigin: pending.endpoint,
    installationId: '123456abcdef',
    identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
  });
  const requests = [];
  const globalState = new Map();
  await withExtensionFixture({
    firstOwnerBootstrap: bootstrap,
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    strictBrowserInvitationRoute: true,
    globalStateStorage: globalState,
    workspaceTrusted: false,
    workspaceFolders: [],
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/claim-first-owner'
        || url.pathname === '/v1/auth/ide/enrollments/current/wait') return json(approvedEnrollmentEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
      throw new Error(`unexpected first-owner trust request ${url.pathname}`);
    },
  }, async ({ opened, errors, grantWorkspaceTrust, consumedFirstOwnerBootstraps, statusItems, clipboardWrites, externalOpened, registrations }) => {
    await waitForFixtureCondition(() => statusItems[0].text === '$(shield) CodeSecurity local · connected',
      'first owner must connect its exact IDE while waiting for trust');
    for (let turn = 0; turn < 5; turn += 1) await new Promise(setImmediate);
    assert.deepEqual(errors, [], 'automatic startup must not leave a stale trust error over the browser');
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · connected');
    assert.deepEqual(consumedFirstOwnerBootstraps(), [], 'installer handoff must remain until a persistent browser can be created');
    assert.deepEqual(opened, []);
    assert.deepEqual(requests, [
      '/v1/auth/ide/enrollments', '/v1/auth/ide/enrollments/current/claim-first-owner',
      '/v1/auth/ide/enrollments/current/wait', '/v1/auth/ide/activate',
    ]);

    grantWorkspaceTrust();
    for (let turn = 0; turn < 30 && opened.length === 0; turn += 1) await new Promise(setImmediate);
    assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`)]);
    assert.deepEqual(consumedFirstOwnerBootstraps(), [bootstrap]);
    assert.deepEqual(requests, [
      '/v1/auth/ide/enrollments', '/v1/auth/ide/enrollments/current/claim-first-owner',
      '/v1/auth/ide/enrollments/current/wait', '/v1/auth/ide/activate', '/v1/auth/ide/browser-invitations',
    ], 'granting trust reuses the exact active IDE without enrollment or activation');
    assert.deepEqual(errors, [], 'the explicit trust event must resume silently without a stale error');
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(externalOpened, []);
    const expectedMembership = integratedDashboardMembershipState(pending.endpoint);
    assert.deepEqual(globalState.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), expectedMembership);
    await registrations.get('lomoCodeSecurity.openDashboard')();
    assert.deepEqual(globalState.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), expectedMembership);
    assert.equal(requests.filter((path) => path === '/v1/auth/ide/browser-invitations').length, 1);
    assert.deepEqual(opened, [
      retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`),
      retainedBrowserUrl('http://127.0.0.1:8080/'),
    ]);
  });
});

test('explicit ephemeral browser storage refuses first-owner and explicit Dashboard without consuming authority', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'ephemeral-first-owner');
  const bootstrap = Object.freeze({
    artifactPath: '/fixture/private/first-owner-browser-v1.json',
    bootstrapToken: 'o'.repeat(43), controlOrigin: active.endpoint, installationId: '123456abcdef',
    identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
  });
  const requests = [];
  await withExtensionFixture({
    firstOwnerBootstrap: bootstrap,
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    browserDataStorage: 'ephemeral', workspaceFolders: [],
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url) => { requests.push(url.pathname); throw new Error('ephemeral storage must not issue an invitation'); },
  }, async ({ errors, opened, registrations, consumedFirstOwnerBootstraps, executedCommands }) => {
    for (let turn = 0; turn < 30 && errors.length === 0; turn += 1) await new Promise(setImmediate);
    await registrations.get('lomoCodeSecurity.openDashboard')();
    assert.equal(errors.length, 2);
    assert(errors.every(({ message }) => /workbench.browser.dataStorage is ephemeral/u.test(message)));
    assert.deepEqual(requests, []);
    assert.deepEqual(opened, []);
    assert.deepEqual(consumedFirstOwnerBootstraps(), []);
    assert.deepEqual(executedCommands, [], 'the user storage preference is never changed');
  });
});

test('first-owner explicit storage recovery and interrupted acknowledgements reuse one member', async (t) => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'first-owner-storage-recovery');
  const bootstrap = Object.freeze({
    artifactPath: '/fixture/private/first-owner-browser-v1.json',
    bootstrapToken: 'o'.repeat(43), controlOrigin: active.endpoint, installationId: '123456abcdef',
    identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
  });
  const invitationId = VALID_BROWSER_INVITATION.split('.')[1];
  const membershipPath = `/v1/auth/ide/browser-invitations/${invitationId}/membership`;

  await t.test('persistent-setting retry waits for acknowledgement, then survives restart without a new grant', async () => {
    const store = new FakeProfileCredentialStore([active]);
    const state = new Map();
    const requests = [];
    let acknowledge;
    let observeAcknowledgement;
    const acknowledged = new Promise((resolve) => { acknowledge = resolve; });
    const acknowledgementRequested = new Promise((resolve) => { observeAcknowledgement = resolve; });
    await withExtensionFixture({
      firstOwnerBootstrap: bootstrap, profileCredentialStore: store, globalStateStorage: state,
      suppressStartupAuthority: false, browserDataStorage: 'ephemeral', workspaceFolders: [],
      strictBrowserInvitationRoute: true, strictBrowserMembershipRoute: true,
      eventStreamFactory: (signal) => heldEventStream(signal),
      route: async (url) => {
        requests.push(url.pathname);
        if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
        assert.equal(url.pathname, membershipPath);
        observeAcknowledgement();
        await acknowledged;
        return json(activeBrowserMembershipEnvelope(invitationId));
      },
    }, async ({ errors, registrations, opened, setBrowserDataStorage, consumedFirstOwnerBootstraps }) => {
      for (let turn = 0; turn < 30 && errors.length === 0; turn += 1) await new Promise(setImmediate);
      assert.equal(errors.length, 1);
      assert.deepEqual(requests, []);
      setBrowserDataStorage('default');
      const opening = registrations.get('lomoCodeSecurity.openDashboard')();
      try {
        await acknowledgementRequested;
        assert.equal(opened.length, 1);
        assert.deepEqual(consumedFirstOwnerBootstraps(), [], 'no handoff consumption before exact server acknowledgement');
        acknowledge();
        await opening;
      } finally {
        acknowledge();
        await opening;
      }
      assert.equal(errors.length, 1);
      assert.deepEqual(consumedFirstOwnerBootstraps(), [bootstrap]);
      assert.deepEqual(state.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), integratedDashboardMembershipState());
      assert.equal(requests.filter((path) => path === '/v1/auth/ide/browser-invitations').length, 1);
    });
    requests.length = 0;
    await withExtensionFixture({
      profileCredentialStore: store, globalStateStorage: state, suppressStartupAuthority: false,
      workspaceFolders: [], strictBrowserInvitationRoute: true, strictBrowserMembershipRoute: true,
      eventStreamFactory: (signal) => heldEventStream(signal),
      route: async (url) => {
        requests.push(url.pathname);
        assert.equal(url.pathname, membershipPath);
        return json(activeBrowserMembershipEnvelope(invitationId));
      },
    }, async ({ errors, opened, consumedFirstOwnerBootstraps }) => {
      for (let turn = 0; turn < 30 && requests.length === 0; turn += 1) await new Promise(setImmediate);
      assert.deepEqual(requests, [membershipPath]);
      assert.deepEqual(errors, []);
      assert.deepEqual(opened, [], 'startup preserves host restoration instead of opening another browser');
      assert.deepEqual(consumedFirstOwnerBootstraps(), []);
      assert.deepEqual(state.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), integratedDashboardMembershipState());
    });
  });

  for (const pending of [false, true]) {
    await t.test(`interrupted ${pending ? 'pending' : 'retained'} acknowledgement completes only installer cleanup`, async () => {
      const state = new Map([[pending ? 'lomoCodeSecurity.integratedDashboardPending.v1' : 'lomoCodeSecurity.integratedDashboardMemberships.v1',
        pending ? pendingIntegratedDashboardState() : integratedDashboardMembershipState()]]);
      const requests = [];
      await withExtensionFixture({
        firstOwnerBootstrap: bootstrap, profileCredentialStore: new FakeProfileCredentialStore([active]),
        globalStateStorage: state, suppressStartupAuthority: false, workspaceFolders: [],
        strictBrowserInvitationRoute: true, strictBrowserMembershipRoute: true,
        eventStreamFactory: (signal) => heldEventStream(signal),
        route: async (url) => {
          requests.push(url.pathname);
          assert.equal(url.pathname, membershipPath);
          return json(activeBrowserMembershipEnvelope(invitationId));
        },
      }, async ({ errors, opened, consumedFirstOwnerBootstraps }) => {
        for (let turn = 0; turn < 30 && consumedFirstOwnerBootstraps().length === 0; turn += 1) await new Promise(setImmediate);
        assert.deepEqual(requests, [membershipPath]);
        assert.deepEqual(errors, []);
        assert.deepEqual(opened, []);
        assert.deepEqual(consumedFirstOwnerBootstraps(), [bootstrap]);
        assert.deepEqual(state.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), integratedDashboardMembershipState());
      });
    });
  }
});

test('status exposes positive workspace trust state and refreshes it after trust is granted', async () => {
  await withExtensionFixture({
    workspaceTrusted: false,
    route: async (url) => { throw new Error(`unexpected trust-status request ${url.pathname}`); },
  }, async ({ grantWorkspaceTrust, statusItems }) => {
    const workspaceIdentity = createHash('sha256').update('file:///workspace/current').digest('hex');
    assert.match(statusItems[0].tooltip, /^Workspace source access: restricted until Workspace Trust is granted\./u);
    assert.deepEqual(statusItems[0].accessibilityInformation, {
      label: `Lomo CodeSecurity. Workspace source access: restricted until Workspace Trust is granted. Workspace source URI SHA-256: ${workspaceIdentity}. ${statusItems[0].text.replace(/\$\([^)]+\)\s*/gu, '').trim()}.`,
    });

    grantWorkspaceTrust();

    assert.match(statusItems[0].tooltip, /^Workspace source access: trusted\./u);
    assert.deepEqual(statusItems[0].accessibilityInformation, {
      label: `Lomo CodeSecurity. Workspace source access: trusted. Workspace source URI SHA-256: ${workspaceIdentity}. ${statusItems[0].text.replace(/\$\([^)]+\)\s*/gu, '').trim()}.`,
    });
  });
});

test('first-owner startup browser failure exposes one retry with a fresh retained fragment invitation', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'first-owner-browser-retry');
  const store = new FakeProfileCredentialStore([]);
  const bootstrap = Object.freeze({
    artifactPath: '/fixture/private/first-owner-browser-v1.json',
    bootstrapToken: 'o'.repeat(43),
    controlOrigin: 'http://127.0.0.1:8080',
    installationId: '123456abcdef',
    identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
  });
  const firstInvitation = `kbi1.${'b'.repeat(24)}.${'c'.repeat(43)}`;
  const retryInvitation = `kbi1.${'d'.repeat(24)}.${'e'.repeat(43)}`;
  const globalState = new Map();
  let invitations = 0;
  let browserOpens = 0;
  await withExtensionFixture({
    firstOwnerBootstrap: bootstrap,
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    strictBrowserInvitationRoute: true,
    workspaceFolders: [],
    warningSelection: 'Open CodeSecurity Dashboard',
    globalStateStorage: globalState,
    eventStreamFactory: (signal) => heldEventStream(signal),
    integratedBrowserResult: async () => {
      browserOpens += 1;
      if (browserOpens === 1) throw new Error('fixture first integrated browser open failed');
      return undefined;
    },
    route: async (url) => {
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/claim-first-owner') {
        return json(approvedEnrollmentEnvelope(pending));
      }
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        return json(approvedEnrollmentEnvelope(pending));
      }
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') {
        invitations += 1;
        return json(browserInvitationEnvelope(invitations === 1 ? firstInvitation : retryInvitation));
      }
      throw new Error(`unexpected first-owner retry request ${url.pathname}`);
    },
  }, async ({ opened, externalOpened, clipboardWrites, warningCalls, errors, consumedFirstOwnerBootstraps }) => {
    for (let turn = 0; turn < 30 && browserOpens < 2; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(invitations, 2);
    assert.deepEqual(opened, [
      retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${firstInvitation}`),
      retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${retryInvitation}`),
    ]);
    assert.equal(warningCalls.length, 1);
    assert.deepEqual(warningCalls[0].actions, ['Open CodeSecurity Dashboard']);
    assert.deepEqual(externalOpened, []);
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(errors, []);
    assert.deepEqual(consumedFirstOwnerBootstraps(), [bootstrap]);
    assert.deepEqual(
      globalState.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
      integratedDashboardMembershipState('http://127.0.0.1:8080', retryInvitation),
    );
  });
});

test('terminal retained first-owner enrollment never consumes its artifact or opens a browser', async () => {
  for (const state of ['rejected', 'expired']) {
    const pending = testAuthority('http://127.0.0.1:8080', 1, `terminal-first-owner-${state}`);
    const store = new FakeProfileCredentialStore([]);
    store.pending.set(pending.endpoint, pending);
    const bootstrap = Object.freeze({
      artifactPath: `/fixture/private/first-owner-${state}.json`,
      bootstrapToken: 'o'.repeat(43),
      controlOrigin: pending.endpoint,
      installationId: '123456abcdef',
      identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
    });
    const requests = [];
    await withExtensionFixture({
      firstOwnerBootstrap: bootstrap,
      profileCredentialStore: store,
      suppressStartupAuthority: false,
      workspaceFolders: [],
      route: async (url) => {
        requests.push(url.pathname);
        assert.equal(url.pathname, '/v1/auth/ide/enrollments/current/wait');
        return json({
          request_id: pending.enrollment_request_id,
          state,
          revision: 2,
          decision_at: state === 'expired' ? null : '2099-08-29T23:50:59Z',
          activation_expires_at: pending.activation_expires_at,
        });
      },
    }, async ({ opened, externalOpened, clipboardWrites, consumedFirstOwnerBootstraps, warningCalls }) => {
      for (let turn = 0; turn < 20 && warningCalls.length === 0; turn += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      assert.deepEqual(requests, ['/v1/auth/ide/enrollments/current/wait']);
      assert.deepEqual(opened, []);
      assert.deepEqual(externalOpened, []);
      assert.deepEqual(clipboardWrites, []);
      assert.deepEqual(consumedFirstOwnerBootstraps(), []);
    });
  }
});

test('promoted first-owner authority finishes browser setup and removes the retained installer artifact', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'promoted-first-owner');
  const store = new FakeProfileCredentialStore([active]);
  const bootstrap = Object.freeze({
    artifactPath: '/fixture/private/first-owner-browser-v1.json',
    bootstrapToken: 'o'.repeat(43),
    controlOrigin: active.endpoint,
    installationId: '123456abcdef',
    identity: Object.freeze({ dev: 1, ino: 2, size: 128, sha256: 'a'.repeat(64) }),
  });
  const requests = [];
  await withExtensionFixture({
    firstOwnerBootstrap: bootstrap,
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    workspaceFolders: [],
    eventStreamFactory: (signal) => heldEventStream(signal),
    strictBrowserInvitationRoute: true,
    route: async (url, init) => {
      requests.push(url.pathname);
      assert.equal(url.pathname, '/v1/auth/ide/browser-invitations');
      assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${active.capability}`);
      return json(browserInvitationEnvelope());
    },
  }, async ({ opened, clipboardWrites, externalOpened, consumedFirstOwnerBootstraps }) => {
    for (let turn = 0; turn < 30 && opened.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(requests, ['/v1/auth/ide/browser-invitations']);
    assert.deepEqual(consumedFirstOwnerBootstraps(), [bootstrap]);
    assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`)]);
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(externalOpened, []);
  });
});

async function waitForFixtureCondition(predicate, message) {
  for (let turn = 0; turn < 60 && !predicate(); turn += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert(predicate(), message);
}

test('active startup without artifact or browser membership waits for explicit recovery and records the recovered browser', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'active-browser-recovery');
  const store = new FakeProfileCredentialStore([active]);
  const invitation = `kbi1.${'h'.repeat(24)}.${'i'.repeat(43)}`;
  const globalState = new Map();
  let invitations = 0;
  let chooseRecovery;
  const recoveryChoice = new Promise((resolve) => { chooseRecovery = resolve; });
  try {
    await withExtensionFixture({
      profileCredentialStore: store,
      suppressStartupAuthority: false,
      firstOwnerBootstrap: undefined,
      workspaceFolders: [],
      errorSelection: recoveryChoice,
      globalStateStorage: globalState,
      strictBrowserInvitationRoute: true,
      eventStreamFactory: (signal) => heldEventStream(signal),
      route: async (url, init) => {
        assert.equal(url.pathname, '/v1/auth/ide/browser-invitations', 'retained recovery must not enroll again');
        assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${active.capability}`);
        invitations += 1;
        return json(browserInvitationEnvelope(invitation));
      },
    }, async ({ opened, externalOpened, clipboardWrites, warningCalls, errors }) => {
      await waitForFixtureCondition(() => errors.length === 1, 'startup must expose explicit browser recovery');
      assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
      assert.equal(invitations, 0, 'no invitation before explicit recovery selection');
      assert.deepEqual(opened, []);
      chooseRecovery('Pair integrated browser again');
      await waitForFixtureCondition(
        () => globalState.has('lomoCodeSecurity.integratedDashboardMemberships.v1'),
        'explicit recovery must acknowledge its exact browser member',
      );
      assert.equal(invitations, 1);
      assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${invitation}`)]);
      assert.deepEqual(warningCalls, []);
      assert.deepEqual(externalOpened, []);
      assert.deepEqual(clipboardWrites, []);
      assert.equal(errors.length, 1);
      assert.deepEqual(store.authorities.get(active.endpoint), active);
      assert.equal(store.pending.size, 0);
      assert.deepEqual(
        globalState.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
        integratedDashboardMembershipState(active.endpoint, invitation),
      );
    });
  } finally {
    chooseRecovery(undefined);
  }
});

test('fresh startup exposes a non-focus-stealing IDE approval code and owner review opens exact Settings externally', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'approval-review');
  const store = new FakeProfileCredentialStore([]);
  let enrollmentReady;
  const enrollmentObserved = new Promise((resolve) => { enrollmentReady = resolve; });
  await withExtensionFixture({
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    quickPick: (items) => items.find(({ label }) => label === 'Open owner review in system browser'),
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/enrollments') {
        assert.deepEqual(JSON.parse(String(init.body)), {
          client_name: 'Fixture Code · current · local',
          client_slot: TEST_CLIENT_SLOT,
          expected_active_generation: 0,
        });
        enrollmentReady();
        return json(enrollmentEnvelope(pending), 201);
      }
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new DOMException('cancelled', 'AbortError')), { once: true });
        });
      }
      throw new Error(`unexpected enrollment request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, statusItems, information, errors, opened, externalOpened, executedCommands, clipboardWrites }) => {
    await enrollmentObserved;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(statusItems[0].text, `$(key) Approval needed · ${TEST_VERIFICATION_CODE}`);
    assert.match(statusItems[0].tooltip, /already-authenticated owner browser opened in the system browser/u);
    assert.deepEqual(store.pending.get(pending.endpoint), pending);
    assert.deepEqual(information, []);
    assert.deepEqual(errors, []);

    await registrations.get('lomoCodeSecurity.pair')();
    assert.deepEqual(externalOpened, ['http://127.0.0.1:8080/?view=settings#ide-access']);
    assert.deepEqual(opened, [], 'an unapproved IDE must not open the unauthenticated integrated browser');
    assert.deepEqual(executedCommands, [], 'review must not issue an integrated-browser invitation before approval');
    assert.deepEqual(clipboardWrites, []);
    assert.equal(statusItems[0].text, `$(key) Approval needed · ${TEST_VERIFICATION_CODE}`);
  });
});

test('failed system-browser owner review offers the non-secret exact Settings address', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'approval-browser-failure');
  const store = new FakeProfileCredentialStore([]);
  let enrollmentReady;
  const enrollmentObserved = new Promise((resolve) => { enrollmentReady = resolve; });
  await withExtensionFixture({
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    externalOpenResult: false,
    warningSelection: 'Copy owner-review address',
    quickPick: (items) => items.find(({ label }) => label === 'Open owner review in system browser'),
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/enrollments') {
        enrollmentReady();
        return json(enrollmentEnvelope(pending), 201);
      }
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new DOMException('cancelled', 'AbortError')), { once: true });
        });
      }
      throw new Error(`unexpected enrollment request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, warnings, information, externalOpened, opened, executedCommands, clipboardWrites }) => {
    await enrollmentObserved;
    await new Promise((resolve) => setImmediate(resolve));
    await registrations.get('lomoCodeSecurity.pair')();

    assert.deepEqual(externalOpened, ['http://127.0.0.1:8080/?view=settings#ide-access']);
    assert.deepEqual(opened, []);
    assert.deepEqual(executedCommands, []);
    assert.deepEqual(clipboardWrites, ['http://127.0.0.1:8080/?view=settings#ide-access']);
    assert.match(warnings[0], /already authenticated owner browser/u);
    assert.match(information.at(-1), /non-secret CodeSecurity owner-review address/u);
  });
});

test('retained paired profile reuses its integrated browser durably and keeps recovery explicit', async () => {
  const retained = testActiveAuthority('http://127.0.0.1:8080', 4, 'startup-retained');
  const store = new FakeProfileCredentialStore([retained]);
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(retained.endpoint),
  ]]);

  let explicitInvitationRequests = 0;
  const restoredTabs = [
    { label: RETAINED_BROWSER_TAB_TITLE, isActive: false },
    { label: 'app.py', isActive: true },
  ];
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    workspaceFolders: [],
    activeTabGroupTabs: restoredTabs,
    otherTabGroupTabs: [{ label: 'Lomo CodeSecurity', isActive: false }],
    globalStateStorage,
    integratedBrowserResult: () => { simulateBrowserReplacement(restoredTabs); },
    quickPick: (items) => items.find((item) => item.action === 'open'),
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      assert.equal(url.pathname, '/v1/auth/ide/browser-invitations');
      assert.equal(init.method, 'POST');
      explicitInvitationRequests += 1;
      return json(browserInvitationEnvelope(
        `kbi1.${'f'.repeat(24)}.${'0'.repeat(43)}`,
        'extra_browser',
      ));
    },
  }, async ({ registrations, opened, externalOpened, executedCommands, statusBarMessages }) => {
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(explicitInvitationRequests, 0, 'retained integrated-browser membership must not request another invitation');
    assert.deepEqual(opened, [], 'retained membership lets VS Code restore the dashboard without startup navigation');

    const authorityOperationsBeforeConnectReview = store.operations.length;
    await registrations.get('lomoCodeSecurity.pair')();
    assert.deepEqual(statusBarMessages.at(-1), {
      message: '$(check) This exact VS Code profile is already connected.',
      timeout: 5_000,
    });
    assert.equal(store.operations.length, authorityOperationsBeforeConnectReview);
    assert.equal(explicitInvitationRequests, 0, 'connected-state feedback must not issue a browser invitation');

    await registrations.get('lomoCodeSecurity.openDashboard')();
    restoredTabs[0].isActive = false;
    restoredTabs[1].isActive = true;
    await registrations.get('lomoCodeSecurity.openDashboard')(41);
    assert.equal(explicitInvitationRequests, 0, 'ordinary route changes must reuse the retained browser member');
    assert.deepEqual(opened, [
      retainedBrowserUrl('http://127.0.0.1:8080/'),
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41'),
    ]);
    assert.deepEqual(
      executedCommands,
      [
        {
          name: 'workbench.action.browser.open',
          args: [{
            url: retainedBrowserUrl('http://127.0.0.1:8080/'),
            reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
          }],
        },
        {
          name: 'workbench.action.browser.open',
          args: [{
            url: retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41'),
            reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
          }],
        },
      ],
      'restored root views and deep links must atomically navigate and focus the exact retained tab',
    );

    await registrations.get('lomoCodeSecurity.addBrowser')();
    assert.equal(explicitInvitationRequests, 1, 'explicit Add Browser must issue exactly one new invitation');
    assert.deepEqual(opened, [
      retainedBrowserUrl('http://127.0.0.1:8080/'),
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41'),
    ]);
    assert.deepEqual(externalOpened, [
      `http://127.0.0.1:8080/#bootstrap=kbi1.${'f'.repeat(24)}.${'0'.repeat(43)}`,
    ], 'explicit Add Browser targets one unpaired system-browser profile without reusing the integrated tab');
    assert.deepEqual(statusBarMessages.at(-1), {
      message: '$(check) CodeSecurity added one independently revocable browser.',
      timeout: 5_000,
    });

    await registrations.get('lomoCodeSecurity.openDashboard')(42);
    assert.equal(opened.at(-1), retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=42'));
    assert.deepEqual(executedCommands.slice(-1), [
      {
        name: 'workbench.action.browser.open',
        args: [{
          url: retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=42'),
          reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
        }],
      },
    ], 'retained navigation stays on the tracked tab after a separately authorized Add Browser action');
  });

  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: new FakeProfileCredentialStore([]),
    suppressStartupAuthority: true,
    workspaceFolders: [],
    globalStateStorage,
    route: async (url) => {
      throw new Error(`IDE revocation must not request a browser invitation: ${url.pathname}`);
    },
  }, async ({ registrations, opened }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')();
    assert.deepEqual(opened, [], 'a revoked IDE must not navigate using an unreconciled browser marker');
  });

  globalStateStorage.delete('lomoCodeSecurity.integratedDashboardMemberships.v1');
  let unexpectedInvitationRequests = 0;
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      unexpectedInvitationRequests += 1;
      throw new Error(`retained IDE recovery must not silently request ${init.method} ${url.pathname}`);
    },
  }, async ({ errors, opened }) => {
    for (let turn = 0; turn < 20 && errors.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(unexpectedInvitationRequests, 0, 'a retained IDE with a missing local marker must not create an orphan browser member');
    assert.deepEqual(opened, [], 'the missing marker remains fail-closed until the user chooses explicit recovery');
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
  });
});

test('startup native findings survive independent browser recovery', { timeout: 10_000 }, async (t) => {
  for (const browserState of ['missing', 'rejected', 'pending', 'trust']) await t.test(browserState, async () => {
    const retained = testActiveAuthority('http://127.0.0.1:8080', 7, `startup-browser-${browserState}`);
    const values = [finding(1, { file_path: 'app.py', severity: 'high' })];
    const globalStateStorage = new Map(browserState === 'missing' ? [] : [[
      'lomoCodeSecurity.integratedDashboardMemberships.v1', integratedDashboardMembershipState(retained.endpoint),
    ]]);
    let releaseBrowser;
    const browserResponse = new Promise((resolve) => { releaseBrowser = resolve; });
    const requests = [];
    await withExtensionFixture({
      strictHybridRoutes: true, strictBrowserInvitationRoute: true, strictBrowserMembershipRoute: true,
      workspaceTrusted: browserState !== 'trust',
      profileCredentialStore: new FakeProfileCredentialStore([retained]), suppressStartupAuthority: false,
      globalStateStorage, eventStreamFactory: (signal) => heldEventStream(signal),
      route: async (url, init) => {
        requests.push({ path: url.pathname, method: init.method || 'GET' });
        if (url.pathname.endsWith('/membership')) return ['pending', 'trust'].includes(browserState) ? browserResponse
          : json({ detail: { code: 'integrated_dashboard_membership_missing',
            action: 'pair_integrated_browser_again', message: 'The retained browser is unavailable.' } }, 404);
        if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'vulnerable-demo', repo_path: '/workspace/current', revision: 1 });
        if (url.pathname === '/v1/projects/7/scans/latest') return json({ id: 41, project_id: 7,
          status: 'completed', gate_decision: 'fail', revision: 1, findings_revision: 1,
          scanner_summary: { scope: { kind: 'workspace', target_path: null } } });
        if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values));
        if (url.pathname === '/v1/scans/41/finding-diagnostics') return json(hybridDiagnosticPage(values));
        throw new Error(`unexpected independent startup request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ entries, opened, treeProvider, grantWorkspaceTrust, statusItems }) => {
      try {
        if (browserState === 'trust') {
          const connectedDeadline = Date.now() + 1000;
          while (Date.now() < connectedDeadline && !/\bconnected\b/u.test(statusItems[0].text)) await new Promise(setImmediate);
          assert.match(statusItems[0].text, /\bconnected\b/u);
          assert.equal(entries.size, 0);
          assert.equal(requests.filter(row => row.path === '/v1/projects/resolve').length, 0,
            'IDE readiness cannot read untrusted source');
          grantWorkspaceTrust();
        }
        const deadline = Date.now() + 1000;
        while (Date.now() < deadline && [...entries.values()].flat().length !== values.length) await new Promise(setImmediate);
        assert.equal([...entries.values()].flat().length, values.length,
          'startup must publish Problems without a tree read triggering lazy reconnect');
        const [root] = treeProvider().getChildren();
        assert(root, 'an authenticated trusted IDE must hydrate while browser recovery fails or remains pending');
        for (let turn = 0; turn < 50 && [...entries.values()].flat().length !== values.length; turn++) await new Promise(setImmediate);
        assert.equal(root.workspace.totalFindings, values.length);
        assert.equal(root.workspace.diagnosticProjection, 'complete');
        assert.equal([...entries.values()].flat().length, values.length);
        assert.deepEqual(opened, [], 'native hydration grants no browser membership or navigation');
        assert.equal(requests.filter(row => row.method === 'POST' && row.path === '/v1/auth/ide/browser-invitations').length, 0);
        assert.equal(requests.filter(row => row.path === '/v1/scans/41/finding-diagnostics').length, 1);
      } finally {
        releaseBrowser(json(activeBrowserMembershipEnvelope(VALID_BROWSER_INVITATION.split('.')[1])));
        for (let turn = 0; turn < 5; turn++) await new Promise(setImmediate);
      }
    });
  });
});

test('retained startup connection automatically restores Tree and Problems for every open workspace', async () => {
  const retained = testActiveAuthority('http://127.0.0.1:8080', 7, 'startup-workspace-projection');
  const values = [
    finding(1, { file_path: 'app.py', severity: 'high' }),
    finding(2, { file_path: 'Dockerfile', severity: 'medium' }),
    finding(3, { file_path: 'infra/main.tf', severity: 'low' }),
  ];
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(retained.endpoint),
  ]]);
  let markDiagnosticsRequested;
  const diagnosticsRequested = new Promise((resolve) => { markDiagnosticsRequested = resolve; });
  const requests = [];
  await withExtensionFixture({
    strictHybridRoutes: true,
    profileCredentialStore: new FakeProfileCredentialStore([retained]),
    suppressStartupAuthority: false,
    globalStateStorage,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'vulnerable-demo', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          gate_decision: 'fail',
          revision: 1,
          findings_revision: 1,
          scanner_summary: { scope: { kind: 'workspace', target_path: null } },
        });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        markDiagnosticsRequested();
        return json(hybridDiagnosticPage(values));
      }
      throw new Error(`unexpected retained-startup request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ entries, errors, opened, statusItems, treeProvider }) => {
    await diagnosticsRequested;
    for (let turn = 0; turn < 50
      && [...entries.values()].reduce((total, diagnostics) => total + diagnostics.length, 0) !== values.length;
      turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    const [root] = treeProvider().getChildren();
    assert(root, 'startup projection publishes the open workspace without an explicit Refresh command');
    assert.equal(root.workspace.label, 'current');
    assert.equal(root.workspace.totalFindings, values.length);
    assert.equal(root.workspace.diagnosticProjection, 'complete');
    assert.equal(
      [...entries.values()].reduce((total, diagnostics) => total + diagnostics.length, 0),
      values.length,
      'the startup owner publishes the complete native DiagnosticCollection',
    );
    assert.equal(statusItems[0].text, `$(shield) connected · fail · ${values.length}`);
    assert.deepEqual(opened, [], 'retained membership remains restored without startup dashboard navigation');
    assert.equal(
      requests.some(({ path }) => path === '/v1/scans/41/finding-diagnostics'),
      true,
      'startup uses the same bounded compact Problems transport as explicit Refresh Findings',
    );
    assert.deepEqual(errors, []);
  });
});

test('retained startup restores inline findings after delayed rich hydration and concurrent unchanged refresh', { timeout: 10_000 }, async (t) => {
  for (const siblingStatus of [undefined, 422, 401]) await t.test(
    siblingStatus === 401 ? 'rejected authority clears every root'
      : siblingStatus === 422 ? 'denied sibling preserves automatic hydration' : 'registered root', async () => {
    const deniedSibling = siblingStatus !== undefined;
    const retained = testActiveAuthority('http://127.0.0.1:8080', 7, 'startup-inline-projection');
    const uriKey = 'file:///workspace/current/generated.ts';
    const text = 'export const generatedFixture = true;';
    const document = {
      uri: { scheme: 'file', authority: '', path: '/workspace/current/generated.ts',
        fsPath: '/workspace/current/generated.ts', toString: () => uriKey },
      version: 1, lineCount: 1, lineAt: () => ({ text }), isDirty: false,
    };
    const decorationCalls = [];
    const editor = {
      document,
      selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: text.length } }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    };
    const values = ['high', 'medium', 'critical'].map((severity, index) => finding(index + 1, {
      file_path: 'generated.ts', scanner: 'semgrep', severity,
      start_line: 1, end_line: 1, start_column: 1, end_column: 10,
    }));
    const credentials = new FakeProfileCredentialStore([retained]);
    const globalStateStorage = new Map([[
      'lomoCodeSecurity.integratedDashboardMemberships.v1',
      integratedDashboardMembershipState(retained.endpoint),
    ]]);
    let releaseRich;
    const richResponse = new Promise((resolve) => { releaseRich = resolve; });
    const requests = [];
    const richSignals = [];
    const latestInline = () => decorationCalls.at(-1)?.options || [];
    try {
      await withExtensionFixture({
        strictHybridRoutes: true, suppressStartupAuthority: false,
        profileCredentialStore: credentials, globalStateStorage,
        initialTextEditors: [editor],
        workspaceFolders: deniedSibling ? ['/workspace/current', '/workspace/denied'].map((root) => ({
          name: root.split('/').at(-1),
          uri: { scheme: 'file', authority: '', path: root, fsPath: root, toString: () => `file://${root}` },
        })) : undefined,
        eventStreamFactory: (signal) => heldEventStream(signal),
        route: async (url, init) => {
          requests.push({ path: url.pathname, method: init.method || 'GET' });
          if (url.pathname === '/v1/projects/resolve') {
            if (JSON.parse(init.body).repo_path === '/workspace/denied') {
              return json({ detail: {
                code: 'source_outside_allowed_root',
                message: 'The selected directory is outside the authorized source root.',
                action: 'authorize_source',
                context: {
                  source_target: { kind: 'mounted_directory', display_path: '/workspace/denied' },
                  authorization_boundary: { kind: 'allowed_roots', display_paths: ['/workspace/current'] },
                },
              } }, siblingStatus);
            }
            return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
          }
          if (url.pathname === '/v1/projects/7/scans/latest') {
            return json({ id: 41, project_id: 7, status: 'completed', gate_decision: 'fail',
              revision: 1, findings_revision: 1 });
          }
          if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values));
          if (url.pathname === '/v1/scans/41/finding-diagnostics') return json(hybridDiagnosticPage(values));
          if (url.pathname === '/v1/scans/41/findings') {
            assert.equal(url.searchParams.get('file_path'), 'generated.ts');
            richSignals.push(init.signal);
            return new Promise((resolve, reject) => {
              const aborted = () => reject(new DOMException('fixture rich request cancelled', 'AbortError'));
              init.signal.addEventListener('abort', aborted, { once: true });
              if (init.signal.aborted) aborted();
              richResponse.then((response) => {
                init.signal.removeEventListener('abort', aborted);
                resolve(response.clone());
              }, reject);
            });
          }
          throw new Error(`unexpected retained inline request ${init.method || 'GET'} ${url.pathname}`);
        },
      }, async ({ registrations, entries, errors, opened, statusItems, treeProvider, treeViewReveals }) => {
        let treeChildReads = 0;
        const provider = treeProvider();
        const originalGetChildren = provider.getChildren.bind(provider);
        provider.getChildren = (...args) => { treeChildReads += 1; return originalGetChildren(...args); };
        for (let turn = 0; turn < 100 && richSignals.length === 0; turn += 1) {
          await new Promise((resolve) => setImmediate(resolve));
        }
        assert.equal(richSignals.length, 1, 'startup admits the already-open file without Tree expansion');
        if (siblingStatus === 401) {
          for (let turn = 0; turn < 100 && !richSignals[0].aborted; turn += 1) {
            await new Promise((resolve) => setImmediate(resolve));
          }
          assert.equal(richSignals[0].aborted, true, 'authority rejection still cancels all pending rich requests');
          releaseRich(json(findingPage(values)));
          await new Promise((resolve) => setImmediate(resolve));
          assert.deepEqual([...entries.keys()], [], 'late rows cannot restore rejected authority');
          assert.deepEqual(latestInline(), []);
          assert.equal(credentials.rejected.has(retained.capability), true);
          assert.equal(treeChildReads, 0);
          assert.deepEqual(opened, []);
          assert.equal(requests.some(({ path }) => /\/auth\/ide\/(enrollments|activate)$/u.test(path)), false);
          return;
        }
        if (deniedSibling) {
          for (let turn = 0; turn < 100 && errors.length === 0; turn += 1) {
            await new Promise((resolve) => setImmediate(resolve));
          }
          assert.equal(errors.length, 1, 'the denied sibling remains an explicit source-boundary failure');
          assert.match(errors[0].message, /outside the authorized source root/u);
          assert.match(errors[0].message, /Selected target: \/workspace\/denied/u);
          assert.deepEqual(errors[0].actions, ['Open Source Setup']);
        }
        assert.equal(richSignals[0].aborted, false, 'a denied sibling does not cancel admitted primary hydration');
        assert.equal(entries.get(uriKey)?.length, 3, 'current compact Problems publish before rich rows');
        assert.deepEqual(latestInline(), [], 'no inline detail is invented while its exact response is pending');

        // First prove the denied-root startup needs no manual recovery. The
        // single-root case also exercises Refresh while rich rows are pending.
        if (!deniedSibling) await registrations.get('lomoCodeSecurity.refreshFindings')();
        releaseRich(json(findingPage(values)));
        for (let turn = 0; turn < 100 && latestInline().length === 0; turn += 1) {
          await new Promise((resolve) => setImmediate(resolve));
        }
        assert.equal(latestInline().length, 1, 'startup renders rich details without a Tree expansion or manual recovery');
        assert.equal(latestInline()[0].renderOptions.after.contentText, '  [CRITICAL · semgrep +2 reports]');
        if (deniedSibling) await registrations.get('lomoCodeSecurity.refreshFindings')();
        assert(requests.filter(({ path }) => path === '/v1/projects/resolve').length >= 2,
          'startup and explicit Refresh revalidate the registered root; stream-ready may also reconcile it');
        assert.equal(requests.filter(({ path }) => path === '/v1/scans/41/finding-diagnostics').length, 1,
          'Refresh preserves the current primary compact projection');
        assert.equal(richSignals.length, 1, 'Refresh does not duplicate or replace the primary rich hydration');
        assert.equal(richSignals.at(-1).aborted, false, 'the current hydration remains admitted');
        assert.equal(latestInline().length, 1);
        assert.equal(latestInline()[0].renderOptions.after.contentText, '  [CRITICAL · semgrep +2 reports]');
        assert.match(latestInline()[0].hoverMessage.value, /S41-F003/u);
        assert.equal(entries.get(uriKey)?.length, 3);
        assert.equal(statusItems[0].text, '$(shield) connected · fail · 3 · 1 scoped');
        assert.equal(treeChildReads, 0, 'no Tree demand supplies the missing automatic hydration');
        assert.deepEqual(treeViewReveals(), []);
        assert.deepEqual(opened, [], 'the retained integrated member is reused without new navigation');
        assert.equal(requests.some(({ path }) => /\/auth\/ide\/(enrollments|activate)$/u.test(path)), false);
        assert.deepEqual(credentials.authorities.get(retained.endpoint), retained);
        if (!deniedSibling) assert.deepEqual(errors, []);
      });
    } finally { releaseRich(json(findingPage(values))); }
  });
});

test('unpaired activation starts one bounded enrollment without a prompt or browser', async () => {
  const store = new FakeProfileCredentialStore([]);
  let inputPrompts = 0;
  let requests = 0;
  await withExtensionFixture({
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    inputValue: () => {
      inputPrompts += 1;
      return 'must-not-be-requested';
    },
    route: async (url) => {
      requests += 1;
      assert.equal(url.pathname, '/v1/auth/ide/enrollments');
      return json({ detail: {
        code: 'ide_enrollment_temporarily_unavailable',
        message: 'The fixture enrollment service is temporarily unavailable.',
        action: 'retry_ide_enrollment',
      } }, 503);
    },
  }, async ({ registrations, executedCommands, information, warnings, errors, statusItems }) => {
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(inputPrompts, 0);
    assert.equal(requests, 1);
    assert.deepEqual(store.operations, [
      {
        operation: 'readPending',
        endpoint: 'http://127.0.0.1:8080',
      },
      {
        operation: 'readAuthority',
        endpoint: 'http://127.0.0.1:8080',
      },
    ]);
    assert.deepEqual(executedCommands, []);
    assert.deepEqual(information, []);
    assert.deepEqual(warnings, []);
    assert.deepEqual(errors, []);
    assert.equal(typeof registrations.get('lomoCodeSecurity.reconnect'), 'function');
    assert.equal(statusItems[0].command, 'lomoCodeSecurity.reconnect');
    assert.match(statusItems[0].tooltip, /select this status to reconnect the exact retained IDE profile/i);
  });
});

test('explicit startup invitation recovery failure preserves retained authority without copying or opening a browser', async () => {
  const retained = testActiveAuthority('http://127.0.0.1:8080', 5, 'startup-invitation-failure');
  const store = new FakeProfileCredentialStore([retained]);
  let invitationRequests = 0;
  let chooseRecovery;
  const recoveryChoice = new Promise((resolve) => { chooseRecovery = resolve; });
  try {
    await withExtensionFixture({
      strictBrowserInvitationRoute: true,
      profileCredentialStore: store,
      suppressStartupAuthority: false,
      workspaceFolders: [],
      errorSelection: recoveryChoice,
      eventStreamFactory: (signal) => heldEventStream(signal),
      route: async (url, init) => {
        assert.equal(url.pathname, '/v1/auth/ide/browser-invitations', 'retained recovery must not enroll again');
        assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${retained.capability}`);
        invitationRequests += 1;
        return json({
          detail: {
            code: 'ide_browser_invitation_temporarily_unavailable',
            message: 'The IDE dashboard invitation service is temporarily unavailable.',
            action: 'retry_add_browser',
          },
        }, 503);
      },
    }, async ({ information, warnings, errors, opened, clipboardWrites, externalOpened }) => {
      await waitForFixtureCondition(() => errors.length === 1, 'startup must expose explicit browser recovery');
      assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
      assert.equal(invitationRequests, 0, 'no invitation before explicit recovery selection');
      assert.deepEqual(opened, []);
      chooseRecovery('Pair integrated browser again');
      await waitForFixtureCondition(() => errors.length === 2, 'failed explicit invitation must expose its error');
      assert.equal(invitationRequests, 1);
      assert.match(errors[1].message, /invitation service is temporarily unavailable/u);
      assert.deepEqual(errors[1].actions, []);
      assert.deepEqual(store.authorities.get(retained.endpoint), retained);
      assert.equal(store.pending.size, 0);
      assert.deepEqual(information, []);
      assert.deepEqual(warnings, []);
      assert.deepEqual(opened, []);
      assert.deepEqual(clipboardWrites, []);
      assert.deepEqual(externalOpened, []);
    });
  } finally {
    chooseRecovery(undefined);
  }
});

test('startup rejected prior-installation authority routes to IDE access recovery, not dashboard recovery', async () => {
  const retained = testActiveAuthority('http://127.0.0.1:8080', 1, 'prior-installation');
  const replacement = testAuthority('http://127.0.0.1:8080', 1, 'replacement-installation');
  const store = new FakeProfileCredentialStore([retained]);
  store.rejected.add(retained.capability);
  store.writePendingError = new ProfileCredentialStoreError(
    'profile_credential_store_write_unconfirmed',
    'same generation from another installation',
  );
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    workspaceFolders: [],
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(replacement), 201);
      if (url.pathname === '/v1/auth/ide/pending') return json({ cancelled: true });
      throw new Error(`unexpected prior-installation recovery request ${url.pathname}`);
    },
  }, async ({ warningCalls, errors, opened, executedCommands }) => {
    for (let turn = 0; turn < 30 && warningCalls.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.deepEqual(requests, [
      { path: '/v1/auth/ide/enrollments', method: 'POST' },
      { path: '/v1/auth/ide/pending', method: 'DELETE' },
    ]);
    assert.equal(warningCalls.length, 1);
    assert.match(warningCalls[0].message, /previous CodeSecurity installation/u);
    assert.deepEqual(warningCalls[0].actions, ['Connect / Review IDE Access']);
    assert.deepEqual(errors, []);
    assert.deepEqual(opened, []);
    assert.equal(
      executedCommands.some(({ name }) => name === 'workbench.action.browser.open'),
      false,
    );
    assert.deepEqual(store.authorities.get(retained.endpoint), retained);
  });
});

test('explicit startup browser recovery failure preserves retained authority without copying', async () => {
  const retained = testActiveAuthority('http://127.0.0.1:8080', 6, 'startup-browser-failure');
  const store = new FakeProfileCredentialStore([retained]);
  let browserAttempts = 0;
  let invitationRequests = 0;
  let chooseRecovery;
  const recoveryChoice = new Promise((resolve) => { chooseRecovery = resolve; });
  try {
    await withExtensionFixture({
      strictBrowserInvitationRoute: true,
      profileCredentialStore: store,
      suppressStartupAuthority: false,
      workspaceFolders: [],
      errorSelection: recoveryChoice,
      eventStreamFactory: (signal) => heldEventStream(signal),
      integratedBrowserResult: async () => {
        browserAttempts += 1;
        throw new Error('fixture integrated browser rejected explicit recovery navigation');
      },
      route: async (url, init) => {
        assert.equal(url.pathname, '/v1/auth/ide/browser-invitations', 'retained recovery must not enroll again');
        assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${retained.capability}`);
        invitationRequests += 1;
        return json(browserInvitationEnvelope());
      },
    }, async ({ information, warnings, errors, opened, clipboardWrites, externalOpened, executedCommands }) => {
      await waitForFixtureCondition(() => errors.length === 1, 'startup must expose explicit browser recovery');
      assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
      assert.equal(invitationRequests, 0, 'no invitation before explicit recovery selection');
      assert.equal(browserAttempts, 0);
      chooseRecovery('Pair integrated browser again');
      await waitForFixtureCondition(() => errors.length === 2, 'failed explicit browser navigation must expose recovery');
      assert.deepEqual(errors[1].actions, ['Copy pairing code']);
      assert.match(errors[1].message, /integrated browser.*could not open/u);
      assert.deepEqual(store.authorities.get(retained.endpoint), retained);
      assert.equal(store.pending.size, 0);
      assert.deepEqual(information, []);
      assert.deepEqual(warnings, []);
      assert.equal(invitationRequests, 1);
      assert.equal(browserAttempts, 1);
      assert.deepEqual(executedCommands.map(({ name }) => name), ['workbench.action.browser.open']);
      assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`)]);
      assert.deepEqual(clipboardWrites, []);
      assert.deepEqual(externalOpened, []);
    });
  } finally {
    chooseRecovery(undefined);
  }
});

test('Refresh Findings after reload reuses the retained profile authority without reenrollment', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'reload-persistence');
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'reload-persistence');
  const store = new FakeProfileCredentialStore([]);
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: store,
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') return json(approvedEnrollmentEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
      throw new Error(`unexpected pairing request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, statusItems }) => {
    await registrations.get('lomoCodeSecurity.pair')();
    assert.deepEqual(store.authorities.get(active.endpoint), active);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · connected');
    assert.deepEqual(errors, []);
  });

  const operationsBeforeReload = store.operations.length;
  const reloadRequests = [];
  const reloadEventAuthorizations = [];
  const firstReloadStream = controllableEventStream();
  let reloadPrompts = 0;
  await withExtensionFixture({
    profileCredentialStore: store,
    realtimeOptions: { maxReconnectFailures: 0 },
    eventStreamFactory: (signal, count, init) => {
      reloadEventAuthorizations.push(new Headers(init.headers).get('Authorization'));
      return count === 1 ? firstReloadStream.response(signal) : heldEventStream(signal);
    },
    inputValue: () => {
      reloadPrompts += 1;
      return 'must-not-be-requested';
    },
    route: async (url, init) => {
      reloadRequests.push({
        path: url.pathname,
        method: init.method || 'GET',
        authorization: new Headers(init.headers).get('Authorization'),
      });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ detail: 'workspace is not registered' }, 404);
      }
      throw new Error(`unexpected reload request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, eventStreams, information, statusItems, warnings }) => {
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · unavailable');
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    const firstRefresh = refresh();
    const coalescedRefresh = refresh();
    for (let turn = 0; turn < 20 && eventStreams() === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    firstReloadStream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    await Promise.all([firstRefresh, coalescedRefresh]);
    for (let turn = 0; turn < 20 && !/connected/.test(statusItems[0].text); turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(reloadPrompts, 0);
    assert.deepEqual(reloadRequests, [{
      path: '/v1/projects/resolve',
      method: 'POST',
      authorization: `Bearer ${active.capability}`,
    }]);
    assert.equal(eventStreams(), 1);
    assert.deepEqual(reloadEventAuthorizations, [`Bearer ${active.capability}`]);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · connected');
    assert(information.some((message) => message.includes('is not registered with CodeSecurity')));
    assert.deepEqual(warnings, []);
    assert.deepEqual(errors, []);

  });

  const reloadOperations = store.operations.slice(operationsBeforeReload);
  assert(reloadOperations.some(({ operation }) => operation === 'readAuthority'));
  assert.equal(
    reloadOperations.some(({ operation }) => [
      'writePending', 'promotePending', 'discardPending', 'markRejected', 'repairCorruptRecords',
    ].includes(operation)),
    false,
  );
  assert.deepEqual(store.authorities.get(active.endpoint), active);
});

test('corrupt regular profile authority repair requires exact modal confirmation', async () => {
  const store = new FakeProfileCredentialStore([]);
  store.readAuthorityError = new ProfileCredentialStoreError(
    'profile_credential_store_corrupt',
    'CodeSecurity refused a malformed profile authority record.',
  );
  store.repairResult = Object.freeze({ removed: Object.freeze(['authority.json']) });
  let requests = 0;
  await withExtensionFixture({
    errorSelection: 'Review and repair exact profile authority',
    warningSelection: 'Repair exact profile authority records',
    profileCredentialStore: store,
    route: async () => {
      requests += 1;
      throw new Error('profile repair must not contact the API');
    },
  }, async ({ registrations, errors, information, warningCalls, statusItems }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();

    assert.equal(requests, 0);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Review and repair exact profile authority']);
    assert.equal(warningCalls.length, 1);
    assert.equal(warningCalls[0].actions[0].modal, true);
    assert.match(warningCalls[0].actions[0].detail, /Symbolic links.*refused/u);
    assert.equal(warningCalls[0].actions[1], 'Repair exact profile authority records');
    assert.deepEqual(
      store.operations.filter(({ operation }) => operation === 'repairCorruptRecords'),
      [{ operation: 'repairCorruptRecords', endpoint: 'http://127.0.0.1:8080' }],
    );
    assert.match(information.at(-1), /Removed 1 corrupt.*http:\/\/127\.0\.0\.1:8080/u);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · IDE access required');
  });
});

test('profile authority repair failure stays typed and does not claim cleanup', async () => {
  const store = new FakeProfileCredentialStore([]);
  store.readAuthorityError = new ProfileCredentialStoreError(
    'profile_credential_store_corrupt',
    'CodeSecurity refused a malformed profile authority record.',
  );
  store.repairError = new ProfileCredentialStoreError(
    'profile_credential_store_insecure',
    'CodeSecurity refused an unexpected file in its profile authority namespace.',
  );
  await withExtensionFixture({
    errorSelection: 'Review and repair exact profile authority',
    warningSelection: 'Repair exact profile authority records',
    profileCredentialStore: store,
    route: async () => {
      throw new Error('profile repair must not contact the API');
    },
  }, async ({ registrations, errors, information, statusItems }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();

    assert.equal(errors.length, 2);
    assert.match(errors[1].message, /unexpected file/u);
    assert.match(errors[1].message, /ownership, permissions, link, and path condition/u);
    assert.deepEqual(errors[1].actions, []);
    assert.deepEqual(information, []);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · unavailable');
  });
});

test('automatic IDE enrollment activates before connecting and opens the dashboard', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'successor');
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'successor');
  const store = new FakeProfileCredentialStore([]);
  const inputPrompts = [];
  const requests = [];
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: store,
    inputValue: (options) => { inputPrompts.push(options); return undefined; },
    route: async (url, init) => {
      requests.push({
        path: url.pathname,
        method: init.method || 'GET',
        authorization: new Headers(init.headers).get('Authorization') || undefined,
        body: init.body ? JSON.parse(String(init.body)) : undefined,
      });
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') return json(approvedEnrollmentEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
      throw new Error(`unexpected pairing request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, statusItems, errors, opened, clipboardWrites, executedCommands }) => {
    await registrations.get('lomoCodeSecurity.pair')();

    assert.equal(inputPrompts.length, 0, 'clean IDE enrollment must never prompt for a pasted secret');
    assert.deepEqual(requests, [
      {
        path: '/v1/auth/ide/enrollments',
        method: 'POST',
        authorization: undefined,
        body: {
          client_name: 'Fixture Code · current · local',
          client_slot: TEST_CLIENT_SLOT,
          expected_active_generation: 0,
        },
      },
      {
        path: '/v1/auth/ide/enrollments/current/wait',
        method: 'GET',
        authorization: `Bearer ${pending.capability}`,
        body: undefined,
      },
      {
        path: '/v1/auth/ide/activate',
        method: 'POST',
        authorization: `Bearer ${pending.capability}`,
        body: undefined,
      },
      {
        path: '/v1/auth/ide/browser-invitations',
        method: 'POST',
        authorization: `Bearer ${active.capability}`,
        body: { purpose: 'integrated_dashboard' },
      },
    ]);
    assert.deepEqual(store.authorities.get(active.endpoint), active);
    assert.deepEqual(store.pending, new Map());
    assert.deepEqual(information, [], 'successful enrollment must not pause or cover its integrated dashboard');
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · connected');
    assert.deepEqual(errors, []);
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`)]);
    assert.deepEqual(executedCommands.filter(({ name }) => name === 'workbench.action.browser.open'), [{
      name: 'workbench.action.browser.open',
      args: [{
        url: retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`),
        reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
      }],
    }]);
  });
});

test('IDE enrollment keeps its durable authority and gives a typed retry when dashboard invitation fails', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'paired-dashboard-failure');
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'paired-dashboard-failure');
  const store = new FakeProfileCredentialStore([]);
  const requests = [];
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: store,
    route: async (url, init) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') return json(approvedEnrollmentEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') {
        return json({
          detail: {
            code: 'ide_browser_invitation_temporarily_unavailable',
            message: 'The IDE dashboard invitation service is temporarily unavailable.',
            action: 'retry_add_browser',
          },
        }, 503);
      }
      throw new Error(`unexpected pairing request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, errors, opened, clipboardWrites }) => {
    await registrations.get('lomoCodeSecurity.pair')();

    assert.deepEqual(requests, [
      '/v1/auth/ide/enrollments',
      '/v1/auth/ide/enrollments/current/wait',
      '/v1/auth/ide/activate',
      '/v1/auth/ide/browser-invitations',
    ]);
    assert.deepEqual(store.authorities.get(active.endpoint), active);
    assert.deepEqual(information, [], 'a typed dashboard failure must not add a blocking success toast');
    assert.deepEqual(opened, []);
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(errors, [{
      message: 'The VS Code profile connected successfully, but CodeSecurity could not authorize its integrated dashboard. '
        + 'The IDE dashboard invitation service is temporarily unavailable. The VS Code profile remains connected. '
        + 'Run Open Dashboard to retry the same fragment-only browser authorization.',
      actions: ['Open Dashboard'],
    }]);
  });
});

test('IDE enrollment keeps its durable authority and gives a typed retry when VS Code rejects the dashboard', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'paired-dashboard-open-failure');
  const active = testActiveAuthority('http://127.0.0.1:8080', 1, 'paired-dashboard-open-failure');
  const store = new FakeProfileCredentialStore([]);
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    profileCredentialStore: store,
    integratedBrowserResult: async () => { throw new Error('fixture browser rejected the request'); },
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/enrollments') return json(enrollmentEnvelope(pending), 201);
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') return json(approvedEnrollmentEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/activate') return json(activationEnvelope(pending));
      if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
      throw new Error(`unexpected pairing request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, errors, clipboardWrites }) => {
    await registrations.get('lomoCodeSecurity.pair')();

    assert.deepEqual(store.authorities.get(active.endpoint), active);
    assert.deepEqual(information, []);
    assert.deepEqual(clipboardWrites, []);
    assert.equal(errors.length, 2);
    assert.deepEqual(errors[0].actions, ['Copy pairing code']);
    assert.match(errors[1].message, /extension remains connected.*did not open.*Run Open Dashboard/isu);
    assert.deepEqual(errors[1].actions, ['Open Dashboard']);
  });
});

test('Connect / Review stays responsive before one durable enrollment publishes its review', async () => {
  const pending = testAuthority('http://127.0.0.1:8080', 1, 'concurrent');
  const store = new FakeProfileCredentialStore([]);
  let enrollmentStarted;
  let releaseEnrollment;
  const enrollmentObserved = new Promise((resolve) => { enrollmentStarted = resolve; });
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: store,
    suppressStartupAuthority: false,
    quickPick: () => undefined,
    route: async (url, init) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/auth/ide/enrollments') {
        enrollmentStarted();
        return new Promise((resolve) => {
          releaseEnrollment = () => resolve(json(enrollmentEnvelope(pending), 201));
        });
      }
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new DOMException('cancelled', 'AbortError')), { once: true });
        });
      }
      throw new Error(`unexpected enrollment request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, errors, quickPickCalls, statusBarMessages, statusItems }) => {
    await enrollmentObserved;
    await Promise.all([
      registrations.get('lomoCodeSecurity.pair')(),
      registrations.get('lomoCodeSecurity.pair')(),
    ]);
    assert.deepEqual(requests, ['/v1/auth/ide/enrollments']);
    assert.deepEqual(statusBarMessages.slice(-2), [
      { message: '$(loading~spin) CodeSecurity is requesting IDE access…', timeout: 5_000 },
      { message: '$(loading~spin) CodeSecurity is requesting IDE access…', timeout: 5_000 },
    ]);
    assert.equal(quickPickCalls.length, 0);

    releaseEnrollment();
    for (let turn = 0; turn < 30 && statusItems[0].text !== `$(key) Approval needed · ${TEST_VERIFICATION_CODE}`; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(requests, [
      '/v1/auth/ide/enrollments',
      '/v1/auth/ide/enrollments/current/wait',
    ]);
    assert.deepEqual(store.pending.get(pending.endpoint), pending);
    assert.equal(statusItems[0].text, `$(key) Approval needed · ${TEST_VERIFICATION_CODE}`);
    await registrations.get('lomoCodeSecurity.pair')();
    assert.equal(quickPickCalls.length, 1);
    assert.equal(quickPickCalls[0].options.title, `IDE access · ${TEST_VERIFICATION_CODE}`);
    assert.deepEqual(errors, []);
    assert.deepEqual(information, []);
  });
});

test('source-open outcome remains opened when the first ACK response is lost', async () => {
  await withExtensionFixture({}, async ({ extensionModule }) => {
    const ledger = new Map();
    const sent = [];
    await assert.rejects(
      extensionModule.persistImmutableSourceOpenOutcome(
        ledger,
        'a'.repeat(32),
        { status: 'opened' },
        async (outcome) => {
          sent.push(outcome);
          throw new Error('ack response lost');
        },
      ),
      /ack response lost/,
    );
    const replayed = await extensionModule.persistImmutableSourceOpenOutcome(
      ledger,
      'a'.repeat(32),
      { status: 'failed', errorCode: 'workspace_not_open' },
      async (outcome) => { sent.push(outcome); },
    );
    assert.deepEqual(replayed, { status: 'opened' });
    assert.deepEqual(sent, [{ status: 'opened' }, { status: 'opened' }]);
  });
});

test('source-open handler reveals the exact validated workspace file and range before acknowledging opened', async () => {
  const commandId = 'b'.repeat(32);
  const followupCommandId = '9'.repeat(32);
  const staleCommandId = 'f'.repeat(32);
  const value = finding(17, {
    file_path: 'src/source-open.ts',
    start_line: 2,
    start_column: 7,
    end_line: 2,
    end_column: 13,
  });
  const acknowledgements = [];
  let detailReads = 0;
  let firstNotificationShown;
  const firstNotification = new Promise((resolve) => { firstNotificationShown = resolve; });
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    informationSelection: () => {
      firstNotificationShown();
      return new Promise(() => {});
    },
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (/^\/v1\/ide\/source-open-commands\/[0-9a-f]{32}\/context$/u.test(url.pathname)) {
        const requestedId = url.pathname.split('/').at(-2);
        return json({
          v: 1,
          command_id: requestedId,
          project_id: 7,
          project_repo_path: '/workspace/current',
        });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([value]));
      if (url.pathname === '/v1/scans/41/findings/17') {
        detailReads += 1;
        assert.equal(url.searchParams.get('expected_revision'), '1');
        assert.equal(url.searchParams.get('expected_findings_revision'), '1');
        return json(findingDetail(17, value));
      }
      if (
        url.pathname === `/v1/ide/source-open-commands/${commandId}/ack`
        || url.pathname === `/v1/ide/source-open-commands/${followupCommandId}/ack`
        || url.pathname === `/v1/ide/source-open-commands/${staleCommandId}/ack`
      ) {
        const acknowledgement = JSON.parse(String(init.body));
        const acknowledgedId = url.pathname.split('/').at(-2);
        acknowledgements.push({ commandId: acknowledgedId, ...acknowledgement });
        return json({
          id: acknowledgedId,
          status: acknowledgement.status,
          revision: 2,
          error_code: acknowledgement.error_code,
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ testApi, changeDocument, openDocument, shownDocuments, errors, information }) => {
    const document = {
      uri: {
        path: '/workspace/current/src/source-open.ts',
        toString: () => 'file:///workspace/current/src/source-open.ts',
      },
      version: 1,
      lineCount: 2,
      lineAt: (line) => ({ text: ['const safe = true;', 'const danger = risky();'][line] }),
      isDirty: false,
    };
    openDocument(document);
    await testApi.refresh();
    const openCommand = {
      v: 1,
      command_id: commandId,
      project_id: 7,
      scan_id: 41,
      finding_id: 17,
      scan_finding_number: 17,
      expected_finding_revision: 1,
      expected_findings_revision: 1,
      expires_at: '2099-08-26T00:00:00Z',
    };
    let firstDelivery = 'notification-blocked';
    const firstDeliveryPromise = testApi.handleSourceOpen(openCommand).then(() => {
      firstDelivery = 'completed';
    });
    await firstNotification;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(
      firstDelivery,
      'completed',
      'a passive notification must not block the serial targeted-command reader',
    );
    await firstDeliveryPromise;

    assert.equal(detailReads, 1, 'the handler reads the exact API-validated finding once before editor navigation');
    assert.deepEqual(acknowledgements, [{
      commandId,
      status: 'opened',
      error_code: null,
    }]);
    assert.equal(shownDocuments.length, 1);
    const editor = shownDocuments[0];
    assert.equal(editor.document, document);
    assert.deepEqual(
      [editor.selection.start.line, editor.selection.start.character, editor.selection.end.line, editor.selection.end.character],
      [1, 6, 1, 12],
    );
    assert.deepEqual(
      [
        editor.revealed[0].range.start.line,
        editor.revealed[0].range.start.character,
        editor.revealed[0].range.end.line,
        editor.revealed[0].range.end.character,
      ],
      [1, 6, 1, 12],
    );
    assert.equal(errors.length, 0);
    assert.match(information.at(-1), /Opened S41-F017.*exact source range/u);

    await testApi.handleSourceOpen({ ...openCommand, command_id: followupCommandId });
    assert.deepEqual(acknowledgements.at(-1), {
      commandId: followupCommandId,
      status: 'opened',
      error_code: null,
    });
    assert.equal(shownDocuments.length, 2, 'each targeted command opens its exact validated source independently');

    changeDocument(document);
    document.isDirty = true;
    await testApi.handleSourceOpen({
      v: 1,
      command_id: staleCommandId,
      project_id: 7,
      scan_id: 41,
      finding_id: 17,
      scan_finding_number: 17,
      expected_finding_revision: 1,
      expected_findings_revision: 1,
      expires_at: '2099-08-26T00:00:00Z',
    });
    assert.equal(detailReads, 3, 'each current-scan source action reads the exact detail once');
    assert.deepEqual(acknowledgements.at(-1), {
      commandId: staleCommandId,
      status: 'failed',
      error_code: 'finding_not_current',
    });
    assert.equal(shownDocuments.length, 2, 'a stale current-scan source must not be shown or selected again');
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /unsaved editor text/u);
  });
});

test('targeted Web source reveal retains the exact hover owner among identical ranges', async () => {
  for (const point of [false, true]) {
    const values = [1, 2].map((id) => finding(id, {
      file_path: 'src/web-owner.ts',
      start_line: 2,
      start_column: 7,
      end_line: 2,
      end_column: point ? 7 : 13,
    }));
    const acknowledgements = [];
    await withExtensionFixture({
      extensionMode: 3,
      streamReady: false,
      route: async (url, init) => {
        if (url.pathname === '/v1/projects/resolve') {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
        }
        if (/^\/v1\/ide\/source-open-commands\/[0-9a-f]{32}\/context$/u.test(url.pathname)) {
          return json({ v: 1, command_id: url.pathname.split('/').at(-2),
            project_id: 7, project_repo_path: '/workspace/current' });
        }
        if (url.pathname === '/v1/projects/7/scans/latest' || url.pathname === '/v1/scans/41') {
          return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
        }
        if (url.pathname === '/v1/scans/41/findings') return json(findingPage(values));
        if (url.pathname === '/v1/scans/41/findings/2') return json(findingDetail(2, values[1]));
        if (/^\/v1\/ide\/source-open-commands\/[0-9a-f]{32}\/ack$/u.test(url.pathname)) {
          const body = JSON.parse(init.body);
          acknowledgements.push(body);
          return json({ id: url.pathname.split('/').at(-2), revision: 2, ...body });
        }
        throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ testApi, openDocument, shownDocuments, provideHover, errors }) => {
      const document = {
        uri: { path: '/workspace/current/src/web-owner.ts',
          toString: () => 'file:///workspace/current/src/web-owner.ts' },
        version: 1,
        lineCount: 2,
        lineAt: (line) => ({ text: ['const safe = true;', 'const danger = risky();'][line] }),
        isDirty: false,
      };
      const hover = () => provideHover(document, { line: 1, character: 6 });
      const advisorIds = (result) => [...result.contents.value.matchAll(
        /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/gu,
      )].map((match) => JSON.parse(decodeURIComponent(match[1]))[0].findingId);
      openDocument(document);
      await testApi.refresh();
      const previous = testApi.snapshot().workspaces[0].findings.find((value) => value.findingId === 1);
      await testApi.revealFinding(previous);
      assert.deepEqual(advisorIds(hover()), [1, 2], 'the prior explicit reveal owns the identical range');
      const command = {
        v: 1, command_id: 'a'.repeat(32), project_id: 7, scan_id: 41,
        finding_id: 2, scan_finding_number: 2,
        expected_finding_revision: 1, expected_findings_revision: 1,
        expires_at: '2099-08-26T00:00:00Z',
      };
      await testApi.handleSourceOpen(command);
      assert.deepEqual(acknowledgements, [{ status: 'opened', error_code: null }]);
      assert.equal(shownDocuments.length, 2);
      const range = shownDocuments.at(-1).selection;
      assert.deepEqual([range.start.line, range.start.character, range.end.line, range.end.character],
        [1, 6, 1, point ? 6 : 12]);
      assert.deepEqual(advisorIds(hover()), [2, 1],
        'the API-validated Web target replaces the prior owner without changing either finding range');

      await testApi.handleSourceOpen({ ...command, command_id: 'b'.repeat(32), finding_id: 99 });
      assert.deepEqual(acknowledgements.at(-1), { status: 'failed', error_code: 'finding_not_current' });
      assert.equal(shownDocuments.length, 2, 'a mismatched command must not navigate or install an owner');
      assert.deepEqual(advisorIds(hover()), [2, 1], 'rejected navigation preserves the current exact owner');
      assert.equal(errors.length, 1);

      if (!point) {
        range.active = range.end;
        const endpoint = provideHover(document, range.active);
        assert(endpoint, 'keyboard Show Hover at the revealed forward selection endpoint has its exact owner');
        assert.deepEqual(advisorIds(endpoint), [2],
          'endpoint access does not widen the identical-range sibling into a pointer hit');
        assert.deepEqual([
          endpoint.range.start.line, endpoint.range.start.character,
          endpoint.range.end.line, endpoint.range.end.character,
        ], [1, 6, 1, 12], 'the stored/displayed finding range is not expanded');
        assert.equal(provideHover(document, { line: 1, character: 13 }), undefined,
          'a pointer beyond the selected endpoint has no special owner access');
        range.active = range.start;
        assert.equal(provideHover(document, range.end), undefined,
          'a pointer at the inactive end of a reversed selection keeps exclusive-end semantics');
        range.active = range.end;
      }
      document.version += 1;
      if (!point) {
        assert.equal(provideHover(document, range.end), undefined,
          'a changed document version cannot use the retained selection endpoint');
      }
      const stale = hover();
      assert(stale, 'current overlapping descriptions remain visible without reusing stale reveal authority');
      assert(stale.contents.value.indexOf('S41-F001') < stale.contents.value.indexOf('S41-F002'));
      if (point) {
        assert.deepEqual(advisorIds(stale), [], 'ambiguous points cannot use an owner from another document version');
        assert.equal(stale.contents.isTrusted, false);
      } else {
        assert.deepEqual(advisorIds(stale), [1, 2], 'nonempty overlap returns to stable, non-preferred ordering');
      }
    });
  }
});

test('retained source-open reconciles an unbound workspace and focuses source over the integrated dashboard before ACK', async () => {
  const commandId = '8'.repeat(32);
  const retained = testActiveAuthority('http://127.0.0.1:8080', 12, 'source-open-recovery');
  const store = new FakeProfileCredentialStore([retained]);
  const globalStateStorage = new Map([
    [
      'lomoCodeSecurity.integratedDashboardMemberships.v1',
      integratedDashboardMembershipState(retained.endpoint),
    ],
  ]);
  const value = finding(17, {
    file_path: 'app.py',
    start_line: 2,
    start_column: 7,
    end_line: 2,
    end_column: 13,
  });
  const acknowledgements = [];
  await withExtensionFixture({
    extensionMode: 3,
    profileCredentialStore: store,
    globalStateStorage,
    streamReady: false,
    deferTextEditorFocus: true,
    textEditorViewColumn: 2,
    activeTabGroupTabs: [{ label: RETAINED_BROWSER_TAB_TITLE, isActive: true }],
    otherTabGroupTabs: [{ label: 'app.py', isActive: true }],
    route: async (url, init) => {
      if (url.pathname === `/v1/ide/source-open-commands/${commandId}/context`) {
        return json({
          v: 1,
          command_id: commandId,
          project_id: 7,
          project_repo_path: '/workspace/current',
        });
      }
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest' || url.pathname === '/v1/scans/41') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
          gate_decision: 'fail',
        });
      }
      if (url.pathname === '/v1/scans/41/findings' && !url.searchParams.has('file_path')) {
        return json(findingPage([value]));
      }
      if (url.pathname === '/v1/scans/41/findings/17') {
        return json(findingDetail(17, value));
      }
      if (url.pathname === `/v1/ide/source-open-commands/${commandId}/ack`) {
        const acknowledgement = JSON.parse(String(init.body));
        acknowledgements.push(acknowledgement);
        return json({
          id: commandId,
          status: acknowledgement.status,
          revision: 2,
          error_code: acknowledgement.error_code,
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({
    testApi, openDocument, entries, shownDocuments, executedCommands, statusItems, errors,
  }) => {
    const document = {
      uri: {
        path: '/workspace/current/app.py',
        toString: () => 'file:///workspace/current/app.py',
      },
      version: 1,
      lineCount: 2,
      lineAt: (line) => ({ text: ['safe = True', 'danger = risky()'][line] }),
      isDirty: false,
    };
    openDocument(document);
    assert.equal(entries.size, 0, 'the retained profile begins with no current native projection');

    await testApi.handleSourceOpen({
      v: 1,
      command_id: commandId,
      project_id: 7,
      scan_id: 41,
      finding_id: 17,
      scan_finding_number: 17,
      expected_finding_revision: 1,
      expected_findings_revision: 1,
      expires_at: '2099-08-26T00:00:00Z',
    });

    assert.equal(entries.get('file:///workspace/current/app.py').length, 1);
    assert.equal(shownDocuments.length, 1);
    assert.deepEqual(
      [
        shownDocuments[0].selection.start.line,
        shownDocuments[0].selection.start.character,
        shownDocuments[0].selection.end.line,
        shownDocuments[0].selection.end.character,
      ],
      [1, 6, 1, 12],
    );
    assert(executedCommands.some(({ name }) => name === 'workbench.action.focusSecondEditorGroup'));
    assert.deepEqual(acknowledgements, [{ status: 'opened', error_code: null }]);
    assert.match(statusItems[0].text, /connecting.*fail.*1 cached/u);
    assert.deepEqual(errors, []);
  });
});

test('source-open rejects projection revision replacement and mutation during show before opened ACK', async () => {
  const retained = testActiveAuthority('http://127.0.0.1:8080', 13, 'source-open-race');
  const original = finding(17, {
    file_path: 'app.py',
    start_line: 2,
    start_column: 7,
    end_line: 2,
    end_column: 13,
  });

  const runCase = async ({ commandId, refreshRevision, mutateOnShow }) => {
    const acknowledgements = [];
    let mutateDuringShow;
    await withExtensionFixture({
      extensionMode: 3,
      profileCredentialStore: new FakeProfileCredentialStore([retained]),
      streamReady: false,
      onShowTextDocument: () => mutateDuringShow?.(),
      route: async (url, init) => {
        if (url.pathname === `/v1/ide/source-open-commands/${commandId}/context`) {
          return json({
            v: 1,
            command_id: commandId,
            project_id: 7,
            project_repo_path: '/workspace/current',
          });
        }
        if (url.pathname === '/v1/projects/resolve') {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: refreshRevision });
        }
        if (url.pathname === '/v1/projects/7/scans/latest') {
          return json({
            id: 41,
            project_id: 7,
            status: 'completed',
            revision: refreshRevision,
            findings_revision: refreshRevision,
            gate_decision: 'fail',
          });
        }
        if (url.pathname === '/v1/scans/41') {
          return json({
            id: 41,
            project_id: 7,
            status: 'completed',
            revision: 1,
            findings_revision: 1,
            gate_decision: 'fail',
          });
        }
        if (url.pathname === '/v1/scans/41/findings' && !url.searchParams.has('file_path')) {
          return json(findingPage([
            refreshRevision === 1 ? original : { ...original, revision: 2, message: 'replacement evidence' },
          ], refreshRevision));
        }
        if (url.pathname === '/v1/scans/41/findings/17') {
          return json(findingDetail(17, original));
        }
        if (url.pathname === `/v1/ide/source-open-commands/${commandId}/ack`) {
          const acknowledgement = JSON.parse(String(init.body));
          acknowledgements.push(acknowledgement);
          return json({
            id: commandId,
            status: acknowledgement.status,
            revision: 2,
            error_code: acknowledgement.error_code,
          });
        }
        throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ testApi, openDocument, changeDocument, shownDocuments, errors }) => {
      const document = {
        uri: {
          path: '/workspace/current/app.py',
          toString: () => 'file:///workspace/current/app.py',
        },
        version: 1,
        lineCount: 2,
        lineAt: (line) => ({ text: ['safe = True', 'danger = risky()'][line] }),
        isDirty: false,
      };
      openDocument(document);
      if (mutateOnShow) mutateDuringShow = () => changeDocument(document);
      await testApi.handleSourceOpen({
        v: 1,
        command_id: commandId,
        project_id: 7,
        scan_id: 41,
        finding_id: 17,
        scan_finding_number: 17,
        expected_finding_revision: 1,
        expected_findings_revision: 1,
        expires_at: '2099-08-26T00:00:00Z',
      });
      assert.equal(acknowledgements.length, 1);
      assert.equal(acknowledgements[0].status, 'failed');
      assert.equal(acknowledgements[0].error_code, refreshRevision === 1
        ? 'finding_not_current'
        : 'revision_conflict');
      assert.equal(shownDocuments.length, mutateOnShow ? 1 : 0);
      if (mutateOnShow) {
        assert.equal(shownDocuments[0].selection, undefined);
        assert.deepEqual(shownDocuments[0].revealed, []);
      }
      assert.equal(errors.length, 1);
    });
  };

  await runCase({ commandId: '4'.repeat(32), refreshRevision: 2, mutateOnShow: false });
  await runCase({ commandId: '5'.repeat(32), refreshRevision: 1, mutateOnShow: true });
});

test('source-open maps a fresh nested project into its trusted open parent without creating a projection', async () => {
  const retained = finding(17, {
    file_path: 'deployment.yaml',
    scan_id: 40,
    scan_finding_number: 5,
    display_id: 'S40-F005',
    start_line: 2,
    start_column: 7,
    end_line: 2,
    end_column: 13,
    revision: 3,
  });
  const commandId = 'd'.repeat(32);
  const dirtyCommandId = 'e'.repeat(32);
  const removedOwnerCommandId = '6'.repeat(32);
  const changedOwnerCommandId = '7'.repeat(32);
  const acknowledgements = [];
  const authoritativeReads = [];
  const uri = (path) => ({
    scheme: 'file', authority: '', path, fsPath: path, toString: () => `file://${path}`,
  });
  const parentFolder = { name: 'parent', uri: uri('/workspace/current') };
  const childFolder = { name: 'child', uri: uri('/workspace/current/k8s') };
  const projectFolder = { name: 'project', uri: uri('/workspace/current/k8s/service') };
  let beforeOwnerSelection;
  let openTopologyMutation;
  let showTopologyMutation;
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    workspaceFolders: [parentFolder],
    onOpenTextDocument: () => openTopologyMutation?.(),
    onShowTextDocument: () => showTopologyMutation?.(),
    route: async (url, init) => {
      if (/^\/v1\/ide\/source-open-commands\/[0-9a-f]{32}\/context$/u.test(url.pathname)) {
        const requestedId = url.pathname.split('/').at(-2);
        authoritativeReads.push(url.pathname);
        return json({
          v: 1,
          command_id: requestedId,
          project_id: 9,
          project_repo_path: '/workspace/current/k8s/service',
        });
      }
      if (url.pathname === '/v1/scans/40') {
        authoritativeReads.push(url.pathname);
        return json({ id: 40, project_id: 9, status: 'completed', revision: 5, findings_revision: 5 });
      }
      if (url.pathname === '/v1/scans/40/findings/5') {
        assert.equal(url.searchParams.get('expected_revision'), '3');
        assert.equal(url.searchParams.get('expected_findings_revision'), '5');
        authoritativeReads.push(`${url.pathname}?${url.searchParams.toString()}`);
        beforeOwnerSelection?.();
        beforeOwnerSelection = undefined;
        return json(findingDetail(17, { ...retained, findings_revision: 5 }));
      }
      if (
        url.pathname === `/v1/ide/source-open-commands/${commandId}/ack`
        || url.pathname === `/v1/ide/source-open-commands/${dirtyCommandId}/ack`
        || url.pathname === `/v1/ide/source-open-commands/${removedOwnerCommandId}/ack`
        || url.pathname === `/v1/ide/source-open-commands/${changedOwnerCommandId}/ack`
      ) {
        const acknowledgement = JSON.parse(String(init.body));
        const acknowledgedId = url.pathname.split('/').at(-2);
        acknowledgements.push({ commandId: acknowledgedId, ...acknowledgement });
        return json({
          id: acknowledgedId,
          status: acknowledgement.status,
          revision: 2,
          error_code: acknowledgement.error_code,
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({
    testApi, openDocument, shownDocuments, information, errors,
    addFolder, removeFolderByName, openWorkspaceFolders,
  }) => {
    const document = {
      uri: {
        path: '/workspace/current/k8s/service/deployment.yaml',
        toString: () => 'file:///workspace/current/k8s/service/deployment.yaml',
      },
      version: 1,
      lineCount: 2,
      lineAt: (line) => ({ text: ['const safe = true;', 'const retained = risky();'][line] }),
      isDirty: false,
    };
    openDocument(document);
    const before = testApi.snapshot();
    assert.deepEqual(before.workspaces, [], 'the fresh open parent has no registered native projection');
    beforeOwnerSelection = () => addFolder(childFolder);
    openTopologyMutation = () => {
      openTopologyMutation = undefined;
      removeFolderByName('parent');
    };
    await testApi.handleSourceOpen({
      v: 1,
      command_id: commandId,
      project_id: 9,
      scan_id: 40,
      finding_id: 17,
      scan_finding_number: 5,
      expected_finding_revision: 3,
      expected_findings_revision: 5,
      expires_at: '2099-08-26T00:00:00Z',
    });

    assert.deepEqual(authoritativeReads, [
      `/v1/ide/source-open-commands/${commandId}/context`,
      '/v1/scans/40',
      '/v1/scans/40/findings/5?expected_revision=3&expected_findings_revision=5',
    ]);
    assert.deepEqual(acknowledgements, [{
      commandId,
      status: 'opened',
      error_code: null,
    }]);
    assert.deepEqual(
      testApi.snapshot().workspaces,
      before.workspaces,
      'targeted source navigation must not create Tree or Problems projection state',
    );
    assert.equal(shownDocuments.length, 1);
    const editor = shownDocuments[0];
    assert.equal(editor.document, document);
    assert.deepEqual(
      [editor.selection.start.line, editor.selection.start.character, editor.selection.end.line, editor.selection.end.character],
      [1, 6, 1, 12],
    );
    assert.equal(errors.length, 0);
    assert.match(information.at(-1), /Opened S40-F005.*exact source range/u);
    assert.deepEqual(
      openWorkspaceFolders().map((folder) => folder.name),
      ['child'],
      'ownership is selected after authoritative reads and remains the deepest root when its parent is removed',
    );

    document.isDirty = true;
    await testApi.handleSourceOpen({
      v: 1,
      command_id: dirtyCommandId,
      project_id: 9,
      scan_id: 40,
      finding_id: 17,
      scan_finding_number: 5,
      expected_finding_revision: 3,
      expected_findings_revision: 5,
      expires_at: '2099-08-26T00:00:00Z',
    });
    assert.deepEqual(acknowledgements.at(-1), {
      commandId: dirtyCommandId,
      status: 'failed',
      error_code: 'finding_not_current',
    });
    assert.deepEqual(authoritativeReads, [
      `/v1/ide/source-open-commands/${commandId}/context`,
      '/v1/scans/40',
      '/v1/scans/40/findings/5?expected_revision=3&expected_findings_revision=5',
      `/v1/ide/source-open-commands/${dirtyCommandId}/context`,
      '/v1/scans/40',
      '/v1/scans/40/findings/5?expected_revision=3&expected_findings_revision=5',
    ], 'each retained-source action must perform one exact authoritative validation sequence');
    assert.equal(shownDocuments.length, 1, 'a dirty retained document must not be shown or selected again');
    assert.deepEqual(
      testApi.snapshot().workspaces,
      before.workspaces,
      'dirty targeted-source rejection must preserve the empty native projection',
    );
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /unsaved editor text/u);

    document.isDirty = false;
    openTopologyMutation = () => {
      openTopologyMutation = undefined;
      removeFolderByName('child');
    };
    await testApi.handleSourceOpen({
      v: 1,
      command_id: removedOwnerCommandId,
      project_id: 9,
      scan_id: 40,
      finding_id: 17,
      scan_finding_number: 5,
      expected_finding_revision: 3,
      expected_findings_revision: 5,
      expires_at: '2099-08-26T00:00:00Z',
    });
    assert.deepEqual(acknowledgements.at(-1), {
      commandId: removedOwnerCommandId,
      status: 'failed',
      error_code: 'workspace_not_open',
    });
    assert.equal(shownDocuments.length, 1, 'owner removal after document open must fail before editor display');
    assert.match(errors.at(-1).message, /exactly one open workspace/u);

    addFolder(childFolder);
    showTopologyMutation = () => {
      showTopologyMutation = undefined;
      addFolder(projectFolder);
    };
    await testApi.handleSourceOpen({
      v: 1,
      command_id: changedOwnerCommandId,
      project_id: 9,
      scan_id: 40,
      finding_id: 17,
      scan_finding_number: 5,
      expected_finding_revision: 3,
      expected_findings_revision: 5,
      expires_at: '2099-08-26T00:00:00Z',
    });
    assert.deepEqual(acknowledgements.at(-1), {
      commandId: changedOwnerCommandId,
      status: 'failed',
      error_code: 'workspace_not_open',
    });
    assert.equal(shownDocuments.length, 2, 'a deeper owner added during show is detected before range selection');
    assert.equal(shownDocuments[1].selection, undefined);
    assert.match(errors.at(-1).message, /unique open workspace.*changed/u);
    assert.deepEqual(testApi.snapshot().workspaces, before.workspaces);
  });
});

test('Restricted Mode source-open acknowledges the typed trust failure without reading source or finding state', async () => {
  const commandId = 'c'.repeat(32);
  const acknowledgements = [];
  const requests = [];
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    workspaceTrusted: false,
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === `/v1/ide/source-open-commands/${commandId}/ack`) {
        acknowledgements.push(JSON.parse(String(init.body)));
        return json({
          id: commandId,
          status: 'failed',
          revision: 2,
          error_code: 'workspace_trust_required',
        });
      }
      throw new Error(`Restricted Mode source-open must not request ${url.pathname}`);
    },
  }, async ({ testApi, resourceStats, snapshotCollections, shownDocuments, errors }) => {
    const before = testApi.snapshot();
    await testApi.handleSourceOpen({
      v: 1,
      command_id: commandId,
      project_id: 7,
      scan_id: 41,
      finding_id: 17,
      scan_finding_number: 17,
      expected_finding_revision: 1,
      expected_findings_revision: 1,
      expires_at: '2099-08-26T00:00:00Z',
    });

    assert.deepEqual(requests, [{
      path: `/v1/ide/source-open-commands/${commandId}/ack`,
      method: 'POST',
    }]);
    assert.deepEqual(acknowledgements, [{
      status: 'failed',
      error_code: 'workspace_trust_required',
    }]);
    assert.deepEqual(resourceStats, []);
    assert.deepEqual(snapshotCollections, []);
    assert.deepEqual(shownDocuments, []);
    const after = testApi.snapshot();
    assert.deepEqual(after.workspaces, before.workspaces, 'a failed Restricted Mode handoff must not mutate finding state');
    assert.equal(after.lastOpenFinding, before.lastOpenFinding);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Restricted Mode/);
  });
});

test('source-open wrong-workspace errors map only from typed problem codes', async () => {
  await withExtensionFixture({}, async ({ extensionModule }) => {
    const typed = new (require('../../dist/client.js').CodeSecurityRequestError)(
      'The selected scan is not open.',
      409,
      false,
      { code: 'workspace_not_open' },
    );
    const untyped = new (require('../../dist/client.js').CodeSecurityRequestError)(
      'workspace not open',
      409,
    );
    assert.equal(extensionModule.sourceOpenErrorCode(typed), 'workspace_not_open');
    const trust = new (require('../../dist/client.js').CodeSecurityRequestError)(
      'Restricted Mode',
      undefined,
      false,
      { code: 'workspace_trust_required', action: 'manage_workspace_trust' },
    );
    assert.equal(extensionModule.sourceOpenErrorCode(trust), 'workspace_trust_required');
    assert.equal(extensionModule.sourceOpenErrorCode(untyped), 'source_open_failed');
  });
});


test('native Windows refresh resolves the opaque local snapshot project without a Remote WSL handoff', async () => {
  const requests = [];
  const windowsFolder = {
    name: 'native-windows',
    uri: {
      scheme: 'file',
      authority: '',
      path: '/C:/work/project',
      fsPath: String.raw`C:\work\project`,
      toString: () => 'file:///C:/work/project',
    },
  };
  await withExtensionFixture({
    route: async (url, init) => {
      requests.push({ path: url.pathname, body: JSON.parse(init.body) });
      return json({ detail: 'project not found' }, 404);
    },
    availableCommands: ['remote-wsl.reopenInWSL'],
    availableExtensions: ['ms-vscode-remote.remote-wsl'],
    workspaceFolders: [windowsFolder],
  }, async ({ registrations, errors, executedCommands, entries }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();

    assert.equal(entries.size, 0);
    assert.equal(errors.length, 0, JSON.stringify(errors));
    assert.deepEqual(executedCommands, []);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].path, '/v1/projects/resolve');
    assert.match(requests[0].body.repo_path, /^\/source-snapshots\/native-windows\/[0-9a-f]{64}$/);
  });
});


test('native Windows refresh publishes Problems and hover when VS Code lower-cases the serialized drive', async () => {
  const rootPath = '/C:/Users/Developer/lomo-qa/vulnerable-demo';
  const rootUri = 'file:///c:/Users/Developer/lomo-qa/vulnerable-demo';
  const filePath = `${rootPath}/infra/main.tf`;
  const fileUri = `${rootUri}/infra/main.tf`;
  const windowsFolder = {
    name: 'vulnerable-demo',
    uri: {
      scheme: 'file',
      authority: '',
      path: rootPath,
      fsPath: String.raw`C:\Users\Developer\lomo-qa\vulnerable-demo`,
      toString: () => rootUri,
    },
  };
  const value = finding(29, {
    scan_id: 8,
    scan_finding_number: 4,
    display_id: 'S8-F004',
    file_path: 'infra/main.tf',
    start_line: 9,
    end_line: 9,
    message: 'Native Windows exact diagnostic',
  });
  await withExtensionFixture({
    streamReady: false,
    workspaceFolders: [windowsFolder],
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        const { repo_path: repoPath } = JSON.parse(init.body);
        assert.match(repoPath, /^\/source-snapshots\/native-windows\/[0-9a-f]{64}$/u);
        return json({ id: 7, name: 'vulnerable-demo', repo_path: repoPath, revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 8,
          project_id: 7,
          status: 'completed',
          gate_decision: 'pass',
          findings_revision: 2,
          revision: 2,
        });
      }
      if (url.pathname === '/v1/scans/8/findings') return json(findingPage([value], 2));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    openDocument,
    provideHover,
    setVisibleTextEditors,
    treeProvider,
  }) => {
    const lines = Array.from({ length: 12 }, (_, index) => `line ${index + 1}`);
    const document = {
      uri: {
        scheme: 'file',
        authority: '',
        path: filePath.replace('/C:/', '/c:/'),
        fsPath: String.raw`C:\Users\Developer\lomo-qa\vulnerable-demo\infra\main.tf`,
        toString: () => fileUri,
      },
      lineCount: lines.length,
      lineAt: (line) => ({ text: lines[line] }),
      isDirty: false,
      version: 1,
    };
    const decorationCalls = [];
    const editor = {
      document,
      visibleRanges: [{
        start: { line: 0, character: 0 },
        end: { line: lines.length - 1, character: lines.at(-1).length },
      }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    };
    openDocument(document);
    setVisibleTextEditors([editor]);

    await registrations.get('lomoCodeSecurity.refreshFindings')();
    await hydrateTreePath(treeProvider(), 'infra/main.tf');

    assert.equal(errors.length, 0, JSON.stringify(errors));
    assert.equal(entries.get(fileUri)?.length, 1, 'Problems owns the lower-serialized native file URI');
    assert(decorationCalls.some(({ options }) => options.length === 1), 'the visible editor receives a finding decoration');
    const hover = provideHover(document, { line: 8, character: 1 });
    assert.match(hover?.contents?.value || '', /S8-F004/u);
  });
});


test('Restricted Mode keeps IDE access but defers integrated Dashboard and source access until trust', async () => {
  const requests = [];
  const inputPrompts = [];
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    workspaceTrusted: false,
    errorSelection: 'Manage Workspace Trust',
    inputValue: (options) => {
      inputPrompts.push(options);
      return undefined;
    },
    route: async (url, init) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
        return json(browserInvitationEnvelope());
      }
      throw new Error('Restricted Mode workspace scan must not contact the backend');
    },
  }, async ({
    registrations, clipboardWrites, errors, executedCommands, information, opened, reports, resourceStats,
    snapshotCollections,
  }) => {
    await registrations.get('lomoCodeSecurity.pair')();
    await registrations.get('lomoCodeSecurity.openDashboard')();

    assert.equal(inputPrompts.length, 0, 'IDE access must not prompt for a pasted secret in Restricted Mode');
    assert.deepEqual(opened, [], 'Restricted Mode must never create an ephemeral paired browser');
    assert.equal(errors.length, 2, 'both Pair completion and explicit Dashboard explain the trust requirement');
    assert(errors.every(({ message }) => /IDE can stay connected.*discard the integrated browser session/su.test(message)), JSON.stringify(errors));
    assert.deepEqual(information, [], 'waiting for Workspace Trust must not display a misleading success notice');
    assert.deepEqual(clipboardWrites, [], 'refused integrated navigation must not overwrite the user clipboard');

    await registrations.get('lomoCodeSecurity.scanWorkspace')();

    assert.deepEqual(resourceStats, []);
    assert.deepEqual(snapshotCollections, []);
    assert.deepEqual(requests, []);
    assert.deepEqual(reports, []);
    assert.equal(errors.length, 3);
    assert.match(errors[0].message, /Restricted Mode.*manage Workspace Trust/s);
    assert.deepEqual(errors[0].actions, ['Manage Workspace Trust']);
    assert.deepEqual(executedCommands.map(({ name }) => name), [
      'workbench.trust.manage',
      'workbench.trust.manage',
      'workbench.trust.manage',
    ]);
  });
});


test('repeat Open Dashboard reconciles and reuses one confirmed integrated-browser member', async () => {
  const requests = [];
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    route: async (url, init) => {
      requests.push({
        path: url.pathname,
        method: init.method || 'GET',
        authorization: new Headers(init.headers).get('Authorization'),
      });
      if (url.pathname === '/v1/auth/ide/browser-invitations') {
        return json(browserInvitationEnvelope());
      }
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch) {
        return json(activeBrowserMembershipEnvelope(membershipMatch[1]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, opened, clipboardWrites, errors, executedCommands }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')();
    await registrations.get('lomoCodeSecurity.openDashboard')();

    assert.deepEqual(requests.map(({ path, method }) => ({ path, method })), [
      { path: '/v1/auth/ide/browser-invitations', method: 'POST' },
      { path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`, method: 'GET' },
      { path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`, method: 'GET' },
    ]);
    assert(requests.every(({ authorization }) => /^Bearer kc1\./u.test(authorization || '')));
    assert.deepEqual(opened, [
      retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`),
      retainedBrowserUrl('http://127.0.0.1:8080/'),
    ]);
    assert.deepEqual(
      executedCommands
        .filter(({ name }) => name === 'workbench.action.browser.open')
        .map(({ args }) => args[0]),
      [
        {
          url: retainedBrowserUrl(`http://127.0.0.1:8080/#bootstrap=${VALID_BROWSER_INVITATION}`),
          reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
        },
        {
          url: retainedBrowserUrl('http://127.0.0.1:8080/'),
          reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
        },
      ],
    );
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(errors, []);
  });
});


test('integrated browser is not retained when the opened host never confirms membership', async () => {
  const requests = [];
  const globalStateStorage = new Map();
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    globalStateStorage,
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/auth/ide/browser-invitations') {
        return json(browserInvitationEnvelope());
      }
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch) {
        return json({
          invitation_id: membershipMatch[1],
          status: 'pending',
          purpose: 'integrated_dashboard',
          expires_at: '2026-08-30T12:10:00Z',
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, warningCalls, opened }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')();

    assert.deepEqual(requests.map(({ path, method }) => ({ path, method })), [
      { path: '/v1/auth/ide/browser-invitations', method: 'POST' },
      { path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`, method: 'GET' },
    ]);
    assert.equal(opened.length, 1, 'the host was asked to open exactly once');
    assert.equal(globalStateStorage.has('lomoCodeSecurity.integratedDashboardMemberships.v1'), false);
    assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardPending.v1'), {
      schema: 'lomo-integrated-dashboard-pending/v1',
      invitations: [{
        endpoint: 'http://127.0.0.1:8080',
        invitationId: 'b'.repeat(24),
        issuedAt: '2026-08-30T12:00:00Z',
        expiresAt: '2026-08-30T12:10:00Z',
      }],
    });
    assert.deepEqual(errors, []);
    assert.equal(warningCalls.length, 1);
    assert.deepEqual(warningCalls[0].actions, [
      'Check same browser pairing',
      'Replace pending invitation',
    ]);
  });
});


test('startup promotes one consumed pending integrated browser without issuing a replacement', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 7, 'consumed-browser-before-local-ack');
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardPending.v1',
    pendingIntegratedDashboardState(active.endpoint),
  ]]);
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch) return json(activeBrowserMembershipEnvelope(membershipMatch[1]));
      throw new Error(`pending acknowledgement recovery must not request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, opened }) => {
    for (
      let turn = 0;
      turn < 30 && !globalStateStorage.has('lomoCodeSecurity.integratedDashboardMemberships.v1');
      turn += 1
    ) await new Promise((resolve) => setImmediate(resolve));

    assert.deepEqual(requests, [{
      path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`,
      method: 'GET',
    }]);
    assert.deepEqual(
      globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
      integratedDashboardMembershipState(active.endpoint),
    );
    assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardPending.v1'), {
      schema: 'lomo-integrated-dashboard-pending/v1',
      invitations: [],
    });
    assert.deepEqual(opened, []);
    assert.deepEqual(errors, []);
  });
});


for (const entry of ['startup', 'command']) {
  for (const status of ['active', 'pending']) {
    test(`${entry} reconciles a consented ${status} replacement before an old revoked browser`, async () => {
      const active = testActiveAuthority('http://127.0.0.1:8080', 7, `replacement-${entry}-${status}`);
      const replacement = `kbi1.${'r'.repeat(24)}.${'s'.repeat(43)}`;
      const old = integratedDashboardMembershipState(active.endpoint);
      const pending = pendingIntegratedDashboardState(active.endpoint, replacement);
      const globalStateStorage = new Map([
        ['lomoCodeSecurity.integratedDashboardMemberships.v1', old],
        ['lomoCodeSecurity.integratedDashboardPending.v1', pending],
      ]);
      const requests = [];
      await withExtensionFixture({
        profileCredentialStore: new FakeProfileCredentialStore([active]),
        suppressStartupAuthority: entry === 'command',
        workspaceFolders: [],
        globalStateStorage,
        strictBrowserInvitationRoute: true,
        strictBrowserMembershipRoute: true,
        eventStreamFactory: signal => heldEventStream(signal),
        route: async (url, init) => {
          requests.push({ path: url.pathname, method: init.method || 'GET' });
          assert.equal(url.pathname, `/v1/auth/ide/browser-invitations/${'r'.repeat(24)}/membership`,
            'the old revoked acknowledgement must not hide a newer consented invitation');
          return json(status === 'active' ? activeBrowserMembershipEnvelope('r'.repeat(24)) : {
            invitation_id: 'r'.repeat(24), status: 'pending', purpose: 'integrated_dashboard',
            expires_at: '2099-08-30T12:10:00Z',
          });
        },
      }, async ({ registrations, errors, warningCalls, opened }) => {
        if (entry === 'command') await registrations.get('lomoCodeSecurity.openDashboard')();
        else for (let turn = 0; turn < 40 && (status === 'active'
          ? globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1')
            ?.memberships?.[0]?.invitationId !== 'r'.repeat(24)
          : warningCalls.length === 0); turn += 1) await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(errors, []);
        assert.equal(requests.length, 1);
        assert.equal(requests[0].method, 'GET');
        assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
          status === 'active' ? integratedDashboardMembershipState(active.endpoint, replacement) : old);
        assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardPending.v1'),
          status === 'active' ? { schema: pending.schema, invitations: [] } : pending);
        assert.equal(warningCalls.length, status === 'pending' ? 1 : 0);
        assert.equal(opened.length, entry === 'command' && status === 'active' ? 1 : 0);
      });
    });
  }
}

test('startup keeps one live pending integrated browser explicit and never issues a replacement', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 7, 'live-browser-before-local-ack');
  const pendingState = pendingIntegratedDashboardState(active.endpoint);
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardPending.v1',
    pendingState,
  ]]);
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch) return json({
        invitation_id: membershipMatch[1],
        status: 'pending',
        purpose: 'integrated_dashboard',
        expires_at: '2099-08-30T12:10:00Z',
      });
      throw new Error(`live pending recovery must not request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, warningCalls, opened }) => {
    for (let turn = 0; turn < 30 && warningCalls.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(requests, [{
      path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`,
      method: 'GET',
    }]);
    assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardPending.v1'), pendingState);
    assert.deepEqual(opened, []);
    assert.deepEqual(errors, []);
    assert.equal(warningCalls.length, 1);
    assert.deepEqual(warningCalls[0].actions, [
      'Check same browser pairing',
      'Replace pending invitation',
    ]);
  });
});


test('startup retains one missing pending acknowledgement until explicit replacement', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 7, 'missing-browser-before-local-ack');
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardPending.v1',
    pendingIntegratedDashboardState(active.endpoint),
  ]]);
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch) return json({ invitation_id: membershipMatch[1], status: 'missing_or_revoked' });
      throw new Error(`missing pending recovery must not request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, opened }) => {
    for (let turn = 0; turn < 30 && errors.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(requests, [{
      path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`,
      method: 'GET',
    }]);
    assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardPending.v1'),
      pendingIntegratedDashboardState(active.endpoint));
    assert.deepEqual(opened, []);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
  });
});


test('revoked integrated browser retains its recovery record and never repairs silently', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 7, 'revoked-browser-record');
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(active.endpoint),
  ]]);
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch) {
        return json({ invitation_id: membershipMatch[1], status: 'missing_or_revoked' });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, opened }) => {
    for (let turn = 0; turn < 20 && errors.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(requests, [{
      path: `/v1/auth/ide/browser-invitations/${'b'.repeat(24)}/membership`,
      method: 'GET',
    }]);
    assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
      integratedDashboardMembershipState(active.endpoint));
    assert.deepEqual(opened, []);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
  });
});

for (const kind of ['acknowledged', 'pending']) {
  test(`declined ${kind} browser recovery stays explicit across dashboard retries and profile restart`, async () => {
    const active = testActiveAuthority('http://127.0.0.1:8080', 7, `declined-browser-${kind}`);
    const key = kind === 'acknowledged'
      ? 'lomoCodeSecurity.integratedDashboardMemberships.v1'
      : 'lomoCodeSecurity.integratedDashboardPending.v1';
    const initial = kind === 'acknowledged'
      ? integratedDashboardMembershipState(active.endpoint)
      : pendingIntegratedDashboardState(active.endpoint);
    const globalStateStorage = new Map([[key, initial]]);
    const requests = [];
    for (let launch = 0; launch < 2; launch += 1) {
      await withExtensionFixture({
        profileCredentialStore: new FakeProfileCredentialStore([active]),
        suppressStartupAuthority: false,
        workspaceFolders: [],
        globalStateStorage,
        strictBrowserInvitationRoute: true,
        strictBrowserMembershipRoute: true,
        eventStreamFactory: signal => heldEventStream(signal),
        route: async (url, init) => {
          requests.push({ path: url.pathname, method: init.method || 'GET' });
          const membership = url.pathname.match(
            /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
          );
          if (membership) return json({ invitation_id: membership[1], status: 'missing_or_revoked' });
          throw new Error(`declined recovery must not request ${init.method || 'GET'} ${url.pathname}`);
        },
      }, async ({ registrations, errors, opened }) => {
        for (let turn = 0; turn < 30 && errors.length === 0; turn += 1) {
          await new Promise(resolve => setImmediate(resolve));
        }
        await registrations.get('lomoCodeSecurity.openDashboard')();
        await registrations.get('lomoCodeSecurity.openDashboard')();
        assert.equal(requests.filter(row => row.method === 'POST').length, 0,
          'dismissing recovery must not make a later Open Dashboard create authority');
        assert.deepEqual(globalStateStorage.get(key), initial);
        assert.deepEqual(opened, []);
        assert.equal(errors.length, 3);
        assert(errors.every(error => error.actions.length === 1
          && error.actions[0] === 'Pair integrated browser again'));
      });
    }
    assert.equal(requests.length, 6);
    assert(requests.every(row => row.method === 'GET'));
  });
}


test('explicit revoked-browser recovery creates and retains exactly one replacement acknowledgement', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 8, 'explicit-browser-recovery');
  const replacement = `kbi1.${'r'.repeat(24)}.${'s'.repeat(43)}`;
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(active.endpoint),
  ]]);
  const requests = [];
  const sourceTab = { label: 'app.py', isActive: true };
  const activeTabs = [sourceTab];
  let recoveredTab;
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    strictBrowserMembershipRoute: true,
    errorSelection: 'Pair integrated browser again',
    activeTabGroupTabs: activeTabs,
    integratedBrowserResult: (url, request) => {
      const target = new URL(url);
      assert.equal(target.searchParams.get('lomo_browser'), 'vscode', 'recovery must retain the integrated browser identity marker');
      sourceTab.isActive = false;
      if (!recoveredTab) {
        assert.equal(Object.hasOwn(request, 'reuseUrlFilter'), false, 'explicit recovery must not reuse a revoked browser tab');
        assert.equal(new URLSearchParams(target.hash.slice(1)).get('bootstrap'), replacement);
        target.hash = '';
        recoveredTab = { label: RETAINED_BROWSER_TAB_TITLE, isActive: true, url: target.toString() };
        activeTabs.push(recoveredTab);
      } else {
        assert.equal(request.reuseUrlFilter, RETAINED_BROWSER_REUSE_FILTER);
        assert.equal(recoveredTab.url, request.reuseUrlFilter, 'the host must match the already-open recovery tab');
        assert.equal(target.hash, '', 'ordinary reopening must not carry another invitation');
        recoveredTab.isActive = true;
        recoveredTab.url = target.toString();
      }
    },
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/auth/ide/browser-invitations') {
        return json(browserInvitationEnvelope(replacement));
      }
      const membershipMatch = url.pathname.match(
        /^\/v1\/auth\/ide\/browser-invitations\/([A-Za-z0-9_-]{24})\/membership$/,
      );
      if (membershipMatch?.[1] === 'b'.repeat(24)) {
        return json({ invitation_id: membershipMatch[1], status: 'missing_or_revoked' });
      }
      if (membershipMatch?.[1] === 'r'.repeat(24)) {
        return json(activeBrowserMembershipEnvelope(membershipMatch[1]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, opened, registrations, closedTabs, externalOpened }) => {
    for (
      let turn = 0;
      turn < 30 && globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1')
        ?.memberships?.[0]?.invitationId !== 'r'.repeat(24);
      turn += 1
    ) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(requests.filter(({ method }) => method === 'POST').length, 1);
    assert.deepEqual(
      globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
      integratedDashboardMembershipState(active.endpoint, replacement),
    );
    assert.equal(opened.length, 1);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Pair integrated browser again']);
    const acknowledgedMembership = globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1');
    recoveredTab.isActive = false;
    sourceTab.isActive = true;
    await registrations.get('lomoCodeSecurity.openDashboard')();
    assert.equal(requests.filter(({ method }) => method === 'POST').length, 1, 'repeated open must not create another invitation');
    assert.deepEqual(globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), acknowledgedMembership);
    assert.deepEqual(activeTabs, [sourceTab, recoveredTab], 'repeated open keeps the exact recovered tab and source neighbor');
    assert.equal(recoveredTab.isActive, true);
    assert.equal(opened.length, 2);
    assert.equal(opened[1], RETAINED_BROWSER_REUSE_FILTER);
    assert.deepEqual(closedTabs, [], 'same-tab reuse must not close either existing tab');
    assert.deepEqual(externalOpened, [], 'integrated recovery must not open or modify a system browser');
    assert.equal(errors.length, 1);
  });
});


test('incompatible browser membership record stays untouched until the exact local reset', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 9, 'invalid-browser-marker');
  const incompatible = {
    schema: 'lomo-integrated-dashboard-memberships/v1',
    endpoints: [active.endpoint],
  };
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    incompatible,
  ]]);
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      throw new Error(`invalid marker must not perform ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, globalStateUpdates, opened }) => {
    for (let turn = 0; turn < 20 && errors.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), incompatible);
    assert.deepEqual(
      globalStateUpdates().filter(({ key }) => key === 'lomoCodeSecurity.integratedDashboardMemberships.v1'),
      [],
    );
    assert.deepEqual(opened, []);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Reset and pair integrated browser/i);
    assert.match(errors[0].message, /only this local dashboard record/i);
    assert.doesNotMatch(errors[0].message, /Remove this endpoint|pre-release/i);
    assert.deepEqual(errors[0].actions, ['Reset and pair integrated browser']);
  });
});


test('explicit incompatible-membership reset removes only that record and confirms one replacement', async () => {
  const active = testActiveAuthority('http://127.0.0.1:8080', 10, 'reset-browser-marker');
  const replacement = `kbi1.${'t'.repeat(24)}.${'u'.repeat(43)}`;
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    {
      schema: 'lomo-integrated-dashboard-memberships/v1',
      endpoints: [active.endpoint],
    },
  ]]);
  let invitations = 0;
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([active]),
    suppressStartupAuthority: false,
    workspaceFolders: [],
    globalStateStorage,
    strictBrowserInvitationRoute: true,
    errorSelection: 'Reset and pair integrated browser',
    eventStreamFactory: (signal) => heldEventStream(signal),
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
        invitations += 1;
        return json(browserInvitationEnvelope(replacement));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ errors, globalStateUpdates, opened }) => {
    for (
      let turn = 0;
      turn < 30 && globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1')
        ?.memberships?.[0]?.invitationId !== 't'.repeat(24);
      turn += 1
    ) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(invitations, 1);
    assert.deepEqual(
      globalStateStorage.get('lomoCodeSecurity.integratedDashboardMemberships.v1'),
      integratedDashboardMembershipState(active.endpoint, replacement),
    );
    const membershipWrites = globalStateUpdates()
      .filter(({ key }) => key === 'lomoCodeSecurity.integratedDashboardMemberships.v1')
      .map(({ value }) => value);
    assert.equal(membershipWrites[0], undefined, 'the incompatible record is explicitly reset first');
    assert(membershipWrites.length >= 2, 'the exact acknowledged replacement must then be persisted');
    for (const value of membershipWrites.slice(1)) {
      assert.deepEqual(value, integratedDashboardMembershipState(active.endpoint, replacement),
        'every subsequent write must preserve the same single acknowledged browser member');
    }
    assert.equal(opened.length, 1);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Reset and pair integrated browser']);
  });
});


test('Add Browser offers explicit open and copy paths without placing its secret in a query or setting', async () => {
  const requests = [];
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    quickPick: (items) => items.find((item) => item.action === 'copy'),
    route: async (url, init) => {
      requests.push({ url: url.toString(), method: init.method, authorization: init.headers.get('Authorization') });
      if (url.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
        return json(browserInvitationEnvelope(VALID_BROWSER_INVITATION, 'extra_browser'));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, clipboardWrites, information, opened, quickPickCalls }) => {
    await registrations.get('lomoCodeSecurity.addBrowser')();

    assert.equal(quickPickCalls.length, 1);
    assert.equal(quickPickCalls[0].options.title, 'Add Browser to Lomo CodeSecurity');
    assert.match(quickPickCalls[0].items[0].description, /Recommended.*10-minute.*unpaired local browser profile/i);
    assert.match(quickPickCalls[0].items[1].description, /already-paired browser is rejected/i);
    assert.deepEqual(clipboardWrites, [VALID_BROWSER_INVITATION]);
    assert.deepEqual(opened, []);
    assert.match(information[0], /one-time browser pairing code.*within 10 minutes/i);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'POST');
    assert.match(requests[0].authorization, /^Bearer kc1\./u);
    assert(!requests[0].url.includes(VALID_BROWSER_INVITATION));
  });
});


test('Add Browser opens a fragment-only invitation and copies it only after an explicit failure action', async () => {
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    errorSelection: 'Copy pairing code',
    quickPick: (items) => items.find((item) => item.action === 'open'),
    externalOpenResult: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
        return json(browserInvitationEnvelope(VALID_BROWSER_INVITATION, 'extra_browser'));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, clipboardWrites, errors, information, opened, externalOpened }) => {
    await registrations.get('lomoCodeSecurity.addBrowser')();

    assert.deepEqual(opened, []);
    assert.equal(externalOpened.length, 1);
    const openedUrl = new URL(externalOpened[0]);
    assert.equal(openedUrl.search, '');
    assert.equal(new URLSearchParams(openedUrl.hash.slice(1)).get('bootstrap'), VALID_BROWSER_INVITATION);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Copy pairing code']);
    assert.deepEqual(clipboardWrites, [VALID_BROWSER_INVITATION]);
    assert.match(information[0], /one-time browser pairing code/i);
  });
});


test('Add Browser fails closed before issuing or copying when this IDE profile has no retained authority', async () => {
  const requests = [];
  await withExtensionFixture({
    profileCredentialStore: new FakeProfileCredentialStore([]),
    route: async (url) => {
      requests.push(url.pathname);
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, clipboardWrites, opened, warnings }) => {
    await registrations.get('lomoCodeSecurity.addBrowser')();

    assert.deepEqual(requests, []);
    assert.deepEqual(clipboardWrites, []);
    assert.deepEqual(opened, []);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /Connect this VS Code profile/i);
  });
});


test('Restricted Mode dismissal blocks folder, file, rescan, refresh, and reveal before source or backend access', async () => {
  const requests = [];
  const folderUri = {
    scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
    toString: () => 'file:///workspace/current',
  };
  const fileUri = {
    scheme: 'file', authority: '', path: '/workspace/current/app.py', fsPath: '/workspace/current/app.py',
    toString: () => 'file:///workspace/current/app.py',
  };
  await withExtensionFixture({
    workspaceTrusted: false,
    route: async (url) => {
      requests.push(url.pathname);
      throw new Error('Restricted Mode source action must not contact the backend');
    },
  }, async ({
    registrations, errors, executedCommands, reports, resourceStats, snapshotCollections,
  }) => {
    await registrations.get('lomoCodeSecurity.scanFolder')(folderUri);
    await registrations.get('lomoCodeSecurity.scanFile')(fileUri);
    await registrations.get('lomoCodeSecurity.rescanFile')({});
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    await registrations.get('lomoCodeSecurity.revealFinding')({});

    assert.deepEqual(resourceStats, [], 'trust admission must precede workspace.fs.stat');
    assert.deepEqual(snapshotCollections, []);
    assert.deepEqual(requests, []);
    assert.deepEqual(reports, []);
    assert.deepEqual(executedCommands, [], 'dismissing Workspace Trust guidance must execute no command');
    assert.equal(errors.length, 5);
    for (const error of errors) {
      assert.match(error.message, /Restricted Mode.*manage Workspace Trust/s);
      assert.deepEqual(error.actions, ['Manage Workspace Trust']);
    }
  });
});

test('Restricted Mode native providers, editor projections, and tree expansion read no source and start no hydration', async () => {
  const value = finding(1, { file_path: 'src/restricted.ts' });
  const requests = [];
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([value]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    changeDocument,
    changeVisibleRanges,
    entries,
    notifyVisibleTextEditorsChanged,
    openDocument,
    provideCodeActions,
    provideHover,
    setVisibleTextEditors,
    setWorkspaceTrusted,
    treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const requestsBeforeRestriction = requests.length;
    const diagnosticsBeforeRestriction = [...entries.entries()];
    setWorkspaceTrusted(false);

    let sourceReads = 0;
    const document = {
      get uri() {
        sourceReads += 1;
        return {
          path: '/workspace/current/src/restricted.ts',
          toString: () => 'file:///workspace/current/src/restricted.ts',
        };
      },
      get version() { sourceReads += 1; return 1; },
      get lineCount() { sourceReads += 1; return 1; },
      get isDirty() { sourceReads += 1; return false; },
      lineAt: () => { sourceReads += 1; return { text: 'restricted();' }; },
    };
    const editor = {
      get document() { sourceReads += 1; return document; },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 12 } }],
      setDecorations: () => { throw new Error('Restricted Mode must not project decorations'); },
    };
    setVisibleTextEditors([editor]);

    assert.equal(provideHover(document, { line: 0, character: 0 }), undefined);
    assert.deepEqual(provideCodeActions(document, {
      start: { line: 0, character: 0 }, end: { line: 0, character: 1 },
    }), []);
    notifyVisibleTextEditorsChanged();
    changeVisibleRanges(editor, editor.visibleRanges);
    openDocument(document);
    changeDocument(document);
    assert.deepEqual(await hydrateTreePath(treeProvider(), 'src/restricted.ts'), []);

    assert.equal(sourceReads, 0, 'untrusted native callbacks must not dereference the document or editor');
    assert.equal(requests.length, requestsBeforeRestriction, 'tree expansion must not start file hydration');
    assert.deepEqual([...entries.entries()], diagnosticsBeforeRestriction, 'suppressed callbacks must not mutate projection state');
  });
});

test('Restricted Mode blocks exact reconciliation before manifest API or local finding-state mutation', async () => {
  const value = finding(1, { file_path: 'src/reconcile.ts' });
  const postRestrictionRequests = [];
  let restricted = false;
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: async (url) => {
      if (restricted) postRestrictionRequests.push(url.pathname);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings' && !url.searchParams.has('file_path')) {
        return json(findingPage([value]));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json({
          detail: {
            code: 'revision_conflict',
            message: 'The finding revision advanced.',
            action: 'refresh_findings',
          },
        }, 409);
      }
      throw new Error(`Restricted Mode reconciliation must not request ${url.pathname}`);
    },
  }, async ({ testApi, setWorkspaceTrusted }) => {
    await testApi.refresh();
    const before = testApi.snapshot();
    const [context] = before.workspaces[0].findings;
    restricted = true;
    setWorkspaceTrusted(false);

    await assert.rejects(
      testApi.queueAdvisor(context),
      (error) => error?.code === 'workspace_trust_required' && error?.action === 'manage_workspace_trust',
    );

    assert.deepEqual(postRestrictionRequests, ['/v1/scans/41/findings/1']);
    assert.deepEqual(testApi.snapshot(), before, 'reconciliation admission must not invalidate or replace local state');
  });
});

test('Restricted Mode transition after manifest load blocks publication before diagnostics or local state', async () => {
  const value = finding(1, { file_path: 'src/publication.ts' });
  const requests = [];
  let restrictWorkspace;
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        restrictWorkspace();
        return json(hybridManifest([value]));
      }
      throw new Error(`Restricted Mode publication must not request ${url.pathname}`);
    },
  }, async ({ entries, setWorkspaceTrusted, testApi }) => {
    restrictWorkspace = () => setWorkspaceTrusted(false);
    await assert.rejects(
      testApi.refresh(),
      (error) => error?.code === 'workspace_trust_required' && error?.action === 'manage_workspace_trust',
    );

    assert.deepEqual(requests, [
      '/v1/projects/resolve',
      '/v1/projects/7/scans/latest',
      '/v1/scans/41/finding-files',
    ]);
    assert.deepEqual([...entries.entries()], []);
    assert.deepEqual(testApi.snapshot().workspaces, []);
  });
});

for (const candidate of [
  {
    label: 'lifecycle PATCH',
    command: 'lomoCodeSecurity.setLifecycle',
    choose: (items) => items.find(({ action }) => action === 'needs_review'),
    errorSelection: 'Manage Workspace Trust',
    expectedCommands: [{ name: 'workbench.trust.manage', args: [] }],
  },
  {
    label: 'irreversible DELETE',
    command: 'lomoCodeSecurity.deleteFinding',
    choose: (items) => items.find(({ action }) => action === 'delete'),
    errorSelection: undefined,
    expectedCommands: [],
  },
]) {
  test(`Restricted Mode trust flip after confirmation blocks ${candidate.label} with no local mutation`, async () => {
    const value = finding(1, { file_path: 'src/mutation.ts' });
    const commandRequests = [];
    let commandStarted = false;
    let restrictWorkspace;
    await withExtensionFixture({
      extensionMode: 3,
      errorSelection: candidate.errorSelection,
      streamReady: false,
      quickPick: (items) => {
        const selected = candidate.choose(items);
        assert(selected, `fixture could not choose ${candidate.label}`);
        restrictWorkspace();
        return selected;
      },
      route: async (url, init) => {
        if (commandStarted) commandRequests.push({ path: url.pathname, method: init.method || 'GET' });
        if (url.pathname === '/v1/projects/resolve') {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
        }
        if (url.pathname === '/v1/projects/7/scans/latest') {
          return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
        }
        if (url.pathname === '/v1/scans/41/findings' && !url.searchParams.has('file_path')) {
          return json(findingPage([value]));
        }
        if (url.pathname === '/v1/scans/41/findings/1') {
          return json(findingDetail(1, { ...value, findings_revision: 1 }));
        }
        throw new Error(`trust-flip admission must not send ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ errors, executedCommands, registrations, setWorkspaceTrusted, testApi, treeProvider }) => {
      await testApi.refresh();
      const before = testApi.snapshot();
      const tree = treeProvider();
      const [severity] = await hydrateTreePath(tree, 'src/mutation.ts');
      const [lifecycle] = tree.getChildren(severity);
      const [findingNode] = tree.getChildren(lifecycle);
      assert(findingNode, 'fixture expected one current finding Tree node');
      tree.getTreeItem(findingNode);
      restrictWorkspace = () => setWorkspaceTrusted(false);
      commandStarted = true;

      await registrations.get(candidate.command)(findingNode);

      assert.deepEqual(commandRequests, [
        { path: '/v1/projects/resolve', method: 'POST' },
        { path: '/v1/scans/41/findings/1', method: 'GET' },
        { path: '/v1/projects/7/scans/latest', method: 'GET' },
      ]);
      assert.deepEqual(testApi.snapshot().workspaces, before.workspaces);
      assert.equal(errors.length, 1);
      assert.match(errors[0].message, /Restricted Mode.*manage Workspace Trust/s);
      assert.deepEqual(errors[0].actions, ['Manage Workspace Trust']);
      assert.deepEqual(executedCommands, candidate.expectedCommands);
    });
  });
}


test('native Windows WSL UNC scan fails before filesystem or backend work and offers the explicit Remote WSL handoff', async () => {
  const requests = [];
  const uncFolder = {
    name: 'project',
    uri: {
      scheme: 'file',
      authority: 'wsl.localhost',
      path: '/Ubuntu-26.04/home/qa/project',
      fsPath: String.raw`\\wsl.localhost\Ubuntu-26.04\home\qa\project`,
      toString: () => 'file://wsl.localhost/Ubuntu-26.04/home/qa/project',
    },
  };
  await withExtensionFixture({
    route: async (url) => {
      requests.push(url.pathname);
      throw new Error('WSL UNC admission must not contact the backend');
    },
    availableCommands: ['remote-wsl.reopenInWSL'],
    availableExtensions: ['ms-vscode-remote.remote-wsl'],
    errorSelection: 'Reopen Workspace in Remote WSL',
    workspaceFolders: [uncFolder],
  }, async ({
    registrations, errors, executedCommands, reports, resourceStats, snapshotCollections,
  }) => {
    await registrations.get('lomoCodeSecurity.scanFolder')(uncFolder.uri);

    assert.deepEqual(resourceStats, [], 'URI admission must precede workspace.fs.stat');
    assert.deepEqual(snapshotCollections, [], 'WSL UNC must not enter native snapshot collection');
    assert.deepEqual(requests, [], 'WSL UNC must not reach the API');
    assert.deepEqual(reports, [], 'WSL UNC must fail before scan progress begins');
    assert.equal(errors.length, 1);
    assert.equal(errors[0].message.includes(String.raw`\\wsl.localhost`), true);
    assert.match(errors[0].message, /native Windows UNC path.*Reopen.*Remote WSL/s);
    assert.deepEqual(errors[0].actions, ['Reopen Workspace in Remote WSL']);
    assert.deepEqual(executedCommands, [{
      name: 'lomoCodeSecurity.reopenInRemoteWsl', args: [],
    }]);

    await registrations.get('lomoCodeSecurity.reopenInRemoteWsl')();
    assert.deepEqual(executedCommands.at(-1), { name: 'remote-wsl.reopenInWSL', args: [] });
  });
});


test('native Windows WSL UNC file scan dismissal performs no filesystem, snapshot, backend, or handoff action', async () => {
  const uncFolder = {
    name: 'project',
    uri: {
      scheme: 'file',
      authority: 'wsl.localhost',
      path: '/Ubuntu-26.04/home/qa/project',
      fsPath: String.raw`\\wsl.localhost\Ubuntu-26.04\home\qa\project`,
      toString: () => 'file://wsl.localhost/Ubuntu-26.04/home/qa/project',
    },
  };
  const fileUri = {
    scheme: 'file',
    authority: 'wsl.localhost',
    path: `${uncFolder.uri.path}/app.py`,
    fsPath: `${uncFolder.uri.fsPath}\\app.py`,
    toString: () => `${uncFolder.uri.toString()}/app.py`,
  };
  const requests = [];
  await withExtensionFixture({
    route: async (url) => {
      requests.push(url.pathname);
      throw new Error('dismissed WSL UNC file admission must not contact the backend');
    },
    workspaceFolders: [uncFolder],
  }, async ({
    registrations, errors, executedCommands, reports, resourceStats, snapshotCollections,
  }) => {
    await registrations.get('lomoCodeSecurity.scanFile')(fileUri);

    assert.deepEqual(resourceStats, [], 'file URI admission must precede workspace.fs.stat');
    assert.deepEqual(snapshotCollections, []);
    assert.deepEqual(requests, []);
    assert.deepEqual(reports, []);
    assert.deepEqual(executedCommands, [], 'dismissing the handoff prompt must execute no command');
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Reopen Workspace in Remote WSL']);
  });
});


test('generic native Windows UNC scan fails closed without the Remote WSL action', async () => {
  const serverFolder = {
    name: 'share',
    uri: {
      scheme: 'file',
      authority: 'server',
      path: '/share/project',
      fsPath: String.raw`\\server\share\project`,
      toString: () => 'file://server/share/project',
    },
  };
  await withExtensionFixture({
    route: async () => { throw new Error('generic UNC admission must not contact the backend'); },
    errorSelection: 'Reopen Workspace in Remote WSL',
    workspaceFolders: [serverFolder],
  }, async ({
    registrations, errors, executedCommands, resourceStats, snapshotCollections,
  }) => {
    await registrations.get('lomoCodeSecurity.scanFolder')(serverFolder.uri);

    assert.deepEqual(resourceStats, []);
    assert.deepEqual(snapshotCollections, []);
    assert.deepEqual(executedCommands, []);
    assert.deepEqual(errors, [{
      message: 'Native Windows snapshot scanning requires an absolute local drive workspace. UNC and virtual filesystem roots are not supported.',
      actions: [],
    }]);
  });
});


test('Remote WSL handoff explains when the official Microsoft extension is unavailable', async () => {
  const windowsFolder = {
    name: 'native-windows',
    uri: {
      scheme: 'file',
      authority: '',
      path: '/C:/work/project',
      fsPath: String.raw`C:\work\project`,
      toString: () => 'file:///C:/work/project',
    },
  };
  await withExtensionFixture({
    route: async () => { throw new Error('handoff availability must not contact the backend'); },
    workspaceFolders: [windowsFolder],
  }, async ({ registrations, errors, executedCommands }) => {
    await registrations.get('lomoCodeSecurity.reopenInRemoteWsl')();

    assert.deepEqual(executedCommands, []);
    assert.deepEqual(errors, [{
      message: 'Install and enable the official Microsoft WSL extension (ms-vscode-remote.remote-wsl), then retry.',
      actions: [],
    }]);
  });
});


test('scan admission timing is shared and doubles only for native Windows or Remote WSL', async () => {
  await withExtensionFixture({}, async ({ extensionModule }) => {
    assert.equal(extensionModule.scanAdmissionDeadlineMs('mounted', undefined), 120_000);
    assert.equal(extensionModule.scanAdmissionDeadlineMs('snapshot', undefined), 240_000);
    assert.equal(extensionModule.scanAdmissionDeadlineMs('mounted', 'wsl'), 240_000);
    assert.equal(extensionModule.scanAdmissionDeadlineMs('mounted', 'WSL'), 240_000);
    assert.equal(extensionModule.scanAdmissionDeadlineMs('mounted', 'ssh-remote'), 120_000);
  });
});


test('scan command acknowledges a durable job and loads only the exact terminal scan diagnostics', async () => {
  const calls = [];
  const scanKeys = [];
  let projectCreated = false;
  await withExtensionFixture({
    route: async (url, init) => {
      calls.push({ path: `${url.pathname}${url.search}`, init });
      if (url.pathname === '/v1/projects/resolve' && init.method === 'POST') {
        assert.deepEqual(JSON.parse(init.body), { repo_path: '/workspace/current' });
        return projectCreated
          ? json({ id: 7, name: 'current', repo_path: '/workspace/current' })
          : json({ detail: 'not found' }, 404);
      }
      if (url.pathname === '/v1/projects' && init.method === 'POST') {
        assert.deepEqual(JSON.parse(init.body), {
          name: 'current', repo_path: '/workspace/current', default_branch: 'main',
        });
        projectCreated = true;
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ detail: 'no scan yet' }, 404);
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        scanKeys.push(new Headers(init.headers).get('Idempotency-Key'));
        assert.match(scanKeys.at(-1), /^vscode-[0-9a-f-]{36}$/);
        if (scanKeys.length === 1) {
          throw new TypeError('generated response-loss fixture');
        }
        return json({ id: 41, project_id: 7, status: 'pending', job_id: 71, job_revision: 1 }, 202);
      }
      if (url.pathname === '/v1/jobs/71') {
        return json({
          id: 71, kind: 'scan', title: 'Scan #41', status: 'completed', stage: 'completed',
          detail: 'Persisted.', progress: 100, scan_id: 41, attempt: 1, max_attempts: 3,
          revision: 4, can_cancel: false, can_retry: false,
        });
      }
      if (url.pathname === '/v1/scans/41') {
        return json({ id: 41, project_id: 7, status: 'partial', revision: 1, findings_revision: 1,
          scanner_summary: { scope: { kind: 'workspace', target_path: null } } });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        assert.equal(url.search, '?limit=200');
        return json(findingPage([finding(501, {
          scan_finding_number: 1,
          display_id: 'S41-F001',
          file_path: 'src/exact.ts',
          start_line: 9,
          end_line: 9,
          message: 'Exact persisted evidence',
          rule_id: 'fixture.rule',
        })]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, reports, information, errors, entries, collection }) => {
    await registrations.get('lomoCodeSecurity.scanWorkspace')();

    assert.equal(errors.length, 0);
    assert.equal(collection.batches, 1);
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/exact.ts']);
    assert(reports.some((item) => item.options?.cancellable === true));
    assert(reports.some((item) => /replaying the same durable command \(2\/3\)/.test(item.message || '')));
    assert(reports.some((item) => /job #71 · completed/.test(item.message || '')));
    assert(information.some((message) => /scan #41 finished with partial evidence.*loaded 1 persisted finding/.test(message)));
  });

  assert.deepEqual(calls.map(({ path }) => path), [
    '/v1/projects/resolve',
    '/v1/projects',
    '/v1/projects/resolve',
    '/v1/projects/7/scans/latest',
    '/v1/scans',
    '/v1/scans',
    '/v1/jobs/71',
    '/v1/scans/41',
    '/v1/scans/41/findings?limit=200',
    '/v1/scans/41',
  ]);
  assert.equal(new Set(scanKeys).size, 1);
  assert(calls.every(({ init }) => /^Bearer kc1\./u.test(new Headers(init.headers).get('Authorization') || '')));
  assert(calls.every(({ init }) => init.signal instanceof AbortSignal));
});

test('workspace batch previews exact roots, keeps separate jobs and reports per-root terminal outcomes', async () => {
  const roots = ['a', 'b'].map((name) => ({ name, uri: {
    scheme: 'file', authority: '', path: `/workspace/${name}`, fsPath: `/workspace/${name}`,
    toString: () => `file:///workspace/${name}`,
  } }));
  for (const scenario of ['all', 'selected', 'preview-cancel', 'review-cancel', 'review-subset', 'cancel-before-start', 'cancel-current', 'boundary-refusal', 'preview-refusal', 'closed-root']) {
    const calls = [];
    const commands = [];
    let results;
    let cancel;
    let closeRoot;
    let cancellationCount = 0;
    let confirmed = false;
    const selectedCount = scenario === 'selected' || scenario === 'preview-refusal' || scenario === 'review-subset' ? 1 : 2;
    await withExtensionFixture({
      workspaceFolders: roots,
      warningSelection: scenario === 'preview-cancel' ? undefined : `Scan ${selectedCount} folder${selectedCount === 1 ? '' : 's'}`,
      cancellationRequested: scenario === 'cancel-before-start',
      captureProgressCancellation: (value) => { cancel = value.cancel; confirmed = true; },
      quickPick: (items, options) => {
        if (options.title === 'Scan Workspace Folders') return items.find((item) => item.all === (scenario !== 'selected'));
        if (options.title === 'Review folders to scan') {
          assert(items.every(item => item.picked && item.description.startsWith('/workspace/') && item.detail));
          return scenario === 'review-cancel' ? undefined : scenario === 'review-subset' ? [items[1]] : items;
        }
        if (options.canPickMany) return [items[1]];
        if (options.title === 'CodeSecurity · workspace folder results') { results = items.map((item) => item.outcome); return undefined; }
        throw new Error(`Unexpected selection ${options.title}`);
      },
      route: async (url, init) => {
        calls.push(`${init.method || 'GET'} ${url.pathname}`);
        if (url.pathname === '/v1/sources/preview') {
          assert.equal(confirmed, false, 'preview must finish before scan progress/admission');
          const { repo_path } = JSON.parse(init.body);
          const authorized = scenario !== 'preview-refusal' || repo_path !== '/workspace/b';
          if (scenario === 'closed-root' && repo_path === '/workspace/b') closeRoot();
          return json({ installation_id: '0123456789ab', repo_path, authorization_mode: 'mounted', authorized,
            configured_roots: ['/workspace'], reason_code: authorized ? null : 'source_outside_allowed_root' });
        }
        if (url.pathname === '/v1/projects/resolve') {
          const { repo_path } = JSON.parse(init.body);
          return json({ id: repo_path.endsWith('/a') ? 7 : 8, name: repo_path.at(-1), repo_path, revision: 1 });
        }
        if (/^\/v1\/projects\/[78]\/scans\/latest$/.test(url.pathname)) return json({ detail: 'no scan' }, 404);
        if (url.pathname === '/v1/scans' && init.method === 'POST') {
          assert.equal(confirmed, true);
          const body = JSON.parse(init.body);
          const id = body.project_id === 7 ? 41 : 42;
          commands.push({ body, key: new Headers(init.headers).get('Idempotency-Key') });
          if (scenario === 'boundary-refusal' && body.project_id === 7) return json({ detail: {
            code: 'source_outside_allowed_root', message: 'The configured source boundary changed after preview.',
            action: 'authorize_source', context: { allowed_roots: ['/new/root'] },
          } }, 422);
          if (scenario === 'cancel-current') cancel();
          return json({ id, project_id: body.project_id, status: 'pending', job_id: id + 30 }, 202);
        }
        const job = /^\/v1\/jobs\/(7[12])(\/cancel)?$/.exec(url.pathname);
        if (job) {
          if (job[2]) { assert.equal(job[1], '71'); cancellationCount += 1; }
          const status = scenario === 'cancel-current' ? (job[2] ? 'cancelled' : 'running') : 'completed';
          return json({ id: Number(job[1]), kind: 'scan', title: 'Scan', status, stage: status,
            progress: 100, scan_id: Number(job[1]) - 30, attempt: 1, max_attempts: 3,
            revision: job[2] ? 3 : 2, can_cancel: status === 'running', can_retry: false });
        }
        const scan = /^\/v1\/scans\/(4[12])$/.exec(url.pathname);
        if (scan) return json({ id: Number(scan[1]), project_id: scan[1] === '41' ? 7 : 8,
          status: scenario === 'cancel-current' ? 'cancelled' : scan[1] === '42' ? 'partial' : 'completed',
          findings_revision: 1 });
        if (/^\/v1\/scans\/4[12]\/findings$/.test(url.pathname)) return json(findingPage([]));
        throw new Error(`Unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ registrations, errors, warningCalls, reports, removeFolderByName }) => {
      closeRoot = () => removeFolderByName('b');
      await registrations.get(scenario === 'all' ? 'lomoCodeSecurity.scanRootFolder' : 'lomoCodeSecurity.scanWorkspaceFolders')();
      assert.deepEqual(errors, [], scenario);
      if (scenario === 'review-cancel') { assert.equal(warningCalls.length, 0); return; }
      assert.match(warningCalls[0].actions[0].detail, /admission checks still apply/);
      assert.match(warningCalls[0].actions[0].detail, /Overlapping roots are not merged/);
      assert.equal(reports.filter((item) => item.options).length, scenario === 'preview-cancel' ? 0 : 1, scenario);
    });
    const expected = {
      all: ['completed', 'partial'], selected: ['partial'], 'preview-cancel': undefined, 'review-cancel': undefined, 'review-subset': ['not_started', 'partial'],
      'cancel-before-start': ['not_started', 'not_started'], 'cancel-current': ['cancelled', 'not_started'],
      'boundary-refusal': ['failed', 'partial'], 'preview-refusal': ['completed', 'not_started'],
      'closed-root': ['completed', 'not_started'],
    }[scenario];
    assert.deepEqual(results?.map((item) => item.status), expected, scenario);
    assert.equal(cancellationCount, scenario === 'cancel-current' ? 1 : 0, scenario);
    assert.equal(calls.includes('POST /v1/projects'), false, 'pre-existing projects need no create');
    if (scenario === 'preview-cancel' || scenario === 'review-cancel' || scenario === 'cancel-before-start') {
      assert.equal(commands.length, 0, scenario);
      assert.equal(calls.some((call) => call.includes('/v1/jobs/')), false);
    }
    for (const { body, key } of commands) {
      assert.deepEqual(Object.keys(body).sort(), ['mode', 'project_id', 'use_ai']);
      assert.equal(body.mode, 'full'); assert.equal(body.use_ai, false); assert(key);
    }
    assert.equal(new Set(commands.map((item) => item.key)).size, commands.length);
    if (scenario === 'boundary-refusal') assert.match(results[0].detail, /changed after preview/);
    if (scenario === 'preview-refusal') assert.match(results[1].detail, /outside configured boundaries/);
  }
});

test('workspace batch keeps long-path review scrollable and confirmation bounded at 32 roots', async () => {
  const roots = Array.from({ length: 32 }, (_, i) => {
    const source = `/workspace/${'long-parent-'.repeat(20)}/repo-${i}`;
    return { name: `repo-${i}`, uri: { scheme: 'file', authority: '', path: source, fsPath: source,
      toString: () => `file://${source}` } };
  });
  for (const invalid of [false, true]) {
    let reviewed = false;
    await withExtensionFixture({
      workspaceFolders: roots, warningSelection: undefined,
      quickPick: (items, options) => {
        if (options.title === 'Scan Workspace Folders') return items.find(item => item.all);
        assert.equal(options.title, 'Review folders to scan');
        assert.equal(options.canPickMany, true); assert.equal(options.matchOnDescription, true);
        assert.deepEqual(items.map(item => item.description), roots.map(root => root.uri.fsPath));
        assert(items.every(item => item.picked)); reviewed = true;
        return invalid ? [items[0], items[0]] : items;
      },
      route: async (url, init) => {
        assert.equal(url.pathname, '/v1/sources/preview', 'review must not register projects or submit scans');
        return json({ installation_id: '0123456789ab', ...JSON.parse(init.body), authorization_mode: 'mounted',
          authorized: true, configured_roots: ['/workspace'], reason_code: null });
      },
    }, async ({ registrations, warningCalls, errors }) => {
      await registrations.get('lomoCodeSecurity.scanWorkspaceFolders')();
      assert.equal(reviewed, true);
      if (invalid) { assert.equal(warningCalls.length, 0); assert.equal(errors.length, 1); }
      else {
        assert.deepEqual(errors, []); assert.equal(warningCalls.length, 1);
        const detail = warningCalls[0].actions[0].detail;
        assert(detail.length < 450); assert(!detail.includes(roots[0].uri.fsPath));
        assert.match(detail, /32 reviewed folders selected; 0 not started/);
        assert.match(detail, /Normal scans do not run Advisor/);
        assert.match(detail, /Cancel stops this batch/);
      }
    });
  }
});

test('workspace batch preserves accepted identities and stops after unconfirmed observation or submission', async () => {
  const roots = ['a', 'b'].map((name) => ({ name, uri: {
    scheme: 'file', authority: '', path: `/workspace/${name}`, fsPath: `/workspace/${name}`,
    toString: () => `file:///workspace/${name}`,
  } }));
  for (const accepted of [true, false]) {
    const submissions = [];
    let results;
    await withExtensionFixture({
      workspaceFolders: roots, warningSelection: 'Scan 2 folders',
      quickPick: (items, options) => {
        if (options.title === 'Scan Workspace Folders') return items.find((item) => item.all);
        if (options.title === 'Review folders to scan') return items;
        results = items.map((item) => item.outcome); return undefined;
      },
      route: async (url, init) => {
        if (url.pathname === '/v1/sources/preview') return json({ installation_id: '0123456789ab', ...JSON.parse(init.body), authorization_mode: 'mounted',
          authorized: true, configured_roots: ['/workspace'], reason_code: null });
        if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'a', repo_path: '/workspace/a' });
        if (url.pathname === '/v1/projects/7/scans/latest') return json({ detail: 'no scan' }, 404);
        if (url.pathname === '/v1/scans' && init.method === 'POST') {
          submissions.push(JSON.parse(init.body));
          // A successful HTTP response lacking the accepted identity cannot
          // prove rejection or safely admit the next root.
          return json(accepted ? { id: 41, project_id: 7, status: 'pending', job_id: 71 } : {}, 202);
        }
        if (url.pathname === '/v1/jobs/71') return json({ detail: 'resource no longer available' }, 404);
        throw new Error(`Unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ registrations, errors }) => {
      await registrations.get('lomoCodeSecurity.scanWorkspaceFolders')();
      assert.deepEqual(errors, []);
      assert.deepEqual(results.map((item) => item.status), ['unconfirmed', 'not_started']);
      assert.equal(results[0].scanId, accepted ? 41 : undefined);
      assert.equal(results[0].jobId, accepted ? 71 : undefined);
      assert.match(results[0].detail, /could not be confirmed/);
      assert.equal(submissions.length, 1, 'uncertain admission/observation stops later roots');
      assert.equal(submissions[0].project_id, 7);
    });
  }
});

test('workspace batch does not cancel an observer owned by another scan command', async () => {
  const roots = ['a', 'b'].map((name) => ({ name, uri: {
    scheme: 'file', authority: '', path: `/workspace/${name}`, fsPath: `/workspace/${name}`,
    toString: () => `file:///workspace/${name}`,
  } }));
  let jobObserved;
  const observing = new Promise((resolve) => { jobObserved = resolve; });
  let finishOther;
  const otherFinished = new Promise((resolve) => { finishOther = resolve; });
  const admissions = [];
  let results;
  await withExtensionFixture({
    workspaceFolders: roots,
    warningSelection: 'Scan 2 folders',
    quickPick: (items, options) => {
      if (options.title === 'Choose a workspace to scan') return items[0];
      if (options.title === 'Scan Workspace Folders') return items.find((item) => item.all);
      if (options.title === 'Review folders to scan') return items;
      if (options.title === 'CodeSecurity · workspace folder results') { results = items.map((item) => item.outcome); return undefined; }
      throw new Error(`Unexpected selection ${options.title}`);
    },
    route: async (url, init) => {
      if (url.pathname === '/v1/sources/preview') return json({ installation_id: '0123456789ab', ...JSON.parse(init.body), authorization_mode: 'mounted',
        authorized: true, configured_roots: ['/workspace'], reason_code: null });
      if (url.pathname === '/v1/projects/resolve') {
        const { repo_path } = JSON.parse(init.body);
        return json({ id: repo_path.endsWith('/a') ? 7 : 8, name: repo_path.at(-1), repo_path });
      }
      if (/^\/v1\/projects\/[78]\/scans\/latest$/.test(url.pathname)) return json({ detail: 'no scan' }, 404);
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        const { project_id } = JSON.parse(init.body);
        admissions.push(project_id);
        const id = project_id === 7 ? 41 : 42;
        return json({ id, project_id, status: 'pending', job_id: id + 30 }, 202);
      }
      const job = /^\/v1\/jobs\/(7[12])$/.exec(url.pathname);
      if (job) {
        if (job[1] === '71') { jobObserved(); await otherFinished; }
        return json({ id: Number(job[1]), kind: 'scan', title: 'Scan', status: 'completed', stage: 'completed',
          progress: 100, scan_id: Number(job[1]) - 30, attempt: 1, max_attempts: 3, revision: 2, can_cancel: false, can_retry: false });
      }
      const scan = /^\/v1\/scans\/(4[12])$/.exec(url.pathname);
      if (scan) return json({ id: Number(scan[1]), project_id: scan[1] === '41' ? 7 : 8, status: 'completed', findings_revision: 1 });
      if (/^\/v1\/scans\/4[12]\/findings$/.test(url.pathname)) return json(findingPage([]));
      throw new Error(`Unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors }) => {
    const other = registrations.get('lomoCodeSecurity.scanWorkspace')();
    await observing;
    try {
      await registrations.get('lomoCodeSecurity.scanWorkspaceFolders')();
      assert.deepEqual(results.map((item) => item.status), ['not_started', 'completed']);
      assert.match(results[0].detail, /does not own or cancel/);
      assert.deepEqual(admissions, [7, 8], 'busy root must not create a second job');
    } finally { finishOther(); await other; }
    assert.deepEqual(errors, []);
  });
});

test('refresh all workspace folders preserves selected source and sibling findings when one root fails', async () => {
  const roots = ['a', 'b', 'c'].map((name) => ({ name, uri: {
    scheme: 'file', authority: '', path: `/workspace/${name}`, fsPath: `/workspace/${name}`,
    toString: () => `file:///workspace/${name}`,
  } }));
  let failC = false;
  let results;
  const resolved = [];
  await withExtensionFixture({
    workspaceFolders: roots, streamReady: false,
    quickPick: (items, options) => {
      assert.equal(options.title, 'CodeSecurity · refreshed workspace folders');
      results = items; return undefined;
    },
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        const { repo_path } = JSON.parse(init.body);
        resolved.push(repo_path);
        if (repo_path.endsWith('/b')) return json({ detail: 'unregistered' }, 404);
        if (failC && repo_path.endsWith('/c')) return json({ detail: { message: 'Current root unavailable.' } }, 503);
        return json({ id: repo_path.endsWith('/a') ? 7 : 9, name: repo_path.at(-1), repo_path });
      }
      const latest = /^\/v1\/projects\/([79])\/scans\/latest$/.exec(url.pathname);
      if (latest) return json({ id: Number(latest[1]) + 34, project_id: Number(latest[1]), status: 'completed', findings_revision: 1 });
      const findings = /^\/v1\/scans\/(4[13])\/findings$/.exec(url.pathname);
      if (findings) return json(findingPage([finding(1, { scan_id: Number(findings[1]), file_path: 'app.py' })]));
      if (url.pathname === '/v1/scans/41/findings/1') return json(findingDetail(1, { file_path: 'app.py' }));
      throw new Error(`Unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, treeProvider, shownDocuments, openDocument }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    assert.deepEqual([...entries.keys()].sort(), ['file:///workspace/a/app.py', 'file:///workspace/c/app.py']);
    const tree = treeProvider();
    const [workspace] = tree.getChildren();
    const [file] = tree.getChildren(workspace).filter(node => node.kind !== 'scan_scope');
    const [severity] = await tree.getChildren(file);
    const [lifecycle] = tree.getChildren(severity);
    const [node] = tree.getChildren(lifecycle);
    openDocument({ uri: { path: '/workspace/a/app.py', toString: () => 'file:///workspace/a/app.py' },
      version: 1, lineCount: 1, lineAt: () => ({ text: 'print("synthetic")' }), isDirty: false });
    await registrations.get('lomoCodeSecurity.revealFinding')(tree.getTreeItem(node).command.arguments[0]);
    assert.equal(shownDocuments.length, 1);
    const selection = shownDocuments[0].selection;
    const originalEntries = [...entries.entries()];
    failC = true;
    resolved.length = 0;
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    assert.deepEqual(resolved, roots.map((root) => root.uri.path));
    assert.deepEqual(results.map((item) => item.description), ['unchanged', 'unregistered', 'refresh failed']);
    assert.deepEqual([...entries.entries()], originalEntries);
    assert.equal(shownDocuments.length, 1, 'refresh must not move the selected editor');
    assert.equal(shownDocuments[0].selection, selection);
    assert.deepEqual(errors, []);
  });
});

test('terminal scan observer releases before toast dismissal and keeps its action live', async () => {
  let scanSubmissions = 0;
  let showFirstTerminalToast;
  const firstTerminalToastShown = new Promise((resolve) => { showFirstTerminalToast = resolve; });
  let chooseFirstTerminalAction;
  const firstTerminalAction = new Promise((resolve) => { chooseFirstTerminalAction = resolve; });

  await withExtensionFixture({
    informationSelection: (message) => {
      if (/scan #41 completed/.test(message)) {
        showFirstTerminalToast();
        return firstTerminalAction;
      }
      return undefined;
    },
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ detail: 'no scan yet' }, 404);
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        scanSubmissions += 1;
        const scanId = 40 + scanSubmissions;
        return json({
          id: scanId,
          project_id: 7,
          status: 'pending',
          job_id: 70 + scanSubmissions,
          job_revision: 1,
        }, 202);
      }
      const jobMatch = /^\/v1\/jobs\/(7[12])$/.exec(url.pathname);
      if (jobMatch) {
        const jobId = Number(jobMatch[1]);
        const scanId = jobId - 30;
        return json({
          id: jobId, kind: 'scan', title: `Scan #${scanId}`, status: 'completed', stage: 'completed',
          detail: 'Persisted.', progress: 100, scan_id: scanId, attempt: 1, max_attempts: 3,
          revision: 2, can_cancel: false, can_retry: false,
        });
      }
      const scanMatch = /^\/v1\/scans\/(4[12])$/.exec(url.pathname);
      if (scanMatch) {
        return json({
          id: Number(scanMatch[1]), project_id: 7, status: 'completed',
          gate_decision: 'pass', revision: 1, findings_revision: 1,
          scanner_summary: { source_coverage: { complete: true } },
        });
      }
      if (/^\/v1\/scans\/4[12]\/findings$/.test(url.pathname)) {
        return json(findingPage([], 1));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, opened, errors, setupContexts }) => {
    const firstCommand = registrations.get('lomoCodeSecurity.scanWorkspace')();
    await firstTerminalToastShown;

    await registrations.get('lomoCodeSecurity.scanWorkspace')();
    chooseFirstTerminalAction('Open scan');
    await firstCommand;
    for (let turn = 0; turn < 10 && opened.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(scanSubmissions, 2);
    assert.equal(setupContexts.get('lomoCodeSecurity.setup.scan'), true, 'same-revision terminal coverage read completes current scan status');
    assert.equal(information.some((message) => /already observing a scan/.test(message)), false);
    assert(opened.some((url) => /[?&]view=findings(?:&|#|$)/.test(url) && /[?&]scan=41(?:&|#|$)/.test(url)));
    assert.equal(errors.length, 0);
  });
});

test('Explorer folder command scans exact workspace-root and nested source targets', async () => {
  const selections = [
    {
      name: 'current',
      uri: {
        scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
        toString: () => 'file:///workspace/current',
      },
    },
    {
      name: 'api',
      uri: {
        scheme: 'file', authority: '', path: '/workspace/current/services/api', fsPath: '/workspace/current/services/api',
        toString: () => 'file:///workspace/current/services/api',
      },
    },
  ];
  for (const selected of selections) {
    const projectBodies = [];
    const scanBodies = [];
    let scanSubmitted = false;
    const nested = selected.name === 'api';
    await withExtensionFixture({
      route: async (url, init) => {
        if (url.pathname === '/v1/projects/resolve') {
          projectBodies.push(JSON.parse(init.body));
          return json({ id: 9, name: 'current', repo_path: '/workspace/current', revision: 1 });
        }
        if (url.pathname === '/v1/projects/9/scans/latest') {
          return scanSubmitted
            ? json({
              id: 51, project_id: 9, status: 'completed', revision: 2,
              gate_decision: 'pass', findings_revision: 1,
            })
            : json({ detail: 'no scan yet' }, 404);
        }
        if (url.pathname === '/v1/scans' && init.method === 'POST') {
          scanSubmitted = true;
          scanBodies.push(JSON.parse(init.body));
          return json({ id: 51, project_id: 9, status: 'pending', job_id: 81, job_revision: 1 }, 202);
        }
        if (url.pathname === '/v1/jobs/81') {
          return json({
            id: 81, kind: 'scan', title: 'Scan #51', status: 'completed', stage: 'completed', progress: 100,
            scan_id: 51, attempt: 1, max_attempts: 3, revision: 2, can_cancel: false, can_retry: false,
          });
        }
        if (url.pathname === '/v1/scans/51') {
          return json({
            id: 51, project_id: 9, status: 'completed', revision: 2,
            gate_decision: 'pass', findings_revision: 1,
          });
        }
        if (url.pathname === '/v1/scans/51/findings') {
          return json(findingPage(nested ? [finding(601, {
            scan_finding_number: 1,
            display_id: 'S51-F001',
            file_path: 'services/api/main.tf',
            start_line: 1,
            end_line: 1,
          })] : [], 1));
        }
        throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ registrations, errors, reports, information, entries }) => {
      const peer = {
        ...selected.uri,
        path: `${selected.uri.path}-peer`,
        fsPath: `${selected.uri.fsPath}-peer`,
        toString: () => `${selected.uri.toString()}-peer`,
      };
      await registrations.get('lomoCodeSecurity.scanFolder')(selected.uri, [selected.uri, peer]);
      if (nested) await registrations.get('lomoCodeSecurity.refreshFindings')();
      assert.equal(errors.length, 0);
      assert(projectBodies.length >= 2);
      assert(projectBodies.every(({ repo_path: repoPath }) => repoPath === '/workspace/current'));
      assert.deepEqual(scanBodies, [{
        project_id: 9,
        mode: 'full',
        use_ai: false,
        ...(nested ? { target_path: 'services/api', target_kind: 'directory' } : {}),
      }]);
      assert(reports.some(({ options }) => options?.title === `CodeSecurity: ${selected.name}`));
      if (nested) {
        assert(information.some((message) => (
          message.includes('scan #51 for services/api completed; loaded 1 persisted finding')
        )));
        assert.equal(
          information.some((message) => message.includes('is not registered with CodeSecurity')),
          false,
        );
        assert.deepEqual([...entries.keys()], ['file:///workspace/current/services/api/main.tf']);
      }
    });
  }
});

test('single-folder Explorer title action scans the sole open root without a resource row', async () => {
  const root = {
    name: 'current',
    uri: {
      scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
      toString: () => 'file:///workspace/current',
    },
  };
  const projectBodies = [];
  const scanBodies = [];
  await withExtensionFixture({
    resourceStatType: 2,
    workspaceFolders: [root],
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        projectBodies.push(JSON.parse(init.body));
        return json({ id: 9, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/9/scans/latest') {
        return json({ detail: 'no scan yet' }, 404);
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        scanBodies.push(JSON.parse(init.body));
        return json({ id: 51, project_id: 9, status: 'pending', job_id: 81, job_revision: 1 }, 202);
      }
      if (url.pathname === '/v1/jobs/81') {
        return json({
          id: 81, kind: 'scan', title: 'Scan #51', status: 'completed', stage: 'completed', progress: 100,
          scan_id: 51, attempt: 1, max_attempts: 3, revision: 2, can_cancel: false, can_retry: false,
        });
      }
      if (url.pathname === '/v1/scans/51') {
        return json({ id: 51, project_id: 9, status: 'completed', gate_decision: 'pass', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/51/findings') return json(findingPage([], 1));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, reports }) => {
    const viewOwnedArgument = { id: 'workbench.explorer.fileView' };
    await registrations.get('lomoCodeSecurity.scanRootFolder')(viewOwnedArgument);
    assert.equal(errors.length, 0, JSON.stringify(errors));
    assert.deepEqual(projectBodies, [
      { repo_path: '/workspace/current' },
      { repo_path: '/workspace/current' },
    ]);
    assert.deepEqual(scanBodies, [{ project_id: 9, mode: 'full', use_ai: false }]);
    assert(reports.some(({ options }) => options?.title === 'CodeSecurity: current'));
  });
});

test('Explorer file command scans only its exact path under the deepest owning workspace root', async () => {
  const parent = {
    name: 'current',
    uri: {
      scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
      toString: () => 'file:///workspace/current',
    },
  };
  const child = {
    name: 'api',
    uri: {
      scheme: 'file', authority: '', path: '/workspace/current/services/api', fsPath: '/workspace/current/services/api',
      toString: () => 'file:///workspace/current/services/api',
    },
  };
  const selected = {
    scheme: 'file', authority: '', path: '/workspace/current/services/api/src/index.ts',
    fsPath: '/workspace/current/services/api/src/index.ts',
    toString: () => 'file:///workspace/current/services/api/src/index.ts',
  };
  const peer = {
    ...selected,
    path: '/workspace/current/services/api/src/peer.ts',
    fsPath: '/workspace/current/services/api/src/peer.ts',
    toString: () => 'file:///workspace/current/services/api/src/peer.ts',
  };
  const projectBodies = [];
  const scanBodies = [];
  await withExtensionFixture({
    workspaceFolders: [parent, child],
    resourceStatType: 1,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        projectBodies.push(JSON.parse(init.body));
        return json({ id: 9, name: 'api', repo_path: '/workspace/current/services/api', revision: 1 });
      }
      if (url.pathname === '/v1/projects/9/scans/latest') {
        return json({ detail: 'no scan yet' }, 404);
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        scanBodies.push(JSON.parse(init.body));
        return json({ id: 51, project_id: 9, status: 'pending', job_id: 81, job_revision: 1 }, 202);
      }
      if (url.pathname === '/v1/jobs/81') {
        return json({
          id: 81, kind: 'scan', title: 'Scan #51', status: 'completed', stage: 'completed', progress: 100,
          scan_id: 51, attempt: 1, max_attempts: 3, revision: 2, can_cancel: false, can_retry: false,
        });
      }
      if (url.pathname === '/v1/scans/51') {
        return json({ id: 51, project_id: 9, status: 'completed', gate_decision: 'pass', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/51/findings') return json(findingPage([], 1));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, reports, information }) => {
    await registrations.get('lomoCodeSecurity.scanFile')(selected, [peer]);
    assert.equal(errors.length, 0);
    assert.deepEqual(projectBodies, [
      { repo_path: '/workspace/current/services/api' },
      { repo_path: '/workspace/current/services/api' },
    ]);
    assert.deepEqual(scanBodies, [{
      project_id: 9,
      mode: 'full',
      use_ai: false,
      target_path: 'src/index.ts',
      target_kind: 'file',
    }]);
    assert(reports.some(({ options }) => options?.title === 'CodeSecurity: index.ts'));
    assert(information.some((message) => (
      message.includes('scan #51 for src/index.ts completed')
    )));
  });
});

test('Explorer file command rejects folders and ambiguous selection before network access', async () => {
  const selected = {
    scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
    toString: () => 'file:///workspace/current',
  };
  let routeCalls = 0;
  await withExtensionFixture({
    route: async () => {
      routeCalls += 1;
      throw new Error('file validation must happen before network access');
    },
  }, async ({ registrations, errors }) => {
    await registrations.get('lomoCodeSecurity.scanFile')(selected, [selected]);
    await registrations.get('lomoCodeSecurity.scanFile')(undefined, [
      selected,
      { ...selected, path: '/workspace/current/two.ts', toString: () => 'file:///workspace/current/two.ts' },
    ]);
    assert.equal(routeCalls, 0);
    assert.deepEqual(errors.map(({ message }) => message), [
      'The selected source does not expose a canonical path below its open workspace.',
      'Select exactly one supported file to scan with CodeSecurity.',
    ]);
  });
});

test('Explorer file command rejects README and other unsupported files before network access', async () => {
  let routeCalls = 0;
  await withExtensionFixture({
    resourceStatType: 1,
    route: async () => {
      routeCalls += 1;
      throw new Error('unsupported file validation must happen before network access');
    },
  }, async ({ registrations, errors }) => {
    for (const name of ['README.md', 'image.png']) {
      const selected = {
        scheme: 'file', authority: '', path: `/workspace/current/${name}`, fsPath: `/workspace/current/${name}`,
        toString: () => `file:///workspace/current/${name}`,
      };
      await registrations.get('lomoCodeSecurity.scanFile')(selected, [selected]);
    }
    assert.equal(routeCalls, 0);
    assert.equal(errors.length, 2);
    assert(errors.every(({ message }) => /file type is not supported/.test(message)));
  });
});

test('outside-root Explorer scan opens the exact Projects source suggestion for new and retained browsers', async (t) => {
  const selected = {
    scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
    toString: () => 'file:///workspace/current',
  };
  const suggestedPath = '/selected/my service/Žluťoučký';
  const encodedPath = Buffer.from(suggestedPath, 'utf8').toString('base64url');
  const invitationId = VALID_BROWSER_INVITATION.split('.')[1];
  const membershipPath = `/v1/auth/ide/browser-invitations/${invitationId}/membership`;
  for (const retained of [false, true]) {
    await t.test(retained ? 'retained browser member' : 'first integrated-browser invitation', async () => {
      const calls = [];
      const state = new Map(retained
        ? [['lomoCodeSecurity.integratedDashboardMemberships.v1', integratedDashboardMembershipState()]] : []);
      await withExtensionFixture({
        errorSelection: 'Open Source Setup',
        streamReady: false,
        globalStateStorage: state,
        strictBrowserInvitationRoute: true,
        strictBrowserMembershipRoute: true,
        route: async (url, init) => {
          calls.push({ path: url.pathname, method: init.method || 'GET' });
          if (url.pathname === '/v1/auth/ide/browser-invitations') return json(browserInvitationEnvelope());
          if (url.pathname === membershipPath) return json(activeBrowserMembershipEnvelope(invitationId));
          if (url.pathname === '/v1/projects/resolve') {
            return json({ detail: {
              code: 'source_outside_allowed_root',
              message: 'The selected directory is outside the authorized source root.',
              action: 'authorize_source',
              context: {
                source_target: { display_path: suggestedPath, ignored_secret: 'do-not-render' },
                authorization_boundary: { display_paths: ['/workspace/one', '/workspace/two'] },
              },
            } }, 422);
          }
          throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
        },
      }, async ({ registrations, errors, information, opened, clipboardWrites, externalOpened }) => {
        await registrations.get('lomoCodeSecurity.scanFolder')(selected, [selected]);
        assert.equal(errors.length, 1);
        assert.match(errors[0].message, /outside the source boundary configured for the local stack/);
        assert(errors[0].message.includes(`Selected target: ${suggestedPath}.`));
        assert.match(errors[0].message, /Authorized roots: \/workspace\/one, \/workspace\/two\./);
        assert.doesNotMatch(errors[0].message, /do-not-render/);
        assert.deepEqual(errors[0].actions, ['Open Source Setup']);
        const destination = `source=${encodedPath}`;
        const fragment = retained ? destination : new URLSearchParams({
          bootstrap: VALID_BROWSER_INVITATION, destination,
        }).toString();
        assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/?view=projects&setup=source#${fragment}`)]);
        const openedUrl = new URL(opened[0]);
        assert.equal(openedUrl.searchParams.has('source'), false, 'the source suggestion never enters a request query');
        const openedFragment = new URLSearchParams(openedUrl.hash.slice(1));
        const sourceFragment = retained ? openedFragment : new URLSearchParams(openedFragment.get('destination'));
        assert.equal(Buffer.from(sourceFragment.get('source'), 'base64url').toString('utf8'), suggestedPath);
        assert.equal(calls.filter(({ path }) => path === '/v1/auth/ide/browser-invitations').length, retained ? 0 : 1);
        assert.deepEqual(state.get('lomoCodeSecurity.integratedDashboardMemberships.v1'), integratedDashboardMembershipState());
        assert.equal(calls.filter(({ path }) => ['/v1/projects', '/v1/scans'].includes(path)).length, 0);
        assert.deepEqual(clipboardWrites, [], 'Source Setup navigation never overwrites the user clipboard');
        assert.deepEqual(externalOpened, [], 'the existing integrated-browser member owns source setup');
        assert.deepEqual(information, [], 'integrated Source Setup is not covered by its own success toast');
      });
    });
  }
});


test('source setup omits unsupported or oversized path suggestions without changing source authority', async (t) => {
  for (const [label, suggestedPath] of [
    ['missing', undefined],
    ['relative', 'selected/service'],
    ['Windows drive', 'C:\\selected\\service'],
    ['UNC', '//server/share'],
    ['control character', '/selected/unsafe\u0000path'],
    ['UTF-8 byte limit', `/${'é'.repeat(256)}`],
  ]) {
    await t.test(label, async () => {
      const selected = {
        scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
        toString: () => 'file:///workspace/current',
      };
      const calls = [];
      await withExtensionFixture({
        errorSelection: 'Open Source Setup', streamReady: false,
        globalStateStorage: new Map([['lomoCodeSecurity.integratedDashboardMemberships.v1', integratedDashboardMembershipState()]]),
        route: async (url, init) => {
          calls.push({ path: url.pathname, method: init.method || 'GET' });
          assert.equal(url.pathname, '/v1/projects/resolve');
          return json({ detail: {
            code: 'source_outside_allowed_root', message: 'Source outside the authorized boundary.', action: 'authorize_source',
            context: { source_target: { display_path: suggestedPath } },
          } }, 422);
        },
      }, async ({ registrations, opened, errors, clipboardWrites }) => {
        await registrations.get('lomoCodeSecurity.scanFolder')(selected, [selected]);
        assert.equal(errors.length, 1);
        assert.deepEqual(opened, [retainedBrowserUrl('http://127.0.0.1:8080/?view=projects&setup=source')]);
        assert.equal(calls.filter(({ path }) => ['/v1/projects', '/v1/scans'].includes(path)).length, 0);
        assert.deepEqual(clipboardWrites, []);
      });
    });
  }
});


test('scanner readiness failure settles progress and opens the exact guided Tools recovery', async () => {
  const selected = {
    scheme: 'file', authority: '', path: '/workspace/current', fsPath: '/workspace/current',
    toString: () => 'file:///workspace/current',
  };
  const scenarios = [
    {
      code: 'scanner_evidence_incomplete',
      message: 'Normal scan requires Trivy DB and the reviewed OpenGrep rules.',
      action: 'prepare_scanners',
      guidance: /Finish scanner preparation/,
      button: 'Prepare scanners',
    },
    {
      code: 'scanner_runtime_prerequisite_missing',
      message: 'The shipped Grype binary is missing from the scanner runtime.',
      action: 'repair_scanner_runtime',
      guidance: /restore the reported binary or offline-execution prerequisite/,
      button: 'Review scanner runtime',
    },
    {
      code: 'scanner_cache_verification_required',
      message: 'Scanner cache verification is in progress.',
      action: 'wait_for_scanner_verification',
      reason: 'verifying',
      guidance: /Wait for the existing scanner cache to finish verification/,
      button: 'View scanner verification',
    },
    {
      code: 'scanner_cache_verification_required',
      message: 'Scanner cache verification timed out.',
      action: 'retry_scanner_verification',
      reason: 'timed_out',
      guidance: /retry verification of the existing cache.*does not download scanner data/,
      button: 'View scanner verification',
    },
    {
      code: 'scanner_cache_verification_required',
      message: 'Scanner cache verification could not complete.',
      action: 'retry_scanner_verification',
      reason: 'failed',
      guidance: /retry verification of the existing cache.*does not download scanner data/,
      button: 'View scanner verification',
    },
  ];

  for (const scenario of scenarios) {
    const lifecycle = [];
    const mutations = [];
    let releaseSelection;
    const selection = new Promise((resolve) => { releaseSelection = resolve; });
    let errorPresented;
    const presented = new Promise((resolve) => { errorPresented = resolve; });
    await withExtensionFixture({
      errorSelection: selection,
      progressLifecycle: (event) => {
        lifecycle.push(event);
        if (event === 'error-presented') errorPresented();
      },
      streamReady: true,
      route: async (url, init) => {
        if (init.method === 'POST') mutations.push({ path: url.pathname, body: JSON.parse(init.body) });
        if (url.pathname === '/v1/projects/resolve') {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
        }
        if (url.pathname === '/v1/projects/7/scans/latest') {
          return json({ detail: 'no scan yet' }, 404);
        }
        if (url.pathname === '/v1/scans' && init.method === 'POST') {
          return json({ detail: {
            code: scenario.code,
            message: scenario.message,
            action: scenario.action,
            context: { target: 'active', generation_id: 'a'.repeat(64) },
            safe_details: { reason_code: scenario.reason },
          } }, 409);
        }
        throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ registrations, errors, opened, reports }) => {
      const command = registrations.get('lomoCodeSecurity.scanFolder')(selected, [selected]);
      await presented;
      assert.deepEqual(lifecycle, ['started', 'resolved', 'settled', 'error-presented']);
      const progressOptions = reports.filter(({ options }) => options).map(({ options }) => options);
      assert.deepEqual(progressOptions, [{
        location: 15,
        title: 'CodeSecurity: current',
        cancellable: true,
      }]);
      assert.equal(errors.length, 1);
      assert.match(errors[0].message, new RegExp(scenario.message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.match(errors[0].message, scenario.guidance);
      assert.deepEqual(errors[0].actions, [scenario.button]);
      assert.deepEqual(opened, [], 'the still-visible prompt must not navigate before explicit selection');
      releaseSelection(scenario.button);
      await command;
      assert.equal(opened.length, 1);
      assert.equal(new URL(opened[0]).searchParams.get('view'), 'tools');
      const admissions = mutations.filter(({ path }) => path !== '/v1/projects/resolve');
      assert.deepEqual(admissions.map(({ path }) => path), ['/v1/scans'],
        'Tools guidance must not grant the IDE a scanner preparation or verification-retry mutation');
      assert.equal(admissions[0].body.coverage_mode, undefined,
        'normal IDE Scan must retain the API complete-coverage default, never silently switch to limited coverage');
      assert.doesNotMatch(errors[0].message, /Persisted state changed; refresh Jobs/);
    });
  }
});


test('scan terminal refresh accepts its completed scan from a repeatedly superseding SSE workspace proof', async () => {
  const stream = controllableEventStream();
  const value = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/exact-after-event.ts',
    message: 'Exact evidence after event reconciliation',
  });
  let scanSubmitted = false;
  let manifestReads = 0;
  let signalExactStarted;
  const exactStarted = new Promise((resolve) => { signalExactStarted = resolve; });

  await withExtensionFixture({
    strictHybridRoutes: true,
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return scanSubmitted
          ? json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 })
          : json({ detail: 'no scan yet' }, 404);
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        scanSubmitted = true;
        return json({ id: 41, project_id: 7, status: 'pending', job_id: 71, job_revision: 1 }, 202);
      }
      if (url.pathname === '/v1/jobs/71') {
        return json({
          id: 71, kind: 'scan', title: 'Scan #41', status: 'completed', stage: 'completed',
          detail: 'Persisted.', progress: 100, scan_id: 41, attempt: 1, max_attempts: 3,
          revision: 4, can_cancel: false, can_retry: false,
        });
      }
      if (url.pathname === '/v1/scans/41') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        manifestReads += 1;
        if (manifestReads === 1) {
          signalExactStarted();
          return new Promise((_resolve, reject) => init.signal.addEventListener(
            'abort',
            () => reject(new DOMException('authoritative proof superseded by a newer event', 'AbortError')),
            { once: true },
          ));
        }
        return json(hybridManifest([value]));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([value]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, errors, entries, eventStreamSignals, globalStateUpdates }) => {
    const pending = registrations.get('lomoCodeSecurity.scanWorkspace')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    await exactStarted;
    stream.send(
      domainEvent(1, 'project.changed', 1)
      + domainEvent(2, 'scan.changed', 1)
      + domainEvent(3, 'findings.changed', 1),
    );
    await pending;
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 3; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(errors.length, 0);
    assert(information.some((message) => /scan #41 completed; loaded 1 persisted finding/.test(message)));
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/exact-after-event.ts']);
    assert.equal(globalStateUpdates().at(-1)?.value.event_id, 3);
    assert.equal(manifestReads, 2, 'the exact attempt and joined SSE workspace chain reconcile once each');
  });
});


test('scan terminal refresh distinguishes proof supersession from other retryable conflicts', async (testContext) => {
  const stream = controllableEventStream();
  const value = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/exact-after-event.ts',
    message: 'Exact evidence after event reconciliation',
  });
  const originalRun = WorkspaceRefreshCoordinator.prototype.run;
  const foregroundProofs = [];
  let scriptedFailures = [];
  let scriptForegroundSupersession = false;
  WorkspaceRefreshCoordinator.prototype.run = function scriptedRun(
    workspaceKey,
    intent,
    operation,
    signal,
  ) {
    if (scriptForegroundSupersession) {
      foregroundProofs.push({ key: intent.key, proof: intent.proof });
      const failure = scriptedFailures.shift();
      if (failure) return Promise.reject(failure);
    }
    return originalRun.call(this, workspaceKey, intent, operation, signal);
  };
  try {
    await withExtensionFixture({
      extensionMode: 3,
      strictHybridRoutes: true,
      eventStreamFactory: (signal) => stream.response(signal),
      route: async (url, init) => {
        if (url.pathname === '/v1/projects/resolve') {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
        }
        if (url.pathname === '/v1/projects/7/scans/latest') {
          return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
        }
        if (url.pathname === '/v1/scans' && init.method === 'POST') {
          return json({ id: 41, project_id: 7, status: 'pending', job_id: 71, job_revision: 1 }, 202);
        }
        if (url.pathname === '/v1/jobs/71') {
          return json({
            id: 71, kind: 'scan', title: 'Scan #41', status: 'completed', stage: 'completed',
            detail: 'Persisted.', progress: 100, scan_id: 41, attempt: 1, max_attempts: 3,
            revision: 4, can_cancel: false, can_retry: false,
          });
        }
        if (url.pathname === '/v1/scans/41') {
          return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
        }
        if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([value]));
        if (url.pathname === '/v1/scans/41/finding-diagnostics') {
          return json(hybridDiagnosticPage([value]));
        }
        if (url.pathname === '/v1/scans/41/findings') return json(findingPage([value]));
        throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
      },
    }, async ({ registrations, information, errors, entries, eventStreamSignals, globalStateUpdates, testApi }) => {
      await testApi.refresh();
      for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      stream.send(
        'event: stream.ready\n'
        + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
      );
      for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      stream.send(domainEvent(1, 'findings.changed', 1));
      for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }

      scriptForegroundSupersession = true;
      await testContext.test('replays after exact and workspace proofs are superseded', async () => {
        scriptedFailures = [
          new RefreshProofSupersededError(),
          new RefreshProofSupersededError(),
        ];
        await registrations.get('lomoCodeSecurity.scanWorkspace')();

        assert.deepEqual(foregroundProofs.map(({ proof }) => proof), [
          'exact:41',
          'workspace',
          'exact:41',
        ]);
        assert.match(foregroundProofs[0].key, /^exact:41:[1-9][0-9]*$/);
        assert.equal(foregroundProofs[1].key, 'manual');
        assert.match(foregroundProofs[2].key, /^exact:41:[1-9][0-9]*$/);
        assert.notEqual(foregroundProofs[0].key, foregroundProofs[2].key);
        assert.equal(errors.length, 0);
        assert(information.some((message) => /scan #41 completed; loaded 1 persisted finding/.test(message)));
        assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/exact-after-event.ts']);
        assert.equal(globalStateUpdates().at(-1)?.value.event_id, 1);
      });

      await testContext.test('surfaces a generic retryable workspace-join conflict', async () => {
        const priorSuccessMessages = information.filter(
          (message) => /scan #41 completed; loaded 1 persisted finding/.test(message),
        ).length;
        foregroundProofs.length = 0;
        scriptedFailures = [
          new RefreshProofSupersededError(),
          new CodeSecurityRequestError('Generic retryable workspace conflict.', 409, true),
        ];
        await registrations.get('lomoCodeSecurity.scanWorkspace')();

        assert.deepEqual(foregroundProofs.map(({ proof }) => proof), ['exact:41', 'workspace']);
        assert.equal(errors.length, 1);
        assert.match(errors[0].message, /Generic retryable workspace conflict/);
        assert.equal(information.filter(
          (message) => /scan #41 completed; loaded 1 persisted finding/.test(message),
        ).length, priorSuccessMessages);
      });
    });
  } finally {
    WorkspaceRefreshCoordinator.prototype.run = originalRun;
  }
});


test('1,000 edits clear one stale file projection and refresh native surfaces only once', async () => {
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([finding(1, { file_path: 'src/edited.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    changeDocument,
    collection,
    entries,
    errors,
    provideCodeActions,
    provideHover,
    setVisibleTextEditors,
    treeProvider,
    treeRefreshes,
    warnings,
  }) => {
    const uriKey = 'file:///workspace/current/src/edited.ts';
    const document = {
      uri: {
        path: '/workspace/current/src/edited.ts',
        toString: () => uriKey,
      },
      lineCount: 1,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: true,
    };
    const decorationCalls = [];
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 12 } }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    }]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    await hydrateTreePath(treeProvider(), 'src/edited.ts');
    assert.deepEqual([...entries.keys()], [uriKey]);
    assert(provideHover(document, { line: 0, character: 2 }));
    assert.equal(provideCodeActions(document, {
      start: { line: 0, character: 2 },
      end: { line: 0, character: 2 },
    }).length, 5);

    const batchesBeforeEdits = collection.batches;
    const deletesBeforeEdits = collection.deletes;
    const decorationsBeforeEdits = decorationCalls.length;
    const refreshesBeforeEdits = treeRefreshes();
    for (let change = 0; change < 1_000; change += 1) changeDocument(document);

    const workspace = treeProvider().getChildren()[0].workspace;
    assert.deepEqual([...workspace.staleFiles], ['src/edited.ts']);
    assert.equal(warnings.length, 1);
    assert.equal(collection.deletes - deletesBeforeEdits, 0);
    assert.equal(collection.batches - batchesBeforeEdits, 1, 'one atomic batch removes the stale URI');
    assert.deepEqual([...entries.keys()], []);
    assert.equal(treeRefreshes() - refreshesBeforeEdits, 1);
    assert.equal(provideHover(document, { line: 0, character: 2 }), undefined);
    assert.deepEqual(provideCodeActions(document, {
      start: { line: 0, character: 2 },
      end: { line: 0, character: 2 },
    }), []);
    const staleDecorationCalls = decorationCalls.slice(decorationsBeforeEdits);
    assert.equal(staleDecorationCalls.length, 1, 'one native refresh clears the inline decoration');
    assert(staleDecorationCalls.every(({ options }) => options.length === 0));
    assert.equal(errors.length, 0);
  });
});


test('same-line native annotations aggregate deterministically at line end and unchanged refreshes do not render', async () => {
  const findings = [
    finding(1, {
      file_path: 'src/grouped.ts', start_line: 2, end_line: 2, severity: 'medium', scanner: 'zeta',
    }),
    finding(2, {
      file_path: 'src/grouped.ts', start_line: 2, end_line: 2, severity: 'critical', scanner: 'zeta',
    }),
    finding(3, {
      file_path: 'src/grouped.ts', start_line: 2, end_line: 2, severity: 'critical', scanner: 'alpha',
      message: 'deterministic primary',
    }),
  ];
  await withExtensionFixture({
    streamReady: true,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(findings));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, setVisibleTextEditors, treeProvider,
    decorationTypes, provideHover, provideCodeActions }) => {
    const uriKey = 'file:///workspace/current/src/grouped.ts';
    const lines = ['const safe = true;', 'const value = dangerous();', 'export { value };'];
    const document = {
      uri: { path: '/workspace/current/src/grouped.ts', toString: () => uriKey },
      lineCount: lines.length,
      lineAt: (line) => ({ text: lines[line] }),
      isDirty: false,
    };
    const decorationCalls = [];
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 2, character: lines[2].length } }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    }]);

    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    await hydrateTreePath(treeProvider(), 'src/grouped.ts');
    assert.equal(entries.get(uriKey).length, 3, 'Problems retains every same-line finding');
    assert.equal(decorationTypes().length, 1, 'Lomo registers only its inline decoration');
    assert(decorationTypes().every(({ configuration }) => !Object.hasOwn(configuration, 'gutterIconPath')),
      'Lomo must not compete with GitLens for the shared gutter-icon slot');
    const inline = decorationCalls.at(-1).options;
    assert.equal(inline.length, 1);
    assert.deepEqual(
      [inline[0].range.start.line, inline[0].range.start.character, inline[0].range.end.line, inline[0].range.end.character],
      [1, lines[1].length, 1, lines[1].length],
      'GitLens-style trailing text is anchored at the document line end',
    );
    assert.equal(inline[0].renderOptions.after.contentText, '  [CRITICAL · alpha +2 reports]');
    assert.match(inline[0].hoverMessage.value, /S41-F003/);
    assert.match(inline[0].hoverMessage.value, /2 other reports on this line\. These may describe different issues; each report keeps its own severity and actions\./);
    assert.equal(inline[0].hoverMessage.isTrusted, false);
    assert.doesNotMatch(inline[0].hoverMessage.value, /command:/u);
    const sourceHover = provideHover(document, { line: 1, character: 2 });
    assert.match(sourceHover.contents.value, /command:lomoCodeSecurity\.openFinding/u);
    assert.match(sourceHover.contents.value, /command:lomoCodeSecurity\.runAdvisor/u);
    assertStableQuickFixCommands(provideCodeActions(document, {
      start: { line: 1, character: 2 }, end: { line: 1, character: 2 },
    }));

    const callsBeforeUnchangedRefresh = decorationCalls.length;
    await refresh();
    assert.equal(
      decorationCalls.length,
      callsBeforeUnchangedRefresh,
      'an authoritative refresh with unchanged visible output must not call setDecorations',
    );
    assert.equal(errors.length, 0);
  });
});


test('current hover Advisor command offers consent before authoritative network work', async () => {
  let scanId = 16;
  let advisorDetailReads = 0;
  let releaseScan17Hydration;
  const scan17Hydration = new Promise((resolve) => { releaseScan17Hydration = resolve; });
  let markScan17HydrationStarted;
  const scan17HydrationStarted = new Promise((resolve) => { markScan17HydrationStarted = resolve; });
  const currentFinding = () => finding(scanId === 16 ? 1_601 : 1_701, {
    scan_id: scanId,
    scan_finding_number: 1,
    display_id: `S${scanId}-F001`,
    file_path: 'app.py',
    start_line: 9,
    end_line: 9,
    severity: 'critical',
    scanner: 'trivy',
    revision: 1,
  });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      const value = currentFinding();
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: scanId,
          project_id: 7,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
        });
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-files`) {
        return json(hybridManifest([value], 1, { id: scanId }));
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-diagnostics`) {
        return json({ ...hybridDiagnosticPage([value], 1), scan_id: scanId });
      }
      if (url.pathname === `/v1/scans/${scanId}/findings` && url.searchParams.has('file_path')) {
        if (scanId === 17) {
          markScan17HydrationStarted();
          return scan17Hydration;
        }
        return json(findingPage([value], 1));
      }
      if (url.pathname === '/v1/scans/17/findings/1') {
        advisorDetailReads += 1;
        assert.equal(url.search, '?expected_revision=1&expected_findings_revision=1');
        return json(findingDetail(1_701, { ...value, findings_revision: 1 }));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    information,
    openDocument,
    provideHover,
    quickPickCalls,
    setVisibleTextEditors,
  }) => {
    const uriKey = 'file:///workspace/current/app.py';
    const lines = Array.from({ length: 10 }, (_, index) => `line ${index + 1}`);
    const document = {
      uri: { path: '/workspace/current/app.py', toString: () => uriKey },
      version: 1,
      lineCount: lines.length,
      lineAt: (line) => ({ text: lines[line] }),
      isDirty: false,
    };
    const decorationCalls = [];
    setVisibleTextEditors([{
      document,
      selection: { start: { line: 8, character: 0 }, end: { line: 8, character: 0 } },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 9, character: lines[9].length } }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    }]);
    openDocument(document);
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    for (let turn = 0; turn < 50; turn += 1) {
      const rendered = decorationCalls.filter(({ decoration }) => decoration.id === 1).at(-1)?.options;
      if (rendered?.[0]?.hoverMessage.value.includes('S16-F001')) break;
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.match(
      decorationCalls.filter(({ decoration }) => decoration.id === 1).at(-1).options[0].hoverMessage.value,
      /S16-F001/u,
    );

    scanId = 17;
    const scan17Refresh = refresh();
    await scan17HydrationStarted;
    await scan17Refresh;
    assert.equal(entries.get(uriKey)[0].code, 'S17-F001', 'Problems may publish the new compact finding first');
    const pendingInline = decorationCalls.at(-1).options;
    assert.deepEqual(pendingInline, [], 'the prior scan inline hover is removed during rich hydration');

    releaseScan17Hydration(json(findingPage([currentFinding()], 1)));
    for (let turn = 0; turn < 50; turn += 1) {
      const rendered = decorationCalls.filter(({ decoration }) => decoration.id === 1).at(-1)?.options;
      if (rendered?.[0]?.hoverMessage.value.includes('S17-F001')) break;
      await new Promise((resolve) => setImmediate(resolve));
    }
    const currentInlineHover = decorationCalls.at(-1).options[0].hoverMessage;
    assert.match(currentInlineHover.value, /S17-F001/u);
    assert.doesNotMatch(currentInlineHover.value, /S16-F001/u);
    assert.equal(currentInlineHover.isTrusted, false, 'decoration hover remains informational');
    assert.doesNotMatch(currentInlineHover.value, /command:/u, 'decoration hover exposes no command URI');

    const currentHover = provideHover(document, { line: 8, character: 0 });
    assert(currentHover, 'the registered source-range HoverProvider serves the current finding');
    assert.match(currentHover.contents.value, /S17-F001/u);
    assert.doesNotMatch(currentHover.contents.value, /S16-F001/u);
    assert.match(
      currentHover.contents.value,
      /\[Open Finding in Web\]\(command:lomoCodeSecurity\.openFinding\?/u,
      'the source hover names the dashboard destination truthfully',
    );
    assert.doesNotMatch(
      currentHover.contents.value,
      /\[Open exact finding\]/u,
      'the dashboard action must not imply that it keeps or reveals source focus',
    );
    assert.deepEqual(currentHover.contents.isTrusted, {
      enabledCommands: ['lomoCodeSecurity.openFinding', 'lomoCodeSecurity.runAdvisor'],
    });
    assert.equal(
      (currentHover.contents.value.match(/command:lomoCodeSecurity\.openFinding\?/gu) || []).length,
      1,
      'the provider exposes one current Open action',
    );
    assert.equal(
      (currentHover.contents.value.match(/command:lomoCodeSecurity\.runAdvisor\?/gu) || []).length,
      1,
      'the provider exposes one current Advisor action',
    );
    const advisorLink = /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/u.exec(currentHover.contents.value);
    assert(advisorLink, 'the current provider hover exposes the Advisor command link');
    const [advisorContext] = JSON.parse(decodeURIComponent(advisorLink[1]));
    assert.equal(advisorContext.scanId, 17);
    assert.equal(advisorContext.findingId, 1_701);
    const advisorCommandName = advisorLink[0].slice('command:'.length).split('?')[0];
    const advisorCommand = registrations.get(advisorCommandName);
    assert(advisorCommand, 'the hover URI names the actual registered Advisor command');
    await advisorCommand(...JSON.parse(decodeURIComponent(advisorLink[1])));
    assert.equal(quickPickCalls.length, 1);
    assert.deepEqual(
      quickPickCalls[0].items.map(({ label, action, description }) => ({ label, action, description })),
      [
        {
          label: 'Cancel',
          action: 'cancel',
          description: 'Safe default — no request is sent and no finding data is disclosed.',
        },
        {
          label: 'Run Advisor',
          action: 'run',
          description: 'Resolve the provider; remote review stays in the Web UI one-finding disclosure flow.',
        },
      ],
    );
    assert.equal(quickPickCalls[0].options.title, 'Run Advisor for S17-F001?');
    assert.match(quickPickCalls[0].options.placeHolder, /Scanner evidence remains authoritative/u);
    assert.equal(quickPickCalls[0].options.ignoreFocusOut, true);
    assert.match(information.at(-1), /Advisor for S17-F001 was cancelled/u);
    assert.equal(advisorDetailReads, 0, 'cancelling the rendered command URI performs no network work');
    assert.equal(errors.length, 0);
  });
});


test('a current manifest resets the Findings tree viewport when its view becomes visible', async () => {
  const values = [
    finding(17, { file_path: 'app.py' }),
    finding(18, { file_path: 'Dockerfile' }),
  ];
  await withExtensionFixture({
    treeViewVisible: false,
    treeViewportOffset: 500,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(values));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    errors,
    registrations,
    setTreeViewVisible,
    treeProvider,
    treeViewReveals,
    treeViewportOffset,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [root] = tree.getChildren();
    assert(root, 'the current workspace root is published');
    assert.deepEqual(
      tree.getChildren(root).filter(node => node.kind !== 'scan_scope').map(({ filePath }) => filePath),
      ['app.py', 'Dockerfile'],
      'the provider publishes the current file collection before the view is shown',
    );
    assert.equal(tree.getParent(root), undefined, 'the revealed workspace is a true Tree root');
    assert.deepEqual(treeViewReveals(), [], 'a background refresh does not steal focus by opening the view');
    assert.equal(treeViewportOffset(), 500, 'the hidden virtual viewport remains untouched');

    setTreeViewVisible(true);
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(treeViewportOffset(), 0, 'revealing the current root resets a stale virtual-list offset');
    assert.equal(treeViewReveals().length, 1);
    assert.equal(treeViewReveals()[0].node, root);
    assert.deepEqual(treeViewReveals()[0].options, { select: false, focus: false, expand: 1 });
    assert.deepEqual(errors, []);
  });
});


test('finding Tree primary action reveals the exact current manifest file and bounded range', async () => {
  const value = finding(17, {
    file_path: 'src/reveal.ts',
    start_line: 2,
    start_column: 7,
    end_line: 2,
    end_column: 13,
  });
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(),
  ]]);
  const activeTabs = [
    { label: `${RETAINED_BROWSER_TAB_TITLE} (127.0.0.1:8080)`, isActive: false },
    { label: 'app.py', isActive: true },
  ];
  await withExtensionFixture({
    modelOpenExternalUriCache: true,
    streamReady: false,
    globalStateStorage,
    activeTabGroupTabs: activeTabs,
    integratedBrowserResult: () => { simulateBrowserReplacement(activeTabs); },
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([value]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, errors, information, openDocument, opened, clipboardWrites, shownDocuments, treeProvider,
    executedCommands,
  }) => {
    const document = {
      uri: {
        path: '/workspace/current/src/reveal.ts',
        toString: () => 'file:///workspace/current/src/reveal.ts',
      },
      version: 1,
      lineCount: 2,
      lineAt: (line) => ({ text: ['const safe = true;', 'const danger = risky();'][line] }),
      isDirty: false,
    };
    openDocument(document);
    await registrations.get('lomoCodeSecurity.refreshFindings')();

    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/reveal.ts');
    const [lifecycle] = tree.getChildren(severity);
    const [findingNode] = tree.getChildren(lifecycle);
    const item = tree.getTreeItem(findingNode);
    assert.equal(item.command.command, 'lomoCodeSecurity.revealFinding');
    assert.equal(item.command.arguments[0].findingRevision, 1);
    await registrations.get(item.command.command)(...item.command.arguments);
    const informationBeforeOpen = [...information];
    const clipboardBeforeOpen = [...clipboardWrites];
    await registrations.get('lomoCodeSecurity.openFinding')(findingNode);

    assert.equal(errors.length, 0);
    assert.equal(
      opened.at(-1),
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41&finding=17'),
    );
    assert.deepEqual(executedCommands.slice(-1), [
      {
        name: 'workbench.action.browser.open',
        args: [{
          url: retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41&finding=17'),
          reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
        }],
      },
    ], 'retained finding navigation must atomically navigate and focus one uniquely titled dashboard tab');
    assert.deepEqual(
      information,
      informationBeforeOpen,
      'integrated finding detail must not add a success toast that covers the browser',
    );
    assert.deepEqual(
      clipboardWrites,
      clipboardBeforeOpen,
      'successful integrated finding navigation must not overwrite the user clipboard',
    );
    assert.equal(shownDocuments.length, 1);
    const [editor] = shownDocuments;
    assert.equal(editor.document, document);
    assert.deepEqual(editor.options, { preview: false, preserveFocus: false, viewColumn: undefined });
    assert.deepEqual(
      [editor.selection.start.line, editor.selection.start.character, editor.selection.end.line, editor.selection.end.character],
      [1, 6, 1, 12],
    );
    assert.equal(editor.revealed.length, 1);
    assert.deepEqual(
      [
        editor.revealed[0].range.start.line,
        editor.revealed[0].range.start.character,
        editor.revealed[0].range.end.line,
        editor.revealed[0].range.end.character,
      ],
      [1, 6, 1, 12],
    );
    assert.equal(editor.revealed[0].revealType, 2);
  });
});

test('retained dashboard navigation requests one atomic exact-route replacement from a stale tab', async () => {
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(),
  ]]);
  const activeTabs = [{ label: 'app.py', isActive: true }];
  const restoredTabs = [{ label: RETAINED_BROWSER_TAB_TITLE, isActive: true }];
  await withExtensionFixture({
    activeTabGroupTabs: activeTabs,
    otherTabGroupTabs: restoredTabs,
    globalStateStorage,
    integratedBrowserResult: () => { simulateBrowserReplacement(activeTabs, 'Browser'); },
    workspaceFolders: [],
  }, async ({ registrations, errors, executedCommands, opened }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')(41);
    await registrations.get('lomoCodeSecurity.openDashboard')(42);

    assert.deepEqual(errors, []);
    assert.deepEqual(opened, [
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41'),
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=42'),
    ]);
    assert.deepEqual(executedCommands, [41, 42].map((scan) => ({
      name: 'workbench.action.browser.open',
      args: [{
        url: retainedBrowserUrl(`http://127.0.0.1:8080/?view=findings&scan=${scan}`),
        reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
      }],
    })));
    assert.equal(restoredTabs.length, 0, 'the superseded restored Browser tab must close after replacement');
    assert.equal(activeTabs.length, 2, 'the source tab plus one replacement Browser tab must remain');
    assert.equal(activeTabs.filter(({ isActive }) => isActive).length, 1);
    assert.equal(activeTabs.find(({ isActive }) => isActive)?.label, 'Browser');
  });
});

test('retained dashboard navigation keeps the exact tab when the host reuses it', async () => {
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(),
  ]]);
  const retained = { label: RETAINED_BROWSER_TAB_TITLE, isActive: false };
  const source = { label: 'app.py', isActive: true };
  const activeTabs = [retained, source];
  await withExtensionFixture({
    activeTabGroupTabs: activeTabs,
    globalStateStorage,
    integratedBrowserResult: () => {
      source.isActive = false;
      retained.isActive = true;
    },
    workspaceFolders: [],
  }, async ({ registrations, closedTabs, errors, executedCommands, opened }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')(41);

    assert.deepEqual(errors, []);
    assert.deepEqual(closedTabs, [], 'successful host reuse must never close the exact retained tab');
    assert.equal(activeTabs.length, 2);
    assert.equal(activeTabs.filter(({ label }) => label === RETAINED_BROWSER_TAB_TITLE).length, 1);
    assert.equal(retained.isActive, true);
    assert.deepEqual(opened, [retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41')]);
    assert.deepEqual(executedCommands, [{
      name: 'workbench.action.browser.open',
      args: [{
        url: retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41'),
        reuseUrlFilter: RETAINED_BROWSER_REUSE_FILTER,
      }],
    }]);
  });
});

test('retained dashboard recovery fails closed when two exact owned tabs are present', async () => {
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(),
  ]]);
  await withExtensionFixture({
    activeTabGroupTabs: [{ label: RETAINED_BROWSER_TAB_TITLE, isActive: true }],
    otherTabGroupTabs: [{ label: RETAINED_BROWSER_TAB_TITLE, isActive: true }],
    globalStateStorage,
    workspaceFolders: [],
  }, async ({ registrations, errors, executedCommands, opened }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')(41);

    assert.deepEqual(opened, []);
    assert.deepEqual(executedCommands, []);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /more than one retained CodeSecurity dashboard/u);
  });
});

test('retained dashboard navigations are serialized and the newest exact finding route settles last', async () => {
  const value = finding(17, { file_path: 'src/queued-route.ts' });
  const globalStateStorage = new Map([[
    'lomoCodeSecurity.integratedDashboardMemberships.v1',
    integratedDashboardMembershipState(),
  ]]);
  const pending = [];
  await withExtensionFixture({
    extensionMode: 3,
    modelOpenExternalUriCache: true,
    streamReady: false,
    globalStateStorage,
    integratedBrowserResult: (url, request) => new Promise((resolve) => {
      pending.push({ url, request, resolve });
    }),
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([value]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, executedCommands, opened, testApi, treeProvider }) => {
    await testApi.refresh();
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, value.file_path);
    const [lifecycle] = tree.getChildren(severity);
    const [findingNode] = tree.getChildren(lifecycle);
    tree.getTreeItem(findingNode);

    const root = registrations.get('lomoCodeSecurity.openDashboard')();
    const scan = registrations.get('lomoCodeSecurity.openDashboard')(41);
    const exact = registrations.get('lomoCodeSecurity.openFinding')(findingNode);
    for (let turn = 0; turn < 20 && pending.length < 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(pending.length, 1, 'only the oldest retained navigation may enter the host at once');
    pending[0].resolve();
    for (let turn = 0; turn < 20 && pending.length < 2; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(pending.length, 2);
    pending[1].resolve();
    for (let turn = 0; turn < 20 && pending.length < 3; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(pending.length, 3);
    pending[2].resolve();
    await Promise.all([root, scan, exact]);

    assert.deepEqual(opened, [
      retainedBrowserUrl('http://127.0.0.1:8080/'),
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41'),
      retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41&finding=17'),
    ]);
    assert(pending.every(({ request }) => request.reuseUrlFilter === RETAINED_BROWSER_REUSE_FILTER));
    assert.deepEqual(executedCommands.map(({ name }) => name), [
      'workbench.action.browser.open',
      'workbench.action.browser.open',
      'workbench.action.browser.open',
    ]);
    assert.equal(testApi.snapshot().lastOpenFinding.integratedBrowserOpened, true);
    assert.equal(errors.length, 0);
  });
});


test('single-finding Tree groups fail closed because commands belong only to finding items', async () => {
  const value = finding(17, { file_path: 'src/single-group.ts' });
  const calls = [];
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      calls.push(url.pathname);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([value]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, opened, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/single-group.ts');
    const [lifecycle] = tree.getChildren(severity);
    calls.length = 0;
    await registrations.get('lomoCodeSecurity.openFinding')(severity);
    await registrations.get('lomoCodeSecurity.openFinding')(lifecycle);
    assert.equal(errors.length, 2);
    assert(errors.every(({ message }) => /Choose a current CodeSecurity finding/iu.test(message)));
    assert.deepEqual(opened, []);
    assert.deepEqual(calls, []);
  });
});


test('multi-finding Tree groups fail closed before open or backend work', async () => {
  const values = [
    finding(17, { file_path: 'src/ambiguous-group.ts', severity: 'high' }),
    finding(18, { file_path: 'src/ambiguous-group.ts', severity: 'high' }),
  ];
  const calls = [];
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      calls.push(url.pathname);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(values));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, opened, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/ambiguous-group.ts');
    calls.length = 0;
    await registrations.get('lomoCodeSecurity.openFinding')(severity);
    assert.deepEqual(opened, []);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Choose a current CodeSecurity finding/iu);
    assert.deepEqual(calls, []);
  });
});


function revealRaceDocument() {
  return {
    uri: {
      path: '/workspace/current/src/reveal-race.ts',
      toString: () => 'file:///workspace/current/src/reveal-race.ts',
    },
    version: 1,
    lineCount: 2,
    lineAt: (line) => ({ text: ['const safe = true;', 'const danger = risky();'][line] }),
    isDirty: false,
  };
}

function revealRaceRoute(state) {
  return async (url) => {
    if (url.pathname === '/v1/projects/resolve') {
      return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
    }
    if (url.pathname === '/v1/projects/7/scans/latest') {
      return json({
        id: 41,
        project_id: 7,
        status: 'completed',
        revision: state.revision,
        findings_revision: state.revision,
      });
    }
    if (url.pathname === '/v1/scans/41/findings') {
      return json(findingPage([state.finding], state.revision));
    }
    throw new Error(`unexpected request GET ${url.pathname}`);
  };
}

function revealRaceFinding() {
  return finding(19, {
    file_path: 'src/reveal-race.ts',
    start_line: 2,
    start_column: 7,
    end_line: 2,
    end_column: 13,
  });
}

test('finding reveal allows a structurally identical projection replacement while opening', async () => {
  const state = { revision: 1, finding: revealRaceFinding() };
  let replaceProjection;
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: revealRaceRoute(state),
    onOpenTextDocument: async () => replaceProjection?.(),
  }, async ({ testApi, openDocument, shownDocuments, errors }) => {
    const document = revealRaceDocument();
    openDocument(document);
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    replaceProjection = () => testApi.refresh();

    await testApi.revealFinding(context);

    assert.equal(errors.length, 0);
    assert.equal(shownDocuments.length, 1);
    assert.deepEqual(
      [
        shownDocuments[0].selection.start.line,
        shownDocuments[0].selection.start.character,
        shownDocuments[0].selection.end.line,
        shownDocuments[0].selection.end.character,
      ],
      [1, 6, 1, 12],
    );
  });
});

test('finding reveal blocks a document that becomes stale while opening', async () => {
  const state = { revision: 1, finding: revealRaceFinding() };
  let makeStale;
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: revealRaceRoute(state),
    onOpenTextDocument: async () => makeStale?.(),
  }, async ({ testApi, changeDocument, openDocument, shownDocuments }) => {
    const document = revealRaceDocument();
    openDocument(document);
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    makeStale = () => {
      document.version += 1;
      document.isDirty = true;
      changeDocument(document);
    };

    await assert.rejects(
      testApi.revealFinding(context),
      /became stale while its file was opening/u,
    );
    assert.equal(shownDocuments.length, 0, 'a stale opening must not reach the editor surface');
  });
});

test('finding reveal does not select after the document becomes stale while showing', async () => {
  const state = { revision: 1, finding: revealRaceFinding() };
  let makeStale;
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: revealRaceRoute(state),
    onShowTextDocument: async () => makeStale?.(),
  }, async ({ testApi, changeDocument, openDocument, shownDocuments }) => {
    const document = revealRaceDocument();
    openDocument(document);
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    makeStale = () => {
      document.version += 1;
      document.isDirty = true;
      changeDocument(document);
    };

    await assert.rejects(
      testApi.revealFinding(context),
      /became stale while its file was showing/u,
    );
    assert.equal(shownDocuments.length, 1);
    assert.equal(shownDocuments[0].selection, undefined);
    assert.deepEqual(shownDocuments[0].revealed, []);
  });
});

test('finding reveal does not select after the collection advances while showing', async () => {
  const state = { revision: 1, finding: revealRaceFinding() };
  let advanceCollection;
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: revealRaceRoute(state),
    onShowTextDocument: async () => advanceCollection?.(),
  }, async ({ testApi, openDocument, shownDocuments }) => {
    const document = revealRaceDocument();
    openDocument(document);
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    advanceCollection = async () => {
      state.revision = 2;
      await testApi.refresh();
    };

    await assert.rejects(
      testApi.revealFinding(context),
      /changed while its file was showing/u,
    );
    assert.equal(shownDocuments.length, 1);
    assert.equal(shownDocuments[0].selection, undefined);
    assert.deepEqual(shownDocuments[0].revealed, []);
  });
});


test('concurrent workspace refreshes coalesce to one metadata and findings reconciliation', async () => {
  let projectReads = 0;
  let latestReads = 0;
  let pageReads = 0;
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });
  let releaseProject;
  const project = new Promise((resolve) => { releaseProject = resolve; });
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        projectReads += 1;
        markStarted();
        return project;
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        latestReads += 1;
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        pageReads += 1;
        return json(findingPage([finding(1, { file_path: 'src/coalesced.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ testApi, entries, errors }) => {
    const refreshes = Array.from({ length: 250 }, () => testApi.refresh());
    await started;
    assert.equal(projectReads, 1);
    releaseProject(json({ id: 7, name: 'current', repo_path: '/workspace/current' }));
    await Promise.all(refreshes);

    assert.equal(projectReads, 1);
    assert.equal(latestReads, 1);
    assert.equal(pageReads, 1);
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/coalesced.ts']);
    assert.equal(errors.length, 0);
  });
});


test('Development refresh hydrates three deterministic bounded contexts without open editors', async () => {
  const values = [
    finding(1, { file_path: 'src/first.ts' }),
    finding(2, { file_path: 'src/second.ts' }),
    finding(3, { file_path: 'src/third.ts' }),
    finding(4, { file_path: 'src/not-qualified.ts' }),
  ];
  const hydratedPaths = [];
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage(values));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const filePath = url.searchParams.get('file_path');
        hydratedPaths.push(filePath);
        return json(findingPage(values.filter((value) => value.file_path === filePath)));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ testApi, deactivate, errors }) => {
    await testApi.refresh();
    const snapshot = testApi.snapshot();
    assert.deepEqual(snapshot.workspaces[0].findings.map(({ findingId }) => findingId), [1, 2, 3]);
    assert.deepEqual(
      hydratedPaths,
      ['src/first.ts', 'src/second.ts', 'src/third.ts'],
      'the qualification priority set is capped at three one-finding files',
    );
    deactivate();
    assert.deepEqual(testApi.snapshot(), {
      statusText: '', treeWorkspaceLabels: [], lastOpenFinding: null, workspaces: [],
    });
    assert.equal(errors.length, 0);
  });
});


test('Development qualification contexts survive lifecycle and deletion reloads and reject a stale context', async () => {
  let revision = 1;
  let values = [
    finding(1, { file_path: 'src/first.ts' }),
    finding(2, { file_path: 'src/second.ts' }),
    finding(3, { file_path: 'src/third.ts' }),
    finding(4, { file_path: 'src/saved-without-rescan.ts' }),
  ];
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          gate_decision: 'fail',
          revision,
          findings_revision: revision,
        });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = revision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest(values, revision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage(values, revision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const filePath = url.searchParams.get('file_path');
        return json(findingPage(values.filter((value) => value.file_path === filePath), revision));
      }
      const detailMatch = url.pathname.match(/^\/v1\/scans\/41\/findings\/([1-9][0-9]*)$/);
      if (detailMatch) {
        const ordinal = Number(detailMatch[1]);
        const value = values.find((candidate) => candidate.scan_finding_number === ordinal);
        return value
          ? json(findingDetail(value.id, { ...value, findings_revision: revision }))
          : json({ detail: 'finding no longer exists' }, 404);
      }
      if (url.pathname === '/v1/findings/1/lifecycle' && init.method === 'PATCH') {
        revision = 2;
        values = values.map((value) => value.id === 1 ? {
          ...value,
          lifecycle_status: 'accepted_risk',
          gate_exempt: true,
          gate_effect: 'non_blocking',
          revision: 2,
        } : value);
        return json(findingDetail(1, { ...values[0], findings_revision: revision }));
      }
      if (url.pathname === '/v1/findings/2' && init.method === 'DELETE') {
        values = values.filter((value) => value.id !== 2);
        revision = 3;
        return json({ deleted: true, finding_id: 2, scan_id: 41 });
      }
      if (url.pathname === '/v1/advisor/providers' && (init.method || 'GET') === 'GET') {
        return json(advisorProviderCollection());
      }
      if (url.pathname === '/v1/findings/3/triage' && init.method === 'POST') {
        assert.deepEqual(JSON.parse(init.body), {
          model: null,
          expected_revision: 1,
          advisor_provider_pin: LOCAL_ADVISOR_PIN,
        });
        return json({ id: 88, kind: 'advisor', finding_id: 3, status: 'queued' });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ testApi, changeDocument, entries, errors, openDocument }) => {
    await testApi.refresh();
    let contexts = testApi.snapshot().workspaces[0].findings;
    assert.deepEqual(contexts.map(({ findingId }) => findingId), [1, 2, 3]);

    const staleUri = 'file:///workspace/current/src/saved-without-rescan.ts';
    const staleDocument = {
      uri: { path: '/workspace/current/src/saved-without-rescan.ts', toString: () => staleUri },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'savedButNotRescanned();' }),
      isDirty: false,
    };
    openDocument(staleDocument);
    staleDocument.isDirty = true;
    staleDocument.version += 1;
    changeDocument(staleDocument);
    staleDocument.isDirty = false;
    assert.equal(entries.has(staleUri), false);

    await testApi.applyLifecycle(contexts[0], 'accepted_risk', 'bounded test receipt');
    contexts = testApi.snapshot().workspaces[0].findings;
    assert.deepEqual(contexts.map(({ findingId }) => findingId), [1, 2, 3]);
    assert.equal(contexts[0].lifecycleStatus, 'accepted_risk');
    assert.deepEqual(testApi.snapshot().workspaces[0].staleFiles, ['src/saved-without-rescan.ts']);
    assert.equal(entries.has(staleUri), false, 'lifecycle reload cannot republish saved but unrescanned evidence');

    const deleted = contexts.find(({ findingId }) => findingId === 2);
    await testApi.deleteFinding(deleted);
    contexts = testApi.snapshot().workspaces[0].findings;
    assert.deepEqual(contexts.map(({ findingId }) => findingId), [1, 3]);
    assert.deepEqual(testApi.snapshot().workspaces[0].staleFiles, ['src/saved-without-rescan.ts']);
    assert.equal(entries.has(staleUri), false, 'deletion reload cannot republish saved but unrescanned evidence');
    const advisor = await testApi.queueAdvisor(contexts.find(({ findingId }) => findingId === 3));
    assert.deepEqual(advisor, { id: 88, status: 'queued' });
    await assert.rejects(
      testApi.queueAdvisor(deleted),
      /finding is no longer current\. Refresh findings and choose it again/i,
    );
    assert.equal(errors.length, 0);
  });
});


test('Development deep-link command rejects an unindexed explicit identity', async () => {
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: async (url) => { throw new Error(`unexpected request GET ${url.pathname}`); },
  }, async ({ registrations, testApi, opened, errors }) => {
    const context = {
      workspaceKey: 'file:///workspace/current',
      findingId: 99,
      scanId: 41,
      scanFindingNumber: 7,
      findingRevision: 1,
    };
    const open = registrations.get('lomoCodeSecurity.openFinding');
    await open(context);
    assert.equal(testApi.snapshot().lastOpenFinding, null);
    assert.deepEqual(opened, []);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Choose a current CodeSecurity finding/);
  });
});


test('Development deep-link command rejects an unindexed identity before integrated-browser execution', async () => {
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    integratedBrowserResult: async () => { throw new Error('integrated browser must not run'); },
    route: async (url) => { throw new Error(`unexpected request GET ${url.pathname}`); },
  }, async ({ registrations, testApi, errors }) => {
    await registrations.get('lomoCodeSecurity.openFinding')({
      workspaceKey: 'file:///workspace/current', findingId: 9, scanId: 41, scanFindingNumber: 2,
    });
    assert.equal(testApi.snapshot().lastOpenFinding, null);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Choose a current CodeSecurity finding/);
  });
});


test('Development deep-link command rejects an unindexed identity before integrated-browser navigation', async () => {
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    integratedBrowserResult: async () => { throw new Error('fixture integrated browser rejected the URI'); },
    route: async (url) => { throw new Error(`unexpected request GET ${url.pathname}`); },
  }, async ({ registrations, testApi, errors }) => {
    await registrations.get('lomoCodeSecurity.openFinding')({
      workspaceKey: 'file:///workspace/current', findingId: 19, scanId: 41, scanFindingNumber: 4,
    });
    assert.equal(testApi.snapshot().lastOpenFinding, null);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Choose a current CodeSecurity finding/);
  });
});


test('Production navigation surfaces an unavailable integrated browser and rejects an unindexed finding', async () => {
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    availableCommands: [],
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
        return json(browserInvitationEnvelope());
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, testApi, errors, clipboardWrites }) => {
    assert.equal(testApi, undefined, 'Production mode must not expose Development/Test hooks');
    await registrations.get('lomoCodeSecurity.openDashboard')();
    await registrations.get('lomoCodeSecurity.openFinding')({
      workspaceKey: 'file:///workspace/current',
      findingId: 19,
      scanId: 41,
      scanFindingNumber: 4,
    });
    assert.equal(errors.length, 2);
    assert.match(errors[0].message, /VS Code integrated browser could not open/);
    assert.match(errors[0].message, /pairing code was not copied, stored/);
    assert.deepEqual(errors[0].actions, ['Copy pairing code']);
    assert.deepEqual(clipboardWrites, []);
    assert.match(errors[1].message, /Choose a current CodeSecurity finding/);
  });
});


test('Production navigation surfaces an integrated-browser rejection', async () => {
  await withExtensionFixture({
    strictBrowserInvitationRoute: true,
    streamReady: false,
    integratedBrowserResult: async () => { throw new Error('fixture integrated browser rejected the URI'); },
    route: async (url, init) => {
      if (url.pathname === '/v1/auth/ide/browser-invitations' && init.method === 'POST') {
        return json(browserInvitationEnvelope());
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, clipboardWrites }) => {
    await registrations.get('lomoCodeSecurity.openDashboard')();
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /VS Code integrated browser could not open/);
    assert.doesNotMatch(errors[0].message, /fixture integrated browser rejected the URI/);
    assert.match(errors[0].message, /pairing code was not copied, stored/);
    assert.deepEqual(errors[0].actions, ['Copy pairing code']);
    assert.deepEqual(clipboardWrites, []);
  });
});


test('stream-ready reconciliation rechecks metadata without duplicating an unchanged findings download', async () => {
  const stream = controllableEventStream();
  let projectReads = 0;
  let latestReads = 0;
  let pageReads = 0;
  await withExtensionFixture({
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        projectReads += 1;
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        latestReads += 1;
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        pageReads += 1;
        return json(findingPage([finding(1, { file_path: 'src/ready.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, eventStreamSignals, globalStateUpdates }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(projectReads, 2);
    assert.equal(latestReads, 2);
    assert.equal(pageReads, 1, 'stream-ready must not repeat the already-proven full Problems hydration');
    assert.equal(globalStateUpdates().at(-1).value.event_id, 0);
    assert.equal(errors.length, 0);
  });
});


test('an event superseding a mid-Problems build waits for the complete replacement before cursor ACK', async () => {
  const stream = controllableEventStream();
  let revision = 1;
  let revisionTwoDiagnosticCalls = 0;
  let signalReplacementStarted;
  const replacementStarted = new Promise((resolve) => { signalReplacementStarted = resolve; });
  let releaseReplacement;
  const replacementPage = new Promise((resolve) => { releaseReplacement = resolve; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url, init) => {
      const value = finding(1, { file_path: 'src/event-atomic.ts', message: `revision ${revision}`, revision });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([value], revision));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        if (revision === 1) return json(hybridDiagnosticPage([value], 1));
        revisionTwoDiagnosticCalls += 1;
        if (revisionTwoDiagnosticCalls === 1) {
          return new Promise((resolve, reject) => {
            init.signal.addEventListener(
              'abort',
              () => reject(new DOMException('superseded manual diagnostic build', 'AbortError')),
              { once: true },
            );
          });
        }
        signalReplacementStarted();
        return replacementPage;
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, entries, errors, eventStreamSignals, globalStateUpdates, treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    revision = 2;
    const manual = registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 50 && revisionTwoDiagnosticCalls === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(treeProvider().getChildren()[0].workspace.diagnosticProjection, 'loading');
    stream.send(domainEvent(1, 'findings.changed', 2));
    await replacementStarted;
    assert.equal(globalStateUpdates().at(-1).value.event_id, 0);
    assert.equal(entries.get('file:///workspace/current/src/event-atomic.ts')[0].message, 'revision 1');

    releaseReplacement(json(hybridDiagnosticPage([
      finding(1, { file_path: 'src/event-atomic.ts', message: 'revision 2', revision: 2 }),
    ], 2)));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    await manual;
    assert.equal(globalStateUpdates().at(-1).value.event_id, 1);
    assert.equal(treeProvider().getChildren()[0].workspace.diagnosticProjection, 'complete');
    assert.equal(entries.get('file:///workspace/current/src/event-atomic.ts')[0].message, 'revision 2');
    assert.equal(errors.length, 0);
  });
});


test('scan and findings events superseding a lifecycle reload return only with its required file current', async () => {
  const stream = controllableEventStream();
  const path = 'src/coordinator-abort.ts';
  const initial = finding(1, { file_path: path, message: 'initial lifecycle evidence' });
  const replacement = {
    ...initial,
    lifecycle_status: 'accepted_risk',
    gate_effect: 'non_blocking',
    gate_exempt: true,
    revision: 2,
    message: 'replacement lifecycle evidence',
  };
  let mutated = false;
  let mutatedHydrationStarts = 0;
  let mutatedManifestReads = 0;
  let requiredHydrationSignal;
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url, init) => {
      const value = mutated ? replacement : initial;
      const revision = mutated ? 2 : 1;
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = revision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        if (mutated) mutatedManifestReads += 1;
        return json(hybridManifest([value], revision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([value], revision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(1, initial));
      }
      if (url.pathname === '/v1/findings/1/lifecycle' && init.method === 'PATCH') {
        mutated = true;
        return json(findingDetail(1, replacement));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        if (!mutated) return json(findingPage([initial], 1));
        mutatedHydrationStarts += 1;
        if (mutatedHydrationStarts === 1) {
          requiredHydrationSignal = init.signal;
          return new Promise((_resolve, reject) => {
            const stop = () => reject(new DOMException('exact hydration superseded', 'AbortError'));
            if (init.signal.aborted) stop();
            else init.signal.addEventListener('abort', stop, { once: true });
          });
        }
        return json(findingPage([replacement], 2));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({
    entries, errors, eventStreamSignals, globalStateUpdates, information, statusBarMessages, testApi, treeProvider,
  }) => {
    await testApi.refresh();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    const context = testApi.snapshot().workspaces[0].findings[0];
    const mutation = testApi.applyLifecycle(
      context,
      'accepted_risk',
      'coordinator cancellation proof',
    );
    for (let turn = 0; turn < 50 && mutatedHydrationStarts < 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(mutatedHydrationStarts, 1, 'the exact required-file hydration must start before SSE replacement');
    stream.send(
      domainEvent(1, 'scan.changed', 2)
      + domainEvent(2, 'findings.changed', 2),
    );
    await mutation;
    assert.equal(requiredHydrationSignal.aborted, true);
    for (let turn = 0; turn < 100 && globalStateUpdates().at(-1)?.value.event_id !== 2; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(globalStateUpdates().at(-1).value.event_id, 2);
    assert.equal(mutatedHydrationStarts, 2, 'replay must start one fresh required context hydration');
    assert.equal(mutatedManifestReads, 2, 'the initial exact and joined SSE workspace chain reconcile once each');
    const workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.diagnosticProjection, 'complete');
    assert.equal(workspace.files.has(path), true, 'joined workspace proof must contain the selected lifecycle file');
    assert.equal(workspace.allFilesStale, false);
    assert.equal(workspace.staleFiles.has(path), false);
    assert.equal(entries.get(`file:///workspace/current/${path}`)[0].message, replacement.message);
    assert.equal(testApi.snapshot().workspaces[0].findings[0].lifecycleStatus, 'accepted_risk');
    assert.equal(information.some((message) => /complete scan revision was reloaded/u.test(message)), false);
    assert.deepEqual(statusBarMessages.at(-1), {
      message: 'S41-F001 is now Accepted risk. Gate effect: Non-blocking for gate. The complete scan revision was reloaded.',
      timeout: 5_000,
    });
    assert.equal(errors.length, 0);
  });
});

test('lifecycle replacement treats a stale expanded-file 409 as supersession without hiding current findings', async () => {
  const targetPath = 'src/lifecycle-target.ts';
  const expandedPath = 'src/expanded-during-lifecycle.ts';
  const initialTarget = finding(1, { file_path: targetPath, message: 'initial lifecycle target' });
  const expandedFinding = finding(2, {
    file_path: expandedPath,
    scan_finding_number: 2,
    display_id: 'S41-F002',
    message: 'expanded sibling finding',
  });
  const replacementTarget = {
    ...initialTarget,
    lifecycle_status: 'gate_exempt',
    gate_effect: 'non_blocking',
    gate_exempt: true,
    revision: 2,
    message: 'current non-blocking lifecycle target',
  };
  let mutated = false;
  let markExpandedHydrationStarted;
  const expandedHydrationStarted = new Promise((resolve) => { markExpandedHydrationStarted = resolve; });

  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      const target = mutated ? replacementTarget : initialTarget;
      const revision = mutated ? 2 : 1;
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = revision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([target, expandedFinding], revision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([target, expandedFinding], revision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(1, initialTarget));
      }
      if (url.pathname === '/v1/findings/1/lifecycle' && init.method === 'PATCH') {
        mutated = true;
        return json(findingDetail(1, replacementTarget));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const path = url.searchParams.get('file_path');
        if (path === expandedPath && url.searchParams.get('expected_revision') === '1') {
          markExpandedHydrationStarted();
          return new Promise((_resolve, reject) => {
            init.signal.addEventListener('abort', () => reject(new CodeSecurityRequestError(
              'findings changed after the selected manifest snapshot',
              409,
              true,
            )), { once: true });
          });
        }
        const values = path === targetPath ? [target] : [expandedFinding];
        return json(findingPage(values, revision));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ errors, registrations, testApi, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [targetSeverity] = await hydrateTreePath(tree, targetPath);
    const [targetLifecycle] = tree.getChildren(targetSeverity);
    const [targetFindingNode] = tree.getChildren(targetLifecycle);
    const workspaceNode = tree.getChildren()[0];
    const fileNode = tree.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')
      .find((node) => node.filePath === expandedPath);
    const expanded = tree.getChildren(fileNode);
    await expandedHydrationStarted;

    tree.getTreeItem(targetFindingNode);
    const context = testApi.snapshot().workspaces[0].findings
      .find(({ findingId }) => findingId === initialTarget.id);
    assert(context, 'the hydrated lifecycle target has one current command context');
    const mutation = testApi.applyLifecycle(
      context,
      'gate_exempt',
      'visible lifecycle replacement regression',
    );
    const supersededChildren = await expanded;
    await mutation;

    assert(Array.isArray(supersededChildren), 'the obsolete Tree read settles as ordinary supersession');
    const currentWorkspaceNode = tree.getChildren()[0];
    const currentFileNode = tree.getChildren(currentWorkspaceNode)
      .find((node) => node.filePath === expandedPath);
    const currentChildren = await tree.getChildren(currentFileNode);
    assert.equal(currentChildren.length, 1);
    const workspace = tree.getChildren()[0].workspace;
    assert.equal(workspace.revision, 2);
    assert.equal(workspace.files.get(targetPath)[0].message, replacementTarget.message);
    assert.equal(workspace.files.get(targetPath)[0].lifecycle_status, 'gate_exempt');
    assert.equal(workspace.files.get(expandedPath)[0].message, expandedFinding.message);
    assert.equal(errors.length, 0);
  });
});

test('lifecycle invalidation cannot hydrate a retained Tree node after the mutation commits', async () => {
  const targetPath = 'src/lifecycle-target.ts';
  const retainedPath = 'src/retained-tree-node.ts';
  const initialTarget = finding(1, { file_path: targetPath, message: 'initial lifecycle target' });
  const retainedFinding = finding(2, {
    file_path: retainedPath,
    scan_finding_number: 2,
    display_id: 'S41-F002',
    message: 'retained sibling finding',
  });
  const replacementTarget = {
    ...initialTarget,
    lifecycle_status: 'gate_exempt',
    gate_effect: 'non_blocking',
    gate_exempt: true,
    revision: 2,
    message: 'current non-blocking lifecycle target',
  };
  let mutated = false;
  let mutationManifestReads = 0;
  let obsoleteHydrationReads = 0;
  let markMutationManifestStarted;
  let releaseMutationManifest;
  const mutationManifestStarted = new Promise((resolve) => { markMutationManifestStarted = resolve; });
  const mutationManifestReleased = new Promise((resolve) => { releaseMutationManifest = resolve; });

  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      const target = mutated ? replacementTarget : initialTarget;
      const revision = mutated ? 2 : 1;
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = revision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        if (mutated) {
          mutationManifestReads += 1;
          if (mutationManifestReads === 1) {
            markMutationManifestStarted();
            await mutationManifestReleased;
          }
        }
        return json(hybridManifest([target, retainedFinding], revision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([target, retainedFinding], revision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(1, initialTarget));
      }
      if (url.pathname === '/v1/findings/1/lifecycle' && init.method === 'PATCH') {
        mutated = true;
        return json(findingDetail(1, replacementTarget));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const path = url.searchParams.get('file_path');
        const expectedRevision = url.searchParams.get('expected_revision');
        if (path === retainedPath && expectedRevision === '1') obsoleteHydrationReads += 1;
        const values = path === targetPath ? [target] : [retainedFinding];
        return json(findingPage(values, revision));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ changeDocument, entries, errors, openDocument, registrations, testApi, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [targetSeverity] = await hydrateTreePath(tree, targetPath);
    const [targetLifecycle] = tree.getChildren(targetSeverity);
    const [targetFindingNode] = tree.getChildren(targetLifecycle);
    tree.getTreeItem(targetFindingNode);
    const initialWorkspaceNode = tree.getChildren()[0];
    const retainedFileNode = tree.getChildren(initialWorkspaceNode)
      .find((node) => node.filePath === retainedPath);
    assert(retainedFileNode, 'the initially rendered Tree retains one sibling file node');
    const retainedUriKey = `file:///workspace/current/${retainedPath}`;
    const retainedDocument = {
      uri: { path: `/workspace/current/${retainedPath}`, toString: () => retainedUriKey },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'changedAfterScan();' }),
      isDirty: false,
    };
    openDocument(retainedDocument);
    retainedDocument.isDirty = true;
    retainedDocument.version += 1;
    changeDocument(retainedDocument);
    retainedDocument.isDirty = false;
    assert.equal(tree.getChildren()[0].workspace.staleFiles.has(retainedPath), true);
    assert.equal(entries.has(retainedUriKey), false);
    const context = testApi.snapshot().workspaces[0].findings
      .find(({ findingId }) => findingId === initialTarget.id);
    assert(context, 'the lifecycle target has one current command context');

    const mutation = testApi.applyLifecycle(
      context,
      'gate_exempt',
      'post-commit Tree invalidation regression',
    );
    await mutationManifestStarted;

    const rootsDuringRefresh = tree.getChildren();
    const obsoleteReadsBeforeRetainedAccess = obsoleteHydrationReads;
    const retainedChildren = await tree.getChildren(retainedFileNode);
    const obsoleteReadsAfterRetainedAccess = obsoleteHydrationReads;
    releaseMutationManifest();
    await mutation;

    assert.deepEqual(rootsDuringRefresh, [], 'no obsolete workspace is rendered during authoritative refresh');
    assert.deepEqual(
      retainedChildren,
      [],
      'a file node retained by VS Code cannot hydrate after its projection was invalidated',
    );
    assert.equal(
      obsoleteReadsAfterRetainedAccess,
      obsoleteReadsBeforeRetainedAccess,
      'the retained node cannot add an obsolete-revision request after mutation invalidation',
    );

    const currentWorkspaceNode = tree.getChildren()[0];
    const currentFileNode = tree.getChildren(currentWorkspaceNode)
      .find((node) => node.filePath === retainedPath);
    const currentChildren = await tree.getChildren(currentFileNode);
    assert.equal(currentChildren.length, 0, 'same-scan mutation cannot republish evidence for edited source');
    assert.equal(obsoleteHydrationReads, obsoleteReadsAfterRetainedAccess);
    assert.equal(currentWorkspaceNode.workspace.revision, 2);
    assert.equal(currentWorkspaceNode.workspace.files.get(targetPath)[0].message, replacementTarget.message);
    assert.equal(currentWorkspaceNode.workspace.staleFiles.has(retainedPath), true);
    assert.equal(entries.has(retainedUriKey), false);
    assert.equal(errors.length, 0);
  });
});


test('a lagged project resolve cannot ACK an update event before its revision is visible', async () => {
  const stream = controllableEventStream();
  let lagProject = false;
  let laggedReads = 0;
  let releaseVisibleProject;
  const visibleProject = new Promise((resolve) => { releaseVisibleProject = resolve; });
  await withExtensionFixture({
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        if (!lagProject) {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
        }
        laggedReads += 1;
        if (laggedReads === 1) return json({ detail: 'temporarily lagged' }, 404);
        await visibleProject;
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 2 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([finding(1, { file_path: 'src/project-lag.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, errors, eventStreamSignals, globalStateUpdates, treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    lagProject = true;
    stream.send(domainEvent(1, 'project.changed', 2));
    for (let turn = 0; turn < 50 && laggedReads < 2; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert.equal(laggedReads, 2, 'project reconciliation should retry a transient resolve 404');
    assert.equal(globalStateUpdates().at(-1).value.event_id, 0);
    assert.equal(treeProvider().getChildren()[0].workspace.projectRevision, 1);

    releaseVisibleProject();
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(globalStateUpdates().at(-1).value.event_id, 1);
    assert.equal(treeProvider().getChildren()[0].workspace.projectRevision, 2);
    assert.equal(errors.length, 0);
  });
});

test('a recreated project supersedes an obsolete predecessor event backlog without blocking the cursor', async () => {
  const stream = controllableEventStream();
  let projectId = 7;
  let scanId = 41;
  const value = () => finding(scanId, {
    scan_id: scanId,
    scan_finding_number: 1,
    display_id: `S${scanId}-F001`,
    file_path: `src/project-${projectId}.ts`,
  });
  await withExtensionFixture({
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: projectId, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === `/v1/projects/${projectId}/scans/latest`) {
        return json({
          id: scanId,
          project_id: projectId,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
        });
      }
      if (url.pathname === `/v1/scans/${scanId}/findings`) {
        return json(findingPage([value()]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, entries, errors, eventStreamSignals, globalStateUpdates, treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    projectId = 8;
    scanId = 42;
    stream.send(projectDomainEvent(1, 7, 2, 'updated'));
    for (let turn = 0; turn < 100 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert.equal(globalStateUpdates().at(-1).value.event_id, 1);
    assert.equal(treeProvider().getChildren()[0].workspace.projectId, 8);
    assert.equal(treeProvider().getChildren()[0].workspace.scanId, 42);
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/project-8.ts']);

    stream.send(projectDomainEvent(2, 7, 3, 'deleted'));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 2; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(projectDomainEvent(3, 8, 1, 'created'));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 3; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(globalStateUpdates().at(-1).value.event_id, 3);
    assert.equal(treeProvider().getChildren()[0].workspace.projectId, 8);
    assert.equal(errors.length, 0);
  });
});


test('scan and project deletion events reconcile native state before their cursors advance', async () => {
  const stream = controllableEventStream();
  let projectDeleted = false;
  let scanPresent = true;
  let scanRevision = 1;
  let findingsRevision = 1;
  let pageReads = 0;
  await withExtensionFixture({
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return projectDeleted
          ? json({ detail: 'deleted' }, 404)
          : json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return scanPresent
          ? json({
            id: 41,
            project_id: 7,
            status: 'completed',
            revision: scanRevision,
            findings_revision: findingsRevision,
          })
          : json({ detail: 'deleted' }, 404);
      }
      if (url.pathname === '/v1/scans/41/findings') {
        pageReads += 1;
        return json(findingPage([
          finding(findingsRevision, {
            scan_finding_number: findingsRevision,
            file_path: 'src/deletion.ts',
            revision: findingsRevision,
          }),
        ], findingsRevision));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    eventStreamSignals,
    globalStateUpdates,
    treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    scanPresent = false;
    stream.send(domainEvent(1, 'scan.changed', 2, 'deleted'));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual([...entries.keys()], []);
    assert.deepEqual(treeProvider().getChildren(), []);
    assert.equal(eventStreamSignals()[0].aborted, false, 'project binding survives deletion of its latest scan');

    scanPresent = true;
    scanRevision = 3;
    findingsRevision = 2;
    stream.send(domainEvent(2, 'scan.changed', 3, 'created'));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 2; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/deletion.ts']);
    assert.equal(pageReads, 2);

    projectDeleted = true;
    stream.send(domainEvent(3, 'project.changed', 2, 'deleted'));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 3; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(globalStateUpdates().at(-1).value.event_id, 3);
    assert.equal(eventStreamSignals()[0].aborted, true, 'the final binding stops only after deletion cursor persistence');
    assert.deepEqual([...entries.keys()], []);
    assert.deepEqual(treeProvider().getChildren(), []);
    assert.equal(errors.length, 0);
  });
});


test('deleting the latest scan publishes an older remaining scan before advancing the event cursor', async () => {
  const stream = controllableEventStream();
  let latestScanId = 41;
  await withExtensionFixture({
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: latestScanId,
          project_id: 7,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
        });
      }
      if (url.pathname === `/v1/scans/${latestScanId}/findings`) {
        return json(findingPage([finding(latestScanId, {
          scan_id: latestScanId,
          scan_finding_number: 1,
          display_id: `S${latestScanId}-F001`,
          file_path: `src/scan-${latestScanId}.ts`,
        })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, entries, errors, eventStreamSignals, globalStateUpdates, treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    latestScanId = 40;
    stream.send(domainEvent(1, 'scan.changed', 2, 'deleted'));
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(globalStateUpdates().at(-1).value.event_id, 1);
    assert.equal(treeProvider().getChildren()[0].workspace.scanId, 40);
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/scan-40.ts']);
    assert.equal(eventStreamSignals()[0].aborted, false);
    assert.equal(errors.length, 0);
  });
});


test('deleting an edited latest scan keeps older fallback evidence stale until a genuinely newer scan', async () => {
  const stream = controllableEventStream();
  const path = 'src/fallback-stale.ts';
  let scanId = 42;
  const current = () => finding(1, {
    scan_id: scanId,
    scan_finding_number: 1,
    display_id: `S${scanId}-F001`,
    file_path: path,
    message: `scan ${scanId} disk evidence`,
  });
  await withExtensionFixture({
    strictHybridRoutes: true,
    eventStreamFactory: (signal) => stream.response(signal),
    route: async (url) => {
      const value = current();
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: scanId, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-files`) {
        return json(hybridManifest([value], 1, { id: scanId }));
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-diagnostics`) {
        return json({ ...hybridDiagnosticPage([value], 1), scan_id: scanId });
      }
      if (url.pathname === `/v1/scans/${scanId}/findings`) {
        return json(findingPage([value], 1));
      }
      throw new Error(`unexpected request GET ${url.pathname}${url.search}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    eventStreamSignals,
    globalStateUpdates,
    openDocument,
    changeDocument,
    provideHover,
    treeProvider,
  }) => {
    const uriKey = `file:///workspace/current/${path}`;
    const document = {
      uri: { path: `/workspace/current/${path}`, toString: () => uriKey },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'fallback();' }),
      isDirty: false,
    };
    openDocument(document);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    let workspaceNode = treeProvider().getChildren()[0];
    let fileNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    await treeProvider().getChildren(fileNode);
    assert.match(provideHover(document, { line: 0, character: 0 }).contents.value, /scan 42 disk evidence/);
    for (let turn = 0; turn < 20 && eventStreamSignals().length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    stream.send(
      'event: stream.ready\n'
      + 'data: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n',
    );
    for (let turn = 0; turn < 50 && globalStateUpdates().at(-1)?.value.event_id !== 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    document.isDirty = true;
    document.version += 1;
    changeDocument(document);
    document.isDirty = false;
    assert.equal(entries.has(uriKey), false);
    scanId = 41;
    stream.send(scanDomainEvent(1, 42, 2, 'deleted'));
    for (let turn = 0; turn < 100 && globalStateUpdates().at(-1)?.value.event_id !== 1; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    let workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.scanId, 41);
    assert.deepEqual([...workspace.staleFiles], [path]);
    assert.equal(entries.has(uriKey), false);
    assert.equal(provideHover(document, { line: 0, character: 0 }), undefined);

    scanId = 43;
    stream.send(scanDomainEvent(2, 43, 1, 'created'));
    for (let turn = 0; turn < 100 && globalStateUpdates().at(-1)?.value.event_id !== 2; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    workspaceNode = treeProvider().getChildren()[0];
    fileNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    await treeProvider().getChildren(fileNode);
    workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.scanId, 43);
    assert.deepEqual([...workspace.staleFiles], []);
    assert.equal(entries.get(uriKey)[0].message, 'scan 43 disk evidence');
    assert.match(provideHover(document, { line: 0, character: 0 }).contents.value, /scan 43 disk evidence/);
    assert.equal(errors.length, 0);
  });
});


test('routine successful refreshes stay non-blocking while unchanged revisions update scan metadata', async () => {
  let latestReads = 0;
  let pageReads = 0;
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({
          id: 7,
          name: 'current',
          repo_path: '/workspace/current',
          revision: latestReads === 0 ? 1 : 2,
        });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        latestReads += 1;
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          revision: latestReads,
          findings_revision: 1,
          gate_decision: latestReads === 1 ? 'fail' : 'pass',
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        pageReads += 1;
        return json(findingPage([finding(1, { file_path: 'src/metadata.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, information, statusBarMessages, statusItems, treeProvider }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    await refresh();

    assert.equal(latestReads, 2);
    assert.equal(pageReads, 1, 'the stable findings revision proves Problems and Tree are already current');
    assert.equal(entries.get('file:///workspace/current/src/metadata.ts').length, 1);
    const workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.projectRevision, 2);
    assert.equal(workspace.scanRevision, 2);
    assert.equal(workspace.gateDecision, 'pass');
    assert.match(statusItems[0].text, /connecting.*pass.*1 cached/);
    assert.match(statusItems[0].tooltip, /may be stale/u);
    assert.deepEqual(information, []);
    assert.equal(statusBarMessages.length, 2);
    assert.match(statusBarMessages[0].message, /loaded 1 persisted finding.*completed scan #41/u);
    assert.match(statusBarMessages[1].message, /verified 1 indexed finding.*current revision.*completed scan #41/u);
    assert.deepEqual(statusBarMessages.map(({ timeout }) => timeout), [5_000, 5_000]);
    assert.equal(errors.length, 0);
  });
});


test('explicit reconnect restores the same retained authority without enrollment or browser churn', async () => {
  const requests = [];
  const retained = testActiveAuthority('http://127.0.0.1:8080', 11, 'explicit-reconnect');
  const store = new FakeProfileCredentialStore([retained]);
  await withExtensionFixture({
    profileCredentialStore: store,
    eventStreamFactory: (signal, count) => count === 1
      ? closedReadyEventStream()
      : heldEventStream(signal),
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          revision: 1,
          findings_revision: 1,
          gate_decision: 'fail',
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([finding(1, { file_path: 'src/reconnecting.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, eventStreams, information, statusBarMessages, statusItems }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 20 && !/reconnecting/.test(statusItems[0].text); turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.match(statusItems[0].text, /reconnecting.*fail.*1 cached/);
    assert.match(statusItems[0].tooltip, /may be stale.*reconnect the exact retained IDE profile/u);
    assert.equal(statusItems[0].command, 'lomoCodeSecurity.reconnect');

    await registrations.get(statusItems[0].command)();

    assert.equal(eventStreams(), 2);
    assert.equal(
      requests.filter(({ path }) => (
        path === '/v1/auth/ide/enrollments'
        || path === '/v1/auth/ide/browser-invitations'
      )).length,
      0,
      'reconnect must not create an enrollment or browser invitation',
    );
    assert.deepEqual(store.authorities.get(retained.endpoint), retained);
    assert.equal(
      store.operations.filter(({ operation }) => new Set([
        'writePending',
        'promotePending',
        'discardPending',
        'markRejected',
      ]).has(operation)).length,
      0,
    );
    assert.match(statusItems[0].text, /connected.*fail.*1/u);
    assert.deepEqual(statusBarMessages.at(-1), {
      message: '$(check) CodeSecurity reconnected this exact VS Code profile.',
      timeout: 5_000,
    });
    assert.deepEqual(information, []);
    assert.equal(errors.length, 0);
  });
});


test('endpoint identity change aborts an in-flight refresh and clears old authority state synchronously', async () => {
  let latestReads = 0;
  let pageReads = 0;
  let secondPageSignal;
  let markSecondPageStarted;
  const secondPageStarted = new Promise((resolve) => { markSecondPageStarted = resolve; });
  let releaseSecondPage;
  const secondPage = new Promise((resolve) => { releaseSecondPage = resolve; });
  await withExtensionFixture({
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: latestReads + 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        latestReads += 1;
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          revision: latestReads,
          findings_revision: latestReads,
          gate_decision: 'fail',
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        pageReads += 1;
        if (pageReads === 1) return json(findingPage([finding(1)], 1));
        secondPageSignal = init.signal;
        markSecondPageStarted();
        return secondPage;
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    changeApiBaseUrl,
    entries,
    errors,
    eventStreamSignals,
    statusItems,
    treeProvider,
  }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    assert.equal(entries.size, 1);
    assert.equal(eventStreamSignals().length, 1);

    const pending = refresh();
    await secondPageStarted;
    changeApiBaseUrl('http://127.0.0.1:8090');
    assert.equal(secondPageSignal.aborted, true);
    assert.equal(eventStreamSignals()[0].aborted, true);
    assert.deepEqual([...entries.keys()], []);
    assert.deepEqual(treeProvider().getChildren(), []);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · IDE access required');

    releaseSecondPage(json(findingPage([finding(2)], 2)));
    await pending;
    assert.deepEqual([...entries.keys()], [], 'the old endpoint response must not resurrect Problems');
    assert.deepEqual(treeProvider().getChildren(), []);
    assert.equal(errors.length, 0);
  });
});


test('endpoint change preserves the prior namespace and cannot abort immediate new-endpoint enrollment', async () => {
  const oldAuthority = testActiveAuthority('http://127.0.0.1:8080', 1, 'old-endpoint');
  const newAuthority = testAuthority('http://127.0.0.1:8090', 1, 'new-endpoint');
  const newActiveAuthority = testActiveAuthority('http://127.0.0.1:8090', 1, 'new-endpoint');
  const store = new FakeProfileCredentialStore([oldAuthority]);
  const requests = [];
  await withExtensionFixture({
    extensionMode: 3,
    profileCredentialStore: store,
    streamReady: true,
    route: async (url, init) => {
      requests.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/auth/ide/enrollments') {
        assert.deepEqual(JSON.parse(String(init.body)), {
          client_name: 'VS Code race fixture',
          client_slot: TEST_CLIENT_SLOT,
          expected_active_generation: 0,
        });
        return json(enrollmentEnvelope(newAuthority), 201);
      }
      if (url.pathname === '/v1/auth/ide/enrollments/current/wait') {
        return json(approvedEnrollmentEnvelope(newAuthority));
      }
      if (url.pathname === '/v1/auth/ide/activate') {
        assert.equal(init.headers.Authorization, `Bearer ${newAuthority.capability}`);
        return json(activationEnvelope(newAuthority));
      }
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([finding(1)]));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ testApi, changeApiBaseUrl, errors, statusItems }) => {
    await testApi.refresh();
    changeApiBaseUrl('http://127.0.0.1:8090');
    await testApi.connectIde('VS Code race fixture');

    assert.deepEqual(store.authorities.get(oldAuthority.endpoint), oldAuthority);
    assert.deepEqual(store.authorities.get(newAuthority.endpoint), newActiveAuthority);
    assert.deepEqual(store.pending, new Map());
    assert.deepEqual(
      requests.filter(({ path }) => path.startsWith('/v1/auth/ide/')).map(({ path }) => path),
      ['/v1/auth/ide/enrollments', '/v1/auth/ide/enrollments/current/wait', '/v1/auth/ide/activate'],
    );
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · connected');
    assert.equal(errors.length, 0);
  });
});

test('a capability-revocation 401 immediately tears down Problems, Tree, and the event stream', async () => {
  let revoked = false;
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (revoked) return json({ detail: 'revoked' }, 401);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([finding(1, { file_path: 'src/revoked.ts' })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, eventStreamSignals, statusItems, treeProvider, warnings }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    assert.equal(entries.size, 1);
    assert.equal(eventStreamSignals().length, 1);
    revoked = true;

    await refresh();
    assert.equal(eventStreamSignals()[0].aborted, true);
    assert.deepEqual([...entries.keys()], []);
    assert.deepEqual(treeProvider().getChildren(), []);
    assert.equal(statusItems[0].text, '$(shield) CodeSecurity local · IDE access required');
    assert.equal(warnings.length, 1);
    assert.equal(errors.length, 0);
  });
});


test('decoration signatures include document, aggregate-member, and authoritative workspace revisions', async () => {
  const primary = finding(1, {
    file_path: 'src/signature.ts', start_line: 1, end_line: 1, severity: 'critical', scanner: 'alpha',
  });
  const secondary = finding(2, {
    file_path: 'src/signature.ts', start_line: 1, end_line: 1, severity: 'medium', scanner: 'zeta',
  });
  const changedSecondary = {
    ...secondary,
    id: 2_002,
    fingerprint: 'fingerprint-2002',
    revision: 2,
  };
  const snapshots = [
    { revision: 1, findings: [primary, secondary] },
    { revision: 1, findings: [primary, secondary] },
    { revision: 2, findings: [primary, changedSecondary] },
    { revision: 3, findings: [primary, changedSecondary] },
  ];
  let metadataRead = 0;
  let activeSnapshot = snapshots[0];
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        activeSnapshot = snapshots[Math.min(metadataRead, snapshots.length - 1)];
        metadataRead += 1;
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          findings_revision: activeSnapshot.revision,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage(activeSnapshot.findings, activeSnapshot.revision));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, notifyVisibleTextEditorsChanged, setVisibleTextEditors }) => {
    const uriKey = 'file:///workspace/current/src/signature.ts';
    const lines = ['dangerous();'];
    const document = {
      uri: { path: '/workspace/current/src/signature.ts', toString: () => uriKey },
      version: 1,
      lineCount: 1,
      lineAt: (line) => ({ text: lines[line] }),
      isDirty: false,
    };
    const decorationCalls = [];
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: lines[0].length } }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    }]);
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');

    await refresh();
    for (let turn = 0; turn < 100 && decorationCalls.length < 1; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    let priorCalls = decorationCalls.length;
    lines[0] = 'different();';
    document.version += 1;
    notifyVisibleTextEditorsChanged();
    await refresh();
    for (let turn = 0; turn < 100 && decorationCalls.length < priorCalls + 1; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert.equal(
      decorationCalls.length - priorCalls,
      2,
      'a same-length document edit must invalidate the cached inline surface',
    );

    priorCalls = decorationCalls.length;
    await refresh();
    for (let turn = 0; turn < 100 && decorationCalls.length < priorCalls + 1; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert.equal(
      decorationCalls.length - priorCalls,
      1,
      'a non-primary same-line identity/revision change must invalidate the aggregate projection',
    );
    const inlineAfterSecondaryChange = decorationCalls
      .filter(({ decoration, options }) => decoration.configuration.after && options.length > 0)
      .at(-1).options;
    assert.equal(inlineAfterSecondaryChange[0].renderOptions.after.contentText, '  [CRITICAL · alpha +1 report]');

    priorCalls = decorationCalls.length;
    await refresh();
    for (let turn = 0; turn < 100 && decorationCalls.length < priorCalls + 1; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert.equal(
      decorationCalls.length - priorCalls,
      2,
      'an authoritative workspace revision change must re-render even when finding fields are unchanged',
    );
    assert.equal(errors.length, 0);
  });
});


test('off and detailed annotation modes preserve Problems while changing only native trailing text', async () => {
  const longMessage = `Artifact: app.py Type: Secret AWS Access Key ID Severity: CRITICAL Match: ${'A'.repeat(80)}🔐tail`;
  for (const [mode, expectedLabel] of [
    ['off', undefined],
    ['detailed', '  [S41-F001 · HIGH · fixture]'],
  ]) {
    await withExtensionFixture({
      inlineAnnotations: mode,
      streamReady: false,
      route: async (url) => {
        if (url.pathname === '/v1/projects/resolve') {
          return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
        }
        if (url.pathname === '/v1/projects/7/scans/latest') {
          return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
        }
        if (url.pathname === '/v1/scans/41/findings') {
          return json(findingPage([finding(1, { file_path: 'src/mode.ts', message: longMessage })]));
        }
        throw new Error(`unexpected request GET ${url.pathname}`);
      },
    }, async ({ registrations, entries, errors, provideHover, setVisibleTextEditors, treeProvider }) => {
      const uriKey = 'file:///workspace/current/src/mode.ts';
      const document = {
        uri: { path: '/workspace/current/src/mode.ts', toString: () => uriKey },
        lineCount: 1,
        lineAt: () => ({ text: 'dangerous();' }),
        isDirty: false,
      };
      const decorationCalls = [];
      setVisibleTextEditors([{
        document,
        visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 12 } }],
        setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
      }]);
      await registrations.get('lomoCodeSecurity.refreshFindings')();
      await hydrateTreePath(treeProvider(), 'src/mode.ts');
      assert.equal(entries.get(uriKey).length, 1, `${mode} mode must not remove Problems diagnostics`);
      const [diagnostic] = entries.get(uriKey);
      assert.equal(Array.from(diagnostic.message).length, 48, 'the native Problems hover title stays compact');
      assert.equal(diagnostic.message.endsWith('…'), true, 'native hover truncation is explicit');
      assert.equal(diagnostic.message.includes('\n'), false, 'the native Problems hover stays on one safe line');
      assert.equal(diagnostic.message.includes('\ufffd'), false, 'native hover truncation preserves Unicode points');
      assert.equal(
        provideHover(document, { line: 0, character: 0 }).contents.value.includes(longMessage),
        true,
        'the rich source hover preserves the complete validated detail',
      );
      if (expectedLabel === undefined) {
        assert(decorationCalls.every(({ options }) => options.length === 0));
      } else {
        const inline = decorationCalls.filter(({ decoration }) => decoration.configuration.after).at(-1).options;
        assert.equal(inline.length, 1);
        assert.equal(inline[0].renderOptions.after.contentText, expectedLabel);
      }
      assert.equal(errors.length, 0);
    });
  }
});


test('persisted info findings remain visible in Problems instead of editor-only Hint severity', async () => {
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([finding(1, {
          file_path: 'src/info.ts',
          severity: 'info',
          message: 'Informational finding that still belongs in Problems.',
        })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const [diagnostic] = entries.get('file:///workspace/current/src/info.ts');
    assert.equal(
      diagnostic.severity,
      2,
      'VS Code Problems indexes Information but excludes editor-only Hint severity',
    );
    assert.notEqual(diagnostic.severity, 3);
    assert.equal(errors.length, 0);
  });
});


test('the 5,000-summary hydration bound projects only viewport overscan and coalesces 100 scroll events', async () => {
  const total = 5_000;
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const offset = Number(url.searchParams.get('cursor') || 0);
        const items = Array.from({ length: Math.min(200, total - offset) }, (_, index) => {
          const ordinal = offset + index + 1;
          return finding(ordinal, {
            file_path: 'src/large.ts',
            start_line: ordinal,
            end_line: ordinal,
            scanner: ordinal % 2 === 0 ? 'trivy' : 'opengrep',
          });
        });
        const nextOffset = offset + items.length;
        const nextCursor = nextOffset < total ? String(nextOffset) : null;
        return json({
          items,
          total,
          truncated: nextCursor !== null,
          next_cursor: nextCursor,
          revision: 1,
        });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    changeVisibleRanges,
    decorationTypes,
    deactivate,
    entries,
    errors,
    setVisibleTextEditors,
    visibleRangeListenerDisposed,
  }) => {
    const uriKey = 'file:///workspace/current/src/large.ts';
    const document = {
      uri: { path: '/workspace/current/src/large.ts', toString: () => uriKey },
      lineCount: total,
      lineAt: (line) => ({ text: `line-${line + 1}` }),
      isDirty: false,
    };
    const editor = {
      document,
      visibleRanges: [{ start: { line: 100, character: 0 }, end: { line: 299, character: 0 } }],
      setDecorations: (decoration, options) => decorationCalls.push({ decoration, options }),
    };
    const decorationCalls = [];
    setVisibleTextEditors([editor]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 100; turn += 1) {
      const latestInline = decorationCalls
        .filter(({ decoration }) => decoration.configuration.after)
        .at(-1)?.options;
      if (latestInline?.length === 240) break;
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    assert.equal(errors.length, 0);
    assert.equal(entries.has(uriKey), false, 'Problems stays unavailable above the host-safe 1,000 total');
    const initialProjection = decorationCalls.slice(-1);
    assert.equal(initialProjection.length, 1);
    assert(initialProjection.every(({ options }) => options.length === 240));
    assert.deepEqual(
      initialProjection.map(({ options }) => [options[0].range.start.line, options.at(-1).range.start.line]),
      [[80, 319]],
      'a 200-line viewport receives exactly 20 deterministic overscan lines on each side',
    );

    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    const pending = new Map();
    let timerId = 0;
    globalThis.setTimeout = (callback, _delay, ...arguments_) => {
      const id = ++timerId;
      pending.set(id, () => callback(...arguments_));
      return id;
    };
    globalThis.clearTimeout = (id) => { pending.delete(id); };
    try {
      const callsBeforeScroll = decorationCalls.length;
      for (let event = 0; event < 100; event += 1) {
        const start = 400 + event;
        changeVisibleRanges(editor, [{
          start: { line: start, character: 0 },
          end: { line: start + 199, character: 0 },
        }]);
      }
      assert.equal(pending.size, 1, 'the visible-range listener owns one coalesced render timer');
      const [scheduled] = pending.values();
      pending.clear();
      scheduled();
      const scrollCalls = decorationCalls.slice(callsBeforeScroll);
      assert.equal(scrollCalls.length <= 3, true, '100 synchronous scroll events render no more than three frames');
      assert.equal(scrollCalls.length, 1, 'the synchronous scroll burst coalesces to one render');
      assert.deepEqual(
        scrollCalls.map(({ options }) => [options[0].range.start.line, options.at(-1).range.start.line]),
        [[479, 718]],
        'the coalesced render reads the final editor viewport plus exact overscan',
      );

      changeVisibleRanges(editor, [{ start: { line: 700, character: 0 }, end: { line: 899, character: 0 } }]);
      assert.equal(pending.size, 1);
      deactivate();
      assert.equal(pending.size, 0, 'deactivation cancels the pending visible-range render');
      assert.equal(visibleRangeListenerDisposed(), true);
      assert.deepEqual(
        decorationTypes().map(({ disposed }) => disposed),
        [true],
        'disposing the inline decoration type clears its decorations from every editor',
      );
      changeVisibleRanges(editor, [{ start: { line: 900, character: 0 }, end: { line: 1099, character: 0 } }]);
      assert.equal(pending.size, 0, 'a disposed controller ignores a retained test-listener reference');
    } finally {
      globalThis.setTimeout = originalSetTimeout;
      globalThis.clearTimeout = originalClearTimeout;
    }
    assert.equal(errors.length, 0);
  });
});

test('three visible 2,000-finding files settle without LRU rehydration livelock', async () => {
  const perFile = 2_000;
  const values = Array.from({ length: perFile * 3 }, (_, index) => finding(index + 1, {
    file_path: `src/visible-${Math.floor(index / perFile) + 1}.ts`,
    start_line: index % perFile + 1,
    end_line: index % perFile + 1,
  }));
  const hydrationStarts = new Map();
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        const offset = Number(url.searchParams.get('cursor') || 0);
        const items = values.slice(offset, offset + 200).map(diagnosticItem);
        const next = offset + items.length;
        return json({
          scan_id: 41,
          items,
          total: values.length,
          truncated: next < values.length,
          next_cursor: next < values.length ? String(next) : null,
          revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const filePath = url.searchParams.get('file_path');
        const offset = Number(url.searchParams.get('cursor') || 0);
        if (offset === 0) hydrationStarts.set(filePath, (hydrationStarts.get(filePath) || 0) + 1);
        const fileValues = values.filter((value) => value.file_path === filePath);
        const items = fileValues.slice(offset, offset + 200);
        const next = offset + items.length;
        return json({
          items,
          total: fileValues.length,
          truncated: next < fileValues.length,
          next_cursor: next < fileValues.length ? String(next) : null,
          revision: 1,
        });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, setVisibleTextEditors, treeProvider }) => {
    setVisibleTextEditors([1, 2, 3].map((number) => {
      const uriKey = `file:///workspace/current/src/visible-${number}.ts`;
      const document = {
        uri: { path: `/workspace/current/src/visible-${number}.ts`, toString: () => uriKey },
        version: 1,
        lineCount: perFile,
        lineAt: () => ({ text: 'visible();' }),
        isDirty: false,
      };
      return {
        document,
        visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 20, character: 0 } }],
        setDecorations() {},
      };
    }));
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    let stableTurns = 0;
    let priorStarts = -1;
    for (let turn = 0; turn < 100 && stableTurns < 10; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
      const starts = [...hydrationStarts.values()].reduce((sum, count) => sum + count, 0);
      stableTurns = starts === priorStarts ? stableTurns + 1 : 0;
      priorStarts = starts;
    }
    const settledStarts = [...hydrationStarts.values()].reduce((sum, count) => sum + count, 0);
    const workspace = treeProvider().getChildren()[0].workspace;
    assert(stableTurns >= 10, 'automatic exact-file hydration should settle');
    assert(settledStarts <= 4, `three visible files started ${settledStarts} exact hydration cycles`);
    assert(workspace.findings.length <= 5_000);
    assert(workspace.files.size <= 2);
    for (let turn = 0; turn < 20; turn += 1) await new Promise((resolve) => setImmediate(resolve));
    assert.equal(
      [...hydrationStarts.values()].reduce((sum, count) => sum + count, 0),
      settledStarts,
      'internal native refreshes cannot retry an LRU-evicted visible file',
    );
    assert.equal(errors.length, 0);
  });
});

test('an abort-ignoring 5,000-row hydration retains its reservation until a required replacement can start', async () => {
  const total = 5_000;
  const paths = ['src/held-a.ts', 'src/replacement-b.ts'];
  const aggregate = (path, first) => {
    const value = manifestAggregate(path, [finding(first, { file_path: path })]);
    return {
      ...value,
      first_scan_finding_number: first,
      total,
      active: total,
      blocking: total,
      severity_counts: { ...value.severity_counts, high: total },
      lifecycle_counts: { ...value.lifecycle_counts, open: total },
    };
  };
  const page = (path, first, offset) => {
    const length = Math.min(200, total - offset);
    const items = Array.from({ length }, (_, index) => {
      const ordinal = first + offset + index;
      return finding(ordinal, {
        file_path: path,
        scan_finding_number: ordinal,
        display_id: `S41-F${String(ordinal).padStart(3, '0')}`,
      });
    });
    const next = offset + length;
    return {
      items,
      total,
      truncated: next < total,
      next_cursor: next < total ? String(next) : null,
      revision: 1,
    };
  };
  let markAStarted;
  const aStarted = new Promise((resolve) => { markAStarted = resolve; });
  let releaseA;
  const heldA = new Promise((resolve) => { releaseA = resolve; });
  let bStarts = 0;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json({
          ...hybridManifest([]),
          total_findings: total * 2,
          total_files: 2,
          items: [aggregate(paths[0], 1), aggregate(paths[1], total + 1)],
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const path = url.searchParams.get('file_path');
        const offset = Number(url.searchParams.get('cursor') || 0);
        if (path === paths[0] && offset === 0) {
          markAStarted();
          return heldA; // Deliberately ignore AbortSignal until the fixture releases the response.
        }
        if (path === paths[1] && offset === 0) bStarts += 1;
        return json(page(path, path === paths[0] ? 1 : total + 1, offset));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    errors,
    setVisibleTextEditors,
    notifyVisibleTextEditorsChanged,
    treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const editor = (path) => {
      const uriKey = `file:///workspace/current/${path}`;
      return {
        document: {
          uri: { path: `/workspace/current/${path}`, toString: () => uriKey },
          version: 1,
          lineCount: 1,
          lineAt: () => ({ text: 'visible();' }),
          isDirty: false,
        },
        visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }],
        setDecorations() {},
      };
    };
    setVisibleTextEditors([editor(paths[0])]);
    notifyVisibleTextEditorsChanged();
    await aStarted;

    setVisibleTextEditors([editor(paths[1])]);
    notifyVisibleTextEditorsChanged();
    const workspaceNode = treeProvider().getChildren()[0];
    const bNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')
      .find((node) => node.filePath === paths[1]);
    const bExpansion = treeProvider().getChildren(bNode);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(bStarts, 0, 'replacement cannot start while abort-ignoring A retains 5k rows');

    releaseA(json(page(paths[0], 1, 0)));
    const children = await bExpansion;
    assert.equal(children.length, 1);
    assert.equal(bStarts, 1);
    const workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.files.has(paths[0]), false);
    assert.equal(workspace.files.has(paths[1]), true);
    assert.equal(workspace.findings.length, total);
    assert.equal(errors.length, 0);
  });
});

test('explicit Tree demand promptly preempts an abort-honoring automatic hydration', async () => {
  const automaticPath = 'src/preempt-auto.ts';
  const requiredPath = 'src/preempt-tree.ts';
  const automaticTotal = 5_000;
  const makeAggregate = (path, first, total) => {
    const value = manifestAggregate(path, [finding(first, { file_path: path })]);
    return {
      ...value,
      first_scan_finding_number: first,
      total,
      active: total,
      blocking: total,
      severity_counts: { ...value.severity_counts, high: total },
      lifecycle_counts: { ...value.lifecycle_counts, open: total },
    };
  };
  let markAutomaticStarted;
  const automaticStarted = new Promise((resolve) => { markAutomaticStarted = resolve; });
  let automaticAborted = false;
  let markRequiredStarted;
  const requiredStarted = new Promise((resolve) => { markRequiredStarted = resolve; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json({
          ...hybridManifest([]),
          total_findings: automaticTotal + 1,
          total_files: 2,
          items: [
            makeAggregate(automaticPath, 1, automaticTotal),
            makeAggregate(requiredPath, automaticTotal + 1, 1),
          ],
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const path = url.searchParams.get('file_path');
        if (path === automaticPath) {
          markAutomaticStarted();
          return new Promise((_resolve, reject) => {
            init.signal.addEventListener('abort', () => {
              automaticAborted = true;
              reject(new DOMException('preempted', 'AbortError'));
            }, { once: true });
          });
        }
        markRequiredStarted();
        return json(findingPage([finding(automaticTotal + 1, {
          file_path: requiredPath,
          scan_finding_number: automaticTotal + 1,
        })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    errors,
    setVisibleTextEditors,
    statusBarMessages,
    notifyVisibleTextEditorsChanged,
    treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const automaticUri = `file:///workspace/current/${automaticPath}`;
    setVisibleTextEditors([{
      document: {
        uri: { path: `/workspace/current/${automaticPath}`, toString: () => automaticUri },
        version: 1,
        lineCount: 1,
        lineAt: () => ({ text: 'automatic();' }),
        isDirty: false,
      },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }],
      setDecorations() {},
    }]);
    notifyVisibleTextEditorsChanged();
    await automaticStarted;
    const workspaceNode = treeProvider().getChildren()[0];
    const requiredNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')
      .find((node) => node.filePath === requiredPath);
    const expansion = treeProvider().getChildren(requiredNode);
    await requiredStarted;
    const children = await expansion;
    assert.equal(automaticAborted, true);
    assert.equal(children.length, 1);
    assert.equal(treeProvider().getChildren()[0].workspace.files.has(requiredPath), true);
    assert.equal(errors.length, 0);
    assert.equal(
      statusBarMessages.some(({ message }) => message.includes('could not load rich findings')),
      false,
      'an intentional abort does not surface as a rich-finding failure',
    );
  });
});

test('failed automatic rich hydration signals recovery once and retries on the next editor event', async () => {
  const filePath = 'src/retry-rich.ts';
  const value = finding(1, { file_path: filePath });
  let hydrationStarts = 0;
  let markRetryStarted;
  const retryStarted = new Promise((resolve) => { markRetryStarted = resolve; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([value]));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([value]));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        hydrationStarts += 1;
        if (hydrationStarts === 1) {
          return json({ detail: 'fixture rich evidence is temporarily unavailable' }, 503);
        }
        markRetryStarted();
        return json(findingPage([value]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    changeVisibleRanges,
    errors,
    setVisibleTextEditors,
    statusBarMessages,
    treeProvider,
  }) => {
    const uriKey = `file:///workspace/current/${filePath}`;
    const editor = {
      document: {
        uri: { path: `/workspace/current/${filePath}`, toString: () => uriKey },
        version: 1,
        lineCount: 1,
        lineAt: () => ({ text: 'retry();' }),
        isDirty: false,
      },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }],
      setDecorations() {},
    };
    setVisibleTextEditors([editor]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 100
      && !statusBarMessages.some(({ message }) => message.includes('could not load rich findings'));
      turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    const failureSignals = statusBarMessages
      .filter(({ message }) => message.includes('could not load rich findings'));
    assert.deepEqual(failureSignals, [{
      message: '$(warning) CodeSecurity could not load rich findings for src/retry-rich.ts. Scroll or reopen the file to retry.',
      timeout: 5_000,
    }]);
    assert.equal(hydrationStarts, 1, 'the failed completion frame must not start a retry loop');

    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    let scheduledVisibleRangeUpdate;
    globalThis.setTimeout = (callback) => {
      scheduledVisibleRangeUpdate = callback;
      return 1;
    };
    globalThis.clearTimeout = () => {};
    try {
      changeVisibleRanges(editor, [{
        start: { line: 0, character: 0 },
        end: { line: 0, character: 1 },
      }]);
      assert.equal(typeof scheduledVisibleRangeUpdate, 'function');
      scheduledVisibleRangeUpdate();
      await retryStarted;
      for (let turn = 0; turn < 100
        && !treeProvider().getChildren()[0].workspace.files.has(filePath); turn += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    } finally {
      globalThis.setTimeout = originalSetTimeout;
      globalThis.clearTimeout = originalClearTimeout;
    }
    assert.equal(hydrationStarts, 2, 'the next editor event retries the released automatic attempt');
    assert.equal(treeProvider().getChildren()[0].workspace.files.has(filePath), true);
    assert.equal(
      statusBarMessages.filter(({ message }) => message.includes('could not load rich findings')).length,
      1,
      'one failure emits one bounded recovery signal',
    );
    assert.equal(errors.length, 0);
  });
});

test('a running automatic hydration promoted by Tree demand survives a visibility change', async () => {
  const totals = new Map([['src/priority-a.ts', 2_000], ['src/visible-b.ts', 4_000]]);
  const firsts = new Map([['src/priority-a.ts', 1], ['src/visible-b.ts', 2_001]]);
  const aggregate = (path) => {
    const total = totals.get(path);
    const first = firsts.get(path);
    const value = manifestAggregate(path, [finding(first, { file_path: path })]);
    return {
      ...value,
      first_scan_finding_number: first,
      total,
      active: total,
      blocking: total,
      severity_counts: { ...value.severity_counts, high: total },
      lifecycle_counts: { ...value.lifecycle_counts, open: total },
    };
  };
  const page = (path, offset) => {
    const total = totals.get(path);
    const first = firsts.get(path);
    const length = Math.min(200, total - offset);
    const items = Array.from({ length }, (_, index) => {
      const ordinal = first + offset + index;
      return finding(ordinal, { file_path: path, scan_finding_number: ordinal });
    });
    const next = offset + length;
    return {
      items,
      total,
      truncated: next < total,
      next_cursor: next < total ? String(next) : null,
      revision: 1,
    };
  };
  let markAStarted;
  const aStarted = new Promise((resolve) => { markAStarted = resolve; });
  let releaseA;
  const heldA = new Promise((resolve) => { releaseA = resolve; });
  let markBStarted;
  const bStarted = new Promise((resolve) => { markBStarted = resolve; });
  let releaseB;
  const heldB = new Promise((resolve) => { releaseB = resolve; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json({
          ...hybridManifest([]),
          total_findings: 6_000,
          total_files: 2,
          items: [...totals.keys()].map(aggregate),
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const path = url.searchParams.get('file_path');
        const offset = Number(url.searchParams.get('cursor') || 0);
        if (path === 'src/priority-a.ts' && offset === 0) {
          markAStarted();
          return heldA;
        }
        if (path === 'src/visible-b.ts' && offset === 0) {
          markBStarted();
          return heldB;
        }
        return json(page(path, offset));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    errors,
    setVisibleTextEditors,
    notifyVisibleTextEditorsChanged,
    treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const editor = (path) => {
      const uriKey = `file:///workspace/current/${path}`;
      return {
        document: {
          uri: { path: `/workspace/current/${path}`, toString: () => uriKey },
          version: 1,
          lineCount: 1,
          lineAt: () => ({ text: 'visible();' }),
          isDirty: false,
        },
        visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }],
        setDecorations() {},
      };
    };
    setVisibleTextEditors([editor('src/priority-a.ts')]);
    notifyVisibleTextEditorsChanged();
    await aStarted;
    const workspaceNode = treeProvider().getChildren()[0];
    const fileNodes = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope');
    const aNode = fileNodes.find((node) => node.filePath === 'src/priority-a.ts');
    const aExpansion = treeProvider().getChildren(aNode);

    setVisibleTextEditors([editor('src/visible-b.ts')]);
    notifyVisibleTextEditorsChanged();
    releaseA(json(page('src/priority-a.ts', 0)));
    const aChildren = await aExpansion;
    assert.equal(aChildren.length, 1, 'Tree demand observes A before competing automatic eviction');
    await bStarted;
    const bNode = fileNodes.find((node) => node.filePath === 'src/visible-b.ts');
    const bExpansion = treeProvider().getChildren(bNode);
    releaseB(json(page('src/visible-b.ts', 0)));
    const bChildren = await bExpansion;
    assert.equal(bChildren.length, 1);
    const workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.files.has('src/visible-b.ts'), true);
    assert(workspace.findings.length <= 5_000);
    assert.equal(errors.length, 0);
  });
});

test('initial rich hydration of many open documents stays within the 64-file and 5,000-summary budgets', async () => {
  const files = 101;
  const perFile = 51;
  const values = Array.from({ length: files * perFile }, (_, index) => finding(index + 1, {
    file_path: `src/open-${Math.floor(index / perFile) + 1}.ts`,
    start_line: index % perFile + 1,
    end_line: index % perFile + 1,
  }));
  let hydrationStarts = 0;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        assert.equal(url.searchParams.get('limit'), '200');
        assert.equal(url.searchParams.get('expected_revision'), '1');
        const offset = Number(url.searchParams.get('cursor') || 0);
        const items = values.slice(offset, offset + 200).map(diagnosticItem);
        const next = offset + items.length;
        return json({
          scan_id: 41,
          items,
          total: values.length,
          truncated: next < values.length,
          next_cursor: next < values.length ? String(next) : null,
          revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        hydrationStarts += 1;
        const filePath = url.searchParams.get('file_path');
        const items = values.filter((value) => value.file_path === filePath);
        return json({ items, total: items.length, truncated: false, next_cursor: null, revision: 1 });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, openDocument, treeProvider }) => {
    for (let number = 1; number <= files; number += 1) {
      const uriKey = `file:///workspace/current/src/open-${number}.ts`;
      openDocument({
        uri: { path: `/workspace/current/src/open-${number}.ts`, toString: () => uriKey },
        version: 1,
        lineCount: perFile,
        lineAt: () => ({ text: 'open();' }),
        isDirty: false,
      });
    }
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 200 && hydrationStarts < 64; turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    const workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(hydrationStarts, 64);
    assert.equal(workspace.findings.length, 64 * perFile);
    assert.equal(workspace.files.size, 64);
    assert(workspace.findings.length <= 5_000);
    assert.equal(errors.length, 0);
  });
});

test('five thousand one-finding open documents hydrate at most 64 files with four physical requests', async () => {
  const files = 5_000;
  const values = Array.from({ length: files }, (_, index) => finding(index + 1, {
    file_path: `src/many-open-${index + 1}.ts`,
  }));
  const manifest = hybridManifest(values);
  const byPath = new Map(values.map((value) => [value.file_path, value]));
  let activeRequests = 0;
  let maximumActiveRequests = 0;
  let hydrationStarts = 0;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        const offset = url.searchParams.has('cursor')
          ? Number(url.searchParams.get('cursor')) - 1
          : 0;
        const items = manifest.items.slice(offset, offset + 200);
        const next = offset + items.length;
        return json({
          ...manifest,
          items,
          truncated: next < manifest.items.length,
          next_cursor: next < manifest.items.length ? String(next + 1) : null,
        });
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        assert.equal(url.searchParams.get('limit'), '200');
        assert.equal(url.searchParams.get('expected_revision'), '1');
        const offset = Number(url.searchParams.get('cursor') || 0);
        const items = values.slice(offset, offset + 200).map(diagnosticItem);
        const next = offset + items.length;
        return json({
          scan_id: 41,
          items,
          total: values.length,
          truncated: next < values.length,
          next_cursor: next < values.length ? String(next) : null,
          revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        hydrationStarts += 1;
        activeRequests += 1;
        maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
        await new Promise((resolve) => setImmediate(resolve));
        activeRequests -= 1;
        const value = byPath.get(url.searchParams.get('file_path'));
        assert(value, 'hydration path must belong to the exact manifest');
        return json(findingPage([value]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, openDocument, treeProvider }) => {
    for (let number = 1; number <= files; number += 1) {
      const uriKey = `file:///workspace/current/src/many-open-${number}.ts`;
      openDocument({
        uri: { path: `/workspace/current/src/many-open-${number}.ts`, toString: () => uriKey },
        version: 1,
        lineCount: 1,
        lineAt: () => ({ text: 'open();' }),
        isDirty: false,
      });
    }
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 200
      && (hydrationStarts < 64 || activeRequests > 0); turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    const workspaceNode = treeProvider().getChildren()[0];
    assert.equal(workspaceNode.workspace.totalFiles, files, 'the exact manifest remains complete');
    assert.equal(hydrationStarts, 64, 'initial automatic hydration has a hard file-count bound');
    assert(maximumActiveRequests <= 4, `observed ${maximumActiveRequests} concurrent rich requests`);
    assert.equal(workspaceNode.workspace.files.size, 64);
    assert.equal(workspaceNode.workspace.findings.length, 64);
    assert.equal(errors.length, 0);
  });
});

test('a pre-dirty document is stale before manifest diagnostics can publish', async () => {
  const value = finding(1, { file_path: 'src/dirty.ts' });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([value]));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') return json(hybridDiagnosticPage([value]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    openDocument,
    provideCodeActions,
    provideHover,
    setVisibleTextEditors,
    statusItems,
  }) => {
    const uriKey = 'file:///workspace/current/src/dirty.ts';
    const document = {
      uri: { path: '/workspace/current/src/dirty.ts', toString: () => uriKey },
      version: 7,
      lineCount: 1,
      lineAt: () => ({ text: 'dirty();' }),
      isDirty: true,
    };
    const editor = {
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 8 } }],
      setDecorations() {},
    };
    setVisibleTextEditors([editor]);
    openDocument(document);
    await registrations.get('lomoCodeSecurity.refreshFindings')();

    assert.equal(entries.size, 0);
    assert.match(statusItems[0].text, /1 stale/);
    assert.equal(provideHover(document, { line: 0, character: 0 }), undefined);
    assert.deepEqual(provideCodeActions(document, {
      start: { line: 0, character: 0 },
      end: { line: 0, character: 1 },
    }), []);
    assert.equal(errors.length, 0);
  });
});

test('edit, save, and close while the first manifest is held remains stale until a newer scan', async () => {
  let scanId = 41;
  let releaseFirstManifest;
  const firstManifest = new Promise((resolve) => { releaseFirstManifest = resolve; });
  let markManifestRequested;
  const manifestRequested = new Promise((resolve) => { markManifestRequested = resolve; });
  const valueForScan = () => finding(scanId, {
    scan_id: scanId,
    scan_finding_number: 1,
    display_id: `S${scanId}-F001`,
    file_path: 'src/changed-before-ownership.ts',
  });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const value = valueForScan();
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: scanId, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        markManifestRequested();
        return firstManifest;
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-files`) {
        return json(hybridManifest([value], 1, { id: scanId }));
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-diagnostics`) {
        return json({ ...hybridDiagnosticPage([value], 1), scan_id: scanId });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, entries, errors, openDocument, changeDocument, closeDocument, treeProvider,
  }) => {
    const pending = registrations.get('lomoCodeSecurity.refreshFindings')();
    await manifestRequested;
    const uriKey = 'file:///workspace/current/src/changed-before-ownership.ts';
    const document = {
      uri: { path: '/workspace/current/src/changed-before-ownership.ts', toString: () => uriKey },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'changed();' }),
      isDirty: true,
    };
    openDocument(document);
    changeDocument(document);
    document.isDirty = false;
    closeDocument(document);
    releaseFirstManifest(json(hybridManifest([valueForScan()], 1)));
    await pending;

    assert.deepEqual([...treeProvider().getChildren()[0].workspace.staleFiles], ['src/changed-before-ownership.ts']);
    assert.equal(entries.has(uriKey), false);

    scanId = 42;
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    assert.deepEqual([...treeProvider().getChildren()[0].workspace.staleFiles], []);
    assert.equal(entries.get(uriKey).length, 1);
    assert.equal(errors.length, 0);
  });
});

test('overflowed document-change history stays fail-closed for the same scan and clears on a newer scan', async () => {
  let scanId = 41;
  let manifestReads = 0;
  let releaseFirstManifest;
  const firstManifest = new Promise((resolve) => { releaseFirstManifest = resolve; });
  let markManifestRequested;
  const manifestRequested = new Promise((resolve) => { markManifestRequested = resolve; });
  const valueForScan = () => finding(scanId, {
    scan_id: scanId,
    scan_finding_number: 1,
    display_id: `S${scanId}-F001`,
    file_path: 'src/history-0.ts',
  });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const value = valueForScan();
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: scanId, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        manifestReads += 1;
        if (manifestReads === 1) {
          markManifestRequested();
          return firstManifest;
        }
        return json(hybridManifest([value], 1));
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-files`) {
        return json(hybridManifest([value], 1, { id: scanId }));
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-diagnostics`) {
        return json({ ...hybridDiagnosticPage([value], 1), scan_id: scanId });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    openDocument,
    changeDocument,
    closeDocument,
    statusItems,
    treeProvider,
  }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    const pending = refresh();
    await manifestRequested;
    for (let index = 0; index < 513; index += 1) {
      const uriKey = `file:///workspace/current/src/history-${index}.ts`;
      const document = {
        uri: { path: `/workspace/current/src/history-${index}.ts`, toString: () => uriKey },
        version: 1,
        lineCount: 1,
        lineAt: () => ({ text: 'changed();' }),
        isDirty: true,
      };
      openDocument(document);
      changeDocument(document);
      document.isDirty = false;
      closeDocument(document);
    }
    releaseFirstManifest(json(hybridManifest([valueForScan()], 1)));
    await pending;

    let workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.allFilesStale, true);
    assert.equal(workspace.diagnosticProjection, 'complete');
    assert.equal(workspace.findings.length, 0);
    assert.equal(workspace.files.size, 0);
    assert.equal(entries.size, 0);
    assert.match(statusItems[0].text, /1 stale/);
    assert.doesNotMatch(statusItems[0].text, /Problems 0\/1/);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Too many documents changed/);

    await refresh();
    workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.allFilesStale, true, 'same-scan refresh cannot forget overflowed edits');
    assert.equal(workspace.diagnosticProjection, 'complete');
    assert.equal(workspace.findings.length, 0);
    assert.equal(workspace.files.size, 0);
    assert.equal(entries.size, 0, 'same-scan compact Problems stay suppressed');

    scanId = 42;
    await refresh();
    workspace = treeProvider().getChildren()[0].workspace;
    assert.equal(workspace.allFilesStale, false);
    assert.equal(entries.get('file:///workspace/current/src/history-0.ts').length, 1);
    assert.equal(errors.length, 1);
  });
});

test('edit then save stays stale across a same-scan lifecycle revision and clears only on a new scan', async () => {
  let scanId = 41;
  let revision = 1;
  const currentFinding = () => finding(1, {
    scan_id: scanId,
    scan_finding_number: 1,
    display_id: `S${scanId}-F001`,
    file_path: 'src/saved-without-rescan.ts',
    message: scanId === 41 ? `same scan revision ${revision}` : 'new scan evidence',
    revision,
  });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const value = currentFinding();
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: scanId, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-files`) {
        const manifest = hybridManifest([value], revision);
        return json({ ...manifest, scan: { ...manifest.scan, id: scanId } });
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-diagnostics`) {
        return json({ ...hybridDiagnosticPage([value], revision), scan_id: scanId });
      }
      if (url.pathname === `/v1/scans/${scanId}/findings`) {
        return json(findingPage([value], revision));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, changeDocument, entries, errors, openDocument, provideHover, setVisibleTextEditors, statusItems,
  }) => {
    const uriKey = 'file:///workspace/current/src/saved-without-rescan.ts';
    const document = {
      uri: { path: '/workspace/current/src/saved-without-rescan.ts', toString: () => uriKey },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'changedAfterScan();' }),
      isDirty: false,
    };
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 19 } }],
      setDecorations() {},
    }]);
    openDocument(document);
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    assert.equal(entries.get(uriKey).length, 1);

    document.isDirty = true;
    document.version += 1;
    changeDocument(document);
    document.isDirty = false;
    revision = 2;
    await refresh();
    assert.equal(entries.has(uriKey), false, 'saving alone does not make disk-scan evidence current');
    assert.equal(provideHover(document, { line: 0, character: 0 }), undefined);
    assert.match(statusItems[0].text, /1 stale/);

    scanId = 42;
    revision = 1;
    await refresh();
    assert.equal(entries.get(uriKey).length, 1);
    assert.equal(entries.get(uriKey)[0].message, 'new scan evidence');
    assert.doesNotMatch(statusItems[0].text, /stale/);
    assert.equal(errors.length, 0);
  });
});

test('open then immediate edit marks manifest ownership stale before rich hydration completes', async () => {
  const value = finding(1, { file_path: 'src/race.ts' });
  let markHydrationStarted;
  const hydrationStarted = new Promise((resolve) => { markHydrationStarted = resolve; });
  let releaseHydration;
  const hydration = new Promise((resolve) => { releaseHydration = resolve; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([value]));
      if (url.pathname === '/v1/scans/41/findings') {
        markHydrationStarted();
        return hydration;
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') return json(hybridDiagnosticPage([value]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, changeDocument, entries, errors, openDocument, setVisibleTextEditors, statusItems, warnings,
  }) => {
    const uriKey = 'file:///workspace/current/src/race.ts';
    const document = {
      uri: { path: '/workspace/current/src/race.ts', toString: () => uriKey },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'race();' }),
      isDirty: false,
    };
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 7 } }],
      setDecorations() {},
    }]);
    openDocument(document);
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings')();
    await hydrationStarted;
    document.isDirty = true;
    document.version += 1;
    changeDocument(document);
    releaseHydration(json(findingPage([value], 1)));
    await refresh;

    assert.equal(entries.size, 0);
    assert.match(statusItems[0].text, /1 stale/);
    assert.equal(warnings.length, 1);
    assert.equal(errors.length, 0);
  });
});

test('aborted new-revision Problems build retains old diagnostics without exposing uncommitted rich rows', async () => {
  const oldValue = finding(1, { file_path: 'src/atomic.ts', start_line: 1, end_line: 1, message: 'old problem' });
  const newValues = [
    finding(1, { file_path: 'src/atomic.ts', start_line: 5, end_line: 5, message: 'new first', revision: 2 }),
    finding(2, { file_path: 'src/atomic.ts', start_line: 6, end_line: 6, message: 'new second', revision: 2 }),
  ];
  let revision = 1;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const values = revision === 1 ? [oldValue] : newValues;
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(values, revision));
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(values, revision));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        if (revision === 2) throw new DOMException('superseded fixture', 'AbortError');
        return json(hybridDiagnosticPage(values, revision));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, entries, errors, openDocument, provideCodeActions, provideHover, setVisibleTextEditors,
  }) => {
    const uriKey = 'file:///workspace/current/src/atomic.ts';
    const document = {
      uri: { path: '/workspace/current/src/atomic.ts', toString: () => uriKey },
      version: 1,
      lineCount: 8,
      lineAt: () => ({ text: 'atomic();' }),
      isDirty: false,
    };
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 7, character: 8 } }],
      setDecorations() {},
    }]);
    openDocument(document);
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    assert.equal(entries.get(uriKey)[0].message, 'old problem');

    revision = 2;
    await refresh();
    assert.equal(entries.get(uriKey).length, 1);
    assert.equal(entries.get(uriKey)[0].message, 'old problem');
    assert.equal(provideHover(document, { line: 0, character: 0 }), undefined);
    assert.equal(provideHover(document, { line: 4, character: 0 }), undefined);
    const actions = provideCodeActions(document, {
      start: { line: 4, character: 0 },
      end: { line: 4, character: 1 },
    });
    assert.deepEqual(actions, []);
    assert.equal(errors.length, 0);
  });
});

test('same findings revision on a newer scan cannot reproject retained Problems before the atomic swap', async () => {
  const oldValue = finding(1, {
    scan_id: 41,
    file_path: 'src/scan-atomic.ts',
    start_line: 1,
    end_line: 1,
    message: 'scan 41 retained problem',
  });
  const newValue = finding(1, {
    scan_id: 42,
    file_path: 'src/scan-atomic.ts',
    start_line: 5,
    end_line: 5,
    message: 'scan 42 uncommitted rich evidence',
  });
  let scanId = 41;
  let markCompactStarted;
  const compactStarted = new Promise((resolve) => { markCompactStarted = resolve; });
  let rejectCompact;
  const heldCompact = new Promise((_resolve, reject) => { rejectCompact = reject; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const value = scanId === 41 ? oldValue : newValue;
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: scanId });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: scanId, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === `/v1/scans/${scanId}/finding-files`) {
        return json(hybridManifest([value], 1, { id: scanId, revision: 1, findings_revision: 1 }));
      }
      if (url.pathname === `/v1/scans/${scanId}/findings`) {
        return json(findingPage([value], 1));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json({ ...hybridDiagnosticPage([oldValue], 1), scan_id: 41 });
      }
      if (url.pathname === '/v1/scans/42/finding-diagnostics') {
        markCompactStarted();
        return heldCompact;
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, openDocument, treeProvider }) => {
    const uriKey = 'file:///workspace/current/src/scan-atomic.ts';
    const document = {
      uri: { path: '/workspace/current/src/scan-atomic.ts', toString: () => uriKey },
      version: 1,
      lineCount: 8,
      lineAt: () => ({ text: 'atomic();' }),
      isDirty: false,
    };
    openDocument(document);
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    let workspaceNode = treeProvider().getChildren()[0];
    let fileNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    await treeProvider().getChildren(fileNode);
    assert.equal(entries.get(uriKey)[0].message, 'scan 41 retained problem');

    scanId = 42;
    const newScanRefresh = refresh();
    await compactStarted;
    workspaceNode = treeProvider().getChildren()[0];
    fileNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    const richChildren = await treeProvider().getChildren(fileNode);
    assert.equal(richChildren.length, 1);
    const currentWorkspace = treeProvider().getChildren()[0].workspace;
    assert.equal(
      currentWorkspace.files.get('src/scan-atomic.ts')[0].message,
      'scan 42 uncommitted rich evidence',
    );
    assert.equal(entries.get(uriKey).length, 1);
    assert.equal(entries.get(uriKey)[0].message, 'scan 41 retained problem');

    rejectCompact(new DOMException('superseded compact projection', 'AbortError'));
    await newScanRefresh;
    assert.equal(entries.get(uriKey).length, 1);
    assert.equal(entries.get(uriKey)[0].message, 'scan 41 retained problem');
    assert.equal(errors.length, 0);
  });
});

test('diagnostic revision drift never replaces the prior atomic Problems projection', async () => {
  const first = finding(1, { file_path: 'src/drift.ts', message: 'stable old problem' });
  const second = finding(1, { file_path: 'src/drift.ts', message: 'drifting new problem', revision: 2 });
  let revision = 1;
  let manifestReads = 0;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const value = revision === 1 ? first : second;
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        manifestReads += 1;
        return json(hybridManifest([value], revision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([value], revision === 1 ? 1 : 3));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    revision = 2;
    await refresh();

    assert.equal(entries.get('file:///workspace/current/src/drift.ts')[0].message, 'stable old problem');
    assert.equal(manifestReads, 4, 'initial projection plus three bounded revision-drift attempts');
    assert.equal(errors.length, 1);
  });
});

test('compact diagnostics must match every manifest file count before atomic publication', async () => {
  let revision = 1;
  const first = finding(1, { file_path: 'src/a.ts', message: 'stable a' });
  const second = finding(2, { file_path: 'src/b.ts', message: 'stable b' });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      const current = [
        { ...first, revision, message: revision === 1 ? 'stable a' : 'new a' },
        { ...second, revision, message: revision === 1 ? 'stable b' : 'new b' },
      ];
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision, findings_revision: revision });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(current, revision));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        const diagnostics = current.map(diagnosticItem);
        if (revision === 2) diagnostics[1] = { ...diagnostics[1], file_path: 'src/a.ts' };
        return json({
          scan_id: 41,
          items: diagnostics,
          total: 2,
          truncated: false,
          next_cursor: null,
          revision,
        });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, treeProvider }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    revision = 2;
    await refresh();

    assert.equal(entries.get('file:///workspace/current/src/a.ts')[0].message, 'stable a');
    assert.equal(entries.get('file:///workspace/current/src/b.ts')[0].message, 'stable b');
    assert.equal(treeProvider().getChildren()[0].workspace.diagnosticProjection, 'loading');
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /per-file manifest counts/);
  });
});

test('above 1,000 findings keeps exact manifest Tree/status while Problems is visibly unavailable', async () => {
  let diagnosticReads = 0;
  const aggregate = manifestAggregate('src/huge.ts', [finding(1, { file_path: 'src/huge.ts' })]);
  aggregate.total = 1_001;
  aggregate.active = 1_001;
  aggregate.blocking = 1_001;
  aggregate.severity_counts.high = 1_001;
  aggregate.lifecycle_counts.open = 1_001;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json({
          ...hybridManifest([], 1),
          total_findings: 1_001,
          total_files: 1,
          items: [aggregate],
        });
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') diagnosticReads += 1;
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, statusItems, statusBarMessages, treeProvider, warnings }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    const workspaceNode = treeProvider().getChildren()[0];
    const fileNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    assert.match(statusItems[0].text, /1001.*Problems unavailable/);
    assert.equal(treeProvider().getTreeItem(fileNode).description, '1001');
    assert.equal(entries.size, 0);
    assert.equal(diagnosticReads, 0);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /indexed 1001 persisted findings.*Problems is unavailable above/);
    await refresh();
    assert.match(statusBarMessages.at(-1).message, /verified 1001 indexed findings.*Problems unavailable/);
    assert.match(statusBarMessages.at(-1).message, /exact Findings tree remains available/);
    assert.doesNotMatch(statusBarMessages.at(-1).message, /undefined/);
    assert.equal(warnings.length, 1, 'an unchanged refresh must not repeat the initial modal warning');
    assert.equal(entries.size, 0);
    assert.equal(diagnosticReads, 0);
    assert.equal(errors.length, 0);
  });
});


test('limited multi-root refresh reports indexed counts and preserves unchanged sibling Problems', async () => {
  const roots = ['sibling', 'current'].map((name) => ({ name, uri: {
    scheme: 'file', authority: '', path: `/workspace/${name}`, fsPath: `/workspace/${name}`,
    toString: () => `file:///workspace/${name}`,
  } }));
  const path = 'src/huge.ts';
  const sibling = finding(1, { scan_id: 42, file_path: path });
  const aggregate = manifestAggregate(path, [finding(1, { file_path: path })]);
  aggregate.total = 1_001;
  aggregate.active = 1_001;
  aggregate.blocking = 1_001;
  aggregate.severity_counts.high = 1_001;
  aggregate.lifecycle_counts.open = 1_001;
  let manifestReads = 0;
  let diagnosticReads = 0;
  const summaries = [];
  await withExtensionFixture({
    workspaceFolders: roots,
    strictHybridRoutes: true,
    streamReady: false,
    quickPick: (items, options) => {
      assert.equal(options.title, 'CodeSecurity · refreshed workspace folders');
      summaries.push(items);
      return undefined;
    },
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        const { repo_path } = JSON.parse(init.body);
        assert(roots.some((root) => root.uri.path === repo_path));
        return json({ id: repo_path.endsWith('/current') ? 7 : 8, name: repo_path.split('/').at(-1),
          repo_path, revision: 1 });
      }
      const latest = /^\/v1\/projects\/([78])\/scans\/latest$/.exec(url.pathname);
      if (latest) return json({ id: Number(latest[1]) + 34, project_id: Number(latest[1]),
        status: 'completed', revision: 1, findings_revision: 1, gate_decision: 'fail' });
      if (url.pathname === '/v1/scans/41/finding-files') {
        manifestReads += 1;
        return json({ ...hybridManifest([], 1), total_findings: 1_001, total_files: 1, items: [aggregate] });
      }
      if (url.pathname === '/v1/scans/42/finding-files') {
        manifestReads += 1;
        return json(hybridManifest([sibling], 1, { id: 42, project_id: 8 }));
      }
      if (url.pathname === '/v1/scans/42/finding-diagnostics') {
        diagnosticReads += 1;
        return json({ ...hybridDiagnosticPage([sibling]), scan_id: 42 });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, collection, errors, treeProvider, warnings }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    assert.deepEqual(summaries[0].map((item) => item.description), ['loaded', 'limited']);
    const siblingProblems = entries.get('file:///workspace/sibling/src/huge.ts');
    assert.equal(siblingProblems.length, 1);
    assert.equal(entries.size, 1, 'the limited root must not replace the sibling with identical relative filenames');
    const batches = collection.batches;
    const siblingBefore = treeProvider().getChildren().find((node) => node.workspace.key === roots[0].uri.toString()).workspace;
    await refresh();
    assert.deepEqual(summaries[1].map((item) => item.description), ['unchanged', 'unchanged']);
    for (const summary of summaries) {
      assert.equal(summary[0].detail, '/workspace/sibling · 1 finding · scan #42');
      assert.equal(summary[1].detail,
        '/workspace/current · 1001 findings · scan #41 · Problems unavailable; exact Findings tree remains available.');
    }
    assert.equal(entries.get('file:///workspace/sibling/src/huge.ts'), siblingProblems);
    assert.equal(entries.size, 1);
    assert.equal(collection.batches, batches, 'unchanged refresh must not republish sibling Problems');
    assert.deepEqual(treeProvider().getChildren().find((node) => node.workspace.key === roots[0].uri.toString()).workspace,
      siblingBefore);
    assert.equal(manifestReads, 2, 'unchanged revisions reuse both exact manifests');
    assert.equal(diagnosticReads, 1, 'only the supported sibling projection loads diagnostics');
    assert.deepEqual(warnings, []);
    assert.deepEqual(errors, []);
  });
});


test('one file above the 5,000 rich bound expands to an exact-scan action without hydration or retained rows', async () => {
  const path = 'src/one-oversized-file.ts';
  const aggregate = manifestAggregate(path, [finding(1, { file_path: path })]);
  aggregate.total = 5_001;
  aggregate.active = 5_001;
  aggregate.blocking = 5_001;
  aggregate.severity_counts.high = 5_001;
  aggregate.lifecycle_counts.open = 5_001;
  let hydrationReads = 0;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json({
          ...hybridManifest([], 1),
          total_findings: 5_001,
          total_files: 1,
          items: [aggregate],
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        hydrationReads += 1;
        throw new Error('oversized file rich hydration must not start');
      }
      throw new Error(`unexpected request GET ${url.pathname}${url.search}`);
    },
  }, async ({ registrations, entries, errors, opened, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const workspaceNode = tree.getChildren()[0];
    const fileNode = tree.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    assert.equal(fileNode.total, 5_001);
    assert.equal(tree.getTreeItem(fileNode).description, '5001');
    const children = await tree.getChildren(fileNode);
    assert.equal(children.length, 1);
    const action = tree.getTreeItem(children[0]);
    assert.match(action.description, /5,001 exact findings.*5,000/);
    assert.deepEqual(action.command.arguments, [41]);
    await registrations.get(action.command.command)(...action.command.arguments);

    const openedUrl = new URL(opened[0]);
    assert.equal(openedUrl.searchParams.get('view'), 'findings');
    assert.equal(openedUrl.searchParams.get('scan'), '41');
    assert.equal(hydrationReads, 0);
    assert.equal(entries.size, 0);
    const workspace = tree.getChildren()[0].workspace;
    assert.equal(workspace.findings.length, 0);
    assert.equal(workspace.files.size, 0);
    assert.equal(errors.length, 0);
  });
});


test('an exact-file response for another manifest path rejects Tree hydration without committing rich rows', async () => {
  const expected = finding(1, { file_path: 'src/expected.ts' });
  const substituted = finding(1, { file_path: 'src/substituted.ts' });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([expected], 1));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([expected], 1));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        assert.equal(url.searchParams.get('file_path'), expected.file_path);
        return json(findingPage([substituted], 1));
      }
      throw new Error(`unexpected request GET ${url.pathname}${url.search}`);
    },
  }, async ({ registrations, entries, errors, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const workspaceNode = tree.getChildren()[0];
    const fileNode = tree.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    await assert.rejects(tree.getChildren(fileNode), (error) => (
      error.status === 409
      && error.retryable === true
      && /file identity/.test(error.message)
    ));

    const workspace = tree.getChildren()[0].workspace;
    assert.equal(workspace.findings.length, 0);
    assert.equal(workspace.files.size, 0);
    assert.equal(entries.get('file:///workspace/current/src/expected.ts').length, 1);
    assert.equal(errors.length, 0);
  });
});


test('a same-file rich response that contradicts manifest lifecycle aggregates is rejected atomically', async () => {
  const expected = finding(1, { file_path: 'src/expected.ts' });
  const substituted = finding(1, {
    file_path: expected.file_path,
    lifecycle_status: 'fixed',
    suppressed: true,
    gate_effect: 'excluded',
  });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([expected], 1));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([expected], 1));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        assert.equal(url.searchParams.get('file_path'), expected.file_path);
        return json(findingPage([substituted], 1));
      }
      throw new Error(`unexpected request GET ${url.pathname}${url.search}`);
    },
  }, async ({ registrations, entries, errors, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const workspaceNode = tree.getChildren()[0];
    const fileNode = tree.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    await assert.rejects(tree.getChildren(fileNode), (error) => (
      error.status === 409
      && error.retryable === true
      && /file identity/.test(error.message)
    ));

    const workspace = tree.getChildren()[0].workspace;
    assert.equal(workspace.findings.length, 0);
    assert.equal(workspace.files.size, 0);
    assert.equal(entries.get('file:///workspace/current/src/expected.ts').length, 1);
    assert.equal(errors.length, 0);
  });
});


test('above 1,000 distinct files publishes complete Problems through bounded replacements', async () => {
  const total = 1_001;
  let diagnosticReads = 0;
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        const offset = Number(url.searchParams.get('cursor') || 0);
        const count = Math.min(200, total - offset);
        const items = Array.from({ length: count }, (_, index) => {
          const ordinal = offset + index + 1;
          return {
            file_path: `src/distinct-${ordinal}.ts`,
            first_scan_finding_number: ordinal,
            total: 1,
            active: 1,
            suppressed: 0,
            gate_exempt: 0,
            blocking: 1,
            severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
            lifecycle_counts: {
              open: 1, needs_review: 0, gate_exempt: 0, accepted_risk: 0,
              ignore: 0, false_positive: 0, fixed: 0,
            },
          };
        });
        const next = offset + count;
        return json({
          scan: {
            id: 41,
            project_id: 7,
            status: 'completed',
            gate_decision: 'fail',
            gate_reasons: [],
            error: null,
            revision: 1,
            findings_revision: 1,
          },
          total_findings: total,
          total_files: total,
          items,
          truncated: next < total,
          next_cursor: next < total ? String(next) : null,
        });
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        diagnosticReads += 1;
        const offset = Number(url.searchParams.get('cursor') || 0);
        const count = Math.min(200, total - offset);
        const rows = Array.from({ length: count }, (_, index) => finding(offset + index + 1, {
          file_path: `src/distinct-${offset + index + 1}.ts`,
        }));
        return json({
          ...hybridDiagnosticPage(rows, 1), total,
          truncated: offset + count < total,
          next_cursor: offset + count < total ? String(offset + count) : null,
        });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, statusItems, treeProvider, warnings }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const workspaceNode = treeProvider().getChildren()[0];
    const pageNodes = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope');
    assert.match(statusItems[0].text, /1001/);
    assert.doesNotMatch(statusItems[0].text, /Problems unavailable/);
    assert.equal(pageNodes.length, 6);
    assert.equal(treeProvider().getChildren(pageNodes[0]).length, 200);
    assert.equal(entries.size, total);
    assert.equal(diagnosticReads, 6);
    assert.equal(workspaceNode.workspace.diagnosticProjection, 'complete');
    assert.equal(warnings.length, 0);
    assert.equal(errors.length, 0);
  });
});


test('cancel button persists one supported cancellation and waits for cleanup confirmation', async () => {
  const calls = [];
  let cancelProgress;
  await withExtensionFixture({
    captureProgressCancellation: ({ cancel }) => { cancelProgress = cancel; },
    route: async (url, init) => {
      calls.push(`${init.method || 'GET'} ${url.pathname}`);
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        cancelProgress();
        return json({ id: 41, project_id: 7, status: 'pending', job_id: 71 }, 202);
      }
      if (url.pathname === '/v1/jobs/71' && init.method !== 'POST') {
        return json({
          id: 71, kind: 'scan', title: 'Scan #41', status: 'running', stage: 'scanner', progress: 20,
          scan_id: 41, attempt: 1, max_attempts: 3, revision: 2, can_cancel: true, can_retry: false,
        });
      }
      if (url.pathname === '/v1/jobs/71/cancel') {
        return json({
          id: 71, kind: 'scan', title: 'Scan #41', status: 'cancelled', stage: 'cancelled', progress: 20,
          scan_id: 41, attempt: 1, max_attempts: 3, revision: 3, can_cancel: false, can_retry: false,
        });
      }
      if (url.pathname === '/v1/scans/41') {
        return json({ id: 41, project_id: 7, status: 'cancelled', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([]));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, information, errors }) => {
    await registrations.get('lomoCodeSecurity.scanWorkspace')();
    assert.equal(errors.length, 0);
    assert(information.some((message) => /cleanup is confirmed/.test(message)));
  });

  assert.equal(calls.filter((call) => call === 'POST /v1/jobs/71/cancel').length, 1);
});


test('native snapshot cancellation before admission aborts local work without inventing a job cancellation', async () => {
  const windowsFolder = {
    name: 'native-windows',
    uri: {
      scheme: 'file',
      authority: '',
      path: '/C:/work/project',
      fsPath: String.raw`C:\work\project`,
      toString: () => 'file:///C:/work/project',
    },
  };
  const lifecycle = [];
  const calls = [];
  let cancelProgress;
  let snapshotSignal;
  await withExtensionFixture({
    captureProgressCancellation: ({ options, cancel }) => {
      assert.deepEqual(options, {
        location: 15,
        title: 'CodeSecurity: native-windows',
        cancellable: true,
      });
      cancelProgress = cancel;
    },
    progressLifecycle: (event) => lifecycle.push(event),
    snapshotCollector: async (_target, signal) => {
      snapshotSignal = signal;
      assert.equal(signal.aborted, false);
      cancelProgress();
      assert.equal(signal.aborted, true, 'pre-admission cancellation aborts the snapshot signal synchronously');
      throw new DOMException('snapshot stopped by user', 'AbortError');
    },
    workspaceFolders: [windowsFolder],
    route: async (url, init) => {
      calls.push(`${init.method || 'GET'} ${url.pathname}`);
      throw new Error(`cancelled snapshot must not request ${url.pathname}`);
    },
  }, async ({ registrations, errors, information, reports, snapshotCollections }) => {
    await registrations.get('lomoCodeSecurity.scanWorkspace')();
    assert.equal(snapshotSignal.aborted, true);
    assert.equal(snapshotCollections.length, 1);
    assert.equal(errors.length, 0, 'user cancellation is not an error prompt');
    assert.equal(information.length, 0, 'no durable job exists to report');
    assert(reports.some(({ message }) => message === 'collecting the selected native Windows source snapshot'));
    assert(reports.some(({ message }) => message === 'saving cancellation request'));
  });

  assert.deepEqual(lifecycle, ['started', 'cancel-requested', 'resolved', 'settled']);
  assert.deepEqual(calls, []);
  assert.equal(calls.some((call) => /\/v1\/jobs\/[1-9][0-9]*\/cancel/u.test(call)), false);
});

test('native collection refuses missing and malformed backend transfer capabilities before source reads', async () => {
  const windowsFolder = { name: 'native', uri: { scheme: 'file', authority: '', path: '/C:/work/project',
    fsPath: String.raw`C:\work\project`, toString: () => 'file:///C:/work/project' } };
  for (const health of [{ ok: true }, { source_snapshot_limits: { schema_version: 1, max_file_bytes: 8_388_608 } }]) {
    await withExtensionFixture({ workspaceFolders: [windowsFolder], sourceTransferHealth: health,
      snapshotCollector: async () => { throw new Error('source collection must not start'); },
      route: async () => { throw new Error('no source admission or project request is allowed'); },
    }, async ({ registrations, errors, snapshotCollections }) => {
      await registrations.get('lomoCodeSecurity.scanWorkspace')();
      assert.equal(snapshotCollections.length, 0);
      assert.match(errors.at(-1).message, /source-transfer contract/);
    });
  }
});

test('Getting Started opens one owned six-step guide and uses only public health without claiming connection', async () => {
  await withExtensionFixture({ sourceTransferHealth: { ok: true },
    route: async () => { throw new Error('opening Getting Started must not request source or credentials'); },
  }, async ({ registrations, executedCommands, setupContexts, setupPanels, errors }) => {
    await registrations.get('lomoCodeSecurity.gettingStarted')();
    assert.deepEqual(executedCommands, []);
    assert.equal(setupPanels.length, 1);
    assert.equal(setupPanels[0].viewType, 'lomoCodeSecurity.setup');
    assert.deepEqual(setupPanels[0].options, { enableScripts: true, enableCommandUris: false, localResourceRoots: [] });
    assert.equal((setupPanels[0].webview.html.match(/<section /g) || []).length, 6);
    setupPanels[0].message({ type: 'ready' });
    assert.equal(setupPanels[0].messages.at(-1).steps.backend, true);
    assert.equal(setupContexts.get('lomoCodeSecurity.setup.backend'), true);
    assert.equal(setupContexts.get('lomoCodeSecurity.setup.connection'), false);
    assert.equal(setupContexts.get('lomoCodeSecurity.setup.scan'), false);
    assert.deepEqual(errors, []);
  });
});

test('Getting Started refuses to publish pending public health after endpoint or trust invalidation', async () => {
  for (const invalidation of ['endpoint', 'trust']) {
    let started;
    const requestStarted = new Promise(resolve => { started = resolve; });
    let release;
    const requestRelease = new Promise(resolve => { release = resolve; });
    await withExtensionFixture({
      sourceTransferHealth: async () => { started(); await requestRelease; return json({ ok: true }); },
      route: async () => { throw new Error('opening Getting Started must not request source or credentials'); },
    }, async ({ registrations, setupContexts, errors, changeApiBaseUrl, setWorkspaceTrusted }) => {
      const walkthrough = registrations.get('lomoCodeSecurity.gettingStarted')();
      await requestStarted;
      if (invalidation === 'endpoint') changeApiBaseUrl('http://127.0.0.1:8090');
      else setWorkspaceTrusted(false);
      release();
      await walkthrough;
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.backend'), false, invalidation);
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.connection'), false, invalidation);
      assert.deepEqual(errors, []);
    });
  }
});

test('concurrent removal supersedes a delayed child project binding without resurrecting its projection', async () => {
  const parentPath = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-context-race-')));
  const parent = { name: 'parent', uri: { scheme: 'file', authority: '', path: parentPath, fsPath: parentPath,
    toString: () => `file://${parentPath}` } };
  fs.mkdirSync(path.join(parentPath, 'repo', '.git'), { recursive: true });
  const state = new Map([[REPOSITORY_CONTEXT_STATE_KEY, { schema_version: 1,
    roots: [newRepositoryContext(parent.uri.toString(), parentPath, 'repo')] }]]);
  let started;
  const firstWriteStarted = new Promise(resolve => { started = resolve; });
  let release;
  const firstWriteRelease = new Promise(resolve => { release = resolve; });
  let writes = 0;
  let confirmedRemoval;
  const removalConfirmed = new Promise(resolve => { confirmedRemoval = resolve; });
  const calls = [];
  try {
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state,
      workspaceStateUpdate: async () => { if (++writes === 1) { started(); await firstWriteRelease; } },
      quickPick: (items, options) => options.canPickMany ? [] : options.title === 'CodeSecurity · refreshed workspace folders' ? undefined : items[0],
      warningSelection: (message, actions) => { if (message === 'Review exact repository selection') confirmedRemoval(); return actions.at(-1); },
      route: async (url, init) => {
        calls.push(url.pathname);
        if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'repo', repo_path: path.join(parentPath, 'repo'), revision: 1 });
        if (url.pathname === '/v1/projects/7/scans/latest') return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
        throw new Error(`stale binding must not request ${url.pathname}`);
      },
    }, async ({ registrations, errors, entries, setupContexts, openWorkspaceFolders }) => {
      const refresh = registrations.get('lomoCodeSecurity.refreshFindings')();
      await firstWriteStarted;
      const remove = registrations.get('lomoCodeSecurity.selectRepositories')();
      await removalConfirmed;
      await new Promise(resolve => setImmediate(resolve));
      release();
      await Promise.all([refresh, remove]);
      assert.deepEqual(state.get(REPOSITORY_CONTEXT_STATE_KEY).roots, []);
      assert.deepEqual(state.get(REPOSITORY_CONTEXT_STATE_KEY).managed_parents, [parent.uri.toString()]);
      assert.equal(entries.size, 0);
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.repositories'), false);
      assert.deepEqual(openWorkspaceFolders(), [parent]);
      assert.deepEqual(errors, []);
      assert.deepEqual(calls, ['/v1/projects/resolve', '/v1/projects/7/scans/latest']);
    });
  } finally { release?.(); fs.rmSync(parentPath, { recursive: true, force: true }); }
});

test('selected child findings survive an empty refresh followed by first scan completion', async (t) => {
  for (const initial of ['unregistered', 'no_scan']) await t.test(initial, async () => {
    const parentPath = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-empty-child-')));
    const parent = { name: 'parent', uri: { scheme: 'file', authority: '', path: parentPath, fsPath: parentPath,
      toString: () => `file://${parentPath}` } };
    const childPath = path.join(parentPath, 'repo');
    fs.mkdirSync(path.join(childPath, '.git'), { recursive: true });
    const state = new Map([[REPOSITORY_CONTEXT_STATE_KEY, { schema_version: 1,
      roots: [newRepositoryContext(parent.uri.toString(), parentPath, 'repo')] }]]);
    const value = finding(501, { scan_finding_number: 1, file_path: 'app.py' });
    let completed = false;
    try {
      await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state,
        strictHybridRoutes: true, streamReady: false, quickPick: () => undefined,
        route: async (url, init) => {
          if (url.pathname === '/v1/projects/resolve') {
            assert.equal(JSON.parse(init.body).repo_path, childPath, 'never resolve the parent');
            return !completed && initial === 'unregistered' ? json({ detail: 'not registered' }, 404)
              : json({ id: 7, name: 'repo', repo_path: childPath, revision: 1 });
          }
          if (url.pathname === '/v1/projects/7/scans/latest') return completed
            ? json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 })
            : json({ detail: 'no scans yet' }, 404);
          if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([value]));
          if (url.pathname === '/v1/scans/41/finding-diagnostics') return json(hybridDiagnosticPage([value]));
          throw new Error(`unexpected empty-child refresh request ${url.pathname}`);
        },
      }, async ({ registrations, errors, entries, treeProvider, removeFolder }) => {
        await registrations.get('lomoCodeSecurity.refreshFindings')();
        assert.equal(entries.size, 0);
        completed = true;
        await registrations.get('lomoCodeSecurity.refreshFindings')();
        assert.deepEqual(errors, []);
        assert.equal(entries.get(`file://${childPath}/app.py`)?.length, 1,
          'an empty projection must retain its selected-child owner for the later scan');
        assert.equal(treeProvider().getChildren().length, 1);
        removeFolder();
        assert.equal(entries.size, 0, 'removing the actual parent still revokes the child projection');
      });
    } finally { fs.rmSync(parentPath, { recursive: true, force: true }); }
  });
});

test('fresh exact-root child project recreation updates local association without source or Git policy writes', async () => {
  const parentPath = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-recreated-child-')));
  const parent = { name: 'parent', uri: { scheme: 'file', authority: '', path: parentPath, fsPath: parentPath,
    toString: () => `file://${parentPath}` } };
  fs.mkdirSync(path.join(parentPath, 'repo', '.git'), { recursive: true });
  const record = { ...newRepositoryContext(parent.uri.toString(), parentPath, 'repo'), project_id: 7 };
  const state = new Map([[REPOSITORY_CONTEXT_STATE_KEY, { schema_version: 1, roots: [record] }]]);
  const calls = [];
  try {
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state,
      route: async (url, init) => {
        calls.push({ path: url.pathname, method: init.method || 'GET' });
        if (url.pathname === '/v1/projects/resolve') {
          assert.deepEqual(JSON.parse(init.body), { repo_path: path.join(parentPath, 'repo') });
          return json({ id: 8, name: 'repo-recreated', repo_path: path.join(parentPath, 'repo'), revision: 1 });
        }
        if (url.pathname === '/v1/projects/8/scans/latest') return json({ detail: 'new project has no scan' }, 404);
        throw new Error(`recovery must not write authority or Git policy: ${url.pathname}`);
      },
    }, async ({ registrations, errors, setupContexts }) => {
      await registrations.get('lomoCodeSecurity.refreshFindings')();
      assert.deepEqual(errors, []);
      assert.equal(state.get(REPOSITORY_CONTEXT_STATE_KEY).roots[0].project_id, 8);
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.repositories'), true);
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.scan'), false);
      assert.deepEqual(calls, [{ path: '/v1/projects/resolve', method: 'POST' }, { path: '/v1/projects/8/scans/latest', method: 'GET' }]);
    });
  } finally { fs.rmSync(parentPath, { recursive: true, force: true }); }
});

test('explicit child discovery preserves the parent and copies only reviewed exact host authorization', async () => {
  const parentPath = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-discovery-')));
  const parent = { name: 'parent', uri: { scheme: 'file', authority: '', path: parentPath, fsPath: parentPath,
    toString: () => `file://${parentPath}` } };
  const state = new Map();
  const calls = [];
  let selectAll = true;
  try {
    for (let index = 0; index < 10; index++) fs.mkdirSync(path.join(parentPath, `repo-${index}`, '.git'), { recursive: true });
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state,
      quickPick: (items, options) => {
        if (!options.canPickMany) return items[0];
        if (!selectAll) assert(items.every(item => item.picked === true), 'repeat discovery retains checked existing children');
        return selectAll ? items : [];
      },
      warningSelection: (_message, actions) => actions.at(-1),
      route: async (url, init) => {
        calls.push({ path: url.pathname, body: JSON.parse(init.body) });
        assert.equal(url.pathname, '/v1/sources/preview');
        return json({ installation_id: '0123456789ab', ...JSON.parse(init.body), authorization_mode: 'mounted',
          authorized: false, configured_roots: ['/some/other/repo'], reason_code: 'source_outside_allowed_root' });
      },
    }, async ({ registrations, errors, clipboardWrites, openWorkspaceFolders, executedCommands, warningCalls, setupContexts }) => {
      await registrations.get('lomoCodeSecurity.selectRepositories')();
      assert.deepEqual(errors, []);
      assert.deepEqual(openWorkspaceFolders(), [parent]);
      assert.equal(executedCommands.length, 0, 'no host or workspace replacement command runs');
      assert.equal(state.get(REPOSITORY_CONTEXT_STATE_KEY).roots.length, 10);
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.repositories'), false, 'selection and source setup alone cannot complete project registration');
      assert.equal(setupContexts.get('lomoCodeSecurity.setup.scan'), false);
      assert(state.get(REPOSITORY_CONTEXT_STATE_KEY).roots.every(record => record.project_id === null));
      assert.equal(calls.length, 10);
      assert(calls.every(call => call.body.repo_path !== parentPath));
      assert.equal(clipboardWrites.length, 1);
      const encoded = clipboardWrites[0].match(/KODESEC_SOURCE_ROOTS_B64=([A-Za-z0-9_-]+)/u)[1];
      assert.deepEqual(JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')),
        Array.from({ length: 10 }, (_, index) => path.join(parentPath, `repo-${index}`)));
      assert.match(warningCalls.at(-1).actions[0].detail, /does not execute it or authorize the parent/);
      selectAll = false;
      await registrations.get('lomoCodeSecurity.selectRepositories')();
      assert.deepEqual(state.get(REPOSITORY_CONTEXT_STATE_KEY).roots, []);
      assert.deepEqual(state.get(REPOSITORY_CONTEXT_STATE_KEY).managed_parents, [parent.uri.toString()]);
      await registrations.get('lomoCodeSecurity.refreshFindings')();
      await registrations.get('lomoCodeSecurity.scanWorkspace')();
      assert.equal(calls.length, 10, 'empty managed selection must not resolve, register, preview, or scan the parent');
      assert.deepEqual(openWorkspaceFolders(), [parent]);
      assert.equal(clipboardWrites.length, 1, 'removing contexts creates no host authorization command');
    });
  } finally { fs.rmSync(parentPath, { recursive: true, force: true }); }
});

test('ten retained child projects restore independent findings while one parent remains open and unregistered', async () => {
  const parentPath = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-children-')));
  const parent = { name: 'parent', uri: { scheme: 'file', authority: '', path: parentPath, fsPath: parentPath,
    toString: () => `file://${parentPath}` } };
  const records = [];
  const calls = [];
  const state = new Map();
  try {
    for (let index = 0; index < 10; index++) {
      fs.mkdirSync(path.join(parentPath, `repo-${index}`, '.git'), { recursive: true });
      records.push(newRepositoryContext(parent.uri.toString(), parentPath, `repo-${index}`));
    }
    state.set(REPOSITORY_CONTEXT_STATE_KEY, { schema_version: 1, roots: records });
    const route = async (url, init) => {
      calls.push({ path: url.pathname, body: init.body && JSON.parse(init.body) });
      if (url.pathname === '/v1/projects/resolve') {
        const root = JSON.parse(init.body).repo_path;
        const index = Array.from({ length: 10 }, (_, index) => path.join(parentPath, `repo-${index}`)).indexOf(root);
        assert(index >= 0, 'the unauthorized parent must never be resolved');
        return json({ id: index + 1, name: `repo-${index}`, repo_path: root, revision: 1 });
      }
      const latest = url.pathname.match(/^\/v1\/projects\/([0-9]+)\/scans\/latest$/u);
      if (latest) return json({ id: 100 + Number(latest[1]), project_id: Number(latest[1]), status: 'completed', revision: 1, findings_revision: 1 });
      const findings = url.pathname.match(/^\/v1\/scans\/([0-9]+)\/findings$/u);
      if (findings) return json(findingPage([finding(200 + Number(findings[1]) - 100,
        { scan_id: Number(findings[1]), scan_finding_number: 1, file_path: 'app.py' })]));
      throw new Error(`unexpected child context request ${url.pathname}`);
    };
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state, route,
      quickPick: () => undefined,
    }, async ({ registrations, errors, entries, treeProvider, openWorkspaceFolders }) => {
      await registrations.get('lomoCodeSecurity.refreshFindings')();
      assert.deepEqual(errors, []);
      assert.equal(entries.size, 10);
      assert.equal(treeProvider().getChildren().length, 10);
      assert.deepEqual(openWorkspaceFolders(), [parent]);
      assert.deepEqual(state.get(REPOSITORY_CONTEXT_STATE_KEY).roots.map(record => record.project_id),
        Array.from({ length: 10 }, (_, index) => index + 1));
      assert(calls.every(call => call.path !== '/v1/projects'));
    });
    const retained = testActiveAuthority('http://127.0.0.1:8080', 7, 'retained-ten-child-contexts');
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state, route,
      profileCredentialStore: new FakeProfileCredentialStore([retained]), suppressStartupAuthority: false,
      globalStateStorage: new Map([['lomoCodeSecurity.integratedDashboardMemberships.v1', integratedDashboardMembershipState(retained.endpoint)]]),
    }, async ({ errors, entries, treeProvider, openWorkspaceFolders, removeFolder }) => {
      const startupDeadline = Date.now() + 3000;
      while (Date.now() < startupDeadline && entries.size < 10) await new Promise(resolve => setTimeout(resolve, 5));
      assert.deepEqual(errors, []);
      assert.equal(entries.size, 10, 'startup reconnect restores selected children from workspace-local metadata');
      assert.equal(treeProvider().getChildren().length, 10);
      assert.deepEqual(openWorkspaceFolders(), [parent]);
      removeFolder();
      assert.equal(entries.size, 0, 'removing the parent removes every owned child projection');
    });
  } finally { fs.rmSync(parentPath, { recursive: true, force: true }); }
});


test('failed scan does not expose operator-wide generic job retry to an IDE capability', async () => {
  const calls = [];
  await withExtensionFixture({
    errorSelection: 'Open jobs',
    route: async (url, init) => {
      calls.push({ path: url.pathname, method: init.method || 'GET', body: init.body });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        return json({ id: 41, project_id: 7, status: 'pending', job_id: 71 }, 202);
      }
      if (url.pathname === '/v1/jobs/71') {
        return json({
          id: 71, kind: 'scan', title: 'Scan #41', status: 'failed', stage: 'failed', detail: 'Prior evidence preserved.',
          error_code: 'scanner_unavailable', progress: 70, scan_id: 41, attempt: 3, max_attempts: 3,
          revision: 8, can_cancel: false, can_retry: true,
        });
      }
      if (url.pathname === '/v1/scans/41') {
        return json({
          id: 41,
          project_id: 7,
          status: 'failed',
          findings_revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([]));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, opened }) => {
    await registrations.get('lomoCodeSecurity.scanWorkspace')();
    for (let turn = 0; turn < 20 && opened.length === 0; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Open scan', 'Open jobs']);
    assert.match(errors[0].message, /Prior evidence preserved.*scanner_unavailable/);
    assert(
      opened.some((url) => /[?&]view=jobs(?:&|#|$)/.test(url)),
      `expected Jobs navigation, got ${JSON.stringify(opened)}`,
    );
  });

  assert.equal(calls.filter(({ path }) => path === '/v1/jobs/71/retry').length, 0);
});


test('removing a workspace aborts an in-flight project registration before scan submission', async () => {
  let registrationStarted;
  const started = new Promise((resolve) => { registrationStarted = resolve; });
  let observedSignal;
  let scanSubmissions = 0;
  await withExtensionFixture({
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        observedSignal = init.signal;
        registrationStarted();
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new DOMException('removed', 'AbortError')), { once: true });
        });
      }
      if (url.pathname === '/v1/scans') {
        scanSubmissions += 1;
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, removeFolder, errors }) => {
    const pending = registrations.get('lomoCodeSecurity.scanWorkspace')();
    await started;
    removeFolder();
    await pending;
    assert.equal(errors.length, 0);
  });

  assert.equal(observedSignal.aborted, true);
  assert.equal(scanSubmissions, 0);
});


test('deactivation aborts an in-flight durable job read without background work', async () => {
  let observationStarted;
  const started = new Promise((resolve) => { observationStarted = resolve; });
  let observedSignal;
  await withExtensionFixture({
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/scans') {
        return json({ id: 41, project_id: 7, status: 'pending', job_id: 71 }, 202);
      }
      if (url.pathname === '/v1/jobs/71') {
        observedSignal = init.signal;
        observationStarted();
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new DOMException('deactivated', 'AbortError')), { once: true });
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, deactivate, errors }) => {
    const pending = registrations.get('lomoCodeSecurity.scanWorkspace')();
    await started;
    deactivate();
    await pending;
    assert.equal(errors.length, 0);
  });

  assert.equal(observedSignal.aborted, true);
});


test('a delayed load cannot resurrect bindings or native state after the only root closes', async () => {
  let pageStarted;
  const started = new Promise((resolve) => { pageStarted = resolve; });
  let finishPage;
  const page = new Promise((resolve) => { finishPage = resolve; });
  await withExtensionFixture({
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        pageStarted();
        return page;
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    removeFolder,
    openWorkspaceFolders,
    entries,
    collection,
    statusItems,
    eventStreams,
    treeProvider,
    errors,
  }) => {
    const pending = registrations.get('lomoCodeSecurity.refreshFindings')();
    await started;
    removeFolder();
    assert.equal(openWorkspaceFolders(), undefined, 'VS Code exposes no workspaceFolders after the last root closes');
    const statusAfterRemoval = statusItems[0].text;
    assert.equal(eventStreams(), 0);
    finishPage(json(findingPage([finding(1)])));
    await pending;
    assert.equal(errors.length, 0);
    assert.equal(eventStreams(), 0);
    assert.deepEqual([...entries.keys()], []);
    assert.equal(collection.batches, 0);
    assert.deepEqual(treeProvider().getChildren(), []);
    assert.equal(statusItems[0].text, statusAfterRemoval);
    assert.doesNotMatch(statusItems[0].text, /\bfail\b|\b1\b/);
  });
});


test('document open and edit during a yielded diagnostic build commit clean ranges and keep stale Problems cleared', async () => {
  const total = 251;
  const findings = Array.from({ length: total }, (_, index) => finding(index + 1, {
    file_path: index < 250 ? 'src/opened-during-build.ts' : 'src/edited-during-build.ts',
    start_line: 2,
    end_line: 2,
  }));
  let signalSecondPage;
  const secondPageStarted = new Promise((resolve) => { signalSecondPage = resolve; });
  let releaseSecondPage;
  const secondPage = new Promise((resolve) => { releaseSecondPage = resolve; });
  await withExtensionFixture({
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest(findings));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        const offset = Number(url.searchParams.get('cursor') || 0);
        if (offset === 200) {
          signalSecondPage();
          return secondPage;
        }
        const items = findings.slice(0, 200).map(diagnosticItem);
        return json({
          scan_id: 41,
          items,
          total,
          truncated: true,
          next_cursor: '200',
          revision: 1,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const filePath = url.searchParams.get('file_path');
        const fileFindings = findings.filter((value) => value.file_path === filePath);
        const offset = Number(url.searchParams.get('cursor') || 0);
        const items = fileFindings.slice(offset, offset + 200);
        const nextOffset = offset + items.length;
        return json({
          items,
          total: fileFindings.length,
          truncated: nextOffset < fileFindings.length,
          next_cursor: nextOffset < fileFindings.length ? String(nextOffset) : null,
          revision: 1,
        });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    openDocument,
    changeDocument,
    provideCodeActions,
    provideHover,
    treeProvider,
  }) => {
      const pending = registrations.get('lomoCodeSecurity.refreshFindings')();
      await secondPageStarted;
      const cleanUri = 'file:///workspace/current/src/opened-during-build.ts';
      const staleUri = 'file:///workspace/current/src/edited-during-build.ts';
      const cleanDocument = {
        uri: { path: '/workspace/current/src/opened-during-build.ts', toString: () => cleanUri },
        version: 1,
        lineCount: 3,
        lineAt: (line) => ({ text: ['', 'dangerous();', ''][line] }),
        isDirty: false,
      };
      const dirtyDocument = {
        uri: { path: '/workspace/current/src/edited-during-build.ts', toString: () => staleUri },
        version: 1,
        lineCount: 3,
        lineAt: (line) => ({ text: ['', 'changed();', ''][line] }),
        isDirty: true,
      };
      openDocument(cleanDocument);
      openDocument(dirtyDocument);
      dirtyDocument.version = 2;
      changeDocument(dirtyDocument);
      releaseSecondPage(json({
        scan_id: 41,
        items: findings.slice(200).map(diagnosticItem),
        total,
        truncated: false,
        next_cursor: null,
        revision: 1,
      }));
      await pending;
      for (let turn = 0; turn < 50
        && entries.get(cleanUri)?.[0]?.range.end.character !== 12; turn += 1) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      assert.equal(entries.get(cleanUri).length, 250);
      assert.deepEqual(
        [entries.get(cleanUri)[0].range.end.line, entries.get(cleanUri)[0].range.end.character],
        [1, 12],
        'a document opened after the build snapshot commits document-aware ranges',
      );
      assert.equal(entries.has(staleUri), false, 'the final commit cannot resurrect stale Problems');
      assert.match(provideHover(cleanDocument, { line: 1, character: 1 }).contents.value, /finding 1/);
      assert.equal(provideHover(dirtyDocument, { line: 1, character: 1 }), undefined);
      assert.deepEqual(provideCodeActions(dirtyDocument, {
        start: { line: 1, character: 1 }, end: { line: 1, character: 1 },
      }), []);
      assert.deepEqual([...treeProvider().getChildren()[0].workspace.staleFiles], ['src/edited-during-build.ts']);
      assert.equal(errors.length, 0);
  });
});


test('scanner-exact Problems range survives a first closed-file activation and reprojects after edits', async () => {
  await withExtensionFixture({
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([finding(1, {
          file_path: 'src/line-only.ts', start_line: 2, start_column: 1, end_line: 2, end_column: 13,
        })]));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    openDocument,
    closeDocument,
    closeDocumentCallbackCount,
    closeDocumentListenerDisposed,
    deactivate,
    errors,
    provideHover,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const uriKey = 'file:///workspace/current/src/line-only.ts';
    const closedRange = entries.get(uriKey)[0].range;
    assert.deepEqual(
      [closedRange.start.line, closedRange.start.character, closedRange.end.line, closedRange.end.character],
      [1, 0, 1, 12],
      'the first closed-file Problems row already has the scanner-normalized exact range',
    );

    let firstDocumentLineReads = 0;
    const firstDocument = {
      uri: {
        path: '/workspace/current/src/line-only.ts',
        toString: () => uriKey,
      },
      version: 1,
      lineCount: 3,
      lineAt: (line) => {
        firstDocumentLineReads += 1;
        return { text: ['', 'dangerous();', ''][line] };
      },
      isDirty: false,
    };
    openDocument(firstDocument);
    let firstHover;
    for (let turn = 0; turn < 50 && !firstHover; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
      firstHover = provideHover(firstDocument, { line: 1, character: 1 });
    }
    const openRange = entries.get(uriKey)[0].range;
    assert.deepEqual(
      [openRange.start.line, openRange.start.character, openRange.end.line, openRange.end.character],
      [1, 0, 1, 12],
    );
    const readsAfterOpen = firstDocumentLineReads;
    assert(firstHover, 'opening the source hydrates hover state without changing its exact range');
    assert.equal(firstDocumentLineReads, readsAfterOpen, 'warm hover reuses the document interval cache');

    closeDocument(firstDocument);
    assert.deepEqual(
      [entries.get(uriKey)[0].range.start.line, entries.get(uriKey)[0].range.end.character],
      [1, 12],
      'closing a document preserves its Problems diagnostic items',
    );

    let reopenedLineReads = 0;
    const reopenedDocument = {
      uri: {
        path: '/workspace/current/src/line-only.ts',
        toString: () => uriKey,
      },
      version: 1,
      lineCount: 3,
      lineAt: (line) => {
        reopenedLineReads += 1;
        return { text: ['', 'risk', ''][line] };
      },
      isDirty: false,
    };
    openDocument(reopenedDocument);
    for (let turn = 0; turn < 50
      && entries.get(uriKey)?.[0]?.range.end.character !== 4; turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert(reopenedLineReads > 0, 'a new document identity builds fresh clamped ranges');
    assert.deepEqual(
      [entries.get(uriKey)[0].range.start.line, entries.get(uriKey)[0].range.end.character],
      [1, 4],
    );
    const readsAfterReopen = reopenedLineReads;
    assert(provideHover(reopenedDocument, { line: 1, character: 3 }));
    assert.equal(reopenedLineReads, readsAfterReopen, 'the rebuilt interval cache is warm after reopen');
    closeDocument(reopenedDocument);
    assert.equal(closeDocumentCallbackCount(), 2);

    deactivate();
    assert.equal(closeDocumentListenerDisposed(), true, 'deactivation disposes the close-document listener');
    const callbacksAfterDeactivate = closeDocumentCallbackCount();
    closeDocument(reopenedDocument);
    assert.equal(
      closeDocumentCallbackCount(),
      callbacksAfterDeactivate,
      'a closed listener cannot call the disposed native controller',
    );
    assert.equal(errors.length, 0);
  });
});


test('adding an unloaded child root suppresses parent Problems and removal reveals them again', async () => {
  const uri = (path) => ({
    scheme: 'file', authority: '', path, fsPath: path, toString: () => `file://${path}`,
  });
  const parent = { name: 'a-parent', uri: uri('/workspace') };
  const child = { name: 'z-child', uri: uri('/workspace/nested') };
  await withExtensionFixture({
    workspaceFolders: [parent],
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve' && init.method === 'POST') {
        return json({ id: 7, name: 'a-parent', repo_path: '/workspace' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 11, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/11/findings') {
        return json(findingPage([finding(1, {
          scan_id: 11,
          scan_finding_number: 1,
          display_id: 'S11-F001',
          file_path: 'nested/shared.ts',
          message: 'parent authority',
        })]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, addFolder, removeFolderByName }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const uriKey = 'file:///workspace/nested/shared.ts';
    assert.equal(entries.get(uriKey)[0].message, 'parent authority');

    addFolder(child);
    assert.equal(entries.has(uriKey), false, 'the deepest open root owns the surface before it is indexed');
    removeFolderByName('z-child');
    assert.equal(entries.get(uriKey)[0].message, 'parent authority');
    assert.equal(errors.length, 0);
  });
});

test('removing a temporary child root clears the attempt ledger and rehydrates the visible parent file', async () => {
  const uri = (path) => ({
    scheme: 'file', authority: '', path, fsPath: path, toString: () => `file://${path}`,
  });
  const parent = { name: 'parent', uri: uri('/workspace') };
  const child = { name: 'child', uri: uri('/workspace/nested') };
  const sharedPath = 'nested/shared.ts';
  const evictionPath = 'eviction.ts';
  const shared = finding(1, {
    scan_id: 11, display_id: 'S11-F001', file_path: sharedPath,
  });
  const aggregate = (path, first, total) => {
    const value = manifestAggregate(path, [finding(first, { file_path: path })]);
    return {
      ...value,
      first_scan_finding_number: first,
      total,
      active: total,
      blocking: total,
      severity_counts: { ...value.severity_counts, high: total },
      lifecycle_counts: { ...value.lifecycle_counts, open: total },
    };
  };
  let sharedStarts = 0;
  await withExtensionFixture({
    workspaceFolders: [parent],
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve' && init.method === 'POST') {
        return json({ id: 7, name: 'parent', repo_path: '/workspace', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 11, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/11/finding-files') {
        return json({
          ...hybridManifest([], 1, { id: 11, project_id: 7 }),
          total_findings: 5_001,
          total_files: 2,
          items: [aggregate(sharedPath, 1, 1), aggregate(evictionPath, 2, 5_000)],
        });
      }
      if (url.pathname === '/v1/scans/11/findings') {
        const path = url.searchParams.get('file_path');
        const offset = Number(url.searchParams.get('cursor') || 0);
        if (path === sharedPath) {
          if (offset === 0) sharedStarts += 1;
          return json(findingPage([shared]));
        }
        const length = Math.min(200, 5_000 - offset);
        const items = Array.from({ length }, (_, index) => {
          const ordinal = offset + index + 2;
          return finding(ordinal, {
            scan_id: 11,
            display_id: `S11-F${String(ordinal).padStart(3, '0')}`,
            file_path: evictionPath,
            scan_finding_number: ordinal,
          });
        });
        const next = offset + length;
        return json({
          items,
          total: 5_000,
          truncated: next < 5_000,
          next_cursor: next < 5_000 ? String(next) : null,
          revision: 1,
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({
    registrations,
    addFolder,
    removeFolderByName,
    errors,
    provideHover,
    setVisibleTextEditors,
    treeProvider,
  }) => {
    const sharedUri = 'file:///workspace/nested/shared.ts';
    const document = {
      uri: { path: '/workspace/nested/shared.ts', toString: () => sharedUri },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'shared();' }),
      isDirty: false,
    };
    setVisibleTextEditors([{
      document,
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }],
      setDecorations() {},
    }]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    for (let turn = 0; turn < 50
      && !provideHover(document, { line: 0, character: 0 }); turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert(provideHover(document, { line: 0, character: 0 }));

    addFolder(child);
    assert.equal(provideHover(document, { line: 0, character: 0 }), undefined);
    const workspaceNode = treeProvider().getChildren()[0];
    const evictionNode = treeProvider().getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')
      .find((node) => node.filePath === evictionPath);
    await treeProvider().getChildren(evictionNode);
    assert.equal(treeProvider().getChildren()[0].workspace.files.has(sharedPath), false);

    removeFolderByName('child');
    for (let turn = 0; turn < 100
      && !provideHover(document, { line: 0, character: 0 }); turn += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    assert.equal(sharedStarts, 2, 'root removal itself admits one fresh parent hydration');
    assert(provideHover(document, { line: 0, character: 0 }));
    assert.equal(errors.length, 0);
  });
});

test('removing a child root deletes child-only Problems even when no ancestor fallback exists', async () => {
  const uri = (path) => ({
    scheme: 'file', authority: '', path, fsPath: path, toString: () => `file://${path}`,
  });
  const parent = { name: 'parent', uri: uri('/workspace') };
  const child = { name: 'child', uri: uri('/workspace/nested') };
  await withExtensionFixture({
    workspaceFolders: [parent, child],
    streamReady: false,
    quickPick: () => undefined,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve' && init.method === 'POST') {
        if (JSON.parse(init.body).repo_path === '/workspace') return json({ detail: 'unregistered' }, 404);
        assert.equal(JSON.parse(init.body).repo_path, '/workspace/nested');
        return json({ id: 8, name: 'child', repo_path: '/workspace/nested' });
      }
      if (url.pathname === '/v1/projects/8/scans/latest') {
        return json({ id: 12, project_id: 8, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/12/findings') {
        return json(findingPage([finding(1, {
          scan_id: 12,
          scan_finding_number: 1,
          display_id: 'S12-F001',
          file_path: 'child-only.ts',
        })]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, removeFolderByName }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const uriKey = 'file:///workspace/nested/child-only.ts';
    assert.equal(entries.get(uriKey).length, 1);
    removeFolderByName('child');
    assert.equal(entries.has(uriKey), false);
    assert.equal(errors.length, 0);
  });
});


test('nested workspace roots retain each owner when diagnostics share one file URI', async () => {
  const uri = (path) => ({
    scheme: 'file',
    authority: '',
    path,
    fsPath: path,
    toString: () => `file://${path}`,
  });
  const parent = { name: 'a-parent', uri: uri('/workspace') };
  const child = { name: 'z-child', uri: uri('/workspace/nested') };
  let parentScanRead = 0;
  await withExtensionFixture({
    workspaceFolders: [parent, child],
    quickPick: () => undefined,
    route: async (url, init) => {
      const path = `${url.pathname}${url.search}`;
      if (path === '/v1/projects/resolve' && init.method === 'POST') {
        const { repo_path: repoPath } = JSON.parse(init.body);
        if (repoPath === '/workspace') return json({ id: 7, name: 'a-parent', repo_path: repoPath });
        if (repoPath === '/workspace/nested') return json({ id: 8, name: 'z-child', repo_path: repoPath });
      }
      if (path === '/v1/projects/7/scans/latest') {
        parentScanRead += 1;
        return json({
          // The first stream handshake performs one authoritative resync of
          // the parent snapshot before adopting its highwater cursor.
          id: parentScanRead <= 2 ? 11 : 13,
          project_id: 7,
          status: 'completed',
          findings_revision: 1,
        });
      }
      if (path === '/v1/projects/8/scans/latest') {
        return json({ id: 12, project_id: 8, status: 'completed', findings_revision: 1 });
      }
      if (path === '/v1/scans/11/findings?limit=200') {
        return json(findingPage([finding(1, {
          scan_id: 11,
          display_id: 'S11-F001',
          file_path: 'nested/shared.ts',
          message: 'parent',
          rule_id: 'p',
          scanner: 'test',
        })]));
      }
      if (path === '/v1/scans/12/findings?limit=200') {
        return json(findingPage([finding(2, {
          scan_id: 12,
          scan_finding_number: 1,
          display_id: 'S12-F001',
          severity: 'medium',
          file_path: 'shared.ts',
          message: 'child',
          rule_id: 'c',
          scanner: 'test',
        })]));
      }
      if (path === '/v1/scans/13/findings?limit=200') {
        return json(findingPage([]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${path}`);
    },
  }, async ({ registrations, entries, errors, openDocument, provideCodeActions, provideHover }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    await refresh();
    assert.deepEqual(
      [...entries.entries()].map(([key, diagnostics]) => [
        key,
        diagnostics.map((diagnostic) => diagnostic.message),
      ]),
      [['file:///workspace/nested/shared.ts', ['child']]],
    );
    const sharedDocument = {
      uri: {
        path: '/workspace/nested/shared.ts',
        toString: () => 'file:///workspace/nested/shared.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'shared();' }),
      isDirty: false,
    };
    openDocument(sharedDocument);
    let hover;
    for (let turn = 0; turn < 20 && !hover; turn += 1) {
      hover = provideHover(sharedDocument, { line: 0, character: 1 });
      if (!hover) await new Promise((resolve) => setImmediate(resolve));
    }
    assert.match(hover.contents.value, /child/);
    const actions = provideCodeActions(sharedDocument, {
      start: { line: 0, character: 1 },
      end: { line: 0, character: 1 },
    });
    assert.equal(actions.length, 5);
    assertStableQuickFixCommands(actions);

    await refresh();
    assert.deepEqual(
      entries.get('file:///workspace/nested/shared.ts').map((diagnostic) => diagnostic.message),
      ['child'],
    );
    assert.match(provideHover(sharedDocument, { line: 0, character: 1 }).contents.value, /child/);
    assert.equal(errors.length, 0);
  });
});


test('Quick Fix no-argument commands retain exact cached identity and fail closed when stale or ambiguous', async () => {
  const first = finding(1, {
    file_path: 'src/quick-fix.ts',
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 8,
  });
  const second = finding(2, {
    file_path: 'src/quick-fix.ts',
    start_line: 2,
    start_column: 1,
    end_line: 2,
    end_column: 8,
  });
  const overlapping = finding(3, {
    file_path: 'src/quick-fix.ts',
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 8,
  });
  const containing = finding(4, {
    file_path: 'src/quick-fix.ts',
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 11,
  });
  await withExtensionFixture({
    streamReady: false,
    quickPick: () => undefined,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([first, second, overlapping, containing]));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    executedCommands,
    warnings,
    quickPickCalls,
    openDocument,
    provideCodeActions,
    setVisibleTextEditors,
    commandsAtCodeActionProviderRegistration,
  }) => {
    assert.deepEqual(
      commandsAtCodeActionProviderRegistration(),
      QUICK_FIX_COMMANDS,
      'all stable no-argument dispatchers are registered before VS Code can request rendered Quick Fixes',
    );
    const uriKey = 'file:///workspace/current/src/quick-fix.ts';
    const document = {
      uri: { path: '/workspace/current/src/quick-fix.ts', toString: () => uriKey },
      version: 1,
      lineCount: 2,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: false,
    };
    const firstSelection = {
      start: { line: 0, character: 1 },
      end: { line: 0, character: 1 },
    };
    const secondSelection = {
      start: { line: 1, character: 1 },
      end: { line: 1, character: 1 },
    };
    const editor = {
      document,
      selection: firstSelection,
      visibleRanges: [firstSelection, secondSelection],
      setDecorations() {},
    };
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    openDocument(document);
    setVisibleTextEditors([editor]);
    const [firstDiagnostic, secondDiagnostic, overlappingDiagnostic, containingDiagnostic] = entries.get(uriKey);
    let firstActions = [];
    for (let turn = 0; turn < 50 && firstActions.length === 0; turn += 1) {
      firstActions = provideCodeActions(document, firstSelection, { diagnostics: [firstDiagnostic] });
      if (firstActions.length === 0) await new Promise((resolve) => setImmediate(resolve));
    }
    const firstCommandBindings = assertStableQuickFixCommands(firstActions);
    for (let turn = 0; turn < 600; turn += 1) {
      const repeatedActions = provideCodeActions(
        document,
        firstSelection,
        { diagnostics: [firstDiagnostic] },
      );
      assert.deepEqual(
        assertStableQuickFixCommands(repeatedActions),
        firstCommandBindings,
        'an identical provider repeat retains the stable argument-free command identities',
      );
    }
    assert.equal(
      [...registrations.keys()].filter((name) => name.startsWith('lomoCodeSecurity.quickFix.')).length,
      QUICK_FIX_COMMANDS.length,
      'provider calls never race the renderer or grow the stable command set',
    );
    const invokeAction = async (action) => {
      const handler = registrations.get(action.command.command);
      assert(handler, `the static Quick Fix dispatcher remains registered: ${action.command.command}`);
      assert.equal(Object.hasOwn(action.command, 'arguments'), false);
      await handler();
    };
    const firstAdvisor = firstActions.find((action) => action.title === 'Run CodeSecurity Advisor');
    assert(firstAdvisor, 'the exact first-finding Advisor Quick Fix is contributed');
    assert.equal(firstAdvisor.command.command, 'lomoCodeSecurity.quickFix.advisor');

    editor.selection = firstSelection;
    const firstOpen = firstActions.find((action) => action.title === 'Open Finding in Web');
    await invokeAction(firstOpen);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.openFinding');
    assert.equal(executedCommands.at(-1).args[0].findingId, 1);

    const firstLifecycle = firstActions.find((action) => action.title === 'Change CodeSecurity lifecycle…');
    await invokeAction(firstLifecycle);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.setLifecycle');
    assert.equal(executedCommands.at(-1).args[0].findingId, 1);

    await invokeAction(firstAdvisor);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.runAdvisor');
    assert.equal(executedCommands.at(-1).args[0].findingId, 1);
    assert.equal(executedCommands.at(-1).args[0].scanFindingNumber, 1);

    editor.selection = secondSelection;
    const secondActions = provideCodeActions(document, secondSelection, { diagnostics: [secondDiagnostic] });
    assert.equal(secondActions.length, 5);
    assertStableQuickFixCommands(secondActions);

    editor.selection = firstSelection;
    await invokeAction(firstAdvisor);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.runAdvisor');
    assert.equal(
      executedCommands.at(-1).args[0].findingId,
      1,
      'VS Code may reuse a cached CodeAction list; every invocation remains bound to its exact finding',
    );

    editor.selection = secondSelection;
    const staleActions = provideCodeActions(document, secondSelection, { diagnostics: [secondDiagnostic] });
    const staleOpen = staleActions.find((action) => action.title === 'Open Finding in Web');
    const executedBeforeStaleClick = executedCommands.length;
    document.version = 2;
    await invokeAction(staleOpen);
    assert.equal(
      executedCommands.length,
      executedBeforeStaleClick,
      'an editor-version change cannot dispatch a finding command',
    );
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);

    document.version = 1;
    const reopenActions = provideCodeActions(document, secondSelection, { diagnostics: [secondDiagnostic] });
    const reopenOpen = reopenActions.find((action) => action.title === 'Open Finding in Web');
    editor.document = { ...document };
    const executedBeforeReopenClick = executedCommands.length;
    await invokeAction(reopenOpen);
    assert.equal(
      executedCommands.length,
      executedBeforeReopenClick,
      'closing and reopening the same URI and version cannot inherit an old Quick Fix authority',
    );
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);

    editor.document = document;
    editor.selection = firstSelection;
    let newestActions;
    for (let version = 2; version <= 514; version += 1) {
      document.version = version;
      newestActions = provideCodeActions(document, firstSelection, { diagnostics: [firstDiagnostic] });
      assertStableQuickFixCommands(newestActions);
    }
    const newestOpen = newestActions.find((action) => action.title === 'Open Finding in Web');
    await invokeAction(newestOpen);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.openFinding');
    assert.equal(executedCommands.at(-1).args[0].findingId, 1);

    document.version = 1;
    const executedBeforeExpiredClick = executedCommands.length;
    await invokeAction(firstOpen);
    assert.equal(executedCommands.length, executedBeforeExpiredClick);
    assert.match(
      warnings.at(-1),
      /Quick Fix is no longer current.*Reopen Quick Fixes/u,
      'an evicted cached action fails closed with visible recovery guidance',
    );

    document.version = 515;
    editor.selection = firstDiagnostic.range;
    const currentActions = provideCodeActions(
      document,
      firstDiagnostic.range,
      { diagnostics: [firstDiagnostic] },
    );
    assertStableQuickFixCommands(currentActions);
    const containingActions = provideCodeActions(
      document,
      containingDiagnostic.range,
      { diagnostics: [containingDiagnostic] },
    );
    assertStableQuickFixCommands(containingActions);
    const executedBeforeExactClick = executedCommands.length;
    await invokeAction(currentActions.find((action) => action.title === 'Run CodeSecurity Advisor'));
    assert.equal(executedCommands.length, executedBeforeExactClick + 1);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.runAdvisor');
    assert.equal(
      executedCommands.at(-1).args[0].findingId,
      1,
      'the exact selected marker range wins over another current finding whose wider range contains it',
    );

    const overlappingActions = provideCodeActions(
      document,
      overlappingDiagnostic.range,
      { diagnostics: [overlappingDiagnostic] },
    );
    assertStableQuickFixCommands(overlappingActions);
    const executedBeforeAmbiguousClick = executedCommands.length;
    await invokeAction(currentActions.find((action) => action.title === 'Run CodeSecurity Advisor'));
    assert.equal(
      executedCommands.length,
      executedBeforeAmbiguousClick,
      'same-range findings cannot be guessed when VS Code exposes no focused Problems diagnostic argument',
    );
    assert.deepEqual(quickPickCalls.at(-1).items.map((item) => item.label), ['S41-F001', 'S41-F003']);
    assert.match(quickPickCalls.at(-1).options.title, /Choose finding.*Run CodeSecurity Advisor/u);
  });
});


test('Quick Fix remains current after discarded actions and caret movement with empty or owned diagnostics', async () => {
  const position = (character) => ({ start: { line: 0, character }, end: { line: 0, character } });
  const items = [
    finding(1, { file_path: 'generated.ts', start_line: 1, start_column: 8, end_line: 1, end_column: 13 }),
    finding(3, { file_path: 'generated.ts', start_line: 1, start_column: null, end_line: 1, end_column: null }),
    finding(4, { file_path: 'generated.ts', start_line: 1, start_column: 10, end_line: 1, end_column: 20 }),
  ];
  let chooseFinding = false;
  const requests = [];
  await withExtensionFixture({
    streamReady: false,
    quickPick: (choices) => chooseFinding ? choices.find(({ label }) => label === 'S41-F001') : undefined,
    route: async (url, init) => {
      requests.push(`${init.method || 'GET'} ${url.pathname}`);
      if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(items));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, executedCommands, warnings, errors, quickPickCalls,
    openDocument, provideCodeActions, setVisibleTextEditors }) => {
    const uriKey = 'file:///workspace/current/generated.ts';
    const document = {
      uri: { path: '/workspace/current/generated.ts', toString: () => uriKey },
      version: 1, lineCount: 1, isDirty: false,
      lineAt: () => ({ text: 'export const generatedFixture = true;' }),
    };
    const editor = { document, selection: position(10), visibleRanges: [position(10)], setDecorations() {} };
    openDocument(document);
    setVisibleTextEditors([editor]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const diagnostics = entries.get(uriKey);
    assert.equal(diagnostics.length, 3);
    let admitted = [];
    for (let turn = 0; turn < 50 && admitted.length === 0; turn += 1) {
      admitted = provideCodeActions(document, editor.selection, { diagnostics });
      if (admitted.length === 0) await new Promise((resolve) => setImmediate(resolve));
    }
    assertStableQuickFixCommands(admitted);
    const requestsBeforeActions = [...requests];
    for (const suppliedDiagnostics of [[], diagnostics]) {
      editor.selection = position(10);
      const discarded = provideCodeActions(document, editor.selection, { diagnostics: suppliedDiagnostics });
      assertStableQuickFixCommands(discarded);
      const commandsBeforeDiscard = executedCommands.length;
      // Dismissing VS Code's action menu invokes no extension command. Model
      // its subsequent automatic provider calls while Home/Right moves the caret.
      for (let character = 0; character <= 7; character += 1) {
        editor.selection = position(character);
        assertStableQuickFixCommands(provideCodeActions(document, editor.selection, {
          diagnostics: suppliedDiagnostics,
        }));
      }
      assert.equal(executedCommands.length, commandsBeforeDiscard);
      const reopened = provideCodeActions(document, editor.selection, { diagnostics: suppliedDiagnostics });
      assertStableQuickFixCommands(reopened);
      const open = reopened.find(({ title }) => title === 'Open Finding in Web');
      chooseFinding = false;
      await registrations.get(open.command.command)();
      assert.equal(executedCommands.length, commandsBeforeDiscard, 'cancelling the exact chooser dispatches nothing');
      assert.equal(quickPickCalls.at(-1).options.title, 'Choose finding · Open Finding in Web');
      assert.deepEqual(quickPickCalls.at(-1).items.map(({ label }) => label), ['S41-F001', 'S41-F003']);
      chooseFinding = true;
      await registrations.get(open.command.command)();
      assert.equal(executedCommands.length, commandsBeforeDiscard + 1);
      assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.openFinding');
      assert.equal(executedCommands.at(-1).args[0].findingId, 1);
      assert.equal(executedCommands.at(-1).args[0].scanFindingNumber, 1);
      assert.deepEqual(entries.get(uriKey), diagnostics, 'caret/menu interactions preserve all current diagnostics');
      assert.deepEqual(requests, requestsBeforeActions, 'provider/chooser interactions do not refresh or mutate resources');
    }
    assert.deepEqual(warnings, []);
    assert.deepEqual(errors, []);
  });
});


test('Quick Fix disambiguates all current diagnostics without selecting the first overlapping scanner', async () => {
  const point = { file_path: 'Dockerfile', start_line: 1, start_column: 1, end_line: 1, end_column: 1 };
  const broad = { ...point, end_line: 7, end_column: 25 };
  const items = [
    finding(3, { ...point, scanner: 'trivy', rule_id: 'DS001', message: 'Pinned base image' }),
    finding(4, { ...broad, scanner: 'checkov', rule_id: 'CKV_DOCKER_2', message: 'HEALTHCHECK instruction' }),
    finding(5, { ...broad, scanner: 'checkov', rule_id: 'CKV_DOCKER_3', message: 'Non-root USER instruction' }),
    finding(6, { ...point, start_line: 2, end_line: 2, end_column: 5, scanner: 'test', rule_id: 'unique-range' }),
    finding(37, { ...point, scanner: 'trivy', rule_id: 'DS002' }),
  ];
  let onChoose = () => undefined;
  await withExtensionFixture({
    streamReady: false,
    quickPick: (choices, options) => onChoose(choices, options),
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(items));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, executedCommands, warnings, quickPickCalls,
    openDocument, provideCodeActions, setVisibleTextEditors }) => {
    const uriKey = 'file:///workspace/current/Dockerfile';
    const document = {
      uri: { path: '/workspace/current/Dockerfile', toString: () => uriKey },
      version: 1, lineCount: 7, lineAt: () => ({ text: 'FROM example:fixture                          ' }), isDirty: false,
    };
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    openDocument(document);
    const selection = { start: { line: 0, character: 0 }, end: { line: 6, character: 24 } };
    const editor = { document, selection, visibleRanges: [selection], setDecorations() {} };
    setVisibleTextEditors([editor]);
    let actions = [];
    let diagnostics;
    for (let turn = 0; turn < 50 && actions.length === 0; turn += 1) {
      diagnostics = entries.get(uriKey) || [];
      actions = provideCodeActions(document, selection, { diagnostics });
      if (actions.length === 0) await new Promise((resolve) => setImmediate(resolve));
    }
    assertStableQuickFixCommands(actions);
    assert.equal(diagnostics.length, 5);
    const invoke = async (action) => registrations.get(action.command.command)();
    const advisor = actions.find((action) => action.title === 'Run CodeSecurity Advisor');
    const beforeCancel = executedCommands.length;
    await invoke(advisor);
    assert.equal(executedCommands.length, beforeCancel, 'cancelled ambiguity never dispatches or requests an action');
    assert.deepEqual(quickPickCalls.at(-1).items.map(({ label }) => label), ['S41-F004', 'S41-F005']);
    assert.match(quickPickCalls.at(-1).items[0].description, /checkov.*CKV_DOCKER_2/u);
    assert.match(quickPickCalls.at(-1).items[0].detail, /Dockerfile:1:1.*HEALTHCHECK/u);

    onChoose = (choices) => choices.find(({ label }) => label === 'S41-F004');
    for (const action of actions) {
      await invoke(action);
      assert.equal(executedCommands.at(-1).args[0].findingId, 4, `${action.title} retains the explicitly chosen logical finding`);
      assert.equal(executedCommands.at(-1).args[0].scanFindingNumber, 4);
    }
    const reversed = provideCodeActions(document, selection, { diagnostics: [...diagnostics].reverse() });
    assertStableQuickFixCommands(reversed);
    await invoke(reversed.find((action) => action.title === 'Run CodeSecurity Advisor'));
    assert.equal(executedCommands.at(-1).args[0].findingId, 4, 'diagnostic order does not choose the action owner');

    const unique = diagnostics.find(({ code }) => code === 'S41-F006');
    editor.selection = unique.range;
    const uniqueActions = provideCodeActions(document, unique.range, { diagnostics });
    const choicesBeforeUnique = quickPickCalls.length;
    await invoke(uniqueActions.find((action) => action.title === 'Run CodeSecurity Advisor'));
    assert.equal(quickPickCalls.length, choicesBeforeUnique, 'one exact current range needs no extra chooser');
    assert.equal(executedCommands.at(-1).args[0].findingId, 6);

    editor.selection = selection;
    const beforeMove = executedCommands.length;
    onChoose = (choices) => {
      editor.selection = unique.range;
      return choices.find(({ label }) => label === 'S41-F004');
    };
    await invoke(advisor);
    assert.equal(executedCommands.length, beforeMove, 'moving selection during the chooser invalidates its authority');
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);

    editor.selection = selection;
    onChoose = (choices) => {
      document.version += 1;
      return choices.find(({ label }) => label === 'S41-F004');
    };
    await invoke(advisor);
    assert.equal(executedCommands.length, beforeMove, 'editing during the chooser invalidates its authority');
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);
  });
});


test('Quick Fix refuses an over-budget candidate set without leaving partial action authority', async () => {
  const items = Array.from({ length: 513 }, (_, index) => finding(index + 1, {
    file_path: 'src/crowded.ts', start_line: 1, start_column: 1, end_line: 1, end_column: 8,
  }));
  await withExtensionFixture({
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(items));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, executedCommands, warnings, openDocument,
    provideCodeActions, setVisibleTextEditors, quickPickCalls, treeProvider }) => {
    const uriKey = 'file:///workspace/current/src/crowded.ts';
    const document = {
      uri: { path: '/workspace/current/src/crowded.ts', toString: () => uriKey },
      version: 1, lineCount: 1, lineAt: () => ({ text: 'danger();' }), isDirty: false,
    };
    const selection = { start: { line: 0, character: 0 }, end: { line: 0, character: 7 } };
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    openDocument(document);
    setVisibleTextEditors([{ document, selection, visibleRanges: [selection], setDecorations() {} }]);
    const provider = treeProvider();
    const [workspaceNode] = await provider.getChildren();
    const [fileNode] = await provider.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope');
    await provider.getChildren(fileNode);
    const diagnostics = entries.get(uriKey) || [];
    const actions = provideCodeActions(document, selection, { diagnostics: diagnostics.slice(0, 1) });
    assert.equal(diagnostics.length, 513);
    assertStableQuickFixCommands(actions);
    const cachedAdvisor = actions.find((action) => action.title === 'Run CodeSecurity Advisor');
    const refused = provideCodeActions(document, selection, { diagnostics });
    assertStableQuickFixCommands(refused);
    assert(refused.every((action) => /Too many overlapping.*Findings tree/u.test(action.disabled?.reason)));
    const before = executedCommands.length;
    await registrations.get(cachedAdvisor.command.command)();
    assert.equal(executedCommands.length, before, 'an earlier cached command cannot consume an evicted partial candidate set');
    assert.equal(quickPickCalls.length, 0);
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);
  });
});


test('Quick Fix cross-call capacity eviction cannot turn an ambiguous pair into a unique owner', async () => {
  const items = Array.from({ length: 513 }, (_, index) => finding(index + 1, {
    file_path: 'src/history.ts', start_line: Math.max(1, index), start_column: 1,
    end_line: Math.max(1, index), end_column: 8,
  }));
  await withExtensionFixture({
    streamReady: false,
    quickPick: () => undefined,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(items));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, entries, executedCommands, warnings, openDocument,
    provideCodeActions, setVisibleTextEditors, quickPickCalls, treeProvider }) => {
    const uriKey = 'file:///workspace/current/src/history.ts';
    const document = {
      uri: { path: '/workspace/current/src/history.ts', toString: () => uriKey },
      version: 1, lineCount: 512, lineAt: () => ({ text: 'danger();' }), isDirty: false,
    };
    const selection = { start: { line: 0, character: 0 }, end: { line: 0, character: 7 } };
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    openDocument(document);
    setVisibleTextEditors([{ document, selection, visibleRanges: [selection], setDecorations() {} }]);
    const provider = treeProvider();
    const [workspaceNode] = await provider.getChildren();
    const [fileNode] = await provider.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope');
    await provider.getChildren(fileNode);
    const diagnostics = entries.get(uriKey);
    assert.equal(diagnostics.length, 513);
    const pair = diagnostics.slice(0, 2);
    const actions = provideCodeActions(document, selection, { diagnostics: pair });
    assertStableQuickFixCommands(actions);
    const advisor = actions.find((action) => action.title === 'Run CodeSecurity Advisor');
    for (const diagnostic of diagnostics.slice(2)) {
      assertStableQuickFixCommands(provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] }));
    }
    const before = executedCommands.length;
    await registrations.get(advisor.command.command)();
    assert.equal(executedCommands.length, before, 'capacity churn must invalidate both original candidates, not silently retain the second');
    assert.equal(quickPickCalls.length, 0);
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);
    provideCodeActions(document, selection, { diagnostics: pair });
    await registrations.get(advisor.command.command)();
    assert.deepEqual(quickPickCalls.at(-1).items.map(({ label }) => label), ['S41-F001', 'S41-F002']);
    assert.equal(executedCommands.length, before, 'reopening restores the complete ambiguous choice; cancellation dispatches nothing');
  });
});


test('cached Quick Fix advances only with the same logical finding revision', async () => {
  let findingsRevision = 1;
  let currentFinding = finding(1, {
    file_path: 'src/revision.ts',
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 8,
  });
  await withExtensionFixture({
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          findings_revision: findingsRevision,
        });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([currentFinding], findingsRevision));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    executedCommands,
    warnings,
    openDocument,
    provideHover,
    provideCodeActions,
    setVisibleTextEditors,
  }) => {
    const uriKey = 'file:///workspace/current/src/revision.ts';
    const document = {
      uri: { path: '/workspace/current/src/revision.ts', toString: () => uriKey },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'danger();' }),
      isDirty: false,
    };
    const selection = {
      start: { line: 0, character: 1 },
      end: { line: 0, character: 1 },
    };
    const editor = {
      document,
      selection,
      visibleRanges: [selection],
      setDecorations() {},
    };
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    await refresh();
    openDocument(document);
    setVisibleTextEditors([editor]);
    const [diagnostic] = entries.get(uriKey);
    let actions = [];
    for (let turn = 0; turn < 50 && actions.length === 0; turn += 1) {
      actions = provideCodeActions(document, selection, { diagnostics: [diagnostic] });
      if (actions.length === 0) await new Promise((resolve) => setImmediate(resolve));
    }
    assertStableQuickFixCommands(actions);
    const cachedOpen = actions.find((action) => action.title === 'Open Finding in Web');
    const invokeCachedOpen = async () => registrations.get(cachedOpen.command.command)();

    findingsRevision = 2;
    currentFinding = finding(1, {
      file_path: 'src/revision.ts',
      start_line: 1,
      start_column: 1,
      end_line: 1,
      end_column: 8,
      revision: 2,
    });
    await refresh();
    let currentHover;
    for (let turn = 0; turn < 50 && !currentHover; turn += 1) {
      currentHover = provideHover(document, selection.start);
      if (!currentHover) await new Promise((resolve) => setImmediate(resolve));
    }
    assert(currentHover, 'the advanced finding projection is hydrated before the cached action runs');
    await invokeCachedOpen();
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.openFinding');
    assert.equal(executedCommands.at(-1).args[0].findingId, 1);
    assert.equal(executedCommands.at(-1).args[0].scanFindingNumber, 1);
    assert.equal(executedCommands.at(-1).args[0].findingRevision, 2);
    assert.equal(executedCommands.at(-1).args[0].findingsRevision, 2);

    findingsRevision = 3;
    currentFinding = finding(1, {
      scan_finding_number: 2,
      file_path: 'src/revision.ts',
      start_line: 1,
      start_column: 1,
      end_line: 1,
      end_column: 8,
      revision: 3,
    });
    await refresh();
    currentHover = undefined;
    for (let turn = 0; turn < 50 && !currentHover; turn += 1) {
      currentHover = provideHover(document, selection.start);
      if (!currentHover) await new Promise((resolve) => setImmediate(resolve));
    }
    assert(currentHover, 'the replacement projection is hydrated before the cached action is rejected');
    const executedBeforeReplacement = executedCommands.length;
    await invokeCachedOpen();
    assert.equal(
      executedCommands.length,
      executedBeforeReplacement,
      'a reused database id with a different scan-local ordinal cannot inherit cached authority',
    );
    assert.match(warnings.at(-1), /Quick Fix is no longer current/u);
  });
});


test('zero-width diagnostic Quick Fix retains its provider-time visible source cursor', async () => {
  const exactFinding = finding(1, {
    file_path: 'app.py',
    start_line: 9,
    start_column: 1,
    end_line: 9,
    end_column: 1,
  });
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([exactFinding]));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    executedCommands,
    openDocument,
    provideCodeActions,
    setVisibleTextEditors,
    warnings,
  }) => {
    const uriKey = 'file:///workspace/current/app.py';
    const document = {
      uri: { path: '/workspace/current/app.py', toString: () => uriKey },
      version: 1,
      lineCount: 9,
      lineAt: () => ({ text: 'AWS_ACCESS_KEY_ID = "fixture"' }),
      isDirty: false,
    };
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    openDocument(document);
    const sourceCursor = {
      start: { line: 8, character: 4 },
      end: { line: 8, character: 4 },
    };
    const editor = {
      document,
      selection: sourceCursor,
      visibleRanges: [sourceCursor],
      setDecorations() {},
    };
    setVisibleTextEditors([editor]);
    let diagnostic;
    for (let turn = 0; turn < 50 && !diagnostic; turn += 1) {
      [diagnostic] = entries.get(uriKey) || [];
      if (!diagnostic) await new Promise((resolve) => setImmediate(resolve));
    }
    assert(diagnostic, 'the exact zero-width finding is projected into Problems');
    assert.deepEqual([
      diagnostic.range.start.line,
      diagnostic.range.start.character,
      diagnostic.range.end.line,
      diagnostic.range.end.character,
    ], [8, 0, 8, 0]);

    let actions = [];
    for (let turn = 0; turn < 50 && actions.length === 0; turn += 1) {
      actions = provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] });
      if (actions.length === 0) await new Promise((resolve) => setImmediate(resolve));
    }
    assertStableQuickFixCommands(actions);
    const advisor = actions.find((action) => action.title === 'Run CodeSecurity Advisor');
    await registrations.get(advisor.command.command)();

    assert.equal(warnings.length, 0);
    assert.equal(executedCommands.at(-1).name, 'lomoCodeSecurity.runAdvisor');
    assert.equal(executedCommands.at(-1).args[0].findingId, exactFinding.id);
    assert.equal(executedCommands.at(-1).args[0].scanFindingNumber, exactFinding.scan_finding_number);
  });
});


test('hover and Code Actions preserve exact API identity across overlapping, multiline, and bounded ranges', async () => {
  const items = [
    finding(1, {
      file_path: 'src/ranges.ts', start_line: 2, start_column: 2, end_line: 5, end_column: 5,
      message: 'earliest multiline match',
    }),
    finding(2, {
      file_path: 'src/ranges.ts', start_line: 4, start_column: 1, end_line: 4, end_column: 8,
      message: 'later overlapping match',
    }),
    finding(3, {
      file_path: 'src/ranges.ts', start_line: null, start_column: null, end_line: null, end_column: null,
      message: 'bounded missing location',
    }),
    finding(4, {
      file_path: 'src/ranges.ts', start_line: 99, start_column: null, end_line: 99, end_column: null,
      message: 'bounded beyond eof',
    }),
  ];
  await withExtensionFixture({
    extensionMode: 3,
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(items));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    entries,
    errors,
    information,
    openDocument,
    provideCodeActions,
    provideHover,
    quickPickCalls,
    setVisibleTextEditors,
    shownDocuments,
    treeProvider,
  }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const lines = Array.from({ length: 6 }, (_, line) => `line ${line + 1} has enough text`);
    const document = {
      uri: {
        path: '/workspace/current/src/ranges.ts',
        toString: () => 'file:///workspace/current/src/ranges.ts',
      },
      version: 1,
      lineCount: lines.length,
      lineAt: (line) => ({ text: lines[line] }),
      isDirty: false,
    };
    openDocument(document);
    const provider = treeProvider();
    const [workspaceNode] = await provider.getChildren();
    const fileNode = (await provider.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope'))
      .find((node) => node.filePath === 'src/ranges.ts');
    const [severityNode] = await provider.getChildren(fileNode);
    const [lifecycleNode] = await provider.getChildren(severityNode);
    const findingNode = (await provider.getChildren(lifecycleNode))
      .find((node) => node.finding.id === 1);
    findingNode.finding.message = `first line\r\nsecond line\n${'x'.repeat(474)}🔐tail`;
    const multilineTreeItem = provider.getTreeItem(findingNode);
    assert.equal(multilineTreeItem.label.includes('\n'), false, 'Tree labels remain one safe line');
    assert.equal(multilineTreeItem.label.endsWith('…'), true, 'single-line truncation is explicit');
    assert.equal(multilineTreeItem.label.includes('\ufffd'), false, 'Unicode truncation never splits an astral character');
    const revealedContext = provider.getTreeItem(findingNode).command.arguments[0];
    await registrations.get('lomoCodeSecurity.revealFinding')(revealedContext);
    assert.equal(shownDocuments.length, 1);
    setVisibleTextEditors(shownDocuments);
    const revealedHover = provideHover(document, { line: 3, character: 2 });
    const revealedAdvisor = /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/u
      .exec(revealedHover.contents.value);
    assert(revealedAdvisor, 'the tree-revealed overlapping finding owns one exact Advisor action');
    const [revealedAdvisorContext] = JSON.parse(decodeURIComponent(revealedAdvisor[1]));
    assert.equal(revealedAdvisorContext.findingId, 1, 'the retained exact tree selection owns the first action');
    let laterDiagnostic;
    for (let turn = 0; turn < 50 && !laterDiagnostic; turn += 1) {
      laterDiagnostic = entries.get('file:///workspace/current/src/ranges.ts')
        ?.find((diagnostic) => diagnostic.code === 'S41-F002');
      if (!laterDiagnostic) await new Promise((resolve) => setImmediate(resolve));
    }
    assert(laterDiagnostic, 'the exact overlapping Problems diagnostic is projected');
    shownDocuments[0].selection = {
      start: laterDiagnostic.range.start,
      end: laterDiagnostic.range.end,
    };
    for (let turn = 0; turn < 50
      && !provideHover(document, { line: 3, character: 2 }); turn += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    const overlapHover = provideHover(document, { line: 3, character: 2 });
    assert.match(overlapHover.contents.value, /later overlapping match/);
    assert.match(overlapHover.contents.value, /first line  \nsecond line  \n/u);
    assert.match(overlapHover.contents.value, /🔐t…/u);
    assert.equal(overlapHover.contents.value.includes('\r'), false, 'CRLF is normalized to LF');
    assert.equal(overlapHover.contents.value.includes('\ufffd'), false, 'hover truncation preserves astral Unicode');
    assert.match(overlapHover.contents.value, /S41-F002/);
    assert.match(overlapHover.contents.value, /S41-F001/);
    const advisorLinks = [...overlapHover.contents.value.matchAll(
      /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/gu,
    )];
    assert.equal(advisorLinks.length, 2, 'every overlapping hover section owns an exact Advisor action');
    const advisorContexts = advisorLinks
      .map((match) => JSON.parse(decodeURIComponent(match[1]))[0]);
    const openContexts = [...overlapHover.contents.value.matchAll(
      /command:lomoCodeSecurity\.openFinding\?([^\s)]+)/gu,
    )].map((match) => JSON.parse(decodeURIComponent(match[1]))[0]);
    assert.deepEqual(
      advisorContexts.map(({ findingId }) => findingId),
      [2, 1],
      'each overlap owns its exact Advisor context in selected-first order',
    );
    assert.deepEqual(
      openContexts.map(({ findingId }) => findingId),
      [2, 1],
      'each overlap owns its exact Open context in selected-first order',
    );
    const [selectedAdvisorContext] = advisorContexts;
    assert.equal(selectedAdvisorContext.findingId, 2, 'the visibly selected finding owns the first action');
    assert.equal(selectedAdvisorContext.scanFindingNumber, 2);
    await registrations.get('lomoCodeSecurity.runAdvisor')(selectedAdvisorContext);
    assert.equal(quickPickCalls[0].options.title, 'Run Advisor for S41-F002?');
    assert.match(information.at(-1), /Advisor for S41-F002 was cancelled/u);
    const actions = provideCodeActions(document, {
      start: { line: 3, character: 2 },
      end: { line: 3, character: 2 },
    });
    assert.equal(actions.length, 5);
    assertStableQuickFixCommands(actions);
    const laterActions = provideCodeActions(document, laterDiagnostic.range, {
      diagnostics: [laterDiagnostic],
    });
    assert.equal(laterActions.length, 5);
    assertStableQuickFixCommands(laterActions);
    assert(laterActions.every((action) => (
      action.diagnostics.length === 1 && action.diagnostics[0] === laterDiagnostic
    )));
    assert.match(provideHover(document, { line: 0, character: 1 }).contents.value, /bounded missing location/);
    assert.match(provideHover(document, { line: 5, character: 1 }).contents.value, /bounded beyond eof/);
    findingNode.finding.message = 'safe\u0000unsafe';
    assert.throws(
      () => provideHover(document, { line: 3, character: 2 }),
      /refused unsafe control or formatting characters/u,
      'native multiline rendering must fail closed if an unsafe control bypasses transport validation',
    );
    assert.equal(
      provideHover(document, { line: 4, character: 4 }),
      undefined,
      'hover retains the exclusive multiline end-column boundary',
    );
    assert.equal(errors.length, 0);
  });
});


test('collapsed exact finding selections retain an explicit owner and reject ambiguous or stale ownership', async () => {
  const broad = finding(1, {
    file_path: 'src/collapsed.ts',
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 8,
    message: 'broad overlap',
  });
  const selected = finding(2, {
    file_path: 'src/collapsed.ts',
    start_line: 1,
    start_column: 3,
    end_line: 1,
    end_column: 3,
    message: 'exact zero-width selection',
  });
  const identical = finding(3, {
    file_path: 'src/collapsed.ts',
    start_line: 1,
    start_column: 3,
    end_line: 1,
    end_column: 3,
    message: 'identical zero-width selection',
  });

  const exercise = async (values, verify, { reveal = true, changedVersion = false } = {}) => withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(values));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    errors,
    openDocument,
    provideHover,
    setVisibleTextEditors,
    shownDocuments,
    treeProvider,
  }) => {
    const document = {
      uri: {
        path: '/workspace/current/src/collapsed.ts',
        toString: () => 'file:///workspace/current/src/collapsed.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'same();' }),
      isDirty: false,
    };
    openDocument(document);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const provider = treeProvider();
    const [workspaceNode] = await provider.getChildren();
    const [fileNode] = await provider.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope');
    const [severityNode] = await provider.getChildren(fileNode);
    const [lifecycleNode] = await provider.getChildren(severityNode);
    const findingNode = (await provider.getChildren(lifecycleNode))
      .find((node) => node.finding.id === selected.id);
    const revealedContext = provider.getTreeItem(findingNode).command.arguments[0];
    if (reveal) {
      await registrations.get('lomoCodeSecurity.revealFinding')(revealedContext);
      assert.equal(shownDocuments.length, 1);
      assert.deepEqual([
        shownDocuments[0].selection.start.line,
        shownDocuments[0].selection.start.character,
        shownDocuments[0].selection.end.line,
        shownDocuments[0].selection.end.character,
      ], [0, 2, 0, 2]);
      setVisibleTextEditors(shownDocuments);
    } else {
      setVisibleTextEditors([{
        document,
        selection: { start: { line: 0, character: 2 }, end: { line: 0, character: 2 } },
        visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 7 } }],
        setDecorations() {},
      }]);
    }
    if (changedVersion) document.version += 1;
    const hover = provideHover(document, { line: 0, character: 2 });
    assert(hover, 'the exact collapsed source position exposes current finding detail');
    verify(hover);
    assert.equal(errors.length, 0);
  });

  await exercise([broad, selected], (hover) => {
    const contexts = [...hover.contents.value.matchAll(
      /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/gu,
    )].map((match) => JSON.parse(decodeURIComponent(match[1]))[0]);
    assert.deepEqual(
      contexts.map(({ findingId }) => findingId),
      [selected.id, broad.id],
      'the uniquely selected zero-width finding owns the first exact action',
    );
    assert.equal(hover.contents.isTrusted.enabledCommands.includes('lomoCodeSecurity.runAdvisor'), true);
  });

  await exercise([broad, selected, identical], (hover) => {
    const contexts = [...hover.contents.value.matchAll(
      /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/gu,
    )].map((match) => JSON.parse(decodeURIComponent(match[1]))[0]);
    assert.deepEqual(
      contexts.map(({ findingId }) => findingId),
      [selected.id, broad.id, identical.id],
      'the current tree-revealed identity disambiguates identical point ranges',
    );
    assert.equal(hover.contents.isTrusted.enabledCommands.includes('lomoCodeSecurity.runAdvisor'), true);
  });

  const assertReadOnly = (hover) => {
    assert.match(hover.contents.value, /S41-F002/u);
    assert.match(hover.contents.value, /S41-F003/u);
    assert.equal(
      /command:lomoCodeSecurity\.(?:runAdvisor|openFinding)\?/u.test(hover.contents.value),
      false,
      'identical collapsed candidates stay visible but cannot guess an interactive owner',
    );
    assert.equal(hover.contents.isTrusted, false);
  };
  await exercise([broad, selected, identical], assertReadOnly, { reveal: false });
  await exercise([broad, selected, identical], assertReadOnly, { changedVersion: true });
});


test('identical overlapping hover ranges stay stable when the visible selection cannot name one finding', async () => {
  const values = [1, 2].map((id) => finding(id, {
    file_path: 'src/identical.ts',
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 8,
  }));
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(values));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, openDocument, provideHover, setVisibleTextEditors, treeProvider }) => {
    const document = {
      uri: {
        path: '/workspace/current/src/identical.ts',
        toString: () => 'file:///workspace/current/src/identical.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'same();' }),
      isDirty: false,
    };
    openDocument(document);
    setVisibleTextEditors([{
      document,
      selection: {
        start: { line: 0, character: 0 },
        end: { line: 0, character: 7 },
      },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 7 } }],
      setDecorations() {},
    }]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    await hydrateTreePath(treeProvider(), 'src/identical.ts');
    const hover = provideHover(document, { line: 0, character: 2 });
    assert(hover, 'both identical current ranges remain visible as exact hover sections');
    const contexts = [...hover.contents.value.matchAll(
      /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/gu,
    )].map((match) => JSON.parse(decodeURIComponent(match[1]))[0]);
    assert.deepEqual(
      contexts.map(({ findingId }) => findingId),
      [1, 2],
      'an ambiguous identical selection preserves stable collection order instead of guessing an owner',
    );
    assert.equal(errors.length, 0);
  });
});


test('interactive hover bounds 5,000 overlapping findings and reports every omitted section', async () => {
  const total = 5_000;
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const offset = Number(url.searchParams.get('cursor') || 0);
        const length = Math.min(200, total - offset);
        const items = Array.from({ length }, (_, index) => {
          const ordinal = offset + index + 1;
          return finding(ordinal, {
            file_path: 'src/dense.ts',
            start_line: 1,
            start_column: ordinal === total ? 2 : 1,
            end_line: 1,
            end_column: ordinal === total ? 4 : 8,
          });
        });
        const next = offset + length;
        return json({
          items,
          total,
          truncated: next < total,
          next_cursor: next < total ? String(next) : null,
          revision: 1,
        });
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations,
    errors,
    openDocument,
    provideHover,
    setVisibleTextEditors,
    treeProvider,
  }) => {
    const document = {
      uri: {
        path: '/workspace/current/src/dense.ts',
        toString: () => 'file:///workspace/current/src/dense.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'dense();' }),
      isDirty: false,
    };
    openDocument(document);
    setVisibleTextEditors([{
      document,
      selection: {
        start: { line: 0, character: 1 },
        end: { line: 0, character: 3 },
      },
      visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 8 } }],
      setDecorations() {},
    }]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    await hydrateTreePath(treeProvider(), 'src/dense.ts');
    let hover;
    for (let turn = 0; turn < 200 && !hover; turn += 1) {
      hover = provideHover(document, { line: 0, character: 2 });
      if (!hover) await new Promise((resolve) => setImmediate(resolve));
    }
    assert(hover, 'the dense current projection exposes one bounded interactive hover');
    assert.equal(
      (hover.contents.value.match(/command:lomoCodeSecurity\.openFinding\?/gu) || []).length,
      8,
    );
    assert.equal(
      (hover.contents.value.match(/command:lomoCodeSecurity\.runAdvisor\?/gu) || []).length,
      8,
    );
    const preferredAdvisor = /command:lomoCodeSecurity\.runAdvisor\?([^\s)]+)/u
      .exec(hover.contents.value);
    assert(preferredAdvisor, 'the exact selected target owns the first bounded Advisor action');
    const [preferredContext] = JSON.parse(decodeURIComponent(preferredAdvisor[1]));
    assert.equal(preferredContext.findingId, total, 'a selected target beyond the cap moves ahead of omission');
    assert.match(hover.contents.value, /4,992 more current findings overlap this source position/u);
    assert.match(hover.contents.value, /Choose one in CodeSecurity Findings for its exact actions/u);
    assert.equal(errors.length, 0);
  });
});


test('direct hover/action indexes invalidate on authoritative replacement and workspace removal', async () => {
  let snapshot = 0;
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: snapshot + 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') {
        snapshot += 1;
        return json(findingPage([finding(snapshot, {
          scan_finding_number: snapshot,
          file_path: 'src/replaced.ts',
          start_line: snapshot,
          end_line: snapshot,
          message: snapshot === 1 ? 'old indexed location' : 'new indexed location',
          revision: snapshot,
        })], snapshot));
      }
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({
    registrations, errors, openDocument, provideCodeActions, provideHover, removeFolder, treeProvider,
  }) => {
    const refresh = registrations.get('lomoCodeSecurity.refreshFindings');
    const document = {
      uri: {
        path: '/workspace/current/src/replaced.ts',
        toString: () => 'file:///workspace/current/src/replaced.ts',
      },
      version: 1,
      lineCount: 2,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: false,
    };
    openDocument(document);
    await refresh();
    await hydrateTreePath(treeProvider(), 'src/replaced.ts');
    assert.match(provideHover(document, { line: 0, character: 1 }).contents.value, /old indexed location/);
    await refresh();
    await hydrateTreePath(treeProvider(), 'src/replaced.ts');
    assert.equal(provideHover(document, { line: 0, character: 1 }), undefined);
    assert.match(provideHover(document, { line: 1, character: 1 }).contents.value, /new indexed location/);
    const currentActions = provideCodeActions(document, {
      start: { line: 1, character: 1 }, end: { line: 1, character: 1 },
    });
    assertStableQuickFixCommands(currentActions);
    removeFolder();
    assert.equal(provideHover(document, { line: 1, character: 1 }), undefined);
    assert.deepEqual(provideCodeActions(document, {
      start: { line: 1, character: 1 }, end: { line: 1, character: 1 },
    }), []);
    assert.equal(errors.length, 0);
  });
});


test('lifecycle mutation reloads one revision-fenced exact scan across a concurrent second-finding change', async () => {
  const calls = [];
  let mutated = false;
  let manifestReadsAfterMutation = 0;
  let diagnosticReadsAfterMutation = 0;
  const first = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/shared.ts',
    message: 'first finding',
  });
  const second = finding(502, {
    scan_finding_number: 2,
    display_id: 'S41-F002',
    file_path: 'src/shared.ts',
    message: 'second finding',
  });
  const exempt = (item) => ({
    ...item,
    lifecycle_status: 'gate_exempt',
    gate_exempt: true,
    gate_effect: 'non_blocking',
    revision: 2,
  });

  await withExtensionFixture({
    strictHybridRoutes: true,
    quickPick: (items) => items.find(({ action }) => action === 'gate_exempt'),
    inputValue: 'Reviewed concurrent evidence',
    route: async (url, init) => {
      calls.push({ path: `${url.pathname}${url.search}`, method: init.method || 'GET', body: init.body });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', gate_decision: 'fail', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = mutated ? (manifestReadsAfterMutation === 1 ? 2 : 3) : 1;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        if (!mutated) return json(hybridManifest([first, second], 1));
        manifestReadsAfterMutation += 1;
        const revision = manifestReadsAfterMutation === 1 ? 2 : 3;
        return json(hybridManifest([exempt(first), exempt(second)], revision, {
          gate_decision: revision === 2 ? 'fail' : 'pass',
        }));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        if (!mutated) return json(hybridDiagnosticPage([first, second], 1));
        diagnosticReadsAfterMutation += 1;
        // The second finding commits between the first post-mutation manifest
        // and compact diagnostic page. The client must reject that mixed revision.
        return json(hybridDiagnosticPage([exempt(first), exempt(second)], 3));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        const values = mutated ? [exempt(first), exempt(second)] : [first, second];
        const expected = Number(url.searchParams.get('expected_revision') || (mutated ? 3 : 1));
        return json(findingPage(values, expected));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(501, {
          ...first,
          scan_finding_number: 1,
          display_id: 'S41-F001',
          revision: 1,
        }));
      }
      if (url.pathname === '/v1/findings/501/lifecycle' && init.method === 'PATCH') {
        assert.deepEqual(JSON.parse(init.body), {
          action: 'gate_exempt',
          reason: 'Reviewed concurrent evidence',
          expected_revision: 1,
        });
        mutated = true;
        return json(findingDetail(501, {
          ...exempt(first),
          scan_finding_number: 1,
          display_id: 'S41-F001',
        }));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({
    registrations, errors, information, openDocument, statusBarMessages, statusItems, treeProvider,
  }) => {
    openDocument({
      uri: {
        path: '/workspace/current/src/shared.ts',
        toString: () => 'file:///workspace/current/src/shared.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: false,
    });
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/shared.ts');
    const [lifecycle] = tree.getChildren(severity);
    const findingNode = tree.getChildren(lifecycle).find(({ finding }) => finding.id === 501);
    assert(findingNode);
    tree.getTreeItem(findingNode);
    await registrations.get('lomoCodeSecurity.setLifecycle')(findingNode);

    assert.equal(errors.length, 0);
    assert.equal(manifestReadsAfterMutation, 2);
    assert.equal(diagnosticReadsAfterMutation, 2);
    const workspace = treeProvider().getChildren()[0].workspace;
    assert.deepEqual(
      workspace.findings.map(({ id, lifecycle_status, gate_effect, revision }) => ({
        id, lifecycle_status, gate_effect, revision,
      })),
      [
        { id: 501, lifecycle_status: 'gate_exempt', gate_effect: 'non_blocking', revision: 2 },
        { id: 502, lifecycle_status: 'gate_exempt', gate_effect: 'non_blocking', revision: 2 },
      ],
    );
    assert.equal(workspace.revision, 3);
    assert.match(statusItems[0].text, /connected.*pass.*2/);
    assert.equal(information.some((message) => /complete scan revision was reloaded/u.test(message)), false);
    assert.match(statusBarMessages.at(-1).message, /complete scan revision was reloaded/u);
    assert.equal(statusBarMessages.at(-1).timeout, 5_000);
  });

  assert.equal(calls.filter(({ path }) => path === '/v1/findings/501/lifecycle').length, 1);
});

test('Advisor reconciles one revision conflict, preserves identity, and reuses the fenced detail', async () => {
  const calls = [];
  let serverRevision = 1;
  let detailReads = 0;
  const currentFinding = () => finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/reconcile.ts',
    revision: serverRevision,
  });
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      calls.push({ path: `${url.pathname}${url.search}`, method: init.method || 'GET', body: init.body });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41, project_id: 7, status: 'completed', gate_decision: 'fail',
          revision: serverRevision, findings_revision: serverRevision,
        });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = serverRevision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([currentFinding()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([currentFinding()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([currentFinding()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        detailReads += 1;
        if (detailReads === 1) {
          assert.equal(url.search, '?expected_revision=1&expected_findings_revision=1');
          serverRevision = 2;
          return json({ detail: {
            code: 'revision_conflict',
            message: 'Findings changed after the selected collection snapshot.',
            action: 'refresh_findings',
          } }, 409);
        }
        assert.equal(url.search, '?expected_revision=2&expected_findings_revision=2');
        return json(findingDetail(501, {
          ...currentFinding(),
          findings_revision: 2,
        }));
      }
      if (url.pathname === '/v1/advisor/providers' && (init.method || 'GET') === 'GET') {
        return json(advisorProviderCollection());
      }
      if (url.pathname === '/v1/findings/501/triage' && init.method === 'POST') {
        assert.deepEqual(JSON.parse(init.body), {
          model: null,
          expected_revision: 2,
          advisor_provider_pin: LOCAL_ADVISOR_PIN,
        });
        return json({ id: 88, kind: 'advisor', finding_id: 501, status: 'queued' });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ testApi, errors }) => {
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    const job = await testApi.queueAdvisor(context);
    assert.deepEqual(job, { id: 88, status: 'queued' });
    assert.equal(detailReads, 2);
    assert.equal(errors.length, 0);
  });
  assert.equal(calls.filter(({ path }) => path.startsWith('/v1/scans/41/findings/1?')).length, 2);
  assert.equal(calls.filter(({ path }) => path === '/v1/findings/501/triage').length, 1);
});


test('Advisor consent defers every request and realtime reconciliation until explicit Run', async (t) => {
  const selected = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/consent.ts',
    revision: 3,
  });
  for (const candidate of [
    { name: 'safe-default Cancel', select: (items) => items[0], run: false },
    { name: 'Escape dismissal', select: () => undefined, run: false },
    { name: 'explicit Run Advisor', select: (items) => items[1], run: true },
  ]) {
    await t.test(candidate.name, async () => {
      const requests = [];
      await withExtensionFixture({
        extensionMode: 3,
        strictHybridRoutes: true,
        streamReady: false,
        quickPick: candidate.select,
        route: async (url, init) => {
          requests.push({ path: url.pathname, method: init.method || 'GET' });
          if (url.pathname === '/v1/projects/resolve') {
            return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
          }
          if (url.pathname === '/v1/projects/7/scans/latest') {
            return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 9 });
          }
          if (url.pathname === '/v1/scans/41/finding-files') {
            return json(hybridManifest([selected], 9));
          }
          if (url.pathname === '/v1/scans/41/finding-diagnostics') {
            return json(hybridDiagnosticPage([selected], 9));
          }
          if (url.pathname === '/v1/scans/41/findings') {
            return json(findingPage([selected], 9));
          }
          if (url.pathname === '/v1/scans/41/findings/1') {
            return json(findingDetail(501, { ...selected, findings_revision: 9 }));
          }
          if (url.pathname === '/v1/advisor/providers') {
            return json({
              revision: 1,
              active_provider_id: null,
              providers: [],
              resolution: {
                provider_id: null,
                transport: 'unavailable',
                reason: 'no_configured_provider',
                eligible_provider_ids: [],
              },
            });
          }
          throw new Error(`Advisor consent fixture did not expect ${init.method || 'GET'} ${url.pathname}`);
        },
      }, async ({
        errors,
        eventStreams,
        information,
        quickPickCalls,
        registrations,
        testApi,
      }) => {
        await testApi.refresh();
        const [snapshot] = testApi.snapshot().workspaces[0].findings;
        assert(snapshot, 'the consent fixture requires one current finding context');
        const context = {
          workspaceKey: snapshot.workspaceKey,
          findingId: snapshot.findingId,
          scanId: snapshot.scanId,
          scanFindingNumber: snapshot.scanFindingNumber,
          findingRevision: snapshot.findingRevision,
          findingsRevision: snapshot.findingsRevision,
        };
        for (let turn = 0; turn < 20 && eventStreams() === 0; turn += 1) {
          await new Promise((resolve) => setImmediate(resolve));
        }
        assert.equal(eventStreams(), 1, 'the normal realtime workspace binding must be observable before consent');
        const streamsBefore = eventStreams();
        const reconnectRequestsBefore = testApi.reconnectRequests();
        requests.length = 0;

        await registrations.get('lomoCodeSecurity.runAdvisor')(context);
        // Flush the promise chain scheduled by the in-memory realtime request;
        // this is an event-loop barrier, not a timing delay.
        await new Promise((resolve) => setImmediate(resolve));

        assert.equal(quickPickCalls.length, 1);
        assert.deepEqual(
          quickPickCalls[0].items.map(({ label, action, description }) => ({ label, action, description })),
          [
            {
              label: 'Cancel',
              action: 'cancel',
              description: 'Safe default — no request is sent and no finding data is disclosed.',
            },
            {
              label: 'Run Advisor',
              action: 'run',
              description: 'Resolve the provider; remote review stays in the Web UI one-finding disclosure flow.',
            },
          ],
        );
        if (!candidate.run) {
          assert.deepEqual(requests, [], 'Cancel and dismissal must perform no REST work');
          assert.equal(eventStreams(), streamsBefore, 'Cancel must not add realtime or reconnect work');
          assert.equal(
            testApi.reconnectRequests(),
            reconnectRequestsBefore,
            'Cancel and dismissal must not request realtime reconciliation',
          );
          assert.match(information.at(-1), /was cancelled; no job request was sent/u);
          assert.deepEqual(errors, []);
          return;
        }
        assert.equal(eventStreams(), streamsBefore, 'the armed reconnect must reuse the existing realtime binding');
        assert(
          testApi.reconnectRequests() > reconnectRequestsBefore,
          'explicit Run must request realtime reconciliation after selection',
        );
        assert(requests.some(({ path }) => path === '/v1/scans/41/findings/1'));
        assert(requests.some(({ path }) => path === '/v1/advisor/providers'));
        assert.equal(requests.some(({ path }) => path === '/v1/findings/501/triage'), false);
        assert.equal(errors.length, 1, 'the unconfigured provider must remain an explicit terminal explanation');
        assert.match(errors[0].message, /no finding data was sent/i);
      });
    });
  }
});


test('Advisor tree command accepts the clicked finding element and explains an unconfigured provider safely', async () => {
  const calls = [];
  let findingsRevision = 9;
  let selected = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/provider.ts',
    revision: 3,
  });
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    quickPick: (items) => items.find(({ action }) => action === 'run'),
    errorSelection: 'Open Advisor Settings',
    route: async (url, init) => {
      calls.push({ path: `${url.pathname}${url.search}`, method: init.method || 'GET', body: init.body });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({
          id: 41,
          project_id: 7,
          status: 'completed',
          gate_decision: 'fail',
          findings_revision: findingsRevision,
        });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([selected], findingsRevision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([selected], findingsRevision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([selected], findingsRevision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        assert.equal(
          url.search,
          `?expected_revision=${selected.revision}&expected_findings_revision=${findingsRevision}`,
        );
        return json(findingDetail(501, { ...selected, findings_revision: findingsRevision }));
      }
      if (url.pathname === '/v1/advisor/providers' && (init.method || 'GET') === 'GET') {
        return json({
          revision: 1,
          active_provider_id: null,
          providers: [],
          resolution: {
            provider_id: null,
            transport: 'unavailable',
            reason: 'no_configured_provider',
            eligible_provider_ids: [],
          },
        });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ testApi, registrations, quickPickCalls, warnings, errors, opened, treeProvider }) => {
    await testApi.refresh();
    const provider = treeProvider();
    const [severityNode] = await hydrateTreePath(provider, 'src/provider.ts');
    const [lifecycleNode] = provider.getChildren(severityNode);
    const [findingNode] = provider.getChildren(lifecycleNode);
    const renderedFinding = provider.getTreeItem(findingNode);
    assert.equal(renderedFinding.contextValue, 'lomoCodeSecurity.finding');
    assert.equal(renderedFinding.command.command, 'lomoCodeSecurity.revealFinding');
    assert.equal(renderedFinding.command.arguments.length, 1);
    assert.equal(Object.isFrozen(renderedFinding.command.arguments[0]), true);
    await registrations.get('lomoCodeSecurity.runAdvisor')(findingNode);

    assert.equal(quickPickCalls.length, 1);
    assert.deepEqual(
      quickPickCalls[0].items.map(({ label, action, description }) => ({ label, action, description })),
      [
        {
          label: 'Cancel',
          action: 'cancel',
          description: 'Safe default — no request is sent and no finding data is disclosed.',
        },
        {
          label: 'Run Advisor',
          action: 'run',
          description: 'Resolve the provider; remote review stays in the Web UI one-finding disclosure flow.',
        },
      ],
    );
    assert.equal(quickPickCalls[0].options.title, 'Run Advisor for S41-F001?');
    assert.equal(warnings.length, 0);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Open Advisor Settings']);
    assert.match(errors[0].message, /authoritative provider state/);
    assert.match(errors[0].message, /no finding data was sent/i);
    assert.equal(errors[0].message.match(/Open Advisor Settings/gu)?.length, 1);
    assert.deepEqual(opened, [
      retainedBrowserUrl(`http://127.0.0.1:8080/?view=settings#bootstrap=${VALID_BROWSER_INVITATION}&destination=advisor-providers`),
    ]);
    assert.equal(calls.filter(({ path }) => path === '/v1/findings/501/triage').length, 0);
    assert.equal(calls.filter(({ path }) => path === '/v1/advisor/providers').length, 1);

    calls.length = 0;
    warnings.length = 0;
    errors.length = 0;
    const cyclicSelection = [];
    cyclicSelection.push(cyclicSelection);
    const forgedFinding = {
      ...renderedFinding,
      command: { ...renderedFinding.command },
    };
    const crossWorkspaceFinding = {
      ...renderedFinding,
      command: {
        ...renderedFinding.command,
        arguments: [{
          ...renderedFinding.command.arguments[0],
          workspaceKey: 'file:///workspace/foreign',
        }],
      },
    };
    const rejectedValues = [
      [],
      [renderedFinding, renderedFinding],
      [[renderedFinding]],
      cyclicSelection,
      [forgedFinding],
      [crossWorkspaceFinding],
    ];
    for (const rejected of rejectedValues) {
      await registrations.get('lomoCodeSecurity.runAdvisor')(rejected);
    }
    assert.equal(warnings.length, 0);
    assert.equal(errors.length, rejectedValues.length);
    assert.equal(calls.length, 0, 'invalid command values must stop before all REST reads');

    selected = finding(501, {
      scan_finding_number: 1,
      display_id: 'S41-F001',
      file_path: 'src/provider.ts',
      revision: 4,
    });
    findingsRevision = 10;
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    calls.length = 0;
    warnings.length = 0;
    errors.length = 0;
    await registrations.get('lomoCodeSecurity.runAdvisor')(findingNode);
    assert.equal(warnings.length, 0);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /authoritative provider state/iu);
    assert.match(errors[0].message, /no finding data was sent/iu);
    assert.equal(
      calls.filter(({ path }) => path === '/v1/scans/41/findings/1?expected_revision=4&expected_findings_revision=10').length,
      1,
      'the retained tree item must normalize once to the same logical finding in the current projection',
    );
    assert.equal(calls.filter(({ path }) => path === '/v1/advisor/providers').length, 1);
    assert.equal(calls.filter(({ path }) => path === '/v1/findings/501/triage').length, 0);

    selected = finding(999, {
      scan_finding_number: 1,
      display_id: 'S41-F001',
      file_path: 'src/replacement.ts',
      revision: 5,
    });
    findingsRevision = 11;
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    calls.length = 0;
    warnings.length = 0;
    errors.length = 0;
    await registrations.get('lomoCodeSecurity.runAdvisor')(findingNode);
    assert.equal(warnings.length, 0);
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].actions, ['Refresh Findings']);
    assert.match(errors[0].message, /Refresh findings, choose the current finding, and retry/iu);
    assert.equal(calls.length, 0, 'a different logical finding must stop before detail, provider, or triage work');
  });
});

test('Advisor admission fails closed for remote and inconsistent provider resolutions', async (t) => {
  const selected = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/provider-boundary.ts',
    revision: 3,
  });
  const cases = [
    {
      name: 'direct',
      provider: advisorProvider({
        id: 'direct-lab', transport: 'direct', base_url: 'http://192.0.2.10:11434',
        authorization: 'authorized', status: 'active', eligible: false,
        reason: 'Remote generation remains disabled.', reason_code: 'remote_generation_disabled',
      }),
      message: /only an exact tested local provider|No tested and currently executable local Advisor provider/,
    },
    {
      name: 'ssh',
      provider: advisorProvider({
        id: 'ssh-lab', transport: 'ssh', ssh_host: '192.0.2.11', ssh_port: 22,
        ssh_user: 'advisor', authorization: 'authorized', status: 'active', eligible: false,
        reason: 'Remote generation remains disabled.', reason_code: 'remote_generation_disabled',
      }),
      message: /only an exact tested local provider|No tested and currently executable local Advisor provider/,
    },
    {
      name: 'inconsistent local selection',
      provider: advisorProvider(),
      collection: advisorProviderCollection(advisorProvider(), {
        resolution: {
          provider_id: 'local-default', transport: 'local', reason: null, eligible_provider_ids: [],
        },
      }),
      message: /inconsistent Advisor provider selection/,
    },
  ];

  for (const candidate of cases.slice(0, 2)) {
    candidate.collection = advisorProviderCollection(candidate.provider, {
      active_provider_id: candidate.provider.id,
      resolution: {
        provider_id: null,
        transport: 'unavailable',
        reason: 'remote_generation_disabled',
        eligible_provider_ids: [],
      },
    });
  }

  for (const candidate of cases) {
    await t.test(candidate.name, async () => {
      const calls = [];
      await withExtensionFixture({
        extensionMode: 3,
        strictHybridRoutes: true,
        streamReady: false,
        route: async (url, init) => {
          calls.push({ path: url.pathname, method: init.method || 'GET' });
          if (url.pathname === '/v1/projects/resolve') {
            return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
          }
          if (url.pathname === '/v1/projects/7/scans/latest') {
            return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 9 });
          }
          if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([selected], 9));
          if (url.pathname === '/v1/scans/41/finding-diagnostics') {
            return json(hybridDiagnosticPage([selected], 9));
          }
          if (url.pathname === '/v1/scans/41/findings') return json(findingPage([selected], 9));
          if (url.pathname === '/v1/scans/41/findings/1') {
            return json(findingDetail(501, { ...selected, findings_revision: 9 }));
          }
          if (url.pathname === '/v1/advisor/providers') {
            return json(candidate.collection || advisorProviderCollection(candidate.provider));
          }
          if (url.pathname === '/v1/findings/501/triage' && init.method === 'POST') {
            throw new Error('triage POST must not be sent after a failed provider preflight');
          }
          throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
        },
      }, async ({ testApi }) => {
        await testApi.refresh();
        const [context] = testApi.snapshot().workspaces[0].findings;
        await assert.rejects(testApi.queueAdvisor(context), candidate.message);
      });
      assert.equal(calls.filter(({ path }) => path === '/v1/advisor/providers').length, 1);
      assert.equal(calls.filter(({ path }) => path === '/v1/findings/501/triage').length, 0);
      assert.equal(calls.some(({ path }) => path.includes('/preview')), false);
    });
  }
});

test('every normalized Advisor entry point opens the exact remote one-finding consent preview without sending', async () => {
  const selected = finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/remote-consent.ts',
    revision: 3,
  });
  const remote = advisorProvider({
    id: 'ssh-lab',
    name: 'Pinned lab Advisor',
    transport: 'ssh',
    base_url: null,
    ssh_host: '192.0.2.11',
    ssh_port: 22,
    ssh_user: 'advisor',
    authorization: 'authorized',
    status: 'active',
    reason: 'Ready for one exact confirmed finding.',
    reason_code: 'remote_single_finding_confirmation_required',
    remediation: 'none',
    content_disclosure_approved: true,
    eligible: false,
  });
  const collection = advisorProviderCollection(remote, {
    active_provider_id: remote.id,
    resolution: {
      provider_id: null,
      transport: 'unavailable',
      reason: 'remote_single_finding_confirmation_required',
      eligible_provider_ids: [],
    },
  });
  const calls = [];
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    quickPick: (items) => items.find(({ action }) => action === 'run'),
    informationSelection: (message, actions) => (
      /Remote review requires the Web UI/u.test(message)
        ? actions.find((action) => action === 'Open exact finding for consent')
        : undefined
    ),
    route: async (url, init) => {
      calls.push({ path: url.pathname, method: init.method || 'GET' });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 9 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') return json(hybridManifest([selected], 9));
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([selected], 9));
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([selected], 9));
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(501, { ...selected, findings_revision: 9 }));
      }
      if (url.pathname === '/v1/advisor/providers') return json(collection);
      if (url.pathname === '/v1/findings/501/triage' && init.method === 'POST') {
        throw new Error('remote VS Code routing must never transmit or enqueue the finding');
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, testApi, opened, treeProvider, information }) => {
    await testApi.refresh();
    const provider = treeProvider();
    const [severityNode] = await hydrateTreePath(provider, selected.file_path);
    const [lifecycleNode] = provider.getChildren(severityNode);
    const [findingNode] = provider.getChildren(lifecycleNode);
    provider.getTreeItem(findingNode);
    const snapshot = testApi.snapshot().workspaces[0].findings[0];
    const normalized = {
      workspaceKey: snapshot.workspaceKey,
      findingId: snapshot.findingId,
      scanId: snapshot.scanId,
      scanFindingNumber: snapshot.scanFindingNumber,
      findingRevision: snapshot.findingRevision,
      findingsRevision: snapshot.findingsRevision,
    };
    const entryPoints = [
      findingNode,
      { ...normalized }, // diagnostic quick fix
      { ...normalized }, // hover command link
      { ...normalized }, // editor command
    ];
    for (const value of entryPoints) {
      await registrations.get('lomoCodeSecurity.runAdvisor')(value);
    }
    assert.equal(information.filter((message) => /No prompt was sent\.$/u.test(message)).length, 4);
    assert.deepEqual(opened, [
      retainedBrowserUrl(`http://127.0.0.1:8080/?view=findings&scan=41&finding=1#bootstrap=${VALID_BROWSER_INVITATION}`),
      ...Array(3).fill(
        retainedBrowserUrl('http://127.0.0.1:8080/?view=findings&scan=41&finding=1'),
      ),
    ]);
  });
  assert.equal(calls.filter(({ path }) => path === '/v1/advisor/providers').length, 4);
  assert.equal(calls.filter(({ path, method }) => path === '/v1/findings/501/triage' && method === 'POST').length, 0);
  assert.equal(calls.some(({ path }) => path.includes('/preview')), false);
});

test('revision reconciliation rejects a foreign replacement without retrying or mutating', async () => {
  let serverRevision = 1;
  let detailReads = 0;
  let advisorWrites = 0;
  const selected = () => finding(serverRevision === 1 ? 501 : 999, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/replaced-identity.ts',
    revision: serverRevision,
  });
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    quickPick: (items) => items.find(({ action }) => action === 'run'),
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: serverRevision });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = serverRevision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        detailReads += 1;
        serverRevision = 2;
        return json({ detail: {
          code: 'revision_conflict',
          message: 'Findings changed after the selected collection snapshot.',
          action: 'refresh_findings',
        } }, 409);
      }
      if (url.pathname === '/v1/findings/501/triage' && init.method === 'POST') {
        advisorWrites += 1;
        return json({ id: 88, kind: 'advisor', finding_id: 501, status: 'queued' });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ errors, registrations, testApi }) => {
    await testApi.refresh();
    const [snapshot] = testApi.snapshot().workspaces[0].findings;
    const context = {
      workspaceKey: snapshot.workspaceKey,
      findingId: snapshot.findingId,
      scanId: snapshot.scanId,
      scanFindingNumber: snapshot.scanFindingNumber,
      findingRevision: snapshot.findingRevision,
      findingsRevision: snapshot.findingsRevision,
    };
    await registrations.get('lomoCodeSecurity.runAdvisor')(context);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /identity now belongs to a different finding/);
    assert.deepEqual(errors[0].actions, ['Refresh Findings']);
    assert.match(errors[0].message, /Refresh findings, choose the current finding, and retry/);
    assert.doesNotMatch(errors[0].message, /Refresh Jobs/);
  });
  assert.equal(detailReads, 1);
  assert.equal(advisorWrites, 0);
});

test('revision reconciliation rejects changed immutable evidence under the same identity', async () => {
  let serverRevision = 1;
  let detailReads = 0;
  let advisorWrites = 0;
  const selected = () => finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/same-identity.ts',
    fingerprint: serverRevision === 1 ? 'original-fingerprint' : 'changed-fingerprint',
    revision: serverRevision,
  });
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: serverRevision });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = serverRevision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        detailReads += 1;
        serverRevision = 2;
        return json({ detail: {
          code: 'revision_conflict',
          message: 'Findings changed after the selected collection snapshot.',
          action: 'refresh_findings',
        } }, 409);
      }
      if (url.pathname === '/v1/findings/501/triage' && init.method === 'POST') {
        advisorWrites += 1;
        return json({ id: 88, kind: 'advisor', finding_id: 501, status: 'queued' });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ testApi }) => {
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    await assert.rejects(
      testApi.queueAdvisor(context),
      /immutable scanner evidence changed/,
    );
  });
  assert.equal(detailReads, 1);
  assert.equal(advisorWrites, 0);
});

test('a second detail revision conflict is terminal after one exact reconciliation', async () => {
  let serverRevision = 1;
  let detailReads = 0;
  let manifestReads = 0;
  let advisorWrites = 0;
  const selected = () => finding(501, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/churn.ts',
    revision: serverRevision,
  });
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', findings_revision: serverRevision });
      }
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = serverRevision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        manifestReads += 1;
        return json(hybridManifest([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([selected()], serverRevision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        detailReads += 1;
        serverRevision = Math.min(serverRevision + 1, 2);
        return json({ detail: {
          code: 'revision_conflict',
          message: 'Findings continued changing.',
          action: 'refresh_findings',
        } }, 409);
      }
      if (url.pathname === '/v1/findings/501/triage' && init.method === 'POST') {
        advisorWrites += 1;
        return json({ id: 88, kind: 'advisor', finding_id: 501, status: 'queued' });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ testApi }) => {
    await testApi.refresh();
    const [context] = testApi.snapshot().workspaces[0].findings;
    await assert.rejects(testApi.queueAdvisor(context), (error) => {
      assert.match(error.message, /changed again during the one bounded reconciliation attempt/);
      assert.equal(error.code, 'finding_not_current');
      assert.equal(error.action, 'refresh_findings');
      return true;
    });
  });
  assert.equal(detailReads, 2);
  assert.equal(manifestReads, 2, 'one initial load plus one exact reconciliation');
  assert.equal(advisorWrites, 0);
});


test('lifecycle reasons are rejected above the server 500-character contract', async () => {
  let lifecycleWrites = 0;
  await withExtensionFixture({
    quickPick: (items) => items.find(({ action }) => action === 'gate_exempt'),
    inputValue: (options) => {
      assert.match(options.validateInput('x'.repeat(501)), /500 characters or fewer/);
      return 'x'.repeat(501);
    },
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', gate_decision: 'fail', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([finding(1)], 1));
      if (url.pathname === '/v1/scans/41/findings/1') return json(findingDetail(1));
      if (url.pathname === '/v1/findings/1/lifecycle' && init.method === 'PATCH') {
        lifecycleWrites += 1;
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, openDocument, treeProvider }) => {
    openDocument({
      uri: { path: '/workspace/current/src/1.ts', toString: () => 'file:///workspace/current/src/1.ts' },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: false,
    });
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/1.ts');
    const [lifecycle] = tree.getChildren(severity);
    const [findingNode] = tree.getChildren(lifecycle);
    tree.getTreeItem(findingNode);
    await registrations.get('lomoCodeSecurity.setLifecycle')(findingNode);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /500 characters or fewer/);
  });
  assert.equal(lifecycleWrites, 0);
});

test('committed lifecycle mutation reports a truthful refresh warning when its revision cannot settle', async () => {
  let mutated = false;
  let lifecycleWrites = 0;
  let postMutationManifestReads = 0;
  const initial = finding(1, {
    scan_finding_number: 1,
    display_id: 'S41-F001',
    file_path: 'src/committed-lifecycle.ts',
    revision: 1,
  });
  const replacement = {
    ...initial,
    lifecycle_status: 'needs_review',
    gate_effect: 'blocking',
    revision: 2,
  };
  await withExtensionFixture({
    extensionMode: 3,
    strictHybridRoutes: true,
    streamReady: false,
    quickPick: (items) => items.find(({ action }) => action === 'needs_review'),
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current', revision: 1 });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', revision: 1, findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        if (!mutated) return json(hybridManifest([initial], 1));
        postMutationManifestReads += 1;
        return json({ detail: {
          code: 'revision_conflict',
          message: 'Findings changed after the selected manifest snapshot.',
          action: 'refresh_findings',
        } }, 409);
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage([initial], 1));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage([initial], 1));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(1, initial));
      }
      if (url.pathname === '/v1/findings/1/lifecycle' && init.method === 'PATCH') {
        lifecycleWrites += 1;
        mutated = true;
        return json(findingDetail(1, replacement));
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ errors, information, registrations, testApi, treeProvider, warningCalls }) => {
    await testApi.refresh();
    const [snapshot] = testApi.snapshot().workspaces[0].findings;
    const context = {
      workspaceKey: snapshot.workspaceKey,
      findingId: snapshot.findingId,
      scanId: snapshot.scanId,
      scanFindingNumber: snapshot.scanFindingNumber,
      findingRevision: snapshot.findingRevision,
      findingsRevision: snapshot.findingsRevision,
    };
    await registrations.get('lomoCodeSecurity.setLifecycle')(context);

    assert.equal(
      lifecycleWrites,
      1,
      `the committed mutation must never be replayed: ${JSON.stringify({ errors, warningCalls, information })}`,
    );
    assert.equal(postMutationManifestReads, 3, 'the existing bounded revision reconciliation owns all retry attempts');
    assert.deepEqual(errors, []);
    assert.equal(information.some((message) => /complete scan revision was reloaded/u.test(message)), false);
    assert.equal(warningCalls.length, 1);
    assert.deepEqual(warningCalls[0].actions, ['Refresh Findings']);
    assert.match(warningCalls[0].message, /S41-F001 is now Needs review with gate effect Blocking/u);
    assert.match(warningCalls[0].message, /committed the lifecycle change/u);
    assert.match(warningCalls[0].message, /do not repeat the change/u);
    assert.doesNotMatch(warningCalls[0].message, /Refresh Jobs/u);
    assert.deepEqual(
      treeProvider().getChildren(),
      [],
      'the obsolete Tree authority is removed until an explicit authoritative refresh',
    );
    assert.deepEqual(testApi.snapshot().workspaces, [], 'no obsolete workspace projection remains actionable');
  });
});


test('hover treats hostile finding fields as text and severity groups keep critical first', async () => {
  const hostile = finding(1, {
    severity: 'critical',
    file_path: 'src/hostile.ts',
    scanner: 'evil **bold** [run](command:workbench.action.closeWindow)',
    rule_id: 'rule` [external](https://attacker.invalid)',
    message: '<img src=x> **owned** [run](command:workbench.action.closeWindow)',
  });
  const high = finding(2, {
    severity: 'high',
    scan_finding_number: 2,
    display_id: 'S41-F002',
    file_path: 'src/hostile.ts',
  });
  await withExtensionFixture({
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', gate_decision: 'fail', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([hostile, high], 1));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, errors, openDocument, provideHover, treeProvider }) => {
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    assert.equal(errors.length, 0);

    const tree = treeProvider();
    const workspaceNode = tree.getChildren()[0];
    const fileNode = tree.getChildren(workspaceNode).filter(node => node.kind !== 'scan_scope')[0];
    assert.deepEqual((await tree.getChildren(fileNode)).map(({ severity }) => severity), ['critical', 'high']);

    const document = {
      uri: {
        scheme: 'file', authority: '', path: '/workspace/current/src/hostile.ts', fsPath: '/workspace/current/src/hostile.ts',
        toString: () => 'file:///workspace/current/src/hostile.ts',
      },
      lineCount: 1,
      lineAt: () => ({ text: 'const vulnerable = true;' }),
      isDirty: false,
    };
    openDocument(document);
    let hover;
    for (let turn = 0; turn < 50 && !hover; turn += 1) {
      hover = provideHover(document, { line: 0, character: 0 });
      if (!hover) await new Promise((resolve) => setImmediate(resolve));
    }
    assert(hover);
    assert.equal(hover.contents.supportThemeIcons, false);
    assert.equal(hover.contents.supportHtml, false);
    assert.deepEqual(hover.contents.isTrusted, {
      enabledCommands: ['lomoCodeSecurity.openFinding', 'lomoCodeSecurity.runAdvisor'],
    });
    const markdown = hover.contents.segments
      .filter(({ kind }) => kind === 'markdown')
      .map(({ value }) => value)
      .join('');
    const text = hover.contents.segments
      .filter(({ kind }) => kind === 'text')
      .map(({ value }) => value)
      .join(' ');
    assert.doesNotMatch(markdown, /workbench\.action|attacker\.invalid|<img|\*\*owned\*\*/);
    assert.match(text, /workbench\.action\.closeWindow/);
    assert.match(text, /attacker\.invalid/);
    assert.match(text, /<img src=x>/);
    assert.deepEqual(
      [...markdown.matchAll(/\(command:([^?]+)\?/g)].map((match) => match[1]),
      [
        'lomoCodeSecurity.openFinding', 'lomoCodeSecurity.runAdvisor',
        'lomoCodeSecurity.openFinding', 'lomoCodeSecurity.runAdvisor',
      ],
    );
  });
});


test('finding rescan action submits only the authoritative finding file', async () => {
  let scanBody;
  await withExtensionFixture({
    informationSelection: (message) => (
      /Scan only src\/1\.ts for S41-F001/.test(message) ? 'Scan exact file' : undefined
    ),
    route: async (url, init) => {
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', gate_decision: 'fail', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage([finding(1)], 1));
      if (url.pathname === '/v1/scans/41/findings/1') return json(findingDetail(1));
      if (url.pathname === '/v1/scans' && init.method === 'POST') {
        scanBody = JSON.parse(init.body);
        return json({ id: 42, project_id: 7, status: 'pending', job_id: 72 }, 202);
      }
      if (url.pathname === '/v1/jobs/72') {
        return json({
          id: 72, kind: 'scan', title: 'Scan #42', status: 'completed', stage: 'completed', progress: 100,
          scan_id: 42, attempt: 1, max_attempts: 3, revision: 2, can_cancel: false, can_retry: false,
        });
      }
      if (url.pathname === '/v1/scans/42') {
        return json({ id: 42, project_id: 7, status: 'completed', gate_decision: 'pass', findings_revision: 1 });
      }
      if (url.pathname === '/v1/scans/42/findings') return json(findingPage([], 1));
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
    },
  }, async ({ registrations, errors, information, openDocument, treeProvider }) => {
    openDocument({
      uri: {
        path: '/workspace/current/src/1.ts',
        toString: () => 'file:///workspace/current/src/1.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: false,
    });
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    await hydrateTreePath(treeProvider(), 'src/1.ts');
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/1.ts');
    const [lifecycle] = tree.getChildren(severity);
    const [findingNode] = tree.getChildren(lifecycle);
    tree.getTreeItem(findingNode);
    await registrations.get('lomoCodeSecurity.rescanFile')(findingNode);
    assert.deepEqual(errors, []);
    assert(information.some((message) => /Scan only src\/1\.ts for S41-F001/.test(message)));
  });
  assert.deepEqual(scanBody, {
    project_id: 7,
    mode: 'full',
    use_ai: false,
    target_path: 'src/1.ts',
    target_kind: 'file',
  });
});


test('finding rescan refuses removed or rebound source ownership after confirmation without touching a sibling', async (t) => {
  for (const change of ['removed', 'removed-and-readded', 'deeper-owner-added']) {
    await t.test(change, async () => {
      const uri = (path) => ({
        scheme: 'file', authority: '', path, fsPath: path, toString: () => `file://${path}`,
      });
      const current = { name: 'demo', uri: uri('/workspace/current') };
      const sibling = { name: 'demo', uri: uri('/workspace/sibling') };
      let confirm;
      let promptShown;
      const prompted = new Promise((resolve) => { promptShown = resolve; });
      const admissionWrites = [];
      await withExtensionFixture({
        workspaceFolders: [current, sibling],
        quickPick: () => undefined,
        informationSelection: (message) => {
          if (!/Scan only src\/1\.ts for S41-F001/.test(message)) return undefined;
          return new Promise((resolve) => { confirm = resolve; promptShown(); });
        },
        route: async (url, init) => {
          if (init.method === 'POST' && ['/v1/projects', '/v1/source-snapshots', '/v1/scans'].includes(url.pathname)) {
            admissionWrites.push(url.pathname);
            throw new Error(`source ownership changed before admission: ${url.pathname}`);
          }
          if (url.pathname === '/v1/projects/resolve') {
            const { repo_path } = JSON.parse(init.body);
            assert(['/workspace/current', '/workspace/sibling'].includes(repo_path));
            return json({ id: repo_path === '/workspace/current' ? 7 : 8, name: 'demo', repo_path });
          }
          if (/^\/v1\/projects\/[78]\/scans\/latest$/.test(url.pathname)) {
            const projectId = Number(url.pathname.split('/')[3]);
            return json({ id: projectId + 34, project_id: projectId, status: 'completed',
              gate_decision: 'fail', findings_revision: 1 });
          }
          if (url.pathname === '/v1/scans/41/findings') return json(findingPage([finding(1)], 1));
          if (url.pathname === '/v1/scans/42/findings') {
            return json(findingPage([finding(2, { scan_id: 42, scan_finding_number: 1, file_path: 'src/1.ts' })], 1));
          }
          if (url.pathname === '/v1/scans/41/findings/1') return json(findingDetail(1));
          throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}`);
        },
      }, async ({ registrations, errors, entries, snapshotCollections, treeProvider, removeFolder, addFolder }) => {
        await registrations.get('lomoCodeSecurity.refreshFindings')();
        const tree = treeProvider();
        const [severity] = await hydrateTreePath(tree, 'src/1.ts');
        const [lifecycle] = tree.getChildren(severity);
        const [findingNode] = tree.getChildren(lifecycle);
        tree.getTreeItem(findingNode);
        const siblingKey = sibling.uri.toString();
        const siblingBefore = tree.getChildren().find((node) => node.workspace.key === siblingKey).workspace;
        const siblingProblems = entries.get(`${siblingKey}/src/1.ts`);
        assert.equal(siblingProblems.length, 1, 'the duplicate-filename sibling starts with its own Problems');

        const pending = registrations.get('lomoCodeSecurity.rescanFile')(findingNode);
        await prompted;
        if (change === 'deeper-owner-added') {
          addFolder({ name: 'new-owner', uri: uri('/workspace/current/src') });
        } else {
          removeFolder();
          if (change === 'removed-and-readded') addFolder({ ...current });
        }
        confirm('Scan exact file');
        await pending;

        assert.deepEqual(admissionWrites, []);
        assert.deepEqual(snapshotCollections, []);
        assert.equal(errors.length, 1);
        assert.match(errors[0].message, /no longer current|source workspace changed|not inside an open workspace/);
        const siblingAfter = tree.getChildren().find((node) => node.workspace.key === siblingKey).workspace;
        assert.deepEqual(siblingAfter, siblingBefore, 'the sibling retains its exact scan and indexed findings');
        assert.deepEqual(entries.get(`${siblingKey}/src/1.ts`), siblingProblems);
        if (change !== 'deeper-owner-added') {
          assert.equal(tree.getChildren().some((node) => node.workspace.key === current.uri.toString()), false,
            'confirming a stale finding must not resurrect its removed source projection');
        }
      });
    });
  }
});


test('finding deletion uses a safe-default confirmation, revision fence, and exact authoritative reload', async () => {
  const calls = [];
  let deleted = false;
  await withExtensionFixture({
    quickPick: (items, options) => {
      assert.deepEqual(items.map(({ label, action }) => ({ label, action })), [
        { label: 'Cancel', action: 'cancel' },
        { label: 'Delete permanently', action: 'delete' },
      ]);
      assert.equal(options.title, 'Delete S41-F001 from scan #41?');
      assert.match(options.placeHolder, /Cancel is the safe default/);
      return items[1];
    },
    strictHybridRoutes: true,
    route: async (url, init) => {
      calls.push({ path: `${url.pathname}${url.search}`, method: init.method || 'GET' });
      if (url.pathname === '/v1/projects/resolve') {
        return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      }
      if (url.pathname === '/v1/projects/7/scans/latest') {
        return json({ id: 41, project_id: 7, status: 'completed', gate_decision: 'fail', findings_revision: 4 });
      }
      const items = deleted ? [] : [finding(501, {
          scan_finding_number: 1,
          display_id: 'S41-F001',
          file_path: 'src/delete.ts',
          revision: 3,
        })];
      const revision = deleted ? 5 : 4;
      if (url.pathname === '/v1/scans/41') {
        const scopeRevision = revision;
        return json({ id: 41, project_id: 7, status: 'completed',
          revision: scopeRevision, findings_revision: scopeRevision,
          scanner_summary: { scope: { kind: 'workspace' } } });
      }
      if (url.pathname === '/v1/scans/41/finding-files') {
        return json(hybridManifest(items, revision, {
          gate_decision: deleted ? 'pass' : 'fail',
        }));
      }
      if (url.pathname === '/v1/scans/41/finding-diagnostics') {
        return json(hybridDiagnosticPage(items, revision));
      }
      if (url.pathname === '/v1/scans/41/findings') {
        return json(findingPage(items, revision));
      }
      if (url.pathname === '/v1/scans/41/findings/1') {
        return json(findingDetail(501, {
          findings_revision: 4,
          scan_finding_number: 1,
          display_id: 'S41-F001',
          file_path: 'src/delete.ts',
          revision: 3,
        }));
      }
      if (url.pathname === '/v1/findings/501' && init.method === 'DELETE') {
        assert.equal(url.search, '?expected_revision=3');
        deleted = true;
        return json({ deleted: true, finding_id: 501, scan_id: 41 });
      }
      throw new Error(`unexpected request ${init.method || 'GET'} ${url.pathname}${url.search}`);
    },
  }, async ({ registrations, entries, errors, information, openDocument, statusItems, treeProvider }) => {
    openDocument({
      uri: {
        path: '/workspace/current/src/delete.ts',
        toString: () => 'file:///workspace/current/src/delete.ts',
      },
      version: 1,
      lineCount: 1,
      lineAt: () => ({ text: 'dangerous();' }),
      isDirty: false,
    });
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    assert.deepEqual([...entries.keys()], ['file:///workspace/current/src/delete.ts']);
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/delete.ts');
    const [lifecycle] = tree.getChildren(severity);
    const [findingNode] = tree.getChildren(lifecycle);
    tree.getTreeItem(findingNode);
    await registrations.get('lomoCodeSecurity.deleteFinding')(findingNode);

    assert.equal(errors.length, 0);
    assert.deepEqual([...entries.keys()], []);
    assert.match(statusItems[0].text, /connected.*pass.*0/);
    assert(information.some((message) => /was deleted.*authoritative gate/.test(message)));
  });

  assert(calls.some(({ path, method }) => path === '/v1/findings/501?expected_revision=3' && method === 'DELETE'));
  assert.deepEqual(calls.slice(-3).map(({ path }) => path), [
    '/v1/scans/41/finding-files?limit=200',
    '/v1/scans/41',
    '/v1/scans/41/finding-diagnostics?limit=200&expected_revision=5',
  ]);
});


test('invalid SCM menu arguments refuse before repository inspection or authority/source requests', async () => {
  for (const command of ['lomoCodeSecurity.protectPushes', 'lomoCodeSecurity.checkOutgoingCommits']) {
    let inspections = 0;
    const repository = { repositoryId: 'a'.repeat(64), get root() { inspections++; return '/workspace/current'; }, gitDirectory: '/workspace/current/.git' };
    await withExtensionFixture({ gitPushRepository: repository,
      quickPick: () => { throw new Error('invalid menu context must not open the palette chooser'); },
      route: async () => { throw new Error('invalid menu context must not request authority/source/policy'); },
    }, async ({ registrations, errors }) => {
      await registrations.get(command)({ id: 'git', rootUri: { scheme: 'file', authority: '', path: '/outside', fsPath: '/outside', toString: () => 'file:///outside' } });
      assert.equal(inspections, 0);
      assert.match(errors.at(-1).message, /one current Git repository/);
    });
  }
});

test('SCM selected child skips repository chooser and opens protection Settings for its exact root', async () => {
  const parentPath = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-scm-child-')));
  const parent = { name: 'parent', uri: { scheme: 'file', authority: '', path: parentPath, fsPath: parentPath,
    toString: () => `file://${parentPath}` } };
  for (const name of ['first', 'second']) fs.mkdirSync(path.join(parentPath, name, '.git'), { recursive: true });
  const state = new Map([[REPOSITORY_CONTEXT_STATE_KEY, { schema_version: 1,
    roots: ['first', 'second'].map(name => newRepositoryContext(parent.uri.toString(), parentPath, name)) }]]);
  const selectedPath = path.join(parentPath, 'second');
  const rootUri = { scheme: 'file', authority: '', path: selectedPath, fsPath: selectedPath,
    toString: () => `file://${selectedPath}` };
  const repository = { repositoryId: 'b'.repeat(64), root: selectedPath, gitDirectory: path.join(selectedPath, '.git') };
  const requests = [];
  const choices = [];
  try {
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: state, gitPushRepository: repository,
      quickPick: (items, options) => {
        choices.push(options.title);
        assert.equal(options.title, 'Protect pushes · second', 'menu uses supplied root, never palette repository chooser');
        return items.find(item => item.id === 'settings');
      },
      route: async (url, init) => {
        requests.push(`${init.method || 'GET'} ${url.pathname}`);
        assert.equal(url.pathname, `/v1/git/push-protection/${repository.repositoryId}`);
        return json({ detail: { code: 'push_setup_required', message: 'Set up this exact clone.' } }, 404);
      },
    }, async ({ registrations, opened, errors, openWorkspaceFolders }) => {
      await registrations.get('lomoCodeSecurity.protectPushes')({ id: 'git', rootUri });
      assert.deepEqual(errors, []);
      assert.deepEqual(choices, ['Protect pushes · second']);
      assert.deepEqual(requests, [`GET /v1/git/push-protection/${repository.repositoryId}`]);
      assert.deepEqual(openWorkspaceFolders(), [parent]);
      assert.deepEqual(opened, [retainedBrowserUrl(`http://127.0.0.1:8080/?view=settings#bootstrap=${VALID_BROWSER_INVITATION}&destination=git-push-protection-${repository.repositoryId}`)]);
    });
  } finally { fs.rmSync(parentPath, { recursive: true, force: true }); }
});


test('readable Trivy titles preserve exact tree, hover and Problems Quick Fix ownership', async () => {
  const cases = require('../fixtures/finding-titles.json');
  const findings = cases.map(({ message }, index) => finding(index + 1, {
    scanner: 'trivy', file_path: 'src/titles.ts', message: message.replaceAll('\n', ' '),
  }));
  await withExtensionFixture({
    streamReady: false,
    route: async (url) => {
      if (url.pathname === '/v1/projects/resolve') return json({ id: 7, name: 'current', repo_path: '/workspace/current' });
      if (url.pathname === '/v1/projects/7/scans/latest') return json({ id: 41, project_id: 7, status: 'completed', findings_revision: 1 });
      if (url.pathname === '/v1/scans/41/findings') return json(findingPage(findings));
      throw new Error(`unexpected request GET ${url.pathname}`);
    },
  }, async ({ registrations, entries, errors, provideHover, provideCodeActions, setVisibleTextEditors, treeProvider }) => {
    const uriKey = 'file:///workspace/current/src/titles.ts';
    const document = {
      uri: { path: '/workspace/current/src/titles.ts', toString: () => uriKey },
      lineCount: 1, lineAt: () => ({ text: 'dangerous();' }), isDirty: false, version: 1,
    };
    setVisibleTextEditors([{
      document, visibleRanges: [{ start: { line: 0, character: 0 }, end: { line: 0, character: 12 } }],
      setDecorations() {},
    }]);
    await registrations.get('lomoCodeSecurity.refreshFindings')();
    const tree = treeProvider();
    const [severity] = await hydrateTreePath(tree, 'src/titles.ts');
    const [lifecycle] = tree.getChildren(severity);
    const nodes = tree.getChildren(lifecycle);
    assert.equal(nodes.length, 3);
    for (const [index, node] of nodes.entries()) {
      assert.equal(tree.getTreeItem(node).label, `${findings[index].display_id} · ${cases[index].title}`);
    }
    const diagnostics = entries.get(uriKey);
    assert.equal(diagnostics.length, 3);
    const hover = provideHover(document, { line: 0, character: 0 }).contents.value;
    for (const [index, diagnostic] of diagnostics.entries()) {
      assert.equal(diagnostic.code, findings[index].display_id);
      assert(hover.includes(findings[index].message), 'full evidence survives title projection');
      assertStableQuickFixCommands(provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] }));
    }
    assert.equal(errors.length, 0);
  });
});

test('folder-to-untitled activation restores fifteen selected children through the real recovery store', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-conversion-')));
  const parentPath = path.join(root, 'workspace'), profileStoragePath = path.join(root, 'profile');
  fs.mkdirSync(parentPath);
  const folder = (name, folderPath) => ({ name, uri: { scheme: 'file', authority: '', path: folderPath,
    fsPath: folderPath, toString: () => `file://${folderPath}` } });
  const parent = folder('workspace', parentPath);
  const metadata = { schema_version: 1, managed_parents: [parent.uri.toString()], roots: [] };
  for (let i = 0; i < 15; i++) {
    fs.mkdirSync(path.join(parentPath, `repo-${i}`, '.git'), { recursive: true });
    metadata.roots.push({ ...newRepositoryContext(parent.uri.toString(), parentPath, `repo-${i}`), project_id: i + 1 });
  }
  const original = new Map([[REPOSITORY_CONTEXT_STATE_KEY, metadata]]), converted = new Map();
  const profile = new Map([['unrelated.setting', 'preserve']]);
  const sessionId = 'c23172b2-77a6-45ec-a570-779f20a58dd01792350634333';
  const requests = [];
  const route = async (url, init) => {
    requests.push({ path: url.pathname, body: init.body && JSON.parse(init.body) });
    if (url.pathname === '/v1/projects/resolve') {
      const selected = metadata.roots.find(record => path.join(parentPath, record.relative_path) === JSON.parse(init.body).repo_path);
      if (!selected) return json({ detail: 'no project for the added empty root' }, 404);
      return json({ id: selected.project_id, name: selected.relative_path,
        repo_path: path.join(parentPath, selected.relative_path), revision: 1 });
    }
    if (/^\/v1\/projects\/\d+\/scans\/latest$/.test(url.pathname)) return json({ detail: 'no scan' }, 404);
    throw new Error(`conversion must not mutate authority or start work: ${url.pathname}`);
  };
  const settle = async predicate => {
    const deadline = performance.now() + 3000;
    while (!predicate() && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 2));
    assert(predicate(), 'bounded actual recovery store did not settle');
  };
  try {
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage: original,
      globalStateStorage: profile, profileStoragePath, sessionId, route,
    }, async ({ errors, warnings }) => {
      const directory = path.join(profileStoragePath, 'repository-recovery-v1');
      await settle(() => fs.existsSync(directory) && fs.readdirSync(directory).some(name => name.endsWith('.json'))
        && !fs.readdirSync(directory).some(name => name.endsWith('.lock')));
      assert.deepEqual(errors, []); assert.deepEqual(warnings, []);
    });
    const addedPath = path.join(parentPath, 'added-qa'); fs.mkdirSync(addedPath);
    const active = testActiveAuthority('http://127.0.0.1:8080', 7, 'retained-folder-conversion');
    profile.set('lomoCodeSecurity.integratedDashboardMemberships.v1', integratedDashboardMembershipState(active.endpoint));
    await withExtensionFixture({ workspaceFolders: [parent, folder('added-qa', addedPath)], workspaceStateStorage: converted,
      globalStateStorage: profile, profileStoragePath, sessionId, route, quickPick: () => undefined,
      profileCredentialStore: new FakeProfileCredentialStore([active]), suppressStartupAuthority: false,
      workspaceFile: { scheme: 'untitled', toString: () => 'untitled:1792350634333' },
    }, async ({ registrations, errors, warnings, quickPickCalls }) => {
      await settle(() => converted.has(REPOSITORY_CONTEXT_STATE_KEY)
        && requests.some(request => request.body?.repo_path === path.join(parentPath, 'repo-14')));
      assert.deepEqual(quickPickCalls, [], 'automatic context recovery uses quiet startup projection, without a summary picker');
      await registrations.get('lomoCodeSecurity.refreshFindings')();
      assert.deepEqual(converted.get(REPOSITORY_CONTEXT_STATE_KEY), metadata);
      assert.deepEqual(original.get(REPOSITORY_CONTEXT_STATE_KEY), metadata);
      assert.deepEqual(errors, []); assert.deepEqual(warnings, []);
      assert(requests.some(request => request.body?.repo_path === path.join(parentPath, 'repo-14')));
      assert(!requests.some(request => request.body?.repo_path === parentPath), 'the parent remains excluded');
      assert(requests.every(request => request.path === '/v1/projects/resolve' || /\/scans\/latest$/.test(request.path)));
      assert.equal(profile.get('unrelated.setting'), 'preserve');
    });
    const rejected = new Map();
    await withExtensionFixture({ workspaceFolders: [parent, folder('added-qa', addedPath)], workspaceStateStorage: rejected,
      globalStateStorage: profile, profileStoragePath,
      sessionId: 'e93172b2-77a6-45ec-a570-779f20a58dd01792350634334', route,
      workspaceFile: { scheme: 'untitled', toString: () => 'untitled:1792350634334' },
      informationSelection: 'Restore selections', workspaceStateUpdate: async () => { throw new Error('uncertain persistence'); },
    }, async ({ warnings, executedCommands }) => {
      await settle(() => warnings.some(message => message.includes('could not preserve repository selections')));
      await new Promise(setImmediate);
      assert.equal(rejected.has(REPOSITORY_CONTEXT_STATE_KEY), false);
      assert.equal(executedCommands.filter(command => command.name === 'lomoCodeSecurity.refreshFindings').length, 0,
        'the actual offer chain must not refresh after rejected restoration');
    });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});


test('repository recovery scope uses physical folders after native snapshot admission through actual activation', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-recovery-path-')));
  const parentPath = path.join(root, 'workspace'); fs.mkdirSync(parentPath);
  const parent = { name: 'workspace', uri: { scheme: 'file', authority: '', path: parentPath,
    fsPath: parentPath, toString: () => `file://${parentPath}` } };
  const metadata = { schema_version: 1, managed_parents: [parent.uri.toString()], roots: [] };
  for (let i = 0; i < 15; i++) {
    fs.mkdirSync(path.join(parentPath, `repo-${i}`, '.git'), { recursive: true });
    metadata.roots.push({ ...newRepositoryContext(parent.uri.toString(), parentPath, `repo-${i}`), project_id: i < 10 ? i + 1 : null });
  }
  const { workspaceSourcePath: actualSourcePath, isNativeWindowsWorkspace: actualNativeWindows } = require('../../dist/workspace.js');
  const sessionId = 'c23172b2-77a6-45ec-a570-779f20a58dd01792350634333';
  try {
    for (const drive of ['C', 'c']) {
      const profileStoragePath = path.join(root, drive === 'C' ? 'profile-drive-upper' : 'profile-drive-lower');
      const workspaceStateStorage = new Map([[REPOSITORY_CONTEXT_STATE_KEY, metadata]]);
      const projected = { uri: { scheme: 'file', authority: '', path: `/${drive}:/owned/workspace`, fsPath: `${drive}:\\owned\\workspace` } };
      const expectedTransport = actualSourcePath(projected, 'win32');
      assert.match(expectedTransport, /^\/source-snapshots\/native-windows\/[a-f0-9]{64}$/u);
      let scope, admissions = 0;
      await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage, profileStoragePath, sessionId,
        captureRepositoryRecoveryScope: value => { scope = value; },
        workspaceSourcePathAdapter: folder => { assert.equal(folder, parent); admissions++; return actualSourcePath(projected, 'win32'); },
        nativeWindowsWorkspaceAdapter: folder => { assert.equal(folder, parent); return actualNativeWindows(projected, 'win32'); },
        route: async url => { throw new Error(`recovery must not submit ${url.pathname}`); },
      }, async ({ warnings, errors }) => {
        assert.equal(scope().folders[0].path, parentPath);
        const directory = path.join(profileStoragePath, 'repository-recovery-v1');
        const deadline = performance.now() + 3000;
        while (!(fs.existsSync(directory) && fs.readdirSync(directory).some(name => name.endsWith('.json'))
          && !fs.readdirSync(directory).some(name => name.endsWith('.lock'))) && performance.now() < deadline)
          await new Promise(resolve => setTimeout(resolve, 2));
        assert.ok(fs.existsSync(directory) && fs.readdirSync(directory).some(name => name.endsWith('.json')),
          'actual recovery must seed physical folder, not attempt lstat on snapshot transport');
        assert.deepEqual(workspaceStateStorage.get(REPOSITORY_CONTEXT_STATE_KEY), metadata);
        assert.deepEqual(warnings, []); assert.deepEqual(errors, []); assert.ok(admissions > 0);
      });
    }
    for (const rejected of [
      { uri: { scheme: 'file', authority: 'server', path: '/share', fsPath: String.raw`\\server\share` } },
      { uri: { scheme: 'memfs', authority: '', path: '/virtual', fsPath: '/virtual' } },
    ]) {
      const profileStoragePath = path.join(root, `rejected-${rejected.uri.scheme}`);
      const workspaceStateStorage = new Map([[REPOSITORY_CONTEXT_STATE_KEY, metadata]]);
      let scope;
      await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage, profileStoragePath, sessionId,
        captureRepositoryRecoveryScope: value => { scope = value; },
        workspaceSourcePathAdapter: () => actualSourcePath(rejected, 'win32'),
        route: async url => { throw new Error(`unsupported recovery must not submit ${url.pathname}`); },
      }, async () => {
        assert.equal(scope(), undefined);
        assert.equal(fs.existsSync(path.join(profileStoragePath, 'repository-recovery-v1')), false);
        assert.deepEqual(workspaceStateStorage.get(REPOSITORY_CONTEXT_STATE_KEY), metadata);
      });
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});


test('repository recovery scope preserves mounted Remote WSL path when fsPath contains authority', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lomo-recovery-mounted-')));
  const parentPath = path.join(root, 'workspace'); fs.mkdirSync(parentPath);
  const uri = { scheme: 'vscode-remote', authority: 'wsl+Ubuntu', path: parentPath,
    fsPath: String.raw`\\wsl.localhost\Ubuntu\home\owned\workspace`,
    toString: () => `vscode-remote://wsl+Ubuntu${parentPath}` };
  const parent = { name: 'workspace', uri };
  const metadata = { schema_version: 1, managed_parents: [uri.toString()], roots: [] };
  const workspaceStateStorage = new Map([[REPOSITORY_CONTEXT_STATE_KEY, metadata]]);
  const profileStoragePath = path.join(root, 'profile'); let scope;
  try {
    await withExtensionFixture({ workspaceFolders: [parent], workspaceStateStorage, profileStoragePath,
      sessionId: 'c23172b2-77a6-45ec-a570-779f20a58dd01792350634333',
      captureRepositoryRecoveryScope: value => { scope = value; },
      route: async url => { throw new Error(`mounted recovery must not submit ${url.pathname}`); },
    }, async ({ warnings, errors }) => {
      assert.notEqual(uri.fsPath, uri.path);
      assert.equal(scope().folders[0].path, parentPath, 'mounted WSL keeps admitted uri.path, not authority-bearing fsPath');
      const directory = path.join(profileStoragePath, 'repository-recovery-v1');
      const deadline = performance.now() + 3000;
      while (!(fs.existsSync(directory) && fs.readdirSync(directory).some(name => name.endsWith('.json'))
        && !fs.readdirSync(directory).some(name => name.endsWith('.lock'))) && performance.now() < deadline)
        await new Promise(resolve => setTimeout(resolve, 2));
      assert.ok(fs.existsSync(directory) && fs.readdirSync(directory).some(name => name.endsWith('.json')));
      assert.deepEqual(workspaceStateStorage.get(REPOSITORY_CONTEXT_STATE_KEY), metadata);
      assert.deepEqual(warnings, []); assert.deepEqual(errors, []);
    });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
