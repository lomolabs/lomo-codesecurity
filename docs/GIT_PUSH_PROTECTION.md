# Git push protection

CodeSecurity can check ordinary pushes from one explicitly approved repository
clone. Local commits remain available. Protection requires an applied local
hook and current complete evidence for the outgoing committed history; a failed
workspace scan alone does not install protection.

This is a local safeguard, not unavoidable remote enforcement. See
[release status](RELEASE_STATUS.md) for accepted scopes, known issues and deferred
platform qualification. Do not replace existing remote controls or rely on this
preview as your only security control.

## Set up protection deliberately

1. Start the backend, connect your editor profile and authorize the exact source
   repository. Prepare the required scanners. Follow [platform setup](PLATFORM_SETUP.md)
   and the [extension guide](VS_CODE_EXTENSION.md) if needed.
2. Run **CodeSecurity: Protect Pushes…** for the intended clone. The Command
   Palette asks you to choose a repository; the Source Control repository menu
   uses its selected clone. Stale or ambiguous selections are refused.
3. Request repository access and approve that exact editor generation in the
   paired owner's browser. Ordinary IDE membership does not grant this separate
   repository permission.
4. Choose the requested On/Off setting, then explicitly **Apply** it in VS Code.
   Review the reported host state and any conflict before relying on protection.

The Web setting records **requested** state. **Change pending · Apply in VS Code**
means the host has not applied it, including a request to turn protection Off.
An already applied On hook may still block during that pending state. **On · last
verified** and **Off · last applied** describe the last observation, not a
permanent guarantee about the next push.

The repository-local hook invokes a separately bundled host helper, including
when the editor is closed and the backend is available. Installation preserves
unrelated hooks and local hook-path configuration; a conflict that cannot be
composed safely is refused. It does not change global Git settings or remotes,
and the API receives no Docker socket or arbitrary host Git execution authority.

## Check outgoing commits

Use **CodeSecurity: Check Outgoing Commits…** to select the configured
destination, local branch/tag and explicit remote reference. Review the exact
committed history before its snapshots and scans are submitted. This command
does not perform a push.

The check binds the canonical repository, all outgoing ref/object pairs,
immutable source content, authorized coverage, current gate policy and scanner
evidence. A dirty working tree, unrelated repository, file/folder scan or the
dashboard's last selected scan cannot substitute for outgoing-commit evidence.
A secret added and removed in earlier outgoing history still travels to the
remote, so a clean tip alone is insufficient.

Each repository has an independent outcome. Unchanged immutable content can
reuse applicable results; changed policy, finding dispositions, scanner/data
identity or refs invalidate the corresponding approval. A catalog check alone
does not install data or change an otherwise matching result. Current readiness
still matters. The known rollback-status readiness issue can conservatively
refuse reuse; once scanner status settles, run **Check Outgoing Commits…** again.

Protection On requires a completed, applicable **pass**. Failed, missing, stale,
partial, cancelled or unavailable verification blocks the push. Disabling gate
evaluation is not a pass. Changing gate thresholds or finding dispositions
cannot repair incomplete coverage. Gate evaluation and installing/removing push
protection remain separate operations.

Cancelling an outgoing check stops its current cancellable job and retains
earlier results. If completion wins the race, the actual completed result remains
usable. A retained cancelled check offers **Start new check** after showing its
scope and prior scan/job identities. Declining starts no work. Accepting retains
the old result, rechecks current state and reuses applicable completed evidence.
Failed and partial results retain their existing recovery path. No cancelled
check is silently converted into a pass.

## Understand a blocked push

VS Code or GitLens may summarize a rejected push with generic advice to pull.
Inspect **Show Command Output** in VS Code or **Open Output Channel** in GitLens.
If it says **Lomo blocked this push**, review protection and the outgoing check
for that exact clone. Pulling alone does not resolve missing security evidence.

After a completed failed outgoing scan, **Review blocking findings** opens its
exact committed-tree scan, including an earlier historical tree with a clean
tip. Choose the intended scan if several trees fail. **Open protection settings**
opens that repository's record without changing a gate or permission.

Normal Git branch and remote setup still applies. An unpublished branch or a
client message such as “Nothing to push” may stop before the hook runs; it is
not a CodeSecurity allow decision. Confirm the intended branch and remote
instead of bypassing the hook to clear a generic editor error.

## Coverage and limits

Coverage is the regular-file content of newly outgoing commit trees, including
earlier outgoing history. Commit messages, tag messages and other non-file Git
metadata are not scanner inputs. Unsupported symlinks, submodules, shallow or
alternate object stores, and unverifiable coverage are explicitly refused.

The current [Git object helper](../extensions/vscode/src/git-push-objects.ts)
enforces these admission bounds:

| Boundary | Limit |
| --- | --- |
| One push | 64 refs, 256 distinct checked commits across refs, 32 KiB hook input |
| One immutable tree | 5,000 regular files, 8 MiB transferred per file, 64 MiB total file content |
| Eligible code analysis | 1 MiB per file; larger eligible code makes coverage incomplete |
| Paths | 64 components and 4,096 UTF-16 code units, with unsafe paths refused |
| One bounded Git metadata command | 4 MiB output |

For an existing remote ref, history excludes commits reachable from its old
commit, which must already be available locally. The new tip is always checked.
A new branch has no old base: all history reachable from its tip counts toward
the commit limit, even if another remote branch already contains it. No fetch
or history truncation is implicit.

A limit refusal approves no push. Select fewer refs for a ref-count refusal;
for history or tree limits, review the rejected scope and use a separately
approved review/enforcement path. A smaller workspace scan cannot fill the
missing proof. Being below these bounds does not itself establish coverage or
platform support.

Immutable Git uploads use [bounded source snapshot storage](SOURCE_SNAPSHOT_STORAGE.md).
One stable snapshot source belongs to each repository; a new project is not
created for every commit. Retained and interrupted data count toward storage
admission. Findings or unrelated state are not deleted to make room.

## Turn off or remove protection

Turning protection **Off** requires an explicit warning and host application.
Cancel leaves the setting unchanged. Once Off is applied, the helper does not
read source, require an online API or impose On-only source/ref limits. Scanning
remains available and remote rules still apply.

Off retains the repository registration and hook configuration for explicit
re-enabling. Removing protection is a separate action: in the exact owning
profile, choose **Protect Pushes… > Remove push protection from this clone…**
and confirm the repository. Removal deletes only the unchanged Lomo-owned hook
and protection registration, including its repository-specific grants and Git
metadata bindings. Projects, scans, findings, retained snapshots, pairing,
remotes and other tools' hooks remain intact.

A project still used by protection or its Git snapshot source cannot be deleted,
even while protection is Off. Remove the registration first; deleting retained
project data is a separate explicit operation.

If local hook removal succeeds while server cleanup is unavailable, pushes no
longer run that hook but registration cleanup remains pending. Retry removal in
the same profile when the service returns. Changed policy, revoked authority,
changed configuration or a new hook requires review. Retries do not silently
adopt new state or delete a replacement hook. Unknown or corrupt files are
preserved. An orphaned registration is not automatically rebound to a same-named
project.

After revoking and re-enrolling an editor, request and approve repository access
for its new generation, then explicitly Apply. The unchanged hook can advance
only when the same repository, profile, endpoint and helper binding still match.
Re-enrollment does not inherit an old grant; pushes stay blocked until valid
application succeeds.

## Validate a setup without publishing

For deliberate manual verification, use a disposable repository and an exact
local bare remote, separate from product source and normal projects. Confirm
the resolved destination before every test push. Review the remote refs before
and after actual ordinary Git pushes: a permitted push must change only the
intended refs, and a rejected or cancelled push must leave them unchanged.
Exercise the installed helper, not a simulated button or policy response.

Use synthetic examples without real secrets. Include earlier problematic
history followed by a clean tip, so checking only the latest files cannot appear
sufficient. Also review On/Off and cancelled-disable behavior, editor-closed
pushes, unavailable/stale evidence and preservation of other hooks. Record the
actual scope and results; a basic manual check does not qualify every ref type,
failure/recovery case or platform. Clean up only the disposable state you own.

## Security boundary

An owner can bypass a local hook with `git push --no-verify`, remove it or push
from another clone. Required CI checks may protect merges but do not prevent
code reaching a remote branch. Even a rejecting pre-receive hook acts after
object transfer; it cannot promise that source or secrets never left the machine.
See [Git hooks](https://git-scm.com/docs/githooks),
[push verification](https://git-scm.com/docs/git-push#Documentation/git-push.txt---no-verify)
and the [security policy](../SECURITY.md). Optional local Git hosting does not
install remote gate enforcement or authorize changes to a hosting service.
