import { spawnSync } from 'node:child_process';

export class OwnedHandoffError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OwnedHandoffError';
    this.code = code;
  }
}

// Metadata only: the credential is never read by PowerShell or passed to it.
// Keep this command fixed; literal paths arrive through bounded stdin JSON.
function windowsHandoffAclCommand(inheritedProjection = '', batch = false) {
  return String.raw`
$ErrorActionPreference = 'Stop'
trap { [Console]::Out.Write('{"failed":true}'); exit 1 }
$raw = [Console]::In.ReadToEnd()
if ($raw.Length -gt 32768) { throw 'input bound' }
$inputPaths = ConvertFrom-Json -InputObject $raw
if (@($inputPaths.PSObject.Properties).Count -ne 2) { throw 'input shape' }
$root = [IO.Path]::GetFullPath($inputPaths.root).TrimEnd([char]'\')
${batch ? 'function Read-PathProof([string]$path) {\n' : ''}$file = [IO.Path]::GetFullPath(${batch ? '$path' : '$inputPaths.path'})
if ($root -notmatch '^[A-Za-z]:\\' -or $root.Length -lt 4 -or
    -not $file.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'path boundary' }
$suffix = $file.Substring($root.Length + 1)
$parts = @($suffix.Split([char]'\'))
if ($parts.Count -lt 1 -or $parts.Count -gt 32) { throw 'depth bound' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$entries = @()
$current = $root
for ($index = 0; $index -le $parts.Count; $index++) {
    $relative = ''
    if ($index -gt 0) {
        $current = Join-Path -Path $current -ChildPath $parts[$index - 1]
        $relative = [string]::Join('/', $parts[0..($index - 1)])
    }
    $item = Get-Item -LiteralPath $current -Force
    $acl = Get-Acl -LiteralPath $current
    $access = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($access.Count -gt 16) { throw 'rule bound' }
    $rules = @($access | ForEach-Object {
        [ordered]@{sid=$_.IdentityReference.Value; allow=($_.AccessControlType -eq 'Allow');
            rights=[int]$_.FileSystemRights; inheritance=[int]$_.InheritanceFlags;
            propagation=[int]$_.PropagationFlags${inheritedProjection}}
    })
    $entries += [ordered]@{relative_path=$relative; directory=[bool]$item.PSIsContainer;
        reparse=[bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint);
        owner_sid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
        protected=[bool]$acl.AreAccessRulesProtected; rules=$rules}
}
[ordered]@{schema='lomo-windows-private-handoff-acl/v1'; current_sid=$identity;
    entries=$entries}${batch ? String.raw`
}
if ($inputPaths.paths -isnot [array] -or $inputPaths.paths.Count -lt 1 -or $inputPaths.paths.Count -gt 8) { throw 'batch bound' }
$proofs = @($inputPaths.paths | ForEach-Object { Read-PathProof $_ })
[ordered]@{schema='lomo-windows-private-handoff-acl-batch/v1'; proofs=$proofs} | ConvertTo-Json -Depth 8 -Compress
` : ' | ConvertTo-Json -Depth 6 -Compress'}
`;
}
const WINDOWS_HANDOFF_ACL_COMMAND = windowsHandoffAclCommand();
const WINDOWS_HANDOFF_ACL_INHERITED_COMMAND = windowsHandoffAclCommand('; inherited=[bool]$_.IsInherited');
const WINDOWS_HANDOFF_ACL_BATCH_COMMAND = windowsHandoffAclCommand('; inherited=[bool]$_.IsInherited', true);

/** Same path proofs and native ACL reader, with one startup for up to eight paths. */
export function readWindowsHandoffAclBatch(paths, root, run = spawnSync) {
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > 8
    || paths.some(path => typeof path !== 'string') || new Set(paths).size !== paths.length) {
    throw new TypeError('ACL batch requires one to eight distinct paths.');
  }
  const input = JSON.stringify({ paths, root });
  if (Buffer.byteLength(input) > 32768) throw new TypeError('ACL batch input exceeds its bound.');
  const result = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_HANDOFF_ACL_BATCH_COMMAND], {
    input, encoding: 'utf8', windowsHide: true, timeout: 10_000, maxBuffer: 65536, shell: false,
  });
  if (result.error || result.signal || result.status !== 0 || typeof result.stdout !== 'string'
    || Buffer.byteLength(result.stdout) > 65536) {
    throw new OwnedHandoffError('windows_acl_unavailable', 'Windows private batch permissions could not be inspected.');
  }
  let proof;
  try { proof = JSON.parse(result.stdout); } catch {
    throw new OwnedHandoffError('windows_acl_invalid', 'Windows private batch permission evidence is invalid.');
  }
  if (!proof || Object.keys(proof).sort().join(',') !== 'proofs,schema'
    || proof.schema !== 'lomo-windows-private-handoff-acl-batch/v1'
    || !Array.isArray(proof.proofs) || proof.proofs.length !== paths.length) {
    throw new OwnedHandoffError('windows_acl_invalid', 'Windows private batch permission evidence is incomplete.');
  }
  return proof.proofs;
}

export function readWindowsHandoffAclProof(path, root, run = spawnSync, { includeInherited = false } = {}) {
  if (typeof includeInherited !== 'boolean') throw new TypeError('ACL projection option must be boolean.');
  const command = includeInherited ? WINDOWS_HANDOFF_ACL_INHERITED_COMMAND : WINDOWS_HANDOFF_ACL_COMMAND;
  const result = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
    input: JSON.stringify({ path, root }), encoding: 'utf8', windowsHide: true,
    timeout: 10_000, maxBuffer: 16 * 1024, shell: false,
  });
  if (result.error || result.signal || result.status !== 0 || typeof result.stdout !== 'string'
    || Buffer.byteLength(result.stdout, 'utf8') > 16 * 1024) {
    throw new OwnedHandoffError('windows_acl_unavailable', 'Windows private handoff permissions could not be inspected.');
  }
  try { return JSON.parse(result.stdout); } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new OwnedHandoffError('windows_acl_invalid', 'Windows private handoff permission evidence is invalid.');
  }
}

