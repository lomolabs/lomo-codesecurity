# Shared fixed installer storage policy. The owning program supplies $sid,
# $utf8 and Refuse-Handoff; this file performs no work when loaded.
function Assert-LocalPath([string]$target) {
    if ($target.Length -lt 4 -or $target.Length -gt 4096 -or $target -notmatch '^[A-Za-z]:\\' -or
        -not [IO.Path]::GetFullPath($target).Equals($target, [StringComparison]::OrdinalIgnoreCase) -or
        $target.Substring(3) -match '[<>:"/|?*\p{Cc}\p{Cf}]') { Refuse-Handoff }
    foreach ($part in $target.Substring(3).Split('\')) {
        if (-not $part -or $part -in @('.', '..') -or $part -match '[. ]$' -or
            $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])([.]|$)') { Refuse-Handoff }
    }
}
function Assert-PrivatePath([string]$target, [bool]$directory) {
    Assert-LocalPath $target
    $item = Get-Item -LiteralPath $target -Force
    # Reject parent reparse traversal too: an ACL on an aliased target is not an
    # installation-owned canonical destination.
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Refuse-Handoff }
        if ($ancestor -is [IO.DirectoryInfo]) { $ancestor = $ancestor.Parent }
        else { $ancestor = $ancestor.Directory }
    }
    $acl = Get-Acl -LiteralPath $target
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ([bool]$item.PSIsContainer -ne $directory -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
        $rules.Count -lt 1 -or $rules.Count -gt 16) { Refuse-Handoff }
    $ownerFull = $false
    foreach ($rule in $rules) {
        $rights = [int]$rule.FileSystemRights
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @($sid.Value,'S-1-5-18','S-1-5-32-544') -or
            $rights -le 0 -or ($rights -band 0x1f01ff) -ne $rights -or
            (-not $directory -and ([int]$rule.InheritanceFlags -ne 0 -or [int]$rule.PropagationFlags -ne 0))) { Refuse-Handoff }
        if ($rule.IdentityReference.Value -eq $sid.Value -and $rights -eq 0x1f01ff -and
            ([int]$rule.PropagationFlags -band 2) -eq 0) { $ownerFull = $true }
    }
    if (-not $ownerFull) { Refuse-Handoff }
}
function New-PrivateSecurity([bool]$directory) {
    if ($directory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
        [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    return $acl
}
function New-PrivateFile([string]$target) {
    # CreateNew is mandatory: never replace either an existing credential or a
    # journal. The DACL is supplied at creation, before any secret is written.
    return [IO.FileStream]::new($target, [IO.FileMode]::CreateNew,
        ([Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write),
        [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, (New-PrivateSecurity $false))
}
function Write-Record([IO.FileStream]$stream, [object]$record) {
    $bytes = $utf8.GetBytes(($record | ConvertTo-Json -Depth 4 -Compress) + "`n")
    if ($bytes.Length -gt 2048) { Refuse-Handoff }
    $stream.Position = 0
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.SetLength($bytes.Length)
    $stream.Flush($true)
    $stream.Position = 0
    $readback = [byte[]]::new($bytes.Length + 1)
    $count = 0
    while ($count -lt $readback.Length) {
        $read = $stream.Read($readback, $count, $readback.Length - $count)
        if ($read -eq 0) { break }
        $count += $read
    }
    if ($count -ne $bytes.Length -or [Convert]::ToBase64String($readback, 0, $count) -cne [Convert]::ToBase64String($bytes)) { Refuse-Handoff }
}
