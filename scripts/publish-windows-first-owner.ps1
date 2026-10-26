# Fixed installer program: its bounded stdin contains only the first-owner DTO.
# Never enable transcription, print that input, or pass it in process arguments.
$ErrorActionPreference = 'Stop'
trap { [Console]::Out.Write('{"error_code":"native_first_owner_handoff_refused"}'); exit 1 }
function Refuse-Handoff { throw 'native-first-owner-handoff-refused' }
$raw = [Console]::In.ReadToEnd()
if ($raw.Length -gt 4096) { Refuse-Handoff }
$request = ConvertFrom-Json -InputObject $raw
if ((@($request.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'bootstrap,control_origin,installation_id' -or
    $request.installation_id -cnotmatch '^[a-f0-9]{12}$' -or
    $request.control_origin -cnotmatch '^http://127[.]0[.]0[.]1:([1-9][0-9]{0,4})$') { Refuse-Handoff }
$port = [int]($request.control_origin.Split(':')[-1])
if ($port -gt 65535) { Refuse-Handoff }
if ($null -ne $request.bootstrap) {
    if ((@($request.bootstrap.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'bootstrap_token,control_origin,installation_id,v' -or
        $request.bootstrap.v -ne 1 -or $request.bootstrap.control_origin -cne $request.control_origin -or
        $request.bootstrap.installation_id -cne $request.installation_id -or
        $request.bootstrap.bootstrap_token -cnotmatch '^[A-Za-z0-9_-]{43}$') { Refuse-Handoff }
}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$utf8 = [Text.UTF8Encoding]::new($false, $true)
function Complete-Handoff([string]$status) {
    [ordered]@{status=$status; installation_id=$request.installation_id; control_origin=$request.control_origin} |
        ConvertTo-Json -Compress
}
# GetFolderPath runs in the native account; inherited WSL HOME/XDG/state values
# are not native destinations and are deliberately not consulted.
$local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
Assert-PrivatePath $local $true
$state = [IO.Path]::Combine($local, 'lomo-kodesec')
$artifact = [IO.Path]::Combine($state, 'first-owner-browser-v1.json')
$journal = [IO.Path]::Combine($state, 'first-owner-windows-handoff-v1.json')
if (-not (Test-Path -LiteralPath $state)) {
    if ($null -eq $request.bootstrap) { Complete-Handoff 'unavailable'; exit 0 }
    [void][IO.Directory]::CreateDirectory($state, (New-PrivateSecurity $true))
}
Assert-PrivatePath $state $true
if (Test-Path -LiteralPath $journal) {
    Assert-PrivatePath $journal $false
    $handle = [IO.FileStream]::new($journal, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($handle.Length -lt 2 -or $handle.Length -gt 2048) { Refuse-Handoff }
        $reader = [IO.StreamReader]::new($handle, $utf8, $false, 2048, $true)
        try { $record = ConvertFrom-Json -InputObject ($reader.ReadToEnd()) } finally { $reader.Dispose() }
        if ((@($record.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'control_origin,installation_id,state,v' -or
            $record.v -ne 1 -or $record.installation_id -cne $request.installation_id -or
            $record.control_origin -cne $request.control_origin -or $record.state -cne 'published') { Refuse-Handoff }
        if (Test-Path -LiteralPath $artifact) { Assert-PrivatePath $artifact $false }
        Complete-Handoff 'retained'
    } finally { $handle.Dispose() }
    exit 0
}
if (Test-Path -LiteralPath $artifact) { Refuse-Handoff }
if ($null -eq $request.bootstrap) { Complete-Handoff 'unavailable'; exit 0 }
$marker = New-PrivateFile $journal
try {
    Assert-PrivatePath $journal $false
    $record = [ordered]@{v=1; installation_id=$request.installation_id; control_origin=$request.control_origin; state='reserved'}
    Write-Record $marker $record
    $destination = New-PrivateFile $artifact
    try {
        Assert-PrivatePath $state $true
        Assert-PrivatePath $artifact $false
        Write-Record $destination $request.bootstrap
    } finally { $destination.Dispose() }
    $record.state = 'published'
    Write-Record $marker $record
    Complete-Handoff 'published'
} finally { $marker.Dispose() }
# An interrupted reserved journal remains a refusal, not permission to replay.
