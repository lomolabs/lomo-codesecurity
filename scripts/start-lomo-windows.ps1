# Fixed native phase, invoked by start-lomo-windows.py with the shared private
# storage functions prepended. No bootstrap or runtime secret is accepted here.
$ErrorActionPreference = 'Stop'
trap { [Console]::Out.Write('{"error_code":"windows_source_startup_refused"}'); exit 1 }
function Refuse-Handoff { throw 'windows-source-startup-refused' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$utf8 = [Text.UTF8Encoding]::new($false, $true)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$raw = [Console]::In.ReadToEnd()
if ($raw.Length -gt 16384) { Refuse-Handoff }
$request = ConvertFrom-Json -InputObject $raw
if ((@($request.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'checkout,code,distro,editor,installation_id,native_helper_hashes,native_script,phase,profile,state_dir,vsix_path,vsix_sha256,workspace' -or
    $request.phase -notin @('preflight','inspect','install','prepare-remote','open') -or
    $request.editor -notin @('native','remote-wsl') -or
    ($request.phase -eq 'prepare-remote' -and $request.editor -ne 'remote-wsl') -or
    ($request.editor -eq 'remote-wsl' -and $request.phase -in @('inspect','install')) -or
    $request.distro -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
    $request.profile.Length -lt 1 -or $request.profile.Length -gt 128 -or
    $request.profile.Trim() -cne $request.profile -or $request.profile -match '[\p{Cc}\p{Cf}]' -or
    ($null -ne $request.installation_id -and $request.installation_id -cnotmatch '^[a-f0-9]{12}$')) { Refuse-Handoff }
Assert-LocalPath $request.code
$code = Get-Item -LiteralPath $request.code -Force
if ($code.PSIsContainer -or $code.Name -cne 'Code.exe') { Refuse-Handoff }
$items = @($code)
if ($request.editor -eq 'native') {
    Assert-LocalPath $request.workspace
    $workspace = Get-Item -LiteralPath $request.workspace -Force
    if (-not $workspace.PSIsContainer) { Refuse-Handoff }
    $items += $workspace
} elseif ($request.workspace.Length -lt 2 -or $request.workspace.Length -gt 4096 -or
    -not $request.workspace.StartsWith('/') -or $request.workspace -match '[\\\p{Cc}\p{Cf}]') { Refuse-Handoff }
foreach ($item in $items) {
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Refuse-Handoff }
        if ($ancestor -is [IO.DirectoryInfo]) { $ancestor = $ancestor.Parent } else { $ancestor = $ancestor.Directory }
    }
}
$signature = Get-AuthenticodeSignature -LiteralPath $request.code
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') { Refuse-Handoff }
$local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
Assert-PrivatePath $local $true
$state = [IO.Path]::Combine($local, 'lomo-kodesec')
$editor = [IO.Path]::Combine($state, 'native-editor')
$marker = [IO.Path]::Combine($editor, 'installation-v1.json')
$userData = [IO.Path]::Combine($editor, 'user-data')
$extensions = [IO.Path]::Combine($editor, 'extensions')
$packages = [IO.Path]::Combine($editor, 'package')
$wslExecutable = $null
if ($request.editor -eq 'remote-wsl') {
    $wslExecutable = [IO.Path]::Combine([Environment]::SystemDirectory, 'wsl.exe')
    Assert-LocalPath $wslExecutable
    $wslFile = Get-Item -LiteralPath $wslExecutable -Force
    if ($wslFile.PSIsContainer -or ($wslFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Refuse-Handoff }
}
# Only this exact public installer may be executed through this selected
# distro's mapping, including the read-only version preflight.
$prefix = '\\wsl.localhost\' + $request.distro + '\'
$alternate = '\\wsl$\' + $request.distro + '\'
$checkoutSuffix = $request.checkout.TrimStart('/').Replace('/', '\')
if ($request.native_script -cne ($prefix + $checkoutSuffix + '\scripts\windows-native-editor.mjs') -and
    $request.native_script -cne ($alternate + $checkoutSuffix + '\scripts\windows-native-editor.mjs')) { Refuse-Handoff }
$helperPaths = @('scripts/windows-native-editor.mjs', 'extensions/vscode/scripts/install.mjs',
    'extensions/vscode/package.json', 'extensions/vscode/test/ui/compatibility-lock.json')
if ($request.native_helper_hashes -isnot [pscustomobject] -or
    (@($request.native_helper_hashes.PSObject.Properties.Name | Sort-Object) -join ',') -cne
    (@($helperPaths | Sort-Object) -join ',')) { Refuse-Handoff }
foreach ($relative in $helperPaths) {
    if ([string]$request.native_helper_hashes.$relative -cnotmatch '^[a-f0-9]{64}$') { Refuse-Handoff }
}
$helperSourceRoot = $request.native_script.Substring(0, $request.native_script.Length - '\scripts\windows-native-editor.mjs'.Length)
function Invoke-LocalNativeEditor([object]$native) {
    # Node in current VS Code refuses WSL UNC files. Keep the exact public
    # helper import closure in a disposable, account-private local directory.
    $temp = [IO.Path]::Combine($local, 'lomo-kodesec-helper-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $temp) { Refuse-Handoff }
    $createdDirectories = @()
    $createdFiles = @()
    try {
        [void][IO.Directory]::CreateDirectory($temp, (New-PrivateSecurity $true))
        $createdDirectories += $temp
        Assert-PrivatePath $temp $true
        foreach ($relativeDirectory in @('scripts', 'extensions', 'extensions\vscode',
                'extensions\vscode\scripts', 'extensions\vscode\test', 'extensions\vscode\test\ui')) {
            $directory = [IO.Path]::Combine($temp, $relativeDirectory)
            if (Test-Path -LiteralPath $directory) { Refuse-Handoff }
            [void][IO.Directory]::CreateDirectory($directory, (New-PrivateSecurity $true))
            $createdDirectories += $directory
            Assert-PrivatePath $directory $true
        }
        foreach ($relative in $helperPaths) {
            $suffix = $relative.Replace('/', '\')
            $sourcePath = [IO.Path]::Combine($helperSourceRoot, $suffix)
            $destination = [IO.Path]::Combine($temp, $suffix)
            $source = Get-Item -LiteralPath $sourcePath -Force
            if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $source.Length -le 0 -or $source.Length -gt 262144 -or
                (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                    [string]$request.native_helper_hashes.$relative) { Refuse-Handoff }
            $reader = [IO.FileStream]::new($sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                $writer = New-PrivateFile $destination
                $createdFiles += $destination
                try {
                    if ($reader.Length -ne $source.Length) { Refuse-Handoff }
                    $buffer = [byte[]]::new(8192)
                    $remaining = [long]$source.Length
                    while ($remaining -gt 0) {
                        $count = $reader.Read($buffer, 0, [int][Math]::Min($remaining, $buffer.Length))
                        if ($count -le 0) { Refuse-Handoff }
                        $writer.Write($buffer, 0, $count)
                        $remaining -= $count
                    }
                    if ($reader.ReadByte() -ne -1 -or $writer.Length -ne $source.Length) { Refuse-Handoff }
                    $writer.Flush($true)
                } finally { $writer.Dispose() }
            } finally { $reader.Dispose() }
            Assert-PrivatePath $destination $false
            if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                    [string]$request.native_helper_hashes.$relative) { Refuse-Handoff }
        }
        $script = [IO.Path]::Combine($temp, 'scripts\windows-native-editor.mjs')
        $settings = [Diagnostics.ProcessStartInfo]::new()
        $settings.FileName = $request.code
        $settings.Arguments = '"' + $script + '"'
        $settings.UseShellExecute = $false
        $settings.CreateNoWindow = $true
        $settings.RedirectStandardInput = $true
        $settings.RedirectStandardOutput = $true
        $settings.RedirectStandardError = $true
        $settings.EnvironmentVariables['ELECTRON_RUN_AS_NODE'] = '1'
        [void]$settings.EnvironmentVariables.Remove('VSCODE_DEV')
        [void]$settings.EnvironmentVariables.Remove('NODE_UNC_HOST_ALLOWLIST')
        if ($request.editor -eq 'native') { $settings.EnvironmentVariables['KODESEC_STATE_DIR'] = $state }
        else { [void]$settings.EnvironmentVariables.Remove('KODESEC_STATE_DIR') }
        $child = [Diagnostics.Process]::Start($settings)
        try {
            $stdout = $child.StandardOutput.ReadToEndAsync()
            $stderr = $child.StandardError.ReadToEndAsync()
            $child.StandardInput.Write(($native | ConvertTo-Json -Compress))
            $child.StandardInput.Close()
            $completed = $child.WaitForExit(312000)
            if (-not $completed) {
                $child.Kill()
                if (-not $child.WaitForExit(10000)) { Refuse-Handoff }
                Refuse-Handoff
            }
            if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { Refuse-Handoff }
            $output = $stdout.GetAwaiter().GetResult()
            $errorText = $stderr.GetAwaiter().GetResult()
            if ($output.Length -gt 8192 -or $errorText.Length -gt 8192) { Refuse-Handoff }
            return [pscustomobject]@{output=$output; exit_code=$child.ExitCode}
        } finally { $child.Dispose() }
    } finally {
        for ($index = $createdFiles.Count - 1; $index -ge 0; $index--) {
            $path = $createdFiles[$index]
            Assert-PrivatePath $path $false
            [IO.File]::Delete($path)
        }
        for ($index = $createdDirectories.Count - 1; $index -ge 0; $index--) {
            $path = $createdDirectories[$index]
            Assert-PrivatePath $path $true
            [IO.Directory]::Delete($path, $false)
        }
    }
}
function Invoke-NativeEditor {
    $native = [ordered]@{phase=$request.phase; editor=$request.editor; distro=$request.distro; cli=$request.code; workspace=$request.workspace; profile=$request.profile;
        userDataDirectory=$userData; extensionsDirectory=$extensions; outputDirectory=$packages; wslExecutable=$wslExecutable}
    $executed = Invoke-LocalNativeEditor $native
    if ($executed.exit_code -ne 0) { Refuse-Handoff }
    $lines = @(([string]$executed.output -split '\r?\n') | Where-Object { $_.StartsWith('LOMO_NATIVE_EDITOR_RESULT:') })
    if ($lines.Count -ne 1 -or $lines[0].Length -gt 8192) { Refuse-Handoff }
    $result = ConvertFrom-Json -InputObject $lines[0].Substring('LOMO_NATIVE_EDITOR_RESULT:'.Length)
    if ($result.phase -cne $request.phase) { Refuse-Handoff }
    return $result
}
$binding = [ordered]@{v=1; installation_id=$request.installation_id; distro=$request.distro; state_dir=$request.state_dir; profile=$request.profile}
foreach ($directory in @($state, $editor, $userData, $extensions, $packages)) {
    if (Test-Path -LiteralPath $directory) { Assert-PrivatePath $directory $true }
}
if (Test-Path -LiteralPath $marker) {
    Assert-PrivatePath $marker $false
    $stream = [IO.FileStream]::new($marker, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($stream.Length -gt 2048) { Refuse-Handoff }
        $reader = [IO.StreamReader]::new($stream, $utf8, $false, 2048, $true)
        try { $observed = ConvertFrom-Json -InputObject ($reader.ReadToEnd()) } finally { $reader.Dispose() }
        if ((@($observed.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'distro,installation_id,profile,state_dir,v' -or
            $observed.v -ne 1 -or $observed.installation_id -cne $request.installation_id -or
            $observed.distro -cne $request.distro -or $observed.state_dir -cne $request.state_dir -or
            $observed.profile -cne $request.profile) { Refuse-Handoff }
    } finally { $stream.Dispose() }
} elseif ((Test-Path -LiteralPath $editor) -and @(Get-ChildItem -LiteralPath $editor -Force | Select-Object -First 1).Count -ne 0) {
    Refuse-Handoff
}
if ($request.phase -eq 'preflight') {
    $result = Invoke-NativeEditor
    if ((@($result.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'phase,status,version,wsl_account' -or
        $result.status -cne 'ready' -or $result.version -cnotmatch '^[0-9]+[.][0-9]+[.][0-9]+$') { Refuse-Handoff }
    [ordered]@{phase='preflight'; status='ready'; user_data=$userData; extensions=$extensions; wsl_account=$result.wsl_account} | ConvertTo-Json -Depth 4 -Compress
    exit 0
}
if ($null -eq $request.installation_id -or $request.vsix_sha256 -cnotmatch '^[a-f0-9]{64}$') { Refuse-Handoff }
# Only these exact public files may be read through this selected distro's UNC
# mapping. The editor workspace itself remains a native local-drive directory.
if ($request.vsix_path -cnotmatch ('^' + [regex]::Escape($request.native_script.Substring(0, $request.native_script.Length - '\scripts\windows-native-editor.mjs'.Length)) + '\\\.kodesec-test\\vscode\\code-security-[0-9]+[.][0-9]+[.][0-9]+[.]vsix$')) { Refuse-Handoff }
foreach ($directory in @($state, $editor)) {
    if (-not (Test-Path -LiteralPath $directory)) { [void][IO.Directory]::CreateDirectory($directory, (New-PrivateSecurity $true)) }
    Assert-PrivatePath $directory $true
}
if (-not (Test-Path -LiteralPath $marker)) {
    $stream = New-PrivateFile $marker
    try { Write-Record $stream $binding } finally { $stream.Dispose() }
}
foreach ($directory in @($userData, $extensions, $packages)) {
    if (-not (Test-Path -LiteralPath $directory)) { [void][IO.Directory]::CreateDirectory($directory, (New-PrivateSecurity $true)) }
    Assert-PrivatePath $directory $true
}
$source = Get-Item -LiteralPath $request.vsix_path -Force
if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $source.Length -le 0 -or $source.Length -gt 2097152 -or
    (Get-FileHash -LiteralPath $request.vsix_path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $request.vsix_sha256) { Refuse-Handoff }
$candidate = [IO.Path]::Combine($packages, $source.Name)
if (Test-Path -LiteralPath $candidate) {
    Assert-PrivatePath $candidate $false
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -cne $request.vsix_sha256) {
        # This is the one exact public, launcher-owned package file. Preserve its
        # replacement until a subsequent verified install; no profile is reset.
        [IO.File]::Copy($request.vsix_path, $candidate, $true)
    }
} else { [IO.File]::Copy($request.vsix_path, $candidate, $false) }
Assert-PrivatePath $candidate $false
if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -cne $request.vsix_sha256) { Refuse-Handoff }
$result = Invoke-NativeEditor
if ($request.phase -eq 'prepare-remote') {
    if ((@($result.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'phase,status,transport_identity' -or
        $result.status -cne 'ready') { Refuse-Handoff }
    $result = [ordered]@{phase='prepare-remote'; status='staged'; transport_identity=$result.transport_identity;
        vsix_path=$candidate; vsix_sha256=$request.vsix_sha256}
}
[ordered]@{phase=$request.phase; result=$result; user_data=$userData; extensions=$extensions} | ConvertTo-Json -Depth 4 -Compress
