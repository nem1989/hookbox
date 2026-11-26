param(
    [string] $InstallDirectory = $PSScriptRoot,
    [string] $ConfigPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $AdminSha256
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath (Join-Path $InstallDirectory 'hookbox.exe')).ProviderPath
if (-not $ConfigPath) { $ConfigPath = Join-Path $InstallDirectory 'config.yaml' }
$config = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
& $exe --config $config --check-config
if ($LASTEXITCODE) { throw 'Invalid configuration' }
if (Get-Service -Name Hookbox -ErrorAction SilentlyContinue) { throw 'Hookbox service already exists' }
$binaryPath = '"{0}" --config "{1}"' -f $exe, $config
# Invoke sc.exe through ProcessStartInfo so the quotes inside binPath survive Windows PowerShell 5.1.
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = Join-Path $env:SystemRoot 'System32\sc.exe'
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.Arguments = 'create Hookbox binPath= "' + $binaryPath.Replace('"','\"') + '" start= auto obj= "NT AUTHORITY\LocalService"'
$process = [Diagnostics.Process]::Start($psi)
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw "sc.exe create failed ($($process.ExitCode))" }
try {
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Hookbox' -Name Environment -PropertyType MultiString -Value @("HOOKBOX_ADMIN_SHA256=$AdminSha256") | Out-Null
} catch {
    # Only reached after this invocation successfully created the service.
    & "$env:SystemRoot\System32\sc.exe" delete Hookbox | Out-Null
    throw
}
Write-Output 'Hookbox installed. Grant LocalService access to the configuration directory and start the service.'
