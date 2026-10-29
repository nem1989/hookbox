#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDirectory,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$TokenSha256,
    [string]$ConfigPath,
    [string]$PythonPath,
    [string]$NssmPath = 'nssm.exe',
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$ServiceName = 'hookbox'
)

$ErrorActionPreference = 'Stop'
$InstallDirectory = (Resolve-Path -LiteralPath $InstallDirectory).Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $InstallDirectory 'config.yaml' }
if (-not $PythonPath) { $PythonPath = Join-Path $InstallDirectory '.venv\Scripts\python.exe' }
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$PythonPath = (Resolve-Path -LiteralPath $PythonPath).Path
$MainPath = (Resolve-Path -LiteralPath (Join-Path $InstallDirectory 'main.py')).Path
$NssmExecutable = (Get-Command $NssmPath -CommandType Application -ErrorAction Stop).Source

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists. No settings were changed."
}

# Preserve literal quotes and paths with spaces under Windows PowerShell 5.1 too.
function ConvertTo-NativeArgument([string]$Value) {
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-Nssm([string[]]$Arguments) {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $NssmExecutable
    $start.Arguments = ($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "NSSM failed with exit code $($process.ExitCode). Inspect the partially installed service before retrying."
        }
    }
    finally {
        $process.Dispose()
    }
}

$LogDirectory = Join-Path $InstallDirectory 'logs'
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
$ApplicationArguments = (ConvertTo-NativeArgument $MainPath) + ' --config ' + (ConvertTo-NativeArgument $ConfigPath)

Invoke-Nssm @('install', $ServiceName, $PythonPath)
Invoke-Nssm @('set', $ServiceName, 'AppDirectory', $InstallDirectory)
Invoke-Nssm @('set', $ServiceName, 'AppParameters', $ApplicationArguments)
Invoke-Nssm @('set', $ServiceName, 'ObjectName', 'NT AUTHORITY\LocalService')
Invoke-Nssm @('set', $ServiceName, 'Start', 'SERVICE_AUTO_START')
Invoke-Nssm @('set', $ServiceName, 'AppEnvironmentExtra', 'PYTHONUNBUFFERED=1', "PYTHON_EXECUTABLE=$PythonPath", "WEBHOOK_TOKEN_SHA256=$TokenSha256")
Invoke-Nssm @('set', $ServiceName, 'AppStdout', (Join-Path $LogDirectory 'stdout.log'))
Invoke-Nssm @('set', $ServiceName, 'AppStderr', (Join-Path $LogDirectory 'stderr.log'))
Invoke-Nssm @('set', $ServiceName, 'AppRotateFiles', '1')
Invoke-Nssm @('set', $ServiceName, 'AppRotateOnline', '1')
Invoke-Nssm @('set', $ServiceName, 'AppRotateBytes', '10485760')
Invoke-Nssm @('set', $ServiceName, 'AppExit', 'Default', 'Restart')
Invoke-Nssm @('set', $ServiceName, 'AppRestartDelay', '5000')
Invoke-Nssm @('set', $ServiceName, 'AppNoConsole', '0')
Invoke-Nssm @('set', $ServiceName, 'AppStopMethodSkip', '0')
Invoke-Nssm @('set', $ServiceName, 'AppStopMethodConsole', '120000')

Write-Host "Service '$ServiceName' installed, not started. Grant LocalService read/execute access to the application and modify access to '$LogDirectory', then run: Start-Service '$ServiceName'"
