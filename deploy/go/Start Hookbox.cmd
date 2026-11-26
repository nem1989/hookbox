@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
powershell.exe -NoLogo -NoProfile -Command ^
  "$ErrorActionPreference = 'Stop';" ^
  "if (!(Test-Path -LiteralPath 'config.yaml')) { [IO.File]::Copy((Join-Path $PWD 'config.example.yaml'), (Join-Path $PWD 'config.yaml')) };" ^
  "if (!$env:HOOKBOX_ADMIN_SHA256) {" ^
  "  $key = & '.\hookbox.exe' --generate-token | ConvertFrom-Json;" ^
  "  if ($LASTEXITCODE -ne 0 -or !$key.token -or $key.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Cannot generate Manager token' };" ^
  "  $env:HOOKBOX_ADMIN_SHA256 = $key.sha256;" ^
  "  Write-Output ('Manager sign-in token: ' + $key.token)" ^
  "} else { Write-Output 'Use your configured Manager token.' };" ^
  "Write-Output 'Once the management listener is ready, open Hookbox Manager.exe. Keep this window open.';" ^
  "& '.\hookbox.exe' --config '.\config.yaml'; exit $LASTEXITCODE"
set "hookboxExit=%errorlevel%"
if not "%hookboxExit%"=="0" pause
popd
exit /b %hookboxExit%
