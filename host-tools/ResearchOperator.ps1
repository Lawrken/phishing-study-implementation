<# Operate the real, finite VM collector. It verifies before visiting dataset sites. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Inspect','Run','Status','Stop','Report','View')][string]$Mode,
    [ValidateRange(1,400)][int]$MaxAttempts = 10,
    [switch]$VerifyOnly,
    [Alias('Continue')][switch]$ContinuePrevious,
    [string]$RunId
)
$ErrorActionPreference = 'Stop'
if ($Mode -eq 'Inspect') { & (Join-Path $PSScriptRoot 'Check-ResearchHost.ps1'); exit }
. (Join-Path $PSScriptRoot 'Resolve-ResearchPython.ps1')
$taskPython = Resolve-ResearchPython
$taskArguments = @((Join-Path $PSScriptRoot 'ResearchOperator.py'), $Mode.ToLowerInvariant(), '--max-attempts', $MaxAttempts)
if ($VerifyOnly) { $taskArguments += '--verify-only' }
if ($ContinuePrevious) { $taskArguments += '--continue-previous' }
if ($RunId) { $taskArguments += @('--run-id', $RunId) }
& $taskPython @taskArguments
if ($LASTEXITCODE -ne 0) { throw 'Operator command did not pass. Read the terminal message and saved result.' }
