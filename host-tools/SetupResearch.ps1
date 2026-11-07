<# Prepare this computer's private runtime. Does not collect website data. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Region,
    [string]$InputsArchive,
    [switch]$DownloadsOnly
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Resolve-ResearchPython.ps1')
$taskPython = Resolve-ResearchPython
$taskVenv = Join-Path $taskRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskVenv)) {
    & $taskPython -m venv (Join-Path $taskRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the local Python environment.' }
}
& $taskVenv -m pip install -r (Join-Path $taskRoot 'replication\requirements-host.txt')
if ($LASTEXITCODE -ne 0) { throw 'Host dependencies could not be installed.' }
$taskArguments = @('-B', (Join-Path $PSScriptRoot 'PrepareResearchVM.py'), '--region', $Region)
if ($InputsArchive) { $taskArguments += @('--inputs-archive', $InputsArchive) }
if ($DownloadsOnly) { $taskArguments += '--downloads-only' }
& $taskVenv @taskArguments
if ($LASTEXITCODE -ne 0) { throw 'Setup stopped. Preserve its console and setup log; collection was not enabled.' }
