function Resolve-ResearchPython {
    $taskRoot = Split-Path -Parent $PSScriptRoot
    $taskCandidates = @()
    if ($env:PHISHING_STUDY_PYTHON) { $taskCandidates += $env:PHISHING_STUDY_PYTHON }
    $taskCandidates += (Join-Path $taskRoot '.venv\Scripts\python.exe')
    $taskCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($taskCommand) { $taskCandidates += $taskCommand.Source }
    $taskCandidates += (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
    foreach ($taskCandidate in $taskCandidates) {
        if (Test-Path -LiteralPath $taskCandidate -PathType Leaf) {
            & $taskCandidate -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'
            if ($LASTEXITCODE -eq 0) { return $taskCandidate }
        }
    }
    throw 'Python 3.12 or newer was not found. Install 64-bit Python, reopen PowerShell, then run SetupResearch.ps1.'
}
