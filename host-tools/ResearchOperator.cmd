@echo off
setlocal
if "%~1"=="" (
    echo Usage: host-tools\ResearchOperator.cmd -Mode Inspect
    echo        host-tools\ResearchOperator.cmd -Mode Run -MaxAttempts 10
    echo        host-tools\ResearchOperator.cmd -Mode Status
    exit /b 2
)
if not exist "%~dp0ResearchOperator.ps1" (
    echo Error: ResearchOperator.ps1 is missing beside this launcher.
    exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -File "%~dp0ResearchOperator.ps1" %*
exit /b %errorlevel%
