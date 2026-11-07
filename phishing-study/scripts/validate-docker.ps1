#Requires -Version 7.0
param(
    [string]$Output = ('validation/linux-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')),
    [string]$Image = 'phishing-study-fixtures:0.1.1'
)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskOutput = [IO.Path]::GetFullPath((Join-Path $taskRoot $Output))
if (-not $taskOutput.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Validation output must be inside the project directory.'
}
foreach ($taskEvidenceFile in @('test-report.json', 'build.txt', 'container.txt', 'selftest')) {
    if (Test-Path -LiteralPath (Join-Path $taskOutput $taskEvidenceFile)) {
        throw 'Use a fresh validation output directory to preserve previous setup and validation evidence.'
    }
}
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
Push-Location $taskRoot
try {
    & docker build --progress plain --tag $Image . 2>&1 | Tee-Object -FilePath (Join-Path $taskOutput 'build.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed; inspect build.txt.' }
    & docker image inspect $Image --format '{{json .}}' | Set-Content -LiteralPath (Join-Path $taskOutput 'image.json')
    if ($LASTEXITCODE -ne 0) { throw 'Docker image inspection failed; image evidence is incomplete.' }
    $containerOutput = '/workspace/' + [IO.Path]::GetRelativePath($taskRoot, $taskOutput).Replace('\', '/')
    & docker run --rm --init --network none --cpus 2 --memory 4g --pids-limit 512 --shm-size 1g `
        --mount "type=bind,source=$taskRoot,target=/workspace" $Image bash scripts/validate-linux.sh $containerOutput `
        2>&1 | Tee-Object -FilePath (Join-Path $taskOutput 'container.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Linux validation failed; inspect container.txt and test-report.json.' }
} finally {
    Pop-Location
}
