# Build the only active runtime from the repository root.
$ErrorActionPreference = 'Stop'
$RepoDir = (Resolve-Path "$PSScriptRoot/..").Path
$wslRepoPath = (wsl -d Ubuntu -e wslpath -a $RepoDir).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve repository path in WSL' }
$lockContent = Get-Content (Join-Path $RepoDir 'toolchain.lock') -Raw
if ($lockContent -notmatch 'pinned_reference\s*=\s*"([^"]+)"') { throw 'Missing pinned toolchain reference' }
$pinnedImage = $Matches[1]
Write-Host "[toolchain] $pinnedImage"
$gitCommit = (git rev-parse --short HEAD 2>$null)
if (-not $gitCommit) { $gitCommit = "unknown" }
$gitDirty = if (git status --porcelain 2>$null) { "-dirty" } else { "" }
$fullCommit = "$gitCommit$gitDirty"
$buildTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "[build-identity] Commit: $fullCommit, Timestamp: $buildTimestamp"
wsl -u root -d Ubuntu -e docker run --rm -v "${wslRepoPath}:/workspace" -w /workspace -e GIT_COMMIT="$fullCommit" -e BUILD_TIMESTAMP="$buildTimestamp" $pinnedImage bash scripts/container_build_verify.sh
if ($LASTEXITCODE -ne 0) { throw "Build or native checks failed: $LASTEXITCODE" }
Push-Location $RepoDir
try {
    python -m unittest tests.test_step2_loader_harness
    if ($LASTEXITCODE -ne 0) { throw 'Python pre-entry checks failed' }
} finally { Pop-Location }
wsl -d Ubuntu --cd $wslRepoPath -e env "DURAK_INVENTORY_NATIVE_LIB=$wslRepoPath/build-obj/test_inventory_native.so" python3 -m unittest tests.test_cosmetics_inventory
if ($LASTEXITCODE -ne 0) { throw 'Native inventory SQLite checks failed' }
& (Join-Path $PSScriptRoot 'package_release.ps1')
Write-Host "[verified] $RepoDir\build (build, host checks and SD package)"
