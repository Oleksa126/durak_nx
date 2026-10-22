# Assemble an SD card overlay without user databases or save files.
$ErrorActionPreference = 'Stop'
$RepoDir = (Resolve-Path "$PSScriptRoot/..").Path
$package = Join-Path $RepoDir 'build'
$originalAssets = Join-Path $RepoDir 'extracted_durak/sdmc/switch/durak_nx/game/assets'
$originalLibs = Join-Path $RepoDir 'extracted_durak/sdmc/switch/durak_nx/game/lib'
$nro = Join-Path $RepoDir 'durak_nx.nro'
$libraries = @('libsqlite3.so', 'libmain.so', 'libunity.so', 'libil2cpp.so')
foreach ($inputPath in @($nro, $originalAssets) + @($libraries | ForEach-Object { Join-Path $originalLibs $_ })) {
    if (-not (Test-Path -LiteralPath $inputPath)) { throw "Missing release input: $inputPath" }
}
# Only replace this generated package; never touch extracted inputs or SD saves.
if ($package -ne (Join-Path $RepoDir 'build') -or -not $package.StartsWith($RepoDir + '\')) {
    throw 'Unsafe package directory'
}
if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Recurse -Force }
$destination = Join-Path $package 'switch/durak_nx'
New-Item -ItemType Directory -Path (Join-Path $destination 'game/lib') -Force | Out-Null
Copy-Item -LiteralPath $nro -Destination $destination
Copy-Item -LiteralPath $originalAssets -Destination (Join-Path $destination 'game') -Recurse
Remove-Item -LiteralPath (Join-Path $destination 'game/assets/bin/Data/data.unity3d')
foreach ($library in $libraries) {
    Copy-Item -LiteralPath (Join-Path $originalLibs $library) -Destination (Join-Path $destination 'game/lib')
}
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $RepoDir 'tools/cache/python'
    python (Join-Path $RepoDir 'scripts/generate_static_catalog.py') --check
    if ($LASTEXITCODE -ne 0) { throw 'Compiled static catalog/managed boundary verification failed' }
    python (Join-Path $RepoDir 'scripts/verify_static_catalog_guard.py')
    if ($LASTEXITCODE -ne 0) { throw 'Assembled static catalog guard ABI verification failed' }
    python (Join-Path $RepoDir 'scripts/verify_offline_cleanup.py')
    if ($LASTEXITCODE -ne 0) { throw 'Offline commerce/counter cleanup target verification failed' }
    python (Join-Path $RepoDir 'scripts/verify_startup_fast.py')
    if ($LASTEXITCODE -ne 0) { throw 'Startup SQL flag verification failed' }
    python (Join-Path $RepoDir 'scripts/verify_single_game_unlock.py')
    if ($LASTEXITCODE -ne 0) { throw 'Single Game and modal patch target verification failed' }
    python (Join-Path $RepoDir 'scripts/verify_cosmetics_unlock.py')
    if ($LASTEXITCODE -ne 0) { throw 'Cosmetics catalog/metadata/instruction verification failed' }
    python (Join-Path $RepoDir 'scripts/hide_main_menu_extras.py') `
        (Join-Path $originalAssets 'bin/Data/data.unity3d') `
        (Join-Path $destination 'game/assets/bin/Data/data.unity3d')
    if ($LASTEXITCODE -ne 0) { throw 'Verified menu asset generation failed (requires UnityPy==1.25.3)' }
} finally { $env:PYTHONPATH = $previousPythonPath }
# Refresh both supported asset paths, including existing canonical copies on SD.
Copy-Item -LiteralPath (Join-Path $destination 'game/assets') -Destination $destination -Recurse
$commit = (git -C $RepoDir rev-parse HEAD).Trim()
$files = @(Get-ChildItem -LiteralPath (Join-Path $package 'switch') -File -Recurse | Sort-Object FullName | ForEach-Object {
    [ordered]@{
        path = $_.FullName.Substring($package.Length + 1).Replace('\', '/')
        bytes = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
})
[ordered]@{ version = '0.1.0'; commit = $commit; files = $files } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding utf8
@'
Durak NX v0.1.0

Copy the switch folder to the root of your Switch SD card and merge folders.
Replace matching application files. Do not delete the existing durak_nx folder.
Launch switch/durak_nx/durak_nx.nro from the Homebrew Menu in application mode.

This package contains the NRO, four ARM64 libraries and verified game assets.
It contains no user databases, PlayerPrefs or save directory.
Existing saves stay on your SD card. manifest.json records SHA256 for each file.
Runtime log: switch/durak_nx/durak_nx.log
'@ | Set-Content -LiteralPath (Join-Path $package 'README.txt') -Encoding utf8
Write-Host "[packaged] $package ($($files.Count) files; v0.1.0; $commit)"
