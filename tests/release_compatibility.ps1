param(
    [Parameter(Mandatory=$true)][string]$Compiler,
    [Parameter(Mandatory=$true)][string]$DependencyRoot,
    [string]$Repository = (Split-Path $PSScriptRoot -Parent),
    [string]$Baseline = '9ad959b',
    [string]$WorkRoot = $env:TEMP
)
$ErrorActionPreference = 'Stop'
$work = Join-Path $WorkRoot ('kasa-compatibility-' + [guid]::NewGuid().ToString('N'))
$old = Join-Path $work 'old-source'
New-Item -ItemType Directory -Path $old -Force | Out-Null
& git -C $Repository archive --format=tar "--output=$work/baseline.tar" $Baseline encryption_engine.cpp encryption_engine.h plaintext_output.h preview_policy.h
if ($LASTEXITCODE -ne 0) { throw 'Cannot extract baseline engine' }
& tar -xf "$work/baseline.tar" -C $old
if ($LASTEXITCODE -ne 0) { throw 'Cannot unpack baseline engine' }
$probe = Join-Path $PSScriptRoot 'release_compatibility_probe.cpp'
foreach ($build in @(@{Name='old'; Source=$old}, @{Name='candidate'; Source=$Repository})) {
    & $Compiler -std=c++20 -O2 -municode -static-libgcc -static-libstdc++ '-I' $build.Source '-I' "$DependencyRoot/include" $probe "$($build.Source)/encryption_engine.cpp" '-L' "$DependencyRoot/lib" -lcrypto -o "$work/$($build.Name).exe"
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed: $($build.Name)" }
}
Copy-Item -LiteralPath "$DependencyRoot/bin/libcrypto-3-x64.dll" -Destination $work
Copy-Item -LiteralPath (Join-Path (Split-Path $Compiler -Parent) 'libwinpthread-1.dll') -Destination $work
$fixtures = Join-Path $work 'fixtures with spaces'
& "$work/old.exe" create $fixtures
if ($LASTEXITCODE -ne 0) { throw 'Baseline fixture generation failed' }
& "$work/candidate.exe" verify $fixtures
if ($LASTEXITCODE -ne 0) { throw 'Candidate verification failed' }
Write-Output "PASS. Synthetic fixtures retained for inspection at: $work"
