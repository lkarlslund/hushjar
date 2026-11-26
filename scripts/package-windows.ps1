# Builds a release and packs it as dist\hushjar-<version>-windows-x86_64.zip
# with hushjar.exe, whose icon is embedded by the build. Run from PowerShell.
# Pass -NoBuild to pack an existing target\release build.
param([switch]$NoBuild)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value
$name = "hushjar-$version-windows-x86_64"

if (-not $NoBuild) {
    cargo build --release --locked -p hushjar
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
}
$stage = "dist\$name"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item target\release\hushjar.exe $stage
Copy-Item README.md $stage
$zip = "dist\$name.zip"
Remove-Item -Force $zip -ErrorAction SilentlyContinue
Compress-Archive -Path "$stage\*" -DestinationPath $zip
Remove-Item -Recurse -Force $stage
Write-Output $zip
