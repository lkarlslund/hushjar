# Builds a release and packs it as dist\hushjar-<version>-windows-<arch>.zip
# (amd64 or arm64) with hushjar.exe, whose icon is embedded by the build. Run from PowerShell.
# Pass -NoBuild to pack an existing target\release build.
param([switch]$NoBuild)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
# The release identity, r<commit count> as scripts/build-number makes it; the
# release workflow sets it, local builds are marked -local.
if (-not $env:HUSHJAR_VERSION) {
    $v = 'r{0:D4}-local' -f [int](git rev-list --count HEAD)
    git diff --quiet --ignore-submodules HEAD --
    if ($LASTEXITCODE -ne 0) { $v += '-dirty' }
    $env:HUSHJAR_VERSION = $v
}
$version = $env:HUSHJAR_VERSION
# The architecture of the Rust toolchain, which is what the build targets.
$rustArch = (rustc -vV | Select-String '^host: (\w+)-').Matches[0].Groups[1].Value
$arch = @{ x86_64 = 'amd64'; aarch64 = 'arm64' }[$rustArch]
$name = "hushjar-$version-windows-$arch"

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
