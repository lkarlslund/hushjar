# Installs rustup on a Windows CI runner that lacks it (the arm64 runners
# come without Rust). Does nothing when rustup is already there.
$ErrorActionPreference = 'Stop'
if (Get-Command rustup -ErrorAction SilentlyContinue) { exit 0 }
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
$installer = Join-Path $env:RUNNER_TEMP 'rustup-init.exe'
Invoke-WebRequest "https://static.rust-lang.org/rustup/dist/$arch-pc-windows-msvc/rustup-init.exe" -OutFile $installer
& $installer -y --profile minimal --default-toolchain none
if ($LASTEXITCODE -ne 0) { throw 'rustup-init failed' }
Add-Content $env:GITHUB_PATH (Join-Path $env:USERPROFILE '.cargo\bin')
