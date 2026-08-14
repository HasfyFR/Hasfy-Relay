<#
.SYNOPSIS
    Build the Hasfy agent MSI.

.DESCRIPTION
    The Windows counterpart of packaging/linux (nfpm) and of Hasfy-Agent's
    packaging/macos/build-pkg.sh: produce a native package so the OS installer
    is the single privileged step in the agent's lifecycle.

    Runs on a Windows runner with the WiX v3 toolset on PATH (candle/light).

.PARAMETER Version
    Package version, "1.2.3". MSI versions are numeric only — a leading "v" or
    a pre-release suffix is rejected by the installer engine, so it is
    normalised here rather than failing halfway through the build.

.PARAMETER Binary
    Path to the already-built hasfy-agent.exe.

.PARAMETER OutDir
    Where to write hasfy-agent-<version>.msi.

.EXAMPLE
    ./build-msi.ps1 -Version 1.2.3 -Binary ./dist/hasfy-agent.exe -OutDir ./dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $Binary,
    [string] $OutDir = "dist"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$wxs = Join-Path $scriptDir "hasfy-agent.wxs"

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

if (-not (Test-Path $Binary)) {
    throw "Binary not found: $Binary"
}

# The MSI ProductVersion is major.minor.build, all numeric. Tags carry a
# leading "v" and releases sometimes a suffix; strip both. Fail loudly on
# anything still unusable rather than shipping an MSI Windows refuses to
# upgrade — a version that does not compare is an install that never replaces
# the previous one.
$msiVersion = ($Version -replace '^v', '') -replace '-.*$', ''
if ($msiVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version '$Version' does not normalise to major.minor.build (got '$msiVersion')"
}

foreach ($tool in @("candle.exe", "light.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found on PATH. Install the WiX v3 toolset."
    }
}

# The .wxs registers the service against this exact name; a rename here would
# leave the daemon installed under a name the uninstaller does not know.
$expectedName = "hasfy-agent.exe"
if ((Split-Path -Leaf $Binary) -ne $expectedName) {
    throw "Binary must be named $expectedName (got '$(Split-Path -Leaf $Binary)')"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$build = Join-Path $OutDir "msi-build"
New-Item -ItemType Directory -Force -Path $build | Out-Null

$resolvedBinary = (Resolve-Path $Binary).Path
$obj = Join-Path $build "hasfy-agent.wixobj"
$msi = Join-Path $OutDir "hasfy-agent-$msiVersion.msi"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

Write-Host "Compiling $wxs (version $msiVersion)"
& candle.exe `
    -nologo `
    -arch x64 `
    -ext WixUtilExtension `
    -dVersion="$msiVersion" `
    -dSourceBinary="$resolvedBinary" `
    -out $obj `
    $wxs
if ($LASTEXITCODE -ne 0) { throw "candle failed with exit code $LASTEXITCODE" }

Write-Host "Linking $msi"
& light.exe `
    -nologo `
    -ext WixUtilExtension `
    -sice:ICE61 `
    -out $msi `
    $obj
if ($LASTEXITCODE -ne 0) { throw "light failed with exit code $LASTEXITCODE" }

# ICE61 is suppressed above because AllowSameVersionUpgrades is deliberate:
# without it, reinstalling the same version — which a rebuilt release does —
# errors out instead of replacing cleanly.

if (-not (Test-Path $msi)) { throw "light reported success but produced no MSI" }

$size = (Get-Item $msi).Length
if ($size -lt 100KB) {
    throw "MSI is suspiciously small ($size bytes) — the payload is probably missing"
}

Write-Host "Built $msi ($([math]::Round($size / 1MB, 2)) MB)"
Write-Output $msi
