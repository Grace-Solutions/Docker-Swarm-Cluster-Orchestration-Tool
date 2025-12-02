<#
.SYNOPSIS
    Build script for dswrmctl (Docker Swarm Control) binaries.

.DESCRIPTION
    Builds dswrmctl for Linux (amd64, arm64), Windows (amd64, arm64), and macOS (amd64, arm64).
    Embeds version information (yyyy-MM-dd-HHmm format) and metadata into binaries.

.PARAMETER Clean
    Remove existing binaries before building.

.PARAMETER Verbose
    Show detailed build progress.

.EXAMPLE
    .\scripts\build.ps1
    .\scripts\build.ps1 -Clean
    .\scripts\build.ps1 -Verbose
#>

[CmdletBinding()]
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Configuration
$BinaryName = "dswrmctl"
# Get repo root - if PSScriptRoot is set, go one level up; otherwise use current directory
if ($PSScriptRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
} else {
    $RepoRoot = (Get-Location).Path
}
$OutputDir = Join-Path $RepoRoot "binaries"
$ResourcesDir = Join-Path $RepoRoot "resources"
$CmdDir = Join-Path $RepoRoot "cmd\clusterctl"
$IconPath = Join-Path $ResourcesDir "0001.ico"

# Dynamic version based on current datetime (yyyy-MM-dd-HHmm)
$Version = Get-Date -Format "yyyy-MM-dd-HHmm"
$BuildTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

Write-Verbose "============================================"
Write-Verbose "  dswrmctl Build Script"
Write-Verbose "  Version: $Version"
Write-Verbose "============================================"

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Clean if requested
if ($Clean) {
    Write-Verbose "Cleaning existing binaries..."
    Get-ChildItem -Path $OutputDir -Filter "$BinaryName*" | Remove-Item -Force
}

# Build targets: [GOOS, GOARCH, Extension, Description]
$Targets = @(
    @("linux",   "amd64", "",     "Linux x86_64"),
    @("linux",   "arm64", "",     "Linux ARM64"),
    @("darwin",  "amd64", "",     "macOS x86_64"),
    @("darwin",  "arm64", "",     "macOS ARM64 (Apple Silicon)"),
    @("windows", "amd64", ".exe", "Windows x86_64"),
    @("windows", "arm64", ".exe", "Windows ARM64")
)

# ldflags for version embedding
$LdFlags = "-s -w -X 'main.Version=$Version' -X 'main.BuildTime=$BuildTime' -X 'main.BinaryName=$BinaryName'"

Write-Verbose "Building $($Targets.Count) targets..."

$SuccessCount = 0
$FailCount = 0

foreach ($Target in $Targets) {
    $GOOS = $Target[0]
    $GOARCH = $Target[1]
    $Ext = $Target[2]
    $Desc = $Target[3]

    $OutputName = "$BinaryName-$GOOS-$GOARCH$Ext"
    $OutputPath = Join-Path $OutputDir $OutputName

    Write-Verbose "  Building $OutputName ($Desc)..."

    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    $env:CGO_ENABLED = "0"

    try {
        # Build command
        $BuildArgs = @(
            "build",
            "-ldflags", $LdFlags,
            "-o", $OutputPath,
            "./cmd/clusterctl"
        )

        $Result = & go @BuildArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed: $Result"
        }

        $FileSize = (Get-Item $OutputPath).Length / 1MB
        Write-Verbose "  $OutputName OK ($([math]::Round($FileSize, 2)) MB)"
        $SuccessCount++
    }
    catch {
        Write-Verbose "  $OutputName FAILED: $_"
        $FailCount++
    }
}

# Clear environment variables
Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Verbose "============================================"
Write-Verbose "  Build Complete"
Write-Verbose "  Success: $SuccessCount / $($Targets.Count)"
if ($FailCount -gt 0) {
    Write-Verbose "  Failed: $FailCount"
}
Write-Verbose "  Output: $OutputDir"
Write-Verbose "============================================"

# List built binaries
Write-Verbose "Built binaries:"
Get-ChildItem -Path $OutputDir -Filter "$BinaryName*" | ForEach-Object {
    $SizeMB = [math]::Round($_.Length / 1MB, 2)
    Write-Verbose "  $($_.Name) ($SizeMB MB)"
}

exit $(if ($FailCount -eq 0) { 0 } else { 1 })

