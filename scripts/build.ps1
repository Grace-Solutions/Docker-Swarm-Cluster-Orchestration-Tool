<#
.SYNOPSIS
    Build script for dscotctl (Docker Swarm Cluster Orchestration Tool Control) binaries.

.DESCRIPTION
    Builds dscotctl for Linux (amd64, arm64), Windows (amd64, arm64), and macOS (amd64, arm64).
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
$BinaryName = "dscotctl"
# Get repo root - if PSScriptRoot is set, go one level up; otherwise use current directory
if ($PSScriptRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
} else {
    $RepoRoot = (Get-Location).Path
}
$OutputDir = Join-Path $RepoRoot "binaries"
$ResourcesDir = Join-Path $RepoRoot "resources"
$CmdDir = Join-Path $RepoRoot "cmd\dscotctl"
$IconPath = Join-Path $ResourcesDir "0001.ico"

# Dynamic version based on current datetime (yyyy-MM-dd-HHmm)
$Now = Get-Date
$Version = $Now.ToString("yyyy-MM-dd-HHmm")
$BuildTime = $Now.ToString("yyyy-MM-ddTHH:mm:ssZ")

# Version components for Windows resource (yyyy.MM.dd.HHmm)
$VerMajor = [int]$Now.ToString("yyyy")
$VerMinor = [int]$Now.ToString("MM")
$VerPatch = [int]$Now.ToString("dd")
$VerBuild = [int]$Now.ToString("HHmm")
$VersionString = "$VerMajor.$VerMinor.$VerPatch.$VerBuild"

Write-Verbose "============================================"
Write-Verbose "  dscotctl Build Script"
Write-Verbose "  Version: $Version"
Write-Verbose "============================================"

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Clean if requested (only binary files, not .json.example or other non-binary files)
if ($Clean) {
    Write-Verbose "Cleaning existing binaries..."
    Get-ChildItem -Path $OutputDir -Filter "$BinaryName-*" | Where-Object { $_.Extension -ne ".example" -and $_.Name -notlike "*.json*" } | Remove-Item -Force
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

# Check if goversioninfo is available for Windows icon embedding
$VersionInfoPath = Join-Path $CmdDir "versioninfo.json"
$HasVersionInfo = (Test-Path $VersionInfoPath) -and (Get-Command goversioninfo -ErrorAction SilentlyContinue)
if ($HasVersionInfo) {
    Write-Verbose "Icon embedding enabled (goversioninfo found)"
} else {
    Write-Verbose "Icon embedding disabled (goversioninfo or versioninfo.json not found)"
}

# Clean any existing .syso files before building
Get-ChildItem -Path $CmdDir -Filter "*.syso" -ErrorAction SilentlyContinue | Remove-Item -Force

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
        # For Windows builds, generate the .syso resource file with embedded icon
        if ($GOOS -eq "windows" -and $HasVersionInfo) {
            Push-Location $CmdDir
            try {
                # Generate architecture-specific .syso file with dynamic version
                # Go looks for resource.syso or resource_windows_<arch>.syso
                $SysoFile = "resource.syso"
                $VerArgs = @(
                    "-ver-major", $VerMajor,
                    "-ver-minor", $VerMinor,
                    "-ver-patch", $VerPatch,
                    "-ver-build", $VerBuild,
                    "-product-ver-major", $VerMajor,
                    "-product-ver-minor", $VerMinor,
                    "-product-ver-patch", $VerPatch,
                    "-product-ver-build", $VerBuild,
                    "-file-version", $VersionString,
                    "-product-version", $VersionString,
                    "-o", $SysoFile
                )
                if ($GOARCH -eq "amd64") {
                    $Result = & goversioninfo -64 @VerArgs 2>&1
                } elseif ($GOARCH -eq "arm64") {
                    $Result = & goversioninfo -arm -64 @VerArgs 2>&1
                }
                if ($LASTEXITCODE -ne 0) {
                    Write-Verbose "    Warning: Failed to generate resource: $Result"
                }
            }
            finally {
                Pop-Location
            }
        }

        # Build command
        $BuildArgs = @(
            "build",
            "-ldflags", $LdFlags,
            "-o", $OutputPath,
            "./cmd/dscotctl"
        )

        $Result = & go @BuildArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed: $Result"
        }

        # Clean up .syso file after Windows build
        if ($GOOS -eq "windows") {
            Get-ChildItem -Path $CmdDir -Filter "*.syso" -ErrorAction SilentlyContinue | Remove-Item -Force
        }

        $FileSize = (Get-Item $OutputPath).Length / 1MB
        Write-Verbose "  $OutputName OK ($([math]::Round($FileSize, 2)) MB)"
        $SuccessCount++
    }
    catch {
        Write-Verbose "  $OutputName FAILED: $_"
        $FailCount++
        # Clean up .syso file on failure too
        Get-ChildItem -Path $CmdDir -Filter "*.syso" -ErrorAction SilentlyContinue | Remove-Item -Force
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

