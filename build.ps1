# PowerShell build script for AgentEdict
param (
    [string]$Action = "all" # "build", "test", "compile", "all"
)

$ErrorActionPreference = "Stop"
$BinDir = Join-Path $PSScriptRoot "bin"
$DistDir = Join-Path $PSScriptRoot "dist"

if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir | Out-Null }
if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir | Out-Null }

function Build-Windows {
    Write-Host "Building Windows binary (bin/edict.exe)..." -ForegroundColor Cyan
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -ldflags="-s -w" -o (Join-Path $BinDir "edict.exe") ./cmd/edict
    Write-Host "Successfully built bin/edict.exe" -ForegroundColor Green
}

function Run-Tests {
    Write-Host "Running tests..." -ForegroundColor Cyan
    go test -v ./...
}

function Run-Compile {
    Write-Host "Compiling profiles for all OS targets..." -ForegroundColor Cyan
    go run ./cmd/edict compile -profiles-dir profiles -target-os all -output-dir (Join-Path $DistDir "profiles")
    Write-Host "Profiles compiled successfully into dist/profiles/" -ForegroundColor Green
}

switch ($Action.ToLower()) {
    "build"   { Build-Windows }
    "test"    { Run-Tests }
    "compile" { Run-Compile }
    "all"     {
        Run-Tests
        Build-Windows
        Run-Compile
    }
    default {
        Write-Error "Unknown action: $Action. Use 'build', 'test', 'compile', or 'all'."
    }
}
