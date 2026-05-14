param(
    [string]$Version = "",
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-HaAuthVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CargoTomlPath
    )

    $content = Get-Content -LiteralPath $CargoTomlPath
    foreach ($line in $content) {
        if ($line -match '^\s*version\s*=\s*"([^"]+)"\s*$') {
            return $Matches[1]
        }
    }

    throw "Could not find package version in $CargoTomlPath"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$cargoTomlPath = Join-Path $repoRoot "Cargo.toml"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-HaAuthVersion -CargoTomlPath $cargoTomlPath
}

$target = "x86_64-pc-windows-msvc"
$artifactDir = Join-Path $repoRoot "dist\v$Version"
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

Push-Location $repoRoot
try {
    if (-not $SkipTests) {
        cargo test -q
        if ($LASTEXITCODE -ne 0) {
            throw "cargo test failed with exit code $LASTEXITCODE"
        }
    }

    if (Get-Command rustup -ErrorAction SilentlyContinue) {
        rustup target add $target
        if ($LASTEXITCODE -ne 0) {
            throw "rustup target add failed with exit code $LASTEXITCODE"
        }
    }

    cargo build --release --target $target
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

$sourceExe = Join-Path $repoRoot "target\$target\release\ha-auth.exe"
if (-not (Test-Path -LiteralPath $sourceExe)) {
    throw "Missing built binary: $sourceExe"
}

$artifactName = "ha-auth-v$Version-$target.exe"
$artifactPath = Join-Path $artifactDir $artifactName
Copy-Item -LiteralPath $sourceExe -Destination $artifactPath -Force

Write-Host "Built Windows x64 release:"
Write-Host "  $artifactPath"
