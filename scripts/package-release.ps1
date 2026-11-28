param(
    [string]$OutDir = "dist",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    $metaJson = cargo metadata --format-version 1 --locked --features desktop --filter-platform x86_64-pc-windows-msvc | ConvertFrom-Json
    $pkg = $metaJson.packages | Where-Object { $_.name -eq "larchscan" } | Select-Object -First 1
    $version = $pkg.version

    if (-not $SkipBuild) {
        Write-Host "Building LarchScan v$version release binaries..."
        $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE ".cargo" }
        $remapFlags = @(
            "--remap-path-prefix=$repoRoot=/src"
            "--remap-path-prefix=$cargoHome=/cargo"
            "--remap-path-prefix=$($env:USERPROFILE)=/user"
            "-C"
            "link-arg=/PDBALTPATH:%_PDB%"
        ) -join " "
        $prevRustFlags = $env:RUSTFLAGS
        $env:RUSTFLAGS = if ($prevRustFlags) { "$prevRustFlags $remapFlags" } else { $remapFlags }
        try {
            cargo build --locked --release --features desktop --bins
            if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
        } finally {
            $env:RUSTFLAGS = $prevRustFlags
        }
    }

    $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repoRoot "target" }
    $desktopExe = Join-Path $targetDir "release\larchscan-desktop.exe"
    $cliExe = Join-Path $targetDir "release\larchscan.exe"

    if (-not (Test-Path $desktopExe)) { throw "Missing $desktopExe" }
    if (-not (Test-Path $cliExe)) { throw "Missing $cliExe" }

    $outPath = if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repoRoot $OutDir }
    $bundleName = "larchscan-$version-windows-x64"
    $stage = Join-Path $outPath $bundleName
    $zipPath = Join-Path $outPath "$bundleName.zip"
    $sumsPath = Join-Path $outPath "larchscan-$version-SHA256SUMS.txt"

    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    New-Item -ItemType Directory -Force -Path $stage, (Join-Path $stage "tools"), (Join-Path $stage "docs\images"), (Join-Path $stage "examples") | Out-Null

    Copy-Item $desktopExe (Join-Path $stage "LarchScan.exe")
    Copy-Item $cliExe (Join-Path $stage "tools\larchscan.exe")
    Copy-Item (Join-Path $repoRoot "LICENSE") $stage
    Copy-Item (Join-Path $repoRoot "README.md") $stage
    Copy-Item (Join-Path $repoRoot "RESEARCH.md") $stage
    Copy-Item (Join-Path $repoRoot "docs\desktop-guide.md") (Join-Path $stage "docs")
    Copy-Item (Join-Path $repoRoot "docs\cli-guide.md") (Join-Path $stage "docs")
    Copy-Item (Join-Path $repoRoot "examples\demo.txt") (Join-Path $stage "examples")

    # Include only images referenced by v0.3 documentation.
    foreach ($img in @("larchscan-icon.png", "desktop-overview.png", "desktop-results.png", "desktop-quarantine.png", "desktop-settings.png")) {
        $srcImg = Join-Path $repoRoot "docs\images\$img"
        if (Test-Path $srcImg) {
            Copy-Item $srcImg (Join-Path $stage "docs\images")
        }
    }

    # Generate a single concise, deduplicated third-party attribution file instead of shipping
    # the 15 MB Rust compiler copyright dump and hundreds of loose files.
    $notices = New-Object System.Collections.Generic.List[string]
    $notices.Add("LarchScan v$version - Third-Party Open-Source Notices")
    $notices.Add("====================================================")
    $notices.Add("")
    $notices.Add("LarchScan is licensed under the MIT License (see LICENSE).")
    $notices.Add("The Rust standard library is dual-licensed under MIT and Apache-2.0:")
    $notices.Add("https://github.com/rust-lang/rust/blob/master/COPYRIGHT")
    $notices.Add("")
    $notices.Add("Resolved Cargo crate dependencies:")
    $notices.Add("")

    $deps = $metaJson.packages |
        Where-Object { $_.name -ne "larchscan" } |
        Sort-Object name, version
    foreach ($dep in $deps) {
        $lic = if ($dep.license) { $dep.license } else { "See crate repository" }
        $repo = if ($dep.repository) { " - $($dep.repository)" } else { "" }
        $notices.Add("- $($dep.name) $($dep.version) ($lic)$repo")
    }
    [IO.File]::WriteAllLines((Join-Path $stage "THIRD-PARTY-NOTICES.txt"), $notices, [Text.UTF8Encoding]::new($false))

    Compress-Archive -Path $stage -DestinationPath $zipPath -CompressionLevel Optimal

    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $desktopHash = (Get-FileHash -LiteralPath (Join-Path $stage "LarchScan.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    $cliHash = (Get-FileHash -LiteralPath (Join-Path $stage "tools\larchscan.exe") -Algorithm SHA256).Hash.ToLowerInvariant()

    $sumLines = @(
        "$zipHash  $bundleName.zip"
        "$desktopHash  $bundleName/LarchScan.exe"
        "$cliHash  $bundleName/tools/larchscan.exe"
    )
    [IO.File]::WriteAllLines($sumsPath, $sumLines, [Text.UTF8Encoding]::new($false))

    $fileCount = (Get-ChildItem $stage -Recurse -File).Count
    $stageBytes = (Get-ChildItem $stage -Recurse -File | Measure-Object Length -Sum).Sum
    $zipBytes = (Get-Item $zipPath).Length

    Write-Host ""
    Write-Host "Packaged: $zipPath ($([math]::Round($zipBytes / 1MB, 2)) MB)"
    Write-Host "Extracted: $fileCount files, $([math]::Round($stageBytes / 1MB, 2)) MB"
    Write-Host "Checksums: $sumsPath"
    Get-Content $sumsPath
} finally {
    Pop-Location
}
