# Fox DPI Cross-Platform Build & Compression Script
# Compiles optimized, stripped binaries with UPX & tar/zip archives.

$ErrorActionPreference = "Stop"

$Version = "v0.1.1"
$DistDir = Join-Path $PSScriptRoot "..\dist"
$RepoRoot = Join-Path $PSScriptRoot ".."

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Building Fox DPI $Version for Distribution" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

if (Test-Path $DistDir) {
    Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Path $DistDir | Out-Null

$Targets = @(
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe"; Archive = "zip" },
    @{ OS = "windows"; Arch = "arm64"; Ext = ".exe"; Archive = "zip" },
    @{ OS = "linux";   Arch = "amd64"; Ext = "";     Archive = "tar.gz" },
    @{ OS = "linux";   Arch = "arm64"; Ext = "";     Archive = "tar.gz" },
    @{ OS = "darwin";  Arch = "amd64"; Ext = "";     Archive = "tar.gz" },
    @{ OS = "darwin";  Arch = "arm64"; Ext = "";     Archive = "tar.gz" }
)

$HasUPX = (Get-Command upx -ErrorAction SilentlyContinue) -ne $null
if ($HasUPX) {
    Write-Host "[+] UPX detected. Executables will be compressed with UPX --best --lzma." -ForegroundColor Green
} else {
    Write-Host "[!] UPX not found. Proceeding with standard Go compiler stripping (-s -w)." -ForegroundColor Yellow
}

Push-Location $RepoRoot
try {
    foreach ($t in $Targets) {
        $TargetName = "$($t.OS)-$($t.Arch)"
        $BinaryName = "foxdpi$($t.Ext)"
        $BuildDir = Join-Path $DistDir $TargetName
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
        $OutputPath = Join-Path $BuildDir $BinaryName

        Write-Host "`n[+] Building $TargetName..." -ForegroundColor White
        $env:GOOS = $t.OS
        $env:GOARCH = $t.Arch
        $env:CGO_ENABLED = "0"

        # -s: omit symbol table and debug info; -w: omit DWARF info
        go build -ldflags="-s -w" -o $OutputPath ./cmd/foxdpi

        $OrigSize = (Get-Item $OutputPath).Length
        Write-Host "    Compiled size: $([math]::Round($OrigSize / 1MB, 2)) MB ($OrigSize bytes)"

        # Apply UPX compression where supported (windows-amd64, linux-amd64, linux-arm64)
        $UpxSupported = ($t.OS -eq "windows" -and $t.Arch -eq "amd64") -or ($t.OS -eq "linux")
        if ($HasUPX -and $UpxSupported) {
            Write-Host "    Compressing with UPX..." -ForegroundColor Gray
            & upx --best --lzma $OutputPath *>$null
            if ($LASTEXITCODE -eq 0) {
                $PackedSize = (Get-Item $OutputPath).Length
                $Ratio = [math]::Round((1 - ($PackedSize / $OrigSize)) * 100, 1)
                Write-Host "    UPX size: $([math]::Round($PackedSize / 1MB, 2)) MB ($PackedSize bytes) [-${Ratio}%]" -ForegroundColor Green
            } else {
                Write-Host "    UPX skipped or not applicable for this architecture." -ForegroundColor Yellow
            }
        }

        # Create Archive
        $ArchiveBase = "foxdpi-$Version-$TargetName"
        if ($t.Archive -eq "zip") {
            $ArchiveFile = Join-Path $DistDir "$ArchiveBase.zip"
            Compress-Archive -Path $OutputPath -DestinationPath $ArchiveFile -Force
            $ArchiveSize = (Get-Item $ArchiveFile).Length
            Write-Host "    Archive created: $ArchiveBase.zip ($([math]::Round($ArchiveSize / 1MB, 2)) MB)" -ForegroundColor Cyan
        } else {
            $ArchiveFile = Join-Path $DistDir "$ArchiveBase.tar.gz"
            Push-Location $BuildDir
            try {
                tar -czf $ArchiveFile $BinaryName
            } finally {
                Pop-Location
            }
            $ArchiveSize = (Get-Item $ArchiveFile).Length
            Write-Host "    Archive created: $ArchiveBase.tar.gz ($([math]::Round($ArchiveSize / 1MB, 2)) MB)" -ForegroundColor Cyan
        }
    }
} finally {
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = ""
    Pop-Location
}

Write-Host "`n==================================================" -ForegroundColor Green
Write-Host "All release archives generated in ./dist/:" -ForegroundColor Green
Get-ChildItem -Path $DistDir | Where-Object { $_.Name -like "foxdpi-*.zip" -or $_.Name -like "foxdpi-*.tar.gz" } | Select-Object Name, @{Name="Size (MB)"; Expression={[math]::Round($_.Length / 1MB, 2)}} | Format-Table -AutoSize
Write-Host "Ready to upload to GitHub Release assets!" -ForegroundColor Green
