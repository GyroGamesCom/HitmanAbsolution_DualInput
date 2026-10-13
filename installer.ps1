# Dual Input mod for Hitman: Absolution - installer / uninstaller.
# Run through install.bat or uninstall.bat.
param(
    [switch]$Uninstall,
    [string]$GameDir
)

$ErrorActionPreference = 'Stop'
$AppId      = '203140'
$GameFolder = 'Hitman Absolution'
$ExeName    = 'HMA.exe'
$ModFiles   = @('xinput9_1_0.dll')
$IniName    = 'xinput_mouse.ini'
$LogNames   = @('xinput_mouse.log')
$BackupDir  = 'DualInput_backup'
# SHA-256 of HMA.exe from the Steam build the mod was made and tested on.
$KnownExe   = 'F143C24385D77F52B7DBC48E42E9F632A6C20E40728EC1805454740E893C4915'
$ModDir     = Join-Path $PSScriptRoot 'mod'

function Resolve-Target($dir) {
    if (-not $dir) { return $null }
    if (Test-Path -LiteralPath (Join-Path $dir $ExeName)) { return $dir }
    return $null
}

function Find-GameDir {
    $steam = $null
    foreach ($key in 'HKCU:\Software\Valve\Steam', 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam') {
        try {
            $p = Get-ItemProperty $key -ErrorAction Stop
            $steam = if ($p.SteamPath) { $p.SteamPath } else { $p.InstallPath }
            if ($steam) { break }
        } catch {}
    }
    if (-not $steam) { return $null }

    $libs = @($steam)
    $vdf = Join-Path $steam 'steamapps\libraryfolders.vdf'
    if (Test-Path $vdf) {
        foreach ($m in [regex]::Matches((Get-Content $vdf -Raw), '"path"\s+"([^"]+)"')) {
            $libs += $m.Groups[1].Value -replace '\\\\', '\'
        }
    }
    foreach ($lib in $libs | Select-Object -Unique) {
        $apps = Join-Path $lib 'steamapps'
        $names = @()
        $acf = Join-Path $apps "appmanifest_$AppId.acf"
        if (Test-Path $acf) {
            $m = [regex]::Match((Get-Content $acf -Raw), '"installdir"\s+"([^"]+)"')
            if ($m.Success) { $names += $m.Groups[1].Value }
        }
        $names += $GameFolder
        foreach ($n in $names | Select-Object -Unique) {
            $t = Resolve-Target (Join-Path $apps "common\$n")
            if ($t) { return $t }
        }
    }
    return $null
}

Write-Host ''
Write-Host '=== Dual Input mod for Hitman: Absolution ===' -ForegroundColor Cyan
Write-Host ''

$GameDir = Resolve-Target $GameDir
if (-not $GameDir) { $GameDir = Find-GameDir }
while (-not $GameDir) {
    Write-Host 'The game was not found automatically (or the folder is wrong).' -ForegroundColor Yellow
    $in = (Read-Host "Paste the game folder (the one with $ExeName), or leave empty to cancel").Trim('" ')
    if (-not $in) { Write-Host 'Cancelled.'; exit 1 }
    $GameDir = Resolve-Target $in
    if (-not $GameDir) { Write-Host "$ExeName not found in: $in" -ForegroundColor Yellow }
}
Write-Host "Game folder: $GameDir"

if (Get-Process -Name 'HMA' -ErrorAction SilentlyContinue) {
    Write-Host ''
    Write-Host 'The game is running. Close it first, then run this again.' -ForegroundColor Yellow
    exit 1
}

$backup = Join-Path $GameDir $BackupDir

if ($Uninstall) {
    foreach ($f in $ModFiles + $LogNames) {
        $path = Join-Path $GameDir $f
        if (Test-Path $path) { Remove-Item $path -Force; Write-Host "  removed  $f" }
    }
    if (Test-Path $backup) {
        Get-ChildItem $backup | ForEach-Object {
            Move-Item $_.FullName (Join-Path $GameDir $_.Name) -Force
            Write-Host "  restored $($_.Name) (from before the mod)"
        }
        Remove-Item $backup -Force -Recurse
    }
    $ini = Join-Path $GameDir $IniName
    if (Test-Path $ini) {
        $a = Read-Host "Delete your settings file $IniName too? (y/N)"
        if ($a -match '^[yY]') { Remove-Item $ini -Force; Write-Host "  removed  $IniName" }
        else { Write-Host "  kept     $IniName" }
    }
    Write-Host ''
    Write-Host 'Mod uninstalled.' -ForegroundColor Green
    exit 0
}

$hash = (Get-FileHash -LiteralPath (Join-Path $GameDir $ExeName) -Algorithm SHA256).Hash
if ($hash -ne $KnownExe) {
    Write-Host ''
    Write-Host 'WARNING: your HMA.exe is a different version than the one the mod was tested on.' -ForegroundColor Yellow
    Write-Host 'The mod checks the game code before hooking and turns itself off if it does not' -ForegroundColor Yellow
    Write-Host 'match (see xinput_mouse.log); the game then behaves as without the mod.' -ForegroundColor Yellow
    $a = Read-Host 'Install anyway? (y/N)'
    if ($a -notmatch '^[yY]') { Write-Host 'Cancelled.'; exit 1 }
}

foreach ($f in $ModFiles) {
    $src = Join-Path $ModDir $f
    $dst = Join-Path $GameDir $f
    if ((Test-Path $dst) -and (Get-FileHash $dst).Hash -ne (Get-FileHash $src).Hash) {
        # Another mod uses the same file name: back it up, unless it is an older copy of this mod.
        $isOurs = Select-String -Path $dst -Pattern $IniName -SimpleMatch -Quiet
        if (-not $isOurs -and -not (Test-Path (Join-Path $backup $f))) {
            New-Item -ItemType Directory -Path $backup -Force | Out-Null
            Copy-Item $dst (Join-Path $backup $f)
            Write-Host "  backed up existing $f to $BackupDir\" -ForegroundColor Yellow
        }
    }
    Copy-Item $src $dst -Force
    Write-Host "  installed $f"
}

$ini = Join-Path $GameDir $IniName
if (Test-Path $ini) {
    Write-Host "  kept your existing $IniName (settings unchanged)"
} else {
    Copy-Item (Join-Path $ModDir $IniName) $ini
    Write-Host "  installed $IniName"
}

Write-Host ''
Write-Host 'Done. Next steps:' -ForegroundColor Green
Write-Host '  1. Steam Input: gyro -> "As Mouse", right trackpad -> "Joystick" (see README).'
Write-Host '  2. Start the game and press a gamepad button once.'
Write-Host "  3. Settings: $ini"
Write-Host '  4. To remove the mod, run uninstall.bat.'
