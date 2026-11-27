#Requires -Version 5.1
<#
.SYNOPSIS
    Installs per-user (HKCU) Windows Explorer context menu entries for Dandi.
.DESCRIPTION
    Registers clean HKCU Explorer shell verbs without requiring Administrator UAC
    and without duplicating Windows 10 / Windows 11 registrations (NanaZip#328):
      - Files & folders: "Compress with Dandi (Clean ZIP)" -> dandi.exe pack
      - Archive extensions (.zip, .7z, .rar, .z01, .001, .tar, .tgz, .gz, .zst, .bz2, .xz, .tzst, .tbz2, .txz):
          "Extract with Dandi (Smart)" -> dandi.exe unpack --mode smart
          "Open in Dandi"              -> dandi-desktop.exe
.PARAMETER DandiBin
    Optional explicit path to dandi.exe.
.PARAMETER DesktopBin
    Optional explicit path to dandi-desktop.exe (or Dandi.exe).
.PARAMETER RegistryRoot
    Optional HKCU registry prefix (default: HKCU:\Software\Classes).
.PARAMETER DryRun
    Print planned registry writes without modifying the registry.
#>
[CmdletBinding()]
param(
    [string]$DandiBin = "",
    [string]$DesktopBin = "",
    [string]$RegistryRoot = "HKCU:\Software\Classes",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ArchiveExtensions = @(
    ".zip", ".7z", ".rar", ".z01", ".001", ".tar", ".tgz", ".gz",
    ".zst", ".bz2", ".xz", ".tzst", ".tbz2", ".txz"
)

function Resolve-SubKeyRoot {
    param([string]$Root)
    $normalized = $Root.Trim()
    if ($normalized -match '^HKCU:\\(.+)$') {
        return $Matches[1].Trim('\')
    }
    if ($normalized -match '^HKEY_CURRENT_USER\\(.+)$') {
        return $Matches[1].Trim('\')
    }
    if ($normalized -match '^[A-Za-z0-9_]+:') {
        throw "RegistryRoot must point to HKCU (got '$Root')."
    }
    return $normalized.Trim('\')
}

function Resolve-BinaryPath {
    param(
        [string]$ExplicitPath,
        [string[]]$CommandNames,
        [string[]]$CandidatePaths,
        [string]$FallbackName
    )
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return $ExplicitPath
    }
    foreach ($cmdName in $CommandNames) {
        $cmd = Get-Command -Name $cmdName -ErrorAction SilentlyContinue
        if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
            return $cmd.Source
        }
    }
    foreach ($candidate in $CandidatePaths) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    return $FallbackName
}

function Set-ShellVerb {
    param(
        [string]$VerbSubKey,
        [string]$Label,
        [string]$CommandLine,
        [string]$IconValue,
        [switch]$DryRunMode
    )
    if ($DryRunMode) {
        Write-Output "[dry-run] HKCU:\$VerbSubKey"
        Write-Output "          (Default) = $Label"
        Write-Output "          command   = $CommandLine"
        return
    }

    $verbKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($VerbSubKey)
    if ($null -eq $verbKey) {
        throw "Failed to create registry key: HKCU:\$VerbSubKey"
    }
    try {
        $verbKey.SetValue("", $Label, [Microsoft.Win32.RegistryValueKind]::String)
        if (-not [string]::IsNullOrWhiteSpace($IconValue)) {
            $verbKey.SetValue("Icon", $IconValue, [Microsoft.Win32.RegistryValueKind]::String)
        }
        $cmdKey = $verbKey.CreateSubKey("command")
        if ($null -eq $cmdKey) {
            throw "Failed to create command subkey under: HKCU:\$VerbSubKey"
        }
        try {
            $cmdKey.SetValue("", $CommandLine, [Microsoft.Win32.RegistryValueKind]::String)
        }
        finally {
            $cmdKey.Dispose()
        }
    }
    finally {
        $verbKey.Dispose()
    }
}

$subRoot = Resolve-SubKeyRoot -Root $RegistryRoot
if ([string]::IsNullOrWhiteSpace($subRoot)) {
    throw "RegistryRoot cannot be empty."
}

$localAppData = [Environment]::GetFolderPath("LocalApplicationData")
$programFiles = [Environment]::GetFolderPath("ProgramFiles")
$userProfile  = [Environment]::GetFolderPath("UserProfile")

$resolvedDandi = Resolve-BinaryPath `
    -ExplicitPath $DandiBin `
    -CommandNames @("dandi.exe", "dandi") `
    -CandidatePaths @(
        (Join-Path $localAppData "Dandi\dandi.exe"),
        (Join-Path $localAppData "Programs\Dandi\dandi.exe"),
        (Join-Path $userProfile ".cargo\bin\dandi.exe"),
        (Join-Path $programFiles "Dandi\dandi.exe")
    ) `
    -FallbackName "dandi.exe"

$resolvedDesktop = Resolve-BinaryPath `
    -ExplicitPath $DesktopBin `
    -CommandNames @("dandi-desktop.exe", "Dandi.exe") `
    -CandidatePaths @(
        (Join-Path $localAppData "Dandi\dandi-desktop.exe"),
        (Join-Path $localAppData "Dandi\Dandi.exe"),
        (Join-Path $localAppData "Programs\Dandi\dandi-desktop.exe"),
        (Join-Path $localAppData "Programs\Dandi\Dandi.exe"),
        (Join-Path $programFiles "Dandi\dandi-desktop.exe"),
        (Join-Path $programFiles "Dandi\Dandi.exe")
    ) `
    -FallbackName "dandi-desktop.exe"

$cliIcon = if (Test-Path -LiteralPath $resolvedDesktop) {
    "`"$resolvedDesktop`",0"
} elseif (Test-Path -LiteralPath $resolvedDandi) {
    "`"$resolvedDandi`",0"
} else {
    ""
}
$desktopIcon = if (Test-Path -LiteralPath $resolvedDesktop) {
    "`"$resolvedDesktop`",0"
} else {
    $cliIcon
}

$compressCommand = "`"$resolvedDandi`" pack -o `"%1.zip`" `"%1`""
$extractCommand  = "`"$resolvedDandi`" unpack --mode smart `"%1`""
$openCommand     = "`"$resolvedDesktop`" `"%1`""

# 1. All files (*) and folders (Directory) -> Compress with Dandi (Clean ZIP)
Set-ShellVerb `
    -VerbSubKey "$subRoot\*\shell\DandiCompress" `
    -Label "Compress with Dandi (Clean ZIP)" `
    -CommandLine $compressCommand `
    -IconValue $cliIcon `
    -DryRunMode:$DryRun

Set-ShellVerb `
    -VerbSubKey "$subRoot\Directory\shell\DandiCompress" `
    -Label "Compress with Dandi (Clean ZIP)" `
    -CommandLine $compressCommand `
    -IconValue $cliIcon `
    -DryRunMode:$DryRun

# 2. Archive extensions via SystemFileAssociations (non-destructive, zero ProgID hijacking)
foreach ($ext in $ArchiveExtensions) {
    Set-ShellVerb `
        -VerbSubKey "$subRoot\SystemFileAssociations\$ext\shell\DandiExtract" `
        -Label "Extract with Dandi (Smart)" `
        -CommandLine $extractCommand `
        -IconValue $cliIcon `
        -DryRunMode:$DryRun

    Set-ShellVerb `
        -VerbSubKey "$subRoot\SystemFileAssociations\$ext\shell\DandiOpen" `
        -Label "Open in Dandi" `
        -CommandLine $openCommand `
        -IconValue $desktopIcon `
        -DryRunMode:$DryRun
}

if (-not $DryRun) {
    Write-Output "Installed Dandi Explorer context menu entries under HKCU:\$subRoot"
    Write-Output "  dandi CLI:     $resolvedDandi"
    Write-Output "  dandi desktop: $resolvedDesktop"
    Write-Output "  extensions:    $($ArchiveExtensions -join ', ')"
}
