#Requires -Version 5.1
<#
.SYNOPSIS
    Removes all per-user (HKCU) Windows Explorer context menu entries added by Dandi.
.DESCRIPTION
    Deletes Dandi's Compress, Extract, and Open shell verbs under HKCU:\Software\Classes
    and prunes empty parent containers created exclusively for those verbs.
.PARAMETER RegistryRoot
    Optional HKCU registry prefix (default: HKCU:\Software\Classes).
.PARAMETER DryRun
    Print planned registry removals without modifying the registry.
#>
[CmdletBinding()]
param(
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

function Remove-SubKeyIfPresent {
    param(
        [string]$SubKeyPath,
        [switch]$DryRunMode
    )
    $existing = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKeyPath, $false)
    if ($null -eq $existing) {
        return $false
    }
    $existing.Dispose()

    if ($DryRunMode) {
        Write-Output "[dry-run] Would remove: HKCU:\$SubKeyPath"
        return $true
    }

    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($SubKeyPath, $false)
    return $true
}

function Remove-EmptySubKey {
    param(
        [string]$SubKeyPath,
        [switch]$DryRunMode
    )
    $existing = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKeyPath, $false)
    if ($null -eq $existing) {
        return
    }
    try {
        $isEmpty = ($existing.SubKeyCount -eq 0) -and ($existing.ValueCount -eq 0)
    }
    finally {
        $existing.Dispose()
    }

    if ($isEmpty) {
        if ($DryRunMode) {
            Write-Output "[dry-run] Would prune empty key: HKCU:\$SubKeyPath"
        } else {
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($SubKeyPath, $false)
        }
    }
}

$subRoot = Resolve-SubKeyRoot -Root $RegistryRoot
if ([string]::IsNullOrWhiteSpace($subRoot)) {
    throw "RegistryRoot cannot be empty."
}

$removedCount = 0

if (Remove-SubKeyIfPresent -SubKeyPath "$subRoot\*\shell\DandiCompress" -DryRunMode:$DryRun) {
    $removedCount++
}
Remove-EmptySubKey -SubKeyPath "$subRoot\*\shell" -DryRunMode:$DryRun
Remove-EmptySubKey -SubKeyPath "$subRoot\*" -DryRunMode:$DryRun

if (Remove-SubKeyIfPresent -SubKeyPath "$subRoot\Directory\shell\DandiCompress" -DryRunMode:$DryRun) {
    $removedCount++
}
Remove-EmptySubKey -SubKeyPath "$subRoot\Directory\shell" -DryRunMode:$DryRun
Remove-EmptySubKey -SubKeyPath "$subRoot\Directory" -DryRunMode:$DryRun

foreach ($ext in $ArchiveExtensions) {
    if (Remove-SubKeyIfPresent -SubKeyPath "$subRoot\SystemFileAssociations\$ext\shell\DandiExtract" -DryRunMode:$DryRun) {
        $removedCount++
    }
    if (Remove-SubKeyIfPresent -SubKeyPath "$subRoot\SystemFileAssociations\$ext\shell\DandiOpen" -DryRunMode:$DryRun) {
        $removedCount++
    }
    Remove-EmptySubKey -SubKeyPath "$subRoot\SystemFileAssociations\$ext\shell" -DryRunMode:$DryRun
    Remove-EmptySubKey -SubKeyPath "$subRoot\SystemFileAssociations\$ext" -DryRunMode:$DryRun
}

Remove-EmptySubKey -SubKeyPath "$subRoot\SystemFileAssociations" -DryRunMode:$DryRun

if (-not $DryRun) {
    Write-Output "Removed $removedCount Dandi context menu key(s) under HKCU:\$subRoot"
}
