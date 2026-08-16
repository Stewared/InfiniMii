[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SaveRoot,

    [Parameter(Mandatory = $true)]
    [string]$LtdPath,

    [string]$BackupRoot,

    [string]$CompatibleLtdPath,

    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedLtdSha = '4b7c936a065cdc59dd03a26dadc5f36c623b39cf9ad24c7ba1db1be4c80501e4'
$expectedCorruptSaveSha = 'c33c3ee39df13f9d06501fdf2ce5a9d944beb6c84293454e2734aaef207f2d5d'
$expectedRepairedSaveSha = '141a97e335b5437e7eec3c77fca263f3835be00ef83ccbbab7abe32a48012443'
$expectedCompatibleLtdSha = 'b944f11268a3f0591ae0a8adb0a328a42c4d16ba01ceedc97e8796c9de07d8bc'
$expectedSaveLength = 2945804
$slotOffset = 0x1fe6e4
$blockLength = 156

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
}

function Test-ByteRangeEqual(
    [byte[]]$Left,
    [int]$LeftOffset,
    [byte[]]$Right,
    [int]$RightOffset,
    [int]$Length
) {
    for ($index = 0; $index -lt $Length; $index++) {
        if ($Left[$LeftOffset + $index] -ne $Right[$RightOffset + $index]) {
            return $false
        }
    }
    return $true
}

function Get-TreeManifest([string]$Root) {
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    return @(
        Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse | ForEach-Object {
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($resolvedRoot.Length).TrimStart('\')
                Length = $_.Length
                Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        } | Sort-Object RelativePath
    )
}

function Assert-ManifestsEqual($Expected, $Actual) {
    if ($Expected.Count -ne $Actual.Count) {
        throw "Backup manifest count differs: expected $($Expected.Count), got $($Actual.Count)."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        $left = $Expected[$index]
        $right = $Actual[$index]
        if (($left.RelativePath -cne $right.RelativePath) `
            -or ($left.Length -ne $right.Length) `
            -or ($left.Sha256 -cne $right.Sha256)) {
            throw "Backup manifest mismatch at $($left.RelativePath)."
        }
    }
}

if (@(Get-Process -Name 'ShareMii', 'Ryujinx', 'Ryujinx.Ava', 'Ryujinx.Canary' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'ShareMii and Ryujinx must both be stopped before inspecting or repairing the save.'
}

$resolvedSaveRoot = (Resolve-Path -LiteralPath $SaveRoot).Path.TrimEnd('\')
$resolvedLtdPath = (Resolve-Path -LiteralPath $LtdPath).Path
$targets = @(
    Join-Path $resolvedSaveRoot '0\Mii.sav'
    Join-Path $resolvedSaveRoot '1\Mii.sav'
)
foreach ($target in $targets) {
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw "Missing journal save: $target"
    }
}

$ltd = [System.IO.File]::ReadAllBytes($resolvedLtdPath)
if ($ltd.Length -ne 436 -or (Get-BytesSha256 $ltd) -cne $expectedLtdSha) {
    throw 'The LTD source is not the exact fresh Claire file associated with this corruption.'
}

$wrongBlock = [byte[]]::new($blockLength)
$correctBlock = [byte[]]::new($blockLength)
[System.Array]::Copy($ltd, 5, $wrongBlock, 0, $blockLength)
[System.Array]::Copy($ltd, 4, $correctBlock, 0, $blockLength)

$repairs = @()
foreach ($target in $targets) {
    $bytes = [System.IO.File]::ReadAllBytes($target)
    if ($bytes.Length -ne $expectedSaveLength -or (Get-BytesSha256 $bytes) -cne $expectedCorruptSaveSha) {
        throw "Journal save fingerprint changed: $target"
    }
    if (-not (Test-ByteRangeEqual $bytes $slotOffset $wrongBlock 0 $blockLength)) {
        throw "Journal save does not contain the uniquely identified shifted Claire block: $target"
    }
    $repaired = [byte[]]$bytes.Clone()
    [System.Array]::Copy($correctBlock, 0, $repaired, $slotOffset, $blockLength)
    $changed = 0
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        if ($bytes[$index] -ne $repaired[$index]) {
            if ($index -lt $slotOffset -or $index -ge ($slotOffset + $blockLength)) {
                throw "Repair would change an out-of-window byte at $index."
            }
            $changed++
        }
    }
    $repairedSha = Get-BytesSha256 $repaired
    if ($changed -ne 111 -or $repairedSha -cne $expectedRepairedSaveSha) {
        throw "Repaired save did not match the independently verified result for $target."
    }
    $repairs += [pscustomobject]@{
        Target = $target
        Bytes = $repaired
        ChangedBytes = $changed
        Sha256 = $repairedSha
    }
}

$compatibleLtd = [byte[]]::new(434)
$compatibleLtd[0] = 2
[System.Array]::Copy($ltd, 4, $compatibleLtd, 5, 156)
[System.Array]::Copy($ltd, 160, $compatibleLtd, 161, 264)
[System.Array]::Copy($ltd, 424, $compatibleLtd, 425, 3)
for ($index = 428; $index -lt 434; $index++) { $compatibleLtd[$index] = 0xa3 }
if ((Get-BytesSha256 $compatibleLtd) -cne $expectedCompatibleLtdSha) {
    throw 'The generated v2 compatibility file did not match its independently verified SHA-256.'
}

if (-not $Apply) {
    [pscustomobject]@{
        Mode = 'dry-run'
        SaveRoot = $resolvedSaveRoot
        SourceLtd = $resolvedLtdPath
        SourceLtdSha256 = $expectedLtdSha
        JournalCount = $repairs.Count
        ChangedBytesPerJournal = 111
        RepairedJournalSha256 = $expectedRepairedSaveSha
        CompatibleLtdSha256 = $expectedCompatibleLtdSha
    } | ConvertTo-Json -Depth 3
    exit 0
}

if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
    throw '-BackupRoot is required with -Apply.'
}
$resolvedBackupRoot = [System.IO.Path]::GetFullPath($BackupRoot).TrimEnd('\')
if ($resolvedBackupRoot.StartsWith($resolvedSaveRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'BackupRoot must be outside the live Ryujinx save directory.'
}
if (Test-Path -LiteralPath $resolvedBackupRoot) {
    throw "BackupRoot already exists: $resolvedBackupRoot"
}
$backupParent = Split-Path -Parent $resolvedBackupRoot
if (-not (Test-Path -LiteralPath $backupParent -PathType Container)) {
    New-Item -ItemType Directory -Path $backupParent | Out-Null
}

if (-not [string]::IsNullOrWhiteSpace($CompatibleLtdPath)) {
    $prospectiveCompatibleOutput = [System.IO.Path]::GetFullPath($CompatibleLtdPath)
    if (Test-Path -LiteralPath $prospectiveCompatibleOutput) {
        throw "CompatibleLtdPath already exists: $prospectiveCompatibleOutput"
    }
}

$sourceManifest = Get-TreeManifest $resolvedSaveRoot
Copy-Item -LiteralPath $resolvedSaveRoot -Destination $resolvedBackupRoot -Recurse
$backupManifest = Get-TreeManifest $resolvedBackupRoot
Assert-ManifestsEqual $sourceManifest $backupManifest

$transactionId = [guid]::NewGuid().ToString('N')
$published = @()
try {
    foreach ($repair in $repairs) {
        $stage = "$($repair.Target).infinimii-$transactionId.tmp"
        $old = "$($repair.Target).infinimii-$transactionId.old"
        [System.IO.File]::WriteAllBytes($stage, $repair.Bytes)
        if ((Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedRepairedSaveSha) {
            throw "Staged repair hash mismatch: $stage"
        }
        Move-Item -LiteralPath $repair.Target -Destination $old
        try {
            Move-Item -LiteralPath $stage -Destination $repair.Target
        } catch {
            Move-Item -LiteralPath $old -Destination $repair.Target
            throw
        }
        $published += [pscustomobject]@{ Target = $repair.Target; Old = $old }
    }
    foreach ($repair in $repairs) {
        $actual = [System.IO.File]::ReadAllBytes($repair.Target)
        if (($actual.Length -ne $expectedSaveLength) `
            -or ((Get-BytesSha256 $actual) -cne $expectedRepairedSaveSha) `
            -or (-not (Test-ByteRangeEqual $actual $slotOffset $correctBlock 0 $blockLength))) {
            throw "Published journal verification failed: $($repair.Target)"
        }
    }
} catch {
    foreach ($entry in @($published | Select-Object -Last 2)) {
        if (Test-Path -LiteralPath $entry.Target) {
            Remove-Item -LiteralPath $entry.Target -Force
        }
        if (Test-Path -LiteralPath $entry.Old) {
            Move-Item -LiteralPath $entry.Old -Destination $entry.Target
        }
    }
    throw
}

foreach ($entry in $published) {
    if (Test-Path -LiteralPath $entry.Old) {
        Remove-Item -LiteralPath $entry.Old -Force
    }
}

$compatibleOutput = $null
if (-not [string]::IsNullOrWhiteSpace($CompatibleLtdPath)) {
    $compatibleOutput = [System.IO.Path]::GetFullPath($CompatibleLtdPath)
    [System.IO.File]::WriteAllBytes($compatibleOutput, $compatibleLtd)
    if ((Get-FileHash -LiteralPath $compatibleOutput -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedCompatibleLtdSha) {
        throw 'Compatible LTD verification failed after writing.'
    }
}

[pscustomobject]@{
    Mode = 'apply'
    BackupRoot = $resolvedBackupRoot
    BackupFiles = $backupManifest.Count
    JournalPaths = $targets
    JournalSha256 = $expectedRepairedSaveSha
    ChangedBytesPerJournal = 111
    CompatibleLtdPath = $compatibleOutput
    CompatibleLtdSha256 = $expectedCompatibleLtdSha
} | ConvertTo-Json -Depth 4
