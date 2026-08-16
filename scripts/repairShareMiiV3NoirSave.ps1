[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SaveRoot,
    [Parameter(Mandatory = $true)][string]$SourceLtdPath,
    [Parameter(Mandatory = $true)][string]$CompatibleLtdPath,
    [Parameter(Mandatory = $true)][string]$VerifiedReplayRoot,
    [Parameter(Mandatory = $true)][string]$VerifiedRepairRoot,
    [Parameter(Mandatory = $true)][string]$ModernSaveEditorRoot,
    [string]$BackupRoot,
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expected = @{
    SourceLtd = '1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef'
    CompatibleLtd = 'd1d0bd6d88303f2bdf33905c9a4bc3206ecc8c7af871acdc4b6328269300b81f'
    CorruptMii = '0f1098013c97ef8d6aba1f66b712d1f68681ae89653c522b8f2ef7623afb37d1'
    ReplayMii = 'b30cb113bd8102cb58e6c229b405e36ed665c7f814b5e8970513767064092ab9'
    RepairedMii = '8fec93660709ecc53a058542b9e8406528da7fc3569b90e2734d7dc7f356c712'
    Player = '4e842c2815bac02f0066a5d4cbcc60ba8a23f4c82178b321460a2dd28bcccf88'
    Map = 'bfe4b5259436e94a6a1ad7bd6a398e8e340b49908c6aa65475c08cef21e64913'
    Empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    CorruptUgc = 'b04ea53ab0321747de173f5368ce0d2f87e1a8b3c20c7ba0cc2c18e33ac562b6'
    Canvas = '9d4b925a51f2a4c3bb5b945c9f8714829f588c134051df8714eb3ecf188f0176'
    Ugc = '269bfddbe59874c430b8aad4bd339de41eccaf6437ca2710be3c3778d641db52'
}
$slotGenderOffset = 0x1FE70F

function Get-Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-File([string]$Path, [long]$Length, [string]$Sha) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -ne $Length -or (Get-Sha $Path) -cne $Sha) {
        throw "Unexpected file fingerprint: $Path"
    }
}
function Get-Manifest([string]$Root) {
    $full = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    @(Get-ChildItem -LiteralPath $full -File -Recurse | ForEach-Object {
        [pscustomobject]@{ Relative = $_.FullName.Substring($full.Length).TrimStart('\'); Length = $_.Length; Sha = Get-Sha $_.FullName }
    } | Sort-Object Relative)
}
function Assert-ManifestEqual($Left, $Right, [string]$Label) {
    if ($Left.Count -ne $Right.Count) { throw "$Label file count differs." }
    for ($i = 0; $i -lt $Left.Count; $i++) {
        if ($Left[$i].Relative -cne $Right[$i].Relative -or $Left[$i].Length -ne $Right[$i].Length -or $Left[$i].Sha -cne $Right[$i].Sha) {
            throw "$Label differs at $($Left[$i].Relative)."
        }
    }
}
function Assert-Journal([string]$Root, [string]$Journal, [bool]$Repaired) {
    $dir = Join-Path $Root $Journal
    Assert-File (Join-Path $dir 'Map.sav') 192576 $expected.Map
    Assert-File (Join-Path $dir 'Player.sav') 1325148 $expected.Player
    if ($Repaired) {
        Assert-File (Join-Path $dir 'Mii.sav') 2945804 $expected.RepairedMii
        Assert-File (Join-Path $dir 'Ugc\UgcFacePaint000.canvas.zs') 4053 $expected.Canvas
        Assert-File (Join-Path $dir 'Ugc\UgcFacePaint000.ugctex.zs') 5818 $expected.Ugc
    } else {
        Assert-File (Join-Path $dir 'Mii.sav') 2945804 $expected.CorruptMii
        Assert-File (Join-Path $dir 'Ugc\UgcFacePaint000.canvas.zs') 0 $expected.Empty
        Assert-File (Join-Path $dir 'Ugc\UgcFacePaint000.ugctex.zs') 9875 $expected.CorruptUgc
    }
}
function Test-ModernParse([string]$Root, [string]$Journal) {
    $editor = (Resolve-Path -LiteralPath $ModernSaveEditorRoot).Path
    $validator = @'
(async()=>{const{readFileSync}=await import("node:fs");const{parseSav,decode,createMaterializedAccessor}=await import("@alexislours/ltd-savedata");const{MII_SCHEMA,PLAYER_SCHEMA}=await import("@alexislours/ltd-savedata/schema");const{listMiiSlots}=await import("@alexislours/ltd-sharemii");const[m,p]=process.argv.slice(1);const saves={mii:createMaterializedAccessor(MII_SCHEMA,decode(MII_SCHEMA,parseSav(new Uint8Array(readFileSync(m))))),player:createMaterializedAccessor(PLAYER_SCHEMA,decode(PLAYER_SCHEMA,parseSav(new Uint8Array(readFileSync(p)))))};const s=listMiiSlots(saves).find(x=>x.slot===1);if(!s||s.empty||s.name!=="Spider-Man Noir")throw Error("slot 1 is not Spider-Man Noir");console.log(JSON.stringify(s))})()
'@
    $prior = [Environment]::GetEnvironmentVariable('INFINIMII_NOIR_SAVE_VALIDATOR', 'Process')
    try {
        $env:INFINIMII_NOIR_SAVE_VALIDATOR = $validator
        Push-Location $editor
        try {
            $output = & node --input-type=module --eval 'await eval(process.env.INFINIMII_NOIR_SAVE_VALIDATOR)' (Join-Path $Root "$Journal\Mii.sav") (Join-Path $Root "$Journal\Player.sav") 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Modern parser rejected journal ${Journal}: $output" }
        } finally { Pop-Location }
    } finally {
        [Environment]::SetEnvironmentVariable('INFINIMII_NOIR_SAVE_VALIDATOR', $prior, 'Process')
    }
}

if (@(Get-Process -Name 'ShareMii','Ryujinx','Ryujinx.Ava','Ryujinx.Canary' -ErrorAction SilentlyContinue).Count) {
    throw 'ShareMii and Ryujinx must be stopped.'
}
$save = (Resolve-Path -LiteralPath $SaveRoot).Path.TrimEnd('\')
$sourceLtd = (Resolve-Path -LiteralPath $SourceLtdPath).Path
$compatibleLtd = (Resolve-Path -LiteralPath $CompatibleLtdPath).Path
$replay = (Resolve-Path -LiteralPath $VerifiedReplayRoot).Path.TrimEnd('\')
$repair = (Resolve-Path -LiteralPath $VerifiedRepairRoot).Path.TrimEnd('\')

Assert-File $sourceLtd 10307 $expected.SourceLtd
Assert-File $compatibleLtd 10305 $expected.CompatibleLtd
Assert-File (Join-Path $replay 'Mii.sav') 2945804 $expected.ReplayMii
Assert-File (Join-Path $repair 'Mii.sav') 2945804 $expected.RepairedMii
Assert-File (Join-Path $repair 'Player.sav') 1325148 $expected.Player
Assert-File (Join-Path $repair 'Ugc\UgcFacePaint000.canvas.zs') 4053 $expected.Canvas
Assert-File (Join-Path $repair 'Ugc\UgcFacePaint000.ugctex.zs') 5818 $expected.Ugc
$replayMii = [IO.File]::ReadAllBytes((Join-Path $replay 'Mii.sav'))
$repairMii = [IO.File]::ReadAllBytes((Join-Path $repair 'Mii.sav'))
$diff = 0
for ($i = 0; $i -lt $replayMii.Length; $i++) { if ($replayMii[$i] -ne $repairMii[$i]) { if ($i -ne $slotGenderOffset) { throw "Unexpected replay/repair difference at 0x$($i.ToString('X'))." }; $diff++ } }
if ($diff -ne 1 -or $replayMii[$slotGenderOffset] -ne 1 -or $repairMii[$slotGenderOffset] -ne 0) { throw 'The verified gender correction is not the exact 1 -> 0 byte change.' }

foreach ($j in '0','1') { Assert-Journal $save $j $false }
if ((Get-Sha (Join-Path $save '0\Mii.sav')) -cne (Get-Sha (Join-Path $save '1\Mii.sav'))) { throw 'Live journals differ.' }

$stage = Join-Path ([IO.Path]::GetTempPath()) ('infinimii-noir-transaction-' + [guid]::NewGuid().ToString('N'))
Copy-Item -LiteralPath $save -Destination $stage -Recurse
try {
    foreach ($j in '0','1') {
        Copy-Item -LiteralPath (Join-Path $repair 'Mii.sav') -Destination (Join-Path $stage "$j\Mii.sav") -Force
        Copy-Item -LiteralPath (Join-Path $repair 'Ugc\UgcFacePaint000.canvas.zs') -Destination (Join-Path $stage "$j\Ugc\UgcFacePaint000.canvas.zs") -Force
        Copy-Item -LiteralPath (Join-Path $repair 'Ugc\UgcFacePaint000.ugctex.zs') -Destination (Join-Path $stage "$j\Ugc\UgcFacePaint000.ugctex.zs") -Force
        Assert-Journal $stage $j $true
        Test-ModernParse $stage $j
    }
    if (-not $Apply) {
        [pscustomobject]@{ Mode='dry-run'; SourceLtdSha256=$expected.SourceLtd; CompatibleLtdSha256=$expected.CompatibleLtd; ReplayMiiSha256=$expected.ReplayMii; RepairedMiiSha256=$expected.RepairedMii; PlayerSha256=$expected.Player; CanvasSha256=$expected.Canvas; UgcSha256=$expected.Ugc; ModernParser='passed-both-journals' } | ConvertTo-Json
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($BackupRoot)) { throw '-BackupRoot is required with -Apply.' }
    $backup = [IO.Path]::GetFullPath($BackupRoot).TrimEnd('\')
    if ($backup.StartsWith($save + '\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $backup)) { throw 'BackupRoot must be new and outside SaveRoot.' }
    $before = Get-Manifest $save
    Copy-Item -LiteralPath $save -Destination $backup -Recurse
    Assert-ManifestEqual $before (Get-Manifest $backup) 'Backup'

    $tx = [guid]::NewGuid().ToString('N'); $published = @()
    $relativeTargets = @('0\Mii.sav','0\Ugc\UgcFacePaint000.canvas.zs','0\Ugc\UgcFacePaint000.ugctex.zs','1\Mii.sav','1\Ugc\UgcFacePaint000.canvas.zs','1\Ugc\UgcFacePaint000.ugctex.zs')
    try {
        foreach ($relative in $relativeTargets) {
            $target = Join-Path $save $relative; $temp = "$target.$tx.tmp"; $old = "$target.$tx.old"
            Copy-Item -LiteralPath (Join-Path $stage $relative) -Destination $temp
            Move-Item -LiteralPath $target -Destination $old
            try { Move-Item -LiteralPath $temp -Destination $target } catch { Move-Item -LiteralPath $old -Destination $target; throw }
            $published += [pscustomobject]@{Target=$target;Old=$old}
        }
        foreach ($j in '0','1') { Assert-Journal $save $j $true; Test-ModernParse $save $j }
    } catch {
        foreach ($entry in @($published | Select-Object -Last $published.Count)) {
            if (Test-Path -LiteralPath $entry.Target) { Remove-Item -LiteralPath $entry.Target -Force }
            if (Test-Path -LiteralPath $entry.Old) { Move-Item -LiteralPath $entry.Old -Destination $entry.Target }
        }
        throw
    }
    foreach ($entry in $published) { Remove-Item -LiteralPath $entry.Old -Force }
    [pscustomobject]@{ Mode='apply'; BackupRoot=$backup; RepairedMiiSha256=$expected.RepairedMii; PlayerSha256=$expected.Player; Journals=2; ModernParser='passed-both-journals' } | ConvertTo-Json
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
