param(
    [string]$BfshaPath = "",
    [string]$MaterialStatePath = ""
)

$ErrorActionPreference = "Stop"

function Get-ByteSha256 {
    param([byte[]]$Bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $hasher.Dispose() }
}

function Get-StreamBytes {
    param([IO.Stream]$Stream)
    $savedPosition = $Stream.Position
    $memory = [IO.MemoryStream]::new()
    try {
        $Stream.Position = 0
        $Stream.CopyTo($memory)
        return $memory.ToArray()
    }
    finally {
        $Stream.Position = $savedPosition
        $memory.Dispose()
    }
}

function Get-InstructionRecord {
    param(
        [object]$ShaderCode,
        [string]$Label
    )
    $stream = Get-StreamBytes $ShaderCode.BinaryData[1]
    if ($stream.Length -lt 128) { throw "$Label stream is shorter than its 0x80-byte header" }
    $instructions = [byte[]]::new($stream.Length - 128)
    [Array]::Copy($stream, 128, $instructions, 0, $instructions.Length)
    return [ordered]@{
        byte_length = $instructions.Length
        sha256 = Get-ByteSha256 $instructions
    }
}

function Find-PresentationMaterial {
    param(
        [object]$State,
        [hashtable]$Selection
    )

    $resource = $State.resources | Where-Object resource_name -eq $Selection.resource | Select-Object -First 1
    $model = $resource.models | Where-Object name -eq $Selection.model | Select-Object -First 1
    $shape = $model.shapes | Where-Object name -eq $Selection.shape | Select-Object -First 1
    $material = $model.materials | Where-Object name -eq $Selection.material | Select-Object -First 1
    if ($null -eq $resource -or $null -eq $model -or $null -eq $shape -or $null -eq $material) {
        throw "Presentation material selection is missing: $($Selection.key)"
    }
    if ([string]$shape.material_name -ne [string]$material.name) {
        throw "Shape/material assignment disagrees for $($Selection.key)"
    }
    return @($shape, $material)
}

$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$projectRoot = (Resolve-Path (Join-Path $workspace "..")).Path
if (-not $BfshaPath) {
    $BfshaPath = Join-Path $projectRoot "ltdDemo_converted_assets\decompressed\1\Shader\GameUber.Trial.100.product.Nin_NX_NVN.bfsha"
}
if (-not $MaterialStatePath) {
    $MaterialStatePath = Join-Path $workspace "renderer\reference_outfit_material_state.json"
}

$toolboxRoot = Join-Path $projectRoot "tools\Switch-Toolbox"
$bfshaAssembly = Join-Path $toolboxRoot "BfshaLibrary.dll"
if (-not (Test-Path -LiteralPath $bfshaAssembly -PathType Leaf)) {
    throw "Required Switch-Toolbox assembly is missing: $bfshaAssembly"
}

[Environment]::CurrentDirectory = $toolboxRoot
foreach ($directory in @($toolboxRoot, (Join-Path $toolboxRoot "Lib"))) {
    Get-ChildItem -LiteralPath $directory -Filter "*.dll" | ForEach-Object {
        try { [Reflection.Assembly]::LoadFrom($_.FullName) | Out-Null }
        catch { }
    }
}

$savedConsole = [Console]::Out
[Console]::SetOut([IO.TextWriter]::Null)
try { $archive = [BfshaLibrary.BfshaFile]::new((Resolve-Path -LiteralPath $BfshaPath).Path) }
finally { [Console]::SetOut($savedConsole) }
$shaderModel = $archive.ShaderModels["GameAll"]
if ($null -eq $shaderModel) {
    throw "GameAll shader model is missing from $BfshaPath"
}

$state = Get-Content -Raw -LiteralPath $MaterialStatePath | ConvertFrom-Json
$selections = @(
    @{
        key = "tops_body"
        resource = "ClothTopsTshirtLong"
        model = "ClothTopsTshirtLong"
        shape = "Tops__mt_Body"
        material = "mt_Body"
    },
    @{
        key = "bottoms_body"
        resource = "ClothBottomsPantsLong"
        model = "ClothBottomsPantsLong"
        shape = "Bottoms__mt_Body"
        material = "mt_Body"
    },
    @{
        key = "shoes_body"
        resource = "ClothShoesStandard"
        model = "ClothShoesStandard"
        shape = "Shoes__mt_Body"
        material = "mt_Body"
    },
    @{
        key = "tops_softmesh"
        resource = "ClothTopsTshirtLong"
        model = "ClothTopsTshirtLong"
        shape = "Softmesh__mt_Softmesh"
        material = "mt_Softmesh"
    },
    @{
        key = "bottoms_softmesh"
        resource = "ClothBottomsPantsLong"
        model = "ClothBottomsPantsLong"
        shape = "Softmesh__mt_Softmesh"
        material = "mt_Softmesh"
    }
)

$records = foreach ($selection in $selections) {
    $resolved = Find-PresentationMaterial $state $selection
    $shape = $resolved[0]
    $material = $resolved[1]
    $optionValues = [Collections.Generic.Dictionary[string, string]]::new()
    foreach ($option in $material.shader_options) {
        $value = [string]$option.value
        if ($value -eq "<Default Value>") { continue }
        if ($value -eq "True") { $value = "1" }
        elseif ($value -eq "False") { $value = "0" }
        $optionValues[[string]$option.name] = $value
    }
    $optionValues["gsys_weight"] = [string]$shape.vertex_skin_count
    $optionValues["gsys_index_stream_format"] = "0"
    $optionValues["gsys_assign_type"] = "gsys_assign_material"
    $optionValues["system_id"] = "0"

    $rawProgramIndex = [int]$shaderModel.GetProgramIndex($optionValues)
    $rawCompatibleProgramIndices = @()
    for ($candidateIndex = 0; $candidateIndex -lt $shaderModel.Programs.Count; $candidateIndex++) {
        if ($shaderModel.IsValidProgram($candidateIndex, $optionValues)) {
            $rawCompatibleProgramIndices += $candidateIndex
        }
    }
    if ($rawProgramIndex -lt 0 -or $rawCompatibleProgramIndices.Count -eq 0 -or $rawCompatibleProgramIndices[0] -ne $rawProgramIndex) {
        throw "Raw presentation compatibility scan disagrees with GetProgramIndex for $($selection.key)"
    }

    $sourceConstraints = @()
    $shaderSamplerNames = @(
        $material.texture_assignments |
            ForEach-Object { @($_.shader_samplers) } |
            ForEach-Object { [string]$_ }
    )
    if ($selection.key -eq "tops_body" -or $selection.key -eq "bottoms_body") {
        if ($shaderSamplerNames -contains "_user0") {
            throw "$($selection.key) unexpectedly binds _user0"
        }
        $optionValues["enable_texture_user0"] = "0"
        $sourceConstraints += [ordered]@{
            option = "enable_texture_user0"
            value = "0"
            evidence = "BFRES material has no _user0 shader-sampler assignment"
        }
    }
    if ($selection.key -eq "bottoms_body") {
        if ($shaderSamplerNames -contains "_e0") {
            throw "bottoms_body unexpectedly binds _e0"
        }
        $optionValues["enable_emission_map"] = "0"
        $sourceConstraints += [ordered]@{
            option = "enable_emission_map"
            value = "0"
            evidence = "BFRES material has no _e0 shader-sampler assignment"
        }
    }

    $programIndex = [int]$shaderModel.GetProgramIndex($optionValues)
    $compatibleProgramIndices = @()
    for ($candidateIndex = 0; $candidateIndex -lt $shaderModel.Programs.Count; $candidateIndex++) {
        if ($shaderModel.IsValidProgram($candidateIndex, $optionValues)) {
            $compatibleProgramIndices += $candidateIndex
        }
    }
    if ($programIndex -lt 0 -or $compatibleProgramIndices.Count -ne 1 -or $compatibleProgramIndices[0] -ne $programIndex) {
        throw "Source-constrained presentation program is not singleton for $($selection.key)"
    }
    $program = $shaderModel.Programs[$programIndex]
    $savedConsole = [Console]::Out
    [Console]::SetOut([IO.TextWriter]::Null)
    try { $variation = $shaderModel.GetShaderVariation($program) }
    finally { [Console]::SetOut($savedConsole) }

    [ordered]@{
        key = $selection.key
        resource = $selection.resource
        model = $selection.model
        shape = $selection.shape
        material = $selection.material
        vertex_skin_count = [int]$shape.vertex_skin_count
        shader_archive = [string]$material.shader_archive
        shading_model = [string]$material.shading_model
        resolver_candidate_program_index = $rawProgramIndex
        raw_compatible_program_indices = $rawCompatibleProgramIndices
        source_constraints = $sourceConstraints
        resolved_program_index = $programIndex
        compatible_program_indices = $compatibleProgramIndices
        selection_status = "exact_unique_after_source_constraints"
        stages = [ordered]@{
            vertex = [ordered]@{
                instructions = Get-InstructionRecord $variation.BinaryProgram.ShaderInfoData.VertexShaderCode "$($selection.key) vertex"
            }
            fragment = [ordered]@{
                instructions = Get-InstructionRecord $variation.BinaryProgram.ShaderInfoData.PixelShaderCode "$($selection.key) fragment"
            }
        }
        resolver = "BfshaLibrary raw compatible-set scan plus explicit missing BFRES sampler constraints and exact system options"
    }
}

$records | ConvertTo-Json -Depth 5
