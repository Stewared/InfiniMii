param(
    [Parameter(Mandatory = $true)]
    [string]$BfshaPath,

    [Parameter(Mandatory = $true)]
    [string]$MaterialStatePath,

    [ValidateSet("Johnny", "Emma")]
    [string]$Target = "Johnny",

    # Optional target-independent request inventory. Existing Johnny/Emma
    # callers intentionally retain their byte-for-byte request behavior.
    [string]$RequestsPath,

    # Optional exact stage-byte export. The JSON identities are unchanged for
    # existing callers that omit this path.
    [string]$StageOutputRoot
)

$ErrorActionPreference = "Stop"

function Get-Sha256 {
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

function Get-StageRecord {
    param($Code, [string]$OutputStem)
    $control = Get-StreamBytes $Code.BinaryData[0]
    $container = Get-StreamBytes $Code.BinaryData[1]
    if ($container.Length -lt 0x80) {
        throw "GameAll stage container is shorter than its 0x80-byte instruction offset"
    }
    $maxwell = [byte[]]::new($container.Length - 0x30)
    [Array]::Copy($container, 0x30, $maxwell, 0, $maxwell.Length)
    $instructions = [byte[]]::new($container.Length - 0x80)
    [Array]::Copy($container, 0x80, $instructions, 0, $instructions.Length)
    $record = [ordered]@{
        control_stream = [ordered]@{ byte_length = $control.Length; sha256 = Get-Sha256 $control }
        container_stream = [ordered]@{ byte_length = $container.Length; sha256 = Get-Sha256 $container }
        maxwell_offset = 48
        maxwell = [ordered]@{ byte_length = $maxwell.Length; sha256 = Get-Sha256 $maxwell }
        instruction_offset = 128
        instructions = [ordered]@{ byte_length = $instructions.Length; sha256 = Get-Sha256 $instructions }
    }
    if ($null -ne $script:resolvedStageOutputRoot -and -not [String]::IsNullOrWhiteSpace($OutputStem)) {
        $payloads = [ordered]@{
            control_stream = $control
            container_stream = $container
            maxwell = $maxwell
            instructions = $instructions
        }
        $files = [ordered]@{}
        foreach ($entry in $payloads.GetEnumerator()) {
            $fileName = "$OutputStem.$($entry.Key).bin"
            $destination = Join-Path $script:resolvedStageOutputRoot $fileName
            [IO.File]::WriteAllBytes($destination, [byte[]]$entry.Value)
            $files[[string]$entry.Key] = $fileName
        }
        $record["exported_files"] = $files
    }
    return $record
}

$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$projectRoot = (Resolve-Path (Join-Path $workspace "..")).Path
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

$resolvedBfsha = (Resolve-Path -LiteralPath $BfshaPath).Path
$resolvedMaterialState = (Resolve-Path -LiteralPath $MaterialStatePath).Path
$script:resolvedStageOutputRoot = $null
if (-not [String]::IsNullOrWhiteSpace($StageOutputRoot)) {
    $script:resolvedStageOutputRoot = [IO.Path]::GetFullPath($StageOutputRoot)
    New-Item -ItemType Directory -Force -Path $script:resolvedStageOutputRoot | Out-Null
}
$savedConsole = [Console]::Out
[Console]::SetOut([IO.TextWriter]::Null)
try { $archive = [BfshaLibrary.BfshaFile]::new($resolvedBfsha) }
finally { [Console]::SetOut($savedConsole) }

$shaderModel = $archive.ShaderModels["GameAll"]
if ($null -eq $shaderModel) { throw "GameAll shader model is missing from $resolvedBfsha" }
$materialState = Get-Content -Raw -LiteralPath $resolvedMaterialState | ConvertFrom-Json
if (-not [String]::IsNullOrWhiteSpace($RequestsPath)) {
    $resolvedRequests = (Resolve-Path -LiteralPath $RequestsPath).Path
    $requestPayload = Get-Content -Raw -LiteralPath $resolvedRequests | ConvertFrom-Json
    $requests = @()
    foreach ($requestEntry in $requestPayload) { $requests += $requestEntry }
    if ($requests.Count -eq 0) { throw "RequestsPath must contain a non-empty JSON array" }
    $keys = @{}
    foreach ($request in $requests) {
        foreach ($field in @("key", "resource", "model", "shape", "material")) {
            if ([String]::IsNullOrWhiteSpace([string]$request.$field)) {
                throw "RequestsPath entry is missing required field '$field'"
            }
        }
        if ($keys.ContainsKey([string]$request.key)) {
            throw "RequestsPath contains duplicate key '$($request.key)'"
        }
        $keys[[string]$request.key] = $true
        if ($null -ne $request.kind -and [string]$request.kind -notin @("hair", "material")) {
            throw "RequestsPath entry '$($request.key)' has unsupported kind '$($request.kind)'"
        }
    }
}
elseif ($Target -eq "Emma") {
    $requests = @(
        [ordered]@{ key = "head"; resource = "MiiHead00"; model = "MiiHead00"; shape = "Head__mt_Head"; material = "mt_Head" },
        [ordered]@{ key = "face_mask"; resource = "MiiHead00"; model = "MiiHead00"; shape = "Mask__mt_Mask"; material = "mt_Mask" },
        [ordered]@{ key = "hair"; resource = "MiiHairAll073"; model = "MiiHairAll073"; shape = "Hair__mt_Hair"; material = "mt_Hair" },
        [ordered]@{ key = "nose"; resource = "MiiNose25"; model = "MiiNose25"; shape = "Nose__mt_Nose"; material = "mt_Nose" },
        [ordered]@{ key = "nose_line"; resource = "MiiNose25"; model = "MiiNose25"; shape = "NoseLine__mt_NoseLine"; material = "mt_NoseLine" },
        [ordered]@{ key = "glass_frame"; resource = "MiiGlass08"; model = "MiiGlass08"; shape = "Flame__mt_Body"; material = "mt_Body" },
        [ordered]@{ key = "glass_lens_opaque"; resource = "MiiGlass08"; model = "MiiGlass08"; shape = "Opa__mt_LensOpa"; material = "mt_LensOpa" }
    )
}
else {
    $requests = @(
        [ordered]@{ key = "head"; resource = "MiiHead14"; model = "MiiHead14"; shape = "Head__mt_Head"; material = "mt_Head" },
        [ordered]@{ key = "face_mask"; resource = "MiiHead14"; model = "MiiHead14"; shape = "Mask__mt_Mask"; material = "mt_Mask" },
        [ordered]@{ key = "hair_back"; resource = "MiiHairBack000"; model = "MiiHairBack000"; shape = "Hair__mt_Hair"; material = "mt_Hair" },
        [ordered]@{ key = "hair_front"; resource = "MiiHairFront029"; model = "MiiHairFront029"; shape = "Hair__mt_Hair"; material = "mt_Hair" }
    )
}

$attributeEntries = $shaderModel.Attributes.ToArray()
$samplerEntries = $shaderModel.Samplers.ToArray()
$uniformBlockEntries = $shaderModel.UniformBlocks.ToArray()
$records = @()
foreach ($request in $requests) {
    if ([string]$request.key -notmatch '^[A-Za-z0-9_-]+$') {
        throw "Request key '$($request.key)' cannot be used as an exact stage filename"
    }
    $resource = $materialState.resources | Where-Object resource_name -eq $request.resource | Select-Object -First 1
    $model = $resource.models | Where-Object name -eq $request.model | Select-Object -First 1
    $shape = $model.shapes | Where-Object name -eq $request.shape | Select-Object -First 1
    $material = $model.materials | Where-Object name -eq $request.material | Select-Object -First 1
    if ($null -eq $resource -or $null -eq $model -or $null -eq $shape -or $null -eq $material) {
        throw "Material request could not be resolved: $($request.key)"
    }

    # BFRES's literal inherited marker is intentionally unconstrained. Supplying
    # a value here would fabricate a default that the selected BFRES did not store.
    $optionValues = [Collections.Generic.Dictionary[string, string]]::new()
    $serializedOptions = @()
    $omittedDefaultOptions = @()
    foreach ($option in $material.shader_options) {
        $serializedValue = [string]$option.value
        $serializedOptions += [ordered]@{ name = [string]$option.name; value = $serializedValue }
        if ($serializedValue -eq "<Default Value>") {
            $omittedDefaultOptions += [string]$option.name
            continue
        }
        $resolverValue = $serializedValue
        if ($resolverValue -eq "True") { $resolverValue = "1" }
        elseif ($resolverValue -eq "False") { $resolverValue = "0" }
        $optionValues[[string]$option.name] = $resolverValue
    }
    $materialConstraints = [ordered]@{}
    foreach ($entry in $optionValues.GetEnumerator() | Sort-Object Key) {
        $materialConstraints[[string]$entry.Key] = [string]$entry.Value
    }

    # These are the same title resolver system keys used by the established
    # GameUber and outfit inspectors; gsys_weight is read from this exact shape.
    $systemOptions = [ordered]@{
        gsys_weight = [string]$shape.vertex_skin_count
        gsys_index_stream_format = "0"
        gsys_assign_type = "gsys_assign_material"
        system_id = "0"
    }
    foreach ($entry in $systemOptions.GetEnumerator()) { $optionValues[$entry.Key] = $entry.Value }

    $requestFamily = [string]$request.family
    $isHairRequest = (
        ([string]$request.kind -eq "hair") -or
        $requestFamily -eq "hair" -or
        $request.key -eq "hair" -or
        $request.key -eq "hair_back" -or
        $request.key -eq "hair_front"
    )
    $isBeardRequest = $requestFamily -eq "beard"
    $isEarRequest = $requestFamily -eq "ear"
    $isHeadwearRequest = $requestFamily -eq "headwear"
    $isDecorationRequest = $requestFamily -eq "decoration"
    $isGlassRequest = $requestFamily -in @(
        "glass_frame", "glass_lens_opaque", "glass_lens_translucent"
    )

    $bfresCompatibleWithoutArchiveDefaults = @()
    for ($candidate = 0; $candidate -lt $shaderModel.Programs.Count; $candidate++) {
        if ($shaderModel.IsValidProgram($candidate, $optionValues)) {
            $bfresCompatibleWithoutArchiveDefaults += $candidate
        }
    }

    # Some exact Mii BFRES shader-option dictionaries do not repeat resolver
    # choices serialized in their exact render-info blocks.  For that proven
    # pair, opaque maps to gsys_renderstate=0 and a disabled alpha test maps to
    # gsys_alpha_test_enable=0. Translucent glass maps to gsys_renderstate=2.
    # Exact front-only legacy headwear additionally maps to
    # gsys_display_face_type=0; this distinguishes GameAll96 from GameAll276.
    # Applying those source bytes distinguishes Hair612 from Hair1068 and the
    # translucent Glass60 branch from its opaque frame/lens branches without
    # relying on GetProgramIndex row order. Beard uses the same exact opaque
    # state even though its two candidate programs currently differ only in
    # map_shift.
    $renderStateConstraints = @()
    if ($isHairRequest -or $isBeardRequest -or $isEarRequest -or $isHeadwearRequest -or $isGlassRequest) {
        $modeRows = @($material.render_infos | Where-Object name -eq "gsys_render_state_mode")
        $alphaRows = @($material.render_infos | Where-Object name -eq "gsys_alpha_test_enable")
        if ($modeRows.Count -ne 1 -or $alphaRows.Count -ne 1) {
            throw "$($request.key) lacks unique BFRES Mii render-state evidence"
        }
        $modeValue = [string]$modeRows[0].value[0]
        $alphaValue = [string]$alphaRows[0].value[0]
        $displayFaceValue = $null
        if ($isHeadwearRequest) {
            $displayFaceRows = @(
                $material.render_infos |
                    Where-Object name -eq "gsys_render_state_display_face"
            )
            if ($displayFaceRows.Count -ne 1) {
                throw "$($request.key) lacks unique BFRES headwear display-face evidence"
            }
            $displayFaceValue = [string]$displayFaceRows[0].value[0]
            if ($modeValue -ne "opaque" -or $alphaValue -ne "false" -or $displayFaceValue -ne "front") {
                throw "$($request.key) exact BFRES headwear surface state changed"
            }
        }
        $renderStateValue = if ($modeValue -eq "opaque") {
            "0"
        }
        elseif ($isGlassRequest -and $modeValue -eq "translucent") {
            "2"
        }
        else {
            $null
        }
        if ($null -ne $renderStateValue -and $alphaValue -eq "false") {
            $optionValues["gsys_renderstate"] = $renderStateValue
            $optionValues["gsys_alpha_test_enable"] = "0"
            $renderStateConstraints += [ordered]@{
                name = "gsys_renderstate"
                value = $renderStateValue
                source = "BFRES RenderInfo gsys_render_state_mode"
                source_value = $modeValue
            }
            $renderStateConstraints += [ordered]@{
                name = "gsys_alpha_test_enable"
                value = "0"
                source = "BFRES RenderInfo gsys_alpha_test_enable"
                source_value = $alphaValue
            }
            if ($isHeadwearRequest) {
                $optionValues["gsys_display_face_type"] = "0"
                $renderStateConstraints += [ordered]@{
                    name = "gsys_display_face_type"
                    value = "0"
                    source = "BFRES RenderInfo gsys_render_state_display_face"
                    source_value = $displayFaceValue
                }
            }
        }
    }

    # Split-hair plus Beard00/01 BFRES materials omit map_shift entirely. The
    # selected GameAll archive itself stores map_shift's default choice/index,
    # so use that binary-backed value rather than inventing or inheriting one
    # from a different Hair/Beard resource. Beard02 serializes map_shift=18 and
    # therefore selects the distinct Beard468 fragment.
    $archiveDefaultConstraints = @()
    if ($isHairRequest -or $isBeardRequest) {
        $serializedMapShift = @($material.shader_options | Where-Object name -eq "map_shift")
        if ($serializedMapShift.Count -gt 1) { throw "$($request.key) has duplicate map_shift options" }
        if ($serializedMapShift.Count -eq 0) {
            $archiveOption = $shaderModel.StaticOptions["map_shift"]
            if ($null -eq $archiveOption -or [string]::IsNullOrEmpty([string]$archiveOption.defaultChoice)) {
                throw "GameAll does not expose a binary-backed map_shift default"
            }
            $defaultValue = [string]$archiveOption.defaultChoice
            $optionValues["map_shift"] = $defaultValue
            $archiveDefaultConstraints += [ordered]@{
                name = "map_shift"
                value = $defaultValue
                default_index = [int]$archiveOption.defaultIndex
                choices = @($archiveOption.choices)
                source = "GameAll StaticOptions.map_shift defaultChoice/defaultIndex"
            }
        }
    }

    # Decoration serializes map_specular_mask as BFRES's inherited marker.
    # GameAll stores its exact archive default as choice/index 0; applying that
    # source value distinguishes the non-specular Decoration programs from the
    # otherwise compatible map_specular_mask=1103 variants.
    if ($isDecorationRequest) {
        $serializedSpecular = @($material.shader_options | Where-Object name -eq "map_specular_mask")
        if ($serializedSpecular.Count -ne 1 -or [string]$serializedSpecular[0].value -ne "<Default Value>") {
            throw "$($request.key) Decoration map_specular_mask inheritance changed"
        }
        $archiveOption = $shaderModel.StaticOptions["map_specular_mask"]
        if ($null -eq $archiveOption -or [string]::IsNullOrEmpty([string]$archiveOption.defaultChoice)) {
            throw "GameAll does not expose a binary-backed map_specular_mask default"
        }
        $defaultValue = [string]$archiveOption.defaultChoice
        $optionValues["map_specular_mask"] = $defaultValue
        $archiveDefaultConstraints += [ordered]@{
            name = "map_specular_mask"
            value = $defaultValue
            default_index = [int]$archiveOption.defaultIndex
            choices = @($archiveOption.choices)
            source = "GameAll StaticOptions.map_specular_mask defaultChoice/defaultIndex"
        }
    }

    # Glass frame's inherited enable_normal_map/map_normal choices are pinned by
    # the exact BFRES absence of a usable normal sampler/texture assignment. The
    # opaque lens has MiiGlass##_Nrm and is resolved by its opaque render state;
    # the translucent lens already serializes its non-default Glass60 choices.
    if ($requestFamily -eq "glass_frame") {
        $normalTextureAssignments = @(
            $material.texture_assignments | Where-Object {
                [string]$_.texture_ref -match '^MiiGlass[0-9]+_Nrm$'
            }
        )
        if ($normalTextureAssignments.Count -ne 0) {
            throw "$($request.key) glass frame unexpectedly binds a normal texture"
        }
        $optionValues["enable_normal_map"] = "0"
        $optionValues["map_normal"] = "0"
        $archiveDefaultConstraints += [ordered]@{
            name = "enable_normal_map"
            value = "0"
            source = "BFRES frame has no usable normal sampler/texture assignment"
        }
        $archiveDefaultConstraints += [ordered]@{
            name = "map_normal"
            value = "0"
            source = "BFRES frame has no usable normal sampler/texture assignment"
        }
    }

    $programIndex = [int]$shaderModel.GetProgramIndex($optionValues)
    if ($programIndex -lt 0) { throw "No GameAll program matched $($request.key)" }
    $compatible = @()
    for ($candidate = 0; $candidate -lt $shaderModel.Programs.Count; $candidate++) {
        if ($shaderModel.IsValidProgram($candidate, $optionValues)) { $compatible += $candidate }
    }
    if ($compatible.Count -eq 0 -or $compatible[0] -ne $programIndex) {
        throw "GameAll compatibility scan disagrees with GetProgramIndex for $($request.key)"
    }

    $program = $shaderModel.Programs[$programIndex]
    $savedConsole = [Console]::Out
    [Console]::SetOut([IO.TextWriter]::Null)
    try { $variation = $shaderModel.GetShaderVariation($program) }
    finally { [Console]::SetOut($savedConsole) }

    $attributes = @()
    foreach ($assignment in $material.attribute_assignments) {
        $entry = $attributeEntries | Where-Object { [string]$_.Key -eq [string]$assignment.shader_attribute } | Select-Object -First 1
        $attributes += [ordered]@{
            shader_attribute = [string]$assignment.shader_attribute
            bfres_vertex_attribute = [string]$assignment.vertex_attribute
            shader_model_index = if ($null -ne $entry) { [int]$entry.Value.Index } else { $null }
            vertex_location = if ($null -ne $entry) { [int]$entry.Value.Location } else { $null }
        }
    }

    $samplers = @()
    for ($index = 0; $index -lt $samplerEntries.Length; $index++) {
        $locations = $program.SamplerLocations[$index]
        if ([int]$locations.VertexLocation -lt 0 -and [int]$locations.FragmentLocation -lt 0) { continue }
        $samplers += [ordered]@{
            name = [string]$samplerEntries[$index].Key
            shader_model_index = [int]$samplerEntries[$index].Value.Index
            vertex_location = [int]$locations.VertexLocation
            fragment_location = [int]$locations.FragmentLocation
        }
    }

    $uniformBlocks = @()
    for ($index = 0; $index -lt $uniformBlockEntries.Length; $index++) {
        $locations = $program.UniformBlockLocations[$index]
        if ([int]$locations.VertexLocation -lt 0 -and [int]$locations.FragmentLocation -lt 0) { continue }
        $block = $uniformBlockEntries[$index].Value
        $uniformBlocks += [ordered]@{
            name = [string]$uniformBlockEntries[$index].Key
            shader_model_dictionary_index = $index
            block_index = [int]$block.Index
            byte_size = [int]$block.Size
            vertex_location = [int]$locations.VertexLocation
            fragment_location = [int]$locations.FragmentLocation
        }
    }

    $records += [ordered]@{
        key = [string]$request.key
        resource = [string]$resource.resource_name
        model = [string]$model.name
        shape = [string]$shape.name
        material = [string]$material.name
        vertex_skin_count = [int]$shape.vertex_skin_count
        serialized_shader_options = $serializedOptions
        omitted_default_options = $omittedDefaultOptions
        constrained_material_options = $materialConstraints
        resolver_system_options = $systemOptions
        bfres_compatible_program_indices_without_archive_defaults = $bfresCompatibleWithoutArchiveDefaults
        render_state_constraints = $renderStateConstraints
        archive_default_constraints = $archiveDefaultConstraints
        resolver = "BfshaLibrary.ShaderModel.GetProgramIndex; unrelated BFRES <Default Value> entries remain unconstrained; proven Hair/Beard/Ear/Glass render-state keys and Headwear render/display-face keys come from exact BFRES RenderInfo; absent Hair/Beard map_shift and inherited Decoration map_specular_mask come from GameAll's stored defaultChoice; Glass frame normal-map defaults come from its exact missing normal binding"
        resolved_program_index = $programIndex
        compatible_program_count = $compatible.Count
        compatible_program_indices = $compatible
        texture_assignments = $material.texture_assignments
        sampler_assignments = $material.sampler_assignments
        attributes = $attributes
        samplers = $samplers
        uniform_blocks = $uniformBlocks
        stages = [ordered]@{
            vertex = Get-StageRecord $variation.BinaryProgram.ShaderInfoData.VertexShaderCode "$($request.key).vertex"
            fragment = Get-StageRecord $variation.BinaryProgram.ShaderInfoData.PixelShaderCode "$($request.key).fragment"
        }
    }
}

[ordered]@{
    archive_name = [string]$archive.Name
    shader_model = [string]$shaderModel.Name
    program_count = [int]$shaderModel.Programs.Count
    requests = $records
} | ConvertTo-Json -Depth 14
