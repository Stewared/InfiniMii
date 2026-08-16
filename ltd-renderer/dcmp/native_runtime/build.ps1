[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [string]$ZstdDll = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot "build"
}
$source = Join-Path $PSScriptRoot "ltd_native_runtime.cpp"
$decodedAssetSource = Join-Path $PSScriptRoot "decoded_asset_cache.cpp"
$sceneMathSource = Join-Path $PSScriptRoot "native_scene_math.cpp"
$poseSource = Join-Path $PSScriptRoot "native_pose.cpp"
$geometrySource = Join-Path $PSScriptRoot "native_geometry.cpp"
$rasterCoreSource = Join-Path $PSScriptRoot "native_raster_core.cpp"
$partsSelectorSource = Join-Path $PSScriptRoot "native_parts_selector.cpp"
$sceneAssemblerSource = Join-Path $PSScriptRoot "native_scene_assembler.cpp"
$sceneCacheAdapterSource = Join-Path $PSScriptRoot "native_scene_cache_adapter.cpp"
$facePlanSource = Join-Path $PSScriptRoot "native_face_plan.cpp"
$materialProviderSource = Join-Path $PSScriptRoot "native_material_provider.cpp"
$materialFieldPackerSource = Join-Path $PSScriptRoot "native_material_field_packer.cpp"
$runtimeMaterialAdapterSource = Join-Path $PSScriptRoot "native_runtime_material_adapter.cpp"
$materialScheduleSource = Join-Path $PSScriptRoot "native_material_schedule.cpp"
$drawDescriptorSource = Join-Path $PSScriptRoot "native_draw_descriptor_builder.cpp"
$drawRuntimeV2Source = Join-Path $PSScriptRoot "native_draw_runtime_v2.c"
$faceRuntimeSource = Join-Path $PSScriptRoot "native_face_runtime.c"
$facepaintDecodeSource = Join-Path $PSScriptRoot "native_facepaint_decode.cpp"
$postprocessSource = Join-Path $PSScriptRoot "native_postprocess.cpp"
$nativePngSource = Join-Path $PSScriptRoot "native_png.cpp"
$renderPipelineSource = Join-Path $PSScriptRoot "native_render_pipeline.cpp"
$noseLineSource = Join-Path $PSScriptRoot "native_noseline12.c"
$noseLineBridgeSource = Join-Path $PSScriptRoot "native_noseline_pipeline_bridge.cpp"
$renderOrchestratorSource = Join-Path $PSScriptRoot "native_render_orchestrator.cpp"
$partsSelectorHeader = Join-Path $PSScriptRoot "native_parts_selector.h"
$partsCatalog = Join-Path $PSScriptRoot "generated\native_parts_catalog.bin"
$partsCatalogManifest = Join-Path $PSScriptRoot "generated\native_parts_catalog.json"
$expectedPartsCatalogSha256 = "d8d56e7ee1e291e2e4cc213ef88521b594093a83952747f1d3c8ab0ca5b00523"
$expectedPartsCatalogManifestSha256 = "43385403ab49b65ddc49179149f86374d0ce73989f97d35c7cbc1c4eb5f9aaf8"
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Native runtime source is missing: $source"
}
if (-not (Test-Path -LiteralPath $decodedAssetSource -PathType Leaf)) {
    throw "Decoded asset-cache source is missing: $decodedAssetSource"
}
foreach ($moduleSource in @(
    $sceneMathSource,
    $poseSource,
    $geometrySource,
    $rasterCoreSource,
    $partsSelectorSource,
    $sceneAssemblerSource,
    $sceneCacheAdapterSource,
    $facePlanSource,
    $materialProviderSource,
    $materialFieldPackerSource,
    $runtimeMaterialAdapterSource,
    $materialScheduleSource,
    $drawDescriptorSource,
    $drawRuntimeV2Source,
    $faceRuntimeSource,
    $facepaintDecodeSource,
    $postprocessSource,
    $nativePngSource,
    $renderPipelineSource,
    $noseLineSource,
    $noseLineBridgeSource,
    $renderOrchestratorSource
)) {
    if (-not (Test-Path -LiteralPath $moduleSource -PathType Leaf)) {
        throw "Native scene module source is missing: $moduleSource"
    }
}
foreach ($partsInput in @($partsSelectorHeader, $partsCatalog, $partsCatalogManifest)) {
    if (-not (Test-Path -LiteralPath $partsInput -PathType Leaf)) {
        throw "Native Parts input is missing: $partsInput"
    }
}
$partsCatalogHash = (Get-FileHash -LiteralPath $partsCatalog -Algorithm SHA256).Hash.ToLowerInvariant()
if ($partsCatalogHash -ne $expectedPartsCatalogSha256) {
    throw "Native Parts catalog SHA-256 $partsCatalogHash is not the pinned $expectedPartsCatalogSha256"
}
$partsCatalogManifestHash = (Get-FileHash -LiteralPath $partsCatalogManifest -Algorithm SHA256).Hash.ToLowerInvariant()
if ($partsCatalogManifestHash -ne $expectedPartsCatalogManifestSha256) {
    throw "Native Parts catalog manifest SHA-256 $partsCatalogManifestHash is not the pinned $expectedPartsCatalogManifestSha256"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "Visual Studio locator is missing: $vswhere"
}
$installationPath = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath | Select-Object -First 1)
if (-not $installationPath) {
    throw "Visual Studio with the x64 C++ toolchain was not found"
}
$vsDevCmd = Join-Path $installationPath "Common7\Tools\VsDevCmd.bat"
if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
    throw "VsDevCmd.bat is missing: $vsDevCmd"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$temporaryExe = Join-Path $resolvedOutputDirectory "ltd_native_runtime.building.exe"
$finalExe = Join-Path $resolvedOutputDirectory "ltd_native_runtime.exe"
$temporaryImportLibrary = Join-Path $resolvedOutputDirectory "ltd_native_runtime.building.lib"
$temporaryExportFile = Join-Path $resolvedOutputDirectory "ltd_native_runtime.building.exp"
$objectFile = Join-Path $resolvedOutputDirectory "ltd_native_runtime.obj"
$decodedAssetObjectFile = Join-Path $resolvedOutputDirectory "decoded_asset_cache.obj"
$sceneMathObjectFile = Join-Path $resolvedOutputDirectory "native_scene_math.obj"
$poseObjectFile = Join-Path $resolvedOutputDirectory "native_pose.obj"
$geometryObjectFile = Join-Path $resolvedOutputDirectory "native_geometry.obj"
$rasterCoreObjectFile = Join-Path $resolvedOutputDirectory "native_raster_core.obj"
$partsSelectorObjectFile = Join-Path $resolvedOutputDirectory "native_parts_selector.obj"
$sceneAssemblerObjectFile = Join-Path $resolvedOutputDirectory "native_scene_assembler.obj"
$sceneCacheAdapterObjectFile = Join-Path $resolvedOutputDirectory "native_scene_cache_adapter.obj"
$facePlanObjectFile = Join-Path $resolvedOutputDirectory "native_face_plan.obj"
$materialProviderObjectFile = Join-Path $resolvedOutputDirectory "native_material_provider.obj"
$materialFieldPackerObjectFile = Join-Path $resolvedOutputDirectory "native_material_field_packer.obj"
$runtimeMaterialAdapterObjectFile = Join-Path $resolvedOutputDirectory "native_runtime_material_adapter.obj"
$materialScheduleObjectFile = Join-Path $resolvedOutputDirectory "native_material_schedule.obj"
$drawDescriptorObjectFile = Join-Path $resolvedOutputDirectory "native_draw_descriptor_builder.obj"
$drawRuntimeV2ObjectFile = Join-Path $resolvedOutputDirectory "native_draw_runtime_v2.obj"
$faceRuntimeObjectFile = Join-Path $resolvedOutputDirectory "native_face_runtime.obj"
$facepaintDecodeObjectFile = Join-Path $resolvedOutputDirectory "native_facepaint_decode.obj"
$postprocessObjectFile = Join-Path $resolvedOutputDirectory "native_postprocess.obj"
$nativePngObjectFile = Join-Path $resolvedOutputDirectory "native_png.obj"
$renderPipelineObjectFile = Join-Path $resolvedOutputDirectory "native_render_pipeline.obj"
$noseLineObjectFile = Join-Path $resolvedOutputDirectory "native_noseline12.obj"
$noseLineBridgeObjectFile = Join-Path $resolvedOutputDirectory "native_noseline_pipeline_bridge.obj"
$renderOrchestratorObjectFile = Join-Path $resolvedOutputDirectory "native_render_orchestrator.obj"

$compileArguments = @(
    "/nologo",
    "/std:c++20",
    "/EHsc",
    "/O2",
    "/MT",
    "/fp:strict",
    "/permissive-",
    "/Zc:__cplusplus",
    "/utf-8",
    "/W4",
    "/WX",
    "/Fo:`"$objectFile`"",
    "/Fe:`"$temporaryExe`"",
    "`"$source`"",
    "/link",
    "/Brepro",
    "bcrypt.lib",
    "ole32.lib",
    "windowscodecs.lib"
)
$mainArguments = $compileArguments -join " "
$decodedCompileArguments = @(
    "/nologo",
    "/std:c++20",
    "/EHsc",
    "/O2",
    "/MT",
    "/fp:strict",
    "/permissive-",
    "/Zc:__cplusplus",
    "/utf-8",
    "/W4",
    "/WX",
    "/c",
    "/Fo:`"$decodedAssetObjectFile`"",
    "`"$decodedAssetSource`""
) -join " "
$nativeCppCompileCommands = [System.Collections.Generic.List[string]]::new()
foreach ($module in @(
    @($sceneMathSource, $sceneMathObjectFile),
    @($poseSource, $poseObjectFile),
    @($geometrySource, $geometryObjectFile),
    @($rasterCoreSource, $rasterCoreObjectFile),
    @($partsSelectorSource, $partsSelectorObjectFile),
    @($sceneAssemblerSource, $sceneAssemblerObjectFile),
    @($sceneCacheAdapterSource, $sceneCacheAdapterObjectFile),
    @($facePlanSource, $facePlanObjectFile),
    @($materialProviderSource, $materialProviderObjectFile),
    @($materialFieldPackerSource, $materialFieldPackerObjectFile),
    @($runtimeMaterialAdapterSource, $runtimeMaterialAdapterObjectFile),
    @($materialScheduleSource, $materialScheduleObjectFile),
    @($drawDescriptorSource, $drawDescriptorObjectFile),
    @($facepaintDecodeSource, $facepaintDecodeObjectFile),
    @($postprocessSource, $postprocessObjectFile),
    @($nativePngSource, $nativePngObjectFile),
    @($renderPipelineSource, $renderPipelineObjectFile),
    @($noseLineBridgeSource, $noseLineBridgeObjectFile),
    @($renderOrchestratorSource, $renderOrchestratorObjectFile)
)) {
    $moduleArguments = @(
        "/nologo",
        "/std:c++20",
        "/EHsc",
        "/O2",
        "/MT",
        "/fp:strict",
        "/permissive-",
        "/Zc:__cplusplus",
        "/utf-8",
        "/W4",
        "/WX",
        "/c",
        "/Fo:`"$($module[1])`"",
        "`"$($module[0])`""
    ) -join " "
    $nativeCppCompileCommands.Add("cl.exe $moduleArguments")
}
$nativeCCompileCommands = [System.Collections.Generic.List[string]]::new()
foreach ($module in @(
    @($drawRuntimeV2Source, $drawRuntimeV2ObjectFile),
    @($faceRuntimeSource, $faceRuntimeObjectFile),
    @($noseLineSource, $noseLineObjectFile)
)) {
    $moduleArguments = @(
        "/nologo",
        "/TC",
        "/std:c17",
        "/O2",
        "/MT",
        "/fp:strict",
        "/utf-8",
        "/W4",
        "/WX",
        "/c",
        "/Fo:`"$($module[1])`"",
        "`"$($module[0])`""
    ) -join " "
    $nativeCCompileCommands.Add("cl.exe $moduleArguments")
}
$linkedObjects = @(
    $decodedAssetObjectFile,
    $sceneMathObjectFile,
    $poseObjectFile,
    $geometryObjectFile,
    $rasterCoreObjectFile,
    $partsSelectorObjectFile,
    $sceneAssemblerObjectFile,
    $sceneCacheAdapterObjectFile,
    $facePlanObjectFile,
    $materialProviderObjectFile,
    $materialFieldPackerObjectFile,
    $runtimeMaterialAdapterObjectFile,
    $materialScheduleObjectFile,
    $drawDescriptorObjectFile,
    $drawRuntimeV2ObjectFile,
    $faceRuntimeObjectFile,
    $facepaintDecodeObjectFile,
    $postprocessObjectFile,
    $nativePngObjectFile,
    $renderPipelineObjectFile,
    $noseLineObjectFile,
    $noseLineBridgeObjectFile,
    $renderOrchestratorObjectFile
) | ForEach-Object { "`"$_`"" }
$mainArguments = $mainArguments.Replace(
    "/link /Brepro", (($linkedObjects -join " ") + " /link /Brepro"))
$compileCommands = @("cl.exe $decodedCompileArguments") +
    $nativeCppCompileCommands + $nativeCCompileCommands + @("cl.exe $mainArguments")
$setupPrefix = "call `"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && "
foreach ($compileCommand in $compileCommands) {
    & $env:ComSpec /d /s /c ($setupPrefix + $compileCommand)
    if ($LASTEXITCODE -ne 0) {
        throw "Native runtime compilation failed with exit code $LASTEXITCODE"
    }
}
if (-not (Test-Path -LiteralPath $temporaryExe -PathType Leaf)) {
    throw "Compiler succeeded without producing $temporaryExe"
}
Move-Item -LiteralPath $temporaryExe -Destination $finalExe -Force
foreach ($compiledObject in @(
    $objectFile,
    $decodedAssetObjectFile,
    $sceneMathObjectFile,
    $poseObjectFile,
    $geometryObjectFile,
    $rasterCoreObjectFile,
    $partsSelectorObjectFile,
    $sceneAssemblerObjectFile,
    $sceneCacheAdapterObjectFile,
    $facePlanObjectFile,
    $materialProviderObjectFile,
    $materialFieldPackerObjectFile,
    $runtimeMaterialAdapterObjectFile,
    $materialScheduleObjectFile,
    $drawDescriptorObjectFile,
    $drawRuntimeV2ObjectFile,
    $faceRuntimeObjectFile,
    $facepaintDecodeObjectFile,
    $postprocessObjectFile,
    $nativePngObjectFile,
    $renderPipelineObjectFile,
    $noseLineObjectFile,
    $noseLineBridgeObjectFile,
    $renderOrchestratorObjectFile
)) {
    if (Test-Path -LiteralPath $compiledObject -PathType Leaf) {
        Remove-Item -LiteralPath $compiledObject -Force
    }
}
foreach ($linkSidecar in @($temporaryImportLibrary, $temporaryExportFile)) {
    if (Test-Path -LiteralPath $linkSidecar -PathType Leaf) {
        Remove-Item -LiteralPath $linkSidecar -Force
    }
}

$zstdCandidates = [System.Collections.Generic.List[string]]::new()
if ($ZstdDll) {
    $zstdCandidates.Add($ZstdDll)
}
if ($env:INFINIMII_NATIVE_ZSTD_DLL) {
    $zstdCandidates.Add($env:INFINIMII_NATIVE_ZSTD_DLL)
}
# Prefer the current standalone zstd shipped with the local Git/VS toolchain.
# The old Zstandard.Net NuGet package remains only a compatibility fallback.
$zstdCandidates.Add((Join-Path $env:ProgramFiles "Git\mingw64\bin\libzstd.dll"))
$zstdCandidates.Add((Join-Path $installationPath `
    "Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\mingw64\bin\libzstd.dll"))
$knownNuGetZstd = Join-Path $env:USERPROFILE ".nuget\packages\zstandard.net\1.1.7\build\x64\libzstd.dll"
$zstdCandidates.Add($knownNuGetZstd)
$nuGetRoot = Join-Path $env:USERPROFILE ".nuget\packages\zstandard.net"
if (Test-Path -LiteralPath $nuGetRoot -PathType Container) {
    Get-ChildItem -LiteralPath $nuGetRoot -Recurse -Filter "libzstd.dll" -File |
        Where-Object { $_.FullName -match "[\\/]build[\\/]x64[\\/]libzstd\.dll$" } |
        Sort-Object FullName -Descending |
        ForEach-Object { $zstdCandidates.Add($_.FullName) }
}
$resolvedZstd = $zstdCandidates |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
    Select-Object -First 1
if (-not $resolvedZstd) {
    throw "An x64 libzstd.dll was not found. Pass -ZstdDll or set INFINIMII_NATIVE_ZSTD_DLL."
}
$deployedZstd = Join-Path $resolvedOutputDirectory "libzstd.dll"
if ((Resolve-Path -LiteralPath $resolvedZstd).Path -ne $deployedZstd) {
    Copy-Item -LiteralPath $resolvedZstd -Destination $deployedZstd -Force
}
$nativePngBackendSource = Join-Path $PSScriptRoot "build\native_png\native_png_zlib1.dll"
$expectedNativePngBackendSha256 = "1a1082400ef0ba899ac6f9264e6c17619d5e967944b99f5ea9ef66eec2f3bc52"
if (-not (Test-Path -LiteralPath $nativePngBackendSource -PathType Leaf)) {
    throw "The pinned native PNG zlib-ng backend is missing: $nativePngBackendSource"
}
$nativePngBackendSourceHash = (Get-FileHash -LiteralPath $nativePngBackendSource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($nativePngBackendSourceHash -ne $expectedNativePngBackendSha256) {
    throw "Native PNG backend SHA-256 $nativePngBackendSourceHash is not the pinned $expectedNativePngBackendSha256"
}
$deployedNativePngBackend = Join-Path $resolvedOutputDirectory "native_png_zlib1.dll"
if ((Resolve-Path -LiteralPath $nativePngBackendSource).Path -ne $deployedNativePngBackend) {
    Copy-Item -LiteralPath $nativePngBackendSource -Destination $deployedNativePngBackend -Force
}

$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$decodedAssetSourceHash = (Get-FileHash -LiteralPath $decodedAssetSource -Algorithm SHA256).Hash.ToLowerInvariant()
$sceneMathSourceHash = (Get-FileHash -LiteralPath $sceneMathSource -Algorithm SHA256).Hash.ToLowerInvariant()
$poseSourceHash = (Get-FileHash -LiteralPath $poseSource -Algorithm SHA256).Hash.ToLowerInvariant()
$geometrySourceHash = (Get-FileHash -LiteralPath $geometrySource -Algorithm SHA256).Hash.ToLowerInvariant()
$rasterCoreSourceHash = (Get-FileHash -LiteralPath $rasterCoreSource -Algorithm SHA256).Hash.ToLowerInvariant()
$partsSelectorSourceHash = (Get-FileHash -LiteralPath $partsSelectorSource -Algorithm SHA256).Hash.ToLowerInvariant()
$sceneAssemblerSourceHash = (Get-FileHash -LiteralPath $sceneAssemblerSource -Algorithm SHA256).Hash.ToLowerInvariant()
$sceneCacheAdapterSourceHash = (Get-FileHash -LiteralPath $sceneCacheAdapterSource -Algorithm SHA256).Hash.ToLowerInvariant()
$facePlanSourceHash = (Get-FileHash -LiteralPath $facePlanSource -Algorithm SHA256).Hash.ToLowerInvariant()
$materialProviderSourceHash = (Get-FileHash -LiteralPath $materialProviderSource -Algorithm SHA256).Hash.ToLowerInvariant()
$materialFieldPackerSourceHash = (Get-FileHash -LiteralPath $materialFieldPackerSource -Algorithm SHA256).Hash.ToLowerInvariant()
$runtimeMaterialAdapterSourceHash = (Get-FileHash -LiteralPath $runtimeMaterialAdapterSource -Algorithm SHA256).Hash.ToLowerInvariant()
$materialScheduleSourceHash = (Get-FileHash -LiteralPath $materialScheduleSource -Algorithm SHA256).Hash.ToLowerInvariant()
$drawDescriptorSourceHash = (Get-FileHash -LiteralPath $drawDescriptorSource -Algorithm SHA256).Hash.ToLowerInvariant()
$drawRuntimeV2SourceHash = (Get-FileHash -LiteralPath $drawRuntimeV2Source -Algorithm SHA256).Hash.ToLowerInvariant()
$faceRuntimeSourceHash = (Get-FileHash -LiteralPath $faceRuntimeSource -Algorithm SHA256).Hash.ToLowerInvariant()
$facepaintDecodeSourceHash = (Get-FileHash -LiteralPath $facepaintDecodeSource -Algorithm SHA256).Hash.ToLowerInvariant()
$postprocessSourceHash = (Get-FileHash -LiteralPath $postprocessSource -Algorithm SHA256).Hash.ToLowerInvariant()
$nativePngSourceHash = (Get-FileHash -LiteralPath $nativePngSource -Algorithm SHA256).Hash.ToLowerInvariant()
$renderPipelineSourceHash = (Get-FileHash -LiteralPath $renderPipelineSource -Algorithm SHA256).Hash.ToLowerInvariant()
$noseLineSourceHash = (Get-FileHash -LiteralPath $noseLineSource -Algorithm SHA256).Hash.ToLowerInvariant()
$noseLineBridgeSourceHash = (Get-FileHash -LiteralPath $noseLineBridgeSource -Algorithm SHA256).Hash.ToLowerInvariant()
$renderOrchestratorSourceHash = (Get-FileHash -LiteralPath $renderOrchestratorSource -Algorithm SHA256).Hash.ToLowerInvariant()
$partsSelectorHeaderHash = (Get-FileHash -LiteralPath $partsSelectorHeader -Algorithm SHA256).Hash.ToLowerInvariant()
$exeHash = (Get-FileHash -LiteralPath $finalExe -Algorithm SHA256).Hash.ToLowerInvariant()
$zstdHash = (Get-FileHash -LiteralPath $deployedZstd -Algorithm SHA256).Hash.ToLowerInvariant()
$nativePngBackendHash = (Get-FileHash -LiteralPath $deployedNativePngBackend -Algorithm SHA256).Hash.ToLowerInvariant()
[ordered]@{
    source = $source
    source_sha256 = $sourceHash
    decoded_asset_source_sha256 = $decodedAssetSourceHash
    native_scene_math_source_sha256 = $sceneMathSourceHash
    native_pose_source_sha256 = $poseSourceHash
    native_geometry_source_sha256 = $geometrySourceHash
    native_raster_core_source_sha256 = $rasterCoreSourceHash
    native_parts_selector_source_sha256 = $partsSelectorSourceHash
    native_scene_assembler_source_sha256 = $sceneAssemblerSourceHash
    native_scene_cache_adapter_source_sha256 = $sceneCacheAdapterSourceHash
    native_face_plan_source_sha256 = $facePlanSourceHash
    native_material_provider_source_sha256 = $materialProviderSourceHash
    native_material_field_packer_source_sha256 = $materialFieldPackerSourceHash
    native_runtime_material_adapter_source_sha256 = $runtimeMaterialAdapterSourceHash
    native_material_schedule_source_sha256 = $materialScheduleSourceHash
    native_draw_descriptor_builder_source_sha256 = $drawDescriptorSourceHash
    native_draw_runtime_v2_source_sha256 = $drawRuntimeV2SourceHash
    native_face_runtime_source_sha256 = $faceRuntimeSourceHash
    native_facepaint_decode_source_sha256 = $facepaintDecodeSourceHash
    native_postprocess_source_sha256 = $postprocessSourceHash
    native_png_source_sha256 = $nativePngSourceHash
    native_render_pipeline_source_sha256 = $renderPipelineSourceHash
    native_noseline12_source_sha256 = $noseLineSourceHash
    native_noseline_pipeline_bridge_source_sha256 = $noseLineBridgeSourceHash
    native_render_orchestrator_source_sha256 = $renderOrchestratorSourceHash
    native_parts_selector_header_sha256 = $partsSelectorHeaderHash
    native_parts_catalog = $partsCatalog
    native_parts_catalog_sha256 = $partsCatalogHash
    native_parts_catalog_manifest = $partsCatalogManifest
    native_parts_catalog_manifest_sha256 = $partsCatalogManifestHash
    executable = $finalExe
    executable_sha256 = $exeHash
    zstd = $deployedZstd
    zstd_sha256 = $zstdHash
    native_png_backend = $deployedNativePngBackend
    native_png_backend_sha256 = $nativePngBackendHash
} | ConvertTo-Json -Compress
