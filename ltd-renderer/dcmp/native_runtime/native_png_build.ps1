[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [string]$ZlibNgArchive = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$zlibNgVersion = "2.3.3"
$zlibNgArchiveSha256 = "f9c65aa9c852eb8255b636fd9f07ce1c406f061ec19a2e7d508b318ca0c907d1"
$zlibNgUrl = "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/$zlibNgVersion.tar.gz"

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot "build\native_png"
}
$source = Join-Path $PSScriptRoot "native_png.cpp"
$toolSource = Join-Path $PSScriptRoot "native_png_tool.cpp"
$header = Join-Path $PSScriptRoot "native_png.h"
foreach ($required in @($source, $toolSource, $header)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Native PNG source is missing: $required"
    }
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
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw "CMake is required to build the pinned zlib-ng backend"
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ("infinimii-native-png-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $archive = if ($ZlibNgArchive) {
        (Resolve-Path -LiteralPath $ZlibNgArchive).Path
    } else {
        $download = Join-Path $temporaryRoot "zlib-ng-$zlibNgVersion.tar.gz"
        Invoke-WebRequest -Uri $zlibNgUrl -OutFile $download
        $download
    }
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw "zlib-ng archive is missing: $archive"
    }
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($archiveHash -ne $zlibNgArchiveSha256) {
        throw "zlib-ng archive SHA-256 $archiveHash is not the pinned $zlibNgArchiveSha256"
    }

    $sourceDirectory = Join-Path $temporaryRoot "source"
    $zlibBuildDirectory = Join-Path $temporaryRoot "zlib-build"
    New-Item -ItemType Directory -Path $sourceDirectory | Out-Null
    & tar.exe -xf $archive -C $sourceDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract the pinned zlib-ng archive"
    }
    $zlibSource = Join-Path $sourceDirectory "zlib-ng-$zlibNgVersion"
    if (-not (Test-Path -LiteralPath $zlibSource -PathType Container)) {
        throw "Pinned zlib-ng archive has an unexpected root"
    }

    & cmake -S $zlibSource -B $zlibBuildDirectory -A x64 `
        -DZLIB_COMPAT=ON `
        -DBUILD_SHARED_LIBS=ON `
        -DBUILD_TESTING=OFF `
        -DWITH_GTEST=OFF `
        -DWITH_BENCHMARKS=OFF `
        -DINSTALL_UTILS=OFF `
        -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
        -DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/Brepro
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned zlib-ng CMake configuration failed"
    }
    & cmake --build $zlibBuildDirectory --config Release --target zlib-ng --parallel
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned zlib-ng build failed"
    }
    $builtZlib = Join-Path $zlibBuildDirectory "Release\zlib1.dll"
    if (-not (Test-Path -LiteralPath $builtZlib -PathType Leaf)) {
        throw "Pinned zlib-ng build produced no zlib1.dll"
    }

    $toolBuild = Join-Path $temporaryRoot "tool-build"
    New-Item -ItemType Directory -Path $toolBuild | Out-Null
    $temporaryTool = Join-Path $toolBuild "native_png_tool.exe"
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
        "/DUNICODE",
        "/D_UNICODE",
        "/I`"$PSScriptRoot`"",
        "/Fe:`"$temporaryTool`"",
        "`"$source`"",
        "`"$toolSource`"",
        "/link",
        "/Brepro"
    )
    $command = "call `"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && " +
        "cl.exe " + ($compileArguments -join " ")
    & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "Native PNG tool compilation failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $temporaryTool -PathType Leaf)) {
        throw "Compiler succeeded without producing native_png_tool.exe"
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $finalTool = Join-Path $resolvedOutput "native_png_tool.exe"
    $finalZlib = Join-Path $resolvedOutput "native_png_zlib1.dll"
    Copy-Item -LiteralPath $temporaryTool -Destination $finalTool -Force
    Copy-Item -LiteralPath $builtZlib -Destination $finalZlib -Force

    [ordered]@{
        abi_version = 1
        source = $source
        source_sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        header_sha256 = (Get-FileHash -LiteralPath $header -Algorithm SHA256).Hash.ToLowerInvariant()
        tool_source_sha256 = (Get-FileHash -LiteralPath $toolSource -Algorithm SHA256).Hash.ToLowerInvariant()
        executable = $finalTool
        executable_sha256 = (Get-FileHash -LiteralPath $finalTool -Algorithm SHA256).Hash.ToLowerInvariant()
        zlib_ng_version = $zlibNgVersion
        zlib_ng_archive_sha256 = $archiveHash
        zlib_ng = $finalZlib
        zlib_ng_sha256 = (Get-FileHash -LiteralPath $finalZlib -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json -Compress
} finally {
    $normalizedTemporary = [System.IO.Path]::GetFullPath($temporaryRoot)
    $normalizedSystemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $normalizedTemporary.StartsWith(
        $normalizedSystemTemp,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing to clean a native-PNG temporary path outside the system temp root"
    }
    if (Test-Path -LiteralPath $normalizedTemporary -PathType Container) {
        Remove-Item -LiteralPath $normalizedTemporary -Recurse -Force
    }
}
