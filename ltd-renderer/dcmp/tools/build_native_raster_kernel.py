#!/usr/bin/env python3
"""Build the minimal NumPy-aware raster kernel beside the renderer sources."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

import numpy


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "renderer" / "native_raster_kernel.c"


def _windows_vsdevcmd() -> Path:
    candidates = (
        Path(os.environ.get("VSINSTALLDIR", "")) / "Common7/Tools/VsDevCmd.bat",
        Path("C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/Tools/VsDevCmd.bat"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/Professional/Common7/Tools/VsDevCmd.bat"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/Enterprise/Common7/Tools/VsDevCmd.bat"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("Visual Studio 2022 C++ build tools were not found")


def build(*, force: bool) -> Path:
    del force  # Direct compiler builds are always clean and deterministic.
    extension_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if not isinstance(extension_suffix, str) or not extension_suffix:
        raise RuntimeError("Python did not report an extension-module suffix")
    destination = ROOT / "renderer" / f"_native_raster_kernel{extension_suffix}"
    with tempfile.TemporaryDirectory(prefix="ltd-native-raster-build-") as directory:
        temporary = Path(directory)
        built = temporary / destination.name
        source_sha256 = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        build_header = temporary / "native_raster_kernel_build.h"
        build_header.write_text(
            "#define LTD_NATIVE_RASTER_KERNEL_ABI_VERSION 1\n"
            f'#define LTD_NATIVE_RASTER_KERNEL_SOURCE_SHA256 "{source_sha256}"\n',
            encoding="ascii",
            newline="\n",
        )
        if sys.platform == "win32":
            vsdevcmd = _windows_vsdevcmd()
            python_include = Path(sysconfig.get_paths()["include"])
            python_lib = Path(sys.base_prefix) / "libs"
            command = (
                f'call "{vsdevcmd}" -arch=x64 -host_arch=x64 >nul && '
                f'cl.exe /nologo /LD /O2 /fp:strict /MD '
                f'/I"{python_include}" /I"{numpy.get_include()}" /I"{temporary}" '
                f'"{SOURCE}" /link /Brepro /OUT:"{built}" '
                f'/LIBPATH:"{python_lib}" python{sys.version_info.major}{sys.version_info.minor}.lib'
            )
            command_file = temporary / "build_native_raster_kernel.cmd"
            command_file.write_text(
                "@echo off\r\n" + command + "\r\n",
                encoding="utf-8",
                newline="",
            )
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", str(command_file)],
                cwd=temporary,
                check=False,
                text=True,
                capture_output=True,
            )
        else:
            compiler = shutil.which("cc")
            if compiler is None:
                raise RuntimeError("a C compiler is required")
            command = [
                compiler,
                "-shared",
                "-O3",
                "-ffp-contract=off",
                "-fPIC",
                f'-I{sysconfig.get_paths()["include"]}',
                f"-I{numpy.get_include()}",
                f"-I{temporary}",
                str(SOURCE),
                "-o",
                str(built),
            ]
            completed = subprocess.run(
                command,
                cwd=temporary,
                check=False,
                text=True,
                capture_output=True,
            )
        if completed.returncode:
            detail = (completed.stdout + completed.stderr).strip()
            raise RuntimeError(f"native raster kernel build failed:\n{detail}")
        if not built.is_file():
            raise RuntimeError("compiler succeeded without producing the extension module")
        shutil.copy2(built, destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    destination = build(force=args.force)
    print(f"built {destination.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
