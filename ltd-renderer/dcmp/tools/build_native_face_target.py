#!/usr/bin/env python3
"""Build the source-sealed exact-current native face target extension."""

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
SOURCE = ROOT / "renderer" / "native_face_target.c"
ABI_VERSION = 1


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


def build() -> Path:
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if not isinstance(suffix, str) or not suffix:
        raise RuntimeError("Python did not report an extension-module suffix")
    destination = ROOT / "renderer" / f"_native_face_target{suffix}"
    with tempfile.TemporaryDirectory(prefix="ltd-native-face-target-") as directory:
        temporary = Path(directory)
        built = temporary / destination.name
        source_sha256 = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        (temporary / "native_face_target_build.h").write_text(
            f"#define LTD_NATIVE_FACE_TARGET_ABI_VERSION {ABI_VERSION}\n"
            f'#define LTD_NATIVE_FACE_TARGET_SOURCE_SHA256 "{source_sha256}"\n',
            encoding="ascii",
            newline="\n",
        )
        if sys.platform == "win32":
            python_include = Path(sysconfig.get_paths()["include"])
            python_lib = Path(sys.base_prefix) / "libs"
            command = (
                f'call "{_windows_vsdevcmd()}" -arch=x64 -host_arch=x64 >nul && '
                f'cl.exe /nologo /LD /O2 /fp:strict /MD '
                f'/I"{python_include}" /I"{numpy.get_include()}" /I"{temporary}" '
                f'"{SOURCE}" /link /Brepro /OUT:"{built}" '
                f'/LIBPATH:"{python_lib}" '
                f'python{sys.version_info.major}{sys.version_info.minor}.lib'
            )
            command_file = temporary / "build.cmd"
            command_file.write_text(
                "@echo off\r\n" + command + "\r\n", encoding="utf-8", newline=""
            )
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", str(command_file)],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
        else:
            compiler = shutil.which("cc")
            if compiler is None:
                raise RuntimeError("a C compiler is required")
            completed = subprocess.run(
                [
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
                ],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
        if completed.returncode:
            raise RuntimeError(
                "native face target build failed:\n"
                + (completed.stdout + completed.stderr).strip()
            )
        if not built.is_file():
            raise RuntimeError("compiler succeeded without producing the extension")
        shutil.copy2(built, destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="accepted for build-script symmetry")
    parser.parse_args()
    result = build()
    print(f"built {result.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
