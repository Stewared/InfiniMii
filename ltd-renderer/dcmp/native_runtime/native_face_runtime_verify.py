#!/usr/bin/env python3
"""Build and verify the standalone face-runtime C ABI without deployed artifacts."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "native_runtime"
SOURCE = RUNTIME / "native_face_runtime.c"
HEADER = RUNTIME / "native_face_runtime.h"
SMOKE = RUNTIME / "native_face_runtime_smoke.c"
ORACLE_SOURCE = ROOT / "renderer" / "native_face_target.c"
ABI_VERSION = 1
CONTRACT_CANONICAL = (
    "ltd.native.face.runtime|abi=1|rgba=RGBA,row-major,top-left|"
    "scalar=IEEE754-binary64|round=FE_TONEAREST|"
    "ops=mask_pipeline,mask_sample_affine,mask_sample_shade_affine,"
    "faceline_wrinkle,faceline_johnny|oracle="
    "d14b5e39d37e9ebcb315924b863c6ca65d3be075fc7edc067d1fecd49181a62a"
)
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_CANONICAL.encode("utf-8")).hexdigest()
ORACLE_SHA256 = hashlib.sha256(ORACLE_SOURCE.read_bytes()).hexdigest()

OK = 0
BUFFER_TOO_SMALL = 2
NONFINITE = 3
ABI_MISMATCH = 6
CONTRACT_MISMATCH = 7
BUFFER_ALIAS = 8


class ConstRGBA8(ctypes.Structure):
    _fields_ = [
        ("pixels", ctypes.POINTER(ctypes.c_uint8)),
        ("buffer_size_bytes", ctypes.c_size_t),
        ("row_stride_bytes", ctypes.c_size_t),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
    ]


class RGBA8(ctypes.Structure):
    _fields_ = [
        ("pixels", ctypes.POINTER(ctypes.c_uint8)),
        ("buffer_size_bytes", ctypes.c_size_t),
        ("row_stride_bytes", ctypes.c_size_t),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
    ]


class ConstRGBA64(ctypes.Structure):
    _fields_ = [
        ("pixels", ctypes.POINTER(ctypes.c_double)),
        ("buffer_size_bytes", ctypes.c_size_t),
        ("row_stride_bytes", ctypes.c_size_t),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
    ]


class RGBA64(ctypes.Structure):
    _fields_ = [
        ("pixels", ctypes.POINTER(ctypes.c_double)),
        ("buffer_size_bytes", ctypes.c_size_t),
        ("row_stride_bytes", ctypes.c_size_t),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
    ]


class RGBA8Stack(ctypes.Structure):
    _fields_ = [
        ("pixels", ctypes.POINTER(ctypes.c_uint8)),
        ("buffer_size_bytes", ctypes.c_size_t),
        ("layer_stride_bytes", ctypes.c_size_t),
        ("row_stride_bytes", ctypes.c_size_t),
    ]


class MaskLayer(ctypes.Structure):
    _fields_ = [
        ("dispatcher_case", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
        ("image", ConstRGBA64),
    ]


class RasterReport(ctypes.Structure):
    _fields_ = [
        ("row_min_inclusive", ctypes.c_int32),
        ("row_max_inclusive", ctypes.c_int32),
        ("column_min_inclusive", ctypes.c_int32),
        ("column_max_inclusive", ctypes.c_int32),
        ("covered_pixel_count", ctypes.c_uint32),
    ]


U8P = ctypes.POINTER(ctypes.c_uint8)
F64P = ctypes.POINTER(ctypes.c_double)


def _u8_pointer(array: np.ndarray) -> U8P:
    return array.ctypes.data_as(U8P)


def _f64_pointer(array: np.ndarray) -> F64P:
    return array.ctypes.data_as(F64P)


def _const_rgba8(array: np.ndarray) -> ConstRGBA8:
    assert array.dtype == np.uint8 and array.ndim == 3 and array.shape[2] == 4
    assert array.flags.c_contiguous
    return ConstRGBA8(
        _u8_pointer(array), array.nbytes, array.strides[0], array.shape[1], array.shape[0]
    )


def _rgba8(array: np.ndarray) -> RGBA8:
    assert array.dtype == np.uint8 and array.ndim == 3 and array.shape[2] == 4
    assert array.flags.c_contiguous
    return RGBA8(
        _u8_pointer(array), array.nbytes, array.strides[0], array.shape[1], array.shape[0]
    )


def _const_rgba64(array: np.ndarray) -> ConstRGBA64:
    if (
        not isinstance(array, np.ndarray)
        or array.dtype != np.float64
        or array.ndim != 3
        or array.shape[2] != 4
        or not array.flags.c_contiguous
    ):
        raise TypeError("mask layer must be a contiguous float64 RGBA array")
    return ConstRGBA64(
        _f64_pointer(array), array.nbytes, array.strides[0], array.shape[1], array.shape[0]
    )


def _rgba64(array: np.ndarray) -> RGBA64:
    assert array.dtype == np.float64 and array.ndim == 3 and array.shape[2] == 4
    assert array.flags.c_contiguous
    return RGBA64(
        _f64_pointer(array), array.nbytes, array.strides[0], array.shape[1], array.shape[0]
    )


def _rgba8_stack(array: np.ndarray) -> RGBA8Stack:
    assert array.dtype == np.uint8 and array.ndim == 4 and array.shape[3] == 4
    assert array.flags.c_contiguous
    if array.shape[0] == 0:
        return RGBA8Stack(U8P(), 0, 0, 0)
    return RGBA8Stack(
        _u8_pointer(array), array.nbytes, array.strides[0], array.strides[1]
    )


class RuntimeAdapter:
    """NumPy-shaped adapter used only to A/B the pure C ABI against the oracle."""

    ABI_VERSION = ABI_VERSION
    SOURCE_SHA256 = CONTRACT_SHA256

    def __init__(self, library_path: Path) -> None:
        self.library = ctypes.CDLL(str(library_path))
        self._bind()
        self._validate_identity()

    def _bind(self) -> None:
        lib = self.library
        lib.ltd_face_runtime_abi_version.argtypes = []
        lib.ltd_face_runtime_abi_version.restype = ctypes.c_uint32
        lib.ltd_face_runtime_contract_sha256.argtypes = []
        lib.ltd_face_runtime_contract_sha256.restype = ctypes.c_char_p
        lib.ltd_face_runtime_oracle_source_sha256.argtypes = []
        lib.ltd_face_runtime_oracle_source_sha256.restype = ctypes.c_char_p
        lib.ltd_face_runtime_status_name.argtypes = [ctypes.c_int]
        lib.ltd_face_runtime_status_name.restype = ctypes.c_char_p
        lib.ltd_face_runtime_require.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        lib.ltd_face_runtime_require.restype = ctypes.c_int
        lib.ltd_face_mask_pipeline.argtypes = [
            ctypes.POINTER(MaskLayer), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(RGBA8), ctypes.POINTER(RGBA8), ctypes.POINTER(RGBA8),
            ctypes.POINTER(RGBA8), ctypes.POINTER(RGBA8Stack), ctypes.POINTER(RGBA8Stack),
        ]
        lib.ltd_face_mask_pipeline.restype = ctypes.c_int
        lib.ltd_face_mask_sample_affine.argtypes = [
            ctypes.POINTER(ConstRGBA8), F64P, ctypes.c_int32, ctypes.c_int32,
            ctypes.POINTER(RGBA64),
        ]
        lib.ltd_face_mask_sample_affine.restype = ctypes.c_int
        lib.ltd_face_mask_sample_shade_affine.argtypes = [
            ctypes.POINTER(ConstRGBA8), F64P, ctypes.c_int32, ctypes.c_int32,
            F64P, F64P, ctypes.POINTER(RGBA64),
        ]
        lib.ltd_face_mask_sample_shade_affine.restype = ctypes.c_int
        lib.ltd_face_faceline_wrinkle.argtypes = [
            ctypes.POINTER(ConstRGBA8), U8P,
            ctypes.c_double, ctypes.c_double, ctypes.c_double, ctypes.c_double,
            ctypes.POINTER(RGBA8), ctypes.POINTER(RasterReport),
        ]
        lib.ltd_face_faceline_wrinkle.restype = ctypes.c_int
        lib.ltd_face_faceline_johnny.argtypes = [
            ctypes.POINTER(ConstRGBA8), U8P, F64P, F64P, ctypes.POINTER(RGBA8),
        ]
        lib.ltd_face_faceline_johnny.restype = ctypes.c_int

    def _status(self, value: int, operation: str) -> None:
        if value != OK:
            name = self.library.ltd_face_runtime_status_name(value).decode("ascii")
            raise ValueError(f"{operation} failed: {name} ({value})")

    def _validate_identity(self) -> None:
        lib = self.library
        assert lib.ltd_face_runtime_abi_version() == ABI_VERSION
        assert lib.ltd_face_runtime_contract_sha256().decode("ascii") == CONTRACT_SHA256
        assert lib.ltd_face_runtime_oracle_source_sha256().decode("ascii") == ORACLE_SHA256
        assert lib.ltd_face_runtime_require(
            ABI_VERSION, CONTRACT_SHA256.encode("ascii")
        ) == OK
        assert lib.ltd_face_runtime_require(
            ABI_VERSION + 1, CONTRACT_SHA256.encode("ascii")
        ) == ABI_MISMATCH
        assert lib.ltd_face_runtime_require(ABI_VERSION, b"0" * 64) == CONTRACT_MISMATCH

    def mask_pipeline(
        self, sources: list[np.ndarray], cases: tuple[int, ...], width: int, height: int
    ) -> tuple[np.ndarray, ...]:
        if len(sources) != len(cases):
            raise ValueError("source/case count mismatch")
        outputs = [np.zeros((height, width, 4), dtype=np.uint8) for _ in range(4)]
        audits = [np.zeros((len(sources), height, width, 4), dtype=np.uint8) for _ in range(2)]
        layer_array = (MaskLayer * len(sources))()
        for index, (case, source) in enumerate(zip(cases, sources)):
            layer_array[index] = MaskLayer(int(case), 0, _const_rgba64(source))
        output_descriptors = [_rgba8(array) for array in outputs]
        audit_descriptors = [_rgba8_stack(array) for array in audits]
        layers_pointer = layer_array if len(sources) else ctypes.POINTER(MaskLayer)()
        status = self.library.ltd_face_mask_pipeline(
            layers_pointer, len(sources), width, height,
            *(ctypes.byref(item) for item in output_descriptors),
            *(ctypes.byref(item) for item in audit_descriptors),
        )
        self._status(status, "mask_pipeline")
        return (*outputs, *audits)

    def mask_sample_affine(
        self,
        source: np.ndarray,
        output_width: int,
        output_height: int,
        *parameters: Any,
    ) -> np.ndarray:
        if len(parameters) != 8:
            raise TypeError("expected six coefficients, mirrored, and float_planes")
        coefficients = np.ascontiguousarray(parameters[:6], dtype=np.float64)
        mirrored, float_planes = map(int, parameters[6:])
        output = np.zeros((output_height, output_width, 4), dtype=np.float64)
        source_descriptor = _const_rgba8(source)
        output_descriptor = _rgba64(output)
        status = self.library.ltd_face_mask_sample_affine(
            ctypes.byref(source_descriptor), _f64_pointer(coefficients),
            mirrored, float_planes, ctypes.byref(output_descriptor),
        )
        self._status(status, "mask_sample_affine")
        return output

    def mask_sample_shade_affine(
        self,
        source: np.ndarray,
        output_width: int,
        output_height: int,
        *parameters: Any,
    ) -> np.ndarray:
        if len(parameters) != 10:
            raise TypeError("expected six coefficients, mirrored, shader, C1, and C2")
        coefficients = np.ascontiguousarray(parameters[:6], dtype=np.float64)
        mirrored = int(parameters[6])
        shader_kind = int(parameters[7])
        c1 = np.ascontiguousarray(parameters[8], dtype=np.float64)
        c2 = np.ascontiguousarray(parameters[9], dtype=np.float64)
        output = np.empty((output_height, output_width, 4), dtype=np.float64)
        source_descriptor = _const_rgba8(source)
        output_descriptor = _rgba64(output)
        status = self.library.ltd_face_mask_sample_shade_affine(
            ctypes.byref(source_descriptor), _f64_pointer(coefficients),
            mirrored, shader_kind, _f64_pointer(c1), _f64_pointer(c2),
            ctypes.byref(output_descriptor),
        )
        self._status(status, "mask_sample_shade_affine")
        return output

    def faceline_wrinkle(
        self,
        source: np.ndarray,
        skin: np.ndarray,
        left: float,
        right: float,
        bottom: float,
        top: float,
    ) -> tuple[np.ndarray, tuple[int, int], tuple[int, int], int]:
        output = np.empty((256, 128, 4), dtype=np.uint8)
        source_descriptor = _const_rgba8(source)
        output_descriptor = _rgba8(output)
        report = RasterReport()
        status = self.library.ltd_face_faceline_wrinkle(
            ctypes.byref(source_descriptor), _u8_pointer(skin),
            left, right, bottom, top, ctypes.byref(output_descriptor), ctypes.byref(report),
        )
        self._status(status, "faceline_wrinkle")
        return (
            output,
            (report.row_min_inclusive, report.row_max_inclusive),
            (report.column_min_inclusive, report.column_max_inclusive),
            report.covered_pixel_count,
        )

    def faceline_johnny(
        self,
        source: np.ndarray,
        skin: np.ndarray,
        c1: np.ndarray,
        c2: np.ndarray,
    ) -> np.ndarray:
        output = np.empty((256, 128, 4), dtype=np.uint8)
        source_descriptor = _const_rgba8(source)
        output_descriptor = _rgba8(output)
        c1 = np.ascontiguousarray(c1, dtype=np.float64)
        c2 = np.ascontiguousarray(c2, dtype=np.float64)
        status = self.library.ltd_face_faceline_johnny(
            ctypes.byref(source_descriptor), _u8_pointer(skin),
            _f64_pointer(c1), _f64_pointer(c2), ctypes.byref(output_descriptor),
        )
        self._status(status, "faceline_johnny")
        return output


def _windows_vsdevcmd() -> Path:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if vswhere.is_file():
        result = subprocess.run(
            [
                str(vswhere), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property", "installationPath",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().splitlines()
        if result:
            candidate = Path(result[0]) / "Common7/Tools/VsDevCmd.bat"
            if candidate.is_file():
                return candidate
    for edition in ("Community", "BuildTools", "Professional", "Enterprise"):
        candidate = Path(
            f"C:/Program Files/Microsoft Visual Studio/2022/{edition}/Common7/Tools/VsDevCmd.bat"
        )
        if candidate.is_file():
            return candidate
    raise RuntimeError("Visual Studio x64 C++ tools were not found")


def _run_checked(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            + (result.stdout + result.stderr).strip()
        )
    return result


def _run_windows_command(command: str, *, cwd: Path) -> subprocess.CompletedProcess[str]:
    command_file = cwd / "native_face_runtime_build.cmd"
    command_file.write_text(
        "@echo off\r\n" + command + "\r\n", encoding="utf-8", newline=""
    )
    return _run_checked(
        [os.environ["ComSpec"], "/d", "/c", str(command_file)], cwd=cwd
    )


def _windows_build_dll(output_directory: Path) -> tuple[Path, list[str]]:
    output_directory.mkdir(parents=True)
    output = output_directory / "native_face_runtime.dll"
    obj = output_directory / "native_face_runtime.obj"
    dev = _windows_vsdevcmd()
    command = (
        f'call "{dev}" -no_logo -arch=x64 -host_arch=x64 >nul && '
        f'cl.exe /nologo /LD /O2 /MT /fp:strict /W4 /WX /std:c17 '
        f'/DLTD_FACE_RUNTIME_BUILD_DLL /Fo:"{obj}" /Fe:"{output}" '
        f'"{SOURCE}" /link /Brepro'
    )
    _run_windows_command(command, cwd=output_directory)
    if not output.is_file():
        raise RuntimeError("compiler did not produce the face-runtime DLL")
    inspect = (
        f'call "{dev}" -no_logo -arch=x64 -host_arch=x64 >nul && '
        f'dumpbin.exe /dependents "{output}"'
    )
    dependencies = _run_windows_command(inspect, cwd=output_directory).stdout.splitlines()
    dependencies = [
        line.strip()
        for line in dependencies
        if line.strip().lower().endswith(".dll")
        and not line.strip().lower().startswith("dump of file ")
    ]
    return output, dependencies


def _windows_build_smoke(output_directory: Path) -> Path:
    output = output_directory / "native_face_runtime_smoke.exe"
    dev = _windows_vsdevcmd()
    command = (
        f'call "{dev}" -no_logo -arch=x64 -host_arch=x64 >nul && '
        f'cl.exe /nologo /O2 /MT /fp:strict /W4 /WX /std:c17 '
        f'/Fe:"{output}" "{SOURCE}" "{SMOKE}" /link /Brepro'
    )
    _run_windows_command(command, cwd=output_directory)
    return output


def _portable_build_dll(output_directory: Path) -> tuple[Path, list[str]]:
    output_directory.mkdir(parents=True)
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C compiler is required")
    output = output_directory / "libnative_face_runtime.so"
    _run_checked(
        [
            compiler, "-std=c11", "-shared", "-fPIC", "-O3", "-Wall", "-Wextra",
            "-Werror", "-ffp-contract=off", str(SOURCE), "-lm", "-o", str(output),
        ],
        cwd=output_directory,
    )
    return output, []


def _portable_build_smoke(output_directory: Path) -> Path:
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C compiler is required")
    output = output_directory / "native_face_runtime_smoke"
    _run_checked(
        [
            compiler, "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
            "-ffp-contract=off", str(SOURCE), str(SMOKE), "-lm", "-o", str(output),
        ],
        cwd=output_directory,
    )
    return output


def _build_dll(output_directory: Path) -> tuple[Path, list[str]]:
    if sys.platform == "win32":
        return _windows_build_dll(output_directory)
    return _portable_build_dll(output_directory)


def _build_smoke(output_directory: Path) -> Path:
    if sys.platform == "win32":
        return _windows_build_smoke(output_directory)
    return _portable_build_smoke(output_directory)


def _negative_buffer_tests(adapter: RuntimeAdapter) -> dict[str, bool]:
    backing = np.zeros(32, dtype=np.uint8)
    source = ConstRGBA8(_u8_pointer(backing), backing.nbytes, 4, 1, 1)
    affine = np.ascontiguousarray([1.0, 0.0, 0.5, 0.0, 1.0, 0.5], dtype=np.float64)
    output = RGBA64(
        ctypes.cast(_u8_pointer(backing), F64P), backing.nbytes, 32, 1, 1
    )
    alias_status = adapter.library.ltd_face_mask_sample_affine(
        ctypes.byref(source), _f64_pointer(affine), 0, 0, ctypes.byref(output)
    )
    assert alias_status == BUFFER_ALIAS
    separate = np.zeros(4, dtype=np.float64)
    undersized = RGBA64(_f64_pointer(separate), separate.nbytes - 1, 32, 1, 1)
    small_status = adapter.library.ltd_face_mask_sample_affine(
        ctypes.byref(source), _f64_pointer(affine), 0, 0, ctypes.byref(undersized)
    )
    assert small_status == BUFFER_TOO_SMALL
    nonfinite = affine.copy()
    nonfinite[2] = np.nan
    valid_output = RGBA64(_f64_pointer(separate), separate.nbytes, 32, 1, 1)
    nonfinite_status = adapter.library.ltd_face_mask_sample_affine(
        ctypes.byref(source), _f64_pointer(nonfinite), 0, 0, ctypes.byref(valid_output)
    )
    assert nonfinite_status == NONFINITE

    contiguous_source = np.arange(16, dtype=np.uint8).reshape(2, 2, 4)
    identity = np.ascontiguousarray([1.0, 0.0, 0.0, 0.0, 1.0, 0.0], dtype=np.float64)
    expected = adapter.mask_sample_affine(
        contiguous_source, 2, 2, *identity, 0, 0
    )
    padded_source = np.zeros(24, dtype=np.uint8)
    padded_source[0:8] = contiguous_source[0].reshape(-1)
    padded_source[12:20] = contiguous_source[1].reshape(-1)
    padded_output = np.zeros(20, dtype=np.float64)
    padded_source_descriptor = ConstRGBA8(
        _u8_pointer(padded_source), padded_source.nbytes, 12, 2, 2
    )
    padded_output_descriptor = RGBA64(
        _f64_pointer(padded_output), padded_output.nbytes, 80, 2, 2
    )
    padded_status = adapter.library.ltd_face_mask_sample_affine(
        ctypes.byref(padded_source_descriptor), _f64_pointer(identity), 0, 0,
        ctypes.byref(padded_output_descriptor),
    )
    assert padded_status == OK
    actual = np.empty((2, 2, 4), dtype=np.float64)
    actual[0] = padded_output[:8].reshape(2, 4)
    actual[1] = padded_output[10:18].reshape(2, 4)
    assert actual.tobytes() == expected.tobytes()
    return {
        "abi_mismatch_rejected": True,
        "contract_mismatch_rejected": True,
        "buffer_alias_rejected": True,
        "undersized_buffer_rejected": True,
        "nonfinite_affine_rejected": True,
        "padded_row_strides_exact": True,
    }


def _worker(library: Path, asset_root: Path, samples: int, skip_full_render: bool) -> int:
    for entry in (str(ROOT), str(ROOT / "renderer"), str(ROOT / "tools")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    import native_face_target as native
    import verify_native_face_target as oracle_verify

    adapter = RuntimeAdapter(library)
    negatives = _negative_buffer_tests(adapter)
    native._compiled = adapter
    native.BACKEND_AVAILABLE = True
    native.IMPORT_ERROR = None
    arguments = [
        str(ROOT / "tools" / "verify_native_face_target.py"),
        "--asset-root", str(asset_root), "--samples", str(samples),
    ]
    if skip_full_render:
        arguments.append("--skip-full-render")
    previous_argv = sys.argv
    captured = io.StringIO()
    try:
        sys.argv = arguments
        with contextlib.redirect_stdout(captured):
            return_code = oracle_verify.main()
    finally:
        sys.argv = previous_argv
    if return_code != 0:
        raise RuntimeError(f"oracle verifier returned {return_code}")
    oracle_result = json.loads(captured.getvalue())
    result = {
        "schema_version": 1,
        "kind": "standalone-native-face-runtime-worker",
        "identity": {
            "abi_version": ABI_VERSION,
            "contract_sha256": CONTRACT_SHA256,
            "oracle_source_sha256": ORACLE_SHA256,
        },
        "fail_closed_negative_tests": negatives,
        "fixture_parity": oracle_result,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--asset-root", type=Path, default=ROOT.parent / "ltdDemo_converted_assets"
    )
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--skip-full-render", action="store_true")
    parser.add_argument("--worker-library", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    if CONTRACT_SHA256 != "5b856b6ab60fcfc3a37a03d8153c1a11217bc23ed39803e0a350bb02fd163c3c":
        raise AssertionError("canonical contract fingerprint changed")
    if ORACLE_SHA256 != "d14b5e39d37e9ebcb315924b863c6ca65d3be075fc7edc067d1fecd49181a62a":
        raise AssertionError("oracle kernel source changed; re-audit the extraction")
    if args.worker_library is not None:
        return _worker(
            args.worker_library.resolve(), args.asset_root.resolve(),
            args.samples, args.skip_full_render,
        )

    with tempfile.TemporaryDirectory(prefix="ltd-native-face-runtime-") as directory:
        temporary = Path(directory)
        first, dependencies = _build_dll(temporary / "build-a")
        second, second_dependencies = _build_dll(temporary / "build-b")
        first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
        second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
        if first_hash != second_hash:
            raise AssertionError(
                f"native face runtime build is not reproducible: {first_hash} != {second_hash}"
            )
        if dependencies != second_dependencies:
            raise AssertionError("repeated builds reported different dependencies")
        forbidden = [name for name in dependencies if "python" in name.lower() or "numpy" in name.lower()]
        if forbidden:
            raise AssertionError(f"standalone library imports host runtimes: {forbidden}")
        smoke = _build_smoke(temporary / "build-a")
        _run_checked([str(smoke)], cwd=smoke.parent)
        worker_command = [
            sys.executable, str(Path(__file__).resolve()),
            "--worker-library", str(first),
            "--asset-root", str(args.asset_root.resolve()),
            "--samples", str(args.samples),
        ]
        if args.skip_full_render:
            worker_command.append("--skip-full-render")
        worker = _run_checked(worker_command, cwd=ROOT)
        worker_result = json.loads(worker.stdout)
        result = {
            "schema_version": 1,
            "kind": "standalone-native-face-runtime-verification",
            "claim": "CPython-free buffer API reproduces exact current accepted face targets",
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "header": str(HEADER.relative_to(ROOT)),
            "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(),
            "abi_version": ABI_VERSION,
            "contract_sha256": CONTRACT_SHA256,
            "oracle_source_sha256": ORACLE_SHA256,
            "reproducible_build": {
                "byte_identical": True,
                "library_sha256": first_hash,
                "dependencies": dependencies,
                "forbidden_host_dependencies": [],
            },
            "standalone_static_link_smoke": True,
            "temporary_build_products_removed_on_exit": True,
            "worker": worker_result,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
