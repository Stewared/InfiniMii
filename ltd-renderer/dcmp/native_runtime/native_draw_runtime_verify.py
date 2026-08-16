#!/usr/bin/env python3
"""Reproducibly build and A/B the CPython-free current-draw runtime subset."""

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
from typing import Any, Callable

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "native_runtime"
SOURCE = RUNTIME / "native_draw_runtime.c"
HEADER = RUNTIME / "native_draw_runtime.h"
SMOKE = RUNTIME / "native_draw_runtime_smoke.c"
CURRENT_SOURCE = ROOT / "renderer" / "native_current_draw_kernel.c"
OPAQUE_SOURCE = ROOT / "renderer" / "native_current_opaque_kernel.c"
ABI_VERSION = 1
CONTRACT_SHA256 = "64db57c14e2ccf01eff2f24fa158caf7ef7635877f75645a3fa109c792cce283"
CURRENT_SHA256 = "14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d"
OPAQUE_SHA256 = "f03b17eac2eb4c16293ae9ddbc40710fb9f3507ad880060e131959b54daadf0c"
PRODUCTION_INPUTS = ("mii0.ltd", "mii1.ltd", "mii2.ltd", "mii4.ltd")

OK = 0
BUFFER_TOO_SMALL = 2
NONFINITE = 3
ABI_MISMATCH = 6
CONTRACT_MISMATCH = 7
BUFFER_ALIAS = 8


class ConstF64(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_double)), ("element_count", ctypes.c_size_t)]


class ConstI64(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_int64)), ("element_count", ctypes.c_size_t)]


class Attachments(ctypes.Structure):
    _fields_ = [
        ("color", ctypes.POINTER(ctypes.c_double)),
        ("color_capacity_bytes", ctypes.c_size_t),
        ("color_row_stride_bytes", ctypes.c_size_t),
        ("depth", ctypes.POINTER(ctypes.c_double)),
        ("depth_capacity_bytes", ctypes.c_size_t),
        ("depth_row_stride_bytes", ctypes.c_size_t),
        ("alpha", ctypes.POINTER(ctypes.c_double)),
        ("alpha_capacity_bytes", ctypes.c_size_t),
        ("alpha_row_stride_bytes", ctypes.c_size_t),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
    ]


class TriangleBatch(ctypes.Structure):
    _fields_ = [
        ("screen", ConstF64),
        ("bounds", ConstI64),
        ("denominators", ConstF64),
        ("triangle_count", ctypes.c_uint32),
    ]


class MipBank(ctypes.Structure):
    _fields_ = [
        ("texels", ctypes.POINTER(ctypes.c_double)),
        ("texel_count", ctypes.c_size_t),
        ("levels", ctypes.POINTER(ctypes.c_int64)),
        ("level_count", ctypes.c_uint32),
    ]


class Texture2D(ctypes.Structure):
    _fields_ = [
        ("texels", ctypes.POINTER(ctypes.c_double)),
        ("texel_count", ctypes.c_size_t),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
    ]


F64x3 = ctypes.c_double * 3
F64x10 = ctypes.c_double * 10


class PlainInput(ctypes.Structure):
    _fields_ = [
        ("triangles", TriangleBatch),
        ("vertex_normals", ConstF64),
        ("base_color_linear", F64x3),
        ("light_direction", F64x3),
        ("light_color", F64x3),
        ("ambient_color", F64x3),
        ("light_intensity", ctypes.c_double),
        ("ambient_intensity", ctypes.c_double),
        ("perspective_correct", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


class BodyInput(ctypes.Structure):
    _fields_ = [
        ("triangles", TriangleBatch),
        ("world_vertices", ConstF64),
        ("vertex_normals", ConstF64),
        ("material_uv", ConstF64),
        ("albedo", MipBank),
        ("albedo_lower_indices", ConstI64),
        ("albedo_upper_indices", ConstI64),
        ("albedo_mip_amounts", ConstF64),
        ("skin", MipBank),
        ("skin_lower_indices", ConstI64),
        ("skin_upper_indices", ConstI64),
        ("skin_mip_amounts", ConstF64),
        ("normal", MipBank),
        ("normal_level_indices", ConstI64),
        ("face_color_linear", F64x3),
        ("light_direction", F64x3),
        ("light_color", F64x3),
        ("ambient_color", F64x3),
        ("light_intensity", ctypes.c_double),
        ("ambient_intensity", ctypes.c_double),
        ("perspective_correct", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


class MaskInput(ctypes.Structure):
    _fields_ = [
        ("triangles", TriangleBatch),
        ("vertex_normals", ConstF64),
        ("material_uv", ConstF64),
        ("generated_texture", Texture2D),
        ("user_texture", Texture2D),
        ("light_direction", F64x3),
        ("light_color", F64x3),
        ("ambient_color", F64x3),
        ("parameters", F64x10),
    ]


F64P = ctypes.POINTER(ctypes.c_double)
I64P = ctypes.POINTER(ctypes.c_int64)


def _f64p(array: np.ndarray) -> F64P:
    return array.ctypes.data_as(F64P)


def _i64p(array: np.ndarray) -> I64P:
    return array.ctypes.data_as(I64P)


def _f64(array: np.ndarray) -> ConstF64:
    if array.dtype != np.float64 or not array.flags.c_contiguous:
        raise TypeError("expected contiguous float64 input")
    return ConstF64(_f64p(array), array.size)


def _i64(array: np.ndarray) -> ConstI64:
    if array.dtype != np.int64 or not array.flags.c_contiguous:
        raise TypeError("expected contiguous int64 input")
    return ConstI64(_i64p(array), array.size)


def _vec3(array: np.ndarray) -> F64x3:
    return F64x3(*(float(value) for value in array))


def _attachments(color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None) -> Attachments:
    alpha_pointer = F64P() if alpha is None else _f64p(alpha)
    return Attachments(
        _f64p(color), color.nbytes, color.strides[0],
        _f64p(depth), depth.nbytes, depth.strides[0],
        alpha_pointer, 0 if alpha is None else alpha.nbytes,
        0 if alpha is None else alpha.strides[0],
        color.shape[1], color.shape[0],
    )


def _triangles(screen: np.ndarray, bounds: np.ndarray, denominators: np.ndarray) -> TriangleBatch:
    return TriangleBatch(_f64(screen), _i64(bounds), _f64(denominators), screen.shape[0])


def _mip_bank(texels: np.ndarray, levels: np.ndarray) -> MipBank:
    return MipBank(_f64p(texels), texels.shape[0], _i64p(levels), levels.shape[0])


def _texture(texture: np.ndarray) -> Texture2D:
    return Texture2D(_f64p(texture), texture.shape[0] * texture.shape[1], texture.shape[1], texture.shape[0])


class Adapter:
    def __init__(self, library_path: Path, body_oracle: Callable[..., Any], plain_oracle: Callable[..., Any], mask_oracle: Callable[..., Any]) -> None:
        self.library = ctypes.CDLL(str(library_path))
        self.body_oracle = body_oracle
        self.plain_oracle = plain_oracle
        self.mask_oracle = mask_oracle
        self.calls = {"Body324_336_348": 0, "Ear372_Nose756": 0, "Mask0": 0}
        self._bind()
        self._identity()

    def _bind(self) -> None:
        lib = self.library
        lib.ltd_draw_runtime_abi_version.argtypes = []
        lib.ltd_draw_runtime_abi_version.restype = ctypes.c_uint32
        for name in ("contract_sha256", "current_source_sha256", "opaque_source_sha256"):
            function = getattr(lib, "ltd_draw_runtime_" + name)
            function.argtypes = []
            function.restype = ctypes.c_char_p
        lib.ltd_draw_runtime_require.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        lib.ltd_draw_runtime_require.restype = ctypes.c_int
        lib.ltd_draw_runtime_status_name.argtypes = [ctypes.c_int]
        lib.ltd_draw_runtime_status_name.restype = ctypes.c_char_p
        lib.ltd_draw_plain_skin.argtypes = [ctypes.POINTER(Attachments), ctypes.POINTER(PlainInput), ctypes.POINTER(ctypes.c_uint64)]
        lib.ltd_draw_plain_skin.restype = ctypes.c_int
        lib.ltd_draw_body.argtypes = [ctypes.POINTER(Attachments), ctypes.POINTER(BodyInput), ctypes.POINTER(ctypes.c_uint64)]
        lib.ltd_draw_body.restype = ctypes.c_int
        lib.ltd_draw_mask0.argtypes = [ctypes.POINTER(Attachments), ctypes.POINTER(MaskInput), ctypes.POINTER(ctypes.c_uint64)]
        lib.ltd_draw_mask0.restype = ctypes.c_int

    def _identity(self) -> None:
        lib = self.library
        assert lib.ltd_draw_runtime_abi_version() == ABI_VERSION
        assert lib.ltd_draw_runtime_contract_sha256().decode() == CONTRACT_SHA256
        assert lib.ltd_draw_runtime_current_source_sha256().decode() == CURRENT_SHA256
        assert lib.ltd_draw_runtime_opaque_source_sha256().decode() == OPAQUE_SHA256
        assert lib.ltd_draw_runtime_require(ABI_VERSION, CONTRACT_SHA256.encode()) == OK
        assert lib.ltd_draw_runtime_require(ABI_VERSION + 1, CONTRACT_SHA256.encode()) == ABI_MISMATCH
        assert lib.ltd_draw_runtime_require(ABI_VERSION, b"0" * 64) == CONTRACT_MISMATCH

    def _status(self, status: int, operation: str) -> None:
        if status != OK:
            name = self.library.ltd_draw_runtime_status_name(status).decode()
            raise ValueError(f"{operation} failed: {name} ({status})")

    @staticmethod
    def _snapshots(color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None) -> tuple[list[np.ndarray | None], list[np.ndarray | None]]:
        return ([color.copy(), depth.copy(), None if alpha is None else alpha.copy()],
                [color.copy(), depth.copy(), None if alpha is None else alpha.copy()])

    @staticmethod
    def _compare_and_commit(original: tuple[np.ndarray, np.ndarray, np.ndarray | None], oracle: list[np.ndarray | None], native: list[np.ndarray | None], oracle_count: int, native_count: int, operation: str) -> int:
        if oracle_count != native_count:
            raise AssertionError(f"{operation} written count changed: {oracle_count} != {native_count}")
        for label, expected, actual in zip(("color", "depth", "alpha"), oracle, native):
            if expected is None or actual is None:
                if expected is not actual:
                    raise AssertionError(f"{operation} {label} optionality changed")
            elif expected.tobytes() != actual.tobytes():
                raise AssertionError(f"{operation} {label} bytes changed")
        np.copyto(original[0], native[0])
        np.copyto(original[1], native[1])
        if original[2] is not None:
            np.copyto(original[2], native[2])
        return native_count

    def draw_plain_skin(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, screen: np.ndarray, bounds: np.ndarray, denominators: np.ndarray, normals: np.ndarray, base: np.ndarray, direction: np.ndarray, light: np.ndarray, ambient: np.ndarray, light_intensity: float, ambient_intensity: float, perspective: int) -> int:
        oracle, native = self._snapshots(color, depth, alpha)
        oracle_count = int(self.plain_oracle(*oracle, screen, bounds, denominators, normals, base, direction, light, ambient, light_intensity, ambient_intensity, perspective))
        descriptor = _attachments(native[0], native[1], native[2])
        payload = PlainInput(_triangles(screen, bounds, denominators), _f64(normals), _vec3(base), _vec3(direction), _vec3(light), _vec3(ambient), light_intensity, ambient_intensity, perspective, 0)
        written = ctypes.c_uint64()
        self._status(self.library.ltd_draw_plain_skin(ctypes.byref(descriptor), ctypes.byref(payload), ctypes.byref(written)), "plain_skin")
        self.calls["Ear372_Nose756"] += 1
        return self._compare_and_commit((color, depth, alpha), oracle, native, oracle_count, written.value, "plain_skin")

    def draw_body(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, screen: np.ndarray, bounds: np.ndarray, denominators: np.ndarray, vertices: np.ndarray, normals: np.ndarray, uv: np.ndarray, albedo_texels: np.ndarray, albedo_levels: np.ndarray, albedo_lower: np.ndarray, albedo_upper: np.ndarray, albedo_amount: np.ndarray, skin_texels: np.ndarray, skin_levels: np.ndarray, skin_lower: np.ndarray, skin_upper: np.ndarray, skin_amount: np.ndarray, normal_texels: np.ndarray, normal_levels: np.ndarray, normal_indices: np.ndarray, face: np.ndarray, direction: np.ndarray, light: np.ndarray, ambient: np.ndarray, light_intensity: float, ambient_intensity: float, perspective: int) -> int:
        arguments = (screen, bounds, denominators, vertices, normals, uv, albedo_texels, albedo_levels, albedo_lower, albedo_upper, albedo_amount, skin_texels, skin_levels, skin_lower, skin_upper, skin_amount, normal_texels, normal_levels, normal_indices, face, direction, light, ambient, light_intensity, ambient_intensity, perspective)
        oracle, native = self._snapshots(color, depth, alpha)
        oracle_count = int(self.body_oracle(*oracle, *arguments))
        descriptor = _attachments(native[0], native[1], native[2])
        payload = BodyInput(
            _triangles(screen, bounds, denominators), _f64(vertices), _f64(normals), _f64(uv),
            _mip_bank(albedo_texels, albedo_levels), _i64(albedo_lower), _i64(albedo_upper), _f64(albedo_amount),
            _mip_bank(skin_texels, skin_levels), _i64(skin_lower), _i64(skin_upper), _f64(skin_amount),
            _mip_bank(normal_texels, normal_levels), _i64(normal_indices),
            _vec3(face), _vec3(direction), _vec3(light), _vec3(ambient),
            light_intensity, ambient_intensity, perspective, 0,
        )
        written = ctypes.c_uint64()
        self._status(self.library.ltd_draw_body(ctypes.byref(descriptor), ctypes.byref(payload), ctypes.byref(written)), "body")
        self.calls["Body324_336_348"] += 1
        return self._compare_and_commit((color, depth, alpha), oracle, native, oracle_count, written.value, "body")

    def draw_mask0(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, screen: np.ndarray, bounds: np.ndarray, denominators: np.ndarray, vertices: np.ndarray, normals: np.ndarray, uv: np.ndarray, generated: np.ndarray, user: np.ndarray, direction: np.ndarray, light: np.ndarray, ambient: np.ndarray, parameters: np.ndarray) -> int:
        arguments = (screen, bounds, denominators, vertices, normals, uv, generated, user, direction, light, ambient, parameters)
        oracle, native = self._snapshots(color, depth, alpha)
        oracle_count = int(self.mask_oracle(*oracle, *arguments))
        descriptor = _attachments(native[0], native[1], native[2])
        payload = MaskInput(
            _triangles(screen, bounds, denominators), _f64(normals), _f64(uv),
            _texture(generated), _texture(user), _vec3(direction), _vec3(light), _vec3(ambient),
            F64x10(*(float(value) for value in parameters)),
        )
        written = ctypes.c_uint64()
        self._status(self.library.ltd_draw_mask0(ctypes.byref(descriptor), ctypes.byref(payload), ctypes.byref(written)), "mask0")
        self.calls["Mask0"] += 1
        return self._compare_and_commit((color, depth, alpha), oracle, native, oracle_count, written.value, "mask0")


def _vsdevcmd() -> Path:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    result = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], check=True, capture_output=True, text=True).stdout.strip().splitlines()
    if not result:
        raise RuntimeError("Visual Studio x64 toolchain not found")
    path = Path(result[0]) / "Common7/Tools/VsDevCmd.bat"
    if not path.is_file():
        raise RuntimeError("VsDevCmd.bat not found")
    return path


def _checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n" + (result.stdout + result.stderr).strip())
    return result


def _windows_command(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    script = cwd / "native_draw_runtime_build.cmd"
    script.write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8", newline="")
    return _checked([os.environ["ComSpec"], "/d", "/c", str(script)], cwd)


def _build_library(directory: Path) -> tuple[Path, list[str]]:
    directory.mkdir(parents=True)
    if sys.platform == "win32":
        output = directory / "native_draw_runtime.dll"
        command = f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /LD /O2 /MT /fp:strict /W4 /WX /std:c17 /DLTD_DRAW_RUNTIME_BUILD_DLL /Fo:"{directory / "runtime.obj"}" /Fe:"{output}" "{SOURCE}" /link /Brepro'
        _windows_command(command, directory)
        inspect = f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && dumpbin.exe /dependents "{output}"'
        lines = _windows_command(inspect, directory).stdout.splitlines()
        dependencies = [line.strip() for line in lines if line.strip().lower().endswith(".dll") and not line.strip().lower().startswith("dump of file ")]
        return output, dependencies
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("C compiler not found")
    output = directory / "libnative_draw_runtime.so"
    _checked([compiler, "-std=c11", "-shared", "-fPIC", "-O3", "-Wall", "-Wextra", "-Werror", "-ffp-contract=off", str(SOURCE), "-lm", "-o", str(output)], directory)
    return output, []


def _build_smoke(directory: Path) -> Path:
    if sys.platform == "win32":
        output = directory / "native_draw_runtime_smoke.exe"
        command = f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /O2 /MT /fp:strict /W4 /WX /std:c17 /Fe:"{output}" "{SOURCE}" "{SMOKE}" /link /Brepro'
        _windows_command(command, directory)
        return output
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("C compiler not found")
    output = directory / "native_draw_runtime_smoke"
    _checked([compiler, "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", "-ffp-contract=off", str(SOURCE), str(SMOKE), "-lm", "-o", str(output)], directory)
    return output


def _render(render_mii: Any, input_name: str, asset_root: Path, output: Path, size: int, view: str) -> bytes:
    sys.argv = [str(ROOT / "renderer" / "render_mii.py"), str(ROOT / input_name), "--asset-root", str(asset_root), "--output-dir", str(output), "--size", str(size), "--view", view, "--supersample-factor", "1", "--build-active-parts", str(output.parent / (output.name + "-active.json"))]
    with contextlib.redirect_stdout(io.StringIO()):
        if render_mii.main() != 0:
            raise RuntimeError("render_mii returned failure")
    name = "mii.png" if view == "portrait" else "mii_full_body.png"
    return (output / name).read_bytes()


def _negative_tests(adapter: Adapter) -> dict[str, bool]:
    color = np.zeros((1, 1, 3), dtype=np.float64)
    depth = np.zeros((1, 1), dtype=np.float64)
    descriptor = _attachments(color, depth, None)
    descriptor.depth = descriptor.color
    descriptor.depth_capacity_bytes = color.nbytes
    descriptor.depth_row_stride_bytes = color.strides[0]
    empty = PlainInput()
    empty.base_color_linear[:] = (1.0, 1.0, 1.0)
    empty.light_direction[:] = (0.0, 0.0, 1.0)
    empty.light_color[:] = (1.0, 1.0, 1.0)
    empty.ambient_color[:] = (1.0, 1.0, 1.0)
    empty.light_intensity = 1.0
    empty.ambient_intensity = 1.0
    empty.perspective_correct = 1
    written = ctypes.c_uint64()
    assert adapter.library.ltd_draw_plain_skin(ctypes.byref(descriptor), ctypes.byref(empty), ctypes.byref(written)) == BUFFER_ALIAS
    descriptor = _attachments(color, depth, None)
    descriptor.color_capacity_bytes -= 1
    assert adapter.library.ltd_draw_plain_skin(ctypes.byref(descriptor), ctypes.byref(empty), ctypes.byref(written)) == BUFFER_TOO_SMALL
    descriptor = _attachments(color, depth, None)
    empty.light_direction[0] = np.nan
    assert adapter.library.ltd_draw_plain_skin(ctypes.byref(descriptor), ctypes.byref(empty), ctypes.byref(written)) == NONFINITE
    return {"abi_mismatch_rejected": True, "contract_mismatch_rejected": True, "attachment_alias_rejected": True, "undersized_attachment_rejected": True, "nonfinite_vector_rejected": True}


def _worker(library: Path, asset_root: Path, samples: int) -> int:
    for entry in (str(ROOT), str(ROOT / "renderer")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    import native_current_draw
    import render_mii

    originals = (native_current_draw._draw_body_compiled, native_current_draw._draw_plain_skin_compiled, native_current_draw._draw_mask0_compiled)
    if any(function is None for function in originals):
        raise RuntimeError("current-draw oracle extension is unavailable")
    adapter = Adapter(library, *originals)
    negatives = _negative_tests(adapter)
    cases = []
    with tempfile.TemporaryDirectory(prefix="ltd-native-draw-runtime-fixtures-") as directory:
        temporary = Path(directory)
        case_index = 0
        for input_name in PRODUCTION_INPUTS:
            for size in (128, 512):
                for view in ("portrait", "full-body"):
                    baseline = _render(render_mii, input_name, asset_root, temporary / f"{case_index}-baseline", size, view)
                    native_current_draw._draw_body_compiled = adapter.draw_body
                    native_current_draw._draw_plain_skin_compiled = adapter.draw_plain_skin
                    native_current_draw._draw_mask0_compiled = adapter.draw_mask0
                    try:
                        accelerated = _render(render_mii, input_name, asset_root, temporary / f"{case_index}-native", size, view)
                    finally:
                        native_current_draw._draw_body_compiled, native_current_draw._draw_plain_skin_compiled, native_current_draw._draw_mask0_compiled = originals
                    if baseline != accelerated:
                        raise AssertionError(f"final PNG changed for {input_name} {view} {size}")
                    cases.append({"input": input_name, "size": size, "view": view, "byte_exact": True, "png_sha256": hashlib.sha256(accelerated).hexdigest(), "png_byte_length": len(accelerated)})
                    case_index += 1
    print(json.dumps({"schema_version": 1, "kind": "standalone-native-draw-runtime-worker", "direct_per_draw_oracle_comparison": True, "fail_closed_negative_tests": negatives, "activation_counts": adapter.calls, "final_cases": cases, "byte_exact_all_cases": True}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-root", type=Path, default=ROOT.parent / "ltdDemo_converted_assets")
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--worker-library", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.samples != 1:
        parser.error("this exact fixture verifier currently accepts --samples 1")
    if hashlib.sha256(CURRENT_SOURCE.read_bytes()).hexdigest() != CURRENT_SHA256 or hashlib.sha256(OPAQUE_SOURCE.read_bytes()).hexdigest() != OPAQUE_SHA256:
        raise AssertionError("current-draw extraction oracle changed; re-audit required")
    if args.worker_library is not None:
        return _worker(args.worker_library.resolve(), args.asset_root.resolve(), args.samples)
    with tempfile.TemporaryDirectory(prefix="ltd-native-draw-runtime-") as directory:
        temporary = Path(directory)
        first, dependencies = _build_library(temporary / "first")
        second, second_dependencies = _build_library(temporary / "second")
        first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
        if first_hash != hashlib.sha256(second.read_bytes()).hexdigest():
            raise AssertionError("draw-runtime builds are not byte reproducible")
        if dependencies != second_dependencies:
            raise AssertionError("draw-runtime dependencies changed between builds")
        if any("python" in name.lower() or "numpy" in name.lower() for name in dependencies):
            raise AssertionError("draw runtime imports a forbidden host runtime")
        smoke = _build_smoke(temporary / "first")
        _checked([str(smoke)], smoke.parent)
        worker = _checked([sys.executable, str(Path(__file__).resolve()), "--worker-library", str(first), "--asset-root", str(args.asset_root.resolve()), "--samples", "1"], ROOT)
        payload = json.loads(worker.stdout)
        print(json.dumps({"schema_version": 1, "kind": "standalone-native-draw-runtime-verification", "claim": "pure C Body/Ear/Nose/Mask subset reproduces exact current accepted draws", "abi_version": ABI_VERSION, "contract_sha256": CONTRACT_SHA256, "source": str(SOURCE.relative_to(ROOT)), "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(), "header": str(HEADER.relative_to(ROOT)), "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(), "oracle_sources": {"native_current_draw_kernel.c": CURRENT_SHA256, "native_current_opaque_kernel.c": OPAQUE_SHA256}, "reproducible_build": {"byte_identical": True, "library_sha256": first_hash, "dependencies": dependencies, "forbidden_host_dependencies": []}, "standalone_static_link_smoke": True, "temporary_products_removed_on_exit": True, "worker": payload, "remaining_profiles": ["Head816", "Hair612", "Hair564EqualEndpoint", "Beard468", "OutfitTops984", "OutfitBottoms936", "OutfitShoes912"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
