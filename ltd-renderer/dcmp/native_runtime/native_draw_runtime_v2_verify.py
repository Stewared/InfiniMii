#!/usr/bin/env python3
"""Build and byte-exact A/B the CPython-free current-draw ABI-2 slice."""

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
SOURCE = RUNTIME / "native_draw_runtime_v2.c"
HEADER = RUNTIME / "native_draw_runtime_v2.h"
BASE_SOURCE = RUNTIME / "native_draw_runtime.c"
BASE_HEADER = RUNTIME / "native_draw_runtime.h"
SMOKE = RUNTIME / "native_draw_runtime_v2_smoke.c"
CURRENT_SOURCE = ROOT / "renderer" / "native_current_draw_kernel.c"
OPAQUE_SOURCE = ROOT / "renderer" / "native_current_opaque_kernel.c"
WRAPPER_SOURCE = ROOT / "renderer" / "native_current_draw.py"
ABI_VERSION = 2
CONTRACT_SHA256 = "6f136e1133dbce3396157a53907fa0167743443c798a40d57fa40cff9192e5f2"
WRAPPER_SHA256 = "405365df31ca29e5938acb63ec59a53b30c7130c4fbc6e1d97d83bfc910ae7d4"
CURRENT_SHA256 = "14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d"
OPAQUE_SHA256 = "f03b17eac2eb4c16293ae9ddbc40710fb9f3507ad880060e131959b54daadf0c"
BASE_SOURCE_SHA256 = "d6329c77634f62b10e16ba244556bf8487593b35eb058f2b89c463c0fe78e6b0"
BASE_HEADER_SHA256 = "ee253593218ff9a5f38420dd5c0a607c91c79bd95a091385c438626c97cf4b6c"
PRODUCTION_INPUTS = ("mii0.ltd", "mii1.ltd", "mii2.ltd", "mii4.ltd")

OK = 0
INVALID_ARGUMENT = 1
VALUE_OUT_OF_RANGE = 4
ABI_MISMATCH = 6
CONTRACT_MISMATCH = 7
HAIR612 = 612
HAIR564 = 564
BEARD468 = 468
OUTFIT984 = 984
OUTFIT936 = 936
OUTFIT912 = 912


class ConstF64(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_double)), ("element_count", ctypes.c_size_t)]


class ConstI64(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_int64)), ("element_count", ctypes.c_size_t)]


class ConstU8(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("element_count", ctypes.c_size_t)]


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
F64x33 = ctypes.c_double * 33


class HeadInput(ctypes.Structure):
    _fields_ = [
        ("triangles", TriangleBatch),
        ("world_vertices", ConstF64),
        ("vertex_normals", ConstF64),
        ("vertex_normal_valid", ConstU8),
        ("albedo_uv", ConstF64),
        ("normal_uv", ConstF64),
        ("albedo_texture", Texture2D),
        ("normal", MipBank),
        ("normal_level_indices", ConstI64),
        ("base_color_linear", F64x3),
        ("light_direction", F64x3),
        ("light_color", F64x3),
        ("ambient_color", F64x3),
        ("light_intensity", ctypes.c_double),
        ("ambient_intensity", ctypes.c_double),
        ("alpha_scalar", ctypes.c_double),
        ("alpha_cutoff", ctypes.c_double),
        ("perspective_correct", ctypes.c_int32),
        ("has_albedo", ctypes.c_int32),
    ]


class HairInput(ctypes.Structure):
    _fields_ = [
        ("triangles", TriangleBatch),
        ("world_vertices", ConstF64),
        ("vertex_normals", ConstF64),
        ("material_uv", ConstF64),
        ("mim", MipBank),
        ("mim_level_indices", ConstI64),
        ("parameters", F64x33),
        ("profile", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


class OutfitInput(ctypes.Structure):
    _fields_ = [
        ("triangles", TriangleBatch),
        ("world_vertices", ConstF64),
        ("vertex_normals", ConstF64),
        ("material_uv", ConstF64),
        ("albedo", MipBank),
        ("albedo_lower_indices", ConstI64),
        ("albedo_upper_indices", ConstI64),
        ("albedo_mip_amounts", ConstF64),
        ("normal", MipBank),
        ("normal_level_indices", ConstI64),
        ("light_direction", F64x3),
        ("light_color", F64x3),
        ("ambient_color", F64x3),
        ("light_intensity", ctypes.c_double),
        ("ambient_intensity", ctypes.c_double),
        ("perspective_correct", ctypes.c_int32),
        ("profile", ctypes.c_int32),
    ]


F64P = ctypes.POINTER(ctypes.c_double)
I64P = ctypes.POINTER(ctypes.c_int64)
U8P = ctypes.POINTER(ctypes.c_uint8)


def _f64p(array: np.ndarray) -> F64P:
    return array.ctypes.data_as(F64P)


def _i64p(array: np.ndarray) -> I64P:
    return array.ctypes.data_as(I64P)


def _u8p(array: np.ndarray) -> U8P:
    return array.ctypes.data_as(U8P)


def _f64(array: np.ndarray) -> ConstF64:
    if array.dtype != np.float64 or not array.flags.c_contiguous:
        raise TypeError("expected contiguous float64 input")
    return ConstF64(_f64p(array), array.size)


def _i64(array: np.ndarray) -> ConstI64:
    if array.dtype != np.int64 or not array.flags.c_contiguous:
        raise TypeError("expected contiguous int64 input")
    return ConstI64(_i64p(array), array.size)


def _u8(array: np.ndarray) -> ConstU8:
    if array.dtype != np.uint8 or not array.flags.c_contiguous:
        raise TypeError("expected contiguous uint8 input")
    return ConstU8(_u8p(array), array.size)


def _vec3(array: np.ndarray) -> F64x3:
    return F64x3(*(float(value) for value in array))


def _attachments(color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None) -> Attachments:
    return Attachments(
        _f64p(color), color.nbytes, color.strides[0],
        _f64p(depth), depth.nbytes, depth.strides[0],
        F64P() if alpha is None else _f64p(alpha),
        0 if alpha is None else alpha.nbytes,
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
    def __init__(self, library_path: Path, oracles: dict[str, Callable[..., Any]]) -> None:
        self.library = ctypes.CDLL(str(library_path))
        self.oracles = oracles
        self.calls = {name: 0 for name in oracles}
        self._bind()
        self._identity()

    def _bind(self) -> None:
        lib = self.library
        lib.ltd_draw_runtime_v2_abi_version.argtypes = []
        lib.ltd_draw_runtime_v2_abi_version.restype = ctypes.c_uint32
        for name in ("contract_sha256", "wrapper_sha256"):
            function = getattr(lib, f"ltd_draw_runtime_v2_{name}")
            function.argtypes = []
            function.restype = ctypes.c_char_p
        lib.ltd_draw_runtime_v2_require.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        lib.ltd_draw_runtime_v2_require.restype = ctypes.c_int
        lib.ltd_draw_head816.argtypes = [ctypes.POINTER(Attachments), ctypes.POINTER(HeadInput), ctypes.POINTER(ctypes.c_uint64)]
        lib.ltd_draw_head816.restype = ctypes.c_int
        lib.ltd_draw_hair.argtypes = [ctypes.POINTER(Attachments), ctypes.POINTER(HairInput), ctypes.POINTER(ctypes.c_uint64)]
        lib.ltd_draw_hair.restype = ctypes.c_int
        lib.ltd_draw_outfit.argtypes = [ctypes.POINTER(Attachments), ctypes.POINTER(OutfitInput), ctypes.POINTER(ctypes.c_uint64)]
        lib.ltd_draw_outfit.restype = ctypes.c_int

    def _identity(self) -> None:
        lib = self.library
        assert lib.ltd_draw_runtime_v2_abi_version() == ABI_VERSION
        assert lib.ltd_draw_runtime_v2_contract_sha256().decode("ascii") == CONTRACT_SHA256
        assert lib.ltd_draw_runtime_v2_wrapper_sha256().decode("ascii") == WRAPPER_SHA256
        assert lib.ltd_draw_runtime_v2_require(ABI_VERSION, CONTRACT_SHA256.encode("ascii")) == OK
        assert lib.ltd_draw_runtime_v2_require(ABI_VERSION + 1, CONTRACT_SHA256.encode("ascii")) == ABI_MISMATCH
        assert lib.ltd_draw_runtime_v2_require(ABI_VERSION, b"0" * 64) == CONTRACT_MISMATCH

    @staticmethod
    def _snapshots(color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None) -> tuple[tuple[np.ndarray, np.ndarray, np.ndarray | None], tuple[np.ndarray, np.ndarray, np.ndarray | None]]:
        return (
            (color.copy(), depth.copy(), None if alpha is None else alpha.copy()),
            (color.copy(), depth.copy(), None if alpha is None else alpha.copy()),
        )

    @staticmethod
    def _compare_and_commit(
        targets: tuple[np.ndarray, np.ndarray, np.ndarray | None],
        oracle: tuple[np.ndarray, np.ndarray, np.ndarray | None],
        native: tuple[np.ndarray, np.ndarray, np.ndarray | None],
        oracle_count: int,
        native_count: int,
        label: str,
    ) -> int:
        if oracle_count != native_count:
            raise AssertionError(f"{label}: fragment count {oracle_count} != {native_count}")
        for channel, (expected, actual) in enumerate(zip(oracle, native, strict=True)):
            if expected is None:
                if actual is not None:
                    raise AssertionError(f"{label}: unexpected alpha attachment")
                continue
            if actual is None or expected.tobytes() != actual.tobytes():
                raise AssertionError(f"{label}: attachment {channel} differs")
        targets[0][...] = native[0]
        targets[1][...] = native[1]
        if targets[2] is not None:
            assert native[2] is not None
            targets[2][...] = native[2]
        return native_count

    @staticmethod
    def _status(status: int, label: str) -> None:
        if status != OK:
            raise AssertionError(f"{label}: native status {status}")

    def draw_head816(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        if len(arguments) != 22:
            raise AssertionError(f"Head816 oracle ABI changed: {len(arguments)} arguments")
        (
            screen, bounds, denominators, vertices, normals, normal_valid,
            albedo_uv, normal_uv, albedo_texture, normal_texels, normal_levels,
            normal_indices, base, direction, light, ambient, light_intensity,
            ambient_intensity, alpha_scalar, alpha_cutoff, perspective, has_albedo,
        ) = arguments
        oracle, native = self._snapshots(color, depth, alpha)
        oracle_count = int(self.oracles["Head816"](*oracle, *arguments))
        descriptor = _attachments(*native)
        payload = HeadInput(
            _triangles(screen, bounds, denominators), _f64(vertices), _f64(normals),
            _u8(normal_valid), _f64(albedo_uv), _f64(normal_uv), _texture(albedo_texture),
            _mip_bank(normal_texels, normal_levels), _i64(normal_indices), _vec3(base),
            _vec3(direction), _vec3(light), _vec3(ambient), float(light_intensity),
            float(ambient_intensity), float(alpha_scalar), float(alpha_cutoff),
            int(perspective), int(has_albedo),
        )
        written = ctypes.c_uint64()
        self._status(self.library.ltd_draw_head816(ctypes.byref(descriptor), ctypes.byref(payload), ctypes.byref(written)), "Head816")
        self.calls["Head816"] += 1
        return self._compare_and_commit((color, depth, alpha), oracle, native, oracle_count, written.value, "Head816")

    def draw_hair(self, profile: int, label: str, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        if len(arguments) != 10:
            raise AssertionError(f"{label} oracle ABI changed: {len(arguments)} arguments")
        screen, bounds, denominators, vertices, normals, uv, texels, levels, indices, parameters = arguments
        oracle, native = self._snapshots(color, depth, alpha)
        oracle_count = int(self.oracles[label](*oracle, *arguments))
        descriptor = _attachments(*native)
        payload = HairInput(
            _triangles(screen, bounds, denominators), _f64(vertices), _f64(normals),
            _f64(uv), _mip_bank(texels, levels), _i64(indices),
            F64x33(*(float(value) for value in parameters)), profile, 0,
        )
        written = ctypes.c_uint64()
        self._status(self.library.ltd_draw_hair(ctypes.byref(descriptor), ctypes.byref(payload), ctypes.byref(written)), label)
        self.calls[label] += 1
        return self._compare_and_commit((color, depth, alpha), oracle, native, oracle_count, written.value, label)

    def draw_hair612(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        return self.draw_hair(HAIR612, "Hair612", color, depth, alpha, *arguments)

    def draw_hair564(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        return self.draw_hair(HAIR564, "Hair564EqualEndpoint", color, depth, alpha, *arguments)

    def draw_beard468(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        return self.draw_hair(BEARD468, "Beard468", color, depth, alpha, *arguments)

    def draw_outfit(self, profile: int, label: str, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        if len(arguments) != 20:
            raise AssertionError(f"{label} oracle ABI changed: {len(arguments)} arguments")
        (
            screen, bounds, denominators, vertices, normals, uv,
            albedo_texels, albedo_levels, lower, upper, amounts,
            normal_texels, normal_levels, normal_indices,
            direction, light, ambient, light_intensity, ambient_intensity, perspective,
        ) = arguments
        oracle, native = self._snapshots(color, depth, alpha)
        oracle_count = int(self.oracles[label](*oracle, *arguments))
        descriptor = _attachments(*native)
        payload = OutfitInput(
            _triangles(screen, bounds, denominators), _f64(vertices), _f64(normals), _f64(uv),
            _mip_bank(albedo_texels, albedo_levels), _i64(lower), _i64(upper), _f64(amounts),
            _mip_bank(normal_texels, normal_levels), _i64(normal_indices),
            _vec3(direction), _vec3(light), _vec3(ambient), float(light_intensity),
            float(ambient_intensity), int(perspective), profile,
        )
        written = ctypes.c_uint64()
        self._status(self.library.ltd_draw_outfit(ctypes.byref(descriptor), ctypes.byref(payload), ctypes.byref(written)), label)
        self.calls[label] += 1
        return self._compare_and_commit((color, depth, alpha), oracle, native, oracle_count, written.value, label)

    def draw_outfit984(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        return self.draw_outfit(OUTFIT984, "Outfit984", color, depth, alpha, *arguments)

    def draw_outfit936(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        return self.draw_outfit(OUTFIT936, "Outfit936", color, depth, alpha, *arguments)

    def draw_outfit912(self, color: np.ndarray, depth: np.ndarray, alpha: np.ndarray | None, *arguments: Any) -> int:
        return self.draw_outfit(OUTFIT912, "Outfit912", color, depth, alpha, *arguments)


def _vsdevcmd() -> Path:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    result = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
        check=True, capture_output=True, text=True,
    ).stdout.strip().splitlines()
    if not result:
        raise RuntimeError("Visual Studio x64 toolchain not found")
    path = Path(result[0]) / "Common7/Tools/VsDevCmd.bat"
    if not path.is_file():
        raise RuntimeError("VsDevCmd.bat not found")
    return path


def _checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n" +
            (result.stdout + result.stderr).strip()
        )
    return result


def _windows_command(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    script = cwd / "native_draw_runtime_v2_build.cmd"
    script.write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8", newline="")
    return _checked([os.environ["ComSpec"], "/d", "/c", str(script)], cwd)


def _build_library(directory: Path) -> tuple[Path, list[str]]:
    directory.mkdir(parents=True)
    if sys.platform == "win32":
        output = directory / "native_draw_runtime_v2.dll"
        command = (
            f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && '
            f'cl.exe /nologo /LD /O2 /MT /fp:strict /W4 /WX /std:c17 '
            f'/DLTD_DRAW_RUNTIME_BUILD_DLL /DLTD_DRAW_RUNTIME_V2_BUILD_DLL '
            f'/Fo:"{directory / "runtime.obj"}" /Fe:"{output}" "{SOURCE}" /link /Brepro'
        )
        _windows_command(command, directory)
        inspect = f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && dumpbin.exe /dependents "{output}"'
        lines = _windows_command(inspect, directory).stdout.splitlines()
        dependencies = [
            line.strip() for line in lines
            if line.strip().lower().endswith(".dll")
            and not line.strip().lower().startswith("dump of file ")
        ]
        return output, dependencies
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("C compiler not found")
    output = directory / "libnative_draw_runtime_v2.so"
    _checked([
        compiler, "-std=c11", "-shared", "-fPIC", "-O3", "-Wall", "-Wextra", "-Werror",
        "-ffp-contract=off", str(SOURCE), "-lm", "-o", str(output),
    ], directory)
    return output, []


def _build_smoke(directory: Path) -> Path:
    if sys.platform == "win32":
        output = directory / "native_draw_runtime_v2_smoke.exe"
        command = (
            f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && '
            f'cl.exe /nologo /O2 /MT /fp:strict /W4 /WX /std:c17 '
            f'/Fe:"{output}" "{SOURCE}" "{SMOKE}" /link /Brepro'
        )
        _windows_command(command, directory)
        return output
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("C compiler not found")
    output = directory / "native_draw_runtime_v2_smoke"
    _checked([
        compiler, "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", "-ffp-contract=off",
        str(SOURCE), str(SMOKE), "-lm", "-o", str(output),
    ], directory)
    return output


def _render(render_mii: Any, input_name: str, asset_root: Path, output: Path, size: int, view: str) -> bytes:
    sys.argv = [
        str(ROOT / "renderer" / "render_mii.py"), str(ROOT / input_name),
        "--asset-root", str(asset_root), "--output-dir", str(output),
        "--size", str(size), "--view", view, "--supersample-factor", "1",
        "--build-active-parts", str(output.parent / (output.name + "-active.json")),
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        if render_mii.main() != 0:
            raise RuntimeError("render_mii returned failure")
    filename = "mii.png" if view == "portrait" else "mii_full_body.png"
    return (output / filename).read_bytes()


def _valid_empty_hair() -> tuple[HairInput, Any, Any]:
    texels = (ctypes.c_double * 4)(1.0, 1.0, 1.0, 1.0)
    levels = (ctypes.c_int64 * 3)(0, 1, 1)
    payload = HairInput()
    payload.mim = MipBank(texels, 1, levels, 1)
    payload.parameters[25] = 1.0
    payload.parameters[32] = 1.0
    payload.profile = HAIR612
    return payload, texels, levels


def _valid_empty_head() -> tuple[HeadInput, Any, Any]:
    texels = (ctypes.c_double * 4)(1.0, 1.0, 1.0, 1.0)
    levels = (ctypes.c_int64 * 3)(0, 1, 1)
    payload = HeadInput()
    payload.albedo_texture = Texture2D(texels, 1, 1, 1)
    payload.normal = MipBank(texels, 1, levels, 1)
    payload.light_direction[2] = 1.0
    payload.light_color[:] = (1.0, 1.0, 1.0)
    payload.ambient_color[:] = (1.0, 1.0, 1.0)
    payload.alpha_scalar = 1.0
    payload.alpha_cutoff = 1.0 / 255.0
    payload.perspective_correct = 1
    return payload, texels, levels


def _negative_tests(adapter: Adapter) -> dict[str, bool]:
    color = np.zeros((1, 1, 3), dtype=np.float64)
    depth = np.ones((1, 1), dtype=np.float64)
    descriptor = _attachments(color, depth, None)
    written = ctypes.c_uint64()

    hair, hair_texels, hair_levels = _valid_empty_hair()
    hair.profile = 999
    assert adapter.library.ltd_draw_hair(ctypes.byref(descriptor), ctypes.byref(hair), ctypes.byref(written)) == INVALID_ARGUMENT
    hair.profile = HAIR564
    assert adapter.library.ltd_draw_hair(ctypes.byref(descriptor), ctypes.byref(hair), ctypes.byref(written)) == CONTRACT_MISMATCH
    hair.profile = HAIR612
    hair.parameters[25] = 0.0
    assert adapter.library.ltd_draw_hair(ctypes.byref(descriptor), ctypes.byref(hair), ctypes.byref(written)) == VALUE_OUT_OF_RANGE

    head, head_texels, head_levels = _valid_empty_head()
    head.perspective_correct = 2
    assert adapter.library.ltd_draw_head816(ctypes.byref(descriptor), ctypes.byref(head), ctypes.byref(written)) == INVALID_ARGUMENT
    head.perspective_correct = 1
    alias = _attachments(color, depth, None)
    alias.depth = alias.color
    alias.depth_capacity_bytes = color.nbytes
    alias.depth_row_stride_bytes = color.strides[0]
    assert adapter.library.ltd_draw_head816(ctypes.byref(alias), ctypes.byref(head), ctypes.byref(written)) == 8
    # Keep ctypes-owned input storage live through all calls above.
    assert hair_texels and hair_levels and head_texels and head_levels
    return {
        "abi_mismatch_rejected": True,
        "contract_mismatch_rejected": True,
        "unknown_hair_profile_rejected": True,
        "hair_profile_parameter_mismatch_rejected": True,
        "hair_flag_drift_rejected": True,
        "head_flag_drift_rejected": True,
        "attachment_alias_rejected": True,
    }


def _source_seals() -> None:
    expected = {
        CURRENT_SOURCE: CURRENT_SHA256,
        OPAQUE_SOURCE: OPAQUE_SHA256,
        WRAPPER_SOURCE: WRAPPER_SHA256,
        BASE_SOURCE: BASE_SOURCE_SHA256,
        BASE_HEADER: BASE_HEADER_SHA256,
    }
    for path, digest in expected.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise AssertionError(f"sealed input changed: {path.relative_to(ROOT)} {actual}")


def _worker(library: Path, asset_root: Path, focused: bool) -> int:
    _source_seals()
    for entry in (str(ROOT), str(ROOT / "renderer")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    import native_current_draw
    import render_mii

    names = {
        "Head816": "_draw_head816_compiled",
        "Hair612": "_draw_hair612_compiled",
        "Hair564EqualEndpoint": "_draw_hair564_compiled",
        "Beard468": "_draw_beard468_compiled",
        "Outfit984": "_draw_outfit984_compiled",
        "Outfit936": "_draw_outfit936_compiled",
        "Outfit912": "_draw_outfit912_compiled",
    }
    originals = {label: getattr(native_current_draw, attribute) for label, attribute in names.items()}
    if any(function is None for function in originals.values()):
        raise RuntimeError("current-draw oracle extension is unavailable")
    adapter = Adapter(library, originals)
    negatives = _negative_tests(adapter)
    replacements = {
        "Head816": adapter.draw_head816,
        "Hair612": adapter.draw_hair612,
        "Hair564EqualEndpoint": adapter.draw_hair564,
        "Beard468": adapter.draw_beard468,
        "Outfit984": adapter.draw_outfit984,
        "Outfit936": adapter.draw_outfit936,
        "Outfit912": adapter.draw_outfit912,
    }
    matrix = (
        [("mii1.ltd", 128, "portrait"), ("mii2.ltd", 128, "portrait")]
        if focused else
        [(name, size, view) for name in PRODUCTION_INPUTS for size in (128, 512) for view in ("portrait", "full-body")]
    )
    cases = []
    with tempfile.TemporaryDirectory(prefix="ltd-native-draw-runtime-v2-fixtures-") as directory:
        temporary = Path(directory)
        for index, (input_name, size, view) in enumerate(matrix):
            baseline = _render(render_mii, input_name, asset_root, temporary / f"{index}-baseline", size, view)
            for label, attribute in names.items():
                setattr(native_current_draw, attribute, replacements[label])
            try:
                accelerated = _render(render_mii, input_name, asset_root, temporary / f"{index}-native", size, view)
            finally:
                for label, attribute in names.items():
                    setattr(native_current_draw, attribute, originals[label])
            if baseline != accelerated:
                raise AssertionError(f"final PNG changed for {input_name} {view} {size}")
            cases.append({
                "input": input_name,
                "size": size,
                "view": view,
                "byte_exact": True,
                "png_sha256": hashlib.sha256(accelerated).hexdigest(),
                "png_byte_length": len(accelerated),
            })
    expected_calls = (
        {
            "Head816": 2,
            "Hair612": 1,
            "Hair564EqualEndpoint": 2,
            "Beard468": 1,
            "Outfit984": 2,
            "Outfit936": 2,
            "Outfit912": 2,
        }
        if focused else
        {
            "Head816": 16,
            "Hair612": 4,
            "Hair564EqualEndpoint": 8,
            "Beard468": 4,
            "Outfit984": 16,
            "Outfit936": 16,
            "Outfit912": 16,
        }
    )
    if adapter.calls != expected_calls:
        raise AssertionError(
            f"accepted-profile activation drift: {adapter.calls} != {expected_calls}"
        )
    print(json.dumps({
        "schema_version": 1,
        "kind": "standalone-native-draw-runtime-v2-focused-worker" if focused else "standalone-native-draw-runtime-v2-worker",
        "direct_per_draw_oracle_comparison": True,
        "fail_closed_negative_tests": negatives,
        "activation_counts": adapter.calls,
        "direct_comparison_count": sum(adapter.calls.values()),
        "final_cases": cases,
        "byte_exact_all_cases": True,
    }, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-root", type=Path, default=ROOT.parent / "ltdDemo_converted_assets")
    parser.add_argument("--worker-library", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--focused-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    _source_seals()
    if args.worker_library is not None:
        return _worker(args.worker_library.resolve(), args.asset_root.resolve(), args.focused_worker)
    if not args.asset_root.is_dir():
        parser.error(f"asset root not found: {args.asset_root}")

    with tempfile.TemporaryDirectory(prefix="ltd-native-draw-runtime-v2-") as directory:
        temporary = Path(directory)
        first, dependencies = _build_library(temporary / "first")
        second, second_dependencies = _build_library(temporary / "second")
        first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
        if first_hash != hashlib.sha256(second.read_bytes()).hexdigest():
            raise AssertionError("draw-runtime ABI-2 builds are not byte reproducible")
        if dependencies != second_dependencies:
            raise AssertionError("draw-runtime ABI-2 dependencies changed between builds")
        forbidden = [name for name in dependencies if "python" in name.lower() or "numpy" in name.lower()]
        if forbidden:
            raise AssertionError(f"draw runtime imports forbidden host runtimes: {forbidden}")
        smoke = _build_smoke(temporary / "first")
        _checked([str(smoke)], smoke.parent)

        common = [
            sys.executable, str(Path(__file__).resolve()),
            "--worker-library", str(first), "--asset-root", str(args.asset_root.resolve()),
        ]
        focused = json.loads(_checked(common + ["--focused-worker"], ROOT).stdout)
        full = json.loads(_checked(common, ROOT).stdout)
        print(json.dumps({
            "schema_version": 1,
            "kind": "standalone-native-draw-runtime-v2-verification",
            "claim": "pure C Head/Hair/Beard/Outfit kernels reproduce every accepted current draw",
            "abi_version": ABI_VERSION,
            "contract_sha256": CONTRACT_SHA256,
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "header": str(HEADER.relative_to(ROOT)),
            "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(),
            "base_abi_source_sha256": BASE_SOURCE_SHA256,
            "base_abi_header_sha256": BASE_HEADER_SHA256,
            "oracle_sources": {
                "native_current_draw.py": WRAPPER_SHA256,
                "native_current_draw_kernel.c": CURRENT_SHA256,
                "native_current_opaque_kernel.c": OPAQUE_SHA256,
            },
            "reproducible_build": {
                "byte_identical": True,
                "library_sha256": first_hash,
                "dependencies": dependencies,
                "forbidden_host_dependencies": forbidden,
            },
            "standalone_static_link_smoke": True,
            "focused_gate": focused,
            "full_matrix": full,
            "remaining_profiles": [],
            "temporary_products_removed_on_exit": True,
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
