#!/usr/bin/env python3
"""Build and compare the standalone material schedule with the Python authority."""

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
import struct
import subprocess
import sys
import tempfile
from typing import Any

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native_runtime" / "native_material_schedule.cpp"
HEADER = ROOT / "native_runtime" / "native_material_schedule.h"
COMPOSE = ROOT / "renderer" / "render_mii.py"
WRAPPER = ROOT / "renderer" / "native_current_draw.py"
CURRENT = ROOT / "renderer" / "native_current_draw_kernel.c"
OPAQUE = ROOT / "renderer" / "native_current_opaque_kernel.c"
SEALS = (
    "2cb56971a3ba7ce7d527ed415d8d9d2a201782a107ed277766a9608c4f9533d4",
    "405365df31ca29e5938acb63ec59a53b30c7130c4fbc6e1d97d83bfc910ae7d4",
    "14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d",
    "f03b17eac2eb4c16293ae9ddbc40710fb9f3507ad880060e131959b54daadf0c",
)
CONTRACT = "ae8bac4873568bb7c3d3ac02e9808afa8d2f69290585b9ecae2ebae8c9323a88"
FIXTURES = ("mii0.ltd", "mii1.ltd", "mii2.ltd", "mii4.ltd")

OK, SOURCE_MISMATCH, FINGERPRINT, TOO_SMALL = 0, 2, 4, 5

FAMILY = {
    "body": 1,
    "outfit_tops": 2,
    "outfit_bottoms": 3,
    "outfit_shoes": 4,
    "mask": 5,
    "head": 6,
    "ear": 7,
    "hair_anisotropic": 8,
    "hair_endpoint": 9,
    "nose": 10,
    "beard_anisotropic": 11,
    "nose_line": 12,
}

ROLE = {"albedo": 1, "normal": 2, "skin": 3, "mic": 4, "parallax": 5,
        "specular": 6, "gradient": 7, "generated": 8, "user0": 9}
ADDRESS = {"clamp": 0, "repeat": 1, "mirror": 2}
MIP = {"point": 0, "linear": 1}

LINEAR_FB = 1 << 0
PERSPECTIVE = 1 << 1
DEPTH_WRITE = 1 << 2
BLEND = 1 << 3
CULL = 1 << 4
CLOCKWISE = 1 << 5
LINEAR_LIGHT = 1 << 6
GAMMA_LIGHT = 1 << 7
CHEAP_SSS = 1 << 8
ANISOTROPIC = 1 << 9
FRONT_EDGE = 1 << 10
RECEIVES = 1 << 11
CASTS = 1 << 12
HAS_UV = 1 << 13
HAS_NORMAL = 1 << 14
HAS_U2 = 1 << 15
MASK_USER0 = 1 << 16


class Seals(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint8 * 32) for name in
                ("compose", "wrapper", "current", "opaque")]


class Extent(ctypes.Structure):
    _fields_ = [("height", ctypes.c_uint32), ("width", ctypes.c_uint32)]


class Texture(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16), ("address_u", ctypes.c_uint8),
        ("address_v", ctypes.c_uint8), ("mip_filter", ctypes.c_uint8),
        ("hardware_srgb", ctypes.c_uint8), ("reserved", ctypes.c_uint16),
        ("source_key", ctypes.c_char_p), ("levels", ctypes.POINTER(Extent)),
        ("level_count", ctypes.c_uint32), ("digest", ctypes.c_uint8 * 32),
    ]


class Field(ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_uint16), ("element_width", ctypes.c_uint16),
        ("reserved", ctypes.c_uint32), ("bytes", ctypes.POINTER(ctypes.c_uint8)),
        ("byte_count", ctypes.c_size_t),
    ]


class SourceDraw(ctypes.Structure):
    _fields_ = [
        ("model_key", ctypes.c_char_p), ("resource_name", ctypes.c_char_p),
        ("group", ctypes.c_char_p), ("authored_index", ctypes.c_uint32),
        ("submitted", ctypes.c_uint32), ("candidate", ctypes.c_uint32),
        ("program", ctypes.c_int32), ("family", ctypes.c_uint16),
        ("priority", ctypes.c_int16), ("flags", ctypes.c_uint32),
        ("transform", ctypes.c_double * 16), ("dynamic", ctypes.c_double * 16),
        ("textures", ctypes.POINTER(Texture)), ("texture_count", ctypes.c_uint32),
        ("fields", ctypes.POINTER(Field)), ("field_count", ctypes.c_uint32),
    ]


class CompiledDraw(ctypes.Structure):
    _fields_ = [
        ("model_key", ctypes.c_char_p), ("resource_name", ctypes.c_char_p),
        ("group", ctypes.c_char_p), ("authored_index", ctypes.c_uint32),
        ("scheduled_index", ctypes.c_uint32), ("submitted", ctypes.c_uint32),
        ("candidate", ctypes.c_uint32), ("kernel", ctypes.c_uint16),
        ("profile", ctypes.c_uint16), ("draw_abi", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3), ("flags", ctypes.c_uint32),
        ("transform", ctypes.c_double * 16), ("dynamic", ctypes.c_double * 16),
        ("texture_hash", ctypes.c_uint8 * 32), ("packed_hash", ctypes.c_uint8 * 32),
    ]


def _checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}{result.stderr}")
    return result


def _vsdevcmd() -> Path:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    install = _checked([str(vswhere), "-latest", "-products", "*", "-requires",
                        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                        "-property", "installationPath"], ROOT).stdout.strip().splitlines()
    if not install:
        raise RuntimeError("Visual Studio x64 toolchain not found")
    return Path(install[0]) / "Common7/Tools/VsDevCmd.bat"


def _windows(command: str, directory: Path) -> subprocess.CompletedProcess[str]:
    script = directory / "build.cmd"
    script.write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8", newline="")
    return _checked([os.environ["ComSpec"], "/d", "/c", str(script)], directory)


def _build(directory: Path) -> tuple[Path, list[str]]:
    directory.mkdir(parents=True)
    if sys.platform == "win32":
        output = directory / "native_material_schedule.dll"
        command = (f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && '
                   f'cl.exe /nologo /LD /O2 /MT /fp:strict /EHsc /W4 /WX /std:c++20 '
                   f'/DLTD_NATIVE_MATERIAL_SCHEDULE_BUILD_DLL /Fo:"{directory / "schedule.obj"}" '
                   f'/Fe:"{output}" "{SOURCE}" /link /Brepro')
        _windows(command, directory)
        inspect = _windows(f'call "{_vsdevcmd()}" -no_logo -arch=x64 -host_arch=x64 >nul && dumpbin /dependents "{output}"', directory)
        dependencies = [line.strip() for line in inspect.stdout.splitlines()
                        if line.strip().lower().endswith(".dll") and
                        not line.strip().lower().startswith("dump of file")]
        return output, dependencies
    compiler = shutil.which("c++")
    if compiler is None:
        raise RuntimeError("C++20 compiler not found")
    output = directory / "libnative_material_schedule.so"
    _checked([compiler, "-std=c++20", "-shared", "-fPIC", "-O3", "-Wall", "-Wextra",
              "-Werror", "-ffp-contract=off", str(SOURCE), "-o", str(output)], directory)
    return output, []


def _source_seals() -> None:
    for path, expected in zip((COMPOSE, WRAPPER, CURRENT, OPAQUE), SEALS, strict=True):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"sealed Python authority changed: {path} {actual}")


def _key(mesh: Any, group: str, style: Any, transform: Any) -> tuple[int, str, int, bytes]:
    matrix = np.identity(4, dtype=np.float64) if transform is None else np.asarray(transform, dtype=np.float64)
    return id(mesh), group, id(style), np.ascontiguousarray(matrix).tobytes()


def _levels(source: Any) -> tuple[np.ndarray, ...]:
    return tuple(source) if isinstance(source, tuple) else (source,)


def _chain_digest(source: Any) -> bytes:
    digest = hashlib.sha256(b"ltd.decoded.texture-chain.v1")
    for level in _levels(source):
        array = np.ascontiguousarray(np.asarray(level)[..., :4])
        digest.update(struct.pack("<IIQ", array.shape[0], array.shape[1], array.nbytes))
        digest.update(array.tobytes())
    return digest.digest()


def _style_flags(raster: Any, mesh: Any, group: str, style: Any) -> int:
    flags = 0
    checks = (
        (bool(raster.linear_framebuffer), LINEAR_FB),
        (bool(raster.perspective_correct), PERSPECTIVE),
        (bool(style.depth_write), DEPTH_WRITE), (bool(style.blend), BLEND),
        (bool(style.cull_back_faces), CULL), (bool(style.clockwise_front_face), CLOCKWISE),
        (bool(style.linear_lighting), LINEAR_LIGHT),
        (bool(style.gamma_correct_lighting), GAMMA_LIGHT),
        (bool(style.cheap_sss_proxy), CHEAP_SSS),
        (bool(style.anisotropic_proxy), ANISOTROPIC),
        (bool(style.front_edge_light_proxy), FRONT_EDGE),
        (bool(style.receives_screenspace_face_shadow), RECEIVES),
        (bool(style.casts_face_shadow), CASTS),
    )
    for enabled, bit in checks:
        if enabled:
            flags |= bit
    triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
    if triangles and all(all(index is not None for index in triangle.texcoord) for triangle in triangles):
        flags |= HAS_UV
    if triangles and all(all(index is not None for index in triangle.normal) for triangle in triangles):
        flags |= HAS_NORMAL
    if "_u2" in getattr(mesh, "texcoord_channels", {}):
        flags |= HAS_U2
    if style.gameuber_mask0_facepaint is not None:
        flags |= MASK_USER0
    return flags


def _dynamic(raster: Any, style: Any) -> list[float]:
    return [
        *map(float, style.color), float(style.alpha_multiplier), float(style.alpha_cutoff),
        float(style.roughness), float(style.anisotropic_shift_scale),
        float(style.anisotropic_shift_offset), float(style.anisotropic_specular_size),
        float(style.anisotropic_toon_intensity), float(style.anisotropic_title_view_scale),
        float(style.anisotropic_radiance_scale), float(style.parallax_scale),
        float(raster.light_intensity), float(raster.ambient_intensity),
    ]


def _texture_specs(style: Any, family: int) -> list[tuple[int, Any, tuple[str, str], str, int]]:
    result: list[tuple[int, Any, tuple[str, str], str, int]] = []
    if family == FAMILY["body"]:
        body = style.gameuber_body348
        result = [
            (ROLE["albedo"], body.albedo_texture, body.albedo_wrap, body.albedo_mip_filter, 1),
            (ROLE["normal"], style.normal_texture, style.normal_wrap, style.normal_mip_filter, 0),
            (ROLE["skin"], body.skin_mask_texture, body.skin_mask_wrap, body.skin_mask_mip_filter, 0),
            (ROLE["mic"], body.material_information_texture, body.material_information_wrap, body.material_information_mip_filter, 0),
        ]
    elif family in (FAMILY["outfit_tops"], FAMILY["outfit_bottoms"], FAMILY["outfit_shoes"]):
        result = [
            (ROLE["albedo"], style.texture, style.texture_wrap, style.texture_mip_filter, 1),
            (ROLE["normal"], style.normal_texture, style.normal_wrap, style.normal_mip_filter, 0),
            (ROLE["mic"], style.roughness_texture, style.roughness_wrap, style.roughness_mip_filter, 0),
        ]
    elif family == FAMILY["mask"]:
        paint = style.gameuber_mask0_facepaint
        if paint is None:
            result = [(ROLE["generated"], style.texture, style.texture_wrap, style.texture_mip_filter, 0)]
        else:
            result = [
                (ROLE["generated"], paint.generated_mask_texture, paint.generated_mask_wrap, paint.generated_mask_mip_filter, 0),
                (ROLE["user0"], paint.user0_texture, paint.user0_wrap, paint.user0_mip_filter, 0),
            ]
    elif family == FAMILY["head"]:
        result = [(ROLE["normal"], style.normal_texture, style.normal_wrap, style.normal_mip_filter, 0)]
        if style.texture is not None:
            result.append((ROLE["albedo"], style.texture, style.texture_wrap, style.texture_mip_filter, 1))
    elif family == FAMILY["nose"]:
        result = [
            (ROLE["parallax"], style.parallax_texture, style.parallax_wrap, style.parallax_mip_filter, 0),
            (ROLE["specular"], style.specular_texture, style.specular_wrap, style.specular_mip_filter, 0),
        ]
    elif family in (FAMILY["hair_anisotropic"], FAMILY["hair_endpoint"]):
        result = [
            (ROLE["specular"], style.specular_texture, style.specular_wrap, style.specular_mip_filter, 0),
            (ROLE["gradient"], style.gradient_texture, style.gradient_wrap, style.gradient_mip_filter, 0),
        ]
    elif family == FAMILY["beard_anisotropic"]:
        result = [(ROLE["specular"], style.specular_texture, style.specular_wrap, style.specular_mip_filter, 0)]
    return result


def _field_bytes(value: Any) -> tuple[bytes, int]:
    if isinstance(value, np.ndarray):
        array = np.ascontiguousarray(value)
        return array.tobytes(), array.dtype.itemsize
    if isinstance(value, (float, np.floating)):
        return struct.pack("<d", float(value)), 8
    if isinstance(value, (int, bool, np.integer)):
        return struct.pack("<q", int(value)), 8
    raise TypeError(f"unsupported packed ABI value: {type(value)!r}")


def _packed_digest(family: int, program: int, fields: list[tuple[bytes, int]]) -> bytes:
    digest = hashlib.sha256(b"ltd.material.packed-abi.v1")
    digest.update(struct.pack("<HHI", family, program & 0xFFFF, len(fields)))
    for tag, (data, width) in enumerate(fields, 1):
        digest.update(struct.pack("<HHQ", tag, width, len(data)))
        digest.update(data)
    return digest.digest()


def _texture_digest(specs: list[dict[str, Any]]) -> bytes:
    digest = hashlib.sha256(b"ltd.material.texture-plan.v1")
    digest.update(struct.pack("<I", len(specs)))
    for spec in sorted(specs, key=lambda value: value["role"]):
        key = spec["key"].encode("ascii")
        digest.update(struct.pack("<HBBBBI", spec["role"], spec["u"], spec["v"], spec["mip"], spec["srgb"], len(key)))
        digest.update(key)
        digest.update(struct.pack("<I", len(spec["levels"])))
        for height, width in spec["levels"]:
            digest.update(struct.pack("<II", height, width))
        digest.update(spec["digest"])
    return digest.digest()


class Capture:
    def __init__(self, native_current_draw: Any, software_renderer: Any) -> None:
        self.native = native_current_draw
        self.software = software_renderer
        self.records: list[dict[str, Any]] = []
        self.by_key: dict[tuple[int, str, int, bytes], dict[str, Any]] = {}
        self.executed: list[tuple[int, str, int, bytes]] = []
        self.current: tuple[int, str, int, bytes] | None = None
        self.original_recorder = software_renderer.DrawRecorder.draw_group
        self.original_raster = software_renderer.OrthographicRasterizer.draw_group
        self.compiled_names = (
            "_draw_head816_compiled", "_draw_hair612_compiled", "_draw_hair564_compiled",
            "_draw_beard468_compiled", "_draw_outfit984_compiled", "_draw_outfit936_compiled",
            "_draw_outfit912_compiled", "_draw_body_compiled", "_draw_plain_skin_compiled",
            "_draw_mask0_compiled",
        )
        self.original_compiled = {name: getattr(native_current_draw, name) for name in self.compiled_names}

    def install(self) -> None:
        capture = self

        def recorder(owner: Any, mesh: Any, group: str, style: Any, transform: Any) -> int:
            key = _key(mesh, group, style, transform)
            if key in capture.by_key:
                raise AssertionError(f"duplicate authored draw identity: {group}")
            identity = style.gameall_identity
            family_name = "" if identity is None else identity.family
            family = FAMILY.get(family_name, 12 if family_name == "nose_line" else 0)
            record = {
                "key": key, "mesh": mesh, "group": group, "style": style,
                "transform": np.identity(4) if transform is None else np.asarray(transform, dtype=np.float64),
                "family": family, "program": -1 if identity is None else int(identity.program_index),
                "submitted": sum(triangle.group == group for triangle in mesh.triangles),
                "candidate": 0, "fields": [], "packed_expected": None,
                "raster": None, "flags": None, "textures": None,
            }
            capture.records.append(record)
            capture.by_key[key] = record
            return capture.original_recorder(owner, mesh, group, style, transform)

        def raster(owner: Any, mesh: Any, group: str, style: Any, transform: Any = None) -> int:
            key = _key(mesh, group, style, transform)
            record = capture.by_key[key]
            record["raster"] = owner
            record["flags"] = _style_flags(owner, mesh, group, style)
            capture.executed.append(key)
            capture.current = key
            try:
                return capture.original_raster(owner, mesh, group, style, transform)
            finally:
                capture.current = None

        self.software.DrawRecorder.draw_group = recorder
        self.software.OrthographicRasterizer.draw_group = raster
        for name, oracle in self.original_compiled.items():
            if oracle is None:
                raise RuntimeError(f"accepted extension oracle missing: {name}")

            def compiled(*arguments: Any, _oracle: Any = oracle) -> Any:
                if capture.current is None:
                    raise AssertionError("compiled draw ran outside a scheduled draw")
                record = capture.by_key[capture.current]
                fields = [_field_bytes(value) for value in arguments[3:]]
                if record["fields"]:
                    raise AssertionError(f"draw dispatched more than once: {record['group']}")
                record["fields"] = fields
                first = arguments[3]
                record["candidate"] = int(first.shape[0])
                record["packed_expected"] = _packed_digest(record["family"], record["program"], fields)
                return _oracle(*arguments)

            setattr(self.native, name, compiled)

    def restore(self) -> None:
        self.software.DrawRecorder.draw_group = self.original_recorder
        self.software.OrthographicRasterizer.draw_group = self.original_raster
        for name, function in self.original_compiled.items():
            setattr(self.native, name, function)


def _bind(library: ctypes.CDLL) -> None:
    library.ltd_native_material_schedule_abi_version.argtypes = []
    library.ltd_native_material_schedule_abi_version.restype = ctypes.c_uint32
    library.ltd_native_material_schedule_contract_sha256.argtypes = []
    library.ltd_native_material_schedule_contract_sha256.restype = ctypes.c_char_p
    library.ltd_native_compile_material_schedule.argtypes = [
        ctypes.POINTER(Seals), ctypes.POINTER(SourceDraw), ctypes.c_size_t,
        ctypes.POINTER(CompiledDraw), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    library.ltd_native_compile_material_schedule.restype = ctypes.c_int


def _seals() -> Seals:
    return Seals(*(type(getattr(Seals(), field))(*bytes.fromhex(value))
                   for field, value in zip(("compose", "wrapper", "current", "opaque"), SEALS, strict=True)))


def _compile_case(library: ctypes.CDLL, capture: Capture) -> dict[str, Any]:
    keep: list[Any] = []
    sources = (SourceDraw * len(capture.records))()
    expected: list[dict[str, Any]] = []
    accepted_profiles = {0, 324, 336, 348, 372, 468, 564, 612, 756, 816, 912, 936, 984}
    for index, record in enumerate(capture.records):
        style, raster = record["style"], record["raster"]
        if raster is None:
            raise AssertionError(f"authored draw was not executed: {record['group']}")
        specs = []
        for role, value, wrap, mip_filter, srgb in _texture_specs(style, record["family"]):
            levels = [(int(np.asarray(level).shape[0]), int(np.asarray(level).shape[1])) for level in _levels(value)]
            specs.append({
                "role": role, "u": ADDRESS[wrap[0]], "v": ADDRESS[wrap[1]],
                "mip": MIP[mip_filter], "srgb": srgb, "levels": levels,
                "digest": _chain_digest(value), "key": f"{record['family']}:{record['program']}:{role}",
            })
        record["textures"] = specs
        texture_array = (Texture * len(specs))()
        keep.append(texture_array)
        for texture_index, spec in enumerate(specs):
            extents = (Extent * len(spec["levels"]))(*(Extent(*level) for level in spec["levels"]))
            key_bytes = spec["key"].encode("ascii")
            keep.extend((extents, key_bytes))
            texture_array[texture_index] = Texture(
                spec["role"], spec["u"], spec["v"], spec["mip"], spec["srgb"], 0,
                key_bytes, extents, len(extents), (ctypes.c_uint8 * 32)(*spec["digest"]),
            )
        field_specs = record["fields"]
        field_array = (Field * len(field_specs))()
        keep.append(field_array)
        for field_index, (data, width) in enumerate(field_specs):
            storage = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
            keep.append(storage)
            field_array[field_index] = Field(field_index + 1, width, 0, storage, len(data))
        model = f"model:{record['group']}".encode("ascii")
        resource = f"resource:{record['family']}:{record['program']}".encode("ascii")
        group = record["group"].encode("ascii")
        keep.extend((model, resource, group))
        dynamic = _dynamic(raster, style)
        if len(dynamic) != 16:
            raise AssertionError("dynamic record width changed")
        source = SourceDraw(
            model, resource, group, index, record["submitted"], record["candidate"],
            record["program"], record["family"], -10 if record["group"] in
            ("Mask__mt_Mask", "NoseLine__mt_NoseLine") else 0,
            record["flags"], (ctypes.c_double * 16)(*record["transform"].reshape(-1)),
            (ctypes.c_double * 16)(*dynamic), texture_array, len(specs), field_array, len(field_specs),
        )
        sources[index] = source
        if record["fields"] and record["program"] in accepted_profiles:
            expected.append({
                "record": record, "authored": index,
                "scheduled": capture.executed.index(record["key"]),
                "texture": _texture_digest(specs), "packed": record["packed_expected"],
            })
    output = (CompiledDraw * 64)()
    count = ctypes.c_size_t()
    seals = _seals()
    status = library.ltd_native_compile_material_schedule(seals, sources, len(sources), output, 64, ctypes.byref(count))
    if status != OK:
        summary = [(record["group"], record["family"], record["program"],
                    record["submitted"], record["flags"], len(record["fields"]),
                    [(item["role"], item["levels"]) for item in record["textures"]])
                   for record in capture.records]
        raise AssertionError(f"native material compile failed: {status}; {summary}")
    if count.value != len(expected):
        raise AssertionError(f"accepted draw count differs: {count.value} != {len(expected)}")
    expected.sort(key=lambda entry: entry["scheduled"])
    for actual, oracle in zip(output[:count.value], expected, strict=True):
        record = oracle["record"]
        if (actual.authored_index, actual.scheduled_index, actual.submitted, actual.candidate,
            actual.profile) != (oracle["authored"], oracle["scheduled"], record["submitted"],
                               record["candidate"], record["program"]):
            raise AssertionError(f"schedule/profile/count mismatch for {record['group']}")
        if bytes(actual.texture_hash) != oracle["texture"]:
            raise AssertionError(
                f"texture plan hash mismatch for {record['group']}: "
                f"{bytes(actual.texture_hash).hex()} != {oracle['texture'].hex()}"
            )
        if bytes(actual.packed_hash) != oracle["packed"]:
            raise AssertionError(f"packed ABI hash mismatch for {record['group']}")
        if bytes(actual.transform) != bytes(sources[actual.authored_index].transform):
            raise AssertionError(f"transform record mismatch for {record['group']}")

    # Fail-closed seals and bounded sizing use the same fully valid case.
    bad = _seals()
    bad.compose[0] ^= 1
    assert library.ltd_native_compile_material_schedule(bad, sources, len(sources), output, 64, ctypes.byref(count)) == SOURCE_MISMATCH
    needed = ctypes.c_size_t()
    assert library.ltd_native_compile_material_schedule(seals, sources, len(sources), output, 0, ctypes.byref(needed)) == TOO_SMALL
    assert needed.value == len(expected)
    return {
        "source_draw_count": len(sources), "accepted_draw_count": len(expected),
        "profiles": [entry["record"]["program"] for entry in expected],
        "groups": [entry["record"]["group"] for entry in expected],
        "scheduled_indices": [entry["scheduled"] for entry in expected],
        "packed_abi_sha256": [entry["packed"].hex() for entry in expected],
        "texture_plan_sha256": [entry["texture"].hex() for entry in expected],
        "source_seal_rejection": True, "bounded_output_rejection": True,
    }


def _worker(library_path: Path, asset_root: Path) -> int:
    _source_seals()
    for entry in (str(ROOT), str(ROOT / "renderer")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    import native_current_draw
    import render_mii
    import software_renderer

    library = ctypes.CDLL(str(library_path))
    _bind(library)
    assert library.ltd_native_material_schedule_abi_version() == 1
    assert library.ltd_native_material_schedule_contract_sha256().decode("ascii") == CONTRACT
    cases = []
    with tempfile.TemporaryDirectory(prefix="ltd-material-schedule-fixtures-") as directory:
        temporary = Path(directory)
        case_index = 0
        for fixture in FIXTURES:
            for size in (128, 512):
                for view in ("portrait", "full-body"):
                    capture = Capture(native_current_draw, software_renderer)
                    capture.install()
                    output = temporary / f"case-{case_index}"
                    sys.argv = [
                        str(COMPOSE), str(ROOT / fixture), "--asset-root", str(asset_root),
                        "--output-dir", str(output), "--size", str(size), "--view", view,
                        "--supersample-factor", "1", "--build-active-parts",
                        str(temporary / f"active-{case_index}.json"),
                    ]
                    try:
                        with contextlib.redirect_stdout(io.StringIO()):
                            if render_mii.main() != 0:
                                raise RuntimeError("render_mii returned failure")
                    finally:
                        capture.restore()
                    result = _compile_case(library, capture)
                    result.update({"fixture": fixture, "size": size, "view": view})
                    cases.append(result)
                    case_index += 1
    print(json.dumps({"cases": cases, "case_count": len(cases), "all_exact": True}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-root", type=Path, default=ROOT.parent / "ltdDemo_converted_assets")
    parser.add_argument("--worker-library", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    _source_seals()
    if args.worker_library is not None:
        return _worker(args.worker_library.resolve(), args.asset_root.resolve())
    with tempfile.TemporaryDirectory(prefix="ltd-native-material-schedule-") as directory:
        temporary = Path(directory)
        first, dependencies = _build(temporary / "first")
        second, second_dependencies = _build(temporary / "second")
        digest = hashlib.sha256(first.read_bytes()).hexdigest()
        if digest != hashlib.sha256(second.read_bytes()).hexdigest():
            raise AssertionError("native material schedule build is not reproducible")
        if dependencies != second_dependencies:
            raise AssertionError("dependency inventory changed between builds")
        if any("python" in item.lower() or "numpy" in item.lower() for item in dependencies):
            raise AssertionError("native schedule imported a forbidden host runtime")
        worker = _checked([sys.executable, str(Path(__file__).resolve()), "--worker-library",
                           str(first), "--asset-root", str(args.asset_root.resolve())], ROOT)
        payload = json.loads(worker.stdout)
        print(json.dumps({
            "schema_version": 1, "kind": "native-material-schedule-verification",
            "contract_sha256": CONTRACT, "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(),
            "reproducible_build": {"byte_exact": True, "sha256": digest, "dependencies": dependencies},
            "python_oracle_source_seals": dict(zip(("compose", "wrapper", "current", "opaque"), SEALS, strict=True)),
            "worker": payload, "temporary_products_removed_on_exit": True,
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
