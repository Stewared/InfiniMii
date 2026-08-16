"""Fail-closed wrapper for the exact-current native face target.

The production compositors retain their complete Python implementations as a
fallback and verifier oracle.  This module exposes the small, source-sealed ABI
that replaces only their dense pixel loops when its extension is admissible.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np


ABI_VERSION = 1
DISABLED_BY_ENVIRONMENT = os.environ.get("LTD_DISABLE_NATIVE_FACE_TARGET") == "1"
DIRECTORY = Path(__file__).resolve().parent
SOURCE = DIRECTORY / "native_face_target.c"
EXPECTED_UPSTREAM_SHA256 = {
    "face_compositor.py": "af4251996dd831dbc9dd4b8323c8956b16d4c8d8ae5de576271176652b824efe",
    "faceline_compositor.py": "f323cbe17fe0881b687ee77a487e345cd1d81ab1182055f59a3e5d6efdf5ff71",
    "gameuber_runtime_inputs.json": "a41c3583a077fa812f44e99d5787f08d6f67f8cee9f45ba614163758e14743b8",
    "mii_faceline_stubble.json": "e8be0d3680a7107b231ce6482a26d1d97f45d5846fa66698496a4834f3219e4b",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_upstream_fingerprints() -> None:
    mismatches = []
    for name, expected in EXPECTED_UPSTREAM_SHA256.items():
        path = DIRECTORY / name
        actual = _sha256(path) if path.is_file() else None
        if actual != expected:
            mismatches.append(f"{name}: {actual or 'missing'} != {expected}")
    if mismatches:
        raise ImportError(
            "native face target upstream fingerprints changed; re-audit before rebuilding: "
            + "; ".join(mismatches)
        )


IMPORT_ERROR: Exception | None = None
try:
    if DISABLED_BY_ENVIRONMENT:
        raise ImportError("native face target disabled by LTD_DISABLE_NATIVE_FACE_TARGET")
    validate_upstream_fingerprints()
    try:
        from . import _native_face_target as _compiled
    except ImportError:  # Direct renderer-directory import.
        import _native_face_target as _compiled  # type: ignore

    if _compiled.ABI_VERSION != ABI_VERSION:
        raise ImportError(
            f"compiled native face ABI {_compiled.ABI_VERSION!r} != {ABI_VERSION}"
        )
    if _compiled.SOURCE_SHA256 != _sha256(SOURCE):
        raise ImportError("compiled native face target does not match its C source")
except (AttributeError, ImportError, OSError) as error:
    IMPORT_ERROR = error
    _compiled = None


BACKEND_AVAILABLE = _compiled is not None
_ACTIVATION_COUNTS: Counter[str] = Counter()


def activation_counts(*, reset: bool = False) -> dict[str, int]:
    """Return successful native activations for production diagnostics."""

    result = dict(sorted(_ACTIVATION_COUNTS.items()))
    if reset:
        _ACTIVATION_COUNTS.clear()
    return result


def _require_backend() -> Any:
    if _compiled is None:
        raise RuntimeError(f"native face target is unavailable: {IMPORT_ERROR}")
    return _compiled


def execute_mii_mask_title_pipeline(
    shaded_layers: list[tuple[int, np.ndarray]],
    canvas_size: tuple[int, int],
) -> Any:
    """Exact native implementation of face_compositor's blend/store stage."""

    try:
        from . import face_compositor
    except ImportError:
        import face_compositor  # type: ignore

    # Retain the production evidence guard.  The compiled loop is pixel-only.
    face_compositor._mii_mask_fixed_function_contract()
    width, height = canvas_size
    ordered = sorted(shaded_layers, key=lambda item: item[0])
    cases = tuple(int(case) for case, _source in ordered)
    if len(cases) != len(set(cases)) or any(case < 0 or case > 20 for case in cases):
        raise ValueError("MiiMask active dispatcher cases are duplicated or outside 0..20")
    sources = []
    expected_shape = (height, width, 4)
    for case, source in ordered:
        if (
            not isinstance(source, np.ndarray)
            or source.dtype != np.float64
            or not source.flags.c_contiguous
            or source.shape != expected_shape
        ):
            raise ValueError(f"MiiMask case {case} has an unsupported source array")
        sources.append(source)

    pass0, case21, final, mesh, pass0_audit, pass1_audit = _require_backend().mask_pipeline(
        sources, cases, int(width), int(height)
    )
    if not np.all(final[..., 3] == 255):
        raise ValueError("MiiMask case21/pass1 target alpha is not opaque")
    _ACTIVATION_COUNTS["MiiMaskPipeline"] += 1
    return face_compositor.MiiMaskPipelineResult(
        dispatcher_cases=cases,
        pass0_target_rgba8=pass0,
        case21_target_rgba8=case21,
        final_target_rgba8=final,
        mesh_input_rgba8=mesh,
        pass0_draw_sha256=tuple(
            hashlib.sha256(pass0_audit[index]).hexdigest()
            for index in range(len(cases))
        ),
        pass1_draw_sha256=tuple(
            hashlib.sha256(pass1_audit[index]).hexdigest()
            for index in range(len(cases))
        ),
    )


def _resolve_shader_abi(placement: Any, pixel_shader: Any) -> tuple[int, np.ndarray, np.ndarray] | None:
    if pixel_shader is None:
        return None
    closure = {
        name: cell.cell_contents
        for name, cell in zip(pixel_shader.__code__.co_freevars, pixel_shader.__closure__ or ())
    }
    shader_name = str(getattr(pixel_shader, "__name__", ""))
    zero = np.zeros(3, dtype=np.float64)
    if placement.modulation_mode == 3 and shader_name in {
        "shader", "mode_3", "mustache_mode_3", "eyebrow_mode_3", "mole_mode_3"
    }:
        colors = [
            np.asarray(value, dtype=np.float64)
            for name, value in closure.items()
            if name.endswith("color_float")
        ]
        # mole_mode_3 captures no value and uses exact black.
        if shader_name == "mole_mode_3" and not colors:
            colors = [zero]
        if len(colors) != 1 or colors[0].shape != (3,):
            raise ValueError("mode-3 face shader closure differs from its source-bound ABI")
        shader_kind, c1, c2 = 1, colors[0], zero
    elif placement.modulation_mode == 2 and shader_name == "mouth_mode_2":
        c1 = np.asarray(closure.get("mouth_color_float"), dtype=np.float64)
        if c1.shape != (3,) or set(closure) != {"mouth_color_float"}:
            raise ValueError("mouth mode-2 closure differs from its source-bound ABI")
        shader_kind, c2 = 2, zero
    elif placement.modulation_mode == 2 and shader_name == "eye_mode_2":
        c1 = np.asarray(closure.get("eye_shadow_color_float"), dtype=np.float64)
        c2 = np.asarray(closure.get("eye_color_float"), dtype=np.float64)
        if c1.shape != (3,) or c2.shape != (3,) or set(closure) != {
            "eye_shadow_color_float", "eye_color_float"
        }:
            raise ValueError("eye mode-2 closure differs from its source-bound ABI")
        shader_kind = 3
    elif placement.modulation_mode == 7 and shader_name == "eye_mode_7":
        c1 = np.asarray(closure.get("eye_color_float"), dtype=np.float64)
        if c1.shape != (3,) or set(closure) != {"eye_color_float"}:
            raise ValueError("eye mode-7 closure differs from its source-bound ABI")
        shader_kind, c2 = 4, zero
    elif placement.modulation_mode == 8 and shader_name == "mouth_mode_8" and not closure:
        shader_kind, c1, c2 = 5, zero, zero
    else:
        return None
    return shader_kind, c1, c2


def supports_sample_shaded_layer(placement: Any, pixel_shader: Any) -> bool:
    """Return whether this shader callable has one exact source-bound ABI."""

    return pixel_shader is None or _resolve_shader_abi(placement, pixel_shader) is not None


def sample_shaded_layer(
    canvas_size: tuple[int, int],
    sprite: Any,
    placement: Any,
    face_units: float = 64.0,
    pixel_shader: Any = None,
) -> np.ndarray:
    """Exact native implementation of Pillow-compatible affine sampling."""

    try:
        from . import face_compositor
    except ImportError:
        import face_compositor  # type: ignore

    if (
        not isinstance(canvas_size, tuple)
        or len(canvas_size) != 2
        or canvas_size[0] <= 0
        or canvas_size[1] <= 0
    ):
        raise ValueError("MiiMask canvas size is invalid")
    pixels_per_unit = canvas_size[0] / face_units
    source = np.asarray(sprite.convert("RGBA"), dtype=np.uint8)
    if not source.flags.c_contiguous:
        source = np.ascontiguousarray(source)
    forward = face_compositor._sprite_forward_matrix(
        sprite.size, placement, pixels_per_unit
    )
    inverse = np.linalg.inv(forward)
    source_center = np.asarray(
        (sprite.width / 2.0, sprite.height / 2.0), dtype=np.float64
    )
    output_center = np.asarray(
        (
            placement.center_x * pixels_per_unit,
            placement.center_y * pixels_per_unit,
        ),
        dtype=np.float64,
    )
    offset = source_center - inverse @ output_center
    if pixel_shader is None:
        sampled = _require_backend().mask_sample_affine(
            source,
            int(canvas_size[0]),
            int(canvas_size[1]),
            float(inverse[0, 0]),
            float(inverse[0, 1]),
            float(offset[0]),
            float(inverse[1, 0]),
            float(inverse[1, 1]),
            float(offset[1]),
            int(bool(placement.mirrored)),
            0,
        )
        _ACTIVATION_COUNTS["MiiMaskAffineSample"] += 1
        return sampled

    shader_abi = _resolve_shader_abi(placement, pixel_shader)
    if shader_abi is None:
        raise ValueError(
            "face shader callable has no exact source-bound native ABI"
        )
    shader_kind, c1, c2 = shader_abi
    shaded = _require_backend().mask_sample_shade_affine(
        source,
        int(canvas_size[0]),
        int(canvas_size[1]),
        float(inverse[0, 0]),
        float(inverse[0, 1]),
        float(offset[0]),
        float(inverse[1, 0]),
        float(inverse[1, 1]),
        float(offset[1]),
        int(bool(placement.mirrored)),
        shader_kind,
        np.ascontiguousarray(c1, dtype=np.float64),
        np.ascontiguousarray(c2, dtype=np.float64),
    )
    if shaded.shape != (canvas_size[1], canvas_size[0], 4):
        raise ValueError("MiiMask pixel shader returned an invalid target shape")
    if not np.all(np.isfinite(shaded)):
        raise ValueError("MiiMask pixel shader returned a non-finite value")
    _ACTIVATION_COUNTS["MiiMaskAffineShade"] += 1
    return np.asarray(shaded, dtype=np.float64)


def compose_wrinkle_upper_pixels(
    skin_rgba8: tuple[int, int, int, int],
    source_rgba8: np.ndarray,
    transform: dict[str, np.float32],
    contract: dict[str, Any],
) -> tuple[np.ndarray, dict[str, Any]]:
    """Exact native implementation of Noir's 128x256 faceline pixels."""

    try:
        from . import faceline_compositor
    except ImportError:
        import faceline_compositor  # type: ignore

    required = ("scale_x", "scale_y", "translation_x", "translation_y")
    if any(name not in transform for name in required):
        raise ValueError("wrinkle transform is incomplete")
    scale_x = np.float32(transform["scale_x"])
    scale_y = np.float32(transform["scale_y"])
    translation_x = np.float32(transform["translation_x"])
    translation_y = np.float32(transform["translation_y"])
    left = faceline_compositor._float32_fma(-1.0, scale_x, translation_x)
    right = faceline_compositor._float32_fma(1.0, scale_x, translation_x)
    bottom = faceline_compositor._float32_fma(-1.0, scale_y, translation_y)
    top = faceline_compositor._float32_fma(1.0, scale_y, translation_y)
    skin = np.asarray(skin_rgba8, dtype=np.uint8)
    if (
        not isinstance(source_rgba8, np.ndarray)
        or source_rgba8.dtype != np.uint8
        or not source_rgba8.flags.c_contiguous
    ):
        raise ValueError("wrinkle source must be a contiguous uint8 array")
    stored, row_range, column_range, covered_count = _require_backend().faceline_wrinkle(
        source_rgba8,
        skin,
        float(left),
        float(right),
        float(bottom),
        float(top),
    )
    raster_report = {
        "clip_bounds_float_bits": {
            "left": faceline_compositor._float_bits_hex(left),
            "right": faceline_compositor._float_bits_hex(right),
            "bottom": faceline_compositor._float_bits_hex(bottom),
            "top": faceline_compositor._float_bits_hex(top),
        },
        "covered_pixel_count": int(covered_count),
        "covered_row_range_inclusive": [int(value) for value in row_range],
        "covered_column_range_inclusive": [int(value) for value in column_range],
    }
    expected = contract["geometry"]["raster_specialization"]
    for name, value in raster_report.items():
        if value != expected[name]:
            raise faceline_compositor.FacelineCompositionError(
                "wrinkle_upper_raster_contract_mismatch",
                f"{name}={value!r}, expected {expected[name]!r}",
            )
    _ACTIVATION_COUNTS["FacelineWrinkle"] += 1
    return stored, raster_report


def compose_johnny_pixels(
    skin_rgba8: tuple[int, int, int, int],
    source_rgba8: np.ndarray,
    ledger: dict[str, Any],
) -> np.ndarray:
    """Exact native implementation of Johnny's 128x256 faceline pixels."""

    try:
        from . import faceline_compositor
    except ImportError:
        import faceline_compositor  # type: ignore

    constants = ledger["composition_contract"]["beard_short07"]["shader_constants"]
    c1 = np.asarray(
        [faceline_compositor._float_from_bits(int(value, 16)) for value in constants["c1_float_bits"]],
        dtype=np.float64,
    )
    c2 = np.asarray(constants["c2_rgba"], dtype=np.float64)
    skin = np.asarray(skin_rgba8, dtype=np.uint8)
    if (
        not isinstance(source_rgba8, np.ndarray)
        or source_rgba8.dtype != np.uint8
        or not source_rgba8.flags.c_contiguous
    ):
        raise ValueError("Johnny source must be a contiguous uint8 array")
    stored = _require_backend().faceline_johnny(source_rgba8, skin, c1, c2)
    _ACTIVATION_COUNTS["FacelineJohnny"] += 1
    return stored


__all__ = [
    "ABI_VERSION",
    "BACKEND_AVAILABLE",
    "DISABLED_BY_ENVIRONMENT",
    "EXPECTED_UPSTREAM_SHA256",
    "IMPORT_ERROR",
    "activation_counts",
    "compose_johnny_pixels",
    "compose_wrinkle_upper_pixels",
    "execute_mii_mask_title_pipeline",
    "sample_shaded_layer",
    "supports_sample_shaded_layer",
    "validate_upstream_fingerprints",
]
