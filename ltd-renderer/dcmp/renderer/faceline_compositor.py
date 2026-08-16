"""Strict portable composition for source-proven generated faceline targets.

This module is intentionally separate from the 256x256 MiiMask/facepaint
compositor.  The title renders BeardShort into the 128x256 faceline target and
later binds that target to ``mt_Head``/``mt_faceline`` ``_a0``.  It never feeds
Mask ``_user0`` and is never a screen-space overlay.

The portable classic contract executes the title's ordered MakeLower,
MakeUpper, WrinkleUpper, WrinkleLower, and BeardShort cases for every exact
Parts record whose native mips and resource flags are staged. Beard is a
separate model Parts category with no faceline sprite and is therefore
admitted but not submitted to this target. Every other generated-faceline
layer remains fail closed.  The two older
target-local contracts for Johnny Thunder and Spider-Man Noir are retained as
independent exact fixtures.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

try:
    from . import native_face_target
    from .face_compositor import _validate_classic_signature_record
except ImportError:  # direct renderer module execution
    import native_face_target  # type: ignore
    from face_compositor import _validate_classic_signature_record  # type: ignore


REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = Path(__file__).with_name("mii_faceline_stubble.json")
CLASSIC_FACE_MIPS = Path(__file__).with_name("classic_bridge_face_sprite_mips.json")
SHARED_FACE_MIPS = Path(__file__).with_name("face_sprite_mips.json")
COLOR_TABLE_SHA256 = (
    "bfd3e98b88443275c30d7ceb0f526a9cfe62e345c496a36dc4795aefb295ec29"
)
CLASSIC_GENERIC_FACELINE_CONTRACT = (
    "classic_make_lower_make_upper_wrinkle_upper_wrinkle_lower_beard_short_ordered_v2"
)
JOHNNY_SHARE_MII_SHA256 = (
    "aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d"
)
SPIDER_MAN_NOIR_SHARE_MII_SHA256 = (
    "1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef"
)
FACELINE_WIDTH = 128
FACELINE_HEIGHT = 256
FACELINE_LAYER_NAMES = (
    "faceline",
    "makeup_lower",
    "makeup_upper",
    "wrinkle_upper",
    "wrinkle_lower",
    "beard_short",
    "beard",
)
CLASSIC_GENERIC_LAYER_ORDER = (
    "makeup_lower",
    "makeup_upper",
    "wrinkle_upper",
    "wrinkle_lower",
    "beard_short",
)
CLASSIC_GENERIC_RECORDS = {
    "makeup_lower": {
        1: ("MakeLower00", {}),
        2: ("MakeLower01", {}),
        3: ("MakeLower02", {"IsSelectableColor": False}),
    },
    "wrinkle_upper": {
        selector: (f"WrinkleUpper{selector - 1:02d}", {})
        for selector in range(1, 8)
    },
    "makeup_upper": {1: ("MakeUpper00", {})},
    "wrinkle_lower": {
        1: ("WrinkleLower00", {}),
        2: ("WrinkleLower01", {}),
        3: ("WrinkleLower02", {}),
        5: ("WrinkleLower04", {}),
        6: ("WrinkleLower05", {}),
    },
    "beard_short": {
        1: ("BeardShort00", {"IsSelectableColor": False}),
        2: ("BeardShort01", {"IsSelectableColor": False}),
        3: ("BeardShort02", {}),
        4: ("BeardShort03", {}),
        5: ("BeardShort04", {}),
        8: ("BeardShort07", {}),
    },
}
CLASSIC_GENERIC_NOTHING_RECORDS = {
    "makeup_lower": ("MakeLowerNothing", {}),
    "makeup_upper": ("MakeUpperNothing", {}),
    "wrinkle_upper": ("WrinkleUpperNothing", {}),
    "wrinkle_lower": ("WrinkleLowerNothing", {}),
    "beard_short": ("BeardShortNothing", {"IsSelectableColor": False}),
}
CLASSIC_NON_SELECTABLE_COLOR_FALLBACKS = {
    ("makeup_lower", "MakeLower02"): 8,
    ("beard_short", "BeardShort00"): 8,
    ("beard_short", "BeardShort01"): 8,
}
BEARD_SHORT_C1_FLOAT_BITS = (0x3EAAAA9F, 0x3ECCCCCD, 0x3ECCCCCD, 0x3F800000)
CLASSIC_GENERIC_TRANSFORM_CASES = {
    # FUN_7101d7025c cases 1..4 use distinct CharInfoEx byte quartets and
    # distinct ELF-resident X/aspect constants.  The common origins are exact
    # 1.0/.72 float32 values; retaining each case explicitly prevents the
    # WrinkleLower case-4 .8 coefficient from inheriting case 3's .9.
    "makeup_lower": {
        "dispatcher_case": 1,
        "serialized_offsets": ["0xf2:x", "0xf3:y", "0xf4:scale", "0xf5:aspect"],
        "base_scale_x_bits": 0x3E23D70A,
        "aspect_scale_bits": 0x3F666666,
        "constant_addresses": ["0x7103e386d4", "0x7103e386d8", "0x7103e386dc", "0x7103e386e0"],
    },
    "makeup_upper": {
        "dispatcher_case": 2,
        "serialized_offsets": ["0xee:x", "0xef:y", "0xf0:scale", "0xf1:aspect"],
        "base_scale_x_bits": 0x3E3851EC,
        "aspect_scale_bits": 0x3F4CCCCD,
        "constant_addresses": ["0x7103e386c4", "0x7103e386c8", "0x7103e386cc", "0x7103e386d0"],
    },
    "wrinkle_upper": {
        "dispatcher_case": 3,
        "serialized_offsets": ["0xfa:x", "0xfb:y", "0xfc:scale", "0xfd:aspect"],
        "base_scale_x_bits": 0x3E23D70A,
        "aspect_scale_bits": 0x3F666666,
        "constant_addresses": ["0x7103a67628->0x03e386f4", "0x7103e386f8", "0x7103e386fc", "0x7103e38700"],
    },
    "wrinkle_lower": {
        "dispatcher_case": 4,
        "serialized_offsets": ["0xf6:x", "0xf7:y", "0xf8:scale", "0xf9:aspect"],
        "base_scale_x_bits": 0x3E23D70A,
        "aspect_scale_bits": 0x3F4CCCCD,
        "constant_addresses": ["0x7103a67610->0x03e386e4", "0x7103e386e8", "0x7103e386ec", "0x7103e386f0"],
    },
}
EXTENDED_FACELINE_SRGB_RGBA8 = {
    110: (252, 217, 192, 255),
    111: (238, 145, 103, 255),
    112: (226, 148, 84, 255),
    113: (88, 54, 35, 255),
}


class FacelineCompositionError(ValueError):
    """A machine-readable fail-closed generated-faceline boundary."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FacelineCompositionResult:
    """The exact stored target bytes plus their runtime provenance report."""

    image: Image.Image
    report: dict[str, Any]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rgba8(color: list[float] | tuple[float, ...]) -> tuple[int, int, int, int]:
    values = list(color[:4])
    while len(values) < 4:
        values.append(1.0)
    return tuple(
        int(round(max(0.0, min(1.0, float(value))) * 255.0)) for value in values
    )  # type: ignore[return-value]


def _resolve_faceline_color(
    colors: dict[str, Any], selector: int
) -> tuple[int, int, int, int]:
    """Execute the source-backed CommonColor/legacy-FacelineColor namespace."""

    if 0 <= selector <= 99:
        table = colors.get("common")
        if not isinstance(table, list) or selector >= len(table):
            raise FacelineCompositionError(
                "common_color_table_incomplete",
                f"common color {selector} is absent",
            )
        return _rgba8(table[selector])
    if 100 <= selector <= 109:
        table = colors.get("faceline")
        index = selector - 100
        if not isinstance(table, list) or index >= len(table):
            raise FacelineCompositionError(
                "legacy_faceline_color_table_incomplete",
                f"faceline color {selector} is absent",
            )
        return _rgba8(table[index])
    if selector in EXTENDED_FACELINE_SRGB_RGBA8:
        # DAT_71032bb9a0 contains two RGB triplets per selector.  The
        # FUN_7101d7025c runtime path requests GammaType 1, i.e. the second
        # (sRGB) triplet recorded here verbatim as RGBA8.
        return EXTENDED_FACELINE_SRGB_RGBA8[selector]
    raise FacelineCompositionError(
        "faceline_color_outside_title_domain",
        f"faceline color {selector} is outside Common 0..99, legacy 100..109, and extended 110..113",
    )


def _load_checked_ledger(path: Path) -> dict[str, Any]:
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FacelineCompositionError("faceline_ledger_unreadable", str(exc)) from exc
    if ledger.get("schema_version") != 1:
        raise FacelineCompositionError(
            "faceline_ledger_schema_mismatch",
            f"expected schema 1, got {ledger.get('schema_version')!r}",
        )
    if ledger.get("status") != "GENERIC_CASES_1_TO_4_AND_LOCAL_FIXTURES_EXACT":
        raise FacelineCompositionError(
            "faceline_ledger_status_mismatch",
            f"unexpected status {ledger.get('status')!r}",
        )
    contract = ledger.get("portable_runtime_contract")
    if not isinstance(contract, dict) or contract.get("implementation") != (
        "renderer/faceline_compositor.py"
    ):
        raise FacelineCompositionError(
            "faceline_ledger_contract_missing",
            "portable runtime contract is absent",
        )
    supported = contract.get("supported_share_mii_sha256")
    if supported != [JOHNNY_SHARE_MII_SHA256, SPIDER_MAN_NOIR_SHARE_MII_SHA256]:
        raise FacelineCompositionError(
            "faceline_ledger_contract_mismatch",
            f"unexpected supported target list {supported!r}",
        )
    return ledger


def _validate_generic_affine_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    """Fail closed unless cases 1..4 match the checked ELF constant ledger."""

    contract = ledger.get("composition_contract", {}).get("generic_affine_cases")
    names = {
        "makeup_lower": "MakeLower",
        "makeup_upper": "MakeUpper",
        "wrinkle_upper": "WrinkleUpper",
        "wrinkle_lower": "WrinkleLower",
    }
    if not isinstance(contract, dict) or set(contract) != set(names.values()):
        raise FacelineCompositionError(
            "classic_faceline_affine_ledger_missing", repr(contract)
        )
    for logical_name, source_name in names.items():
        runtime = CLASSIC_GENERIC_TRANSFORM_CASES[logical_name]
        source = contract[source_name]
        expected_bits = {
            "base_scale_x": f"0x{int(runtime['base_scale_x_bits']):08x}",
            "aspect_scale": f"0x{int(runtime['aspect_scale_bits']):08x}",
            "translation_origin_x": "0x3f800000",
            "translation_origin_y": "0x3f3851ec",
        }
        if (
            source.get("descriptor_case") != runtime["dispatcher_case"]
            or source.get("serialized_offsets") != runtime["serialized_offsets"]
            or source.get("constant_float_bits") != expected_bits
        ):
            raise FacelineCompositionError(
                "classic_faceline_affine_ledger_mismatch", logical_name
            )
    portable = ledger.get("portable_runtime_contract", {})
    if (
        portable.get("generic_contract_key") != CLASSIC_GENERIC_FACELINE_CONTRACT
        or portable.get("generic_affine_cases_exact") != [1, 2, 3, 4]
    ):
        raise FacelineCompositionError(
            "classic_faceline_generic_runtime_contract_mismatch", repr(portable)
        )
    return contract


def _active_records(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FacelineCompositionError("active_parts_unreadable", str(exc)) from exc
    records_list = manifest.get("records")
    if not isinstance(records_list, list):
        raise FacelineCompositionError(
            "active_parts_schema_mismatch", "records is not a list"
        )
    records = {
        str(record.get("logical_name")): record
        for record in records_list
        if isinstance(record, dict)
    }
    if len(records) != len(records_list):
        raise FacelineCompositionError(
            "active_parts_duplicate_logical_name",
            "records do not have unique logical names",
        )
    return manifest, records


def _require_exact_johnny_selection(
    char_info: dict[str, Any],
    active_parts_path: Path,
    ledger: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    target = ledger["targets"]["johnny_thunder"]
    expected_active = target["active_parts"]
    actual_active_hash = _sha256(active_parts_path)
    if actual_active_hash != expected_active["sha256"]:
        raise FacelineCompositionError(
            "active_parts_hash_mismatch",
            f"{active_parts_path} is {actual_active_hash}, expected {expected_active['sha256']}",
        )
    _manifest, records = _active_records(active_parts_path)
    missing = [name for name in FACELINE_LAYER_NAMES if name not in records]
    if missing:
        raise FacelineCompositionError(
            "faceline_active_records_missing", ", ".join(missing)
        )

    expected_fields = target["serialized_fields"]
    for name, expected in expected_fields.items():
        actual = char_info.get(name)
        if int(actual) != int(expected):
            raise FacelineCompositionError(
                "johnny_serialized_field_mismatch",
                f"{name}={actual!r}, expected {expected!r}",
            )

    enabled_layers = [
        name for name in FACELINE_LAYER_NAMES if bool(records[name].get("enabled"))
    ]
    if enabled_layers != ["faceline", "beard_short"]:
        raise FacelineCompositionError(
            "unsupported_enabled_faceline_layer",
            f"Johnny contract supports exactly faceline+beard_short, got {enabled_layers}",
        )

    faceline = records["faceline"]
    if (
        int(faceline.get("selector", -1)) != int(char_info["faceline_type"])
        or faceline.get("category") != "Faceline"
        or not faceline.get("resolved")
    ):
        raise FacelineCompositionError(
            "faceline_base_selection_mismatch", "Faceline14 base selection changed"
        )

    stubble = records["beard_short"]
    expected_stubble = target["active_stubble"]
    checks = {
        "selector": int(stubble.get("selector", -1)),
        "category": stubble.get("category"),
        "record": stubble.get("record"),
        "texture_name": stubble.get("texture_name"),
        "resolved": bool(stubble.get("resolved")),
        "enabled": bool(stubble.get("enabled")),
    }
    for name, actual in checks.items():
        if actual != expected_stubble[name]:
            raise FacelineCompositionError(
                "beard_short_selection_mismatch",
                f"{name}={actual!r}, expected {expected_stubble[name]!r}",
            )
    return records


def _require_exact_spider_man_noir_selection(
    char_info: dict[str, Any],
    active_parts_path: Path,
    ledger: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    target = ledger["targets"]["spider_man_noir"]
    expected_active = target["active_parts"]
    actual_active_hash = _sha256(active_parts_path)
    if actual_active_hash != expected_active["sha256"]:
        raise FacelineCompositionError(
            "active_parts_hash_mismatch",
            f"{active_parts_path} is {actual_active_hash}, expected {expected_active['sha256']}",
        )
    _manifest, records = _active_records(active_parts_path)
    missing = [name for name in FACELINE_LAYER_NAMES if name not in records]
    if missing:
        raise FacelineCompositionError(
            "faceline_active_records_missing", ", ".join(missing)
        )

    for name, expected in target["serialized_fields"].items():
        actual = char_info.get(name)
        if actual is None or int(actual) != int(expected):
            raise FacelineCompositionError(
                "mii0_serialized_field_mismatch",
                f"{name}={actual!r}, expected {expected!r}",
            )

    enabled_layers = [
        name for name in FACELINE_LAYER_NAMES if bool(records[name].get("enabled"))
    ]
    if enabled_layers != ["faceline", "wrinkle_upper"]:
        raise FacelineCompositionError(
            "unsupported_enabled_faceline_layer",
            "Spider-Man Noir contract supports exactly faceline+wrinkle_upper, "
            f"got {enabled_layers}",
        )
    faceline = records["faceline"]
    if (
        int(faceline.get("selector", -1)) != 0
        or faceline.get("category") != "Faceline"
        or faceline.get("record") != "Faceline00"
        or not faceline.get("resolved")
        or not faceline.get("enabled")
    ):
        raise FacelineCompositionError(
            "faceline_base_selection_mismatch", "Faceline00 base selection changed"
        )
    wrinkle = records["wrinkle_upper"]
    expected_wrinkle = {
        "selector": 1,
        "category": "WrinkleUpper",
        "record": "WrinkleUpper00",
        "texture_name": "WrinkleUpper00",
        "resolved": True,
        "enabled": True,
    }
    for name, expected in expected_wrinkle.items():
        actual = (
            bool(wrinkle.get(name))
            if name in {"resolved", "enabled"}
            else wrinkle.get(name)
        )
        if actual != expected:
            raise FacelineCompositionError(
                "wrinkle_upper_selection_mismatch",
                f"{name}={actual!r}, expected {expected!r}",
            )
    return records


def _load_beard_short_mip0(ledger: dict[str, Any]) -> tuple[np.ndarray, Path]:
    source = ledger["composition_contract"]["beard_short07"]["source_texture"]
    path = REPOSITORY / source["path"]
    actual_hash = _sha256(path)
    if actual_hash != source["sha256"]:
        raise FacelineCompositionError(
            "beard_short_texture_hash_mismatch",
            f"{path} is {actual_hash}, expected {source['sha256']}",
        )
    with Image.open(path) as handle:
        rgba = np.asarray(handle.convert("RGBA"), dtype=np.uint8)
    expected_size = tuple(int(value) for value in source["dimensions"])
    if (rgba.shape[1], rgba.shape[0]) != expected_size:
        raise FacelineCompositionError(
            "beard_short_texture_dimensions_mismatch",
            f"got {(rgba.shape[1], rgba.shape[0])}, expected {expected_size}",
        )
    decoded_hash = hashlib.sha256(rgba.tobytes()).hexdigest()
    if decoded_hash != source["decoded_rgba_sha256"]:
        raise FacelineCompositionError(
            "beard_short_decoded_pixels_mismatch",
            f"decoded pixels are {decoded_hash}, expected {source['decoded_rgba_sha256']}",
        )
    if (
        np.any(rgba[..., 0] != 0)
        or np.any(rgba[..., 2] != 0)
        or np.any(rgba[..., 3] != 255)
    ):
        raise FacelineCompositionError(
            "beard_short_channel_contract_mismatch",
            "BeardShort07 must have R=0, B=0, A=255",
        )
    return rgba, path


def _load_wrinkle_upper_selected_mip(
    ledger: dict[str, Any],
) -> tuple[np.ndarray, Path, int]:
    source = ledger["composition_contract"]["wrinkle_upper00"]["source_texture"]
    path = REPOSITORY / source["path"]
    actual_hash = _sha256(path)
    if actual_hash != source["sha256"]:
        raise FacelineCompositionError(
            "wrinkle_upper_texture_hash_mismatch",
            f"{path} is {actual_hash}, expected {source['sha256']}",
        )
    with Image.open(path) as handle:
        rgba = np.asarray(handle.convert("RGBA"), dtype=np.uint8)
    expected_size = tuple(int(value) for value in source["dimensions"])
    if (rgba.shape[1], rgba.shape[0]) != expected_size:
        raise FacelineCompositionError(
            "wrinkle_upper_texture_dimensions_mismatch",
            f"got {(rgba.shape[1], rgba.shape[0])}, expected {expected_size}",
        )
    decoded_hash = hashlib.sha256(rgba.tobytes()).hexdigest()
    if decoded_hash != source["decoded_rgba_sha256"]:
        raise FacelineCompositionError(
            "wrinkle_upper_decoded_pixels_mismatch",
            f"decoded pixels are {decoded_hash}, expected {source['decoded_rgba_sha256']}",
        )
    if (
        not np.array_equal(rgba[..., 0], rgba[..., 1])
        or not np.array_equal(rgba[..., 0], rgba[..., 2])
        or np.any(rgba[..., 3] != 255)
    ):
        raise FacelineCompositionError(
            "wrinkle_upper_channel_contract_mismatch",
            "WrinkleUpper00 must decode as BC4 R=G=B with A=255",
        )
    mip_level = int(source["selected_native_mip"])
    if mip_level != 2:
        raise FacelineCompositionError(
            "wrinkle_upper_selected_mip_mismatch",
            f"expected checked native mip 2, got {mip_level}",
        )
    return rgba, path, mip_level


def _float_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def _float32_fma(
    a: float | np.float32,
    b: float | np.float32,
    c: float | np.float32,
) -> np.float32:
    """Round one scalar multiply-add once, matching the AArch64 FMADD path."""

    return np.float32(
        float(np.float32(a)) * float(np.float32(b)) + float(np.float32(c))
    )


def _float_bits_hex(value: float | np.float32) -> str:
    bits = struct.unpack("<I", struct.pack("<f", np.float32(value)))[0]
    return f"0x{bits:08x}"


def _build_wrinkle_upper_transform(
    char_info: dict[str, Any], contract: dict[str, Any]
) -> tuple[dict[str, np.float32], dict[str, Any]]:
    transform_contract = contract["transform"]
    constants = {
        name: np.float32(_float_from_bits(int(bits, 16)))
        for name, bits in transform_contract["constant_float_bits"].items()
    }
    scale_term = _float32_fma(
        int(char_info["wrinkle_upper_scale"]),
        constants["scale_step"],
        constants["scale_origin"],
    )
    scale_x = np.float32(constants["base_scale_x"] * scale_term)
    aspect_term = _float32_fma(
        int(char_info["wrinkle_upper_aspect"]),
        constants["aspect_step"],
        constants["aspect_origin"],
    )
    scale_y = np.float32(
        np.float32(
            constants["aspect_scale"] * np.float32(scale_x * aspect_term)
        )
        * constants["half"]
    )
    x_step = np.float32(
        np.float32(
            np.float32(int(char_info["wrinkle_upper_x"]))
            * constants["position_step"]
        )
        * constants["translation_step_x"]
    )
    translation_x = np.float32(
        np.float32(constants["translation_origin_x"] + x_step) - scale_x
    )
    y_step = np.float32(
        np.float32(
            np.float32(int(char_info["wrinkle_upper_y"]))
            * constants["position_step"]
        )
        * constants["translation_step_y"]
    )
    translation_y = _float32_fma(
        scale_y,
        constants["translation_height_coefficient"],
        np.float32(constants["translation_origin_y"] + y_step),
    )
    values = {
        "scale_x": scale_x,
        "scale_y": scale_y,
        "translation_x": translation_x,
        "translation_y": translation_y,
    }
    actual_bits = {name: _float_bits_hex(value) for name, value in values.items()}
    if actual_bits != transform_contract["float_bits"]:
        raise FacelineCompositionError(
            "wrinkle_upper_transform_mismatch",
            f"derived bits {actual_bits}, expected {transform_contract['float_bits']}",
        )

    sampler_contract = contract["sampler"]
    rho_x = 256.0 / (FACELINE_WIDTH * float(scale_x))
    rho_y = 256.0 / (FACELINE_HEIGHT * float(scale_y))
    rho = max(rho_x, rho_y)
    biased_lod = min(13.0, max(0.0, float(np.log2(rho)) - 0.7))
    selected_mip = int(np.floor(biased_lod + 0.5))
    if selected_mip != int(sampler_contract["selected_native_mip"]):
        raise FacelineCompositionError(
            "wrinkle_upper_lod_mismatch",
            f"derived mip {selected_mip}, expected {sampler_contract['selected_native_mip']}",
        )
    report = {
        **{name: float(value) for name, value in values.items()},
        "float_bits": actual_bits,
        "rho_x": rho_x,
        "rho_y": rho_y,
        "rho": rho,
        "biased_lod": biased_lod,
        "selected_native_mip": selected_mip,
    }
    return values, report


def _bilinear_sample_normalized(
    source_rgba8: np.ndarray, u: np.ndarray, v: np.ndarray
) -> np.ndarray:
    height, width = source_rgba8.shape[:2]
    source = source_rgba8.astype(np.float64) / 255.0
    x = u * width - 0.5
    y = v * height - 0.5
    x0 = np.floor(x).astype(np.int64)
    y0 = np.floor(y).astype(np.int64)
    fraction_x = x - x0
    fraction_y = y - y0
    # The transformed quad never leaves normalized UV [0,1].  Linear mirror
    # duplicates edge texels there, so clamped integer taps are equivalent.
    x0_clamped = np.clip(x0, 0, width - 1)
    x1_clamped = np.clip(x0 + 1, 0, width - 1)
    y0_clamped = np.clip(y0, 0, height - 1)
    y1_clamped = np.clip(y0 + 1, 0, height - 1)
    return (
        source[y0_clamped, x0_clamped]
        * (1.0 - fraction_x)[..., None]
        * (1.0 - fraction_y)[..., None]
        + source[y0_clamped, x1_clamped]
        * fraction_x[..., None]
        * (1.0 - fraction_y)[..., None]
        + source[y1_clamped, x0_clamped]
        * (1.0 - fraction_x)[..., None]
        * fraction_y[..., None]
        + source[y1_clamped, x1_clamped]
        * fraction_x[..., None]
        * fraction_y[..., None]
    )


def _compose_wrinkle_upper_pixels(
    skin_rgba8: tuple[int, int, int, int],
    source_rgba8: np.ndarray,
    transform: dict[str, np.float32],
    contract: dict[str, Any],
) -> tuple[np.ndarray, dict[str, Any]]:
    scale_x = transform["scale_x"]
    scale_y = transform["scale_y"]
    translation_x = transform["translation_x"]
    translation_y = transform["translation_y"]
    left = _float32_fma(-1.0, scale_x, translation_x)
    right = _float32_fma(1.0, scale_x, translation_x)
    bottom = _float32_fma(-1.0, scale_y, translation_y)
    top = _float32_fma(1.0, scale_y, translation_y)

    pixel_x = np.arange(FACELINE_WIDTH, dtype=np.float64) + 0.5
    pixel_y = np.arange(FACELINE_HEIGHT, dtype=np.float64) + 0.5
    ndc_x = 2.0 * pixel_x / FACELINE_WIDTH - 1.0
    ndc_y = 1.0 - 2.0 * pixel_y / FACELINE_HEIGHT
    u = (ndc_x - float(left)) / float(right - left)
    v = (float(top) - ndc_y) / float(top - bottom)
    uv_x, uv_y = np.meshgrid(u, v)
    covered = (
        (uv_x >= 0.0)
        & (uv_x <= 1.0)
        & (uv_y >= 0.0)
        & (uv_y <= 1.0)
    )
    sampled = _bilinear_sample_normalized(source_rgba8, uv_x, uv_y)
    destination = np.empty(
        (FACELINE_HEIGHT, FACELINE_WIDTH, 4), dtype=np.float64
    )
    destination[:] = np.asarray(skin_rgba8, dtype=np.float64) / 255.0
    source_alpha = sampled[..., 0]
    # MiiMask selector 3 emits straight black RGB and sample.r alpha.  Pipeline
    # index 4 uses SRC_ALPHA for RGB and ONE for alpha.
    destination[covered, :3] *= 1.0 - source_alpha[covered, None]
    destination[covered, 3] = source_alpha[covered] + destination[covered, 3] * (
        1.0 - source_alpha[covered]
    )
    stored = np.rint(np.clip(destination, 0.0, 1.0) * 255.0).astype(np.uint8)
    rows, columns = np.where(covered)
    raster_report = {
        "clip_bounds_float_bits": {
            "left": _float_bits_hex(left),
            "right": _float_bits_hex(right),
            "bottom": _float_bits_hex(bottom),
            "top": _float_bits_hex(top),
        },
        "covered_pixel_count": int(covered.sum()),
        "covered_row_range_inclusive": [int(rows.min()), int(rows.max())],
        "covered_column_range_inclusive": [int(columns.min()), int(columns.max())],
    }
    expected = contract["geometry"]["raster_specialization"]
    for name in (
        "clip_bounds_float_bits",
        "covered_pixel_count",
        "covered_row_range_inclusive",
        "covered_column_range_inclusive",
    ):
        if raster_report[name] != expected[name]:
            raise FacelineCompositionError(
                "wrinkle_upper_raster_contract_mismatch",
                f"{name}={raster_report[name]!r}, expected {expected[name]!r}",
            )
    return stored, raster_report


_compose_wrinkle_upper_pixels_python = _compose_wrinkle_upper_pixels
if native_face_target.BACKEND_AVAILABLE:
    _compose_wrinkle_upper_pixels = native_face_target.compose_wrinkle_upper_pixels


def _build_portable_layer_transform(
    char_info: dict[str, Any], prefix: str
) -> tuple[dict[str, np.float32], dict[str, Any]]:
    """Execute one exact FUN_7101d7025c case-1..4 affine path."""

    case = CLASSIC_GENERIC_TRANSFORM_CASES.get(prefix)
    if case is None:
        raise FacelineCompositionError(
            "classic_faceline_transform_case_unknown", prefix
        )
    base_scale_x = np.float32(_float_from_bits(int(case["base_scale_x_bits"])))
    aspect_scale = np.float32(_float_from_bits(int(case["aspect_scale_bits"])))
    scale_step = np.float32(_float_from_bits(0x3ECCCCCD))
    scale_origin = np.float32(_float_from_bits(0x3F800000))
    aspect_step = np.float32(_float_from_bits(0x3DF5C28F))
    aspect_origin = np.float32(_float_from_bits(0x3F23D70A))
    half = np.float32(_float_from_bits(0x3F000000))
    position_step = np.float32(_float_from_bits(0x3FA51EB8))
    translation_step_x = np.float32(_float_from_bits(0xBD800000))
    translation_step_y = np.float32(_float_from_bits(0xBD000000))
    translation_origin_x = np.float32(_float_from_bits(0x3F800000))
    translation_origin_y = np.float32(_float_from_bits(0x3F3851EC))
    translation_height_coefficient = np.float32(_float_from_bits(0x80000000))
    scale_value = int(char_info[f"{prefix}_scale"])
    aspect_value = int(char_info[f"{prefix}_aspect"])
    x_value = int(char_info[f"{prefix}_x"])
    y_value = int(char_info[f"{prefix}_y"])
    scale_x = np.float32(
        base_scale_x * _float32_fma(scale_value, scale_step, scale_origin)
    )
    aspect_term = _float32_fma(aspect_value, aspect_step, aspect_origin)
    scale_y = np.float32(
        np.float32(aspect_scale * np.float32(scale_x * aspect_term)) * half
    )
    x_step = np.float32(
        np.float32(np.float32(x_value) * position_step) * translation_step_x
    )
    translation_x = np.float32(
        np.float32(translation_origin_x + x_step) - scale_x
    )
    y_step = np.float32(
        np.float32(np.float32(y_value) * position_step) * translation_step_y
    )
    translation_y = _float32_fma(
        scale_y,
        translation_height_coefficient,
        np.float32(translation_origin_y + y_step),
    )
    values = {
        "scale_x": scale_x,
        "scale_y": scale_y,
        "translation_x": translation_x,
        "translation_y": translation_y,
    }
    rho_x = 256.0 / (FACELINE_WIDTH * float(scale_x))
    rho_y = 256.0 / (FACELINE_HEIGHT * float(scale_y))
    rho = max(rho_x, rho_y)
    biased_lod = min(13.0, max(0.0, float(np.log2(rho)) - 0.7))
    selected_mip = int(np.floor(biased_lod + 0.5))
    return values, {
        **{name: float(value) for name, value in values.items()},
        "float_bits": {name: _float_bits_hex(value) for name, value in values.items()},
        "rho_x": rho_x,
        "rho_y": rho_y,
        "biased_lod": biased_lod,
        "selected_native_mip": selected_mip,
        "source_function": f"FUN_7101d7025c case {case['dispatcher_case']}",
        "descriptor_case": int(case["dispatcher_case"]),
        "serialized_offsets": list(case["serialized_offsets"]),
        "constant_addresses": list(case["constant_addresses"]),
        "constant_float_bits": {
            "base_scale_x": f"0x{int(case['base_scale_x_bits']):08x}",
            "aspect_scale": f"0x{int(case['aspect_scale_bits']):08x}",
            "translation_origin_x": "0x3f800000",
            "translation_origin_y": "0x3f3851ec",
        },
    }


def _load_classic_face_mip(
    name: str,
    level: int,
    *,
    expected_logical_name: str | None = None,
    expected_selector: int | None = None,
    expected_resource_flags: dict[str, Any] | None = None,
) -> tuple[np.ndarray, Path]:
    record = None
    for manifest_path in (CLASSIC_FACE_MIPS, SHARED_FACE_MIPS):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        record = manifest.get("textures", {}).get(name)
        if isinstance(record, dict):
            break
    if not isinstance(record, dict):
        raise FacelineCompositionError("classic_faceline_texture_missing", name)
    if expected_logical_name is not None:
        identity = record.get("active_record_identity")
        expected_dimensions = (
            [256, 512] if expected_logical_name == "beard_short" else [256, 256]
        )
        is_single_channel = expected_logical_name in (
            "makeup_upper", "wrinkle_upper", "wrinkle_lower"
        )
        expected_format = "BC4_UNORM" if is_single_channel else "ASTC_4x4_UNORM"
        expected_channels = "R,R,R,1" if is_single_channel else "R,G,B,A"
        expected_mip_count = 10 if expected_logical_name == "beard_short" else 9
        if (
            not isinstance(identity, dict)
            or identity.get("logical_name") != expected_logical_name
            or identity.get("selector") != expected_selector
            or identity.get("record") != name
            or identity.get("texture_name") != name
            or identity.get("resource_flags") != expected_resource_flags
            or record.get("native_dimensions") != expected_dimensions
            or record.get("format") != expected_format
            or record.get("channels") != expected_channels
            or record.get("mip_count") != expected_mip_count
        ):
            raise FacelineCompositionError(
                "classic_faceline_mip_evidence_mismatch",
                f"{expected_logical_name}:{name}",
            )
    levels = record.get("levels")
    matches = [item for item in levels or [] if int(item.get("level", -1)) == level]
    if len(matches) != 1:
        raise FacelineCompositionError("classic_faceline_mip_missing", f"{name} mip {level}")
    item = matches[0]
    path = REPOSITORY / str(item["path"])
    if not path.is_file() or _sha256(path) != item["sha256"]:
        raise FacelineCompositionError("classic_faceline_mip_hash_mismatch", str(path))
    with Image.open(path) as handle:
        rgba = np.asarray(handle.convert("RGBA"), dtype=np.uint8)
    if [rgba.shape[1], rgba.shape[0]] != item["dimensions"]:
        raise FacelineCompositionError("classic_faceline_mip_dimensions_mismatch", name)
    return rgba, path


def _layer_sample(
    source_rgba8: np.ndarray, transform: dict[str, np.float32]
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    left = _float32_fma(-1.0, transform["scale_x"], transform["translation_x"])
    right = _float32_fma(1.0, transform["scale_x"], transform["translation_x"])
    bottom = _float32_fma(-1.0, transform["scale_y"], transform["translation_y"])
    top = _float32_fma(1.0, transform["scale_y"], transform["translation_y"])
    pixel_x = np.arange(FACELINE_WIDTH, dtype=np.float64) + 0.5
    pixel_y = np.arange(FACELINE_HEIGHT, dtype=np.float64) + 0.5
    ndc_x = 2.0 * pixel_x / FACELINE_WIDTH - 1.0
    ndc_y = 1.0 - 2.0 * pixel_y / FACELINE_HEIGHT
    u = (ndc_x - float(left)) / float(right - left)
    v = (float(top) - ndc_y) / float(top - bottom)
    uv_x, uv_y = np.meshgrid(u, v)
    covered = (uv_x >= 0.0) & (uv_x <= 1.0) & (uv_y >= 0.0) & (uv_y <= 1.0)
    sampled = _bilinear_sample_normalized(source_rgba8, uv_x, uv_y)
    rows, columns = np.where(covered)
    return sampled, covered, {
        "clip_bounds_float_bits": {
            "left": _float_bits_hex(left), "right": _float_bits_hex(right),
            "bottom": _float_bits_hex(bottom), "top": _float_bits_hex(top),
        },
        "covered_pixel_count": int(covered.sum()),
        "covered_row_range_inclusive": [int(rows.min()), int(rows.max())],
        "covered_column_range_inclusive": [int(columns.min()), int(columns.max())],
    }


def _store_rgba8_and_reload(destination: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Model the RGBA8-UNORM render-target store between ordered title draws."""

    stored = np.rint(np.clip(destination, 0.0, 1.0) * 255.0).astype(np.uint8)
    return stored.astype(np.float64) / 255.0, stored


def _require_generic_classic_selection(
    char_info: dict[str, Any],
    active_parts_path: Path,
    classic_resource_signature_records: dict[str, dict[str, Any]] | None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Validate the exact Parts records admitted by the generic contract."""

    _manifest, records = _active_records(active_parts_path)
    missing = [name for name in FACELINE_LAYER_NAMES if name not in records]
    if missing:
        raise FacelineCompositionError(
            "classic_faceline_record_inventory_incomplete", repr(missing)
        )
    projections: dict[str, dict[str, Any] | None] = {}
    for name in FACELINE_LAYER_NAMES:
        try:
            projections[name] = _validate_classic_signature_record(
                name, records[name], classic_resource_signature_records
            )
        except ValueError as exc:
            raise FacelineCompositionError(
                "classic_faceline_signature_projection_mismatch", f"{name}: {exc}"
            ) from exc
    enabled = [name for name in FACELINE_LAYER_NAMES if records[name].get("enabled")]
    if not enabled or enabled[0] != "faceline":
        raise FacelineCompositionError(
            "classic_faceline_base_not_enabled", repr(enabled)
        )
    unsupported = [
        name
        for name in enabled
        if name not in ("faceline", "beard") and name not in CLASSIC_GENERIC_LAYER_ORDER
    ]
    if unsupported:
        raise FacelineCompositionError(
            "unsupported_enabled_faceline_layer", repr(unsupported)
        )
    ordered = [name for name in CLASSIC_GENERIC_LAYER_ORDER if name in enabled]

    faceline = records["faceline"]
    try:
        faceline_selector = int(faceline["selector"])
        serialized_faceline_selector = int(char_info["faceline_type"])
    except (KeyError, TypeError, ValueError) as exc:
        raise FacelineCompositionError(
            "classic_faceline_base_selection_missing", str(exc)
        ) from exc
    if (
        faceline.get("category") != "Faceline"
        or faceline.get("is_nothing") is not False
        or faceline_selector != serialized_faceline_selector
        or projections["faceline"] is not None
        or faceline.get("resolved") is not True
    ):
        raise FacelineCompositionError(
            "classic_faceline_base_selection_mismatch",
            f"active={faceline_selector}, serialized={serialized_faceline_selector}",
        )

    selector_field = {
        "makeup_lower": "makeup_lower_type",
        "makeup_upper": "makeup_upper_type",
        "wrinkle_upper": "wrinkle_upper_type",
        "wrinkle_lower": "wrinkle_lower_type",
        "beard_short": "stubble_type",
    }
    category = {
        "makeup_lower": "MakeLower",
        "makeup_upper": "MakeUpper",
        "wrinkle_upper": "WrinkleUpper",
        "wrinkle_lower": "WrinkleLower",
        "beard_short": "BeardShort",
    }
    for logical_name in CLASSIC_GENERIC_LAYER_ORDER:
        record = records[logical_name]
        try:
            selector = int(record["selector"])
            serialized_selector = int(char_info[selector_field[logical_name]])
        except (KeyError, TypeError, ValueError) as exc:
            raise FacelineCompositionError(
                "classic_faceline_selection_outside_contract", logical_name
            ) from exc
        if selector != serialized_selector:
            raise FacelineCompositionError(
                "classic_faceline_serialized_selection_mismatch",
                f"{logical_name}: active={selector}, serialized={serialized_selector}",
            )
        if logical_name not in ordered:
            projection = projections[logical_name]
            if (
                isinstance(projection, dict)
                and projection.get("kind") == "title_lookup_empty"
            ):
                continue
            expected_name, expected_flags = CLASSIC_GENERIC_NOTHING_RECORDS[
                logical_name
            ]
            if (
                selector != 0
                or not isinstance(projection, dict)
                or projection.get("kind") != "exact_parts_nothing"
                or record.get("category") != category[logical_name]
                or record.get("record") != expected_name
                or record.get("texture_name") is not None
                or record.get("resource_flags") != expected_flags
                or record.get("is_nothing") is not True
            ):
                raise FacelineCompositionError(
                    "classic_faceline_disabled_selection_mismatch", logical_name
                )
            continue
        if projections[logical_name] is not None or record.get("resolved") is not True:
            raise FacelineCompositionError(
                "classic_faceline_active_projection_mismatch", logical_name
            )
        try:
            expected_name, expected_flags = CLASSIC_GENERIC_RECORDS[logical_name][
                selector
            ]
        except KeyError as exc:
            raise FacelineCompositionError(
                "classic_faceline_selection_outside_contract", logical_name
            ) from exc
        if (
            record.get("category") != category[logical_name]
            or record.get("record") != expected_name
            or record.get("texture_name") != expected_name
            or record.get("resource_flags") != expected_flags
            or record.get("is_nothing") is not False
        ):
            raise FacelineCompositionError(
                "classic_faceline_selection_mismatch",
                f"{logical_name}:{selector}:{record.get('record')!r}",
            )
    return records, ordered


def compose_classic_generic_faceline_target(
    char_info: dict[str, Any],
    active_parts_path: Path,
    color_table_path: Path,
    classic_resource_signature_records: dict[str, dict[str, Any]] | None,
) -> FacelineCompositionResult | None:
    """Compose every title-ordered classic generated-faceline sprite layer.

    This is a generic resource contract, not a per-Mii pixel fixture.  Every
    selected texture, resource flag, transform, shader selector, blend mode,
    and inter-draw RGBA8 store is checked locally before execution.
    """

    evidence_ledger = _load_checked_ledger(DEFAULT_LEDGER)
    _validate_generic_affine_ledger(evidence_ledger)
    records, ordered = _require_generic_classic_selection(
        char_info, active_parts_path, classic_resource_signature_records
    )
    if not ordered:
        # The v2 contract includes an exact empty draw list.  No generated
        # target is allocated or bound in that case; mt_Head follows its
        # checked skin-color fallback path.
        return None
    if not color_table_path.is_file() or _sha256(color_table_path) != COLOR_TABLE_SHA256:
        raise FacelineCompositionError(
            "classic_faceline_color_table_mismatch", str(color_table_path)
        )
    try:
        colors = json.loads(color_table_path.read_text(encoding="utf-8"))
        skin_selector = int(char_info["faceline_color"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise FacelineCompositionError(
            "classic_faceline_color_input_invalid", str(exc)
        ) from exc
    skin = _resolve_faceline_color(colors, skin_selector)
    destination = np.empty((FACELINE_HEIGHT, FACELINE_WIDTH, 4), dtype=np.float64)
    destination[:] = np.asarray(skin, dtype=np.float64) / 255.0
    stored = np.broadcast_to(
        np.asarray(skin, dtype=np.uint8),
        (FACELINE_HEIGHT, FACELINE_WIDTH, 4),
    ).copy()
    layer_reports: list[dict[str, Any]] = []

    for logical_name in ordered:
        record = records[logical_name]
        selector = int(record["selector"])
        texture_name, resource_flags = CLASSIC_GENERIC_RECORDS[logical_name][selector]
        if logical_name != "beard_short":
            transform, transform_report = _build_portable_layer_transform(
                char_info, logical_name
            )
            mip_level = int(transform_report["selected_native_mip"])
            source_rgba8, source_path = _load_classic_face_mip(
                texture_name,
                mip_level,
                expected_logical_name=logical_name,
                expected_selector=selector,
                expected_resource_flags=resource_flags,
            )
            sampled, covered, raster_report = _layer_sample(source_rgba8, transform)
        else:
            mip_level = 0
            source_rgba8, source_path = _load_classic_face_mip(
                texture_name,
                mip_level,
                expected_logical_name=logical_name,
                expected_selector=selector,
                expected_resource_flags=resource_flags,
            )
            if source_rgba8.shape != (
                FACELINE_HEIGHT * 2,
                FACELINE_WIDTH * 2,
                4,
            ):
                raise FacelineCompositionError(
                    "beard_short_sampling_ratio_changed", texture_name
                )
            sampled = (
                source_rgba8.reshape(FACELINE_HEIGHT, 2, FACELINE_WIDTH, 2, 4)
                .astype(np.float64)
                .mean(axis=(1, 3))
                / 255.0
            )
            covered = np.ones((FACELINE_HEIGHT, FACELINE_WIDTH), dtype=bool)
            transform_report = {
                "kind": "identity fullscreen title slot",
                "source_function": "FUN_7101d7025c case 5",
                "selected_native_mip": 0,
                "sampler": "MiiSampler; centered 2x2 mip0 bilinear footprint",
            }
            raster_report = {
                "covered_pixel_count": FACELINE_WIDTH * FACELINE_HEIGHT,
                "covered_row_range_inclusive": [0, FACELINE_HEIGHT - 1],
                "covered_column_range_inclusive": [0, FACELINE_WIDTH - 1],
            }

        common_report: dict[str, Any] = {
            "logical_name": logical_name,
            "selector": selector,
            "record": texture_name,
            "resource_flags": resource_flags,
            "texture": str(source_path.relative_to(REPOSITORY)).replace("\\", "/"),
            "texture_sha256": _sha256(source_path),
            "source_mip_level": mip_level,
            "transform": transform_report,
            "raster": raster_report,
        }
        if logical_name == "makeup_lower":
            serialized_color_selector = int(char_info["makeup_lower_color"])
            effective_color_selector = CLASSIC_NON_SELECTABLE_COLOR_FALLBACKS.get(
                (logical_name, texture_name), serialized_color_selector
            )
            c1 = np.asarray(
                _resolve_faceline_color(colors, effective_color_selector),
                dtype=np.float64,
            ) / 255.0
            # Selector 6: r*C1 + g*(C2-r*C1), with title C2=zero.
            source = sampled[..., 0, None] * (1.0 - sampled[..., 1, None]) * c1
            destination[covered] = source[covered] + destination[covered] * (
                1.0 - source[..., 3][covered, None]
            )
            common_report.update(
                {
                    "shader_selector": 6,
                    "shader_equation": "sample.r*C1 + sample.g*(C2 - sample.r*C1)",
                    "shader_c1": "effective MakeLower color",
                    "shader_c2": [0.0, 0.0, 0.0, 0.0],
                    "serialized_color_selector": serialized_color_selector,
                    "effective_color_selector": effective_color_selector,
                    "non_selectable_color_fallback": (
                        "CommonColor[8]"
                        if effective_color_selector != serialized_color_selector
                        else None
                    ),
                    "blend": "premultiplied source-over (ONE, ONE_MINUS_SRC_ALPHA)",
                }
            )
        elif logical_name == "makeup_upper":
            serialized_color_selector = int(char_info["makeup_upper_color"])
            c1 = np.asarray(
                _resolve_faceline_color(colors, serialized_color_selector),
                dtype=np.float64,
            ) / 255.0
            source_alpha = sampled[..., 0]
            destination[covered, :3] = (
                c1[:3] * source_alpha[covered, None]
                + destination[covered, :3] * (1.0 - source_alpha[covered, None])
            )
            destination[covered, 3] = source_alpha[covered] + destination[
                covered, 3
            ] * (1.0 - source_alpha[covered])
            common_report.update(
                {
                    "shader_selector": 3,
                    "shader_equation": "rgb=C1.rgb; alpha=sample.r",
                    "shader_c1": "serialized MakeUpper color",
                    "serialized_color_selector": serialized_color_selector,
                    "blend": "straight-alpha RGB source-over; source-over alpha",
                }
            )
        elif logical_name in ("wrinkle_upper", "wrinkle_lower"):
            if (
                np.any(source_rgba8[..., 0] != source_rgba8[..., 1])
                or np.any(source_rgba8[..., 0] != source_rgba8[..., 2])
                or np.any(source_rgba8[..., 3] != 255)
            ):
                raise FacelineCompositionError(
                    "wrinkle_channel_contract_mismatch", texture_name
                )
            source_alpha = sampled[..., 0]
            # Selector 3 emits renderer-global WrinkleColor (checked default
            # black) as straight RGB and sample.r as alpha.
            destination[covered, :3] *= 1.0 - source_alpha[covered, None]
            destination[covered, 3] = source_alpha[covered] + destination[
                covered, 3
            ] * (1.0 - source_alpha[covered])
            common_report.update(
                {
                    "shader_selector": 3,
                    "shader_equation": "rgb=C1.rgb; alpha=sample.r",
                    "shader_c1_rgb": [0.0, 0.0, 0.0],
                    "shader_c1_source": "renderer-global WrinkleColor constructor default",
                    "blend": "straight-alpha RGB source-over; source-over alpha",
                }
            )
        else:
            serialized_color_selector = int(char_info["stubble_color"])
            effective_color_selector = CLASSIC_NON_SELECTABLE_COLOR_FALLBACKS.get(
                (logical_name, texture_name), serialized_color_selector
            )
            c1 = np.asarray(
                [_float_from_bits(bits) for bits in BEARD_SHORT_C1_FLOAT_BITS],
                dtype=np.float64,
            )
            c2 = np.asarray(
                _resolve_faceline_color(colors, effective_color_selector),
                dtype=np.float64,
            ) / 255.0
            # Full selector-6 equation is required for every BeardShort mask;
            # no green-only channel specialization is assumed.
            source = sampled[..., 0, None] * c1 + sampled[..., 1, None] * (
                c2 - sampled[..., 0, None] * c1
            )
            destination = source + destination * (1.0 - source[..., 3, None])
            common_report.update(
                {
                    "shader_selector": 6,
                    "shader_equation": "sample.r*C1 + sample.g*(C2 - sample.r*C1)",
                    "shader_c1_float_bits": [
                        f"0x{bits:08x}" for bits in BEARD_SHORT_C1_FLOAT_BITS
                    ],
                    "shader_c2": "effective BeardShort color",
                    "serialized_color_selector": serialized_color_selector,
                    "effective_color_selector": effective_color_selector,
                    "non_selectable_color_fallback": (
                        "CommonColor[8]"
                        if effective_color_selector != serialized_color_selector
                        else None
                    ),
                    "blend": "premultiplied source-over (ONE, ONE_MINUS_SRC_ALPHA)",
                }
            )

        # Each layer is a separate title draw into RGBA8 UNORM.  Reloading the
        # stored bytes here prevents an accidental higher-precision fusion of
        # ordered combinations.
        destination, stored = _store_rgba8_and_reload(destination)
        common_report["rgba8_store_after_draw"] = True
        layer_reports.append(common_report)

    stored_hash = hashlib.sha256(stored.tobytes()).hexdigest()
    return FacelineCompositionResult(
        image=Image.fromarray(stored, mode="RGBA"),
        report={
            "status": "source_backed_generic_classic_faceline_target",
            "contract_key": CLASSIC_GENERIC_FACELINE_CONTRACT,
            "dimensions": [FACELINE_WIDTH, FACELINE_HEIGHT],
            "stored_rgba_sha256": stored_hash,
            "stored_hash_scope": (
                "portable ordered RGBA8 result of checked native mips, title transforms, "
                "shader equations, non-selectable-color fallback, and blend state"
            ),
            "skin_color_selector": skin_selector,
            "color_table_sha256": COLOR_TABLE_SHA256,
            "affine_evidence": {
                "path": str(DEFAULT_LEDGER.relative_to(REPOSITORY)).replace("\\", "/"),
                "sha256": _sha256(DEFAULT_LEDGER),
                "descriptor_cases": [1, 2, 3, 4],
                "source_function": "FUN_7101d7025c",
            },
            "title_draw_order": list(CLASSIC_GENERIC_LAYER_ORDER),
            "executed_draw_order": ordered,
            "target_binding": "mt_Head (fallback mt_faceline) _a0 -> Head GameAll816",
            "mask_user0_binding": False,
            "layers": layer_reports,
            "title_final_pixel_equivalence_claimed": False,
            "fail_closed_layers": [
                "mustache",
                "mole",
                "eye accessories",
            ],
        },
    )


def compose_classic_average_faceline_target(
    char_info: dict[str, Any], active_parts_path: Path, color_table_path: Path
) -> FacelineCompositionResult:
    """Compose the average Mii's exact MakeLower00 then WrinkleUpper00 target."""

    _manifest, records = _active_records(active_parts_path)
    enabled = [name for name in FACELINE_LAYER_NAMES if records.get(name, {}).get("enabled")]
    if enabled != ["faceline", "makeup_lower", "wrinkle_upper"]:
        raise FacelineCompositionError("unsupported_enabled_faceline_layer", repr(enabled))
    expected = {
        "makeup_lower": (1, "MakeLower00", "MakeLower00"),
        "wrinkle_upper": (1, "WrinkleUpper00", "WrinkleUpper00"),
    }
    for logical_name, (selector, record_name, texture_name) in expected.items():
        record = records[logical_name]
        if (int(record.get("selector", -1)), record.get("record"), record.get("texture_name")) != (
            selector, record_name, texture_name
        ):
            raise FacelineCompositionError("classic_faceline_selection_mismatch", logical_name)

    colors = json.loads(color_table_path.read_text(encoding="utf-8"))
    skin = _resolve_faceline_color(colors, int(char_info["faceline_color"]))
    destination = np.empty((FACELINE_HEIGHT, FACELINE_WIDTH, 4), dtype=np.float64)
    destination[:] = np.asarray(skin, dtype=np.float64) / 255.0
    layer_reports: list[dict[str, Any]] = []

    makeup_transform, makeup_report = _build_portable_layer_transform(char_info, "makeup_lower")
    makeup_source, makeup_path = _load_classic_face_mip(
        "MakeLower00", int(makeup_report["selected_native_mip"])
    )
    sampled, covered, raster = _layer_sample(makeup_source, makeup_transform)
    makeup_color = np.asarray(
        _resolve_faceline_color(colors, int(char_info["makeup_lower_color"])), dtype=np.float64
    ) / 255.0
    # MiiMask selector 6 with C1=MakeLower color and C2=zero:
    # output = sample.r*C1 + sample.g*(C2-sample.r*C1). Pipeline 5 is
    # premultiplied source-over.
    source = sampled[..., 0, None] * (1.0 - sampled[..., 1, None]) * makeup_color
    destination[covered] = source[covered] + destination[covered] * (
        1.0 - source[..., 3][covered, None]
    )
    layer_reports.append({
        "logical_name": "makeup_lower", "texture": str(makeup_path.relative_to(REPOSITORY)).replace("\\", "/"),
        "shader_selector": 6, "pipeline": "premultiplied source-over", "transform": makeup_report, "raster": raster,
    })

    wrinkle_transform, wrinkle_report = _build_portable_layer_transform(char_info, "wrinkle_upper")
    wrinkle_source, wrinkle_path = _load_classic_face_mip(
        "WrinkleUpper00", int(wrinkle_report["selected_native_mip"])
    )
    sampled, covered, raster = _layer_sample(wrinkle_source, wrinkle_transform)
    alpha = sampled[..., 0]
    destination[covered, :3] *= 1.0 - alpha[covered, None]
    destination[covered, 3] = alpha[covered] + destination[covered, 3] * (1.0 - alpha[covered])
    layer_reports.append({
        "logical_name": "wrinkle_upper", "texture": str(wrinkle_path.relative_to(REPOSITORY)).replace("\\", "/"),
        "shader_selector": 3, "pipeline": "straight-alpha source-over", "transform": wrinkle_report, "raster": raster,
    })

    stored = np.rint(np.clip(destination, 0.0, 1.0) * 255.0).astype(np.uint8)
    stored_hash = hashlib.sha256(stored.tobytes()).hexdigest()
    return FacelineCompositionResult(
        image=Image.fromarray(stored, mode="RGBA"),
        report={
            "status": "source_backed_make_lower00_wrinkle_upper00_faceline_target",
            "dimensions": [FACELINE_WIDTH, FACELINE_HEIGHT],
            "stored_rgba_sha256": stored_hash,
            "stored_hash_scope": "portable RGBA8 result of checked native mips, title affine, shader equations, order, and blend",
            "target_binding": "mt_Head (fallback mt_faceline) _a0 -> Head GameAll816",
            "mask_user0_binding": False,
            "layers": layer_reports,
            "title_final_pixel_equivalence_claimed": False,
        },
    )


def compose_classic_green_stubble_faceline_target(
    char_info: dict[str, Any], active_parts_path: Path, color_table_path: Path
) -> FacelineCompositionResult:
    """Compose classic BeardShort02/03 using only their proven green mask.

    FUN_7101d7025c case 5 uses the identity slot transform, MiiMask selector 6,
    and premultiplied source-over.  These two classic textures have exact
    R=0/B=0/A=255 channels, so the unresolved C1 term cancels and the complete
    output depends only on G and the serialized stubble common color.
    """

    _manifest, records = _active_records(active_parts_path)
    enabled = [
        name for name in FACELINE_LAYER_NAMES if records.get(name, {}).get("enabled")
    ]
    if enabled != ["faceline", "beard_short"]:
        raise FacelineCompositionError(
            "unsupported_enabled_faceline_layer", repr(enabled)
        )
    stubble = records["beard_short"]
    selector = int(stubble.get("selector", -1))
    expected_name = {3: "BeardShort02", 4: "BeardShort03"}.get(selector)
    if (
        expected_name is None
        or stubble.get("record") != expected_name
        or stubble.get("texture_name") != expected_name
    ):
        raise FacelineCompositionError(
            "classic_green_stubble_selection_mismatch",
            f"selector={selector}, record={stubble.get('record')!r}",
        )

    source_rgba8, source_path = _load_classic_face_mip(expected_name, 0)
    if (
        source_rgba8.shape != (FACELINE_HEIGHT * 2, FACELINE_WIDTH * 2, 4)
        or np.any(source_rgba8[..., 0] != 0)
        or np.any(source_rgba8[..., 2] != 0)
        or np.any(source_rgba8[..., 3] != 255)
    ):
        raise FacelineCompositionError(
            "classic_green_stubble_channel_contract_mismatch", expected_name
        )
    sample = (
        source_rgba8.reshape(FACELINE_HEIGHT, 2, FACELINE_WIDTH, 2, 4)
        .astype(np.float64)
        .mean(axis=(1, 3))
        / 255.0
    )
    colors = json.loads(color_table_path.read_text(encoding="utf-8"))
    skin = np.asarray(
        _resolve_faceline_color(colors, int(char_info["faceline_color"])),
        dtype=np.float64,
    ) / 255.0
    stubble_color = np.asarray(
        _resolve_faceline_color(colors, int(char_info["stubble_color"])),
        dtype=np.float64,
    ) / 255.0
    # With sample.r=0, selector 6 reduces exactly to sample.g*C2.
    source = sample[..., 1, None] * stubble_color
    destination = np.empty(
        (FACELINE_HEIGHT, FACELINE_WIDTH, 4), dtype=np.float64
    )
    destination[:] = skin
    destination = source + destination * (1.0 - source[..., 3, None])
    stored = np.rint(np.clip(destination, 0.0, 1.0) * 255.0).astype(np.uint8)
    stored_hash = hashlib.sha256(stored.tobytes()).hexdigest()
    return FacelineCompositionResult(
        image=Image.fromarray(stored, mode="RGBA"),
        report={
            "status": "source_backed_classic_green_stubble_faceline_target",
            "dimensions": [FACELINE_WIDTH, FACELINE_HEIGHT],
            "stored_rgba_sha256": stored_hash,
            "stored_hash_scope": (
                "RGBA8 result of exact native mip0, identity 2x downsample, "
                "selector-6 green-mask specialization, and premultiplied source-over"
            ),
            "target_binding": "mt_Head (fallback mt_faceline) _a0 -> Head GameAll816",
            "mask_user0_binding": False,
            "layers": [
                {
                    "logical_name": "beard_short",
                    "selector": selector,
                    "texture": str(source_path.relative_to(REPOSITORY)).replace("\\", "/"),
                    "source_mip_level": 0,
                    "shader_selector": 6,
                    "pipeline": "premultiplied source-over",
                    "cancelled_unresolved_term": "sample.r*C1 is identically zero",
                }
            ],
            "title_final_pixel_equivalence_claimed": False,
        },
    )
def _compose_johnny_pixels(
    skin_rgba8: tuple[int, int, int, int], source_rgba8: np.ndarray, ledger: dict[str, Any]
) -> np.ndarray:
    """Execute selector 6, pipeline 5, and RGBA8-UNORM storage conversion."""

    # Fullscreen identity plus the constructor's exact Y flip maps each target
    # pixel to a centered 2x2 footprint in native mip 0.  LOD 0.3 selects mip 0
    # with MiiSampler's nearest-mip rule.
    if source_rgba8.shape != (FACELINE_HEIGHT * 2, FACELINE_WIDTH * 2, 4):
        raise FacelineCompositionError(
            "beard_short_sampling_ratio_changed",
            f"source array shape is {source_rgba8.shape}",
        )
    sample = source_rgba8.reshape(
        FACELINE_HEIGHT, 2, FACELINE_WIDTH, 2, 4
    ).astype(np.float64).mean(axis=(1, 3)) / 255.0

    constants = ledger["composition_contract"]["beard_short07"]["shader_constants"]
    c1 = np.asarray(
        [_float_from_bits(int(value, 16)) for value in constants["c1_float_bits"]],
        dtype=np.float64,
    )
    c2 = np.asarray(constants["c2_rgba"], dtype=np.float64)
    # Exact selector-6 SASS: r*C1 + g*(C2-r*C1), including alpha.
    source_output = (
        sample[..., 0, None] * c1
        + sample[..., 1, None]
        * (c2 - sample[..., 0, None] * c1)
    )

    destination = np.empty(
        (FACELINE_HEIGHT, FACELINE_WIDTH, 4), dtype=np.float64
    )
    destination[:] = np.asarray(skin_rgba8, dtype=np.float64) / 255.0
    source_alpha = source_output[..., 3, None]
    # Pipeline descriptor 5 selects ONE / ONE_MINUS_SRC_ALPHA for RGB and A.
    blended = source_output + destination * (1.0 - source_alpha)
    return np.rint(np.clip(blended, 0.0, 1.0) * 255.0).astype(np.uint8)


_compose_johnny_pixels_python = _compose_johnny_pixels
if native_face_target.BACKEND_AVAILABLE:
    _compose_johnny_pixels = native_face_target.compose_johnny_pixels


def compose_johnny_faceline_target(
    char_info: dict[str, Any],
    active_parts_path: Path,
    color_table_path: Path,
    *,
    share_mii_sha256: str,
    ledger_path: Path = DEFAULT_LEDGER,
) -> FacelineCompositionResult:
    """Build Johnny's exact 128x256 stored faceline target or fail closed."""

    if share_mii_sha256 != JOHNNY_SHARE_MII_SHA256:
        raise FacelineCompositionError(
            "unsupported_faceline_target",
            f"only Johnny {JOHNNY_SHARE_MII_SHA256} is executable, got {share_mii_sha256}",
        )
    ledger = _load_checked_ledger(ledger_path)
    _require_exact_johnny_selection(char_info, active_parts_path, ledger)

    color_source = ledger["sources"]["color_table"]
    actual_color_hash = _sha256(color_table_path)
    if actual_color_hash != color_source["sha256"]:
        raise FacelineCompositionError(
            "color_table_hash_mismatch",
            f"{color_table_path} is {actual_color_hash}, expected {color_source['sha256']}",
        )
    colors = json.loads(color_table_path.read_text(encoding="utf-8"))
    skin_rgba8 = _resolve_faceline_color(colors, int(char_info["faceline_color"]))
    if list(skin_rgba8) != ledger["targets"]["johnny_thunder"]["skin_rgba8"]:
        raise FacelineCompositionError(
            "johnny_skin_color_mismatch",
            f"resolved {skin_rgba8}, expected ledger skin color",
        )
    stubble_rgba8 = _resolve_faceline_color(colors, int(char_info["stubble_color"]))
    if stubble_rgba8 != (0, 0, 0, 255):
        raise FacelineCompositionError(
            "johnny_stubble_color_mismatch",
            f"CommonColor[{char_info['stubble_color']}] resolved to {stubble_rgba8}",
        )

    source_rgba8, source_path = _load_beard_short_mip0(ledger)
    stored = _compose_johnny_pixels(skin_rgba8, source_rgba8, ledger)
    stored_hash = hashlib.sha256(stored.tobytes()).hexdigest()
    expected_hash = ledger["portable_runtime_contract"]["targets"][
        JOHNNY_SHARE_MII_SHA256
    ]["deterministic_portable_stored_rgba_sha256"]
    if stored_hash != expected_hash:
        raise FacelineCompositionError(
            "faceline_output_hash_mismatch",
            f"stored bytes are {stored_hash}, expected {expected_hash}",
        )

    image = Image.fromarray(stored, mode="RGBA")
    return FacelineCompositionResult(
        image=image,
        report={
            "status": "exact_source_backed_beard_short07_faceline_target",
            "share_mii_sha256": share_mii_sha256,
            "dimensions": [FACELINE_WIDTH, FACELINE_HEIGHT],
            "stored_rgba_sha256": stored_hash,
            "stored_hash_scope": ledger["portable_runtime_contract"]["filter_quantization_boundary"],
            "target_format": "RGBA8_SRGB storage / RGBA8_UNORM write view",
            "framebuffer_srgb_conversion": False,
            "source_texture": str(source_path.relative_to(REPOSITORY)).replace("\\", "/"),
            "source_mip_level": 0,
            "shader_archive": "MiiMask.bnsh",
            "shader_selector": 6,
            "blend": "premultiplied source-over",
            "target_binding": "mt_Head (fallback mt_faceline) _a0 -> Head GameAll816",
            "mask_user0_binding": False,
            "ledger_path": str(ledger_path.relative_to(REPOSITORY)).replace("\\", "/"),
            "ledger_sha256": _sha256(ledger_path),
            "fail_closed_boundaries": ledger["fail_closed_boundaries"],
        },
    )


def compose_spider_man_noir_faceline_target(
    char_info: dict[str, Any],
    active_parts_path: Path,
    color_table_path: Path,
    *,
    share_mii_sha256: str,
    ledger_path: Path = DEFAULT_LEDGER,
) -> FacelineCompositionResult:
    """Build Spider-Man Noir's exact local WrinkleUpper00 faceline target."""

    if share_mii_sha256 != SPIDER_MAN_NOIR_SHARE_MII_SHA256:
        raise FacelineCompositionError(
            "unsupported_faceline_target",
            "Spider-Man Noir entry requires "
            f"{SPIDER_MAN_NOIR_SHARE_MII_SHA256}, got {share_mii_sha256}",
        )
    ledger = _load_checked_ledger(ledger_path)
    _require_exact_spider_man_noir_selection(
        char_info, active_parts_path, ledger
    )

    color_source = ledger["sources"]["color_table"]
    actual_color_hash = _sha256(color_table_path)
    if actual_color_hash != color_source["sha256"]:
        raise FacelineCompositionError(
            "color_table_hash_mismatch",
            f"{color_table_path} is {actual_color_hash}, expected {color_source['sha256']}",
        )
    colors = json.loads(color_table_path.read_text(encoding="utf-8"))
    skin_rgba8 = _resolve_faceline_color(colors, int(char_info["faceline_color"]))
    expected_skin = tuple(ledger["targets"]["spider_man_noir"]["skin_rgba8"])
    if skin_rgba8 != expected_skin:
        raise FacelineCompositionError(
            "mii0_skin_color_mismatch",
            f"resolved {skin_rgba8}, expected {expected_skin}",
        )

    contract = ledger["composition_contract"]["wrinkle_upper00"]
    constants = contract["shader_constants"]
    if (
        constants["selected_variant"]
        != "WrinkleColor (not WrinkleColorWhenBlackSkin)"
        or constants["system_param_override_keys_present"] != []
        or constants["constructor_default_rgb"] != [0.0, 0.0, 0.0]
    ):
        raise FacelineCompositionError(
            "wrinkle_upper_color_contract_mismatch",
            "renderer-global WrinkleColor is no longer the checked black default",
        )

    transform, transform_report = _build_wrinkle_upper_transform(
        char_info, contract
    )
    source_rgba8, source_path, mip_level = _load_wrinkle_upper_selected_mip(
        ledger
    )
    stored, raster_report = _compose_wrinkle_upper_pixels(
        skin_rgba8, source_rgba8, transform, contract
    )
    stored_hash = hashlib.sha256(stored.tobytes()).hexdigest()
    expected_hash = ledger["portable_runtime_contract"]["targets"][
        SPIDER_MAN_NOIR_SHARE_MII_SHA256
    ]["deterministic_portable_stored_rgba_sha256"]
    if stored_hash != expected_hash:
        raise FacelineCompositionError(
            "faceline_output_hash_mismatch",
            f"stored bytes are {stored_hash}, expected {expected_hash}",
        )

    return FacelineCompositionResult(
        image=Image.fromarray(stored, mode="RGBA"),
        report={
            "status": "exact_source_backed_wrinkle_upper00_local_faceline_target",
            "share_mii_sha256": share_mii_sha256,
            "dimensions": [FACELINE_WIDTH, FACELINE_HEIGHT],
            "stored_rgba_sha256": stored_hash,
            "stored_hash_scope": ledger["portable_runtime_contract"]["filter_quantization_boundary"],
            "target_format": "RGBA8_SRGB storage / RGBA8_UNORM write view",
            "framebuffer_srgb_conversion": False,
            "source_texture": str(source_path.relative_to(REPOSITORY)).replace(
                "\\", "/"
            ),
            "source_mip_level": mip_level,
            "shader_archive": "MiiMask.bnsh",
            "shader_selector": 3,
            "wrinkle_color_namespace": "Mii renderer-global WrinkleColor",
            "wrinkle_color_rgb": [0.0, 0.0, 0.0],
            "transform": transform_report,
            "raster": raster_report,
            "blend": "straight-alpha RGB source-over; source-over alpha",
            "target_binding": "mt_Head (fallback mt_faceline) _a0 -> Head GameAll816",
            "mask_user0_binding": False,
            "ledger_path": str(ledger_path.relative_to(REPOSITORY)).replace(
                "\\", "/"
            ),
            "ledger_sha256": _sha256(ledger_path),
            "fail_closed_boundaries": ledger["fail_closed_boundaries"],
        },
    )


def compose_faceline_target(
    char_info: dict[str, Any],
    active_parts_path: Path,
    color_table_path: Path,
    *,
    share_mii_sha256: str,
    ledger_path: Path = DEFAULT_LEDGER,
    contract_key: str | None = None,
    classic_resource_signature_records: dict[str, dict[str, Any]] | None = None,
) -> FacelineCompositionResult | None:
    """Dispatch only source-complete generated-faceline target contracts."""

    if contract_key == CLASSIC_GENERIC_FACELINE_CONTRACT:
        return compose_classic_generic_faceline_target(
            char_info,
            active_parts_path,
            color_table_path,
            classic_resource_signature_records,
        )
    if share_mii_sha256 == JOHNNY_SHARE_MII_SHA256:
        return compose_johnny_faceline_target(
            char_info,
            active_parts_path,
            color_table_path,
            share_mii_sha256=share_mii_sha256,
            ledger_path=ledger_path,
        )
    if share_mii_sha256 == SPIDER_MAN_NOIR_SHARE_MII_SHA256:
        return compose_spider_man_noir_faceline_target(
            char_info,
            active_parts_path,
            color_table_path,
            share_mii_sha256=share_mii_sha256,
            ledger_path=ledger_path,
        )
    raise FacelineCompositionError(
        "unsupported_faceline_target",
        f"no complete generated-faceline contract for {share_mii_sha256}",
    )


__all__ = [
    "DEFAULT_LEDGER",
    "FACELINE_HEIGHT",
    "FACELINE_WIDTH",
    "FacelineCompositionError",
    "FacelineCompositionResult",
    "JOHNNY_SHARE_MII_SHA256",
    "SPIDER_MAN_NOIR_SHARE_MII_SHA256",
    "CLASSIC_GENERIC_FACELINE_CONTRACT",
    "compose_faceline_target",
    "compose_classic_generic_faceline_target",
    "compose_johnny_faceline_target",
    "compose_spider_man_noir_faceline_target",
]
