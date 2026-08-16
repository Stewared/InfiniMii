"""Compose the recovered Mii facial-layer texture from CharInfoEx selectors.

This follows the FFL/Nintendo mask formulas recovered alongside the game:
the 64-unit face coordinate system, origin-anchored mirrored eye/eyebrow quads,
per-part scale/aspect/rotation/position controls, and RGB-layer modulation.
The Living-the-Dream selector table is important: a numeric zero is a real
part for faceline and eyebrows but is an explicit ``Nothing`` entry for the
other zero-valued optional layers in the supplied Mii.
"""

from __future__ import annotations

import json
import hashlib
import math
from dataclasses import dataclass, asdict, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import numpy as np
from PIL import Image

try:
    from . import native_face_target
    from .classic_bridge_support import (
        OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES,
        inactive_projection,
    )
except ImportError:  # direct renderer module execution
    import native_face_target  # type: ignore
    from classic_bridge_support import (  # type: ignore
        OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES,
        inactive_projection,
    )


FACE_UNITS = 64.0
ACTIVE_PARTS_PATH = Path(__file__).with_name("mii_active_parts.json")
FACE_SPRITE_MIP_MANIFEST = Path(__file__).with_name("face_sprite_mips.json")
CLASSIC_FACE_PRESENTATION = Path(__file__).with_name("classic_face_presentation.json")
GAMEUBER_RUNTIME_INPUTS = Path(__file__).with_name("gameuber_runtime_inputs.json")
REPOSITORY = Path(__file__).resolve().parents[1]
TEXTURE_SCALE_X = 0.88961464
TEXTURE_SCALE_Y = 0.9276675
SPACING_MULTIPLIER = 0.88961464
POSITION_X_MULTIPLIER = 1.7792293
POSITION_Y_MULTIPLIER = 1.0760943
MII_SAMPLER_LOD_BIAS = -0.7
MII_SAMPLER_MIN_LOD = 0.0
MII_SAMPLER_MAX_LOD = 13.0
EXTENDED_FACELINE_SRGB_RGBA8 = {
    110: (252, 217, 192, 255),
    111: (238, 145, 103, 255),
    112: (226, 148, 84, 255),
    113: (88, 54, 35, 255),
}

# Disabled MiiMask sprite categories are valid only when PartsIndex selected
# that category's explicit Nothing record.  Geometry categories and the
# separate faceline target are deliberately not included here.
ORDINARY_MASK_NOTHING_RECORDS = {
    "eye": "EyeNothing",
    "eye_highlight": "HighlightNothing",
    "eyelash_upper": "EyelashUpperNothing",
    "eyelash_lower": "EyelashLowerNothing",
    "eyelid_upper": "EyelidUpperNothing",
    "eyelid_lower": "EyelidLowerNothing",
    "eyebrow": "EyebrowNothing",
    "mouth": "MouthNothing",
    "mustache": "MustacheNothing",
    "mole": "MoleNothing",
}

# The extended eye-accessory path is recovered directly from
# FUN_7101d74350.  Eye002 supplies its expression axis through the Parts
# metadata, while EyelashUpper01 has no axis override and therefore uses the
# zero default.  The five base values come from Eye002's row in
# MiiEyeAccessoryParam.Trial.100.rstbl.byml; this Mii's five serialized
# accessory deltas are all zero, so the row values pass through unchanged.
DESCRIPTOR_ROTATE_X_DIVISOR = 1.1240822
DESCRIPTOR_ROTATE_Y_DIVISOR = 1.0779724
EYE002_EXPRESSION_AXIS = (0.386, -0.037)
EYELASH_UPPER01_AXIS = (0.0, 0.0)
EYELASH_UPPER01_DEFAULT = {
    "x": 19,
    "y": 13,
    "rotate": 29,
    "scale": 8,
    "aspect": 3,
}
POSITION_X_ADD = 3.5323312
POSITION_Y_ADD = 4.629278

EYE_Y_ADD = 18.451523
EYEBROW_Y_ADD = 16.549807
MOUTH_Y_ADD = POSITION_Y_ADD + 24.629572
# Direct FUN_7101d75d68 case-0/1 literal.  Keeping the emitted float instead
# of re-summing two rounded decompiler constants avoids a 1e-6-unit drift.
MUSTACHE_Y_ADD = 31.763554

# Recovered FFL type-specific rotation corrections. Living the Dream extends
# the catalogs, whose ordinary default remains four ticks when not listed.
EYE_ROTATION_BASE = (
    3, 4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 4, 3, 3, 4,
    4, 4, 3, 3, 4, 3, 4, 3, 3, 4, 3, 4, 4, 3, 4, 4,
    4, 3, 3, 3, 4, 4, 3, 3, 3, 4, 4, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 4, 4, 4, 4, 3, 4, 4, 3, 4, 4, 4, 4,
)
EYEBROW_ROTATION_BASE = (
    6, 6, 5, 7, 6, 7, 6, 7, 4, 7, 6, 8,
    5, 5, 6, 6, 7, 7, 6, 6, 5, 6, 7, 5,
    6, 6, 6, 6,
)


@dataclass(frozen=True)
class LayerPlacement:
    name: str
    source_texture: str
    center_x: float
    center_y: float
    width: float
    height: float
    rotation_degrees: float
    mirrored: bool
    selector: int
    parts_record: str
    dispatcher_case: int
    modulation_mode: int | None = None
    source_mip_level: int = 0
    source_mip_dimensions: tuple[int, int] | None = None
    source_rho: float = 1.0
    source_biased_lod: float = 0.0
    source_mip_manifest: str | None = None
    source_bntx_sha256: str | None = None
    # FUN_7101d76bf0 applies these two parent-eye terms after the accessory's
    # own rotation. Ordinary face sprites retain the identity defaults.
    parent_aspect: float = 1.0
    parent_rotation_degrees: float = 0.0


PixelShader = Callable[[np.ndarray], np.ndarray]


@dataclass(frozen=True)
class MiiMaskPipelineResult:
    """Stored bytes from the recovered ordinary-face target sequence.

    ``final_target_rgba8`` is the literal RGBA8_UNORM target after case 21 and
    pass 1, so its alpha is necessarily opaque.  ``mesh_input_rgba8`` keeps
    those exact stored RGB bytes but carries pass 0's independently stored
    additive alpha as the explicit portable Mask coverage companion.  The
    latter is not represented as the title target's alpha: conflating the two
    would make the complete identity-space Mask mesh opaque.
    """

    dispatcher_cases: tuple[int, ...]
    pass0_target_rgba8: np.ndarray
    case21_target_rgba8: np.ndarray
    final_target_rgba8: np.ndarray
    mesh_input_rgba8: np.ndarray
    pass0_draw_sha256: tuple[str, ...]
    pass1_draw_sha256: tuple[str, ...]


def _rgba_bytes(color: list[float] | tuple[float, ...]) -> tuple[int, int, int, int]:
    values = list(color[:4])
    while len(values) < 4:
        values.append(1.0)
    return tuple(int(round(max(0.0, min(1.0, value)) * 255.0)) for value in values)  # type: ignore[return-value]


def _common_color(colors: dict[str, Any], index: int) -> tuple[int, int, int, int]:
    if not 0 <= index < len(colors["common"]):
        raise ValueError(f"common color index {index} is outside the recovered 0..99 table")
    return _rgba_bytes(colors["common"][index])


def _active_records(active_parts_path: Path) -> dict[str, dict[str, Any]]:
    manifest = json.loads(active_parts_path.read_text(encoding="utf-8"))
    records = {record["logical_name"]: record for record in manifest["records"]}
    if len(records) != manifest["selector_count"]:
        raise ValueError("active-parts manifest contains duplicate logical names")
    return records


def _selected_texture(
    records: dict[str, dict[str, Any]],
    logical_name: str,
    char_info: dict[str, Any],
) -> tuple[str, str] | None:
    """Return the selected texture/Parts record after validating its selector."""

    record = records[logical_name]
    selector_field = record.get("selector_field")
    if selector_field is not None and int(char_info[selector_field]) != int(record["selector"]):
        raise ValueError(
            f"{logical_name} selector differs from renderer/mii_active_parts.json; "
            "regenerate it with tools/build_mii_active_parts.py"
        )
    if not record.get("enabled"):
        return None
    texture_name = record.get("texture_name")
    if not texture_name:
        raise ValueError(f"enabled {logical_name} record has no renderable texture")
    return f"{texture_name}.png", f"{record['record']}.mii__Parts.bgyml"


def _require_exact_nothing_record(
    records: dict[str, dict[str, Any]],
    logical_name: str,
    expected_record: str,
    classic_resource_signature_records: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Accept an empty ordinary sprite slot only for its exact Nothing record."""

    record = records[logical_name]
    if classic_resource_signature_records is not None:
        projection = _validate_classic_signature_record(
            logical_name, record, classic_resource_signature_records
        )
        if isinstance(projection, dict) and projection.get("kind") in (
            "exact_parts_nothing",
            "title_lookup_empty",
        ):
            return
    if (
        record.get("enabled") is not False
        or record.get("resolved") is not True
        or record.get("is_nothing") is not True
        or record.get("record") != expected_record
        or record.get("texture_name") is not None
    ):
        raise ValueError(
            f"{logical_name} has no renderable texture and is not exact {expected_record}"
        )


def _validate_disabled_ordinary_sprite_records(
    records: dict[str, dict[str, Any]],
    classic_resource_signature_records: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Fail closed if an inactive ordinary MiiMask slot is not exact Nothing."""

    for logical_name, expected_record in ORDINARY_MASK_NOTHING_RECORDS.items():
        if not records[logical_name].get("enabled"):
            if classic_resource_signature_records is not None:
                projection = _validate_classic_signature_record(
                    logical_name,
                    records[logical_name],
                    classic_resource_signature_records,
                )
                if isinstance(projection, dict) and projection.get("kind") in (
                    "exact_parts_nothing",
                    "title_lookup_empty",
                ):
                    continue
            _require_exact_nothing_record(records, logical_name, expected_record)


def resolve_skin_color(colors: dict[str, Any], selector: int) -> tuple[int, int, int, int]:
    """Resolve the title's direct-common/legacy-faceline color namespace.

    ``FUN_7101d68ae8`` accepts the CharInfoEx byte at +0x2d through 0x71.
    ``FUN_7101d69220`` converts an nn::mii legacy faceline color by adding
    100, so 100..109 address the ten-entry faceline table.  Direct extended
    values 0..99 retain their common-color-table identity.
    """

    if 100 <= selector <= 109:
        return _rgba_bytes(colors["faceline"][selector - 100])
    if 0 <= selector <= 99:
        return _common_color(colors, selector)
    if selector in EXTENDED_FACELINE_SRGB_RGBA8:
        return EXTENDED_FACELINE_SRGB_RGBA8[selector]
    raise ValueError(f"faceline color {selector} is outside the title domain 0..113")


def _rgb_layered(source: Image.Image, red: tuple[int, ...], green: tuple[int, ...], blue: tuple[int, ...]) -> Image.Image:
    pixels = np.asarray(source.convert("RGBA"), dtype=np.float64) / 255.0
    color_r = np.asarray(red[:3], dtype=np.float64) / 255.0
    color_g = np.asarray(green[:3], dtype=np.float64) / 255.0
    color_b = np.asarray(blue[:3], dtype=np.float64) / 255.0
    result = (
        pixels[..., 0, None] * color_r
        + pixels[..., 1, None] * color_g
        + pixels[..., 2, None] * color_b
    )
    rgba = np.empty_like(pixels)
    rgba[..., :3] = np.clip(result, 0.0, 1.0)
    rgba[..., 3] = pixels[..., 3]
    return Image.fromarray(np.rint(rgba * 255.0).astype(np.uint8), mode="RGBA")


def _luminance_alpha(source: Image.Image, color: tuple[int, int, int, int]) -> Image.Image:
    pixels = np.asarray(source.convert("RGBA"), dtype=np.float64) / 255.0
    luminance = np.max(pixels[..., :3], axis=2) * pixels[..., 3]
    result = np.empty_like(pixels)
    result[..., :3] = np.asarray(color[:3], dtype=np.float64) / 255.0
    result[..., 3] = luminance * (color[3] / 255.0)
    return Image.fromarray(np.rint(np.clip(result, 0.0, 1.0) * 255.0).astype(np.uint8), mode="RGBA")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@lru_cache(maxsize=1)
def _mii_mask_fixed_function_contract() -> dict[str, Any]:
    """Bind the portable compositor to the recovered title target state.

    The evidence ledger is Kestron's executable 15-draw instance of the
    generic dispatcher.  Its three fixed-function states and case-21 output
    are invariant for every ordinary MiiMask target; only the gated case list
    varies with CharInfoEx.
    """

    ledger = json.loads(GAMEUBER_RUNTIME_INPUTS.read_text(encoding="utf-8"))
    if ledger.get("schema_version") != 3:
        raise ValueError("GameUber runtime-input ledger schema changed")
    prepass = ledger.get("mii_mask_prepass")
    if not isinstance(prepass, dict):
        raise ValueError("GameUber runtime-input ledger has no MiiMask prepass")
    fixed = prepass.get("fixed_function_state")
    states = fixed.get("pipeline_states") if isinstance(fixed, dict) else None
    if not isinstance(states, list) or len(states) != 3:
        raise ValueError("MiiMask fixed-function pipeline inventory changed")
    expected_rgb = {
        "pass_0": ("one", "zero", "add"),
        "case_21": ("source_alpha", "one_minus_source_alpha", "add"),
        "pass_1": ("one", "one_minus_source_alpha", "add"),
    }
    by_name = {str(state.get("name")): state for state in states if isinstance(state, dict)}
    if set(by_name) != set(expected_rgb):
        raise ValueError("MiiMask fixed-function pipeline names changed")
    for name, expected in expected_rgb.items():
        state = by_name[name]
        rgb = state.get("rgb_blend")
        alpha = state.get("alpha_blend")
        if (
            not isinstance(rgb, dict)
            or (rgb.get("source"), rgb.get("destination"), rgb.get("equation")) != expected
            or alpha != {"source": "one", "destination": "one", "equation": "add"}
            or state.get("color_write_mask") != "rgba"
            or state.get("depth_test_enabled") is not False
            or state.get("depth_write_enabled") is not False
            or state.get("stencil_test_enabled") is not False
            or state.get("cull_mode") != "none"
        ):
            raise ValueError(f"MiiMask {name} fixed-function state changed")

    target = prepass.get("target")
    if not isinstance(target, dict) or target.get("dimensions") != [256, 256]:
        raise ValueError("MiiMask target dimensions changed")
    views = target.get("storage_and_view_formats")
    if (
        not isinstance(views, dict)
        or views.get("base_texture_and_sample_view", {}).get("format_code") != "0x0b06"
        or views.get("mii_mask_color_target_view", {}).get("format_code") != "0x0b01"
        or target.get("clear", {}).get("rgba") != [0.0, 0.0, 0.0, 0.0]
        or target.get("draw_order") != "pass0 cases 0..21, then pass1 cases 0..20"
    ):
        raise ValueError("MiiMask target/write-view contract changed")
    case21 = prepass.get("case21")
    if (
        not isinstance(case21, dict)
        or case21.get("fragment_shader_path", {}).get("output_rgba") != [0.0, 0.0, 0.0, 1.0]
        or case21.get("blend_result", {}).get("full_target_effect")
        != "replace with opaque black before pass1"
        or case21.get("executable") is not True
    ):
        raise ValueError("MiiMask case-21 opaque-black transition changed")
    if prepass.get("minimal_exact_subset", {}).get("executable") is not True:
        raise ValueError("MiiMask exact target sequence is no longer executable")
    return {
        "ledger_path": GAMEUBER_RUNTIME_INPUTS.name,
        "ledger_sha256": _sha256(GAMEUBER_RUNTIME_INPUTS),
        "source_dimensions": [256, 256],
        "pipeline_states": {
            name: {
                "source_virtual_address": by_name[name]["source_virtual_address"],
                "descriptor_words": by_name[name]["descriptor_words"],
                "rgb_blend": by_name[name]["rgb_blend"],
                "alpha_blend": by_name[name]["alpha_blend"],
            }
            for name in ("pass_0", "case_21", "pass_1")
        },
        "write_view": "RGBA8_UNORM (0x0b01)",
        "sample_view": "RGBA8_SRGB (0x0b06)",
        "case21_source_rgba": [0, 0, 0, 255],
    }


def _resolve_evidence_path(value: str) -> Path:
    """Resolve both repository- and project-relative legacy evidence paths."""

    path = Path(value)
    candidates = (
        path.resolve() if path.is_absolute() else (REPOSITORY / path).resolve(),
        path.resolve() if path.is_absolute() else (REPOSITORY.parent / path).resolve(),
    )
    matches = [candidate for candidate in candidates if candidate.is_file()]
    unique = list(dict.fromkeys(matches))
    if len(unique) != 1:
        raise ValueError(f"evidence path {value!r} resolves to {len(unique)} files")
    return unique[0]


def _validate_file_record(record: dict[str, Any], label: str) -> Path:
    path = _resolve_evidence_path(str(record["path"]))
    if path.stat().st_size != int(record["byte_length"]) or _sha256(path) != record["sha256"]:
        raise ValueError(f"{label} identity changed: {record['path']}")
    return path


@lru_cache(maxsize=1)
def _classic_face_presentation_contract() -> dict[str, Any]:
    """Load and bind the generic compositor to its exact title evidence."""

    ledger = json.loads(CLASSIC_FACE_PRESENTATION.read_text(encoding="utf-8"))
    if (
        ledger.get("schema_version") != 1
        or ledger.get("status") != "SOURCE_BACKED_COMPLETE_CLASSIC_FACE_PRESENTATION"
    ):
        raise ValueError("classic face-presentation ledger schema/status changed")
    sources = ledger.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("classic face-presentation ledger has no evidence sources")
    # The runtime consumes these four sources directly. The ledger also pins
    # the main ELF/decompiler/shader-stage identities for the focused verifier,
    # without rehashing the 65 MiB executable on every renderer process.
    for key in (
        "classic_resource_domain",
        "classic_face_sprite_mips",
        "parts_metadata_jsonl",
        "eye_accessory_rsdb",
    ):
        _validate_file_record(sources[key], f"classic face presentation {key}")
    resource = ledger.get("resource_contract")
    if (
        not isinstance(resource, dict)
        or resource.get("sprite_count") != 154
        or resource.get("record_count") != 184
        or len(resource.get("eye_accessory_rows", {})) != 60
    ):
        raise ValueError("classic face-presentation resource inventory changed")
    return ledger


@lru_cache(maxsize=1)
def _classic_inactive_projection_contract() -> dict[str, Any]:
    """Return the hash-bound domain contract used by canonical no-draw rows."""

    ledger = _classic_face_presentation_contract()
    source = ledger["sources"]["classic_resource_domain"]
    path = _validate_file_record(source, "classic face presentation classic_resource_domain")
    domain = json.loads(path.read_text(encoding="utf-8"))
    contract = domain.get("inactive_projection_contract")
    if (
        domain.get("schema_version") != 1
        or not isinstance(contract, dict)
        or contract.get("schema_version") != 1
        or contract.get("selector_semantics")
        != "raw effective CharInfo selector; never remapped"
        or not isinstance(contract.get("existing_selectors_by_logical_name"), dict)
        or not isinstance(contract.get("exact_records"), list)
        or len(contract["exact_records"]) != 103
    ):
        raise ValueError("classic inactive-projection resource domain changed")
    return contract


def _validate_classic_inactive_signature(canonical: dict[str, Any]) -> None:
    """Validate a canonical no-draw record against the source domain itself."""

    contract = _classic_inactive_projection_contract()
    projection = canonical.get("inactive_projection")
    kind = projection.get("kind") if isinstance(projection, dict) else None
    if kind not in ("exact_parts_nothing", "gate_disabled", "title_lookup_empty"):
        raise ValueError("classic face inactive projection kind changed")
    if projection != inactive_projection(kind):
        raise ValueError("classic face inactive projection shape changed")
    logical_name = canonical.get("logical_name")
    selector = canonical.get("selector")
    if type(selector) is not int or selector < 0:
        raise ValueError("classic face inactive projection selector is invalid")

    if kind == "title_lookup_empty":
        existing = contract["existing_selectors_by_logical_name"]
        if (
            logical_name not in OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES
            or logical_name not in existing
            or selector in existing[logical_name]
            or canonical.get("resolved") is not False
            or canonical.get("record") is not None
            or canonical.get("is_nothing") is not False
            or canonical.get("parts_config") is not None
            or canonical.get("components") != {}
            or canonical.get("components_hash") != {}
            or canonical.get("resource_flags") != {}
        ):
            raise ValueError(
                f"classic face selector is not an exact optional title lookup miss: "
                f"{logical_name}:{selector}"
            )
        return

    matches = [
        item
        for item in contract["exact_records"]
        if item.get("logical_name") == logical_name
        and item.get("selector") == selector
        and kind in item.get("projection_kinds", [])
    ]
    if len(matches) != 1:
        raise ValueError(
            f"classic face inactive selector lacks one exact title identity: "
            f"{logical_name}:{selector}"
        )
    exact = matches[0]
    exact_parts = exact.get("parts_config")
    canonical_parts = canonical.get("parts_config")
    if (
        canonical.get("resolved") is not True
        or canonical.get("category") != exact.get("category")
        or canonical.get("record") != exact.get("record")
        or canonical.get("is_nothing") is not exact.get("is_nothing")
        or not isinstance(exact_parts, dict)
        or not isinstance(canonical_parts, dict)
        or canonical_parts.get("byte_length") != exact_parts.get("byte_length")
        or canonical_parts.get("sha256") != exact_parts.get("sha256")
        or canonical.get("components") != exact.get("components")
        or canonical.get("components_hash") != exact.get("components_hash")
        or canonical.get("resource_flags") != exact.get("resource_flags")
    ):
        raise ValueError("classic face inactive exact Parts identity changed")
    if kind == "exact_parts_nothing":
        if (
            canonical.get("is_nothing") is not True
            or not str(canonical.get("record", "")).endswith("Nothing")
        ):
            raise ValueError("classic face exact Nothing projection changed")
    elif (
        kind != "gate_disabled"
        or logical_name != "hair_front"
        or canonical.get("is_nothing") is not False
        or canonical.get("gate") != "selected Hair.IsAttachableHairFront"
        or canonical.get("gate_enabled") is not False
    ):
        raise ValueError("classic face HairFront gate-disabled projection changed")


def _validate_classic_signature_record(
    logical_name: str,
    active: dict[str, Any],
    classic_resource_signature_records: dict[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Bind one raw Parts record to its admitted canonical signature record.

    The canonical record is produced by ``active_resource_signature`` and has
    already passed the complete component resolver.  We still validate its
    inactive projection against the independently hash-bound resource domain
    here so an out-of-presentation selector can never become a generic skip.
    """

    if not isinstance(classic_resource_signature_records, dict):
        raise ValueError("classic face canonical resource signature is missing")
    canonical = classic_resource_signature_records.get(logical_name)
    if not isinstance(canonical, dict) or canonical.get("logical_name") != logical_name:
        raise ValueError(f"classic face canonical record is missing for {logical_name}")

    try:
        selector_matches = int(active.get("selector", -1)) == int(canonical["selector"])
    except (KeyError, TypeError, ValueError):
        selector_matches = False
    canonical_parts = canonical.get("parts_config")
    if canonical_parts is None:
        parts_match = (
            active.get("parts_config") is None
            and active.get("parts_config_sha256") is None
            and active.get("parts_config_byte_length") is None
        )
    else:
        parts_match = (
            isinstance(canonical_parts, dict)
            and active.get("parts_config_sha256") == canonical_parts.get("sha256")
            and active.get("parts_config_byte_length") == canonical_parts.get("byte_length")
        )
    canonical_texture = canonical.get("texture")
    texture_matches = (
        active.get("texture_name") is None
        if canonical_texture is None
        else isinstance(canonical_texture, dict)
        and active.get("texture_name") == canonical_texture.get("name")
    )
    canonical_is_nothing = canonical.get("is_nothing")
    raw_is_nothing = active.get("is_nothing")
    is_nothing_matches = raw_is_nothing is canonical_is_nothing
    if canonical.get("resolved") is False and canonical_is_nothing is False:
        # The raw title lookup miss carries no Parts record, so old/new builders
        # may serialize this source-side field as null or false.  The canonical
        # signature always projects it to false.
        is_nothing_matches = raw_is_nothing in (None, False)
    if (
        not selector_matches
        or active.get("selector_field") != canonical.get("selector_field")
        or active.get("category") != canonical.get("category")
        or active.get("resolved") is not canonical.get("resolved")
        or active.get("record") != canonical.get("record")
        or bool(active.get("enabled")) is not bool(canonical.get("enabled"))
        or not is_nothing_matches
        or active.get("gate") != canonical.get("gate")
        or bool(active.get("gate_enabled")) is not bool(canonical.get("gate_enabled"))
        or active.get("components", {}) != canonical.get("components", {})
        or active.get("components_hash", {}) != canonical.get("components_hash", {})
        or active.get("resource_flags", {}) != canonical.get("resource_flags", {})
        or active.get("inactive_projection") != canonical.get("inactive_projection")
        or not parts_match
        or not texture_matches
    ):
        raise ValueError(f"classic face canonical Parts/signature record differs for {logical_name}")

    projection = canonical.get("inactive_projection")
    if projection is None:
        if active.get("inactive_projection") is not None:
            raise ValueError(f"classic face active record has an inactive projection: {logical_name}")
        return None
    if (
        canonical.get("enabled") is not False
        or canonical.get("models") != []
        or canonical.get("texture") is not None
    ):
        raise ValueError(f"classic face inactive signature has render payload: {logical_name}")
    _validate_classic_inactive_signature(canonical)
    return projection


def _validate_classic_face_selection(
    records: dict[str, dict[str, Any]],
    char_info: dict[str, Any],
    classic_resource_signature_records: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    """Require each ordinary active record to match one admitted ledger row."""

    ledger = _classic_face_presentation_contract()
    inventory = {
        (item["logical_name"], int(item["selector"])): item
        for item in ledger["resource_contract"]["records"]
    }
    for logical_name, selector_field in (
        ("faceline", "faceline_type"), ("beard", "beard_type")
    ):
        active = records.get(logical_name)
        if active is None:
            raise ValueError(f"classic base face record {logical_name} is missing")
        projection = _validate_classic_signature_record(
            logical_name, active, classic_resource_signature_records
        )
        selector = int(active.get("selector", -1))
        expected = inventory.get((logical_name, selector))
        if selector != int(char_info[selector_field]):
            raise ValueError(f"classic base face selection differs for {logical_name}")
        if expected is None:
            if (
                logical_name != "faceline"
                and isinstance(projection, dict)
                and projection.get("kind") in (
                    "exact_parts_nothing",
                    "title_lookup_empty",
                )
            ):
                continue
            raise ValueError(f"classic base face selection differs for {logical_name}")
        if active.get("resolved") is not True or (
            active.get("category") != expected["category"]
            or active.get("record") != expected["record"]
            or active.get("is_nothing") is not expected["is_nothing"]
            or active.get("parts_config_sha256") != expected["parts_config"]["sha256"]
            or active.get("parts_config_byte_length") != expected["parts_config"]["byte_length"]
            or bool(active.get("enabled")) == bool(expected["is_nothing"])
        ):
            raise ValueError(f"classic base face selection differs for {logical_name}")
        if logical_name == "faceline" and projection is not None:
            raise ValueError("classic required faceline cannot be source-inactive")
    selector_fields = {
        "eye": "eye_type",
        "eye_highlight": "eye_highlight_type",
        "eyelash_upper": "eyelash_upper_type",
        "eyelash_lower": "eyelash_lower_type",
        "eyelid_upper": "eyelid_upper_type",
        "eyelid_lower": "eyelid_lower_type",
        "eyebrow": "eyebrow_type",
        "mouth": "mouth_type",
        "mustache": "mustache_type",
        "mole": None,
    }
    for logical_name, selector_field in selector_fields.items():
        active = records.get(logical_name)
        if active is None:
            raise ValueError(f"classic face record {logical_name} is missing")
        projection = _validate_classic_signature_record(
            logical_name, active, classic_resource_signature_records
        )
        selector = int(active.get("selector", -1))
        if selector_field is not None and selector != int(char_info[selector_field]):
            raise ValueError(f"classic face serialized selector differs for {logical_name}")
        expected = inventory.get((logical_name, selector))
        if expected is None:
            if (
                not isinstance(projection, dict)
                or projection.get("kind")
                not in ("exact_parts_nothing", "title_lookup_empty")
            ):
                raise ValueError(
                    f"classic face selector is outside contract: {logical_name}:{selector}"
                )
            continue
        if active.get("resolved") is not True:
            raise ValueError(f"classic face record {logical_name} is unresolved")
        actual_texture = active.get("texture_name")
        if (
            active.get("category") != expected["category"]
            or active.get("record") != expected["record"]
            or actual_texture != expected["texture_name"]
            or active.get("is_nothing") is not expected["is_nothing"]
            or active.get("components_hash", {}) != expected["components_hash"]
            or active.get("resource_flags", {}) != expected["resource_flags"]
            or active.get("parts_config_sha256") != expected["parts_config"]["sha256"]
            or active.get("parts_config_byte_length") != expected["parts_config"]["byte_length"]
        ):
            raise ValueError(f"classic face active record identity differs for {logical_name}")
        expected_enabled = not bool(expected["is_nothing"])
        if bool(active.get("enabled")) != expected_enabled:
            raise ValueError(f"classic face enabled state differs for {logical_name}")
    mole_enabled = bool(char_info["face_flags"]["mole_enabled"])
    if bool(records["mole"].get("enabled")) != mole_enabled:
        raise ValueError("mole Parts gate differs from face_flags.mole_enabled")
    return ledger


def validate_classic_face_presentation(
    char_info: dict[str, Any],
    active_parts_path: Path,
    color_table_path: Path,
    classic_resource_signature_records: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate the complete classic face admission boundary without drawing."""

    records = _active_records(active_parts_path)
    _validate_disabled_ordinary_sprite_records(
        records, classic_resource_signature_records
    )
    ledger = _validate_classic_face_selection(
        records, char_info, classic_resource_signature_records
    )
    colors = json.loads(color_table_path.read_text(encoding="utf-8"))
    skin = resolve_skin_color(colors, int(char_info["faceline_color"]))
    for field in (
        "eye_color", "eye_shadow_color", "eyebrow_color", "mouth_color",
        "mustache_color", "makeup_lower_color", "makeup_upper_color", "stubble_color",
    ):
        _common_color(colors, int(char_info[field]))

    inventory = {
        (item["logical_name"], int(item["selector"])): item
        for item in ledger["resource_contract"]["records"]
    }
    generated_layers = (
        "makeup_lower", "makeup_upper", "wrinkle_upper", "wrinkle_lower", "beard_short"
    )
    generated_selector_fields = {
        "makeup_lower": "makeup_lower_type",
        "makeup_upper": "makeup_upper_type",
        "wrinkle_upper": "wrinkle_upper_type",
        "wrinkle_lower": "wrinkle_lower_type",
        "beard_short": "stubble_type",
    }
    for logical_name in generated_layers:
        active = records.get(logical_name)
        if active is None:
            raise ValueError(f"classic faceline record {logical_name} is missing")
        projection = _validate_classic_signature_record(
            logical_name, active, classic_resource_signature_records
        )
        expected = inventory.get((logical_name, int(active.get("selector", -1))))
        if int(active.get("selector", -1)) != int(char_info[generated_selector_fields[logical_name]]):
            raise ValueError(f"classic faceline serialized selector differs for {logical_name}")
        if expected is None:
            if (
                not isinstance(projection, dict)
                or projection.get("kind") != "title_lookup_empty"
            ):
                raise ValueError(f"classic faceline active record differs for {logical_name}")
            continue
        if active.get("resolved") is not True or (
            active.get("category") != expected["category"]
            or active.get("record") != expected["record"]
            or active.get("texture_name") != expected["texture_name"]
            or active.get("is_nothing") is not expected["is_nothing"]
            or active.get("resource_flags", {}) != expected["resource_flags"]
            or bool(active.get("enabled")) == bool(expected["is_nothing"])
        ):
            raise ValueError(f"classic faceline active record differs for {logical_name}")

    enabled_generated = [name for name in generated_layers if records[name].get("enabled")]
    no_draw = [
        {
            "logical_name": name,
            "record": records[name].get("record"),
            "selector": int(records[name]["selector"]),
            "inactive_projection": classic_resource_signature_records[name].get(
                "inactive_projection"
            ),
        }
        for name in ORDINARY_MASK_NOTHING_RECORDS
        if not records[name].get("enabled")
    ]
    admission = ledger["char_info_admission"]
    return {
        "status": "source_backed_complete_classic_face_presentation",
        "contract_key": "classic_face_presentation_v1",
        "contract_path": CLASSIC_FACE_PRESENTATION.name,
        "contract_sha256": _sha256(CLASSIC_FACE_PRESENTATION),
        "ordinary_mask_complete": True,
        "faceline_target_required": bool(enabled_generated),
        "faceline_contract_key": (
            ledger["faceline_target_contract"]["key"] if enabled_generated else None
        ),
        "faceline_title_draw_order": ledger["faceline_target_contract"]["title_draw_order"],
        "faceline_base_record": records["faceline"].get("record"),
        "beard_geometry_record": records["beard"].get("record"),
        "beard_inactive_projection": classic_resource_signature_records["beard"].get(
            "inactive_projection"
        ),
        "enabled_faceline_layers": enabled_generated,
        "nothing_no_draw": no_draw,
        "skin_selector": int(char_info["faceline_color"]),
        "skin_srgb_rgba8": list(skin),
        "consumed_face_flags": admission["face_flags_consumed"],
        "face_texture_invariant_flags": admission["face_texture_invariant_flags"],
        "mouth_inverted_semantic": admission["mouth_inverted_semantic"],
    }


@lru_cache(maxsize=8)
def _face_sprite_mip_records(
    manifest_paths: tuple[Path, ...],
) -> dict[str, dict[str, Any]]:
    combined: dict[str, dict[str, Any]] = {}
    for manifest_path in manifest_paths:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != 1 or not isinstance(manifest.get("textures"), dict):
            raise ValueError(f"{manifest_path} has an unsupported face-mip schema")
        source = manifest.get("source")
        if not isinstance(source, dict):
            raise ValueError(f"{manifest_path} has no exact packed-BNTX source record")
        _validate_file_record(source, f"{manifest_path.name} packed BNTX")
        for texture_name, record in manifest["textures"].items():
            if texture_name in combined:
                raise ValueError(f"face-mip texture {texture_name} is duplicated across manifests")
            combined[texture_name] = {
                "record": record,
                "manifest_path": manifest_path,
                "source": source,
            }
    return combined


def _validate_supplemental_sprite_identity(
    texture_name: str,
    entry: dict[str, Any],
    active_records: dict[str, dict[str, Any]],
    char_info: dict[str, Any],
) -> None:
    """Bind supplemental mips to the exact active Parts and packed BNTX."""

    record = entry["record"]
    identity = record.get("active_record_identity")
    if identity is None:
        return
    if not isinstance(identity, dict):
        raise ValueError(f"{texture_name} active-record identity is malformed")
    logical_name = identity.get("logical_name")
    active = active_records.get(logical_name)
    if active is None:
        raise ValueError(f"{texture_name} has no active {logical_name} record")
    expected = {
        "category": identity.get("category"),
        "selector": identity.get("selector"),
        "record": identity.get("record"),
        "texture_name": identity.get("texture_name"),
    }
    if any(active.get(key) != value for key, value in expected.items()):
        raise ValueError(f"{texture_name} does not match the exact active Parts record")
    if not active.get("resolved") or not active.get("enabled"):
        raise ValueError(f"{texture_name} active Parts record is not resolved/enabled")
    config = identity.get("parts_config")
    if not isinstance(config, dict):
        raise ValueError(f"{texture_name} lacks an exact Parts-config record")
    if (
        active.get("parts_config_sha256") != config.get("sha256")
        or active.get("parts_config_byte_length") != config.get("byte_length")
    ):
        raise ValueError(f"{texture_name} active Parts-config identity changed")
    _validate_file_record(config, f"{texture_name} Parts config")
    packed = record.get("packed_bntx")
    if not isinstance(packed, dict) or packed.get("sha256") != entry["source"].get("sha256"):
        raise ValueError(f"{texture_name} packed-BNTX identity differs from its manifest source")
    for flag, expected_value in identity.get("required_char_info_flags", {}).items():
        if char_info.get("face_flags", {}).get(flag) is not expected_value:
            raise ValueError(f"{texture_name} requires face_flags.{flag}={expected_value}")


def _sprite_forward_matrix(
    source_size: tuple[int, int],
    placement: LayerPlacement,
    pixels_per_unit: float,
) -> np.ndarray:
    raw_width = placement.width / TEXTURE_SCALE_X
    raw_height = placement.height / TEXTURE_SCALE_Y
    angle = np.deg2rad(placement.rotation_degrees)
    cosine = float(np.cos(angle))
    sine = float(np.sin(angle))
    source_scale = np.asarray(
        (
            (raw_width * pixels_per_unit) / source_size[0],
            (raw_height * pixels_per_unit) / source_size[1],
        ),
        dtype=np.float64,
    )
    rotation = np.asarray(((cosine, -sine), (sine, cosine)), dtype=np.float64)
    parent_angle = np.deg2rad(placement.parent_rotation_degrees)
    parent_rotation = np.asarray(
        (
            (float(np.cos(parent_angle)), -float(np.sin(parent_angle))),
            (float(np.sin(parent_angle)), float(np.cos(parent_angle))),
        ),
        dtype=np.float64,
    )
    parent_deformation = parent_rotation @ np.diag((1.0, placement.parent_aspect))
    atlas_scale = np.diag((TEXTURE_SCALE_X, TEXTURE_SCALE_Y))
    return atlas_scale @ parent_deformation @ rotation @ np.diag(source_scale)


def _select_native_sprite_mip(
    sprite: Image.Image,
    placement: LayerPlacement,
    resolution: int,
    face_units: float,
    active_records: dict[str, dict[str, Any]],
    char_info: dict[str, Any],
    manifest_paths: tuple[Path, ...],
) -> tuple[Image.Image, LayerPlacement]:
    """Select the exact point mip from the affine UV derivatives.

    MiiSampler uses normalized bilinear min/mag sampling, nearest mip selection,
    and a -0.7 LOD bias.  Multiplying normalized UV derivatives by the native
    texture dimensions is equivalent to measuring the columns of the inverse
    base-mip pixel-to-target-pixel matrix constructed here.
    """

    records = _face_sprite_mip_records(manifest_paths)
    texture_name = Path(placement.source_texture).stem
    if texture_name not in records:
        raise ValueError(f"native face-sprite mip cache has no {texture_name} record")
    entry = records[texture_name]
    record = entry["record"]
    _validate_supplemental_sprite_identity(texture_name, entry, active_records, char_info)
    base_size = tuple(int(value) for value in record["native_dimensions"])
    if sprite.size != base_size:
        raise ValueError(
            f"{placement.source_texture} is {sprite.size}, expected native base dimensions {base_size}"
        )

    forward = _sprite_forward_matrix(base_size, placement, resolution / face_units)
    inverse = np.linalg.inv(forward)
    rho = max(float(np.linalg.norm(inverse[:, 0])), float(np.linalg.norm(inverse[:, 1])))
    biased_lod = min(
        MII_SAMPLER_MAX_LOD,
        max(MII_SAMPLER_MIN_LOD, math.log2(rho) + MII_SAMPLER_LOD_BIAS),
    )
    mip_level = min(int(record["mip_count"]) - 1, math.floor(biased_lod + 0.5))
    level = record["levels"][mip_level]
    if int(level["level"]) != mip_level:
        raise ValueError(f"{texture_name} mip manifest is not indexed by level")
    mip_path = REPOSITORY / level["path"]
    if (
        not mip_path.is_file()
        or mip_path.stat().st_size != int(level["byte_length"])
        or _sha256(mip_path) != level["sha256"]
    ):
        raise ValueError(f"cached {texture_name} mip {mip_level} identity changed")
    with Image.open(mip_path) as cached:
        selected = cached.convert("RGBA").copy()
    expected_size = tuple(int(value) for value in level["dimensions"])
    if selected.size != expected_size:
        raise ValueError(f"cached {texture_name} mip {mip_level} has unexpected dimensions")
    return selected, replace(
        placement,
        source_mip_level=mip_level,
        source_mip_dimensions=expected_size,
        source_rho=rho,
        source_biased_lod=biased_lod,
        source_mip_manifest=entry["manifest_path"].name,
        source_bntx_sha256=entry["source"]["sha256"],
    )


def _sample_shaded_layer(
    canvas_size: tuple[int, int],
    sprite: Image.Image,
    placement: LayerPlacement,
    face_units: float = FACE_UNITS,
    pixel_shader: PixelShader | None = None,
) -> np.ndarray:
    """Raster-sample one recovered quad and execute its MiiMask mode.

    FUN_7101d76bf0 rotates in the unscaled 64-unit mask coordinate system and
    only then applies the render-target X/Y scale.  Resizing anisotropically
    before using ``Image.rotate`` reverses those operations and distorts every
    rotated layer, most visibly EyelashUpper01.  Pillow's affine transform is
    inverse-mapped, so construct the exact forward matrix and invert it.  This
    function deliberately does not composite: the title's shader output is
    consumed by three recovered fixed-function states, not Pillow source-over.
    """

    pixels_per_unit = canvas_size[0] / face_units
    if placement.mirrored:
        sprite = sprite.transpose(Image.Transpose.FLIP_LEFT_RIGHT)

    # Positive recovered angles rotate clockwise in the downwards-Y image
    # coordinate system.  The atlas' nonuniform scale is deliberately left of
    # the rotation matrix: output = atlas_scale * rotation * local_position.
    forward = _sprite_forward_matrix(sprite.size, placement, pixels_per_unit)
    inverse = np.linalg.inv(forward)
    source_center = np.asarray((sprite.width / 2.0, sprite.height / 2.0), dtype=np.float64)
    output_center = np.asarray(
        (placement.center_x * pixels_per_unit, placement.center_y * pixels_per_unit),
        dtype=np.float64,
    )
    offset = source_center - inverse @ output_center
    affine = (
        float(inverse[0, 0]),
        float(inverse[0, 1]),
        float(offset[0]),
        float(inverse[1, 0]),
        float(inverse[1, 1]),
        float(offset[1]),
    )
    if pixel_shader is None:
        transformed = sprite.transform(
            canvas_size,
            Image.Transform.AFFINE,
            affine,
            # The recovered MiiSampler uses linear minification/magnification.
            Image.Resampling.BILINEAR,
            fillcolor=(0, 0, 0, 0),
        )
    else:
        # MiiMask samples the unmodulated texture first and then executes its
        # channel-mode equation.  Transform four float planes independently
        # to avoid an intermediate 8-bit quantization before that equation.
        source = np.asarray(sprite.convert("RGBA"), dtype=np.float32) / 255.0
        sampled_channels: list[np.ndarray] = []
        for channel in range(4):
            plane = Image.fromarray(source[..., channel], mode="F").transform(
                canvas_size,
                Image.Transform.AFFINE,
                affine,
                Image.Resampling.BILINEAR,
                fillcolor=0.0,
            )
            sampled_channels.append(np.asarray(plane, dtype=np.float64))
        shaded = pixel_shader(np.stack(sampled_channels, axis=2))
        if shaded.shape != (canvas_size[1], canvas_size[0], 4):
            raise ValueError("MiiMask pixel shader returned an invalid target shape")
        if not np.all(np.isfinite(shaded)):
            raise ValueError("MiiMask pixel shader returned a non-finite value")
        return np.asarray(shaded, dtype=np.float64)
    return np.asarray(transformed.convert("RGBA"), dtype=np.float64) / 255.0


# Keep the complete recovered Python implementation above as the exact
# fallback and verifier oracle. A missing, disabled, stale, or ABI-mismatched
# extension leaves these bindings untouched; a source-sealed backend replaces
# only the dense affine sampling/shading and fixed-function pixel stages.
_sample_shaded_layer_python = _sample_shaded_layer
if native_face_target.BACKEND_AVAILABLE:
    def _sample_shaded_layer(
        canvas_size: tuple[int, int],
        sprite: Image.Image,
        placement: LayerPlacement,
        face_units: float = FACE_UNITS,
        pixel_shader: PixelShader | None = None,
    ) -> np.ndarray:
        if not native_face_target.supports_sample_shaded_layer(
            placement, pixel_shader
        ):
            return _sample_shaded_layer_python(
                canvas_size, sprite, placement, face_units, pixel_shader
            )
        return native_face_target.sample_shaded_layer(
            canvas_size, sprite, placement, face_units, pixel_shader
        )


def _store_rgba8(values: np.ndarray) -> np.ndarray:
    """Clamp and store one draw through the recovered RGBA8_UNORM view."""

    return np.rint(np.clip(values, 0.0, 1.0) * 255.0).astype(np.uint8)


def _blend_mii_mask_draw(
    destination_rgba8: np.ndarray,
    source: np.ndarray,
    *,
    rgb_state: str,
) -> np.ndarray:
    """Execute one pass-0 or pass-1 draw and its mandatory RGBA8 store.

    MiiMask's shared epilogue discards exactly-zero output alpha for every
    ordinary selector.  Alpha uses ADD(ONE, ONE) in both passes.  RGB is either
    replacement in pass 0 or premultiplied source-over in pass 1, even though
    several shader modes emit straight color; preserving that unusual pairing
    is essential at overlaps and antialiased edges.
    """

    if source.shape != destination_rgba8.shape or source.shape[-1] != 4:
        raise ValueError("MiiMask blend source and target shapes differ")
    if not np.all(np.isfinite(source)):
        raise ValueError("MiiMask blend source contains non-finite values")
    if np.any(source[..., 3] < 0.0) or np.any(source[..., 3] > 1.0):
        raise ValueError("MiiMask shader alpha is outside the recovered UNORM domain")
    destination = destination_rgba8.astype(np.float64) / 255.0
    output = destination.copy()
    drawn = source[..., 3] != 0.0
    if rgb_state == "pass_0_one_zero":
        output[drawn, :3] = source[drawn, :3]
    elif rgb_state == "pass_1_one_one_minus_source_alpha":
        source_alpha = source[drawn, 3, None]
        output[drawn, :3] = (
            source[drawn, :3] + destination[drawn, :3] * (1.0 - source_alpha)
        )
    else:
        raise ValueError(f"unknown MiiMask RGB blend state {rgb_state!r}")
    output[drawn, 3] = source[drawn, 3] + destination[drawn, 3]
    return _store_rgba8(output)


def _execute_mii_mask_title_pipeline(
    shaded_layers: list[tuple[int, np.ndarray]],
    canvas_size: tuple[int, int],
) -> MiiMaskPipelineResult:
    """Execute the generic clear/pass0/case21/pass1 MiiMask sequence.

    The checked Kestron instance submits seven active cases and therefore 15
    draws.  Other CharInfoEx records gate a different number of cases, but use
    this identical sequence and fixed-function state.
    """

    _mii_mask_fixed_function_contract()
    width, height = canvas_size
    if width <= 0 or height <= 0:
        raise ValueError("MiiMask target dimensions must be positive")
    ordered = sorted(shaded_layers, key=lambda item: item[0])
    cases = tuple(int(case) for case, _source in ordered)
    if len(cases) != len(set(cases)) or any(case < 0 or case > 20 for case in cases):
        raise ValueError("MiiMask active dispatcher cases are duplicated or outside 0..20")
    expected_shape = (height, width, 4)
    for case, source in ordered:
        if source.shape != expected_shape:
            raise ValueError(f"MiiMask case {case} has target shape {source.shape!r}")

    stored = np.zeros(expected_shape, dtype=np.uint8)
    pass0_hashes: list[str] = []
    for _case, source in ordered:
        stored = _blend_mii_mask_draw(stored, source, rgb_state="pass_0_one_zero")
        pass0_hashes.append(hashlib.sha256(stored.tobytes()).hexdigest())
    pass0 = stored.copy()

    # Selector zero returns C1=(0,0,0,1), case 21 covers the full target, and
    # SRC_ALPHA/ONE_MINUS_SRC_ALPHA therefore stores opaque black everywhere.
    # Alpha's ONE/ONE add also clamps to one regardless of pass-0 coverage.
    case21 = np.zeros(expected_shape, dtype=np.uint8)
    case21[..., 3] = 255
    stored = case21.copy()

    pass1_hashes: list[str] = []
    for _case, source in ordered:
        stored = _blend_mii_mask_draw(
            stored,
            source,
            rgb_state="pass_1_one_one_minus_source_alpha",
        )
        pass1_hashes.append(hashlib.sha256(stored.tobytes()).hexdigest())
    if not np.all(stored[..., 3] == 255):
        raise ValueError("MiiMask case21/pass1 target alpha is not opaque")

    # GameAll0 literally exports alpha one and has no KIL, so feeding the
    # target's opaque alpha to mt_Mask would expose the complete identity-space
    # shield.  Pass 0 supplies the only source-backed per-feature alpha before
    # case 21 destroys it: ADD(ONE,ONE), stored to the same RGBA8_UNORM target
    # after every draw.  Carry that byte plane explicitly as the portable
    # unresolved-pass coverage input while retaining pass-1's exact RGB.
    mesh_input = stored.copy()
    mesh_input[..., 3] = pass0[..., 3]
    mesh_input[mesh_input[..., 3] == 0, :3] = 0
    return MiiMaskPipelineResult(
        dispatcher_cases=cases,
        pass0_target_rgba8=pass0,
        case21_target_rgba8=case21,
        final_target_rgba8=stored,
        mesh_input_rgba8=mesh_input,
        pass0_draw_sha256=tuple(pass0_hashes),
        pass1_draw_sha256=tuple(pass1_hashes),
    )


_execute_mii_mask_title_pipeline_python = _execute_mii_mask_title_pipeline
if native_face_target.BACKEND_AVAILABLE:
    _execute_mii_mask_title_pipeline = (
        native_face_target.execute_mii_mask_title_pipeline
    )


def _rotation_degrees(selector: int, user_rotation: int, table: tuple[int, ...]) -> float:
    base = table[selector] if 0 <= selector < len(table) else 4
    ticks = (user_rotation + 32 - base) % 32
    return ticks * (360.0 / 32.0)


def _descriptor_pivot(
    origin_x: float,
    origin_y: float,
    width: float,
    height: float,
    rotation_degrees: float,
    axis_x: float,
    axis_y: float,
) -> tuple[float, float]:
    """Recover descriptor slots 7/8 written by FUN_7101d77130.

    These are the rotation pivot consumed by the extended eye-accessory
    helpers.  They are not the final bitmap center: X is still the Mii mask's
    mirrored inner-edge descriptor coordinate.
    """

    angle = np.deg2rad(rotation_degrees)
    sine = float(np.sin(angle))
    cosine = float(np.cos(angle))
    offset_x = width * axis_x
    offset_y = height * axis_y
    return (
        origin_x + (offset_y * sine + cosine * offset_x) / DESCRIPTOR_ROTATE_X_DIVISOR,
        origin_y - (offset_y * cosine - sine * offset_x) / DESCRIPTOR_ROTATE_Y_DIVISOR,
    )


def _side_origin_center(
    origin_x: float,
    origin_y: float,
    raw_width: float,
    rotation_degrees: float,
    direction: float,
) -> tuple[float, float]:
    """Convert a title LEFT/RIGHT edge origin to the rotated bitmap center."""

    angle = np.deg2rad(rotation_degrees)
    offset = np.asarray((direction * raw_width / 2.0, 0.0), dtype=np.float64)
    rotation = np.asarray(
        ((np.cos(angle), -np.sin(angle)), (np.sin(angle), np.cos(angle))),
        dtype=np.float64,
    )
    center = np.asarray((origin_x, origin_y), dtype=np.float64) + np.diag(
        (TEXTURE_SCALE_X, TEXTURE_SCALE_Y)
    ) @ rotation @ offset
    return float(center[0]), float(center[1])


def _pivoted_side_center(
    origin_x: float,
    origin_y: float,
    raw_width: float,
    raw_height: float,
    rotation_degrees: float,
    direction: float,
    axis_x: float,
    axis_y: float,
) -> tuple[float, float]:
    """Center an edge-origin sprite around its Parts ``RotateAxis`` pivot."""

    angle = np.deg2rad(rotation_degrees)
    rotation = np.asarray(
        ((np.cos(angle), -np.sin(angle)), (np.sin(angle), np.cos(angle))),
        dtype=np.float64,
    )
    pivot = np.asarray((direction * raw_width * axis_x, raw_height * axis_y))
    center = np.asarray((direction * raw_width / 2.0, 0.0))
    local = pivot + rotation @ (center - pivot)
    result = np.asarray((origin_x, origin_y)) + np.diag(
        (TEXTURE_SCALE_X, TEXTURE_SCALE_Y)
    ) @ local
    return float(result[0]), float(result[1])


def compose_face_texture(
    char_info: dict[str, Any],
    texture_root: Path,
    color_table_path: Path,
    resolution: int = 1024,
    transparent_base: bool = False,
    active_parts_path: Path = ACTIVE_PARTS_PATH,
    face_sprite_mip_manifests: tuple[Path, ...] | None = None,
    classic_resource_signature_records: dict[str, dict[str, Any]] | None = None,
) -> tuple[Image.Image, dict[str, Any]]:
    """Return one recovered MiiMask target view and an auditable report.

    ``transparent_base=False`` returns the literal opaque case21/pass1 target.
    ``transparent_base=True`` is the downstream portable mesh view: identical
    stored RGB plus the separately preserved pass0 feature-coverage alpha.  The
    argument name is retained for callers, but it no longer selects an invented
    skin/transparent Pillow background.
    """

    colors = json.loads(color_table_path.read_text(encoding="utf-8"))
    manifest_paths = tuple(
        path.resolve()
        for path in (
            face_sprite_mip_manifests
            if face_sprite_mip_manifests is not None
            else (FACE_SPRITE_MIP_MANIFEST,)
        )
    )
    if not manifest_paths:
        raise ValueError("at least one exact face-sprite mip manifest is required")
    active_records = _active_records(active_parts_path)
    classic_contract: dict[str, Any] | None = None
    if any(path.name == "classic_bridge_face_sprite_mips.json" for path in manifest_paths):
        _validate_disabled_ordinary_sprite_records(
            active_records, classic_resource_signature_records
        )
        classic_contract = _validate_classic_face_selection(
            active_records, char_info, classic_resource_signature_records
        )
    else:
        _validate_disabled_ordinary_sprite_records(active_records)
    skin = resolve_skin_color(colors, int(char_info["faceline_color"]))
    canvas_size = (resolution, resolution)
    placements: list[LayerPlacement] = []
    draw_queue: list[tuple[int, Image.Image, LayerPlacement, PixelShader | None]] = []

    eye_scale = 0.4 * char_info["eye_scale"] + 1.0
    eye_aspect = 0.12 * char_info["eye_aspect"] + 0.64
    eye_width = 5.34375 * eye_scale * TEXTURE_SCALE_X
    eye_height = 4.5 * eye_scale * eye_aspect * TEXTURE_SCALE_Y
    eye_spacing = char_info["eye_x"] * SPACING_MULTIPLIER
    eye_y = char_info["eye_y"] * POSITION_Y_MULTIPLIER + EYE_Y_ADD
    eye_rotation = _rotation_degrees(char_info["eye_type"], char_info["eye_rotate"], EYE_ROTATION_BASE)
    selected_eye = _selected_texture(active_records, "eye", char_info)
    if selected_eye is None:
        _require_exact_nothing_record(
            active_records, "eye", "EyeNothing", classic_resource_signature_records
        )
        eye_source_name = ""
        eye_parts_record = "EyeNothing"
        eye_source: Image.Image | None = None
    else:
        eye_source_name, eye_parts_record = selected_eye
        eye_source = Image.open(texture_root / eye_source_name)
    black = (0, 0, 0, 255)
    white = (255, 255, 255, 255)
    eye_color = _common_color(colors, char_info["eye_color"])
    eye_color_float = np.asarray(eye_color[:3], dtype=np.float64) / 255.0
    eye_shadow_color = _common_color(colors, int(char_info["eye_shadow_color"]))
    eye_shadow_color_float = np.asarray(eye_shadow_color[:3], dtype=np.float64) / 255.0

    def eye_mode_7(sample: np.ndarray) -> np.ndarray:
        """MiiMask mode 7: RGB=G*C2+B*C3, A=saturate(A-R)."""

        result = np.empty_like(sample)
        result[..., :3] = sample[..., 1, None] + sample[..., 2, None] * eye_color_float
        result[..., 3] = np.clip(sample[..., 3] - sample[..., 0], 0.0, 1.0)
        return result

    def eye_mode_2(sample: np.ndarray) -> np.ndarray:
        """MiiMask mode 2: RGB=R*C1+G*C2+B*C3, A=sample A."""

        result = np.empty_like(sample)
        result[..., :3] = (
            sample[..., 0, None] * eye_shadow_color_float
            + sample[..., 1, None]
            + sample[..., 2, None] * eye_color_float
        )
        result[..., 3] = sample[..., 3]
        return result

    eye_shadow_enabled = bool(char_info["face_flags"]["eye_shadow_enabled"])
    eye_shader_mode = 2 if eye_shadow_enabled else 7
    eye_shader = eye_mode_2 if eye_shadow_enabled else eye_mode_7

    # RIGHT/LEFT refer to the character. The recovered quad origins anchor at
    # the inner edge and mirror the left-eye texture coordinates.
    for dispatcher_case, name, inner_x, direction, mirrored, rotation in (
        (16, "eye_character_right", 32.0 - eye_spacing, -1.0, False, eye_rotation),
        (17, "eye_character_left", 32.0 + eye_spacing, 1.0, True, (360.0 - eye_rotation) % 360.0),
    ):
        if eye_source is None:
            break
        center_x, center_y = _side_origin_center(
            inner_x, eye_y, eye_width / TEXTURE_SCALE_X, rotation, direction
        )
        placement = LayerPlacement(
            name=name,
            source_texture=eye_source_name,
            center_x=center_x,
            center_y=center_y,
            width=eye_width,
            height=eye_height,
            rotation_degrees=rotation,
            mirrored=mirrored,
            selector=char_info["eye_type"],
            parts_record=eye_parts_record,
            dispatcher_case=dispatcher_case,
            modulation_mode=eye_shader_mode,
        )
        draw_queue.append((dispatcher_case, eye_source, placement, eye_shader))

    # FUN_7101d73ee0/74350/74850/74d50/75260 combine each serialized
    # accessory tuple with the selected eye's exact RSDB default row.  All 60
    # classic rows are frozen in classic_face_presentation.json.
    selected_accessories = {
        logical_name: _selected_texture(active_records, logical_name, char_info)
        for logical_name in (
            "eye_highlight", "eyelash_upper", "eyelash_lower",
            "eyelid_upper", "eyelid_lower",
        )
    }
    if any(value is not None for value in selected_accessories.values()):
        if eye_source is None:
            raise ValueError("an enabled eye accessory requires a renderable eye record")
        presentation = classic_contract or _classic_face_presentation_contract()
        eye_contract = presentation["resource_contract"]["eye_accessory_rows"].get(
            str(int(char_info["eye_type"]))
        )
        if eye_contract is None or eye_contract["eye_record"] != active_records["eye"]["record"]:
            raise ValueError("selected eye has no matching EyeAccessoryRef contract")
        default_row = eye_contract["defaults"]
        eye_axis = eye_contract["axis_for_expression"]
        eye_raw_width = eye_width / TEXTURE_SCALE_X
        eye_raw_height = eye_height / TEXTURE_SCALE_Y
        eye_parent_aspect = eye_raw_height / (eye_raw_width * 0.84210527)

        def mode_3(color: tuple[int, int, int, int]) -> PixelShader:
            color_float = np.asarray(color[:3], dtype=np.float64) / 255.0

            def shader(sample: np.ndarray) -> np.ndarray:
                result = np.empty_like(sample)
                result[..., :3] = color_float
                result[..., 3] = sample[..., 0]
                return result

            return shader

        accessory_specs = (
            ("eye_highlight", "Highlight", 6, white, "highlight"),
            ("eyelash_upper", "EyelashUpper", 8, black, "lash"),
            ("eyelash_lower", "EyelashLower", 10, black, "lash"),
            ("eyelid_upper", "EyelidUpper", 12, black, "lid"),
            ("eyelid_lower", "EyelidLower", 14, black, "lid"),
        )
        for logical_name, row_prefix, first_case, color, kind in accessory_specs:
            selected = selected_accessories[logical_name]
            if selected is None:
                continue
            texture_name, parts_record = selected
            source = Image.open(texture_root / texture_name)
            pos = default_row[f"{row_prefix}Pos"]
            limits = {"x": 32 if kind == "highlight" else 31,
                      "y": 32 if kind == "highlight" else (36 if kind == "lid" else 31),
                      "rotate": 31, "scale": 14, "aspect": 6}
            defaults = {
                "x": int(pos["X"]), "y": int(pos["Y"]),
                "rotate": int(default_row[f"{row_prefix}Rotate"]),
                "scale": int(default_row[f"{row_prefix}Scale"]),
                "aspect": int(default_row[f"{row_prefix}Aspect"]),
            }
            values = {
                field: min(limits[field], max(0, defaults[field] + int(char_info[f"{logical_name}_{field}"])))
                for field in defaults
            }
            if kind == "highlight":
                fit_width = eye_raw_width
                if int(char_info["eye_highlight_y"]) & 1:
                    fit_width = min(eye_raw_width, eye_raw_height / 0.84210527)
                raw_width = (values["scale"] * 0.0345479 + 0.1554656) * fit_width
                raw_height = (values["aspect"] * 0.12 + 0.64) * raw_width
            else:
                scale_add = 5 if kind == "lash" else 8
                scale_factor = 0.035714287 if kind == "lash" else 0.04
                raw_width = (values["scale"] + scale_add) * scale_factor * eye_raw_width
                raw_height = (values["aspect"] * 0.12 + 0.64) * 0.84210527 * raw_width

            for side_offset, direction, mirrored, base_rotation in (
                (0, -1.0, False, eye_rotation),
                (1, 1.0, True, -eye_rotation),
            ):
                eye_origin_x = 32.0 + direction * eye_spacing
                pivot_x, pivot_y = _descriptor_pivot(
                    eye_origin_x, eye_y, eye_raw_width, eye_raw_height,
                    base_rotation, float(eye_axis["X"]) * direction, float(eye_axis["Y"]),
                )
                if kind == "highlight":
                    center_x = pivot_x + (
                        (values["x"] / 32.0 - 0.5) * eye_raw_width
                    ) / -DESCRIPTOR_ROTATE_X_DIVISOR
                    center_y = pivot_y + (
                        (values["y"] / 32.0 - 0.5) * eye_raw_height
                    ) / DESCRIPTOR_ROTATE_Y_DIVISOR
                    parent_aspect = 1.0
                    parent_rotation = 0.0
                else:
                    angle = np.deg2rad(base_rotation)
                    sine, cosine = float(np.sin(angle)), float(np.cos(angle))
                    offset_x = direction * eye_raw_width * (
                        values["x"] / 31.0 - float(eye_axis["X"])
                    )
                    y_value = values["y"] - (5 if kind == "lid" else 0)
                    offset_y = -eye_raw_height * (
                        float(eye_axis["Y"]) + y_value / 31.0 - 0.5
                    )
                    center_x = pivot_x + (
                        sine * offset_y + cosine * offset_x
                    ) / DESCRIPTOR_ROTATE_X_DIVISOR
                    center_y = pivot_y + (
                        cosine * offset_y - sine * offset_x
                    ) / -DESCRIPTOR_ROTATE_Y_DIVISOR
                    parent_aspect = eye_parent_aspect
                    parent_rotation = base_rotation
                own_rotation = direction * -1.0 * values["rotate"] * (360.0 / 32.0)
                placement = LayerPlacement(
                    name=f"{logical_name}_character_{'right' if side_offset == 0 else 'left'}",
                    source_texture=texture_name,
                    center_x=center_x,
                    center_y=center_y,
                    width=raw_width * TEXTURE_SCALE_X,
                    height=raw_height * TEXTURE_SCALE_Y,
                    rotation_degrees=own_rotation % 360.0,
                    mirrored=mirrored,
                    selector=int(char_info[f"{logical_name}_type"]),
                    parts_record=parts_record,
                    dispatcher_case=first_case + side_offset,
                    modulation_mode=3,
                    parent_aspect=parent_aspect,
                    parent_rotation_degrees=parent_rotation,
                )
                draw_queue.append((first_case + side_offset, source, placement, mode_3(color)))

    eyebrow_scale = 0.4 * char_info["eyebrow_scale"] + 1.0
    eyebrow_aspect = 0.12 * char_info["eyebrow_aspect"] + 0.64
    eyebrow_width = 5.0625 * eyebrow_scale * TEXTURE_SCALE_X
    eyebrow_height = 4.5 * eyebrow_scale * eyebrow_aspect * TEXTURE_SCALE_Y
    # FUN_7101d73b50 subtracts one full X-position step before mirroring the
    # two descriptor origins.  Omitting it moves both brows 1.7792293 mask
    # units too far outward.
    eyebrow_spacing = (
        char_info["eyebrow_x"] * SPACING_MULTIPLIER - POSITION_X_MULTIPLIER
    )
    eyebrow_y = char_info["eyebrow_y"] * POSITION_Y_MULTIPLIER + EYEBROW_Y_ADD
    eyebrow_rotation = _rotation_degrees(
        char_info["eyebrow_type"], char_info["eyebrow_rotate"], EYEBROW_ROTATION_BASE
    )
    selected_eyebrow = _selected_texture(active_records, "eyebrow", char_info)
    if selected_eyebrow is None:
        _require_exact_nothing_record(
            active_records,
            "eyebrow",
            "EyebrowNothing",
            classic_resource_signature_records,
        )
        eyebrow_name = ""
        eyebrow_parts_record = "EyebrowNothing"
        eyebrow_source: Image.Image | None = None
    else:
        eyebrow_name, eyebrow_parts_record = selected_eyebrow
        eyebrow_source = Image.open(texture_root / eyebrow_name)
    eyebrow_color = _common_color(colors, char_info["eyebrow_color"])
    eyebrow_color_float = np.asarray(eyebrow_color[:3], dtype=np.float64) / 255.0

    def eyebrow_mode_3(sample: np.ndarray) -> np.ndarray:
        """MiiMask mode 3: constant C1 RGB with sampled R as alpha."""

        result = np.empty_like(sample)
        result[..., :3] = eyebrow_color_float
        result[..., 3] = sample[..., 0]
        return result
    for dispatcher_case, name, inner_x, direction, mirrored, rotation in (
        (4, "eyebrow_character_right", 32.0 - eyebrow_spacing, -1.0, False, eyebrow_rotation),
        (5, "eyebrow_character_left", 32.0 + eyebrow_spacing, 1.0, True, (360.0 - eyebrow_rotation) % 360.0),
    ):
        if eyebrow_source is None:
            break
        center_x, center_y = _side_origin_center(
            inner_x, eyebrow_y, eyebrow_width / TEXTURE_SCALE_X, rotation, direction
        )
        placement = LayerPlacement(
            name=name,
            source_texture=eyebrow_name,
            center_x=center_x,
            center_y=center_y,
            width=eyebrow_width,
            height=eyebrow_height,
            rotation_degrees=rotation,
            mirrored=mirrored,
            selector=char_info["eyebrow_type"],
            parts_record=eyebrow_parts_record,
            dispatcher_case=dispatcher_case,
            modulation_mode=3,
        )
        draw_queue.append((dispatcher_case, eyebrow_source, placement, eyebrow_mode_3))

    mouth_scale = 0.4 * char_info["mouth_scale"] + 1.0
    mouth_aspect = 0.12 * char_info["mouth_aspect"] + 0.64
    mouth_width = 6.1875 * mouth_scale * TEXTURE_SCALE_X
    mouth_height = 4.5 * mouth_scale * mouth_aspect * TEXTURE_SCALE_Y
    mouth_y = char_info["mouth_y"] * POSITION_Y_MULTIPLIER + MOUTH_Y_ADD
    selected_mouth = _selected_texture(active_records, "mouth", char_info)
    if selected_mouth is None:
        _require_exact_nothing_record(
            active_records, "mouth", "MouthNothing", classic_resource_signature_records
        )
        mouth_name = ""
        mouth_parts_record = "MouthNothing"
        mouth_sprite: Image.Image | None = None
    else:
        mouth_name, mouth_parts_record = selected_mouth
        mouth_sprite = Image.open(texture_root / mouth_name)
    # face_flags.mouth_inverted is the title's default-lip shader selector.
    # FUN_7101d75d68 never flips the mouth quad or its texture coordinates.
    mouth_default_lip = bool(char_info["face_flags"]["mouth_inverted"])
    mouth_color = _common_color(colors, int(char_info["mouth_color"]))
    mouth_color_float = np.asarray(mouth_color[:3], dtype=np.float64) / 255.0

    def mouth_mode_2(sample: np.ndarray) -> np.ndarray:
        """MiiMask mode 2 default lip: C1=C2=mouth color, C3=white."""

        result = np.empty_like(sample)
        result[..., :3] = (
            (sample[..., 0, None] + sample[..., 1, None]) * mouth_color_float
            + sample[..., 2, None]
        )
        result[..., 3] = sample[..., 3]
        return result

    def mouth_mode_8(sample: np.ndarray) -> np.ndarray:
        """MiiMask mode 8: RGB=B*C3, A=saturate(A-R-G).

        Mouth015's Parts resource disables the default-lip path and its
        UseTextureColor query is false.  With the serialized mouth-inversion
        flag clear, FUN_7101d75d68 selects mode 8 for both checked targets.
        Its blue source channel is zero, so the surviving alpha is the narrow
        black residual/outline rather than another mouth part's lip-color
        blend.
        """

        result = np.empty_like(sample)
        result[..., :3] = sample[..., 2, None]
        result[..., 3] = np.clip(
            sample[..., 3] - sample[..., 0] - sample[..., 1], 0.0, 1.0
        )
        return result

    if mouth_sprite is not None:
        mouth_placement = LayerPlacement(
            name="mouth",
            source_texture=mouth_name,
            center_x=32.0,
            center_y=mouth_y,
            width=mouth_width,
            height=mouth_height,
            rotation_degrees=char_info["mouth_rotate"] * (360.0 / 32.0),
            mirrored=False,
            selector=char_info["mouth_type"],
            parts_record=mouth_parts_record,
            dispatcher_case=2,
            modulation_mode=2 if mouth_default_lip else 8,
        )
        draw_queue.append(
            (2, mouth_sprite, mouth_placement, mouth_mode_2 if mouth_default_lip else mouth_mode_8)
        )

    # FUN_7101d75d68 cases 0/1 and their helper recover two mirrored mustache
    # halves.  Both are anchored at x=32; the raw part width extends outward
    # from that shared inner edge.  The target's aspect byte is retained in
    # CharInfoEx and used by the title even though the legacy FFL lineage fixed
    # it to three.
    selected_mustache = _selected_texture(active_records, "mustache", char_info)
    if selected_mustache is not None:
        mustache_name, mustache_parts_record = selected_mustache
        mustache_color = _common_color(colors, char_info["mustache_color"])
        mustache_source = Image.open(texture_root / mustache_name)
        mustache_color_float = np.asarray(mustache_color[:3], dtype=np.float64) / 255.0

        def mustache_mode_3(sample: np.ndarray) -> np.ndarray:
            result = np.empty_like(sample)
            result[..., :3] = mustache_color_float
            result[..., 3] = sample[..., 0]
            return result
        mustache_scale = 0.4 * char_info["mustache_scale"] + 1.0
        mustache_aspect = 0.12 * char_info["mustache_aspect"] + 0.64
        mustache_width = 4.5 * mustache_scale * TEXTURE_SCALE_X
        mustache_height = 9.0 * mustache_scale * mustache_aspect * TEXTURE_SCALE_Y
        mustache_y = char_info["mustache_y"] * POSITION_Y_MULTIPLIER + MUSTACHE_Y_ADD
        rotate_axis = active_records["mustache"].get("resource_flags", {}).get(
            "RotateAxis", {"X": 0.0, "Y": 0.0}
        )
        if set(rotate_axis) != {"X", "Y"}:
            raise ValueError("mustache RotateAxis evidence is malformed")
        inverted_rotation = 180.0 if char_info["face_flags"]["mustache_inverted"] else 0.0
        for dispatcher_case, name, direction, mirrored, rotation in (
            (0, "mustache_character_right", -1.0, False, inverted_rotation),
            (1, "mustache_character_left", 1.0, True, -inverted_rotation),
        ):
            center_x, center_y = _pivoted_side_center(
                32.0,
                mustache_y,
                mustache_width / TEXTURE_SCALE_X,
                mustache_height / TEXTURE_SCALE_Y,
                rotation,
                direction,
                float(rotate_axis["X"]),
                float(rotate_axis["Y"]),
            )
            placement = LayerPlacement(
                name=name,
                source_texture=mustache_name,
                center_x=center_x,
                center_y=center_y,
                width=mustache_width,
                height=mustache_height,
                rotation_degrees=rotation % 360.0,
                mirrored=mirrored,
                selector=char_info["mustache_type"],
                parts_record=mustache_parts_record,
                dispatcher_case=dispatcher_case,
                modulation_mode=3,
            )
            draw_queue.append((dispatcher_case, mustache_source, placement, mustache_mode_3))

    selected_mole = _selected_texture(active_records, "mole", char_info)
    if selected_mole is not None:
        mole_name, mole_parts_record = selected_mole
        mole_source = Image.open(texture_root / mole_name)

        def mole_mode_3(sample: np.ndarray) -> np.ndarray:
            result = np.empty_like(sample)
            result[..., :3] = 0.0
            result[..., 3] = sample[..., 0]
            return result

        mole_raw_width = 0.4 * int(char_info["mole_scale"]) + 1.0
        mole_placement = LayerPlacement(
            name="mole",
            source_texture=mole_name,
            center_x=int(char_info["mole_x"]) * POSITION_X_MULTIPLIER + 17.766165,
            center_y=int(char_info["mole_y"]) * POSITION_Y_MULTIPLIER + 17.959862,
            width=mole_raw_width * TEXTURE_SCALE_X,
            height=mole_raw_width * TEXTURE_SCALE_Y,
            rotation_degrees=0.0,
            mirrored=False,
            selector=int(active_records["mole"]["selector"]),
            parts_record=mole_parts_record,
            dispatcher_case=20,
            modulation_mode=3,
        )
        draw_queue.append((20, mole_source, mole_placement, mole_mode_3))

    # The title's descriptor dispatcher draws cases 0..20 in order.  This is
    # observable where the mustache overlaps the mouth: the mouth must land on
    # top, followed by brows/accessories and finally the eyes.  Queueing keeps
    # that order independent from the calculation order above.
    shaded_layers: list[tuple[int, np.ndarray]] = []
    for dispatcher_case, sprite, placement, pixel_shader in sorted(
        draw_queue, key=lambda item: item[0]
    ):
        sampled_sprite, sampled_placement = _select_native_sprite_mip(
            sprite, placement, resolution, FACE_UNITS, active_records, char_info, manifest_paths
        )
        shaded_layers.append(
            (
                dispatcher_case,
                _sample_shaded_layer(
                    canvas_size,
                    sampled_sprite,
                    sampled_placement,
                    pixel_shader=pixel_shader,
                ),
            )
        )
        placements.append(sampled_placement)
    pipeline = _execute_mii_mask_title_pipeline(shaded_layers, canvas_size)
    returned_rgba8 = (
        pipeline.mesh_input_rgba8 if transparent_base else pipeline.final_target_rgba8
    )
    canvas = Image.fromarray(returned_rgba8, mode="RGBA")

    face_layer_names = (
        "wrinkle_lower", "wrinkle_upper", "makeup_upper", "makeup_lower",
        "eye_highlight", "eyelash_upper", "eyelash_lower", "eyelid_upper",
        "eyelid_lower", "beard_short", "mole",
    )
    omitted = [
        {
            "logical_name": name,
            "field": active_records[name].get("selector_field"),
            "selector": active_records[name]["selector"],
            "record": active_records[name].get("record"),
            "gate": active_records[name].get("gate"),
        }
        for name in face_layer_names
        if not active_records[name].get("enabled")
    ]
    # These enabled records are not MiiMask quads. The faceline-target
    # dispatcher submits them as full-target Head816 layers in exact order;
    # keeping them out of this transparent Mask0 atlas is intentional.
    separate_faceline_target_layers = []
    for logical_name in (
        "makeup_lower",
        "makeup_upper",
        "wrinkle_upper",
        "wrinkle_lower",
        "beard_short",
    ):
        record = active_records[logical_name]
        if not record.get("enabled"):
            continue
        separate_faceline_target_layers.append(
            {
                "logical_name": logical_name,
                "field": record.get("selector_field"),
                "selector": record["selector"],
                "record": record.get("record"),
                "texture_name": record.get("texture_name"),
                "target": "faceline 128x256 -> Head816 _a0",
                "mask0_atlas_action": "not submitted",
            }
        )
    if not char_info["face_flags"]["eye_shadow_enabled"]:
        omitted.append(
            {"logical_name": "eye_shadow", "field": "face_flags.eye_shadow_enabled", "selector": 0,
             "record": "disabled flag", "gate": "face_flags.eye_shadow_enabled"}
        )
    fixed_function = _mii_mask_fixed_function_contract()
    coverage_alpha = pipeline.mesh_input_rgba8[..., 3]
    coverage_sha256 = hashlib.sha256(coverage_alpha.tobytes()).hexdigest()
    final_sha256 = hashlib.sha256(pipeline.final_target_rgba8.tobytes()).hexdigest()
    mesh_sha256 = hashlib.sha256(pipeline.mesh_input_rgba8.tobytes()).hexdigest()
    report = {
        "presentation_contract": (
            {
                "status": "source_backed_complete_classic_face_presentation",
                "key": "classic_face_presentation_v1",
                "path": CLASSIC_FACE_PRESENTATION.name,
                "sha256": _sha256(CLASSIC_FACE_PRESENTATION),
                "faceline_contract_key": classic_contract["faceline_target_contract"]["key"],
                "mouth_inverted_semantic": classic_contract["char_info_admission"]["mouth_inverted_semantic"],
                "face_texture_invariant_flags": classic_contract["char_info_admission"]["face_texture_invariant_flags"],
            }
            if classic_contract is not None
            else None
        ),
        "coordinate_system": "64x64 recovered FFL mask space; +x right, +y down",
        "transform_order": (
            "local part scale -> own rotation -> optional parent-eye Y aspect/rotation "
            "-> render-target X/Y scale -> translation"
        ),
        "sampler": {
            "source": "FUN_7101d88f98 -> FUN_7100ba6e00",
            "descriptor_bytes": "01 01 01 00 00 01 29 00",
            "filter_word": "0x29",
            "minification": "linear",
            "magnification": "linear",
            "mip_filter": "nearest",
            "lod_bias": -0.7,
            "address_mode_uvw": "mirror",
            "border_color": "white",
            "max_anisotropy": "1:1",
            "lod_formula": (
                "rho=max(length(d(source_texel)/dx),length(d(source_texel)/dy)); "
                "lod=clamp(log2(rho)-0.7,0,13); level=floor(lod+0.5)"
            ),
            "mip_manifest": FACE_SPRITE_MIP_MANIFEST.name,
            "mip_manifests": [path.name for path in manifest_paths],
            "target_resolution_result": {
                placement.name: {
                    "texture": placement.source_texture,
                    "rho": placement.source_rho,
                    "biased_lod": placement.source_biased_lod,
                    "selected_level": placement.source_mip_level,
                    "selected_dimensions": list(placement.source_mip_dimensions or ()),
                    "manifest": placement.source_mip_manifest,
                    "packed_bntx_sha256": placement.source_bntx_sha256,
                }
                for placement in placements
            },
            "target_address_result": "all active quad UVs remain in 0..1",
        },
        "resolution": resolution,
        "transparent_base": transparent_base,
        "returned_image_role": (
            "portable Mask0 mesh input: exact pass1 RGB plus explicit pass0 coverage alpha"
            if transparent_base
            else "literal MiiMask case21/pass1 RGBA8_UNORM target"
        ),
        "ordinary_mask_target": {
            "status": "source_backed_generic_fixed_function_sequence",
            "evidence": {
                "path": fixed_function["ledger_path"],
                "sha256": fixed_function["ledger_sha256"],
            },
            "source_dimensions": fixed_function["source_dimensions"],
            "executed_dimensions": [resolution, resolution],
            "dimension_status": (
                "exact title dimensions" if resolution == 256 else "portable scaled specialization"
            ),
            "clear_rgba8": [0, 0, 0, 0],
            "dispatcher_cases": list(pipeline.dispatcher_cases),
            "sequence": [
                "pass0 active cases ascending",
                "case21 fullscreen opaque black",
                "pass1 active cases ascending",
            ],
            "submitted_draw_count": len(pipeline.dispatcher_cases) * 2 + 1,
            "checked_kestron_active_draw_count": 15,
            "pipeline_states": fixed_function["pipeline_states"],
            "rgba8_store_after_every_draw": True,
            "write_view": fixed_function["write_view"],
            "sample_view": fixed_function["sample_view"],
            "pass0_draw_rgba8_sha256": list(pipeline.pass0_draw_sha256),
            "pass0_final_rgba8_sha256": hashlib.sha256(
                pipeline.pass0_target_rgba8.tobytes()
            ).hexdigest(),
            "case21_rgba8_sha256": hashlib.sha256(
                pipeline.case21_target_rgba8.tobytes()
            ).hexdigest(),
            "final_rgba8_sha256": final_sha256,
            "final_alpha_values": [255],
        },
        "downstream_mask_coverage": {
            "status": "explicit_source_backed_companion_for_unresolved_engine_pass",
            "representation": (
                "pass0 ADD(ONE,ONE) alpha after per-draw RGBA8_UNORM stores; "
                "carried separately from the opaque native target alpha"
            ),
            "source_boundary": (
                "MiiMask shared epilogue discards output alpha zero; pass0 is the last "
                "source-backed feature-alpha plane before case21 forces target alpha one"
            ),
            "downstream_boundary": (
                "mt_Mask gequal 0.5 cutout is retained by the portable renderer; selected "
                "GameAll0 program 0 itself exports alpha one and has no KIL"
            ),
            "exact_engine_pass": "unresolved; companion alpha is not claimed as native target alpha",
            "alpha_sha256": coverage_sha256,
            "mesh_input_rgba8_sha256": mesh_sha256,
            "alpha_min": int(coverage_alpha.min()),
            "alpha_max": int(coverage_alpha.max()),
            "transparent_pixels": int(np.count_nonzero(coverage_alpha == 0)),
            "partial_alpha_pixels": int(
                np.count_nonzero((coverage_alpha > 0) & (coverage_alpha < 255))
            ),
            "opaque_pixels": int(np.count_nonzero(coverage_alpha == 255)),
            "zero_rgb_below_zero_alpha": True,
            "portable_alpha_test": {"function": "gequal", "value": 0.5},
        },
        "empty_ordinary_sprite_slots": [
            {
                "logical_name": logical_name,
                "record": active_records[logical_name]["record"],
                "selector": active_records[logical_name]["selector"],
            }
            for logical_name in ORDINARY_MASK_NOTHING_RECORDS
            if not active_records[logical_name].get("enabled")
        ],
        "skin_selector": char_info["faceline_color"],
        "skin_srgb_rgba8": list(skin),
        "skin_hex": "#" + "".join(f"{channel:02X}" for channel in skin),
        "eye_shadow_enabled": eye_shadow_enabled,
        "eye_shadow_srgb_rgba8": list(eye_shadow_color),
        "mouth_default_lip_enabled": mouth_default_lip,
        "active_parts_manifest": str(active_parts_path.name),
        "placements": [asdict(placement) for placement in placements],
        "separate_faceline_target_layers": separate_faceline_target_layers,
        "explicitly_omitted_layers": omitted,
    }
    return canvas, report
