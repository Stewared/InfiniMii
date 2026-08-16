"""Render the supplied Living-the-Dream ShareMii from recovered game assets.

The renderer consumes the exact CharInfoEx selectors in a checked ShareMii, the
PartsIndex-resolved Nintendo BFRES models and BNTX-derived textures, recovered
FFL color tables, and recovered 64-unit face-layout equations.  It creates a
deterministic reconstructed portrait plus an optional posed full-body preview.
The ShareMii record does not contain a clothing/outfit identifier, so full-body
mode uses a checked, explicitly labeled title-resource presentation outfit and
the title's one-frame IconPose animation.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image


def _console_print(value: object) -> None:
    """Write a CLI summary without letting a host code page fail the render."""

    text = str(value)
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    safe_text = text.encode(encoding, errors="backslashreplace").decode(encoding)
    print(safe_text)


def _presentation_context_digest(
    *,
    kind: str | None = None,
    ltd_sha256: str | None = None,
    canonical_hair_type: int | None = None,
    source_hair_type: int | None = None,
    favorite_color: int | None = None,
    legacy_headwear_source_type: int | None = None,
) -> str:
    digest = hashlib.sha256()
    digest.update(PRESENTATION_CONTEXT_DOMAIN)
    if kind is None:
        digest.update(b"none")
    elif kind == INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND:
        digest.update(kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(ltd_sha256).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(favorite_color).encode("ascii"))
        digest.update(b"\0")
        digest.update(
            (
                str(legacy_headwear_source_type)
                if legacy_headwear_source_type is not None
                else "none"
            ).encode("ascii")
        )
    else:
        digest.update(kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(ltd_sha256).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(canonical_hair_type).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(source_hair_type).encode("ascii"))
    return digest.hexdigest()


def _load_presentation_context(
    path: Path | None,
    document: dict[str, Any],
) -> dict[str, Any]:
    """Load the optional stored-source presentation discriminator fail-closed."""

    if path is None:
        return {
            "kind": "none",
            "sha256": _presentation_context_digest(),
            "for_hat": False,
            "source_hair_type": None,
            "canonical_hair_type": int(document["char_info"]["hair_type"]),
            "favorite_color": None,
            "favorite_color_rgb_hex": None,
            "favorite_shirt": inactive_favorite_shirt_report(),
            "source_boundary": "no external stored-source presentation context supplied",
        }
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_size > 4096:
        raise ValueError("presentation context must be a small regular JSON file")
    value = _load_request_json(resolved)
    legacy_expected_keys = {
        "schemaVersion",
        "kind",
        "ltdSha256",
        "canonicalHairType",
        "sourceHairType",
    }
    favorite_expected_keys = {
        "schemaVersion",
        "kind",
        "ltdSha256",
        "favoriteColor",
        "legacyHeadwearSourceType",
    }
    if not isinstance(value, dict):
        raise ValueError("presentation context schema changed")
    if value.get("kind") == INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND:
        if set(value) != favorite_expected_keys:
            raise ValueError("favorite-shirt presentation context schema changed")
        raw_ltd_sha256 = value.get("ltdSha256")
        ltd_sha256 = raw_ltd_sha256.lower() if isinstance(raw_ltd_sha256, str) else ""
        favorite_color = value.get("favoriteColor")
        legacy_headwear_source_type = value.get("legacyHeadwearSourceType")
        if (
            value.get("schemaVersion") != 1
            or not isinstance(raw_ltd_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", ltd_sha256)
            or ltd_sha256 != document["sha256"]
            or type(favorite_color) is not int
            or not 0 <= favorite_color < len(INFINIMII_FAVORITE_SHIRT_RGB_HEX)
            or (
                legacy_headwear_source_type is not None
                and (
                    type(legacy_headwear_source_type) is not int
                    or legacy_headwear_source_type not in (34, 57)
                )
            )
            or (
                legacy_headwear_source_type is not None
                and int(document["char_info"]["hair_type"]) != 45
            )
        ):
            raise ValueError(
                "presentation context is outside the InfiniMii favorite-shirt policy domain"
            )
        rgb_hex = INFINIMII_FAVORITE_SHIRT_RGB_HEX[favorite_color]
        normalized = {
            "kind": INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
            "favorite_color": favorite_color,
            "favorite_color_rgb_hex": rgb_hex,
        }
        favorite_selection = favorite_shirt_selection_from_context(normalized)
        if favorite_selection is None:
            raise ValueError("favorite-shirt context did not resolve a palette selection")
        return {
            **normalized,
            "sha256": _presentation_context_digest(
                kind=INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
                ltd_sha256=ltd_sha256,
                favorite_color=favorite_color,
                legacy_headwear_source_type=legacy_headwear_source_type,
            ),
            "for_hat": legacy_headwear_source_type is not None,
            "source_hair_type": legacy_headwear_source_type,
            "canonical_hair_type": int(document["char_info"]["hair_type"]),
            "favorite_shirt": favorite_selection.report(),
            "source_boundary": (
                "trusted InfiniMii original stored/source general.favoriteColor; "
                "LTD-hash-bound explicit site presentation policy, not title-exact behavior"
            ),
        }
    if set(value) != legacy_expected_keys:
        raise ValueError("presentation context schema changed")
    if (
        type(value["schemaVersion"]) is not int
        or not isinstance(value["kind"], str)
        or not isinstance(value["ltdSha256"], str)
        or type(value["canonicalHairType"]) is not int
        or type(value["sourceHairType"]) is not int
    ):
        raise ValueError("presentation context field types changed")
    ltd_sha256 = value["ltdSha256"].lower()
    canonical_hair_type = value["canonicalHairType"]
    source_hair_type = value["sourceHairType"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != LEGACY_HEADWEAR_CONTEXT_KIND
        or not re.fullmatch(r"[0-9a-f]{64}", ltd_sha256)
        or ltd_sha256 != document["sha256"]
        or canonical_hair_type != 45
        or int(document["char_info"]["hair_type"]) != canonical_hair_type
        or source_hair_type not in (34, 57)
    ):
        raise ValueError("presentation context is outside the checked legacy-headwear domain")
    return {
        "kind": LEGACY_HEADWEAR_CONTEXT_KIND,
        "sha256": _presentation_context_digest(
            kind=LEGACY_HEADWEAR_CONTEXT_KIND,
            ltd_sha256=ltd_sha256,
            canonical_hair_type=canonical_hair_type,
            source_hair_type=source_hair_type,
        ),
        "for_hat": True,
        "source_hair_type": source_hair_type,
        "canonical_hair_type": canonical_hair_type,
        "favorite_color": None,
        "favorite_color_rgb_hex": None,
        "favorite_shirt": inactive_favorite_shirt_report(),
        "source_boundary": (
            "trusted InfiniMii stored-source discriminator for a lossy legacy "
            "hair 34/57 to CharInfoEx hair 45 conversion; the LTD bytes themselves "
            "do not contain a headwear selector"
        ),
    }

try:
    from . import gameuber_cpu, native_current_draw
    from .classic_bridge_support import active_resource_signature, resolve_capability
    from .classic_mii_normalization import (
        effective_char_info,
        load_checked_runtime_profile,
    )
    from .face_compositor import compose_face_texture, resolve_skin_color
    from .faceline_compositor import (
        JOHNNY_SHARE_MII_SHA256,
        SPIDER_MAN_NOIR_SHARE_MII_SHA256,
        compose_faceline_target,
    )
    from .face_mask_projection import (
        build_face_mask_lattice_mesh,
        face_mask_projection_report,
        load_face_mask_position_map,
    )
    from .infinimii_favorite_shirt import (
        EXPECTED_RGB_HEX as INFINIMII_FAVORITE_SHIRT_RGB_HEX,
        POLICY_KIND as INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
        FavoriteShirtSelection,
        inactive_report as inactive_favorite_shirt_report,
        selection_from_presentation_context as favorite_shirt_selection_from_context,
    )
    from .ltd_format import load_share_mii
    from .model_pose import (
        BoneBindTransform,
        PosedModel,
        attached_part_transform,
        bone_bind_transforms,
        mii_body_scale,
        pose_model,
        rigid_shape_bind_transform,
        skinned_shape_bind_contract,
    )
    from .share_mii_facepaint import (
        ShareMiiV3FacePaint,
        decode_share_mii_v3_facepaint,
    )
    from .runtime_file_cache import load_json_shared as _cached_load_json
    from .runtime_file_cache import load_json_uncached as _load_request_json
    from .runtime_file_cache import matches_file as _cached_matches_file
    from .runtime_file_cache import read_bytes as _cached_read_bytes
    from .runtime_file_cache import sha256 as _cached_sha256
    from .screen_space_face_shadow import (
        PORTABLE_CHEAP_SSS_INPUT,
        TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS,
        TitlePrepassAvailability,
        resolve_screen_space_face_visibility,
    )
    from .snapshot_postprocess import snapshot_pfx_tone_map_gamma0
    from .software_renderer import (
        GameUberBody348LocalMaterialInputs,
        GameUberMask0FacePaintInputs,
        MaterialStyle,
        ObjMesh,
        OrthographicRasterizer,
        PerspectiveRasterizer,
        DrawRecorder,
        identity,
        load_obj,
        rotation_z,
        scale,
        texture_from_image,
        translation,
        validate_material_style_routing,
    )
except ImportError:  # Direct ``python renderer/render_mii.py`` invocation.
    import gameuber_cpu
    import native_current_draw
    from classic_bridge_support import active_resource_signature, resolve_capability
    from classic_mii_normalization import effective_char_info, load_checked_runtime_profile
    from face_compositor import compose_face_texture, resolve_skin_color
    from faceline_compositor import (
        JOHNNY_SHARE_MII_SHA256,
        SPIDER_MAN_NOIR_SHARE_MII_SHA256,
        compose_faceline_target,
    )
    from face_mask_projection import (
        build_face_mask_lattice_mesh,
        face_mask_projection_report,
        load_face_mask_position_map,
    )
    from infinimii_favorite_shirt import (
        EXPECTED_RGB_HEX as INFINIMII_FAVORITE_SHIRT_RGB_HEX,
        POLICY_KIND as INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
        FavoriteShirtSelection,
        inactive_report as inactive_favorite_shirt_report,
        selection_from_presentation_context as favorite_shirt_selection_from_context,
    )
    from ltd_format import load_share_mii
    from model_pose import (
        BoneBindTransform,
        PosedModel,
        attached_part_transform,
        bone_bind_transforms,
        mii_body_scale,
        pose_model,
        rigid_shape_bind_transform,
        skinned_shape_bind_contract,
    )
    from share_mii_facepaint import ShareMiiV3FacePaint, decode_share_mii_v3_facepaint
    from runtime_file_cache import load_json_shared as _cached_load_json
    from runtime_file_cache import load_json_uncached as _load_request_json
    from runtime_file_cache import matches_file as _cached_matches_file
    from runtime_file_cache import read_bytes as _cached_read_bytes
    from runtime_file_cache import sha256 as _cached_sha256
    from screen_space_face_shadow import (
        PORTABLE_CHEAP_SSS_INPUT,
        TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS,
        TitlePrepassAvailability,
        resolve_screen_space_face_visibility,
    )
    from snapshot_postprocess import snapshot_pfx_tone_map_gamma0
    from software_renderer import (
        GameUberBody348LocalMaterialInputs,
        GameUberMask0FacePaintInputs,
        MaterialStyle,
        ObjMesh,
        OrthographicRasterizer,
        PerspectiveRasterizer,
        DrawRecorder,
        identity,
        load_obj,
        rotation_z,
        scale,
        texture_from_image,
        translation,
        validate_material_style_routing,
    )


REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_ASSET_ROOT = REPOSITORY.parent / "ltdDemo_converted_assets"
MODEL_CACHE = REPOSITORY / "renderer" / "assets" / "models"
HEAD_ATTACHMENT_BONE_NAMES = ("set_beard", "set_ear", "set_hair", "set_nose")
TEXTURE_MIP_CACHE = REPOSITORY / "renderer" / "assets" / "texture_mips"
MII2_TEXTURE_MIP_CACHE = REPOSITORY / "renderer" / "assets" / "texture_mips_mii2"
MII3_TEXTURE_MIP_CACHE = REPOSITORY / "renderer" / "assets" / "texture_mips_mii3"
TEXTURE_MIPS = REPOSITORY / "renderer" / "texture_mips.json"
REFERENCE_TEXTURE_MIP_CACHE = (
    REPOSITORY / "renderer" / "assets" / "reference_outfit_texture_mips"
)
COLOR_TABLE = REPOSITORY / "renderer" / "assets" / "color_tables.json"
ICON_POSE = REPOSITORY / "renderer" / "assets" / "animations" / "IconPose.json"
ACTIVE_PARTS = REPOSITORY / "renderer" / "mii_active_parts.json"
MII2_ACTIVE_PARTS = REPOSITORY / "renderer" / "mii2_active_parts.json"
MII3_ACTIVE_PARTS = REPOSITORY / "renderer" / "mii3_active_parts.json"
MII4_ACTIVE_PARTS = REPOSITORY / "renderer" / "mii4_active_parts.json"
MII0_ACTIVE_PARTS = REPOSITORY / "renderer" / "mii0_active_parts.json"
REFERENCE_OUTFIT = REPOSITORY / "renderer" / "reference_capture_outfit.json"
PRESENTATION_OUTFIT = REPOSITORY / "renderer" / "presentation_outfit.json"
REFERENCE_OUTFIT_MATERIAL_STATE = (
    REPOSITORY / "renderer" / "reference_outfit_material_state.json"
)
REFERENCE_OUTFIT_TEXTURE_MIPS = (
    REPOSITORY / "renderer" / "reference_outfit_texture_mips.json"
)
REFERENCE_OUTFIT_TEXTURE_NAMES = tuple(
    f"ClothTopsTshirtLongTexDefault_Body_Alb.{variation:02d}"
    for variation in range(17)
) + (
    "ClothTopsTshirtLongTexDefault_Body_Nrm",
    "ClothTopsTshirtLongTexDefault_Body_Msk",
    "ClothTopsTshirtLongTexDefault_Body_Mic",
    "ClothBottomsPantsLongTexDefault_Body_Alb.00",
    "ClothBottomsPantsLongTexDefault_Body_Alb.10",
    "ClothBottomsPantsLongTexDefault_Body_Nrm",
    "ClothBottomsPantsLongTexDefault_Body_Msk",
    "ClothBottomsPantsLongTexDefault_Body_Mic",
    "ClothShoesStandardTexDefault_Body_Alb.00",
    "ClothShoesStandardTexDefault_Body_Alb.10",
    "ClothShoesStandardTexDefault_Body_Nrm",
    "ClothShoesStandardTexDefault_Body_Mic",
    "ClothSocksBodyBaseTexDefault_Socks_Alb.00",
    "ClothSocksBodyBaseTexDefault_Socks_Alb.10",
    "ClothSocksBodyBaseTexDefault_Socks_Nrm",
    "ClothSocksBodyBaseTexDefault_Socks_Skm",
)
REFERENCE_OUTFIT_MIP_CHAIN_HASH_SCOPE = (
    "sha256(UTF-8 JSON of the complete selected texture manifest record with "
    "sort_keys=True and separators=(',', ':'))"
)
MII_MASK_SEMANTICS = REPOSITORY / "renderer" / "mii_mask_semantics.json"
FACE_SPRITE_MIPS = REPOSITORY / "renderer" / "face_sprite_mips.json"
GAMEUBER_ACTIVE_PROGRAMS = REPOSITORY / "renderer" / "gameuber_active_programs.json"
TITLE_SHADER_EXECUTION = REPOSITORY / "renderer" / "title_shader_execution.json"
HAIR_SHADER_EXPRESSION = REPOSITORY / "renderer" / "hair_shader_expression.json"
MII2_TEXTURE_MIPS = REPOSITORY / "renderer" / "mii2_texture_mips.json"
MII2_GAMEUBER_PROGRAMS = REPOSITORY / "renderer" / "mii2_gameuber_programs.json"
MII3_TEXTURE_MIPS = REPOSITORY / "renderer" / "mii3_texture_mips.json"
MII3_GAMEUBER_PROGRAMS = REPOSITORY / "renderer" / "mii3_gameuber_programs.json"
CLASSIC_BRIDGE_TEXTURE_MIP_CACHE = (
    REPOSITORY / "renderer" / "assets" / "texture_mips_classic_bridge"
)
CLASSIC_BRIDGE_TEXTURE_MIPS = (
    REPOSITORY / "renderer" / "classic_bridge_texture_mips.json"
)
CLASSIC_BRIDGE_FACE_SPRITE_MIPS = (
    REPOSITORY / "renderer" / "classic_bridge_face_sprite_mips.json"
)
CLASSIC_BRIDGE_GAMEUBER_PROGRAMS = (
    REPOSITORY / "renderer" / "classic_bridge_gameuber_programs.json"
)
CLASSIC_BRIDGE_RESOURCE_BUNDLES = (
    REPOSITORY / "renderer" / "classic_bridge_resource_bundles.json"
)
CLASSIC_MODEL_ADMISSION = REPOSITORY / "renderer" / "classic_model_admission.json"
MII_RENDERING_SYMBOLS = REPOSITORY / "manifests" / "mii_rendering_symbols.csv"
HEAD_ATTACHMENT_DECOMP_SOURCE = (
    REPOSITORY
    / "src"
    / "functions"
    / "internal"
    / "batch_04"
    / "7101d00000"
    / "2466_functions.inc"
)
CLASSIC_MII_RUNTIME_PROFILE = (
    REPOSITORY / "renderer" / "classic_mii_runtime_profile.json"
)
CLASSIC_FACE_PRESENTATION = (
    REPOSITORY / "renderer" / "classic_face_presentation.json"
)
CLASSIC_BRIDGE_PORTRAIT_FRAMING = (
    REPOSITORY / "renderer" / "classic_bridge_portrait_framing.json"
)
LEGACY_HEADWEAR_PRESENTATION = (
    REPOSITORY / "renderer" / "legacy_headwear_presentation.json"
)
TITLE_MII_ICON_SNAPSHOT = REPOSITORY / "renderer" / "title_mii_icon_snapshot.json"
MII_POSE_PIPELINE = REPOSITORY / "renderer" / "mii_pose_pipeline.json"
BODY_BASE_CUTLINE_SOURCE = REPOSITORY / "renderer" / "body_base_cutline_source.json"
SHARE_MII_FACEPAINT = REPOSITORY / "renderer" / "share_mii_facepaint.json"
MII_ICON_MASK_RESOLUTION = 256
MII_ICON_FACELINE_RESOLUTION = (128, 256)
SOURCE_BACKED_FACELINE_TARGETS = frozenset(
    (JOHNNY_SHARE_MII_SHA256, SPIDER_MAN_NOIR_SHARE_MII_SHA256)
)
PRESENTATION_CONTEXT_DOMAIN = b"InfiniMii/LTD/presentation-context/v1\0"
LEGACY_HEADWEAR_CONTEXT_KIND = "legacy-collapsed-hair-headwear-v1"

# System.mii__SystemParam.bgyml BodyBaseCutline entries selected by the external
# outfit records. The numeric keys are stored by those records; the mapped shape
# names come from the title parameter table and are consumed by
# FUN_7101bce0c0/FUN_7101bcd440. They are visibility choices, never fitted
# geometry offsets.
BODY_BASE_CUTLINE_GROUPS: dict[int, frozenset[str]] = {
    3312601720: frozenset({"BodyChest__mt_Tops", "BodyArm__mt_Tops"}),
    2895499086: frozenset(),
    1032020994: frozenset({"BodySole__mt_Socks"}),
    3296514992: frozenset({"BodyHip__mt_Bottoms"}),
}

ACTIVE_PARTS_BY_SHARE_MII_SHA256: dict[str, Path] = {
    "c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b": ACTIVE_PARTS,
    "aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d": MII2_ACTIVE_PARTS,
    "d3098f9156c7ec7a7fa99c38954f1c460b3e7031313fc4e6e5ab6031c4e18776": MII3_ACTIVE_PARTS,
    "966fa6bf82aa46c8e5b9f16842982a3b715b86ccd1933f540044b05b8d3fc391": MII4_ACTIVE_PARTS,
    "1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef": MII0_ACTIVE_PARTS,
}


@dataclass(frozen=True)
class HairShaderSelection:
    """Exact GameAll identity plus the locally portable scope for one hair resource."""

    gameall_program: int
    evidence_path: Path
    exact_local_scope: str
    use_hair612_anisotropic_proxy: bool
    disabled_local_scope: str | None = None
    use_hair708_face_gradient: bool = False
    use_constant_hair_color_linear: bool = False
    model_name: str | None = None
    fragment_instructions_sha256: str | None = None


@dataclass(frozen=True)
class HairModelSelection:
    """One exact Parts model role and its prepared BFRES/OBJ execution path."""

    model_key: str
    logical_name: str
    resource_name: str
    role: str
    fmdb: str
    model_name: str
    model_index: int
    obj_path: Path
    for_hat: bool
    flip_requested: bool
    is_flippable: bool
    explicit_flipped_model: bool
    mirror_horizontal: bool

    @property
    def flip_horizontal_sign(self) -> float:
        return -1.0 if self.flip_requested and self.is_flippable else 1.0

    def report(self) -> dict[str, Any]:
        return {
            "logical_name": self.logical_name,
            "resource": self.resource_name,
            "role": self.role,
            "fmdb": self.fmdb,
            "model_name": self.model_name,
            "model_index": self.model_index,
            "obj": _logical_path(self.obj_path),
            "for_hat": self.for_hat,
            "flip_requested": self.flip_requested,
            "is_flippable": self.is_flippable,
            "explicit_flipped_model": self.explicit_flipped_model,
            "runtime_horizontal_mirror": self.mirror_horizontal,
            "flip_horizontal_sign": self.flip_horizontal_sign,
            "clockwise_front_face": self.mirror_horizontal,
            "tangent_handedness_execution": (
                "reconstructed authored tangent.w multiplied by flip_horizontal_sign "
                "before every software TBN consumer"
            ),
        }


@dataclass(frozen=True)
class LegacyHeadwearSelection:
    """One source-context-authorized title headwear presentation draw."""

    source_hair_type: int
    presentation_kind: str
    resource_name: str
    model_name: str
    model_index: int
    shape_name: str
    obj_path: Path
    albedo_texture: str
    normal_texture: str
    roughness_texture: str
    gameall_program: int
    vertex_instructions_sha256: str
    fragment_instructions_sha256: str
    contract_sha256: str
    hat_offset_translation: tuple[float, float, float]
    hat_offset_rotation_degrees: tuple[float, float, float]
    hat_attachment_matrix: tuple[tuple[float, float, float, float], ...]

    def report(self) -> dict[str, Any]:
        return {
            "source_hair_type": self.source_hair_type,
            "presentation_kind": self.presentation_kind,
            "resource": self.resource_name,
            "model": self.model_name,
            "model_index": self.model_index,
            "shape": self.shape_name,
            "obj": _logical_path(self.obj_path),
            "contract": {
                "path": _logical_path(LEGACY_HEADWEAR_PRESENTATION),
                "sha256": self.contract_sha256,
            },
            "gameall_program": self.gameall_program,
            "vertex_instructions_sha256": self.vertex_instructions_sha256,
            "fragment_instructions_sha256": self.fragment_instructions_sha256,
            "textures": {
                "albedo": self.albedo_texture,
                "normal": self.normal_texture,
                "roughness": self.roughness_texture,
            },
            "draw_order": "after hat-compatible Hair 45",
            "transform": (
                "head_scene_transform @ translation(HatOffsetTrans) @ "
                "rotation_x(radians(HatOffsetRotate.X)) @ exact rigid BFRES shape bind"
            ),
            "title_hat_attachment": {
                "source": "Mii SystemParam HatOffsetTrans/HatOffsetRotate",
                "translation": list(self.hat_offset_translation),
                "rotation_degrees": list(self.hat_offset_rotation_degrees),
                "matrix": [list(row) for row in self.hat_attachment_matrix],
                "direct_title_consumer_call_claimed": False,
            },
            "additional_body_height_offset_or_scale": None,
            "raster_state": {
                "display_face": "front",
                "cull_back_faces": True,
                "depth_test": "lequal",
                "depth_write": True,
                "blend": False,
                "alpha_test": False,
            },
            "portable_local_material": (
                "hardware-sRGB albedo; BC5 signed-XY normal reconstruction; "
                "native Mic.B roughness via byte-equivalent cached channel 0"
            ),
            "known_deltas": (
                "2:1 albedo anisotropy, authored tangent/color mask semantics, and "
                "full GameAll96 specular/edge/SSS/environment/emission response are unavailable"
            ),
            "title_final_lighting_equivalence_claimed": False,
        }


@dataclass(frozen=True)
class BeardShaderSelection:
    """Exact GameAll program and BFRES anisotropic constants for one beard."""

    gameall_program: int
    fragment_instructions_sha256: str
    anisotropic_shift_scale: float
    anisotropic_shift_offset: float


@dataclass(frozen=True)
class DecorationShaderSelection:
    """Exact Decoration program/stages for a selected BFRES model variant."""

    gameall_program: int
    vertex_skin_count: int
    vertex_instructions_sha256: str
    fragment_instructions_sha256: str


@dataclass(frozen=True)
class GameAllMaterialSelection:
    """One exact submitted material program with its authenticated provenance."""

    family: str
    gameall_program: int
    resource_name: str
    model_name: str
    shape_name: str
    material_name: str
    evidence_path: Path
    evidence_sha256: str
    vertex_instructions_sha256: str
    fragment_instructions_sha256: str
    active_program_ledger: Path
    active_program_ledger_sha256: str
    active_selection_status: str
    active_resolved_program: int | None
    active_compatible_programs: tuple[int, ...]
    resolution_basis: str
    validated_nested_file_records: int

    def report(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "gameall_program": self.gameall_program,
            "resource": self.resource_name,
            "model": self.model_name,
            "shape": self.shape_name,
            "material": self.material_name,
            "vertex_instructions_sha256": self.vertex_instructions_sha256,
            "fragment_instructions_sha256": self.fragment_instructions_sha256,
            "evidence": {
                "path": _logical_path(self.evidence_path),
                "sha256": self.evidence_sha256,
            },
            "active_program_ledger": {
                "path": _logical_path(self.active_program_ledger),
                "sha256": self.active_program_ledger_sha256,
                "selection_status": self.active_selection_status,
                "resolved_program_index": self.active_resolved_program,
                "compatible_program_indices": list(self.active_compatible_programs),
            },
            "resolution_basis": self.resolution_basis,
            "validated_nested_file_records": self.validated_nested_file_records,
        }


@dataclass(frozen=True)
class BodyGameAllSelection:
    """Exact BodyBaseDefault group program and both selected stage identities."""

    group_name: str
    material_name: str
    vertex_skin_count: int
    gameall_program: int
    vertex_instructions_sha256: str
    fragment_instructions_sha256: str
    evidence_path: Path
    evidence_sha256: str
    reflection_key: str
    validated_instruction_files: int

    def report(self) -> dict[str, Any]:
        return {
            "resource": "BodyBaseDefault",
            "model": "BodyBaseDefault",
            "shape": self.group_name,
            "material": self.material_name,
            "vertex_skin_count": self.vertex_skin_count,
            "family": "body",
            "gameall_program": self.gameall_program,
            "compatible_program_indices": [self.gameall_program],
            "vertex_instructions_sha256": self.vertex_instructions_sha256,
            "fragment_instructions_sha256": self.fragment_instructions_sha256,
            "reflection_key": self.reflection_key,
            "evidence": {
                "path": _logical_path(self.evidence_path),
                "sha256": self.evidence_sha256,
            },
            "validated_instruction_files": self.validated_instruction_files,
        }


@dataclass(frozen=True)
class OutfitGameAllSelection:
    """Source-constrained exact GameAll selection for one submitted outfit slot."""

    logical_slot: str
    family: str
    resource_name: str
    shape_name: str
    gameall_program: int
    raw_compatible_programs: tuple[int, ...]
    source_constraints: tuple[tuple[str, str], ...]
    title_shader_execution_key: str
    active_material_samplers: tuple[str, ...]
    inactive_serialized_assignments: tuple[tuple[str, str, int, str], ...]
    vertex_instructions_sha256: str
    fragment_instructions_sha256: str
    evidence_path: Path
    evidence_sha256: str

    def report(self) -> dict[str, Any]:
        return {
            "logical_slot": self.logical_slot,
            "family": self.family,
            "resource": self.resource_name,
            "model": self.resource_name,
            "shape": self.shape_name,
            "material": "mt_Body",
            "resolver_candidate_program_index": self.raw_compatible_programs[0],
            "raw_compatible_program_indices": list(self.raw_compatible_programs),
            "source_constraints": [
                {"option": option, "value": value}
                for option, value in self.source_constraints
            ],
            "gameall_program": self.gameall_program,
            "compatible_program_indices": [self.gameall_program],
            "selection_status": "exact_unique_after_source_constraints",
            "compiled_sampler_activity": {
                "title_shader_execution_key": self.title_shader_execution_key,
                "active_material_samplers": list(self.active_material_samplers),
                "inactive_serialized_assignments": [
                    {
                        "shader_sampler": shader_sampler,
                        "material_sampler": material_sampler,
                        "material_sampler_index": material_sampler_index,
                        "texture_ref": texture_ref,
                    }
                    for (
                        shader_sampler,
                        material_sampler,
                        material_sampler_index,
                        texture_ref,
                    ) in self.inactive_serialized_assignments
                ],
            },
            "vertex_instructions_sha256": self.vertex_instructions_sha256,
            "fragment_instructions_sha256": self.fragment_instructions_sha256,
            "evidence": {
                "path": _logical_path(self.evidence_path),
                "sha256": self.evidence_sha256,
            },
        }


@dataclass(frozen=True)
class RenderSupport:
    """Checked renderer resources selected before any model or texture load."""

    selection_kind: str
    material_texture_cache_roots: tuple[Path, ...]
    material_texture_manifests: tuple[Path, ...]
    face_sprite_mip_manifests: tuple[Path, ...]
    active_program_ledger: Path
    presentation_variation: int
    presentation_profile: dict[str, Any] | None
    nose_parallax_height_scale: float
    classic_bridge_report: dict[str, Any] | None
    body_program_selections: dict[str, BodyGameAllSelection]
    outfit_program_selections: dict[str, OutfitGameAllSelection]
    glass_frame_program_selection: GameAllMaterialSelection | None
    glass_lens_program_selection: GameAllMaterialSelection | None
    faceline_contract: str | None = None
    portrait_framing_profile: dict[str, Any] | None = None
    legacy_headwear_selection: LegacyHeadwearSelection | None = None
    # Canonical records from active_resource_signature(), after the component
    # capability resolver has validated every active or source-inactive Parts
    # selection.  Face consumers use these records to distinguish a proven
    # no-draw projection from an unsupported selector; the raw active-parts
    # manifest is not an admission authority by itself.
    classic_resource_signature_records: dict[str, dict[str, Any]] | None = None


HAIR_SHADER_BY_MODEL_RESOURCE: dict[str, HairShaderSelection] = {
    "MiiHairAllLegacy121": HairShaderSelection(
        gameall_program=612,
        evidence_path=GAMEUBER_ACTIVE_PROGRAMS,
        exact_local_scope="Hair612 base, shifted-bitangent anisotropic kernel, and MIM.G mask",
        use_hair612_anisotropic_proxy=True,
    ),
    "MiiHairAll073": HairShaderSelection(
        gameall_program=1056,
        evidence_path=HAIR_SHADER_EXPRESSION,
        exact_local_scope="Hair1056 MGH.R sRGB-endpoint mix followed by the compiled 2.2 power",
        use_hair612_anisotropic_proxy=False,
    ),
    "MiiHairBack000": HairShaderSelection(
        gameall_program=564,
        evidence_path=MII2_GAMEUBER_PROGRAMS,
        exact_local_scope=(
            "Hair564 MGH.R sRGB-endpoint mix followed by abs(x)^2.2; "
            "_o0/_user1 bindings and selected fragment stage are hash-bound"
        ),
        use_hair612_anisotropic_proxy=False,
    ),
    "MiiHairFront029": HairShaderSelection(
        gameall_program=564,
        evidence_path=MII2_GAMEUBER_PROGRAMS,
        exact_local_scope=(
            "Hair564 MGH.R sRGB-endpoint mix followed by abs(x)^2.2; "
            "_o0/_user1 bindings and selected fragment stage are hash-bound"
        ),
        use_hair612_anisotropic_proxy=False,
    ),
    "MiiHairAllLegacy043": HairShaderSelection(
        gameall_program=672,
        evidence_path=CLASSIC_BRIDGE_GAMEUBER_PROGRAMS,
        exact_local_scope=(
            "Hair672 exact MGH.R sRGB endpoint mix followed by abs(x)^2.2; "
            "_user1 fragment location/descriptor and selected stage are hash-bound"
        ),
        use_hair612_anisotropic_proxy=False,
        disabled_local_scope=(
            "MGH.G scatter/cheap-SSS continuation and title environment/radiance inputs are "
            "not independently recovered and remain disabled; no Hair564/612 program is aliased"
        ),
    ),
    "MiiHairAllLegacy068": HairShaderSelection(
        gameall_program=564,
        evidence_path=CLASSIC_BRIDGE_GAMEUBER_PROGRAMS,
        exact_local_scope=(
            "Hair564 exact MGH.R sRGB endpoint mix followed by abs(x)^2.2; "
            "the selected fragment instruction binary is hash-identical to the audited Hair564 stage"
        ),
        use_hair612_anisotropic_proxy=False,
        disabled_local_scope=(
            "title environment/radiance inputs remain unavailable; no Hair612 anisotropic proxy is used"
        ),
    ),
}

# The generalized classic ledger resolves a large selector domain, but a unique
# program is not by itself a portable CPU implementation.  Admit a new hair
# resource only when its exact fragment instruction hash is one of the five
# locally audited kernels below.  This lets equivalent program indices reuse an
# equation without treating a merely binary-compatible candidate as resolved.
CLASSIC_HAIR_SHADER_BY_FRAGMENT_SHA256: dict[str, dict[str, Any]] = {
    "2dca1dac7fbab547ba32c96e347b0ad4bb930203f9716afdaea2dd939d822e56": {
        "exact_local_scope": (
            "Hair408/420/432 exact texture-independent mii_hair_color0 linear base; "
            "the uniquely selected fragment instruction binary reads the three runtime "
            "linear color components directly and binds only MIM as _o0"
        ),
        "use_hair612_anisotropic_proxy": False,
        "use_constant_hair_color_linear": True,
        "disabled_local_scope": (
            "native anisotropic/environment radiance inputs remain unavailable; no endpoint "
            "MGH texture or cross-program anisotropic proxy is invented"
        ),
    },
    "c5b930cd98f5ca11ab4560bc7cffc7888b3180f92d372ee95c69f3b3cc94f89c": {
        "exact_local_scope": (
            "Hair396 exact texture-independent mii_hair_color0 linear base; the uniquely "
            "selected fragment instruction binary reads the three runtime linear color "
            "components directly and binds only MIM as _o0"
        ),
        "use_hair612_anisotropic_proxy": False,
        "use_constant_hair_color_linear": True,
        "disabled_local_scope": (
            "native anisotropic/environment radiance inputs remain unavailable; no endpoint "
            "MGH texture or cross-program anisotropic proxy is invented"
        ),
    },
    "1413aab91715c2caa713f4ae191805bac3717557f3c2b1b409da279be65015fe": {
        "exact_local_scope": (
            "Hair564-family exact MGH.R sRGB endpoint mix followed by abs(x)^2.2; "
            "the uniquely selected fragment instruction binary is hash-bound"
        ),
        "use_hair612_anisotropic_proxy": False,
        "disabled_local_scope": (
            "title environment/radiance inputs remain unavailable; no Hair612 "
            "anisotropic proxy is used"
        ),
    },
    "bc367f43b2e9ea39c08970fb541f0c92712d6d37d0fbef74eabf8939f49e9c4f": {
        "exact_local_scope": (
            "Hair612-family base, shifted-bitangent anisotropic kernel, and MIM.G mask; "
            "the uniquely selected fragment instruction binary is hash-bound"
        ),
        "use_hair612_anisotropic_proxy": True,
        "disabled_local_scope": None,
    },
    "607f872554b3eb2dacef12377f1c988aaf9dd9f147eea357f8abbb37c769a811": {
        "exact_local_scope": (
            "Hair672-family exact MGH.R sRGB endpoint mix followed by abs(x)^2.2; "
            "the uniquely selected fragment instruction binary is hash-bound"
        ),
        "use_hair612_anisotropic_proxy": False,
        "disabled_local_scope": (
            "MGH.G scatter/cheap-SSS continuation and title environment/radiance inputs "
            "are not independently recovered and remain disabled"
        ),
    },
    "a71b2c18fcfa92e481e376baa590b71c5649370ff32d52342ca02a714e85215c": {
        "exact_local_scope": (
            "Hair708 exact MGH.R endpoint mix, MGH.G face-color mix, and abs(x)^2.2; "
            "the Hair612-family shifted-bitangent anisotropic kernel and MIM.G/B inputs "
            "are also instruction-bound"
        ),
        "use_hair612_anisotropic_proxy": True,
        "use_hair708_face_gradient": True,
        "disabled_local_scope": (
            "cheap-SSS and native title environment/radiance inputs remain unavailable; "
            "anisotropic radiance uses the explicitly reported portable single-key proxy"
        ),
    },
    "fa362e5aeae6d330ccf3c513346b6c8926c8778068a797b97c75f83c32772d17": {
        "exact_local_scope": (
            "Hair1116 exact MGH.R sRGB endpoint mix followed by abs(x)^2.2, plus "
            "BC5_SNORM RG normal sampling and Z=sqrt(saturate(1-R^2-G^2))"
        ),
        "use_hair612_anisotropic_proxy": False,
        "use_hair708_face_gradient": False,
        "disabled_local_scope": (
            "native title environment/radiance inputs remain unavailable; no anisotropic "
            "kernel is borrowed by the specular-disabled Hair1116 program"
        ),
    },
}

# These values are serialized by each mt_Beard material. Beard00/01 omit
# map_shift, which resolves through GameAll's stored defaultChoice=0 to program
# 456; their local shift is therefore the constant offset rather than MIM.B.
BEARD_SHADER_BY_MODEL_RESOURCE: dict[str, BeardShaderSelection] = {
    "MiiBeard00": BeardShaderSelection(
        gameall_program=456,
        fragment_instructions_sha256=(
            "1c9a86950b1faaa766180950cec6d3ec2c21b69da377936a9002096ddc774b07"
        ),
        anisotropic_shift_scale=0.0,
        anisotropic_shift_offset=-2.0,
    ),
    "MiiBeard01": BeardShaderSelection(
        gameall_program=456,
        fragment_instructions_sha256=(
            "1c9a86950b1faaa766180950cec6d3ec2c21b69da377936a9002096ddc774b07"
        ),
        anisotropic_shift_scale=0.0,
        anisotropic_shift_offset=-1.4,
    ),
    "MiiBeard02": BeardShaderSelection(
        gameall_program=468,
        fragment_instructions_sha256=(
            "66c8032db1ac2cd85f96340392d2b39afae581e4bc803668219d51713ecbde7d"
        ),
        anisotropic_shift_scale=1.0,
        anisotropic_shift_offset=-1.3,
    ),
}

# Source-backed defaults and decoded title configuration used by
# FUN_7101d7c4e0. FUN_7101d5f8c8 initializes opacity/multi/rate to .5/.5/.4;
# System.mii__SystemParam.bgyml overrides GlassLensOpacity to .7 and keeps the
# multiply flag false. The omitted HairBandColorRate therefore remains .4.
CHECKED_MII_SYSTEM_PARAMETERS: dict[str, Any] = {
    "IsGlassLensMultiplyBlend": False,
    "GlassLensOpacity": 0.699999988079071,
    "GlassLensOpacityMulti": 0.5,
    "HairBandColorRate": 0.4000000059604645,
    "HairBandColorWhenBlack": (
        0.22943705320358276,
        0.22943705320358276,
        0.22943705320358276,
        1.0,
    ),
}

MATERIAL_TEXTURE_CACHE_ROOTS_BY_SHARE_MII_SHA256: dict[str, tuple[Path, ...]] = {
    "c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b": (
        TEXTURE_MIP_CACHE,
    ),
    "aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d": (
        TEXTURE_MIP_CACHE,
        MII2_TEXTURE_MIP_CACHE,
    ),
    "d3098f9156c7ec7a7fa99c38954f1c460b3e7031313fc4e6e5ab6031c4e18776": (
        TEXTURE_MIP_CACHE,
        MII3_TEXTURE_MIP_CACHE,
    ),
    # Spider-Man resolves only MiiHead00 plus exact Nothing records. Head00's
    # checked native Nmh chain is already in the shared cache; no nonexistent
    # target-specific material cache is reported.
    "966fa6bf82aa46c8e5b9f16842982a3b715b86ccd1933f540044b05b8d3fc391": (
        TEXTURE_MIP_CACHE,
    ),
    # Spider-Man Noir resolves the same checked MiiHead00 material surfaces;
    # its enabled WrinkleUpper sprite is provided by the face-sprite cache,
    # not a target-specific model-material cache.
    "1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef": (
        TEXTURE_MIP_CACHE,
    ),
}

TARGET_SPECIFIC_MATERIAL_TEXTURE_MIPS_BY_SHARE_MII_SHA256: dict[
    str, tuple[Path, Path]
] = {
    "aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d": (
        MII2_TEXTURE_MIPS,
        MII2_TEXTURE_MIP_CACHE,
    ),
    "d3098f9156c7ec7a7fa99c38954f1c460b3e7031313fc4e6e5ab6031c4e18776": (
        MII3_TEXTURE_MIPS,
        MII3_TEXTURE_MIP_CACHE,
    ),
}

_configured_material_texture_cache_roots: tuple[Path, ...] | None = None
MAX_RUNTIME_OBJ_MESHES = 16


@dataclass(frozen=True)
class _RuntimeObjMeshEntry:
    source_identity: tuple[str, str, str | None]
    mesh: ObjMesh


_runtime_obj_mesh_lock = threading.RLock()
_runtime_obj_meshes: OrderedDict[str, _RuntimeObjMeshEntry] = OrderedDict()

# ShareMii carries no ClothSet or character-color selector. These values are
# explicit renderer presentation choices: Kestron keeps the capture-supplied
# variation 10; Johnny uses neutral presentation variation 00. Neither value is
# reported as serialized Mii state or a title runtime default.
PRESENTATION_VARIATION_BY_SHARE_MII_SHA256: dict[str, int] = {
    "c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b": 10,
    "aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d": 0,
    "d3098f9156c7ec7a7fa99c38954f1c460b3e7031313fc4e6e5ab6031c4e18776": 0,
    "966fa6bf82aa46c8e5b9f16842982a3b715b86ccd1933f540044b05b8d3fc391": 0,
    "1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef": 0,
}

GAMEUBER_PROGRAM_LEDGER_BY_SHARE_MII_SHA256: dict[str, Path] = {
    "c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b": GAMEUBER_ACTIVE_PROGRAMS,
    "aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d": MII2_GAMEUBER_PROGRAMS,
    "d3098f9156c7ec7a7fa99c38954f1c460b3e7031313fc4e6e5ab6031c4e18776": MII3_GAMEUBER_PROGRAMS,
    # MiiHead00 is the sole enabled model. The established ledger is keyed by
    # exact resource/material bytes, so it also covers this target's Head/Mask.
    "966fa6bf82aa46c8e5b9f16842982a3b715b86ccd1933f540044b05b8d3fc391": GAMEUBER_ACTIVE_PROGRAMS,
    "1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef": GAMEUBER_ACTIVE_PROGRAMS,
}


GLASS_GAMEALL_PROGRAM_STAGE_HASHES: dict[tuple[str, int], tuple[str, str]] = {
    (
        "glass_frame",
        360,
    ): (
        "3efdb06c0c1c886d7698c6a78e6a11fd55e07b70438f32b852ebe719ff7016bb",
        "cc917505ceddf2aefaaa0b640bc1421f92235ab8f89c6e426dc651a2a71b5759",
    ),
    (
        "glass_lens_translucent",
        60,
    ): (
        "9863df2bbefbae036a39333a94acae9b95838c160567b4a9eefaa48e2ca1596a",
        "a62c75fe0b789862367f7b3d673b7fc15e0b332d6ec900eef6f87a1598d5bd2f",
    ),
    (
        "glass_lens_opaque",
        768,
    ): (
        "b7f33b1713e88efad53107c63a36097b0d617c41916969eca6a193d191ed009e",
        "dae3e9dc72cf1dca42d805354e7fcf453b1d3877e8c409ebb7e35274dabefb36",
    ),
}

BODY_GAMEALL_PROGRAM_BY_GROUP: dict[str, tuple[str, int, int]] = {
    "BodyArm__mt_Tops": ("mt_Tops", 3, 336),
    "BodyChest__mt_Tops": ("mt_Tops", 4, 348),
    "BodyElbow__mt_Tops": ("mt_Tops", 3, 336),
    "BodyFoot__mt_Socks": ("mt_Socks", 2, 324),
    "BodyHand__mt_Tops": ("mt_Tops", 3, 336),
    "BodyHip__mt_Bottoms": ("mt_Bottoms", 3, 336),
    "BodyHip__mt_Socks": ("mt_Socks", 2, 324),
    "BodyKnee__mt_Socks": ("mt_Socks", 3, 336),
    "BodyLeg__mt_Socks": ("mt_Socks", 2, 324),
    "BodyShoulder__mt_Tops": ("mt_Tops", 4, 348),
    "BodySole__mt_Socks": ("mt_Socks", 2, 324),
    "BodyThigh__mt_Socks": ("mt_Socks", 3, 336),
    "BodyWaist__mt_Tops": ("mt_Tops", 3, 336),
}
BODY_GAMEALL_VERTEX_INSTRUCTION_SHA256_BY_PROGRAM = {
    324: "52527c1acf08b9849a52483b570e04c669defc6a0e4e54c271192f503d444d96",
    336: "29596c2d40cbdfb6fa2b6a6e1f4345e6d0ad8f1a1bdc211bda9f76efec85a742",
    348: "a5fc2b73fba103325a88cc66bbc2b3b146bcac0f8b14df75ba5ab110eecf803c",
}
BODY_GAMEALL_VERTEX_INSTRUCTION_LENGTH_BY_PROGRAM = {324: 2432, 336: 2944, 348: 3456}
BODY_GAMEALL_FRAGMENT_INSTRUCTION_SHA256 = (
    "bf85659d4e63e19a3528cf30368d2b3a729eaf3e8e1c72b69d34b59dc34fb746"
)

OUTFIT_GAMEALL_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "tops": {
        "family": "outfit_tops",
        "resource": "ClothTopsTshirtLong",
        "shape": "Tops__mt_Body",
        "program": 984,
        "raw": [984, 1008],
        "constraints": [("enable_texture_user0", "0")],
        "vertex_length": 3456,
        "vertex": "a5fc2b73fba103325a88cc66bbc2b3b146bcac0f8b14df75ba5ab110eecf803c",
        "fragment_length": 9600,
        "fragment": "18632ddd0d13c88d69eb858d8485ba96ed108cf73c1bc94419f13141e860bed6",
        "title_shader_execution_key": "body_tops_program_984",
        "active_material_samplers": ["_a0", "_e0", "_n0", "_r0"],
        "inactive_serialized_assignments": [
            {
                "shader_sampler": "_alp0",
                "material_sampler": "_alp0",
                "material_sampler_index": 2,
                "texture_ref": "Dummy_Msk",
            }
        ],
    },
    "bottoms": {
        "family": "outfit_bottoms",
        "resource": "ClothBottomsPantsLong",
        "shape": "Bottoms__mt_Body",
        "program": 936,
        "raw": [936, 960, 984, 1008],
        "constraints": [
            ("enable_texture_user0", "0"),
            ("enable_emission_map", "0"),
        ],
        "vertex_length": 3456,
        "vertex": "a5fc2b73fba103325a88cc66bbc2b3b146bcac0f8b14df75ba5ab110eecf803c",
        "fragment_length": 9344,
        "fragment": "6b937426ba67cd87274ba4a9d53846c43ee91ced4246956596727fc1810ee12a",
        "title_shader_execution_key": "body_bottoms_program_936",
        "active_material_samplers": ["_a0", "_n0", "_r0"],
        "inactive_serialized_assignments": [
            {
                "shader_sampler": "_alp0",
                "material_sampler": "_alp0",
                "material_sampler_index": 2,
                "texture_ref": "Dummy_Msk",
            }
        ],
    },
    "shoes": {
        "family": "outfit_shoes",
        "resource": "ClothShoesStandard",
        "shape": "Shoes__mt_Body",
        "program": 912,
        "raw": [912],
        "constraints": [],
        "vertex_length": 2432,
        "vertex": "52527c1acf08b9849a52483b570e04c669defc6a0e4e54c271192f503d444d96",
        "fragment_length": 9344,
        "fragment": "6b937426ba67cd87274ba4a9d53846c43ee91ced4246956596727fc1810ee12a",
        "title_shader_execution_key": "shoes_program_912",
        "active_material_samplers": ["_a0", "_n0", "_r0"],
        "inactive_serialized_assignments": [
            {
                "shader_sampler": "_alp0",
                "material_sampler": "_alp0",
                "material_sampler_index": 0,
                "texture_ref": "Dummy_Msk",
            }
        ],
    },
}


def _sha256(path: Path) -> str:
    return _cached_sha256(path)


def _logical_path(path: Path) -> str:
    """Return a stable repository-relative path for machine-readable reports."""
    return Path(os.path.relpath(path.resolve(), REPOSITORY)).as_posix()


def _select_hair_shader(
    resource_name: str,
    model_name: str | None = None,
) -> HairShaderSelection:
    """Select the exact Hair program for one resource *and* BFRES model."""

    selected_model = resource_name if model_name is None else model_name
    ledger = _cached_load_json(CLASSIC_BRIDGE_GAMEUBER_PROGRAMS)
    resource_hair_materials = [
        material
        for material in ledger.get("programs", [])
        if (
            material.get("resource") == resource_name
            and material.get("family") == "hair"
            and material.get("shape") == "Hair__mt_Hair"
            and material.get("material") == "mt_Hair"
        )
    ]
    if not resource_hair_materials:
        direct = HAIR_SHADER_BY_MODEL_RESOURCE.get(resource_name)
        if direct is not None and selected_model == resource_name:
            return direct
        raise ValueError(
            f"no checked GameAll hair selection exists for {resource_name}/{selected_model}"
        )
    hair_materials = [
        material
        for material in resource_hair_materials
        if material.get("model") == selected_model
    ]
    if len(hair_materials) != 1:
        raise ValueError(
            f"no unique checked GameAll hair selection exists for {resource_name}/{selected_model}"
        )
    material = hair_materials[0]
    program = material.get("resolved_program_index")
    fragment_hash = (
        material.get("stages", {})
        .get("fragment", {})
        .get("instructions", {})
        .get("sha256")
    )
    scope = CLASSIC_HAIR_SHADER_BY_FRAGMENT_SHA256.get(str(fragment_hash))
    if (
        material.get("family") != "hair"
        or material.get("resource") != resource_name
        or material.get("model") != selected_model
        or material.get("shape") != "Hair__mt_Hair"
        or material.get("material") != "mt_Hair"
        or material.get("selection_status") != "exact_unique"
        or not isinstance(program, int)
        or scope is None
    ):
        raise ValueError(
            f"{resource_name}/{selected_model} has no uniquely resolved, locally audited GameAll hair kernel"
        )
    return HairShaderSelection(
        gameall_program=program,
        evidence_path=CLASSIC_BRIDGE_GAMEUBER_PROGRAMS,
        exact_local_scope=str(scope["exact_local_scope"]),
        use_hair612_anisotropic_proxy=bool(scope["use_hair612_anisotropic_proxy"]),
        disabled_local_scope=(
            str(scope["disabled_local_scope"])
            if scope["disabled_local_scope"] is not None
            else None
        ),
        use_hair708_face_gradient=bool(scope.get("use_hair708_face_gradient", False)),
        use_constant_hair_color_linear=bool(
            scope.get("use_constant_hair_color_linear", False)
        ),
        model_name=selected_model,
        fragment_instructions_sha256=str(fragment_hash),
    )


def _hair_gameall_identity(
    selection: HairShaderSelection,
) -> gameuber_cpu.GameAllProgramIdentity:
    """Bind one audited Hair instruction family without cross-program effects."""

    if selection.use_constant_hair_color_linear:
        family = "hair_constant"
    elif selection.use_hair612_anisotropic_proxy:
        family = "hair_anisotropic"
    else:
        family = "hair_endpoint"
    return gameuber_cpu.gameall_program_identity(family, selection.gameall_program)


def _select_decoration_shader(
    resource_name: str,
    model_name: str | None = None,
) -> DecorationShaderSelection:
    selected_model = resource_name if model_name is None else model_name
    ledger = _cached_load_json(CLASSIC_BRIDGE_GAMEUBER_PROGRAMS)
    matches = [
        record
        for record in ledger.get("programs", [])
        if (
            record.get("resource") == resource_name
            and record.get("model") == selected_model
            and record.get("shape") == "Decoration__mt_Decoration"
            and record.get("material") == "mt_Decoration"
        )
    ]
    if len(matches) != 1:
        raise ValueError(
            f"no unique checked Decoration material exists for {resource_name}/{selected_model}"
        )
    record = matches[0]
    program = record.get("resolved_program_index")
    skin_count = record.get("vertex_skin_count")
    vertex_hash = (
        record.get("stages", {}).get("vertex", {}).get("instructions", {}).get("sha256")
    )
    fragment_hash = (
        record.get("stages", {}).get("fragment", {}).get("instructions", {}).get("sha256")
    )
    expected_vertex = {
        0: "2d079182597f72cbb0296771f342162e15d1ed97e815d9c88c0a16be264b498c",
        1: "0c75eb001a5678e67b338dca31eb77b9a44d03750a2f01375cb3ff72e7086fa5",
    }
    expected_program = {0: 480, 1: 492}
    expected_fragment = (
        "6f04a09c896cb7c92ade6ddef1fde621b087e44c9ef671abd2911160bd06cacb"
    )
    if (
        record.get("family") != "decoration"
        or record.get("selection_status") != "exact_unique"
        or skin_count not in expected_program
        or program != expected_program[skin_count]
        or vertex_hash != expected_vertex[skin_count]
        or fragment_hash != expected_fragment
    ):
        raise ValueError(
            f"{resource_name}/{selected_model} has no locally audited Decoration480/492 path"
        )
    return DecorationShaderSelection(
        gameall_program=int(program),
        vertex_skin_count=int(skin_count),
        vertex_instructions_sha256=str(vertex_hash),
        fragment_instructions_sha256=str(fragment_hash),
    )


def _resolve_repository_path(value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (REPOSITORY / path).resolve()


def _validate_file_record(record: dict[str, Any], label: str) -> Path:
    """Validate one checked repository-relative file record and return its path."""

    if not isinstance(record, dict) or not {
        "path",
        "byte_length",
        "sha256",
    }.issubset(record):
        raise ValueError(f"{label} is not a complete checked file record")
    recorded_path = Path(str(record["path"]))
    path = recorded_path if recorded_path.is_absolute() else REPOSITORY / recorded_path
    validated = _cached_matches_file(
        path,
        byte_length=int(record["byte_length"]),
        sha256_digest=str(record["sha256"]),
    )
    if validated is None:
        raise ValueError(f"{label} changed: {record['path']}")
    return validated


def _validate_nested_file_records(value: Any, label: str) -> int:
    """Validate every nested ``path/byte_length/sha256`` evidence record."""

    count = 0
    if isinstance(value, dict):
        if {"path", "byte_length", "sha256"}.issubset(value):
            _validate_file_record(value, label)
            count += 1
        for key, child in value.items():
            count += _validate_nested_file_records(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            count += _validate_nested_file_records(child, f"{label}[{index}]")
    return count


def _validate_material_texture_manifest(
    manifest_path: Path,
    cache_root: Path,
    required_names: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Validate an exact BNTX-derived material mip cache.

    Comprehensive classic manifests contain thousands of evidence files.  A
    render validates only the textures admitted by its capability; the manifest
    file itself remains hash-bound by the resource bundle.  Small established
    fixture manifests retain their full-inventory validation.
    """

    manifest = _cached_load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError(f"material mip manifest schema changed: {manifest_path}")
    textures = manifest.get("textures")
    if not isinstance(textures, list):
        raise ValueError(f"material mip manifest has no texture inventory: {manifest_path}")
    names = [str(texture["name"]) for texture in textures]
    if len(set(names)) != len(names) or len(names) != int(manifest["texture_count"]):
        raise ValueError(f"material mip texture inventory changed: {manifest_path}")
    if not cache_root.is_dir():
        raise FileNotFoundError(f"material mip cache root is missing: {cache_root}")
    selected_names = set(names) if required_names is None else set(required_names)
    missing_names = selected_names - set(names)
    if missing_names:
        raise ValueError(
            f"material mip manifest lacks required textures {sorted(missing_names)}: "
            f"{manifest_path}"
        )
    if required_names is None:
        actual_directories = {path.name for path in cache_root.iterdir() if path.is_dir()}
        if set(names) != actual_directories:
            raise ValueError(f"material mip cache directory inventory changed: {cache_root}")

    level_count = 0
    for texture in textures:
        if texture["name"] not in selected_names:
            continue
        source = texture.get("source")
        if isinstance(source, dict):
            _validate_file_record(source, f"{manifest_path.name}:{texture['name']}:source")
        elif isinstance(source, str):
            _validate_file_record(
                {
                    "path": source,
                    "byte_length": texture["source_byte_length"],
                    "sha256": texture["source_sha256"],
                },
                f"{manifest_path.name}:{texture['name']}:source",
            )
        else:
            raise ValueError(f"{texture['name']} has no exact source BNTX identity")

        levels = texture.get("levels")
        if not isinstance(levels, list) or not levels:
            raise ValueError(f"{texture['name']} has no exact mip levels")
        texture_directory = (cache_root / texture["name"]).resolve()
        expected_files: set[Path] = set()
        for expected_level, level in enumerate(levels):
            if int(level["level"]) != expected_level:
                raise ValueError(f"{texture['name']} mip level order changed")
            path = _validate_file_record(
                level, f"{manifest_path.name}:{texture['name']}:mip{expected_level}"
            )
            if path.parent != texture_directory:
                raise ValueError(f"{texture['name']} mip escaped its checked cache directory")
            expected_files.add(path)
        actual_files = {
            path.resolve()
            for path in texture_directory.iterdir()
            if path.is_file()
        }
        if actual_files != expected_files:
            raise ValueError(f"{texture['name']} mip file inventory changed")
        level_count += len(levels)
    if required_names is None and level_count != int(manifest["mip_level_count"]):
        raise ValueError(f"material mip level inventory changed: {manifest_path}")
    return {
        "path": _logical_path(manifest_path),
        "sha256": _sha256(manifest_path),
        "cache_root": _logical_path(cache_root),
        "texture_count": len(selected_names),
        "level_count": level_count,
        "textures": sorted(selected_names),
        "validation_scope": "complete-manifest" if required_names is None else "active-capability",
    }


def _validate_required_char_info(
    char_info: dict[str, Any], required: dict[str, Any], prefix: str = "char_info"
) -> None:
    for key, expected in required.items():
        if key not in char_info:
            raise ValueError(f"classic capability requires missing {prefix}.{key}")
        actual = char_info[key]
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                raise ValueError(f"classic capability requires an object at {prefix}.{key}")
            _validate_required_char_info(actual, expected, f"{prefix}.{key}")
        elif actual != expected:
            raise ValueError(
                f"classic capability requires {prefix}.{key}={expected!r}, got {actual!r}"
            )


def _file_record_identity(record: dict[str, Any]) -> tuple[str, int, str]:
    """Return the strict portable identity of one hash-bound file record."""

    try:
        return (
            str(record["path"]),
            int(record["byte_length"]),
            str(record["sha256"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("classic file record is incomplete") from error


def _value_at_contract_path(value: dict[str, Any], dotted_path: str) -> Any:
    current: Any = value
    for component in dotted_path.split("."):
        if not isinstance(current, dict) or component not in current:
            raise ValueError(
                f"classic model admission requires effective_char_info.{dotted_path}"
            )
        current = current[component]
    return current


def _validate_model_admission_predicates(
    char_info: dict[str, Any],
    required: dict[str, Any],
    *,
    external_context: dict[str, Any] | None = None,
) -> None:
    """Evaluate the admission manifest's declarative effective-CharInfo predicates."""

    if required.get("_namespace") != "effective_char_info":
        raise ValueError("classic model admission predicate namespace changed")
    external = required.get("_external_context", {})
    if not isinstance(external, dict):
        raise ValueError("classic model admission external context changed")

    def validate_constraint(path: str, actual: Any, constraint: dict[str, Any]) -> None:
        operators = {
            key
            for key in constraint
            if key
            not in {
                "effect",
                "reason",
                "ignored_for_mode",
            }
        }
        supported = {"equals", "accepted_values", "one_of", "required", "required_for_modes"}
        if not operators or not operators <= supported:
            raise ValueError(
                f"classic model admission has an unsupported predicate at {path}: "
                f"{sorted(operators)!r}"
            )
        if "equals" in constraint and actual != constraint["equals"]:
            raise ValueError(
                f"classic model admission requires {path}={constraint['equals']!r}, "
                f"got {actual!r}"
            )
        allowed = constraint.get("accepted_values", constraint.get("one_of"))
        if allowed is not None and (
            not isinstance(allowed, list) or actual not in allowed
        ):
            raise ValueError(
                f"classic model admission requires {path} in {allowed!r}, got {actual!r}"
            )
        if constraint.get("required") not in (None, True):
            raise ValueError(f"classic model admission has an invalid required flag at {path}")
        required_modes = constraint.get("required_for_modes")
        if required_modes is not None:
            if not isinstance(required_modes, list):
                raise ValueError(
                    f"classic model admission required_for_modes changed at {path}"
                )
            mode = _value_at_contract_path(char_info, "glass_lens_material_mode")
            if mode in required_modes and actual is None:
                raise ValueError(
                    f"classic model admission requires {path} for glass mode {mode}"
                )

    def walk(container: dict[str, Any], prefix: str = "effective_char_info") -> None:
        for key, constraint in container.items():
            if key.startswith("_"):
                continue
            path = f"{prefix}.{key}"
            actual = _value_at_contract_path(char_info, key) if prefix == "effective_char_info" else None
            if not isinstance(constraint, dict):
                raise ValueError(f"classic model admission predicate changed at {path}")
            has_operator = any(
                operator in constraint
                for operator in (
                    "equals",
                    "accepted_values",
                    "one_of",
                    "required",
                    "required_for_modes",
                )
            )
            if has_operator:
                validate_constraint(path, actual, constraint)
                continue
            if not isinstance(actual, dict):
                raise ValueError(f"classic model admission requires an object at {path}")
            for nested_key, nested_constraint in constraint.items():
                nested_actual = _value_at_contract_path(char_info, f"{key}.{nested_key}")
                if not isinstance(nested_constraint, dict):
                    raise ValueError(
                        f"classic model admission predicate changed at {path}.{nested_key}"
                    )
                validate_constraint(
                    f"{path}.{nested_key}", nested_actual, nested_constraint
                )

    walk(required)
    actual_external = external_context or {}
    for key, constraint in external.items():
        if key != "for_hat" or not isinstance(constraint, dict):
            raise ValueError("classic model admission external context is unsupported")
        validate_constraint(
            "external_context.for_hat",
            bool(actual_external.get("for_hat", False)),
            constraint,
        )


def _validate_classic_model_admission(
    *,
    evidence: dict[str, Any],
    portable_scope: dict[str, Any],
    char_info: dict[str, Any],
    active_records: dict[str, dict[str, Any]],
    resource_signature: dict[str, Any],
    for_hat: bool = False,
) -> tuple[dict[str, Any], float, frozenset[str], int]:
    """Validate one capability's model selections against the generated manifest.

    Central capability generation selects entry indices only.  This render
    boundary remains the sole consumer of the entry predicates and exact model
    role resolver, so there is no second resource or shader allowlist.
    """

    evidence_manifest = evidence.get("classic_model_admission")
    evidence_profile = evidence.get("classic_mii_runtime_profile")
    scope = portable_scope.get("classic_model_admission")
    if not isinstance(evidence_manifest, dict) or not isinstance(evidence_profile, dict):
        raise ValueError("classic bridge lacks model-admission runtime evidence")
    if not isinstance(scope, dict):
        raise ValueError("classic capability lacks a model-admission scope")
    scope_manifest = scope.get("manifest")
    scope_profile = scope.get("runtime_profile")
    selected_entries = scope.get("selected_entries")
    if (
        not isinstance(scope_manifest, dict)
        or not isinstance(scope_profile, dict)
        or not isinstance(selected_entries, dict)
    ):
        raise ValueError("classic model-admission portable scope changed")
    if _file_record_identity(scope_manifest) != _file_record_identity(evidence_manifest):
        raise ValueError("classic model-admission scope differs from runtime evidence")
    if _file_record_identity(scope_profile) != _file_record_identity(evidence_profile):
        raise ValueError("classic runtime-profile scope differs from runtime evidence")

    manifest_path = _validate_file_record(
        evidence_manifest, "classic_bridge.runtime_evidence.classic_model_admission"
    )
    profile_path = _validate_file_record(
        evidence_profile, "classic_bridge.runtime_evidence.classic_mii_runtime_profile"
    )
    if manifest_path != CLASSIC_MODEL_ADMISSION.resolve():
        raise ValueError("classic model admission differs from the checked renderer manifest")
    if profile_path != CLASSIC_MII_RUNTIME_PROFILE.resolve():
        raise ValueError("classic Mii runtime profile differs from the checked renderer profile")
    manifest = _cached_load_json(manifest_path)
    runtime_profile = _cached_load_json(profile_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("classic model-admission schema changed")
    profile_key = runtime_profile.get("key")
    if (
        not isinstance(profile_key, str)
        or scope_profile.get("key") != profile_key
        or manifest.get("global_rules", {}).get("normalization", {}).get("profile_key")
        != profile_key
    ):
        raise ValueError("classic model admission runtime-profile key changed")
    inputs = manifest.get("provenance", {}).get("inputs", {})
    validated_manifest_inputs: dict[str, Path] = {}
    for input_key, evidence_key in (
        ("runtime_normalization_profile", "classic_mii_runtime_profile"),
        ("material_state", "material_state"),
        ("gameuber_programs", "gameuber_programs"),
        ("resource_domain", "classic_resource_domain"),
    ):
        input_record = inputs.get(input_key)
        evidence_record = evidence.get(evidence_key)
        if (
            not isinstance(input_record, dict)
            or not isinstance(evidence_record, dict)
            or _file_record_identity(input_record) != _file_record_identity(evidence_record)
        ):
            raise ValueError(
                f"classic model admission input {input_key} differs from runtime evidence"
            )
        validated_manifest_inputs[input_key] = _validate_file_record(
            evidence_record,
            f"classic_bridge.classic_model_admission.inputs.{input_key}",
        )
    for input_key, expected_path in (
        ("render_mii", Path(__file__).resolve()),
        ("gameuber_cpu", (REPOSITORY / "renderer" / "gameuber_cpu.py").resolve()),
        (
            "software_renderer",
            (REPOSITORY / "renderer" / "software_renderer.py").resolve(),
        ),
        (
            "native_current_draw",
            (REPOSITORY / "renderer" / "native_current_draw.py").resolve(),
        ),
        (
            "native_current_draw_kernel_source",
            (REPOSITORY / "renderer" / "native_current_draw_kernel.c").resolve(),
        ),
        (
            "native_current_opaque_kernel_source",
            (REPOSITORY / "renderer" / "native_current_opaque_kernel.c").resolve(),
        ),
        (
            "face_compositor",
            (REPOSITORY / "renderer" / "face_compositor.py").resolve(),
        ),
        (
            "faceline_compositor",
            (REPOSITORY / "renderer" / "faceline_compositor.py").resolve(),
        ),
        (
            "native_face_target",
            (REPOSITORY / "renderer" / "native_face_target.py").resolve(),
        ),
        (
            "native_face_target_kernel_source",
            (REPOSITORY / "renderer" / "native_face_target.c").resolve(),
        ),
        ("model_pose", (REPOSITORY / "renderer" / "model_pose.py").resolve()),
        (
            "bfres_exporter_source",
            (REPOSITORY / "tools" / "bfres-exporter" / "Program.cs").resolve(),
        ),
        ("mii_rendering_symbols", MII_RENDERING_SYMBOLS.resolve()),
        ("head_attachment_decomp_source", HEAD_ATTACHMENT_DECOMP_SOURCE.resolve()),
    ):
        input_record = inputs.get(input_key)
        if not isinstance(input_record, dict):
            raise ValueError(f"classic model admission lacks exact source input {input_key}")
        checked_path = _validate_file_record(
            input_record,
            f"classic_bridge.classic_model_admission.inputs.{input_key}",
        )
        if checked_path != expected_path:
            raise ValueError(f"classic model admission source input path changed: {input_key}")

    selector_index = manifest.get("selector_index")
    entries = manifest.get("entries")
    if not isinstance(selector_index, dict) or not isinstance(entries, list):
        raise ValueError("classic model-admission selector inventory changed")
    expected_logical_names = set(selector_index)
    if set(selected_entries) != expected_logical_names:
        raise ValueError("classic capability model-admission logical inventory changed")

    signature_payload = resource_signature.get("payload")
    signature_records = (
        signature_payload.get("records") if isinstance(signature_payload, dict) else None
    )
    if not isinstance(signature_records, list):
        raise ValueError("classic model admission lacks the active resource signature")
    signature_by_logical_name = {
        str(record.get("logical_name")): record
        for record in signature_records
        if isinstance(record, dict)
    }
    if (
        len(signature_by_logical_name) != len(signature_records)
        or not expected_logical_names.issubset(signature_by_logical_name)
    ):
        raise ValueError("classic model admission signature inventory changed")

    resource_domain_path = validated_manifest_inputs.get("resource_domain")
    resource_domain = (
        _cached_load_json(resource_domain_path)
        if isinstance(resource_domain_path, Path)
        else None
    )
    domain_model_resources = (
        resource_domain.get("model_resources")
        if isinstance(resource_domain, dict)
        and resource_domain.get("schema_version") == 1
        else None
    )
    if not isinstance(domain_model_resources, list) or not domain_model_resources:
        raise ValueError("classic resource-domain model inventory changed")
    head_model_unit_resources = {
        str(model.get("resource_name"))
        for model in domain_model_resources
        if isinstance(model, dict)
        and model.get("role") == "ModelUnit"
        and re.fullmatch(r"MiiHead\d{2}", str(model.get("resource_name", "")))
    }
    if not head_model_unit_resources:
        raise ValueError("classic resource domain has no Head ModelUnit inventory")

    bangs_side = bool(char_info["face_flags"]["bangs_side"])
    admission_resources: set[str] = set()
    nested_file_records = 0
    head_resource = _active_model_resource(active_records, "faceline")
    head_texcoord_records = manifest.get("provenance", {}).get(
        "multi_uv_head_texcoord_sidecars"
    )
    if (
        not isinstance(head_resource, str)
        or not isinstance(head_texcoord_records, dict)
        or set(head_texcoord_records) != head_model_unit_resources
    ):
        raise ValueError("classic model admission Head named-UV inventory changed")
    head_texcoord_record = head_texcoord_records.get(head_resource)
    if not isinstance(head_texcoord_record, dict):
        raise ValueError(f"classic model admission lacks {head_resource} named UVs")
    head_texcoord_path = _validate_file_record(
        head_texcoord_record,
        f"classic_bridge.classic_model_admission.{head_resource}.named_texcoords",
    )
    expected_head_texcoord_path = (
        MODEL_CACHE / head_resource / f"{head_resource}.texcoords.json"
    ).resolve()
    if head_texcoord_path != expected_head_texcoord_path:
        raise ValueError("classic model admission Head named-UV path changed")
    runtime_head_named_texcoords = _prepared_head_named_texcoord_report(head_resource)
    if (
        runtime_head_named_texcoords["resource"] != head_resource
        or _file_record_identity(head_texcoord_record)
        != _file_record_identity(runtime_head_named_texcoords["sidecar"])
        or runtime_head_named_texcoords["texcoord_bindings"]
        != {"texture": "_u0", "normal": "_u2"}
    ):
        raise ValueError("classic model admission selected-Head named UVs changed")
    nested_file_records += 1

    head_attachment_records = manifest.get("provenance", {}).get(
        "head_attachment_bones"
    )
    if (
        not isinstance(head_attachment_records, dict)
        or set(head_attachment_records) != head_model_unit_resources
    ):
        raise ValueError("classic model admission Head attachment inventory changed")
    head_attachment_record = head_attachment_records.get(head_resource)
    if not isinstance(head_attachment_record, dict):
        raise ValueError(f"classic model admission lacks {head_resource} attachments")
    prepared_head_record = head_attachment_record.get("prepared_bfres")
    if not isinstance(prepared_head_record, dict):
        raise ValueError(
            f"classic model admission lacks {head_resource} attachment source"
        )
    prepared_head_path = _validate_file_record(
        prepared_head_record,
        f"classic_bridge.classic_model_admission.{head_resource}.attachments",
    )
    expected_prepared_head_path = (MODEL_CACHE / head_resource / "bfres.json").resolve()
    if prepared_head_path != expected_prepared_head_path:
        raise ValueError("classic model admission Head attachment source path changed")
    runtime_head_attachments = _prepared_head_attachment_report(head_resource)
    if (
        head_attachment_record.get("resource") != head_resource
        or head_attachment_record.get("model_index") != 0
        or head_attachment_record.get("resolver")
        != "renderer.model_pose.bone_bind_transforms"
        or head_attachment_record.get("source") != runtime_head_attachments["source"]
        or head_attachment_record.get("bones") != runtime_head_attachments["bones"]
        or _file_record_identity(prepared_head_record)
        != _file_record_identity(runtime_head_attachments["prepared_bfres"])
    ):
        raise ValueError("classic model admission selected-Head attachments changed")
    nested_file_records += 1
    report_entries: dict[str, Any] = {}
    nose_parallax_height_scale = 0.0
    selected_field_names = {
        "entry_index",
        "selector",
        "resource_name",
        "model_role",
        "model_name",
        "model_index",
        "inactive_projection",
    }

    for logical_name in sorted(expected_logical_names):
        selected = selected_entries.get(logical_name)
        active = active_records.get(logical_name)
        if not isinstance(selected, dict) or set(selected) != selected_field_names:
            raise ValueError(
                f"classic capability selected entry changed for {logical_name}"
            )
        signature_record = signature_by_logical_name[logical_name]
        selected_projection = selected["inactive_projection"]
        if selected_projection is not None or selected["entry_index"] == -1:
            signature_selector = signature_record.get("selector")
            selected_null_fields = {
                "resource_name": None,
                "model_role": None,
                "model_name": None,
                "model_index": None,
            }
            if (
                not isinstance(selected_projection, dict)
                or selected["entry_index"] != -1
                or type(selected.get("selector")) is not int
                or selected["selector"] != signature_selector
                or {
                    field: selected.get(field) for field in selected_null_fields
                }
                != selected_null_fields
                or signature_record.get("inactive_projection")
                != selected_projection
                or signature_record.get("enabled") is not False
                or signature_record.get("models") != []
                or signature_record.get("texture") is not None
            ):
                raise ValueError(
                    f"classic capability inactive sentinel changed for {logical_name}"
                )
            if active is not None and (
                not isinstance(active, dict)
                or active.get("selector") != signature_selector
                or active.get("inactive_projection") != selected_projection
                or active.get("enabled") is not False
            ):
                raise ValueError(
                    f"classic inactive Parts/signature projection differs for {logical_name}"
                )
            # A disabled raw Parts row may retain dormant source ModelUnits or
            # texture provenance (for example HairFront ordinary/hat variants
            # and HairNothing). active_resource_signature already validates
            # that raw payload and projects canonical models=[]/texture=None;
            # the selected sentinel above is the sole render-facing contract.
            report_entries[logical_name] = {
                "entry_index": -1,
                "selector": int(signature_selector),
                "resource_name": None,
                "model_role": None,
                "model_name": None,
                "model_index": None,
                "inactive_projection": selected_projection,
                "central_variant_selection": "not_applicable_source_inactive",
                "external_entry_lookup": "skipped",
                "status": "source_inactive_no_draw",
            }
            continue
        if type(selected["entry_index"]) is not int or selected["entry_index"] < 0:
            raise ValueError(
                f"classic capability has an unnamed inactive entry for {logical_name}"
            )
        if not isinstance(active, dict):
            raise ValueError(f"active Parts lacks model-admission record {logical_name}")
        if (
            signature_record.get("inactive_projection") is not None
            or signature_record.get("enabled") is not True
            or not isinstance(signature_record.get("models"), list)
            or not signature_record["models"]
        ):
            raise ValueError(
                f"classic capability routed an inactive signature through external admission for {logical_name}"
            )
        selector = int(active["selector"])
        if signature_record.get("selector") != selector:
            raise ValueError(
                f"classic model admission signature selector changed for {logical_name}"
            )
        indexed = selector_index.get(logical_name, {}).get(str(selector))
        if not isinstance(indexed, dict):
            raise ValueError(
                f"classic model admission lacks {logical_name} selector {selector}"
            )
        entry_index = int(indexed["entry_index"])
        if (
            selected["entry_index"] != entry_index
            or int(selected["selector"]) != selector
            or entry_index < 0
            or entry_index >= len(entries)
        ):
            raise ValueError(
                f"classic capability selected the wrong admission entry for {logical_name}"
            )
        entry = entries[entry_index]
        if (
            not isinstance(entry, dict)
            or entry.get("logical_name") != logical_name
            or int(entry.get("selector", -1)) != selector
            or entry.get("parts_record") != active.get("record")
            or bool(entry.get("is_nothing")) != bool(active.get("is_nothing"))
            or entry.get("resource_flags", {}) != active.get("resource_flags", {})
        ):
            raise ValueError(
                f"classic model admission Parts identity changed for {logical_name}"
            )
        entry_parts = entry.get("parts_config")
        if not isinstance(entry_parts, dict) or (
            str(entry_parts.get("path")),
            int(entry_parts.get("byte_length", -1)),
            str(entry_parts.get("sha256")),
        ) != (
            str(active.get("parts_config")),
            int(active.get("parts_config_byte_length", -1)),
            str(active.get("parts_config_sha256")),
        ):
            raise ValueError(
                f"classic model admission Parts source changed for {logical_name}"
            )
        _validate_model_admission_predicates(
            char_info,
            entry.get("required_char_info", {}),
            external_context={"for_hat": for_hat},
        )
        admission = entry.get("admission", {})
        if (
            admission.get("admitted_when_constraints_match") is not True
            or admission.get("blockers") != []
        ):
            raise ValueError(f"classic model admission blocks {logical_name}:{selector}")

        is_nothing = bool(entry["is_nothing"])
        enabled = bool(active.get("enabled"))
        if logical_name == "hair_front":
            main_hair = active_records.get("hair", {})
            gate_enabled = bool(
                main_hair.get("resource_flags", {}).get("IsAttachableHairFront")
            )
            if (
                active.get("gate") != "selected Hair.IsAttachableHairFront"
                or bool(active.get("gate_enabled")) != gate_enabled
                or enabled != gate_enabled
                or (not gate_enabled and admission.get("no_draw_when_gate_false") is not True)
            ):
                raise ValueError("classic HairFront gate differs from the effective Hair Parts")
        elif enabled != (not is_nothing):
            raise ValueError(f"classic model admission draw state changed for {logical_name}")

        expected_resource: str | None = None
        expected_role: str | None = None
        expected_model_name: str | None = None
        expected_model_index: int | None = None
        selected_variant: dict[str, Any] | None = None
        if enabled:
            expected_resource = str(entry.get("resource_name"))
            model_units = [
                model
                for model in active.get("model_resources", [])
                if model.get("role") == "ModelUnit"
            ]
            if (
                len(model_units) != 1
                or model_units[0].get("resource_name") != expected_resource
                or model_units[0].get("bfres") != entry.get("bfres", {}).get("path")
            ):
                raise ValueError(
                    f"classic model admission resource differs from active Parts for {logical_name}"
                )
            variants = entry.get("model_variants")
            if not isinstance(variants, list) or not variants:
                raise ValueError(f"classic model admission has no variants for {logical_name}")
            if logical_name in {"hair", "hair_front"}:
                hair_selection = _hair_model_selection(
                    active,
                    model_key=logical_name,
                    logical_name=logical_name,
                    bangs_side=bangs_side,
                    for_hat=for_hat,
                )
                if hair_selection is None:
                    raise ValueError(f"classic Hair resolver did not select {logical_name}")
                expected_resource = hair_selection.resource_name
                expected_role = hair_selection.role
                expected_model_name = hair_selection.model_name
                expected_model_index = hair_selection.model_index
            else:
                primary = [
                    variant
                    for variant in variants
                    if variant.get("logical_role") == "ModelUnit"
                ]
                if len(primary) != 1:
                    raise ValueError(
                        f"classic model admission has no unique ModelUnit for {logical_name}"
                    )
                expected_role = "ModelUnit"
                expected_model_name = str(primary[0]["model_name"])
                expected_model_index = int(primary[0]["model_index"])
            matches = [
                variant
                for variant in variants
                if variant.get("logical_role") == expected_role
                and variant.get("model_name") == expected_model_name
                and int(variant.get("model_index", -1)) == expected_model_index
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"classic selected model variant is absent for {logical_name}"
                )
            selected_variant = matches[0]
            if logical_name in {"hair", "hair_front"}:
                contexts = selected_variant.get("role_selection", {}).get(
                    "selection_contexts", []
                )
                actual_context = {
                    "for_hat": for_hat,
                    "face_flags.bangs_side": bangs_side,
                    "runtime_horizontal_mirror": hair_selection.mirror_horizontal,
                    "flip_horizontal_sign": hair_selection.flip_horizontal_sign,
                    "clockwise_front_face": hair_selection.mirror_horizontal,
                }
                if not any(
                    isinstance(context, dict)
                    and all(context.get(key) == value for key, value in actual_context.items())
                    for context in contexts
                ):
                    raise ValueError(
                        f"classic Hair role context is not admitted for {logical_name}"
                    )
            nested_file_records += _validate_nested_file_records(
                [selected_variant],
                f"classic_bridge.classic_model_admission.{logical_name}",
            )
            admission_resources.add(expected_resource)

        central_selected = {
            "entry_index": entry_index,
            "selector": selector,
            "resource_name": expected_resource,
            "model_role": None,
            "model_name": None,
            "model_index": None,
            "inactive_projection": None,
        }
        if selected != central_selected:
            raise ValueError(
                f"classic capability entry/resource selection differs from runtime for {logical_name}"
            )
        if logical_name == "nose":
            surface = entry.get("runtime", {}).get("surface", {})
            parallax = surface.get("parallax") if surface.get("present") else None
            nose_parallax_height_scale = (
                float(parallax["parallax_height_scale"])
                if isinstance(parallax, dict)
                else 0.0
            )
        report_entries[logical_name] = {
            "entry_index": entry_index,
            "selector": selector,
            "resource_name": expected_resource,
            "model_role": expected_role,
            "model_name": expected_model_name,
            "model_index": expected_model_index,
            "inactive_projection": None,
            "central_variant_selection": "deferred_to_render_boundary",
            "status": "validated_no_draw" if not enabled else "validated_selected_variant",
        }

    return (
        {
            "path": _logical_path(manifest_path),
            "sha256": _sha256(manifest_path),
            "schema_version": manifest["schema_version"],
            "runtime_profile": {
                "path": _logical_path(profile_path),
                "sha256": _sha256(profile_path),
                "key": profile_key,
            },
            "selected_entries": report_entries,
            "selected_head_named_texcoords": runtime_head_named_texcoords,
            "selected_head_attachments": {
                "resource": head_resource,
                "prepared_bfres": runtime_head_attachments["prepared_bfres"],
                "source": runtime_head_attachments["source"],
                "bones": runtime_head_attachments["bones"],
            },
            "validation_basis": (
                "effective CharInfo selector + exact active Parts + generated entry predicate + "
                "renderer model-role selection; no secondary allowlist"
            ),
        },
        nose_parallax_height_scale,
        frozenset(admission_resources),
        nested_file_records,
    )


def _resolve_legacy_headwear_selection(
    profile: dict[str, Any],
    presentation_context: dict[str, Any],
    char_info: dict[str, Any],
    program_document: dict[str, Any],
) -> tuple[LegacyHeadwearSelection | None, tuple[str, ...], int]:
    """Resolve a lossy legacy selector only through its checked sidecar."""

    boundary = profile.get("source_boundary", {})
    color_contract = profile.get("color_contract", {})
    draw_contract = profile.get("runtime_draw_contract", {})
    hat_attachment = profile.get("hat_attachment", {})
    portable_hat_matrix = hat_attachment.get("portable_local_matrix", {})
    records = profile.get("headwear")
    expected_translation = (0.0, 0.3779999911785126, -0.037140000611543655)
    expected_rotation_degrees = (-12.0, 0.0, 0.0)
    expected_hat_matrix = (
        (1.0, 0.0, 0.0, 0.0),
        (0.0, 0.9781476007338057, 0.20791169081775934, 0.3779999911785126),
        (0.0, -0.20791169081775934, 0.9781476007338057, -0.037140000611543655),
        (0.0, 0.0, 0.0, 1.0),
    )
    attachment_rows = portable_hat_matrix.get("column_vector_rows")
    if (
        profile.get("schema_version") != 1
        or boundary.get("selector_is_serialized_in_ltd") is not False
        or boundary.get("source_discriminator_values") != [34, 57]
        or boundary.get("mongo_or_person_identity_used") is not False
        or boundary.get("display_name_or_target_hash_used") is not False
        or color_contract.get("runtime_field") != "effective canonical hair_color_primary"
        or color_contract.get("allowed_indices") != list(range(8))
        or color_contract.get("favorite_color_is_not_the_variation_selector") is not True
        or draw_contract.get("normal_hair_action")
        != "replace the ordinary Hair 45 model draw with ModelUnitForHat"
        or draw_contract.get("headwear_transform")
        != (
            "head_scene_transform @ translation(HatOffsetTrans) @ "
            "rotation_x(radians(HatOffsetRotate.X)) @ prepared_rigid_shape_bind_transform"
        )
        or draw_contract.get("additional_title_hat_attachment") != portable_hat_matrix
        or draw_contract.get("model_unit_scale") != 1
        or hat_attachment.get("translation", {}).get("xyz") != list(expected_translation)
        or hat_attachment.get("translation", {}).get("float32_bits")
        != ["0x00000000", "0x3ec18937", "0xbd18201d"]
        or hat_attachment.get("rotation_degrees", {}).get("xyz")
        != list(expected_rotation_degrees)
        or hat_attachment.get("rotation_degrees", {}).get("float32_bits")
        != ["0xc1400000", "0x00000000", "0x00000000"]
        or portable_hat_matrix.get("formula")
        != "translation(HatOffsetTrans) @ rotation_x(radians(HatOffsetRotate.X))"
        or attachment_rows != [list(row) for row in expected_hat_matrix]
        or not isinstance(records, list)
        or len(records) != 2
    ):
        raise ValueError("legacy headwear presentation contract changed")

    nested_file_records = 0
    for label, file_record in (
        ("system_param", hat_attachment.get("source")),
        ("byml_decoder", hat_attachment.get("decoder")),
    ):
        if not isinstance(file_record, dict):
            raise ValueError(f"legacy headwear lacks {label} source evidence")
        _validate_file_record(file_record, f"legacy_headwear.hat_attachment.{label}")
        nested_file_records += 1

    for_hat = bool(presentation_context.get("for_hat"))
    if not for_hat:
        if presentation_context.get("kind") not in {
            "none",
            INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
        }:
            raise ValueError("inactive legacy headwear context has an unexpected kind")
        return None, (), nested_file_records
    if presentation_context.get("kind") not in {
        LEGACY_HEADWEAR_CONTEXT_KIND,
        INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
    }:
        raise ValueError("active legacy headwear context kind changed")
    source_hair_type = presentation_context.get("source_hair_type")
    if (
        type(source_hair_type) is not int
        or source_hair_type not in (34, 57)
        or presentation_context.get("canonical_hair_type") != 45
        or int(char_info.get("hair_type", -1)) != 45
    ):
        raise ValueError("legacy headwear context disagrees with effective CharInfo")

    expected_identity = {
        34: ("simple_knit", "ClothHeadwearHatSimpleKnit", "SimpleKnit__mt_Body"),
        57: ("simple_cap", "ClothHeadwearHatSimpleCap", "SimpleCap__mt_Body"),
    }[source_hair_type]
    matches = [record for record in records if record.get("legacy_hair_type") == source_hair_type]
    if len(matches) != 1:
        raise ValueError("legacy headwear selector does not resolve exactly once")
    record = matches[0]
    presentation_kind, resource_name, shape_name = expected_identity
    prepared = record.get("prepared_model", {})
    if (
        record.get("canonical_ltd_hair_type") != 45
        or record.get("presentation_kind") != presentation_kind
        or record.get("resource_name") != resource_name
        or prepared.get("model") != resource_name
        or prepared.get("shape") != shape_name
        or prepared.get("material") != "mt_Body"
        or prepared.get("vertex_skin_count") != 0
        or prepared.get("rigid_bone_index") != 2
    ):
        raise ValueError("legacy headwear resource identity changed")

    for key in ("bfres",):
        _validate_file_record(record[key], f"legacy_headwear.{source_hair_type}.{key}")
        nested_file_records += 1
    metadata_path = _validate_file_record(
        prepared["metadata"], f"legacy_headwear.{source_hair_type}.prepared_metadata"
    )
    obj_path = _validate_file_record(
        prepared["obj"], f"legacy_headwear.{source_hair_type}.prepared_obj"
    )
    nested_file_records += 2
    if metadata_path != MODEL_CACHE / resource_name / "bfres.json":
        raise ValueError("legacy headwear prepared metadata path changed")
    if obj_path != MODEL_CACHE / resource_name / f"{resource_name}.obj":
        raise ValueError("legacy headwear prepared OBJ path changed")

    hair_color = char_info.get("hair_color_primary")
    if type(hair_color) is not int or hair_color not in range(8):
        raise ValueError("legacy headwear hair-color variation is outside 0..7")
    texture_names = {
        str(texture.get("name")): texture
        for texture in record.get("texture_variations", [])
        if isinstance(texture, dict)
    }
    albedo = f"{resource_name}_Body_Alb.{hair_color:02d}"
    normal = f"{resource_name}_Body_Nrm"
    roughness = f"{resource_name}_Body_Mic"
    required_textures = (albedo, normal, roughness)
    if not all(name in texture_names for name in required_textures):
        raise ValueError("legacy headwear selected texture variation is missing")
    for name in required_textures:
        _validate_file_record(
            texture_names[name]["source"],
            f"legacy_headwear.{source_hair_type}.texture.{name}",
        )
        nested_file_records += 1

    programs = [
        item
        for item in program_document.get("programs", [])
        if item.get("family") == "headwear" and item.get("resource") == resource_name
    ]
    if len(programs) != 1:
        raise ValueError("legacy headwear GameUber identity does not resolve exactly once")
    program = programs[0]
    vertex_sha256 = str(program.get("stages", {}).get("vertex", {}).get("instructions", {}).get("sha256"))
    fragment_sha256 = str(program.get("stages", {}).get("fragment", {}).get("instructions", {}).get("sha256"))
    if (
        program.get("resolved_program_index") != 96
        or program.get("compatible_program_indices") != [96]
        or program.get("selection_status") != "exact_unique"
        or vertex_sha256
        != "e1ec9246616bbb1cd97352dd7773ca2bc21c8793750d70dee94a6cabdb8f969c"
        or fragment_sha256
        != "d392a14ccc3b7d4494d62392029fdf83ccb0ef2a1af6f4dad43cf00d6bbfc0bf"
    ):
        raise ValueError("legacy headwear GameAll96 program identity changed")
    nested_file_records += _validate_nested_file_records(
        program, f"legacy_headwear.{source_hair_type}.gameuber"
    )

    selection = LegacyHeadwearSelection(
        source_hair_type=source_hair_type,
        presentation_kind=presentation_kind,
        resource_name=resource_name,
        model_name=resource_name,
        model_index=0,
        shape_name=shape_name,
        obj_path=obj_path,
        albedo_texture=albedo,
        normal_texture=normal,
        roughness_texture=roughness,
        gameall_program=96,
        vertex_instructions_sha256=vertex_sha256,
        fragment_instructions_sha256=fragment_sha256,
        contract_sha256=_sha256(LEGACY_HEADWEAR_PRESENTATION),
        hat_offset_translation=expected_translation,
        hat_offset_rotation_degrees=expected_rotation_degrees,
        hat_attachment_matrix=expected_hat_matrix,
    )
    return selection, required_textures, nested_file_records


def _resolve_classic_bridge_support(
    document: dict[str, Any],
    active_parts_manifest: dict[str, Any],
    active_records: dict[str, dict[str, Any]],
    *,
    presentation_context: dict[str, Any] | None = None,
) -> RenderSupport:
    """Resolve a generic classic bridge only by the exact active resource signature."""

    bundle = _cached_load_json(CLASSIC_BRIDGE_RESOURCE_BUNDLES)
    if bundle.get("schema_version") != 1:
        raise ValueError("classic-bridge resource bundle schema changed")
    evidence = bundle.get("runtime_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("classic-bridge bundle has no runtime evidence")

    material_state_path = _validate_file_record(
        evidence["material_state"], "classic_bridge.runtime_evidence.material_state"
    )
    material_state = _cached_load_json(material_state_path)
    nested_file_record_count = 0

    material_manifest_records = evidence.get("material_texture_manifests")
    material_root_values = evidence.get("material_texture_cache_roots")
    if (
        not isinstance(material_manifest_records, list)
        or not isinstance(material_root_values, list)
        or len(material_manifest_records) != len(material_root_values)
    ):
        raise ValueError("classic material manifest/root inventory changed")
    material_manifests = tuple(
        _validate_file_record(record, f"classic_bridge.material_manifest[{index}]")
        for index, record in enumerate(material_manifest_records)
    )
    material_roots = tuple(
        _resolve_repository_path(str(value)) for value in material_root_values
    )
    expected_material_pair = (
        (TEXTURE_MIPS.resolve(), TEXTURE_MIP_CACHE.resolve()),
        (CLASSIC_BRIDGE_TEXTURE_MIPS.resolve(), CLASSIC_BRIDGE_TEXTURE_MIP_CACHE.resolve()),
    )
    if tuple(zip(material_manifests, material_roots)) != expected_material_pair:
        raise ValueError("classic material cache identities differ from the checked v1 bridge")

    face_manifest_records = evidence.get("face_sprite_mip_manifests")
    if not isinstance(face_manifest_records, list) or len(face_manifest_records) != 1:
        raise ValueError("classic face-sprite manifest inventory changed")
    face_manifests = tuple(
        _validate_file_record(record, f"classic_bridge.face_manifest[{index}]")
        for index, record in enumerate(face_manifest_records)
    )
    if face_manifests != (CLASSIC_BRIDGE_FACE_SPRITE_MIPS.resolve(),):
        raise ValueError(
            "classic face-sprite manifest differs from the complete checked classic domain"
        )

    program_ledger = _validate_file_record(
        evidence["gameuber_programs"], "classic_bridge.runtime_evidence.gameuber_programs"
    )
    program_document = _cached_load_json(program_ledger)
    if program_ledger != CLASSIC_BRIDGE_GAMEUBER_PROGRAMS.resolve():
        raise ValueError("classic GameUber ledger differs from the checked v1 bridge")

    packed_mii_parts = _validate_file_record(
        evidence["packed_mii_parts_bntx"],
        "classic_bridge.runtime_evidence.packed_mii_parts_bntx",
    )
    presentation_path = _validate_file_record(
        evidence["presentation_outfit"],
        "classic_bridge.runtime_evidence.presentation_outfit",
    )
    if presentation_path != PRESENTATION_OUTFIT.resolve():
        raise ValueError("classic presentation ledger differs from the checked v1 bridge")
    portrait_framing_path = _validate_file_record(
        evidence["portrait_framing"],
        "classic_bridge.runtime_evidence.portrait_framing",
    )
    if portrait_framing_path != CLASSIC_BRIDGE_PORTRAIT_FRAMING.resolve():
        raise ValueError("classic portrait-framing ledger differs from the checked bridge")
    portrait_framing_profile = _cached_load_json(portrait_framing_path)
    portrait_tracking = portrait_framing_profile.get("portrait_tracking", {})
    if (
        portrait_framing_profile.get("schema_version") != 2
        or portrait_framing_profile.get("kind") != "classic_bridge_portrait_framing"
        or portrait_tracking.get("classification")
        != "user_directed_semantic_head_anchor_relative"
        or portrait_tracking.get("source_bone") != "Head"
        or portrait_tracking.get("appearance_pixels_used_for_tracking") is not False
    ):
        raise ValueError("classic portrait-framing contract changed")
    legacy_headwear_path = _validate_file_record(
        evidence["legacy_headwear_presentation"],
        "classic_bridge.runtime_evidence.legacy_headwear_presentation",
    )
    if legacy_headwear_path != LEGACY_HEADWEAR_PRESENTATION.resolve():
        raise ValueError("classic legacy-headwear ledger differs from the checked bridge")
    legacy_headwear_profile = _cached_load_json(legacy_headwear_path)
    face_presentation_path = _validate_file_record(
        evidence["classic_face_presentation"],
        "classic_bridge.runtime_evidence.classic_face_presentation",
    )
    if face_presentation_path != CLASSIC_FACE_PRESENTATION.resolve():
        raise ValueError(
            "classic face-presentation ledger differs from the checked renderer contract"
        )
    face_presentation = _cached_load_json(face_presentation_path)
    faceline_target_contract = face_presentation.get("faceline_target_contract", {})
    faceline_contract_key = faceline_target_contract.get("key")
    if (
        face_presentation.get("schema_version") != 1
        or face_presentation.get("status")
        != "SOURCE_BACKED_COMPLETE_CLASSIC_FACE_PRESENTATION"
        or faceline_contract_key
        != "classic_make_lower_make_upper_wrinkle_upper_wrinkle_lower_beard_short_ordered_v2"
    ):
        raise ValueError("classic face-presentation contract changed")

    prepared_cache = evidence.get("prepared_model_cache")
    if not isinstance(prepared_cache, dict):
        raise ValueError("classic bridge has no prepared-model inventory")

    signature = active_resource_signature(
        active_parts_manifest,
        repository=REPOSITORY,
        packed_mii_parts_bntx=packed_mii_parts,
    )
    capability = resolve_capability(bundle, signature)
    _validate_required_char_info(
        document["char_info"], capability.get("required_char_info", {})
    )
    profile = capability.get("presentation_profile")
    if (
        not isinstance(profile, dict)
        or profile.get("selection_kind") != "renderer presentation preset"
        or profile.get("share_mii_contains_cloth_set_or_color") is not False
    ):
        raise ValueError("classic capability presentation boundary changed")
    variation = int(profile["variation_index"])
    if variation != 0:
        raise ValueError("classic v1 bridge requires explicit neutral presentation variation 00")
    portable_scope = capability.get("portable_scope")
    if not isinstance(portable_scope, dict):
        raise ValueError("classic capability has no portable scope")
    (
        legacy_headwear_selection,
        legacy_headwear_textures,
        legacy_headwear_nested_file_records,
    ) = _resolve_legacy_headwear_selection(
        legacy_headwear_profile,
        presentation_context or {},
        document["char_info"],
        program_document,
    )
    nested_file_record_count += legacy_headwear_nested_file_records
    capability_material_textures = portable_scope.get("material_textures")
    if not isinstance(capability_material_textures, list) or any(
        not isinstance(value, str) for value in capability_material_textures
    ):
        raise ValueError("classic capability has no exact material-texture scope")
    portable_scope["material_textures"] = list(
        dict.fromkeys([*capability_material_textures, *legacy_headwear_textures])
    )
    selected_models = portable_scope.get("models")
    if (
        not isinstance(selected_models, list)
        or any(not isinstance(value, str) for value in selected_models)
        or selected_models != signature["payload"]["active_model_resources"]
    ):
        raise ValueError("classic capability model scope differs from its active signature")
    if portable_scope.get("faceline_contract") != faceline_contract_key:
        raise ValueError(
            "classic capability faceline contract differs from presentation evidence"
        )
    (
        model_admission_report,
        nose_parallax_height_scale,
        admission_resources,
        admission_nested_file_records,
    ) = _validate_classic_model_admission(
        evidence=evidence,
        portable_scope=portable_scope,
        char_info=document["char_info"],
        active_records=active_records,
        resource_signature=signature,
        for_hat=bool((presentation_context or {}).get("for_hat")),
    )
    nested_file_record_count += admission_nested_file_records
    legacy_models = set(selected_models) - set(admission_resources)
    if not legacy_models or any(
        not resource_name.startswith("MiiHead") for resource_name in legacy_models
    ):
        raise ValueError(
            "classic model admission must leave only the selected Head resource on the legacy path"
        )

    # The comprehensive ledgers are evidence inventories, not a reason to hash
    # thousands of unrelated files for every HTTP render.  Their top-level files
    # are already hash-bound above; validate nested source/stage files only for
    # the components admitted by this exact capability.
    material_resources = material_state.get("resources")
    if not isinstance(material_resources, list):
        raise ValueError("classic material-state resource inventory changed")
    selected_material_resources = [
        record
        for record in material_resources
        if record.get("resource_name") in legacy_models
    ]
    if {str(record.get("resource_name")) for record in selected_material_resources} != set(
        legacy_models
    ):
        raise ValueError("classic capability lacks exact Head material-state evidence")
    nested_file_record_count += _validate_nested_file_records(
        selected_material_resources, "classic_bridge.active_material_state"
    )

    selected_program_records = [
        record
        for record in program_document.get("programs", [])
        if record.get("resource") in legacy_models
    ]
    if not selected_program_records:
        raise ValueError("classic capability lacks active Head GameUber program evidence")
    nested_file_record_count += _validate_nested_file_records(
        selected_program_records, "classic_bridge.active_gameuber_programs"
    )

    for resource_name in sorted(legacy_models):
        cache = prepared_cache.get(resource_name)
        if not isinstance(cache, dict):
            raise ValueError(f"classic bridge has no prepared cache for {resource_name}")
        root = _resolve_repository_path(str(cache["root"]))
        files = cache.get("files")
        if not isinstance(files, list) or len(files) != int(cache["file_count"]):
            raise ValueError(f"{resource_name} prepared-model inventory changed")
        expected_files = {
            _validate_file_record(
                record, f"classic_bridge.prepared_model_cache.{resource_name}"
            )
            for record in files
        }
        actual_files = {path.resolve() for path in root.rglob("*") if path.is_file()}
        if expected_files != actual_files:
            raise ValueError(f"{resource_name} prepared-model cache contains untracked files")

    body_program_selections = _resolve_body_gameall_materials()
    outfit_program_selections = _resolve_outfit_gameall_materials()
    glass_frame_program_selection, glass_lens_program_selection = (
        _resolve_glass_gameall_materials(
            document["char_info"], active_records, program_ledger
        )
    )
    return RenderSupport(
        selection_kind="exact active-resource signature",
        material_texture_cache_roots=material_roots,
        material_texture_manifests=material_manifests,
        face_sprite_mip_manifests=face_manifests,
        active_program_ledger=program_ledger,
        presentation_variation=variation,
        presentation_profile=profile,
        nose_parallax_height_scale=nose_parallax_height_scale,
        classic_bridge_report={
            "path": _logical_path(CLASSIC_BRIDGE_RESOURCE_BUNDLES),
            "sha256": _sha256(CLASSIC_BRIDGE_RESOURCE_BUNDLES),
            "schema_version": bundle["schema_version"],
            "capability_key": capability["key"],
            "resolution_basis": (
                "exact equality of the canonical active Parts/BFRES/BNTX payload and its SHA-256; "
                "no LTD hash, name, CreateId, profile, personality, or voice field participates"
            ),
            "resource_signature": {
                "algorithm": signature["algorithm"],
                "sha256": signature["sha256"],
                "record_count": len(signature["payload"]["records"]),
                "active_model_resources": signature["payload"]["active_model_resources"],
                "active_texture_resources": signature["payload"]["active_texture_resources"],
                "inactive_projections": [
                    {
                        "logical_name": record["logical_name"],
                        "selector": record["selector"],
                        "projection": record["inactive_projection"],
                    }
                    for record in signature["payload"]["records"]
                    if record.get("inactive_projection") is not None
                ],
                "excluded_target_fields": signature["excluded_target_fields"],
            },
            "required_char_info": capability.get("required_char_info", {}),
            "portable_scope": portable_scope,
            "model_admission": model_admission_report,
            "presentation_contract": {
                "path": _logical_path(face_presentation_path),
                "sha256": _sha256(face_presentation_path),
                "status": face_presentation["status"],
                "key": faceline_contract_key,
                "faceline_contract": faceline_contract_key,
            },
            "legacy_headwear_presentation": (
                legacy_headwear_selection.report()
                if legacy_headwear_selection is not None
                else {
                    "status": "inactive_no_source_context",
                    "contract": {
                        "path": _logical_path(legacy_headwear_path),
                        "sha256": _sha256(legacy_headwear_path),
                    },
                }
            ),
            "validated_nested_source_or_stage_file_records": nested_file_record_count,
        },
        body_program_selections=body_program_selections,
        outfit_program_selections=outfit_program_selections,
        glass_frame_program_selection=glass_frame_program_selection,
        glass_lens_program_selection=glass_lens_program_selection,
        faceline_contract=faceline_contract_key,
        portrait_framing_profile=portrait_framing_profile,
        legacy_headwear_selection=legacy_headwear_selection,
        classic_resource_signature_records={
            str(record["logical_name"]): json.loads(json.dumps(record))
            for record in signature["payload"]["records"]
        },
    )


def _resolve_render_support(
    document: dict[str, Any],
    active_parts_manifest: dict[str, Any],
    active_records: dict[str, dict[str, Any]],
    *,
    classic_bridge: bool,
    presentation_context: dict[str, Any] | None = None,
) -> RenderSupport:
    if classic_bridge:
        return _resolve_classic_bridge_support(
            document,
            active_parts_manifest,
            active_records,
            presentation_context=presentation_context or {},
        )
    target_sha256 = document["sha256"]
    try:
        roots = MATERIAL_TEXTURE_CACHE_ROOTS_BY_SHARE_MII_SHA256[target_sha256]
        program_ledger = GAMEUBER_PROGRAM_LEDGER_BY_SHARE_MII_SHA256[target_sha256]
        variation = PRESENTATION_VARIATION_BY_SHARE_MII_SHA256[target_sha256]
    except KeyError as error:
        raise ValueError(f"no checked fixture renderer support exists for {target_sha256}") from error
    body_program_selections = _resolve_body_gameall_materials()
    outfit_program_selections = _resolve_outfit_gameall_materials()
    glass_frame_program_selection, glass_lens_program_selection = (
        _resolve_glass_gameall_materials(
            document["char_info"], active_records, program_ledger
        )
    )
    return RenderSupport(
        selection_kind="checked target-pinned fixture",
        material_texture_cache_roots=roots,
        material_texture_manifests=(TEXTURE_MIPS,),
        face_sprite_mip_manifests=(FACE_SPRITE_MIPS,),
        active_program_ledger=program_ledger,
        presentation_variation=variation,
        presentation_profile=None,
        nose_parallax_height_scale=0.25,
        classic_bridge_report=None,
        body_program_selections=body_program_selections,
        outfit_program_selections=outfit_program_selections,
        glass_frame_program_selection=glass_frame_program_selection,
        glass_lens_program_selection=glass_lens_program_selection,
    )


def _configure_material_texture_caches(
    document: dict[str, Any], active_parts_path: Path, support: RenderSupport
) -> dict[str, Any]:
    """Select only the checked cache roots for this exact ShareMii target."""

    global _configured_material_texture_cache_roots
    target_sha256 = document["sha256"]
    roots = support.material_texture_cache_roots
    if any(not root.is_dir() for root in roots):
        raise FileNotFoundError(f"selected material-texture cache root is missing: {roots}")
    # A persistent worker is strictly serial.  Make the implicit cache-root
    # input part of its lifetime: retain decoded mips while the exact checked
    # root tuple is unchanged, and atomically discard every name-only entry
    # before selecting a different capability family.  Manifest/file identity
    # validation below still runs for every request, so this is acceleration,
    # never authority.
    if _configured_material_texture_cache_roots != roots:
        _material_texture.cache_clear()
        clear_native_draw_caches = getattr(
            native_current_draw, "clear_runtime_caches", None
        )
        if clear_native_draw_caches is not None:
            clear_native_draw_caches()
        _configured_material_texture_cache_roots = roots

    if support.classic_bridge_report is not None:
        portable_scope = support.classic_bridge_report.get("portable_scope", {})
        required_values = portable_scope.get("material_textures")
        if not isinstance(required_values, list) or any(
            not isinstance(value, str) for value in required_values
        ):
            raise ValueError("classic capability has no exact material-texture scope")
        required = frozenset(required_values)
        resolved_required: set[str] = set()
        checked_manifests = []
        for manifest_path, cache_root in zip(
            support.material_texture_manifests,
            support.material_texture_cache_roots,
            strict=True,
        ):
            manifest = _cached_load_json(manifest_path)
            manifest_textures = manifest.get("textures")
            if not isinstance(manifest_textures, list):
                raise ValueError(f"material mip manifest has no texture inventory: {manifest_path}")
            manifest_names = {str(record["name"]) for record in manifest_textures}
            selected = required & manifest_names
            # The established shared cache is small and also supplies the fixed
            # body/outfit presentation.  Keep its complete validation; scope the
            # comprehensive classic cache to the active capability only.
            validation_names = None if manifest_path == TEXTURE_MIPS.resolve() else frozenset(selected)
            checked_manifests.append(
                _validate_material_texture_manifest(
                    manifest_path, cache_root, validation_names
                )
            )
            overlap = resolved_required & selected
            if overlap:
                raise ValueError(
                    f"classic material texture resolves in more than one cache: {sorted(overlap)}"
                )
            resolved_required.update(selected)
        if resolved_required != set(required):
            raise ValueError(
                "classic material-texture scope is not fully cached: "
                f"{sorted(set(required) - resolved_required)}"
            )
        names = [
            name for manifest in checked_manifests for name in manifest["textures"]
        ]
        if len(set(names)) != len(names):
            raise ValueError("classic material texture resolves in more than one cache")
        return {
            "selection_kind": support.selection_kind,
            "active_cache_roots": [_logical_path(root) for root in roots],
            "manifests": checked_manifests,
            "target_specific_cache": None,
            "boundary": (
                "cache support is selected by the exact active resource signature; the input "
                "LTD hash and profile are validation/report fields only"
            ),
        }

    shared = _cached_load_json(TEXTURE_MIPS)
    report: dict[str, Any] = {
        "target_sha256": target_sha256,
        "active_cache_roots": [_logical_path(root) for root in roots],
        "shared_head_and_body_cache": {
            "path": _logical_path(TEXTURE_MIPS),
            "sha256": _sha256(TEXTURE_MIPS),
            "texture_count": shared["texture_count"],
            "level_count": shared["mip_level_count"],
            "scope": (
                "Kestron selected model textures plus BodyBaseDefault; the secondary target "
                "resolves shared body names here and selected model names from its own cache"
            ),
        },
        "target_specific_cache": None,
    }
    target_specific = TARGET_SPECIFIC_MATERIAL_TEXTURE_MIPS_BY_SHARE_MII_SHA256.get(
        target_sha256
    )
    if target_specific is None:
        return report

    manifest_path, cache_root = target_specific
    manifest = _cached_load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("target-specific material-texture mip manifest schema mismatch")
    target = manifest["target"]
    if target["sha256"] != target_sha256 or target["display_name"] != document["display_name"]:
        raise ValueError("target-specific material-texture mip manifest targets a different ShareMii")
    selection = manifest["selection_manifest"]
    if (
        selection["path"] != _logical_path(active_parts_path)
        or selection["sha256"] != _sha256(active_parts_path)
        or selection["target_sha256"] != target_sha256
    ):
        raise ValueError("target-specific material-texture mip manifest has stale PartsIndex evidence")
    textures = manifest["textures"]
    texture_names = {texture["name"] for texture in textures}
    actual_directories = {path.name for path in cache_root.iterdir() if path.is_dir()}
    if (
        len(textures) != manifest["texture_count"]
        or sum(len(texture["levels"]) for texture in textures) != manifest["mip_level_count"]
        or texture_names != actual_directories
    ):
        raise ValueError("target-specific material-texture mip manifest/cache inventory mismatch")
    for texture in textures:
        for level in texture["levels"]:
            path = REPOSITORY / level["path"]
            if (
                not path.is_file()
                or path.stat().st_size != level["byte_length"]
                or _sha256(path) != level["sha256"]
            ):
                raise ValueError(f"target-specific checked material mip changed: {level['path']}")
    report["target_specific_cache"] = {
        "path": _logical_path(manifest_path),
        "sha256": _sha256(manifest_path),
        "target_sha256": target_sha256,
        "selection_manifest_sha256": selection["sha256"],
        "texture_count": manifest["texture_count"],
        "level_count": manifest["mip_level_count"],
        "textures": sorted(texture_names),
        "generator": manifest["generator"],
    }
    return report


def _presentation_body_base_cutline_groups() -> frozenset[str]:
    """Resolve exact BodyBaseDefault groups hidden by the presentation outfit."""

    source = _cached_load_json(BODY_BASE_CUTLINE_SOURCE)
    if source.get("reference_image_values_used") is not False:
        raise ValueError("BodyBaseCutline source must reject reference-image values")
    checked = {
        int(item["key"]): frozenset(item["body_base_obj_groups_hidden"])
        for item in source["entries"]
    }
    if checked != BODY_BASE_CUTLINE_GROUPS:
        raise ValueError("BodyBaseCutline runtime mapping differs from checked SystemParam")
    groups: set[str] = set()
    for key in (3312601720, 3296514992, 2895499086, 1032020994):
        if key not in BODY_BASE_CUTLINE_GROUPS:
            raise ValueError(f"unresolved BodyBaseCutline key {key}")
        groups.update(BODY_BASE_CUTLINE_GROUPS[key])
    return frozenset(groups)


def _load_presentation_outfit_profile(
    document: dict[str, Any],
    support: RenderSupport,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the checked non-ShareMii clothing profile for this exact input."""

    ledger = _cached_load_json(PRESENTATION_OUTFIT)
    boundary = ledger["source_boundary"]
    if boundary["share_mii_contains_cloth_set_or_color"] is not False:
        raise ValueError("presentation ledger must not claim ShareMii clothing state")
    if boundary["reference_image_values_used_for_offsets_defaults_or_cutlines"] is not False:
        raise ValueError("presentation ledger must reject image-derived renderer values")
    if support.presentation_profile is not None:
        profile = support.presentation_profile
        if int(profile["variation_index"]) != support.presentation_variation:
            raise ValueError("classic presentation variation differs from matched capability")
        return ledger, profile
    profiles = [
        profile
        for profile in ledger["profiles"]
        if profile["share_mii_sha256"] == document["sha256"]
    ]
    if len(profiles) != 1:
        raise ValueError("ShareMii must resolve exactly one checked presentation profile")
    profile = profiles[0]
    if support.presentation_variation != int(profile["variation_index"]):
        raise ValueError("renderer presentation variation differs from checked ledger")
    return ledger, profile


def _load_active_parts(
    document: dict[str, Any],
    override_path: Path | None = None,
    normalization_report: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Load the PartsIndex result pinned to this exact ShareMii input."""

    if override_path is not None:
        manifest_path = override_path.resolve()
        if not manifest_path.is_file():
            raise FileNotFoundError(f"explicit active-parts manifest is missing: {manifest_path}")
    else:
        try:
            manifest_path = ACTIVE_PARTS_BY_SHARE_MII_SHA256[document["sha256"]]
        except KeyError as error:
            raise ValueError(
                "no checked PartsIndex manifest exists for ShareMii " + document["sha256"]
            ) from error
    manifest = (
        _load_request_json(manifest_path)
        if override_path is not None
        else dict(_cached_load_json(manifest_path))
    )
    if manifest.get("schema_version") != 1:
        raise ValueError("active-parts manifest schema changed")
    manifest["manifest_path"] = _logical_path(manifest_path)
    embedded_effective = manifest.get("effective_char_info")
    if embedded_effective is not None and embedded_effective != document["char_info"]:
        raise ValueError("active-parts effective CharInfo differs from renderer normalization")
    embedded_normalization = manifest.get("char_info_normalization")
    if (
        embedded_normalization is not None
        and normalization_report is not None
        and embedded_normalization != normalization_report
    ):
        raise ValueError("active-parts CharInfo normalization report differs from renderer")
    target = manifest["target"]
    expected_hash = target["sha256"]
    if document["sha256"] != expected_hash:
        raise ValueError(
            f"{manifest_path.name} targets {expected_hash}, not {document['sha256']}; "
            "regenerate it with tools/build_mii_active_parts.py --input/--output"
        )
    expected_target_fields = {
        "byte_length": document["byte_length"],
        "display_name": document["display_name"],
        "internal_name": document["char_info"]["name"],
        "gender": document["char_info"]["gender"],
        "face_gender": document["personality_and_voice"]["face_gender"],
    }
    if {key: target.get(key) for key in expected_target_fields} != expected_target_fields:
        raise ValueError("active-parts manifest target metadata differs from the live LTD")
    parts_metadata = manifest.get("parts_metadata", {})
    parts_metadata_path = _resolve_repository_path(str(parts_metadata.get("path")))
    if (
        not parts_metadata_path.is_file()
        or _sha256(parts_metadata_path) != parts_metadata.get("sha256")
    ):
        raise ValueError("active-parts PartsIndex metadata changed")
    records = {record["logical_name"]: record for record in manifest["records"]}
    if len(records) != manifest["selector_count"]:
        raise ValueError(f"{manifest_path} contains duplicate logical part names")
    for logical_name, record in records.items():
        selector_field = record.get("selector_field")
        if selector_field is not None:
            if selector_field not in document["char_info"]:
                raise ValueError(f"{logical_name} names unknown selector field {selector_field}")
            if int(record["selector"]) != int(document["char_info"][selector_field]):
                raise ValueError(
                    f"{logical_name} selector differs from live CharInfo.{selector_field}"
                )
        gate = record.get("gate")
        if isinstance(gate, str) and gate.startswith("face_flags."):
            flag = gate.removeprefix("face_flags.")
            if bool(record.get("gate_enabled")) != bool(
                document["char_info"]["face_flags"].get(flag)
            ):
                raise ValueError(f"{logical_name} gate differs from live CharInfo face flag")
    if sum(bool(record.get("enabled")) for record in records.values()) != int(
        manifest["enabled_record_count"]
    ):
        raise ValueError("active-parts enabled record count changed")
    return manifest, records


def _active_model_resource(records: dict[str, dict[str, Any]], logical_name: str) -> str | None:
    record = records[logical_name]
    if not record.get("enabled"):
        return None
    model_units = [
        model for model in record.get("model_resources", []) if model.get("role") == "ModelUnit"
    ]
    if not model_units:
        return None
    return str(model_units[0]["resource_name"])


def _hair_model_selection(
    record: dict[str, Any],
    *,
    model_key: str,
    logical_name: str,
    bangs_side: bool,
    for_hat: bool = False,
) -> HairModelSelection | None:
    """Resolve native Hair primary/hat/flip roles to one exact prepared model.

    ``FUN_7101d6ca20`` stores CharInfoEx face-flag bit 1 and the Hair/HairFront
    consumers query the Parts provider only when that bit is set.  A checked
    flipped FMDB is selected when present.  ``IsFlippable`` records without a
    flipped FMDB use the provider's horizontal-reflection path instead.
    """

    if not record.get("enabled"):
        return None
    models = record.get("model_resources", [])
    if not isinstance(models, list):
        raise ValueError(f"{logical_name} model_resources must be a list")
    by_role: dict[str, dict[str, Any]] = {}
    for model in models:
        role = str(model.get("role"))
        if role in by_role:
            raise ValueError(f"{logical_name} contains duplicate {role} model roles")
        by_role[role] = model

    primary_role = "ModelUnitForHat" if for_hat else "ModelUnit"
    flipped_role = "FlippedModelUnitForHat" if for_hat else "FlippedModelUnit"
    primary = by_role.get(primary_role)
    if primary is None:
        raise ValueError(f"{logical_name} has no checked {primary_role}")
    is_flippable = bool(record.get("resource_flags", {}).get("IsFlippable"))
    flip_requested = bool(bangs_side)
    explicit = is_flippable and flip_requested and flipped_role in by_role
    selected = by_role[flipped_role] if explicit else primary
    role = flipped_role if explicit else primary_role
    resource_name = str(selected.get("resource_name"))
    fmdb = str(selected.get("fmdb"))
    model_name = Path(fmdb).stem
    if not resource_name or not model_name:
        raise ValueError(f"{logical_name}/{role} has an incomplete checked FMDB record")

    catalog_path = MODEL_CACHE / resource_name / "bfres.json"
    if not catalog_path.is_file():
        raise FileNotFoundError(f"missing prepared BFRES metadata: {catalog_path}")
    catalog = _cached_load_json(catalog_path)
    matches = [
        index
        for index, model in enumerate(catalog.get("Models", []))
        if model.get("Name") == model_name
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{logical_name}/{role} FMDB basename must identify exactly one BFRES model: "
            f"{resource_name}/{model_name}"
        )
    obj_path = MODEL_CACHE / resource_name / f"{model_name}.obj"
    if not obj_path.is_file():
        raise FileNotFoundError(f"missing prepared BFRES model export: {obj_path}")
    return HairModelSelection(
        model_key=model_key,
        logical_name=logical_name,
        resource_name=resource_name,
        role=role,
        fmdb=fmdb,
        model_name=model_name,
        model_index=matches[0],
        obj_path=obj_path,
        for_hat=for_hat,
        flip_requested=flip_requested,
        is_flippable=is_flippable,
        explicit_flipped_model=explicit,
        mirror_horizontal=is_flippable and flip_requested and not explicit,
    )


def _active_hair_model_selections(
    records: dict[str, dict[str, Any]],
    char_info: dict[str, Any],
    *,
    for_hat: bool = False,
) -> tuple[HairModelSelection, ...]:
    """Return exact active Hair/HairFront model roles from effective CharInfo."""

    bangs_side = bool(char_info["face_flags"]["bangs_side"])
    selected: list[HairModelSelection] = []
    for model_key, logical_name in (("hair", "hair"), ("hair_front", "hair_front")):
        selection = _hair_model_selection(
            records[logical_name],
            model_key=model_key,
            logical_name=logical_name,
            bangs_side=bangs_side,
            for_hat=for_hat,
        )
        if selection is not None:
            selected.append(selection)
    if not selected:
        hair_record = records["hair"]
        if (
            hair_record.get("resolved")
            and hair_record.get("is_nothing")
            and hair_record.get("record") == "HairNothing"
            and not hair_record.get("enabled")
            and not records["hair_front"].get("enabled")
        ):
            return ()
        raise ValueError("the active ShareMii does not resolve a main hair model or HairNothing")
    if selected[0].model_key != "hair":
        raise ValueError("the active ShareMii does not resolve a main hair model")
    return tuple(selected)


def _active_hair_model_resources(
    records: dict[str, dict[str, Any]],
) -> tuple[tuple[str, str], ...]:
    """Return the selected main hair and any source-enabled front attachment."""

    selected: list[tuple[str, str]] = []
    for model_key, logical_name in (("hair", "hair"), ("hair_front", "hair_front")):
        resource = _active_model_resource(records, logical_name)
        if resource is not None:
            selected.append((model_key, resource))
    if not selected:
        hair_record = records["hair"]
        if (
            hair_record.get("resolved")
            and hair_record.get("is_nothing")
            and hair_record.get("record") == "HairNothing"
            and not hair_record.get("enabled")
            and not records["hair_front"].get("enabled")
        ):
            return ()
        raise ValueError("the active ShareMii does not resolve a main hair model or HairNothing")
    if selected[0][0] != "hair":
        raise ValueError("the active ShareMii does not resolve a main hair model")
    return tuple(selected)


@lru_cache(maxsize=None)
def _prepared_bfres_model(resource_name: str, model_index: int = 0) -> dict[str, Any]:
    """Load the exact prepared BFRES metadata for one selected model resource."""

    path = MODEL_CACHE / resource_name / "bfres.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing prepared BFRES metadata: {path}")
    document = _cached_load_json(path)
    models = document.get("Models", [])
    if model_index < 0 or model_index >= len(models):
        raise ValueError(f"prepared BFRES model index is unavailable: {resource_name}/{model_index}")
    model = models[model_index]
    if model_index == 0 and model.get("Name") != resource_name:
        raise ValueError(
            f"prepared BFRES must contain exactly one primary {resource_name} model"
        )
    return model


@lru_cache(maxsize=None)
def _prepared_head_attachment_bindings(
    resource_name: str,
) -> tuple[BoneBindTransform, ...]:
    """Resolve all selected-Head attachment bones in one cached hierarchy pass."""

    model = _prepared_bfres_model(resource_name)
    bindings = bone_bind_transforms(model, HEAD_ATTACHMENT_BONE_NAMES)
    frozen: list[BoneBindTransform] = []
    for name in HEAD_ATTACHMENT_BONE_NAMES:
        binding = bindings[name]
        matrix = binding.matrix.copy()
        matrix.setflags(write=False)
        frozen.append(
            BoneBindTransform(
                matrix=matrix,
                bone_index=binding.bone_index,
                bone_name=binding.bone_name,
                bone_chain=binding.bone_chain,
            )
        )
    return tuple(frozen)


def _prepared_head_attachment_binding(
    resource_name: str, bone_name: str
) -> BoneBindTransform:
    """Return one immutable selected-Head attachment record by exact bone name."""

    if bone_name not in HEAD_ATTACHMENT_BONE_NAMES:
        raise ValueError(f"unsupported Head attachment bone: {bone_name}")
    matches = [
        binding
        for binding in _prepared_head_attachment_bindings(resource_name)
        if binding.bone_name == bone_name
    ]
    if len(matches) != 1:
        raise ValueError(f"{resource_name} must contain exactly one {bone_name} bone")
    return matches[0]


def _prepared_head_attachment_report(resource_name: str) -> dict[str, Any]:
    """Report the exact cached selected-Head attachment hierarchy and matrices."""

    metadata_path = MODEL_CACHE / resource_name / "bfres.json"
    return {
        "resource": resource_name,
        "prepared_bfres": {
            "path": _logical_path(metadata_path),
            "byte_length": metadata_path.stat().st_size,
            "sha256": _sha256(metadata_path),
        },
        "resolver": "renderer.model_pose.bone_bind_transforms",
        "source": {
            "function": "FUN_7101d7e7e0",
            "symbol_manifest": "manifests/mii_rendering_symbols.csv",
            "decomp_source": (
                "src/functions/internal/batch_04/7101d00000/2466_functions.inc"
            ),
            "existing_canonical_name": "create_mii_generated_face_render_target_pair",
            "proposed_name": "assemble_mii_face_parts_render_model",
            "function_start_line": 66508,
            "decomp_line_span": [67100, 67275],
            "caller": {"function": "FUN_7101d7a710", "decomp_line": 63948},
            "role": (
                "selected Faceline Head/set_hair,set_beard,set_nose,set_ear "
                "lookup and parent-chain accumulation"
            ),
        },
        "bones": {
            binding.bone_name: {
                "bone_index": binding.bone_index,
                "bone_chain": list(binding.bone_chain),
                "bind_world_matrix": binding.matrix.tolist(),
                "bind_world_translation": binding.matrix[:3, 3].tolist(),
            }
            for binding in _prepared_head_attachment_bindings(resource_name)
        },
    }


def _prepared_head_named_texcoord_report(resource_name: str) -> dict[str, Any]:
    """Report the selected Head's exact named-UV sidecar and material routing."""

    sidecar_path = MODEL_CACHE / resource_name / f"{resource_name}.texcoords.json"
    if not sidecar_path.is_file():
        raise FileNotFoundError(f"missing prepared Head named-UV sidecar: {sidecar_path}")
    return {
        "resource": resource_name,
        "sidecar": {
            "path": _logical_path(sidecar_path),
            "byte_length": sidecar_path.stat().st_size,
            "sha256": _sha256(sidecar_path),
        },
        "texcoord_bindings": {
            "texture": "_u0",
            "normal": "_u2",
        },
        "scope": (
            "Head816 generated faceline _a0 uses the folded/mirrored _u0 stream; "
            "the authored Head normal-height map remains on _u2"
        ),
    }


def _prepared_shape(
    resource_name: str, shape_name: str, model_index: int = 0
) -> dict[str, Any]:
    matches = [
        shape
        for shape in _prepared_bfres_model(resource_name, model_index).get("Shapes", [])
        if shape.get("Name") == shape_name
    ]
    if len(matches) != 1:
        raise ValueError(f"{resource_name} must contain exactly one {shape_name} shape")
    return matches[0]


def _prepared_rigid_shape_binding(
    resource_name: str, shape_name: str, model_index: int = 0
) -> Any:
    catalog_path = MODEL_CACHE / resource_name / "bfres.json"
    if not catalog_path.is_file():
        raise FileNotFoundError(f"missing prepared BFRES metadata: {catalog_path}")
    return rigid_shape_bind_transform(catalog_path, shape_name, model_index)


def _prepared_rigid_shape_report(
    resource_name: str, shape_name: str, model_index: int = 0
) -> dict[str, Any]:
    catalog_path = MODEL_CACHE / resource_name / "bfres.json"
    binding = _prepared_rigid_shape_binding(resource_name, shape_name, model_index)
    return {
        "resource": resource_name,
        "model_index": model_index,
        "shape": shape_name,
        "vertex_skin_count": 0,
        "bone_index": binding.bone_index,
        "bone_name": binding.bone_name,
        "bone_chain": list(binding.bone_chain),
        "bind_world_matrix": binding.matrix.tolist(),
        "bind_world_translation": binding.matrix[:3, 3].tolist(),
        "prepared_bfres": {
            "path": _logical_path(catalog_path),
            "byte_length": catalog_path.stat().st_size,
            "sha256": _sha256(catalog_path),
        },
    }


def _prepared_post_pose_shape_transform(
    resource_name: str, shape_name: str, model_index: int = 0
) -> np.ndarray:
    """Return only the transform still required after ``pose_model``.

    Smooth/cloth-skinned vertices are already evaluated through their BFRES
    palette and inverse-bind matrices by ``pose_model``. Rigid shapes remain
    bone-local and therefore require their complete bind-world matrix here.
    """

    shape = _prepared_shape(resource_name, shape_name, model_index)
    skin_count = int(shape.get("VertexSkinCount", -1))
    if skin_count < 0:
        raise ValueError(f"{resource_name}/{shape_name} has invalid VertexSkinCount")
    if skin_count == 0:
        return _prepared_rigid_shape_binding(resource_name, shape_name, model_index).matrix
    return identity()


def _prepared_skinned_shape_report(
    resource_name: str, shape_name: str, model_index: int = 0
) -> dict[str, Any]:
    catalog_path = MODEL_CACHE / resource_name / "bfres.json"
    contract = skinned_shape_bind_contract(catalog_path, shape_name, model_index)
    return {
        "resource": resource_name,
        "model_index": model_index,
        "shape": shape_name,
        "vertex_skin_count": contract.vertex_skin_count,
        "vertex_offset": contract.vertex_offset,
        "vertex_count": contract.vertex_count,
        "shape_bone_index": contract.shape_bone_index,
        "shape_bone_name": contract.shape_bone_name,
        "matrix_to_bone_list": list(contract.matrix_to_bone_list),
        "palette_bone_names": list(contract.palette_bone_names),
        "used_palette_indices": list(contract.used_palette_indices),
        "smooth_matrix_count": contract.smooth_matrix_count,
        "rigid_palette_indices": list(contract.rigid_palette_indices),
        "inverse_bind_identity_max_error": contract.bind_identity_max_error,
        "source_weight_sum_range": [
            contract.minimum_weight_sum,
            contract.maximum_weight_sum,
        ],
        "execution": (
            "pose_model BFRES MatrixToBoneList rigid-palette deformation without weights "
            "or inverse bind; no separate shape bind matrix is applied after the posed mesh"
            if contract.vertex_skin_count == 1 and contract.rigid_palette_indices
            else "pose_model BFRES MatrixToBoneList + inverse-bind deformation; no separate "
            "rigid shape bind matrix is applied after the posed mesh"
        ),
        "prepared_bfres": {
            "path": _logical_path(catalog_path),
            "byte_length": catalog_path.stat().st_size,
            "sha256": _sha256(catalog_path),
        },
    }


def _resolved_parts_report(records: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for logical_name, record in records.items():
        result[logical_name] = {
            "selector_field": record.get("selector_field"),
            "selector": record.get("selector"),
            "record": record.get("record"),
            "enabled": bool(record.get("enabled")),
            "model_resources": [
                model["resource_name"] for model in record.get("model_resources", [])
            ],
            "texture": record.get("texture_name"),
        }
    return result


def _faceline_position_map_index(records: dict[str, dict[str, Any]]) -> int:
    """Resolve MiiFacelineNN_Pos from the selected Parts record, not its PartsIndex."""

    record = records["faceline"]
    if not record.get("resolved") or not record.get("enabled"):
        raise ValueError("the active faceline Parts record is not renderable")
    match = re.fullmatch(r"Faceline(\d{2})", str(record.get("record")))
    if match is None:
        raise ValueError("faceline Parts FileName does not identify MiiFacelineNN_Pos")
    position_index = int(match.group(1))
    if not 0 <= position_index <= 15:
        raise ValueError("faceline position-map index is outside the recovered 0..15 set")
    return position_index


def _mask_texture(source: np.ndarray, color: tuple[float, float, float]) -> np.ndarray:
    luminance = np.max(source[..., :3], axis=2) * source[..., 3]
    result = np.empty_like(source)
    result[..., :3] = np.asarray(color, dtype=np.float64)
    result[..., 3] = luminance
    return result


@lru_cache(maxsize=None)
def _material_texture(name: str) -> tuple[np.ndarray, ...]:
    """Load every exact BNTX mip level for one selected material texture."""
    if _configured_material_texture_cache_roots is None:
        raise RuntimeError("ShareMii material-texture caches were not configured")
    candidates = [root / name for root in _configured_material_texture_cache_roots]
    matches = [path for path in candidates if path.is_dir()]
    if len(matches) != 1:
        raise FileNotFoundError(
            f"selected texture must resolve in exactly one checked mip cache: {name}; "
            f"matches={matches}"
        )
    directory = matches[0]
    paths = sorted(directory.glob("mip_*.png"))
    if not paths:
        raise FileNotFoundError(f"selected texture mip cache is missing: {directory}")
    levels: list[np.ndarray] = []
    for path in paths:
        with Image.open(path) as image:
            levels.append(texture_from_image(image))
    return tuple(levels)


def _optional_material_texture(name: str) -> tuple[np.ndarray, ...] | None:
    if _configured_material_texture_cache_roots is None:
        raise RuntimeError("ShareMii material-texture caches were not configured")
    return (
        _material_texture(name)
        if any((root / name).is_dir() for root in _configured_material_texture_cache_roots)
        else None
    )


def _material_texture_is_available(name: str) -> bool:
    if _configured_material_texture_cache_roots is None:
        raise RuntimeError("ShareMii material-texture caches were not configured")
    return any((root / name).is_dir() for root in _configured_material_texture_cache_roots)


def _obj_source_identity(path: Path) -> tuple[str, str, str | None]:
    """Authenticate exactly the two files consumed by ``load_obj``."""

    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise FileNotFoundError(f"prepared BFRES model export is not a file: {resolved}")
    obj_digest = _sha256(resolved)
    sidecar = resolved.with_name(resolved.stem + ".texcoords.json")
    sidecar_digest = _sha256(sidecar) if sidecar.is_file() else None
    return str(resolved), obj_digest, sidecar_digest


def _clone_obj_mesh(mesh: ObjMesh) -> ObjMesh:
    """Keep mutable request ownership separate from the persistent cache."""

    return ObjMesh(
        positions=mesh.positions.copy(),
        texcoords=mesh.texcoords.copy(),
        normals=mesh.normals.copy(),
        triangles=list(mesh.triangles),
        texcoord_channels={
            name: values.copy() for name, values in mesh.texcoord_channels.items()
        },
    )


def _freeze_obj_mesh(mesh: ObjMesh) -> ObjMesh:
    for values in (mesh.positions, mesh.texcoords, mesh.normals):
        values.setflags(write=False)
    for values in mesh.texcoord_channels.values():
        values.setflags(write=False)
    return mesh


def _load_runtime_obj(path: Path) -> ObjMesh:
    """Load a source-sealed OBJ once and return a request-owned clone.

    A cache hit still authenticates the current OBJ and optional named-UV
    sidecar on every request.  Misses compare the complete identity before and
    after parsing, so a mid-parse mutation is never installed or returned.
    """

    for _ in range(3):
        before = _obj_source_identity(path)
        cache_key = os.path.normcase(before[0])
        with _runtime_obj_mesh_lock:
            cached = _runtime_obj_meshes.get(cache_key)
            if cached is not None and cached.source_identity == before:
                cloned = _clone_obj_mesh(cached.mesh)
                after = _obj_source_identity(path)
                if after == before:
                    _runtime_obj_meshes.move_to_end(cache_key)
                    return cloned
                continue
        parsed = load_obj(Path(before[0]))
        after = _obj_source_identity(path)
        if after != before:
            continue
        frozen = _freeze_obj_mesh(parsed)
        entry = _RuntimeObjMeshEntry(before, frozen)
        with _runtime_obj_mesh_lock:
            _runtime_obj_meshes[cache_key] = entry
            _runtime_obj_meshes.move_to_end(cache_key)
            while len(_runtime_obj_meshes) > MAX_RUNTIME_OBJ_MESHES:
                _runtime_obj_meshes.popitem(last=False)
        return _clone_obj_mesh(frozen)
    raise OSError(f"prepared BFRES model changed repeatedly while parsing: {path}")


def _load_models(
    records: dict[str, dict[str, Any]],
    hair_selections: tuple[HairModelSelection, ...] = (),
    legacy_headwear_selection: LegacyHeadwearSelection | None = None,
) -> dict[str, ObjMesh]:
    paths = {
        "body": MODEL_CACHE / "BodyBaseDefault" / "BodyBaseDefault.obj",
        # These two belong to the separately cataloged external-outfit view;
        # the ShareMii payload itself has no outfit selector.
        "reference_top": (
            MODEL_CACHE / "ClothTopsTshirtLong" / "ClothTopsTshirtLong.obj"
        ),
        "reference_shoes": (
            MODEL_CACHE / "ClothShoesStandard" / "ClothShoesStandard.obj"
        ),
        "presentation_bottoms": (
            MODEL_CACHE / "ClothBottomsPantsLong" / "ClothBottomsPantsLong.obj"
        ),
    }
    for key, logical_name in (
        ("head", "faceline"),
        ("nose", "nose"),
        ("ear", "ear"),
        ("beard", "beard"),
        ("glass", "glass_primary"),
    ):
        resource = _active_model_resource(records, logical_name)
        if resource is not None:
            paths[key] = MODEL_CACHE / resource / f"{resource}.obj"
    if hair_selections:
        for selection in hair_selections:
            paths[selection.model_key] = selection.obj_path
    else:
        for key, logical_name in (("hair", "hair"), ("hair_front", "hair_front")):
            resource = _active_model_resource(records, logical_name)
            if resource is not None:
                paths[key] = MODEL_CACHE / resource / f"{resource}.obj"
    if legacy_headwear_selection is not None:
        paths["legacy_headwear"] = legacy_headwear_selection.obj_path
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing prepared BFRES model export(s): " + ", ".join(missing))
    return {name: _load_runtime_obj(path) for name, path in paths.items()}


def _srgb_to_linear(value: np.ndarray) -> np.ndarray:
    return np.where(
        value <= 0.04045,
        value / 12.92,
        np.power((value + 0.055) / 1.055, 2.4),
    )


def _glass_lens_runtime_state(
    char_info: dict[str, Any], colors: dict[str, Any]
) -> dict[str, Any]:
    """Resolve title-correct lens visibility and exact local uniforms.

    FUN_7101d7daf0 first enables every glass material and then hides one: mode
    2 hides Trs, while modes 0/1 hide Opa. The active title parameter archive
    plus the constructor defaults recover the formerly missing mode-1 opacity
    and multiply-blend state.
    """

    mode = int(char_info["glass_lens_material_mode"])
    if mode not in (0, 1, 2):
        raise ValueError(f"glass_lens_material_mode must be 0, 1, or 2, got {mode}")
    active_translucent = mode != 2
    lens_color_index = 8 if mode == 0 else int(char_info["glass_lens_color"])
    try:
        color = tuple(float(value) for value in colors["common"][lens_color_index])
    except (IndexError, KeyError, TypeError) as error:
        raise ValueError(f"glass_lens_color index is unavailable: {lens_color_index}") from error
    if len(color) != 4:
        raise ValueError("glass lens common color must be RGBA")
    multiply_blend = bool(
        CHECKED_MII_SYSTEM_PARAMETERS["IsGlassLensMultiplyBlend"]
    )
    opacity = (
        0.0
        if mode == 0
        else 1.0
        if mode == 2
        else float(
            CHECKED_MII_SYSTEM_PARAMETERS[
                "GlassLensOpacityMulti" if multiply_blend else "GlassLensOpacity"
            ]
        )
    )
    local_state = gameuber_cpu.glass_lens_runtime_state(
        color,
        opacity,
        is_multiply_blend=multiply_blend,
    )
    effective_alpha = float(local_state.effective_alpha)
    # mt_LensTrs uses src=one, dst=one-minus-src-alpha. The CPU framebuffer
    # therefore receives the shader's premultiplied source representation.
    premultiplied_color = (
        *(float(channel) * effective_alpha for channel in color[:3]),
        color[3],
    )
    return {
        "material_mode": mode,
        "material_mode_field": "glass_lens_material_mode",
        "lens_color_field": "glass_lens_color",
        "lens_color_index": lens_color_index,
        "active_lens": "Trs__mt_LensTrs" if active_translucent else "Opa__mt_LensOpa",
        "active_material": "mt_LensTrs" if active_translucent else "mt_LensOpa",
        "hidden_lens": "Opa__mt_LensOpa" if active_translucent else "Trs__mt_LensTrs",
        "const_color_albedo": color,
        "portable_premultiplied_color": premultiplied_color,
        "raw_opacity": opacity,
        "const_single_alpha": effective_alpha,
        "glass_decay_color": tuple(float(value) for value in local_state.glass_decay_rgba),
        "blend": active_translucent,
        "premultiplied_rgb_blend": active_translucent,
        "depth_write": not active_translucent,
        "alpha_test": False,
        "system_parameter_independent": mode != 1,
        "system_parameters": {
            "IsGlassLensMultiplyBlend": multiply_blend,
            "GlassLensOpacity": CHECKED_MII_SYSTEM_PARAMETERS["GlassLensOpacity"],
            "GlassLensOpacityMulti": CHECKED_MII_SYSTEM_PARAMETERS[
                "GlassLensOpacityMulti"
            ],
            "selected_opacity": opacity,
        },
    }


def _decoration_runtime_state(
    char_info: dict[str, Any], colors: dict[str, Any]
) -> dict[str, Any]:
    """Resolve FUN_7101d7e010/FUN_7101d7c4e0's main-hair band color."""

    primary_index = int(char_info["hair_color_primary"])
    stored_secondary_index = int(char_info["hair_color_secondary"])
    dual_color = bool(char_info["face_flags"]["back_dual_color"])
    selected_index = stored_secondary_index if dual_color else primary_index
    try:
        selected_srgb = np.asarray(colors["common"][selected_index], dtype=np.float64)
    except (IndexError, KeyError, TypeError) as error:
        raise ValueError(
            f"Decoration common-color index is unavailable: {selected_index}"
        ) from error
    if selected_srgb.shape != (4,) or not np.all(np.isfinite(selected_srgb)):
        raise ValueError("Decoration common color must be one finite RGBA vector")
    selected_linear = np.concatenate(
        (_srgb_to_linear(selected_srgb[:3]), selected_srgb[3:])
    )
    fallback = "none"
    if selected_index == primary_index:
        if np.all(selected_linear[:3] == 0.0):
            selected_linear = np.asarray(
                CHECKED_MII_SYSTEM_PARAMETERS["HairBandColorWhenBlack"],
                dtype=np.float64,
            )
            fallback = "HairBandColorWhenBlack"
        else:
            selected_linear = selected_linear.copy()
            selected_linear[:3] *= float(
                CHECKED_MII_SYSTEM_PARAMETERS["HairBandColorRate"]
            )
            fallback = "HairBandColorRate"
    local_base = gameuber_cpu.decoration480_492_local_base_linear(selected_linear)
    return {
        "primary_color_index": primary_index,
        "stored_secondary_color_index": stored_secondary_index,
        "back_dual_color": dual_color,
        "selected_color_index": selected_index,
        "fallback": fallback,
        "mii_constant_color0_linear": tuple(float(value) for value in local_base),
        "hair_band_color_rate": CHECKED_MII_SYSTEM_PARAMETERS["HairBandColorRate"],
        "hair_band_color_when_black": CHECKED_MII_SYSTEM_PARAMETERS[
            "HairBandColorWhenBlack"
        ],
    }


def _resolved_material_program(
    ledger_path: Path,
    resource: str,
    shape: str,
    material: str,
) -> int | None:
    ledger = _cached_load_json(ledger_path)
    matches = [
        record for record in ledger.get("programs", [])
        if (
            record.get("resource") == resource
            and record.get("shape") == shape
            and record.get("material") == material
        )
    ]
    if len(matches) != 1:
        return None
    record = matches[0]
    program = record.get("resolved_program_index")
    return int(program) if record.get("selection_status") == "exact_unique" and program is not None else None


def _single_gameall_material_record(
    document: dict[str, Any],
    *,
    resource: str,
    model: str,
    shape: str,
    material: str,
    label: str,
) -> dict[str, Any]:
    matches = [
        record
        for record in document.get("programs", [])
        if (
            isinstance(record, dict)
            and record.get("resource") == resource
            and record.get("model") == model
            and record.get("shape") == shape
            and record.get("material") == material
        )
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{label} must contain exactly one {resource}/{model}/{shape}/{material} row"
        )
    return matches[0]


def _validate_active_gameall_material_claim(
    record: dict[str, Any],
    *,
    family: str,
    expected_program: int,
    label: str,
) -> tuple[str, int | None, tuple[int, ...]]:
    """Validate what the selected target ledger does and does not establish."""

    if record.get("family") != family and record.get("key") != family:
        raise ValueError(f"{label} does not identify the expected {family} material")
    status = record.get("selection_status")
    program = record.get("resolved_program_index")
    compatible_raw = record.get("compatible_program_indices")
    if (
        not isinstance(status, str)
        or not isinstance(compatible_raw, list)
        or not compatible_raw
        or any(type(value) is not int for value in compatible_raw)
        or len(set(compatible_raw)) != len(compatible_raw)
    ):
        raise ValueError(f"{label} has an invalid selection claim")
    compatible = tuple(int(value) for value in compatible_raw)
    if status == "exact_unique":
        if type(program) is not int or program != expected_program or compatible != (
            expected_program,
        ):
            raise ValueError(f"{label} exact selection differs from GameAll{expected_program}")
        return status, program, compatible
    if (
        not status.startswith("unresolved_")
        or program is not None
        or expected_program not in compatible
    ):
        raise ValueError(
            f"{label} neither resolves nor retains compatible GameAll{expected_program}"
        )
    return status, None, compatible


def _validate_exact_generalized_gameall_material_record(
    record: dict[str, Any],
    *,
    family: str,
    expected_program: int,
    label: str,
) -> tuple[str, str]:
    """Validate the exact generalized program row used by a production draw."""

    try:
        expected_vertex, expected_fragment = GLASS_GAMEALL_PROGRAM_STAGE_HASHES[
            (family, expected_program)
        ]
    except KeyError as error:
        raise ValueError(f"{label} has no audited Glass stage family") from error
    vertex = str(
        record.get("stages", {})
        .get("vertex", {})
        .get("instructions", {})
        .get("sha256")
    )
    fragment = str(
        record.get("stages", {})
        .get("fragment", {})
        .get("instructions", {})
        .get("sha256")
    )
    if (
        record.get("family") != family
        or record.get("selection_status") != "exact_unique"
        or record.get("resolved_program_index") != expected_program
        or record.get("compatible_program_indices") != [expected_program]
        or vertex != expected_vertex
        or fragment != expected_fragment
    ):
        raise ValueError(
            f"{label} differs from the audited {family}/GameAll{expected_program} row"
        )
    return vertex, fragment


def _validate_generalized_gameall_stage_files(
    document: dict[str, Any], record: dict[str, Any], *, label: str
) -> int:
    """Hash-check the exact cached binaries named by one generalized row."""

    stage_cache = document.get("stage_cache")
    if not isinstance(stage_cache, dict):
        raise ValueError(f"{label} has no checked stage cache")
    root = _resolve_repository_path(str(stage_cache.get("root")))
    expected_root = (REPOSITORY / "renderer" / "assets" / "classic_bridge_gameuber_stages").resolve()
    files = stage_cache.get("files")
    if (
        root != expected_root
        or not isinstance(files, list)
        or len(files) != stage_cache.get("file_count")
    ):
        raise ValueError(f"{label} stage-cache inventory changed")
    by_name: dict[str, list[dict[str, Any]]] = {}
    for file_record in files:
        if isinstance(file_record, dict) and isinstance(file_record.get("path"), str):
            by_name.setdefault(Path(file_record["path"]).name, []).append(file_record)

    validated = 0
    stages = record.get("stages")
    if not isinstance(stages, dict):
        raise ValueError(f"{label} has no selected stage records")
    for stage_name in ("vertex", "fragment"):
        stage = stages.get(stage_name)
        exported = stage.get("exported_files") if isinstance(stage, dict) else None
        if not isinstance(stage, dict) or not isinstance(exported, dict):
            raise ValueError(f"{label} lacks {stage_name} exported-stage evidence")
        for stream_name in (
            "control_stream",
            "container_stream",
            "maxwell",
            "instructions",
        ):
            exported_name = exported.get(stream_name)
            inline_record = stage.get(stream_name)
            matches = by_name.get(str(exported_name), [])
            if (
                not isinstance(exported_name, str)
                or not isinstance(inline_record, dict)
                or len(matches) != 1
                or matches[0].get("byte_length") != inline_record.get("byte_length")
                or matches[0].get("sha256") != inline_record.get("sha256")
            ):
                raise ValueError(
                    f"{label} {stage_name}.{stream_name} cache identity changed"
                )
            checked_path = _validate_file_record(
                matches[0], f"{label}.{stage_name}.{stream_name}"
            )
            if checked_path.parent != root:
                raise ValueError(f"{label} stage file escaped its checked cache root")
            validated += 1
    if validated != 8:
        raise ValueError(f"{label} did not validate exactly eight selected stage files")
    return validated


def _select_glass_gameall_material(
    active_program_ledger: Path,
    *,
    resource: str,
    model: str,
    family: str,
    shape: str,
    material: str,
    expected_program: int,
) -> GameAllMaterialSelection:
    """Cross-check one active Glass draw against the hash-bound general ledger.

    Older target fixtures intentionally leave inherited shader options
    unresolved.  Their compatible sets are retained as primary provenance, but
    never silently promoted to an exact identity: the submitted program comes
    only from the exact resource/model/material row in the generalized ledger
    referenced and hash-checked by the classic resource bundle.
    """

    active_program_ledger = active_program_ledger.resolve()
    active_document = _cached_load_json(active_program_ledger)
    active_record = _single_gameall_material_record(
        active_document,
        resource=resource,
        model=model,
        shape=shape,
        material=material,
        label=f"active Glass ledger {active_program_ledger.name}",
    )
    active_status, active_program, active_compatible = (
        _validate_active_gameall_material_claim(
            active_record,
            family=family,
            expected_program=expected_program,
            label=f"active Glass ledger {active_program_ledger.name}",
        )
    )

    bundle = _cached_load_json(CLASSIC_BRIDGE_RESOURCE_BUNDLES)
    evidence = bundle.get("runtime_evidence")
    generalized_record = evidence.get("gameuber_programs") if isinstance(evidence, dict) else None
    if bundle.get("schema_version") != 1 or not isinstance(generalized_record, dict):
        raise ValueError("classic resource bundle lacks generalized GameUber evidence")
    generalized_path = _validate_file_record(
        generalized_record, "glass.generalized_gameuber_programs"
    )
    if generalized_path != CLASSIC_BRIDGE_GAMEUBER_PROGRAMS.resolve():
        raise ValueError("Glass generalized GameUber evidence path changed")
    generalized_document = _cached_load_json(generalized_path)
    exact_record = _single_gameall_material_record(
        generalized_document,
        resource=resource,
        model=model,
        shape=shape,
        material=material,
        label="generalized Glass GameUber ledger",
    )
    vertex_hash, fragment_hash = _validate_exact_generalized_gameall_material_record(
        exact_record,
        family=family,
        expected_program=expected_program,
        label="generalized Glass GameUber ledger",
    )
    nested_count = _validate_generalized_gameall_stage_files(
        generalized_document,
        exact_record,
        label=f"glass.{resource}.{family}.generalized_gameuber",
    )
    if active_program_ledger != generalized_path:
        nested_count += _validate_nested_file_records(
            active_record, f"glass.{resource}.{family}.active_gameuber"
        )

    if active_program_ledger == generalized_path:
        resolution_basis = "hash-bound generalized exact resource/model/material row"
    elif active_status == "exact_unique":
        resolution_basis = (
            "target-selected exact row agrees with the hash-bound generalized "
            "resource/model/material row"
        )
    else:
        resolution_basis = (
            "target ledger remains explicitly unresolved; its compatible set is not promoted. "
            "The hash-bound generalized exact resource/model/material row supplies the submitted "
            f"GameAll{expected_program} identity"
        )
    return GameAllMaterialSelection(
        family=family,
        gameall_program=expected_program,
        resource_name=resource,
        model_name=model,
        shape_name=shape,
        material_name=material,
        evidence_path=generalized_path,
        evidence_sha256=_sha256(generalized_path),
        vertex_instructions_sha256=vertex_hash,
        fragment_instructions_sha256=fragment_hash,
        active_program_ledger=active_program_ledger,
        active_program_ledger_sha256=_sha256(active_program_ledger),
        active_selection_status=active_status,
        active_resolved_program=active_program,
        active_compatible_programs=active_compatible,
        resolution_basis=resolution_basis,
        validated_nested_file_records=nested_count,
    )


def _resolve_glass_gameall_materials(
    char_info: dict[str, Any],
    active_records: dict[str, dict[str, Any]],
    active_program_ledger: Path,
) -> tuple[GameAllMaterialSelection | None, GameAllMaterialSelection | None]:
    resource = _active_model_resource(active_records, "glass_primary")
    if resource is None:
        return None, None
    frame = _select_glass_gameall_material(
        active_program_ledger,
        resource=resource,
        model=resource,
        family="glass_frame",
        shape="Flame__mt_Body",
        material="mt_Body",
        expected_program=360,
    )
    mode = int(char_info["glass_lens_material_mode"])
    if mode not in (0, 1, 2):
        raise ValueError(f"glass_lens_material_mode must be 0, 1, or 2, got {mode}")
    translucent = mode != 2
    lens = _select_glass_gameall_material(
        active_program_ledger,
        resource=resource,
        model=resource,
        family=("glass_lens_translucent" if translucent else "glass_lens_opaque"),
        shape=("Trs__mt_LensTrs" if translucent else "Opa__mt_LensOpa"),
        material=("mt_LensTrs" if translucent else "mt_LensOpa"),
        expected_program=(60 if translucent else 768),
    )
    return frame, lens


def _validate_exact_body_gameall_record(
    record: dict[str, Any],
    *,
    group_name: str,
    material_name: str,
    vertex_skin_count: int,
    expected_program: int,
    label: str,
) -> tuple[str, str, str]:
    identity = record.get("identity")
    selection = record.get("selection")
    if not isinstance(identity, dict) or not isinstance(selection, dict):
        raise ValueError(f"{label} lacks identity/selection records")
    vertex_binary = selection.get("vertex_binary")
    pixel_binary = selection.get("pixel_binary")
    vertex_instructions = (
        vertex_binary.get("instruction_code") if isinstance(vertex_binary, dict) else None
    )
    fragment_instructions = (
        pixel_binary.get("instruction_code") if isinstance(pixel_binary, dict) else None
    )
    expected_vertex = BODY_GAMEALL_VERTEX_INSTRUCTION_SHA256_BY_PROGRAM[expected_program]
    expected_vertex_length = BODY_GAMEALL_VERTEX_INSTRUCTION_LENGTH_BY_PROGRAM[
        expected_program
    ]
    key = record.get("key")
    if (
        not isinstance(key, str)
        or not key.startswith("body_")
        or identity.get("resource") != "BodyBaseDefault"
        or identity.get("model") != "BodyBaseDefault"
        or identity.get("shape") != group_name
        or identity.get("material") != material_name
        or identity.get("vertex_skin_count") != vertex_skin_count
        or selection.get("shader_archive") != "GameUber"
        or selection.get("shading_model") != "GameAll"
        or selection.get("program_index") != expected_program
        or selection.get("compatible_program_indices") != [expected_program]
        or selection.get("system_options", {}).get("gsys_weight")
        != str(vertex_skin_count)
        or vertex_instructions
        != {"byte_length": expected_vertex_length, "sha256": expected_vertex}
        or fragment_instructions
        != {
            "byte_length": 8832,
            "sha256": BODY_GAMEALL_FRAGMENT_INSTRUCTION_SHA256,
        }
    ):
        raise ValueError(
            f"{label} differs from exact Body{expected_program} group/stage evidence"
        )
    return key, expected_vertex, BODY_GAMEALL_FRAGMENT_INSTRUCTION_SHA256


def _validate_body_instruction_file(
    binary: dict[str, Any], *, label: str
) -> Path:
    instruction = binary.get("instruction_code")
    filename = binary.get("instruction_file")
    if (
        binary.get("instruction_stream_offset") != 128
        or not isinstance(instruction, dict)
        or not isinstance(filename, str)
        or Path(filename).name != filename
    ):
        raise ValueError(f"{label} instruction-file record changed")
    path = (REPOSITORY / "tools" / "_shader_work" / filename).resolve()
    root = (REPOSITORY / "tools" / "_shader_work").resolve()
    if path.parent != root:
        raise ValueError(f"{label} instruction file escaped its checked root")
    validated = _cached_matches_file(
        path,
        byte_length=int(instruction["byte_length"]),
        sha256_digest=str(instruction["sha256"]),
    )
    if validated is None:
        raise ValueError(f"{label} instruction file changed: {filename}")
    return validated


def _resolve_body_gameall_materials() -> dict[str, BodyGameAllSelection]:
    presentation = _cached_load_json(PRESENTATION_OUTFIT)
    source_record = presentation.get("sources", {}).get("body_programs")
    if presentation.get("schema_version") != 1 or not isinstance(source_record, dict):
        raise ValueError("presentation outfit lacks the expanded Body program evidence")
    evidence_path = _validate_file_record(source_record, "presentation.body_programs")
    if evidence_path != GAMEUBER_ACTIVE_PROGRAMS.resolve():
        raise ValueError("presentation Body program evidence path changed")
    ledger = _cached_load_json(evidence_path)
    for source_key in (
        "body_material_state",
        "program_reflection",
        "gameuber_bfsha",
    ):
        record = ledger.get("source_artifacts", {}).get(source_key)
        if not isinstance(record, dict):
            raise ValueError(f"Body program ledger lacks {source_key} provenance")
        _validate_file_record(record, f"body_programs.source_artifacts.{source_key}")

    body_records = [
        record
        for record in ledger.get("programs", [])
        if isinstance(record, dict)
        and record.get("identity", {}).get("resource") == "BodyBaseDefault"
    ]
    by_group: dict[str, list[dict[str, Any]]] = {}
    for record in body_records:
        by_group.setdefault(str(record.get("identity", {}).get("shape")), []).append(record)
    if set(by_group) != set(BODY_GAMEALL_PROGRAM_BY_GROUP) or any(
        len(records) != 1 for records in by_group.values()
    ):
        raise ValueError("Body program ledger must contain exactly the 13 submitted groups")

    result: dict[str, BodyGameAllSelection] = {}
    for group_name, (material_name, skin_count, program) in (
        BODY_GAMEALL_PROGRAM_BY_GROUP.items()
    ):
        record = by_group[group_name][0]
        key, vertex_hash, fragment_hash = _validate_exact_body_gameall_record(
            record,
            group_name=group_name,
            material_name=material_name,
            vertex_skin_count=skin_count,
            expected_program=program,
            label=f"Body program ledger {group_name}",
        )
        selection = record["selection"]
        _validate_body_instruction_file(
            selection["vertex_binary"], label=f"Body program ledger {group_name}.vertex"
        )
        _validate_body_instruction_file(
            selection["pixel_binary"], label=f"Body program ledger {group_name}.fragment"
        )
        result[group_name] = BodyGameAllSelection(
            group_name=group_name,
            material_name=material_name,
            vertex_skin_count=skin_count,
            gameall_program=program,
            vertex_instructions_sha256=vertex_hash,
            fragment_instructions_sha256=fragment_hash,
            evidence_path=evidence_path,
            evidence_sha256=_sha256(evidence_path),
            reflection_key=key,
            validated_instruction_files=2,
        )
    return result


def _validate_exact_outfit_gameall_record(
    record: dict[str, Any], *, logical_slot: str, label: str
) -> OutfitGameAllSelection:
    expected = OUTFIT_GAMEALL_EXPECTATIONS[logical_slot]
    constraints = tuple(
        (str(item.get("option")), str(item.get("value")))
        for item in record.get("source_constraints", [])
        if isinstance(item, dict)
    )
    vertex = record.get("stages", {}).get("vertex", {}).get("instructions")
    fragment = record.get("stages", {}).get("fragment", {}).get("instructions")
    compiled_sampler_activity = record.get("compiled_sampler_activity")
    if (
        record.get("resource") != expected["resource"]
        or record.get("model") != expected["resource"]
        or record.get("shape") != expected["shape"]
        or record.get("material") != "mt_Body"
        or record.get("shader_archive") != "GameUber"
        or record.get("shading_model") != "GameAll"
        or record.get("resolver_candidate_program_index") != expected["raw"][0]
        or record.get("raw_compatible_program_indices") != expected["raw"]
        or constraints != tuple(expected["constraints"])
        or record.get("resolved_program_index") != expected["program"]
        or record.get("compatible_program_indices") != [expected["program"]]
        or record.get("selection_status") != "exact_unique_after_source_constraints"
        or not isinstance(compiled_sampler_activity, dict)
        or compiled_sampler_activity.get("title_shader_execution_key")
        != expected["title_shader_execution_key"]
        or compiled_sampler_activity.get("active_material_samplers")
        != expected["active_material_samplers"]
        or "_alp0" in compiled_sampler_activity.get("active_material_samplers", [])
        or compiled_sampler_activity.get("inactive_serialized_assignments")
        != expected["inactive_serialized_assignments"]
        or vertex
        != {"byte_length": expected["vertex_length"], "sha256": expected["vertex"]}
        or fragment
        != {
            "byte_length": expected["fragment_length"],
            "sha256": expected["fragment"],
        }
    ):
        raise ValueError(f"{label} exact compatible-set/stage evidence changed")
    return OutfitGameAllSelection(
        logical_slot=logical_slot,
        family=str(expected["family"]),
        resource_name=str(expected["resource"]),
        shape_name=str(expected["shape"]),
        gameall_program=int(expected["program"]),
        raw_compatible_programs=tuple(int(value) for value in expected["raw"]),
        source_constraints=tuple(expected["constraints"]),
        title_shader_execution_key=str(expected["title_shader_execution_key"]),
        active_material_samplers=tuple(expected["active_material_samplers"]),
        inactive_serialized_assignments=tuple(
            (
                str(item["shader_sampler"]),
                str(item["material_sampler"]),
                int(item["material_sampler_index"]),
                str(item["texture_ref"]),
            )
            for item in expected["inactive_serialized_assignments"]
        ),
        vertex_instructions_sha256=str(expected["vertex"]),
        fragment_instructions_sha256=str(expected["fragment"]),
        evidence_path=PRESENTATION_OUTFIT.resolve(),
        evidence_sha256=_sha256(PRESENTATION_OUTFIT),
    )


def _resolve_outfit_gameall_materials() -> dict[str, OutfitGameAllSelection]:
    presentation = _cached_load_json(PRESENTATION_OUTFIT)
    if presentation.get("schema_version") != 1:
        raise ValueError("presentation outfit schema changed")
    sources = presentation.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("presentation outfit lacks exact source records")
    for source_key in (
        "program_resolver",
        "material_state",
        "gameuber_shader_archive",
        "title_shader_execution",
    ):
        source_record = sources.get(source_key)
        if not isinstance(source_record, dict):
            raise ValueError(f"presentation outfit lacks {source_key} evidence")
        _validate_file_record(source_record, f"presentation.sources.{source_key}")
    slots = presentation.get("slots")
    if not isinstance(slots, list):
        raise ValueError("presentation outfit slot inventory changed")
    by_slot = {
        str(slot.get("logical_slot")): slot
        for slot in slots
        if isinstance(slot, dict)
    }
    if set(by_slot) != {"tops", "bottoms", "socks", "shoes"}:
        raise ValueError("presentation outfit must contain exactly four logical slots")
    result: dict[str, OutfitGameAllSelection] = {}
    for logical_slot in ("tops", "bottoms", "shoes"):
        program_record = by_slot[logical_slot].get("body_program")
        if not isinstance(program_record, dict):
            raise ValueError(f"presentation {logical_slot} lacks GameAll evidence")
        result[logical_slot] = _validate_exact_outfit_gameall_record(
            program_record,
            logical_slot=logical_slot,
            label=f"presentation {logical_slot}",
        )
    return result


def _reference_outfit_mip_chain_sha256(record: dict[str, Any]) -> str:
    """Hash one complete manifest record, including its ordered level ledger."""

    encoded = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_reference_outfit_texture_mip_inventory(
    *,
    repository: Path = REPOSITORY,
    ledger_path: Path = REFERENCE_OUTFIT_TEXTURE_MIPS,
    cache_root: Path = REFERENCE_TEXTURE_MIP_CACHE,
    trusted_ledger_record: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Authenticate the complete external-outfit source and decoded-mip ledger."""

    repository = repository.resolve()
    ledger_path = ledger_path.resolve()
    cache_root = cache_root.resolve()

    def resolve_path(value: str) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (repository / path).resolve()

    if trusted_ledger_record is None:
        presentation = _cached_load_json(PRESENTATION_OUTFIT)
        trusted_ledger_record = presentation.get("sources", {}).get("texture_mips")
    if not isinstance(trusted_ledger_record, dict):
        raise ValueError("presentation outfit lacks a trusted texture-mip ledger record")
    trusted_path = resolve_path(str(trusted_ledger_record.get("path", "")))
    if trusted_path != ledger_path or _cached_matches_file(
        ledger_path,
        byte_length=int(trusted_ledger_record.get("byte_length", -1)),
        sha256_digest=str(trusted_ledger_record.get("sha256", "")),
    ) is None:
        raise ValueError("reference-outfit mip ledger changed from presentation evidence")

    ledger = _cached_load_json(ledger_path)
    if not isinstance(ledger, dict) or set(ledger) != {
        "schema_version",
        "description",
        "generator",
        "decoder",
        "evidence_sources",
        "texture_count",
        "mip_level_count",
        "textures",
    }:
        raise ValueError("reference-outfit mip ledger schema changed")
    textures = ledger.get("textures")
    if (
        ledger.get("schema_version") != 1
        or ledger.get("texture_count") != len(REFERENCE_OUTFIT_TEXTURE_NAMES)
        or not isinstance(textures, list)
        or len(textures) != len(REFERENCE_OUTFIT_TEXTURE_NAMES)
    ):
        raise ValueError("reference-outfit texture inventory changed")
    evidence_sources = ledger.get("evidence_sources")
    if not isinstance(evidence_sources, list) or len(evidence_sources) != 3:
        raise ValueError("reference-outfit mip evidence-source inventory changed")
    for evidence_index, evidence in enumerate(evidence_sources):
        if not isinstance(evidence, dict):
            raise ValueError("reference-outfit mip evidence-source record changed")
        evidence_path = resolve_path(str(evidence.get("path", "")))
        if _cached_matches_file(
            evidence_path,
            byte_length=int(evidence.get("byte_length", -1)),
            sha256_digest=str(evidence.get("sha256", "")),
        ) is None:
            raise ValueError(
                f"reference-outfit mip evidence source {evidence_index} changed"
            )
    by_name: dict[str, dict[str, Any]] = {}
    level_total = 0
    recorded_paths: set[str] = set()
    for texture_index, record in enumerate(textures):
        if not isinstance(record, dict) or set(record) != {
            "name",
            "semantic_role",
            "source",
            "source_byte_length",
            "source_sha256",
            "width",
            "height",
            "mip_count",
            "format",
            "native_channels",
            "sampler",
            "binding_evidence",
            "levels",
        }:
            raise ValueError(
                f"reference-outfit texture record {texture_index} schema changed"
            )
        name = record.get("name")
        if name != REFERENCE_OUTFIT_TEXTURE_NAMES[texture_index] or name in by_name:
            raise ValueError("reference-outfit texture order or identity changed")
        expected_source = f"../ltdDemo_converted_assets/decompressed/1/Tex/{name}.bntx"
        if record["source"] != expected_source:
            raise ValueError(f"reference-outfit source path changed: {name}")
        source_path = resolve_path(str(record["source"]))
        if _cached_matches_file(
            source_path,
            byte_length=int(record["source_byte_length"]),
            sha256_digest=str(record["source_sha256"]),
        ) is None:
            raise ValueError(f"reference-outfit source BNTX changed: {name}")
        levels = record.get("levels")
        mip_count = record.get("mip_count")
        if (
            type(mip_count) is not int
            or not isinstance(levels, list)
            or mip_count <= 0
            or len(levels) != mip_count
        ):
            raise ValueError(f"reference-outfit mip count changed: {name}")
        expected_width = int(record["width"])
        expected_height = int(record["height"])
        for level_index, level in enumerate(levels):
            if not isinstance(level, dict) or set(level) != {
                "level", "width", "height", "mode", "path", "byte_length", "sha256"
            }:
                raise ValueError(f"reference-outfit mip record schema changed: {name}")
            if (
                level.get("level") != level_index
                or level.get("width") != expected_width
                or level.get("height") != expected_height
                or level.get("mode") != "RGBA"
            ):
                raise ValueError(f"reference-outfit mip geometry/order changed: {name}")
            logical_path = str(level["path"])
            expected_logical_path = (
                "renderer/assets/reference_outfit_texture_mips/"
                f"{name}/mip_{level_index:02d}.png"
            )
            if logical_path != expected_logical_path or logical_path in recorded_paths:
                raise ValueError(f"reference-outfit mip path/order changed: {name}")
            recorded_paths.add(logical_path)
            level_path = resolve_path(logical_path)
            if _cached_matches_file(
                level_path,
                byte_length=int(level["byte_length"]),
                sha256_digest=str(level["sha256"]),
            ) is None:
                raise ValueError(f"reference-outfit checked mip changed: {logical_path}")
            expected_width = max(1, expected_width // 2)
            expected_height = max(1, expected_height // 2)
        level_total += mip_count
        by_name[name] = record
    if ledger.get("mip_level_count") != level_total:
        raise ValueError("reference-outfit total mip-level count changed")
    actual_paths = {
        Path(os.path.relpath(path.resolve(), repository)).as_posix()
        for path in cache_root.glob("*/*")
        if path.is_file()
    }
    if actual_paths != recorded_paths:
        raise ValueError("reference-outfit cache contains unledgered or missing mip files")
    return by_name


@lru_cache(maxsize=1)
def _reference_outfit_texture_mip_inventory() -> dict[str, dict[str, Any]]:
    """Return the once-per-process authenticated production outfit inventory."""

    return _validate_reference_outfit_texture_mip_inventory()


def _bind_favorite_shirt_mip_provenance(
    favorite_shirt_report: dict[str, Any],
    texture_records: dict[str, dict[str, Any]],
) -> None:
    """Bind an active shirt report to its exact BNTX and ordered mip record."""

    if favorite_shirt_report.get("status") != "active":
        return
    selected_name = str(favorite_shirt_report.get("source_albedo"))
    selected_record = texture_records.get(selected_name)
    if selected_record is None:
        raise ValueError("favorite-shirt albedo is absent from the checked mip ledger")
    if selected_record["source_sha256"] != favorite_shirt_report.get(
        "source_bntx_sha256"
    ):
        raise ValueError("favorite-shirt BNTX identity differs from the checked mip ledger")
    selected_record_sha256 = _reference_outfit_mip_chain_sha256(selected_record)
    favorite_shirt_report.update({
        "mapping_basis": "curated_named_authored_variant_with_neutral_fallback",
        "authored_shirt_family_and_loading_mechanism_title_exact": True,
        "favorite_color_to_suffix_projection_title_exact": False,
        "selected_mip_manifest_record": selected_record,
        "source_mip_chain_sha256": selected_record_sha256,
        "source_mip_chain_hash_scope": REFERENCE_OUTFIT_MIP_CHAIN_HASH_SCOPE,
    })


@lru_cache(maxsize=None)
def _reference_texture(name: str) -> tuple[np.ndarray, ...]:
    """Load an authenticated native mip chain in exact ledger order."""

    record = _reference_outfit_texture_mip_inventory().get(name)
    if record is None:
        raise KeyError(f"reference-outfit texture is not in the checked ledger: {name}")
    levels: list[np.ndarray] = []
    for level in record["levels"]:
        path = _resolve_repository_path(str(level["path"]))
        if _cached_matches_file(
            path,
            byte_length=int(level["byte_length"]),
            sha256_digest=str(level["sha256"]),
        ) is None:
            raise ValueError(f"reference-outfit checked mip changed: {level['path']}")
        payload = _cached_read_bytes(path)
        if (
            len(payload) != int(level["byte_length"])
            or hashlib.sha256(payload).hexdigest() != level["sha256"]
        ):
            raise ValueError(
                f"reference-outfit mip changed while loading: {level['path']}"
            )
        with Image.open(io.BytesIO(payload)) as image:
            if (
                image.format != "PNG"
                or image.mode != level["mode"]
                or image.size != (level["width"], level["height"])
            ):
                raise ValueError(f"reference-outfit decoded mip changed: {level['path']}")
            levels.append(texture_from_image(image))
    return tuple(levels)


@dataclass(frozen=True)
class PresentationInactiveAlphaMaskEvidence:
    """Checked serialized ``_alp0`` data that the selected shader omits."""

    report: dict[str, Any]


@lru_cache(maxsize=None)
def _presentation_inactive_alpha_mask_evidence(
    texture_name: str,
    resource_name: str,
    selection: OutfitGameAllSelection,
) -> PresentationInactiveAlphaMaskEvidence:
    """Validate a serialized mask without admitting it to alpha or depth."""

    mip_ledger = _cached_load_json(REFERENCE_OUTFIT_TEXTURE_MIPS)
    texture_records = [
        record for record in mip_ledger["textures"] if record["name"] == texture_name
    ]
    if len(texture_records) != 1:
        raise ValueError(f"{texture_name} must resolve exactly once in the mip ledger")
    texture_record = texture_records[0]
    sampler = texture_record["sampler"]
    binding_evidence = texture_record["binding_evidence"]
    expected_texture_evidence = {
        "semantic_role": "alpha_mask",
        "native_channels": "R,R,R,R",
        "material_sampler": "_alp0",
        "shader_sampler": "_alp0",
        "min_filter": "linear",
        "mag_filter": "linear",
        "mipmap_filter": "linear",
        "wrap_u": "clamp",
        "wrap_v": "clamp",
        "wrap_w": "clamp",
        "max_anisotropic": 2,
        "compare_function": "never",
        "min_lod": 0.0,
        "max_lod": 13.0,
        "lod_bias": 0.0,
        "state": "renderer/reference_outfit_material_state.json",
        "resource": resource_name,
        "model": resource_name,
        "material": "mt_Body",
        "serialized_texture_ref": "Dummy_Msk",
        "runtime_texture_substitution": None,
        "selected_program_sampler_status": "inactive_compiled_sampler_assignment",
    }
    actual_texture_evidence = {
        "semantic_role": texture_record["semantic_role"],
        "native_channels": texture_record["native_channels"],
        **{
            key: sampler[key]
            for key in (
                "material_sampler",
                "shader_sampler",
                "min_filter",
                "mag_filter",
                "mipmap_filter",
                "wrap_u",
                "wrap_v",
                "wrap_w",
                "max_anisotropic",
                "compare_function",
                "min_lod",
                "max_lod",
                "lod_bias",
            )
        },
        **{
            key: binding_evidence[key]
            for key in (
                "state",
                "resource",
                "model",
                "material",
                "serialized_texture_ref",
                "runtime_texture_substitution",
                "selected_program_sampler_status",
            )
        },
    }
    if actual_texture_evidence != expected_texture_evidence:
        raise ValueError(f"{texture_name} alpha binding differs from the checked mip ledger")

    material_ledger = _cached_load_json(REFERENCE_OUTFIT_MATERIAL_STATE)
    resources = [
        resource
        for resource in material_ledger["resources"]
        if resource["resource_name"] == resource_name
    ]
    if len(resources) != 1:
        raise ValueError(f"{resource_name} must resolve exactly once in material state")
    models = [model for model in resources[0]["models"] if model["name"] == resource_name]
    if len(models) != 1:
        raise ValueError(f"{resource_name} model must resolve exactly once in material state")
    materials = [material for material in models[0]["materials"] if material["name"] == "mt_Body"]
    if len(materials) != 1:
        raise ValueError(f"{resource_name}/mt_Body must resolve exactly once")
    material = materials[0]

    alpha_samplers = [item for item in material["samplers"] if item["name"] == "_alp0"]
    if len(alpha_samplers) != 1:
        raise ValueError(f"{resource_name}/mt_Body must bind exactly one _alp0 sampler")
    material_sampler = alpha_samplers[0]
    expected_material_sampler = {
        "texture_ref": "Dummy_Msk",
        "wrap_u": "Clamp",
        "wrap_v": "Clamp",
        "wrap_w": "Clamp",
        "compare_function": "Never",
        "max_anisotropic": "Ratio_2_1",
        "shrink_filter": "Linear",
        "expand_filter": "Linear",
        "mipmap_filter": "Linear",
        "min_lod": 0,
        "max_lod": 13,
        "lod_bias": 0,
    }
    if {key: material_sampler[key] for key in expected_material_sampler} != expected_material_sampler:
        raise ValueError(f"{resource_name}/mt_Body _alp0 sampler state changed")

    shader_options = {item["name"]: item["value"] for item in material["shader_options"]}
    expected_shader_options = {
        "gsys_geometry_culling": "True",
        "enable_alpha_tex": "True",
        "map_alpha": "11",
    }
    if {key: shader_options.get(key) for key in expected_shader_options} != expected_shader_options:
        raise ValueError(f"{resource_name}/mt_Body alpha shader options changed")

    render_info = {
        item["name"]: item["value"][0]
        for item in material["render_infos"]
        if len(item["value"]) == 1
    }
    expected_render_state = {
        "gsys_render_state_mode": "mask",
        "gsys_render_state_display_face": "both",
        "gsys_render_state_blend_mode": "none",
        "gsys_depth_test_enable": "true",
        "gsys_depth_test_func": "lequal",
        "gsys_depth_test_write": "true",
        "gsys_alpha_test_enable": "true",
        "gsys_alpha_test_func": "gequal",
        "gsys_alpha_test_value": 0.5,
    }
    if {key: render_info.get(key) for key in expected_render_state} != expected_render_state:
        raise ValueError(f"{resource_name}/mt_Body fixed render state changed")

    if (
        selection.resource_name != resource_name
        or "_alp0" in selection.active_material_samplers
        or selection.inactive_serialized_assignments
        != (("_alp0", "_alp0", int(material_sampler["index"]), "Dummy_Msk"),)
    ):
        raise ValueError(
            f"{resource_name}/mt_Body _alp0 is no longer serialized-inactive in the selected program"
        )

    texture = _reference_texture(texture_name)
    red_levels = [level[..., 0] for level in texture]
    all_white = all(np.all(level == 1.0) for level in red_levels)
    expected_all_white = resource_name == "ClothBottomsPantsLong"
    if all_white != expected_all_white:
        expectation = "all-white" if expected_all_white else "nontrivial"
        raise ValueError(f"{texture_name} is no longer the checked {expectation} alpha chain")

    return PresentationInactiveAlphaMaskEvidence(
        report={
            "external_texture_candidate": texture_name,
            "serialized_binding": "Dummy_Msk -> _alp0",
            "selected_program": selection.gameall_program,
            "title_shader_execution_key": selection.title_shader_execution_key,
            "selected_program_sampler_status": "inactive_compiled_sampler_assignment",
            "active_compiled_material_samplers": list(
                selection.active_material_samplers
            ),
            "runtime_texture_substitution": None,
            "native_channels": texture_record["native_channels"],
            "mip_count": texture_record["mip_count"],
            "content": (
                "all-white at every native mip; retained as inactive evidence"
                if all_white
                else "nontrivial inactive chain; native mip 0 spans 0..1"
            ),
            "serialized_sampler": sampler,
            "serialized_fixed_render_state": expected_render_state,
            "portable_effect": (
                "none: selected compiled shader omits _alp0; this texture cannot "
                "change opacity, alpha cutoff, depth acceptance, or depth writes"
            ),
        },
    )


def _head_gameall816_material_style(
    skin: tuple[float, float, float, float],
    head_normal: np.ndarray | tuple[np.ndarray, ...],
    faceline_texture: np.ndarray | None,
) -> MaterialStyle:
    """Bind the generated faceline RT to Head816's independent ``_a0`` path.

    The compiled Head816 local base is ``sample(_a0, uv).rgb``; it does not
    multiply by ``mii_face_color``.  Supplying white here makes the existing
    generic sampled-albedo path execute that exact local equation, including
    the hardware sRGB decode requested by ``linear_lighting``.  The portable
    lighting response remains the separately reported Head816 boundary.
    """

    if faceline_texture is None:
        return MaterialStyle(
            skin,
            gameall_identity=gameuber_cpu.gameall_program_identity("head", 816),
            normal_texture=head_normal,
            normal_wrap=("repeat", "repeat"),
            normal_channels=(0, 3),
            cheap_sss_proxy=True,
            linear_lighting=True,
            receives_screenspace_face_shadow=True,
            texcoord_bindings={"normal": "_u2"},
        )
    return MaterialStyle(
        (1.0, 1.0, 1.0, 1.0),
        gameall_identity=gameuber_cpu.gameall_program_identity("head", 816),
        texture=faceline_texture,
        # mt_Head `_a0`: Mirror U, Repeat V, linear min/mag, point mip.
        # The generated target has one level, so the point-mip decision is 0.
        texture_wrap=("mirror", "repeat"),
        texture_mip_filter="point",
        normal_texture=head_normal,
        normal_wrap=("repeat", "repeat"),
        normal_channels=(0, 3),
        # Head816 compiles the recovered local cheap-SSS curve, but its scalar
        # input is an interpolation involving gsys_user4.g and title-prepass
        # terms.  Those inputs are unavailable, so the rasterizer records the
        # compiled branch identity while disabling its correction fail-closed;
        # raw NdotL is never substituted for the missing title value.
        cheap_sss_proxy=True,
        linear_lighting=True,
        receives_screenspace_face_shadow=True,
        # Head816's vertex/material options route the generated face albedo
        # through the folded _u0 stream while texcoord_select_normal=2 keeps
        # the authored normal-height map on the conventional _u2 stream.
        texcoord_bindings={"texture": "_u0", "normal": "_u2"},
    )


def _production_draw_routing_report(calls: list[Any]) -> dict[str, Any]:
    """Require and report explicit shader routing for every production draw."""

    draws: list[dict[str, Any]] = []
    for draw_index, call in enumerate(calls):
        validate_material_style_routing(call.style, require_named=True)
        identity = call.style.gameall_identity
        if identity is not None:
            draws.append(
                {
                    "draw_index": draw_index,
                    "group": call.group,
                    "routing_status": "audited_gameall_local",
                    "family": identity.family,
                    "program_index": identity.program_index,
                    "local_base_scope": identity.local_base_scope,
                    "cheap_sss_local_curve": identity.cheap_sss_local_curve,
                    "anisotropic_local_kernel": identity.anisotropic_local_kernel,
                    "front_edge_local_gate": identity.front_edge_local_gate,
                    "receives_screen_space_face_shadow": identity.receives_screen_space_face_shadow,
                    "literal_title_final_coverage": identity.literal_title_final_coverage,
                    "generic_phong_enabled": call.style.specular_strength != 0.0,
                    "title_final_response_status": (
                        "unresolved_missing_gsys_environment_context_material_GlobalUBO_and_prepasses"
                    ),
                }
            )
            continue
        draws.append(
            {
                "draw_index": draw_index,
                "group": call.group,
                "routing_status": "named_unresolved_portable",
                "portable_family": call.style.unresolved_portable_family,
                "generic_phong_enabled": call.style.specular_strength != 0.0,
                "title_final_response_status": "unresolved_portable_family",
            }
        )
    return {
        "draws": draws,
        "draw_count": len(draws),
        "audited_gameall_draw_count": sum(
            draw["routing_status"] == "audited_gameall_local" for draw in draws
        ),
        "named_unresolved_portable_draw_count": sum(
            draw["routing_status"] == "named_unresolved_portable" for draw in draws
        ),
        "anonymous_draw_count": 0,
        "generic_phong_on_audited_gameall": False,
        "title_final_radiance_equivalence_claimed": False,
        "boundary": (
            "every production draw is either an instruction-audited GameAll local identity "
            "or a named unresolved portable family; gsys_environment/context/material/GlobalUBO "
            "and title prepass inputs remain fail-closed"
        ),
    }


_TITLE_MII_ALPHA_MASK_PRIORITY = {
    "Mask__mt_Mask": -10,
    "NoseLine__mt_NoseLine": -10,
}
_TITLE_MII_TRANSLUCENT_LENS_GROUP = "Trs__mt_LensTrs"


def _title_mii_draw_schedule(calls: list[Any]) -> tuple[list[Any], dict[str, Any]]:
    """Apply the recovered ModelSortKey priority prefix to the Mii model queue.

    The title combines opaque and alpha-mask model records in one pass.  Its
    unsigned ascending 64-bit key puts the biased signed ``gsys_priority`` in
    bits 48..53, below runtime and priority-hint but above the remaining key.
    Every checked Mii material here has the same runtime and ``player`` hint:
    Mask/NoseLine author -10 and the other staged opaque materials author 0.

    The lower, still-unrecovered key fields are deliberately not synthesized.
    Python's stable sort therefore preserves authored submission order for
    equal priorities.  LensTrs belongs to the separate translucent/no-write
    pass and never participates in this opaque+alpha-mask partition.
    """

    authored = list(calls)
    try:
        mii_start = next(
            index for index, call in enumerate(authored) if call.group == "Head__mt_Head"
        )
    except StopIteration as error:
        raise ValueError("recorded scene has no Mii Head draw to anchor model scheduling") from error

    prefix = authored[:mii_start]
    opa_alpha_mask: list[Any] = []
    translucent: list[Any] = []
    for call in authored[mii_start:]:
        if call.group == _TITLE_MII_TRANSLUCENT_LENS_GROUP:
            if not call.style.blend or call.style.depth_write:
                raise ValueError("mt_LensTrs must remain translucent with depth writes disabled")
            translucent.append(call)
            continue
        if call.style.blend or not call.style.depth_write:
            raise ValueError(
                f"unsupported Mii model pass state for {call.group}: "
                "only opaque/alpha-mask depth-writing draws and LensTrs are recovered"
            )
        opa_alpha_mask.append(call)

    priority = lambda call: _TITLE_MII_ALPHA_MASK_PRIORITY.get(call.group, 0)
    scheduled_opa_alpha_mask = sorted(opa_alpha_mask, key=priority)
    priorities = sorted({priority(call) for call in scheduled_opa_alpha_mask})
    stable_ties = all(
        [id(call) for call in opa_alpha_mask if priority(call) == value]
        == [id(call) for call in scheduled_opa_alpha_mask if priority(call) == value]
        for value in priorities
    )
    if not stable_ties:
        raise RuntimeError("Mii ModelSortKey priority partition changed equal-priority order")

    scheduled = [*prefix, *scheduled_opa_alpha_mask, *translucent]
    if sorted(map(id, scheduled)) != sorted(map(id, authored)):
        raise RuntimeError("Mii model scheduling did not preserve the exact draw inventory")

    return scheduled, {
        "title_pass": "Model(Opa+AlphaMask)",
        "recovered_prefix_order": (
            "unsigned ascending ModelSortKey priority prefix only; lower 48 bits remain unresolved"
        ),
        "packed_prefix": {
            "runtime_bits": [58, 61],
            "priority_hint_bits": [54, 57],
            "gsys_priority_bits": [48, 53],
            "signed_bias": {"runtime": 8, "priority_hint": 8, "gsys_priority": 32},
            "checked_runtime_and_hint": "equal for the staged Mii materials; priority_hint=player",
        },
        "evidence": {
            "debug_format": "ModelSortKey : 0x%016llx (Runtime:%d PriorityHint:%d Priority:%d)",
            "debug_pack_address": "0x71026f76f8",
            "production_pack_addresses": [
                "0x71026f6690",
                "0x71026f6cf8",
                "0x710272a160",
            ],
        },
        "authored_mii_groups": [call.group for call in authored[mii_start:]],
        "scheduled_opa_alpha_mask": [
            {"group": call.group, "gsys_priority": priority(call)}
            for call in scheduled_opa_alpha_mask
        ],
        "priority_buckets": priorities,
        "equal_priority_policy": (
            "conservative stable authored submission order; title lower-48-bit tie order remains "
            "unresolved and no same-priority category order is claimed"
        ),
        "equal_priority_order_preserved": stable_ties,
        "translucent_pass": [
            {
                "group": call.group,
                "gsys_priority": -8,
                "depth_write": call.style.depth_write,
            }
            for call in translucent
        ],
    }


def _compose_scene(
    rasterizer: OrthographicRasterizer,
    models: dict[str, ObjMesh],
    char_info: dict[str, Any],
    face_texture: np.ndarray,
    faceline_texture: np.ndarray | None,
    facepaint: ShareMiiV3FacePaint | None,
    asset_root: Path,
    head_scene_transform: np.ndarray,
    include_body: bool,
    include_reference_outfit: bool,
    presentation_variation: int,
    favorite_shirt_selection: FavoriteShirtSelection | None,
    nose_parallax_height_scale: float,
    active_records: dict[str, dict[str, Any]],
    body_pose: PosedModel | None = None,
    for_hat: bool = False,
    legacy_headwear_selection: LegacyHeadwearSelection | None = None,
    body_program_selections: dict[str, BodyGameAllSelection] | None = None,
    outfit_program_selections: dict[str, OutfitGameAllSelection] | None = None,
    glass_frame_program_selection: GameAllMaterialSelection | None = None,
    glass_lens_program_selection: GameAllMaterialSelection | None = None,
) -> dict[str, int]:
    colors = _cached_load_json(COLOR_TABLE)
    skin_rgba8 = resolve_skin_color(colors, char_info["faceline_color"])
    skin = tuple(channel / 255.0 for channel in skin_rgba8)
    hair = tuple(colors["common"][char_info["hair_color_primary"]])
    beard = tuple(colors["common"][char_info["beard_color"]])
    stored_hair_secondary = tuple(colors["common"][char_info["hair_color_secondary"]])
    glass = tuple(colors["common"][char_info["glass_primary_color"]])
    head_resource = _active_model_resource(active_records, "faceline")
    hair_model_selections = _active_hair_model_selections(
        active_records, char_info, for_hat=for_hat
    )
    hair_resources = tuple(
        (selection.model_key, selection.resource_name)
        for selection in hair_model_selections
    )
    hair_selection_by_key = {
        selection.model_key: selection for selection in hair_model_selections
    }
    nose_resource = _active_model_resource(active_records, "nose")
    beard_resource = _active_model_resource(active_records, "beard")
    glass_resource = _active_model_resource(active_records, "glass_primary")
    glass_lens_state = (
        _glass_lens_runtime_state(char_info, colors) if glass_resource is not None else None
    )
    if head_resource is None:
        raise ValueError("the active ShareMii must resolve a faceline model")
    head_attachments = {
        binding.bone_name: binding.matrix
        for binding in _prepared_head_attachment_bindings(head_resource)
    }
    head_normal = _material_texture(f"{head_resource}_Head_Nmh")
    nose_model = models.get("nose") if nose_resource is not None else None
    nose_has_surface = (
        nose_model is not None and "Nose__mt_Nose" in nose_model.groups
    )
    nose_has_line = (
        nose_model is not None and "NoseLine__mt_NoseLine" in nose_model.groups
    )
    nose_height = (
        _material_texture(f"{nose_resource}_Hgt") if nose_has_surface else None
    )
    nose_material_mask = (
        _material_texture(f"{nose_resource}_Mim") if nose_has_surface else None
    )
    nose_line_mask = (
        _material_texture(f"{nose_resource}_NoseLine_Msk")
        if nose_has_line
        else None
    )
    glass_normal = (
        _optional_material_texture(f"{glass_resource}_Nrm") if glass_resource is not None else None
    )
    counts: dict[str, int] = {}

    if include_body:
        if body_pose is None:
            raise ValueError("full-body rendering requires the recovered body pose")
        body = body_pose.mesh
        if set(body.groups) != set(BODY_GAMEALL_PROGRAM_BY_GROUP):
            raise RuntimeError("BodyBaseDefault submitted-group inventory changed")
        if body_program_selections is None or set(body_program_selections) != set(
            BODY_GAMEALL_PROGRAM_BY_GROUP
        ):
            raise RuntimeError("BodyBaseDefault exact GameAll selection inventory changed")
        body_scale = mii_body_scale(char_info["build"], char_info["height"])
        body_transform = scale(*body_scale)
        body_styles: dict[str, MaterialStyle] = {}
        for material_name, resource_name in (
            ("mt_Tops", "Tops"),
            ("mt_Bottoms", "Bottoms"),
            ("mt_Socks", "Socks"),
        ):
            skin_mask = _material_texture(f"BodyBaseDefault_{resource_name}_Skm")
            body_albedo = _material_texture(f"BodyBaseDefault_{resource_name}_Alb")
            body_normal = _material_texture(f"BodyBaseDefault_{resource_name}_Nrm")
            material_information = _material_texture(
                f"BodyBaseDefault_{resource_name}_Mic"
            )
            if include_reference_outfit and resource_name == "Socks":
                body_albedo = _reference_texture(
                    f"ClothSocksBodyBaseTexDefault_Socks_Alb.{presentation_variation:02d}"
                )
                body_normal = _reference_texture(
                    "ClothSocksBodyBaseTexDefault_Socks_Nrm"
                )
                skin_mask = _reference_texture(
                    "ClothSocksBodyBaseTexDefault_Socks_Skm"
                )
            body_styles[material_name] = MaterialStyle(
                (1.0, 1.0, 1.0, 1.0),
                # This material-input template is never submitted directly.
                # Each BFRES group below replaces the identity from its exact
                # skin-count-selected Body324/336/348 evidence row.
                gameall_identity=None,
                gameuber_body348=GameUberBody348LocalMaterialInputs(
                    albedo_texture=body_albedo,
                    albedo_wrap=("clamp", "clamp"),
                    albedo_mip_filter="linear",
                    skin_mask_texture=skin_mask,
                    skin_mask_wrap=("clamp", "clamp"),
                    skin_mask_mip_filter="linear",
                    material_information_texture=material_information,
                    material_information_wrap=("clamp", "clamp"),
                    material_information_mip_filter="point",
                    face_color_linear_rgb=tuple(
                        _srgb_to_linear(np.asarray(skin[:3], dtype=np.float64))
                    ),
                    const_single_roughness=0.75,
                ),
                normal_texture=body_normal,
                normal_wrap=("clamp", "clamp"),
                normal_mip_filter="point",
                roughness=0.75,
                cheap_sss_proxy=True,
                cheap_sss_mask_texture=skin_mask,
                cheap_sss_mask_wrap=("clamp", "clamp"),
                cheap_sss_mask_mip_filter="linear",
                cheap_sss_mask_channel=1,
                cheap_sss_mask_invert=True,
                linear_lighting=True,
            )
        hidden_body_groups = (
            _presentation_body_base_cutline_groups()
            if include_reference_outfit
            else frozenset()
        )
        for group in body.groups:
            if group in hidden_body_groups:
                continue
            if body_program_selections is None or group not in body_program_selections:
                raise RuntimeError(f"Body draw lacks exact GameAll selection: {group}")
            body_program = body_program_selections[group]
            suffix = next((key for key in body_styles if key in group), "mt_Tops")
            if suffix != body_program.material_name:
                raise RuntimeError(f"Body material selection changed for {group}")
            body_style = replace(
                body_styles[suffix],
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    "body", body_program.gameall_program
                ),
            )
            counts[f"body:{group}"] = rasterizer.draw_group(
                body, group, body_style, body_transform
            )

        if include_reference_outfit:
            if outfit_program_selections is None or set(outfit_program_selections) != {
                "tops",
                "bottoms",
                "shoes",
            }:
                raise RuntimeError("presentation outfit lacks exact GameAll selections")
            top_program = outfit_program_selections["tops"]
            top_albedo_name = (
                favorite_shirt_selection.source_albedo
                if favorite_shirt_selection is not None
                else f"ClothTopsTshirtLongTexDefault_Body_Alb.{presentation_variation:02d}"
            )
            top_albedo = _reference_texture(top_albedo_name)
            top_style = MaterialStyle(
                (1.0, 1.0, 1.0, 1.0),
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    top_program.family, top_program.gameall_program
                ),
                texture=top_albedo,
                texture_wrap=("clamp", "clamp"),
                texture_mip_filter="linear",
                normal_texture=_reference_texture(
                    "ClothTopsTshirtLongTexDefault_Body_Nrm"
                ),
                normal_wrap=("clamp", "clamp"),
                normal_mip_filter="point",
                roughness_texture=_reference_texture(
                    "ClothTopsTshirtLongTexDefault_Body_Mic"
                ),
                roughness_wrap=("clamp", "clamp"),
                roughness_mip_filter="point",
                roughness_channel=0,
                roughness_scale=1.0,
                roughness_bias=0.0,
                # Exact 984 omits serialized _alp0. Its active albedo has
                # native alpha 1, so the portable draw is opaque and no mask
                # or guessed shader-output cutoff can affect depth.
                alpha_cutoff=0.0,
                cull_back_faces=False,
                depth_write=True,
                blend=False,
                linear_lighting=True,
            )
            # Program 36 binds Dummy_Alb and the live replacement is not
            # recovered. Do not substitute the outer-top albedo or invent the
            # former hard-coded 0.4 modulation for Softmesh.
            for group in models["reference_top"].groups:
                if "mt_Softmesh" in group:
                    continue
                counts[f"reference_top:{group}"] = rasterizer.draw_group(
                    models["reference_top"],
                    group,
                    top_style,
                    body_transform,
                )

            bottoms_program = outfit_program_selections["bottoms"]
            bottoms_style = MaterialStyle(
                (1.0, 1.0, 1.0, 1.0),
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    bottoms_program.family, bottoms_program.gameall_program
                ),
                texture=_reference_texture(
                    f"ClothBottomsPantsLongTexDefault_Body_Alb.{presentation_variation:02d}"
                ),
                texture_wrap=("clamp", "clamp"),
                texture_mip_filter="linear",
                normal_texture=_reference_texture(
                    "ClothBottomsPantsLongTexDefault_Body_Nrm"
                ),
                normal_wrap=("clamp", "clamp"),
                normal_mip_filter="point",
                roughness_texture=_reference_texture(
                    "ClothBottomsPantsLongTexDefault_Body_Mic"
                ),
                roughness_wrap=("clamp", "clamp"),
                roughness_mip_filter="point",
                roughness_channel=0,
                roughness_scale=1.0,
                roughness_bias=0.0,
                # Exact 936 likewise compiles _alp0 out.
                alpha_cutoff=0.0,
                cull_back_faces=False,
                depth_write=True,
                blend=False,
                linear_lighting=True,
            )
            for group in models["presentation_bottoms"].groups:
                if "mt_Softmesh" in group:
                    continue
                counts[f"presentation_bottoms:{group}"] = rasterizer.draw_group(
                    models["presentation_bottoms"], group, bottoms_style, body_transform
                )

            shoes_program = outfit_program_selections["shoes"]
            shoe_style = MaterialStyle(
                (1.0, 1.0, 1.0, 1.0),
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    shoes_program.family, shoes_program.gameall_program
                ),
                texture=_reference_texture(
                    f"ClothShoesStandardTexDefault_Body_Alb.{presentation_variation:02d}"
                ),
                texture_wrap=("clamp", "clamp"),
                texture_mip_filter="linear",
                normal_texture=_reference_texture(
                    "ClothShoesStandardTexDefault_Body_Nrm"
                ),
                normal_wrap=("clamp", "clamp"),
                normal_mip_filter="point",
                roughness_texture=_reference_texture(
                    "ClothShoesStandardTexDefault_Body_Mic"
                ),
                roughness_wrap=("clamp", "clamp"),
                roughness_mip_filter="point",
                roughness_channel=0,
                roughness_scale=1.0,
                roughness_bias=0.0,
                # Exact 912 also records _alp0 only as an inactive serialized
                # assignment. The native albedo alpha channel is constant 1.
                alpha_cutoff=0.0,
                cull_back_faces=False,
                depth_write=True,
                blend=False,
                linear_lighting=True,
            )
            for group in models["reference_shoes"].groups:
                counts[f"reference_shoes:{group}"] = rasterizer.draw_group(
                    models["reference_shoes"], group, shoe_style, body_transform
                )

    head_model = models["head"]
    # VertexSkinCount=0 shapes are bone-local. Resolve the complete BFRES bind
    # parent chain rather than borrowing a local bone offset from one resource.
    head_bone = _prepared_rigid_shape_binding(head_resource, "Head__mt_Head").matrix
    counts["head:Head__mt_Head"] = rasterizer.draw_group(
        head_model,
        "Head__mt_Head",
        # The selected *_Head_Nmh is an ASTC luminance/alpha normal-height map;
        # the converted PNG preserves its two signed normal components in R/A.
        _head_gameall816_material_style(skin, head_normal, faceline_texture),
        head_scene_transform @ head_bone,
    )

    # FUN_7101d6d538 cases 7/8 emit the selected faceline's complete set_ear
    # bind-world transform twice, with a world-X reflection for the opposite
    # side. FUN_7101d6ee04 contributes (ear_y - 4) * -0.015 to world Y. Each
    # Ear00..03 model is rigid and retains its own complete BFRES shape bind.
    ear_resource = _active_model_resource(active_records, "ear")
    if ear_resource is not None and "ear" in models:
        ear_attachment = head_attachments["set_ear"].copy()
        ear_attachment[1, 3] += (char_info["ear_y"] - 4) * -0.015
        ear_size = (char_info["ear_scale"] * 0.175 + 0.75) / 1.1
        ear_shape_transform = _prepared_rigid_shape_binding(
            ear_resource, "Ear__mt_Ear"
        ).matrix
        ear_right = ear_attachment @ scale(ear_size) @ ear_shape_transform
        ear_left = scale(-1.0, 1.0, 1.0) @ ear_right
        ear_style = MaterialStyle(
            skin,
            gameall_identity=gameuber_cpu.gameall_program_identity("ear", 372),
            cheap_sss_proxy=True,
            linear_lighting=True,
            receives_screenspace_face_shadow=True,
        )
        counts["ear:right:Ear__mt_Ear"] = rasterizer.draw_group(
            models["ear"],
            "Ear__mt_Ear",
            ear_style,
            head_scene_transform @ ear_right,
        )
        counts["ear:left:Ear__mt_Ear"] = rasterizer.draw_group(
            models["ear"],
            "Ear__mt_Ear",
            MaterialStyle(
                skin,
                gameall_identity=gameuber_cpu.gameall_program_identity("ear", 372),
                clockwise_front_face=True,
                cheap_sss_proxy=True,
                linear_lighting=True,
                receives_screenspace_face_shadow=True,
            ),
            head_scene_transform @ ear_left,
        )

    # The final title draw keeps the selected faceline model's original
    # 288-triangle Mask shape
    # and swaps the generated 22-layer face RT into its _a0 slot. FaceMaskPos
    # is CPU-sampled separately for attachment anchors; it is not a replacement
    # VBO/IBO. Mask's shape bone is identity, with no hand-fit scale or +Z bias.
    face_mask_model = models["face_mask"]
    mask_style = (
        MaterialStyle(
            (1.0, 1.0, 1.0, 1.0),
            gameall_identity=gameuber_cpu.gameall_program_identity("mask", 0),
            gameuber_mask0_facepaint=GameUberMask0FacePaintInputs(
                generated_mask_texture=face_texture,
                generated_mask_wrap=("repeat", "repeat"),
                generated_mask_mip_filter="point",
                user0_texture=(
                    facepaint.ugc_render_rgba8.astype(np.float64) / 255.0
                ),
                user0_wrap=("clamp", "clamp"),
                user0_mip_filter="point",
                user0_tex_srt=facepaint.tex_srt,
                replace_albedo_color_linear_rgba=(0.0, 0.0, 0.0, 0.0),
                # The UGC provider and renderer constructors initialize this
                # state to zero. sync_mii_character_data_and_refresh_render_models
                # (0x7100de5090), commit_mii_renderer_staging_state
                # (0x7101bcffd4), and apply_mii_model_ugc_texture_state
                # (0x7101bd62c8) can replace it through character source +0xa0,
                # desired +0x150, active +0xa8, then renderer +0xf84. No v3
                # import bridge to source +0xa0 was recovered, so execute
                # only the source-backed constructor endpoint and report the
                # live imported-record override as unresolved.
                source_backed_constructor_const_single0_value=0.0,
                const_single0_runtime_state=(
                    "source-backed constructor value zero; imported provider-record "
                    "+0xa0 override is unresolved for ShareMii v3"
                ),
                emission_color_linear_rgb=(1.0, 1.0, 1.0),
                emission_intensity=0.1,
                portable_coverage_threshold=0.5,
            ),
            alpha_cutoff=0.5,
            cull_back_faces=False,
            linear_lighting=True,
        )
        if facepaint is not None
        else MaterialStyle(
            (1.0, 1.0, 1.0, 1.0),
            gameall_identity=gameuber_cpu.gameall_program_identity("mask", 0),
            texture=face_texture,
            texture_emission_intensity=0.1,
            # GameAll program 0: with const_single0=0 and
            # replace_albedo_color=(0,0,0,0), the no-UGC Dummy_Alb fallback
            # simplifies the local base to mix(U.rgb, A.rgb, A.a). Both image
            # views are sRGB-decoded before this operation; #808080 therefore
            # becomes the exact IEC-linear value below.
            texture_alpha_under_color_linear=(
                0.21586050011389926,
                0.21586050011389926,
                0.21586050011389926,
            ),
            alpha_cutoff=0.5,
            cull_back_faces=False,
            linear_lighting=True,
        )
    )
    counts["head:Mask__mt_Mask"] = rasterizer.draw_group(
        face_mask_model,
        "Mask__mt_Mask",
        mask_style,
        head_scene_transform
        @ _prepared_rigid_shape_binding(head_resource, "Mask__mt_Mask").matrix,
    )

    # Rigid hair vertices remain shape-bone local, while pose_model has already
    # evaluated smooth hair through its BFRES palette. Resolve the remaining
    # post-pose transform from each active BFRES so neither class can silently
    # inherit another model's shape transform.
    for model_key, hair_resource in hair_resources:
        hair_model_selection = hair_selection_by_key[model_key]
        # FUN_7101d7e010 writes main/back endpoint state from face-flag bit 2
        # and the attached-front endpoint from bit 3. FUN_7101d7c4e0 selects
        # the attached-front state only for material slots 8/9.
        dual_color_flag = (
            "bangs_dual_color" if model_key == "hair_front" else "back_dual_color"
        )
        hair_secondary = (
            stored_hair_secondary
            if char_info["face_flags"][dual_color_flag]
            else hair
        )
        hair_shader = _select_hair_shader(
            hair_resource, model_name=hair_model_selection.model_name
        )
        hair_alpha = _optional_material_texture(f"{hair_resource}_Msk")
        hair_normal = _optional_material_texture(f"{hair_resource}_Nrm")
        hair_material_mask = _material_texture(f"{hair_resource}_Mim")
        hair_gradient = (
            None
            if hair_shader.use_constant_hair_color_linear
            else _material_texture(f"{hair_resource}_Mgh")
        )
        hair_model_transform = (
            scale(-1.0, 1.0, 1.0)
            if hair_model_selection.mirror_horizontal
            else identity()
        )
        # Every checked primary Hair+Decoration BFRES lists Decoration before
        # Hair. Preserve that model draw order and evaluate its distinct
        # program480/492 constant-color family instead of borrowing Hair's
        # endpoint-gradient shader.
        if "Decoration__mt_Decoration" in models[model_key].groups:
            if model_key != "hair":
                raise ValueError("Decoration is only audited on the main Hair model slot")
            decoration_shader = _select_decoration_shader(
                hair_resource, model_name=hair_model_selection.model_name
            )
            decoration_state = _decoration_runtime_state(char_info, colors)
            counts[f"{model_key}:Decoration__mt_Decoration"] = rasterizer.draw_group(
                models[model_key],
                "Decoration__mt_Decoration",
                MaterialStyle(
                    tuple(decoration_state["mii_constant_color0_linear"]),
                    gameall_identity=gameuber_cpu.gameall_program_identity(
                        "decoration", decoration_shader.gameall_program
                    ),
                    occlusion_texture=hair_material_mask,
                    occlusion_wrap=("repeat", "repeat"),
                    occlusion_channel=0,
                    roughness=1.0,
                    # The runtime helper has already produced the exact linear
                    # mii_constant_color0 endpoint; do not sRGB-decode it twice.
                    linear_lighting=False,
                    casts_face_shadow=True,
                    clockwise_front_face=hair_model_selection.mirror_horizontal,
                    flip_horizontal_sign=hair_model_selection.flip_horizontal_sign,
                ),
                head_scene_transform
                @ head_attachments["set_hair"]
                @ hair_model_transform
                @ _prepared_post_pose_shape_transform(
                    hair_resource,
                    "Decoration__mt_Decoration",
                    hair_model_selection.model_index,
                ),
            )
        hair708_gradient: dict[str, Any] = {}
        if hair_shader.use_hair708_face_gradient:
            hair708_gradient = {
                "hair708_face_color_linear": tuple(
                    float(value)
                    for value in _srgb_to_linear(np.asarray(skin[:3], dtype=np.float64))
                ),
                "hair708_face_blend_channel": 1,
            }
        constant_hair_base: dict[str, Any] = {}
        if hair_shader.use_constant_hair_color_linear:
            constant_hair_base = {
                "hair_constant_color_linear": tuple(
                    float(value)
                    for value in _srgb_to_linear(
                        np.asarray(hair[:3], dtype=np.float64)
                    )
                ),
                "linear_lighting": True,
            }
        hair612_proxy: dict[str, Any] = {}
        if hair_shader.use_hair612_anisotropic_proxy:
            # The Hair612-family local shifted-bitangent kernel is binary-backed
            # for the exact selected program. Its title light records remain
            # unavailable, so the CPU renderer supplies the explicitly labeled
            # one-key radiance proxy only for that audited fragment family.
            hair612_proxy = {
                "anisotropic_proxy": True,
                "anisotropic_shift_channel": 2,
                "anisotropic_shift_scale": 1.0,
                "anisotropic_shift_offset": 0.0,
                "anisotropic_specular_size": 10.0,
                "anisotropic_toon_intensity": 1.0,
                "anisotropic_title_view_scale": 1.0,
                "anisotropic_radiance_scale": 1.0,
                "front_edge_light_proxy": True,
                "front_edge_light_view_angle_degrees": 65.0,
                "front_edge_light_intensity": 2.5,
                "roughness": 0.28,
            }
        counts[f"{model_key}:Hair__mt_Hair"] = rasterizer.draw_group(
            models[model_key],
            "Hair__mt_Hair",
            MaterialStyle(
                hair,
                gameall_identity=_hair_gameall_identity(hair_shader),
                alpha_texture=hair_alpha,
                alpha_wrap=("repeat", "repeat"),
                alpha_mip_filter="linear",
                normal_texture=hair_normal,
                normal_wrap=("repeat", "repeat"),
                occlusion_texture=hair_material_mask,
                occlusion_wrap=("repeat", "repeat"),
                occlusion_channel=0,
                specular_texture=hair_material_mask,
                specular_wrap=("repeat", "repeat"),
                specular_channel=1,
                alpha_cutoff=0.5,
                gradient_texture=hair_gradient,
                gradient_wrap=("repeat", "repeat"),
                gradient_mip_filter="linear",
                gradient_channel=0,
                gradient_colors=(
                    None
                    if hair_shader.use_constant_hair_color_linear
                    else (hair[:3], hair_secondary[:3])
                ),
                gamma_correct_lighting=not hair_shader.use_constant_hair_color_linear,
                casts_face_shadow=True,
                clockwise_front_face=hair_model_selection.mirror_horizontal,
                flip_horizontal_sign=hair_model_selection.flip_horizontal_sign,
                **constant_hair_base,
                **hair708_gradient,
                **hair612_proxy,
            ),
            head_scene_transform
            @ head_attachments["set_hair"]
            @ hair_model_transform
            @ _prepared_post_pose_shape_transform(
                hair_resource,
                "Hair__mt_Hair",
                hair_model_selection.model_index,
            ),
        )

    if legacy_headwear_selection is not None:
        headwear_model = models.get("legacy_headwear")
        if headwear_model is None:
            raise ValueError("active legacy headwear has no loaded prepared model")
        headwear_shape = legacy_headwear_selection.shape_name
        if headwear_shape not in headwear_model.groups:
            raise ValueError("active legacy headwear shape is absent from its prepared OBJ")
        headwear_bind = _prepared_rigid_shape_binding(
            legacy_headwear_selection.resource_name,
            headwear_shape,
            legacy_headwear_selection.model_index,
        ).matrix
        if not np.allclose(headwear_bind, identity(), rtol=0.0, atol=1e-12):
            raise ValueError("legacy headwear rigid bind is no longer the checked identity")
        counts[f"legacy_headwear:{headwear_shape}"] = rasterizer.draw_group(
            headwear_model,
            headwear_shape,
            MaterialStyle(
                (1.0, 1.0, 1.0, 1.0),
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    "headwear", legacy_headwear_selection.gameall_program
                ),
                texture=_material_texture(legacy_headwear_selection.albedo_texture),
                texture_wrap=("repeat", "repeat"),
                texture_mip_filter="linear",
                normal_texture=_material_texture(
                    legacy_headwear_selection.normal_texture
                ),
                normal_wrap=("repeat", "repeat"),
                normal_mip_filter="point",
                normal_channels=(0, 1),
                roughness_texture=_material_texture(
                    legacy_headwear_selection.roughness_texture
                ),
                roughness_wrap=("repeat", "repeat"),
                roughness_mip_filter="point",
                roughness_channel=0,
                roughness_scale=1.0,
                roughness_bias=0.0,
                alpha_cutoff=0.0,
                cull_back_faces=True,
                depth_write=True,
                blend=False,
                linear_lighting=True,
                casts_face_shadow=True,
            ),
            head_scene_transform
            @ np.asarray(
                legacy_headwear_selection.hat_attachment_matrix,
                dtype=np.float64,
            )
            @ headwear_bind,
        )

    # FUN_7101d6d538 cases 5/6: compose Nose/NoseLine at the selected
    # faceline's complete set_nose bind-world transform, then apply the exact
    # selector controls.
    if nose_resource is not None and "nose" in models:
        if not nose_has_line or nose_line_mask is None:
            raise ValueError("a selected nose model must resolve its checked NoseLine shape/mask")
        nose_scale = (char_info["nose_scale"] * 0.175 + 0.4) / 1.1
        nose_y_delta = (char_info["nose_y"] - 9) * -0.015
        nose_attachment = (
            head_scene_transform
            @ head_attachments["set_nose"]
            @ translation(0.0, nose_y_delta, 0.0)
            @ scale(nose_scale)
        )
        nose_line_shape_transform = _prepared_rigid_shape_binding(
            nose_resource, "NoseLine__mt_NoseLine"
        ).matrix
        if nose_has_surface:
            if nose_height is None or nose_material_mask is None:
                raise ValueError("a selected Nose surface must resolve Hgt and Mim textures")
            nose_shape_transform = _prepared_rigid_shape_binding(
                nose_resource, "Nose__mt_Nose"
            ).matrix
            counts["nose:Nose__mt_Nose"] = rasterizer.draw_group(
                nose_model,
                "Nose__mt_Nose",
                MaterialStyle(
                    skin,
                    gameall_identity=gameuber_cpu.gameall_program_identity("nose", 756),
                    parallax_texture=nose_height,
                    parallax_wrap=("repeat", "repeat"),
                    parallax_mip_filter="point",
                    parallax_channel=0,
                    parallax_scale=nose_parallax_height_scale,
                    specular_texture=nose_material_mask,
                    specular_wrap=("clamp", "clamp"),
                    specular_channel=1,
                    roughness=0.75,
                    cheap_sss_proxy=True,
                    linear_lighting=True,
                    receives_screenspace_face_shadow=True,
                ),
                nose_attachment @ nose_shape_transform,
            )
    # nn::mii::GetNoselineColor resolves to the modern Mii feature-line sRGB
    # constant #221817.  NoseLine is a four-vertex carrier quad; mt_NoseLine
    # maps MiiNose06_NoseLine_Msk through _a0 (map_alpha=100) and its mask
    # render state requests coverage >= .5.  The partially resolved GameAll12
    # binary nevertheless omits _a0/KIL and writes alpha=1, proving that an
    # engine override/pass is still missing from the standalone shader view.
    # This explicit texture reject is the source- and screenshot-consistent
    # portable boundary; an untextured interpretation covers the whole quad.
        counts["nose:NoseLine__mt_NoseLine"] = rasterizer.draw_group(
            nose_model,
            "NoseLine__mt_NoseLine",
            MaterialStyle(
                (*_srgb_to_linear(np.asarray((34, 24, 23), dtype=np.float64) / 255.0), 1.0),
                gameall_identity=gameuber_cpu.gameall_program_identity("nose_line", 12),
                alpha_texture=nose_line_mask,
                alpha_wrap=("repeat", "repeat"),
                alpha_mip_filter="point",
                alpha_cutoff=0.5,
                lit=False,
            ),
            nose_attachment @ nose_line_shape_transform,
        )

    # The selected faceline's complete set_beard bind-world transform precedes
    # the Beard resource's own rigid shape bind. Its sole Mim texture is the
    # native occlusion/specular material mask.
    if beard_resource is not None and "beard" in models:
        try:
            beard_shader = BEARD_SHADER_BY_MODEL_RESOURCE[beard_resource]
        except KeyError as error:
            raise ValueError(
                f"no checked GameAll beard selection exists for {beard_resource}"
            ) from error
        beard_material_mask = _material_texture(f"{beard_resource}_Mim")
        beard_shape_transform = _prepared_rigid_shape_binding(
            beard_resource, "Beard__mt_Beard"
        ).matrix
        counts["beard:Beard__mt_Beard"] = rasterizer.draw_group(
            models["beard"],
            "Beard__mt_Beard",
            MaterialStyle(
                beard,
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    "beard_anisotropic", beard_shader.gameall_program
                ),
                occlusion_texture=beard_material_mask,
                occlusion_wrap=("repeat", "repeat"),
                occlusion_channel=0,
                specular_texture=beard_material_mask,
                specular_wrap=("repeat", "repeat"),
                specular_channel=1,
                anisotropic_proxy=True,
                anisotropic_shift_channel=2,
                anisotropic_shift_scale=beard_shader.anisotropic_shift_scale,
                anisotropic_shift_offset=beard_shader.anisotropic_shift_offset,
                anisotropic_specular_size=10.0,
                anisotropic_toon_intensity=0.5,
                anisotropic_title_view_scale=1.0,
                anisotropic_radiance_scale=1.0,
                front_edge_light_proxy=True,
                front_edge_light_view_angle_degrees=65.0,
                front_edge_light_intensity=0.75,
                roughness=0.28,
                linear_lighting=True,
            ),
            head_scene_transform
            @ head_attachments["set_beard"]
            @ beard_shape_transform,
        )

    # When PartsIndex enables a primary glass resource, FUN_7101d6d538 case 1
    # uses set_nose plus the title's explicit Y/Z offsets and CharInfoEx
    # scale/aspect factors. A GlassNothing record never reaches this path.
    # FUN_7101d7daf0 enables every material, then hides Trs for lens material
    # mode 2 or hides Opa for modes 0/1. Mode 0's source-independent uniforms
    # are black/alpha0/decay(1,1,1,0); the exact Trs BFRES state is
    # premultiplied RGB blending with no depth write.
    if glass_resource is not None and "glass" in models:
        if glass_lens_state is None:
            raise RuntimeError("active glass resource has no lens state")
        if (
            glass_frame_program_selection is None
            or glass_lens_program_selection is None
            or glass_frame_program_selection.resource_name != glass_resource
            or glass_lens_program_selection.resource_name != glass_resource
        ):
            raise RuntimeError("active glass draw lacks exact authenticated GameAll selections")
        glass_scale_x = char_info["glass_scale"] * 0.15 + 0.4
        glass_scale_y = glass_scale_x * (char_info["glass_aspect"] * 0.12 + 0.64)
        glass_y_delta = 0.05 + (char_info["glass_y"] - 12) * -0.015
        glass_transform = (
            head_scene_transform
            @ head_attachments["set_nose"]
            @ translation(0.0, glass_y_delta, 0.02)
            @ scale(glass_scale_x, glass_scale_y, glass_scale_x)
        )
        glass_model = models["glass"]
        glass_frame_shape_transform = _prepared_rigid_shape_binding(
            glass_resource, "Flame__mt_Body"
        ).matrix
        counts["glass:Flame__mt_Body"] = rasterizer.draw_group(
            glass_model,
            "Flame__mt_Body",
            MaterialStyle(
                glass,
                gameall_identity=gameuber_cpu.gameall_program_identity(
                    glass_frame_program_selection.family,
                    glass_frame_program_selection.gameall_program,
                ),
                linear_lighting=True,
            ),
            glass_transform @ glass_frame_shape_transform,
        )
        active_lens = str(glass_lens_state["active_lens"])
        if (
            glass_lens_program_selection.shape_name != active_lens
            or glass_lens_program_selection.material_name
            != str(glass_lens_state["active_material"])
        ):
            raise RuntimeError("active Glass lens state differs from its exact GameAll selection")
        if active_lens in glass_model.groups:
            glass_lens_shape_transform = _prepared_rigid_shape_binding(
                glass_resource, active_lens
            ).matrix
            counts[f"glass:{active_lens}"] = rasterizer.draw_group(
                glass_model,
                active_lens,
                MaterialStyle(
                    tuple(glass_lens_state["portable_premultiplied_color"]),
                    gameall_identity=gameuber_cpu.gameall_program_identity(
                        glass_lens_program_selection.family,
                        glass_lens_program_selection.gameall_program,
                    ),
                    normal_texture=glass_normal,
                    normal_wrap=("repeat", "repeat"),
                    alpha_multiplier=float(glass_lens_state["const_single_alpha"]),
                    blend=bool(glass_lens_state["blend"]),
                    premultiplied_rgb_blend=bool(
                        glass_lens_state["premultiplied_rgb_blend"]
                    ),
                    depth_write=bool(glass_lens_state["depth_write"]),
                    # The exact Trs material has alpha testing disabled. Zero
                    # alpha fragments therefore reach its blend operation.
                    alpha_cutoff=0.0,
                ),
                glass_transform @ glass_lens_shape_transform,
            )

    return counts


def _classic_bust_camera(
    profile: dict[str, Any],
    body_pose: PosedModel,
    char_info: dict[str, Any],
) -> dict[str, Any]:
    """Resolve the checked bust crop around the posed semantic Head anchor."""

    base = profile.get("source_backed_base")
    crop = profile.get("fixed_crop")
    tracking = profile.get("portrait_tracking")
    if not all(isinstance(value, dict) for value in (base, crop, tracking)):
        raise ValueError("classic portrait-framing ledger is incomplete")
    if (
        base.get("snapshot") != "EditorMiiPreview"
        or base.get("projection") != "Perspective"
        or tracking.get("applies_to_views") != ["appearance_bust_portrait"]
        or "posed_full_body" not in tracking.get("excluded_views", [])
    ):
        raise ValueError("classic portrait-framing scope changed")

    camera_distance = float(base["focal_plane_distance_z"])
    base_vertical_fov = float(base["vertical_fov_degrees"])
    base_camera_at_y = float(base["camera_at"][1])
    viewport_width, viewport_height = (int(value) for value in crop["base_viewport_size"])
    crop_width, crop_height = (int(value) for value in crop["size"])
    if (
        [viewport_width, viewport_height] != [512, 512]
        or crop["xyxy_exclusive"] != [156, 141, 356, 349]
        or [crop_width, crop_height] != [200, 208]
    ):
        raise ValueError("classic portrait-framing crop changed")

    base_half_height = camera_distance * np.tan(
        np.deg2rad(base_vertical_fov) * 0.5
    )
    vertical_fov = float(
        np.rad2deg(
            2.0
            * np.arctan(
                np.tan(np.deg2rad(base_vertical_fov) * 0.5)
                * (crop_height / viewport_height)
            )
        )
    )
    horizontal_projection_scale = crop_height / crop_width
    calibration_camera_at_y = base_camera_at_y + (
        float(crop["upward_center_shift_pixels"]) / viewport_height
    ) * (2.0 * base_half_height)

    calibration = tracking.get("calibration_char_info")
    if calibration != {"build": 64, "height": 64}:
        raise ValueError("classic portrait-framing calibration CharInfo changed")
    calibration_scale = mii_body_scale(64, 64)
    calibration_head_scene = attached_part_transform(
        body_pose.bone_world["Head"], calibration_scale
    )
    calibration_head_y = float(calibration_head_scene[1, 3])
    camera_offset_y = calibration_camera_at_y - calibration_head_y
    expected_values = (
        (tracking.get("calibration_head_anchor_y"), calibration_head_y),
        (tracking.get("calibration_camera_at_y"), calibration_camera_at_y),
        (tracking.get("camera_at_offset_y"), camera_offset_y),
    )
    if any(
        not isinstance(recorded, (int, float))
        or not np.isclose(float(recorded), derived, rtol=0.0, atol=1e-12)
        for recorded, derived in expected_values
    ):
        raise ValueError("classic portrait-framing calibration no longer derives exactly")
    recorded_scale = np.asarray(tracking.get("calibration_body_scale"), dtype=np.float64)
    if recorded_scale.shape != (3,) or not np.allclose(
        recorded_scale, calibration_scale, rtol=0.0, atol=1e-12
    ):
        raise ValueError("classic portrait-framing calibration body scale changed")

    body_scale = mii_body_scale(char_info["build"], char_info["height"])
    head_scene = attached_part_transform(body_pose.bone_world["Head"], body_scale)
    head_anchor_y = float(head_scene[1, 3])
    camera_at_y = head_anchor_y + camera_offset_y
    half_height = camera_distance * np.tan(np.deg2rad(vertical_fov) * 0.5)
    return {
        "camera_distance": camera_distance,
        "vertical_fov": vertical_fov,
        "horizontal_projection_scale": horizontal_projection_scale,
        "camera_at_y": camera_at_y,
        "bounds": (
            -half_height / horizontal_projection_scale,
            half_height / horizontal_projection_scale,
            camera_at_y - half_height,
            camera_at_y + half_height,
        ),
        "body_scale": body_scale,
        "head_scene": head_scene,
        "tracking_report": {
            "presentation_policy": tracking["classification"],
            "tracking_applied": True,
            "full_body_tracking": False,
            "semantic_anchor": {
                "bone": "Head",
                "source_function": "renderer.model_pose.attached_part_transform",
                "build": int(char_info["build"]),
                "height": int(char_info["height"]),
                "body_scale": np.asarray(body_scale, dtype=np.float64).tolist(),
                "world_y": head_anchor_y,
            },
            "calibration": {
                "build": 64,
                "height": 64,
                "head_anchor_y": calibration_head_y,
                "camera_at_y": calibration_camera_at_y,
                "camera_at_offset_y": camera_offset_y,
            },
            "appearance_pixels_used_for_tracking": False,
        },
    }


def render_view(
    document: dict[str, Any],
    models: dict[str, ObjMesh],
    face_texture: np.ndarray,
    faceline_texture: np.ndarray | None,
    facepaint: ShareMiiV3FacePaint | None,
    asset_root: Path,
    size: int,
    full_body: bool,
    reference_outfit: bool,
    body_pose: PosedModel,
    active_records: dict[str, dict[str, Any]],
    support: RenderSupport,
    supersample_factor: int = 2,
    presentation_context: dict[str, Any] | None = None,
) -> tuple[Image.Image, dict[str, Any]]:
    # InfiniMii's portable classic bridge uses a bust portrait rather than the
    # title's detached-head MiiIcon capture.  This is a presentation/camera
    # choice requested by the site (referenceFraming.png); it does not alter
    # CharInfoEx, Parts selection, geometry, or material inputs.  Fixture
    # renders without an explicit active-parts bridge retain the recovered
    # MiiIcon path byte-for-byte.
    bridge_bust = not full_body and support.classic_bridge_report is not None
    scene_includes_body = full_body or bridge_bust
    # Every production classic-bridge image is an asset for InfiniMii rather
    # than an opaque diagnostic capture. This covers both the bust route and
    # an explicitly requested full-body render. Numbered research fixtures,
    # which do not carry a classic-bridge manifest, retain their existing
    # opaque title-presentation contract.
    transparent_output = support.classic_bridge_report is not None
    horizontal_projection_scale = 1.0
    framing_tracking_report: dict[str, Any] | None = None
    if full_body:
        # GfxSnapshotSetting/EditorMiiPreview uses CameraAt.y=.97,
        # CameraPos.z=9.4, and a 15-degree vertical FOV.  The CPU rasterizer is
        # perspective; the focal-plane envelope below is retained for the
        # report and contains
        # the complete posed assembly (measured y=.0020..1.9458) without the
        # prior hard-coded crop at y=1.46.
        # A world/gameplay camera is not encoded in ShareMii. Until an explicit
        # scene/camera record is supplied, every full-body resource variant uses
        # the exact EditorMiiPreview camera instead of unsupported offsets.
        camera_distance = 9.4
        vertical_fov = 15.0
        camera_at_y = 0.97
        half_height = camera_distance * np.tan(np.deg2rad(vertical_fov) * 0.5)
        bounds = (
            -half_height,
            half_height,
            camera_at_y - half_height,
            camera_at_y + half_height,
        )
        body_scale = mii_body_scale(document["char_info"]["build"], document["char_info"]["height"])
        head_scene = attached_part_transform(body_pose.bone_world["Head"], body_scale)
    elif bridge_bust:
        # Start with the exact EditorMiiPreview focal-plane camera, then apply
        # the requested 208/512 vertical bust crop.  The crop center is 11
        # pixels above the full-body frame center at the checked 64/64
        # calibration. The crop then follows the source-backed posed Head
        # attachment, so CharInfo build/height cannot move the face within the
        # bust. The reference is horizontally tighter (200/512), represented
        # by the camera's independent horizontal projection scale. Expressing
        # both as camera parameters keeps every triangle at native scale; no
        # post-render resize or appearance-derived geometry fitting occurs.
        if support.portrait_framing_profile is None:
            raise ValueError("classic bust render has no checked portrait-framing profile")
        bust_camera = _classic_bust_camera(
            support.portrait_framing_profile,
            body_pose,
            document["char_info"],
        )
        camera_distance = bust_camera["camera_distance"]
        vertical_fov = bust_camera["vertical_fov"]
        horizontal_projection_scale = bust_camera["horizontal_projection_scale"]
        camera_at_y = bust_camera["camera_at_y"]
        bounds = bust_camera["bounds"]
        body_scale = bust_camera["body_scale"]
        head_scene = bust_camera["head_scene"]
        framing_tracking_report = bust_camera["tracking_report"]
    else:
        # GfxSnapshotSetting/MiiIcon: orthographic ProjHeight=1.31 and
        # CameraAt=(0,.45,0), for exact square bounds below.
        bounds = (-0.655, 0.655, -0.205, 1.105)
        head_scene = identity()

    output_width = size
    # Both MiiIcon and EditorMiiPreview explicitly enable IsPfxSSAA.  Render
    # the portable target at twice the output dimensions and resolve once at
    # the end; the title's proprietary resolve kernel is not available.
    if supersample_factor not in (1, 2):
        raise ValueError("supersample_factor must be exactly 1 or 2")
    render_width = output_width * supersample_factor
    render_height = size * supersample_factor
    rasterizer = (
        PerspectiveRasterizer(
            render_width,
            render_height,
            camera_position=(0.0, camera_at_y - 0.01, camera_distance),
            camera_target=(0.0, camera_at_y, 0.0),
            vertical_fov_degrees=vertical_fov,
            horizontal_projection_scale=horizontal_projection_scale,
            linear_framebuffer=True,
            transparent_background=transparent_output,
        )
        if scene_includes_body
        else OrthographicRasterizer(
            render_width, render_height, bounds, linear_framebuffer=True
        )
    )
    rasterizer.light_direction = np.asarray(
        (
            -0.26200262947185154,
            0.6427876055437831,
            0.7198463143679528,
        ),
        dtype=np.float64,
    )
    # SnapshotSetting resolves these values exactly.  The title's full
    # GameUber light/shadow prepass is not portable, so named production draws
    # use a continuous hemispheric response normalized at the front-facing
    # normal.  This portable boundary is recorded in the render report.
    ambient_value = 0.7297400236129761
    # FUN_71017c4cfc performs float32 powf(rgb, 2.200000047683716),
    # luminance/saturation mixing, and AmbientIntensity multiplication before
    # uploading the scene buffer.  EnvMapSaturation=1 makes the Mii defaults
    # the exact float32 reference value below.
    ambient_linear = 0.4999999403953552
    snapshot_light_intensity = 2.5 if scene_includes_body else 6.0
    rasterizer.light_color = np.ones(3, dtype=np.float64)
    rasterizer.light_intensity = snapshot_light_intensity
    rasterizer.ambient_color = np.full(3, ambient_linear, dtype=np.float64)
    rasterizer.ambient_intensity = 1.0
    # This normalization remains part of the anonymous diagnostic Lambert
    # path. Named production draws use the front-normalized hemispheric
    # response documented below: it retains bounded normal-map/fold response
    # without recreating the unsupported hard N.L terminator. The exact title
    # final-radiance buffers remain unavailable, and no reference-image values
    # enter either path.
    rasterizer.light_normalization = float(np.pi)
    applied_light_scope = (
        "every named production material uses a continuous front-normalized hemispheric "
        "response from the recovered Snapshot key/fill/direction while title environment/"
        "material/GlobalUBO/prepass inputs are unavailable; audited GameAll local equations "
        "remain active and hard max(N.L,0) Lambert is anonymous-diagnostic-only"
    )
    rasterizer.specular_intensity = 3.5 if scene_includes_body else 1.0
    if transparent_output:
        # InfiniMii render assets are native transparent render targets.  No
        # presentation matte or ground-shadow pixels are drawn, and the
        # rasterizer accumulates source-over alpha alongside premultiplied RGB.
        # This is deliberately not a post-render chroma key.
        presentation_background = None
    else:
        rasterizer.add_vertical_background_gradient((0.93, 0.97, 1.0), (0.78, 0.87, 0.97))
        if scene_includes_body:
            rasterizer.add_ground_shadow((0.0, 0.02), (0.52, 0.075), 0.20)
        else:
            rasterizer.add_ground_shadow((0.0, -0.16), (0.38, 0.045), 0.10)
        presentation_background = rasterizer.color.copy()
    recorder = DrawRecorder()
    favorite_shirt_selection = favorite_shirt_selection_from_context(
        presentation_context or {}
    )
    # FUN_7101bc6e80 removes inherited body scale from the attached part's
    # 3x3 basis. No recovered call applies a second geometry scale to the Mii
    # head assembly, so every view submits the same unit-scale part geometry.
    view_head_scene = head_scene
    counts = _compose_scene(
        recorder,
        models,
        document["char_info"],
        face_texture,
        faceline_texture,
        facepaint,
        asset_root,
        view_head_scene,
        include_body=scene_includes_body,
        include_reference_outfit=scene_includes_body,
        presentation_variation=support.presentation_variation,
        favorite_shirt_selection=favorite_shirt_selection,
        nose_parallax_height_scale=support.nose_parallax_height_scale,
        active_records=active_records,
        body_pose=body_pose,
        for_hat=bool((presentation_context or {}).get("for_hat")),
        legacy_headwear_selection=support.legacy_headwear_selection,
        body_program_selections=support.body_program_selections,
        outfit_program_selections=support.outfit_program_selections,
        glass_frame_program_selection=support.glass_frame_program_selection,
        glass_lens_program_selection=support.glass_lens_program_selection,
    )
    scheduled_calls, draw_schedule_report = _title_mii_draw_schedule(recorder.calls)
    declared_face_shadow_casters = tuple(
        call for call in scheduled_calls if call.style.casts_face_shadow
    )
    gameall_routing_report = _production_draw_routing_report(scheduled_calls)
    portable_face_shadow = resolve_screen_space_face_visibility(
        availability=TitlePrepassAvailability(
            face_shadow_same_view_projection=True,
        ),
        fragment_shape=(),
    )
    # Keep exact caster/receiver routing as reportable title state, but do not
    # execute a world-space orthographic shadow map. Head816/Nose756/Ear372
    # sample FaceShadowMap through the recovered same-view pass. Its attachment
    # format semantics, sampler-binding join, and constant-buffer upload are not
    # yet authenticated together; absent those inputs, visibility is neutral.
    for call in scheduled_calls:
        rasterizer.draw_group(call.mesh, call.group, call.style, call.transform)
    # GameUber material outputs, blending, and SnapshotPfx operate in a linear
    # working buffer. MiiIcon enables the recovered tone-map specialization;
    # EditorMiiPreview disables it. The title bloom image remains unavailable,
    # so an explicit zero bloom input is supplied rather than inventing a blur.
    if not scene_includes_body:
        display_linear = snapshot_pfx_tone_map_gamma0(rasterizer.color)
        # The gradient and oval ground shadow are explicitly portable
        # presentation elements, not pixels drawn by GfxMiiIcon (DrawSky is
        # false). Keep untouched presentation samples outside the model's
        # z-buffer coverage out of the title tone-map pass.
        if presentation_background is None:
            raise RuntimeError("opaque MiiIcon output is missing its presentation background")
        display_linear[~np.isfinite(rasterizer.depth)] = presentation_background[
            ~np.isfinite(rasterizer.depth)
        ]
    else:
        display_linear = rasterizer.color
    raster_image = rasterizer.image(display_linear)
    if transparent_output:
        # Pillow's RGBa mode is premultiplied-alpha RGBA. Resolve in that mode
        # so Lanczos filtering produces a coverage-correct anti-aliased edge,
        # then return the straight-alpha RGBA required by PNG.
        resolved_image = (
            raster_image.convert("RGBa")
            .resize((output_width, size), Image.Resampling.LANCZOS)
            .convert("RGBA")
            if supersample_factor > 1
            else raster_image
        )
        # RGBa -> RGBA unpremultiplication can leave a few integer-rounding
        # remnants under exactly-zero alpha. Canonicalize only those invisible
        # samples; partially covered anti-aliased pixels remain untouched.
        resolved_pixels = np.asarray(resolved_image, dtype=np.uint8).copy()
        resolved_pixels[resolved_pixels[..., 3] == 0, :3] = 0
        resolved_image = Image.fromarray(resolved_pixels, mode="RGBA")
    else:
        resolved_image = (
            raster_image.resize((output_width, size), Image.Resampling.LANCZOS)
            if supersample_factor > 1
            else raster_image
        )
    return resolved_image, {
        "view": (
            "screenshot_reference_outfit"
            if reference_outfit
            else "posed_full_body" if full_body else "appearance_bust_portrait" if bridge_bust else "appearance_portrait"
        ),
        "world_bounds": list(bounds),
        "size": [output_width, size],
        "supersampling": {
            "setting": "IsPfxSSAA=true",
            "portable_profile": (
                "research-2x-lanczos"
                if supersample_factor == 2
                else "native-resolution-v1"
            ),
            "raster_size": [render_width, render_height],
            "resolve": (
                "portable 2x Lanczos in premultiplied-alpha space; title resolve kernel unavailable"
                if transparent_output and supersample_factor == 2
                else "portable 2x Lanczos; title resolve kernel unavailable"
                if supersample_factor == 2
                else "direct native-resolution portable raster; title SSAA resolve kernel unavailable"
            ),
        },
        "color_pipeline": {
            "working_space": "linear RGB framebuffer; material conversion and blending occur before output transfer",
            "tone_mapping": (
                "exact SnapshotPfx gamma0 MiiIcon curve with zero bloom input"
                if not scene_includes_body
                else "disabled by EditorMiiPreview"
            ),
            "bloom_input": "zero; extraction/pyramid/kernel remain unrecovered",
            "output_transfer": (
                "exact CaptureIcon NVN RGBA8_SRGB (format 0x38): shader gamma0 has no transfer and hardware encodes IEC-sRGB once"
                if not scene_includes_body
                else "portable IEC-sRGB encode once; EditorMiiPreview destination format/transfer remains unproven"
            ),
            "presentation_background": (
                "none; native transparent render target with no matte or ground-shadow presentation pixels"
                if transparent_output
                else "capture-neutral gradient/ground shadow composited outside model coverage after MiiIcon tone mapping; DrawSky=false"
            ),
            "alpha_output": (
                {
                    "png_mode": "RGBA",
                    "storage": "straight alpha",
                    "render_target": "premultiplied linear RGB plus native source-over alpha coverage",
                    "transparent_rgb": [0, 0, 0],
                    "ssaa_resolve": (
                        "2x Lanczos in premultiplied-alpha space"
                        if supersample_factor == 2
                        else "disabled for the native-resolution production latency profile"
                    ),
                    "chroma_key": False,
                }
                if transparent_output
                else None
            ),
        },
        "submitted_triangles": counts,
        "submitted_triangle_total": sum(counts.values()),
        "model_draw_schedule": draw_schedule_report,
        "camera": (
            {
                "snapshot": "MiiIcon",
                "projection": "orthographic",
                "camera_at": [0.0, 0.45, 0.0],
                "camera_distance": 1.0,
                "projection_height": 1.31,
                "near": 0.0,
                "far": 2.0,
            }
            if not scene_includes_body
            else {
                "snapshot": "EditorMiiPreview",
                "projection": "perspective",
                "camera_at": [0.0, camera_at_y, 0.0],
                "camera_position": [0.0, camera_at_y - 0.01, camera_distance],
                "vertical_fov_degrees": vertical_fov,
                "horizontal_projection_scale": horizontal_projection_scale,
                "reference_aspect": None,
                "scope": (
                    "title EditorMiiPreview projection with a user-directed portable crop that follows the source-backed posed Head attachment; referenceFraming.png supplies only the calibrated crop"
                    if bridge_bust
                    else "title EditorMiiPreview setting; external raster supplies no camera constants"
                    if reference_outfit
                    else "title EditorMiiPreview setting"
                ),
                "attached_part_geometry_scale": [1.0, 1.0, 1.0],
                "framing_reference": (
                    {
                        "path": "referenceFraming.png",
                        "reference_size": [512, 512],
                        "equivalent_editor_preview_crop": [156, 141, 356, 349],
                        "horizontal_projection_scale": horizontal_projection_scale,
                        "appearance_pixels_used_for_material_or_geometry": False,
                        "appearance_pixels_used_for_tracking": False,
                    }
                    if bridge_bust
                    else None
                ),
                "framing_contract": (
                    {
                        "path": _logical_path(CLASSIC_BRIDGE_PORTRAIT_FRAMING),
                        "sha256": _sha256(CLASSIC_BRIDGE_PORTRAIT_FRAMING),
                        "schema_version": support.portrait_framing_profile["schema_version"],
                        **(framing_tracking_report or {}),
                    }
                    if bridge_bust
                    else None
                ),
                "title_final_pixel_equivalence_claimed": False,
            }
        ),
        "gameall_local_program_routing": gameall_routing_report,
        "light": {
            "latitude_degrees": 40.0,
            "longitude_degrees": -20.0,
            "intensity": snapshot_light_intensity,
            "shadow_intensity": 1.3 if scene_includes_body else 1.0,
            "specular_intensity": 3.5 if scene_includes_body else 1.0,
            "ambient_color_serialized": [ambient_value, ambient_value, ambient_value, 1.0],
            "ambient_color_light_buffer_linear": [
                ambient_linear,
                ambient_linear,
                ambient_linear,
                1.0,
            ],
            "ambient_upload_formula": "linear=powf(serialized_rgb,2.200000047683716); Y=dot(linear,[.2989119887,.5866109729,.1144779995]); saturated=Y+EnvMapSaturation*(linear-Y); output=saturated*AmbientIntensity",
            "ambient_intensity": 1.0,
            "light_buffer_upload": {
                "key_radiance": [
                    snapshot_light_intensity,
                    snapshot_light_intensity,
                    snapshot_light_intensity,
                    1.0,
                ],
                "direction_to_light": rasterizer.light_direction.tolist(),
                "ambient_rgb": [ambient_linear, ambient_linear, ambient_linear],
                "shadow_scalar": 1.3 if scene_includes_body else 1.0,
                "status": "exact FUN_71017c4cfc upload; downstream GameUber/prepass response remains unavailable",
            },
            "portable_response": {
                "named_production_formula": "local_material_rgb * (A + K * clamp(.5 + .5*dot(N,L),0,1)) / (A + K * clamp(.5 + .5*L.z,0,1)); where A=appliedFill.rgb*fillIntensity and K=appliedKey.rgb*keyIntensity, per channel; denominator<=1e-12 uses identity",
                "diagnostic_unnamed_material_formula": "base * (appliedFill.rgb * fillIntensity + appliedKey.rgb * keyIntensity * max(dot(N,L),0)) / normalization",
                "applied_key_rgb": rasterizer.light_color.tolist(),
                "applied_key_intensity": rasterizer.light_intensity,
                "applied_fill_rgb": rasterizer.ambient_color.tolist(),
                "applied_fill_intensity": rasterizer.ambient_intensity,
                "diagnostic_unnamed_normalization_divisor": rasterizer.light_normalization,
                "named_zero_denominator_fallback": "identity",
                "scope": applied_light_scope,
                "status": "portable continuous front-normalized hemispheric production response; exact title final-radiance inputs remain unavailable and no title-final equivalence is claimed",
                "title_final_pixel_equivalence_claimed": False,
            },
            "front_edge_light_proxy": {
                "environment_rgb_linear": rasterizer.edge_light_color.tolist(),
                "gate": "(NdotV < cos(serialized_degrees)) * max(NdotL,0); NdotV compare is exact, while cosine conversion, missing title light-channel response, and RGB are explicit boundaries",
                "material_scalars": {"hair": 2.5, "beard": 0.75},
                "disabled_known_paths": "Head/Ear also compile a scalar 5 edge path, but their title edge RGB is unavailable; no image-derived substitute is supplied",
            },
            "cheap_sss_title_input": {
                "exact_local_curve": "gameuber_cpu.cheap_sss_local_scatter_816_756_372_348",
                "compiled_programs": [816, 756, 372, 324, 336, 348],
                "execution_status": PORTABLE_CHEAP_SSS_INPUT.status,
                "correction_enabled": PORTABLE_CHEAP_SSS_INPUT.correction_enabled,
                "title_light_input_x": None,
                "missing_inputs": list(PORTABLE_CHEAP_SSS_INPUT.missing_inputs),
                "decoded_head816_interpolation": "base = r29_pre * r30; x = base + gsys_user4.g * (r31_pre - base)",
                "raw_ndotl_substitution": False,
                "boundary": "gsys_light_prepass is sampled and gsys_user4.g participates in the decoded interpolation, but the authenticated prepass value and remaining operands are unavailable",
            },
            "screen_space_face_shadow": {
                "title_object": "ScreenSpaceFaceShadowMap",
                "same_view_target": "FaceShadowMap",
                "exact_title_parameters": {
                    "enable": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.enable,
                    "fade_enable": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.fade_enable,
                    "search_num": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.search_num,
                    "search_length": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.search_length,
                    "softness": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.softness,
                    "center_y": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.center_y,
                    "scale_y": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.scale_y,
                    "depth_offset": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.depth_offset,
                    "fade_start": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.fade_start,
                    "fade_end": TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS.fade_end,
                },
                "source_evidence": {
                    "module": "renderer/screen_space_face_shadow.py",
                    "module_sha256": _sha256(REPOSITORY / "renderer" / "screen_space_face_shadow.py"),
                    "ledger": "renderer/screen_space_face_shadow_source.json",
                    "ledger_sha256": _sha256(REPOSITORY / "renderer" / "screen_space_face_shadow_source.json"),
                },
                "snapshot_setting_shadow_intensity": 1.3 if scene_includes_body else 1.0,
                "actual_execution": portable_face_shadow.execution_enabled,
                "missing_inputs": list(portable_face_shadow.missing_inputs),
                "portable_visibility": float(portable_face_shadow.visibility),
                "portable_applied_opacity": 0.0,
                "source_material_routing": {
                    "caster_render_info": "cast_face_shadow=1",
                    "receiver_shader_option": "enable_screenspace_face_shadow=1",
                    "declared_caster_groups": [
                        call.group for call in declared_face_shadow_casters
                    ],
                    "executed_caster_groups": [],
                    "receiver_groups": [
                        call.group
                        for call in scheduled_calls
                        if call.style.receives_screenspace_face_shadow
                    ],
                    "non_receiver_groups": [
                        call.group
                        for call in scheduled_calls
                        if not call.style.receives_screenspace_face_shadow
                    ],
                },
                "status": portable_face_shadow.status,
                "removed_unsupported_substitute": "world-space orthographic depth map with bias .01, 3x3 PCF, and .35/.45 opacity",
                "scope": "caster/receiver identities, title parameters, same-view target construction, and the Head816 bounded UV/depth search are source-backed; raw format 0x59 semantics, the attachment-to-sampler join, exact cbuf15 uploads, and prepass texels remain unresolved, so no shadow is synthesized",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=REPOSITORY / "mii1.ltd")
    parser.add_argument("--asset-root", type=Path, default=DEFAULT_ASSET_ROOT)
    parser.add_argument(
        "--active-parts",
        type=Path,
        help=(
            "explicit generic PartsIndex manifest; enables fail-closed classic-bridge "
            "resolution by exact active resource signature instead of a fixture SHA"
        ),
    )
    parser.add_argument(
        "--build-active-parts",
        type=Path,
        help=(
            "build the exact active-parts manifest at this path in-process, then "
            "consume it as the classic bridge authority"
        ),
    )
    parser.add_argument(
        "--presentation-context",
        type=Path,
        help=(
            "optional hash-bound stored-source presentation context; this never "
            "changes the LTD or its CharInfoEx selectors"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "diagnostic output directory; use render_all_miis.bat to publish "
            "the canonical face/full-body pair for every numbered input"
        ),
    )
    parser.add_argument("--size", type=int, default=768)
    parser.add_argument(
        "--supersample-factor",
        type=int,
        choices=(1, 2),
        default=2,
        help=(
            "portable raster scale; 2 preserves the research capture profile, "
            "while 1 is the native-resolution production latency profile"
        ),
    )
    parser.add_argument(
        "--view",
        choices=("portrait", "full-body", "reference-outfit", "both", "all"),
        default="all",
    )
    args = parser.parse_args()
    if args.active_parts is not None and args.build_active_parts is not None:
        parser.error("--active-parts and --build-active-parts are mutually exclusive")
    if args.size < 128:
        parser.error("--size must be at least 128")
    if args.output_dir.is_symlink():
        parser.error("--output-dir must not be a symlink")
    if args.output_dir.exists():
        if not args.output_dir.is_dir():
            parser.error("--output-dir must be a directory")
        if any(args.output_dir.iterdir()):
            parser.error(
                "--output-dir must be empty; final publication is owned by "
                "tools/render_final_outputs.py"
            )

    if args.build_active_parts is not None:
        active_output = args.build_active_parts.resolve()
        if active_output.exists() or active_output.is_symlink():
            parser.error("--build-active-parts destination must not already exist")
        if not active_output.parent.is_dir():
            parser.error("--build-active-parts parent directory is missing")
        if str(REPOSITORY) not in sys.path:
            sys.path.insert(0, str(REPOSITORY))
        from tools.build_mii_active_parts import build_manifest, serialized

        active_output.write_bytes(serialized(build_manifest(args.input.resolve())))
        args.active_parts = active_output

    document = load_share_mii(args.input)
    raw_char_info = document["char_info"]
    # The generated profile is bundle-hash-bound runtime evidence.  Only its
    # generator checks the original local Ryujinx configuration; deployed
    # rendering must not depend on that workstation-only source file.
    classic_runtime_profile = load_checked_runtime_profile(
        validate_runtime_source=False
    )
    normalized_char_info, char_info_normalization = effective_char_info(
        raw_char_info, classic_runtime_profile
    )
    document["char_info"] = normalized_char_info
    presentation_context = _load_presentation_context(
        args.presentation_context,
        document,
    )
    facepaint = decode_share_mii_v3_facepaint(document)
    active_parts_manifest, active_records = _load_active_parts(
        document,
        args.active_parts,
        char_info_normalization,
    )
    active_parts_path = REPOSITORY / active_parts_manifest["manifest_path"]
    support = _resolve_render_support(
        document,
        active_parts_manifest,
        active_records,
        classic_bridge=args.active_parts is not None,
        presentation_context=presentation_context,
    )
    material_texture_cache_report = _configure_material_texture_caches(
        document, active_parts_path, support
    )
    presentation_outfit, presentation_profile = _load_presentation_outfit_profile(
        document, support
    )
    # Authenticate the complete source-BNTX and decoded-level inventory before
    # any draw can consume a reference-outfit texture.
    presentation_texture_records = _reference_outfit_texture_mip_inventory()
    presentation_texture_mips = _cached_load_json(REFERENCE_OUTFIT_TEXTURE_MIPS)
    favorite_shirt_report = presentation_context["favorite_shirt"]
    _bind_favorite_shirt_mip_provenance(
        favorite_shirt_report, presentation_texture_records
    )
    presentation_inactive_alpha_masks = {
        "tops_body": _presentation_inactive_alpha_mask_evidence(
            "ClothTopsTshirtLongTexDefault_Body_Msk",
            "ClothTopsTshirtLong",
            support.outfit_program_selections["tops"],
        ).report,
        "bottoms_body": _presentation_inactive_alpha_mask_evidence(
            "ClothBottomsPantsLongTexDefault_Body_Msk",
            "ClothBottomsPantsLong",
            support.outfit_program_selections["bottoms"],
        ).report,
    }
    face_mask_position_map = load_face_mask_position_map(
        _faceline_position_map_index(active_records)
    )
    face_mask_lattice = build_face_mask_lattice_mesh(face_mask_position_map)
    mask_projection_report = face_mask_projection_report(
        face_mask_position_map, face_mask_lattice
    )
    # The projection manifest's forensic example is MiiHead00. Replace that
    # example in this target report with the exact selected faceline resource;
    # the position map remains a CPU anchor source, never substitute geometry.
    mask_projection_report.pop("final_mask_draw", None)
    mask_projection_report["path"] = _logical_path(face_mask_position_map.path)
    mask_projection_report["runtime_role"] = (
        "CPU bilinear/nearest-valid RGBA16F position lookup for 3D attachment anchors"
    )
    mask_projection_report["runtime_consumer"] = "0x7101b7b0d0"
    mask_projection_report["worker_callers"] = ["0x7101b7f15c", "0x7101b7f284"]
    head_resource = _active_model_resource(active_records, "faceline")
    if head_resource is None:
        raise ValueError("active-parts manifest does not resolve a faceline model")
    mask_shape = _prepared_shape(head_resource, "Mask__mt_Mask")
    mask_projection_report["final_mask_geometry"] = {
        "resource": head_resource,
        "shape": "Mask__mt_Mask",
        "vertices": int(mask_shape["VertexCount"]),
        "indices": int(mask_shape["IndexCount"]),
        "triangles": int(mask_shape["IndexCount"]) // 3,
        "position_texture_used_as_geometry": False,
    }
    texture_root = args.asset_root / "textures_png" / "1" / "Tex" / "Pack"
    face_image, face_report = compose_face_texture(
        document["char_info"],
        texture_root,
        COLOR_TABLE,
        resolution=MII_ICON_MASK_RESOLUTION,
        active_parts_path=active_parts_path,
        face_sprite_mip_manifests=support.face_sprite_mip_manifests,
        classic_resource_signature_records=support.classic_resource_signature_records,
    )
    face_layers, face_layers_report = compose_face_texture(
        document["char_info"],
        texture_root,
        COLOR_TABLE,
        resolution=MII_ICON_MASK_RESOLUTION,
        transparent_base=True,
        active_parts_path=active_parts_path,
        face_sprite_mip_manifests=support.face_sprite_mip_manifests,
        classic_resource_signature_records=support.classic_resource_signature_records,
    )
    faceline_result = (
        compose_faceline_target(
            document["char_info"],
            active_parts_path,
            COLOR_TABLE,
            share_mii_sha256=document["sha256"],
            contract_key=support.faceline_contract,
            classic_resource_signature_records=support.classic_resource_signature_records,
        )
        if (
            document["sha256"] in SOURCE_BACKED_FACELINE_TARGETS
            or support.faceline_contract is not None
        )
        else None
    )
    faceline_texture = (
        texture_from_image(faceline_result.image)
        if faceline_result is not None
        else None
    )
    hair_model_selections = _active_hair_model_selections(
        active_records,
        document["char_info"],
        for_hat=bool(presentation_context["for_hat"]),
    )
    hair_selection_by_key = {
        selection.model_key: selection for selection in hair_model_selections
    }
    models = _load_models(
        active_records,
        hair_model_selections,
        support.legacy_headwear_selection,
    )
    models["face_mask"] = models["head"]
    hair_resources = tuple(
        (selection.model_key, selection.resource_name)
        for selection in hair_model_selections
    )
    hair_poses: dict[str, PosedModel] = {}
    for model_key, hair_resource in hair_resources:
        hair_model_selection = hair_selection_by_key[model_key]
        posed = pose_model(
            models[model_key],
            MODEL_CACHE / hair_resource / "bfres.json",
            model_index=hair_model_selection.model_index,
        )
        models[model_key] = posed.mesh
        hair_poses[model_key] = posed
    body_pose = pose_model(
        models["body"],
        MODEL_CACHE / "BodyBaseDefault" / "bfres.json",
        ICON_POSE,
    )
    models["body"] = body_pose.mesh
    reference_top_pose = pose_model(
        models["reference_top"],
        MODEL_CACHE / "ClothTopsTshirtLong" / "bfres.json",
        ICON_POSE,
    )
    models["reference_top"] = reference_top_pose.mesh
    reference_shoes_pose = pose_model(
        models["reference_shoes"],
        MODEL_CACHE / "ClothShoesStandard" / "bfres.json",
        ICON_POSE,
    )
    models["reference_shoes"] = reference_shoes_pose.mesh
    presentation_bottoms_pose = pose_model(
        models["presentation_bottoms"],
        MODEL_CACHE / "ClothBottomsPantsLong" / "bfres.json",
        ICON_POSE,
    )
    models["presentation_bottoms"] = presentation_bottoms_pose.mesh
    args.output_dir.mkdir(parents=True, exist_ok=True)
    face_path = args.output_dir / "mii_face_atlas.png"
    mesh_face_path = args.output_dir / "mii_face_mesh_input.png"
    face_image.save(face_path)
    face_layers.save(mesh_face_path)

    outputs: list[dict[str, Any]] = []
    requested = (
        ("portrait", "full-body", "reference-outfit")
        if args.view == "all"
        else ("portrait", "full-body") if args.view == "both" else (args.view,)
    )
    for view in requested:
        reference_outfit = view == "reference-outfit"
        full_body = view in {"full-body", "reference-outfit"}
        image, view_report = render_view(
            document,
            models,
            texture_from_image(face_layers),
            faceline_texture,
            facepaint,
            args.asset_root,
            args.size,
            full_body,
            reference_outfit,
            body_pose,
            active_records,
            support,
            args.supersample_factor,
            presentation_context,
        )
        filename = (
            "mii_reference_outfit.png"
            if reference_outfit
            else "mii_full_body.png" if full_body else "mii.png"
        )
        output = args.output_dir / filename
        image.save(output, optimize=True)
        view_report.update({"path": filename, "sha256": _sha256(output)})
        outputs.append(view_report)

    nose_resource = _active_model_resource(active_records, "nose")
    ear_resource = _active_model_resource(active_records, "ear")
    beard_resource = _active_model_resource(active_records, "beard")
    glass_resource = _active_model_resource(active_records, "glass_primary")
    hair_shaders = {
        resource: _select_hair_shader(
            resource,
            model_name=hair_selection_by_key[model_key].model_name,
        )
        for model_key, resource in hair_resources
    }
    report_colors = _cached_load_json(COLOR_TABLE)
    hair_decorations: dict[str, dict[str, Any]] = {}
    for model_key, resource in hair_resources:
        hair_model_selection = hair_selection_by_key[model_key]
        if "Decoration__mt_Decoration" not in models[model_key].groups:
            continue
        selection = _select_decoration_shader(
            resource, model_name=hair_model_selection.model_name
        )
        state = _decoration_runtime_state(document["char_info"], report_colors)
        skin_count = int(
            _prepared_shape(
                resource,
                "Decoration__mt_Decoration",
                hair_model_selection.model_index,
            )["VertexSkinCount"]
        )
        hair_decorations[resource] = {
            "material": "mt_Decoration",
            "draw_order": "before Hair__mt_Hair (exact primary BFRES shape order)",
            "gameall_program": selection.gameall_program,
            "vertex_skin_count": selection.vertex_skin_count,
            "vertex_instructions_sha256": selection.vertex_instructions_sha256,
            "fragment_instructions_sha256": selection.fragment_instructions_sha256,
            "occlusion_mask": f"{resource}_Mim / _o0 / native R",
            "runtime_color": state,
            "local_base": "Decoration480/492 mii_constant_color0 identity base",
            "model_selection": hair_model_selection.report(),
            "rigid_shape_bind": (
                _prepared_rigid_shape_report(
                    resource,
                    "Decoration__mt_Decoration",
                    hair_model_selection.model_index,
                )
                if skin_count == 0
                else None
            ),
            "skinned_shape_pose": (
                _prepared_skinned_shape_report(
                    resource,
                    "Decoration__mt_Decoration",
                    hair_model_selection.model_index,
                )
                if skin_count > 0
                else None
            ),
        }
    active_program_ledger = support.active_program_ledger
    nose_has_surface = (
        nose_resource is not None
        and "nose" in models
        and "Nose__mt_Nose" in models["nose"].groups
    )
    nose_has_line = (
        nose_resource is not None
        and "nose" in models
        and "NoseLine__mt_NoseLine" in models["nose"].groups
    )

    def hair_anisotropic_report(resource: str) -> dict[str, Any]:
        selection = hair_shaders[resource]
        if selection.use_hair612_anisotropic_proxy:
            return {
                "status": (
                    f"GameAll {selection.gameall_program} exact Hair612-family local kernel "
                    "with portable title-radiance proxy"
                ),
                "exact_local_kernel": (
                    "shifted-bitangent exponential kernel from gameuber_cpu.py, "
                    "selected only for an instruction-audited fragment family"
                ),
                "roughness": 0.28,
                "aniso_specular_size": 10.0,
                "mim_channels": "G=specular mask, B=anisotropic shift",
                "runtime_inputs_not_captured": [
                    "aniso_shift_scale",
                    "aniso_shift_offset",
                    "toon_specular_intensity",
                    "title_view_scale",
                    "title light records",
                ],
                "portable_proxy_inputs": {
                    "aniso_shift_scale": 1.0,
                    "aniso_shift_offset": 0.0,
                    "toon_specular_intensity": 1.0,
                    "title_view_scale": 1.0,
                    "radiance": "portable single SnapshotSetting key",
                    "reference_capture_final_radiance_scale": None,
                },
            }
        return {
            "status": f"no cross-program anisotropic proxy applied to GameAll {selection.gameall_program}",
            "reason": (
                "the selected program's exact local base scope is recorded, but its runtime "
                "environment/radiance inputs are unavailable; Hair612 constants are not borrowed"
            ),
            "portable_proxy_inputs": None,
        }

    resolved_parts = _resolved_parts_report(active_records)
    resolved_parts["faceline"]["position_texture"] = face_mask_position_map.texture_name

    active_material_path: dict[str, Any] = {
        "body_default": {
            "materials": ["mt_Tops", "mt_Bottoms", "mt_Socks"],
            "gameall_programs_by_group": {
                group: selection.report()
                for group, selection in sorted(support.body_program_selections.items())
            },
            "program_group_inventory": {
                str(program): sorted(
                    group
                    for group, selection in support.body_program_selections.items()
                    if selection.gameall_program == program
                )
                for program in (324, 336, 348)
            },
            "textures": "BodyBaseDefault_{Tops,Bottoms,Socks}_{Alb,Nrm,Skm,Mic}",
            "replace_albedo_shader_option": True,
            "replace_albedo_color": [0.0, 0.0, 0.0, 0.0],
            "replace_albedo_effect": "no-op; alpha is zero and no active runtime binder write was found",
            "local_shader_execution": "exact skin-count-selected GameAll 324/336/348 programs share the audited Body fragment family; its local surface is evaluated per fragment from raw Alb/Skm/Mic and face color",
            "base_formula": "mix(mii_face_color.linear, Alb.hardware_srgb_sample_linear, Skm.g)",
            "roughness_formula": "mix(Mic.r, const_single_roughness, 1-Skm.g)",
            "const_single_metalness": 1.0,
            "const_single_roughness": 0.75,
        },
        "presentation_outfit": {
            "selection_kind": "renderer presentation preset; ShareMii has no clothing selector",
            "favorite_shirt": presentation_context["favorite_shirt"],
            "tops": {
                "resource": "ClothTopsTshirtLong",
                "material": "mt_Body",
                "gameall_program": support.outfit_program_selections["tops"].gameall_program,
                "albedo": (
                    presentation_context["favorite_shirt"]["source_albedo"]
                    if presentation_context["favorite_shirt"]["status"] == "active"
                    else f"ClothTopsTshirtLongTexDefault_Body_Alb.{support.presentation_variation:02d}"
                ),
                "albedo_source_bntx_sha256": presentation_context["favorite_shirt"].get(
                    "source_bntx_sha256"
                ),
                "albedo_mip_chain_sha256": presentation_context["favorite_shirt"].get(
                    "source_mip_chain_sha256"
                ),
                "albedo_mip_chain_hash_scope": presentation_context["favorite_shirt"].get(
                    "source_mip_chain_hash_scope"
                ),
                "normal": "ClothTopsTshirtLongTexDefault_Body_Nrm (unchanged)",
                "material_information": "ClothTopsTshirtLongTexDefault_Body_Mic (unchanged)",
                "serialized_alpha_mask": "inactive in selected GameAll 984; not sampled",
                "presentation_profile_variation_used_for_policy": False,
            },
        },
        "head": {
            "resource": head_resource,
            "material": "mt_Head",
            "gameall_program": 816,
            "named_texcoords": _prepared_head_named_texcoord_report(head_resource),
            "active_texcoord_bindings": {
                "texture": "_u0" if faceline_result is not None else None,
                "normal": "_u2",
            },
            "program_evidence": {
                "path": _logical_path(active_program_ledger),
                "sha256": _sha256(active_program_ledger),
            },
            "normal_height": f"{head_resource}_Head_Nmh",
            "normal_channels": "R/A",
            "albedo_slot": "_a0",
            "generated_faceline_target": (
                {
                    "status": faceline_result.report["status"],
                    "dimensions": faceline_result.report["dimensions"],
                    "stored_rgba_sha256": faceline_result.report[
                        "stored_rgba_sha256"
                    ],
                    "stored_hash_scope": faceline_result.report[
                        "stored_hash_scope"
                    ],
                    "binding": faceline_result.report["target_binding"],
                    "mask_user0_binding": faceline_result.report[
                        "mask_user0_binding"
                    ],
                }
                if faceline_result is not None
                else None
            ),
            "local_base_formula": (
                "sample(_a0, uv).rgb through the generated target's sRGB view"
                if faceline_result is not None
                else "constant skin-color fallback; no generated _a0 target is sampled"
            ),
            "albedo_sampler": "mirror U, repeat V, linear min/mag, point mip",
            "cheap_sss_execution": {
                "status": PORTABLE_CHEAP_SSS_INPUT.status,
                "correction_enabled": PORTABLE_CHEAP_SSS_INPUT.correction_enabled,
                "raw_ndotl_substitution": False,
                "scope": "Head816 compiled curve is retained as program identity, but correction is disabled for both generated-_a0 and constant-skin paths until gsys_light_prepass and the gsys_user4.g interpolation inputs are authenticated",
            },
            "portable_boundary": (
                "generated _a0 equation, binding, sampler mode, transform, and mip are source-backed; "
                "CPU filter quantization is portable, while title frame/environment/prepass buffers "
                "and final lighting remain unresolved"
                if faceline_result is not None
                else "no complete generated-faceline target contract is active for this ShareMii"
            ),
            "rigid_shape_bind": _prepared_rigid_shape_report(
                head_resource, "Head__mt_Head"
            ),
        },
        "face_mask": {
            "material": "mt_Mask",
            "gameall_program": 0,
            "program_evidence": {
                "path": _logical_path(active_program_ledger),
                "sha256": _sha256(active_program_ledger),
            },
            "shader_archive": "GameUber",
            "shading_model": "GameAll",
            "albedo_slot": "_a0",
            "generated_target": "mask 256x256",
            "faceline_target": "separate 128x256 Head _a0 target; never a Mask0 input",
            "target_source": (
                "GfxMiiIcon directly uses the built-in manager descriptors at "
                "+0x100/+0x428; it does not request a pooled or dynamic tier"
            ),
            "position_texture": face_mask_position_map.texture_name,
            "position_decode": "RGBA16F",
            "position_texture_role": "CPU attachment-anchor lookup; not bound by mt_Mask",
            "geometry": {
                "resource": head_resource,
                "shape": "Mask__mt_Mask",
                "vertices": int(mask_shape["VertexCount"]),
                "indices": int(mask_shape["IndexCount"]),
                "triangles": int(mask_shape["IndexCount"]) // 3,
                "rigid_shape_bind": _prepared_rigid_shape_report(
                    head_resource, "Mask__mt_Mask"
                ),
            },
            "sampler": "repeat U/V, linear min/mag, point mip, 1:1 anisotropy",
            "render_state": "two-sided, depth lequal/write, alpha gequal 0.5, blending disabled",
            "user_albedo_slot": "_user0" if facepaint is not None else "Dummy_Alb",
            "tex_mtx_user0": (
                facepaint.report["tex_mtx_user0"] if facepaint is not None else None
            ),
            "coverage_proxy": (
                "generated _a0 alpha OR sampled UGC _user0 alpha, threshold 0.5; "
                "portable unresolved-pass proxy, not literal GameAll0 alpha"
                if facepaint is not None
                else "reject generated _a0 alpha below 0.5 before portable GameAll shading"
            ),
            "local_albedo": (
                "exact GameAll0 equation k=max(A.a-min(U.a,const_single0),0), "
                "under=mix(U.rgb,U.a*C.rgb,C.a), rgb=mix(under,A.rgb,k); "
                "renderer uses the source-backed constructor endpoint const_single0=0; "
                "the character source +0xa0 -> desired +0x150 -> active +0xa8 -> renderer +0xf84 "
                "imported-record override chain is proven, but its v3 input write is unresolved; "
                "C=replace_albedo_color=(0,0,0,0), inputs remain independent"
                if facepaint is not None
                else "mix(Dummy_Alb.sRGB-decoded #808080, generated _a0.rgb, _a0.a) with const_single0=0, replace_albedo_color=(0,0,0,0), and no UGC"
            ),
            "ordinary_emission": "exact local term 0.1 * _a0.rgb * _a0.a, added after portable lighting",
            "const_single0_runtime_state": (
                "source-backed constructor endpoint zero; "
                "sync_mii_character_data_and_refresh_render_models (0x7100de5090), "
                "commit_mii_renderer_staging_state (0x7101bcffd4), and "
                "apply_mii_model_ugc_texture_state (0x7101bd62c8) prove the "
                "imported override chain from character source +0xa0 to renderer "
                "+0xf84, but no ShareMii-v3 write to source +0xa0 is recovered."
                if facepaint is not None
                else "exact constructor/no-UGC path remains zero"
            ),
            "program0_audit_note": "unique GameAll 0 exports alpha 1 with no KIL, which contradicts the transparent RT clear, visible identity-space Mask extent, BFRES cutout state, and title output; the cutoff is a necessary missing engine/pass-override emulation boundary, not a claimed shader output",
        },
        "hair": [
            {
                "model_key": model_key,
                "resource": resource,
                "model_selection": hair_selection_by_key[model_key].report(),
                "material": "mt_Hair",
                "gameall_program": hair_shaders[resource].gameall_program,
                "program_model_name": hair_shaders[resource].model_name,
                "program_evidence": {
                    "path": _logical_path(hair_shaders[resource].evidence_path),
                    "sha256": _sha256(hair_shaders[resource].evidence_path),
                    "exact_local_scope": hair_shaders[resource].exact_local_scope,
                    "disabled_local_scope": hair_shaders[
                        resource
                    ].disabled_local_scope,
                    "fragment_instructions_sha256": hair_shaders[
                        resource
                    ].fragment_instructions_sha256,
                },
                "alpha": (
                    f"{resource}_Msk / _alp0 / gequal 0.5"
                    if _material_texture_is_available(f"{resource}_Msk")
                    else None
                ),
                "normal": (
                    (
                        f"{resource}_Nrm / _n0 / BC5_SNORM RG; "
                        "Z=sqrt(saturate(1-R^2-G^2))"
                        if hair_shaders[resource].gameall_program == 1116
                        else f"{resource}_Nrm / _n0"
                    )
                    if _material_texture_is_available(f"{resource}_Nrm")
                    else None
                ),
                "occlusion_and_specular_mask": (
                    f"{resource}_Mim / _o0 / native R=occlusion, G=specular"
                ),
                "gradient": {
                    "texture": (
                        None
                        if hair_shaders[resource].use_constant_hair_color_linear
                        else (
                            f"{resource}_Mgh / _user1 / native R,G"
                            if hair_shaders[resource].use_hair708_face_gradient
                            else f"{resource}_Mgh / _user1 / native R"
                        )
                    ),
                    "formula": (
                        "mii_hair_color0.linear.rgb (identity; no MGH sample or power)"
                        if hair_shaders[resource].use_constant_hair_color_linear
                        else (
                            "endpoint=mix(mii_hair_color_srgb0, mii_hair_color_srgb1, "
                            "Mgh.r); mixed=mix(endpoint, mii_face_color.linear, Mgh.g); "
                            "pow(abs(mixed), 2.2)"
                            if hair_shaders[resource].use_hair708_face_gradient
                            else "mix(mii_hair_color_srgb0, mii_hair_color_srgb1, "
                            "Mgh.r), then pow(abs(rgb), 2.2)"
                        )
                    ),
                    "execution_scope": hair_shaders[resource].exact_local_scope,
                    "disabled_scope": hair_shaders[resource].disabled_local_scope,
                    "primary_color_index": document["char_info"]["hair_color_primary"],
                    "stored_secondary_color_index": document["char_info"]["hair_color_secondary"],
                    "dual_color_flag": (
                        "bangs_dual_color"
                        if model_key == "hair_front"
                        else "back_dual_color"
                    ),
                    "dual_color_enabled": document["char_info"]["face_flags"][
                        "bangs_dual_color"
                        if model_key == "hair_front"
                        else "back_dual_color"
                    ],
                    "effective_secondary_color_index": (
                        document["char_info"]["hair_color_secondary"]
                        if document["char_info"]["face_flags"][
                            "bangs_dual_color"
                            if model_key == "hair_front"
                            else "back_dual_color"
                        ]
                        else document["char_info"]["hair_color_primary"]
                    ),
                },
                "anisotropic_specular": hair_anisotropic_report(resource),
                "decoration": hair_decorations.get(resource),
                "rigid_shape_bind": (
                    _prepared_rigid_shape_report(
                        resource,
                        "Hair__mt_Hair",
                        hair_selection_by_key[model_key].model_index,
                    )
                    if int(
                        _prepared_shape(
                            resource,
                            "Hair__mt_Hair",
                            hair_selection_by_key[model_key].model_index,
                        )["VertexSkinCount"]
                    ) == 0
                    else None
                ),
                "skinned_shape_pose": (
                    _prepared_skinned_shape_report(
                        resource,
                        "Hair__mt_Hair",
                        hair_selection_by_key[model_key].model_index,
                    )
                    if int(
                        _prepared_shape(
                            resource,
                            "Hair__mt_Hair",
                            hair_selection_by_key[model_key].model_index,
                        )["VertexSkinCount"]
                    ) > 0
                    else None
                ),
            }
            for model_key, resource in hair_resources
        ],
    }
    if support.legacy_headwear_selection is not None:
        legacy_headwear_report = support.legacy_headwear_selection.report()
        active_material_path["legacy_headwear"] = {
            **legacy_headwear_report,
            "loaded": True,
            "rendered": True,
            "draw_key": (
                "legacy_headwear:"
                f"{support.legacy_headwear_selection.shape_name}"
            ),
            "base_color_formula": (
                "hardware_srgb_decode(sample(_a0).rgb); "
                "replace_albedo_color alpha is zero, so no tint is applied"
            ),
            "normal_formula": (
                "decode signed BC5 _n0.xy; reconstruct "
                "z=sqrt(max(1-x*x-y*y,0)); normalize through authored TBN"
            ),
            "roughness_formula": (
                "sample native Mic.B through the byte-equivalent cached PNG channel 0"
            ),
        }
    if nose_resource is not None:
        active_material_path["nose"] = {
            "resource": nose_resource,
            "material": "mt_Nose" if nose_has_surface else None,
            "gameall_program": 756 if nose_has_surface else None,
            "surface_present": nose_has_surface,
            "height": (
                f"{nose_resource}_Hgt / _user0 / native R / exact parallax scale "
                f"{support.nose_parallax_height_scale:g}"
                if nose_has_surface
                else None
            ),
            "parallax_height_scale": (
                support.nose_parallax_height_scale if nose_has_surface else None
            ),
            "specular_mask": (
                f"{nose_resource}_Mim / _s0 / native G"
                if nose_has_surface
                else None
            ),
            "line": {
                "present": nose_has_line,
                "color": "solid nn::mii nose-line color #221817 on passing pixels",
                "coverage": f"{nose_resource}_NoseLine_Msk / _a0 / native replicated R / gequal 0.5",
                "portable_boundary": "sample _a0.r and reject below 0.5; required by the BFRES binding/state and observed title output",
                "program12_contradiction": "partial resolver program 12 has no _a0 or KIL and writes alpha=1, so a missing runtime override/pass must consume the bound mask",
            },
            "line_gameall_program": 12,
            "rigid_shape_binds": {
                "surface": (
                    _prepared_rigid_shape_report(nose_resource, "Nose__mt_Nose")
                    if nose_has_surface
                    else None
                ),
                "line": _prepared_rigid_shape_report(
                    nose_resource, "NoseLine__mt_NoseLine"
                ),
            },
        }
    if ear_resource is not None:
        active_material_path["ear"] = {
            "resource": ear_resource,
            "material": "mt_Ear",
            "gameall_program": 372,
            "textures": [],
            "rigid_shape_bind": _prepared_rigid_shape_report(
                ear_resource, "Ear__mt_Ear"
            ),
            "program_evidence": {
                "vertex_instructions_sha256": (
                    "8cda33ed6bf58dc7dfefb573c67bf0d9b7c390a0c53cd22599c1aea9dfba3d03"
                ),
                "fragment_instructions_sha256": (
                    "b0eb2d9efe841233f7a8f427e413a883510d6f39c3818da424a085bd4aa5dd5c"
                ),
            },
            "loaded": True,
            "rendered": True,
        }
    if beard_resource is not None:
        beard_shader = BEARD_SHADER_BY_MODEL_RESOURCE[beard_resource]
        active_material_path["beard"] = {
            "resource": beard_resource,
            "material": "mt_Beard",
            "gameall_program": beard_shader.gameall_program,
            "fragment_instructions_sha256": (
                beard_shader.fragment_instructions_sha256
            ),
            "occlusion_and_specular_mask": (
                f"{beard_resource}_Mim / _o0 / native R=occlusion, G=specular"
            ),
            "anisotropic_specular": {
                "exact_local_kernel": "Hair612/Beard456/468 shifted-bitangent exponential kernel from gameuber_cpu.py",
                "roughness": 0.28,
                "aniso_specular_size": 10.0,
                "aniso_shift_offset": beard_shader.anisotropic_shift_offset,
                "toon_specular_intensity": 0.5,
                "portable_proxy_inputs": {
                    "aniso_shift_scale": beard_shader.anisotropic_shift_scale,
                    "title_view_scale": 1.0,
                    "radiance": "portable single SnapshotSetting/capture-profile key",
                    "reference_capture_final_radiance_scale": None,
                },
            },
        }
    if glass_resource is not None:
        if (
            support.glass_frame_program_selection is None
            or support.glass_lens_program_selection is None
        ):
            raise RuntimeError("active Glass report lacks authenticated GameAll selections")
        glass_lens_state = _glass_lens_runtime_state(
            document["char_info"], _cached_load_json(COLOR_TABLE)
        )
        active_lens = str(glass_lens_state["active_lens"])
        active_lens_material = str(glass_lens_state["active_material"])
        active_lens_program = _resolved_material_program(
            active_program_ledger,
            glass_resource,
            active_lens,
            active_lens_material,
        )
        classic_glass_scope = (
            support.classic_bridge_report.get("portable_scope", {}).get("glass")
            if support.classic_bridge_report is not None
            else None
        )
        portable_boundary = (
            classic_glass_scope.get("portable_execution")
            if isinstance(classic_glass_scope, dict)
            else (
                "submit the exact active lens geometry, visibility, mode-independent uniforms, "
                "and BFRES blend/depth state; unrecovered GameAll environment/reflection inputs "
                "are zeroed, so no title-final reflected radiance is claimed"
            )
        )
        active_material_path["glass"] = {
            "resource": glass_resource,
            "frame": "Flame__mt_Body",
            "frame_resolved_title_gameall_program": (
                support.glass_frame_program_selection.gameall_program
            ),
            "frame_program_selection": support.glass_frame_program_selection.report(),
            "active_program_ledger_frame_resolved_program": _resolved_material_program(
                active_program_ledger,
                glass_resource,
                "Flame__mt_Body",
                "mt_Body",
            ),
            "material_mode_field": glass_lens_state["material_mode_field"],
            "material_mode": glass_lens_state["material_mode"],
            "lens_color_field": glass_lens_state["lens_color_field"],
            "lens_color_index": glass_lens_state["lens_color_index"],
            "active_lens": active_lens,
            "active_lens_material": active_lens_material,
            "hidden_lens": glass_lens_state["hidden_lens"],
            "normal": (
                f"{glass_resource}_Nrm / _n0"
                if _material_texture_is_available(f"{glass_resource}_Nrm")
                else None
            ),
            "frame_color_index": document["char_info"]["glass_primary_color"],
            "uniforms": {
                "const_color_albedo": list(glass_lens_state["const_color_albedo"]),
                "const_single_alpha": glass_lens_state["const_single_alpha"],
                "glass_decay_color": list(glass_lens_state["glass_decay_color"]),
                "raw_opacity": glass_lens_state["raw_opacity"],
                "portable_premultiplied_color": list(
                    glass_lens_state["portable_premultiplied_color"]
                ),
                "system_parameter_independent": glass_lens_state[
                    "system_parameter_independent"
                ],
                "system_parameters": glass_lens_state["system_parameters"],
            },
            "render_state": {
                "alpha_test": glass_lens_state["alpha_test"],
                "depth_write": glass_lens_state["depth_write"],
                "rgb_blend": (
                    "src=one, dst=one_minus_src_alpha, op=add"
                    if glass_lens_state["premultiplied_rgb_blend"]
                    else "disabled"
                ),
                "cpu_alpha_target_boundary": (
                    (
                        "classic-bridge presentation framebuffer stores premultiplied RGB plus "
                        "portable source-over coverage alpha; active lens alpha contributes to "
                        "RGBA output, while exact Trs alpha-target blend factors remain "
                        "ledger-recorded and are not claimed exact"
                    )
                    if support.classic_bridge_report is not None
                    else (
                        "numbered-fixture presentation framebuffer stores RGB only; exact Trs "
                        "alpha-target factors are recorded in the program ledger but do not "
                        "produce an output alpha channel"
                    )
                ),
            },
            "resolved_title_gameall_program": (
                support.glass_lens_program_selection.gameall_program
            ),
            "lens_program_selection": support.glass_lens_program_selection.report(),
            "active_program_ledger_lens_resolved_program": active_lens_program,
            "portable_boundary": portable_boundary,
            "rigid_shape_binds": {
                "frame": _prepared_rigid_shape_report(
                    glass_resource, "Flame__mt_Body"
                ),
                "opaque_lens": _prepared_rigid_shape_report(
                    glass_resource, "Opa__mt_LensOpa"
                ),
                "translucent_lens": _prepared_rigid_shape_report(
                    glass_resource, "Trs__mt_LensTrs"
                ),
            },
        }

    head_attachment_report = _prepared_head_attachment_report(head_resource)
    head_attachment_bones = head_attachment_report["bones"]
    binary_backed_model_transforms: dict[str, Any] = {
        "selected_head_attachments": head_attachment_report,
        "hair_and_hair_front": {
            "attachment_bone": "set_hair",
            "attachment": head_attachment_bones["set_hair"],
            "composition": (
                "head_scene @ selected_head.set_hair bind-world @ optional world-X "
                "reflection @ per-shape post-pose transform"
            ),
        },
    }
    if nose_resource is not None:
        binary_backed_model_transforms["nose_and_nose_line"] = {
            "source_function": "FUN_7101d6d538 cases 5/6",
            "attachment_bone": "set_nose",
            "attachment": head_attachment_bones["set_nose"],
            "local_y_delta": (document["char_info"]["nose_y"] - 9) * -0.015,
            "uniform_scale": (document["char_info"]["nose_scale"] * 0.175 + 0.4)
            / 1.1,
            "composition": (
                "head_scene @ selected_head.set_nose bind-world @ local Y delta @ "
                "uniform scale @ per-shape BFRES bind-world"
            ),
            "shape_bindings": {
                "nose": (
                    _prepared_rigid_shape_report(nose_resource, "Nose__mt_Nose")
                    if nose_has_surface
                    else None
                ),
                "nose_line": _prepared_rigid_shape_report(
                    nose_resource, "NoseLine__mt_NoseLine"
                ),
            },
        }
    if ear_resource is not None:
        binary_backed_model_transforms["ear_pair"] = {
            "source_function": "FUN_7101d6d538 cases 7/8 + FUN_7101d6ee04",
            "resource": ear_resource,
            "ear_y": document["char_info"]["ear_y"],
            "ear_y_delta": (document["char_info"]["ear_y"] - 4) * -0.015,
            "attachment_bone": "set_ear",
            "attachment": head_attachment_bones["set_ear"],
            "shape_bind": _prepared_rigid_shape_report(
                ear_resource, "Ear__mt_Ear"
            ),
            "uniform_scale": (document["char_info"]["ear_scale"] * 0.175 + 0.75)
            / 1.1,
            "right_composition": (
                "selected_head.set_ear bind-world with world-Y delta @ S @ "
                "BFRES bind-world"
            ),
            "left_composition": "reflect_world_x @ right",
        }
    if beard_resource is not None:
        binary_backed_model_transforms["beard"] = {
            "source_function": "FUN_7101d6d538 beard attachment case",
            "attachment_bone": "set_beard",
            "attachment": head_attachment_bones["set_beard"],
            "composition": (
                "head_scene @ selected_head.set_beard bind-world @ per-shape "
                "BFRES bind-world"
            ),
            "shape_bind": _prepared_rigid_shape_report(
                beard_resource, "Beard__mt_Beard"
            ),
        }
    if glass_resource is not None:
        glass_scale = document["char_info"]["glass_scale"] * 0.15 + 0.4
        binary_backed_model_transforms["glass"] = {
            "source_function": "FUN_7101d6d538 case 1",
            "attachment_bone": "set_nose",
            "attachment": head_attachment_bones["set_nose"],
            "local_translation_delta": [
                0.0,
                0.05 + (document["char_info"]["glass_y"] - 12) * -0.015,
                0.02,
            ],
            "scale": [
                glass_scale,
                glass_scale * (document["char_info"]["glass_aspect"] * 0.12 + 0.64),
                glass_scale,
            ],
            "composition": (
                "head_scene @ selected_head.set_nose bind-world @ local Y/Z delta @ "
                "scale @ per-shape BFRES bind-world"
            ),
            "shape_bindings": {
                "frame": _prepared_rigid_shape_report(
                    glass_resource, "Flame__mt_Body"
                ),
                "opaque_lens": _prepared_rigid_shape_report(
                    glass_resource, "Opa__mt_LensOpa"
                ),
                "translucent_lens": _prepared_rigid_shape_report(
                    glass_resource, "Trs__mt_LensTrs"
                ),
            },
        }

    report = {
        "input": _logical_path(args.input),
        "input_sha256": document["sha256"],
        "presentation_context": {
            "kind": presentation_context["kind"],
            "sha256": presentation_context["sha256"],
            "for_hat": presentation_context["for_hat"],
            "source_hair_type": presentation_context["source_hair_type"],
            "canonical_hair_type": presentation_context["canonical_hair_type"],
            "favorite_color": presentation_context["favorite_color"],
            "favorite_color_rgb_hex": presentation_context[
                "favorite_color_rgb_hex"
            ],
            "favorite_shirt": presentation_context["favorite_shirt"],
            "source_boundary": presentation_context["source_boundary"],
        },
        "char_info": {
            "raw": raw_char_info,
            "effective": document["char_info"],
            "normalization": char_info_normalization,
            "runtime_profile": {
                "key": classic_runtime_profile["key"],
                "path": _logical_path(Path(classic_runtime_profile["artifact"]["path"])),
                "byte_length": classic_runtime_profile["artifact"]["byte_length"],
                "sha256": classic_runtime_profile["artifact"]["sha256"],
            },
        },
        "selection_manifest": {
            "path": _logical_path(active_parts_path),
            "sha256": _sha256(active_parts_path),
            "target_sha256": active_parts_manifest["target"]["sha256"],
            "selector_count": active_parts_manifest["selector_count"],
            "enabled_record_count": active_parts_manifest["enabled_record_count"],
            "generator": active_parts_manifest["generator"],
        },
        "material_texture_mips": material_texture_cache_report,
        "resource_support": {
            "selection_kind": support.selection_kind,
            "classic_bridge": support.classic_bridge_report,
            "nose_parallax_height_scale": support.nose_parallax_height_scale,
            "presentation_variation": support.presentation_variation,
        },
        "display_name": document["display_name"],
        "char_info_name": document["char_info"]["name"],
        "renderer": "recovered Nintendo assets + deterministic CPU rasterizer",
        "asset_root": _logical_path(args.asset_root),
        "snapshot_pipeline": {
            "path": _logical_path(TITLE_MII_ICON_SNAPSHOT),
            "sha256": _sha256(TITLE_MII_ICON_SNAPSHOT),
            "profiles": ["MiiIcon", "EditorMiiPreview"],
            "exact_scope": "camera/settings, degree conversion, key/ambient scene-buffer upload, GamePfx SnapshotPfx variation and gamma0 tone curve, CaptureIcon NVN RGBA8_SRGB target",
            "portable_boundary": "GameUber light/shadow prepass, bloom extraction/pyramid, and SSAA resolve remain substituted or unresolved as recorded per output",
        },
        "skeletal_assembly": {
            "evidence": {
                "path": _logical_path(MII_POSE_PIPELINE),
                "sha256": _sha256(MII_POSE_PIPELINE),
                "schema_version": 1,
            },
            "body_animation": {
                "resource": "AnimationIcon.bfres",
                "animation": body_pose.animation_name,
                "frame": 0,
                "loop": False,
                "catalog": _logical_path(ICON_POSE),
                "catalog_sha256": _sha256(ICON_POSE),
                "bind_identity_max_error": body_pose.bind_identity_max_error,
                "skinning": "BFRES MatrixToBoneList + inverse bind matrices + _i0/_w0",
            },
            "hair": [
                {
                    "model_key": model_key,
                    "model": resource,
                    "model_selection": hair_selection_by_key[model_key].report(),
                    "static_pose": "BFRES rest/bind pose at zero simulation time",
                    "bind_identity_max_error": hair_poses[
                        model_key
                    ].bind_identity_max_error,
                }
                for model_key, resource in hair_resources
            ],
            "body_scale": {
                "source_function": "FUN_7101bd04a8",
                "build": document["char_info"]["build"],
                "height": document["char_info"]["height"],
                "runtime_branch": "raw CharInfo path (+0xac == -1), established by FUN_7101bcbf1c and reasserted by FUN_7101dd9020",
                "xyz": list(
                    mii_body_scale(document["char_info"]["build"], document["char_info"]["height"])
                ),
            },
            "head_attachment": {
                "anchor": "body-scaled posed Head translation plus render-space Y -= body_x*0.09074663 from FUN_7101bd04a8",
                "body_to_part_bridge": "FUN_7101bc6e80 divides the mapped parent 3x3 basis componentwise by body scale before the part skeleton consumes it",
                "base_part_geometry_scale": [1.0, 1.0, 1.0],
                "culling_only_function": "FUN_7101bd05f0 / update_mii_part_model_culling_radii uses BFRES Shape.RadiusArray; it does not prove geometry scale",
                "all_view_geometry_scale": "unit scale; no reference-image fit override",
            },
            "presentation_outfit": {
                "gameall_program_selections": {
                    slot: selection.report()
                    for slot, selection in sorted(
                        support.outfit_program_selections.items()
                    )
                },
                "body_socks_program_selection": support.body_program_selections[
                    "BodyFoot__mt_Socks"
                ].report(),
                "tops_animation": reference_top_pose.animation_name,
                "tops_bind_identity_max_error": reference_top_pose.bind_identity_max_error,
                "bottoms_animation": presentation_bottoms_pose.animation_name,
                "bottoms_bind_identity_max_error": presentation_bottoms_pose.bind_identity_max_error,
                "shoes_animation": reference_shoes_pose.animation_name,
                "shoes_bind_identity_max_error": reference_shoes_pose.bind_identity_max_error,
                "scope": "all canonical posed_full_body outputs",
                "body_base_cutline": {
                    "source": "System.mii__SystemParam.bgyml via FUN_7101bce0c0/FUN_7101bcd440",
                    "checked_ledger": {
                        "path": _logical_path(BODY_BASE_CUTLINE_SOURCE),
                        "sha256": _sha256(BODY_BASE_CUTLINE_SOURCE),
                    },
                    "keys": [3312601720, 3296514992, 2895499086, 1032020994],
                    "hidden_body_groups": sorted(_presentation_body_base_cutline_groups()),
                    "top_reconciliation": "key 0xc5724a78 contains exactly BodyChest hash 0xcdb78d9e and BodyArm hash 0x7d25514e; BodyElbow/BodyWaist are not in this row",
                },
            },
        },
        "resolved_parts": resolved_parts,
        "active_material_path": active_material_path,
        "shader_evidence": {
            "mii_mask": {
                "path": _logical_path(MII_MASK_SEMANTICS),
                "sha256": _sha256(MII_MASK_SEMANTICS),
            },
            "active_gameuber_programs": {
                "path": _logical_path(active_program_ledger),
                "sha256": _sha256(active_program_ledger),
                "target_scope": "checked selected-model program identities and stage/interface hashes; any unresolved compatible set remains fail-closed in the ledger",
            },
            "active_hair_programs": [
                {
                    "model_key": model_key,
                    "resource": resource,
                    "model_name": hair_shaders[resource].model_name,
                    "gameall_program": hair_shaders[resource].gameall_program,
                    "fragment_instructions_sha256": hair_shaders[
                        resource
                    ].fragment_instructions_sha256,
                    "path": _logical_path(hair_shaders[resource].evidence_path),
                    "sha256": _sha256(hair_shaders[resource].evidence_path),
                    "exact_local_scope": hair_shaders[resource].exact_local_scope,
                    "disabled_local_scope": hair_shaders[
                        resource
                    ].disabled_local_scope,
                }
                for model_key, resource in hair_resources
            ],
            "gameuber_cpu": {
                "path": "renderer/gameuber_cpu.py",
                "sha256": _sha256(REPOSITORY / "renderer" / "gameuber_cpu.py"),
                "exact_scope": "selected hair base expressions; Hair612-fragment-family and Beard456/468 kernels where the exact program matches; Nose parallax, the shared Body324/336/348 fragment base/roughness, Mask0 mix/emission, and cheap-SSS response",
                "proxy_scope": "the single-key anisotropic proxy is enabled only for exact Hair612-fragment-family selections (program 612/624/636, plus audited Hair708) and exact Beard456/468 selections",
            },
            "snapshot_postprocess": {
                "path": "renderer/snapshot_postprocess.py",
                "sha256": _sha256(REPOSITORY / "renderer" / "snapshot_postprocess.py"),
                "exact_scope": "MiiIcon no-exposure gamma0 luminance weights, exponential curve, shoulder mix, and saturate",
                "portable_boundary": "zero bloom image; the destination IEC-sRGB encode is binary-backed",
            },
        },
        "recovered_raster_state": {
            "sampling": "normalized bilinear min/mag with original point/linear BNTX mip chains",
            "known_sampling_delta": "Hair Msk/Mgh requests 2:1 anisotropy; CPU path uses isotropic LOD. Presentation _alp0 states are serialized but inactive in selected 984/936/912 and are not sampled.",
            "display_faces": (
                "mt_Mask and the presentation top, pants, and shoes mt_Body "
                "materials are two-sided; other submitted materials are front-face only"
            ),
            "mask_materials": "gequal 0.5, blending disabled, depth lequal/write enabled",
        },
        "portable_approximations": {
            "body_default_programs_324_336_348": {
                "selection": "each of the 13 BFRES groups is bound to its singleton GameAll program by exact VertexSkinCount and both selected stage hashes",
                "recovered_base_formula": "mix(mii_face_color.linear, Alb.hardware_srgb_sample_linear, Skm.g)",
                "recovered_roughness_formula": "mix(Mic.r, .75, 1-Skm.g)",
                "replace_albedo_color": [0.0, 0.0, 0.0, 0.0],
                "applied": "exact local base and roughness expressions evaluated per fragment from raw Alb/Skm/Mic",
                "known_delta": "the exact cheap-SSS local curve is identified but its correction is inactive_missing_light_prepass; raw NdotL is not substituted, ScreenSpaceFaceShadow/FaceShadow visibility remains neutral, and final GameUber BRDF remains unresolved",
            },
            "presentation_outfit_gameall": {
                "applied": "top, pants, shoes, and socks exact active albedo, tangent normal, native mip chain, and material-information/skin-mask inputs; selected 984/936/912 omit serialized _alp0, so no outfit mask or guessed alpha cutoff affects opacity or depth",
                "resolved_body_programs": {"presentation_top": 984, "presentation_bottoms": 936, "body_socks": 324, "presentation_shoes": 912},
                "program_selections": {
                    **{
                        slot: selection.report()
                        for slot, selection in sorted(
                            support.outfit_program_selections.items()
                        )
                    },
                    "body_socks": support.body_program_selections[
                        "BodyFoot__mt_Socks"
                    ].report(),
                },
                "softmesh_program_36": "skipped fail-closed: serialized _a0 -> Dummy_Alb has no recovered live substitution",
                "known_delta": "title environment/SSAO/ground-GI, edge-toon RGB, and compiled top/pants/shoe final response still require runtime prepass and material-buffer inputs",
                "top_emission": "program 984 compiles _e0, but the selected texture project has no Emm surface; no emissive texture is invented",
            },
            "hair_and_beard_anisotropic_radiance": {
                "selected_hair_programs": {
                    resource: hair_shaders[resource].gameall_program
                    for _model_key, resource in hair_resources
                },
                "per_resource": {
                    resource: hair_anisotropic_report(resource)
                    for _model_key, resource in hair_resources
                },
                "portable_wrapper": "single normalized SnapshotSetting key is used only for exact Hair612-fragment-family (program 612/624/636 plus Hair708) and Beard456/468 local kernels",
                "known_delta": "title light records, LTC/environment terms, and runtime material buffers remain unavailable; no reference-image radiance multiplier is supplied",
            },
        },
        "face_mask_projection": mask_projection_report,
        "binary_backed_model_transforms": binary_backed_model_transforms,
        "face_texture": {
            "generated_faceline_target": (
                faceline_result.report if faceline_result is not None else None
            ),
            "target_separation": (
                "generated faceline 128x256 -> mt_Head _a0; generated mask 256x256 -> "
                "mt_Mask _a0; decoded UGC facepaint -> mt_Mask _user0"
            ),
            "face_sprite_mips": {
                "path": _logical_path(FACE_SPRITE_MIPS),
                "sha256": _sha256(FACE_SPRITE_MIPS),
                "manifests": [
                    {
                        "path": _logical_path(path),
                        "sha256": _sha256(path),
                    }
                    for path in support.face_sprite_mip_manifests
                ],
                "selection": (
                    "exact texture identity + active Parts config/record + packed BNTX; "
                    "the compositor recomputes transform, footprint, and LOD from live CharInfo"
                ),
            },
            "opaque_preview": {
                "path": face_path.name,
                "sha256": _sha256(face_path),
                "transparent_base": face_report["transparent_base"],
            },
            "mesh_input": {
                "path": mesh_face_path.name,
                "sha256": _sha256(mesh_face_path),
                "transparent_base": face_layers_report["transparent_base"],
            },
            "share_mii_v3_facepaint": (
                {
                    **facepaint.report,
                    "evidence_ledger": {
                        "path": _logical_path(SHARE_MII_FACEPAINT),
                        "sha256": _sha256(SHARE_MII_FACEPAINT),
                    },
                }
                if facepaint is not None
                else None
            ),
            **{key: value for key, value in face_report.items() if key != "transparent_base"},
        },
        "hair_attachment_state": {
            "hair_front_type": document["char_info"]["hair_front_type"],
            "hair_back_type": document["char_info"]["hair_back_type"],
            "main_record": active_records["hair"].get("record"),
            "front_enabled": bool(active_records["hair_front"].get("enabled")),
            "resolved_front_record": active_records["hair_front"].get("record"),
            "front_gate_enabled": active_records["hair_front"].get("gate_enabled"),
            "back_state_evidence": active_records["hair_back_editor_state"].get("evidence"),
            "rendered_models": [resource for _model_key, resource in hair_resources],
            "effective_bangs_side": bool(
                document["char_info"]["face_flags"]["bangs_side"]
            ),
            "model_selections": [
                selection.report() for selection in hair_model_selections
            ],
            "legacy_headwear": (
                support.legacy_headwear_selection.report()
                if support.legacy_headwear_selection is not None
                else None
            ),
            "hair_back_model_boundary": (
                "hair_back_type is subordinate editor state; the checked Parts domain has no "
                "HairBack category or independently submitted HairBack model role"
            ),
            "hat_model_boundary": (
                "the hash-bound external source context selects Hair45 ModelUnitForHat and "
                "the checked legacy headwear draw; the lossy canonical LTD bytes remain unchanged"
                if support.legacy_headwear_selection is not None
                else
                "ModelUnitForHat/FlippedModelUnitForHat require an exact source-backed external "
                "hat-worn context; this LTD render selects the ordinary model roles"
            ),
            "boundary": (
                "HairNothing is the exact selected main record; no hair geometry is submitted"
                if active_records["hair"].get("is_nothing")
                else (
                    "front attachment submitted because the selected Hair record is attachable"
                    if active_records["hair_front"].get("enabled")
                    else "subordinate front selector is inactive for the selected Hair record"
                )
            ),
        },
        "outputs": outputs,
        "presentation_outfit": {
            "path": _logical_path(PRESENTATION_OUTFIT),
            "sha256": _sha256(PRESENTATION_OUTFIT),
            "selection_kind": "renderer presentation preset",
            "share_mii_contains_cloth_set_or_color": False,
            "profile": presentation_profile,
            "slots": presentation_outfit["slots"],
            "rendered_in_full_body": any(output["view"] in {"posed_full_body", "screenshot_reference_outfit"} for output in outputs),
            "rendered_in_bust_portrait": any(
                output["view"] == "appearance_bust_portrait" for output in outputs
            ),
            "required_draw_keys": [
                "reference_top:Tops__mt_Body",
                "presentation_bottoms:Bottoms__mt_Body",
                "body:BodyFoot__mt_Socks",
                "reference_shoes:Shoes__mt_Body",
            ],
            "body_base_cutline": {
                "path": _logical_path(BODY_BASE_CUTLINE_SOURCE),
                "sha256": _sha256(BODY_BASE_CUTLINE_SOURCE),
                "hidden_body_groups": sorted(_presentation_body_base_cutline_groups()),
            },
            "capture_provenance_for_kestron_top_socks_shoes": {
                "path": _logical_path(REFERENCE_OUTFIT),
                "sha256": _sha256(REFERENCE_OUTFIT),
            },
            "material_state": {
                "path": _logical_path(REFERENCE_OUTFIT_MATERIAL_STATE),
                "sha256": _sha256(REFERENCE_OUTFIT_MATERIAL_STATE),
                "serialized_inactive_alpha_mask_chains": presentation_inactive_alpha_masks,
                "programs": {
                    "tops_body": support.outfit_program_selections[
                        "tops"
                    ].gameall_program,
                    "bottoms_body": support.outfit_program_selections[
                        "bottoms"
                    ].gameall_program,
                    "shoes_body": support.outfit_program_selections[
                        "shoes"
                    ].gameall_program,
                    "socks_body": support.body_program_selections[
                        "BodyFoot__mt_Socks"
                    ].gameall_program,
                    "tops_and_bottoms_softmesh_skipped": 36,
                },
            },
            "native_mips": {
                "path": _logical_path(REFERENCE_OUTFIT_TEXTURE_MIPS),
                "sha256": _sha256(REFERENCE_OUTFIT_TEXTURE_MIPS),
                "texture_count": presentation_texture_mips["texture_count"],
                "level_count": presentation_texture_mips["mip_level_count"],
                "complete_source_and_level_inventory_validated_before_draw": True,
                "runtime_level_loading": "exact selected-manifest level path/order; no directory glob",
            },
            "softmesh": presentation_outfit["softmesh_boundary"],
        },
    }
    report_path = args.output_dir / "render_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _console_print(f"rendered {document['display_name']} from {args.input}")
    for output in outputs:
        _console_print(
            f"  {output['view']}: {output['path']} "
            f"({output['submitted_triangle_total']} triangles)"
        )
    _console_print(f"  report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
