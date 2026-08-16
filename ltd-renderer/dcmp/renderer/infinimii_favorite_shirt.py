"""Strict InfiniMii FavoriteColor-to-default-shirt presentation policy.

The title's default shirt is authored as a 17-variation albedo family.  The
stored legacy ``FavoriteColor`` has only 12 values and is absent from LTD, so
InfiniMii owns the semantic 12-to-17 projection.  Once projected, the renderer
selects the complete title-authored albedo (including its two-tone artwork and
alpha) rather than painting a constant color over variation 00.  Geometry,
UVs, normal and material-information maps remain owned by the ordinary title
material path.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


POLICY_PATH = Path(__file__).with_name("infinimii_favorite_shirt_policy.json")
POLICY_KIND = "infinimii-favorite-shirt-v1"
EXPECTED_RGB_HEX = (
    "D21E14", "FF6E19", "FFD820", "78D220", "007830", "0A48B4",
    "3CAAE0", "F55A7D", "7328AD", "483818", "E0E0E0", "181814",
)

# InfiniMii policy projection from classic FavoriteColor order
# (red, orange, yellow, lime, green, blue, light blue, pink, purple, brown,
# white, black) to the title-authored CharacterColor albedo suffixes.  The
# title family has one neutral shirt, so classic white and black both select
# variation 00.
EXPECTED_AUTHORED_VARIATIONS = (8, 3, 4, 10, 11, 16, 14, 6, 15, 1, 0, 0)
EXPECTED_AUTHORED_VARIANT_LABELS = (
    "red", "orange", "yellow", "lime", "green", "blue",
    "cyan", "pink", "purple", "ochre_brown", "neutral", "neutral",
)
EXPECTED_AUTHORED_BNTX_SHA256 = (
    "c2ed4aac0d0972d38355fadba9c15359400d29776e3a5907ca7f217f00089a2d",
    "cf4cc1ae2acb5a7c9f50e818acb0a6c006484aad27951ea798227498a1714763",
    "4f685b12832a90c65e3734cdc05ed942ffdd661e9bcff3e22e846c87183b28fc",
    "f0358240b1289669695f0072fef71c4e10d7ac3d7513ac1b96937a7d6f28a187",
    "4b36a8555b9c6530030e267ba518a19e23785c499c946a2689520ad7bd1cae2a",
    "bb54fcfc2da30887aa46eb470f0b6a31b78234fe0d98c59fdfb8685332d7a625",
    "0264bc00e2d1bdde38aa4db4f190079412eb9fa8be6f51a4eb3c357a8cc4b513",
    "a59b571ded674196b11be0f23bd9669d43400e1933a363b4180f13408b55e81a",
    "1ab172b87e1990b7b955035ebd4bb1dbfa41d50abdffb91c021e937fd17efec9",
    "bf448f669de9dd39643054df15ce3ccc8035601982bfea455a1fe3d219555585",
    "80c0522aeba44f45e11cfde3e09a78ebf4747ef31ca1e1085f0410fcaa7e52cc",
    "ff95b41731b36aebc85d952362ba638aba1785035c3902d14a29a48a355ec461",
    "736e01a204bb49fe72c0ecd54892974ef5db11166f29f2d38a4d9b520f7571c6",
    "c2434cfed5bf7813902bc3ebdf5a13ec7333412b380ba59f7b386d0d24cc29a3",
    "06c903b5495adb70715323a4bfccbf8b05d33f878d0a88fe2b92ed7b5382dbf1",
    "c6d54342d952d98c73860e344e8fd7efbe9d4863aadb031db72a9a3820733d5a",
    "cb6fc6efe2981b47c84bcbb84269394412b876d2781ed6f99ff4db8b1b8b8c36",
)
AUTHORED_ALBEDO_PATTERN = "ClothTopsTshirtLongTexDefault_Body_Alb.{variation:02d}"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=1)
def load_policy() -> dict[str, Any]:
    raw = POLICY_PATH.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "policy", "description", "title_exact",
        "title_exact_boundary", "mapping_basis", "source_boundary", "shirt_albedo",
        "favorite_color_rgb_hex", "favorite_color_to_authored_variation",
        "favorite_color_to_authored_variant_label", "authored_variation_bntx_sha256",
    }:
        raise ValueError("InfiniMii favorite-shirt policy schema changed")
    if (
        value["schema_version"] != 2
        or value["policy"] != POLICY_KIND
        or value["title_exact"] is not False
        or value["title_exact_boundary"] != {
            "authored_shirt_family_and_loading_mechanism": True,
            "favorite_color_to_suffix_projection": False,
        }
        or value["mapping_basis"]
        != "curated_named_authored_variant_with_neutral_fallback"
        or tuple(value["favorite_color_rgb_hex"]) != EXPECTED_RGB_HEX
        or tuple(value["favorite_color_to_authored_variation"])
        != EXPECTED_AUTHORED_VARIATIONS
        or tuple(value["favorite_color_to_authored_variant_label"])
        != EXPECTED_AUTHORED_VARIANT_LABELS
        or tuple(value["authored_variation_bntx_sha256"])
        != EXPECTED_AUTHORED_BNTX_SHA256
        or value["source_boundary"] != {
            "source_field": "general.favoriteColor",
            "context_is_ltd_sha256_bound": True,
            "share_mii_contains_favorite_color": False,
            "presentation_profile_variation_used": False,
            "reference_image_values_used": False,
        }
        or value["shirt_albedo"] != {
            "mode": "select_authored_character_color_albedo",
            "authored_albedo_variation_used": True,
            "texture_name_pattern": AUTHORED_ALBEDO_PATTERN,
            "source_rgb_used": True,
            "source_alpha_preserved": True,
            "alpha_sampler_active": False,
            "normal_texture_unchanged": "ClothTopsTshirtLongTexDefault_Body_Nrm",
            "material_information_texture_unchanged": "ClothTopsTshirtLongTexDefault_Body_Mic",
        }
    ):
        raise ValueError("InfiniMii favorite-shirt policy contract changed")
    return value


@dataclass(frozen=True)
class FavoriteShirtSelection:
    favorite_color: int
    rgb_hex: str
    authored_variation: int
    authored_variant_label: str

    @property
    def source_albedo(self) -> str:
        return AUTHORED_ALBEDO_PATTERN.format(variation=self.authored_variation)

    @property
    def source_bntx_sha256(self) -> str:
        return EXPECTED_AUTHORED_BNTX_SHA256[self.authored_variation]

    def report(self) -> dict[str, Any]:
        contract = load_policy()
        return {
            "status": "active",
            "policy": POLICY_KIND,
            "favorite_color": self.favorite_color,
            "rgb_hex": self.rgb_hex,
            "source_field": contract["source_boundary"]["source_field"],
            "context_is_ltd_sha256_bound": True,
            "title_exact": False,
            "authored_shirt_family_and_loading_mechanism_title_exact": True,
            "favorite_color_to_suffix_projection_title_exact": False,
            "mapping_basis": contract["mapping_basis"],
            "authored_variation": self.authored_variation,
            "authored_variant_label": self.authored_variant_label,
            "albedo_mode": contract["shirt_albedo"]["mode"],
            "source_albedo": self.source_albedo,
            "source_bntx_sha256": self.source_bntx_sha256,
            "source_rgb_used": True,
            "source_alpha_preserved": True,
            "authored_albedo_variation_used": True,
            "presentation_profile_variation_used": False,
            "alpha_sampler_active": False,
            "normal_texture_unchanged": contract["shirt_albedo"]["normal_texture_unchanged"],
            "material_information_texture_unchanged": contract["shirt_albedo"]["material_information_texture_unchanged"],
            "policy_artifact": {
                "path": "renderer/infinimii_favorite_shirt_policy.json",
                "byte_length": POLICY_PATH.stat().st_size,
                "sha256": _sha256(POLICY_PATH),
            },
        }


def inactive_report() -> dict[str, Any]:
    return {
        "status": "inactive_no_source_context",
        "policy": POLICY_KIND,
        "title_exact": False,
    }


def selection_from_presentation_context(
    context: dict[str, Any],
) -> FavoriteShirtSelection | None:
    load_policy()
    if context.get("kind") != POLICY_KIND:
        return None
    favorite_color = context.get("favorite_color")
    rgb_hex = context.get("favorite_color_rgb_hex")
    if (
        type(favorite_color) is not int
        or not 0 <= favorite_color < len(EXPECTED_RGB_HEX)
        or not isinstance(rgb_hex, str)
        or not re.fullmatch(r"[0-9A-F]{6}", rgb_hex)
        or rgb_hex != EXPECTED_RGB_HEX[favorite_color]
    ):
        raise ValueError("favorite-shirt context is outside the checked palette domain")
    return FavoriteShirtSelection(
        favorite_color=favorite_color,
        rgb_hex=rgb_hex,
        authored_variation=EXPECTED_AUTHORED_VARIATIONS[favorite_color],
        authored_variant_label=EXPECTED_AUTHORED_VARIANT_LABELS[favorite_color],
    )
