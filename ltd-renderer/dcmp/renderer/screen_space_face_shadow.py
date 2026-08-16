"""Fail-closed title screen-space face-shadow and cheap-SSS inputs.

The selected Mii Head/Nose/Ear programs consume frame-owned title resources.
Those resources are not interchangeable with the portable renderer's visible
depth buffer.  This module therefore exposes the recovered parameter and
shader dataflow without inventing a replacement prepass.

No function in this module accepts a Lambert-lighting substitute.  Until the
title light-prepass value and the remaining interpolation terms are supplied
from one authenticated draw capture, cheap-SSS is inactive.  Likewise, face
shadow visibility remains neutral until the attachment format, binding, and
constant-buffer upload are all recovered and an exact kernel is implemented.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

import numpy as np


INACTIVE_MISSING_LIGHT_PREPASS = "inactive_missing_light_prepass"
INACTIVE_MISSING_FACE_SHADOW_INPUTS = "inactive_missing_face_shadow_inputs"
INACTIVE_UNRECOVERED_SHADER_CONTRACT = "inactive_unrecovered_shader_contract"
ACTIVE_CAPTURED_TITLE_INPUTS = "active_captured_title_inputs"


def _float32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits))[0]


@dataclass(frozen=True)
class ScreenSpaceFaceShadowParameters:
    """Exact title parameter values after native defaults plus BYML overrides."""

    enable: bool
    fade_enable: bool
    search_num: int
    search_length: float
    softness: float
    center_y: float
    scale_y: float
    depth_offset: float
    fade_start: float
    fade_end: float


TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS = ScreenSpaceFaceShadowParameters(
    enable=True,
    fade_enable=True,
    # SearchNum and CenterY are absent from the shipped BYML.  The executable
    # parameter constructor initializes their native storage to 10 and 0.0.
    search_num=10,
    search_length=_float32_from_bits(0x3CF5C28F),
    softness=_float32_from_bits(0x3DCCCCCD),
    center_y=_float32_from_bits(0x00000000),
    scale_y=_float32_from_bits(0x3E99999A),
    depth_offset=_float32_from_bits(0x38D1B717),
    fade_start=_float32_from_bits(0x41A00000),
    fade_end=_float32_from_bits(0x41F00000),
)


@dataclass(frozen=True)
class TitlePrepassAvailability:
    """Authenticated title inputs required before either effect may execute."""

    gsys_light_prepass: bool = False
    gsys_user4: bool = False
    cheap_sss_interpolation_terms: bool = False
    face_shadow_same_view_projection: bool = False
    face_shadow_attachment_format: bool = False
    face_shadow_sampler_binding: bool = False
    face_shadow_cbuf_upload: bool = False


@dataclass(frozen=True)
class CheapSssInputResolution:
    """Resolution of the scalar input consumed by the decoded cheap-SSS curve."""

    status: str
    correction_enabled: bool
    title_light_input_x: np.ndarray | None
    missing_inputs: tuple[str, ...]


@dataclass(frozen=True)
class FaceShadowVisibilityResolution:
    """Neutral visibility plus an explicit reason that title execution is absent."""

    status: str
    execution_enabled: bool
    visibility: np.ndarray
    missing_inputs: tuple[str, ...]


def decoded_head816_cheap_sss_interpolation(
    r29_pre: Any,
    r30: Any,
    r31_pre: Any,
    gsys_user4_g: Any,
) -> np.ndarray:
    """Evaluate the recovered Head816 interpolation dataflow.

    The decoded instructions are::

        delta = r31_pre - r29_pre * r30
        base = r29_pre * r30
        x = base + gsys_user4_g * delta

    This helper records the operand identity and operation order.  It is not a
    claim of bit-exact Maxwell fused-multiply-add rounding.
    """

    r29_value = np.asarray(r29_pre, dtype=np.float64)
    r30_value = np.asarray(r30, dtype=np.float64)
    r31_value = np.asarray(r31_pre, dtype=np.float64)
    user4_value = np.asarray(gsys_user4_g, dtype=np.float64)
    base = r29_value * r30_value
    delta = r31_value - base
    return base + user4_value * delta


def resolve_cheap_sss_title_light_input(
    *,
    availability: TitlePrepassAvailability,
    r29_pre: Any | None = None,
    r30: Any | None = None,
    r31_pre: Any | None = None,
    gsys_user4_g: Any | None = None,
) -> CheapSssInputResolution:
    """Resolve cheap-SSS input only from authenticated title-prepass terms."""

    if not availability.gsys_light_prepass:
        return CheapSssInputResolution(
            status=INACTIVE_MISSING_LIGHT_PREPASS,
            correction_enabled=False,
            title_light_input_x=None,
            missing_inputs=("gsys_light_prepass",),
        )

    missing: list[str] = []
    if not availability.gsys_user4 or gsys_user4_g is None:
        missing.append("gsys_user4.g")
    if not availability.cheap_sss_interpolation_terms:
        missing.append("cheap_sss_interpolation_terms")
    for name, value in (
        ("r29_pre", r29_pre),
        ("r30", r30),
        ("r31_pre", r31_pre),
    ):
        if value is None:
            missing.append(name)
    if missing:
        return CheapSssInputResolution(
            status=INACTIVE_UNRECOVERED_SHADER_CONTRACT,
            correction_enabled=False,
            title_light_input_x=None,
            missing_inputs=tuple(missing),
        )

    return CheapSssInputResolution(
        status=ACTIVE_CAPTURED_TITLE_INPUTS,
        correction_enabled=True,
        title_light_input_x=decoded_head816_cheap_sss_interpolation(
            r29_pre,
            r30,
            r31_pre,
            gsys_user4_g,
        ),
        missing_inputs=(),
    )


def resolve_screen_space_face_visibility(
    *,
    availability: TitlePrepassAvailability,
    fragment_shape: tuple[int, ...],
) -> FaceShadowVisibilityResolution:
    """Return neutral visibility until the exact title kernel is executable."""

    if any(type(size) is not int or size < 0 for size in fragment_shape):
        raise ValueError("fragment_shape must contain nonnegative integers")
    requirements = (
        ("same_view_projection", availability.face_shadow_same_view_projection),
        ("attachment_format", availability.face_shadow_attachment_format),
        ("sampler_binding", availability.face_shadow_sampler_binding),
        ("cbuf_upload", availability.face_shadow_cbuf_upload),
    )
    missing = tuple(name for name, present in requirements if not present)
    status = (
        INACTIVE_MISSING_FACE_SHADOW_INPUTS
        if missing
        else INACTIVE_UNRECOVERED_SHADER_CONTRACT
    )
    return FaceShadowVisibilityResolution(
        status=status,
        execution_enabled=False,
        visibility=np.ones(fragment_shape, dtype=np.float64),
        missing_inputs=missing,
    )


# The portable renderer currently has no authenticated title prepass capture.
# Precompute this immutable result once; rasterization must not allocate a new
# status object for every triangle merely to take the disabled branch.
PORTABLE_MISSING_TITLE_PREPASS = TitlePrepassAvailability()
PORTABLE_CHEAP_SSS_INPUT = resolve_cheap_sss_title_light_input(
    availability=PORTABLE_MISSING_TITLE_PREPASS
)


__all__ = [
    "ACTIVE_CAPTURED_TITLE_INPUTS",
    "CheapSssInputResolution",
    "FaceShadowVisibilityResolution",
    "INACTIVE_MISSING_FACE_SHADOW_INPUTS",
    "INACTIVE_MISSING_LIGHT_PREPASS",
    "INACTIVE_UNRECOVERED_SHADER_CONTRACT",
    "PORTABLE_CHEAP_SSS_INPUT",
    "PORTABLE_MISSING_TITLE_PREPASS",
    "ScreenSpaceFaceShadowParameters",
    "TITLE_SCREEN_SPACE_FACE_SHADOW_PARAMETERS",
    "TitlePrepassAvailability",
    "decoded_head816_cheap_sss_interpolation",
    "resolve_cheap_sss_title_light_input",
    "resolve_screen_space_face_visibility",
]
