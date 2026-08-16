"""Recovered local SnapshotPfx tone-map equations.

The MiiIcon specialization has tone mapping enabled, gamma mode zero, and
ExposureExp zero.  This module evaluates the exact shader-local curve while
keeping unavailable bloom imagery explicit. CaptureIcon's destination is the
recovered NVN RGBA8_SRGB target, so the caller encodes IEC-sRGB exactly once.
It does not synthesize the title's bloom pyramid or SSAA resolve.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import ArrayLike, NDArray


FloatArray = NDArray[np.float64]
LUMINANCE_WEIGHTS = np.asarray(
    (0.2989000082015991, 0.5866000056266785, 0.1143999993801117),
    dtype=np.float64,
)


def snapshot_pfx_tone_map_gamma0(
    scene_linear_rgb: ArrayLike,
    bloom_linear_rgb: ArrayLike | None = None,
) -> FloatArray:
    """Evaluate the recovered tone-enabled, gamma-zero SnapshotPfx core.

    For the active MiiIcon no-exposure specialization::

        C = scene + bloom
        Y = dot(C, (0.2989, 0.5866, 0.1144))
        E = 1 - exp(-Y)
        base = C * E / Y
        shoulder = E * E
        target = 1 - exp(-C)
        output = saturate(mix(base, target, shoulder))

    The analytic limit ``E/Y -> 1`` is used at zero luminance.
    """

    scene = np.asarray(scene_linear_rgb, dtype=np.float64)
    if scene.ndim == 0 or scene.shape[-1] != 3:
        raise ValueError("scene_linear_rgb must have a final axis of length 3")
    if not np.all(np.isfinite(scene)) or np.any(scene < 0.0):
        raise ValueError("scene_linear_rgb must contain finite nonnegative values")
    if bloom_linear_rgb is None:
        bloom = np.zeros_like(scene)
    else:
        bloom = np.asarray(bloom_linear_rgb, dtype=np.float64)
        if bloom.shape != scene.shape:
            raise ValueError("bloom_linear_rgb must match the scene shape")
        if not np.all(np.isfinite(bloom)) or np.any(bloom < 0.0):
            raise ValueError("bloom_linear_rgb must contain finite nonnegative values")

    combined = scene + bloom
    luminance = np.sum(combined * LUMINANCE_WEIGHTS, axis=-1)
    exposure_curve = -np.expm1(-luminance)
    ratio = np.ones_like(luminance)
    np.divide(exposure_curve, luminance, out=ratio, where=luminance != 0.0)
    base = combined * ratio[..., np.newaxis]
    shoulder = exposure_curve * exposure_curve
    target = -np.expm1(-combined)
    return np.clip(
        base + (target - base) * shoulder[..., np.newaxis], 0.0, 1.0
    )


__all__ = ["LUMINANCE_WEIGHTS", "snapshot_pfx_tone_map_gamma0"]
