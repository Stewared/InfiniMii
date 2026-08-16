"""Optional exact-output compiled coverage kernel for the portable renderer.

The extension is deliberately narrow: Python continues to own recovered scene
construction and material behavior, while the per-pixel triangle coverage and
early-depth prefix runs in compiled code.  Missing or disabled native code
falls back to the original NumPy implementation without changing output.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any


DISABLED_BY_ENVIRONMENT = os.environ.get("LTD_DISABLE_NATIVE_RASTER_KERNEL") == "1"
IMPORT_ERROR: Exception | None = None

if not DISABLED_BY_ENVIRONMENT:
    try:
        import _native_raster_kernel as _compiled

        source = Path(__file__).with_name("native_raster_kernel.c")
        expected_source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        if _compiled.ABI_VERSION != 1:
            raise ImportError(
                f"compiled raster ABI {_compiled.ABI_VERSION!r} is not supported"
            )
        if _compiled.SOURCE_SHA256 != expected_source_sha256:
            raise ImportError("compiled raster kernel does not match its C source")
        _coverage_fragments = _compiled.coverage_fragments
        _sample_bilinear = _compiled.sample_bilinear
    except (AttributeError, ImportError, OSError) as error:
        # A source checkout remains runnable before a local build, and a stale
        # extension fails closed instead of silently changing renderer output.
        IMPORT_ERROR = error
        _coverage_fragments = None
        _sample_bilinear = None
else:
    _coverage_fragments = None
    _sample_bilinear = None


BACKEND_AVAILABLE = _coverage_fragments is not None


def coverage_fragments(
    screen: Any,
    depth: Any,
    x0: int,
    x1: int,
    y0: int,
    y1: int,
    denominator: float,
) -> tuple[Any, Any, Any, Any, Any, Any] | None:
    if _coverage_fragments is None:
        raise RuntimeError("the compiled raster coverage kernel is unavailable")
    return _coverage_fragments(screen, depth, x0, x1, y0, y1, denominator)


_WRAP_MODE = {"clamp": 0, "repeat": 1, "mirror": 2}


def sample_bilinear(
    source: Any,
    u_coordinates: Any,
    v_coordinates: Any,
    x_offset: int,
    y_offset: int,
    wrap: tuple[str, str],
) -> Any:
    if _sample_bilinear is None:
        raise RuntimeError("the compiled raster texture kernel is unavailable")
    try:
        wrap_x = _WRAP_MODE[wrap[0]]
        wrap_y = _WRAP_MODE[wrap[1]]
    except (KeyError, IndexError) as error:
        raise ValueError(f"unsupported texture wrap mode: {wrap!r}") from error
    return _sample_bilinear(
        source,
        u_coordinates,
        v_coordinates,
        x_offset,
        y_offset,
        wrap_x,
        wrap_y,
    )
