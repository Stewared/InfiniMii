"""Optional native whole-draw kernels for current portable renderer output.

The production :mod:`software_renderer` dispatches here only when a complete
material/group/rasterizer fingerprint matches.  Python remains the authority
for recovered scene construction, transforms, projection, front-face
filtering, and point-mip selection.  The extension receives only contiguous
primitive arrays and mutates the caller-owned color/depth/alpha attachments in
place; every unsupported fingerprint executes the unchanged Python path.

The implemented responses are the *current portable* Head816, Hair612,
equal-endpoint Hair564, Beard468, opaque OutfitTops984/Bottoms936/Shoes912,
Body324/336/348, Ear372, Nose756, and Mask0 profiles.  They are not a claim
that the title's missing environment, material, GlobalUBO, light-prepass, or
face-shadow inputs were recovered.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Any

import numpy as np

try:
    from . import gameuber_cpu
except ImportError:  # Direct renderer-directory import.
    import gameuber_cpu


ABI_VERSION = 8
DISABLED_BY_ENVIRONMENT = os.environ.get("LTD_DISABLE_NATIVE_CURRENT_DRAW") == "1"
IMPORT_ERROR: Exception | None = None

if not DISABLED_BY_ENVIRONMENT:
    try:
        try:
            from . import _native_current_draw as _compiled
        except ImportError:  # Direct renderer-directory import.
            import _native_current_draw as _compiled

        _source = Path(__file__).with_name("native_current_draw_kernel.c")
        _opaque_source = Path(__file__).with_name(
            "native_current_opaque_kernel.c"
        )
        _expected_source_sha256 = hashlib.sha256(_source.read_bytes()).hexdigest()
        _expected_opaque_source_sha256 = hashlib.sha256(
            _opaque_source.read_bytes()
        ).hexdigest()
        if _compiled.ABI_VERSION != ABI_VERSION:
            raise ImportError(
                f"compiled current-draw ABI {_compiled.ABI_VERSION!r} is not supported"
            )
        if _compiled.SOURCE_SHA256 != _expected_source_sha256:
            raise ImportError("compiled current-draw kernel does not match its C source")
        if _compiled.OPAQUE_SOURCE_SHA256 != _expected_opaque_source_sha256:
            raise ImportError("compiled current-draw opaque kernel does not match its C source")
        _draw_head816_compiled = _compiled.draw_head816
        _draw_hair612_compiled = _compiled.draw_hair612
        _draw_beard468_compiled = _compiled.draw_beard468
        _draw_hair564_compiled = _compiled.draw_hair564
        _draw_outfit984_compiled = _compiled.draw_outfit984
        _draw_outfit936_compiled = _compiled.draw_outfit936
        _draw_outfit912_compiled = _compiled.draw_outfit912
        _draw_body_compiled = _compiled.draw_body
        _draw_plain_skin_compiled = _compiled.draw_plain_skin
        _draw_mask0_compiled = _compiled.draw_mask0
        if _compiled.HAIR612_PARAMETER_COUNT != 33:
            raise ImportError("compiled Hair612 parameter ABI changed")
    except (AttributeError, ImportError, OSError) as error:
        IMPORT_ERROR = error
        _draw_head816_compiled = None
        _draw_hair612_compiled = None
        _draw_beard468_compiled = None
        _draw_hair564_compiled = None
        _draw_outfit984_compiled = None
        _draw_outfit936_compiled = None
        _draw_outfit912_compiled = None
        _draw_body_compiled = None
        _draw_plain_skin_compiled = None
        _draw_mask0_compiled = None
else:
    _draw_head816_compiled = None
    _draw_hair612_compiled = None
    _draw_beard468_compiled = None
    _draw_hair564_compiled = None
    _draw_outfit984_compiled = None
    _draw_outfit936_compiled = None
    _draw_outfit912_compiled = None
    _draw_body_compiled = None
    _draw_plain_skin_compiled = None
    _draw_mask0_compiled = None


BACKEND_AVAILABLE = (
    _draw_head816_compiled is not None
    and _draw_hair612_compiled is not None
    and _draw_beard468_compiled is not None
    and _draw_hair564_compiled is not None
    and _draw_outfit984_compiled is not None
    and _draw_outfit936_compiled is not None
    and _draw_outfit912_compiled is not None
    and _draw_body_compiled is not None
    and _draw_plain_skin_compiled is not None
    and _draw_mask0_compiled is not None
)


@dataclass(frozen=True)
class FlattenedHead816Draw:
    """Contiguous ABI payload for one already transformed Head816 group.

    Array layouts are intentionally explicit and index-free.  Candidate
    triangles retain source order.  ``normal_levels`` rows are
    ``(texel_offset, height, width)`` into the packed ``normal_texels`` bank.
    """

    screen_triangles: np.ndarray  # float64 [triangle, corner, xyz]
    bounds: np.ndarray  # int64 [triangle, (x0, x1, y0, y1)]
    denominators: np.ndarray  # float64 [triangle]
    world_vertices: np.ndarray  # float64 [triangle, corner, xyz]
    vertex_normals: np.ndarray  # float64 [triangle, corner, xyz]
    vertex_normal_valid: np.ndarray  # uint8 [triangle]
    albedo_uv: np.ndarray  # float64 [triangle, corner, uv]
    normal_uv: np.ndarray  # float64 [triangle, corner, uv]
    albedo_texture: np.ndarray  # float64 [height, width, rgba], RGB already linear
    normal_texels: np.ndarray  # float64 [packed texel, rgba]
    normal_levels: np.ndarray  # int64 [level, (offset, height, width)]
    normal_level_indices: np.ndarray  # int64 [triangle]
    base_color_linear: np.ndarray  # float64 [rgb]
    has_albedo_texture: bool
    alpha_scalar: float
    submitted_triangle_count: int

    @property
    def candidate_triangle_count(self) -> int:
        return int(self.screen_triangles.shape[0])


@dataclass(frozen=True)
class Head816DrawResult:
    """Prototype dispatch counters; attachment data is mutated in place."""

    submitted_triangles: int
    candidate_triangles: int
    written_fragments: int


@dataclass(frozen=True)
class FlattenedHair612Draw:
    """Contiguous current-output Hair612 payload in source triangle order."""

    screen_triangles: np.ndarray
    bounds: np.ndarray
    denominators: np.ndarray
    world_vertices: np.ndarray
    vertex_normals: np.ndarray
    material_uv: np.ndarray
    mim_texels: np.ndarray
    mim_levels: np.ndarray
    mim_level_indices: np.ndarray
    parameters: np.ndarray
    submitted_triangle_count: int

    @property
    def candidate_triangle_count(self) -> int:
        return int(self.screen_triangles.shape[0])


@dataclass(frozen=True)
class Hair612DrawResult:
    """Hair612 dispatch counters; caller-owned attachments were mutated."""

    submitted_triangles: int
    candidate_triangles: int
    written_fragments: int


@dataclass(frozen=True)
class FlattenedOpaqueOutfitDraw:
    """Contiguous exact-current payload for an admitted opaque outfit draw."""

    screen_triangles: np.ndarray
    bounds: np.ndarray
    denominators: np.ndarray
    world_vertices: np.ndarray
    vertex_normals: np.ndarray
    material_uv: np.ndarray
    albedo_texels: np.ndarray
    albedo_levels: np.ndarray
    albedo_lower_indices: np.ndarray
    albedo_upper_indices: np.ndarray
    albedo_mip_amounts: np.ndarray
    normal_texels: np.ndarray
    normal_levels: np.ndarray
    normal_level_indices: np.ndarray
    submitted_triangle_count: int

    @property
    def candidate_triangle_count(self) -> int:
        return int(self.screen_triangles.shape[0])


@dataclass(frozen=True)
class OpaqueOutfitDrawResult:
    """Opaque outfit dispatch counters; caller-owned attachments were mutated."""

    submitted_triangles: int
    candidate_triangles: int
    written_fragments: int


@dataclass(frozen=True)
class FlattenedBodyDraw:
    """Contiguous exact-current Body324/336/348 attachment payload."""

    screen_triangles: np.ndarray
    bounds: np.ndarray
    denominators: np.ndarray
    world_vertices: np.ndarray
    vertex_normals: np.ndarray
    material_uv: np.ndarray
    albedo_texels: np.ndarray
    albedo_levels: np.ndarray
    albedo_lower_indices: np.ndarray
    albedo_upper_indices: np.ndarray
    albedo_mip_amounts: np.ndarray
    skin_texels: np.ndarray
    skin_levels: np.ndarray
    skin_lower_indices: np.ndarray
    skin_upper_indices: np.ndarray
    skin_mip_amounts: np.ndarray
    normal_texels: np.ndarray
    normal_levels: np.ndarray
    normal_level_indices: np.ndarray
    face_color_linear: np.ndarray
    submitted_triangle_count: int

    @property
    def candidate_triangle_count(self) -> int:
        return int(self.screen_triangles.shape[0])


@dataclass(frozen=True)
class FlattenedPlainSkinDraw:
    """Texture-free current Ear372/Nose756 attachment payload."""

    screen_triangles: np.ndarray
    bounds: np.ndarray
    denominators: np.ndarray
    vertex_normals: np.ndarray
    base_color_linear: np.ndarray
    submitted_triangle_count: int

    @property
    def candidate_triangle_count(self) -> int:
        return int(self.screen_triangles.shape[0])


@dataclass(frozen=True)
class OpaqueCurrentDrawResult:
    """Body/Ear/Nose dispatch counters; caller-owned attachments were mutated."""

    submitted_triangles: int
    candidate_triangles: int
    written_fragments: int


# Compatibility names for callers written against the first Tops-only ABI.
FlattenedOutfit984Draw = FlattenedOpaqueOutfitDraw
Outfit984DrawResult = OpaqueOutfitDrawResult


@dataclass(frozen=True)
class FlattenedMask0Draw:
    screen_triangles: np.ndarray
    bounds: np.ndarray
    denominators: np.ndarray
    world_vertices: np.ndarray
    vertex_normals: np.ndarray
    material_uv: np.ndarray
    generated_texture: np.ndarray
    user_texture: np.ndarray
    light_direction: np.ndarray
    light_color: np.ndarray
    ambient_color: np.ndarray
    parameters: np.ndarray
    submitted_triangle_count: int

    @property
    def candidate_triangle_count(self) -> int:
        return int(self.screen_triangles.shape[0])


@dataclass(frozen=True)
class Mask0DrawResult:
    submitted_triangles: int
    candidate_triangles: int
    written_fragments: int


MAX_PACKED_TEXTURES = 16
_packed_texture_cache: OrderedDict[
    tuple[int, bool], tuple[Any, np.ndarray, np.ndarray]
] = OrderedDict()


def clear_runtime_caches() -> None:
    """Drop non-authoritative packed-mip acceleration state."""

    _packed_texture_cache.clear()


def runtime_cache_size() -> int:
    """Return the resident packed texture count for lifecycle verification."""

    return len(_packed_texture_cache)


def _as_contiguous_exact(
    value: Any,
    dtype: np.dtype[Any] | type[Any],
    shape: tuple[int | None, ...],
    name: str,
    *,
    writable: bool = False,
) -> np.ndarray:
    """Validate the no-copy public ABI used by :func:`draw_head816_flat`."""

    if not isinstance(value, np.ndarray):
        raise TypeError(f"{name} must be a NumPy array")
    expected_dtype = np.dtype(dtype)
    if value.dtype != expected_dtype:
        raise TypeError(f"{name} must have dtype {expected_dtype}")
    if value.ndim != len(shape) or any(
        expected is not None and actual != expected
        for actual, expected in zip(value.shape, shape)
    ):
        expected_shape = tuple("*" if item is None else item for item in shape)
        raise ValueError(f"{name} must have shape {expected_shape}, got {value.shape}")
    if not value.flags.c_contiguous or not value.flags.aligned:
        raise ValueError(f"{name} must be C-contiguous and aligned")
    if writable and not value.flags.writeable:
        raise ValueError(f"{name} must be writable")
    return value


def _point_mip_index(
    screen: np.ndarray,
    triangle_uv: np.ndarray,
    base_height: int,
    base_width: int,
    level_count: int,
) -> int:
    """Repeat ``sample_uv_map``'s exact triangle-constant point-mip choice."""

    if level_count == 1:
        return 0
    screen_edges = np.asarray(
        (screen[1, :2] - screen[0, :2], screen[2, :2] - screen[0, :2]),
        dtype=np.float64,
    )
    uv_edges = np.asarray(
        (triangle_uv[1] - triangle_uv[0], triangle_uv[2] - triangle_uv[0]),
        dtype=np.float64,
    )
    gradient = np.linalg.solve(screen_edges, uv_edges)
    rho_x = np.hypot(
        gradient[0, 0] * base_width,
        gradient[0, 1] * base_height,
    )
    rho_y = np.hypot(
        gradient[1, 0] * base_width,
        gradient[1, 1] * base_height,
    )
    lod = float(
        np.clip(
            np.log2(max(float(rho_x), float(rho_y), 1.0)),
            0.0,
            level_count - 1,
        )
    )
    return min(level_count - 1, int(np.floor(lod + 0.5)))


def _linear_mip_selection(
    screen: np.ndarray,
    triangle_uv: np.ndarray,
    base_height: int,
    base_width: int,
    level_count: int,
) -> tuple[int, int, float]:
    """Repeat ``sample_uv_map``'s triangle-constant trilinear selection."""

    if level_count == 1:
        return 0, 0, 0.0
    screen_edges = np.asarray(
        (screen[1, :2] - screen[0, :2], screen[2, :2] - screen[0, :2]),
        dtype=np.float64,
    )
    uv_edges = np.asarray(
        (triangle_uv[1] - triangle_uv[0], triangle_uv[2] - triangle_uv[0]),
        dtype=np.float64,
    )
    gradient = np.linalg.solve(screen_edges, uv_edges)
    rho_x = np.hypot(
        gradient[0, 0] * base_width,
        gradient[0, 1] * base_height,
    )
    rho_y = np.hypot(
        gradient[1, 0] * base_width,
        gradient[1, 1] * base_height,
    )
    lod = float(
        np.clip(
            np.log2(max(float(rho_x), float(rho_y), 1.0)),
            0.0,
            level_count - 1,
        )
    )
    lower = int(np.floor(lod))
    return lower, min(level_count - 1, lower + 1), lod - lower


def _require_current_head816_style(style: Any, rasterizer: Any) -> None:
    """Fail closed if the caller is not the exact current Head816 branch."""

    identity = getattr(style, "gameall_identity", None)
    if identity is None or (identity.family, identity.program_index) != ("head", 816):
        raise ValueError("native current-draw prototype accepts only Head816")
    if not bool(getattr(rasterizer, "linear_framebuffer", False)):
        raise ValueError("Head816 prototype requires the current linear framebuffer")

    expected_values = {
        "gameuber_body348": None,
        "gameuber_mask0_facepaint": None,
        "texture_emission_intensity": 0.0,
        "texture_alpha_under_color_linear": None,
        "alpha_texture": None,
        "height_texture": None,
        "parallax_texture": None,
        "occlusion_texture": None,
        "specular_texture": None,
        "roughness_texture": None,
        "gradient_texture": None,
        "gradient_colors": None,
        "hair_constant_color_linear": None,
        "hair708_face_color_linear": None,
        "specular_strength": 0.0,
        "anisotropic_proxy": False,
        "cheap_sss_proxy": True,
        "cheap_sss_mask_texture": None,
        "front_edge_light_proxy": False,
        "lit": True,
        "depth_write": True,
        "cull_back_faces": True,
        "clockwise_front_face": False,
        "flip_horizontal_sign": 1.0,
        "blend": False,
        "premultiplied_rgb_blend": False,
        "gamma_correct_lighting": False,
        "linear_lighting": True,
        "receives_screenspace_face_shadow": True,
        "unresolved_portable_family": None,
    }
    changed = [
        name
        for name, expected in expected_values.items()
        if getattr(style, name, object()) != expected
    ]
    if changed:
        raise ValueError(
            "Head816 prototype does not implement changed material fields: "
            + ", ".join(changed)
        )
    if style.normal_texture is None:
        raise ValueError("current Head816 requires its RA normal-height texture")
    if (
        tuple(style.normal_wrap) != ("repeat", "repeat")
        or style.normal_mip_filter != "point"
        or tuple(style.normal_channels) != (0, 3)
        or float(style.normal_strength) != 1.0
    ):
        raise ValueError("Head816 normal sampler/reconstruction state changed")
    if float(style.alpha_cutoff) != 1.0 / 255.0:
        raise ValueError("Head816 alpha cutoff changed")
    if float(style.alpha_multiplier) != 1.0:
        raise ValueError("Head816 alpha multiplier changed")

    if style.texture is None:
        expected_bindings = {"normal": "_u2"}
    else:
        if isinstance(style.texture, tuple):
            raise ValueError("current generated Head816 _a0 target must have one level")
        if (
            tuple(style.texture_wrap) != ("mirror", "repeat")
            or style.texture_mip_filter != "point"
        ):
            raise ValueError("Head816 generated-faceline sampler state changed")
        expected_bindings = {"texture": "_u0", "normal": "_u2"}
    if dict(style.texcoord_bindings) != expected_bindings:
        raise ValueError("Head816 _u0/_u2 routing changed")

    # The current branch records the recovered curve but deliberately leaves
    # it disabled until title prepass/user4 inputs are authenticated.
    try:
        from .screen_space_face_shadow import PORTABLE_CHEAP_SSS_INPUT
    except ImportError:
        from screen_space_face_shadow import PORTABLE_CHEAP_SSS_INPUT
    if PORTABLE_CHEAP_SSS_INPUT.correction_enabled:
        raise ValueError("Head816 cheap-SSS execution changed; prototype is stale")


def supports_head816_draw(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
) -> bool:
    """Return whether the complete current Head816 fingerprint is supported.

    This boundary is intentionally pure: ordinary unsupported draws return
    ``False`` and remain eligible for the existing Python implementation.
    Explicit flatten/execute calls stay strict and diagnose stale contracts.
    """

    if _draw_head816_compiled is None or group != "Head__mt_Head":
        return False
    try:
        _require_current_head816_style(style, rasterizer)
    except (AttributeError, ImportError, TypeError, ValueError):
        return False
    if group not in getattr(mesh, "groups", ()):
        return False
    channels = getattr(mesh, "texcoord_channels", {})
    if not isinstance(channels, dict) or "_u2" not in channels:
        return False
    if style.texture is not None and "_u0" not in channels:
        return False
    return True


def flatten_head816_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedHead816Draw:
    """Flatten one current Head816 group without changing any attachment."""

    _require_current_head816_style(style, rasterizer)
    if group != "Head__mt_Head":
        raise ValueError("Head816 prototype accepts only Head__mt_Head")

    matrix = (
        np.identity(4, dtype=np.float64)
        if transform is None
        else np.asarray(transform, dtype=np.float64)
    )
    positions = rasterizer._transform_positions(mesh.positions, matrix)
    normals = rasterizer._transform_normals(mesh.normals, matrix)
    projected = rasterizer._project(positions)
    triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
    submitted_count = len(triangles)

    normal_source = (
        style.normal_texture
        if isinstance(style.normal_texture, tuple)
        else (style.normal_texture,)
    )
    normal_levels_list: list[np.ndarray] = []
    normal_level_rows: list[tuple[int, int, int]] = []
    texel_offset = 0
    for index, level in enumerate(normal_source):
        level_array = np.asarray(level)
        if (
            level_array.dtype != np.float64
            or level_array.ndim != 3
            or level_array.shape[0] <= 0
            or level_array.shape[1] <= 0
            or level_array.shape[2] < 4
        ):
            raise ValueError(
                f"Head816 normal mip {index} must be nonempty float64 RGBA"
            )
        rgba = np.ascontiguousarray(level_array[..., :4], dtype=np.float64)
        normal_levels_list.append(rgba.reshape(-1, 4))
        normal_level_rows.append((texel_offset, rgba.shape[0], rgba.shape[1]))
        texel_offset += rgba.shape[0] * rgba.shape[1]
    normal_texels = np.ascontiguousarray(
        np.concatenate(normal_levels_list, axis=0), dtype=np.float64
    )
    normal_levels = np.ascontiguousarray(normal_level_rows, dtype=np.int64)

    if style.texture is None:
        # The compiled ABI always receives a concrete RGBA array.  This
        # sentinel is never sampled when has_albedo_texture is false.
        albedo_texture = np.ones((1, 1, 4), dtype=np.float64)
        has_albedo = False
    else:
        level = np.asarray(style.texture)
        if (
            level.dtype != np.float64
            or level.ndim != 3
            or level.shape[0] <= 0
            or level.shape[1] <= 0
            or level.shape[2] < 4
        ):
            raise ValueError("Head816 generated _a0 must be nonempty float64 RGBA")
        # Reuse the rasterizer's exact whole-level IEC-sRGB decode/cache.
        albedo_texture = np.ascontiguousarray(
            rasterizer._hardware_srgb_texture_level(level)[..., :4],
            dtype=np.float64,
        )
        has_albedo = True

    base_rgb = np.asarray(style.color[:3], dtype=np.float64)
    base_color_linear = np.ascontiguousarray(
        np.where(
            base_rgb <= 0.04045,
            base_rgb / 12.92,
            np.power((base_rgb + 0.055) / 1.055, 2.4),
        ),
        dtype=np.float64,
    )
    alpha_scalar = float(style.color[3] * style.alpha_multiplier)

    if submitted_count == 0:
        return FlattenedHead816Draw(
            *(np.empty(shape, dtype=dtype) for shape, dtype in (
                ((0, 3, 3), np.float64),
                ((0, 4), np.int64),
                ((0,), np.float64),
                ((0, 3, 3), np.float64),
                ((0, 3, 3), np.float64),
                ((0,), np.uint8),
                ((0, 3, 2), np.float64),
                ((0, 3, 2), np.float64),
            )),
            albedo_texture=albedo_texture,
            normal_texels=normal_texels,
            normal_levels=normal_levels,
            normal_level_indices=np.empty((0,), dtype=np.int64),
            base_color_linear=base_color_linear,
            has_albedo_texture=has_albedo,
            alpha_scalar=alpha_scalar,
            submitted_triangle_count=0,
        )

    vertex_indices = np.asarray([triangle.vertex for triangle in triangles], dtype=np.int64)
    screens = projected[vertex_indices]
    finite = np.all(np.isfinite(screens), axis=(1, 2))
    candidate = finite.copy()
    safe_screens = np.where(finite[:, None, None], screens, 0.0)
    screen_x = safe_screens[..., 0]
    screen_y = safe_screens[..., 1]
    x0 = np.maximum(0, np.floor(np.min(screen_x, axis=1))).astype(np.int64)
    x1 = np.minimum(
        rasterizer.width - 1, np.ceil(np.max(screen_x, axis=1))
    ).astype(np.int64)
    y0 = np.maximum(0, np.floor(np.min(screen_y, axis=1))).astype(np.int64)
    y1 = np.minimum(
        rasterizer.height - 1, np.ceil(np.max(screen_y, axis=1))
    ).astype(np.int64)
    candidate &= (x0 <= x1) & (y0 <= y1)
    denominator = (
        (screen_x[:, 0] - screen_x[:, 1])
        * (screen_y[:, 2] - screen_y[:, 1])
        - (screen_y[:, 0] - screen_y[:, 1])
        * (screen_x[:, 2] - screen_x[:, 1])
    )
    candidate &= np.abs(denominator) >= 1e-10
    candidate &= denominator > 0.0
    selected = np.flatnonzero(candidate)

    selected_triangles = [triangles[int(index)] for index in selected]
    selected_vertices = vertex_indices[selected]
    selected_screens = np.ascontiguousarray(screens[selected], dtype=np.float64)
    bounds = np.ascontiguousarray(
        np.column_stack((x0[selected], x1[selected], y0[selected], y1[selected])),
        dtype=np.int64,
    )
    denominators = np.ascontiguousarray(denominator[selected], dtype=np.float64)
    world_vertices = np.ascontiguousarray(positions[selected_vertices], dtype=np.float64)

    vertex_normal_valid = np.ascontiguousarray(
        [all(index is not None for index in triangle.normal) for triangle in selected_triangles],
        dtype=np.uint8,
    )
    vertex_normals = np.zeros((len(selected), 3, 3), dtype=np.float64)
    for output_index, triangle in enumerate(selected_triangles):
        if vertex_normal_valid[output_index]:
            vertex_normals[output_index] = normals[
                np.asarray(triangle.normal, dtype=np.int64)
            ]
    vertex_normals = np.ascontiguousarray(vertex_normals)

    try:
        normal_channel = mesh.texcoord_channels["_u2"]
    except KeyError as error:
        raise ValueError("Head816 mesh is missing authored _u2") from error
    normal_uv = np.ascontiguousarray(normal_channel[selected_vertices], dtype=np.float64)
    if not np.all(np.isfinite(normal_uv)):
        raise ValueError("Head816 selected shape has non-finite _u2")

    if has_albedo:
        try:
            albedo_channel = mesh.texcoord_channels["_u0"]
        except KeyError as error:
            raise ValueError("Head816 mesh is missing authored _u0") from error
        albedo_uv = np.ascontiguousarray(albedo_channel[selected_vertices], dtype=np.float64)
        if not np.all(np.isfinite(albedo_uv)):
            raise ValueError("Head816 selected shape has non-finite _u0")
    else:
        albedo_uv = np.zeros((len(selected), 3, 2), dtype=np.float64)

    normal_level_indices = np.ascontiguousarray(
        [
            _point_mip_index(
                selected_screens[index],
                normal_uv[index],
                int(normal_levels[0, 1]),
                int(normal_levels[0, 2]),
                len(normal_levels),
            )
            for index in range(len(selected))
        ],
        dtype=np.int64,
    )

    return FlattenedHead816Draw(
        screen_triangles=selected_screens,
        bounds=bounds,
        denominators=denominators,
        world_vertices=world_vertices,
        vertex_normals=vertex_normals,
        vertex_normal_valid=vertex_normal_valid,
        albedo_uv=albedo_uv,
        normal_uv=normal_uv,
        albedo_texture=albedo_texture,
        normal_texels=normal_texels,
        normal_levels=normal_levels,
        normal_level_indices=normal_level_indices,
        base_color_linear=base_color_linear,
        has_albedo_texture=has_albedo,
        alpha_scalar=alpha_scalar,
        submitted_triangle_count=submitted_count,
    )


def draw_head816_flat(
    color: np.ndarray,
    depth: np.ndarray,
    target_alpha: np.ndarray | None,
    payload: FlattenedHead816Draw,
    *,
    light_direction: np.ndarray,
    light_color: np.ndarray,
    ambient_color: np.ndarray,
    light_intensity: float,
    ambient_intensity: float,
    perspective_correct: bool,
    alpha_cutoff: float = 1.0 / 255.0,
) -> int:
    """Execute the flat ABI and mutate caller-owned attachments in place.

    No input is coerced here: dtype/shape/contiguity errors fail before the C
    call.  Consequently the writable buffers passed to C are the exact arrays
    owned by the rasterizer, not temporary writeback copies.
    """

    if _draw_head816_compiled is None:
        detail = "" if IMPORT_ERROR is None else f": {IMPORT_ERROR}"
        raise RuntimeError(f"native current-draw prototype is unavailable{detail}")
    color = _as_contiguous_exact(color, np.float64, (None, None, 3), "color", writable=True)
    depth = _as_contiguous_exact(depth, np.float64, color.shape[:2], "depth", writable=True)
    if target_alpha is not None:
        target_alpha = _as_contiguous_exact(
            target_alpha,
            np.float64,
            color.shape[:2],
            "target_alpha",
            writable=True,
        )

    triangle_count = payload.candidate_triangle_count
    arrays = (
        (payload.screen_triangles, np.float64, (triangle_count, 3, 3), "screen_triangles"),
        (payload.bounds, np.int64, (triangle_count, 4), "bounds"),
        (payload.denominators, np.float64, (triangle_count,), "denominators"),
        (payload.world_vertices, np.float64, (triangle_count, 3, 3), "world_vertices"),
        (payload.vertex_normals, np.float64, (triangle_count, 3, 3), "vertex_normals"),
        (payload.vertex_normal_valid, np.uint8, (triangle_count,), "vertex_normal_valid"),
        (payload.albedo_uv, np.float64, (triangle_count, 3, 2), "albedo_uv"),
        (payload.normal_uv, np.float64, (triangle_count, 3, 2), "normal_uv"),
        (payload.albedo_texture, np.float64, (None, None, 4), "albedo_texture"),
        (payload.normal_texels, np.float64, (None, 4), "normal_texels"),
        (payload.normal_levels, np.int64, (None, 3), "normal_levels"),
        (payload.normal_level_indices, np.int64, (triangle_count,), "normal_level_indices"),
        (payload.base_color_linear, np.float64, (3,), "base_color_linear"),
        (light_direction, np.float64, (3,), "light_direction"),
        (light_color, np.float64, (3,), "light_color"),
        (ambient_color, np.float64, (3,), "ambient_color"),
    )
    checked = [
        _as_contiguous_exact(value, dtype, shape, name)
        for value, dtype, shape, name in arrays
    ]
    if payload.albedo_texture.shape[0] <= 0 or payload.albedo_texture.shape[1] <= 0:
        raise ValueError("albedo_texture must be nonempty")
    if payload.normal_texels.shape[0] <= 0 or payload.normal_levels.shape[0] <= 0:
        raise ValueError("normal mip bank must be nonempty")

    return int(
        _draw_head816_compiled(
            color,
            depth,
            target_alpha,
            *checked,
            float(light_intensity),
            float(ambient_intensity),
            float(payload.alpha_scalar),
            float(alpha_cutoff),
            int(bool(perspective_correct)),
            int(bool(payload.has_albedo_texture)),
        )
    )


def draw_head816_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> Head816DrawResult:
    """Flatten and execute one isolated current-output Head816 draw."""

    payload = flatten_head816_group(rasterizer, mesh, group, style, transform)
    written = draw_head816_flat(
        rasterizer.color,
        rasterizer.depth,
        rasterizer.target_alpha,
        payload,
        light_direction=np.ascontiguousarray(rasterizer.light_direction, dtype=np.float64),
        light_color=np.ascontiguousarray(rasterizer.light_color, dtype=np.float64),
        ambient_color=np.ascontiguousarray(rasterizer.ambient_color, dtype=np.float64),
        light_intensity=float(rasterizer.light_intensity),
        ambient_intensity=float(rasterizer.ambient_intensity),
        perspective_correct=bool(rasterizer.perspective_correct),
        alpha_cutoff=float(style.alpha_cutoff),
    )
    return Head816DrawResult(
        submitted_triangles=payload.submitted_triangle_count,
        candidate_triangles=payload.candidate_triangle_count,
        written_fragments=written,
    )


def try_draw_head816_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> Head816DrawResult | None:
    """Draw a supported Head816 group, or return ``None`` for Python fallback."""

    if not supports_head816_draw(rasterizer, mesh, group, style):
        return None
    return draw_head816_group(rasterizer, mesh, group, style, transform)


def _supports_anisotropic_rasterizer_state(rasterizer: Any) -> bool:
    """Admit only finite camera/light state handled by the flat ABI."""

    try:
        light = np.asarray(rasterizer.light_direction, dtype=np.float64)
        camera = rasterizer.camera_position
        return (
            np.asarray(rasterizer.edge_light_color).shape == (3,)
            and not np.any(np.asarray(rasterizer.edge_light_color, dtype=np.float64))
            and light.shape == (3,)
            and np.all(np.isfinite(light))
            and float(np.linalg.norm(light)) > 1e-12
            and (
                camera is None
                or (
                    np.asarray(camera).shape == (3,)
                    and np.all(np.isfinite(np.asarray(camera, dtype=np.float64)))
                )
            )
        )
    except (AttributeError, TypeError, ValueError):
        return False


def supports_hair612_draw(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
) -> bool:
    """Pure strict fingerprint for the one exact-current Hair612 profile."""

    identity = getattr(style, "gameall_identity", None)
    if (
        _draw_hair612_compiled is None
        or group != "Hair__mt_Hair"
        or identity is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None))
        != ("hair_anisotropic", 612)
        or not bool(getattr(rasterizer, "linear_framebuffer", False))
        or not _supports_anisotropic_rasterizer_state(rasterizer)
    ):
        return False
    expected = {
        "gameuber_body348": None,
        "gameuber_mask0_facepaint": None,
        "texture": None,
        "alpha_texture": None,
        "normal_texture": None,
        "height_texture": None,
        "parallax_texture": None,
        "roughness_texture": None,
        "cheap_sss_mask_texture": None,
        "hair_constant_color_linear": None,
        "hair708_face_color_linear": None,
        "unresolved_portable_family": None,
        "texcoord_bindings": {},
        "anisotropic_proxy": True,
        "cheap_sss_proxy": False,
        "front_edge_light_proxy": True,
        "specular_strength": 0.0,
        "gamma_correct_lighting": True,
        "linear_lighting": False,
        "lit": True,
        "depth_write": True,
        "blend": False,
        "premultiplied_rgb_blend": False,
        "cull_back_faces": True,
        "clockwise_front_face": False,
        "alpha_multiplier": 1.0,
        "alpha_cutoff": 0.5,
        "flip_horizontal_sign": 1.0,
        "anisotropic_shift_channel": 2,
        "anisotropic_shift_scale": 1.0,
        "anisotropic_shift_offset": 0.0,
        "anisotropic_specular_size": 10.0,
        "anisotropic_toon_intensity": 1.0,
        "anisotropic_title_view_scale": 1.0,
        "anisotropic_radiance_scale": 1.0,
        "roughness": 0.28,
        "specular_wrap": ("repeat", "repeat"),
        "specular_mip_filter": "point",
        "specular_channel": 1,
        "gradient_wrap": ("repeat", "repeat"),
        "gradient_mip_filter": "linear",
        "gradient_channel": 0,
    }
    try:
        if any(getattr(style, name) != value for name, value in expected.items()):
            return False
        if (
            style.specular_texture is None
            or style.occlusion_texture is not style.specular_texture
            or style.gradient_texture is None
            or style.gradient_colors is None
            or float(style.color[3]) < float(style.alpha_cutoff)
        ):
            return False
        endpoints = np.asarray(style.gradient_colors, dtype=np.float64)
        if endpoints.shape != (2, 3) or not np.array_equal(endpoints[0], endpoints[1]):
            return False
        gradient_levels = style.gradient_texture if isinstance(
            style.gradient_texture, tuple
        ) else (style.gradient_texture,)
        if not gradient_levels or any(
            not isinstance(level, np.ndarray)
            or level.ndim != 3
            or level.shape[2] <= style.gradient_channel
            or not np.all(np.isfinite(level))
            for level in gradient_levels
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return bool(triangles) and all(
            all(index is not None for index in triangle.texcoord)
            and all(index is not None for index in triangle.normal)
            for triangle in triangles
        )
    except (AttributeError, TypeError, ValueError):
        return False


def supports_beard468_draw(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
) -> bool:
    """Pure strict fingerprint for the exact current Beard02/program468 path."""

    identity = getattr(style, "gameall_identity", None)
    if (
        _draw_beard468_compiled is None
        or group != "Beard__mt_Beard"
        or identity is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None))
        != ("beard_anisotropic", 468)
        or not bool(getattr(rasterizer, "linear_framebuffer", False))
        or not _supports_anisotropic_rasterizer_state(rasterizer)
    ):
        return False
    expected = {
        "gameuber_body348": None,
        "gameuber_mask0_facepaint": None,
        "texture": None,
        "alpha_texture": None,
        "normal_texture": None,
        "height_texture": None,
        "parallax_texture": None,
        "roughness_texture": None,
        "gradient_texture": None,
        "gradient_colors": None,
        "cheap_sss_mask_texture": None,
        "hair_constant_color_linear": None,
        "hair708_face_color_linear": None,
        "unresolved_portable_family": None,
        "texcoord_bindings": {},
        "anisotropic_proxy": True,
        "cheap_sss_proxy": False,
        "front_edge_light_proxy": True,
        "specular_strength": 0.0,
        "gamma_correct_lighting": False,
        "linear_lighting": True,
        "lit": True,
        "depth_write": True,
        "blend": False,
        "premultiplied_rgb_blend": False,
        "cull_back_faces": True,
        "clockwise_front_face": False,
        "alpha_multiplier": 1.0,
        "alpha_cutoff": 1.0 / 255.0,
        "flip_horizontal_sign": 1.0,
        "anisotropic_shift_channel": 2,
        "anisotropic_shift_scale": 1.0,
        "anisotropic_shift_offset": -1.3,
        "anisotropic_specular_size": 10.0,
        "anisotropic_toon_intensity": 0.5,
        "anisotropic_title_view_scale": 1.0,
        "anisotropic_radiance_scale": 1.0,
        "roughness": 0.28,
        "specular_wrap": ("repeat", "repeat"),
        "specular_mip_filter": "point",
        "specular_channel": 1,
        "occlusion_wrap": ("repeat", "repeat"),
        "occlusion_mip_filter": "point",
        "occlusion_channel": 0,
    }
    try:
        if any(getattr(style, name) != value for name, value in expected.items()):
            return False
        if (
            style.specular_texture is None
            or style.occlusion_texture is not style.specular_texture
            or float(style.color[3]) < float(style.alpha_cutoff)
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return bool(triangles) and all(
            all(index is not None for index in triangle.texcoord)
            and all(index is not None for index in triangle.normal)
            for triangle in triangles
        )
    except (AttributeError, TypeError, ValueError):
        return False


def supports_hair564_equal_draw(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
) -> bool:
    """Admit the equal-endpoint current Hair564 path used by Johnny Thunder."""

    identity = getattr(style, "gameall_identity", None)
    if (
        _draw_hair564_compiled is None
        or group != "Hair__mt_Hair"
        or identity is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None))
        != ("hair_endpoint", 564)
        or not bool(getattr(rasterizer, "linear_framebuffer", False))
        or not _supports_anisotropic_rasterizer_state(rasterizer)
    ):
        return False
    expected = {
        "gameuber_body348": None,
        "gameuber_mask0_facepaint": None,
        "texture": None,
        "alpha_texture": None,
        "normal_texture": None,
        "height_texture": None,
        "parallax_texture": None,
        "roughness_texture": None,
        "cheap_sss_mask_texture": None,
        "hair_constant_color_linear": None,
        "hair708_face_color_linear": None,
        "unresolved_portable_family": None,
        "texcoord_bindings": {},
        "anisotropic_proxy": False,
        "cheap_sss_proxy": False,
        "front_edge_light_proxy": False,
        "specular_strength": 0.0,
        "gamma_correct_lighting": True,
        "linear_lighting": False,
        "lit": True,
        "depth_write": True,
        "blend": False,
        "premultiplied_rgb_blend": False,
        "cull_back_faces": True,
        "clockwise_front_face": False,
        "alpha_multiplier": 1.0,
        "alpha_cutoff": 0.5,
        "flip_horizontal_sign": 1.0,
        "specular_wrap": ("repeat", "repeat"),
        "specular_mip_filter": "point",
        "specular_channel": 1,
        "occlusion_wrap": ("repeat", "repeat"),
        "occlusion_mip_filter": "point",
        "occlusion_channel": 0,
        "gradient_wrap": ("repeat", "repeat"),
        "gradient_mip_filter": "linear",
        "gradient_channel": 0,
    }
    try:
        if any(getattr(style, name) != value for name, value in expected.items()):
            return False
        if (
            style.specular_texture is None
            or style.occlusion_texture is not style.specular_texture
            or style.gradient_texture is None
            or style.gradient_colors is None
            or float(style.color[3]) < float(style.alpha_cutoff)
        ):
            return False
        endpoints = np.asarray(style.gradient_colors, dtype=np.float64)
        if (
            endpoints.shape != (2, 3)
            or not np.all(np.isfinite(endpoints))
            or not np.array_equal(endpoints[0], endpoints[1])
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return bool(triangles) and all(
            all(index is not None for index in triangle.texcoord)
            and all(index is not None for index in triangle.normal)
            for triangle in triangles
        )
    except (AttributeError, TypeError, ValueError):
        return False


_OPAQUE_OUTFIT_PROFILES: dict[
    tuple[str, int, str],
    tuple[int, tuple[tuple[int, int], ...], tuple[tuple[int, int], ...], tuple[tuple[int, int], ...]],
] = {
    ("outfit_tops", 984, "Tops__mt_Body"): (
        1104,
        ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1)),
        ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1)),
        ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1)),
    ),
    ("outfit_bottoms", 936, "Bottoms__mt_Body"): (
        774,
        ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1)),
        ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1)),
        ((8, 8), (4, 4), (2, 2), (1, 1)),
    ),
    ("outfit_shoes", 912, "Shoes__mt_Body"): (
        508,
        ((256, 256), (128, 128), (64, 64), (32, 32), (16, 16), (8, 8), (4, 4), (2, 2), (1, 1)),
        ((256, 256), (128, 128), (64, 64), (32, 32), (16, 16), (8, 8), (4, 4), (2, 2), (1, 1)),
        ((256, 256), (128, 128), (64, 64), (32, 32), (16, 16), (8, 8), (4, 4), (2, 2), (1, 1)),
    ),
}


def _supports_opaque_outfit_draw(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    *,
    profile: tuple[str, int, str],
    compiled: Any,
) -> bool:
    """Admit one authenticated opaque outfit profile, failing closed."""

    identity = getattr(style, "gameall_identity", None)
    if (
        compiled is None
        or group != profile[2]
        or identity is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None))
        != profile[:2]
        or not bool(getattr(rasterizer, "linear_framebuffer", False))
        or not bool(getattr(rasterizer, "perspective_correct", False))
    ):
        return False
    expected = {
        "color": (1.0, 1.0, 1.0, 1.0),
        "gameuber_body348": None,
        "gameuber_mask0_facepaint": None,
        "texture_wrap": ("clamp", "clamp"),
        "texture_mip_filter": "linear",
        "texture_emission_intensity": 0.0,
        "texture_alpha_under_color_linear": None,
        "alpha_texture": None,
        "alpha_wrap": ("clamp", "clamp"),
        "alpha_mip_filter": "point",
        "normal_wrap": ("clamp", "clamp"),
        "normal_mip_filter": "point",
        "normal_channels": (0, 1),
        "normal_strength": 1.0,
        "height_texture": None,
        "height_wrap": ("clamp", "clamp"),
        "height_mip_filter": "point",
        "height_channel": 0,
        "height_strength": 0.0,
        "parallax_texture": None,
        "parallax_wrap": ("clamp", "clamp"),
        "parallax_mip_filter": "point",
        "parallax_channel": 0,
        "parallax_scale": 0.0,
        "occlusion_texture": None,
        "occlusion_wrap": ("clamp", "clamp"),
        "occlusion_mip_filter": "point",
        "occlusion_channel": 0,
        "specular_texture": None,
        "specular_wrap": ("clamp", "clamp"),
        "specular_mip_filter": "point",
        "specular_channel": 0,
        "specular_strength": 0.0,
        "anisotropic_proxy": False,
        "cheap_sss_proxy": False,
        "cheap_sss_mask_texture": None,
        "front_edge_light_proxy": False,
        "front_edge_light_view_angle_degrees": 50.0,
        "front_edge_light_intensity": 0.0,
        "roughness_wrap": ("clamp", "clamp"),
        "roughness_mip_filter": "point",
        "roughness_channel": 0,
        "roughness_scale": 1.0,
        "roughness_bias": 0.0,
        "roughness": 1.0,
        "lit": True,
        "casts_face_shadow": False,
        "receives_screenspace_face_shadow": False,
        "alpha_multiplier": 1.0,
        "depth_write": True,
        "alpha_cutoff": 0.0,
        "cull_back_faces": False,
        "clockwise_front_face": False,
        "flip_horizontal_sign": 1.0,
        "blend": False,
        "premultiplied_rgb_blend": False,
        "gradient_texture": None,
        "gradient_wrap": ("clamp", "clamp"),
        "gradient_mip_filter": "point",
        "gradient_channel": 0,
        "gradient_colors": None,
        "hair_constant_color_linear": None,
        "hair708_face_color_linear": None,
        "gamma_correct_lighting": False,
        "linear_lighting": True,
        "unresolved_portable_family": None,
        "texcoord_bindings": {},
    }
    try:
        if any(getattr(style, name) != value for name, value in expected.items()):
            return False
        if style.texture is None or style.normal_texture is None or style.roughness_texture is None:
            return False
        light_arrays = (
            np.asarray(rasterizer.light_direction),
            np.asarray(rasterizer.light_color),
            np.asarray(rasterizer.ambient_color),
        )
        if any(value.shape != (3,) or not np.all(np.isfinite(value)) for value in light_arrays):
            return False
        if not all(
            np.isfinite(float(value))
            for value in (rasterizer.light_intensity, rasterizer.ambient_intensity)
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        triangle_count, albedo_shapes, normal_shapes, roughness_shapes = (
            _OPAQUE_OUTFIT_PROFILES[profile]
        )
        if len(triangles) != triangle_count or not all(
            all(index is not None for index in triangle.texcoord)
            and all(index is not None for index in triangle.normal)
            for triangle in triangles
        ):
            return False
        for source, expected_shapes in (
            (style.texture, albedo_shapes),
            (style.normal_texture, normal_shapes),
            (style.roughness_texture, roughness_shapes),
        ):
            levels = source if isinstance(source, tuple) else (source,)
            if tuple(level.shape[:2] for level in levels) != expected_shapes:
                return False
            if any(
                not isinstance(level, np.ndarray)
                or level.dtype != np.float64
                or level.ndim != 3
                or level.shape[2] < 4
                or not np.all(np.isfinite(level))
                for level in levels
            ):
                return False
        return True
    except (AttributeError, TypeError, ValueError):
        return False


def supports_outfit984_draw(
    rasterizer: Any, mesh: Any, group: str, style: Any
) -> bool:
    """Admit only exact current OutfitTops984."""

    return _supports_opaque_outfit_draw(
        rasterizer,
        mesh,
        group,
        style,
        profile=("outfit_tops", 984, "Tops__mt_Body"),
        compiled=_draw_outfit984_compiled,
    )


def supports_outfit936_draw(
    rasterizer: Any, mesh: Any, group: str, style: Any
) -> bool:
    """Admit only exact current OutfitBottoms936."""

    return _supports_opaque_outfit_draw(
        rasterizer,
        mesh,
        group,
        style,
        profile=("outfit_bottoms", 936, "Bottoms__mt_Body"),
        compiled=_draw_outfit936_compiled,
    )


def supports_outfit912_draw(
    rasterizer: Any, mesh: Any, group: str, style: Any
) -> bool:
    """Admit only exact current OutfitShoes912."""

    return _supports_opaque_outfit_draw(
        rasterizer,
        mesh,
        group,
        style,
        profile=("outfit_shoes", 912, "Shoes__mt_Body"),
        compiled=_draw_outfit912_compiled,
    )


# BodyBaseDefault has one fixed mesh and three shared local GameAll programs.
# These group/count/texture-shape records are independent authentication
# boundaries: an unrelated model that merely selects Body336 does not enter
# the compiled path.
_BODY_GROUPS: dict[str, tuple[int, int, tuple[tuple[int, int], ...]]] = {
    "BodyFoot__mt_Socks": (324, 268, ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1))),
    "BodyHip__mt_Socks": (324, 12, ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1))),
    "BodyLeg__mt_Socks": (324, 240, ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1))),
    "BodyElbow__mt_Tops": (336, 212, ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1))),
    "BodyHand__mt_Tops": (336, 392, ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1))),
    "BodyKnee__mt_Socks": (336, 124, ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1))),
    "BodyThigh__mt_Socks": (336, 96, ((288, 384), (144, 192), (72, 96), (36, 48), (18, 24), (9, 12), (4, 6), (2, 3), (1, 1))),
    "BodyWaist__mt_Tops": (336, 80, ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1))),
    "BodyShoulder__mt_Tops": (348, 226, ((480, 384), (240, 192), (120, 96), (60, 48), (30, 24), (15, 12), (7, 6), (3, 3), (1, 1))),
}
_MIC_SHAPES = ((8, 8), (4, 4), (2, 2), (1, 1))
_NOSE_TEXTURE_SHAPES = ((128, 128), (64, 64), (32, 32), (16, 16), (8, 8), (4, 4), (2, 2), (1, 1))


def _texture_matches(source: Any, shapes: tuple[tuple[int, int], ...]) -> bool:
    levels = source if isinstance(source, tuple) else (source,)
    return (
        tuple(level.shape[:2] for level in levels) == shapes
        and all(
            isinstance(level, np.ndarray)
            and level.dtype == np.float64
            and level.ndim == 3
            and level.shape[2] >= 4
            and np.all(np.isfinite(level))
            for level in levels
        )
    )


def _supports_opaque_raster_state(rasterizer: Any) -> bool:
    try:
        arrays = (
            np.asarray(rasterizer.light_direction),
            np.asarray(rasterizer.light_color),
            np.asarray(rasterizer.ambient_color),
        )
        return (
            bool(rasterizer.linear_framebuffer)
            and bool(rasterizer.perspective_correct)
            and all(
                value.dtype == np.float64
                and value.shape == (3,)
                and np.all(np.isfinite(value))
                for value in arrays
            )
            and np.isfinite(float(rasterizer.light_intensity))
            and np.isfinite(float(rasterizer.ambient_intensity))
        )
    except (AttributeError, TypeError, ValueError):
        return False


_BODY_EXPECTED = {
    "color": (1.0, 1.0, 1.0, 1.0),
    "gameuber_mask0_facepaint": None,
    "texture": None, "texture_wrap": ("clamp", "clamp"), "texture_mip_filter": "point",
    "texture_emission_intensity": 0.0, "texture_alpha_under_color_linear": None,
    "alpha_texture": None, "alpha_wrap": ("clamp", "clamp"), "alpha_mip_filter": "point",
    "normal_wrap": ("clamp", "clamp"), "normal_mip_filter": "point",
    "normal_channels": (0, 1), "normal_strength": 1.0,
    "height_texture": None, "height_wrap": ("clamp", "clamp"), "height_mip_filter": "point",
    "height_channel": 0, "height_strength": 0.0,
    "parallax_texture": None, "parallax_wrap": ("clamp", "clamp"), "parallax_mip_filter": "point",
    "parallax_channel": 0, "parallax_scale": 0.0,
    "occlusion_texture": None, "occlusion_wrap": ("clamp", "clamp"), "occlusion_mip_filter": "point",
    "occlusion_channel": 0,
    "specular_texture": None, "specular_wrap": ("clamp", "clamp"), "specular_mip_filter": "point",
    "specular_channel": 0, "specular_strength": 0.0,
    "anisotropic_proxy": False, "anisotropic_shift_channel": 2,
    "anisotropic_shift_scale": 1.0, "anisotropic_shift_offset": 0.0,
    "anisotropic_specular_size": 10.0, "anisotropic_toon_intensity": 1.0,
    "anisotropic_title_view_scale": 1.0, "anisotropic_radiance_scale": 1.0,
    "cheap_sss_proxy": True, "cheap_sss_mask_wrap": ("clamp", "clamp"),
    "cheap_sss_mask_mip_filter": "linear", "cheap_sss_mask_channel": 1,
    "cheap_sss_mask_invert": True, "front_edge_light_proxy": False,
    "front_edge_light_view_angle_degrees": 50.0, "front_edge_light_intensity": 0.0,
    "roughness": 0.75, "roughness_texture": None, "roughness_wrap": ("clamp", "clamp"),
    "roughness_mip_filter": "point", "roughness_channel": 0,
    "roughness_scale": 1.0, "roughness_bias": 0.0,
    "lit": True, "casts_face_shadow": False, "receives_screenspace_face_shadow": False,
    "alpha_multiplier": 1.0, "depth_write": True, "alpha_cutoff": 1.0 / 255.0,
    "cull_back_faces": True, "clockwise_front_face": False, "flip_horizontal_sign": 1.0,
    "blend": False, "premultiplied_rgb_blend": False,
    "gradient_texture": None, "gradient_wrap": ("clamp", "clamp"),
    "gradient_mip_filter": "point", "gradient_channel": 0, "gradient_colors": None,
    "hair_constant_color_linear": None, "hair708_face_color_linear": None,
    "hair708_face_blend_channel": 1, "gamma_correct_lighting": False,
    "linear_lighting": True, "unresolved_portable_family": None, "texcoord_bindings": {},
}


def supports_body_draw(rasterizer: Any, mesh: Any, group: str, style: Any) -> bool:
    """Admit the nine exact BodyBaseDefault 324/336/348 draws."""

    profile = _BODY_GROUPS.get(group)
    identity = getattr(style, "gameall_identity", None)
    body = getattr(style, "gameuber_body348", None)
    if (
        _draw_body_compiled is None
        or profile is None
        or identity is None
        or body is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None))
        != ("body", profile[0])
        or not _supports_opaque_raster_state(rasterizer)
    ):
        return False
    try:
        try:
            from .screen_space_face_shadow import PORTABLE_CHEAP_SSS_INPUT
        except ImportError:
            from screen_space_face_shadow import PORTABLE_CHEAP_SSS_INPUT
        if PORTABLE_CHEAP_SSS_INPUT.correction_enabled:
            return False
        if any(getattr(style, name) != value for name, value in _BODY_EXPECTED.items()):
            return False
        if style.normal_texture is None or style.cheap_sss_mask_texture is not body.skin_mask_texture:
            return False
        if (
            tuple(body.albedo_wrap) != ("clamp", "clamp") or body.albedo_mip_filter != "linear"
            or tuple(body.skin_mask_wrap) != ("clamp", "clamp") or body.skin_mask_mip_filter != "linear"
            or tuple(body.material_information_wrap) != ("clamp", "clamp")
            or body.material_information_mip_filter != "point"
            or float(body.const_single_roughness) != 0.75
        ):
            return False
        face = np.asarray(body.face_color_linear_rgb, dtype=np.float64)
        if face.shape != (3,) or not np.all(np.isfinite(face)):
            return False
        shapes = profile[2]
        if not all(
            _texture_matches(source, expected)
            for source, expected in (
                (body.albedo_texture, shapes), (body.skin_mask_texture, shapes),
                (body.material_information_texture, _MIC_SHAPES), (style.normal_texture, shapes),
            )
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return (
            mesh.positions.shape == (3214, 3) and mesh.texcoords.shape == (3214, 2)
            and mesh.normals.shape == (3214, 3) and not mesh.texcoord_channels
            and len(triangles) == profile[1]
            and all(
                all(index is not None for index in triangle.texcoord)
                and all(index is not None for index in triangle.normal)
                for triangle in triangles
            )
        )
    except (AttributeError, ImportError, TypeError, ValueError):
        return False


_PLAIN_COMMON_EXPECTED = {
    "gameuber_body348": None, "gameuber_mask0_facepaint": None,
    "texture": None, "texture_wrap": ("clamp", "clamp"), "texture_mip_filter": "point",
    "texture_emission_intensity": 0.0, "texture_alpha_under_color_linear": None,
    "alpha_texture": None, "alpha_wrap": ("clamp", "clamp"), "alpha_mip_filter": "point",
    "normal_texture": None, "normal_wrap": ("clamp", "clamp"), "normal_mip_filter": "point",
    "normal_channels": (0, 1), "normal_strength": 1.0,
    "height_texture": None, "height_wrap": ("clamp", "clamp"), "height_mip_filter": "point",
    "height_channel": 0, "height_strength": 0.0,
    "occlusion_texture": None, "occlusion_wrap": ("clamp", "clamp"), "occlusion_mip_filter": "point",
    "occlusion_channel": 0, "roughness_texture": None,
    "roughness_wrap": ("clamp", "clamp"), "roughness_mip_filter": "point",
    "roughness_channel": 0, "roughness_scale": 1.0, "roughness_bias": 0.0,
    "specular_strength": 0.0, "anisotropic_proxy": False, "anisotropic_shift_channel": 2,
    "anisotropic_shift_scale": 1.0, "anisotropic_shift_offset": 0.0,
    "anisotropic_specular_size": 10.0, "anisotropic_toon_intensity": 1.0,
    "anisotropic_title_view_scale": 1.0, "anisotropic_radiance_scale": 1.0,
    "cheap_sss_proxy": True, "cheap_sss_mask_texture": None,
    "cheap_sss_mask_wrap": ("clamp", "clamp"), "cheap_sss_mask_mip_filter": "point",
    "cheap_sss_mask_channel": 0, "cheap_sss_mask_invert": False,
    "front_edge_light_proxy": False, "front_edge_light_view_angle_degrees": 50.0,
    "front_edge_light_intensity": 0.0, "lit": True, "casts_face_shadow": False,
    "receives_screenspace_face_shadow": True, "alpha_multiplier": 1.0,
    "depth_write": True, "alpha_cutoff": 1.0 / 255.0, "cull_back_faces": True,
    "flip_horizontal_sign": 1.0, "blend": False, "premultiplied_rgb_blend": False,
    "gradient_texture": None, "gradient_wrap": ("clamp", "clamp"),
    "gradient_mip_filter": "point", "gradient_channel": 0, "gradient_colors": None,
    "hair_constant_color_linear": None, "hair708_face_color_linear": None,
    "hair708_face_blend_channel": 1, "gamma_correct_lighting": False,
    "linear_lighting": True, "unresolved_portable_family": None, "texcoord_bindings": {},
}


def _plain_common_matches(rasterizer: Any, style: Any) -> bool:
    try:
        try:
            from .screen_space_face_shadow import PORTABLE_CHEAP_SSS_INPUT
        except ImportError:
            from screen_space_face_shadow import PORTABLE_CHEAP_SSS_INPUT
        color = np.asarray(style.color, dtype=np.float64)
        return (
            _draw_plain_skin_compiled is not None
            and _supports_opaque_raster_state(rasterizer)
            and not PORTABLE_CHEAP_SSS_INPUT.correction_enabled
            and color.shape == (4,) and np.all(np.isfinite(color)) and float(color[3]) == 1.0
            and all(getattr(style, name) == value for name, value in _PLAIN_COMMON_EXPECTED.items())
        )
    except (AttributeError, ImportError, TypeError, ValueError):
        return False


def supports_ear372_draw(rasterizer: Any, mesh: Any, group: str, style: Any) -> bool:
    identity = getattr(style, "gameall_identity", None)
    if (
        group != "Ear__mt_Ear" or identity is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None)) != ("ear", 372)
        or not _plain_common_matches(rasterizer, style)
    ):
        return False
    try:
        if (
            style.parallax_texture is not None or tuple(style.parallax_wrap) != ("clamp", "clamp")
            or style.parallax_mip_filter != "point" or int(style.parallax_channel) != 0
            or float(style.parallax_scale) != 0.0 or style.specular_texture is not None
            or tuple(style.specular_wrap) != ("clamp", "clamp") or style.specular_mip_filter != "point"
            or int(style.specular_channel) != 0 or float(style.roughness) != 1.0
            or not isinstance(style.clockwise_front_face, bool)
            or mesh.positions.shape != (432, 3) or mesh.texcoords.shape != (432, 2)
            or mesh.normals.shape != (432, 3) or mesh.groups != (group,) or mesh.texcoord_channels
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return len(triangles) == 360 and all(
            all(index is not None for index in triangle.normal) for triangle in triangles
        )
    except (AttributeError, TypeError, ValueError):
        return False


def supports_nose756_draw(rasterizer: Any, mesh: Any, group: str, style: Any) -> bool:
    identity = getattr(style, "gameall_identity", None)
    if (
        group != "Nose__mt_Nose" or identity is None
        or (getattr(identity, "family", None), getattr(identity, "program_index", None)) != ("nose", 756)
        or not _plain_common_matches(rasterizer, style)
    ):
        return False
    try:
        camera = np.asarray(rasterizer.camera_position, dtype=np.float64)
        if (
            style.clockwise_front_face or float(style.roughness) != 0.75
            or style.parallax_texture is None or tuple(style.parallax_wrap) != ("repeat", "repeat")
            or style.parallax_mip_filter != "point" or int(style.parallax_channel) != 0
            or float(style.parallax_scale) != 0.25 or style.specular_texture is None
            or tuple(style.specular_wrap) != ("clamp", "clamp") or style.specular_mip_filter != "point"
            or int(style.specular_channel) != 1
            or not _texture_matches(style.parallax_texture, _NOSE_TEXTURE_SHAPES)
            or not _texture_matches(style.specular_texture, _NOSE_TEXTURE_SHAPES)
            or camera.shape != (3,) or not np.all(np.isfinite(camera))
            or mesh.positions.shape != (414, 3) or mesh.texcoords.shape != (414, 2)
            or mesh.normals.shape != (414, 3)
            or mesh.groups != ("Nose__mt_Nose", "NoseLine__mt_NoseLine") or mesh.texcoord_channels
        ):
            return False
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return len(triangles) == 370 and all(
            all(index is not None for index in triangle.normal)
            and all(index is not None for index in triangle.texcoord)
            for triangle in triangles
        )
    except (AttributeError, TypeError, ValueError):
        return False


_MASK0_COMMON_STYLE = {
    "color": (1.0, 1.0, 1.0, 1.0),
    "gameuber_body348": None,
    "alpha_texture": None,
    "normal_texture": None,
    "height_texture": None,
    "parallax_texture": None,
    "occlusion_texture": None,
    "specular_texture": None,
    "roughness_texture": None,
    "gradient_texture": None,
    "gradient_colors": None,
    "cheap_sss_mask_texture": None,
    "hair_constant_color_linear": None,
    "hair708_face_color_linear": None,
    "alpha_multiplier": 1.0,
    "alpha_cutoff": 0.5,
    "lit": True,
    "depth_write": True,
    "cull_back_faces": False,
    "clockwise_front_face": False,
    "flip_horizontal_sign": 1.0,
    "blend": False,
    "premultiplied_rgb_blend": False,
    "gamma_correct_lighting": False,
    "linear_lighting": True,
    "anisotropic_proxy": False,
    "cheap_sss_proxy": False,
    "front_edge_light_proxy": False,
    "specular_strength": 0.0,
    "receives_screenspace_face_shadow": False,
    "casts_face_shadow": False,
    "unresolved_portable_family": None,
    "texcoord_bindings": {},
}


def _mask0_mode(style: Any, rasterizer: Any) -> int:
    """Return generated-only/UGC mode while rejecting all material drift."""

    identity = getattr(style, "gameall_identity", None)
    if identity is None or (identity.family, identity.program_index) != ("mask", 0):
        raise ValueError("Mask0 requires exact mask/program-0 identity")
    if not bool(getattr(rasterizer, "linear_framebuffer", False)):
        raise ValueError("Mask0 requires the current linear framebuffer")
    changed = [
        name for name, expected in _MASK0_COMMON_STYLE.items()
        if getattr(style, name, object()) != expected
    ]
    if changed:
        raise ValueError("Mask0 material fingerprint changed: " + ", ".join(changed))
    paint = style.gameuber_mask0_facepaint
    if paint is None:
        expected = {
            "texture_wrap": ("clamp", "clamp"),
            "texture_mip_filter": "point",
            "texture_emission_intensity": 0.1,
            "texture_alpha_under_color_linear": (
                0.21586050011389926,
                0.21586050011389926,
                0.21586050011389926,
            ),
        }
        if style.texture is None or isinstance(style.texture, tuple):
            raise ValueError("generated-only Mask0 requires one generated level")
        changed = [name for name, value in expected.items() if getattr(style, name, object()) != value]
        if changed:
            raise ValueError("generated-only Mask0 fingerprint changed: " + ", ".join(changed))
        return 0
    if (
        style.texture is not None
        or style.texture_alpha_under_color_linear is not None
        or style.texture_emission_intensity != 0.0
    ):
        raise ValueError("UGC Mask0 owns _a0/_user0 without generic texture state")
    expected_paint = {
        "generated_mask_wrap": ("repeat", "repeat"),
        "generated_mask_mip_filter": "point",
        "user0_wrap": ("clamp", "clamp"),
        "user0_mip_filter": "point",
        "replace_albedo_color_linear_rgba": (0.0, 0.0, 0.0, 0.0),
        "source_backed_constructor_const_single0_value": 0.0,
        "emission_color_linear_rgb": (1.0, 1.0, 1.0),
        "emission_intensity": 0.1,
        "portable_coverage_threshold": 0.5,
    }
    changed = [name for name, value in expected_paint.items() if getattr(paint, name, object()) != value]
    if changed:
        raise ValueError("UGC Mask0 fingerprint changed: " + ", ".join(changed))
    if isinstance(paint.generated_mask_texture, tuple) or isinstance(paint.user0_texture, tuple):
        raise ValueError("Mask0 accepts one texture level per binding")
    rows = np.asarray(paint.user0_tex_srt.affine_rows, dtype=np.float64)
    if rows.shape != (2, 3) or not np.all(np.isfinite(rows)):
        raise ValueError("Mask0 user0 TexSrt affine is invalid")
    return 1


def supports_mask0_draw(rasterizer: Any, mesh: Any, group: str, style: Any) -> bool:
    if _draw_mask0_compiled is None or group != "Mask__mt_Mask":
        return False
    try:
        _mask0_mode(style, rasterizer)
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        return len(triangles) == 288 and all(
            all(index is not None for index in triangle.texcoord)
            and all(index is not None for index in triangle.normal)
            for triangle in triangles
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _linear_texture(rasterizer: Any, source: Any, name: str) -> np.ndarray:
    array = np.asarray(source)
    if (
        array.dtype != np.float64
        or array.ndim != 3
        or array.shape[0] <= 0
        or array.shape[1] <= 0
        or array.shape[2] < 4
        or not np.all(np.isfinite(array))
    ):
        raise ValueError(f"{name} must be finite float64 RGBA")
    return np.ascontiguousarray(
        rasterizer._hardware_srgb_texture_level(array)[..., :4], dtype=np.float64
    )


def _pack_rgba_mips(source: Any, name: str) -> tuple[np.ndarray, np.ndarray]:
    key = (id(source), False)
    cached = _packed_texture_cache.get(key)
    if cached is not None and cached[0] is source:
        _packed_texture_cache.move_to_end(key)
        return cached[1], cached[2]
    levels = source if isinstance(source, tuple) else (source,)
    arrays: list[np.ndarray] = []
    rows: list[tuple[int, int, int]] = []
    offset = 0
    for index, level in enumerate(levels):
        array = np.asarray(level)
        if (
            array.dtype != np.float64
            or array.ndim != 3
            or array.shape[0] <= 0
            or array.shape[1] <= 0
            or array.shape[2] < 4
            or not np.all(np.isfinite(array))
        ):
            raise ValueError(f"{name} mip {index} must be finite float64 RGBA")
        rgba = np.ascontiguousarray(array[..., :4], dtype=np.float64)
        arrays.append(rgba.reshape(-1, 4))
        rows.append((offset, rgba.shape[0], rgba.shape[1]))
        offset += rgba.shape[0] * rgba.shape[1]
    packed = np.ascontiguousarray(np.concatenate(arrays, axis=0), dtype=np.float64)
    descriptors = np.ascontiguousarray(rows, dtype=np.int64)
    _packed_texture_cache[key] = (source, packed, descriptors)
    _packed_texture_cache.move_to_end(key)
    while len(_packed_texture_cache) > MAX_PACKED_TEXTURES:
        _packed_texture_cache.popitem(last=False)
    return packed, descriptors


def _pack_srgb_rgba_mips(
    rasterizer: Any, source: Any, name: str
) -> tuple[np.ndarray, np.ndarray]:
    """Pack the rasterizer's exact whole-level hardware-sRGB decode."""

    key = (id(source), True)
    cached = _packed_texture_cache.get(key)
    if cached is not None and cached[0] is source:
        _packed_texture_cache.move_to_end(key)
        return cached[1], cached[2]
    levels = source if isinstance(source, tuple) else (source,)
    arrays: list[np.ndarray] = []
    rows: list[tuple[int, int, int]] = []
    offset = 0
    for index, level in enumerate(levels):
        decoded = np.asarray(rasterizer._hardware_srgb_texture_level(level))
        if (
            decoded.dtype != np.float64
            or decoded.ndim != 3
            or decoded.shape[0] <= 0
            or decoded.shape[1] <= 0
            or decoded.shape[2] < 4
            or not np.all(np.isfinite(decoded))
        ):
            raise ValueError(f"{name} mip {index} must decode to finite float64 RGBA")
        rgba = np.ascontiguousarray(decoded[..., :4], dtype=np.float64)
        arrays.append(rgba.reshape(-1, 4))
        rows.append((offset, rgba.shape[0], rgba.shape[1]))
        offset += rgba.shape[0] * rgba.shape[1]
    packed = np.ascontiguousarray(np.concatenate(arrays, axis=0), dtype=np.float64)
    descriptors = np.ascontiguousarray(rows, dtype=np.int64)
    _packed_texture_cache[key] = (source, packed, descriptors)
    _packed_texture_cache.move_to_end(key)
    while len(_packed_texture_cache) > MAX_PACKED_TEXTURES:
        _packed_texture_cache.popitem(last=False)
    return packed, descriptors


def _anisotropic_parameters(
    rasterizer: Any,
    style: Any,
    base_linear: np.ndarray,
    *,
    execute_anisotropy: bool,
) -> np.ndarray:
    light = np.asarray(rasterizer.light_direction, dtype=np.float64)
    anisotropic_light = light / np.linalg.norm(light)
    ambient = np.asarray(rasterizer.ambient_color, dtype=np.float64) * float(
        rasterizer.ambient_intensity
    )
    key = np.asarray(rasterizer.light_color, dtype=np.float64) * float(
        rasterizer.light_intensity
    )
    front = ambient + key * float(np.clip(0.5 + 0.5 * light[2], 0.0, 1.0))
    radiance = (
        np.asarray(rasterizer.light_color, dtype=np.float64)
        * float(rasterizer.light_intensity)
        / float(rasterizer.light_normalization)
    )
    roughness = max(float(style.roughness), 1e-12)
    inverse_r2 = 1.0 / max(roughness * roughness, 1e-12)
    kernel_factor = (
        inverse_r2
        * float(style.anisotropic_specular_size)
        * gameuber_cpu.INV_FOUR_PI
        * float(style.anisotropic_toon_intensity)
        * float(style.anisotropic_radiance_scale)
    )
    return np.ascontiguousarray(
        np.concatenate(
            (
                np.ravel(base_linear), light, ambient, key, front,
                np.asarray(
                    (0.0, 0.0, 0.0)
                    if rasterizer.camera_position is None
                    else rasterizer.camera_position,
                    dtype=np.float64,
                ),
                radiance,
                np.asarray(
                    (
                        inverse_r2, kernel_factor,
                        style.anisotropic_shift_scale,
                        style.anisotropic_shift_offset,
                        style.flip_horizontal_sign,
                        float(rasterizer.camera_position is not None),
                        float(rasterizer.perspective_correct),
                        style.anisotropic_title_view_scale,
                    ),
                    dtype=np.float64,
                ),
                anisotropic_light,
                np.asarray((float(execute_anisotropy),), dtype=np.float64),
            )
        ),
        dtype=np.float64,
    )


def _hair612_parameters(rasterizer: Any, style: Any) -> np.ndarray:
    endpoint = np.asarray(style.gradient_colors[0], dtype=np.float64)
    return _anisotropic_parameters(
        rasterizer,
        style,
        gameuber_cpu.hair_endpoint_gradient_base_linear(
            endpoint, endpoint, np.float64(0.0)
        ),
        execute_anisotropy=True,
    )


def _beard468_parameters(rasterizer: Any, style: Any) -> np.ndarray:
    base = np.asarray(style.color[:3], dtype=np.float64)
    base_linear = np.where(
        base <= 0.04045,
        base / 12.92,
        np.power((base + 0.055) / 1.055, 2.4),
    )
    return _anisotropic_parameters(
        rasterizer, style, base_linear, execute_anisotropy=True
    )


def _hair564_equal_parameters(rasterizer: Any, style: Any) -> np.ndarray:
    endpoint = np.asarray(style.gradient_colors[0], dtype=np.float64)
    return _anisotropic_parameters(
        rasterizer,
        style,
        gameuber_cpu.hair_endpoint_gradient_base_linear(
            endpoint, endpoint, np.float64(0.0)
        ),
        execute_anisotropy=False,
    )


def _flatten_anisotropic_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None,
    *,
    parameters: np.ndarray,
    texture_name: str,
) -> FlattenedHair612Draw:
    """Flatten one strictly admitted current anisotropic draw."""
    matrix = np.identity(4, dtype=np.float64) if transform is None else np.asarray(
        transform, dtype=np.float64
    )
    positions = rasterizer._transform_positions(mesh.positions, matrix)
    normals = rasterizer._transform_normals(mesh.normals, matrix)
    projected = rasterizer._project(positions)
    triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
    vertex_indices = np.asarray([triangle.vertex for triangle in triangles], dtype=np.int64)
    screens = projected[vertex_indices]
    finite = np.all(np.isfinite(screens), axis=(1, 2))
    candidate = finite.copy()
    safe = np.where(finite[:, None, None], screens, 0.0)
    sx, sy = safe[..., 0], safe[..., 1]
    x0 = np.maximum(0, np.floor(np.min(sx, axis=1))).astype(np.int64)
    x1 = np.minimum(rasterizer.width - 1, np.ceil(np.max(sx, axis=1))).astype(np.int64)
    y0 = np.maximum(0, np.floor(np.min(sy, axis=1))).astype(np.int64)
    y1 = np.minimum(rasterizer.height - 1, np.ceil(np.max(sy, axis=1))).astype(np.int64)
    candidate &= (x0 <= x1) & (y0 <= y1)
    denominator = (
        (sx[:, 0] - sx[:, 1]) * (sy[:, 2] - sy[:, 1])
        - (sy[:, 0] - sy[:, 1]) * (sx[:, 2] - sx[:, 1])
    )
    candidate &= np.abs(denominator) >= 1e-10
    candidate &= denominator > 0.0
    selected = np.flatnonzero(candidate)
    selected_triangles = [triangles[int(index)] for index in selected]
    selected_vertices = vertex_indices[selected]
    selected_screens = np.ascontiguousarray(screens[selected], dtype=np.float64)
    bounds = np.ascontiguousarray(
        np.column_stack((x0[selected], x1[selected], y0[selected], y1[selected])),
        dtype=np.int64,
    )
    if len(selected_triangles):
        selected_uv = np.ascontiguousarray(
            [mesh.texcoords[np.asarray(triangle.texcoord, dtype=np.int64)]
             for triangle in selected_triangles],
            dtype=np.float64,
        )
        selected_normals = np.ascontiguousarray(
            [normals[np.asarray(triangle.normal, dtype=np.int64)]
             for triangle in selected_triangles],
            dtype=np.float64,
        )
    else:
        selected_uv = np.empty((0, 3, 2), dtype=np.float64)
        selected_normals = np.empty((0, 3, 3), dtype=np.float64)
    mim_texels, mim_levels = _pack_rgba_mips(style.specular_texture, texture_name)
    mip_indices = np.ascontiguousarray(
        [
            _point_mip_index(
                selected_screens[index], selected_uv[index],
                int(mim_levels[0, 1]), int(mim_levels[0, 2]), len(mim_levels),
            )
            for index in range(len(selected))
        ],
        dtype=np.int64,
    )
    return FlattenedHair612Draw(
        screen_triangles=selected_screens,
        bounds=bounds,
        denominators=np.ascontiguousarray(denominator[selected], dtype=np.float64),
        world_vertices=np.ascontiguousarray(positions[selected_vertices], dtype=np.float64),
        vertex_normals=selected_normals,
        material_uv=selected_uv,
        mim_texels=mim_texels,
        mim_levels=mim_levels,
        mim_level_indices=mip_indices,
        parameters=parameters,
        submitted_triangle_count=len(triangles),
    )


def flatten_hair612_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedHair612Draw:
    """Flatten the strictly supported Hair612 group without attachment writes."""

    if not supports_hair612_draw(rasterizer, mesh, group, style):
        raise ValueError("draw does not match the supported current Hair612 fingerprint")
    return _flatten_anisotropic_group(
        rasterizer,
        mesh,
        group,
        style,
        transform,
        parameters=_hair612_parameters(rasterizer, style),
        texture_name="Hair612 MIM",
    )


def draw_hair612_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> Hair612DrawResult:
    """Execute one strictly fingerprinted current-output Hair612 draw."""

    payload = flatten_hair612_group(rasterizer, mesh, group, style, transform)
    return _draw_anisotropic_payload(
        rasterizer, payload, _draw_hair612_compiled
    )


def _draw_anisotropic_payload(
    rasterizer: Any,
    payload: FlattenedHair612Draw,
    compiled_draw: Any,
) -> Hair612DrawResult:
    """Validate and execute the shared Hair612/Beard468 flat ABI."""

    count = payload.candidate_triangle_count
    arrays = (
        (payload.screen_triangles, np.float64, (count, 3, 3), "screen_triangles"),
        (payload.bounds, np.int64, (count, 4), "bounds"),
        (payload.denominators, np.float64, (count,), "denominators"),
        (payload.world_vertices, np.float64, (count, 3, 3), "world_vertices"),
        (payload.vertex_normals, np.float64, (count, 3, 3), "vertex_normals"),
        (payload.material_uv, np.float64, (count, 3, 2), "material_uv"),
        (payload.mim_texels, np.float64, (None, 4), "mim_texels"),
        (payload.mim_levels, np.int64, (None, 3), "mim_levels"),
        (payload.mim_level_indices, np.int64, (count,), "mim_level_indices"),
        (payload.parameters, np.float64, (33,), "parameters"),
    )
    checked = [
        _as_contiguous_exact(value, dtype, shape, name)
        for value, dtype, shape, name in arrays
    ]
    color = _as_contiguous_exact(
        rasterizer.color, np.float64, (None, None, 3), "color", writable=True
    )
    depth = _as_contiguous_exact(
        rasterizer.depth, np.float64, color.shape[:2], "depth", writable=True
    )
    target_alpha = rasterizer.target_alpha
    if target_alpha is not None:
        target_alpha = _as_contiguous_exact(
            target_alpha, np.float64, color.shape[:2], "target_alpha", writable=True
        )
    written = int(
        compiled_draw(color, depth, target_alpha, *checked)
    )
    return Hair612DrawResult(
        submitted_triangles=payload.submitted_triangle_count,
        candidate_triangles=count,
        written_fragments=written,
    )


def flatten_beard468_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedHair612Draw:
    """Flatten the strictly supported Beard02/program468 draw."""

    if not supports_beard468_draw(rasterizer, mesh, group, style):
        raise ValueError("draw does not match the supported current Beard468 fingerprint")
    return _flatten_anisotropic_group(
        rasterizer,
        mesh,
        group,
        style,
        transform,
        parameters=_beard468_parameters(rasterizer, style),
        texture_name="Beard468 MIM",
    )


def draw_beard468_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> Hair612DrawResult:
    """Execute one strictly fingerprinted current-output Beard468 draw."""

    return _draw_anisotropic_payload(
        rasterizer,
        flatten_beard468_group(rasterizer, mesh, group, style, transform),
        _draw_beard468_compiled,
    )


def flatten_hair564_equal_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedHair612Draw:
    """Flatten one strictly supported equal-endpoint Hair564 draw."""

    if not supports_hair564_equal_draw(rasterizer, mesh, group, style):
        raise ValueError("draw does not match the supported current Hair564 fingerprint")
    return _flatten_anisotropic_group(
        rasterizer,
        mesh,
        group,
        style,
        transform,
        parameters=_hair564_equal_parameters(rasterizer, style),
        texture_name="Hair564 inactive MIM",
    )


def draw_hair564_equal_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> Hair612DrawResult:
    """Execute one exact-current equal-endpoint Hair564 draw."""

    return _draw_anisotropic_payload(
        rasterizer,
        flatten_hair564_equal_group(rasterizer, mesh, group, style, transform),
        _draw_hair564_compiled,
    )


def _flatten_opaque_outfit_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None,
    *,
    supports: Any,
    profile_name: str,
) -> FlattenedOpaqueOutfitDraw:
    """Flatten one strictly admitted opaque outfit draw without writes."""

    if not supports(rasterizer, mesh, group, style):
        raise ValueError(
            f"draw does not match the supported current {profile_name} fingerprint"
        )
    matrix = np.identity(4, dtype=np.float64) if transform is None else np.asarray(
        transform, dtype=np.float64
    )
    positions = rasterizer._transform_positions(mesh.positions, matrix)
    normals = rasterizer._transform_normals(mesh.normals, matrix)
    projected = rasterizer._project(positions)
    triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
    vertex_indices = np.asarray([triangle.vertex for triangle in triangles], dtype=np.int64)
    screens = projected[vertex_indices]
    finite = np.all(np.isfinite(screens), axis=(1, 2))
    candidate = finite.copy()
    safe = np.where(finite[:, None, None], screens, 0.0)
    sx, sy = safe[..., 0], safe[..., 1]
    x0 = np.maximum(0, np.floor(np.min(sx, axis=1))).astype(np.int64)
    x1 = np.minimum(rasterizer.width - 1, np.ceil(np.max(sx, axis=1))).astype(np.int64)
    y0 = np.maximum(0, np.floor(np.min(sy, axis=1))).astype(np.int64)
    y1 = np.minimum(rasterizer.height - 1, np.ceil(np.max(sy, axis=1))).astype(np.int64)
    candidate &= (x0 <= x1) & (y0 <= y1)
    denominator = (
        (sx[:, 0] - sx[:, 1]) * (sy[:, 2] - sy[:, 1])
        - (sy[:, 0] - sy[:, 1]) * (sx[:, 2] - sx[:, 1])
    )
    candidate &= np.abs(denominator) >= 1e-10
    selected = np.flatnonzero(candidate)
    selected_triangles = [triangles[int(index)] for index in selected]
    selected_vertices = vertex_indices[selected]
    selected_screens = np.ascontiguousarray(screens[selected], dtype=np.float64)
    bounds = np.ascontiguousarray(
        np.column_stack((x0[selected], x1[selected], y0[selected], y1[selected])),
        dtype=np.int64,
    )
    material_uv = np.ascontiguousarray(
        [mesh.texcoords[np.asarray(triangle.texcoord, dtype=np.int64)] for triangle in selected_triangles],
        dtype=np.float64,
    ).reshape((-1, 3, 2))
    selected_normals = np.ascontiguousarray(
        [normals[np.asarray(triangle.normal, dtype=np.int64)] for triangle in selected_triangles],
        dtype=np.float64,
    ).reshape((-1, 3, 3))
    if not np.all(np.isfinite(material_uv)) or not np.all(np.isfinite(selected_normals)):
        raise ValueError(f"{profile_name} selected primitive attributes must be finite")

    albedo_texels, albedo_levels = _pack_srgb_rgba_mips(
        rasterizer, style.texture, f"{profile_name} albedo"
    )
    normal_texels, normal_levels = _pack_rgba_mips(
        style.normal_texture, f"{profile_name} normal"
    )
    albedo_selections = [
        _linear_mip_selection(
            selected_screens[index], material_uv[index],
            int(albedo_levels[0, 1]), int(albedo_levels[0, 2]), len(albedo_levels),
        )
        for index in range(len(selected))
    ]
    albedo_lower = np.ascontiguousarray(
        [selection[0] for selection in albedo_selections], dtype=np.int64
    )
    albedo_upper = np.ascontiguousarray(
        [selection[1] for selection in albedo_selections], dtype=np.int64
    )
    albedo_amounts = np.ascontiguousarray(
        [selection[2] for selection in albedo_selections], dtype=np.float64
    )
    normal_indices = np.ascontiguousarray(
        [
            _point_mip_index(
                selected_screens[index], material_uv[index],
                int(normal_levels[0, 1]), int(normal_levels[0, 2]), len(normal_levels),
            )
            for index in range(len(selected))
        ],
        dtype=np.int64,
    )
    return FlattenedOpaqueOutfitDraw(
        screen_triangles=selected_screens,
        bounds=bounds,
        denominators=np.ascontiguousarray(denominator[selected], dtype=np.float64),
        world_vertices=np.ascontiguousarray(positions[selected_vertices], dtype=np.float64),
        vertex_normals=selected_normals,
        material_uv=material_uv,
        albedo_texels=albedo_texels,
        albedo_levels=albedo_levels,
        albedo_lower_indices=albedo_lower,
        albedo_upper_indices=albedo_upper,
        albedo_mip_amounts=albedo_amounts,
        normal_texels=normal_texels,
        normal_levels=normal_levels,
        normal_level_indices=normal_indices,
        submitted_triangle_count=len(triangles),
    )


def flatten_outfit984_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedOpaqueOutfitDraw:
    return _flatten_opaque_outfit_group(
        rasterizer,
        mesh,
        group,
        style,
        transform,
        supports=supports_outfit984_draw,
        profile_name="OutfitTops984",
    )


def flatten_outfit936_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedOpaqueOutfitDraw:
    return _flatten_opaque_outfit_group(
        rasterizer,
        mesh,
        group,
        style,
        transform,
        supports=supports_outfit936_draw,
        profile_name="OutfitBottoms936",
    )


def flatten_outfit912_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedOpaqueOutfitDraw:
    return _flatten_opaque_outfit_group(
        rasterizer,
        mesh,
        group,
        style,
        transform,
        supports=supports_outfit912_draw,
        profile_name="OutfitShoes912",
    )


def _draw_opaque_outfit_group(
    rasterizer: Any,
    payload: FlattenedOpaqueOutfitDraw,
    compiled: Any,
) -> OpaqueOutfitDrawResult:
    """Execute one admitted opaque outfit payload."""

    triangle_count = payload.candidate_triangle_count
    color = _as_contiguous_exact(
        rasterizer.color, np.float64, (None, None, 3), "color", writable=True
    )
    depth = _as_contiguous_exact(
        rasterizer.depth, np.float64, color.shape[:2], "depth", writable=True
    )
    target_alpha = rasterizer.target_alpha
    if target_alpha is not None:
        target_alpha = _as_contiguous_exact(
            target_alpha, np.float64, color.shape[:2], "target_alpha", writable=True
        )
    arrays = (
        (payload.screen_triangles, np.float64, (triangle_count, 3, 3), "screen_triangles"),
        (payload.bounds, np.int64, (triangle_count, 4), "bounds"),
        (payload.denominators, np.float64, (triangle_count,), "denominators"),
        (payload.world_vertices, np.float64, (triangle_count, 3, 3), "world_vertices"),
        (payload.vertex_normals, np.float64, (triangle_count, 3, 3), "vertex_normals"),
        (payload.material_uv, np.float64, (triangle_count, 3, 2), "material_uv"),
        (payload.albedo_texels, np.float64, (None, 4), "albedo_texels"),
        (payload.albedo_levels, np.int64, (None, 3), "albedo_levels"),
        (payload.albedo_lower_indices, np.int64, (triangle_count,), "albedo_lower_indices"),
        (payload.albedo_upper_indices, np.int64, (triangle_count,), "albedo_upper_indices"),
        (payload.albedo_mip_amounts, np.float64, (triangle_count,), "albedo_mip_amounts"),
        (payload.normal_texels, np.float64, (None, 4), "normal_texels"),
        (payload.normal_levels, np.int64, (None, 3), "normal_levels"),
        (payload.normal_level_indices, np.int64, (triangle_count,), "normal_level_indices"),
        (np.ascontiguousarray(rasterizer.light_direction, dtype=np.float64), np.float64, (3,), "light_direction"),
        (np.ascontiguousarray(rasterizer.light_color, dtype=np.float64), np.float64, (3,), "light_color"),
        (np.ascontiguousarray(rasterizer.ambient_color, dtype=np.float64), np.float64, (3,), "ambient_color"),
    )
    checked = [
        _as_contiguous_exact(value, dtype, shape, name)
        for value, dtype, shape, name in arrays
    ]
    written = int(
        compiled(
            color,
            depth,
            target_alpha,
            *checked,
            float(rasterizer.light_intensity),
            float(rasterizer.ambient_intensity),
            int(bool(rasterizer.perspective_correct)),
        )
    )
    return OpaqueOutfitDrawResult(
        submitted_triangles=payload.submitted_triangle_count,
        candidate_triangles=payload.candidate_triangle_count,
        written_fragments=written,
    )


def draw_outfit984_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> OpaqueOutfitDrawResult:
    """Execute exact current OutfitTops984."""

    return _draw_opaque_outfit_group(
        rasterizer,
        flatten_outfit984_group(rasterizer, mesh, group, style, transform),
        _draw_outfit984_compiled,
    )


def draw_outfit936_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> OpaqueOutfitDrawResult:
    """Execute exact current OutfitBottoms936."""

    return _draw_opaque_outfit_group(
        rasterizer,
        flatten_outfit936_group(rasterizer, mesh, group, style, transform),
        _draw_outfit936_compiled,
    )


def draw_outfit912_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> OpaqueOutfitDrawResult:
    """Execute exact current OutfitShoes912."""

    return _draw_opaque_outfit_group(
        rasterizer,
        flatten_outfit912_group(rasterizer, mesh, group, style, transform),
        _draw_outfit912_compiled,
    )


def _selected_opaque_geometry(
    rasterizer: Any,
    mesh: Any,
    group: str,
    transform: Any,
    *,
    clockwise: bool,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, list[Any]]:
    """Transform/project and source-order filter one strict opaque draw."""

    matrix = np.identity(4, dtype=np.float64) if transform is None else np.asarray(
        transform, dtype=np.float64
    )
    positions = rasterizer._transform_positions(mesh.positions, matrix)
    normals = rasterizer._transform_normals(mesh.normals, matrix)
    projected = rasterizer._project(positions)
    triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
    vertices = np.asarray([triangle.vertex for triangle in triangles], dtype=np.int64)
    screens = projected[vertices]
    finite = np.all(np.isfinite(screens), axis=(1, 2))
    candidate = finite.copy()
    safe = np.where(finite[:, None, None], screens, 0.0)
    sx, sy = safe[..., 0], safe[..., 1]
    x0 = np.maximum(0, np.floor(np.min(sx, axis=1))).astype(np.int64)
    x1 = np.minimum(rasterizer.width - 1, np.ceil(np.max(sx, axis=1))).astype(np.int64)
    y0 = np.maximum(0, np.floor(np.min(sy, axis=1))).astype(np.int64)
    y1 = np.minimum(rasterizer.height - 1, np.ceil(np.max(sy, axis=1))).astype(np.int64)
    candidate &= (x0 <= x1) & (y0 <= y1)
    denominator = (
        (sx[:, 0] - sx[:, 1]) * (sy[:, 2] - sy[:, 1])
        - (sy[:, 0] - sy[:, 1]) * (sx[:, 2] - sx[:, 1])
    )
    candidate &= np.abs(denominator) >= 1e-10
    candidate &= denominator < 0.0 if clockwise else denominator > 0.0
    selected = np.flatnonzero(candidate)
    return (
        np.ascontiguousarray(screens[selected], dtype=np.float64),
        np.ascontiguousarray(
            np.column_stack((x0[selected], x1[selected], y0[selected], y1[selected])),
            dtype=np.int64,
        ),
        np.ascontiguousarray(denominator[selected], dtype=np.float64),
        np.ascontiguousarray(positions[vertices[selected]], dtype=np.float64),
        np.ascontiguousarray(normals, dtype=np.float64),
        [triangles[int(index)] for index in selected],
    )


def flatten_body_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: Any = None,
) -> FlattenedBodyDraw:
    """Flatten one authenticated Body324/336/348 draw without writes."""

    if not supports_body_draw(rasterizer, mesh, group, style):
        raise ValueError("draw does not match an exact current Body324/336/348 fingerprint")
    screens, bounds, denominators, vertices, normals, triangles = _selected_opaque_geometry(
        rasterizer, mesh, group, transform, clockwise=False
    )
    count = len(triangles)
    uv = np.ascontiguousarray(
        [mesh.texcoords[np.asarray(triangle.texcoord, dtype=np.int64)] for triangle in triangles],
        dtype=np.float64,
    ).reshape((-1, 3, 2))
    vertex_normals = np.ascontiguousarray(
        [normals[np.asarray(triangle.normal, dtype=np.int64)] for triangle in triangles],
        dtype=np.float64,
    ).reshape((-1, 3, 3))
    body = style.gameuber_body348
    albedo_texels, albedo_levels = _pack_srgb_rgba_mips(
        rasterizer, body.albedo_texture, "opaque body albedo"
    )
    skin_texels, skin_levels = _pack_rgba_mips(
        body.skin_mask_texture, "opaque body skin mask"
    )
    normal_texels, normal_levels = _pack_rgba_mips(
        style.normal_texture, "opaque body normal"
    )

    def linear_selections(
        levels: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        choices = [
            _linear_mip_selection(
                screens[index], uv[index], int(levels[0, 1]),
                int(levels[0, 2]), len(levels)
            )
            for index in range(count)
        ]
        return (
            np.ascontiguousarray([choice[0] for choice in choices], dtype=np.int64),
            np.ascontiguousarray([choice[1] for choice in choices], dtype=np.int64),
            np.ascontiguousarray([choice[2] for choice in choices], dtype=np.float64),
        )

    albedo_lower, albedo_upper, albedo_amount = linear_selections(albedo_levels)
    skin_lower, skin_upper, skin_amount = linear_selections(skin_levels)
    normal_indices = np.ascontiguousarray(
        [
            _point_mip_index(
                screens[index], uv[index], int(normal_levels[0, 1]),
                int(normal_levels[0, 2]), len(normal_levels)
            )
            for index in range(count)
        ],
        dtype=np.int64,
    )
    return FlattenedBodyDraw(
        screens, bounds, denominators, vertices, vertex_normals, uv,
        albedo_texels, albedo_levels, albedo_lower, albedo_upper, albedo_amount,
        skin_texels, skin_levels, skin_lower, skin_upper, skin_amount,
        normal_texels, normal_levels, normal_indices,
        np.ascontiguousarray(body.face_color_linear_rgb, dtype=np.float64),
        _BODY_GROUPS[group][1],
    )


def flatten_plain_skin_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: Any = None,
) -> FlattenedPlainSkinDraw:
    """Flatten one authenticated Ear372 or Nose756 draw without writes."""

    if not (
        supports_ear372_draw(rasterizer, mesh, group, style)
        or supports_nose756_draw(rasterizer, mesh, group, style)
    ):
        raise ValueError("draw does not match an exact current Ear372/Nose756 fingerprint")
    screens, bounds, denominators, _vertices, normals, triangles = _selected_opaque_geometry(
        rasterizer, mesh, group, transform, clockwise=bool(style.clockwise_front_face)
    )
    vertex_normals = np.ascontiguousarray(
        [normals[np.asarray(triangle.normal, dtype=np.int64)] for triangle in triangles],
        dtype=np.float64,
    ).reshape((-1, 3, 3))
    base = np.asarray(style.color[:3], dtype=np.float64)
    linear = np.where(
        base <= 0.04045,
        base / 12.92,
        np.power((base + 0.055) / 1.055, 2.4),
    )
    return FlattenedPlainSkinDraw(
        screens, bounds, denominators, vertex_normals,
        np.ascontiguousarray(linear, dtype=np.float64),
        sum(triangle.group == group for triangle in mesh.triangles),
    )


def _opaque_attachments(rasterizer: Any) -> tuple[np.ndarray, np.ndarray, np.ndarray | None]:
    color = _as_contiguous_exact(
        rasterizer.color, np.float64, (None, None, 3), "color", writable=True
    )
    depth = _as_contiguous_exact(
        rasterizer.depth, np.float64, color.shape[:2], "depth", writable=True
    )
    target_alpha = rasterizer.target_alpha
    if target_alpha is not None:
        target_alpha = _as_contiguous_exact(
            target_alpha, np.float64, color.shape[:2], "target_alpha", writable=True
        )
    return color, depth, target_alpha


def draw_body_group(
    rasterizer: Any, mesh: Any, group: str, style: Any, transform: Any = None
) -> OpaqueCurrentDrawResult:
    payload = flatten_body_group(rasterizer, mesh, group, style, transform)
    color, depth, target_alpha = _opaque_attachments(rasterizer)
    count = payload.candidate_triangle_count
    arrays = (
        (payload.screen_triangles, np.float64, (count, 3, 3), "screen_triangles"),
        (payload.bounds, np.int64, (count, 4), "bounds"),
        (payload.denominators, np.float64, (count,), "denominators"),
        (payload.world_vertices, np.float64, (count, 3, 3), "world_vertices"),
        (payload.vertex_normals, np.float64, (count, 3, 3), "vertex_normals"),
        (payload.material_uv, np.float64, (count, 3, 2), "material_uv"),
        (payload.albedo_texels, np.float64, (None, 4), "albedo_texels"),
        (payload.albedo_levels, np.int64, (None, 3), "albedo_levels"),
        (payload.albedo_lower_indices, np.int64, (count,), "albedo_lower_indices"),
        (payload.albedo_upper_indices, np.int64, (count,), "albedo_upper_indices"),
        (payload.albedo_mip_amounts, np.float64, (count,), "albedo_mip_amounts"),
        (payload.skin_texels, np.float64, (None, 4), "skin_texels"),
        (payload.skin_levels, np.int64, (None, 3), "skin_levels"),
        (payload.skin_lower_indices, np.int64, (count,), "skin_lower_indices"),
        (payload.skin_upper_indices, np.int64, (count,), "skin_upper_indices"),
        (payload.skin_mip_amounts, np.float64, (count,), "skin_mip_amounts"),
        (payload.normal_texels, np.float64, (None, 4), "normal_texels"),
        (payload.normal_levels, np.int64, (None, 3), "normal_levels"),
        (payload.normal_level_indices, np.int64, (count,), "normal_level_indices"),
        (payload.face_color_linear, np.float64, (3,), "face_color_linear"),
        (np.ascontiguousarray(rasterizer.light_direction), np.float64, (3,), "light_direction"),
        (np.ascontiguousarray(rasterizer.light_color), np.float64, (3,), "light_color"),
        (np.ascontiguousarray(rasterizer.ambient_color), np.float64, (3,), "ambient_color"),
    )
    checked = [_as_contiguous_exact(value, dtype, shape, name) for value, dtype, shape, name in arrays]
    written = int(_draw_body_compiled(
        color, depth, target_alpha, *checked,
        float(rasterizer.light_intensity), float(rasterizer.ambient_intensity),
        int(bool(rasterizer.perspective_correct)),
    ))
    return OpaqueCurrentDrawResult(payload.submitted_triangle_count, count, written)


def draw_plain_skin_group(
    rasterizer: Any, mesh: Any, group: str, style: Any, transform: Any = None
) -> OpaqueCurrentDrawResult:
    payload = flatten_plain_skin_group(rasterizer, mesh, group, style, transform)
    color, depth, target_alpha = _opaque_attachments(rasterizer)
    count = payload.candidate_triangle_count
    arrays = (
        (payload.screen_triangles, np.float64, (count, 3, 3), "screen_triangles"),
        (payload.bounds, np.int64, (count, 4), "bounds"),
        (payload.denominators, np.float64, (count,), "denominators"),
        (payload.vertex_normals, np.float64, (count, 3, 3), "vertex_normals"),
        (payload.base_color_linear, np.float64, (3,), "base_color_linear"),
        (np.ascontiguousarray(rasterizer.light_direction), np.float64, (3,), "light_direction"),
        (np.ascontiguousarray(rasterizer.light_color), np.float64, (3,), "light_color"),
        (np.ascontiguousarray(rasterizer.ambient_color), np.float64, (3,), "ambient_color"),
    )
    checked = [_as_contiguous_exact(value, dtype, shape, name) for value, dtype, shape, name in arrays]
    written = int(_draw_plain_skin_compiled(
        color, depth, target_alpha, *checked,
        float(rasterizer.light_intensity), float(rasterizer.ambient_intensity),
        int(bool(rasterizer.perspective_correct)),
    ))
    return OpaqueCurrentDrawResult(payload.submitted_triangle_count, count, written)


def flatten_mask0_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> FlattenedMask0Draw:
    """Flatten one strict generated-only or UGC Mask0 draw."""

    mode = _mask0_mode(style, rasterizer)
    if group != "Mask__mt_Mask":
        raise ValueError("Mask0 accepts only Mask__mt_Mask")
    triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
    if len(triangles) != 288 or any(
        any(index is None for index in triangle.texcoord)
        or any(index is None for index in triangle.normal)
        for triangle in triangles
    ):
        raise ValueError("Mask0 requires the exact 288-triangle authored shape")
    matrix = np.identity(4, dtype=np.float64) if transform is None else np.asarray(
        transform, dtype=np.float64
    )
    positions = rasterizer._transform_positions(mesh.positions, matrix)
    normals = rasterizer._transform_normals(mesh.normals, matrix)
    projected = rasterizer._project(positions)
    vertices = np.asarray([triangle.vertex for triangle in triangles], dtype=np.int64)
    screens = projected[vertices]
    finite = np.all(np.isfinite(screens), axis=(1, 2))
    safe = np.where(finite[:, None, None], screens, 0.0)
    sx, sy = safe[..., 0], safe[..., 1]
    x0 = np.maximum(0, np.floor(np.min(sx, axis=1))).astype(np.int64)
    x1 = np.minimum(rasterizer.width - 1, np.ceil(np.max(sx, axis=1))).astype(np.int64)
    y0 = np.maximum(0, np.floor(np.min(sy, axis=1))).astype(np.int64)
    y1 = np.minimum(rasterizer.height - 1, np.ceil(np.max(sy, axis=1))).astype(np.int64)
    denominator = (
        (sx[:, 0] - sx[:, 1]) * (sy[:, 2] - sy[:, 1])
        - (sy[:, 0] - sy[:, 1]) * (sx[:, 2] - sx[:, 1])
    )
    candidate = finite & (x0 <= x1) & (y0 <= y1) & (np.abs(denominator) >= 1e-10)
    selected = np.flatnonzero(candidate)
    selected_triangles = [triangles[int(index)] for index in selected]
    selected_vertices = vertices[selected]
    material_uv = (
        np.ascontiguousarray(
            [mesh.texcoords[np.asarray(triangle.texcoord, dtype=np.int64)] for triangle in selected_triangles],
            dtype=np.float64,
        )
        if len(selected)
        else np.empty((0, 3, 2), dtype=np.float64)
    )
    vertex_normals = (
        np.ascontiguousarray(
            [normals[np.asarray(triangle.normal, dtype=np.int64)] for triangle in selected_triangles],
            dtype=np.float64,
        )
        if len(selected)
        else np.empty((0, 3, 3), dtype=np.float64)
    )
    if mode:
        paint = style.gameuber_mask0_facepaint
        generated = _linear_texture(rasterizer, paint.generated_mask_texture, "Mask0 _a0")
        user = _linear_texture(rasterizer, paint.user0_texture, "Mask0 _user0")
        affine = np.asarray(paint.user0_tex_srt.affine_rows, dtype=np.float64).reshape(-1)
    else:
        generated = _linear_texture(rasterizer, style.texture, "Mask0 _a0")
        user = np.ones((1, 1, 4), dtype=np.float64)
        affine = np.zeros(6, dtype=np.float64)
    parameters = np.ascontiguousarray(
        np.concatenate(
            (
                np.asarray(
                    (
                        rasterizer.light_intensity,
                        rasterizer.ambient_intensity,
                        float(rasterizer.perspective_correct),
                        float(mode),
                    ),
                    dtype=np.float64,
                ),
                affine,
            )
        ),
        dtype=np.float64,
    )
    return FlattenedMask0Draw(
        screen_triangles=np.ascontiguousarray(screens[selected], dtype=np.float64),
        bounds=np.ascontiguousarray(
            np.column_stack((x0[selected], x1[selected], y0[selected], y1[selected])),
            dtype=np.int64,
        ),
        denominators=np.ascontiguousarray(denominator[selected], dtype=np.float64),
        world_vertices=np.ascontiguousarray(positions[selected_vertices], dtype=np.float64),
        vertex_normals=vertex_normals,
        material_uv=material_uv,
        generated_texture=generated,
        user_texture=user,
        light_direction=np.ascontiguousarray(rasterizer.light_direction, dtype=np.float64),
        light_color=np.ascontiguousarray(rasterizer.light_color, dtype=np.float64),
        ambient_color=np.ascontiguousarray(rasterizer.ambient_color, dtype=np.float64),
        parameters=parameters,
        submitted_triangle_count=len(triangles),
    )


def draw_mask0_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> Mask0DrawResult:
    """Execute one exact-current Mask0 draw through the consolidated ABI."""

    payload = flatten_mask0_group(rasterizer, mesh, group, style, transform)
    count = payload.candidate_triangle_count
    arrays = (
        (payload.screen_triangles, np.float64, (count, 3, 3), "screen_triangles"),
        (payload.bounds, np.int64, (count, 4), "bounds"),
        (payload.denominators, np.float64, (count,), "denominators"),
        (payload.world_vertices, np.float64, (count, 3, 3), "world_vertices"),
        (payload.vertex_normals, np.float64, (count, 3, 3), "vertex_normals"),
        (payload.material_uv, np.float64, (count, 3, 2), "material_uv"),
        (payload.generated_texture, np.float64, (None, None, 4), "generated_texture"),
        (payload.user_texture, np.float64, (None, None, 4), "user_texture"),
        (payload.light_direction, np.float64, (3,), "light_direction"),
        (payload.light_color, np.float64, (3,), "light_color"),
        (payload.ambient_color, np.float64, (3,), "ambient_color"),
        (payload.parameters, np.float64, (10,), "parameters"),
    )
    checked = [_as_contiguous_exact(value, dtype, shape, name) for value, dtype, shape, name in arrays]
    color = _as_contiguous_exact(
        rasterizer.color, np.float64, (None, None, 3), "color", writable=True
    )
    depth = _as_contiguous_exact(
        rasterizer.depth, np.float64, color.shape[:2], "depth", writable=True
    )
    target_alpha = rasterizer.target_alpha
    if target_alpha is not None:
        target_alpha = _as_contiguous_exact(
            target_alpha, np.float64, color.shape[:2], "target_alpha", writable=True
        )
    written = int(_draw_mask0_compiled(color, depth, target_alpha, *checked))
    return Mask0DrawResult(payload.submitted_triangle_count, count, written)


def try_draw_group(
    rasterizer: Any,
    mesh: Any,
    group: str,
    style: Any,
    transform: np.ndarray | None = None,
) -> int | None:
    """Handle a supported whole draw, or leave it untouched for Python fallback."""

    head = try_draw_head816_group(rasterizer, mesh, group, style, transform)
    if head is not None:
        return head.submitted_triangles
    if supports_hair612_draw(rasterizer, mesh, group, style):
        return draw_hair612_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_beard468_draw(rasterizer, mesh, group, style):
        return draw_beard468_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_hair564_equal_draw(rasterizer, mesh, group, style):
        return draw_hair564_equal_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_outfit984_draw(rasterizer, mesh, group, style):
        return draw_outfit984_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_outfit936_draw(rasterizer, mesh, group, style):
        return draw_outfit936_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_outfit912_draw(rasterizer, mesh, group, style):
        return draw_outfit912_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_body_draw(rasterizer, mesh, group, style):
        return draw_body_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if (
        supports_ear372_draw(rasterizer, mesh, group, style)
        or supports_nose756_draw(rasterizer, mesh, group, style)
    ):
        return draw_plain_skin_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    if supports_mask0_draw(rasterizer, mesh, group, style):
        return draw_mask0_group(
            rasterizer, mesh, group, style, transform
        ).submitted_triangles
    return None


__all__ = [
    "ABI_VERSION",
    "BACKEND_AVAILABLE",
    "DISABLED_BY_ENVIRONMENT",
    "FlattenedHead816Draw",
    "FlattenedHair612Draw",
    "FlattenedBodyDraw",
    "FlattenedOpaqueOutfitDraw",
    "FlattenedOutfit984Draw",
    "FlattenedPlainSkinDraw",
    "FlattenedMask0Draw",
    "Hair612DrawResult",
    "Head816DrawResult",
    "OpaqueOutfitDrawResult",
    "OpaqueCurrentDrawResult",
    "Outfit984DrawResult",
    "Mask0DrawResult",
    "IMPORT_ERROR",
    "MAX_PACKED_TEXTURES",
    "clear_runtime_caches",
    "draw_beard468_group",
    "draw_body_group",
    "draw_head816_flat",
    "draw_head816_group",
    "draw_hair612_group",
    "draw_hair564_equal_group",
    "draw_outfit912_group",
    "draw_outfit936_group",
    "draw_outfit984_group",
    "draw_mask0_group",
    "draw_plain_skin_group",
    "flatten_beard468_group",
    "flatten_body_group",
    "flatten_head816_group",
    "flatten_hair612_group",
    "flatten_hair564_equal_group",
    "flatten_outfit912_group",
    "flatten_outfit936_group",
    "flatten_outfit984_group",
    "flatten_mask0_group",
    "flatten_plain_skin_group",
    "runtime_cache_size",
    "supports_beard468_draw",
    "supports_body_draw",
    "supports_ear372_draw",
    "supports_hair612_draw",
    "supports_hair564_equal_draw",
    "supports_head816_draw",
    "supports_outfit912_draw",
    "supports_outfit936_draw",
    "supports_outfit984_draw",
    "supports_mask0_draw",
    "supports_nose756_draw",
    "try_draw_head816_group",
    "try_draw_group",
]
