"""Small deterministic OBJ renderer used by the recovered Mii pipeline.

The game uses NVN and NintendoWare shaders that cannot run on a desktop host.
This module keeps the recovered geometry, UVs, normals, draw ordering, material
colors, and alpha semantics while providing a portable orthographic rasterizer.
It deliberately has no OpenGL/DirectX dependency so the reconstruction can be
reproduced in the analysis workspace and in CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from numpy.typing import ArrayLike
from PIL import Image

try:
    from . import (
        gameuber_cpu,
        native_current_draw,
        native_raster_kernel,
        screen_space_face_shadow,
    )
    from .share_mii_facepaint import FacePaintTexSrt
except ImportError:  # Direct execution/import from renderer/render_mii.py.
    import gameuber_cpu
    import native_current_draw
    import native_raster_kernel
    import screen_space_face_shadow
    from share_mii_facepaint import FacePaintTexSrt


TextureSource = np.ndarray | tuple[np.ndarray, ...]

_TEXCOORD_BINDING_ROLES = frozenset(
    {
        "texture",
        "alpha",
        "normal",
        "height",
        "parallax",
        "occlusion",
        "specular",
        "roughness",
        "gradient",
        "cheap_sss_mask",
        "body_albedo",
        "body_skin_mask",
        "body_material_information",
        "mask_generated",
        "mask_user0",
    }
)


def _cross3(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    """Fast exact cross product for equal-shaped float64 xyz arrays."""

    result = np.empty_like(left)
    result[..., 0] = left[..., 1] * right[..., 2] - left[..., 2] * right[..., 1]
    result[..., 1] = left[..., 2] * right[..., 0] - left[..., 0] * right[..., 2]
    result[..., 2] = left[..., 0] * right[..., 1] - left[..., 1] * right[..., 0]
    return result


@dataclass(frozen=True)
class ObjTriangle:
    """One indexed OBJ triangle and its source shape/group."""

    group: str
    vertex: tuple[int, int, int]
    texcoord: tuple[int | None, int | None, int | None]
    normal: tuple[int | None, int | None, int | None]


@dataclass
class ObjMesh:
    """The OBJ attributes and triangles recovered from one BFRES model."""

    positions: np.ndarray
    texcoords: np.ndarray
    normals: np.ndarray
    triangles: list[ObjTriangle]
    # OBJ can index only one UV set per face corner.  Prepared BFRES models
    # with multiple authored sets retain them here by their canonical vertex
    # attribute names (for example ``_u0`` and ``_u2``).  Each array is
    # position-indexed; NaN rows identify shapes that do not author that set.
    texcoord_channels: dict[str, np.ndarray] = field(default_factory=dict)

    @property
    def groups(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(triangle.group for triangle in self.triangles))


@dataclass(frozen=True)
class GameUberBody348LocalMaterialInputs:
    """Source-backed local inputs shared by BodyBaseDefault GameAll 324/336/348.

    The compiled fragment samples ``Alb`` through an sRGB view, reads
    ``Skm.g`` and ``Mic.r`` as linear scalar channels, and evaluates the two
    equations implemented by :func:`gameuber_cpu.body348_local_surface`.
    Lighting/prepass inputs are deliberately absent: they remain unresolved
    and are outside this executable local-material contract.

    Sampler state is explicit so selecting this path cannot silently acquire a
    made-up wrap mode or mip filter from the portable rasterizer.
    """

    albedo_texture: TextureSource
    albedo_wrap: tuple[str, str]
    albedo_mip_filter: str
    skin_mask_texture: TextureSource
    skin_mask_wrap: tuple[str, str]
    skin_mask_mip_filter: str
    material_information_texture: TextureSource
    material_information_wrap: tuple[str, str]
    material_information_mip_filter: str
    face_color_linear_rgb: tuple[float, float, float]
    const_single_roughness: float


@dataclass(frozen=True)
class GameUberMask0FacePaintInputs:
    """GameAll0 inputs for a complete ShareMii v3 face paint.

    Generated ``_a0`` and UGC ``_user0`` remain independent shader samples;
    this type never precomposes them.  Every sampler/value is required so a
    face-paint render cannot acquire a silent portable default.  The
    ``const_single0`` endpoint is explicitly marked as constructor fallback
    state because the imported provider-record override is not captured.
    """

    generated_mask_texture: TextureSource
    generated_mask_wrap: tuple[str, str]
    generated_mask_mip_filter: str
    user0_texture: TextureSource
    user0_wrap: tuple[str, str]
    user0_mip_filter: str
    user0_tex_srt: FacePaintTexSrt
    replace_albedo_color_linear_rgba: tuple[float, float, float, float]
    source_backed_constructor_const_single0_value: float
    const_single0_runtime_state: str
    emission_color_linear_rgb: tuple[float, float, float]
    emission_intensity: float
    portable_coverage_threshold: float


@dataclass
class MaterialStyle:
    """Portable approximation of the recovered GameUber/Mii material state."""

    color: tuple[float, float, float, float] = (1.0, 1.0, 1.0, 1.0)
    gameuber_body348: GameUberBody348LocalMaterialInputs | None = None
    gameuber_mask0_facepaint: GameUberMask0FacePaintInputs | None = None
    texture: TextureSource | None = None
    texture_wrap: tuple[str, str] = ("clamp", "clamp")
    texture_mip_filter: str = "point"
    texture_emission_intensity: float = 0.0
    texture_alpha_under_color_linear: tuple[float, float, float] | None = None
    alpha_texture: TextureSource | None = None
    alpha_wrap: tuple[str, str] = ("clamp", "clamp")
    alpha_mip_filter: str = "point"
    normal_texture: TextureSource | None = None
    normal_wrap: tuple[str, str] = ("clamp", "clamp")
    normal_mip_filter: str = "point"
    normal_channels: tuple[int, int] = (0, 1)
    normal_strength: float = 1.0
    height_texture: TextureSource | None = None
    height_wrap: tuple[str, str] = ("clamp", "clamp")
    height_mip_filter: str = "point"
    height_channel: int = 0
    height_strength: float = 0.0
    parallax_texture: TextureSource | None = None
    parallax_wrap: tuple[str, str] = ("clamp", "clamp")
    parallax_mip_filter: str = "point"
    parallax_channel: int = 0
    parallax_scale: float = 0.0
    occlusion_texture: TextureSource | None = None
    occlusion_wrap: tuple[str, str] = ("clamp", "clamp")
    occlusion_mip_filter: str = "point"
    occlusion_channel: int = 0
    specular_texture: TextureSource | None = None
    specular_wrap: tuple[str, str] = ("clamp", "clamp")
    specular_mip_filter: str = "point"
    specular_channel: int = 0
    specular_strength: float = 0.0
    anisotropic_proxy: bool = False
    anisotropic_shift_channel: int = 2
    anisotropic_shift_scale: float = 1.0
    anisotropic_shift_offset: float = 0.0
    anisotropic_specular_size: float = 10.0
    anisotropic_toon_intensity: float = 1.0
    anisotropic_title_view_scale: float = 1.0
    anisotropic_radiance_scale: float = 1.0
    cheap_sss_proxy: bool = False
    cheap_sss_mask_texture: TextureSource | None = None
    cheap_sss_mask_wrap: tuple[str, str] = ("clamp", "clamp")
    cheap_sss_mask_mip_filter: str = "point"
    cheap_sss_mask_channel: int = 0
    cheap_sss_mask_invert: bool = False
    front_edge_light_proxy: bool = False
    front_edge_light_view_angle_degrees: float = 50.0
    front_edge_light_intensity: float = 0.0
    roughness: float = 1.0
    roughness_texture: TextureSource | None = None
    roughness_wrap: tuple[str, str] = ("clamp", "clamp")
    roughness_mip_filter: str = "point"
    roughness_channel: int = 0
    roughness_scale: float = 1.0
    roughness_bias: float = 0.0
    lit: bool = True
    # The Mii materials split ordinary depth shadows from the dedicated
    # screen-space face-shadow path.  Hair/headwear opt into the latter as
    # casters through BFRES RenderInfo ``cast_face_shadow``; Head/Nose/Ear opt
    # in as receivers through GameAll ``enable_screenspace_face_shadow``.
    # Mask (the generated eyes/mouth/etc. carrier), glasses, beard, and body
    # materials do neither.  Keep these flags explicit so a portable shadow
    # substitute cannot silently darken a foreground face layer or admit an
    # unrelated opaque mesh as a face-shadow caster.
    casts_face_shadow: bool = False
    receives_screenspace_face_shadow: bool = False
    alpha_multiplier: float = 1.0
    depth_write: bool = True
    alpha_cutoff: float = 1.0 / 255.0
    cull_back_faces: bool = True
    clockwise_front_face: bool = False
    flip_horizontal_sign: float = 1.0
    blend: bool = False
    premultiplied_rgb_blend: bool = False
    gradient_texture: TextureSource | None = None
    gradient_wrap: tuple[str, str] = ("clamp", "clamp")
    gradient_mip_filter: str = "point"
    gradient_channel: int = 0
    gradient_colors: tuple[
        tuple[float, float, float], tuple[float, float, float]
    ] | None = None
    hair_constant_color_linear: tuple[float, float, float] | None = None
    hair708_face_color_linear: tuple[float, float, float] | None = None
    hair708_face_blend_channel: int = 1
    gamma_correct_lighting: bool = False
    linear_lighting: bool = False
    gameall_identity: gameuber_cpu.GameAllProgramIdentity | None = None
    # Production draws must either bind one audited GameAll identity or name
    # the portable family whose title program/local response is unresolved.
    # Generic unit-test materials may leave both fields unset; render_mii makes
    # this routing mandatory before executing its recorded scene.
    unresolved_portable_family: str | None = None
    # Optional BFRES sampler-role -> canonical vertex-attribute bindings.
    # Absent roles retain the legacy OBJ face-corner UV stream exactly.
    texcoord_bindings: dict[str, str] = field(default_factory=dict)


def validate_material_style_routing(
    style: MaterialStyle,
    *,
    require_named: bool = False,
) -> None:
    """Enforce isolated GameAll gates and optionally require named routing."""

    identity = style.gameall_identity
    portable_family = style.unresolved_portable_family
    if identity is not None and portable_family is not None:
        raise ValueError(
            "a material cannot be both audited GameAll and unresolved portable"
        )
    if portable_family is not None:
        if (
            not isinstance(portable_family, str)
            or not portable_family
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789_"
                for character in portable_family
            )
        ):
            raise ValueError(
                "unresolved_portable_family must be a nonempty lowercase identifier"
            )
        if (
            style.gameuber_body348 is not None
            or style.gameuber_mask0_facepaint is not None
            or style.cheap_sss_proxy
            or style.anisotropic_proxy
            or style.front_edge_light_proxy
            or style.specular_strength != 0.0
            or style.hair_constant_color_linear is not None
            or style.hair708_face_color_linear is not None
            or style.receives_screenspace_face_shadow
        ):
            raise ValueError(
                f"unresolved portable family {portable_family!r} cannot execute an audited GameAll-only or generic lighting branch"
            )
        return
    if identity is None:
        if require_named:
            raise ValueError(
                "production material has neither an audited GameAll identity nor a named unresolved portable family"
            )
        return
    identity = gameuber_cpu.validate_gameall_program_identity(identity)
    if style.cheap_sss_proxy and not identity.cheap_sss_local_curve:
        raise ValueError(
            f"GameAll {identity.family}/{identity.program_index} has no audited cheap-SSS local curve"
        )
    if style.anisotropic_proxy and not identity.anisotropic_local_kernel:
        raise ValueError(
            f"GameAll {identity.family}/{identity.program_index} has no audited anisotropic local kernel"
        )
    if style.front_edge_light_proxy and not identity.front_edge_local_gate:
        raise ValueError(
            f"GameAll {identity.family}/{identity.program_index} has no audited front-edge local gate"
        )
    if style.specular_strength != 0.0:
        raise ValueError(
            f"generic Phong is not an audited local branch of GameAll {identity.family}/{identity.program_index}"
        )
    if (
        style.receives_screenspace_face_shadow
        != identity.receives_screen_space_face_shadow
    ):
        raise ValueError(
            f"GameAll {identity.family}/{identity.program_index} screen-space face-shadow routing changed"
        )
    if style.gameuber_body348 is not None and identity.family != "body":
        raise ValueError("GameUber Body local inputs require a body/324, 336, or 348 identity")
    if style.gameuber_mask0_facepaint is not None and identity.family != "mask":
        raise ValueError("GameUber Mask0 inputs require the mask/0 program identity")
    if style.hair_constant_color_linear is not None and identity.family != "hair_constant":
        raise ValueError("constant-color Hair inputs require a hair_constant identity")


def _validate_gameall_material_style(style: MaterialStyle) -> None:
    """Compatibility wrapper for the rasterizer's per-style validation."""

    validate_material_style_routing(style)


@dataclass(frozen=True)
class DrawCall:
    """One ordered mesh/material submission recorded for multipass rendering."""

    mesh: ObjMesh
    group: str
    style: MaterialStyle
    transform: np.ndarray


class DrawRecorder:
    """Collect draw calls while preserving the title-derived submission order."""

    def __init__(self) -> None:
        self.calls: list[DrawCall] = []

    def draw_group(
        self,
        mesh: ObjMesh,
        group: str,
        style: MaterialStyle,
        transform: np.ndarray,
    ) -> int:
        self.calls.append(DrawCall(mesh, group, style, np.asarray(transform, dtype=np.float64)))
        return sum(triangle.group == group for triangle in mesh.triangles)


def _obj_index(value: str, length: int) -> int | None:
    if not value:
        return None
    index = int(value)
    return index - 1 if index > 0 else length + index


def _load_named_texcoords(
    obj_path: Path,
    position_count: int,
    texcoords: np.ndarray,
    triangles: list[ObjTriangle],
) -> dict[str, np.ndarray]:
    """Load and validate the exporter's optional multi-UV sidecar."""

    sidecar_path = obj_path.with_name(obj_path.stem + ".texcoords.json")
    if not sidecar_path.is_file():
        return {}
    document: Any = json.loads(sidecar_path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("SchemaVersion") != 1
        or document.get("VertexIndexing") != "obj_position_zero_based"
        or document.get("CoordinateConvention")
        != "u_bfres_x__v_one_minus_bfres_y"
        or document.get("Model") != obj_path.stem
        or document.get("VertexCount") != position_count
    ):
        raise ValueError(f"unsupported or mismatched named-UV sidecar: {sidecar_path}")
    shape_records = document.get("Shapes")
    if not isinstance(shape_records, list) or not shape_records:
        raise ValueError(f"named-UV sidecar has no shapes: {sidecar_path}")

    channels: dict[str, np.ndarray] = {}
    coverage: dict[str, np.ndarray] = {}
    shape_by_group: dict[str, dict[str, Any]] = {}
    occupied_vertices = np.zeros(position_count, dtype=bool)
    for shape in shape_records:
        if not isinstance(shape, dict):
            raise ValueError(f"named-UV sidecar shape is not an object: {sidecar_path}")
        group = shape.get("Group")
        offset = shape.get("VertexOffset")
        count = shape.get("VertexCount")
        channel_records = shape.get("Channels")
        if (
            not isinstance(group, str)
            or not group
            or group in shape_by_group
            or not isinstance(offset, int)
            or not isinstance(count, int)
            or count <= 0
            or offset < 0
            or offset + count > position_count
            or not isinstance(channel_records, dict)
        ):
            raise ValueError(f"named-UV sidecar shape metadata is malformed: {sidecar_path}")
        shape_slice = slice(offset, offset + count)
        if np.any(occupied_vertices[shape_slice]):
            raise ValueError(f"named-UV sidecar shape ranges overlap: {sidecar_path}")
        occupied_vertices[shape_slice] = True
        shape_by_group[group] = shape
        for name, values in channel_records.items():
            if (
                not isinstance(name, str)
                or not name.startswith("_u")
                or not name[2:].isdigit()
            ):
                raise ValueError(f"named-UV sidecar channel name is malformed: {sidecar_path}")
            array = np.asarray(values, dtype=np.float64)
            if array.shape != (count, 2) or not np.all(np.isfinite(array)):
                raise ValueError(
                    f"named-UV sidecar channel {group}/{name} is malformed: {sidecar_path}"
                )
            target = channels.setdefault(
                name, np.full((position_count, 2), np.nan, dtype=np.float64)
            )
            target_coverage = coverage.setdefault(
                name, np.zeros(position_count, dtype=bool)
            )
            if np.any(target_coverage[shape_slice]):
                raise ValueError(
                    f"named-UV sidecar channel {name} overlaps itself: {sidecar_path}"
                )
            target[shape_slice] = array
            target_coverage[shape_slice] = True

    if not np.all(occupied_vertices):
        raise ValueError(f"named-UV sidecar does not cover every OBJ vertex: {sidecar_path}")
    if len(channels) < 2:
        raise ValueError(f"named-UV sidecar does not preserve multiple channels: {sidecar_path}")

    # Bind the legacy OBJ stream back to its declared source channel.  This
    # catches stale sidecars and prevents named UVs from silently drifting
    # away from the face-corner indices used by all existing materials.
    for triangle in triangles:
        shape = shape_by_group.get(triangle.group)
        if shape is None:
            raise ValueError(
                f"OBJ group {triangle.group!r} is absent from named-UV sidecar: {sidecar_path}"
            )
        obj_channel = shape.get("ObjChannel")
        if obj_channel is None:
            if any(index is not None for index in triangle.texcoord):
                raise ValueError(
                    f"OBJ group {triangle.group!r} unexpectedly has UV indices: {obj_path}"
                )
            continue
        if obj_channel not in channels or not all(
            index is not None for index in triangle.texcoord
        ):
            raise ValueError(
                f"OBJ channel binding is incomplete for {triangle.group!r}: {sidecar_path}"
            )
        vertex_indices = np.asarray(triangle.vertex, dtype=np.int64)
        texcoord_indices = np.asarray(triangle.texcoord, dtype=np.int64)
        named = channels[obj_channel][vertex_indices]
        legacy = texcoords[texcoord_indices]
        if not np.array_equal(named, legacy):
            raise ValueError(
                f"OBJ UVs differ from {triangle.group!r}/{obj_channel}: {sidecar_path}"
            )
    return channels


def load_obj(path: Path | str) -> ObjMesh:
    """Read the subset of OBJ emitted by ``tools/bfres-exporter``."""

    positions: list[tuple[float, float, float]] = []
    texcoords: list[tuple[float, float]] = []
    normals: list[tuple[float, float, float]] = []
    triangles: list[ObjTriangle] = []
    group = "unnamed"

    obj_path = Path(path)
    with obj_path.open("r", encoding="utf-8") as source:
        for raw_line in source:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            record = fields[0]
            if record == "g":
                group = " ".join(fields[1:]) or "unnamed"
            elif record == "v":
                positions.append(tuple(map(float, fields[1:4])))
            elif record == "vt":
                texcoords.append(tuple(map(float, fields[1:3])))
            elif record == "vn":
                normals.append(tuple(map(float, fields[1:4])))
            elif record == "f":
                corners: list[tuple[int, int | None, int | None]] = []
                for field in fields[1:]:
                    indices = field.split("/")
                    vertex = _obj_index(indices[0], len(positions))
                    if vertex is None:
                        raise ValueError(f"face without a vertex index in {path}")
                    texcoord = _obj_index(indices[1], len(texcoords)) if len(indices) > 1 else None
                    normal = _obj_index(indices[2], len(normals)) if len(indices) > 2 else None
                    corners.append((vertex, texcoord, normal))
                # The exporter emits triangles, but fan triangulation makes the
                # reader useful for hand-inspected OBJ variants as well.
                for corner in range(1, len(corners) - 1):
                    tri = (corners[0], corners[corner], corners[corner + 1])
                    triangles.append(
                        ObjTriangle(
                            group=group,
                            vertex=tuple(item[0] for item in tri),
                            texcoord=tuple(item[1] for item in tri),
                            normal=tuple(item[2] for item in tri),
                        )
                    )

    position_array = np.asarray(positions, dtype=np.float64)
    texcoord_array = np.asarray(texcoords, dtype=np.float64)
    return ObjMesh(
        positions=position_array,
        texcoords=texcoord_array,
        normals=np.asarray(normals, dtype=np.float64),
        triangles=triangles,
        texcoord_channels=_load_named_texcoords(
            obj_path, len(position_array), texcoord_array, triangles
        ),
    )


def identity() -> np.ndarray:
    return np.identity(4, dtype=np.float64)


def translation(x: float, y: float, z: float) -> np.ndarray:
    matrix = identity()
    matrix[:3, 3] = (x, y, z)
    return matrix


def scale(x: float, y: float | None = None, z: float | None = None) -> np.ndarray:
    if y is None:
        y = x
    if z is None:
        z = x
    matrix = identity()
    matrix[0, 0], matrix[1, 1], matrix[2, 2] = x, y, z
    return matrix


def rotation_z(radians: float) -> np.ndarray:
    cosine, sine = np.cos(radians), np.sin(radians)
    matrix = identity()
    matrix[0, 0], matrix[0, 1] = cosine, -sine
    matrix[1, 0], matrix[1, 1] = sine, cosine
    return matrix


def texture_from_image(image: Image.Image) -> np.ndarray:
    return np.asarray(image.convert("RGBA"), dtype=np.float64) / 255.0


def _srgb_to_linear(value: np.ndarray) -> np.ndarray:
    value = np.asarray(value, dtype=np.float64)
    return np.where(
        value <= 0.04045,
        value / 12.92,
        np.power((value + 0.055) / 1.055, 2.4),
    )


def _linear_to_srgb(value: np.ndarray) -> np.ndarray:
    value = np.maximum(np.asarray(value, dtype=np.float64), 0.0)
    return np.where(
        value <= 0.0031308,
        value * 12.92,
        1.055 * np.power(value, 1.0 / 2.4) - 0.055,
    )


class OrthographicRasterizer:
    """A z-buffered, smooth-shaded, textured orthographic rasterizer."""

    def __init__(
        self,
        width: int,
        height: int,
        world_bounds: tuple[float, float, float, float],
        background: tuple[float, float, float] = (0.95, 0.97, 1.0),
        linear_framebuffer: bool = False,
        transparent_background: bool = False,
    ) -> None:
        self.width = width
        self.height = height
        self.x_min, self.x_max, self.y_min, self.y_max = world_bounds
        self.linear_framebuffer = bool(linear_framebuffer)
        self.transparent_background = bool(transparent_background)
        self.color = np.empty((height, width, 3), dtype=np.float64)
        background_color = np.asarray(background, dtype=np.float64)
        if self.transparent_background:
            # A transparent target keeps premultiplied RGB internally.  This
            # lets source-over fragments accumulate without inventing an RGB
            # matte, and avoids the colored fringe produced by chroma-keying
            # an already composited presentation background.
            self.color.fill(0.0)
            self.target_alpha: np.ndarray | None = np.zeros(
                (height, width), dtype=np.float64
            )
        else:
            self.color[:] = (
                _srgb_to_linear(background_color)
                if self.linear_framebuffer
                else background_color
            )
            self.target_alpha = None
        self.depth = np.full((height, width), -np.inf, dtype=np.float64)
        self._sample_x = np.arange(width, dtype=np.float64)[None, :] + 0.5
        self._sample_y = np.arange(height, dtype=np.float64)[:, None] + 0.5
        self.camera_position: np.ndarray | None = None
        self.perspective_correct = False
        self.light_direction = np.asarray((-0.35, 0.48, 0.805), dtype=np.float64)
        self.light_direction /= np.linalg.norm(self.light_direction)
        # Defaults preserve the original portable response.  Callers with a
        # recovered snapshot profile replace these with the title's resource
        # values and an explicitly documented normalization boundary.
        self.light_color = np.ones(3, dtype=np.float64)
        self.light_intensity = 0.4
        self.ambient_color = np.full(3, 0.6, dtype=np.float64)
        self.ambient_intensity = 1.0
        self.light_normalization = 1.0
        self.specular_intensity = 1.0
        # Snapshot/GameUber edge-light RGB comes from title environment
        # records that are not present in the decompile. Keep it disabled until
        # a source-backed environment profile supplies a value.
        self.edge_light_color = np.zeros(3, dtype=np.float64)
        # NVN sRGB texture views decode each texel before linear filtering.
        # Cache that hardware-visible representation by source-array identity;
        # each rasterizer owns the cache, so identities cannot outlive their
        # corresponding arrays or leak across renders.
        self._srgb_texture_level_cache: dict[
            int, tuple[np.ndarray, np.ndarray]
        ] = {}

    def _hardware_srgb_texture_level(self, level: np.ndarray) -> np.ndarray:
        """Return an RGBA level with RGB decoded as an NVN sRGB view.

        Alpha is copied without transformation.  Decoding a whole native mip
        once also ensures bilinear/trilinear interpolation happens between
        linear texels, rather than applying an incorrect decode after the
        filtered sample.
        """

        key = id(level)
        cached = self._srgb_texture_level_cache.get(key)
        if cached is not None and cached[0] is level:
            return cached[1]
        decoded = np.asarray(level, dtype=np.float64).copy()
        if decoded.ndim != 3 or decoded.shape[2] < 3:
            raise ValueError("an sRGB texture level must have at least three channels")
        decoded[..., :3] = _srgb_to_linear(decoded[..., :3])
        self._srgb_texture_level_cache[key] = (level, decoded)
        return decoded

    def add_vertical_background_gradient(
        self,
        top: tuple[float, float, float],
        bottom: tuple[float, float, float],
    ) -> None:
        amount = np.linspace(0.0, 1.0, self.height, dtype=np.float64)[:, None, None]
        top_value = np.asarray(top, dtype=np.float64)
        bottom_value = np.asarray(bottom, dtype=np.float64)
        if self.linear_framebuffer:
            top_value = _srgb_to_linear(top_value)
            bottom_value = _srgb_to_linear(bottom_value)
        top_color = top_value[None, None, :]
        bottom_color = bottom_value[None, None, :]
        self.color[:] = top_color * (1.0 - amount) + bottom_color * amount

    def add_ground_shadow(
        self,
        center: tuple[float, float],
        radius: tuple[float, float],
        opacity: float = 0.14,
    ) -> None:
        x_world = self.x_min + np.arange(self.width) * (self.x_max - self.x_min) / max(1, self.width - 1)
        y_world = self.y_max - np.arange(self.height) * (self.y_max - self.y_min) / max(1, self.height - 1)
        x_grid, y_grid = np.meshgrid(x_world, y_world)
        distance = ((x_grid - center[0]) / radius[0]) ** 2 + ((y_grid - center[1]) / radius[1]) ** 2
        alpha = np.exp(-distance * 2.2) * opacity
        self.color *= 1.0 - alpha[..., None]

    def _project(self, positions: np.ndarray) -> np.ndarray:
        projected = np.empty_like(positions)
        projected[:, 0] = (positions[:, 0] - self.x_min) / (self.x_max - self.x_min) * (self.width - 1)
        projected[:, 1] = (self.y_max - positions[:, 1]) / (self.y_max - self.y_min) * (self.height - 1)
        projected[:, 2] = positions[:, 2]
        return projected

    @staticmethod
    def _transform_positions(positions: np.ndarray, matrix: np.ndarray) -> np.ndarray:
        homogeneous = np.column_stack((positions, np.ones(len(positions), dtype=np.float64)))
        return (matrix @ homogeneous.T).T[:, :3]

    @staticmethod
    def _transform_normals(normals: np.ndarray, matrix: np.ndarray) -> np.ndarray:
        if not len(normals):
            return normals
        normal_matrix = np.linalg.inv(matrix[:3, :3]).T
        transformed = (normal_matrix @ normals.T).T
        lengths = np.linalg.norm(transformed, axis=1)
        lengths[lengths == 0.0] = 1.0
        return transformed / lengths[:, None]

    def draw_group(
        self,
        mesh: ObjMesh,
        group: str,
        style: MaterialStyle,
        transform: np.ndarray | None = None,
    ) -> int:
        """Draw one source shape and return its submitted triangle count."""

        _validate_gameall_material_style(style)
        native_result = native_current_draw.try_draw_group(
            self, mesh, group, style, transform
        )
        if native_result is not None:
            return native_result
        matrix = identity() if transform is None else transform
        positions = self._transform_positions(mesh.positions, matrix)
        normals = self._transform_normals(mesh.normals, matrix)
        projected = self._project(positions)
        if style.hair_constant_color_linear is not None:
            base_source_color = gameuber_cpu.hair_constant_color_base_linear(
                style.hair_constant_color_linear
            )
        else:
            base_color = np.asarray(style.color[:3], dtype=np.float64)
            base_source_color = (
                _srgb_to_linear(base_color) if style.linear_lighting else base_color
            )
        triangles = [triangle for triangle in mesh.triangles if triangle.group == group]
        count = len(triangles)
        if not count:
            return 0
        if count < 32:
            for triangle in triangles:
                self._draw_triangle(
                    mesh,
                    triangle,
                    projected,
                    positions,
                    normals,
                    style,
                    precomputed_base_source_color=base_source_color,
                )
            return count

        # Cull the cheap, triangle-invariant rejection cases in one vectorized
        # pass.  This is especially valuable for closed hair/headwear meshes:
        # their back half used to enter thousands of Python _draw_triangle
        # calls only to return before allocating a raster grid.  Every test is
        # the exact scalar predicate repeated at the top of _draw_triangle;
        # submitted triangle counts deliberately remain unchanged.
        vertex_indices = np.asarray(
            [triangle.vertex for triangle in triangles], dtype=np.int64
        )
        screens = projected[vertex_indices]
        finite = np.all(np.isfinite(screens), axis=(1, 2))
        candidate = finite.copy()
        safe_screens = np.where(finite[:, None, None], screens, 0.0)
        screen_x = safe_screens[..., 0]
        screen_y = safe_screens[..., 1]
        x0 = np.maximum(0, np.floor(np.min(screen_x, axis=1))).astype(np.int64)
        x1 = np.minimum(
            self.width - 1, np.ceil(np.max(screen_x, axis=1))
        ).astype(np.int64)
        y0 = np.maximum(0, np.floor(np.min(screen_y, axis=1))).astype(np.int64)
        y1 = np.minimum(
            self.height - 1, np.ceil(np.max(screen_y, axis=1))
        ).astype(np.int64)
        candidate &= (
            (x0 <= x1)
            & (y0 <= y1)
        )
        denominator = (
            (screen_x[:, 0] - screen_x[:, 1])
            * (screen_y[:, 2] - screen_y[:, 1])
            - (screen_y[:, 0] - screen_y[:, 1])
            * (screen_x[:, 2] - screen_x[:, 1])
        )
        candidate &= np.abs(denominator) >= 1e-10
        if style.cull_back_faces:
            candidate &= (
                denominator < 0.0
                if style.clockwise_front_face
                else denominator > 0.0
            )
        for index in np.flatnonzero(candidate):
            triangle = triangles[int(index)]
            self._draw_triangle(
                mesh,
                triangle,
                projected,
                positions,
                normals,
                style,
                precomputed_base_source_color=base_source_color,
                prechecked_screen=screens[index],
                prechecked_bounds=(x0[index], x1[index], y0[index], y1[index]),
                prechecked_denominator=denominator[index],
            )
        return count

    def draw_groups(
        self,
        mesh: ObjMesh,
        groups: Iterable[str],
        style: MaterialStyle,
        transform: np.ndarray | None = None,
    ) -> int:
        return sum(self.draw_group(mesh, group, style, transform) for group in groups)

    def _draw_triangle(
        self,
        mesh: ObjMesh,
        triangle: ObjTriangle,
        projected: np.ndarray,
        world_positions: np.ndarray,
        world_normals: np.ndarray,
        style: MaterialStyle,
        *,
        precomputed_base_source_color: np.ndarray | None = None,
        prechecked_screen: np.ndarray | None = None,
        prechecked_bounds: tuple[int, int, int, int] | None = None,
        prechecked_denominator: float | None = None,
    ) -> None:
        def edge(a: np.ndarray, b: np.ndarray, x: np.ndarray, y: np.ndarray) -> np.ndarray:
            return (x - a[0]) * (b[1] - a[1]) - (y - a[1]) * (b[0] - a[0])

        if prechecked_screen is None:
            screen = projected[np.asarray(triangle.vertex)]
            if not np.all(np.isfinite(screen)):
                return
            x0 = max(0, int(np.floor(np.min(screen[:, 0]))))
            x1 = min(self.width - 1, int(np.ceil(np.max(screen[:, 0]))))
            y0 = max(0, int(np.floor(np.min(screen[:, 1]))))
            y1 = min(self.height - 1, int(np.ceil(np.max(screen[:, 1]))))
            if x0 > x1 or y0 > y1:
                return
            denominator = edge(screen[1], screen[2], screen[0, 0], screen[0, 1])
            if abs(float(denominator)) < 1e-10:
                return
            # Projection flips Y. Front-facing, counter-clockwise model-space
            # triangles therefore have a positive value under this edge function.
            if style.cull_back_faces:
                if style.clockwise_front_face:
                    if denominator >= 0.0:
                        return
                elif denominator <= 0.0:
                    return
        else:
            if prechecked_bounds is None or prechecked_denominator is None:
                raise ValueError("a prechecked triangle requires bounds and denominator")
            screen = prechecked_screen
            x0, x1, y0, y1 = (int(value) for value in prechecked_bounds)
            denominator = float(prechecked_denominator)
        depth_view = self.depth[y0 : y1 + 1, x0 : x1 + 1]
        if native_raster_kernel.BACKEND_AVAILABLE:
            coverage = native_raster_kernel.coverage_fragments(
                screen,
                self.depth,
                x0,
                x1,
                y0,
                y1,
                denominator,
            )
            if coverage is None:
                return
            (
                fragment_y,
                fragment_x,
                affine_weight0,
                affine_weight1,
                affine_weight2,
                z_value,
            ) = coverage
        else:
            x_grid = self._sample_x[:, x0 : x1 + 1]
            y_grid = self._sample_y[y0 : y1 + 1, :]
            affine_weight0 = edge(screen[1], screen[2], x_grid, y_grid) / denominator
            affine_weight1 = edge(screen[2], screen[0], x_grid, y_grid) / denominator
            affine_weight2 = 1.0 - affine_weight0 - affine_weight1
            inside = (
                (affine_weight0 >= -1e-7)
                & (affine_weight1 >= -1e-7)
                & (affine_weight2 >= -1e-7)
            )
            if not np.any(inside):
                return

            z_value = (
                affine_weight0 * screen[0, 2]
                + affine_weight1 * screen[1, 2]
                + affine_weight2 * screen[2, 2]
            )
            # BFRES GameAll materials in this renderer use the title's LEQUAL
            # depth state.  Our depth representation is reversed (larger means
            # closer), so its exact equivalent is GEQUAL.  A tolerance here is
            # not harmless: it promotes genuinely-behind coplanar feature carriers to
            # ties and lets a later Mask/NoseLine/accessory draw overwrite the
            # surface in front of it.
            visible = inside & (z_value >= depth_view)
            if not np.any(visible):
                return

            # Shade only fragments that survived coverage and early depth. Keep a
            # singleton row dimension so existing shader broadcasting and reduction
            # order remain exact; saved coordinates map back into the framebuffer.
            fragment_y, fragment_x = np.nonzero(visible)
            affine_weight0 = affine_weight0[fragment_y, fragment_x][None, :]
            affine_weight1 = affine_weight1[fragment_y, fragment_x][None, :]
            affine_weight2 = affine_weight2[fragment_y, fragment_x][None, :]
            z_value = z_value[fragment_y, fragment_x][None, :]
        weight0, weight1, weight2 = affine_weight0, affine_weight1, affine_weight2
        if self.perspective_correct:
            denominator_w = z_value
            safe = np.where(np.abs(denominator_w) < 1e-20, 1.0, denominator_w)
            weight0 = affine_weight0 * screen[0, 2] / safe
            weight1 = affine_weight1 * screen[1, 2] / safe
            weight2 = affine_weight2 * screen[2, 2] / safe

        texture = style.texture
        body348 = style.gameuber_body348
        mask0_facepaint = style.gameuber_mask0_facepaint
        if style.gamma_correct_lighting and style.linear_lighting:
            raise ValueError("a material cannot request both pow-2.2 and IEC-sRGB lighting")
        if style.flip_horizontal_sign not in (-1.0, 1.0):
            raise ValueError("flip_horizontal_sign must be exactly +1 or -1")
        if style.hair708_face_color_linear is not None and (
            not style.gamma_correct_lighting
            or style.gradient_texture is None
            or style.gradient_colors is None
        ):
            raise ValueError(
                "Hair708 face-color blending requires the pow-2.2 MGH gradient path"
            )
        if style.hair_constant_color_linear is not None and (
            not style.linear_lighting
            or style.gamma_correct_lighting
            or style.gradient_texture is not None
            or style.gradient_colors is not None
        ):
            raise ValueError(
                "constant-color Hair requires a linear, texture-independent base path"
            )
        if style.premultiplied_rgb_blend and not style.blend:
            raise ValueError("premultiplied RGB blending requires blend=True")
        if body348 is not None and texture is not None:
            raise ValueError(
                "GameUber Body324/336/348 owns its Alb binding; generic MaterialStyle.texture must be unset"
            )
        if mask0_facepaint is not None and (texture is not None or body348 is not None):
            raise ValueError(
                "GameUber Mask0 owns _a0/_user0; generic texture and Body local inputs must be unset"
            )
        alpha: float | np.ndarray = float(
            style.color[3] * style.alpha_multiplier
        )
        source_color = np.empty((*weight0.shape, 3), dtype=np.float64)
        # nn::mii color binders and ordinary sRGB albedo views feed linear RGB
        # to GameUber. Decode the uniform endpoint separately from sampled
        # texels so multiplication happens in the same space as the shader.
        if precomputed_base_source_color is None:
            if style.hair_constant_color_linear is not None:
                precomputed_base_source_color = (
                    gameuber_cpu.hair_constant_color_base_linear(
                        style.hair_constant_color_linear
                    )
                )
            else:
                base_color = np.asarray(style.color[:3], dtype=np.float64)
                precomputed_base_source_color = (
                    _srgb_to_linear(base_color)
                    if style.linear_lighting
                    else base_color
                )
        source_color[:] = precomputed_base_source_color
        texture_alpha_sample: np.ndarray | None = None
        body348_roughness: np.ndarray | None = None
        local_emission: np.ndarray | None = None

        alpha_texture = style.alpha_texture
        normal_texture = style.normal_texture
        height_texture = style.height_texture
        parallax_texture = style.parallax_texture
        occlusion_texture = style.occlusion_texture
        specular_texture = style.specular_texture
        roughness_texture = style.roughness_texture
        gradient_texture = style.gradient_texture
        unknown_texcoord_roles = set(style.texcoord_bindings) - _TEXCOORD_BINDING_ROLES
        if unknown_texcoord_roles:
            raise ValueError(
                "unsupported texture-coordinate binding role(s): "
                + ", ".join(sorted(unknown_texcoord_roles))
            )
        for role, channel in style.texcoord_bindings.items():
            if (
                not isinstance(channel, str)
                or not channel.startswith("_u")
                or not channel[2:].isdigit()
            ):
                raise ValueError(f"invalid BFRES texcoord binding for {role}: {channel!r}")

        default_texcoord_indices = (
            np.asarray(triangle.texcoord, dtype=np.int64)
            if all(index is not None for index in triangle.texcoord)
            else None
        )
        vertex_indices = np.asarray(triangle.vertex, dtype=np.int64)
        triangle_uv_cache: dict[str | None, np.ndarray | None] = {}
        interpolated_uv_cache: dict[
            str | None, tuple[np.ndarray, np.ndarray, np.ndarray] | None
        ] = {}

        def triangle_uv_for(role: str | None) -> np.ndarray | None:
            channel = None if role is None else style.texcoord_bindings.get(role)
            if channel in triangle_uv_cache:
                return triangle_uv_cache[channel]
            if channel is None:
                result = (
                    None
                    if default_texcoord_indices is None
                    else mesh.texcoords[default_texcoord_indices]
                )
            else:
                authored = mesh.texcoord_channels.get(channel)
                if authored is None:
                    raise ValueError(
                        f"material requests absent BFRES texcoord channel {channel} for {role}"
                    )
                result = authored[vertex_indices]
                if not np.all(np.isfinite(result)):
                    raise ValueError(
                        f"shape {triangle.group!r} does not author BFRES texcoord channel "
                        f"{channel} requested for {role}"
                    )
            triangle_uv_cache[channel] = result
            return result

        def interpolated_uv_for(
            role: str | None,
        ) -> tuple[np.ndarray, np.ndarray, np.ndarray] | None:
            channel = None if role is None else style.texcoord_bindings.get(role)
            if channel in interpolated_uv_cache:
                return interpolated_uv_cache[channel]
            triangle_uv = triangle_uv_for(role)
            if triangle_uv is None:
                result = None
            else:
                result = (
                    triangle_uv,
                    weight0 * triangle_uv[0, 0]
                    + weight1 * triangle_uv[1, 0]
                    + weight2 * triangle_uv[2, 0],
                    weight0 * triangle_uv[0, 1]
                    + weight1 * triangle_uv[1, 1]
                    + weight2 * triangle_uv[2, 1],
                )
            interpolated_uv_cache[channel] = result
            return result

        def has_uv_for(role: str | None) -> bool:
            return triangle_uv_for(role) is not None

        default_interpolated = interpolated_uv_for(None)
        uv = None if default_interpolated is None else default_interpolated[0]
        u_value = None if default_interpolated is None else default_interpolated[1]
        v_value = None if default_interpolated is None else default_interpolated[2]
        has_uv = default_interpolated is not None
        if style.hair708_face_color_linear is not None and not has_uv:
            raise ValueError("Hair708 face-color blending requires authored texture coordinates")
        sample_geometry_cache: dict[
            tuple[int, int, int, int, str, str, int, int],
            tuple[
                np.ndarray,
                np.ndarray,
                np.ndarray,
                np.ndarray,
                np.ndarray,
                np.ndarray,
                np.ndarray,
                np.ndarray,
            ],
        ] = {}
        texture_lod_cache: dict[tuple[int, int, int, int], float] = {}
        sample_result_cache: dict[
            tuple[int, int, int, str, str, str, int, int, bool],
            tuple[TextureSource, np.ndarray, np.ndarray, np.ndarray],
        ] = {}
        def sample_uv_map(
            source: TextureSource,
            x_offset: int = 0,
            y_offset: int = 0,
            wrap: tuple[str, str] = ("clamp", "clamp"),
            mip_filter: str = "point",
            u_coordinates: np.ndarray | None = None,
            v_coordinates: np.ndarray | None = None,
            hardware_srgb_rgb: bool = False,
            binding_role: str | None = None,
        ) -> np.ndarray:
            interpolated = interpolated_uv_for(binding_role)
            if interpolated is None:
                raise ValueError("UV texture requested for a triangle without texture coordinates")
            sample_triangle_uv, bound_u_value, bound_v_value = interpolated

            levels = source if isinstance(source, tuple) else (source,)
            base = levels[0]
            sample_u = bound_u_value if u_coordinates is None else u_coordinates
            sample_v = bound_v_value if v_coordinates is None else v_coordinates
            result_key = (
                id(source),
                x_offset,
                y_offset,
                wrap[0],
                wrap[1],
                mip_filter,
                id(sample_u),
                id(sample_v),
                hardware_srgb_rgb,
            )
            cached_result = sample_result_cache.get(result_key)
            if (
                cached_result is not None
                and cached_result[0] is source
                and cached_result[1] is sample_u
                and cached_result[2] is sample_v
            ):
                return cached_result[3]
            if len(levels) == 1:
                lod = 0.0
            else:
                lod_key = (
                    base.shape[0],
                    base.shape[1],
                    len(levels),
                    id(sample_triangle_uv),
                )
                cached_lod = texture_lod_cache.get(lod_key)
                if cached_lod is None:
                    screen_edges = np.asarray(
                        (
                            screen[1, :2] - screen[0, :2],
                            screen[2, :2] - screen[0, :2],
                        ),
                        dtype=np.float64,
                    )
                    uv_edges = np.asarray(
                        (
                            sample_triangle_uv[1] - sample_triangle_uv[0],
                            sample_triangle_uv[2] - sample_triangle_uv[0],
                        ),
                        dtype=np.float64,
                    )
                    gradient = np.linalg.solve(screen_edges, uv_edges)
                    rho_x = np.hypot(
                        gradient[0, 0] * base.shape[1],
                        gradient[0, 1] * base.shape[0],
                    )
                    rho_y = np.hypot(
                        gradient[1, 0] * base.shape[1],
                        gradient[1, 1] * base.shape[0],
                    )
                    cached_lod = float(
                        np.clip(
                            np.log2(max(float(rho_x), float(rho_y), 1.0)),
                            0.0,
                            len(levels) - 1,
                        )
                    )
                    texture_lod_cache[lod_key] = cached_lod
                lod = cached_lod

            def sample_level(level: int) -> np.ndarray:
                level_source = levels[level]
                sample_source = (
                    self._hardware_srgb_texture_level(level_source)
                    if hardware_srgb_rgb
                    else level_source
                )
                if native_raster_kernel.BACKEND_AVAILABLE:
                    return native_raster_kernel.sample_bilinear(
                        sample_source,
                        sample_u,
                        sample_v,
                        x_offset,
                        y_offset,
                        wrap,
                    )
                # All active BFRES samplers specify linear minification and
                # magnification. GPU normalized coordinates put texel centers
                # at (n + 0.5) / size.
                def wrap_indices(indices: np.ndarray, size: int, mode: str) -> np.ndarray:
                    if mode == "repeat":
                        return np.mod(indices, size)
                    if mode == "mirror":
                        period = size * 2
                        mirrored = np.mod(indices, period)
                        return np.where(mirrored < size, mirrored, period - 1 - mirrored)
                    if mode != "clamp":
                        raise ValueError(f"unsupported texture wrap mode: {mode}")
                    return np.clip(indices, 0, size - 1)

                geometry_key = (
                    level_source.shape[0],
                    level_source.shape[1],
                    x_offset,
                    y_offset,
                    wrap[0],
                    wrap[1],
                    id(sample_u),
                    id(sample_v),
                )
                cached_geometry = sample_geometry_cache.get(geometry_key)
                if (
                    cached_geometry is None
                    or cached_geometry[0] is not sample_u
                    or cached_geometry[1] is not sample_v
                ):
                    tex_x = sample_u * level_source.shape[1] - 0.5 + x_offset
                    # The OBJ exporter converts BFRES UV Y into conventional OBJ UV.
                    tex_y = (
                        (1.0 - sample_v) * level_source.shape[0] - 0.5 + y_offset
                    )
                    x0_sample = np.floor(tex_x).astype(np.int64)
                    y0_sample = np.floor(tex_y).astype(np.int64)
                    x_amount = (tex_x - x0_sample)[..., None]
                    y_amount = (tex_y - y0_sample)[..., None]
                    x0_index = wrap_indices(
                        x0_sample, level_source.shape[1], wrap[0]
                    )
                    x1_index = wrap_indices(
                        x0_sample + 1, level_source.shape[1], wrap[0]
                    )
                    y0_index = wrap_indices(
                        y0_sample, level_source.shape[0], wrap[1]
                    )
                    y1_index = wrap_indices(
                        y0_sample + 1, level_source.shape[0], wrap[1]
                    )
                    cached_geometry = (
                        sample_u,
                        sample_v,
                        x0_index,
                        x1_index,
                        y0_index,
                        y1_index,
                        x_amount,
                        y_amount,
                    )
                    sample_geometry_cache[geometry_key] = cached_geometry
                (
                    _,
                    _,
                    x0_index,
                    x1_index,
                    y0_index,
                    y1_index,
                    x_amount,
                    y_amount,
                ) = cached_geometry
                top = sample_source[y0_index, x0_index] * (1.0 - x_amount) + sample_source[
                    y0_index, x1_index
                ] * x_amount
                bottom = sample_source[y1_index, x0_index] * (1.0 - x_amount) + sample_source[
                    y1_index, x1_index
                ] * x_amount
                return top * (1.0 - y_amount) + bottom * y_amount

            if mip_filter == "point":
                result = sample_level(
                    min(len(levels) - 1, int(np.floor(lod + 0.5)))
                )
            else:
                if mip_filter != "linear":
                    raise ValueError(f"unsupported mipmap filter: {mip_filter}")
                lower = int(np.floor(lod))
                upper = min(len(levels) - 1, lower + 1)
                amount = lod - lower
                result = (
                    sample_level(lower) * (1.0 - amount)
                    + sample_level(upper) * amount
                )
            sample_result_cache[result_key] = (source, sample_u, sample_v, result)
            return result

        if body348 is not None:
            if not all(
                has_uv_for(role)
                for role in (
                    "body_albedo",
                    "body_skin_mask",
                    "body_material_information",
                )
            ):
                raise ValueError("GameUber Body324/336/348 requires authored texture coordinates")
            albedo_sample = sample_uv_map(
                body348.albedo_texture,
                wrap=body348.albedo_wrap,
                mip_filter=body348.albedo_mip_filter,
                hardware_srgb_rgb=True,
                binding_role="body_albedo",
            )
            skin_mask_sample = sample_uv_map(
                body348.skin_mask_texture,
                wrap=body348.skin_mask_wrap,
                mip_filter=body348.skin_mask_mip_filter,
                binding_role="body_skin_mask",
            )
            material_information_sample = sample_uv_map(
                body348.material_information_texture,
                wrap=body348.material_information_wrap,
                mip_filter=body348.material_information_mip_filter,
                binding_role="body_material_information",
            )
            if skin_mask_sample.shape[2] < 2:
                raise ValueError("GameUber Body324/336/348 Skm view must expose shader channel G")
            body_surface = gameuber_cpu.body348_local_surface(
                body348.face_color_linear_rgb,
                albedo_sample[..., :3],
                skin_mask_sample[..., 1],
                material_information_sample[..., 0],
                body348.const_single_roughness,
            )
            source_color = body_surface.base_linear_rgb
            body348_roughness = body_surface.roughness
        elif mask0_facepaint is not None:
            user_interpolated = interpolated_uv_for("mask_user0")
            if not has_uv_for("mask_generated") or user_interpolated is None:
                raise ValueError("GameUber Mask0 requires authored texture coordinates")
            generated_sample = sample_uv_map(
                mask0_facepaint.generated_mask_texture,
                wrap=mask0_facepaint.generated_mask_wrap,
                mip_filter=mask0_facepaint.generated_mask_mip_filter,
                hardware_srgb_rgb=True,
                binding_role="mask_generated",
            )
            user_u, user_v = mask0_facepaint.user0_tex_srt.map_obj_uv_for_portable_sampler(
                user_interpolated[1], user_interpolated[2]
            )
            user_sample = sample_uv_map(
                mask0_facepaint.user0_texture,
                wrap=mask0_facepaint.user0_wrap,
                mip_filter=mask0_facepaint.user0_mip_filter,
                u_coordinates=user_u,
                v_coordinates=user_v,
                hardware_srgb_rgb=True,
                binding_role="mask_user0",
            )
            mask_surface = gameuber_cpu.mask0_local_surface(
                user_sample,
                generated_sample,
                mask0_facepaint.replace_albedo_color_linear_rgba,
                mask0_facepaint.source_backed_constructor_const_single0_value,
                mask0_facepaint.emission_color_linear_rgb,
                mask0_facepaint.emission_intensity,
                front_facing=denominator > 0.0,
            )
            source_color = mask_surface.albedo_linear_rgb
            local_emission = mask_surface.ordinary_emission_linear_rgb

            # GameAll0 itself writes alpha one and has no KIL.  This union is
            # solely the explicitly portable unresolved-pass coverage proxy:
            # UGC-only pixels must survive even where generated _a0 is empty.
            # It does not alter or stand in for the shader's literal alpha.
            generated_coverage = gameuber_cpu.portable_mask0_runtime_override_coverage(
                generated_sample[..., 3],
                threshold=mask0_facepaint.portable_coverage_threshold,
            )
            user_coverage = gameuber_cpu.portable_mask0_runtime_override_coverage(
                user_sample[..., 3],
                threshold=mask0_facepaint.portable_coverage_threshold,
            )
            alpha = alpha * np.logical_or(generated_coverage, user_coverage)
        elif texture is not None and has_uv_for("texture"):
            sample = sample_uv_map(
                texture,
                wrap=style.texture_wrap,
                mip_filter=style.texture_mip_filter,
                hardware_srgb_rgb=style.linear_lighting,
                binding_role="texture",
            )
            source_color *= sample[..., :3]
            alpha = alpha * sample[..., 3]
            texture_alpha_sample = sample[..., 3]

        if alpha_texture is not None and has_uv_for("alpha"):
            # Alpha-enabled HairAll resources bind their authored Msk surface
            # as _alp0; its RGB channels are identical and its render info
            # specifies a gequal 0.5 alpha test. Split HairBack/HairFront 564
            # resources do not enter this branch because they bind no _alp0.
            alpha = alpha * sample_uv_map(
                alpha_texture,
                wrap=style.alpha_wrap,
                mip_filter=style.alpha_mip_filter,
                binding_role="alpha",
            )[..., 0]

        # Alpha is final after the generic/Mask0/_alp0 samples above.  Discard
        # failed lanes before normal mapping and anisotropic
        # lighting; those equations cannot make a killed fragment observable.
        alpha_pass = alpha >= style.alpha_cutoff
        if not np.any(alpha_pass):
            return
        if isinstance(alpha_pass, np.ndarray) and not np.all(alpha_pass):
            keep = alpha_pass[0]
            fragment_y = fragment_y[keep]
            fragment_x = fragment_x[keep]
            weight0 = weight0[:, keep]
            weight1 = weight1[:, keep]
            weight2 = weight2[:, keep]
            z_value = z_value[:, keep]
            if isinstance(alpha, np.ndarray):
                alpha = alpha[:, keep]
            source_color = source_color[:, keep]
            if u_value is not None:
                u_value = u_value[:, keep]
            if v_value is not None:
                v_value = v_value[:, keep]
            if texture_alpha_sample is not None:
                texture_alpha_sample = texture_alpha_sample[:, keep]
            if body348_roughness is not None:
                body348_roughness = body348_roughness[:, keep]
            if local_emission is not None:
                local_emission = local_emission[:, keep]
            # Interpolated coordinates and sampled texels above still have the
            # pre-discard lane count.  Rebuild lazily from the compacted
            # barycentric weights before any normal/material sample.
            interpolated_uv_cache.clear()
            sample_geometry_cache.clear()
            sample_result_cache.clear()
            default_interpolated = interpolated_uv_for(None)
            uv = None if default_interpolated is None else default_interpolated[0]
            u_value = None if default_interpolated is None else default_interpolated[1]
            v_value = None if default_interpolated is None else default_interpolated[2]

        if (
            gradient_texture is not None
            and style.gradient_colors is not None
            and has_uv_for("gradient")
        ):
            gradient_sample = sample_uv_map(
                gradient_texture,
                wrap=style.gradient_wrap,
                mip_filter=style.gradient_mip_filter,
                binding_role="gradient",
            )
            amount = gradient_sample[..., style.gradient_channel]
            first = np.asarray(style.gradient_colors[0], dtype=np.float64)
            second = np.asarray(style.gradient_colors[1], dtype=np.float64)
            source_color = first * (1.0 - amount[..., None]) + second * amount[..., None]

        if style.lit:
            if style.gamma_correct_lighting:
                # The recovered GameAll hair shader explicitly performs this
                # per-channel conversion after its sRGB endpoint mix.
                if style.hair708_face_color_linear is not None:
                    source_color = gameuber_cpu.hair708_face_gradient_base_linear(
                        first,
                        second,
                        style.hair708_face_color_linear,
                        amount,
                        gradient_sample[..., style.hair708_face_blend_channel],
                    )
                else:
                    source_color = gameuber_cpu.hair_endpoint_gradient_base_linear(
                        first
                        if gradient_texture is not None and style.gradient_colors is not None
                        else source_color,
                        second
                        if gradient_texture is not None and style.gradient_colors is not None
                        else source_color,
                        amount
                        if gradient_texture is not None and style.gradient_colors is not None
                        else 0.0,
                    )
            # IEC-sRGB uniform colors and texture texels were already decoded
            # independently above. The Body324/336/348 fragment family also returns a local linear value.
            # Keep all subsequent local equations and proxy lighting in that
            # linear working space.
            if local_emission is None:
                local_emission = (
                    source_color
                    * texture_alpha_sample[..., None]
                    * style.texture_emission_intensity
                    if texture_alpha_sample is not None and style.texture_emission_intensity
                    else None
                )
            if (
                texture_alpha_sample is not None
                and style.texture_alpha_under_color_linear is not None
            ):
                under_color = np.asarray(
                    style.texture_alpha_under_color_linear, dtype=np.float64
                )
                user_rgba = np.empty((*texture_alpha_sample.shape, 4), dtype=np.float64)
                user_rgba[..., :3] = under_color
                user_rgba[..., 3] = 1.0
                mask_rgba = np.concatenate(
                    (source_color, texture_alpha_sample[..., None]), axis=2
                )
                mask_surface = gameuber_cpu.mask0_local_surface(
                    user_rgba,
                    mask_rgba,
                    np.zeros(4, dtype=np.float64),
                    0.0,
                    np.ones(3, dtype=np.float64),
                    0.1,
                )
                source_color = mask_surface.albedo_linear_rgb
                local_emission = mask_surface.ordinary_emission_linear_rgb
            vertices = world_positions[np.asarray(triangle.vertex)]
            geometric_normal = _cross3(
                vertices[1] - vertices[0], vertices[2] - vertices[0]
            )
            geometric_length = np.linalg.norm(geometric_normal)
            if geometric_length:
                geometric_normal /= geometric_length

            if all(index is not None for index in triangle.normal):
                vertex_normal = world_normals[np.asarray(triangle.normal, dtype=np.int64)]
                shading_normal = (
                    weight0[..., None] * vertex_normal[0]
                    + weight1[..., None] * vertex_normal[1]
                    + weight2[..., None] * vertex_normal[2]
                )
                lengths = np.linalg.norm(shading_normal, axis=2)
                lengths[lengths == 0.0] = 1.0
                shading_normal /= lengths[..., None]
            else:
                shading_normal = np.empty((*weight0.shape, 3), dtype=np.float64)
                shading_normal[:] = geometric_normal

            # Program 756's Nose06 path performs one height fetch and shifts
            # the subsequent material UV; it does not derive a normal from
            # neighboring height samples.  Reconstruct its tangent-view
            # vector per fragment so Mim is sampled at the same displaced UV.
            material_interpolated = interpolated_uv_for("specular")
            material_uv = (
                None if material_interpolated is None else material_interpolated[0]
            )
            material_u_value = (
                None if material_interpolated is None else material_interpolated[1]
            )
            material_v_value = (
                None if material_interpolated is None else material_interpolated[2]
            )
            parallax_interpolated = interpolated_uv_for("parallax")
            parallax_uv = (
                None if parallax_interpolated is None else parallax_interpolated[0]
            )
            parallax_u_value = (
                None if parallax_interpolated is None else parallax_interpolated[1]
            )
            parallax_v_value = (
                None if parallax_interpolated is None else parallax_interpolated[2]
            )
            if (
                parallax_texture is not None
                and style.parallax_scale
                and parallax_uv is not None
                and parallax_u_value is not None
                and parallax_v_value is not None
            ):
                if (
                    specular_texture is not None
                    and style.texcoord_bindings.get("parallax")
                    != style.texcoord_bindings.get("specular")
                ):
                    raise ValueError(
                        "parallax-displaced specular sampling requires one BFRES texcoord channel"
                    )
                edge1 = vertices[1] - vertices[0]
                edge2 = vertices[2] - vertices[0]
                delta1 = parallax_uv[1] - parallax_uv[0]
                delta2 = parallax_uv[2] - parallax_uv[0]
                determinant = delta1[0] * delta2[1] - delta2[0] * delta1[1]
                if abs(float(determinant)) > 1e-12:
                    tangent = (edge1 * delta2[1] - edge2 * delta1[1]) / determinant
                    raw_bitangent = (-edge1 * delta2[0] + edge2 * delta1[0]) / determinant
                    tangent_length = np.linalg.norm(tangent)
                    if tangent_length > 1e-12:
                        tangent /= tangent_length
                        tangent_field = tangent - shading_normal * np.sum(
                            shading_normal * tangent, axis=2
                        )[..., None]
                        tangent_lengths = np.linalg.norm(tangent_field, axis=2)
                        tangent_lengths[tangent_lengths == 0.0] = 1.0
                        tangent_field /= tangent_lengths[..., None]
                        handedness = np.sign(
                            float(np.dot(_cross3(geometric_normal, tangent), raw_bitangent))
                        )
                        if handedness == 0.0:
                            handedness = 1.0
                        # Every audited GameAll Hair vertex stage loads the
                        # authored tangent.w at a[0xac], multiplies it by the
                        # runtime flip_horizontal_sign uniform, and stores it
                        # back to the same varying.  Our OBJ path reconstructs
                        # tangent.w from geometry/UVs, then applies that exact
                        # title multiplier before any TBN consumer.
                        handedness *= style.flip_horizontal_sign
                        bitangent_field = _cross3(shading_normal, tangent_field) * handedness
                        if self.camera_position is None:
                            view_direction_field = np.empty_like(shading_normal)
                            view_direction_field[:] = (0.0, 0.0, 1.0)
                        else:
                            fragment_position = (
                                weight0[..., None] * vertices[0]
                                + weight1[..., None] * vertices[1]
                                + weight2[..., None] * vertices[2]
                            )
                            view_direction_field = self.camera_position - fragment_position
                            view_lengths = np.linalg.norm(view_direction_field, axis=2)
                            view_lengths[view_lengths == 0.0] = 1.0
                            view_direction_field /= view_lengths[..., None]
                        view_tangent_x = np.sum(
                            view_direction_field * tangent_field, axis=2
                        )
                        view_tangent_y = np.sum(
                            view_direction_field * bitangent_field, axis=2
                        )
                        view_tangent_z = np.sum(
                            view_direction_field * shading_normal, axis=2
                        )
                        safe_z = np.where(
                            np.abs(view_tangent_z) < 1e-5,
                            np.copysign(1e-5, view_tangent_z + 1e-20),
                            view_tangent_z,
                        )
                        height = sample_uv_map(
                            parallax_texture,
                            wrap=style.parallax_wrap,
                            mip_filter=style.parallax_mip_filter,
                            binding_role="parallax",
                        )[..., style.parallax_channel]
                        displaced_uv = gameuber_cpu.nose756_parallax_uv(
                            np.stack((parallax_u_value, parallax_v_value), axis=2),
                            height,
                            np.stack((view_tangent_x, view_tangent_y, safe_z), axis=2),
                            epsilon=1e-12,
                            parallax_height_scale=style.parallax_scale,
                        )
                        material_u_value = displaced_uv[..., 0]
                        material_v_value = displaced_uv[..., 1]

            normal_role = "normal" if normal_texture is not None else "height"
            normal_interpolated = interpolated_uv_for(normal_role)
            normal_uv = (
                None if normal_interpolated is None else normal_interpolated[0]
            )
            if (
                normal_texture is not None
                and height_texture is not None
                and style.texcoord_bindings.get("normal")
                != style.texcoord_bindings.get("height")
            ):
                raise ValueError(
                    "combined normal/height reconstruction requires one BFRES texcoord channel"
                )
            if (
                (normal_texture is not None or height_texture is not None)
                and normal_uv is not None
            ):
                # Rebuild a portable tangent-space normal from the native
                # component swizzle and, where present, the height-map slope.
                normal_x = np.zeros(weight0.shape, dtype=np.float64)
                normal_y = np.zeros(weight0.shape, dtype=np.float64)
                if normal_texture is not None:
                    normal_sample = sample_uv_map(
                        normal_texture,
                        wrap=style.normal_wrap,
                        mip_filter=style.normal_mip_filter,
                        binding_role="normal",
                    )
                    normal_x += (
                        normal_sample[..., style.normal_channels[0]] * 2.0 - 1.0
                    ) * style.normal_strength
                    normal_y += (
                        normal_sample[..., style.normal_channels[1]] * 2.0 - 1.0
                    ) * style.normal_strength
                if height_texture is not None and style.height_strength:
                    height_left = sample_uv_map(
                        height_texture,
                        x_offset=-1,
                        wrap=style.height_wrap,
                        mip_filter=style.height_mip_filter,
                        binding_role="height",
                    )[..., style.height_channel]
                    height_right = sample_uv_map(
                        height_texture,
                        x_offset=1,
                        wrap=style.height_wrap,
                        mip_filter=style.height_mip_filter,
                        binding_role="height",
                    )[..., style.height_channel]
                    height_up = sample_uv_map(
                        height_texture,
                        y_offset=-1,
                        wrap=style.height_wrap,
                        mip_filter=style.height_mip_filter,
                        binding_role="height",
                    )[..., style.height_channel]
                    height_down = sample_uv_map(
                        height_texture,
                        y_offset=1,
                        wrap=style.height_wrap,
                        mip_filter=style.height_mip_filter,
                        binding_role="height",
                    )[..., style.height_channel]
                    normal_x -= (height_right - height_left) * style.height_strength
                    normal_y += (height_down - height_up) * style.height_strength
                normal_xy_length = np.sqrt(normal_x * normal_x + normal_y * normal_y)
                normal_xy_scale = np.minimum(1.0, 0.999999 / np.maximum(normal_xy_length, 1e-12))
                normal_x *= normal_xy_scale
                normal_y *= normal_xy_scale
                normal_z = np.sqrt(
                    np.maximum(0.0, 1.0 - normal_x * normal_x - normal_y * normal_y)
                )
                edge1 = vertices[1] - vertices[0]
                edge2 = vertices[2] - vertices[0]
                delta1 = normal_uv[1] - normal_uv[0]
                delta2 = normal_uv[2] - normal_uv[0]
                determinant = delta1[0] * delta2[1] - delta2[0] * delta1[1]
                if abs(float(determinant)) > 1e-12:
                    tangent = (edge1 * delta2[1] - edge2 * delta1[1]) / determinant
                    raw_bitangent = (-edge1 * delta2[0] + edge2 * delta1[0]) / determinant
                    tangent_length = np.linalg.norm(tangent)
                    if tangent_length > 1e-12:
                        tangent /= tangent_length
                        tangent_field = tangent - shading_normal * np.sum(
                            shading_normal * tangent, axis=2
                        )[..., None]
                        tangent_lengths = np.linalg.norm(tangent_field, axis=2)
                        tangent_lengths[tangent_lengths == 0.0] = 1.0
                        tangent_field /= tangent_lengths[..., None]
                        handedness = np.sign(
                            float(np.dot(_cross3(geometric_normal, tangent), raw_bitangent))
                        )
                        if handedness == 0.0:
                            handedness = 1.0
                        handedness *= style.flip_horizontal_sign
                        bitangent_field = _cross3(shading_normal, tangent_field) * handedness
                        shading_normal = (
                            tangent_field * normal_x[..., None]
                            + bitangent_field * normal_y[..., None]
                            + shading_normal * normal_z[..., None]
                        )
                        normal_lengths = np.linalg.norm(shading_normal, axis=2)
                        normal_lengths[normal_lengths == 0.0] = 1.0
                        shading_normal /= normal_lengths[..., None]

            diffuse = np.maximum(0.0, np.sum(shading_normal * self.light_direction, axis=2))
            # The opted-in Head/Nose/Ear path consumes the title's
            # ScreenSpaceFaceShadowMap/FaceShadowMap buffers. Their exact
            # texels and projection inputs are unavailable, so the portable
            # renderer uses neutral visibility. A world-space depth map is not
            # a valid substitute for this screen-space shader input.
            direct_visibility: float | np.ndarray = 1.0
            if (
                style.gameall_identity is not None
                or style.unresolved_portable_family is not None
            ):
                # Exact GameAll final radiance still depends on title-owned
                # environment, material, GlobalUBO, and prepass inputs.  A
                # hard max(N.L, 0)/pi fallback invented a broad terminator,
                # while the later identity fallback erased every recovered
                # normal-map and cloth-normal response.  Keep this explicitly
                # portable response between those two failure modes: use the
                # exact Snapshot key/fill/direction supplied by the caller,
                # wrap N.L into a continuous hemispheric factor, and normalize
                # against a front-facing normal.  Thus N=(0,0,1) is exactly
                # neutral, curved/tangent normals retain bounded variation,
                # and no reference-image constant or unauthenticated shadow
                # buffer enters the equation. Anonymous diagnostic materials
                # below retain the conventional Lambert path.
                hemisphere = np.clip(
                    0.5
                    + 0.5
                    * np.sum(shading_normal * self.light_direction, axis=2),
                    0.0,
                    1.0,
                )
                front_hemisphere = float(
                    np.clip(0.5 + 0.5 * self.light_direction[2], 0.0, 1.0)
                )
                ambient_radiance = self.ambient_color * self.ambient_intensity
                key_radiance = self.light_color * self.light_intensity
                normal_radiance = (
                    ambient_radiance[None, None, :]
                    + key_radiance[None, None, :] * hemisphere[..., None]
                )
                front_radiance = (
                    ambient_radiance + key_radiance * front_hemisphere
                )
                light = np.ones_like(source_color)
                np.divide(
                    normal_radiance,
                    front_radiance[None, None, :],
                    out=light,
                    where=front_radiance[None, None, :] > 1e-12,
                )
            else:
                light = (
                    self.ambient_color[None, None, :] * self.ambient_intensity
                    + self.light_color[None, None, :]
                    * self.light_intensity
                    * diffuse[..., None]
                    * np.asarray(direct_visibility)[..., None]
                ) / self.light_normalization
            # MIM.r participates in title shadow, edge, and environment terms,
            # but its final coupling requires the unresolved GameUber prepass
            # buffers. Do not replace that missing equation with an arbitrary
            # ambient floor. The same sampled map remains available below for
            # the recovered edge gate and anisotropic material channels.
            source_color *= light

            if style.cheap_sss_proxy:
                # The recovered local curve cannot execute without the
                # title-owned gsys_light_prepass and gsys_user4.g-driven
                # interpolation terms.  A visible Lambert N.L is not that
                # input, so the portable path disables this correction rather
                # than inventing a raw-light substitute.
                cheap_sss_input = screen_space_face_shadow.PORTABLE_CHEAP_SSS_INPUT
                if cheap_sss_input.correction_enabled:
                    scatter = gameuber_cpu.cheap_sss_local_scatter_816_756_372_348(
                        cheap_sss_input.title_light_input_x,
                        0.2,
                        1.6,
                        np.asarray((0.8, 0.03, 0.03), dtype=np.float64),
                    )
                    if (
                        style.cheap_sss_mask_texture is not None
                        and has_uv_for("cheap_sss_mask")
                    ):
                        scatter_mask = sample_uv_map(
                            style.cheap_sss_mask_texture,
                            wrap=style.cheap_sss_mask_wrap,
                            mip_filter=style.cheap_sss_mask_mip_filter,
                            binding_role="cheap_sss_mask",
                        )[..., style.cheap_sss_mask_channel]
                        if style.cheap_sss_mask_invert:
                            scatter_mask = 1.0 - scatter_mask
                        scatter *= np.clip(scatter_mask, 0.0, 1.0)[..., None]
                    source_color += scatter

            if style.front_edge_light_proxy and np.any(self.edge_light_color):
                if self.camera_position is None:
                    edge_view_direction = np.empty_like(shading_normal)
                    edge_view_direction[:] = (0.0, 0.0, 1.0)
                else:
                    edge_fragment_position = (
                        weight0[..., None] * vertices[0]
                        + weight1[..., None] * vertices[1]
                        + weight2[..., None] * vertices[2]
                    )
                    edge_view_direction = self.camera_position - edge_fragment_position
                    edge_view_lengths = np.linalg.norm(edge_view_direction, axis=2)
                    edge_view_lengths[edge_view_lengths == 0.0] = 1.0
                    edge_view_direction /= edge_view_lengths[..., None]
                ndotv = np.sum(shading_normal * edge_view_direction, axis=2)
                # The comparison against NdotV is binary-backed.  Converting
                # the serialized degree field with cosine is the coherent but
                # still uncaptured runtime-buffer boundary.
                threshold = np.cos(
                    np.deg2rad(style.front_edge_light_view_angle_degrees)
                )
                edge_gate = ndotv < threshold
                # The compiled path multiplies the gate by title light/env
                # channels rather than emitting a view-only outline.  Their
                # exact buffers are absent; modulate the capture proxy by the
                # recovered key-facing term so it remains directional.
                edge_directional = (
                    edge_gate
                    * diffuse
                    * np.asarray(direct_visibility, dtype=np.float64)
                )
                edge_mask: float | np.ndarray = 1.0
                if occlusion_texture is not None and has_uv_for("occlusion"):
                    edge_mask = sample_uv_map(
                        occlusion_texture,
                        wrap=style.occlusion_wrap,
                        mip_filter=style.occlusion_mip_filter,
                        binding_role="occlusion",
                    )[..., style.occlusion_channel]
                source_color += (
                    edge_directional[..., None]
                    * np.asarray(edge_mask)[..., None]
                    * self.edge_light_color[None, None, :]
                    * style.front_edge_light_intensity
                )

            if style.specular_strength:
                if self.camera_position is None:
                    view_direction = np.empty_like(shading_normal)
                    view_direction[:] = (0.0, 0.0, 1.0)
                else:
                    fragment_position = (
                        weight0[..., None] * vertices[0]
                        + weight1[..., None] * vertices[1]
                        + weight2[..., None] * vertices[2]
                    )
                    view_direction = self.camera_position - fragment_position
                    view_lengths = np.linalg.norm(view_direction, axis=2)
                    view_lengths[view_lengths == 0.0] = 1.0
                    view_direction /= view_lengths[..., None]
                half_direction = view_direction + self.light_direction
                half_lengths = np.linalg.norm(half_direction, axis=2)
                half_lengths[half_lengths == 0.0] = 1.0
                half_direction /= half_lengths[..., None]
                specular_angle = np.maximum(
                    0.0, np.sum(shading_normal * half_direction, axis=2)
                )
                if body348_roughness is not None:
                    roughness = body348_roughness
                elif roughness_texture is not None and has_uv_for("roughness"):
                    roughness = np.clip(
                        style.roughness_bias
                        + style.roughness_scale
                        * sample_uv_map(
                            roughness_texture,
                            wrap=style.roughness_wrap,
                            mip_filter=style.roughness_mip_filter,
                            binding_role="roughness",
                        )[..., style.roughness_channel],
                        0.0,
                        1.0,
                    )
                else:
                    roughness = float(np.clip(style.roughness, 0.0, 1.0))
                exponent = 2.0 + (1.0 - roughness) * 62.0
                specular = (
                    np.power(specular_angle, exponent)
                    * style.specular_strength
                    * self.specular_intensity
                )
                if specular_texture is not None and has_uv_for("specular"):
                    specular *= sample_uv_map(
                        specular_texture,
                        wrap=style.specular_wrap,
                        mip_filter=style.specular_mip_filter,
                        u_coordinates=material_u_value,
                        v_coordinates=material_v_value,
                        binding_role="specular",
                    )[..., style.specular_channel]
                source_color += specular[..., None]

            if style.anisotropic_proxy:
                if specular_texture is None or material_uv is None:
                    raise ValueError(
                        "Hair612/Beard468 anisotropy requires the active MIM texture and UVs"
                    )
                edge1 = vertices[1] - vertices[0]
                edge2 = vertices[2] - vertices[0]
                delta1 = material_uv[1] - material_uv[0]
                delta2 = material_uv[2] - material_uv[0]
                determinant = delta1[0] * delta2[1] - delta2[0] * delta1[1]
                if abs(float(determinant)) > 1e-12:
                    tangent = (edge1 * delta2[1] - edge2 * delta1[1]) / determinant
                    raw_bitangent = (-edge1 * delta2[0] + edge2 * delta1[0]) / determinant
                    tangent_length = np.linalg.norm(tangent)
                    if tangent_length > 1e-12:
                        tangent /= tangent_length
                        tangent_field = tangent - shading_normal * np.sum(
                            shading_normal * tangent, axis=2
                        )[..., None]
                        tangent_lengths = np.linalg.norm(tangent_field, axis=2)
                        valid_tangent = tangent_lengths > 1e-12
                        tangent_lengths[~valid_tangent] = 1.0
                        tangent_field /= tangent_lengths[..., None]
                        handedness = np.sign(
                            float(
                                np.dot(
                                    _cross3(geometric_normal, tangent), raw_bitangent
                                )
                            )
                        )
                        if handedness == 0.0:
                            handedness = 1.0
                        handedness *= style.flip_horizontal_sign
                        if self.camera_position is None:
                            view_direction = np.empty_like(shading_normal)
                            view_direction[:] = (0.0, 0.0, 1.0)
                        else:
                            fragment_position = (
                                weight0[..., None] * vertices[0]
                                + weight1[..., None] * vertices[1]
                                + weight2[..., None] * vertices[2]
                            )
                            view_direction = self.camera_position - fragment_position
                            view_lengths = np.linalg.norm(view_direction, axis=2)
                            view_lengths[view_lengths == 0.0] = 1.0
                            view_direction /= view_lengths[..., None]
                        mim_sample = sample_uv_map(
                            specular_texture,
                            wrap=style.specular_wrap,
                            mip_filter=style.specular_mip_filter,
                            u_coordinates=material_u_value,
                            v_coordinates=material_v_value,
                            binding_role="specular",
                        )
                        frame = gameuber_cpu.anisotropic_frame_612_468(
                            shading_normal,
                            tangent_field,
                            handedness,
                            mim_sample[..., style.anisotropic_shift_channel],
                            aniso_shift_scale=style.anisotropic_shift_scale,
                            aniso_shift_offset=style.anisotropic_shift_offset,
                            epsilon=1e-12,
                        )
                        anisotropic = (
                            gameuber_cpu.proxy_single_key_light_anisotropic_specular_612_468(
                                frame,
                                view_direction,
                                self.light_direction,
                                self.light_color
                                * self.light_intensity
                                / self.light_normalization,
                                title_view_scale=style.anisotropic_title_view_scale,
                                roughness=style.roughness,
                                aniso_specular_size=style.anisotropic_specular_size,
                                mim_g=mim_sample[..., style.specular_channel],
                                toon_specular_intensity=style.anisotropic_toon_intensity,
                                epsilon=1e-12,
                            )
                            * style.anisotropic_radiance_scale
                        )
                        source_color[valid_tangent] += anisotropic[valid_tangent]

            if local_emission is not None:
                source_color += local_emission

            # The recovered cheap-SSS correction is signed and its exact input
            # is a missing title prepass term.  A portable proxy can therefore
            # undershoot zero even though the downstream SnapshotPfx scene
            # input is a nonnegative radiance domain (mii0's dark Head816 is a
            # concrete adversary).  Preserve every finite recovered/proxy
            # contribution, then apply the physical radiance floor once at the
            # material-output boundary.  Non-finite output still fails closed.
            if not np.all(np.isfinite(source_color)):
                raise FloatingPointError("material shading produced non-finite radiance")
            np.maximum(source_color, 0.0, out=source_color)

            if not self.linear_framebuffer:
                if style.gamma_correct_lighting:
                    source_color = np.power(np.maximum(source_color, 0.0), 1.0 / 2.2)
                elif style.linear_lighting or body348 is not None:
                    source_color = _linear_to_srgb(source_color)

        target_y = fragment_y
        target_x = fragment_x
        color_view = self.color[y0 : y1 + 1, x0 : x1 + 1]
        if style.blend:
            effective_alpha = np.clip(alpha, 0.0, 1.0)
            fragment_alpha = (
                effective_alpha[0]
                if isinstance(effective_alpha, np.ndarray)
                else float(effective_alpha)
            )
            if style.premultiplied_rgb_blend:
                # NVN color blend src=one, dst=one-minus-src-alpha. The source
                # shader output is already premultiplied; do not multiply it a
                # second time. Glass01/mt_LensTrs is the first exact caller.
                color_view[target_y, target_x] = (
                    source_color[0]
                    + color_view[target_y, target_x]
                    * (1.0 - np.asarray(fragment_alpha)[..., None])
                )
            else:
                color_view[target_y, target_x] = (
                    source_color[0] * np.asarray(fragment_alpha)[..., None]
                    + color_view[target_y, target_x]
                    * (1.0 - np.asarray(fragment_alpha)[..., None])
                )
        else:
            # Opaque and mask GameUber modes disable blending. Alpha controls
            # the gequal test, but a passing fragment overwrites the target.
            color_view[target_y, target_x] = source_color[0]
        if self.target_alpha is not None:
            alpha_view = self.target_alpha[y0 : y1 + 1, x0 : x1 + 1]
            if style.blend:
                alpha_view[target_y, target_x] = (
                    fragment_alpha
                    + alpha_view[target_y, target_x]
                    * (1.0 - fragment_alpha)
                )
            else:
                # Opaque/mask render-target writes replace alpha with one once
                # their alpha test passes, matching the corresponding RGB
                # overwrite above.
                alpha_view[target_y, target_x] = 1.0
        if style.depth_write:
            depth_view[target_y, target_x] = z_value[0]

    def image(self, linear_color: np.ndarray | None = None) -> Image.Image:
        color = self.color if linear_color is None else np.asarray(linear_color, dtype=np.float64)
        if color.shape != self.color.shape:
            raise ValueError("linear_color must match the framebuffer shape")
        if self.target_alpha is not None:
            alpha = np.clip(self.target_alpha, 0.0, 1.0)
            # The transparent render target stores premultiplied linear RGB.
            # PNG RGBA is straight-alpha, so remove coverage before applying
            # the output transfer. Fully transparent pixels remain canonical
            # transparent black.
            straight_color = np.zeros_like(color)
            covered = alpha > 1e-12
            straight_color[covered] = color[covered] / alpha[covered, None]
            if self.linear_framebuffer:
                straight_color = _linear_to_srgb(straight_color)
            rgb = np.clip(np.rint(straight_color * 255.0), 0, 255).astype(np.uint8)
            alpha_pixels = np.clip(np.rint(alpha * 255.0), 0, 255).astype(np.uint8)
            return Image.fromarray(
                np.dstack((rgb, alpha_pixels)),
                mode="RGBA",
            )
        if self.linear_framebuffer:
            color = _linear_to_srgb(color)
        pixels = np.clip(np.rint(color * 255.0), 0, 255).astype(np.uint8)
        return Image.fromarray(pixels, mode="RGB")


class PerspectiveRasterizer(OrthographicRasterizer):
    """CPU perspective camera with perspective-correct attribute interpolation."""

    def __init__(
        self,
        width: int,
        height: int,
        camera_position: tuple[float, float, float],
        camera_target: tuple[float, float, float],
        vertical_fov_degrees: float,
        horizontal_projection_scale: float = 1.0,
        camera_up: tuple[float, float, float] = (0.0, 1.0, 0.0),
        background: tuple[float, float, float] = (0.95, 0.97, 1.0),
        linear_framebuffer: bool = False,
        transparent_background: bool = False,
    ) -> None:
        eye = np.asarray(camera_position, dtype=np.float64)
        target = np.asarray(camera_target, dtype=np.float64)
        forward = target - eye
        distance = float(np.linalg.norm(forward))
        if distance <= 0.0:
            raise ValueError("perspective camera position and target coincide")
        forward /= distance
        up_hint = np.asarray(camera_up, dtype=np.float64)
        right = _cross3(forward, up_hint)
        right_length = float(np.linalg.norm(right))
        if right_length <= 0.0:
            raise ValueError("perspective camera up vector is parallel to its view")
        right /= right_length
        up = _cross3(right, forward)
        tangent = float(np.tan(np.deg2rad(vertical_fov_degrees) * 0.5))
        if tangent <= 0.0:
            raise ValueError("perspective camera FOV must be positive")
        aspect = width / height
        focal_half_height = distance * tangent
        focal_bounds = (
            float(target[0] - focal_half_height * aspect),
            float(target[0] + focal_half_height * aspect),
            float(target[1] - focal_half_height),
            float(target[1] + focal_half_height),
        )
        super().__init__(
            width,
            height,
            focal_bounds,
            background,
            linear_framebuffer=linear_framebuffer,
            transparent_background=transparent_background,
        )
        self.camera_position = eye
        self.perspective_correct = True
        self._camera_forward = forward
        self._camera_right = right
        self._camera_up = up
        self._vertical_tangent = tangent
        self._aspect = aspect
        self._horizontal_projection_scale = float(horizontal_projection_scale)
        if self._horizontal_projection_scale <= 0.0:
            raise ValueError("horizontal_projection_scale must be positive")

    def _project(self, positions: np.ndarray) -> np.ndarray:
        relative = positions - self.camera_position
        depth = relative @ self._camera_forward
        projected = np.full_like(positions, np.nan)
        valid = depth > 1e-8
        projected[valid, 0] = (
            (relative[valid] @ self._camera_right)
            / (depth[valid] * self._vertical_tangent * self._aspect)
            * self._horizontal_projection_scale
            + 1.0
        ) * 0.5 * (self.width - 1)
        projected[valid, 1] = (
            1.0
            - (relative[valid] @ self._camera_up)
            / (depth[valid] * self._vertical_tangent)
        ) * 0.5 * (self.height - 1)
        # Reciprocal camera depth is both monotonic for the z-buffer (larger
        # means closer) and the interpolation divisor used above.
        projected[valid, 2] = 1.0 / depth[valid]
        return projected
