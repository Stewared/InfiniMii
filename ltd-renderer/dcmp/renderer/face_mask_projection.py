"""Decode and inspect the title's Mii face-position lookup maps.

``GameCommon.sharcb``'s ``FaceMaskPos`` program rasterizes the original Mask
shape in UV space and writes its bone-transformed XYZ coordinates.  The title
ships those results as sixteen 32x32 ``MiiFacelineNN_Pos`` textures.  Despite
the BNTX format tag, each decoded 8-byte texel is four little-endian binary16
values (RGBA16F), with alpha zero outside the mask and one on its surface.

The runtime CPU-samples the selected map to place 34 facial-feature anchors.
It does *not* use the 32x32 lattice as final render geometry: ``mt_Mask`` is
drawn on MiiHead00's original 275-vertex, 864-index (288-triangle) shape and
samples the generated face atlas through ``_u0``.  The lattice helper below is
retained only as a forensic visualization of the position-map payload.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

try:
    from .software_renderer import ObjMesh, ObjTriangle
except ImportError:  # Direct ``python renderer/render_mii.py`` invocation.
    from software_renderer import ObjMesh, ObjTriangle


POSITION_MAP_WIDTH = 32
POSITION_MAP_HEIGHT = 32
POSITION_MAP_CHANNELS = 4
POSITION_MAP_TEXEL_BYTES = 8
POSITION_MAP_BYTE_LENGTH = (
    POSITION_MAP_WIDTH
    * POSITION_MAP_HEIGHT
    * POSITION_MAP_CHANNELS
    * np.dtype("<f2").itemsize
)
POSITION_MAP_ROOT = Path(__file__).resolve().parent / "assets" / "face_mask_positions"
POSITION_MAP_MANIFEST = POSITION_MAP_ROOT / "manifest.json"
MASK_GROUP = "Mask__mt_Mask"
RUNTIME_POSITION_SAMPLER = "0x7101b7b0d0"
RUNTIME_POSITION_SAMPLER_CALLS = ("0x7101b7f15c", "0x7101b7f284")
RUNTIME_ANCHOR_WORKER = "0x7101b7e7d0"
PORTRAIT_FACELINE_TARGET = (128, 256)
PORTRAIT_MASK_TARGET = (256, 256)


@dataclass(frozen=True)
class FaceMaskPositionMap:
    """One decoded ``MiiFacelineNN_Pos`` position lattice."""

    faceline_type: int
    texture_name: str
    path: Path
    sha256: str
    rgba: np.ndarray

    @property
    def valid(self) -> np.ndarray:
        return self.rgba[..., 3] >= 0.5

    @property
    def xyz(self) -> np.ndarray:
        return self.rgba[..., :3]


def position_texture_name(faceline_type: int) -> str:
    """Return the title's exact position-texture name for a faceline selector."""

    if not 0 <= faceline_type <= 15:
        raise ValueError(f"faceline type {faceline_type} is outside the recovered 0..15 set")
    return f"MiiFaceline{faceline_type:02d}_Pos"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_face_mask_position_map(
    faceline_type: int,
    asset_root: Path = POSITION_MAP_ROOT,
) -> FaceMaskPositionMap:
    """Load and verify the selected 32x32 RGBA16F position map."""

    texture_name = position_texture_name(faceline_type)
    path = asset_root / f"{texture_name}.rgba16f"
    payload = path.read_bytes()
    if len(payload) != POSITION_MAP_BYTE_LENGTH:
        raise ValueError(
            f"{path} has {len(payload)} bytes; expected {POSITION_MAP_BYTE_LENGTH} RGBA16F bytes"
        )
    digest = hashlib.sha256(payload).hexdigest()
    manifest_path = asset_root / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest["textures"][texture_name]["sha256"]
        if digest != expected:
            raise ValueError(f"{texture_name} hash {digest} does not match manifest {expected}")

    rgba = np.frombuffer(payload, dtype="<f2").astype(np.float64).reshape(
        POSITION_MAP_HEIGHT, POSITION_MAP_WIDTH, POSITION_MAP_CHANNELS
    )
    alpha = rgba[..., 3]
    if not np.all((alpha == 0.0) | (alpha == 1.0)):
        raise ValueError(f"{texture_name} alpha is not the recovered binary coverage mask")
    if not np.any(alpha == 1.0):
        raise ValueError(f"{texture_name} has no covered position texels")
    if not np.all(np.isfinite(rgba)):
        raise ValueError(f"{texture_name} contains non-finite position data")
    return FaceMaskPositionMap(faceline_type, texture_name, path, digest, rgba)


def sample_face_mask_anchor(
    position_map: FaceMaskPositionMap,
    u: float,
    v: float,
) -> np.ndarray | None:
    """Sample a 3D anchor using the recovered runtime coordinate convention.

    ``FUN_7101b7b0d0`` maps normalized coordinates to texel centers with
    ``x = u * width - 0.5`` and ``y = v * height - 0.5``, clamps the four
    neighboring texels, bilinearly interpolates all RGBA channels, and returns
    ``xyz / alpha`` when coverage is positive.  If the interpolation is fully
    transparent, it searches the immediately surrounding texel rings for the
    nearest covered sample.  This helper mirrors those externally observable
    semantics; runtime ``v`` increases toward image row 31.
    """

    rgba = position_map.rgba
    height, width, _ = rgba.shape
    texel_x = float(u) * width
    texel_y = float(v) * height

    # The binary uses FCVTZS on center-relative values.  For all interior
    # coordinates this is the conventional adjacent-center pair; clamping
    # preserves the title's edge behavior.
    x0 = int(np.trunc(texel_x - 0.5))
    x1 = int(np.trunc(texel_x + 0.5))
    y0 = int(np.trunc(texel_y - 0.5))
    y1 = int(np.trunc(texel_y + 0.5))
    x0 = min(max(x0, 0), width - 1)
    x1 = min(max(x1, 0), width - 1)
    y0 = min(max(y0, 0), height - 1)
    y1 = min(max(y1, 0), height - 1)

    x_amount = texel_x - (x0 + 0.5)
    y_amount = texel_y - (y0 + 0.5)
    top = rgba[y0, x0] * (1.0 - x_amount) + rgba[y0, x1] * x_amount
    bottom = rgba[y1, x0] * (1.0 - x_amount) + rgba[y1, x1] * x_amount
    sampled = top * (1.0 - y_amount) + bottom * y_amount
    if sampled[3] > 0.0:
        return sampled[:3] / sampled[3]

    # The title expands the initial sample rectangle by at most three texel
    # rings, testing only newly exposed texels and retaining the nearest one.
    original_x_min, original_x_max = sorted((x0, x1))
    original_y_min, original_y_max = sorted((y0, y1))
    inner_x_min, inner_x_max = original_x_min, original_x_max
    inner_y_min, inner_y_max = original_y_min, original_y_max
    for radius in range(1, 4):
        outer_x_min = max(original_x_min - radius, 0)
        outer_x_max = min(original_x_max + radius, width - 1)
        outer_y_min = max(original_y_min - radius, 0)
        outer_y_max = min(original_y_max + radius, height - 1)
        nearest: tuple[float, np.ndarray] | None = None
        for row in range(outer_y_min, outer_y_max + 1):
            for column in range(outer_x_min, outer_x_max + 1):
                if inner_x_min <= column <= inner_x_max and inner_y_min <= row <= inner_y_max:
                    continue
                texel = rgba[row, column]
                if texel[3] <= 0.0:
                    continue
                distance = (texel_x - (column + 0.5)) ** 2 + (
                    texel_y - (row + 0.5)
                ) ** 2
                if nearest is None or distance < nearest[0]:
                    nearest = (distance, texel)
        if nearest is not None:
            texel = nearest[1]
            return texel[:3] / texel[3]
        inner_x_min, inner_x_max = outer_x_min, outer_x_max
        inner_y_min, inner_y_max = outer_y_min, outer_y_max
    return None


def build_face_mask_lattice_mesh(position_map: FaceMaskPositionMap) -> ObjMesh:
    """Triangulate valid texel centers for forensic visualization only.

    UVs are the exact normalized texel centers used by GPU linear sampling.
    Image row zero maps to conventional OBJ V near one, matching the decoded
    ``FaceMaskPos`` vertex shader's ``clip_y = 1 - 2 * v`` expression.

    This mesh is not submitted by the title and must not replace the original
    ``Mask__mt_Mask`` BFRES shape.
    """

    valid = position_map.valid
    vertex_index = np.full(valid.shape, -1, dtype=np.int64)
    rows, columns = np.nonzero(valid)
    vertex_index[rows, columns] = np.arange(len(rows), dtype=np.int64)
    positions = position_map.xyz[rows, columns].copy()
    texcoords = np.column_stack(
        (
            (columns.astype(np.float64) + 0.5) / POSITION_MAP_WIDTH,
            1.0 - (rows.astype(np.float64) + 0.5) / POSITION_MAP_HEIGHT,
        )
    )

    raw_triangles: list[tuple[int, int, int]] = []
    for row in range(POSITION_MAP_HEIGHT - 1):
        for column in range(POSITION_MAP_WIDTH - 1):
            corners = (
                int(vertex_index[row, column]),
                int(vertex_index[row, column + 1]),
                int(vertex_index[row + 1, column]),
                int(vertex_index[row + 1, column + 1]),
            )
            present = [index for index in corners if index >= 0]
            if len(present) == 4:
                raw_triangles.extend(((corners[0], corners[2], corners[1]), (corners[1], corners[2], corners[3])))
            elif len(present) == 3:
                raw_triangles.append(tuple(present))

    # Smooth normals are reconstructed from the half-float surface.  Flip any
    # boundary triangle whose winding points away from the title's +Z camera.
    normals = np.zeros_like(positions)
    oriented: list[tuple[int, int, int]] = []
    for indices in raw_triangles:
        first, second, third = indices
        normal = np.cross(positions[second] - positions[first], positions[third] - positions[first])
        if normal[2] < 0.0:
            second, third = third, second
            normal = -normal
        if np.linalg.norm(normal) <= 1e-12:
            continue
        oriented.append((first, second, third))
        normals[first] += normal
        normals[second] += normal
        normals[third] += normal
    lengths = np.linalg.norm(normals, axis=1)
    lengths[lengths == 0.0] = 1.0
    normals /= lengths[:, None]

    triangles = [
        ObjTriangle(
            group=MASK_GROUP,
            vertex=indices,
            texcoord=indices,
            normal=indices,
        )
        for indices in oriented
    ]
    return ObjMesh(positions=positions, texcoords=texcoords, normals=normals, triangles=triangles)


def face_mask_projection_report(
    position_map: FaceMaskPositionMap,
    mesh: ObjMesh,
) -> dict[str, object]:
    """Return the evidence and selected-resource fields used by render reports."""

    covered = position_map.xyz[position_map.valid]
    return {
        "method": "FaceMaskPos RGBA16F CPU attachment-anchor lookup",
        "faceline_type": position_map.faceline_type,
        "texture": position_map.texture_name,
        "path": position_map.path.as_posix(),
        "sha256": position_map.sha256,
        "decoded_format": "little-endian RGBA16F",
        "dimensions": [POSITION_MAP_WIDTH, POSITION_MAP_HEIGHT],
        "valid_texels": int(np.count_nonzero(position_map.valid)),
        "position_bounds": {
            "min": covered.min(axis=0).tolist(),
            "max": covered.max(axis=0).tolist(),
        },
        "runtime_role": "CPU bilinear/nearest-valid position lookup for 34 3D attachment anchors",
        "runtime_consumer": RUNTIME_POSITION_SAMPLER,
        "runtime_consumer_calls": list(RUNTIME_POSITION_SAMPLER_CALLS),
        "runtime_worker": RUNTIME_ANCHOR_WORKER,
        "runtime_uv_mapping": "x=u*width-0.5; y=v*height-0.5; v increases with image row",
        "forensic_lattice": {
            "rendered_by_title": False,
            "vertices": int(len(mesh.positions)),
            "triangles": int(len(mesh.triangles)),
            "uv_mapping": "u=(column+0.5)/32; v_obj=1-(row+0.5)/32",
        },
        "final_mask_draw": {
            "resource": "MiiHead00",
            "shape": MASK_GROUP,
            "material": "mt_Mask",
            "vertices": 275,
            "indices": 864,
            "triangles": 288,
            "texcoord": "_u0",
            "position_map_used_as_geometry": False,
            "model_transform": "identity Mask bone; no hand-fit scale or Z translation",
        },
        "shader": {
            "archive": "GameCommon.sharcb",
            "program": "FaceMaskPos",
            "vertex_expression": "clip.xy=(2*aTexCoord.x-1, 1-2*aTexCoord.y); out.xyz=cBoneMtx*aPosition",
            "fragment_expression": "target0=vec4(interpolatedPosition.xyz, 1)",
        },
        "runtime_targets": {
            "gfx_mii_icon": {
                "faceline": list(PORTRAIT_FACELINE_TARGET),
                "mask": list(PORTRAIT_MASK_TARGET),
                "source": "built-in manager descriptors +0x100/+0x428",
            },
            "pooled_tiers": [
                {"faceline": [192, 384], "mask": [512, 512], "count": 4},
                {"faceline": [128, 256], "mask": [384, 384], "count": 8},
                {"faceline": [96, 192], "mask": [256, 256], "count": 16},
                {"faceline": [48, 96], "mask": [128, 128], "count": 72},
            ],
            "fallback_pool": {
                "faceline": [128, 256],
                "mask": [384, 384],
                "count": 14,
            },
            "request_derived": {"function": "0x7101d7e7e0", "used_by_gfx_mii_icon": False},
        },
    }
