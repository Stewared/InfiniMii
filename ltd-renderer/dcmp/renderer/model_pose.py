"""NintendoWare BFRES skeleton evaluation and smooth skinning.

The prepared model catalogs retain the BFRES bone hierarchy, smooth-matrix
palette, inverse bind matrices, and per-vertex skin indices/weights.  This
module evaluates those records directly so static title animations can be
rendered without baking guessed transforms into the exported OBJ files.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import numpy as np

try:
    from .software_renderer import ObjMesh
except ImportError:
    from software_renderer import ObjMesh


@dataclass(frozen=True)
class PosedModel:
    """A posed OBJ plus evaluated bone matrices and reproducibility metrics."""

    mesh: ObjMesh
    bone_world: dict[str, np.ndarray]
    bind_identity_max_error: float
    animation_name: str | None


@dataclass(frozen=True)
class RigidShapeBindTransform:
    """One VertexSkinCount=0 shape's complete BFRES bind-space bone transform."""

    matrix: np.ndarray
    shape_name: str
    bone_index: int
    bone_name: str
    bone_chain: tuple[str, ...]


@dataclass(frozen=True)
class BoneBindTransform:
    """One named BFRES bone's complete bind-world transform."""

    matrix: np.ndarray
    bone_index: int
    bone_name: str
    bone_chain: tuple[str, ...]


@dataclass(frozen=True)
class SkinnedShapeBindContract:
    """Checked BFRES smooth-palette contract for one prepared OBJ shape."""

    shape_name: str
    vertex_skin_count: int
    vertex_offset: int
    vertex_count: int
    shape_bone_index: int
    shape_bone_name: str
    matrix_to_bone_list: tuple[int, ...]
    palette_bone_names: tuple[str, ...]
    used_palette_indices: tuple[int, ...]
    smooth_matrix_count: int
    rigid_palette_indices: tuple[int, ...]
    bind_identity_max_error: float
    minimum_weight_sum: float
    maximum_weight_sum: float


def _rotation_xyz(values: list[float]) -> np.ndarray:
    """BFRES EulerXYZ rotation (column vectors: Rz @ Ry @ Rx)."""

    x, y, z = (float(value) for value in values[:3])
    cx, sx = np.cos(x), np.sin(x)
    cy, sy = np.cos(y), np.sin(y)
    cz, sz = np.cos(z), np.sin(z)
    rx = np.asarray(((1, 0, 0), (0, cx, -sx), (0, sx, cx)), dtype=np.float64)
    ry = np.asarray(((cy, 0, sy), (0, 1, 0), (-sy, 0, cy)), dtype=np.float64)
    rz = np.asarray(((cz, -sz, 0), (sz, cz, 0), (0, 0, 1)), dtype=np.float64)
    return rz @ ry @ rx


def _local_matrix(scale: list[float], rotation: list[float], translation: list[float]) -> np.ndarray:
    matrix = np.identity(4, dtype=np.float64)
    matrix[:3, :3] = _rotation_xyz(rotation) @ np.diag(np.asarray(scale[:3], dtype=np.float64))
    matrix[:3, 3] = np.asarray(translation[:3], dtype=np.float64)
    return matrix


def _inverse_bind(values: list[float]) -> np.ndarray:
    matrix = np.identity(4, dtype=np.float64)
    matrix[:3, :4] = np.asarray(values, dtype=np.float64).reshape(3, 4)
    return matrix


def _animation_transforms(path: Path | None) -> tuple[str | None, dict[str, dict[str, Any]]]:
    if path is None:
        return None, {}
    animation = json.loads(path.read_text(encoding="utf-8"))
    has_curves = any(bone.get("Curves") for bone in animation["Bones"])
    if animation["FrameCount"] != 1 or has_curves:
        raise ValueError(f"{path} is not a static one-frame skeletal pose")
    transforms = {bone["Name"]: bone for bone in animation["Bones"]}
    return str(animation["Name"]), transforms


def _world_matrices(
    bones: list[dict[str, Any]], pose: dict[str, dict[str, Any]]
) -> list[np.ndarray]:
    world: list[np.ndarray] = []
    for index, bone in enumerate(bones):
        animated = pose.get(bone["Name"])
        local = _local_matrix(
            animated["BaseScale"] if animated else bone["Scale"],
            animated["BaseRotation"] if animated else bone["Rotation"],
            animated["BaseTranslation"] if animated else bone["Position"],
        )
        parent = int(bone["ParentIndex"])
        world.append(local if parent < 0 else world[parent] @ local)
    return world


def bone_bind_transforms(
    model: dict[str, Any], bone_names: tuple[str, ...]
) -> dict[str, BoneBindTransform]:
    """Resolve named bones through one in-memory BFRES bind hierarchy pass.

    Attachment consumers already hold the prepared ``bfres.json`` model in a
    shared immutable cache.  Accepting that model directly avoids reopening
    and reparsing the same catalog once per attachment while keeping the
    EulerXYZ hierarchy evaluation in the same checked implementation used by
    rigid shapes and skinning.
    """

    if model.get("SkeletonRotationMode") != "EulerXYZ":
        raise ValueError(
            f"unsupported BFRES rotation mode: {model.get('SkeletonRotationMode')}"
        )
    if not bone_names or len(set(bone_names)) != len(bone_names):
        raise ValueError("BFRES attachment bone names must be unique and nonempty")
    bones = model.get("Bones", [])
    if not isinstance(bones, list):
        raise ValueError("BFRES Bones must be a list")
    for index, bone in enumerate(bones):
        parent = int(bone.get("ParentIndex", -2))
        if parent < -1 or parent >= index:
            raise ValueError(
                f"BFRES bone {bone.get('Name')} has a non-topological parent {parent}"
            )
    indices: dict[str, int] = {}
    requested = set(bone_names)
    for index, bone in enumerate(bones):
        name = str(bone.get("Name"))
        if name in requested:
            if name in indices:
                raise ValueError(f"BFRES contains duplicate bone {name}")
            indices[name] = index
    missing = requested - set(indices)
    if missing:
        raise ValueError(f"BFRES lacks attachment bones: {sorted(missing)}")

    world = _world_matrices(bones, {})
    result: dict[str, BoneBindTransform] = {}
    for name in bone_names:
        bone_index = indices[name]
        chain_indices: list[int] = []
        visited: set[int] = set()
        current = bone_index
        while current >= 0:
            if current >= len(bones) or current in visited:
                raise ValueError(f"{name} has an invalid or cyclic BFRES parent chain")
            visited.add(current)
            chain_indices.append(current)
            current = int(bones[current]["ParentIndex"])
        chain_indices.reverse()
        result[name] = BoneBindTransform(
            matrix=world[bone_index].copy(),
            bone_index=bone_index,
            bone_name=name,
            bone_chain=tuple(str(bones[index]["Name"]) for index in chain_indices),
        )
    return result


def rigid_shape_bind_transform(
    catalog_path: Path,
    shape_name: str,
    model_index: int = 0,
) -> RigidShapeBindTransform:
    """Resolve a rigid shape through its complete BFRES parent bone chain."""

    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    models = catalog.get("Models", [])
    if model_index < 0 or model_index >= len(models):
        raise ValueError(f"BFRES model index is unavailable: {model_index}")
    model = models[model_index]
    if model.get("SkeletonRotationMode") != "EulerXYZ":
        raise ValueError(f"unsupported BFRES rotation mode: {model.get('SkeletonRotationMode')}")
    matches = [shape for shape in model.get("Shapes", []) if shape.get("Name") == shape_name]
    if len(matches) != 1:
        raise ValueError(f"BFRES must contain exactly one {shape_name} shape")
    shape = matches[0]
    if int(shape.get("VertexSkinCount", -1)) != 0:
        raise ValueError(f"{shape_name} is not a rigid VertexSkinCount=0 shape")
    bones = model.get("Bones", [])
    bone_index = int(shape.get("BoneIndex", -1))
    if bone_index < 0 or bone_index >= len(bones):
        raise ValueError(f"{shape_name} has invalid BFRES BoneIndex {bone_index}")
    world = _world_matrices(bones, {})
    chain_indices: list[int] = []
    visited: set[int] = set()
    current = bone_index
    while current >= 0:
        if current >= len(bones) or current in visited:
            raise ValueError(f"{shape_name} has an invalid or cyclic BFRES parent chain")
        visited.add(current)
        chain_indices.append(current)
        current = int(bones[current]["ParentIndex"])
    chain_indices.reverse()
    return RigidShapeBindTransform(
        matrix=world[bone_index].copy(),
        shape_name=shape_name,
        bone_index=bone_index,
        bone_name=str(bones[bone_index]["Name"]),
        bone_chain=tuple(str(bones[index]["Name"]) for index in chain_indices),
    )


def skinned_shape_bind_contract(
    catalog_path: Path,
    shape_name: str,
    model_index: int = 0,
) -> SkinnedShapeBindContract:
    """Validate and describe one smooth-skinned BFRES shape.

    Skin indices in the prepared catalog address ``MatrixToBoneList`` rather
    than the skeleton directly.  Keeping that distinction in one checked
    contract prevents classic skin2/skin3 hair from accidentally entering the
    rigid shape path or treating palette indices as bone indices.
    """

    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    models = catalog.get("Models", [])
    if model_index < 0 or model_index >= len(models):
        raise ValueError(f"BFRES model index is unavailable: {model_index}")
    model = models[model_index]
    if model.get("SkeletonRotationMode") != "EulerXYZ":
        raise ValueError(f"unsupported BFRES rotation mode: {model.get('SkeletonRotationMode')}")
    matches = [shape for shape in model.get("Shapes", []) if shape.get("Name") == shape_name]
    if len(matches) != 1:
        raise ValueError(f"BFRES must contain exactly one {shape_name} shape")
    shape = matches[0]
    skin_count = int(shape.get("VertexSkinCount", -1))
    if skin_count <= 0:
        raise ValueError(f"{shape_name} is not a palette-skinned shape")

    bones = model.get("Bones", [])
    shape_bone_index = int(shape.get("BoneIndex", -1))
    if shape_bone_index < 0 or shape_bone_index >= len(bones):
        raise ValueError(f"{shape_name} has invalid BFRES BoneIndex {shape_bone_index}")
    palette = tuple(int(index) for index in model.get("MatrixToBoneList", []))
    inverse_binds = tuple(
        _inverse_bind(values) for values in model.get("InverseModelMatrices", [])
    )
    smooth_count = len(inverse_binds)
    if not palette or len(palette) < smooth_count:
        raise ValueError("BFRES matrix palette is shorter than its inverse-bind table")
    if any(index < 0 or index >= len(bones) for index in palette):
        raise ValueError(f"{shape_name} matrix palette contains an invalid bone index")
    for palette_index, bone_index in enumerate(palette[:smooth_count]):
        if int(bones[bone_index].get("SmoothMatrixIndex", -1)) != palette_index:
            raise ValueError(
                f"{shape_name} smooth palette slot {palette_index} disagrees with its bone"
            )
    for palette_index, bone_index in enumerate(
        palette[smooth_count:], start=smooth_count
    ):
        if int(bones[bone_index].get("RigidMatrixIndex", -1)) != palette_index:
            raise ValueError(
                f"{shape_name} rigid palette slot {palette_index} disagrees with its bone"
            )

    vertex_count = int(shape.get("VertexCount", -1))
    vertex_offset = int(shape.get("VertexOffset", -1))
    if vertex_count < 0 or vertex_offset < 0:
        raise ValueError(f"{shape_name} has an invalid prepared OBJ vertex range")
    indices = np.asarray(shape.get("SkinIndices", []), dtype=np.int64)
    if indices.ndim != 2 or indices.shape[0] != vertex_count or indices.shape[1] < skin_count:
        raise ValueError(f"skin array dimensions differ for {shape_name}")
    indices = indices[:, :skin_count]
    raw_weights = np.asarray(shape.get("SkinWeights", []), dtype=np.float64)
    if skin_count == 1 and raw_weights.size == 0:
        weights = np.ones((vertex_count, 1), dtype=np.float64)
    else:
        if (
            raw_weights.ndim != 2
            or raw_weights.shape[0] != vertex_count
            or raw_weights.shape[1] < skin_count
        ):
            raise ValueError(f"skin array dimensions differ for {shape_name}")
        weights = raw_weights[:, :skin_count]
    if not np.all(np.isfinite(weights)) or np.any(weights < 0.0):
        raise ValueError(f"invalid skin weights in {shape_name}")
    if np.any(indices < 0) or np.any(indices >= len(palette)):
        raise ValueError(f"invalid skin palette index in {shape_name}")
    if skin_count > 1 and np.any(indices >= smooth_count):
        raise ValueError(f"smooth skinning references a rigid palette slot in {shape_name}")
    weight_sums = np.sum(weights, axis=1)
    if np.any(weight_sums <= 0.0):
        raise ValueError(f"zero total skin weight in {shape_name}")

    bind_world = _world_matrices(bones, {})
    bind_error = max(
        (
            float(np.max(np.abs(bind_world[bone_index] @ inverse - np.identity(4))))
            for bone_index, inverse in zip(palette[:smooth_count], inverse_binds)
        ),
        default=0.0,
    )
    if bind_error > 2.0e-5:
        raise ValueError(f"BFRES inverse-bind validation failed (max error {bind_error:g})")

    return SkinnedShapeBindContract(
        shape_name=shape_name,
        vertex_skin_count=skin_count,
        vertex_offset=vertex_offset,
        vertex_count=vertex_count,
        shape_bone_index=shape_bone_index,
        shape_bone_name=str(bones[shape_bone_index]["Name"]),
        matrix_to_bone_list=palette,
        palette_bone_names=tuple(str(bones[index]["Name"]) for index in palette),
        used_palette_indices=tuple(int(index) for index in np.unique(indices)),
        smooth_matrix_count=smooth_count,
        rigid_palette_indices=tuple(range(smooth_count, len(palette))),
        bind_identity_max_error=bind_error,
        minimum_weight_sum=float(np.min(weight_sums)),
        maximum_weight_sum=float(np.max(weight_sums)),
    )


def pose_model(
    mesh: ObjMesh,
    catalog_path: Path,
    animation_path: Path | None = None,
    model_index: int = 0,
) -> PosedModel:
    """Apply a static BFRES animation to all smooth-skinned OBJ vertices."""

    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    models = catalog.get("Models", [])
    if model_index < 0 or model_index >= len(models):
        raise ValueError(f"BFRES model index is unavailable: {model_index}")
    model = models[model_index]
    if model["SkeletonRotationMode"] != "EulerXYZ":
        raise ValueError(f"unsupported BFRES rotation mode: {model['SkeletonRotationMode']}")
    animation_name, pose = _animation_transforms(animation_path)
    bind_world = _world_matrices(model["Bones"], {})
    posed_world = _world_matrices(model["Bones"], pose)
    palette = [int(index) for index in model["MatrixToBoneList"]]
    inverse_binds = [_inverse_bind(values) for values in model["InverseModelMatrices"]]
    smooth_count = len(inverse_binds)
    if len(palette) < smooth_count:
        raise ValueError("BFRES matrix palette is shorter than its inverse-bind table")

    bones = model["Bones"]
    if any(index < 0 or index >= len(bones) for index in palette):
        raise ValueError("BFRES matrix palette contains an invalid bone index")
    for palette_index, bone_index in enumerate(palette[:smooth_count]):
        if int(bones[bone_index].get("SmoothMatrixIndex", -1)) != palette_index:
            raise ValueError("BFRES smooth palette index disagrees with its bone")
    for palette_index, bone_index in enumerate(
        palette[smooth_count:], start=smooth_count
    ):
        if int(bones[bone_index].get("RigidMatrixIndex", -1)) != palette_index:
            raise ValueError("BFRES rigid palette index disagrees with its bone")

    bind_error = 0.0
    for bone_index, inverse in zip(palette[:smooth_count], inverse_binds):
        bind_error = max(
            bind_error,
            float(np.max(np.abs(bind_world[bone_index] @ inverse - np.identity(4)))),
        )
    if bind_error > 2.0e-5:
        raise ValueError(f"BFRES inverse-bind validation failed (max error {bind_error:g})")

    positions = mesh.positions.copy()
    normals = mesh.normals.copy()
    for shape in model["Shapes"]:
        skin_count = int(shape["VertexSkinCount"])
        if skin_count <= 0:
            continue
        offset = int(shape["VertexOffset"])
        count = int(shape["VertexCount"])
        if offset < 0 or count < 0 or offset + count > len(mesh.positions):
            raise ValueError(f"invalid prepared OBJ vertex range for {shape['Name']}")
        raw_indices = np.asarray(shape["SkinIndices"], dtype=np.int64)
        if raw_indices.ndim != 2 or raw_indices.shape[0] != count or raw_indices.shape[1] < skin_count:
            raise ValueError(f"skin array dimensions differ for {shape['Name']}")
        indices = raw_indices[:, :skin_count]
        raw_weights = np.asarray(shape.get("SkinWeights", []), dtype=np.float64)
        if skin_count == 1 and raw_weights.size == 0:
            weights = np.ones((count, 1), dtype=np.float64)
        else:
            if (
                raw_weights.ndim != 2
                or raw_weights.shape[0] != count
                or raw_weights.shape[1] < skin_count
            ):
                raise ValueError(f"skin array dimensions differ for {shape['Name']}")
            weights = raw_weights[:, :skin_count]
        if not np.all(np.isfinite(weights)) or np.any(weights < 0.0):
            raise ValueError(f"invalid skin weights in {shape['Name']}")
        if np.any(indices < 0) or np.any(indices >= len(palette)):
            raise ValueError(f"invalid skin palette index in {shape['Name']}")
        if skin_count > 1 and np.any(indices >= smooth_count):
            raise ValueError(f"smooth skinning references a rigid palette slot in {shape['Name']}")
        weight_sums = np.sum(weights, axis=1)
        if np.any(weight_sums <= 0.0):
            raise ValueError(f"zero total skin weight in {shape['Name']}")
        weights = weights / weight_sums[:, None]
        source_positions = mesh.positions[offset : offset + count]
        source_normals = mesh.normals[offset : offset + count]
        output_positions = np.zeros_like(source_positions)
        output_normals = np.zeros_like(source_normals)
        homogeneous = np.column_stack((source_positions, np.ones(count, dtype=np.float64)))
        for influence in range(skin_count):
            for palette_index in np.unique(indices[:, influence]):
                selected = indices[:, influence] == palette_index
                if palette_index < smooth_count:
                    deform = (
                        posed_world[palette[palette_index]]
                        @ inverse_binds[palette_index]
                    )
                else:
                    deform = posed_world[palette[palette_index]]
                transformed_positions = (deform @ homogeneous[selected].T).T[:, :3]
                transformed_normals = (deform[:3, :3] @ source_normals[selected].T).T
                influence_weight = weights[selected, influence, None]
                output_positions[selected] += transformed_positions * influence_weight
                output_normals[selected] += transformed_normals * influence_weight
        lengths = np.linalg.norm(output_normals, axis=1)
        lengths[lengths == 0.0] = 1.0
        positions[offset : offset + count] = output_positions
        normals[offset : offset + count] = output_normals / lengths[:, None]

    return PosedModel(
        ObjMesh(
            positions,
            mesh.texcoords,
            normals,
            mesh.triangles,
            mesh.texcoord_channels,
        ),
        {bone["Name"]: posed_world[index] for index, bone in enumerate(model["Bones"])},
        bind_error,
        animation_name,
    )


def mii_body_scale(
    build: int,
    height: int,
    model_provider_index: int = -1,
) -> tuple[float, float, float]:
    """Evaluate ``FUN_7101bd04a8`` with its recovered branch selector.

    ``FUN_7101bcbf1c`` initializes the owning ``MiiModelRenderState`` field at
    ``+0xac`` to ``-1``. ``FUN_7101dd9020`` reasserts ``-1`` in the temporary
    mannequin provider record. Thus the renderer default uses raw CharInfo
    build/height. A non-negative provider index selects the alternate capped
    branch (build <= 85, height <= 103).

    The arithmetic stays in float32 because the decompiled operands and
    destinations are C ``float`` values.
    """

    selected_build = int(build)
    selected_height = int(height)
    if int(model_provider_index) != -1:
        selected_build = min(selected_build, 85)
        selected_height = min(selected_height, 103)

    build_f32 = np.float32(selected_build)
    height_f32 = np.float32(selected_height)
    x = np.float32(
        np.float32(
            np.float32(build_f32 * np.float32(0.006015625)) + np.float32(0.5)
        )
        * np.float32(0.79114896)
    )
    yz = np.float32(
        np.float32(
            np.float32(
                np.float32(
                    np.float32(
                        np.float32(build_f32 * np.float32(0.003671875))
                        + np.float32(0.4)
                    )
                    * height_f32
                )
                * np.float32(0.0078125)
            )
            + np.float32(build_f32 * np.float32(0.0017968749))
            + np.float32(0.4)
        )
        * np.float32(0.7908809)
    )
    return float(x), float(yz), float(yz)


def remove_inherited_scale_from_part_basis(
    basis: np.ndarray,
    inherited_scale: tuple[float, float, float],
) -> np.ndarray:
    """Apply the exact local 3x3 operation in ``FUN_7101bc6e80``.

    The bridge divides matrix elements 0/4/8 by X, 1/5/9 by Y, and 2/6/10
    by Z in the decompiler's flat row-major view. Equivalently, it divides
    each basis column by the corresponding inherited body scale. Translation
    is not part of this operation.
    """

    result = np.asarray(basis, dtype=np.float64).copy()
    if result.shape != (3, 3):
        raise ValueError("Mii part attachment basis must be 3x3")
    scale_values = np.asarray(inherited_scale, dtype=np.float64)
    if scale_values.shape != (3,) or np.any(scale_values == 0.0):
        raise ValueError("Mii part inherited scale must contain three nonzero values")
    result /= scale_values[None, :]
    return result


def attached_part_transform(
    head_world: np.ndarray, body_scale: tuple[float, float, float]
) -> np.ndarray:
    """Attach a rigid Mii part to the body Head anchor.

    ``FUN_7101bd04a8`` scales the Head-joint translation by the body XYZ
    proportions and applies a local-X correction of
    ``-body_x * 0.09074663``.  The body Head basis maps that local X axis onto
    negative render-space Y.  ``FUN_7101bd05f0`` was previously mistaken for
    a geometry-scale setter; its operand is each BFRES Shape.RadiusArray value
    and it updates scaled culling radii.  It therefore does not justify the
    former uniform ``body_x`` shrink of every attached Mii part.

    The dedicated body-to-part bone bridge in ``FUN_7101bc6e80`` divides the
    mapped 3x3 parent basis componentwise by the body scale before a part
    skeleton consumes it.  Unit geometry is therefore the source-backed base
    interpretation.  A separate uniform part-scale path is still possible,
    but ``FUN_7101bd05f0`` is not evidence for one.
    """

    result = np.identity(4, dtype=np.float64)
    # The body rig's Head bone uses NintendoWare's X-forward joint basis,
    # while standalone Mii part models are authored in render-space XYZ.  The
    # engine's model attachment cancels that basis and propagates the joint
    # origin. FUN_7101bd05f0 updates culling radii, not geometry scale.
    result[:3, :3] = remove_inherited_scale_from_part_basis(
        np.diag(np.asarray(body_scale, dtype=np.float64)), body_scale
    )
    result[:3, 3] = np.asarray(body_scale) * head_world[:3, 3]
    result[1, 3] -= float(body_scale[0]) * 0.09074663
    return result
