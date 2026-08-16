"""Fail-closed GPU preparation for source-backed MiiMask face-atlas draws.

Every prepared layer uses the translated linked MiiMask stages, native-produced
Maxwell cbuf bytes, a checked native mip PNG decoded by the backend, and the
literal half-float quad streams.  Rendering writes through the source-proven
RGBA8_UNORM target alias and exposes the stored bytes for an RGBA8_SRGB sample view.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import json
import sys
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Mapping

from .title_shader_runner import (
    BoundTitleShaderResources,
    ExactConstantBufferBinding,
    ExactTextureBinding,
    LinkedTitleShaderProgram,
    MissingExactShaderBindingError,
    StageConstantBufferKey,
    StageSamplerKey,
    TitleShaderArtifactMismatchError,
    TitleShaderBackend,
    TitleShaderRuntimeBindings,
    TitleVertexAttributeBinding,
    _checked_file_bytes,
)


MII_MASK_PROGRAM_KEY = "mii_mask_face_compositor"
MII_MASK_VERTEX_CBUF_KEY = StageConstantBufferKey("vertex", 3)
MII_MASK_FRAGMENT_CBUF_KEY = StageConstantBufferKey("fragment", 3)
MII_MASK_TEXTURE_KEY = StageSamplerKey("fragment", 0)
MII_MASK_EXPECTED_CASES: tuple[int, ...] = (0, 1, 2, 4, 5, 16, 17, 21)
MII_MASK_EXPECTED_SOURCE_NAMES: tuple[str, ...] = (
    "geometry_source_ledger",
    "runtime_payload_ledger",
    "texture_mip_source_ledger",
)
MII_MASK_EXPECTED_SELECTION: Mapping[str, str] = {
    "archive": "MiiMask.bnsh",
    "vertex_container_file_offset": "0x0",
    "fragment_container_file_offset": "0x2200",
}
REFERENCE_IMAGE_BASENAME = "reference" + ".png"
CAPTURE_DERIVATION_MARKER = "capture" + "_derived"
GL_FRAMEBUFFER_SRGB = 0x8DB9
GL_BLEND = 0x0BE2
GL_DEPTH_TEST = 0x0B71
GL_CULL_FACE = 0x0B44
GL_SCISSOR_TEST = 0x0C11
GL_STENCIL_TEST = 0x0B90
GL_COLOR_WRITEMASK = 0x0C23
GL_DEPTH_WRITEMASK = 0x0B72
GL_RGBA8 = 0x8058
GL_SRGB8_ALPHA8 = 0x8C43
GL_BLEND_DST_RGB = 0x80C8
GL_BLEND_SRC_RGB = 0x80C9
GL_BLEND_DST_ALPHA = 0x80CA
GL_BLEND_SRC_ALPHA = 0x80CB
GL_BLEND_EQUATION_RGB = 0x8009
GL_BLEND_EQUATION_ALPHA = 0x883D
GL_UPPER_LEFT = 0x8CA2
GL_NEGATIVE_ONE_TO_ONE = 0x935E
GL_CLIP_ORIGIN = 0x935C
GL_CLIP_DEPTH_MODE = 0x935D


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_executable_mii_mask_texture_source(
    proof_key: str,
    texture_record: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Reject validation/capture imagery before it can become an executable sampler."""

    source_artifact = texture_record.get("source_artifact")
    if not isinstance(source_artifact, Mapping):
        raise MissingExactShaderBindingError(f"{proof_key} texture source is missing")
    source_path = str(source_artifact.get("path", "")).strip()
    normalized_path = source_path.replace("\\", "/")
    path_markers = {
        part.casefold().replace("-", "_").replace(" ", "_")
        for part in normalized_path.split("/")
        if part
    }
    if (
        not source_path
        or normalized_path.rsplit("/", 1)[-1].casefold() == REFERENCE_IMAGE_BASENAME
        or {"validation_only", CAPTURE_DERIVATION_MARKER} & path_markers
    ):
        raise MissingExactShaderBindingError(
            f"{proof_key} executable texture cannot use external validation imagery"
        )

    for metadata in (texture_record, source_artifact):
        if (
            metadata.get("validation_only") is True
            or metadata.get(CAPTURE_DERIVATION_MARKER) is True
        ):
            raise MissingExactShaderBindingError(
                f"{proof_key} executable texture cannot use external validation imagery"
            )
        for field in (
            "role",
            "classification",
            "source_role",
            "source_classification",
            "derivation",
        ):
            marker = str(metadata.get(field, "")).casefold().replace("-", "_").replace(" ", "_")
            if "validation_only" in marker or CAPTURE_DERIVATION_MARKER in marker:
                raise MissingExactShaderBindingError(
                    f"{proof_key} executable texture cannot use external validation imagery"
                )
    return source_artifact


def _validate_mii_mask_geometry_source(
    proof_key: str,
    dispatcher_case: int,
    geometry: Mapping[str, Any],
    geometry_source_ledger_artifact: Mapping[str, Any],
) -> None:
    """Bind embedded draw streams to the exact authenticated runtime-ledger record."""

    source_artifact = geometry.get("source_artifact")
    if not isinstance(source_artifact, Mapping):
        raise MissingExactShaderBindingError(f"{proof_key} geometry source is missing")
    _checked_file_bytes(source_artifact)
    if not isinstance(geometry_source_ledger_artifact, Mapping):
        raise MissingExactShaderBindingError(
            f"{proof_key} geometry has no checked runtime-ledger source"
        )
    if dispatcher_case != 21 and source_artifact != geometry_source_ledger_artifact:
        raise MissingExactShaderBindingError(
            f"{proof_key} geometry is not keyed to the checked runtime-ledger artifact"
        )
    # Case 21's primary artifact is the authenticated ELF containing its native
    # float literals.  All converted half streams are keyed by the separate
    # checked runtime JSON record, avoiding invented ELF file offsets.
    source_bytes = _checked_file_bytes(geometry_source_ledger_artifact)
    try:
        source_payload = json.loads(source_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TitleShaderArtifactMismatchError(
            f"{proof_key} geometry source is not the checked runtime JSON ledger"
        ) from exc
    if not isinstance(source_payload, Mapping):
        raise MissingExactShaderBindingError(f"{proof_key} geometry source ledger is malformed")
    prepass = source_payload.get("mii_mask_prepass")
    quad_mesh = prepass.get("quad_mesh") if isinstance(prepass, Mapping) else None
    if not isinstance(quad_mesh, Mapping):
        raise MissingExactShaderBindingError(
            f"{proof_key} geometry source ledger has no MiiMask quad mesh"
        )

    if dispatcher_case == 21:
        source_geometry = quad_mesh.get("case21_fullscreen_quad")
    else:
        variants = quad_mesh.get("variants")
        if not isinstance(variants, list):
            raise MissingExactShaderBindingError(
                f"{proof_key} geometry source ledger has no quad variants"
            )
        try:
            variant = int(geometry["variant"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MissingExactShaderBindingError(
                f"{proof_key} geometry has no exact source variant key"
            ) from exc
        matches = [
            record
            for record in variants
            if isinstance(record, Mapping) and int(record.get("variant", -1)) == variant
        ]
        if len(matches) != 1:
            raise MissingExactShaderBindingError(
                f"{proof_key} geometry source variant {variant} is missing or duplicated"
            )
        source_geometry = matches[0]
    if not isinstance(source_geometry, Mapping):
        raise MissingExactShaderBindingError(
            f"{proof_key} geometry source record is missing"
        )

    for stream_name in ("position_stream", "texcoord_stream"):
        embedded_stream = geometry.get(stream_name)
        source_stream = source_geometry.get(stream_name)
        if not isinstance(embedded_stream, Mapping) or not isinstance(source_stream, Mapping):
            raise MissingExactShaderBindingError(
                f"{proof_key} {stream_name} source record is malformed"
            )
        for field in ("format", "byte_length", "raw_hex", "sha256", "conversion_path"):
            if embedded_stream.get(field) != source_stream.get(field):
                raise TitleShaderArtifactMismatchError(
                    f"{proof_key} {stream_name} differs from its checked runtime source record"
                )

    source_indices_hex = str(quad_mesh.get("indices_raw_hex", ""))
    if not source_indices_hex or geometry.get("indices_raw_hex") != source_indices_hex:
        raise TitleShaderArtifactMismatchError(
            f"{proof_key} index stream differs from its checked runtime source record"
        )
    try:
        source_indices = bytes.fromhex(source_indices_hex)
    except ValueError as exc:
        raise TitleShaderArtifactMismatchError(
            f"{proof_key} checked runtime index stream is malformed"
        ) from exc
    if geometry.get("indices_sha256") != _sha256(source_indices):
        raise TitleShaderArtifactMismatchError(
            f"{proof_key} index hash differs from its checked runtime source record"
        )


def validate_mii_mask_program_specification(specification: Mapping[str, Any]) -> None:
    """Authenticate the non-GPU structure and source payloads of the live draw set.

    Both the high-level strict renderer and :class:`MiiMaskGpuRenderer` call this
    validator.  It prevents a status report from declaring a malformed or
    partially authenticated draw ledger executable before a GL context exists.
    The actual host translation remains explicitly non-bit-exact and is tested
    separately by the GPU verifier.
    """

    if specification.get("key") != MII_MASK_PROGRAM_KEY:
        raise MissingExactShaderBindingError("unexpected MiiMask program identity")
    if specification.get("selection") != MII_MASK_EXPECTED_SELECTION:
        raise MissingExactShaderBindingError(
            "MiiMask shader selection changed; expected MiiMask.bnsh offsets 0x0/0x2200"
        )
    unresolved = specification.get("unresolved_runtime_inputs")
    if not isinstance(unresolved, list):
        raise MissingExactShaderBindingError("MiiMask unresolved-input record is malformed")
    fidelity = specification.get("execution_fidelity")
    if (
        not isinstance(fidelity, Mapping)
        or fidelity.get("selected_stage_binaries_exact") is not True
        or fidelity.get("stage_pairing_exact") is not True
        or fidelity.get("host_abi_rewrite_only") is not True
        or not isinstance(fidelity.get("translated_execution_bit_exact"), bool)
    ):
        raise MissingExactShaderBindingError("MiiMask execution-fidelity record is malformed")

    target = specification.get("render_target_state")
    if not isinstance(target, Mapping):
        raise MissingExactShaderBindingError("MiiMask render-target state is missing")
    required_target_values = {
        "dimensions": [256, 256],
        "viewport": [0, 0, 256, 256],
        "scissor": [0, 0, 256, 256],
        "primitive_topology": "triangles",
        "framebuffer_color_conversion_state": "disabled_source_proven_by_unorm_write_view",
    }
    for field, expected in required_target_values.items():
        if target.get(field) != expected:
            raise MissingExactShaderBindingError(
                f"MiiMask render-target field {field!r} differs from its checked value"
            )
    alias = target.get("texture_view_alias")
    if not isinstance(alias, Mapping):
        raise MissingExactShaderBindingError("MiiMask texture-view alias proof is missing")
    if alias.get("base_texture_format", {}).get("title_code") != "0x0b06" or alias.get(
        "color_target_view_format", {}
    ).get("title_code") != "0x0b01":
        raise MissingExactShaderBindingError("MiiMask sRGB-sample/UNORM-write alias changed")

    checked_sources = specification.get("checked_draw_sources")
    if not isinstance(checked_sources, Mapping) or set(checked_sources) != {
        *MII_MASK_EXPECTED_SOURCE_NAMES,
        "draw_order",
    }:
        raise MissingExactShaderBindingError("MiiMask checked source inventory changed")
    if checked_sources["draw_order"] != [
        "pass_0 cases 0,1,2,4,5,16,17",
        "case_21 unconditional fullscreen draw",
        "pass_1 cases 0,1,2,4,5,16,17",
    ]:
        raise MissingExactShaderBindingError("MiiMask checked draw order changed")
    for name in MII_MASK_EXPECTED_SOURCE_NAMES:
        record = checked_sources[name]
        if not isinstance(record, Mapping):
            raise MissingExactShaderBindingError(f"MiiMask checked source {name!r} is malformed")
        _checked_file_bytes(record)

    proofs = specification.get("checked_draw_inputs")
    if not isinstance(proofs, list) or len(proofs) != len(MII_MASK_EXPECTED_CASES):
        raise MissingExactShaderBindingError("MiiMask checked draw count changed")
    try:
        ordered = sorted(proofs, key=lambda proof: int(proof["draw_index"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise MissingExactShaderBindingError("MiiMask draw indices are malformed") from exc
    if tuple(int(proof["draw_index"]) for proof in ordered) != tuple(range(8)) or tuple(
        int(proof["dispatcher_case"]) for proof in ordered
    ) != MII_MASK_EXPECTED_CASES:
        raise MissingExactShaderBindingError("MiiMask draw indices or dispatcher cases changed")

    for proof in ordered:
        proof_key = str(proof.get("key", ""))
        dispatcher_case = int(proof["dispatcher_case"])
        expected_passes = ["case_21"] if dispatcher_case == 21 else ["pass_0", "pass_1"]
        if not proof_key or proof.get("draw_passes") != expected_passes:
            raise MissingExactShaderBindingError(
                f"MiiMask dispatcher case {dispatcher_case} has malformed pass metadata"
            )

        constant_buffers = proof.get("constant_buffers")
        if not isinstance(constant_buffers, list) or {
            StageConstantBufferKey.from_record(record) for record in constant_buffers
        } != {MII_MASK_VERTEX_CBUF_KEY, MII_MASK_FRAGMENT_CBUF_KEY}:
            raise MissingExactShaderBindingError(f"{proof_key} cbuf proof inventory changed")
        for record in constant_buffers:
            payload = bytes.fromhex(str(record.get("payload_hex", "")))
            if len(payload) != int(record.get("byte_length", -1)) or _sha256(payload) != str(
                record.get("payload_sha256")
            ):
                raise TitleShaderArtifactMismatchError(f"{proof_key} cbuf payload hash changed")
            source_artifact = record.get("source_artifact")
            if not isinstance(source_artifact, Mapping):
                raise MissingExactShaderBindingError(f"{proof_key} cbuf source is missing")
            source = _checked_file_bytes(source_artifact)
            if "source_byte_offset" not in record:
                raise MissingExactShaderBindingError(
                    f"{proof_key} cbuf proof requires explicit source_byte_offset"
                )
            source_offset = int(record["source_byte_offset"])
            if source_offset < 0 or source[source_offset : source_offset + len(payload)] != payload:
                raise TitleShaderArtifactMismatchError(f"{proof_key} cbuf source range changed")
            coverage = record.get("payload_coverage")
            if coverage == "selected_branch_required_bytes":
                mask = bytes.fromhex(str(record.get("known_byte_mask_hex", "")))
                if len(mask) != len(payload) or _sha256(mask) != record.get(
                    "known_byte_mask_sha256"
                ):
                    raise TitleShaderArtifactMismatchError(f"{proof_key} cbuf mask changed")
                mask_artifact = record.get("known_mask_source_artifact")
                if not isinstance(mask_artifact, Mapping):
                    raise MissingExactShaderBindingError(f"{proof_key} cbuf mask source is missing")
                packed_mask = _checked_file_bytes(mask_artifact)
                if packed_mask[source_offset : source_offset + len(mask)] != mask:
                    raise TitleShaderArtifactMismatchError(f"{proof_key} cbuf mask source changed")
                if record.get("active_branch_required_ranges_fully_known") is not True or record.get(
                    "unknown_bytes_are_unread_host_materialization"
                ) is not True:
                    raise MissingExactShaderBindingError(f"{proof_key} cbuf coverage is incomplete")
            elif coverage != "full_source_bytes":
                raise MissingExactShaderBindingError(f"{proof_key} cbuf coverage is unclassified")

        textures = proof.get("textures")
        if not isinstance(textures, list) or len(textures) != 1 or StageSamplerKey.from_record(
            textures[0]
        ) != MII_MASK_TEXTURE_KEY:
            raise MissingExactShaderBindingError(f"{proof_key} texture proof inventory changed")
        texture_record = textures[0]
        texture_source_artifact = _validate_executable_mii_mask_texture_source(
            proof_key, texture_record
        )
        checked_png = _checked_file_bytes(texture_source_artifact)
        from PIL import Image

        with Image.open(BytesIO(checked_png)) as image:
            decoded = image.convert("RGBA")
            decoded_size = decoded.size
            decoded_bytes = decoded.tobytes()
        if decoded_size != tuple(int(value) for value in texture_record["decoded_size"]) or _sha256(
            decoded_bytes
        ) != str(texture_record["decoded_rgba_sha256"]):
            raise TitleShaderArtifactMismatchError(f"{proof_key} decoded texture proof changed")
        if not str(texture_record.get("provenance", "")).strip():
            raise MissingExactShaderBindingError(f"{proof_key} texture provenance is missing")

        geometry = proof.get("geometry")
        if not isinstance(geometry, Mapping):
            raise MissingExactShaderBindingError(f"{proof_key} geometry proof is missing")
        _validate_mii_mask_geometry_source(
            proof_key,
            dispatcher_case,
            geometry,
            checked_sources["geometry_source_ledger"],
        )
        for stream_name, expected_length in (("position_stream", 32), ("texcoord_stream", 16)):
            stream = geometry.get(stream_name)
            if not isinstance(stream, Mapping):
                raise MissingExactShaderBindingError(f"{proof_key} {stream_name} is missing")
            payload = bytes.fromhex(str(stream.get("raw_hex", "")))
            if (
                len(payload) != expected_length
                or len(payload) != int(stream.get("byte_length", -1))
                or _sha256(payload) != str(stream.get("sha256"))
            ):
                raise TitleShaderArtifactMismatchError(f"{proof_key} {stream_name} changed")
        indices = bytes.fromhex(str(geometry.get("indices_raw_hex", "")))
        if len(indices) != 12 or _sha256(indices) != str(geometry.get("indices_sha256")):
            raise TitleShaderArtifactMismatchError(f"{proof_key} index stream changed")


def _load_system_gl() -> Any:
    """Load only core GL 1.1 calls needed to set/query title write masks."""

    if sys.platform == "win32":
        library = ctypes.WinDLL("opengl32")
    elif sys.platform == "darwin":
        library = ctypes.CDLL("/System/Library/Frameworks/OpenGL.framework/OpenGL")
    else:
        library_name = ctypes.util.find_library("GL")
        if not library_name:
            raise MissingExactShaderBindingError("system OpenGL library is unavailable")
        library = ctypes.CDLL(library_name)
    library.glColorMask.argtypes = [ctypes.c_ubyte] * 4
    library.glColorMask.restype = None
    library.glDepthMask.argtypes = [ctypes.c_ubyte]
    library.glDepthMask.restype = None
    library.glGetBooleanv.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_ubyte)]
    library.glGetBooleanv.restype = None
    library.glGetIntegerv.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_int)]
    library.glGetIntegerv.restype = None
    library.glIsEnabled.argtypes = [ctypes.c_uint]
    library.glIsEnabled.restype = ctypes.c_ubyte
    return library


def _set_and_verify_exact_write_state(context: Any) -> None:
    """Apply all source-proven non-blend state and verify it on the live context."""

    import moderngl

    gl = _load_system_gl()
    if sys.platform == "win32":
        gl.wglGetProcAddress.argtypes = [ctypes.c_char_p]
        gl.wglGetProcAddress.restype = ctypes.c_void_p
        address = gl.wglGetProcAddress(b"glClipControl")
        prototype = ctypes.WINFUNCTYPE(None, ctypes.c_uint, ctypes.c_uint)
    elif hasattr(gl, "glXGetProcAddressARB"):
        gl.glXGetProcAddressARB.argtypes = [ctypes.c_char_p]
        gl.glXGetProcAddressARB.restype = ctypes.c_void_p
        address = gl.glXGetProcAddressARB(b"glClipControl")
        prototype = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_uint)
    else:
        address = ctypes.cast(getattr(gl, "glClipControl", None), ctypes.c_void_p).value
        prototype = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_uint)
    if not address or int(address) in {1, 2, 3, -1}:
        raise MissingExactShaderBindingError("GL 4.5 glClipControl entrypoint is unavailable")
    prototype(address)(GL_UPPER_LEFT, GL_NEGATIVE_ONE_TO_ONE)

    context.viewport = (0, 0, 256, 256)
    context.scissor = (0, 0, 256, 256)
    context.enable_direct(GL_SCISSOR_TEST)
    context.disable_direct(GL_FRAMEBUFFER_SRGB)
    context.disable_direct(GL_STENCIL_TEST)
    context.disable(moderngl.DEPTH_TEST | moderngl.CULL_FACE)
    context.enable(moderngl.BLEND)
    context.blend_equation = (moderngl.FUNC_ADD, moderngl.FUNC_ADD)

    gl.glColorMask(1, 1, 1, 1)
    gl.glDepthMask(0)
    color_mask = (ctypes.c_ubyte * 4)()
    depth_mask = (ctypes.c_ubyte * 1)()
    gl.glGetBooleanv(GL_COLOR_WRITEMASK, color_mask)
    gl.glGetBooleanv(GL_DEPTH_WRITEMASK, depth_mask)
    if tuple(color_mask) != (1, 1, 1, 1) or tuple(depth_mask) != (0,):
        raise MissingExactShaderBindingError("live GL write masks differ from MiiMask state")
    for parameter, expected_value in (
        (GL_CLIP_ORIGIN, GL_UPPER_LEFT),
        (GL_CLIP_DEPTH_MODE, GL_NEGATIVE_ONE_TO_ONE),
    ):
        actual = ctypes.c_int()
        gl.glGetIntegerv(parameter, ctypes.byref(actual))
        if actual.value != expected_value:
            raise MissingExactShaderBindingError(
                f"live GL clip-control parameter {parameter:#x} is {actual.value:#x}, "
                f"expected {expected_value:#x}"
            )
    expected_enabled = {
        GL_BLEND: True,
        GL_DEPTH_TEST: False,
        GL_CULL_FACE: False,
        GL_STENCIL_TEST: False,
        GL_SCISSOR_TEST: True,
        GL_FRAMEBUFFER_SRGB: False,
    }
    for capability, expected in expected_enabled.items():
        if bool(gl.glIsEnabled(capability)) is not expected:
            raise MissingExactShaderBindingError(
                f"live GL capability {capability:#x} differs from exact MiiMask state"
            )


def _set_and_verify_exact_blend_state(
    context: Any,
    source_rgb: int,
    destination_rgb: int,
) -> None:
    """Apply one recovered RGB blend tuple with the shared alpha ADD ONE/ONE tuple."""

    import moderngl

    context.blend_func = (source_rgb, destination_rgb, moderngl.ONE, moderngl.ONE)
    context.blend_equation = (moderngl.FUNC_ADD, moderngl.FUNC_ADD)
    gl = _load_system_gl()
    expected = {
        GL_BLEND_SRC_RGB: source_rgb,
        GL_BLEND_DST_RGB: destination_rgb,
        GL_BLEND_SRC_ALPHA: moderngl.ONE,
        GL_BLEND_DST_ALPHA: moderngl.ONE,
        GL_BLEND_EQUATION_RGB: moderngl.FUNC_ADD,
        GL_BLEND_EQUATION_ALPHA: moderngl.FUNC_ADD,
    }
    for parameter, expected_value in expected.items():
        actual = ctypes.c_int()
        gl.glGetIntegerv(parameter, ctypes.byref(actual))
        if actual.value != expected_value:
            raise MissingExactShaderBindingError(
                f"live GL blend parameter {parameter:#x} is {actual.value:#x}, "
                f"expected {expected_value:#x}"
            )


@dataclass
class RenderedMiiMaskAtlas:
    """Stored host-translation output plus explicit title write/sample-view domains."""

    stored_rgba8_upper_left: bytes
    stored_sha256: str
    width: int = 256
    height: int = 256
    color_target_view_format: str = "RGBA8_UNORM (0x0b01)"
    sampled_texture_view_format: str = "RGBA8_SRGB (0x0b06)"

    def top_left_rgba8(self) -> bytes:
        """Return raw rows unchanged; title window-origin mode 1 is upper-left."""

        return self.stored_rgba8_upper_left

    def create_srgb_sampling_texture(self, context: Any) -> Any:
        """Emulate the title's sRGB sampled view over the stored output bytes."""

        return context.texture(
            (self.width, self.height),
            4,
            self.stored_rgba8_upper_left,
            alignment=1,
            dtype="f1",
            internal_format=GL_SRGB8_ALPHA8,
        )

    def save_png(self, path: Path) -> None:
        """Write a top-left-origin diagnostic PNG without color conversion."""

        from PIL import Image

        Image.frombytes("RGBA", (self.width, self.height), self.top_left_rgba8()).save(path)


@dataclass
class CheckedMiiMaskGeometry:
    """One exact helper-created Mii sprite quad expressed as ModernGL resources."""

    vertex_array: Any
    position_buffer: Any
    texcoord_buffer: Any
    index_buffer: Any
    index_count: int
    geometry_variant: int

    def release(self) -> None:
        self.vertex_array.release()
        self.index_buffer.release()
        self.texcoord_buffer.release()
        self.position_buffer.release()


@dataclass
class CheckedMiiMaskLayer:
    """Source-authenticated resources for one live Kestron dispatcher case."""

    proof_key: str
    dispatcher_case: int
    draw_index: int
    draw_passes: tuple[str, ...]
    runtime_bindings: TitleShaderRuntimeBindings
    geometry: CheckedMiiMaskGeometry
    owned_texture_binding: ExactTextureBinding

    def bind(self, backend: TitleShaderBackend, linked: LinkedTitleShaderProgram) -> BoundTitleShaderResources:
        return backend.bind_runtime_resources(linked, self.runtime_bindings)

    def release(self) -> None:
        self.geometry.release()
        self.owned_texture_binding.texture.release()


class MiiMaskGpuRenderer:
    """Strict API for source-backed translated-title MiiMask atlas execution."""

    def __init__(self, backend: TitleShaderBackend) -> None:
        self.backend = backend
        matches = [
            program
            for program in backend.execution_ledger.get("programs", [])
            if isinstance(program, Mapping) and program.get("key") == MII_MASK_PROGRAM_KEY
        ]
        if len(matches) != 1:
            raise MissingExactShaderBindingError(
                "MiiMask title program is missing or duplicated in the execution ledger"
            )
        validate_mii_mask_program_specification(matches[0])
        self.linked = backend.link_program(MII_MASK_PROGRAM_KEY)

    @property
    def checked_proof_keys(self) -> tuple[str, ...]:
        return tuple(
            str(record["key"])
            for record in sorted(
                self.linked.specification["checked_draw_inputs"],
                key=lambda record: int(record["draw_index"]),
            )
        )

    def _proof(self, proof_key: str) -> Mapping[str, Any]:
        matches = [
            record
            for record in self.linked.specification["checked_draw_inputs"]
            if str(record["key"]) == proof_key
        ]
        if len(matches) != 1:
            raise MissingExactShaderBindingError(
                f"MiiMask checked draw input {proof_key!r} is missing or duplicated"
            )
        return matches[0]

    def _create_geometry(self, proof: Mapping[str, Any]) -> CheckedMiiMaskGeometry:
        geometry = proof["geometry"]
        _validate_mii_mask_geometry_source(
            str(proof["key"]),
            int(proof["dispatcher_case"]),
            geometry,
            self.linked.specification["checked_draw_sources"]["geometry_source_ledger"],
        )
        position_record = geometry["position_stream"]
        texcoord_record = geometry["texcoord_stream"]
        position = bytes.fromhex(str(position_record["raw_hex"]))
        texcoord = bytes.fromhex(str(texcoord_record["raw_hex"]))
        indices = bytes.fromhex(str(geometry["indices_raw_hex"]))
        for label, payload, record in (
            ("position", position, position_record),
            ("texcoord", texcoord, texcoord_record),
        ):
            if len(payload) != int(record["byte_length"]) or _sha256(payload) != record["sha256"]:
                raise TitleShaderArtifactMismatchError(
                    f"MiiMask {proof['key']} {label} stream failed its checked proof"
                )
        if len(position) != 4 * 8 or len(texcoord) != 4 * 4:
            raise TitleShaderArtifactMismatchError("MiiMask quad is not four half4/half2 vertices")
        if len(indices) != 6 * 2 or _sha256(indices) != geometry["indices_sha256"]:
            raise TitleShaderArtifactMismatchError("MiiMask uint16 quad indices changed")

        position_buffer = None
        texcoord_buffer = None
        index_buffer = None
        try:
            position_buffer = self.backend.context.buffer(position)
            texcoord_buffer = self.backend.context.buffer(texcoord)
            index_buffer = self.backend.context.buffer(indices)
            vertex_array = self.backend.create_vertex_array(
                self.linked,
                (
                    TitleVertexAttributeBinding(
                        buffer=position_buffer,
                        moderngl_format="4f2",
                        glsl_attribute_name="in_attr0",
                        source_attribute_name="MiiSpritePosition",
                    ),
                    TitleVertexAttributeBinding(
                        buffer=texcoord_buffer,
                        moderngl_format="2f2",
                        glsl_attribute_name="in_attr1",
                        source_attribute_name="MiiSpriteTexCoord",
                    ),
                ),
                index_buffer=index_buffer,
                index_element_size=2,
            )
        except Exception:
            if index_buffer is not None:
                index_buffer.release()
            if texcoord_buffer is not None:
                texcoord_buffer.release()
            if position_buffer is not None:
                position_buffer.release()
            raise
        return CheckedMiiMaskGeometry(
            vertex_array=vertex_array,
            position_buffer=position_buffer,
            texcoord_buffer=texcoord_buffer,
            index_buffer=index_buffer,
            index_count=6,
            geometry_variant=int(geometry["variant"]),
        )

    def prepare_layer(self, proof_key: str) -> CheckedMiiMaskLayer:
        proof = self._proof(proof_key)
        vertex_cbuf: ExactConstantBufferBinding | None = None
        fragment_cbuf: ExactConstantBufferBinding | None = None
        texture: ExactTextureBinding | None = None
        geometry: CheckedMiiMaskGeometry | None = None
        try:
            vertex_cbuf = self.backend.constant_buffer_from_program_proof(
                self.linked, proof_key, MII_MASK_VERTEX_CBUF_KEY
            )
            fragment_cbuf = self.backend.constant_buffer_from_program_proof(
                self.linked, proof_key, MII_MASK_FRAGMENT_CBUF_KEY
            )
            texture = self.backend.upload_checked_program_texture(
                self.linked, proof_key, MII_MASK_TEXTURE_KEY
            )
            geometry = self._create_geometry(proof)
            return CheckedMiiMaskLayer(
                proof_key=proof_key,
                dispatcher_case=int(proof["dispatcher_case"]),
                draw_index=int(proof["draw_index"]),
                draw_passes=tuple(str(value) for value in proof["draw_passes"]),
                runtime_bindings=TitleShaderRuntimeBindings(
                    constant_buffers={
                        MII_MASK_VERTEX_CBUF_KEY: vertex_cbuf,
                        MII_MASK_FRAGMENT_CBUF_KEY: fragment_cbuf,
                    },
                    textures={MII_MASK_TEXTURE_KEY: texture},
                ),
                geometry=geometry,
                owned_texture_binding=texture,
            )
        except Exception:
            if geometry is not None:
                geometry.release()
            if texture is not None:
                texture.texture.release()
            raise

    def validate_all_layers(self) -> None:
        """Exercise every source check and host binding without issuing a draw."""

        for proof_key in self.checked_proof_keys:
            layer = self.prepare_layer(proof_key)
            try:
                owned_buffers = layer.bind(self.backend, self.linked)
                owned_buffers.release()
            finally:
                layer.release()

    def assert_atlas_render_executable(self) -> None:
        unresolved = list(self.linked.specification.get("unresolved_runtime_inputs", []))
        if unresolved:
            raise MissingExactShaderBindingError(
                "source-backed MiiMask atlas draw remains fail-closed: " + "; ".join(unresolved)
            )
        conversion = self.linked.specification["render_target_state"].get(
            "framebuffer_color_conversion_state"
        )
        if conversion != "disabled_source_proven_by_unorm_write_view":
            raise MissingExactShaderBindingError(
                "MiiMask 0x0b01 UNORM color-target view state is not source-proven"
            )

    def render_atlas(self) -> RenderedMiiMaskAtlas:
        """Execute the source-backed 15-draw translated-title atlas sequence."""

        import moderngl

        self.assert_atlas_render_executable()
        proof_keys = self.checked_proof_keys
        active_keys = tuple(key for key in proof_keys if key != "kestron_case_21")
        if len(active_keys) != 7 or proof_keys[-1:] != ("kestron_case_21",):
            raise MissingExactShaderBindingError(
                "MiiMask checked draw sequence is not seven gated layers plus case 21"
            )

        target = None
        framebuffer = None
        layers: dict[str, CheckedMiiMaskLayer] = {}
        try:
            target = self.backend.context.texture(
                (256, 256),
                4,
                dtype="f1",
                internal_format=GL_RGBA8,
            )
            framebuffer = self.backend.context.framebuffer(color_attachments=[target])
            framebuffer.use()
            _set_and_verify_exact_write_state(self.backend.context)
            framebuffer.clear(0.0, 0.0, 0.0, 0.0, viewport=(0, 0, 256, 256))
            layers = {key: self.prepare_layer(key) for key in proof_keys}

            draw_sequence = (
                (
                    "pass_0",
                    active_keys,
                    moderngl.ONE,
                    moderngl.ZERO,
                ),
                (
                    "case_21",
                    ("kestron_case_21",),
                    moderngl.SRC_ALPHA,
                    moderngl.ONE_MINUS_SRC_ALPHA,
                ),
                (
                    "pass_1",
                    active_keys,
                    moderngl.ONE,
                    moderngl.ONE_MINUS_SRC_ALPHA,
                ),
            )
            for pass_name, keys, source_rgb, destination_rgb in draw_sequence:
                _set_and_verify_exact_blend_state(
                    self.backend.context,
                    source_rgb,
                    destination_rgb,
                )
                for key in keys:
                    layer = layers[key]
                    if pass_name not in layer.draw_passes:
                        raise MissingExactShaderBindingError(
                            f"{key} is not checked for MiiMask pipeline {pass_name}"
                        )
                    bound = layer.bind(self.backend, self.linked)
                    try:
                        layer.geometry.vertex_array.render(
                            mode=moderngl.TRIANGLES,
                            vertices=layer.geometry.index_count,
                        )
                    finally:
                        bound.release()
                if pass_name == "case_21":
                    case21_bytes = target.read(alignment=1)
                    if case21_bytes != bytes((0, 0, 0, 255)) * (256 * 256):
                        raise TitleShaderArtifactMismatchError(
                            "MiiMask case 21 did not produce its source-proven opaque-black full target"
                        )

            stored = target.read(alignment=1)
            if len(stored) != 256 * 256 * 4 or any(alpha != 255 for alpha in stored[3::4]):
                raise TitleShaderArtifactMismatchError(
                    "MiiMask translated-title target is not a complete opaque 256x256 RGBA8 atlas"
                )
            if not any(stored[index] for index in range(0, len(stored), 4)):
                raise TitleShaderArtifactMismatchError(
                    "MiiMask translated-title pass 1 produced no checked feature pixels"
                )
            return RenderedMiiMaskAtlas(
                stored_rgba8_upper_left=stored,
                stored_sha256=_sha256(stored),
            )
        finally:
            for layer in reversed(tuple(layers.values())):
                layer.release()
            if framebuffer is not None:
                framebuffer.release()
            if target is not None:
                target.release()

    def release(self) -> None:
        self.linked.program.release()


__all__ = [
    "CheckedMiiMaskGeometry",
    "CheckedMiiMaskLayer",
    "MII_MASK_FRAGMENT_CBUF_KEY",
    "MII_MASK_PROGRAM_KEY",
    "MII_MASK_TEXTURE_KEY",
    "MII_MASK_VERTEX_CBUF_KEY",
    "MiiMaskGpuRenderer",
    "RenderedMiiMaskAtlas",
    "validate_mii_mask_program_specification",
]
