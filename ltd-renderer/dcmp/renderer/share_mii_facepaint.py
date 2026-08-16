"""Decode the source-backed ShareMii v3 face-paint surfaces.

The v3 container carries two representations of the same authored paint:

* ``Canvas`` is the editor/reconstruction state: a 256x256 RGBA8 NVN
  block-linear surface.
* ``UGC`` is the sampled render texture: a 512x512 BC1 NVN block-linear
  surface bound to GameAll0's ``_user0`` slot.

Neither representation is inferred from a reference render.  The storage
sizes, encoder format, layout mode, block-height calculation, mask material
binding, and live face-paint transform are recovered from the title code and
checked resources.  Unsupported versions and malformed or partial payloads
fail closed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import numpy as np
import zstandard


ZSTANDARD_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"
CANVAS_WIDTH = 256
CANVAS_HEIGHT = 256
CANVAS_BYTES_PER_PIXEL = 4
CANVAS_DECODED_BYTE_LENGTH = 0x40000
UGC_WIDTH = 512
UGC_HEIGHT = 512
UGC_BLOCK_WIDTH = UGC_WIDTH // 4
UGC_BLOCK_HEIGHT = UGC_HEIGHT // 4
UGC_BYTES_PER_BLOCK = 8
UGC_DECODED_BYTE_LENGTH = 0x20000
NVN_BLOCK_HEIGHT_GOBS = 16

# Exact shipped System.mii__SystemParam values.  These are live configuration
# inputs read by the renderer, not constructor defaults and not fitted values.
FACE_PAINT_SIZE = (np.float32(0.75), np.float32(0.75))
FACE_PAINT_OFFSET = (np.float32(0.0), np.float32(0.03))


@dataclass(frozen=True)
class FacePaintTexSrt:
    """Exact binder SRT inputs plus the portable ModeMaya affine boundary."""

    size: tuple[float, float]
    offset: tuple[float, float]
    scaling: tuple[float, float]
    translation: tuple[float, float]
    # Rows of the affine transform consumed by the decoded mask vertex stage:
    # (u', v') = ((m00*u + m01*v + tx), (m10*u + m11*v + ty)).
    affine_rows: tuple[tuple[float, float, float], tuple[float, float, float]]

    def map_bfres_uv(
        self, u: np.ndarray | float, v: np.ndarray | float
    ) -> tuple[np.ndarray, np.ndarray]:
        """Apply the portable ModeMaya compatibility affine in BFRES UV space."""

        u_value = np.asarray(u, dtype=np.float64)
        v_value = np.asarray(v, dtype=np.float64)
        row_u, row_v = self.affine_rows
        return (
            row_u[0] * u_value + row_u[1] * v_value + row_u[2],
            row_v[0] * u_value + row_v[1] * v_value + row_v[2],
        )

    def map_obj_uv_for_portable_sampler(
        self, u: np.ndarray | float, v: np.ndarray | float
    ) -> tuple[np.ndarray, np.ndarray]:
        """Map exported OBJ UVs while preserving the title's BFRES-V transform.

        The OBJ exporter stores ``v_obj = 1-v_bfres`` and the portable sampler
        converts it back when addressing image rows.  Applying the TexSrt
        directly to ``v_obj`` would reverse the sign of FacePaintOffset.y.
        """

        u_obj = np.asarray(u, dtype=np.float64)
        v_obj = np.asarray(v, dtype=np.float64)
        mapped_u, mapped_v_bfres = self.map_bfres_uv(u_obj, 1.0 - v_obj)
        return mapped_u, 1.0 - mapped_v_bfres


@dataclass(frozen=True)
class ShareMiiV3FacePaint:
    """Decoded surfaces, exact binder inputs, and a portable affine boundary."""

    canvas_editor_rgba8: np.ndarray
    ugc_render_rgba8: np.ndarray
    tex_srt: FacePaintTexSrt
    report: dict[str, Any]


def _f32(value: float | np.floating[Any]) -> np.float32:
    return np.float32(value)


@lru_cache(maxsize=1)
def facepaint_tex_srt() -> FacePaintTexSrt:
    """Build exact binder values and the explicit portable ModeMaya affine."""

    size_x, size_y = FACE_PAINT_SIZE
    offset_x, offset_y = FACE_PAINT_OFFSET
    scale_x = _f32(_f32(1.0) / size_x)
    scale_y = _f32(_f32(1.0) / size_y)
    translation_x = _f32(_f32(_f32(0.5) - _f32(size_x * _f32(0.5))) + offset_x)
    translation_y = _f32(_f32(_f32(0.5) - _f32(size_y * _f32(0.5))) + offset_y)

    # mt_Mask authors tex_mtx_user0 as ModeMaya with zero rotation.  The title
    # binder's SRT values above and the vertex-stage affine consumption are
    # exact.  The intervening nn::g3d ModeMaya-to-constant-buffer converter is
    # not present in the decompilation, so these rows are an explicit portable
    # compatibility conversion and are not claimed as captured runtime cbuf.
    matrix_tx = _f32(-_f32(scale_x * translation_x))
    matrix_ty = _f32(
        _f32(scale_y * _f32(translation_y - _f32(1.0))) + _f32(1.0)
    )
    return FacePaintTexSrt(
        size=(float(size_x), float(size_y)),
        offset=(float(offset_x), float(offset_y)),
        scaling=(float(scale_x), float(scale_y)),
        translation=(float(translation_x), float(translation_y)),
        affine_rows=(
            (float(scale_x), 0.0, float(matrix_tx)),
            (0.0, float(scale_y), float(matrix_ty)),
        ),
    )


def _strict_zstandard_frame(encoded: bytes, expected_size: int, label: str) -> bytes:
    """Decode exactly one known-size frame and reject every trailing byte."""

    if not encoded.startswith(ZSTANDARD_FRAME_MAGIC):
        raise ValueError(f"{label} is not a Zstandard frame")
    try:
        declared_size = zstandard.frame_content_size(encoded)
    except zstandard.ZstdError as error:
        raise ValueError(f"{label} has an invalid Zstandard frame header") from error
    # zstandard 0.25 exposes the constants as unsigned size_t sentinels while
    # frame_content_size() returns their signed Python representations.
    if declared_size in (
        zstandard.CONTENTSIZE_ERROR,
        zstandard.CONTENTSIZE_UNKNOWN,
        -2,
        -1,
    ):
        raise ValueError(f"{label} must declare its exact decompressed size")
    if declared_size != expected_size:
        raise ValueError(
            f"{label} declares {declared_size} decoded bytes; expected {expected_size}"
        )

    decoder = zstandard.ZstdDecompressor().decompressobj()
    try:
        decoded = decoder.decompress(encoded)
    except zstandard.ZstdError as error:
        raise ValueError(f"{label} Zstandard decompression failed") from error
    if not decoder.eof:
        raise ValueError(f"{label} contains a truncated Zstandard frame")
    if decoder.unused_data:
        raise ValueError(f"{label} contains trailing or concatenated frame data")
    if decoder.unconsumed_tail:
        raise ValueError(f"{label} left unconsumed compressed data")
    if len(decoded) != expected_size:
        raise ValueError(
            f"{label} decoded to {len(decoded)} bytes; expected {expected_size}"
        )
    return decoded


def _block_linear_address(
    x_element: int,
    y_element: int,
    width_elements: int,
    bytes_per_element: int,
    block_height_gobs: int = NVN_BLOCK_HEIGHT_GOBS,
) -> int:
    """Return the byte address used by the recovered NVN block-linear copy."""

    width_gobs = (width_elements * bytes_per_element + 63) // 64
    x_bytes = x_element * bytes_per_element
    return (
        (y_element // (8 * block_height_gobs)) * 512 * block_height_gobs * width_gobs
        + (x_bytes // 64) * 512 * block_height_gobs
        + ((y_element % (8 * block_height_gobs)) // 8) * 512
        + ((x_bytes % 64) // 32) * 256
        + ((y_element % 8) // 2) * 64
        + ((x_bytes % 32) // 16) * 32
        + (y_element % 2) * 16
        + (x_bytes % 16)
    )


def _deswizzle_block_linear(
    source: bytes,
    width_elements: int,
    height_elements: int,
    bytes_per_element: int,
    *,
    label: str,
) -> bytes:
    """Copy one exact block-linear surface to row-major element order."""

    if width_elements <= 0 or height_elements <= 0 or bytes_per_element <= 0:
        raise ValueError(f"{label} has an invalid surface extent")
    output = bytearray(width_elements * height_elements * bytes_per_element)
    for y_element in range(height_elements):
        for x_element in range(width_elements):
            source_offset = _block_linear_address(
                x_element, y_element, width_elements, bytes_per_element
            )
            source_end = source_offset + bytes_per_element
            if source_end > len(source):
                raise ValueError(f"{label} block-linear address exceeds its payload")
            output_offset = (
                (y_element * width_elements + x_element) * bytes_per_element
            )
            output[output_offset : output_offset + bytes_per_element] = source[
                source_offset:source_end
            ]
    return bytes(output)


def _rgb565_rgba8(value: int) -> np.ndarray:
    red = (value >> 11) & 0x1F
    green = (value >> 5) & 0x3F
    blue = value & 0x1F
    return np.asarray(
        (
            (red << 3) | (red >> 2),
            (green << 2) | (green >> 4),
            (blue << 3) | (blue >> 2),
            255,
        ),
        dtype=np.uint16,
    )


def _decode_bc1_row_major(blocks: bytes, width: int, height: int) -> np.ndarray:
    """Decode standard little-endian BC1 blocks without color-space conversion."""

    if width % 4 or height % 4:
        raise ValueError("BC1 extent must be divisible by four")
    blocks_x = width // 4
    blocks_y = height // 4
    expected_size = blocks_x * blocks_y * UGC_BYTES_PER_BLOCK
    if len(blocks) != expected_size:
        raise ValueError(f"BC1 surface has {len(blocks)} bytes; expected {expected_size}")

    output = np.empty((height, width, 4), dtype=np.uint8)
    transparent = np.asarray((0, 0, 0, 0), dtype=np.uint16)
    for block_y in range(blocks_y):
        for block_x in range(blocks_x):
            offset = (block_y * blocks_x + block_x) * UGC_BYTES_PER_BLOCK
            color0, color1, selectors = struct.unpack_from("<HHI", blocks, offset)
            endpoint0 = _rgb565_rgba8(color0)
            endpoint1 = _rgb565_rgba8(color1)
            if color0 > color1:
                palette = (
                    endpoint0,
                    endpoint1,
                    (2 * endpoint0 + endpoint1) // 3,
                    (endpoint0 + 2 * endpoint1) // 3,
                )
            else:
                palette = (
                    endpoint0,
                    endpoint1,
                    (endpoint0 + endpoint1) // 2,
                    transparent,
                )
            for pixel_y in range(4):
                for pixel_x in range(4):
                    selector_index = 2 * (pixel_y * 4 + pixel_x)
                    output[block_y * 4 + pixel_y, block_x * 4 + pixel_x] = palette[
                        (selectors >> selector_index) & 3
                    ]
    output.setflags(write=False)
    return output


def _payload_bytes(record: dict[str, Any], label: str) -> bytes:
    if record.get("declared_present") is not True:
        raise ValueError(f"{label} is not declared present")
    if record.get("compression") != "zstandard":
        raise ValueError(f"{label} is not identified as Zstandard")
    raw_hex = record.get("raw_hex")
    if not isinstance(raw_hex, str):
        raise ValueError(f"{label} has no encoded payload bytes")
    try:
        encoded = bytes.fromhex(raw_hex)
    except ValueError as error:
        raise ValueError(f"{label} payload hex is invalid") from error
    if len(encoded) != record.get("byte_length"):
        raise ValueError(f"{label} payload length metadata changed")
    if hashlib.sha256(encoded).hexdigest() != record.get("sha256"):
        raise ValueError(f"{label} payload hash metadata changed")
    return encoded


@lru_cache(maxsize=8)
def _decode_frames(canvas_encoded: bytes, ugc_encoded: bytes) -> tuple[np.ndarray, np.ndarray]:
    canvas_block_linear = _strict_zstandard_frame(
        canvas_encoded, CANVAS_DECODED_BYTE_LENGTH, "ShareMii v3 Canvas"
    )
    ugc_block_linear = _strict_zstandard_frame(
        ugc_encoded, UGC_DECODED_BYTE_LENGTH, "ShareMii v3 UGC"
    )
    canvas_row_major = _deswizzle_block_linear(
        canvas_block_linear,
        CANVAS_WIDTH,
        CANVAS_HEIGHT,
        CANVAS_BYTES_PER_PIXEL,
        label="ShareMii v3 Canvas",
    )
    ugc_blocks = _deswizzle_block_linear(
        ugc_block_linear,
        UGC_BLOCK_WIDTH,
        UGC_BLOCK_HEIGHT,
        UGC_BYTES_PER_BLOCK,
        label="ShareMii v3 UGC",
    )
    canvas = np.frombuffer(canvas_row_major, dtype=np.uint8).reshape(
        CANVAS_HEIGHT, CANVAS_WIDTH, 4
    )
    canvas.setflags(write=False)
    ugc = _decode_bc1_row_major(ugc_blocks, UGC_WIDTH, UGC_HEIGHT)
    return canvas, ugc


def _opaque_bbox(image: np.ndarray) -> list[int] | None:
    coordinates = np.argwhere(image[..., 3] != 0)
    if not len(coordinates):
        return None
    y_min, x_min = coordinates.min(axis=0)
    y_max, x_max = coordinates.max(axis=0)
    return [int(x_min), int(y_min), int(x_max), int(y_max)]


def _float32_bits(value: float) -> str:
    return f"0x{struct.unpack('<I', struct.pack('<f', value))[0]:08x}"


def decode_share_mii_v3_facepaint(
    document: dict[str, Any],
) -> ShareMiiV3FacePaint | None:
    """Decode a complete v3 face-paint pair, return ``None`` when absent.

    V2 face-paint storage is deliberately not interpreted by this path.  A v2
    file with declared payloads therefore fails closed rather than borrowing
    the v3 layout.
    """

    header = document.get("header")
    if not isinstance(header, dict):
        raise ValueError("ShareMii document has no header")
    has_canvas = header.get("has_canvas") is True
    has_ugc = header.get("has_ugc_texture") is True
    canvas_record = document.get("canvas_texture_payload")
    ugc_record = document.get("ugc_texture_payload")
    if not isinstance(canvas_record, dict) or not isinstance(ugc_record, dict):
        raise ValueError("ShareMii document has no embedded texture records")
    canvas_length = canvas_record.get("byte_length")
    ugc_length = ugc_record.get("byte_length")

    if header.get("version") != 3:
        if has_canvas or has_ugc or canvas_length or ugc_length:
            raise ValueError("embedded face paint is supported only for ShareMii v3")
        return None
    if not has_canvas and not has_ugc:
        if canvas_length != 0 or ugc_length != 0:
            raise ValueError("undeclared ShareMii v3 face-paint payload bytes are present")
        return None
    if not (has_canvas and has_ugc):
        raise ValueError("ShareMii v3 face paint requires both Canvas and UGC flags")
    if not canvas_length or not ugc_length:
        raise ValueError("ShareMii v3 face paint requires both embedded payloads")

    canvas_encoded = _payload_bytes(canvas_record, "ShareMii v3 Canvas")
    ugc_encoded = _payload_bytes(ugc_record, "ShareMii v3 UGC")
    canvas, ugc = _decode_frames(canvas_encoded, ugc_encoded)
    canvas_nearest_2x = np.repeat(np.repeat(canvas, 2, axis=0), 2, axis=1)
    exact_pixel_match = np.all(canvas_nearest_2x == ugc, axis=2)
    tex_srt = facepaint_tex_srt()
    report = {
        "status": "complete ShareMii v3 face paint decoded",
        "container_version": 3,
        "canvas": {
            "role": "editor/reconstruction state; not sampled by mt_Mask",
            "encoded_byte_length": len(canvas_encoded),
            "encoded_sha256": hashlib.sha256(canvas_encoded).hexdigest(),
            "decoded_block_linear_byte_length": CANVAS_DECODED_BYTE_LENGTH,
            "decoded_block_linear_sha256": hashlib.sha256(
                _strict_zstandard_frame(
                    canvas_encoded, CANVAS_DECODED_BYTE_LENGTH, "ShareMii v3 Canvas"
                )
            ).hexdigest(),
            "format": "RGBA8_UNORM",
            "dimensions": [CANVAS_WIDTH, CANVAS_HEIGHT],
            "layout": "NVN block-linear, blockHeight=16 GOBs",
            "row_major_rgba8_sha256": hashlib.sha256(canvas.tobytes()).hexdigest(),
            "nonzero_alpha_bbox_inclusive": _opaque_bbox(canvas),
        },
        "ugc": {
            "role": "sampled render texture bound to mt_Mask GameAll0 _user0",
            "encoded_byte_length": len(ugc_encoded),
            "encoded_sha256": hashlib.sha256(ugc_encoded).hexdigest(),
            "decoded_block_linear_byte_length": UGC_DECODED_BYTE_LENGTH,
            "decoded_block_linear_sha256": hashlib.sha256(
                _strict_zstandard_frame(
                    ugc_encoded, UGC_DECODED_BYTE_LENGTH, "ShareMii v3 UGC"
                )
            ).hexdigest(),
            "format": "BC1_UNORM sampled through an sRGB texture view",
            "dimensions": [UGC_WIDTH, UGC_HEIGHT],
            "layout": "NVN block-linear BC1 blocks, blockHeight=16 GOBs",
            "row_major_rgba8_sha256": hashlib.sha256(ugc.tobytes()).hexdigest(),
            "nonzero_alpha_bbox_inclusive": _opaque_bbox(ugc),
            "unique_rgba8_count": int(np.unique(ugc.reshape(-1, 4), axis=0).shape[0]),
        },
        "inline_canvas_ugc_cross_check": {
            "purpose": (
                "orientation and channel validation using two payloads from the same "
                "ShareMii; no reference-image pixels participate"
            ),
            "comparison": "Canvas nearest-upsampled 2x versus decoded lossy BC1 UGC",
            "exact_rgba8_pixel_count": int(np.count_nonzero(exact_pixel_match)),
            "total_pixel_count": int(exact_pixel_match.size),
            "exact_rgba8_pixel_fraction": float(np.mean(exact_pixel_match)),
            "alpha_difference_pixel_count": int(
                np.count_nonzero(canvas_nearest_2x[..., 3] != ugc[..., 3])
            ),
            "limits": "BC1 is lossy; disagreement is reported, not repaired from Canvas",
        },
        "tex_mtx_user0": {
            "configuration_source": (
                "program/1/Parameter/MiiSystem/System.mii__SystemParam.bgyml"
            ),
            "size": list(tex_srt.size),
            "offset": list(tex_srt.offset),
            "scaling": list(tex_srt.scaling),
            "translation": list(tex_srt.translation),
            "mode": "ModeMaya",
            "rotation": 0.0,
            "affine_rows": [list(row) for row in tex_srt.affine_rows],
            "affine_float32_bits": [
                [_float32_bits(value) for value in row] for row in tex_srt.affine_rows
            ],
            "coordinate_domain": (
                "title transform is evaluated in BFRES UV; portable OBJ V is inverted "
                "before and after the transform"
            ),
            "status": (
                "exact title binder size/offset-derived SRT and exact authored ModeMaya "
                "mode; affine rows use the portable BFRES ModeMaya compatibility "
                "conversion because the live nn::g3d constant-buffer converter is unavailable"
            ),
        },
        "coverage_boundary": (
            "GameAll0 exports alpha one and has no KIL. Portable mask coverage is a "
            "separate unresolved pass-override proxy using generated-alpha OR UGC-alpha; "
            "it is not literal shader alpha and does not precompose the two RGB inputs."
        ),
        "reference_image_values_used": False,
    }
    return ShareMiiV3FacePaint(canvas, ugc, tex_srt, report)


__all__ = [
    "FacePaintTexSrt",
    "ShareMiiV3FacePaint",
    "decode_share_mii_v3_facepaint",
    "facepaint_tex_srt",
]
