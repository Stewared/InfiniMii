"""Parser for Tomodachi Life: Living the Dream ShareMii v2/v3 files.

The format identification comes from the executable/resource work in this
repository and is cross-checked against charinfo-ex and ltd-sharemii.  The v2
and v3 container layouts are decoded separately; both carry the same 0x98-byte
CharInfoEx record used by the title.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import uuid
from pathlib import Path
from typing import Any

import zstandard


CHAR_INFO_SIZE = 152
MII_BLOCK_SIZE = 4 + CHAR_INFO_SIZE
PERSONALITY_SIZE = 18 * 4
DISPLAY_NAME_SIZE = 64
PRONUNCIATION_SIZE = 128
V2_SEXUALITY_SIZE = 3
V3_SEXUALITY_SIZE = 4
V2_SECTION_MARKER = b"\xa3" * 3
V3_CANVAS_MARKER = b"\xa3" * 4
V3_UGC_TEXTURE_MARKER = b"\xa4" * 4
ZSTANDARD_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"
PERSONALITY_FIELDS = (
    "sociability",
    "audaciousness",
    "activeness",
    "commonsense",
    "gaiety",
    "voice_formant",
    "voice_speed",
    "voice_intonation",
    "voice_pitch",
    "voice_tension",
    "voice_preset_type_hash",
    "face_gender_hash",
    "pronoun_type_hash",
    "cloth_style_hash",
    "birthday_year",
    "birthday_day",
    "birthday_direct_age",
    "birthday_month",
)

HASH_ENUMS = {
    0x0DDCBE76: "male",
    0x3BE5D8D4: "he",
    0x3B1F8B15: "female",
    0x25AF6EE5: "she",
}

BYTE_FIELDS = (
    "font_region",
    "gender",
    "height",
    "build",
    "region_move",
    "face_flags_raw",
    "faceline_type",
    "faceline_color",
    "wrinkle_lower_type",
    "wrinkle_lower_scale",
    "wrinkle_lower_aspect",
    "wrinkle_lower_x",
    "wrinkle_lower_y",
    "wrinkle_upper_type",
    "wrinkle_upper_scale",
    "wrinkle_upper_aspect",
    "wrinkle_upper_x",
    "wrinkle_upper_y",
    "makeup_upper_type",
    "makeup_upper_color",
    "makeup_upper_scale",
    "makeup_upper_aspect",
    "makeup_upper_x",
    "makeup_upper_y",
    "makeup_lower_type",
    "makeup_lower_color",
    "makeup_lower_scale",
    "makeup_lower_aspect",
    "makeup_lower_x",
    "makeup_lower_y",
)

POST_HAIR_BYTE_FIELDS = (
    "hair_color_primary",
    "hair_color_secondary",
    "hair_front_type",
    "hair_back_type",
    "hair_style_flags_raw",
    "ear_type",
    "ear_scale",
    "ear_y",
    "eye_type",
    "eye_color",
    "eye_scale",
    "eye_aspect",
    "eye_rotate",
    "eye_x",
    "eye_y",
    "eye_shadow_color",
    "eye_highlight_type",
    "eye_highlight_scale",
    "eye_highlight_aspect",
    "eye_highlight_rotate",
    "eye_highlight_x",
    "eye_highlight_y",
    "eyelash_upper_type",
    "eyelash_upper_scale",
    "eyelash_upper_aspect",
    "eyelash_upper_rotate",
    "eyelash_upper_x",
    "eyelash_upper_y",
    "eyelash_lower_type",
    "eyelash_lower_scale",
    "eyelash_lower_aspect",
    "eyelash_lower_rotate",
    "eyelash_lower_x",
    "eyelash_lower_y",
    "eyelid_upper_type",
    "eyelid_upper_scale",
    "eyelid_upper_aspect",
    "eyelid_upper_rotate",
    "eyelid_upper_x",
    "eyelid_upper_y",
    "eyelid_lower_type",
    "eyelid_lower_scale",
    "eyelid_lower_aspect",
    "eyelid_lower_rotate",
    "eyelid_lower_x",
    "eyelid_lower_y",
    "eyebrow_type",
    "eyebrow_color",
    "eyebrow_scale",
    "eyebrow_aspect",
    "eyebrow_rotate",
    "eyebrow_x",
    "eyebrow_y",
    "nose_type",
    "nose_scale",
    "nose_y",
    "mouth_type",
    "mouth_color",
    "mouth_scale",
    "mouth_aspect",
    "mouth_rotate",
    "mouth_y",
    "beard_type",
    "beard_color",
    "stubble_type",
    "stubble_color",
    "mustache_type",
    "mustache_color",
    "mustache_scale",
    "mustache_aspect",
    "mustache_y",
    "glass_primary_type",
    "glass_primary_color",
    "glass_scale",
    "glass_aspect",
    "glass_y",
    "glass_lens_material_mode",
    "glass_lens_color",
    "mole_scale",
    "mole_x",
    "mole_y",
    "schema_version",
)


def _wstring(data: bytes) -> str:
    return data.decode("utf-16le").split("\0", 1)[0]


def _take(data: bytes, offset: int, length: int, section: str) -> bytes:
    end = offset + length
    if end > len(data):
        available = max(0, len(data) - offset)
        raise ValueError(
            f"truncated {section}: expected {length} byte(s) at 0x{offset:x}, "
            f"got {available}"
        )
    return data[offset:end]


def _payload_record(payload: bytes, offset: int, declared_present: bool) -> dict[str, Any]:
    """Describe an opaque embedded texture payload without guessing its pixels."""

    return {
        "offset": offset,
        "byte_length": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "declared_present": declared_present,
        "compression": "zstandard" if payload.startswith(ZSTANDARD_FRAME_MAGIC) else None,
        "raw_hex": payload.hex(),
    }


def _zstandard_frame_byte_length(data: bytes, offset: int, section: str) -> int:
    """Return one complete frame's encoded length without scanning its bytes for markers."""

    encoded_and_tail = data[offset:]
    if not encoded_and_tail.startswith(ZSTANDARD_FRAME_MAGIC):
        raise ValueError(f"expected Zstandard {section} frame at 0x{offset:x}")
    decoder = zstandard.ZstdDecompressor().decompressobj()
    try:
        decoder.decompress(encoded_and_tail)
    except zstandard.ZstdError as error:
        raise ValueError(f"invalid Zstandard {section} frame at 0x{offset:x}: {error}") from error
    if not decoder.eof:
        raise ValueError(f"truncated Zstandard {section} frame at 0x{offset:x}")
    consumed = len(encoded_and_tail) - len(decoder.unused_data)
    if consumed <= 0:
        raise ValueError(f"empty Zstandard {section} frame at 0x{offset:x}")
    return consumed


def parse_char_info(data: bytes) -> dict[str, Any]:
    if len(data) != CHAR_INFO_SIZE:
        raise ValueError(f"CharInfoEx must be {CHAR_INFO_SIZE} bytes, got {len(data)}")
    result: dict[str, Any] = {
        "uuid_raw": data[:16].hex(),
        "uuid": str(uuid.UUID(bytes=data[:16])),
        "name": _wstring(data[16:38]),
    }
    cursor = 38
    for name in BYTE_FIELDS:
        result[name] = data[cursor]
        cursor += 1
    result["hair_type"] = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2
    for name in POST_HAIR_BYTE_FIELDS:
        result[name] = data[cursor]
        cursor += 1
    if cursor != CHAR_INFO_SIZE:
        raise AssertionError(f"CharInfoEx schema consumed {cursor} bytes")

    face_flags = result["face_flags_raw"]
    result["face_flags"] = {
        "special_mii": bool(face_flags & 0x01),
        "bangs_side": bool(face_flags & 0x02),
        "back_dual_color": bool(face_flags & 0x04),
        "bangs_dual_color": bool(face_flags & 0x08),
        "eye_shadow_enabled": bool(face_flags & 0x10),
        "mouth_inverted": bool(face_flags & 0x20),
        "mustache_inverted": bool(face_flags & 0x40),
        "mole_enabled": bool(face_flags & 0x80),
    }
    hair_flags = result["hair_style_flags_raw"]
    result["hair_style_flags"] = {
        "left_side": bool(hair_flags & 0x01),
        "right_side": bool(hair_flags & 0x02),
        "reserved": hair_flags >> 2,
    }
    return result


def parse_share_mii(data: bytes) -> dict[str, Any]:
    if not data:
        raise ValueError("file is too short to contain a ShareMii header")

    version = data[0]
    if version not in (2, 3):
        raise ValueError(f"only ShareMii v2 and v3 are supported, got version {version}")

    if version == 2:
        header_raw = _take(data, 0, 5, "ShareMii v2 format header")
        _, has_canvas, has_ugc_texture, reserved, legacy_padding = header_raw
        mii_block_offset = 5
        sexuality_size = V2_SEXUALITY_SIZE
    else:
        header_raw = _take(data, 0, 4, "ShareMii v3 format header")
        _, has_canvas, has_ugc_texture, reserved = header_raw
        legacy_padding = None
        mii_block_offset = 4
        sexuality_size = V3_SEXUALITY_SIZE

    mii_block_raw = _take(data, mii_block_offset, MII_BLOCK_SIZE, "ShareMii Mii block")
    char_info_length = struct.unpack_from("<I", mii_block_raw, 0)[0]
    if char_info_length != CHAR_INFO_SIZE:
        raise ValueError(f"expected CharInfoEx length {CHAR_INFO_SIZE}, got {char_info_length}")

    cursor = mii_block_offset + 4
    char_info_offset = cursor
    char_info_raw = _take(data, cursor, char_info_length, "CharInfoEx")
    cursor += char_info_length

    personality_offset = cursor
    personality_raw = _take(data, cursor, PERSONALITY_SIZE, "personality and voice block")
    personality_values = struct.unpack("<18i", personality_raw)
    cursor += PERSONALITY_SIZE
    personality = dict(zip(PERSONALITY_FIELDS, personality_values, strict=True))
    personality["voice_preset_type"] = HASH_ENUMS.get(personality["voice_preset_type_hash"])
    personality["face_gender"] = HASH_ENUMS.get(personality["face_gender_hash"])
    personality["pronoun_type"] = HASH_ENUMS.get(personality["pronoun_type_hash"])
    personality["cloth_style"] = HASH_ENUMS.get(personality["cloth_style_hash"])

    display_name_offset = cursor
    display_name = _wstring(_take(data, cursor, DISPLAY_NAME_SIZE, "display name"))
    cursor += DISPLAY_NAME_SIZE
    pronunciation_offset = cursor
    pronunciation = _wstring(_take(data, cursor, PRONUNCIATION_SIZE, "pronunciation"))
    cursor += PRONUNCIATION_SIZE
    sexuality_offset = cursor
    sexuality_raw = _take(data, cursor, sexuality_size, "sexuality block")
    love_gender_flags = list(sexuality_raw[:3])
    cursor += sexuality_size

    canvas_marker_offset = cursor
    if version == 2:
        canvas_marker = _take(data, cursor, len(V2_SECTION_MARKER), "v2 canvas marker")
        if canvas_marker != V2_SECTION_MARKER:
            raise ValueError(f"expected ShareMii v2 canvas marker at 0x{cursor:x}")
        canvas_payload_offset = cursor + len(V2_SECTION_MARKER)
        ugc_marker_offset = data.rfind(V2_SECTION_MARKER, canvas_payload_offset)
        if ugc_marker_offset < canvas_payload_offset:
            raise ValueError("ShareMii v2 UGC texture marker is missing")
        ugc_texture_marker = data[ugc_marker_offset : ugc_marker_offset + len(V2_SECTION_MARKER)]
    else:
        canvas_marker = _take(data, cursor, len(V3_CANVAS_MARKER), "v3 canvas marker")
        if canvas_marker != V3_CANVAS_MARKER:
            raise ValueError(f"expected ShareMii v3 canvas marker at 0x{cursor:x}")
        canvas_payload_offset = cursor + len(V3_CANVAS_MARKER)
        canvas_payload_length = (
            _zstandard_frame_byte_length(data, canvas_payload_offset, "canvas")
            if has_canvas
            else 0
        )
        ugc_marker_offset = canvas_payload_offset + canvas_payload_length
        ugc_texture_marker = _take(
            data,
            ugc_marker_offset,
            len(V3_UGC_TEXTURE_MARKER),
            "v3 UGC texture marker",
        )
        if ugc_texture_marker != V3_UGC_TEXTURE_MARKER:
            raise ValueError(
                f"expected ShareMii v3 UGC texture marker immediately after the canvas frame at 0x{ugc_marker_offset:x}"
            )

    canvas_payload = data[canvas_payload_offset:ugc_marker_offset]
    ugc_payload_offset = ugc_marker_offset + len(ugc_texture_marker)
    ugc_texture_payload = data[ugc_payload_offset:]

    header = {
        "version": version,
        "has_canvas": bool(has_canvas),
        "has_ugc_texture": bool(has_ugc_texture),
        "reserved": reserved,
        "char_info_length": char_info_length,
    }
    if version == 2:
        # Preserve the v2 parser's public field exactly.  V3 has no byte at
        # this position; its 156-byte Mii block begins at file offset 0x04.
        header["legacy_padding"] = legacy_padding

    love_gender: dict[str, Any] = {
        "male": bool(love_gender_flags[0]),
        "female": bool(love_gender_flags[1]),
        "third": bool(love_gender_flags[2]),
        "raw": list(sexuality_raw),
        "serialized_length": sexuality_size,
    }
    if version == 3:
        # The checked container schema exposes a four-byte sexuality block,
        # but neither local title evidence nor the codec assigns a semantic
        # name to its fourth byte.  Keep it visible without inventing one.
        love_gender["uninterpreted_fourth_byte"] = sexuality_raw[3]

    return {
        "format": "Tomodachi Life: Living the Dream ShareMii",
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_length": len(data),
        "header": header,
        "char_info": parse_char_info(char_info_raw),
        "personality_and_voice": personality,
        "display_name": display_name,
        "pronunciation": pronunciation,
        "love_gender": love_gender,
        "canvas_marker": canvas_marker.hex(),
        "ugc_texture_marker": ugc_texture_marker.hex(),
        "canvas_texture_payload": _payload_record(
            canvas_payload, canvas_payload_offset, bool(has_canvas)
        ),
        "ugc_texture_payload": _payload_record(
            ugc_texture_payload, ugc_payload_offset, bool(has_ugc_texture)
        ),
        "serialized_sections": {
            "format_header": {"offset": 0, "byte_length": len(header_raw)},
            "mii_block": {"offset": mii_block_offset, "byte_length": MII_BLOCK_SIZE},
            "char_info": {"offset": char_info_offset, "byte_length": char_info_length},
            "personality_and_voice": {
                "offset": personality_offset,
                "byte_length": PERSONALITY_SIZE,
            },
            "display_name": {"offset": display_name_offset, "byte_length": DISPLAY_NAME_SIZE},
            "pronunciation": {
                "offset": pronunciation_offset,
                "byte_length": PRONUNCIATION_SIZE,
            },
            "sexuality": {"offset": sexuality_offset, "byte_length": sexuality_size},
            "canvas_marker": {
                "offset": canvas_marker_offset,
                "byte_length": len(canvas_marker),
            },
            "canvas_texture_payload": {
                "offset": canvas_payload_offset,
                "byte_length": len(canvas_payload),
            },
            "ugc_texture_marker": {
                "offset": ugc_marker_offset,
                "byte_length": len(ugc_texture_marker),
            },
            "ugc_texture_payload": {
                "offset": ugc_payload_offset,
                "byte_length": len(ugc_texture_payload),
            },
        },
    }


def load_share_mii(path: Path | str) -> dict[str, Any]:
    return parse_share_mii(Path(path).read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    document = load_share_mii(args.input)
    # Keep the stdout form portable even when a Windows caller forces a narrow
    # console code page. File output remains explicit UTF-8 JSON.
    text = json.dumps(document, indent=2, ensure_ascii=not bool(args.output)) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
