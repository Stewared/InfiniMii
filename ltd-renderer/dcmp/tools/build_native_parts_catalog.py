#!/usr/bin/env python3
"""Build the compact, authenticated catalog for native PartsIndex selection.

This is deliberately an offline tool.  It delegates BYML-v7 fallback decoding
and checked-runtime-profile validation to the same authorities used by
``tools/build_mii_active_parts.py`` and emits a deterministic binary that the
native runtime can consume without Python, JSON, or BYML support.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from renderer.classic_mii_normalization import (  # noqa: E402
    load_checked_runtime_profile,
)
from tools import build_mii_active_parts as authority  # noqa: E402


OUTPUT_DIRECTORY = ROOT / "native_runtime" / "generated"
BINARY_NAME = "native_parts_catalog.bin"
MANIFEST_NAME = "native_parts_catalog.json"
MAGIC = b"IMPARTS\0"
FORMAT_VERSION = 1
HEADER_SIZE = 88
PROFILE_SIZE = 4 + 6 * 152
ENTRY_SIZE = 28
MODEL_SIZE = 8
ABSENT_STRING = 0xFFFFFFFF

# This ordering is part of the native ABI, not inferred from dictionary order.
CATEGORIES = (
    "Faceline",
    "WrinkleLower",
    "WrinkleUpper",
    "MakeUpper",
    "MakeLower",
    "Hair",
    "HairFront",
    "Ear",
    "Eye",
    "Highlight",
    "EyelashUpper",
    "EyelashLower",
    "EyelidUpper",
    "EyelidLower",
    "Eyebrow",
    "Nose",
    "Mouth",
    "Beard",
    "BeardShort",
    "Mustache",
    "Glass",
    "Mole",
)
CATEGORY_IDS = {name: index for index, name in enumerate(CATEGORIES)}


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def relative(path: Path) -> str:
    return Path(os.path.relpath(path.resolve(), ROOT)).as_posix()


def canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


class StringTable:
    def __init__(self) -> None:
        self.payload = bytearray(b"\0")
        self.offsets: dict[str, int] = {"": 0}

    def add(self, value: str) -> int:
        existing = self.offsets.get(value)
        if existing is not None:
            return existing
        encoded = value.encode("utf-8")
        if b"\0" in encoded:
            raise ValueError("catalog string contains NUL")
        offset = len(self.payload)
        self.payload.extend(encoded)
        self.payload.append(0)
        self.offsets[value] = offset
        return offset


def _checked_profile() -> tuple[dict[str, Any], bytes]:
    profile = load_checked_runtime_profile(validate_runtime_source=False)
    profile_path = ROOT / "renderer" / "classic_mii_runtime_profile.json"
    payload = profile_path.read_bytes()
    # The checked loader adds only an artifact identity; all runtime fields are
    # still sourced from these exact bytes.
    if profile.get("key") != "classic-title-ryujinx-usa-special-normalization-v1":
        raise ValueError("unexpected classic runtime profile key")
    return profile, payload


def _profile_payload(profile: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    runtime = profile.get("runtime")
    templates = profile.get("default_char_info_templates")
    if not isinstance(runtime, dict) or not isinstance(templates, dict):
        raise ValueError("classic runtime profile is incomplete")
    special_enabled = runtime.get("is_enabled_special_mii")
    merged_region = runtime.get("merged_region_code")
    if not isinstance(special_enabled, bool) or merged_region not in (0, 1, 2):
        raise ValueError("classic runtime normalization settings are invalid")
    decoded: list[bytes] = []
    template_manifest: list[dict[str, Any]] = []
    for index in range(6):
        item = templates.get(str(index))
        if not isinstance(item, dict):
            raise ValueError(f"missing SDK default CharInfoEx {index}")
        try:
            raw = base64.b64decode(str(item["char_info_base64"]), validate=True)
        except (KeyError, ValueError) as error:
            raise ValueError(f"invalid SDK default CharInfoEx {index}") from error
        if len(raw) != 152:
            raise ValueError(f"SDK default CharInfoEx {index} has length {len(raw)}")
        expected_sha = str(item.get("char_info_sha256", ""))
        if sha256_bytes(raw) != expected_sha:
            raise ValueError(f"SDK default CharInfoEx {index} hash changed")
        if raw[39] != (1 if index >= 3 else 0):
            raise ValueError(f"SDK default CharInfoEx {index} gender changed")
        decoded.append(raw)
        template_manifest.append(
            {"index": index, "byte_length": len(raw), "sha256": expected_sha}
        )
    payload = bytes((int(special_enabled), int(merged_region), 0, 0)) + b"".join(decoded)
    if len(payload) != PROFILE_SIZE:
        raise AssertionError("native profile block size changed")
    return payload, {
        "is_enabled_special_mii": special_enabled,
        "merged_region_code": merged_region,
        "templates": template_manifest,
    }


def build_catalog() -> tuple[bytes, dict[str, Any]]:
    parts, metadata_sha, fallback_count = authority.load_parts()
    profile, profile_bytes = _checked_profile()
    profile_block, profile_manifest = _profile_payload(profile)

    selected: list[tuple[int, int, Path, dict[str, Any]]] = []
    for (category, selector), (source, data) in parts.items():
        category_id = CATEGORY_IDS.get(category)
        if category_id is None:
            continue
        if not 0 <= selector <= 0xFFFF:
            raise ValueError(f"PartsIndex selector is outside uint16: {category}:{selector}")
        selected.append((category_id, selector, source.resolve(), data))
    selected.sort(key=lambda item: (item[0], item[1]))
    if not selected:
        raise ValueError("PartsIndex evidence yielded no native selector records")

    strings = StringTable()
    entry_payload = bytearray()
    model_payload = bytearray()
    model_count = 0
    source_records: list[dict[str, Any]] = []
    category_counts = {name: 0 for name in CATEGORIES}
    prior: tuple[int, int] | None = None

    for category_id, selector, source, data in selected:
        key = (category_id, selector)
        if prior is not None and key <= prior:
            raise ValueError("native PartsIndex ordering or uniqueness changed")
        prior = key
        category = CATEGORIES[category_id]
        category_counts[category] += 1

        source_bytes = source.read_bytes()
        source_identity = {
            "path": relative(source),
            "byte_length": len(source_bytes),
            "sha256": sha256_bytes(source_bytes),
        }
        source_records.append(source_identity)
        file_name = str(data.get("FileName", source.name.split(".", 1)[0]))
        texture = data.get("TextureName")
        if texture is not None and not isinstance(texture, str):
            raise ValueError(f"non-string TextureName in {category}:{selector}")
        models = authority._model_resources(data)
        models_start = model_count
        for model in models:
            role = model.get("role")
            resource = model.get("resource_name")
            if not isinstance(role, str) or not isinstance(resource, str):
                raise ValueError(f"invalid model resource in {category}:{selector}")
            model_payload.extend(struct.pack("<II", strings.add(role), strings.add(resource)))
            model_count += 1

        is_nothing = file_name.endswith("Nothing")
        attachable = bool(data.get("IsAttachableHairFront", False))
        flags = (
            (1 if is_nothing else 0)
            | (2 if attachable else 0)
            | (4 if texture else 0)
            | (8 if models else 0)
        )
        texture_offset = strings.add(texture) if texture else ABSENT_STRING
        entry_payload.extend(
            struct.pack(
                "<HHIIIIIHH",
                category_id,
                selector,
                strings.add(file_name),
                strings.add(source_identity["path"]),
                texture_offset,
                models_start,
                len(models),
                flags,
                0,
            )
        )

    metadata_path = authority.PARTS_METADATA.resolve()
    metadata_bytes = metadata_path.read_bytes()
    if sha256_bytes(metadata_bytes) != metadata_sha:
        raise OSError("PartsIndex metadata changed during native catalog build")
    profile_path = ROOT / "renderer" / "classic_mii_runtime_profile.json"
    provenance_inputs = [
        {
            "kind": "parts_metadata",
            "path": relative(metadata_path),
            "byte_length": len(metadata_bytes),
            "sha256": metadata_sha,
        },
        {
            "kind": "normalization_profile",
            "path": relative(profile_path),
            "byte_length": len(profile_bytes),
            "sha256": sha256_bytes(profile_bytes),
        },
        *({"kind": "parts_config", **item} for item in source_records),
    ]
    provenance_payload = canonical_json({"inputs": provenance_inputs})
    source_digest = hashlib.sha256(provenance_payload).digest()

    profile_offset = HEADER_SIZE
    entries_offset = profile_offset + len(profile_block)
    models_offset = entries_offset + len(entry_payload)
    strings_offset = models_offset + len(model_payload)
    total_size = strings_offset + len(strings.payload)
    header = struct.pack(
        "<8sIIIIIIIIIIII32s",
        MAGIC,
        FORMAT_VERSION,
        total_size,
        profile_offset,
        len(profile_block),
        entries_offset,
        len(selected),
        ENTRY_SIZE,
        models_offset,
        model_count,
        MODEL_SIZE,
        strings_offset,
        len(strings.payload),
        source_digest,
    )
    if len(header) != HEADER_SIZE:
        raise AssertionError(f"native Parts header size changed: {len(header)}")
    binary = header + profile_block + bytes(entry_payload) + bytes(model_payload) + bytes(strings.payload)
    if len(binary) != total_size:
        raise AssertionError("native Parts catalog length changed")

    manifest = {
        "schema": "infinimii-native-parts-catalog-v1",
        "generator": "tools/build_native_parts_catalog.py",
        "binary": {
            "path": f"native_runtime/generated/{BINARY_NAME}",
            "byte_length": len(binary),
            "sha256": sha256_bytes(binary),
            "format_version": FORMAT_VERSION,
        },
        "source_bundle_sha256": source_digest.hex(),
        "parts_metadata": {
            "indexed_record_count": len(parts),
            "selected_record_count": len(selected),
            "plain_hash_fallback_record_count": fallback_count,
            "category_counts": category_counts,
        },
        "normalization_profile": profile_manifest,
        "catalog": {
            "entry_count": len(selected),
            "model_resource_count": model_count,
            "string_table_byte_length": len(strings.payload),
            "logical_selector_count": len(authority.SELECTORS),
        },
        "provenance_inputs": provenance_inputs,
    }
    return binary, manifest


def write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--output-directory", type=Path, default=OUTPUT_DIRECTORY)
    args = parser.parse_args()

    output_directory = args.output_directory.resolve()
    binary_path = output_directory / BINARY_NAME
    manifest_path = output_directory / MANIFEST_NAME
    binary, manifest = build_catalog()
    manifest_payload = canonical_json(manifest)
    if args.check:
        if not binary_path.is_file() or binary_path.read_bytes() != binary:
            raise ValueError(f"native Parts catalog is stale: {binary_path}")
        if not manifest_path.is_file() or manifest_path.read_bytes() != manifest_payload:
            raise ValueError(f"native Parts catalog manifest is stale: {manifest_path}")
    else:
        write_atomic(binary_path, binary)
        write_atomic(manifest_path, manifest_payload)
    print(
        "native Parts catalog OK: "
        f"{manifest['parts_metadata']['selected_record_count']} entries, "
        f"{manifest['catalog']['model_resource_count']} model links, "
        f"sha256={manifest['binary']['sha256']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"native Parts catalog failed: {error}", file=sys.stderr)
        raise SystemExit(1)
