#!/usr/bin/env python3
"""Resolve every ShareMii render selector through the title's PartsIndex metadata."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
sys.path.insert(0, str(ROOT))

from renderer.ltd_format import load_share_mii  # noqa: E402
from renderer.classic_mii_normalization import (  # noqa: E402
    effective_char_info,
    load_checked_runtime_profile,
)
from renderer.classic_bridge_support import inactive_projection  # noqa: E402
from renderer import runtime_file_cache  # noqa: E402
from tools.byml_v7 import decode_little_endian_byml_v7  # noqa: E402


INPUT = ROOT / "mii1.ltd"
PARTS_METADATA = ROOT / "manifests" / "render_asset_byml_metadata.jsonl"
OUTPUT = ROOT / "renderer" / "mii_active_parts.json"
DEFAULT_ASSET_ROOT = Path(
    os.environ.get(
        "LTD_RENDERER_ASSET_ROOT",
        str(PROJECT / "ltdDemo_converted_assets"),
    )
).resolve()
PARTS_ROOT_FRAGMENT = "/Pack/MiiParts/Mii/Parts/"
BYAML_EXT_PLAIN_HASH_ERROR = "ByamlException: Unknown node type '20'."
MAX_PARTS_INDEX_CACHE_ENTRIES = 2


@dataclass(frozen=True)
class _PartsIndexCacheEntry:
    metadata_path: Path
    metadata_sha256: str
    parts: dict[tuple[str, int], tuple[Path, dict[str, Any]]]
    plain_hash_fallback_record_count: int
    fallback_files: tuple[tuple[Path, int, str], ...]


_parts_index_cache_lock = threading.RLock()
_parts_index_cache: OrderedDict[tuple[str, str, str], _PartsIndexCacheEntry] = OrderedDict()

# Ordered like the appearance data, with the title's Parts category made
# explicit.  Hair front/back are editor sub-state: only HairFront has its own
# catalog, and it is gated by the selected main Hair record.
SELECTORS: tuple[tuple[str, str | None, str | None], ...] = (
    ("faceline", "faceline_type", "Faceline"),
    ("wrinkle_lower", "wrinkle_lower_type", "WrinkleLower"),
    ("wrinkle_upper", "wrinkle_upper_type", "WrinkleUpper"),
    ("makeup_upper", "makeup_upper_type", "MakeUpper"),
    ("makeup_lower", "makeup_lower_type", "MakeLower"),
    ("hair", "hair_type", "Hair"),
    ("hair_front", "hair_front_type", "HairFront"),
    ("hair_back_editor_state", "hair_back_type", None),
    ("ear", "ear_type", "Ear"),
    ("eye", "eye_type", "Eye"),
    ("eye_highlight", "eye_highlight_type", "Highlight"),
    ("eyelash_upper", "eyelash_upper_type", "EyelashUpper"),
    ("eyelash_lower", "eyelash_lower_type", "EyelashLower"),
    ("eyelid_upper", "eyelid_upper_type", "EyelidUpper"),
    ("eyelid_lower", "eyelid_lower_type", "EyelidLower"),
    ("eyebrow", "eyebrow_type", "Eyebrow"),
    ("nose", "nose_type", "Nose"),
    ("mouth", "mouth_type", "Mouth"),
    ("beard", "beard_type", "Beard"),
    ("beard_short", "stubble_type", "BeardShort"),
    ("mustache", "mustache_type", "Mustache"),
    ("glass_primary", "glass_primary_type", "Glass"),
    ("mole", None, "Mole"),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return Path(os.path.relpath(path, ROOT)).as_posix()


def _model_resources(value: Any, asset_root: Path) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []

    def visit(node: Any, key_path: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                visit(child, key_path + (key,))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                visit(child, key_path + (str(index),))
        elif key_path and key_path[-1] == "Fmdb" and isinstance(node, str):
            match = re.search(r"/([^/]+)/output/[^/]+\.fmdb$", node)
            resource_name = match.group(1) if match else Path(node).stem
            bfres = asset_root / "decompressed" / "1" / "Model" / f"{resource_name}.bfres"
            found.append(
                {
                    "role": ".".join(key_path[:-1]),
                    "fmdb": node,
                    "resource_name": resource_name,
                    "bfres": relative(bfres),
                    "bfres_exists": bfres.is_file(),
                }
            )

    visit(value, ())
    return found


def _resolve_metadata_source(recorded_path: str, asset_root: Path) -> Path:
    """Rebase the immutable manifest's asset path onto this deployment.

    The checked JSONL intentionally retains the original absolute capture
    paths because its byte hash is pinned by multiple runtime contracts. Only
    the path used for local I/O is relocated; the manifest bytes stay exact.
    """
    portable_parts = PurePosixPath(recorded_path.replace("\\", "/")).parts
    asset_component = "ltdDemo_converted_assets"
    try:
        asset_index = next(
            index
            for index, part in enumerate(portable_parts)
            if part.casefold() == asset_component.casefold()
        )
    except StopIteration as error:
        raise OSError(
            f"PartsIndex metadata path is outside {asset_component}: {recorded_path}"
        ) from error

    resolved_asset_root = asset_root.resolve()
    resolved = resolved_asset_root.joinpath(*portable_parts[asset_index + 1:]).resolve()
    if not resolved.is_relative_to(resolved_asset_root):
        raise OSError(f"PartsIndex metadata path escapes the asset root: {recorded_path}")
    return resolved


def load_parts(asset_root: Path = DEFAULT_ASSET_ROOT) -> tuple[
    dict[tuple[str, int], tuple[Path, dict[str, Any]]], str, int
]:
    # The JSONL is immutable checked evidence but still authenticated on every
    # request.  Reuse its parsed 764-record index only while that full digest
    # and every separately decoded fallback BYML identity remain exact.
    metadata_path = PARTS_METADATA.resolve(strict=True)
    metadata_hash = runtime_file_cache.sha256(metadata_path)
    resolved_asset_root = asset_root.resolve()
    cache_key = (
        os.path.normcase(str(metadata_path)),
        metadata_hash,
        os.path.normcase(str(resolved_asset_root)),
    )
    with _parts_index_cache_lock:
        cached = _parts_index_cache.get(cache_key)
    if cached is not None and all(
        runtime_file_cache.matches_file(
            path,
            byte_length=byte_length,
            sha256_digest=digest,
        )
        is not None
        for path, byte_length, digest in cached.fallback_files
    ):
        candidate = copy.deepcopy(cached.parts)
        metadata_unchanged = (
            runtime_file_cache.sha256(metadata_path) == metadata_hash
        )
        fallbacks_unchanged = all(
            runtime_file_cache.matches_file(
                path,
                byte_length=byte_length,
                sha256_digest=digest,
            )
            is not None
            for path, byte_length, digest in cached.fallback_files
        )
        if not metadata_unchanged or not fallbacks_unchanged:
            raise OSError("PartsIndex evidence changed while cloning cached index")
        with _parts_index_cache_lock:
            if _parts_index_cache.get(cache_key) is cached:
                _parts_index_cache.move_to_end(cache_key)
        # build_manifest reads only; a defensive copy prevents a future caller
        # from poisoning persistent worker state through nested BYML records.
        return candidate, metadata_hash, cached.plain_hash_fallback_record_count

    index: dict[tuple[str, int], tuple[Path, dict[str, Any]]] = {}
    plain_hash_fallback_record_count = 0
    fallback_files: list[tuple[Path, int, str]] = []
    metadata_payload = runtime_file_cache.read_bytes(metadata_path)
    # Detect a write racing the cached SHA/read boundary before accepting the
    # parsed index. The second SHA is a state-checked cache hit when unchanged.
    if runtime_file_cache.sha256(metadata_path) != metadata_hash:
        raise OSError(f"PartsIndex metadata changed while parsing: {metadata_path}")
    for raw_line in metadata_payload.decode("utf-8").splitlines():
        item = json.loads(raw_line)
        source = _resolve_metadata_source(str(item["path"]), resolved_asset_root)
        normalized = source.as_posix()
        if PARTS_ROOT_FRAGMENT not in normalized:
            continue
        data = item.get("data")
        if not isinstance(data, dict) and item.get("error") == BYAML_EXT_PLAIN_HASH_ERROR:
            before_length = source.stat().st_size
            before_digest = runtime_file_cache.sha256(source)
            data = decode_little_endian_byml_v7(source)
            if runtime_file_cache.matches_file(
                source,
                byte_length=before_length,
                sha256_digest=before_digest,
            ) is None:
                raise OSError(f"PartsIndex fallback changed while decoding: {source}")
            fallback_files.append((source.resolve(), before_length, before_digest))
            plain_hash_fallback_record_count += 1
        if not isinstance(data, dict):
            continue
        category = data.get("Category")
        parts_index = data.get("PartsIndex")
        if not isinstance(category, str) or not isinstance(parts_index, int) or parts_index < 0:
            continue
        key = (category, parts_index)
        if key in index:
            raise RuntimeError(f"ambiguous PartsIndex {category}:{parts_index}")
        index[key] = (source, data)
    if runtime_file_cache.sha256(metadata_path) != metadata_hash:
        raise OSError(f"PartsIndex metadata changed while parsing: {metadata_path}")
    if any(
        runtime_file_cache.matches_file(
            path,
            byte_length=byte_length,
            sha256_digest=digest,
        )
        is None
        for path, byte_length, digest in fallback_files
    ):
        raise OSError("PartsIndex fallback changed before parsed-index commit")
    entry = _PartsIndexCacheEntry(
        metadata_path=metadata_path,
        metadata_sha256=metadata_hash,
        parts=index,
        plain_hash_fallback_record_count=plain_hash_fallback_record_count,
        fallback_files=tuple(fallback_files),
    )
    with _parts_index_cache_lock:
        _parts_index_cache[cache_key] = entry
        _parts_index_cache.move_to_end(cache_key)
        while len(_parts_index_cache) > MAX_PARTS_INDEX_CACHE_ENTRIES:
            _parts_index_cache.popitem(last=False)
    return copy.deepcopy(index), metadata_hash, plain_hash_fallback_record_count


def resolve_record(
    parts: dict[tuple[str, int], tuple[Path, dict[str, Any]]],
    category: str,
    selector: int,
) -> tuple[Path, dict[str, Any]]:
    try:
        return parts[(category, selector)]
    except KeyError as error:
        raise RuntimeError(f"no {category} PartsIndex record for selector {selector}") from error


def build_manifest(
    input_path: Path = INPUT,
    asset_root: Path = DEFAULT_ASSET_ROOT,
) -> dict[str, Any]:
    document = load_share_mii(input_path)
    raw_char = document["char_info"]
    # The generated profile is the deployable runtime authority.  Its builder
    # alone verifies the local Ryujinx configuration source; production hosts
    # need only the bundle-hash-bound checked artifact.
    runtime_profile = load_checked_runtime_profile(validate_runtime_source=False)
    char, normalization = effective_char_info(raw_char, runtime_profile)
    resolved_asset_root = asset_root.resolve()
    parts, metadata_hash, plain_hash_fallback_record_count = load_parts(
        resolved_asset_root
    )
    selected_hair_source, selected_hair = resolve_record(parts, "Hair", int(char["hair_type"]))
    hair_front_enabled = bool(selected_hair.get("IsAttachableHairFront", False))

    records: list[dict[str, Any]] = []
    for logical_name, field, category in SELECTORS:
        if logical_name == "mole":
            selector = 1 if char["face_flags"]["mole_enabled"] else 0
            gate = "face_flags.mole_enabled"
            gate_enabled = bool(char["face_flags"]["mole_enabled"])
        else:
            selector = int(char[field])
            gate = None
            gate_enabled = True

        if logical_name == "hair_front":
            gate = "selected Hair.IsAttachableHairFront"
            gate_enabled = hair_front_enabled
        elif logical_name == "hair_back_editor_state":
            records.append(
                {
                    "logical_name": logical_name,
                    "selector_field": field,
                    "selector": selector,
                    "category": None,
                    "resolved": False,
                    "enabled": False,
                    "gate": "subordinate main-hair editor state; no HairBack Parts category exists",
                    "evidence": "retained and named, but not an independent PartsIndex selector",
                }
            )
            continue

        assert category is not None
        resolved_part = parts.get((category, selector))
        if resolved_part is None:
            records.append(
                {
                    "logical_name": logical_name,
                    "selector_field": field,
                    "selector": selector,
                    "category": category,
                    "resolved": False,
                    "enabled": False,
                    "gate": gate,
                    "gate_enabled": gate_enabled,
                    "inactive_projection": inactive_projection(
                        "title_lookup_empty"
                    ),
                    "unresolved_reason": (
                        f"no {category} PartsIndex record for selector {selector} "
                        "in the decoded title metadata"
                    ),
                    "evidence": "omitted fail-closed; no substitute PartsIndex was inferred",
                }
            )
            continue
        source, data = resolved_part
        file_name = str(data.get("FileName", source.name.split(".", 1)[0]))
        texture_name = data.get("TextureName")
        models = _model_resources(data, resolved_asset_root)
        is_nothing = file_name.endswith("Nothing")
        render_payload = bool(texture_name or models)
        enabled = gate_enabled and not is_nothing and render_payload
        projection = (
            inactive_projection("exact_parts_nothing")
            if is_nothing
            else inactive_projection("gate_disabled")
            if not gate_enabled
            else None
        )
        source_bytes = source.read_bytes()
        record: dict[str, Any] = {
            "logical_name": logical_name,
            "selector_field": field,
            "selector": selector,
            "category": category,
            "resolved": True,
            "record": file_name,
            "enabled": enabled,
            "is_nothing": is_nothing,
            "gate": gate,
            "gate_enabled": gate_enabled,
            "inactive_projection": projection,
            "parts_config": relative(source),
            "parts_config_byte_length": len(source_bytes),
            "parts_config_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "model_resources": models,
            "texture_name": texture_name,
            "components": data.get("Components", {}),
            "components_hash": data.get("ComponentsHash", {}),
            "resource_flags": {
                key: data[key]
                for key in (
                    "IsAttachableHairFront",
                    "IsFlippable",
                    "IsSelectableColor",
                    "IsSelectableSubColor",
                    "RotateAxis",
                    "AxisForExpression",
                )
                if key in data
            },
        }
        if texture_name:
            bntx = resolved_asset_root / "decompressed" / "1" / "Tex" / "Pack" / f"{texture_name}.bntx"
            png = resolved_asset_root / "textures_png" / "1" / "Tex" / "Pack" / f"{texture_name}.png"
            record["texture_resource"] = {
                "bntx": relative(bntx),
                "bntx_exists": bntx.is_file(),
                "png": relative(png),
                "png_exists": png.is_file(),
            }
        records.append(record)

    enabled_models: list[str] = []
    enabled_textures: list[str] = []
    for record in records:
        if not record.get("enabled"):
            continue
        # The no-hat MiiIcon path consumes the record's primary ModelUnit.
        # Plain-hash HairPartsModelUnit entries are conditional alternatives,
        # so merely decoding them does not make them active submissions.
        enabled_models.extend(
            model["resource_name"]
            for model in record.get("model_resources", [])
            if model.get("role") == "ModelUnit"
        )
        if record.get("texture_name"):
            enabled_textures.append(record["texture_name"])

    return {
        "schema_version": 1,
        "description": "Generic PartsIndex resolution for every render selector in the selected ShareMii.",
        "generator": "tools/build_mii_active_parts.py",
        "target": {
            "path": relative(input_path),
            "byte_length": input_path.stat().st_size,
            "sha256": sha256(input_path),
            "display_name": document["display_name"],
            "internal_name": char["name"],
            "raw_internal_name": raw_char["name"],
            "gender": char["gender"],
            "face_gender": document["personality_and_voice"]["face_gender"],
        },
        "char_info_normalization": normalization,
        "effective_char_info": char,
        "parts_metadata": {
            "path": relative(PARTS_METADATA),
            "sha256": metadata_hash,
            "indexed_record_count": len(parts),
            "plain_hash_fallback_record_count": plain_hash_fallback_record_count,
            "plain_hash_fallback": (
                "bounds-checked little-endian BYML v7 node 0x20 decoding"
            ),
        },
        "selector_count": len(records),
        "unresolved_parts_index_count": sum(
            record.get("category") is not None and not record.get("resolved")
            for record in records
        ),
        "enabled_record_count": sum(bool(record.get("enabled")) for record in records),
        "active_model_resources": list(dict.fromkeys(enabled_models)),
        "active_texture_resources": list(dict.fromkeys(enabled_textures)),
        "records": records,
    }


def serialized(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> int:
    # Windows still commonly inherits a legacy console code page.  Display names
    # are UTF-16 in CharInfo and are therefore not limited to that code page;
    # reporting a valid Japanese (or otherwise non-ASCII) name must not turn a
    # successful manifest build into an encoding failure.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="regenerate in memory and compare byte-for-byte")
    parser.add_argument("--input", type=Path, default=INPUT, help="ShareMii input (default: mii1.ltd)")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="manifest destination")
    parser.add_argument(
        "--asset-root",
        type=Path,
        default=DEFAULT_ASSET_ROOT,
        help="converted LTD asset root (default: sibling ltdDemo_converted_assets)",
    )
    args = parser.parse_args()
    input_path = args.input.resolve()
    output_path = args.output.resolve()
    payload = serialized(build_manifest(input_path, args.asset_root.resolve()))
    if args.check:
        if not output_path.is_file() or output_path.read_bytes() != payload:
            print(f"{relative(output_path)} is stale", file=sys.stderr)
            return 1
    else:
        output_path.write_bytes(payload)
    manifest = json.loads(payload)
    print(
        f"active Mii parts OK: {manifest['target']['display_name']}, "
        f"{manifest['selector_count']} selectors, {manifest['enabled_record_count']} enabled, "
        f"{len(manifest['active_model_resources'])} models, "
        f"{len(manifest['active_texture_resources'])} textures"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, AssertionError) as error:
        print(f"active Mii parts failed: {error}", file=sys.stderr)
        raise SystemExit(1)
