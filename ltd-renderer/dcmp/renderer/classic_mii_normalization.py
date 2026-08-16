"""Source-backed classic-Mii normalization shared by selection and rendering."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Mapping

try:
    from .ltd_format import parse_char_info
except ImportError:  # renderer scripts also execute this directory as sys.path[0]
    from ltd_format import parse_char_info


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PROFILE = ROOT / "renderer/classic_mii_runtime_profile.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _validate_external_file_record(record: Mapping[str, Any], label: str) -> None:
    path = Path(str(record.get("path", "")))
    if not path.is_file():
        raise ValueError(f"{label} evidence is missing: {path}")
    if path.stat().st_size != int(record.get("byte_length", -1)):
        raise ValueError(f"{label} evidence size changed: {path}")
    if _sha256_file(path) != str(record.get("sha256", "")):
        raise ValueError(f"{label} evidence hash changed: {path}")


def load_checked_runtime_profile(
    path: Path = RUNTIME_PROFILE,
    *,
    validate_runtime_source: bool = True,
) -> dict[str, Any]:
    """Load and validate the frozen title profile and all six default templates."""

    raw = path.read_bytes()
    profile = json.loads(raw)
    if (
        profile.get("schema_version") != 1
        or profile.get("key")
        != "classic-title-ryujinx-usa-special-normalization-v1"
    ):
        raise ValueError("unsupported classic Mii runtime profile")
    runtime = profile.get("runtime")
    if not isinstance(runtime, dict):
        raise ValueError("classic Mii runtime profile is missing runtime state")
    if runtime.get("is_enabled_special_mii") is not True:
        raise ValueError("checked classic runtime must enable special Miis")
    if runtime.get("merged_region_code") not in (0, 1, 2):
        raise ValueError("checked classic runtime has an invalid merged-region code")
    if validate_runtime_source:
        _validate_external_file_record(
            runtime.get("configuration_evidence", {}), "runtime configuration"
        )

    templates = profile.get("default_char_info_templates")
    if not isinstance(templates, dict) or set(templates) != {
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
    }:
        raise ValueError("classic Mii runtime profile must carry defaults 0..5")
    for key, record in templates.items():
        try:
            template = base64.b64decode(
                str(record["char_info_base64"]), validate=True
            )
        except (KeyError, ValueError) as error:
            raise ValueError(f"default CharInfoEx {key} is malformed") from error
        if len(template) != 0x98:
            raise ValueError(f"default CharInfoEx {key} is not 0x98 bytes")
        if _sha256_bytes(template) != record.get("char_info_sha256"):
            raise ValueError(f"default CharInfoEx {key} hash changed")
        decoded = parse_char_info(template)
        index = int(key)
        if int(decoded["gender"] != 0) != int(index >= 3):
            raise ValueError(f"default CharInfoEx {key} has the wrong gender")
        if decoded["face_flags_raw"] != 0 or decoded["region_move"] != 0:
            raise ValueError(f"default CharInfoEx {key} is not an ordinary local Mii")

    profile["artifact"] = {
        "path": path.resolve().as_posix(),
        "byte_length": len(raw),
        "sha256": _sha256_bytes(raw),
    }
    return profile


def _validate_source_char_info(char_info: Mapping[str, Any]) -> tuple[str, int, int]:
    try:
        uuid_raw = str(char_info["uuid_raw"])
        create_id = bytes.fromhex(uuid_raw)
        gender = int(char_info["gender"])
        region_move = int(char_info["region_move"])
        flags = int(char_info["face_flags_raw"])
        nested_special = bool(char_info["face_flags"]["special_mii"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("CharInfoEx lacks valid normalization fields") from error
    if len(create_id) != 16 or str(uuid.UUID(bytes=create_id)) != char_info.get("uuid"):
        raise ValueError("CharInfoEx CreateId fields disagree")
    if gender not in (0, 1):
        raise ValueError(f"unsupported CharInfoEx gender {gender}")
    if nested_special != bool(flags & 1):
        raise ValueError("CharInfoEx special_mii flag disagrees with face_flags_raw")
    return uuid_raw, gender, region_move


def _changed_fields(
    raw: Mapping[str, Any], effective: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    changed: dict[str, dict[str, Any]] = {}
    for key in sorted(set(raw) | set(effective)):
        if raw.get(key) != effective.get(key):
            changed[key] = {"raw": raw.get(key), "effective": effective.get(key)}
    return changed


def effective_char_info(
    char_info: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return title-effective CharInfoEx plus a deterministic audit report.

    This function performs no I/O and mutates neither input.  Callers load the
    checked profile once with :func:`load_checked_runtime_profile`, then use
    this same function before active-parts selection, face composition, body
    sizing, model loading, and report generation.
    """

    uuid_raw, gender, region_move = _validate_source_char_info(char_info)
    raw = copy.deepcopy(dict(char_info))
    effective = copy.deepcopy(raw)
    runtime = profile.get("runtime")
    templates = profile.get("default_char_info_templates")
    if not isinstance(runtime, Mapping) or not isinstance(templates, Mapping):
        raise ValueError("classic Mii runtime profile is incomplete")

    special = bool(int(raw["face_flags_raw"]) & 1)
    special_enabled = bool(runtime.get("is_enabled_special_mii"))
    merged_region = int(runtime.get("merged_region_code", -1))
    if region_move not in (0, 1, 2, 3):
        raise ValueError(f"unexpected special-Mii region_move {region_move}")

    expected_region = {1: 0, 2: 1, 3: 2}.get(region_move)
    replace = special and (
        not special_enabled
        or (expected_region is not None and expected_region != merged_region)
    )
    default_index: int | None = None
    if replace:
        create_id = bytes.fromhex(uuid_raw)
        default_index = (3 if gender else 0) + create_id[15] % 3
        template_record = templates.get(str(default_index))
        if not isinstance(template_record, Mapping):
            raise ValueError(f"missing SDK default CharInfoEx {default_index}")
        template = base64.b64decode(
            str(template_record.get("char_info_base64", "")), validate=True
        )
        template = create_id + template[16:]
        effective = parse_char_info(template)
        if effective["uuid_raw"] != uuid_raw or effective["gender"] != gender:
            raise ValueError("SDK default normalization did not preserve identity/gender")

    if not special:
        action = "ordinary_noop"
    elif replace:
        action = "replace_with_sdk_default"
    elif region_move == 0:
        action = "special_preserved_no_region_move"
    else:
        action = "special_preserved_matching_region"
    changed = _changed_fields(raw, effective)
    report = {
        "profile_key": profile.get("key"),
        "profile_sha256": (
            profile.get("artifact", {}).get("sha256")
            if isinstance(profile.get("artifact"), Mapping)
            else None
        ),
        "source_function": "normalize_special_origin_mii_char_info_ex@0x7101d6ef40",
        "action": action,
        "normalized": replace,
        "is_enabled_special_mii": special_enabled,
        "merged_region_code": merged_region,
        "source_region_move": region_move,
        "expected_merged_region": expected_region,
        "default_index": default_index,
        "raw_char_info_sha256": _canonical_digest(raw),
        "effective_char_info_sha256": _canonical_digest(effective),
        "changed_fields": changed,
    }
    return effective, report


__all__ = [
    "RUNTIME_PROFILE",
    "effective_char_info",
    "load_checked_runtime_profile",
]
