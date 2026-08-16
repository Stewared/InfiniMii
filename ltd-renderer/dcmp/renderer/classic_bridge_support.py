"""Fail-closed resource signatures for target-independent classic LTD rendering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from .runtime_file_cache import sha256 as _cached_sha256
except ImportError:  # Direct import from renderer/render_mii.py.
    from runtime_file_cache import sha256 as _cached_sha256


SIGNATURE_SCHEMA_VERSION = 2
INTENTIONAL_PSEUDO_RECORD = "hair_back_editor_state"
INACTIVE_PROJECTION_KINDS = frozenset(
    {"exact_parts_nothing", "gate_disabled", "title_lookup_empty"}
)
INACTIVE_PROJECTION_PREDICATES = {
    "exact_parts_nothing": "exact Parts FileName ends with Nothing",
    "gate_disabled": "selected Hair.IsAttachableHairFront is false",
    "title_lookup_empty": (
        "exact title PartsIndex lookup returns an empty resource name"
    ),
}
SEPARATE_FACELINE_TARGET_LAYERS = frozenset(
    {"makeup_lower", "makeup_upper", "wrinkle_upper", "wrinkle_lower", "beard_short"}
)
OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES = frozenset(
    {
        "wrinkle_lower",
        "wrinkle_upper",
        "makeup_upper",
        "makeup_lower",
        "hair",
        "hair_front",
        "ear",
        "eye",
        "eye_highlight",
        "eyelash_upper",
        "eyelash_lower",
        "eyelid_upper",
        "eyelid_lower",
        "eyebrow",
        "nose",
        "mouth",
        "beard",
        "beard_short",
        "mustache",
        "glass_primary",
        "mole",
    }
)
SIGNATURE_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "parts_metadata_sha256",
        "records",
        "active_model_resources",
        "active_texture_resources",
    }
)
SIGNATURE_KEYS = frozenset(
    {"algorithm", "sha256", "payload", "excluded_target_fields"}
)
SIGNATURE_RECORD_KEYS = frozenset(
    {
        "logical_name",
        "selector_field",
        "selector",
        "category",
        "resolved",
        "record",
        "enabled",
        "is_nothing",
        "gate",
        "gate_enabled",
        "parts_config",
        "models",
        "texture",
        "components",
        "components_hash",
        "resource_flags",
        "inactive_projection",
    }
)


def inactive_projection(kind: str) -> dict[str, Any]:
    """Return the canonical non-remapping projection for one no-draw state."""

    if kind not in INACTIVE_PROJECTION_KINDS:
        raise ValueError(f"unknown inactive Parts projection: {kind}")
    return {
        "kind": kind,
        "raw_selector_preserved": True,
        "selector_normalized": False,
        "source_predicate": INACTIVE_PROJECTION_PREDICATES[kind],
    }
CLASSIC_GENERIC_FACELINE_CONTRACT_KEY = (
    "classic_make_lower_make_upper_wrinkle_upper_wrinkle_lower_beard_short_ordered_v2"
)
CLASSIC_GENERIC_FACELINE_CONTRACT = {
    "key": CLASSIC_GENERIC_FACELINE_CONTRACT_KEY,
    "allowed_enabled_logical_names": [
        "makeup_lower",
        "makeup_upper",
        "wrinkle_upper",
        "wrinkle_lower",
        "beard_short",
    ],
    "title_draw_order": [
        "makeup_lower",
        "makeup_upper",
        "wrinkle_upper",
        "wrinkle_lower",
        "beard_short",
    ],
    "records": {
        "makeup_lower": ["MakeLower00", "MakeLower01", "MakeLower02"],
        "makeup_upper": ["MakeUpper00"],
        "wrinkle_upper": [f"WrinkleUpper{index:02d}" for index in range(7)],
        "wrinkle_lower": [
            "WrinkleLower00",
            "WrinkleLower01",
            "WrinkleLower02",
            "WrinkleLower04",
            "WrinkleLower05",
        ],
        "beard_short": [
            *[f"BeardShort{index:02d}" for index in range(5)],
            "BeardShort07",
        ],
    },
    "resource_flags_by_record": {
        "makeup_lower": {
            "MakeLower00": {},
            "MakeLower01": {},
            "MakeLower02": {"IsSelectableColor": False},
        },
        "makeup_upper": {"MakeUpper00": {}},
        "wrinkle_upper": {f"WrinkleUpper{index:02d}": {} for index in range(7)},
        "wrinkle_lower": {
            "WrinkleLower00": {},
            "WrinkleLower01": {},
            "WrinkleLower02": {},
            "WrinkleLower04": {},
            "WrinkleLower05": {},
        },
        "beard_short": {
            "BeardShort00": {"IsSelectableColor": False},
            "BeardShort01": {"IsSelectableColor": False},
            "BeardShort02": {},
            "BeardShort03": {},
            "BeardShort04": {},
            "BeardShort07": {},
        },
    },
    "non_selectable_color_fallbacks": {
        "makeup_lower": {"MakeLower02": 8},
        "beard_short": {"BeardShort00": 8, "BeardShort01": 8},
    },
    "source_evidence": {
        "function": "FUN_7101d7025c",
        "case_order": [1, 2, 3, 4, 5],
        "shader_selectors": {
            "makeup_lower": 6,
            "makeup_upper": 3,
            "wrinkle_upper": 3,
            "wrinkle_lower": 3,
            "beard_short": 6,
        },
        "blend": {
            "makeup_lower": "premultiplied source-over",
            "makeup_upper": "straight-alpha source-over",
            "wrinkle_upper": "straight-alpha source-over",
            "wrinkle_lower": "straight-alpha source-over",
            "beard_short": "premultiplied source-over",
        },
        "beard_short_c1_float_bits": [
            "0x3eaaaa9f",
            "0x3ecccccd",
            "0x3ecccccd",
            "0x3f800000",
        ],
        "rgba8_store_between_draws": True,
    },
}


def sha256(path: Path) -> str:
    return _cached_sha256(path)


def _resolve(repository: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _signature_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _model_unit_resources(record: dict[str, Any]) -> list[str]:
    return list(
        dict.fromkeys(
            str(model["resource_name"])
            for model in record.get("models", [])
            if model.get("role") == "ModelUnit"
        )
    )


def _validate_resource_signature(signature: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(signature, dict) or set(signature) != SIGNATURE_KEYS:
        raise ValueError("classic-bridge resource signature shape changed")
    payload = signature.get("payload")
    excluded = signature.get("excluded_target_fields")
    if not isinstance(payload, dict) or set(payload) != SIGNATURE_PAYLOAD_KEYS:
        raise ValueError("classic-bridge component signature payload shape changed")
    if (
        signature.get("algorithm") != "sha256(canonical-json-v1)"
        or signature.get("sha256") != _signature_digest(payload)
    ):
        raise ValueError("classic-bridge component signature digest is invalid")
    if payload.get("schema_version") != SIGNATURE_SCHEMA_VERSION:
        raise ValueError(
            f"classic-bridge component signature schema must be "
            f"{SIGNATURE_SCHEMA_VERSION}"
        )
    if not isinstance(excluded, list) or any(not isinstance(value, str) for value in excluded):
        raise ValueError("classic-bridge excluded-target inventory changed")
    return payload


def _signature_static_identity(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record.get(key)
        for key in (
            "logical_name",
            "selector_field",
            "selector",
            "category",
            "record",
            "is_nothing",
            "parts_config",
            "components",
            "components_hash",
            "resource_flags",
        )
    }


def validate_inactive_projection_record(
    contract: dict[str, Any], record: dict[str, Any]
) -> bool:
    """Validate a source-backed inactive selector before active-domain lookup.

    The raw selector is never substituted.  Exact Nothing and disabled
    HairFront records are matched to title Parts identities.  A lookup-empty
    record is accepted only when the exact title selector inventory proves the
    raw selector is absent and the logical role is optional.
    """

    projection = record.get("inactive_projection")
    if projection is None:
        return False
    if (
        not isinstance(projection, dict)
        or projection.get("kind") not in INACTIVE_PROJECTION_KINDS
        or projection != inactive_projection(str(projection.get("kind")))
        or record.get("enabled") is not False
        or record.get("models") != []
        or record.get("texture") is not None
    ):
        raise ValueError("classic-bridge inactive projection shape changed")
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != 1
        or contract.get("selector_semantics")
        != "raw effective CharInfo selector; never remapped"
    ):
        raise ValueError("classic-bridge inactive projection contract changed")

    logical_name = str(record.get("logical_name"))
    selector = record.get("selector")
    if type(selector) is not int or selector < 0:
        raise ValueError("classic-bridge inactive projection selector is invalid")
    kind = str(projection["kind"])
    if kind == "title_lookup_empty":
        optional_names = contract.get("optional_title_lookup_empty_logical_names")
        existing = contract.get("existing_selectors_by_logical_name")
        if (
            not isinstance(optional_names, list)
            or set(optional_names) != OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES
            or logical_name not in optional_names
            or not isinstance(existing, dict)
            or logical_name not in existing
            or not isinstance(existing[logical_name], list)
            or existing[logical_name] != sorted(set(existing[logical_name]))
            or any(type(value) is not int or value < 0 for value in existing[logical_name])
            or selector in existing[logical_name]
            or record.get("resolved") is not False
            or record.get("record") is not None
            or record.get("is_nothing") is not False
            or record.get("parts_config") is not None
            or record.get("components") != {}
            or record.get("components_hash") != {}
            or record.get("resource_flags") != {}
        ):
            raise ValueError(
                f"classic-bridge selector is not an exact optional title lookup miss: "
                f"{logical_name}:{selector}"
            )
        return True

    exact_records = contract.get("exact_records")
    if not isinstance(exact_records, list):
        raise ValueError("classic-bridge inactive exact-record inventory is missing")
    matches = [
        item
        for item in exact_records
        if item.get("logical_name") == logical_name
        and item.get("selector") == selector
        and kind in item.get("projection_kinds", [])
    ]
    if len(matches) != 1:
        raise ValueError(
            f"classic-bridge inactive selector lacks one exact title identity: "
            f"{logical_name}:{selector}"
        )
    exact = matches[0]
    if (
        record.get("resolved") is not True
        or _signature_static_identity(record) != exact.get("signature_identity")
    ):
        raise ValueError("classic-bridge inactive exact Parts identity changed")
    if kind == "exact_parts_nothing":
        if (
            record.get("is_nothing") is not True
            or not str(record.get("record", "")).endswith("Nothing")
        ):
            raise ValueError("classic-bridge exact Nothing projection changed")
    elif (
        kind != "gate_disabled"
        or logical_name != "hair_front"
        or record.get("is_nothing") is not False
        or record.get("gate") != "selected Hair.IsAttachableHairFront"
        or record.get("gate_enabled") is not False
    ):
        raise ValueError("classic-bridge HairFront gate-disabled projection changed")
    return True


def _resolve_component_capability(
    catalog: dict[str, Any], signature: dict[str, Any]
) -> dict[str, Any]:
    """Compose a capability only from individually staged exact components."""

    if catalog.get("schema_version") != 1:
        raise ValueError("classic-bridge component catalog schema must be 1")
    payload = _validate_resource_signature(signature)
    if payload.get("parts_metadata_sha256") != catalog.get("parts_metadata_sha256"):
        raise ValueError("classic-bridge Parts metadata is outside the component catalog")

    records = payload.get("records")
    required_order = catalog.get("signature_record_order")
    if not isinstance(records, list) or not isinstance(required_order, list):
        raise ValueError("classic-bridge component record inventory is missing")
    logical_names = [record.get("logical_name") for record in records]
    if logical_names != required_order or len(set(logical_names)) != len(logical_names):
        raise ValueError("classic-bridge component signature record order changed")

    domain_records = catalog.get("records")
    if not isinstance(domain_records, list):
        raise ValueError("classic-bridge component catalog has no exact Parts records")
    domain_by_selector: dict[tuple[str, int], dict[str, Any]] = {}
    for record in domain_records:
        key = (str(record.get("logical_name")), int(record.get("selector", -1)))
        if key in domain_by_selector:
            raise ValueError(f"classic-bridge component catalog duplicates {key!r}")
        domain_by_selector[key] = record

    staged_models = catalog.get("staged_models")
    staged_textures = catalog.get("staged_face_textures")
    rules = catalog.get("composition_rules")
    if not isinstance(staged_models, dict) or not isinstance(staged_textures, dict):
        raise ValueError("classic-bridge component staging evidence is missing")
    if not isinstance(rules, dict):
        raise ValueError("classic-bridge component composition rules are missing")
    inactive_projection_contract = catalog.get("inactive_projection_contract")
    if not isinstance(inactive_projection_contract, dict):
        raise ValueError("classic-bridge inactive projection contract is missing")
    normalization_contract = catalog.get("char_info_normalization")
    if (
        not isinstance(normalization_contract, dict)
        or normalization_contract.get("key")
        != "classic-title-ryujinx-usa-special-normalization-v1"
        or normalization_contract.get("order")
        != "before active Parts, face, body, model, and material selection"
        or not isinstance(normalization_contract.get("runtime_profile"), dict)
    ):
        raise ValueError("classic-bridge CharInfo normalization contract changed")
    model_admission = catalog.get("classic_model_admission")
    uses_complete_model_admission = isinstance(model_admission, dict)
    admission_logical_names = (
        "hair",
        "hair_front",
        "beard",
        "glass_primary",
        "nose",
        "ear",
    )
    admission_entries: dict[str, dict[str, Any]] = {}
    admission_selector_index: dict[str, dict[str, Any]] = {}
    if uses_complete_model_admission:
        manifest_record = model_admission.get("manifest")
        runtime_profile_record = model_admission.get("runtime_profile")
        if (
            model_admission.get("logical_names") != list(admission_logical_names)
            or not isinstance(manifest_record, dict)
            or not isinstance(runtime_profile_record, dict)
            or runtime_profile_record.get("key") != normalization_contract.get("key")
            or {
                key: runtime_profile_record.get(key)
                for key in ("path", "byte_length", "sha256")
            }
            != normalization_contract.get("runtime_profile")
            or not isinstance(model_admission.get("entries"), dict)
            or not isinstance(model_admission.get("selector_index"), dict)
        ):
            raise ValueError("classic-bridge complete model-admission contract changed")
        admission_entries = model_admission["entries"]
        admission_selector_index = model_admission["selector_index"]
        if tuple(admission_selector_index) != admission_logical_names:
            raise ValueError("classic-bridge model-admission selector inventory changed")

    records_by_name: dict[str, dict[str, Any]] = {}
    derived_models: list[str] = []
    derived_textures: list[str] = []
    selected_model_entries: dict[str, dict[str, Any]] = {}
    selected_model_entry_records: dict[str, dict[str, Any]] = {}
    for record in records:
        logical_name = str(record.get("logical_name"))
        if logical_name == INTENTIONAL_PSEUDO_RECORD:
            if record != catalog.get("intentional_pseudo_record"):
                raise ValueError("classic-bridge hair-back pseudo-record changed")
            records_by_name[logical_name] = record
            continue
        if set(record) != SIGNATURE_RECORD_KEYS:
            raise ValueError(f"classic-bridge signature record shape changed for {logical_name}")
        if validate_inactive_projection_record(inactive_projection_contract, record):
            records_by_name[logical_name] = record
            if uses_complete_model_admission and logical_name in admission_logical_names:
                selected_model_entries[logical_name] = {
                    "entry_index": -1,
                    "selector": int(record["selector"]),
                    "resource_name": None,
                    "model_role": None,
                    "model_name": None,
                    "model_index": None,
                    "inactive_projection": json.loads(
                        json.dumps(record["inactive_projection"])
                    ),
                }
                selected_model_entry_records[logical_name] = {
                    "material_textures": []
                }
            continue
        try:
            selector = int(record["selector"])
            domain = domain_by_selector[(logical_name, selector)]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                f"classic-bridge selector is outside the exact component domain: {logical_name}"
            ) from error

        static_identity = _signature_static_identity(record)
        if static_identity != domain.get("signature_identity"):
            raise ValueError(
                f"classic-bridge exact Parts/component identity changed for {logical_name}:{selector}"
            )
        if record.get("resolved") is not True:
            raise ValueError(f"classic-bridge component {logical_name} is unresolved")

        gate_kind = domain.get("gate_kind")
        if gate_kind == "hair_front":
            gate_enabled = bool(record.get("gate_enabled"))
            if record.get("gate") != "selected Hair.IsAttachableHairFront":
                raise ValueError("classic-bridge hair-front gate identity changed")
        elif gate_kind == "mole":
            gate_enabled = selector == 1
            if record.get("gate") != "face_flags.mole_enabled":
                raise ValueError("classic-bridge mole gate identity changed")
            if bool(record.get("gate_enabled")) is not gate_enabled:
                raise ValueError("classic-bridge mole selector/gate disagreement")
        else:
            gate_enabled = True
            if record.get("gate") is not None or record.get("gate_enabled") is not True:
                raise ValueError(f"classic-bridge unexpected conditional gate on {logical_name}")
        expected_enabled = not bool(record.get("is_nothing")) and gate_enabled
        if bool(record.get("enabled")) is not expected_enabled:
            raise ValueError(f"classic-bridge enabled state disagrees for {logical_name}")
        expected_models = domain.get("models", []) if expected_enabled else []
        expected_texture = domain.get("texture") if expected_enabled else None
        if record.get("models") != expected_models or record.get("texture") != expected_texture:
            raise ValueError(f"classic-bridge active resource identity changed for {logical_name}")

        if uses_complete_model_admission and logical_name in admission_logical_names:
            logical_index = admission_selector_index.get(logical_name)
            index_record = (
                logical_index.get(str(selector)) if isinstance(logical_index, dict) else None
            )
            if not isinstance(index_record, dict):
                raise ValueError(
                    f"classic-bridge model selector is outside admission: {logical_name}:{selector}"
                )
            entry_index = index_record.get("entry_index")
            compact_entry = admission_entries.get(str(entry_index))
            expected_resources = _model_unit_resources(record)
            if (
                not isinstance(entry_index, int)
                or not isinstance(compact_entry, dict)
                or compact_entry.get("logical_name") != logical_name
                or compact_entry.get("selector") != selector
                or compact_entry.get("is_nothing") != bool(record.get("is_nothing"))
                or compact_entry.get("resource_name") != index_record.get("resource_name")
                or compact_entry.get("admission_status")
                != index_record.get("admission_status")
                or not str(compact_entry.get("admission_status", "")).startswith("admitted")
                or (
                    expected_enabled
                    and expected_resources != [compact_entry.get("resource_name")]
                )
                or (not expected_enabled and expected_resources)
            ):
                raise ValueError(
                    f"classic-bridge selected model-admission entry changed: {logical_name}"
                )
            selected_model_entries[logical_name] = {
                "entry_index": entry_index,
                "selector": selector,
                "resource_name": (
                    compact_entry.get("resource_name") if expected_enabled else None
                ),
                # The exact variant is selected later from effective CharInfo
                # (ordinary/flip/reflection/hat).  Null here is intentional: the
                # resource signature alone does not contain those runtime flags.
                "model_role": None,
                "model_name": None,
                "model_index": None,
                "inactive_projection": None,
            }
            selected_model_entry_records[logical_name] = compact_entry

        for resource in _model_unit_resources(record):
            if resource not in derived_models:
                derived_models.append(resource)
        texture = record.get("texture")
        if isinstance(texture, dict):
            name = str(texture.get("name"))
            if name not in derived_textures:
                derived_textures.append(name)
        records_by_name[logical_name] = record

    if derived_models != payload.get("active_model_resources"):
        raise ValueError("classic-bridge composed model inventory disagrees with signature")
    if derived_textures != payload.get("active_texture_resources"):
        raise ValueError("classic-bridge composed texture inventory disagrees with signature")
    if uses_complete_model_admission:
        if set(selected_model_entries) != set(admission_logical_names):
            raise ValueError("classic-bridge did not resolve every model-admission selector")
        selected_model_entries = {
            name: selected_model_entries[name] for name in admission_logical_names
        }
    admitted_active_resources = {
        str(selected_model_entries[name]["resource_name"])
        for name in admission_logical_names
        if records_by_name[name].get("enabled")
    } if uses_complete_model_admission else set()
    missing_models = [
        name
        for name in derived_models
        if name not in staged_models and name not in admitted_active_resources
    ]
    missing_textures = [name for name in derived_textures if name not in staged_textures]
    if missing_models or missing_textures:
        raise ValueError(
            "classic-bridge composition has unstaged components: "
            f"models={missing_models}, face_textures={missing_textures}"
        )

    hair_attachable = bool(
        records_by_name["hair"].get("resource_flags", {}).get(
            "IsAttachableHairFront", False
        )
    )
    if bool(records_by_name["hair_front"].get("gate_enabled")) is not hair_attachable:
        raise ValueError("classic-bridge main-hair/front-hair gate disagreement")

    allowed_models = rules.get("allowed_model_resources_by_logical_name", {})
    allowed_textures = rules.get("allowed_face_textures_by_logical_name", {})
    required_active = rules.get("required_active_logical_names", [])
    allowed_nothing = rules.get("allowed_nothing_logical_names", [])
    if not isinstance(allowed_models, dict) or not isinstance(allowed_textures, dict):
        raise ValueError("classic-bridge component role rules changed")
    for logical_name, record in records_by_name.items():
        if logical_name == INTENTIONAL_PSEUDO_RECORD:
            continue
        model_resources = _model_unit_resources(record)
        allowed_for_role = allowed_models.get(logical_name, [])
        if any(resource not in allowed_for_role for resource in model_resources):
            raise ValueError(f"classic-bridge model role is not composable: {logical_name}")
        if uses_complete_model_admission and logical_name in admission_logical_names:
            # The compact entry above is the sole model-side authority.  The
            # full external manifest is hash-checked and revalidated by the
            # renderer before any variant/shape/material load.
            continue
        for resource in model_resources:
            staged = staged_models.get(resource, {})
            contract = staged.get("admission_contract")
            programs = staged.get("program_evidence")
            if (
                not isinstance(contract, dict)
                or contract.get("logical_name") != logical_name
                or not isinstance(programs, list)
                or not programs
                or any(
                    program.get("selection_status") != "exact_unique"
                    or not isinstance(program.get("resolved_program_index"), int)
                    or not isinstance(program.get("fragment_instructions_sha256"), str)
                    for program in programs
                )
            ):
                raise ValueError(
                    f"classic-bridge staged program/admission evidence changed: {logical_name}"
                )
        texture = record.get("texture")
        if isinstance(texture, dict) and texture.get("name") not in allowed_textures.get(
            logical_name, []
        ):
            raise ValueError(f"classic-bridge face-texture role is not composable: {logical_name}")
    if required_active != ["faceline"]:
        raise ValueError("classic-bridge required active-component boundary changed")
    if any(not records_by_name[name].get("enabled") for name in required_active):
        raise ValueError("classic-bridge composition lacks a required active base component")
    if allowed_nothing != []:
        raise ValueError("classic-bridge legacy Nothing-component boundary changed")
    allowed_inactive = rules.get("allowed_inactive_projection_logical_names")
    if (
        not isinstance(allowed_inactive, list)
        or set(allowed_inactive) != OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES
    ):
        raise ValueError("classic-bridge inactive-component boundary changed")
    for logical_name, record in records_by_name.items():
        if logical_name in {INTENTIONAL_PSEUDO_RECORD, "faceline"}:
            continue
        if not record.get("enabled") and (
            logical_name not in allowed_inactive
            or record.get("inactive_projection") is None
        ):
            raise ValueError(
                f"classic-bridge inactive {logical_name} lacks a source-backed projection"
            )

    optional_names = rules.get("required_disabled_logical_names", [])
    expected_disabled = [] if uses_complete_model_admission else ["hair_front"]
    if optional_names != expected_disabled:
        raise ValueError("classic-bridge unsupported optional-component boundary changed")
    if any(records_by_name[name].get("enabled") for name in optional_names):
        raise ValueError("classic-bridge composition enables an unsupported optional component")
    faceline_names = rules.get("separate_faceline_logical_names", [])
    if faceline_names != [
        "makeup_lower",
        "makeup_upper",
        "wrinkle_upper",
        "wrinkle_lower",
        "beard_short",
    ]:
        raise ValueError("classic-bridge separate faceline-layer boundary changed")
    enabled_faceline = [
        name for name in faceline_names if records_by_name[name].get("enabled")
    ]
    contracts = rules.get("faceline_contracts")
    if contracts != [CLASSIC_GENERIC_FACELINE_CONTRACT]:
        raise ValueError("classic-bridge faceline contract inventory changed")
    contract = contracts[0]
    # The ordered v2 contract also defines the exact empty draw list.  Binding
    # it unconditionally prevents the runtime from inventing a separate
    # no-faceline contract and keeps report/evidence identity uniform.
    faceline_contract = contract["key"]
    if enabled_faceline:
        allowed_names = contract["allowed_enabled_logical_names"]
        draw_order = contract["title_draw_order"]
        if (
            any(name not in allowed_names for name in enabled_faceline)
            or enabled_faceline
            != [name for name in draw_order if name in enabled_faceline]
        ):
            raise ValueError("classic-bridge generated faceline layers lack an exact contract")
        for name in enabled_faceline:
            selected_record = records_by_name[name].get("record")
            if selected_record not in contract["records"][name]:
                raise ValueError(
                    "classic-bridge generated faceline layers lack an exact contract"
                )
            expected_flags = contract["resource_flags_by_record"][name].get(
                selected_record
            )
            if (
                expected_flags is None
                or records_by_name[name].get("resource_flags") != expected_flags
            ):
                raise ValueError(
                    "classic-bridge generated faceline resource flags lack an exact contract"
                )

    required_char_info = json.loads(json.dumps(rules.get("required_char_info", {})))
    if not uses_complete_model_admission and "MiiGlass01" in derived_models:
        required_char_info["glass_lens_material_mode"] = 0
    rigid_audit = {
        name: staged_models[name]["rigid_shape_bind_audit"]
        for name in derived_models
        if name in staged_models
    }
    material_textures = list(
        dict.fromkeys(
            [
                texture_name
                for model_name in derived_models
                if model_name in staged_models
                for texture_name in staged_models[model_name].get("material_textures", [])
            ]
            + (
                [
                    texture_name
                    for logical_name in admission_logical_names
                    if records_by_name[logical_name].get("enabled")
                    for texture_name in selected_model_entry_records[logical_name].get(
                        "material_textures", []
                    )
                ]
                if uses_complete_model_admission
                else []
            )
        )
    )
    model_programs = {
        name: staged_models[name].get("program_evidence", [])
        for name in derived_models
        if name in staged_models
    }
    nose_resources = _model_unit_resources(records_by_name["nose"])
    nose_enabled = bool(records_by_name["nose"].get("enabled"))
    if (nose_enabled and len(nose_resources) != 1) or (
        not nose_enabled and nose_resources
    ):
        raise ValueError("classic-bridge composed nose resource disagrees with draw state")
    nose_resource = nose_resources[0] if nose_resources else None
    if uses_complete_model_admission:
        nose_parallax_height_scale = None
        glass_scope = None
        model_admission_scope = {
            "manifest": json.loads(json.dumps(model_admission["manifest"])),
            "runtime_profile": json.loads(json.dumps(model_admission["runtime_profile"])),
            "selected_entries": selected_model_entries,
        }
    else:
        nose_parameters = (
            staged_models[nose_resource].get("exact_parameters", {})
            if nose_resource is not None
            else {}
        )
        try:
            nose_parallax_height_scale = (
                float(nose_parameters["parallax_height_scale"])
                if nose_resource is not None
                else None
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("classic-bridge nose lacks exact parallax-height evidence") from error
        glass_scope = rules.get("glass_scope") if "MiiGlass01" in derived_models else None
        model_admission_scope = None
    if faceline_contract == CLASSIC_GENERIC_FACELINE_CONTRACT_KEY:
        faceline_target_layers = (
            "ordered source-backed MakeLower/MakeUpper/WrinkleUpper/"
            "WrinkleLower/BeardShort target"
        )
    else:
        faceline_target_layers = "all exact Nothing; any enabled layer fails before matching"
    return {
        "key": f"component_catalog_v1_{signature['sha256'][:20]}",
        "resolution_kind": "exact-components-composed",
        "resource_signature": signature,
        "required_char_info": required_char_info,
        "presentation_profile": catalog.get("presentation_profile"),
        "portable_scope": {
            "models": derived_models,
            "face_sprites": derived_textures,
            "material_textures": material_textures,
            "model_programs": model_programs,
            "nose_resource": nose_resource,
            "nose_parallax_height_scale": nose_parallax_height_scale,
            "faceline_target_layers": faceline_target_layers,
            "faceline_contract": faceline_contract,
            "rigid_shape_bind_audit": rigid_audit,
            "glass": glass_scope,
            "classic_model_admission": model_admission_scope,
            "char_info_normalization": json.loads(
                json.dumps(normalization_contract)
            ),
            "glass_title_program": (
                "all selected frame and lens materials resolve through the exact model-admission "
                "entry; title-final environment/reflection radiance remains outside the portable scope"
                if uses_complete_model_admission
                and records_by_name["glass_primary"].get("enabled")
                else "mode-0 Trs lens resolves uniquely to GameAll60 with exact uniforms/state; "
                "the frame program and final environment/reflection radiance remain unresolved"
                if glass_scope is not None
                else None
            ),
        },
    }


def active_resource_signature(
    manifest: dict[str, Any],
    *,
    repository: Path,
    packed_mii_parts_bntx: Path,
) -> dict[str, Any]:
    """Return a target/name/profile-free exact Parts/BFRES/BNTX signature."""

    if manifest.get("schema_version") != 1:
        raise ValueError("active-parts manifest schema must be 1")
    records = manifest.get("records")
    if not isinstance(records, list) or len(records) != manifest.get("selector_count"):
        raise ValueError("active-parts selector inventory changed")
    logical_names = [record.get("logical_name") for record in records]
    if len(set(logical_names)) != len(logical_names):
        raise ValueError("active-parts manifest contains duplicate logical names")
    if not packed_mii_parts_bntx.is_file():
        raise FileNotFoundError(f"packed MiiParts BNTX is missing: {packed_mii_parts_bntx}")
    packed_identity = {
        "byte_length": packed_mii_parts_bntx.stat().st_size,
        "sha256": sha256(packed_mii_parts_bntx),
    }

    signature_records: list[dict[str, Any]] = []
    active_models: list[str] = []
    active_textures: list[str] = []
    for source_record in records:
        logical_name = str(source_record["logical_name"])
        if logical_name == INTENTIONAL_PSEUDO_RECORD:
            if (
                source_record.get("category") is not None
                or source_record.get("resolved") is not False
                or source_record.get("enabled") is not False
                or source_record.get("gate")
                != "subordinate main-hair editor state; no HairBack Parts category exists"
            ):
                raise ValueError("hair_back_editor_state is not the exact intentional pseudo-record")
            signature_records.append(
                {
                    "logical_name": logical_name,
                    "selector_field": source_record.get("selector_field"),
                    "selector": source_record.get("selector"),
                    "category": None,
                    "resolved": False,
                    "enabled": False,
                    "gate": source_record.get("gate"),
                    "evidence": source_record.get("evidence"),
                }
            )
            continue
        if not source_record.get("resolved"):
            projection = source_record.get("inactive_projection")
            if (
                projection != inactive_projection("title_lookup_empty")
                or source_record.get("category") is None
                or source_record.get("enabled") is not False
                or source_record.get("record") is not None
                or source_record.get("is_nothing") not in (None, False)
                or source_record.get("parts_config") is not None
                or source_record.get("model_resources", []) != []
                or source_record.get("texture_name") is not None
                or source_record.get("components", {}) != {}
                or source_record.get("components_hash", {}) != {}
                or source_record.get("resource_flags", {}) != {}
            ):
                raise ValueError(
                    f"{logical_name} unresolved Parts selection is not the canonical "
                    "title-lookup-empty projection"
                )
            signature_records.append(
                {
                    "logical_name": logical_name,
                    "selector_field": source_record.get("selector_field"),
                    "selector": int(source_record["selector"]),
                    "category": source_record.get("category"),
                    "resolved": False,
                    "record": None,
                    "enabled": False,
                    "is_nothing": False,
                    "gate": source_record.get("gate"),
                    "gate_enabled": bool(source_record.get("gate_enabled")),
                    "parts_config": None,
                    "models": [],
                    "texture": None,
                    "components": {},
                    "components_hash": {},
                    "resource_flags": {},
                    "inactive_projection": projection,
                }
            )
            continue
        config_path = _resolve(repository, str(source_record["parts_config"]))
        config_identity = {
            "byte_length": int(source_record["parts_config_byte_length"]),
            "sha256": str(source_record["parts_config_sha256"]),
        }
        if (
            not config_path.is_file()
            or config_path.stat().st_size != config_identity["byte_length"]
            or sha256(config_path) != config_identity["sha256"]
        ):
            raise ValueError(f"{logical_name} exact Parts config changed")

        is_nothing = bool(source_record.get("is_nothing"))
        gate_enabled = bool(source_record.get("gate_enabled"))
        projection = (
            inactive_projection("exact_parts_nothing")
            if is_nothing
            else inactive_projection("gate_disabled")
            if not gate_enabled
            else None
        )
        if source_record.get("inactive_projection") != projection:
            raise ValueError(
                f"{logical_name} inactive projection disagrees with its exact Parts/gate state"
            )
        if projection is not None and source_record.get("enabled") is not False:
            raise ValueError(f"{logical_name} inactive projection cannot be enabled")
        if projection is not None and projection["kind"] == "gate_disabled" and (
            logical_name != "hair_front"
            or source_record.get("gate") != "selected Hair.IsAttachableHairFront"
        ):
            raise ValueError("only the exact HairFront attachment gate may suppress a Parts record")

        render_payload = bool(
            source_record.get("texture_name") or source_record.get("model_resources", [])
        )
        enabled = projection is None and render_payload
        if bool(source_record.get("enabled")) is not enabled:
            raise ValueError(f"{logical_name} enabled state disagrees with exact Parts payload")
        if projection is None and not render_payload:
            raise ValueError(f"{logical_name} resolved Parts record has no render payload")
        models: list[dict[str, Any]] = []
        if enabled:
            for model in source_record.get("model_resources", []):
                bfres_path = _resolve(repository, str(model["bfres"]))
                if not model.get("bfres_exists") or not bfres_path.is_file():
                    raise ValueError(f"{logical_name} selected BFRES is missing: {bfres_path}")
                models.append(
                    {
                        "role": model.get("role"),
                        "fmdb": model.get("fmdb"),
                        "resource_name": model.get("resource_name"),
                        "bfres": {
                            "byte_length": bfres_path.stat().st_size,
                            "sha256": sha256(bfres_path),
                        },
                    }
                )
                if model.get("role") == "ModelUnit":
                    active_models.append(str(model["resource_name"]))
        texture_name = source_record.get("texture_name") if enabled else None
        texture = None
        if texture_name:
            texture = {"name": str(texture_name), "packed_bntx": packed_identity}
            active_textures.append(str(texture_name))
        signature_records.append(
            {
                "logical_name": logical_name,
                "selector_field": source_record.get("selector_field"),
                "selector": int(source_record["selector"]),
                "category": source_record.get("category"),
                "resolved": True,
                "record": source_record.get("record"),
                "enabled": enabled,
                "is_nothing": is_nothing,
                "gate": source_record.get("gate"),
                "gate_enabled": gate_enabled,
                "parts_config": config_identity,
                "models": models,
                "texture": texture,
                "components": source_record.get("components", {}),
                "components_hash": source_record.get("components_hash", {}),
                "resource_flags": source_record.get("resource_flags", {}),
                "inactive_projection": projection,
            }
        )

    active_models = list(dict.fromkeys(active_models))
    active_textures = list(dict.fromkeys(active_textures))
    if active_models != manifest.get("active_model_resources"):
        raise ValueError("active primary ModelUnit inventory differs from manifest")
    if active_textures != manifest.get("active_texture_resources"):
        raise ValueError("active texture inventory differs from manifest")
    payload = {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "parts_metadata_sha256": manifest.get("parts_metadata", {}).get("sha256"),
        "records": signature_records,
        "active_model_resources": active_models,
        "active_texture_resources": active_textures,
    }
    return {
        "algorithm": "sha256(canonical-json-v1)",
        "sha256": hashlib.sha256(_canonical_bytes(payload)).hexdigest(),
        "payload": payload,
        "excluded_target_fields": [
            "target.path",
            "target.sha256",
            "target.display_name",
            "target.internal_name",
            "target.gender",
            "target.face_gender",
            "ShareMii profile/personality/voice fields",
        ],
    }


def resolve_capability(
    bundle: dict[str, Any], signature: dict[str, Any]
) -> dict[str, Any]:
    """Resolve a signature through the complete component contract.

    Frozen exact profiles are retained as provenance for the original bridge
    samples, but they must not bypass newer component, interaction, or runtime
    evidence.  A generated bundle with a component catalog therefore routes
    every input through the same resolver.  Exact-profile fallback exists only
    for reading an older bundle that predates the component catalog.
    """

    _validate_resource_signature(signature)
    if bundle.get("schema_version") != 1:
        raise ValueError("classic-bridge resource bundle schema must be 1")
    capabilities = bundle.get("capabilities")
    if not isinstance(capabilities, list):
        raise ValueError("classic-bridge resource bundle has no capabilities")
    catalog = bundle.get("component_catalog")
    if (
        bundle.get("resolution_policy") == "uniform-component-first-v1"
        and isinstance(catalog, dict)
    ):
        return _resolve_component_capability(catalog, signature)

    matches = [
        capability
        for capability in capabilities
        if capability.get("resource_signature", {}).get("sha256") == signature["sha256"]
        and capability.get("resource_signature", {}).get("payload") == signature["payload"]
    ]
    if len(matches) > 1:
        raise ValueError(
            "classic bridge requires exactly one exact resource-signature capability; "
            f"found {len(matches)} for {signature['sha256']}"
        )
    if matches:
        return matches[0]
    if isinstance(catalog, dict):
        return _resolve_component_capability(catalog, signature)
    raise ValueError(
        "classic bridge requires exactly one exact resource-signature capability; "
        f"found 0 for {signature['sha256']}"
    )


__all__ = [
    "CLASSIC_GENERIC_FACELINE_CONTRACT",
    "CLASSIC_GENERIC_FACELINE_CONTRACT_KEY",
    "INACTIVE_PROJECTION_KINDS",
    "OPTIONAL_TITLE_LOOKUP_EMPTY_LOGICAL_NAMES",
    "SEPARATE_FACELINE_TARGET_LAYERS",
    "active_resource_signature",
    "inactive_projection",
    "resolve_capability",
    "sha256",
    "validate_inactive_projection_record",
]
