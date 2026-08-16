"""Strict orchestration for the recovered title Mii renderer.

The portable renderer in :mod:`renderer.render_mii` remains useful as a
reconstruction, but it is not the title pipeline.  This module only accepts
the selected, translated title shaders and evidence-backed runtime bindings.
It can currently execute the complete MiiMask atlas.  A full GameUber scene
draw stays fail-closed until every required live buffer, sampler, camera,
animation, and environment input has a recovered producer or a captured value.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from renderer.mii_mask_gpu import (
    MiiMaskGpuRenderer,
    RenderedMiiMaskAtlas,
    validate_mii_mask_program_specification,
)
from renderer.title_shader_runner import TitleShaderBackend, TitleShaderExecutionError


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_PARTS_PATH = Path(__file__).with_name("mii_active_parts.json")
ACTIVE_PROGRAMS_PATH = Path(__file__).with_name("gameuber_active_programs.json")
EXECUTION_LEDGER_PATH = Path(__file__).with_name("title_shader_execution.json")
RUNTIME_INPUTS_PATH = Path(__file__).with_name("gameuber_runtime_inputs.json")
GAMEPLAY_CONTEXT_PATH = Path(__file__).with_name("gameplay_capture_context.json")
MII_ICON_SNAPSHOT_PATH = Path(__file__).with_name("title_mii_icon_snapshot.json")
MII_ICON_ORCHESTRATION_PATH = Path(__file__).with_name("mii_icon_draw_orchestration.json")
GSYS_CONTEXT_SHAPE_SOURCE_PATH = Path(__file__).with_name(
    "gsys_context_shape_source_trace.json"
)
GAMEUBER_ENVIRONMENT_SOURCE_PATH = Path(__file__).with_name(
    "gameuber_mii_icon_environment_source.json"
)
GLOBALUBO_SOURCE_CONTRACT_PATH = (
    REPOSITORY_ROOT / "tools" / "globalubo_recovery" / "globalubo_source_contract.json"
)

RENDER_CONTEXTS: tuple[str, ...] = ("mii-icon", "gameplay-reference")

EXPECTED_ARTIFACT_SCHEMAS: Mapping[Path, int] = {
    ACTIVE_PARTS_PATH: 1,
    ACTIVE_PROGRAMS_PATH: 1,
    EXECUTION_LEDGER_PATH: 1,
    RUNTIME_INPUTS_PATH: 3,
    GAMEPLAY_CONTEXT_PATH: 1,
    MII_ICON_SNAPSHOT_PATH: 4,
    MII_ICON_ORCHESTRATION_PATH: 1,
    GSYS_CONTEXT_SHAPE_SOURCE_PATH: 1,
    GAMEUBER_ENVIRONMENT_SOURCE_PATH: 1,
    GLOBALUBO_SOURCE_CONTRACT_PATH: 1,
}

EXPECTED_ATLAS_SOURCE_NAMES: tuple[str, ...] = (
    "geometry_source_ledger",
    "runtime_payload_ledger",
    "texture_mip_source_ledger",
)
EXPECTED_ATLAS_CASES: tuple[int, ...] = (0, 1, 2, 4, 5, 16, 17, 21)

EXACT_SCENE_PROGRAM_KEYS: tuple[str, ...] = (
    "head",
    "face_mask",
    "hair",
    "nose",
    "nose_line",
    "ear",
    "beard",
    "body_arm_tops",
    "body_tops",
    "body_elbow_tops",
    "body_foot_socks",
    "body_hand_tops",
    "body_hip_bottoms",
    "body_hip_socks",
    "body_knee_socks",
    "body_leg_socks",
    "body_shoulder_tops",
    "body_sole_socks",
    "body_thigh_socks",
    "body_waist_tops",
)
EXACT_FACE_ATLAS_PROGRAM_KEY = "mii_mask_face_compositor"
EXACT_POSTPROCESS_PROGRAM_KEY = "snapshot_pfx_mii_icon"


class TitleMiiRendererError(RuntimeError):
    """Base error for strict title-render orchestration."""


class TitleMiiTargetMismatchError(TitleMiiRendererError):
    """The live ShareMii input differs from the checked Kestron target."""


class FullTitleSceneUnavailableError(TitleMiiRendererError):
    """Full rendering was rejected because source-backed runtime inputs are missing."""

    def __init__(self, status: Mapping[str, Any]) -> None:
        self.status = status
        blockers = status["full_scene"]["blockers"]
        preview = "; ".join(str(item["summary"]) for item in blockers[:6])
        if len(blockers) > 6:
            preview += f"; ... and {len(blockers) - 6} more"
        super().__init__(
            "full title rendering remains fail-closed because source-backed runtime inputs "
            f"are missing: {preview}"
        )


@dataclass(frozen=True)
class CheckedJsonArtifact:
    """One parsed local evidence artifact and its content identity."""

    path: Path
    payload: Mapping[str, Any]
    byte_length: int
    sha256: str

    @classmethod
    def load(
        cls,
        path: Path,
        expected_schema_version: int,
        required_keys: Sequence[str],
    ) -> "CheckedJsonArtifact":
        resolved = path.resolve()
        raw = resolved.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, Mapping):
            raise TitleMiiRendererError(f"renderer artifact is not a JSON object: {resolved}")
        if payload.get("schema_version") != expected_schema_version:
            raise TitleMiiRendererError(
                f"renderer artifact {resolved} has schema {payload.get('schema_version')!r}; "
                f"expected {expected_schema_version}"
            )
        missing = [key for key in required_keys if key not in payload]
        if missing:
            raise TitleMiiRendererError(
                f"renderer artifact {resolved} lacks required fields {missing}"
            )
        return cls(
            path=resolved,
            payload=payload,
            byte_length=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        )

    def report_record(self) -> dict[str, Any]:
        try:
            relative = self.path.relative_to(REPOSITORY_ROOT)
        except ValueError:
            relative = self.path
        return {
            "path": relative.as_posix(),
            "byte_length": self.byte_length,
            "sha256": self.sha256,
        }


def _program_by_key(programs: Sequence[Mapping[str, Any]], key: str) -> Mapping[str, Any]:
    matches = [program for program in programs if str(program.get("key")) == key]
    if len(matches) != 1:
        raise TitleMiiRendererError(f"title program {key!r} is missing or duplicated")
    return matches[0]


def _blocker_summary(program_key: str, record: Any) -> str:
    if isinstance(record, str):
        detail = record
    elif isinstance(record, Mapping):
        detail = str(
            record.get("name")
            or record.get("title_name")
            or record.get("input_kind")
            or record.get("reason")
            or "unresolved runtime input"
        )
        stage = record.get("stage") or record.get("shader_stage")
        if stage:
            detail = f"{stage} {detail}"
    else:
        detail = str(record)
    return f"{program_key}: {detail}"


def _source_artifact_status(name: str, record: Mapping[str, Any]) -> dict[str, Any]:
    path = REPOSITORY_ROOT / str(record["path"])
    payload = path.read_bytes()
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    expected_length = int(record["byte_length"])
    expected_sha256 = str(record["sha256"])
    return {
        "name": name,
        "path": str(record["path"]),
        "expected_byte_length": expected_length,
        "actual_byte_length": len(payload),
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha256,
        "matches": len(payload) == expected_length and actual_sha256 == expected_sha256,
    }


def _strict_execution_blockers(
    program_key: str,
    record: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    if "hard_fail_blockers" not in record or not isinstance(
        record["hard_fail_blockers"], list
    ):
        raise TitleMiiRendererError(
            f"runtime GameUber coverage for {program_key!r} has no blocker list"
        )
    if record.get("policy") != "hard_fail; no zero/default/dummy substitution":
        raise TitleMiiRendererError(
            f"runtime GameUber coverage for {program_key!r} changed fail-closed policy"
        )
    blockers = record["hard_fail_blockers"]
    if not all(isinstance(blocker, Mapping) for blocker in blockers):
        raise TitleMiiRendererError(
            f"runtime GameUber coverage for {program_key!r} has a malformed blocker"
        )
    executable = record.get("executable")
    if not isinstance(executable, bool) or executable != (len(blockers) == 0):
        raise TitleMiiRendererError(
            f"runtime GameUber executable/blocker state is inconsistent for {program_key!r}"
        )
    return list(blockers)


def _translation_fidelity_blocker(
    program_key: str,
    program: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return a hard blocker unless the selected host translation is bit-exact."""

    fidelity = program.get("execution_fidelity")
    if not isinstance(fidelity, Mapping):
        raise TitleMiiRendererError(
            f"title shader execution fidelity is missing for {program_key!r}"
        )
    if fidelity.get("selected_stage_binaries_exact") is not True or fidelity.get(
        "stage_pairing_exact"
    ) is not True:
        raise TitleMiiRendererError(
            f"selected title shader binary identity is not exact for {program_key!r}"
        )
    if fidelity.get("host_abi_rewrite_only") is not True:
        raise TitleMiiRendererError(
            f"title shader host ABI rewrite contract changed for {program_key!r}"
        )
    bit_exact = fidelity.get("translated_execution_bit_exact")
    if not isinstance(bit_exact, bool):
        raise TitleMiiRendererError(
            f"title shader translation fidelity is malformed for {program_key!r}"
        )
    stages = program.get("stages")
    if not isinstance(stages, Mapping) or set(stages) != {"vertex", "fragment"}:
        raise TitleMiiRendererError(f"title shader stages are malformed for {program_key!r}")
    limitations: dict[str, list[Mapping[str, Any]]] = {}
    for stage_name, stage in stages.items():
        if not isinstance(stage, Mapping):
            raise TitleMiiRendererError(
                f"title shader {stage_name} stage is malformed for {program_key!r}"
            )
        stage_exact = stage.get("host_translation_bit_exact")
        stage_limitations = stage.get("translation_limitations")
        if not isinstance(stage_exact, bool) or not isinstance(stage_limitations, list) or not all(
            isinstance(record, Mapping) for record in stage_limitations
        ):
            raise TitleMiiRendererError(
                f"title shader {stage_name} fidelity is malformed for {program_key!r}"
            )
        if stage_exact != (len(stage_limitations) == 0):
            raise TitleMiiRendererError(
                f"title shader {stage_name} fidelity is inconsistent for {program_key!r}"
            )
        if stage_limitations:
            limitations[str(stage_name)] = list(stage_limitations)
    if bit_exact != (not limitations):
        raise TitleMiiRendererError(
            f"aggregate title shader fidelity is inconsistent for {program_key!r}"
        )
    if bit_exact:
        return None
    return {
        "scope": "shader_translation_fidelity",
        "program": program_key,
        "summary": (
            f"{program_key}: selected title shader binaries are exact, but the host "
            "translation is not instruction-equivalent"
        ),
        "record": {
            "translated_execution_bit_exact": False,
            "stage_limitations": limitations,
        },
    }


def _collect_checked_artifacts(value: Any, label: str = "atlas") -> list[dict[str, Any]]:
    """Authenticate every file-backed artifact record reachable from one atlas program.

    The execution ledger also contains hashes for embedded byte strings and ELF
    virtual-address ranges.  Those deliberately have no ``path`` and are checked
    by the title-execution generator/verifier, so they are not file-artifact
    records and must not be misclassified here.
    """

    records: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        artifact_keys = {"path", "byte_length", "sha256"}
        if artifact_keys.issubset(value):
            records.append(_source_artifact_status(label, value))
            return records
        for key, child in value.items():
            records.extend(_collect_checked_artifacts(child, f"{label}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            records.extend(_collect_checked_artifacts(child, f"{label}[{index}]"))
    return records


class StrictTitleMiiRenderer:
    """Evidence-only renderer for the live Kestron title pipeline."""

    def __init__(
        self,
        backend: TitleShaderBackend | None = None,
        render_context: str = "mii-icon",
    ) -> None:
        if render_context not in RENDER_CONTEXTS:
            raise ValueError(f"unsupported strict title render context {render_context!r}")
        self.backend = backend
        self.render_context = render_context
        self.active_parts = CheckedJsonArtifact.load(
            ACTIVE_PARTS_PATH, EXPECTED_ARTIFACT_SCHEMAS[ACTIVE_PARTS_PATH], ("target", "records")
        )
        self.active_programs = CheckedJsonArtifact.load(
            ACTIVE_PROGRAMS_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[ACTIVE_PROGRAMS_PATH],
            ("target", "programs"),
        )
        self.execution = CheckedJsonArtifact.load(
            EXECUTION_LEDGER_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[EXECUTION_LEDGER_PATH],
            ("programs", "direct_source_symbols"),
        )
        self.runtime_inputs = CheckedJsonArtifact.load(
            RUNTIME_INPUTS_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[RUNTIME_INPUTS_PATH],
            ("target", "programs", "rules"),
        )
        self.gameplay_context = CheckedJsonArtifact.load(
            GAMEPLAY_CONTEXT_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[GAMEPLAY_CONTEXT_PATH],
            ("image_derived_values_used", "reference_target", "explicitly_non_inferable"),
        )
        self.mii_icon_snapshot = CheckedJsonArtifact.load(
            MII_ICON_SNAPSHOT_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[MII_ICON_SNAPSHOT_PATH],
            ("resolved_profiles", "unresolved_runtime_inputs"),
        )
        self.mii_icon_orchestration = CheckedJsonArtifact.load(
            MII_ICON_ORCHESTRATION_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[MII_ICON_ORCHESTRATION_PATH],
            (
                "policy",
                "manager",
                "render_job_state_machine",
                "face_target_routing",
                "model_render_target_record_routing",
                "remaining_hard_boundary",
            ),
        )
        self.gsys_context_shape_source = CheckedJsonArtifact.load(
            GSYS_CONTEXT_SHAPE_SOURCE_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[GSYS_CONTEXT_SHAPE_SOURCE_PATH],
            ("scope", "selected_gameuber_reads", "kestron_target_values", "identity_ledger"),
        )
        self.gameuber_environment_source = CheckedJsonArtifact.load(
            GAMEUBER_ENVIRONMENT_SOURCE_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[GAMEUBER_ENVIRONMENT_SOURCE_PATH],
            (
                "policy",
                "shader_consumer_contract",
                "mii_icon_snapshot_and_environment_boundary",
                "resolution",
                "decomp_symbols",
            ),
        )
        self.globalubo_source_contract = CheckedJsonArtifact.load(
            GLOBALUBO_SOURCE_CONTRACT_PATH,
            EXPECTED_ARTIFACT_SCHEMAS[GLOBALUBO_SOURCE_CONTRACT_PATH],
            (
                "status",
                "rules",
                "constant_buffer",
                "offset_sets",
                "active_stages",
                "unproven_boundary",
                "symbol_inventory",
            ),
        )
        self._validate_live_target()
        self._validate_program_inventory()
        self._validate_reference_policy()
        self._validate_orchestration_boundary()
        self._validate_runtime_source_boundaries()
        self._validate_backend_ledger()

    def _validate_reference_policy(self) -> None:
        if self.gameplay_context.payload["image_derived_values_used"] is not False:
            raise TitleMiiRendererError("gameplay context contains image-derived renderer values")
        reference = self.gameplay_context.payload["reference_target"]
        if not isinstance(reference, Mapping):
            raise TitleMiiRendererError("gameplay reference-target record is malformed")
        if reference.get("role") != "validation_only" or reference.get(
            "supplies_renderer_parameters"
        ) is not False:
            raise TitleMiiRendererError("reference image is not restricted to validation")

    def _validate_backend_ledger(self) -> None:
        if self.backend is None:
            return
        backend_path = Path(self.backend.execution_ledger_path).resolve()
        if backend_path != self.execution.path:
            raise TitleMiiRendererError(
                "injected title backend uses a different execution-ledger path"
            )
        backend_raw = backend_path.read_bytes()
        if (
            len(backend_raw) != self.execution.byte_length
            or hashlib.sha256(backend_raw).hexdigest() != self.execution.sha256
            or self.backend.execution_ledger != self.execution.payload
        ):
            raise TitleMiiRendererError(
                "injected title backend execution ledger differs from the authenticated ledger"
            )

    def _validate_orchestration_boundary(self) -> None:
        policy = self.mii_icon_orchestration.payload["policy"]
        if not isinstance(policy, Mapping):
            raise TitleMiiRendererError("MiiIcon orchestration policy is malformed")
        expected = {
            "reference_png_used": False,
            "guessed_offsets_or_defaults_used": False,
            "full_scene_executable": False,
        }
        for key, value in expected.items():
            if policy.get(key) is not value:
                raise TitleMiiRendererError(
                    f"MiiIcon orchestration policy changed for {key!r}"
                )
        manager = self.mii_icon_orchestration.payload["manager"]
        if not isinstance(manager, Mapping) or (
            manager.get("registered_name"),
            manager.get("job_count"),
            manager.get("job_size"),
        ) != ("MiiIconMgr", 4, 0x1010):
            raise TitleMiiRendererError("MiiIcon manager/job identity changed")
        request_queue = self.mii_icon_orchestration.payload["request_queue"]
        if not isinstance(request_queue, Mapping) or (
            request_queue.get("upsert_function"),
            request_queue.get("actor_update_function"),
            request_queue.get("record_size"),
            request_queue.get("actor_request_variants"),
        ) != ("0x7101bc7160", "0x7100dbff90", 0x128, [0, 1, 2]):
            raise TitleMiiRendererError("MiiIcon request-queue identity changed")
        target_routing = self.mii_icon_orchestration.payload[
            "model_render_target_record_routing"
        ]
        if not isinstance(target_routing, Mapping) or (
            target_routing.get("replace_single_target_function"),
            target_routing.get("clear_targets_function"),
        ) != ("0x7101c696d0", "0x7101c698a0"):
            raise TitleMiiRendererError("model render-target routing identity changed")
        if target_routing.get("job_state_calls") != {
            "clear_before_callback_install": "0x7101bc9090",
            "install_manager_target": "0x7101bc9324",
            "clear_on_job_reset": "0x7101bc9e1c",
        }:
            raise TitleMiiRendererError("model render-target job-state calls changed")
        boundary = self.mii_icon_orchestration.payload["remaining_hard_boundary"]
        if not isinstance(boundary, Mapping) or boundary.get("record") != (
            "unresolved_final_gameuber_model_draw_orchestration"
        ):
            raise TitleMiiRendererError("MiiIcon final draw-orchestration boundary changed")

    def _validate_runtime_source_boundaries(self) -> None:
        """Reject any source-contract artifact that silently supplies live values."""

        environment_policy = self.gameuber_environment_source.payload["policy"]
        if not isinstance(environment_policy, Mapping):
            raise TitleMiiRendererError("GameUber environment-source policy is malformed")
        expected_environment_policy = {
            "reference_png_used": False,
            "guessed_offsets_or_defaults_used": False,
            "constructor_defaults_substituted_for_active_state": False,
            "active_environment_set_inferred_from_name_similarity": False,
            "full_scene_executable": False,
        }
        for key, value in expected_environment_policy.items():
            if key not in environment_policy or environment_policy[key] is not value:
                raise TitleMiiRendererError(
                    f"GameUber environment-source policy changed for {key!r}"
                )

        environment_resolution = self.gameuber_environment_source.payload["resolution"]
        if not isinstance(environment_resolution, Mapping):
            raise TitleMiiRendererError("GameUber environment-source resolution is malformed")
        unresolved_environment_fields = (
            "exact_active_environment_set",
            "exact_active_gsys_user4_view",
            "exact_active_gsys_user4_sampler",
            "exact_active_gsys_user4_format_dimensions_texels",
            "exact_active_selector_values",
            "exact_active_gsys_environment_9024_bytes",
        )
        for field in unresolved_environment_fields:
            if field not in environment_resolution or environment_resolution[field] is not None:
                raise TitleMiiRendererError(
                    f"uncaptured GameUber environment field {field!r} was supplied"
                )
        forbidden = environment_resolution.get("forbidden_substitutions")
        if not isinstance(forbidden, list) or not forbidden:
            raise TitleMiiRendererError(
                "GameUber environment-source boundary lacks forbidden substitutions"
            )

        consumer = self.gameuber_environment_source.payload["shader_consumer_contract"]
        if not isinstance(consumer, Mapping) or not isinstance(consumer.get("programs"), list):
            raise TitleMiiRendererError("GameUber environment consumer inventory is malformed")
        environment_programs = consumer["programs"]
        environment_keys = tuple(str(record.get("key")) for record in environment_programs)
        if environment_keys != EXACT_SCENE_PROGRAM_KEYS:
            raise TitleMiiRendererError(
                f"GameUber environment program coverage changed: {environment_keys!r}"
            )
        runtime_programs = self.runtime_inputs.payload["programs"]
        for record in environment_programs:
            key = str(record["key"])
            runtime_program = _program_by_key(runtime_programs, key)
            if int(record.get("program_index", -1)) != int(
                runtime_program.get("program_index", -2)
            ):
                raise TitleMiiRendererError(
                    f"GameUber environment/runtime program identity differs for {key!r}"
                )

        context_scope = self.gsys_context_shape_source.payload["scope"]
        if not isinstance(context_scope, Mapping):
            raise TitleMiiRendererError("Context/Shape source scope is malformed")
        buffers = context_scope.get("buffers")
        if not isinstance(buffers, list):
            raise TitleMiiRendererError("Context/Shape buffer inventory is malformed")
        buffer_identity = {
            (
                int(record.get("maxwell_constant_buffer", -1)),
                str(record.get("name")),
                int(record.get("byte_size", -1)),
            )
            for record in buffers
            if isinstance(record, Mapping)
        }
        if len(buffer_identity) != len(buffers) or buffer_identity != {
            (4, "gsys_context", 2496),
            (7, "gsys_shape", 256),
        }:
            raise TitleMiiRendererError(
                f"Context/Shape buffer identity changed: {sorted(buffer_identity)!r}"
            )
        evidence_policy = context_scope.get("evidence_policy")
        if (
            not isinstance(evidence_policy, list)
            or context_scope.get("reference_image_values_used") is not False
        ):
            raise TitleMiiRendererError(
                "Context/Shape source policy permits image-derived values"
            )

        selected_reads = self.gsys_context_shape_source.payload[
            "selected_gameuber_reads"
        ]
        if not isinstance(selected_reads, Mapping):
            raise TitleMiiRendererError("Context/Shape selected-read contract is malformed")
        templates = selected_reads.get("templates")
        program_templates = selected_reads.get("program_templates")
        if not isinstance(templates, Mapping) or not isinstance(
            program_templates, list
        ):
            raise TitleMiiRendererError("Context/Shape read templates are malformed")
        context_program_keys = tuple(
            str(record.get("program"))
            for record in program_templates
            if isinstance(record, Mapping)
        )
        if (
            len(context_program_keys) != len(program_templates)
            or context_program_keys != EXACT_SCENE_PROGRAM_KEYS
        ):
            raise TitleMiiRendererError(
                "Context/Shape selected-read program closure changed"
            )

        def checked_context_shape_offsets(
            template_name: object, buffer_name: str
        ) -> tuple[int, ...] | None:
            if template_name is None:
                return None
            values = templates.get(str(template_name))
            if not isinstance(values, list) or not all(
                isinstance(offset, int) for offset in values
            ):
                raise TitleMiiRendererError(
                    f"Context/Shape template {template_name!r} is malformed"
                )
            offsets = tuple(values)
            byte_size = 2496 if buffer_name == "gsys_context" else 256
            if offsets != tuple(sorted(set(offsets))) or any(
                offset % 4 or offset < 0 or offset >= byte_size for offset in offsets
            ):
                raise TitleMiiRendererError(
                    f"Context/Shape template {template_name!r} is not canonical"
                )
            return offsets

        contract_context_shape_rows: dict[
            tuple[str, str, str], tuple[int, ...]
        ] = {}
        for record in program_templates:
            key = str(record["program"])
            for stage, buffer_name, field in (
                ("vertex", "gsys_context", "context_vertex"),
                ("fragment", "gsys_context", "context_fragment"),
                ("vertex", "gsys_shape", "shape_vertex"),
                ("fragment", "gsys_shape", "shape_fragment"),
            ):
                offsets = checked_context_shape_offsets(record.get(field), buffer_name)
                if offsets is None:
                    continue
                identity = (key, stage, buffer_name)
                if identity in contract_context_shape_rows:
                    raise TitleMiiRendererError(
                        f"duplicate Context/Shape selected-read row {identity!r}"
                    )
                contract_context_shape_rows[identity] = offsets
        if (
            int(selected_reads.get("row_count", -1)) != 67
            or len(contract_context_shape_rows) != 67
        ):
            raise TitleMiiRendererError("Context/Shape selected-read row count changed")

        runtime_context_shape_rows: dict[
            tuple[str, str, str], tuple[int, ...]
        ] = {}
        for program in runtime_programs:
            key = str(program.get("key"))
            for stage in ("vertex", "fragment"):
                stage_record = program.get(stage)
                if not isinstance(stage_record, Mapping):
                    raise TitleMiiRendererError(
                        f"runtime Context/Shape stage is malformed for {key!r}"
                    )
                stage_buffers = stage_record.get("constant_buffers")
                if not isinstance(stage_buffers, list):
                    raise TitleMiiRendererError(
                        f"runtime Context/Shape bindings are malformed for {key!r}"
                    )
                for buffer in stage_buffers:
                    if not isinstance(buffer, Mapping) or buffer.get("name") not in {
                        "gsys_context",
                        "gsys_shape",
                    }:
                        continue
                    buffer_name = str(buffer["name"])
                    access = buffer.get("access")
                    if not isinstance(access, Mapping) or not isinstance(
                        access.get("fixed_byte_offsets"), list
                    ):
                        raise TitleMiiRendererError(
                            f"runtime Context/Shape offsets are malformed for {key!r}"
                        )
                    identity = (key, stage, buffer_name)
                    if identity in runtime_context_shape_rows:
                        raise TitleMiiRendererError(
                            f"duplicate runtime Context/Shape row {identity!r}"
                        )
                    runtime_context_shape_rows[identity] = tuple(
                        int(offset) for offset in access["fixed_byte_offsets"]
                    )
        if contract_context_shape_rows != runtime_context_shape_rows:
            raise TitleMiiRendererError(
                "Context/Shape source contract differs from selected shader reads"
            )
        claimed_context_shape_unions = selected_reads.get("union_offsets")
        if not isinstance(claimed_context_shape_unions, Mapping):
            raise TitleMiiRendererError("Context/Shape selected-read unions are malformed")
        for buffer_name in ("gsys_context", "gsys_shape"):
            actual_union = sorted(
                {
                    offset
                    for (_key, _stage, name), offsets in contract_context_shape_rows.items()
                    if name == buffer_name
                    for offset in offsets
                }
            )
            if claimed_context_shape_unions.get(buffer_name) != actual_union:
                raise TitleMiiRendererError(
                    f"{buffer_name} selected-read union changed"
                )

        target_values = self.gsys_context_shape_source.payload["kestron_target_values"]
        if not isinstance(target_values, Mapping):
            raise TitleMiiRendererError("Context/Shape Kestron-value boundary is malformed")
        if target_values.get("status") != "unresolved_live_draw_bytes":
            raise TitleMiiRendererError("Context/Shape live-byte status changed")
        if target_values.get("resolved_kestron_words") != [] or target_values.get(
            "resolved_kestron_byte_ranges"
        ) != []:
            raise TitleMiiRendererError(
                "uncaptured Kestron Context/Shape values were supplied"
            )
        draws = target_values.get("draws")
        if not isinstance(draws, list):
            raise TitleMiiRendererError("Context/Shape per-program boundary is malformed")
        draw_keys = tuple(str(record.get("program")) for record in draws)
        if draw_keys != EXACT_SCENE_PROGRAM_KEYS:
            raise TitleMiiRendererError(
                f"Context/Shape program coverage changed: {draw_keys!r}"
            )

        global_contract = self.globalubo_source_contract.payload
        if global_contract.get("status") != "BIND_BRIDGE_UNPROVEN_DO_NOT_PROMOTE":
            raise TitleMiiRendererError("GlobalUBO bind-bridge stop condition changed")
        global_rules = global_contract.get("rules")
        if not isinstance(global_rules, Mapping) or (
            global_rules.get("reference_image_used") is not False
            or global_rules.get("defaults_or_zero_fills_are_recovered_values") is not False
            or global_rules.get("only_active_program_reads_are_in_scope") is not True
            or global_rules.get("resolved_payload_words") != []
        ):
            raise TitleMiiRendererError("GlobalUBO source contract supplied unproven values")
        global_buffer = global_contract.get("constant_buffer")
        if not isinstance(global_buffer, Mapping) or (
            int(global_buffer.get("number", -1)),
            str(global_buffer.get("name")),
            str(global_buffer.get("canonical_block")),
            int(global_buffer.get("byte_size", -1)),
            int(global_buffer.get("active_stage_count", -1)),
            int(global_buffer.get("stage_read_count_with_duplicates", -1)),
            int(global_buffer.get("unique_active_dword_count", -1)),
        ) != (15, "gsys_user1", "GlobalUBO", 3376, 40, 1163, 90):
            raise TitleMiiRendererError("GlobalUBO source-contract identity changed")
        offset_sets = global_contract.get("offset_sets")
        active_stages = global_contract.get("active_stages")
        if not isinstance(offset_sets, Mapping) or not isinstance(active_stages, list):
            raise TitleMiiRendererError("GlobalUBO active-stage contract is malformed")
        contract_stage_offsets: dict[tuple[str, int, str], tuple[int, ...]] = {}
        contract_stage_order: list[tuple[str, int, str]] = []
        for record in active_stages:
            if not isinstance(record, Mapping):
                raise TitleMiiRendererError("GlobalUBO active-stage record is malformed")
            offset_set_name = str(record.get("offset_set"))
            values = offset_sets.get(offset_set_name)
            if not isinstance(values, list):
                raise TitleMiiRendererError(
                    f"GlobalUBO offset set {offset_set_name!r} is malformed"
                )
            try:
                offsets = tuple(int(str(value), 16) for value in values)
            except ValueError as exc:
                raise TitleMiiRendererError(
                    f"GlobalUBO offset set {offset_set_name!r} contains a non-hex value"
                ) from exc
            if offsets != tuple(sorted(set(offsets))) or any(
                offset % 4 or offset < 0 or offset >= 3376 for offset in offsets
            ):
                raise TitleMiiRendererError(
                    f"GlobalUBO offset set {offset_set_name!r} is not canonical"
                )
            identity = (
                str(record.get("key")),
                int(record.get("program_index", -1)),
                str(record.get("stage")),
            )
            if identity in contract_stage_offsets:
                raise TitleMiiRendererError(f"duplicate GlobalUBO stage {identity!r}")
            contract_stage_offsets[identity] = offsets
            contract_stage_order.append(identity)

        expected_global_stage_order = [
            (
                key,
                int(_program_by_key(runtime_programs, key).get("program_index", -1)),
                stage,
            )
            for key in EXACT_SCENE_PROGRAM_KEYS
            for stage in ("vertex", "fragment")
        ]
        if contract_stage_order != expected_global_stage_order:
            raise TitleMiiRendererError(
                "GlobalUBO active-stage key/order/program closure changed"
            )

        runtime_stage_offsets: dict[tuple[str, int, str], tuple[int, ...]] = {}
        for program in runtime_programs:
            key = str(program.get("key"))
            program_index = int(program.get("program_index", -1))
            strict_execution = program.get("strict_execution")
            if not isinstance(strict_execution, Mapping):
                raise TitleMiiRendererError(
                    f"runtime GlobalUBO coverage is missing for {key!r}"
                )
            for blocker in _strict_execution_blockers(key, strict_execution):
                if blocker.get("input_kind") != "constant_buffer" or int(
                    blocker.get("constant_buffer", -1)
                ) != 15:
                    continue
                offsets = blocker.get("unresolved_fixed_byte_offsets")
                if not isinstance(offsets, list) or not all(
                    isinstance(offset, int) for offset in offsets
                ):
                    raise TitleMiiRendererError(
                        f"runtime GlobalUBO offsets are malformed for {key!r}"
                    )
                identity = (key, program_index, str(blocker.get("stage")))
                runtime_stage_offsets[identity] = tuple(offsets)
        if contract_stage_offsets != runtime_stage_offsets:
            raise TitleMiiRendererError(
                "GlobalUBO source contract differs from selected shader reads"
            )
        if sum(len(offsets) for offsets in contract_stage_offsets.values()) != int(
            global_buffer["stage_read_count_with_duplicates"]
        ):
            raise TitleMiiRendererError("GlobalUBO duplicate read count changed")
        union_offsets = sorted(
            {offset for offsets in contract_stage_offsets.values() for offset in offsets}
        )
        if [f"0x{offset:x}" for offset in union_offsets] != global_buffer.get(
            "unique_active_byte_offsets"
        ):
            raise TitleMiiRendererError("GlobalUBO unique active offsets changed")
        unproven_boundary = global_contract.get("unproven_boundary")
        if not isinstance(unproven_boundary, Mapping) or not all(
            isinstance(unproven_boundary.get(field), str) and unproven_boundary[field]
            for field in ("registered_source", "required_destination", "stop_reason", "consequence")
        ):
            raise TitleMiiRendererError("GlobalUBO missing-bind boundary is malformed")

    def _validate_live_target(self) -> None:
        targets = [
            self.active_parts.payload.get("target"),
            self.active_programs.payload.get("target"),
            self.runtime_inputs.payload.get("target"),
        ]
        if not all(isinstance(target, Mapping) for target in targets):
            raise TitleMiiTargetMismatchError("a required live-target record is missing")
        expected_hashes = {str(target["sha256"]) for target in targets}
        expected_lengths = {int(target["byte_length"]) for target in targets}
        if len(expected_hashes) != 1 or len(expected_lengths) != 1:
            raise TitleMiiTargetMismatchError("renderer ledgers disagree on the live target")
        target_path = REPOSITORY_ROOT / str(targets[0]["path"])
        payload = target_path.read_bytes()
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if len(payload) not in expected_lengths or actual_sha256 not in expected_hashes:
            raise TitleMiiTargetMismatchError(
                f"{target_path} differs from the checked target: "
                f"{len(payload)} bytes, SHA-256 {actual_sha256}"
            )
        if str(targets[0].get("display_name")) != "Kestron":
            raise TitleMiiTargetMismatchError("the checked title target is not Kestron")

    def _validate_program_inventory(self) -> None:
        active = self.active_programs.payload.get("programs")
        executable = self.execution.payload.get("programs")
        runtime = self.runtime_inputs.payload.get("programs")
        if (
            not isinstance(active, list)
            or not isinstance(executable, list)
            or not isinstance(runtime, list)
        ):
            raise TitleMiiRendererError("active/executable title program inventory is malformed")
        active_keys = tuple(str(record.get("key")) for record in active)
        if active_keys != EXACT_SCENE_PROGRAM_KEYS:
            raise TitleMiiRendererError(
                f"live GameUber selection changed: {active_keys!r}"
            )
        for key in (
            *EXACT_SCENE_PROGRAM_KEYS,
            EXACT_FACE_ATLAS_PROGRAM_KEY,
            EXACT_POSTPROCESS_PROGRAM_KEY,
        ):
            _program_by_key(executable, key)
        runtime_keys = tuple(str(record.get("key")) for record in runtime)
        if runtime_keys != EXACT_SCENE_PROGRAM_KEYS:
            raise TitleMiiRendererError(
                f"runtime GameUber coverage changed: {runtime_keys!r}"
            )
        for key in EXACT_SCENE_PROGRAM_KEYS:
            active_program = _program_by_key(active, key)
            execution_program = _program_by_key(executable, key)
            runtime_program = _program_by_key(runtime, key)
            active_selection = active_program.get("selection")
            execution_selection = execution_program.get("selection")
            if not isinstance(active_selection, Mapping) or not isinstance(
                execution_selection, Mapping
            ):
                raise TitleMiiRendererError(f"shader selection is malformed for {key!r}")
            selection_triples = {
                (
                    str(active_selection.get("shader_archive")),
                    str(active_selection.get("shading_model")),
                    int(active_selection.get("program_index", -1)),
                ),
                (
                    str(execution_selection.get("archive")),
                    str(execution_selection.get("shader_model")),
                    int(execution_selection.get("program_index", -1)),
                ),
                (
                    "GameUber",
                    "GameAll",
                    int(runtime_program.get("program_index", -1)),
                ),
            }
            if selection_triples != {
                ("GameUber", "GameAll", int(active_selection["program_index"]))
            }:
                raise TitleMiiRendererError(
                    f"active/runtime/execution shader identity differs for {key!r}: "
                    f"{sorted(selection_triples)}"
                )

            runtime_stage_binaries = runtime_program.get("selected_stage_binaries")
            execution_stages = execution_program.get("stages")
            if not isinstance(runtime_stage_binaries, Mapping) or not isinstance(
                execution_stages, Mapping
            ):
                raise TitleMiiRendererError(
                    f"selected stage identity is malformed for {key!r}"
                )
            for stage, selection_field in (
                ("vertex", "vertex_binary"),
                ("fragment", "pixel_binary"),
            ):
                active_binary = active_selection.get(selection_field)
                runtime_binary = runtime_stage_binaries.get(stage)
                execution_stage = execution_stages.get(stage)
                if not all(
                    isinstance(record, Mapping)
                    for record in (active_binary, runtime_binary, execution_stage)
                ):
                    raise TitleMiiRendererError(
                        f"{stage} stage identity is malformed for {key!r}"
                    )
                if active_binary != runtime_binary:
                    raise TitleMiiRendererError(
                        f"active/runtime {stage} binary identity differs for {key!r}"
                    )
                source_binary = execution_stage.get("source_binary")
                selected_stream = active_binary.get("stream_1")
                if not isinstance(source_binary, Mapping) or not isinstance(
                    selected_stream, Mapping
                ):
                    raise TitleMiiRendererError(
                        f"execution {stage} source identity is malformed for {key!r}"
                    )
                if (
                    int(source_binary.get("byte_length", -1)),
                    str(source_binary.get("sha256")),
                ) != (
                    int(selected_stream.get("byte_length", -2)),
                    str(selected_stream.get("sha256")),
                ):
                    raise TitleMiiRendererError(
                        f"active/execution {stage} stage identity differs for {key!r}"
                    )

            runtime_constant_buffers: list[tuple[str, int, str, int]] = []
            runtime_samplers: list[tuple[str, str, int]] = []
            for stage in ("vertex", "fragment"):
                runtime_stage = runtime_program.get(stage)
                if not isinstance(runtime_stage, Mapping):
                    raise TitleMiiRendererError(
                        f"runtime {stage} interface is malformed for {key!r}"
                    )
                stage_buffers = runtime_stage.get("constant_buffers")
                stage_samplers = runtime_stage.get("samplers")
                if not isinstance(stage_buffers, list) or not isinstance(
                    stage_samplers, list
                ):
                    raise TitleMiiRendererError(
                        f"runtime {stage} bindings are malformed for {key!r}"
                    )
                for buffer in stage_buffers:
                    if not isinstance(buffer, Mapping):
                        raise TitleMiiRendererError(
                            f"runtime {stage} constant-buffer binding is malformed for {key!r}"
                        )
                    runtime_constant_buffers.append(
                        (
                            stage,
                            int(buffer.get("constant_buffer", -1)),
                            str(buffer.get("name")),
                            int(buffer.get("byte_size", -1)),
                        )
                    )
                for sampler in stage_samplers:
                    if not isinstance(sampler, Mapping):
                        raise TitleMiiRendererError(
                            f"runtime {stage} sampler binding is malformed for {key!r}"
                        )
                    runtime_samplers.append(
                        (
                            stage,
                            str(sampler.get("name")),
                            int(sampler.get("decoder_offset", -1)),
                        )
                    )

            execution_constant_buffers = execution_program.get("constant_buffers")
            execution_samplers = execution_program.get("samplers")
            if not isinstance(execution_constant_buffers, list) or not isinstance(
                execution_samplers, list
            ):
                raise TitleMiiRendererError(
                    f"execution binding interface is malformed for {key!r}"
                )
            execution_constant_buffer_identity = [
                (
                    str(buffer.get("shader_stage")),
                    int(buffer.get("maxwell_constant_buffer", -1)),
                    str(buffer.get("title_name")),
                    int(buffer.get("required_byte_length", -1)),
                )
                for buffer in execution_constant_buffers
                if isinstance(buffer, Mapping)
            ]
            execution_sampler_identity = [
                (
                    str(sampler.get("shader_stage")),
                    str(sampler.get("title_name")),
                    int(sampler.get("decoder_descriptor_offset", -1)),
                )
                for sampler in execution_samplers
                if isinstance(sampler, Mapping)
            ]
            if (
                len(execution_constant_buffer_identity)
                != len(execution_constant_buffers)
                or len(set(runtime_constant_buffers)) != len(runtime_constant_buffers)
                or len(set(execution_constant_buffer_identity))
                != len(execution_constant_buffer_identity)
                or set(runtime_constant_buffers) != set(execution_constant_buffer_identity)
            ):
                raise TitleMiiRendererError(
                    f"runtime/execution constant-buffer interface differs for {key!r}"
                )
            if (
                len(execution_sampler_identity) != len(execution_samplers)
                or len(set(runtime_samplers)) != len(runtime_samplers)
                or len(set(execution_sampler_identity)) != len(execution_sampler_identity)
                or set(runtime_samplers) != set(execution_sampler_identity)
            ):
                raise TitleMiiRendererError(
                    f"runtime/execution sampler interface differs for {key!r}"
                )

            active_identity = active_program.get("identity")
            runtime_identity = runtime_program.get("identity")
            geometry = execution_program.get("geometry")
            if not all(
                isinstance(record, Mapping)
                for record in (active_identity, runtime_identity, geometry)
            ):
                raise TitleMiiRendererError(f"geometry identity is malformed for {key!r}")
            for field in ("resource", "model", "shape", "material"):
                if active_identity.get(field) != runtime_identity.get(field):
                    raise TitleMiiRendererError(
                        f"active/runtime {field} identity differs for {key!r}"
                    )
            geometry_fields = {
                "resource": "resource_name",
                "model": "model_name",
                "shape": "shape_name",
            }
            for identity_field, geometry_field in geometry_fields.items():
                if active_identity.get(identity_field) != geometry.get(geometry_field):
                    raise TitleMiiRendererError(
                        f"active/execution {identity_field} identity differs for {key!r}"
                    )
            vertex_attributes = execution_program.get("vertex_attributes")
            if not isinstance(vertex_attributes, list) or not vertex_attributes:
                raise TitleMiiRendererError(
                    f"execution vertex-attribute identity is missing for {key!r}"
                )
            assignment_sources = [
                record.get("bfres_assignment_source")
                for record in vertex_attributes
                if isinstance(record, Mapping)
            ]
            if len(assignment_sources) != len(vertex_attributes) or not all(
                isinstance(record, Mapping) for record in assignment_sources
            ):
                raise TitleMiiRendererError(
                    f"execution BFRES assignment identity is malformed for {key!r}"
                )
            for assignment in assignment_sources:
                for field in ("resource", "model", "material"):
                    if assignment.get(field) != active_identity.get(field):
                        raise TitleMiiRendererError(
                            f"active/execution {field} assignment differs for {key!r}"
                        )

        postprocess = _program_by_key(executable, EXACT_POSTPROCESS_PROGRAM_KEY)
        postprocess_selection = postprocess.get("selection")
        if not isinstance(postprocess_selection, Mapping) or (
            postprocess_selection.get("archive"),
            postprocess_selection.get("shader_model"),
            int(postprocess_selection.get("vertex_variation_index", -1)),
            int(postprocess_selection.get("fragment_variation_index", -1)),
        ) != ("GamePfx", "SnapshotPfx", 398, 399):
            raise TitleMiiRendererError("MiiIcon SnapshotPfx shader identity changed")

    def build_status(self) -> dict[str, Any]:
        """Build a deterministic readiness report without supplying any defaults."""

        execution_programs = self.execution.payload["programs"]
        runtime_programs = self.runtime_inputs.payload["programs"]
        active_programs = self.active_programs.payload["programs"]
        blockers: list[dict[str, Any]] = []
        program_status: list[dict[str, Any]] = []
        for key in EXACT_SCENE_PROGRAM_KEYS:
            program = _program_by_key(execution_programs, key)
            runtime_program = _program_by_key(runtime_programs, key)
            active_program = _program_by_key(active_programs, key)
            strict_execution = runtime_program.get("strict_execution")
            if not isinstance(strict_execution, Mapping):
                raise TitleMiiRendererError(
                    f"runtime GameUber coverage for {key!r} has no strict-execution record"
                )
            unresolved = _strict_execution_blockers(key, strict_execution)
            fidelity_blocker = _translation_fidelity_blocker(key, program)
            selection = active_program.get("selection")
            if not isinstance(selection, Mapping) or not isinstance(
                selection.get("title_final_status"), str
            ):
                raise TitleMiiRendererError(
                    f"title-final shader selection status is malformed for {key!r}"
                )
            title_final_status = str(selection["title_final_status"])
            expected_title_final_status = (
                "contradicted standalone resolver variant; coverage requires the authored "
                "mask/runtime override"
                if key == "nose_line"
                else "audited active resolver variant"
            )
            if title_final_status != expected_title_final_status:
                raise TitleMiiRendererError(
                    f"title-final shader selection boundary changed for {key!r}"
                )
            program_status.append(
                {
                    "key": key,
                    "shader_archive": program.get("selection", {}).get("archive"),
                    "program_index": program.get("selection", {}).get("program_index"),
                    "translated_vertex": program["stages"]["vertex"]["translated_glsl"],
                    "translated_fragment": program["stages"]["fragment"]["translated_glsl"],
                    "raw_bfres_geometry": program.get("geometry"),
                    "unresolved_runtime_input_count": len(unresolved),
                    "runtime_executable": bool(strict_execution.get("executable")),
                    "runtime_policy": strict_execution.get("policy"),
                    "title_final_status": title_final_status,
                    "translated_execution_bit_exact": fidelity_blocker is None,
                }
            )
            for record in unresolved:
                blockers.append(
                    {
                        "scope": "gameuber_program",
                        "program": key,
                        "summary": _blocker_summary(key, record),
                        "record": record,
                    }
                )
            if fidelity_blocker is not None:
                blockers.append(fidelity_blocker)
            if title_final_status != "audited active resolver variant":
                blockers.append(
                    {
                        "scope": "shader_pass_selection",
                        "program": key,
                        "summary": f"{key}: {title_final_status}",
                        "record": {
                            "title_final_status": title_final_status,
                            "required_resolution": (
                                "recover the actual runtime shader/pass override; the partial "
                                "material resolver result is not a final title shader identity"
                            ),
                        },
                    }
                )

        recovered_semantics = self.active_programs.payload.get("recovered_semantics")
        if not isinstance(recovered_semantics, Mapping):
            raise TitleMiiRendererError("active GameUber semantics ledger is malformed")
        face_mask_semantics = recovered_semantics.get("face_mask")
        if not isinstance(face_mask_semantics, Mapping):
            raise TitleMiiRendererError("face-mask title coverage semantics are missing")
        face_mask_boundary = face_mask_semantics.get("title_final_coverage_boundary")
        if not isinstance(face_mask_boundary, Mapping):
            raise TitleMiiRendererError("face-mask title coverage boundary is missing")
        expected_face_mask_boundary = (
            "literal standalone GameAll 0 is contradicted; runtime override/pass remains "
            "unresolved"
        )
        if face_mask_boundary.get("status") != expected_face_mask_boundary:
            raise TitleMiiRendererError("face-mask title coverage boundary changed")
        blockers.append(
            {
                "scope": "shader_pass_selection",
                "program": "face_mask",
                "summary": (
                    "face_mask: the standalone selected GameAll program is contradicted; "
                    "the title-final coverage override/pass is unresolved"
                ),
                "record": {
                    "status": face_mask_boundary["status"],
                    "contradiction": face_mask_boundary.get("contradiction"),
                    "portable_emulation_allowed": False,
                },
            }
        )

        geometry_policy = self.execution.payload.get("geometry_policy")
        if not isinstance(geometry_policy, Mapping) or geometry_policy.get(
            "mesh_index_required_explicitly"
        ) is not True:
            raise TitleMiiRendererError("title geometry selection policy is malformed")
        mesh_records: list[dict[str, Any]] = []
        for key in EXACT_SCENE_PROGRAM_KEYS:
            geometry = _program_by_key(execution_programs, key).get("geometry")
            if not isinstance(geometry, Mapping) or geometry.get(
                "mesh_selection_policy"
            ) != "explicit_only":
                raise TitleMiiRendererError(
                    f"title mesh-selection policy is malformed for {key!r}"
                )
            mesh_records.append(
                {
                    "program": key,
                    "resource": geometry.get("resource_name"),
                    "model": geometry.get("model_name"),
                    "shape": geometry.get("shape_name"),
                    "current_host_mesh_index": 0,
                }
            )
        blockers.append(
            {
                "scope": "geometry_mesh_lod_selection",
                "program": None,
                "summary": (
                    "runtime BFRES mesh/LOD selection is unresolved; mesh 0 is an explicit "
                    "host diagnostic choice, not a recovered title draw decision"
                ),
                "record": {
                    "mesh_index_required_explicitly": True,
                    "affected_draws": mesh_records,
                },
            }
        )

        if self.render_context == "gameplay-reference":
            context_blockers = self.gameplay_context.payload["explicitly_non_inferable"]
            if not isinstance(context_blockers, list):
                raise TitleMiiRendererError("gameplay unresolved-input ledger is malformed")
            for detail in context_blockers:
                blockers.append(
                    {
                        "scope": "gameplay_capture_context",
                        "program": None,
                        "summary": f"gameplay context: {detail}",
                        "record": str(detail),
                    }
                )
        else:
            snapshot_blockers = self.mii_icon_snapshot.payload["unresolved_runtime_inputs"]
            if not isinstance(snapshot_blockers, list):
                raise TitleMiiRendererError("MiiIcon unresolved-input ledger is malformed")
            for record in snapshot_blockers:
                if not isinstance(record, Mapping):
                    raise TitleMiiRendererError("MiiIcon unresolved-input entry is malformed")
                classification = str(record.get("classification"))
                if classification not in {"unresolved", "high_confidence_inference"}:
                    raise TitleMiiRendererError(
                        f"unknown MiiIcon runtime-input classification {classification!r}"
                    )
                blockers.append(
                    {
                        "scope": "mii_icon_snapshot",
                        "program": None,
                        "summary": f"MiiIcon: {record.get('name', 'unresolved runtime input')}",
                        "record": dict(record),
                    }
                )

        orchestration_boundary = self.mii_icon_orchestration.payload["remaining_hard_boundary"]
        blockers.append(
            {
                "scope": "draw_orchestration",
                "program": None,
                "summary": "full scene: " + str(orchestration_boundary["detail"]),
                "record": str(orchestration_boundary["record"]),
            }
        )

        postprocess_program = _program_by_key(
            execution_programs, EXACT_POSTPROCESS_PROGRAM_KEY
        )
        postprocess_unresolved = postprocess_program.get("unresolved_runtime_inputs")
        if not isinstance(postprocess_unresolved, list) or not all(
            isinstance(record, str) and record for record in postprocess_unresolved
        ):
            raise TitleMiiRendererError(
                "MiiIcon SnapshotPfx unresolved-input ledger is malformed"
            )
        for record in postprocess_unresolved:
            blockers.append(
                {
                    "scope": "postprocess_program",
                    "program": EXACT_POSTPROCESS_PROGRAM_KEY,
                    "summary": f"SnapshotPfx: {record}",
                    "record": record,
                }
            )
        postprocess_fidelity_blocker = _translation_fidelity_blocker(
            EXACT_POSTPROCESS_PROGRAM_KEY, postprocess_program
        )
        if postprocess_fidelity_blocker is not None:
            blockers.append(postprocess_fidelity_blocker)

        atlas_program = _program_by_key(execution_programs, EXACT_FACE_ATLAS_PROGRAM_KEY)
        if "unresolved_runtime_inputs" not in atlas_program or not isinstance(
            atlas_program["unresolved_runtime_inputs"], list
        ):
            raise TitleMiiRendererError("face-atlas program lacks an unresolved-input list")
        atlas_unresolved = list(atlas_program["unresolved_runtime_inputs"])
        checked_draw_sources = atlas_program.get("checked_draw_sources")
        if not isinstance(checked_draw_sources, Mapping):
            raise TitleMiiRendererError("face-atlas program has no checked source ledger")
        if set(checked_draw_sources) != {*EXPECTED_ATLAS_SOURCE_NAMES, "draw_order"}:
            raise TitleMiiRendererError("face-atlas checked source names changed")
        for name in EXPECTED_ATLAS_SOURCE_NAMES:
            record = checked_draw_sources[name]
            if not isinstance(record, Mapping) or not {
                "path",
                "byte_length",
                "sha256",
            }.issubset(record):
                raise TitleMiiRendererError(
                    f"face-atlas source {name!r} is not a complete checked artifact"
                )
        expected_draw_order = [
            "pass_0 cases 0,1,2,4,5,16,17",
            "case_21 unconditional fullscreen draw",
            "pass_1 cases 0,1,2,4,5,16,17",
        ]
        if checked_draw_sources["draw_order"] != expected_draw_order:
            raise TitleMiiRendererError("face-atlas source draw order changed")

        checked_inputs = atlas_program.get("checked_draw_inputs")
        if not isinstance(checked_inputs, list) or len(checked_inputs) != 8:
            raise TitleMiiRendererError("face-atlas checked draw input count changed")
        ordered_inputs = sorted(checked_inputs, key=lambda record: int(record["draw_index"]))
        if tuple(int(record["draw_index"]) for record in ordered_inputs) != tuple(range(8)):
            raise TitleMiiRendererError("face-atlas draw indices are not contiguous")
        if tuple(int(record["dispatcher_case"]) for record in ordered_inputs) != EXPECTED_ATLAS_CASES:
            raise TitleMiiRendererError("face-atlas dispatcher cases changed")
        for record in ordered_inputs:
            case = int(record["dispatcher_case"])
            expected_passes = ["case_21"] if case == 21 else ["pass_0", "pass_1"]
            if record.get("draw_passes") != expected_passes:
                raise TitleMiiRendererError(
                    f"face-atlas draw passes changed for dispatcher case {case}"
                )
        atlas_draw_count = sum(len(record["draw_passes"]) for record in ordered_inputs)
        if atlas_draw_count != 15:
            raise TitleMiiRendererError("face-atlas title draw count changed")

        try:
            validate_mii_mask_program_specification(atlas_program)
        except (TitleShaderExecutionError, KeyError, TypeError, ValueError) as exc:
            # The shared validator uses the title-shader backend's fail-closed
            # exception family.  Normalize it at this orchestration boundary so
            # the CLI always emits a structured renderer failure instead of a
            # backend traceback.
            raise TitleMiiRendererError(
                f"face-atlas source authentication failed: {exc}"
            ) from exc

        atlas_source_checks = _collect_checked_artifacts(atlas_program)
        if not atlas_source_checks:
            raise TitleMiiRendererError("face-atlas contains no checked artifacts")
        unique_checks: dict[tuple[str, str, int], dict[str, Any]] = {}
        for record in atlas_source_checks:
            key = (
                str(record["path"]),
                str(record["expected_sha256"]),
                int(record["expected_byte_length"]),
            )
            unique_checks.setdefault(key, record)
        atlas_source_checks = list(unique_checks.values())
        atlas_sources_current = all(record["matches"] for record in atlas_source_checks)
        fidelity = atlas_program.get("execution_fidelity")
        if not isinstance(fidelity, Mapping):
            raise TitleMiiRendererError("face-atlas execution fidelity record is missing")
        host_translation_bit_exact = fidelity.get("translated_execution_bit_exact")
        if not isinstance(host_translation_bit_exact, bool):
            raise TitleMiiRendererError("face-atlas translation fidelity is malformed")
        atlas_fidelity_blocker = _translation_fidelity_blocker(
            EXACT_FACE_ATLAS_PROGRAM_KEY, atlas_program
        )
        if atlas_fidelity_blocker is not None:
            blockers.append(atlas_fidelity_blocker)
        atlas_host_executable = not atlas_unresolved and atlas_sources_current
        atlas_title_equivalent_ready = (
            atlas_host_executable and atlas_fidelity_blocker is None
        )
        return {
            "schema_version": 1,
            "renderer": "StrictTitleMiiRenderer",
            "render_context": self.render_context,
            "policy": {
                "title_shader_only": True,
                "cpu_material_fallback_allowed": False,
                "reference_png_supplies_executable_values": False,
                "unknown_runtime_values_are_defaulted": False,
            },
            "target": dict(self.active_parts.payload["target"]),
            "evidence": {
                "active_parts": self.active_parts.report_record(),
                "active_gameuber_programs": self.active_programs.report_record(),
                "title_shader_execution": self.execution.report_record(),
                "gameuber_runtime_inputs": self.runtime_inputs.report_record(),
                "gameplay_capture_context": self.gameplay_context.report_record(),
                "mii_icon_snapshot": self.mii_icon_snapshot.report_record(),
                "mii_icon_draw_orchestration": self.mii_icon_orchestration.report_record(),
                "gsys_context_shape_source_trace": self.gsys_context_shape_source.report_record(),
                "gameuber_mii_icon_environment_source": self.gameuber_environment_source.report_record(),
                "gameuber_globalubo_source_contract": self.globalubo_source_contract.report_record(),
            },
            "face_atlas": {
                "ready": atlas_title_equivalent_ready,
                "title_equivalent_ready": atlas_title_equivalent_ready,
                "source_current": atlas_sources_current,
                "host_executable": atlas_host_executable,
                "program": EXACT_FACE_ATLAS_PROGRAM_KEY,
                "shader_archive": atlas_program.get("selection", {}).get("archive"),
                "draw_count": atlas_draw_count,
                "unresolved_runtime_inputs": atlas_unresolved,
                "checked_source_artifacts": atlas_source_checks,
                "execution_fidelity": dict(fidelity),
                "translated_execution_bit_exact": host_translation_bit_exact,
                "fidelity_blockers": (
                    [] if atlas_fidelity_blocker is None else [atlas_fidelity_blocker]
                ),
            },
            "full_scene": {
                "ready": not blockers,
                "programs": program_status,
                "postprocess": {
                    "key": EXACT_POSTPROCESS_PROGRAM_KEY,
                    "selection": dict(postprocess_program["selection"]),
                    "unresolved_runtime_inputs": list(postprocess_unresolved),
                    "translated_execution_bit_exact": (
                        postprocess_fidelity_blocker is None
                    ),
                },
                "blocker_count": len(blockers),
                "blockers": blockers,
                "failure_policy": "hard_fail",
            },
        }

    def render_face_atlas(self) -> RenderedMiiMaskAtlas:
        """Execute the source-backed 15-draw translated MiiMask atlas pipeline."""

        if self.backend is None:
            raise TitleMiiRendererError("face-atlas rendering requires a title shader backend")
        status = self.build_status()
        if not status["face_atlas"]["host_executable"]:
            stale = [
                record["name"]
                for record in status["face_atlas"]["checked_source_artifacts"]
                if not record["matches"]
            ]
            raise TitleMiiRendererError(
                "source-backed face-atlas inputs are not current; regenerate the title execution "
                f"ledger after its source ledgers settle (stale={stale})"
            )
        renderer: MiiMaskGpuRenderer | None = None
        try:
            renderer = MiiMaskGpuRenderer(self.backend)
            return renderer.render_atlas()
        except TitleShaderExecutionError as exc:
            raise TitleMiiRendererError(
                f"face-atlas translated-title backend execution failed: {exc}"
            ) from exc
        finally:
            if renderer is not None:
                renderer.release()

    def render_full_scene(self) -> None:
        """Execute a full title scene only after all required inputs are source-backed."""

        status = self.build_status()
        if not status["full_scene"]["ready"]:
            raise FullTitleSceneUnavailableError(status)
        raise AssertionError("full-scene status cannot be ready before orchestration is recovered")


__all__ = [
    "EXACT_FACE_ATLAS_PROGRAM_KEY",
    "EXACT_POSTPROCESS_PROGRAM_KEY",
    "EXACT_SCENE_PROGRAM_KEYS",
    "FullTitleSceneUnavailableError",
    "RENDER_CONTEXTS",
    "StrictTitleMiiRenderer",
    "TitleMiiRendererError",
    "TitleMiiTargetMismatchError",
]
