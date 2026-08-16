"""Fail-closed activation policy for a future native LTD renderer.

This module does not render pixels.  It joins the strict title-pipeline status
with independently collected native-executable, quality, and latency evidence.
Production may select a native LTD backend only when every condition is true.
An interpreter launcher, guest-ISA emulator, software rasterizer, or compiled
wrapper around the portable Python renderer is deliberately ineligible.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping


NATIVE_LTD_BACKEND_EVIDENCE_SCHEMA = 1
NATIVE_LTD_MAX_P95_MS = 1_000.0
NATIVE_LTD_MIN_BENCHMARK_SAMPLES = 10
NATIVE_LTD_MIN_SOURCE_FIXTURES = 4
NATIVE_LTD_REQUIRED_VIEWS = ("portrait", "full-body")
NATIVE_LTD_BACKEND_KIND = "compiled-host-native-gpu"
COMPILED_BINARY_FORMATS = frozenset({"PE", "ELF", "MACH-O"})


class NativeLtdBackendUnavailable(RuntimeError):
    """Raised when code attempts to activate an unproven native backend."""

    def __init__(self, audit: Mapping[str, Any]) -> None:
        self.audit = dict(audit)
        blockers = list(audit.get("activation_blockers", ()))
        preview = "; ".join(str(item.get("message", "unknown blocker")) for item in blockers[:5])
        if len(blockers) > 5:
            preview += f"; ... and {len(blockers) - 5} more"
        super().__init__(f"native LTD backend is not activation-ready: {preview}")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _records(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [record for record in value if isinstance(record, Mapping)]


def _blocker(code: str, message: str, **detail: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "message": message}
    if detail:
        result["detail"] = detail
    return result


def summarize_title_blockers(strict_status: Mapping[str, Any]) -> dict[str, Any]:
    """Return stable counts without copying the large forensic blocker records."""

    full_scene = _mapping(strict_status.get("full_scene"))
    blockers = _records(full_scene.get("blockers"))
    by_scope = Counter(str(record.get("scope") or "unknown") for record in blockers)
    by_input_kind: Counter[str] = Counter()
    for record in blockers:
        nested = record.get("record")
        input_kind = nested.get("input_kind") if isinstance(nested, Mapping) else None
        by_input_kind[str(input_kind or "other")] += 1
    return {
        "total": len(blockers),
        "by_scope": dict(sorted(by_scope.items())),
        "by_input_kind": dict(sorted(by_input_kind.items())),
    }


def _evaluate_strict_title_status(
    strict_status: Mapping[str, Any], blockers: list[dict[str, Any]]
) -> None:
    if strict_status.get("schema_version") != 1 or strict_status.get("renderer") != "StrictTitleMiiRenderer":
        blockers.append(_blocker(
            "STRICT_STATUS_INVALID",
            "The candidate is not bound to the authenticated strict title-renderer status.",
        ))
        return

    expected_policy = {
        "title_shader_only": True,
        "cpu_material_fallback_allowed": False,
        "reference_png_supplies_executable_values": False,
        "unknown_runtime_values_are_defaulted": False,
    }
    if _mapping(strict_status.get("policy")) != expected_policy:
        blockers.append(_blocker(
            "TITLE_POLICY_NOT_STRICT",
            "The title status permits a fallback, reference-derived value, or runtime default.",
        ))

    face_atlas = _mapping(strict_status.get("face_atlas"))
    if (
        face_atlas.get("ready") is not True
        or face_atlas.get("title_equivalent_ready") is not True
        or face_atlas.get("translated_execution_bit_exact") is not True
        or face_atlas.get("fidelity_blockers") not in ([], ())
    ):
        blockers.append(_blocker(
            "FACE_ATLAS_NOT_TITLE_EQUIVALENT",
            "The face-atlas shader path is host-executable but not title-equivalent.",
        ))

    full_scene = _mapping(strict_status.get("full_scene"))
    title_blockers = _records(full_scene.get("blockers"))
    reported_count = full_scene.get("blocker_count")
    if full_scene.get("ready") is not True:
        blockers.append(_blocker(
            "FULL_SCENE_NOT_READY",
            "The strict title renderer still rejects the full Mii scene.",
        ))
    if reported_count != 0 or title_blockers:
        blockers.append(_blocker(
            "FULL_SCENE_HAS_BLOCKERS",
            "The strict title renderer has unresolved full-scene inputs or fidelity gaps.",
            reported_count=reported_count,
            actual_count=len(title_blockers),
        ))

    programs = _records(full_scene.get("programs"))
    if len(programs) != 20:
        blockers.append(_blocker(
            "SCENE_PROGRAM_INVENTORY_INCOMPLETE",
            "The exact twenty-program GameUber scene inventory is not activation-ready.",
            program_count=len(programs),
        ))
    if any(
        program.get("runtime_executable") is not True
        or program.get("unresolved_runtime_input_count") != 0
        for program in programs
    ):
        blockers.append(_blocker(
            "SCENE_PROGRAM_INPUTS_UNRESOLVED",
            "One or more GameUber programs still lack exact runtime inputs.",
        ))
    if any(program.get("translated_execution_bit_exact") is not True for program in programs):
        blockers.append(_blocker(
            "SCENE_SHADER_TRANSLATION_NOT_EXACT",
            "One or more selected GameUber shaders are not instruction-equivalent on the host.",
        ))

    postprocess = _mapping(full_scene.get("postprocess"))
    if (
        postprocess.get("translated_execution_bit_exact") is not True
        or postprocess.get("unresolved_runtime_inputs") not in ([], ())
    ):
        blockers.append(_blocker(
            "POSTPROCESS_NOT_TITLE_EQUIVALENT",
            "SnapshotPfx inputs, geometry, or translated instructions remain unresolved.",
        ))


def _evaluate_candidate(
    candidate: Mapping[str, Any] | None, blockers: list[dict[str, Any]]
) -> None:
    if candidate is None:
        blockers.append(_blocker(
            "NATIVE_CANDIDATE_MISSING",
            "No audited compiled native LTD renderer candidate exists.",
        ))
        return
    if candidate.get("schema_version") != NATIVE_LTD_BACKEND_EVIDENCE_SCHEMA:
        blockers.append(_blocker(
            "NATIVE_CANDIDATE_SCHEMA_INVALID",
            "The native candidate evidence schema is missing or unsupported.",
        ))
    if candidate.get("backend_kind") != NATIVE_LTD_BACKEND_KIND:
        blockers.append(_blocker(
            "NATIVE_BACKEND_KIND_INVALID",
            "The backend is not an audited compiled host-native GPU renderer.",
        ))

    executable = _mapping(candidate.get("executable"))
    if (
        executable.get("verified") is not True
        or executable.get("binary_format") not in COMPILED_BINARY_FORMATS
        or not isinstance(executable.get("byte_length"), int)
        or executable.get("byte_length", 0) <= 0
        or not isinstance(executable.get("sha256"), str)
        or len(executable.get("sha256", "")) != 64
    ):
        blockers.append(_blocker(
            "COMPILED_EXECUTABLE_NOT_VERIFIED",
            "The candidate executable bytes and native binary format have not been verified.",
        ))

    execution = _mapping(candidate.get("execution"))
    required_true = ("host_native_binary", "host_gpu_driver")
    required_false = (
        "guest_instruction_emulation",
        "interpreted_runtime",
        "software_rasterizer",
        "portable_cpu_fallback",
        "spawns_renderer_child_process",
    )
    for field in required_true:
        if execution.get(field) is not True:
            blockers.append(_blocker(
                "NATIVE_EXECUTION_CONTRACT_INVALID",
                f"Native execution evidence does not prove {field}.",
                field=field,
            ))
    for field in required_false:
        if execution.get(field) is not False:
            blockers.append(_blocker(
                "FORBIDDEN_EXECUTION_MODE",
                f"Native activation forbids {field}.",
                field=field,
            ))

    source_audit = _mapping(candidate.get("source_audit"))
    if (
        source_audit.get("complete") is not True
        or not isinstance(source_audit.get("translation_unit_count"), int)
        or source_audit.get("translation_unit_count", 0) < 1
        or source_audit.get("forbidden_dependency_count") != 0
    ):
        blockers.append(_blocker(
            "NATIVE_SOURCE_AUDIT_INCOMPLETE",
            "The complete native entrypoint/source dependency closure has not passed audit.",
        ))

    quality = _mapping(candidate.get("quality"))
    views = quality.get("views")
    fixture_count = quality.get("source_fixture_count")
    compared_count = quality.get("compared_output_count")
    expected_outputs = (
        fixture_count * len(NATIVE_LTD_REQUIRED_VIEWS)
        if isinstance(fixture_count, int) and fixture_count >= 0
        else NATIVE_LTD_MIN_SOURCE_FIXTURES * len(NATIVE_LTD_REQUIRED_VIEWS)
    )
    views_are_complete = isinstance(views, list) and tuple(views) == NATIVE_LTD_REQUIRED_VIEWS
    if (
        quality.get("corpus_kind") != "accepted-title-output-corpus"
        or not isinstance(fixture_count, int)
        or fixture_count < NATIVE_LTD_MIN_SOURCE_FIXTURES
        or not views_are_complete
        or not isinstance(compared_count, int)
        or compared_count < expected_outputs
    ):
        blockers.append(_blocker(
            "QUALITY_CORPUS_INCOMPLETE",
            "Both views of the accepted native-LTD fixture corpus have not been compared.",
        ))
    if (
        quality.get("pixel_mismatch_count") != 0
        or quality.get("output_hash_mismatch_count") != 0
        or quality.get("missing_output_count") != 0
        or quality.get("renderer_output_stable") is not True
    ):
        blockers.append(_blocker(
            "QUALITY_PARITY_FAILED",
            "The native candidate does not preserve every accepted output pixel and hash.",
        ))

    benchmark = _mapping(candidate.get("benchmark"))
    sample_count = benchmark.get("sample_count")
    p95_ms = benchmark.get("p95_ms")
    if (
        benchmark.get("benchmark_kind") != "cold-process-end-to-end"
        or benchmark.get("size") != 512
        or not isinstance(sample_count, int)
        or sample_count < NATIVE_LTD_MIN_BENCHMARK_SAMPLES
        or benchmark.get("includes_decode") is not True
        or benchmark.get("includes_render") is not True
        or benchmark.get("includes_png_encoding") is not True
        or not isinstance(p95_ms, (int, float))
    ):
        blockers.append(_blocker(
            "NATIVE_BENCHMARK_INVALID",
            "The candidate lacks a sufficient cold end-to-end 512px benchmark.",
        ))
    elif float(p95_ms) > NATIVE_LTD_MAX_P95_MS:
        blockers.append(_blocker(
            "NATIVE_LATENCY_TARGET_MISSED",
            "The native candidate misses the one-second end-to-end p95 target.",
            p95_ms=float(p95_ms),
            maximum_p95_ms=NATIVE_LTD_MAX_P95_MS,
        ))


def evaluate_native_ltd_backend(
    strict_status: Mapping[str, Any],
    candidate_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate all production activation conditions without side effects."""

    blockers: list[dict[str, Any]] = []
    _evaluate_strict_title_status(strict_status, blockers)
    _evaluate_candidate(candidate_evidence, blockers)
    return {
        "schema_version": 1,
        "backend": "LTD",
        "native_definition": (
            "compiled host-native executable using the host GPU driver; no guest-ISA "
            "emulation, interpreted renderer, software rasterizer, or portable CPU fallback"
        ),
        "ready": not blockers,
        "latency_target": {
            "benchmark_kind": "cold-process-end-to-end",
            "size": 512,
            "maximum_p95_ms": NATIVE_LTD_MAX_P95_MS,
            "minimum_samples": NATIVE_LTD_MIN_BENCHMARK_SAMPLES,
        },
        "quality_target": {
            "corpus_kind": "accepted-title-output-corpus",
            "minimum_source_fixtures": NATIVE_LTD_MIN_SOURCE_FIXTURES,
            "required_views": list(NATIVE_LTD_REQUIRED_VIEWS),
            "allowed_pixel_mismatches": 0,
        },
        "title_blocker_summary": summarize_title_blockers(strict_status),
        "activation_blockers": blockers,
    }


def require_native_ltd_backend_ready(
    strict_status: Mapping[str, Any],
    candidate_evidence: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    """Return the audit or raise; this is the only intended activation gate."""

    audit = evaluate_native_ltd_backend(strict_status, candidate_evidence)
    if not audit["ready"]:
        raise NativeLtdBackendUnavailable(audit)
    return audit


__all__ = [
    "COMPILED_BINARY_FORMATS",
    "NATIVE_LTD_BACKEND_EVIDENCE_SCHEMA",
    "NATIVE_LTD_BACKEND_KIND",
    "NATIVE_LTD_MAX_P95_MS",
    "NATIVE_LTD_MIN_BENCHMARK_SAMPLES",
    "NATIVE_LTD_MIN_SOURCE_FIXTURES",
    "NATIVE_LTD_REQUIRED_VIEWS",
    "NativeLtdBackendUnavailable",
    "evaluate_native_ltd_backend",
    "require_native_ltd_backend_ready",
    "summarize_title_blockers",
]
