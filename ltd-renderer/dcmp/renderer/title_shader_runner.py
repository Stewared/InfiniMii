"""Strict execution backend for the title's decoded Maxwell shader stages.

This module deliberately has no material, lighting, texture, or transform
defaults.  A draw is accepted only when every stage-local title binding is
present, or when the execution ledger contains the exact source bytes for a
program constant.  The decoder's GLSL equations are not edited; the only
source rewrite gives Maxwell's stage-local cbuf/sampler namespaces distinct
OpenGL bindings and identifiers.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXECUTION_LEDGER_PATH = Path(__file__).with_name("title_shader_execution.json")
DEFAULT_GEOMETRY_MANIFEST_PATH = Path(__file__).with_name("title_geometry") / "manifest.json"

_CONSTANT_BUFFER_DECLARATION = re.compile(
    r"layout\(binding\s*=\s*\d+\s*,\s*std430\)\s+readonly\s+buffer\s+cbuf_(\d+)"
)
_SAMPLER_DECLARATION = re.compile(
    r"^\s*uniform\s+(sampler(?:1D|2D|3D|Cube|2DArray|CubeArray)(?:Shadow)?)\s+"
    r"(SPIRV_Cross_Combinedtexture_(\d+)sampler_\d+|texture_(\d+))\s*;\s*$",
    re.MULTILINE,
)
_SAMPLER_IDENTIFIER = re.compile(
    r"\b(SPIRV_Cross_Combinedtexture_(\d+)sampler_\d+|texture_(\d+))\b"
)
_VERTEX_INPUT = re.compile(r"layout\(location\s*=\s*(\d+)\)\s+in\s+vec4\s+in_attr(\d+)\s*;")
_EXACT_CONSTANT_BUFFER_CREATION_TOKEN = object()
_EXACT_TEXTURE_CREATION_TOKEN = object()


class TitleShaderExecutionError(RuntimeError):
    """Base error for a rejected title-shader operation."""


class MissingExactShaderBindingError(TitleShaderExecutionError):
    """Raised instead of supplying a guessed cbuf, sampler, or attribute."""


class TitleShaderArtifactMismatchError(TitleShaderExecutionError):
    """Raised when a checked shader or geometry artifact changed on disk."""


@dataclass(frozen=True, order=True)
class StageConstantBufferKey:
    """Maxwell constant-buffer identity in one shader-stage namespace."""

    shader_stage: str
    maxwell_constant_buffer: int

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "StageConstantBufferKey":
        return cls(str(record["shader_stage"]), int(record["maxwell_constant_buffer"]))


@dataclass(frozen=True, order=True)
class StageSamplerKey:
    """Decoded sampler identity in one shader-stage namespace."""

    shader_stage: str
    decoder_sampler_index: int

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "StageSamplerKey":
        return cls(str(record["shader_stage"]), int(record["decoder_sampler_index"]))


@dataclass
class TitleShaderRuntimeBindings:
    """Explicit runtime resources for one draw; no fields are synthesized."""

    constant_buffers: Mapping[StageConstantBufferKey, "ExactConstantBufferBinding"] = field(
        default_factory=dict
    )
    textures: Mapping[StageSamplerKey, "ExactTextureBinding"] = field(default_factory=dict)


@dataclass(frozen=True)
class ExactConstantBufferBinding:
    """Cbuf bytes minted from a checked input proof in the execution ledger."""

    payload: bytes
    provenance: str
    source_symbols: tuple[str, ...]
    payload_sha256: str
    program_key: str
    proof_key: str
    binding_key: StageConstantBufferKey
    payload_coverage: str
    known_byte_mask_sha256: str | None
    _creation_token: Any = field(repr=False)

    def validate(self) -> bytes:
        if self._creation_token is not _EXACT_CONSTANT_BUFFER_CREATION_TOKEN:
            raise MissingExactShaderBindingError(
                "cbuf was not constructed through TitleShaderBackend.constant_buffer_from_program_proof"
            )
        if not self.provenance or not self.source_symbols:
            raise MissingExactShaderBindingError("runtime cbuf binding has no source provenance")
        if _sha256_bytes(self.payload) != self.payload_sha256:
            raise TitleShaderArtifactMismatchError(
                f"runtime cbuf payload changed after provenance capture ({self.provenance})"
            )
        if self.payload_coverage not in {"full_source_bytes", "selected_branch_required_bytes"}:
            raise MissingExactShaderBindingError(
                f"runtime cbuf has unsupported payload coverage {self.payload_coverage!r}"
            )
        if self.payload_coverage == "selected_branch_required_bytes" and not self.known_byte_mask_sha256:
            raise MissingExactShaderBindingError("branch-aware runtime cbuf has no checked known-byte mask")
        return self.payload


@dataclass(frozen=True)
class ExactTextureBinding:
    """GPU texture created from a checked artifact under a ledger-approved sampler specialization."""

    texture: Any
    provenance: str
    source_artifact: Mapping[str, Any]
    decoded_rgba_sha256: str
    decoded_size: tuple[int, int]
    sampler_specialization: str
    program_key: str
    proof_key: str
    binding_key: StageSamplerKey
    _creation_token: Any = field(repr=False)

    def validate(self, sampler_record: Mapping[str, Any]) -> Any:
        if self._creation_token is not _EXACT_TEXTURE_CREATION_TOKEN:
            raise MissingExactShaderBindingError(
                "texture was not uploaded through TitleShaderBackend.upload_checked_rgba_texture"
            )
        if not self.provenance.strip():
            raise MissingExactShaderBindingError("runtime texture binding has no source provenance")
        _checked_file_bytes(self.source_artifact)
        accepted = {
            str(record["name"]): record
            for record in sampler_record.get("accepted_host_specializations", [])
        }
        if self.sampler_specialization not in accepted:
            raise MissingExactShaderBindingError(
                f"{sampler_record['title_name']} does not accept sampler specialization "
                f"{self.sampler_specialization!r}; accepted={sorted(accepted)}"
            )
        texture_size = tuple(int(value) for value in self.texture.size)
        if texture_size != self.decoded_size:
            raise TitleShaderArtifactMismatchError(
                f"checked texture upload changed size: GPU={texture_size}, source={self.decoded_size}"
            )
        import moderngl

        if tuple(self.texture.filter) != (moderngl.LINEAR, moderngl.LINEAR):
            raise MissingExactShaderBindingError(
                f"{sampler_record['title_name']} requires linear minification/magnification"
            )
        if self.texture.repeat_x or self.texture.repeat_y:
            raise MissingExactShaderBindingError(
                "selected-native-mip specialization requires clamp-to-edge; its equivalence to "
                "the title mirror state is restricted to the checked closed-unit sprite UV domain"
            )
        if float(self.texture.anisotropy) != 1.0:
            raise MissingExactShaderBindingError(
                "selected-native-mip sampler specialization requires anisotropy 1"
            )
        if str(self.texture.swizzle) != "RGBA":
            raise MissingExactShaderBindingError(
                "selected-native-mip sampler specialization requires an RGBA texture swizzle"
            )
        gpu_payload = self.texture.read(alignment=1)
        if _sha256_bytes(gpu_payload) != self.decoded_rgba_sha256:
            raise TitleShaderArtifactMismatchError(
                "checked texture pixels changed after the backend-owned source upload"
            )
        return self.texture


@dataclass(frozen=True)
class TitleVertexAttributeBinding:
    """One GL input plus its exact source semantic."""

    buffer: Any
    moderngl_format: str
    glsl_attribute_name: str
    source_attribute_name: str


@dataclass
class LinkedTitleShaderProgram:
    """A linked ModernGL program and its normalized, auditable sources."""

    key: str
    specification: Mapping[str, Any]
    program: Any
    normalized_vertex_glsl: str
    normalized_fragment_glsl: str


@dataclass
class BoundTitleShaderResources:
    """Owns temporary GL buffers that must live through a draw."""

    constant_buffer_objects: list[Any] = field(default_factory=list)

    def release(self) -> None:
        for buffer_object in reversed(self.constant_buffer_objects):
            buffer_object.release()
        self.constant_buffer_objects.clear()


@dataclass
class TitleGeometryDraw:
    """VAO resources built only from the checked BFRES geometry pack."""

    vertex_array: Any
    vertex_buffers: list[Any]
    index_buffer: Any
    index_count: int
    mesh_index: int
    first_vertex: int

    def release(self) -> None:
        self.vertex_array.release()
        self.index_buffer.release()
        for buffer_object in reversed(self.vertex_buffers):
            buffer_object.release()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _checked_file_bytes(record: Mapping[str, Any]) -> bytes:
    path = REPOSITORY_ROOT / str(record["path"])
    payload = path.read_bytes()
    expected_length = int(record["byte_length"])
    expected_sha256 = str(record["sha256"])
    if len(payload) != expected_length or _sha256_bytes(payload) != expected_sha256:
        raise TitleShaderArtifactMismatchError(
            f"checked artifact changed: {path} (expected {expected_length} bytes, {expected_sha256})"
        )
    return payload


def _checked_source_constant_bytes(record: Mapping[str, Any]) -> bytes:
    """Authenticate embedded bytes against a checked source artifact and exact byte range."""

    payload = bytes.fromhex(str(record["source_constant_hex"]))
    if _sha256_bytes(payload) != str(record["source_constant_sha256"]):
        raise TitleShaderArtifactMismatchError("embedded source constant failed its payload hash")
    range_artifact = record.get("source_artifact")
    whole_artifact = record.get("source_constant_artifact")
    artifact = range_artifact or whole_artifact
    if not isinstance(artifact, Mapping):
        raise MissingExactShaderBindingError(
            "embedded source constant has no checked source artifact; self-hashed bytes are rejected"
        )
    source = _checked_file_bytes(artifact)
    has_source_offset = "source_byte_offset" in record
    has_source_length = "source_byte_length" in record
    if has_source_offset or has_source_length:
        if not has_source_offset or not has_source_length:
            raise MissingExactShaderBindingError(
                "embedded source constant requires explicit source_byte_offset and "
                "source_byte_length"
            )
        source_offset = int(record["source_byte_offset"])
        source_length = int(record["source_byte_length"])
        if source_offset < 0 or source_length != len(payload):
            raise TitleShaderArtifactMismatchError(
                "embedded source constant has an invalid checked source range"
            )
        if source[source_offset : source_offset + source_length] != payload:
            raise TitleShaderArtifactMismatchError(
                "embedded source constant differs from its checked source artifact range"
            )
    elif isinstance(whole_artifact, Mapping) and range_artifact is None:
        # ``source_constant_artifact`` is the ledger's explicit whole-artifact
        # mode for standalone extracted cbuf banks.  It never implies a zero
        # offset into a larger artifact: the complete checked file must be the
        # payload byte-for-byte.
        if source != payload:
            raise TitleShaderArtifactMismatchError(
                "embedded source constant differs from its checked whole-source artifact"
            )
    else:
        raise MissingExactShaderBindingError(
            "embedded source constant requires an explicit checked source range"
        )
    return payload


def _stage_identifier(shader_stage: str) -> str:
    if shader_stage not in {"vertex", "fragment"}:
        raise ValueError(f"unsupported shader stage {shader_stage!r}")
    return shader_stage


def normalize_decoded_stage_glsl(
    source: str,
    shader_stage: str,
    constant_buffer_host_bindings: Mapping[int, int],
    sampler_types: Mapping[int, str],
) -> str:
    """Namespace stage resources without changing decoded shader equations."""

    stage = _stage_identifier(shader_stage)
    declared_constant_buffers = {int(value) for value in _CONSTANT_BUFFER_DECLARATION.findall(source)}
    missing_constant_buffers = sorted(declared_constant_buffers - set(constant_buffer_host_bindings))
    if missing_constant_buffers:
        raise TitleShaderExecutionError(
            f"{stage} GLSL has unassigned cbuf indices {missing_constant_buffers}"
        )

    def replace_constant_buffer_declaration(match: re.Match[str]) -> str:
        cbuf_index = int(match.group(1))
        host_binding = int(constant_buffer_host_bindings[cbuf_index])
        return (
            f"layout(binding = {host_binding}, std430) readonly buffer "
            f"Title{stage.title()}ConstantBuffer{cbuf_index}"
        )

    normalized = _CONSTANT_BUFFER_DECLARATION.sub(replace_constant_buffer_declaration, source)
    for cbuf_index in sorted(declared_constant_buffers):
        normalized = re.sub(
            rf"\bcbuf_{cbuf_index}_1\b",
            f"title_{stage}_constant_buffer_{cbuf_index}",
            normalized,
        )

    declared_sampler_types: dict[int, set[str]] = {}
    for declaration in _SAMPLER_DECLARATION.finditer(normalized):
        sampler_index = int(declaration.group(3) or declaration.group(4))
        declared_sampler_types.setdefault(sampler_index, set()).add(declaration.group(1))
    referenced_sampler_indices = {
        int(match.group(2) or match.group(3)) for match in _SAMPLER_IDENTIFIER.finditer(normalized)
    }
    if referenced_sampler_indices != set(sampler_types):
        raise TitleShaderExecutionError(
            f"{stage} sampler ledger differs from GLSL: source={sorted(referenced_sampler_indices)}, "
            f"ledger={sorted(sampler_types)}"
        )
    for sampler_index, declared_types in declared_sampler_types.items():
        if declared_types != {sampler_types[sampler_index]}:
            raise TitleShaderExecutionError(
                f"{stage} sampler {sampler_index} type mismatch: {declared_types} versus "
                f"{sampler_types[sampler_index]}"
            )

    normalized = _SAMPLER_DECLARATION.sub("", normalized)

    def replace_sampler_identifier(match: re.Match[str]) -> str:
        sampler_index = int(match.group(2) or match.group(3))
        return f"title_{stage}_sampler_{sampler_index}"

    normalized = _SAMPLER_IDENTIFIER.sub(replace_sampler_identifier, normalized)
    sampler_declarations = "".join(
        f"uniform {sampler_types[index]} title_{stage}_sampler_{index};\n"
        for index in sorted(sampler_types)
    )
    if sampler_declarations:
        version_line_end = normalized.find("\n")
        if version_line_end < 0 or not normalized.startswith("#version"):
            raise TitleShaderExecutionError(f"{stage} GLSL has no #version line")
        normalized = (
            normalized[: version_line_end + 1]
            + "\n"
            + sampler_declarations
            + normalized[version_line_end + 1 :]
        )
    return normalized


def _program_by_key(ledger: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    matches = [program for program in ledger["programs"] if program["key"] == key]
    if len(matches) != 1:
        raise KeyError(f"title shader program {key!r} is missing or duplicated")
    return matches[0]


class TitleShaderBackend:
    """ModernGL backend that hard-fails every unresolved title input."""

    def __init__(
        self,
        context: Any,
        execution_ledger_path: Path = DEFAULT_EXECUTION_LEDGER_PATH,
    ) -> None:
        self.context = context
        self.execution_ledger_path = execution_ledger_path.resolve()
        self.execution_ledger = json.loads(self.execution_ledger_path.read_text(encoding="utf-8"))
        if self.execution_ledger.get("schema_version") != 1:
            raise TitleShaderExecutionError("unsupported title shader execution ledger schema")

    @classmethod
    def create_standalone(
        cls,
        execution_ledger_path: Path = DEFAULT_EXECUTION_LEDGER_PATH,
        minimum_opengl_version: int = 450,
    ) -> "TitleShaderBackend":
        import moderngl

        context = moderngl.create_standalone_context(require=minimum_opengl_version)
        return cls(context, execution_ledger_path)

    def link_program(self, key: str) -> LinkedTitleShaderProgram:
        specification = _program_by_key(self.execution_ledger, key)
        stage_sources: dict[str, str] = {}
        for shader_stage in ("vertex", "fragment"):
            stage_record = specification["stages"][shader_stage]
            source = _checked_file_bytes(stage_record["translated_glsl"]).decode("utf-8")
            cbuf_bindings = {
                int(record["maxwell_constant_buffer"]): int(record["host_storage_binding"])
                for record in specification["constant_buffers"]
                if record["shader_stage"] == shader_stage
            }
            sampler_types = {
                int(record["decoder_sampler_index"]): str(record["glsl_sampler_type"])
                for record in specification["samplers"]
                if record["shader_stage"] == shader_stage
            }
            stage_sources[shader_stage] = normalize_decoded_stage_glsl(
                source,
                shader_stage,
                cbuf_bindings,
                sampler_types,
            )
        program = self.context.program(
            vertex_shader=stage_sources["vertex"],
            fragment_shader=stage_sources["fragment"],
        )
        return LinkedTitleShaderProgram(
            key=key,
            specification=specification,
            program=program,
            normalized_vertex_glsl=stage_sources["vertex"],
            normalized_fragment_glsl=stage_sources["fragment"],
        )

    def constant_buffer_from_program_proof(
        self,
        linked: LinkedTitleShaderProgram,
        proof_key: str,
        binding_key: StageConstantBufferKey,
    ) -> ExactConstantBufferBinding:
        """Mint one immutable cbuf solely from a checked per-draw ledger proof."""

        proofs = [
            proof
            for proof in linked.specification.get("checked_draw_inputs", [])
            if str(proof["key"]) == proof_key
        ]
        if len(proofs) != 1:
            raise MissingExactShaderBindingError(
                f"{linked.key} checked draw input {proof_key!r} is missing or duplicated"
            )
        records = [
            record
            for record in proofs[0].get("constant_buffers", [])
            if StageConstantBufferKey.from_record(record) == binding_key
        ]
        if len(records) != 1:
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} has no unique checked {binding_key} cbuf proof"
            )
        record = records[0]
        payload = bytes.fromhex(str(record["payload_hex"]))
        expected_sha256 = str(record["payload_sha256"])
        if len(payload) != int(record["byte_length"]) or _sha256_bytes(payload) != expected_sha256:
            raise TitleShaderArtifactMismatchError(
                f"{linked.key}/{proof_key} embedded cbuf proof failed its length/hash"
            )
        source_artifact = record.get("source_artifact")
        if not isinstance(source_artifact, Mapping):
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} cbuf proof has no checked source artifact"
            )
        source = _checked_file_bytes(source_artifact)
        if "source_byte_offset" not in record:
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} cbuf proof requires explicit source_byte_offset"
            )
        source_offset = int(record["source_byte_offset"])
        if source_offset < 0 or source[source_offset : source_offset + len(payload)] != payload:
            raise TitleShaderArtifactMismatchError(
                f"{linked.key}/{proof_key} cbuf differs from its checked source artifact range"
            )
        payload_coverage = str(record.get("payload_coverage", ""))
        known_byte_mask_sha256: str | None = None
        if payload_coverage == "full_source_bytes":
            pass
        elif payload_coverage == "selected_branch_required_bytes":
            if not record.get("active_branch_required_ranges_fully_known"):
                raise MissingExactShaderBindingError(
                    f"{linked.key}/{proof_key} selected branch cbuf coverage is incomplete"
                )
            if not record.get("unknown_bytes_are_unread_host_materialization"):
                raise MissingExactShaderBindingError(
                    f"{linked.key}/{proof_key} does not prove that unclaimed bytes are unread"
                )
            mask = bytes.fromhex(str(record["known_byte_mask_hex"]))
            known_byte_mask_sha256 = str(record["known_byte_mask_sha256"])
            if len(mask) != len(payload) or _sha256_bytes(mask) != known_byte_mask_sha256:
                raise TitleShaderArtifactMismatchError(
                    f"{linked.key}/{proof_key} selected branch known-byte mask changed"
                )
            mask_artifact = record.get("known_mask_source_artifact")
            if not isinstance(mask_artifact, Mapping):
                raise MissingExactShaderBindingError(
                    f"{linked.key}/{proof_key} selected branch mask has no source artifact"
                )
            packed_mask = _checked_file_bytes(mask_artifact)
            if packed_mask[source_offset : source_offset + len(mask)] != mask:
                raise TitleShaderArtifactMismatchError(
                    f"{linked.key}/{proof_key} selected branch mask differs from its artifact"
                )
            required_word_offsets = [
                int(value) for value in record.get("active_branch_required_word_offsets", [])
            ]
            if not required_word_offsets or any(
                offset < 0
                or offset + 4 > len(mask)
                or mask[offset : offset + 4] != b"\xff" * 4
                for offset in required_word_offsets
            ):
                raise MissingExactShaderBindingError(
                    f"{linked.key}/{proof_key} selected branch requires an unclaimed cbuf word"
                )
        else:
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} cbuf proof has no accepted payload-coverage classification"
            )
        source_symbols = tuple(str(symbol) for symbol in record.get("source_symbols", []))
        provenance = str(record.get("provenance", "")).strip()
        if not provenance or not source_symbols:
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} cbuf proof has no decompiled provenance"
            )
        return ExactConstantBufferBinding(
            payload=payload,
            provenance=provenance,
            source_symbols=source_symbols,
            payload_sha256=expected_sha256,
            program_key=linked.key,
            proof_key=proof_key,
            binding_key=binding_key,
            payload_coverage=payload_coverage,
            known_byte_mask_sha256=known_byte_mask_sha256,
            _creation_token=_EXACT_CONSTANT_BUFFER_CREATION_TOKEN,
        )

    def upload_checked_program_texture(
        self,
        linked: LinkedTitleShaderProgram,
        proof_key: str,
        binding_key: StageSamplerKey,
    ) -> ExactTextureBinding:
        """Decode and upload a PNG named and hashed by one checked draw proof."""

        proofs = [
            proof
            for proof in linked.specification.get("checked_draw_inputs", [])
            if str(proof["key"]) == proof_key
        ]
        if len(proofs) != 1:
            raise MissingExactShaderBindingError(
                f"{linked.key} checked draw input {proof_key!r} is missing or duplicated"
            )
        records = [
            record
            for record in proofs[0].get("textures", [])
            if StageSamplerKey.from_record(record) == binding_key
        ]
        if len(records) != 1:
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} has no unique checked {binding_key} texture proof"
            )
        record = records[0]
        source_artifact = record["source_artifact"]
        checked_png = _checked_file_bytes(source_artifact)
        from io import BytesIO

        from PIL import Image

        with Image.open(BytesIO(checked_png)) as image:
            decoded = image.convert("RGBA")
            width, height = decoded.size
            payload = decoded.tobytes()
        expected_size = tuple(int(value) for value in record["decoded_size"])
        expected_sha256 = str(record["decoded_rgba_sha256"])
        if (width, height) != expected_size or _sha256_bytes(payload) != expected_sha256:
            raise TitleShaderArtifactMismatchError(
                f"{linked.key}/{proof_key} decoded texture differs from its checked pixel proof"
            )
        provenance = str(record.get("provenance", "")).strip()
        if not provenance:
            raise MissingExactShaderBindingError(
                f"{linked.key}/{proof_key} texture proof has no provenance"
            )
        import moderngl

        texture = self.context.texture((width, height), 4, payload, alignment=1)
        texture.filter = (moderngl.LINEAR, moderngl.LINEAR)
        texture.repeat_x = False
        texture.repeat_y = False
        texture.anisotropy = 1.0
        return ExactTextureBinding(
            texture=texture,
            provenance=provenance,
            source_artifact=dict(source_artifact),
            decoded_rgba_sha256=expected_sha256,
            decoded_size=(width, height),
            sampler_specialization=str(record["sampler_specialization"]),
            program_key=linked.key,
            proof_key=proof_key,
            binding_key=binding_key,
            _creation_token=_EXACT_TEXTURE_CREATION_TOKEN,
        )

    def bind_runtime_resources(
        self,
        linked: LinkedTitleShaderProgram,
        runtime_bindings: TitleShaderRuntimeBindings,
    ) -> BoundTitleShaderResources:
        required_constant_buffers = {
            StageConstantBufferKey.from_record(record): record
            for record in linked.specification["constant_buffers"]
        }
        unexpected_constant_buffers = set(runtime_bindings.constant_buffers) - set(required_constant_buffers)
        if unexpected_constant_buffers:
            raise MissingExactShaderBindingError(
                f"unexpected cbuf bindings for {linked.key}: {sorted(unexpected_constant_buffers)}"
            )

        resolved_payloads: dict[StageConstantBufferKey, bytes] = {}
        for binding_key, record in required_constant_buffers.items():
            if binding_key in runtime_bindings.constant_buffers:
                exact_binding = runtime_bindings.constant_buffers[binding_key]
                if not isinstance(exact_binding, ExactConstantBufferBinding):
                    raise MissingExactShaderBindingError(
                        f"{linked.key} {binding_key} must be an ExactConstantBufferBinding; "
                        "unproven raw bytes are rejected"
                    )
                if exact_binding.program_key != linked.key or exact_binding.binding_key != binding_key:
                    raise MissingExactShaderBindingError(
                        f"cbuf proof {exact_binding.proof_key!r} was minted for "
                        f"{exact_binding.program_key}/{exact_binding.binding_key}, not "
                        f"{linked.key}/{binding_key}"
                    )
                payload = exact_binding.validate()
            elif record.get("source_constant_hex") is not None:
                payload = _checked_source_constant_bytes(record)
            else:
                raise MissingExactShaderBindingError(
                    f"{linked.key} requires explicit {binding_key.shader_stage} cbuf"
                    f"[{binding_key.maxwell_constant_buffer}] ({record['title_name']})"
                )
            required_byte_length = int(record["required_byte_length"])
            if len(payload) != required_byte_length:
                raise MissingExactShaderBindingError(
                    f"{linked.key} {binding_key} is {len(payload)} bytes; exact binding requires "
                    f"{required_byte_length}"
                )
            resolved_payloads[binding_key] = payload

        required_samplers = {
            StageSamplerKey.from_record(record): record for record in linked.specification["samplers"]
        }
        if set(runtime_bindings.textures) != set(required_samplers):
            missing = sorted(set(required_samplers) - set(runtime_bindings.textures))
            unexpected = sorted(set(runtime_bindings.textures) - set(required_samplers))
            raise MissingExactShaderBindingError(
                f"{linked.key} texture bindings differ: missing={missing}, unexpected={unexpected}"
            )

        owned = BoundTitleShaderResources()
        for binding_key, payload in resolved_payloads.items():
            record = required_constant_buffers[binding_key]
            buffer_object = self.context.buffer(payload)
            buffer_object.bind_to_storage_buffer(int(record["host_storage_binding"]))
            owned.constant_buffer_objects.append(buffer_object)
        for binding_key, exact_texture in runtime_bindings.textures.items():
            record = required_samplers[binding_key]
            if not isinstance(exact_texture, ExactTextureBinding):
                raise MissingExactShaderBindingError(
                    f"{linked.key} {binding_key} must be an ExactTextureBinding; arbitrary "
                    "ModernGL Texture objects are rejected"
                )
            if exact_texture.program_key != linked.key or exact_texture.binding_key != binding_key:
                raise MissingExactShaderBindingError(
                    f"texture proof {exact_texture.proof_key!r} was minted for "
                    f"{exact_texture.program_key}/{exact_texture.binding_key}, not "
                    f"{linked.key}/{binding_key}"
                )
            texture = exact_texture.validate(record)
            texture_unit = int(record["host_texture_unit"])
            texture.use(location=texture_unit)
            uniform_name = (
                f"title_{binding_key.shader_stage}_sampler_{binding_key.decoder_sampler_index}"
            )
            linked.program[uniform_name].value = texture_unit
        return owned

    def create_vertex_array(
        self,
        linked: LinkedTitleShaderProgram,
        attribute_bindings: Sequence[TitleVertexAttributeBinding],
        index_buffer: Any | None = None,
        index_element_size: int = 4,
    ) -> Any:
        expected = {
            str(record["glsl_attribute_name"]): str(record["source_attribute_name"])
            for record in linked.specification["vertex_attributes"]
        }
        provided = {
            binding.glsl_attribute_name: binding.source_attribute_name
            for binding in attribute_bindings
        }
        if provided != expected:
            raise MissingExactShaderBindingError(
                f"{linked.key} vertex attributes differ: expected={expected}, provided={provided}"
            )
        content = [
            (binding.buffer, binding.moderngl_format, binding.glsl_attribute_name)
            for binding in attribute_bindings
        ]
        return self.context.vertex_array(
            linked.program,
            content,
            index_buffer=index_buffer,
            index_element_size=index_element_size,
        )


def _decode_signed_field(value: int, bit_count: int) -> int:
    sign_bit = 1 << (bit_count - 1)
    return value - (1 << bit_count) if value & sign_bit else value


def decode_bfres_vertex_attribute_for_gl(
    raw_stream: bytes,
    vertex_count: int,
    stride: int,
    byte_offset: int,
    bfres_format: str,
) -> tuple[bytes, str]:
    """Apply the BFRES/NVN fixed-function fetch conversion without OBJ data."""

    direct_formats: dict[str, tuple[str, int]] = {
        "Format_32_32_32_Single": ("3f4", 12),
        "Format_16_16_Single": ("2f2", 4),
        "Format_16_16_16_16_Single": ("4f2", 8),
        "Format_8_8_UInt": ("2u1", 2),
        "Format_8_8_8_8_UInt": ("4u1", 4),
    }
    if bfres_format in direct_formats:
        element_format, element_size = direct_formats[bfres_format]
        suffix_size = stride - byte_offset - element_size
        if suffix_size < 0:
            raise TitleShaderExecutionError(
                f"{bfres_format} at {byte_offset} exceeds {stride}-byte BFRES stride"
            )
        nodes: list[str] = []
        if byte_offset:
            nodes.append(f"{byte_offset}x1")
        nodes.append(element_format)
        if suffix_size:
            nodes.append(f"{suffix_size}x1")
        required_length = checked_stream_length = vertex_count * stride
        if len(raw_stream) != required_length:
            raise TitleShaderArtifactMismatchError(
                f"BFRES stream is {len(raw_stream)} bytes; {vertex_count}*{stride}={checked_stream_length}"
            )
        return raw_stream, " ".join(nodes)

    component_count: int
    decode_vertex: Any
    if bfres_format == "Format_10_10_10_2_SNorm":
        component_count = 4

        def decode_vertex(source: memoryview) -> tuple[float, ...]:
            packed = struct.unpack_from("<I", source)[0]
            signed = (
                _decode_signed_field(packed & 0x3FF, 10),
                _decode_signed_field((packed >> 10) & 0x3FF, 10),
                _decode_signed_field((packed >> 20) & 0x3FF, 10),
                _decode_signed_field((packed >> 30) & 0x3, 2),
            )
            return (
                max(-1.0, signed[0] / 511.0),
                max(-1.0, signed[1] / 511.0),
                max(-1.0, signed[2] / 511.0),
                max(-1.0, float(signed[3])),
            )

        source_element_size = 4
    elif bfres_format in {"Format_8_8_UNorm", "Format_8_8_8_8_UNorm"}:
        component_count = 2 if bfres_format == "Format_8_8_UNorm" else 4
        source_element_size = component_count

        def decode_vertex(source: memoryview) -> tuple[float, ...]:
            return tuple(int(value) / 255.0 for value in source[:component_count])

    elif bfres_format == "Format_16_16_UNorm":
        component_count = 2
        source_element_size = 4

        def decode_vertex(source: memoryview) -> tuple[float, ...]:
            values = struct.unpack_from("<HH", source)
            return values[0] / 65535.0, values[1] / 65535.0

    else:
        raise TitleShaderExecutionError(f"unsupported exact BFRES vertex format {bfres_format}")

    if byte_offset + source_element_size > stride:
        raise TitleShaderArtifactMismatchError(
            f"{bfres_format} at {byte_offset} exceeds {stride}-byte BFRES stride"
        )
    if len(raw_stream) != vertex_count * stride:
        raise TitleShaderArtifactMismatchError(
            f"BFRES stream is {len(raw_stream)} bytes; expected {vertex_count * stride}"
        )
    output = bytearray(vertex_count * component_count * sizeof_float32())
    source_view = memoryview(raw_stream)
    for vertex_index in range(vertex_count):
        source_start = vertex_index * stride + byte_offset
        values = decode_vertex(source_view[source_start : source_start + source_element_size])
        struct.pack_into(
            "<" + "f" * component_count,
            output,
            vertex_index * component_count * sizeof_float32(),
            *values,
        )
    return bytes(output), f"{component_count}f4"


def sizeof_float32() -> int:
    """Named fixed width used by canonical converted vertex streams."""

    return 4


class TitleGeometryPack:
    """Hash-check and bind the exact BFRES geometry pack."""

    def __init__(self, manifest_path: Path = DEFAULT_GEOMETRY_MANIFEST_PATH) -> None:
        self.manifest_path = manifest_path.resolve()
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if self.manifest.get("schema_version") != 1:
            raise TitleShaderExecutionError("unsupported title geometry manifest schema")

    def _shape_record(
        self,
        resource_name: str,
        model_name: str,
        shape_name: str,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
        resources = [record for record in self.manifest["resources"] if record["resource_name"] == resource_name]
        if len(resources) != 1:
            raise KeyError(f"geometry resource {resource_name!r} is missing or duplicated")
        models = [record for record in resources[0]["models"] if record["name"] == model_name]
        if len(models) != 1:
            raise KeyError(f"geometry model {resource_name}/{model_name} is missing or duplicated")
        shapes = [record for record in models[0]["shapes"] if record["name"] == shape_name]
        if len(shapes) != 1:
            raise KeyError(f"geometry shape {resource_name}/{model_name}/{shape_name} is missing or duplicated")
        return resources[0], models[0], shapes[0]

    def build_draw(
        self,
        backend: TitleShaderBackend,
        linked: LinkedTitleShaderProgram,
        mesh_index: int,
    ) -> TitleGeometryDraw:
        geometry = linked.specification.get("geometry")
        if not geometry:
            raise TitleShaderExecutionError(f"{linked.key} has no BFRES geometry record")
        _, model, shape = self._shape_record(
            str(geometry["resource_name"]),
            str(geometry["model_name"]),
            str(geometry["shape_name"]),
        )
        vertex_buffer_index = int(shape["vertex_buffer_index"])
        vertex_buffers = [
            record for record in model["vertex_buffers"]
            if int(record["vertex_buffer_index"]) == vertex_buffer_index
        ]
        if len(vertex_buffers) != 1:
            raise TitleShaderArtifactMismatchError("shape vertex buffer is missing or duplicated")
        vertex_buffer_record = vertex_buffers[0]
        attributes_by_name = {
            str(record["name"]): record for record in vertex_buffer_record["attributes"]
        }
        streams_by_index = {
            int(record["stream_index"]): record for record in vertex_buffer_record["streams"]
        }

        gl_buffers: list[Any] = []
        attribute_bindings: list[TitleVertexAttributeBinding] = []
        for expected_attribute in linked.specification["vertex_attributes"]:
            source_attribute_name = str(expected_attribute["source_attribute_name"])
            if source_attribute_name not in attributes_by_name:
                raise MissingExactShaderBindingError(
                    f"{linked.key} shape lacks exact BFRES attribute {source_attribute_name}"
                )
            attribute = attributes_by_name[source_attribute_name]
            stream = streams_by_index[int(attribute["buffer_index"])]
            raw_stream = _checked_file_bytes(stream)
            converted_stream, moderngl_format = decode_bfres_vertex_attribute_for_gl(
                raw_stream,
                int(vertex_buffer_record["vertex_count"]),
                int(stream["stride"]),
                int(attribute["byte_offset"]),
                str(attribute["format"]),
            )
            gl_buffer = backend.context.buffer(converted_stream)
            gl_buffers.append(gl_buffer)
            attribute_bindings.append(
                TitleVertexAttributeBinding(
                    buffer=gl_buffer,
                    moderngl_format=moderngl_format,
                    glsl_attribute_name=str(expected_attribute["glsl_attribute_name"]),
                    source_attribute_name=source_attribute_name,
                )
            )

        meshes = [record for record in shape["meshes"] if int(record["mesh_index"]) == mesh_index]
        if len(meshes) != 1:
            raise MissingExactShaderBindingError(
                f"{linked.key} requires an explicit existing BFRES mesh index; got {mesh_index}"
            )
        mesh = meshes[0]
        if mesh["primitive_type"] != "Triangles":
            raise TitleShaderExecutionError(
                f"unsupported exact BFRES primitive type {mesh['primitive_type']}"
            )
        canonical_indices = _checked_file_bytes(mesh["canonical_uint32_index_stream"])
        first_vertex = int(mesh["first_vertex"])
        if first_vertex:
            values = struct.unpack("<" + "I" * (len(canonical_indices) // 4), canonical_indices)
            canonical_indices = struct.pack("<" + "I" * len(values), *(value + first_vertex for value in values))
        index_buffer = backend.context.buffer(canonical_indices)
        vertex_array = backend.create_vertex_array(
            linked,
            attribute_bindings,
            index_buffer=index_buffer,
            index_element_size=4,
        )
        return TitleGeometryDraw(
            vertex_array=vertex_array,
            vertex_buffers=gl_buffers,
            index_buffer=index_buffer,
            index_count=int(mesh["index_count"]),
            mesh_index=mesh_index,
            first_vertex=first_vertex,
        )


__all__ = [
    "BoundTitleShaderResources",
    "ExactConstantBufferBinding",
    "ExactTextureBinding",
    "LinkedTitleShaderProgram",
    "MissingExactShaderBindingError",
    "StageConstantBufferKey",
    "StageSamplerKey",
    "TitleGeometryDraw",
    "TitleGeometryPack",
    "TitleShaderArtifactMismatchError",
    "TitleShaderBackend",
    "TitleShaderExecutionError",
    "TitleShaderRuntimeBindings",
    "TitleVertexAttributeBinding",
    "decode_bfres_vertex_attribute_for_gl",
    "normalize_decoded_stage_glsl",
]
