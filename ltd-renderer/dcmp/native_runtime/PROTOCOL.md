# LTD native runtime boundary

`ltd_native_runtime.exe` is an isolated, persistent native Windows process. It
does not launch or embed Python. The current implementation intentionally owns
the process/protocol boundary, ShareMii LTD v2/v3 parsing, native PartsIndex
selection (with checked active-parts manifest ingestion retained for compatibility),
immutable asset indexing, and decoded OBJ/UV/PNG/material
metadata caches. It also owns a bounded BodyBaseDefault/IconPose scene
verification path through pose/skinning, camera, projection, triangle setup,
coverage, and source-authenticated bilinear texture probes. The executable now
links the frozen multi-model scene assembler, material scheduler, draw
descriptor builder, draw ABI2, face runtime, LTD facepaint decoder,
postprocess, native PNG module, native material/face/scene adapters, and the
render-pipeline orchestrator. `render_ltd` owns the complete accepted native
render, PNG, report, and two-file output transaction for its exact admitted
domain. Inputs outside that domain fail closed so the app can retain its
existing renderer fallback.

## Build and launch

```powershell
& .\native_runtime\build.ps1
.\native_runtime\build\ltd_native_runtime.exe --probe
.\native_runtime\build\ltd_native_runtime.exe
```

The build copies an x64 `libzstd.dll` and the pinned
`native_png_zlib1.dll` beside the executable. Override zstd discovery
with `-ZstdDll C:\path\libzstd.dll` or `INFINIMII_NATIVE_ZSTD_DLL`. At runtime,
the environment override is checked first and the sibling DLL second. No DLL
is loaded from the request file's directory.

## JSONL protocol v1

One UTF-8 JSON object is read from stdin per line and exactly one compact UTF-8
JSON object is written to stdout. The process flushes after every response.
Requests are capped at 64 KiB, duplicate object keys are rejected, protocol
protocol-version numbers are integral, and unknown request fields fail closed.

Every request has these fields:

```json
{"protocol":"infinimii.ltd-native-runtime","version":1,"request_id":"unique-id","op":"readiness"}
```

Every response repeats `protocol`, `version`, `request_id`, and `op`, then has
either `{"ok":true,"result":...}` or
`{"ok":false,"error":{"code":"...","message":"..."}}`. A request that is
too malformed to expose its identifiers returns JSON `null` for those fields.
An error affects only its request; the persistent process continues.

Operations:

- `hello`: returns runtime version, native PID, and persistent process model.
- `readiness`: returns linked module identities, the exact admitted-output
  coverage, and `activation_ready:true` only when the zstd and native-PNG
  backends, Parts/material catalogs, source pins, and all native render
  contracts authenticate. The runtime opens and SHA-256-authenticates the
  sibling `native_png_zlib1.dll` during this check. Missing zstd forces
  `activation_ready:false` and `capabilities.native_render:false`, but an
  independently authenticated PNG backend remains
  `capabilities.native_png:true`. A missing PNG backend or one whose bytes do
  not match the build pin forces `activation_ready:false`,
  `capabilities.native_render:false`, and `capabilities.native_png:false`.
  Every degraded state includes a concrete dependency blocker; parser and PNG
  capabilities that do not need the missing dependency remain separately
  reportable. Readiness releases its backend handle after this probe. Every
  `render_ltd` request therefore reopens the sibling with write/delete sharing
  denied, hashes the bytes through that retained handle, and keeps the handle
  alive through encoder teardown. Replacing or mutating the DLL after a green
  readiness response cannot reuse stale trust: the same worker rejects that
  render with `NATIVE_RENDER_PNG_BACKEND` before creating either output file.
- `parse_ltd`: requires a UTF-8 `path`; optional `validate_zstd` defaults to
  true. Returns native LTD metadata, CharInfoEx, personality/voice, names,
  sexuality bytes, section offsets, payload hashes, and validation records.
- `prepare_assets`: authenticates one LTD and checked active-parts manifest,
  validates live selectors/gates/target identity and every declared Parts
  hash, then returns an immutable OBJ/material/texture source index. Required
  fields are `repository_root`, `ltd_path`, `active_parts_path`, `model_root`,
  `face_texture_root`, and `material_texture_roots`.
- `prepare_decoded_assets`: accepts the same fields as `prepare_assets`, then
  also populates process-resident immutable decoded caches and returns exact
  cache metadata:
  - OBJ float64 stream counts/hashes, fan-triangulated topology, and group
    triangle counts matching `software_renderer.load_obj`;
  - exporter sidecar `_uN` float64 channel coverage and hashes, with strict
    schema/range validation;
  - every selected PNG/source/mip decoded by Windows Imaging Component to
    row-major straight RGBA8, with dimensions, byte hash, and alpha counts;
  - selected BFRES catalog materials normalized into ordered resource/model/
    material records with shader identity, texture/sampler names, parameter
    names, and render-info names.
- `prepare_native_parts`: replaces `active_parts_path` with `catalog_path` and
  accepts the other `prepare_decoded_assets` fields unchanged. The executable
  pins the catalog to SHA-256
  `d8d56e7ee1e291e2e4cc213ef88521b594093a83952747f1d3c8ab0ca5b00523`,
  extracts the exact 152-byte CharInfoEx section from the authenticated LTD,
  performs special-origin normalization and all 23 PartsIndex selections in
  native C++, then feeds the resulting models/textures/configs into the same
  immutable asset and decoded-cache preparation path. It returns the usual
  `asset_index`/`decoded_cache` plus `native_parts`, containing the effective
  CharInfo bytes, normalization result, all records, active inventories, and
  live catalog identity. The expected hash is compiled/build-pinned; requests
  cannot replace it.
- `verify_scene_pipeline`: accepts all `prepare_decoded_assets` fields plus
  `pose_path`, `view` (`bust` or `full_body`), and `output_size` (exactly 128
  or 512). It first runs the complete checked asset boundary, then executes a
  bounded, native-only BodyBaseDefault/IconPose probe:
  - EulerXYZ world matrices and palette skinning;
  - float32 CharInfo body scale and recovered bust/full-body camera math;
  - perspective transform/projection and all BodyBase triangle setups;
  - coverage for at most 64 accepted triangles and 4,194,304 fragments;
  - clamp/repeat/mirror bilinear samples from the first authenticated decoded
    texture in the immutable asset index;
  - stable counts, source seals, raw hashes, tolerance-safe quantized hashes,
    module ABI versions, and stage timings.
  It returns no pixels and explicitly reports `pixels_produced: false` and
  `activation_ready: false`. The fixed draw-state vector proves the scheduling
  ABI; it is not a generated complete production draw list.
- `render_ltd`: the activated app-facing render boundary. It requires
  `repository_root`, `ltd_path`, `catalog_path`, `model_root`,
  `face_texture_root`, `material_texture_roots`, `pose_path`, an existing
  `output_dir`, `view` (`portrait` or `full_body`), `output_size` (128 or
  512), and these exact nested records:

  ```json
  {
    "supersampling":{"profile":"native-resolution-v1","raster_size":128},
    "presentation_context":{"kind":"none","sha256":"cd70c8439a2ea7f6948a85179a90b1bcad4fe38f07aba5cc737b1b72b08e6a2e"}
  }
  ```

  It verifies every linked ABI/contract, runs native Parts selection and full
  decoded-asset preparation, seals the one-frame EulerXYZ `IconPose`, decodes
  v3 canvas/UGC facepaint, builds the source-authenticated FacePlan and typed
  material bundle, assembles every selected model, executes the single mixed
  draw schedule (including NoseLine12), transfers straight RGBA8, and encodes
  the exact accepted PNG through the pinned sibling zlib-ng backend. Readiness
  also binds material catalog
  `86248cb6a85b55e60d32fb621d114ee96d9144ede4d05b62503e6fffa5197640`
  to source bundle
  `44714a22fdf3848ff70c65ce07a559e60dff87852b5c93829bcb94a23e935b10`.

  Admission is deliberately finite: the exact SHA-256 identities of `mii0`,
  `mii1`, `mii2`, and `mii4`, portrait/full-body, and 128/512 at native
  resolution (16 cases). Any other LTD, size, view, presentation context,
  source mutation, module mutation, or catalog mutation returns an error and
  writes nothing. Request rejection is not a worker-health failure; the Node
  adapter preserves the existing renderer fallback.

  A successful request stages the PNG and report under unique names inside
  the canonical `output_dir`, flushes both, then publishes only
  `mii.png`/`mii_full_body.png` and `render_report.json`. Report publication is
  the transaction marker. A failed stage or commit removes staged files and
  rolls back a newly published PNG; it never leaves a one-file success.

  The response is metadata only and reports `activation_ready:true`,
  `pixels_produced:true`, `png_produced:true`, `files_written:true`, exact
  input/output/report SHA-256 values, canonical output/report paths, completed
  stage timings (including staged write, flush, publish, and cleanup time in
  `report_and_write`/`total`), `transaction_cleanup_complete:true`, and the
  same parsed `render_report` object written to disk.
  The report has exactly one output record. Portrait uses
  `appearance_bust_portrait`; full body uses `posed_full_body`; both record
  square size/raster dimensions, `native-resolution-v1`, submitted triangle
  identities/counts, and the PNG hash.

  The canonical `kind:none` presentation report is app-validator compatible:
  `for_hat:false`, null source-hair/favorite-color values, identical inactive
  `infinimii-favorite-shirt-v1` records in presentation context and
  presentation outfit, inactive classic-bridge legacy headwear, null
  attachment headwear, no `for_hat` model selection, no legacy-headwear
  material or submitted-triangle key, and the exact 23-record
  `sha256(canonical-json-v1)` classic resource signature/capability key derived
  from native Parts selection. Capability provenance is never inferred from a
  name, LTD path, or caller-supplied profile.

  The admitted final-file SHA-256 matrix is fixed. These hashes cover the PNG
  file bytes returned by the pinned encoder, not only decoded pixels:

  | fixture | input LTD SHA-256 | portrait 128 | portrait 512 | full body 128 | full body 512 |
  | --- | --- | --- | --- | --- | --- |
  | `mii0` | `1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef` | `93b3857e4366c61ddc294d23c158dd4b4e4f8e4f55e2592d8908317059da2152` | `c112ec1c32caa183df27127c62042d273f900e3ed5be678160f935578b62e1bf` | `58ff5987824e83f76cca2abe012ee9a08e0b5b70c9b0e8a61353453508a8879b` | `97bb0bd0550fc1c060a5748fdb3fe775befb4a3fa23f642635ddb496924accc0` |
  | `mii1` | `c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b` | `1eb93d0f586e3f61d7b3a87181294114193f5b496d1a3aa855ec36a9e8b62e35` | `49e46e53f728198eeb218ac6d1222e4327a96962adfad00bebb97256b32c9f63` | `a05183d6458237fd8b528230ea233d71f65be0aa18fea3ad320fcdeb8743a598` | `7a87b37fe1173aed65183aaac622b412188f390723346612d00e899f2e954e88` |
  | `mii2` | `aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d` | `cd445204d52d02c7cdbf3d37def66fcfffe223ed31281dd50b6bd2ab3bdb7f3c` | `6fc44e3b4a84bc7dd7e6126247236b6e2c3362268a236a82ecbd0d53ffd55840` | `9fede701225f5be472c2e85e5f969d3b67eee1a8494d7d48b56c859a13e2d38a` | `b418b534c7a42d703aa228fb271e6715c414d203fe40b144f02790ffb858a8a4` |
  | `mii4` | `966fa6bf82aa46c8e5b9f16842982a3b715b86ccd1933f540044b05b8d3fc391` | `903c4d6e8955a922123411b9b04c5e7d7b0a0176549b996cf52b48c80b1d7a61` | `bcc70fb08c66f34aaf4957c222a9ec94d6a30c104695280a1b25871462d53c38` | `cea9c7ff700631770faa9ef28f9bf8feb4c6b0897aff320cff380789685a4292` | `74637f5943a74cef9f8da685d20c661c454f827c70625861f36c2e3a5469257c` |

  The corresponding classic-bridge signature binding is:

  | fixture | capability key | 23-record resource signature SHA-256 |
  | --- | --- | --- |
  | `mii0` | `component_catalog_v1_bbfd5c0ab4028defec1d` | `bbfd5c0ab4028defec1db8d94c735dcf9f8bc29f5e8555f017f8524b906263e0` |
  | `mii1` | `component_catalog_v1_020cfdb6f8fc2f0b417c` | `020cfdb6f8fc2f0b417c29a3b6752014d1680f7ad438a589db38a0b84fcd5c91` |
  | `mii2` | `component_catalog_v1_89178a7180174d322c20` | `89178a7180174d322c20fa737fd418a103d5f96139b47d8aff01bfb781884103` |
  | `mii4` | `component_catalog_v1_456e3a50cefdf7e6186d` | `456e3a50cefdf7e6186de80e1e80e62f7fe874b45290074c5baf9b52db668185` |
- `shutdown`: acknowledges the request and exits cleanly after writing it.

`parse_ltd` caps input at 64 MiB. With validation enabled, declared payloads
must be exactly one zstd frame with a declared decoded size no larger than
16 MiB; decompression must produce exactly that size. A false header flag with
non-empty payload or a true flag with an empty payload is rejected. V3 canvas
frame delimiting itself requires zstd even if validation is disabled, because
the UGC marker is required to follow that frame exactly. V2 retains the
authoritative last-`a3a3a3` marker rule.
The dynamically loaded ABI uses the official `ZSTD_CONTENTSIZE_UNKNOWN ==
UINT64_MAX` and `ZSTD_CONTENTSIZE_ERROR == UINT64_MAX - 1` sentinels; the
verifier reconstructs an unknown-content-size v3 frame and requires the
distinct `LTD_ZSTD_UNKNOWN_SIZE` result.

Active-parts, native-Parts, and decoded-asset requests fail closed on target, CharInfo,
selector, gate, record-count, declared-size, declared-hash, path, inventory,
or material-texture ambiguity. Source bytes are authenticated on every request;
once a path is pinned, any changed size or SHA-256 is rejected for the process
lifetime. Decode-cache hits therefore eliminate OBJ/PNG decoding but do not
skip source authentication. The cache is capped at 256 OBJ entries, 16,384
texture entries, and 1 GiB of decoded resident data.

`prepare_decoded_assets` does not return pixel buffers or mesh arrays over
JSONL. Those remain resident inside the executable for later scene/raster
stages; the protocol exposes deterministic counts and hashes for parity tests.
The current "compiled material" record is normalized, authenticated catalog
metadata. It is not executable GameUber semantics and is not described as such.

`verify_scene_pipeline` hashes IEEE-754 intermediate buffers inside the EXE.
It additionally reports signed-int64 hashes after rounding floats to six
decimal places; these are the cross-language parity contract for operations
whose independently verified C and NumPy implementations can differ below the
published module tolerances. Raw hashes must remain identical across repeated
requests and reproducible builds. The operation authenticates every source on
each request, so its current wall time includes source sealing and is not a
renderer latency claim.

## Activated scope and boundaries

Implemented in this executable:

- Windows process lifecycle and deterministic JSONL response serialization;
- strict request parsing and validation;
- bounded native file I/O and SHA-256 via Windows CNG;
- LTD v2/v3 headers, CharInfoEx, personality/voice, UTF-16 names, sexuality,
  marker, offset, and payload parsing;
- dynamically loaded native zstd frame delimiting and bounded decompression;
- checked active-parts ingestion and live-LTD validation;
- source-authenticated native PartsIndex selection, including special-origin
  normalization, HairFront/mole gates, exact Nothing/unresolved rules, and
  ordered active model/texture inventories;
- process-lifetime immutable source sealing and OBJ/material/texture indexing;
- native OBJ topology and named-UV parsing;
- native WIC PNG-to-RGBA8 decoding and resident texture/mip caching;
- normalized selected-material metadata compilation;
- native float32 body scaling, attachment, bust/full-body camera math, and
  stable draw-state scheduling (scene-math ABI v1);
- native EulerXYZ world matrices and smooth/rigid palette skinning (pose ABI
  v1);
- native transforms, perspective projection, triangle bounds, denominator,
  and culling setup (geometry ABI v1);
- bounded native sample-center coverage/depth tests and RGBA64 bilinear
  clamp/repeat/mirror sampling (raster-core ABI v1);
- multi-model source-authenticated scene assembly ABI v1 for the four
  authoritative fixture domains, connected through the owning scene-cache
  adapter;
- native material schedule and draw-descriptor ABIs v1, draw runtime ABI2,
  face runtime ABI1, postprocess ABI1, native PNG ABI1, and render-pipeline
  ABI2, all contract-checked at runtime;
- caller-buffer native ShareMii v3 256 RGBA8 and 512 BC1 block-linear
  facepaint decode, including exact TexSrt constants;
- source-authenticated FacePlan, material publication adapter, immutable mip
  provider, field packer, draw descriptor ownership, and NoseLine12 bridge;
- a single authenticated mixed draw loop, native postprocess/transfer/PNG,
  exact output copying, app-compatible report construction, and rollback-safe
  PNG/report publication;
- retained verification of all 16 admitted outputs against independently
  accepted PNG SHA-256 values, report/file hash binding, transparent RGBA
  invariants, rejection no-write behavior, and the test-only
  `INFINIMII_NATIVE_TEST_FAIL_SECOND_PUBLISH=1` fault seam, which proves that a
  second-publish failure restores both pre-existing output files and removes
  all stage/backup sidecars;
- dependency-negative readiness verification for missing zstd, missing native
  PNG, and source-tampered native PNG, with no activated render capability in
  any degraded state;
- a same-worker readiness-to-render mutation regression: readiness succeeds
  with the authentic PNG backend, the sibling is then replaced, and rendering
  fails closed with no PNG, report, or transaction sidecar while the worker
  remains healthy.

The activation is intentionally not a general LTD renderer claim. New LTD
hashes, render sizes, views, supersampling policies, presentation contexts, or
draw profiles remain outside admission and use the existing fallback until
independently captured, source-sealed, and added to the exact corpus. Runtime
worker supervision and concurrency remain the responsibility of InfiniMii's
bounded native worker pool.

This boundary targets the repository's current accepted portable output. It
does not by itself provide title-native evidence or establish that the portable
renderer matches Nintendo's renderer; those are separate evidence requirements.
