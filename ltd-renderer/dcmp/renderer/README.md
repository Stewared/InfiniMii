# Recovered numbered ShareMii renderer

This directory contains two deliberately separate render paths. The strict
path is currently scoped to Kestron in the 434-byte ShareMii v2 `mii1.ltd`
(SHA-256
`c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b`).
The portable publication path dynamically discovers exact `mii[0-9].ltd`
filenames; the current set is Kestron (`mii1`), Johnny Thunder (`mii2`), Emma
(`mii3`), and Spider-Man (`mii4`).
`title_mii_renderer.py` is the strict new path: it executes selected translated
title stages against raw BFRES data and rejects every missing runtime binding.
The selected binaries, draw inputs, and fixed state are source-backed, but host
execution of the translated shaders is explicitly **not bit-exact** to the
title GPU. `render_mii.py` is the older deterministic CPU reconstruction and
remains an explicitly approximate diagnostic.

`render_worker.py` is a minimal JSON-lines host for that same portable path.
It keeps only the interpreter and mutation-sensitive evidence/model caches
alive between serial requests; every request still receives an isolated output
directory and reruns the checked manifest/file validation. It is an exact
acceleration of `render_mii.py`, not a native or title-equivalent renderer.
`tools/verify_render_worker.py --asset-root <converted-assets>` compares exact
PNG bytes against cold processes across three distinct fixtures and revisits
the first fixture after cache-root switching.

Run from the repository root:

```powershell
python -m pip install -r renderer\requirements.txt
python tools\render_title_mii.py --stage face-atlas
python tools\render_title_mii.py --stage full
python tools\render_title_mii.py --stage full --context gameplay-reference
python tools\verify_title_mii_renderer.py
```

The source-backed translated-title path currently executes a 15-draw MiiMask
atlas diagnostic. It is not persisted unless `--output` is supplied, and its
status report is likewise opt-in through `--report`. This atlas is an intermediate face input, not a complete
Kestron or scene render, and the translated host execution is not bit-exact;
the strict report therefore distinguishes `host_executable=true` from
`title_equivalent_ready=false`.
`--stage full` intentionally exits with an error while any GameUber
context/shape/environment/global buffer, prepass,
camera, animation, shader/pass override, mesh/LOD decision, post-process input,
or draw-routing value lacks source-backed bytes; unknown
inputs remain fail-closed instead of receiving guessed offsets or defaults.
Supply `--report <path>` to persist that structured blocker report. It never
imports the CPU material renderer. `reference.png` is validation-only and
never supplies executable values. The default `mii-icon` context uses the
source-backed snapshot path; `gameplay-reference` reports the screenshot's
unavailable world state without treating any unrelated catalog camera as a
default.

`mii_icon_draw_orchestration.json` records the source-validated manager side of
that path: the exact `MiiIconMgr` registration and singleton, four contiguous
0x1010-byte render jobs, the six-state job machine, and the installed model
callbacks that route the 128x256 faceline target followed by the 256x256
MiiMask target. It intentionally leaves final GameUber shape/pass submission
and scene render-target scheduling unresolved and fail-closed.

The portable comparison path is:

```powershell
render_all_miis.bat
python tools\verify_render_numbered_miis.py
```

`render_all_miis.bat` is the Windows batch entry point for numbered inputs. It
matches complete `mii[0-9].ltd` filenames in the repository root without
matching `mii.ltd`, `mii10.ltd`, or suffix-bearing files. Each input publishes
`miiN_face.png` and `miiN_full_body.png` under `renderer/output/`. Renders are
staged and validated before rollback-capable publication, so an unsupported or
failed input cannot leave a partially updated batch. Use `--check` to rerender
and compare without changing published files. Stale numbered render pairs are
removed transactionally. After all inputs validate, the same transaction
removes only the two exact pre-rename duplicates `mii_face.png` and
`mii_full_body.png`; rollback restores them if publication fails. Unrelated
files remain untouched. The current `mii0` through `mii4` set therefore owns
exactly ten numbered PNGs under `renderer/output/`. `render_mii.py
--output-dir <temporary-path>` remains available for detailed reports and
individual diagnostic views.

The same renderer also accepts an explicit generated PartsIndex manifest for
checked InfiniMii RCD-to-LTD inputs. The frozen
`classic_bridge_resource_bundles.json`, its runtime profiles, and its hash-bound
selector, component, model, face-sprite, material, BNTX, and GameUber evidence
admit all 3,152 usable records in the validated local InfiniMii corpus. The
`QWvah`, `1SEg1`, and synthetic-average capabilities are provenance seeds, not
the coverage boundary. Records are admitted by their resolved classic resources
and compatible evidence, not by Mii ID or whole-file allowlisting.

Native LTDs outside that checked classic selector, runtime-profile, and evidence
domain remain fail-closed. The 3,152-record result does not authorize arbitrary
LTDs and is not a claim of arbitrary wardrobe or clothing, Canvas/UGC, or other
app-specific payload support. Every usable record in the frozen corpus is
expected to resolve, assemble, and render; a failure is an acceptance failure.

The historical selected LTDs, canonical generated RCDs, redacted conversion
reports, and validation-only thumbnails under `infinimii_output/source_bundle/`
remain provenance fixtures rather than an allowlist. Their exact active
manifests and portrait/full-body diagnostics remain under
`infinimii_output/active_parts/` and `infinimii_output/renders/`. The source
records were read from the loopback local InfiniMii Mongo instance without
writes. `QWvah` uses the explicitly declared historical raw-Wii palette schema;
`1SEg1` uses the canonical MiiJS-v3 schema. `ek6JD` is now covered by the frozen
corpus bundle and is no longer an expected flipped-hair rejection. Every
successful LTD regenerates its canonical RCD byte-for-byte through a matching
template. Thumbnail pixels remain validation-only and never supply renderer
constants or pass/fail pixels. Sample bodies use neutral presentation variation
00 because neither RCD nor LTD provides a ClothSet or garment colors.

Full-body publication uses the checked `presentation_outfit.json` resources:
top GameAll 984, long-pants GameAll 936, BodyBase BodyFoot socks 324, and shoes 912.
Their exact BodyBase cutlines hide Chest+Arm, Hip, and Sole respectively, and
the selected 984/936/912 compiled sampler inventories omit their serialized
`_alp0` assignments. Those mask chains remain checked inactive evidence and do
not affect portable opacity, alpha cutoff, or depth.
ShareMii contains no ClothSet fields, so these are explicitly labeled renderer
presentation choices (Kestron variation 10; neutral variation 00 for the other
numbered fixtures), not serialized character values. Unresolved Softmesh
program 36 stays skipped.

## Authoritative target selection

`mii_active_parts.json`, generated by `tools/build_mii_active_parts.py`, is the
Kestron/`mii1.ltd` selection ledger. It resolves all 23 PartsIndex selectors and
their gates.

| CharInfoEx field | Value | Resolved record/resource |
|---|---:|---|
| `faceline_type` | 0 | `Faceline00` / `MiiHead00` |
| `hair_type` | 121 | `HairAllLegacy121` / `MiiHairAllLegacy121` |
| `ear_type` | 1 | `Ear00` / `MiiEar00` |
| `eye_type` | 2 | `Eye002` |
| `eyebrow_type` | 19 | `Eyebrow19` |
| `nose_type` | 6 | `Nose06` / `MiiNose06` |
| `mouth_type` | 15 | `Mouth015` |
| `beard_type` | 3 | `Beard02` / `MiiBeard02` |
| `mustache_type` | 4 | `Mustache03` |

There is no active glass model: the sole primary Glass PartsIndex selector
resolves to `GlassNothing`. The separate lens-material mode and lens-color
bytes control materials only after a Glass model exists; they are not a second
Parts selector. Hair front is gated off because the selected legacy hair is not
attachable; hair-back bytes are subordinate editor state, not an independent
Parts category. Wrinkle, makeup, highlight, eyelash, eyelid, and stubble
selectors resolve to disabled records, while the mole and eye-shadow enable
flags are clear.

`mii2_active_parts.json` is the current selection ledger for the published
Johnny Thunder pair. Its source-backed selections are `Faceline14`/
`MiiHead14`, attachable `HairBack000`/`MiiHairBack000`, attached
`HairFront029`/`MiiHairFront029`, Eye018, Eyebrow15, Mouth015, and
BeardShort07. Ear and Nose are explicit `Nothing` records. WrinkleUpper
selector 12 has no matching decoded PartsIndex record and remains fail-closed.
BeardShort07 is applied through the checked separate 128x256 faceline target,
not the ordinary 256x256 MiiMask atlas. `mii_asset_selection.json` retains Emma-specific
`mii3.ltd` selection evidence and does not select the other numbered inputs.
That ledger also records the corrected Glass contract: CharInfoEx `+0x8d` is
the only Glass PartsIndex selector, while `+0x92` is a lens-material mode and
`+0x93` is its color. The title enables all Glass materials and then hides
`mt_LensTrs` only for mode 2; modes 0 and 1 hide `mt_LensOpa`. Emma and the
InfiniMii Glass01 sample therefore use the translucent lens geometry in mode 0,
not a fabricated second `GlassNothing` selection.

## Face composition and projection

`ltd_format.py` names and decodes every byte in the record;
`mii_fields.csv` accounts for all 434 bytes exactly once. `face_compositor.py`
implements the recovered 64-unit part coordinate system, scale/aspect, origin
mirroring, rotation pivots, per-part offsets, and MiiMask channel dispatch.
For the live Normal expression:

- `Eye002` uses mode 7: color comes from its green and blue channels and alpha
  is `saturate(A-R)`;
- `Eyebrow19` and `Mustache03` use the recovered mode-3 modulation path;
- `Mouth015` uses mode 8: color comes from blue, while alpha is
  `saturate(A-R-G)`, retaining the authored dark residual.

The exact formulas, dispatcher cases, binary sources, colors, and placement
records are in `mii_mask_semantics.json`. The compositor uses the title's
MiiSampler state: linear min/mag, point mip, LOD bias -0.7, mirrored UVW,
LOD range 0..13, and 1:1 anisotropy. At the native 256x256 face target the
calculated point-mip selections are:

| Sprite | Selected mip |
|---|---:|
| `Eye002` | 1 |
| `Eyebrow19` | 1 |
| `Mouth015` | 1 |
| `Mustache03` | 2 |

For Johnny Thunder, the corresponding selections are `Eye018` mip 1,
`Eyebrow15` mip 1, and `Mouth015` mip 2. BeardShort07 and Spider-Man Noir's
WrinkleUpper00 are routed to the separate 128x256 Head faceline target with
their checked local equations, transforms, native mips, sampler, and blend
state. `face_sprite_mips.json` and `assets/face_sprite_mips/` retain 92 checked native levels across eleven sprites
and bind each target selection to its ShareMii/active-parts SHA.

For ShareMii v3, `share_mii_facepaint.py` strictly decodes the Canvas and UGC
Zstandard frames. Canvas is 256x256 RGBA8 editor/reconstruction state and is
not sampled by the model. UGC is a 512x512 BC1 NVN block-linear texture bound
to Mask0 `_user0`, independently of the ordinary generated `_a0` mask. The
ModeMaya host affine and OR-alpha coverage rule are clearly reported portable
boundaries; no values are derived from `reference2.png`.

`MiiFaceMaskPos.bntx` has a different job. Its sixteen 32x32 payloads decode as
RGBA16F position maps and the executable bilinearly samples them to construct
34 part-attachment anchors. They are not a tessellated replacement face. The
final atlas remains a 256x256 RGBA8 sRGB render target sampled by
`MiiHead00`'s original `Mask__mt_Mask` mesh: 275 vertices, 864 indices, and 288
triangles. GfxMiiIcon's preceding faceline target is 128x256. See
`assets/face_mask_positions/README.md` and its `manifest.json` for hashes,
addresses, formats, and topology.

The live no-UGC `mt_Mask` local expression has also been recovered. In linear
RGB it reduces to `mix(Dummy_Alb.rgb, atlas.rgb, atlas.a)`, with an additional
ordinary emission term `0.1 * atlas.rgb * atlas.a`. Literal standalone GameAll
0 writes opaque alpha over the much larger Mask mesh, contradicting title
output. The CPU renderer therefore rejects atlas alpha below 0.5 before applying
the exact local expression. That coverage test is an explicit emulation of an
unlocated title override/pass.

## Geometry, pose, and materials

The renderer uses the exported BFRES topology and vertex attributes rather than
replacement primitives. Body vertices use the title's IconPose smooth skinning,
Kestron's decoded height/build scale, and the recovered head attachment. The
legacy hair stays on its authored rigid path. `MiiEar00` is instanced on both
sides with the recovered mirrored transform and corrected winding.

`mii_material_state.json` exhaustively records the five active face/model
resources: `MiiHead00`, `MiiHairAllLegacy121`, `MiiEar00`, `MiiNose06`, and
`MiiBeard02`. `texture_mips.json` contains 20 textures and 161 native mip
levels across the live Mii inputs, mask fallback, and BodyBaseDefault. The
audited GameAll selections in `gameuber_active_programs.json` are Head 816,
Mask 0, Hair 612, Nose 756, NoseLine 12, Ear 372, Beard 468, and all 13
BodyBaseDefault groups: skin-count-2 groups use 324, skin-count-3 groups use
336, and skin-count-4 groups use 348.

Recovered local behavior includes head normal reconstruction; no-specular head
and ear variants; the head/ear cheap-subsurface response curve; Hair/Beard MIM
channel roles and anisotropic kernel; Nose HGT parallax and MIM specular mask;
the exact mask RGB mix and emission; and the shared Body 324/336/348 albedo,
skin-mask, roughness, and BC5 normal equations. The title-light input to several of these formulas is
not interchangeable with raw `NdotL`; the CPU implementation labels any
portable substitute accordingly.

The nose-line BFRES binds a BC4 mask and fixed `GEQUAL 0.5` state, but the first
partial resolver match, GameAll 12, samples no local texture and writes alpha 1.
Drawing it literally produces a solid quad. The renderer uses the authored mask
red channel for coverage and the recovered feature-line color `#221817`, while
recording the missing engine override as a boundary.

Johnny's `mii2_gameuber_programs.json` binds Head14 to GameAll 816, its Mask to
GameAll 0, and both HairBack000 and HairFront029 to the same exact GameAll 564
vertex/fragment stage pair. `mii2_texture_mips.json` supplies their five exact
material textures across 46 native levels. The portable renderer executes the
Hair564 MGH.R local base expression and does not borrow Hair612-only
anisotropic constants. Kestron's HairAllLegacy121 program 612 remains
documented by `gameuber_active_programs.json`.

`hair_shader_expression.json` and its builder retain Emma/`mii3.ltd`
HairAll073 GameAll 1056 evidence. They are not a `mii2.ltd` shader or selection
input.

## Cameras, lighting, and post-process

`title_mii_icon_snapshot.json` is the authoritative snapshot ledger. Among its
recovered values:

- MiiIcon uses an orthographic 1.31-high view with square bounds
  `[-0.655, 0.655] x [-0.205, 1.105]`;
- its white key has intensity 6 and surface-to-light direction approximately
  `(-0.262003, 0.642788, 0.719846)`;
- ambient RGB is `0.7297400236` at intensity 1, with shadow and specular
  intensity 1;
- bloom is enabled with threshold 3, intensity 0.7, luminance clamp 1.5, and
  expand 0.005; tone mapping and SSAA are enabled;
- EditorMiiPreview uses perspective FOV 15, camera position `(0, 0.96, 9.4)`,
  key intensity 2.5, shadow 1.3, specular 3.5, and tone mapping disabled.

Portable classic-bridge portraits use a separately disclosed bust-presentation
profile. The source-backed base remains EditorMiiPreview; the user-supplied
`referenceFraming.png` authorizes only the fixed 512-pixel crop
`[156, 141, 356, 349]` (exclusive XYXY). That crop derives FOV
`6.122961298090818`, camera-at Y `1.023175266603659`, horizontal projection
scale `1.04`, and focal-plane bounds
`[-0.48341151457871906, 0.48341151457871906, 0.5204272914417912,
1.5259232417655268]` from the title's 15-degree, 9.4-unit camera. The reference
pixels supply no CharInfoEx, model, geometry, material, texture, shader,
lighting, or post-process values and never fit an individual Mii. The complete
hash-bound provenance, alpha envelope, formulas, and framing tolerances are in
`classic_bridge_portrait_framing.json`; `tools/verify_reference_framing.py`
also confirms that numbered fixture portraits remain on the detached-head
MiiIcon path while bridge busts disclose their presentation top at the lower
frame edge. Classic-bridge busts and explicitly requested full-body renders
are emitted as straight-alpha RGBA PNGs from a native transparent render
target: source-over alpha is accumulated with
premultiplied linear RGB, the 2x SSAA image is Lanczos-resolved in
premultiplied-alpha space, and only then is it converted to straight alpha.
No gradient, ground-shadow matte, background subtraction, or chroma key enters
those InfiniMii render pixels. Numbered MiiIcon fixtures keep their recovered opaque
presentation contract.

`snapshot_postprocess.py` implements the recovered MiiIcon gamma-zero local
tone-map core. For `C = scene + bloom`, it uses luminance weights
`(0.2989000082, 0.5866000056, 0.1143999994)`, `E = 1-exp(-Y)`,
`base = C*E/Y`, `shoulder = E^2`, and
`saturate(mix(base, 1-exp(-C), shoulder))`, with the analytic zero-luminance
limit. Those equations and the serialized values above are exact.

The complete upstream GameUber/light-prepass BRDF, screen-space face shadow,
environment/context UBOs, shadow-map filtering, bloom extraction/blur imagery,
SSAA kernel, and final output transfer are not all available from the resources
alone. The current portable lighting is therefore useful reconstruction work,
not evidence of final title radiance. The strict title renderer treats each of
these as a required runtime binding instead of substituting it.

## Reference outfit

The supplied 337x637 screenshot supports a high-confidence presentation match:
variation 10 of `ClothTopsTshirtLongDefault`, `ClothSocksDefault`, and
`ClothShoesStandardDefault`. `reference_capture_outfit.json` records why each
item was selected; `reference_outfit_material_state.json` contains two BFRES
resources, three models, five shapes, and five materials; and
`reference_outfit_texture_mips.json` contains ten textures and 90 exact levels.

This state is external to ShareMii. The portable renderer can display the
outfit geometry and textures in its separately sourced preview context, but it
does not infer the screenshot's gameplay camera, actor transform, idle clip or
frame, warm scene light, shadow, background, or environment. Those runtime
choices remain unresolved rather than capture-fitted or attributed to
`mii1.ltd`. `reference.png` remains validation-only and does not authorize
fitting executable offsets, transforms, camera values, or defaults.

## Verification

The portable fallback now has an optional source-sealed CPython/C extension
for the exact current-output Head816, Hair612, equal-endpoint Hair564,
Beard468, OutfitTops984, OutfitBottoms936, OutfitShoes912, and Mask0 draw
fingerprints.
It writes the existing float64 color/depth/alpha attachments directly and
falls back to the unchanged Python loop for every unsupported fingerprint; it
does not claim to implement the title's missing runtime inputs. Build and
verify it with:

```powershell
python tools\build_native_current_draw.py --force
python tools\verify_native_current_draw.py
```

The verifier independently exercises freshly generated production active
parts for the four valid LTD fixtures at 128 and 512 pixels in portrait and
full-body views, rather than relying only on the legacy fixture-bound manifests.

The complete suite is:

```powershell
python tools\verify_all.py
```

Useful focused checks while changing rendering code are:

```powershell
python tools\build_mii_active_parts.py --check
python tools\check_mii_mask_semantics.py
python tools\build_face_sprite_mip_cache.py --check
python tools\verify_mii_face_mask_render.py
python tools\build_gameuber_active_programs.py --check
python tools\build_gameuber_runtime_inputs.py --check
python tools\verify_gsys_context_shape_source_trace.py
python tools\verify_gameuber_mii_icon_environment_source.py --check
python tools\verify_globalubo_source_contract.py
python tools\verify_title_shader_execution.py
python tools\verify_title_mii_renderer.py
python tools\verify_gameuber_cpu.py
python tools\verify_mii_icon_snapshot_pipeline.py
python tools\build_mii_icon_draw_orchestration.py --check
python tools\verify_snapshot_postprocess.py
python tools\verify_rendering.py
```
