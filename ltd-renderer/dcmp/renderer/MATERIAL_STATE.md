# Live Kestron material and shader state

[`mii_material_state.json`](mii_material_state.json) is the deterministic static
BFRES material extraction for the five model resources selected by the live
`mii1.ltd`: `MiiHead00`, `MiiHairAllLegacy121`, `MiiNose06`, `MiiEar00`, and
`MiiBeard02`. It contains 5 resources, 6 models, 8 shapes, 8 materials, 12
texture assignments using 8 unique names, 12 sampler states, 42 vertex-attribute
assignments, 17 shader-sampler assignments, 242 shader options, 410 typed shader
parameters, and 250 typed render-info entries. Every source has a repository-
relative path, byte length, and SHA-256.

## Active bindings

| Resource/material | Static texture bindings | Audited GameAll program |
|---|---|---:|
| `MiiHead00/mt_Head` | `Dummy_Alb -> _a0`, `Head_Nmh -> _n0` | 816 |
| `MiiHead00/mt_Mask` | runtime face atlas replaces `_a0`; no-UGC `_user0` falls back to `Dummy_Alb` | 0 |
| `MiiHairAllLegacy121/mt_Hair` | `Mim -> _o0`, `Mgh -> _user1` | 612 |
| `MiiNose06/mt_Nose` | `Hgt -> _user0`, `Mim -> _s0` | 756 |
| `MiiNose06/mt_NoseLine` | `NoseLine_Msk -> _a0` | 12, partial/non-final |
| `MiiEar00/mt_Ear` | no local texture | 372 |
| `MiiBeard02/mt_Beard` | `Mim -> _o0` | 468 |

The hair resource contains both `MiiHairAllLegacy121` and its hat model, sharing
`mt_Hair`. Head geometry selects `_u2` for `mt_Head`, while the Mask shape uses
`_u0`; the exported mesh metadata preserves that distinction.

Static BFRES state is not the whole runtime state. For example, Head 816 reads
`_a0`, and title code supplies the live skin-colored input even though the
serialized reference is named `Dummy_Alb`. Runtime colors, generated render
targets, and global uniform buffers are recorded separately in
[`gameuber_active_programs.json`](gameuber_active_programs.json).

## Recovered local equations

- Head 816 reconstructs tangent-space normal XY from the shader-visible RG pair
  of `Head_Nmh`; the authored payload stores that pair in physical R/A. Head and
  Ear 372 compile specular out. Their cheap-subsurface curve and constants are
  recovered exactly, but its input is assembled from the title light prepass,
  shadow, environment, and context data—not raw `NdotL`.
- Mask 0 samples the generated 256x256 sRGB face atlas and no-UGC `Dummy_Alb` in
  linear RGB. With the live constants its local albedo is
  `mix(Dummy_Alb.rgb, atlas.rgb, atlas.a)` and ordinary emission is
  `0.1 * atlas.rgb * atlas.a`. Literal program 0 provides no usable final
  coverage over the oversized Mask mesh; the CPU alpha cutoff is an explicitly
  documented engine-pass emulation.
- Hair 612 uses `MIM.r` for occlusion/edge/shadow masking, `MIM.g` for direct
  anisotropic-specular masking, `MIM.b` for anisotropic shift, and `MGH.r` for
  the primary/secondary color interpolation. The anisotropic kernel is
  recovered, while three runtime/template values and final title-light RGB
  still require a buffer capture.
- Nose 756 uses `depth = 0.25 * (1-Hgt.r)` for its parallax UV displacement and
  `MIM.g` as the specular mask at the shifted UV.
- Beard 468 uses the runtime constant color; `MIM.r/g/b` carry the same
  occlusion/specular/shift roles used by the anisotropic path. Its serialized
  roughness is 0.28, toon specular intensity 0.5, lobe size 10, and shift offset
  -1.3.
- NoseLine's BFRES state binds the 256x256 BC4 mask and specifies masked
  `GEQUAL 0.5` drawing, but partial resolver match 12 reads no local sampler and
  outputs alpha 1. The portable path therefore uses `sample(mask, uv).r >= 0.5`
  for coverage and identifies the missing title override rather than drawing a
  solid rectangle.

`gameuber_active_programs.json` also audits every BodyBaseDefault group: skin-2
groups use program 324, skin-3 groups use 336, and only Chest/Shoulder use 348.
Their shared fragment equation mixes face-color linear RGB and hardware-decoded
albedo by the skin mask, derives roughness from the skin/material channels, and
reconstructs the BC5 normal. Body state is stored in
[`body_material_state.json`](body_material_state.json), not added to the five
live face resources above.

## Related native data

- [`texture_mips.json`](texture_mips.json) contains 20 textures and 161 exact
  native levels for the live Mii model inputs, the mask fallback, and
  BodyBaseDefault.
- [`face_sprite_mips.json`](face_sprite_mips.json) separately contains the 34
  native MiiParts levels used to build the face atlas.
- [`reference_outfit_material_state.json`](reference_outfit_material_state.json)
  contains the two screenshot-inferred outfit BFRES resources; its ten textures
  and 90 levels are in `reference_outfit_texture_mips.json`.
- [`title_mii_icon_snapshot.json`](title_mii_icon_snapshot.json) preserves exact
  camera, serialized light, ambient, shadow/specular, bloom, tone-map-enable,
  and SSAA-enable state. `snapshot_postprocess.py` contains the recovered exact
  local gamma-zero MiiIcon tone curve. The upstream light/shadow/environment
  buffers, bloom extraction/blur imagery, output transfer, and capture
  environment remain bounded.

[`hair_shader_expression.json`](hair_shader_expression.json) is not active live
state. It is retained binary-backed evidence for the archived `mii3.ltd`/Emma
`HairAll073` regression fixture and is not an input to current `mii2.ltd`.

Generate or verify the live manifests without changing repository files:

```powershell
python tools\build_mii_material_state.py --check
python tools\build_texture_mip_cache.py --check
python tools\build_gameuber_active_programs.py --check
python tools\verify_gameuber_cpu.py
```

These checks are also part of `python tools\verify_all.py`.
