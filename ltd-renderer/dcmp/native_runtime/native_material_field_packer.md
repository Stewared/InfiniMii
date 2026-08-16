# Native material field packer ABI 1 — provider boundary

This source-sealed API defines the remaining standalone boundary between native
scene/model data and the already-verified material scheduler/typed descriptor
builder. It accepts no Python-shaped packed arrays. Its inputs are:

- an immutable `native_scene_assembler` draw and model view;
- the exact 152-byte effective CharInfo selected by native Parts;
- explicit normalized material metadata, including every color, sampler key,
  alpha/roughness/anisotropy constant, lighting vector/intensity, camera value,
  winding/blend/depth flag, and source seal;
- a callback returning immutable decoded mip chains by exact key and SHA-256;
- typed RGBA64 outputs from native face/head-mask/facepaint production, plus
  the native facepaint TexSrt.

The intended output is one pack-owned `ltd_native_source_draw`, including all
texture descriptors and packed ABI fields for Body324/336/348, Ear372,
Nose756, Mask0, Head816, Hair612/564, Beard468, and Outfit984/936/912. The
record then feeds `native_material_schedule` and
`native_draw_descriptor_builder` without any opaque prepacked caller payload.

## Exact producer inventory

Already available natively:

- candidate screen/bounds/denominator/world vertex/world normal arrays and
  material/`_u0`/`_u2` UVs from `native_scene_assembler`;
- source-triangle provenance and effective 152-byte CharInfo from native Parts;
- decoded base RGBA8 PNGs from `DecodedAssetCache`;
- native face-mask/faceline RGBA8/RGBA64 operations and native ShareMii
  facepaint decode/TexSrt;
- accepted draw scheduling, typed descriptor ownership, ABI1/ABI2 draw kernels,
  postprocess, and PNG encoding.

The following native producers are still missing and must be supplied exactly;
the packer currently fails closed rather than recreating their values:

1. **Normalized BFRES/material metadata view.** The existing runtime exposes
   normalized material data only through internal JSON assembly, not a stable
   typed C/C++ view. Required fields are shader family/program, texture and
   sampler bindings, color/alpha/roughness values, Body348 face color, and the
   Hair612/564/Beard468 anisotropic constants. The header's
   `ltd_native_normalized_material_view` is the precise handoff.
2. **Authenticated mip-chain provider.** `DecodedAssetCache` publicly exposes
   one decoded base RGBA8 PNG. Exact current payloads require every authored
   mip as RGBA64, preserving linear vs hardware-sRGB interpretation, along
   with exact level extents/source seals. The callback in the header is the
   required cache-neutral API; it may be backed by an extended cache without
   coupling the C ABI to C++ containers.
3. **Complete native face target producer.** `native_face_runtime` implements
   kernels but does not itself resolve assets/colors or publish the exact
   generated Head816 `_a0` and Mask0 `_a0` RGBA64 views. These exact products
   are required through `ltd_native_material_face_views`.
4. **CharInfo color-table normalization.** Native Parts provides bytes, but no
   source-sealed typed palette service currently maps `faceline_color`,
   `hair_color_primary/secondary`, and `beard_color` to the exact current
   sRGB/linear vectors. Those resolved values must populate the normalized
   material view; the packer will not embed an unauthenticated palette.

With those providers present, all remaining algorithms are locally specified:
IEC sRGB decode before filtering, mip-bank packing, point/trilinear LOD from
screen/UV gradients, Head816 normal-validity/UV routing, Mask0 affine fields,
piecewise color conversion for head/beard, `abs(x)^2.2` hair endpoint color,
and the 33-scalar anisotropic parameter vector.

The current implementation validates all seals, request identities, profiles,
finite scene/material values, and decoded texture-provider records under MSVC
`/W4 /WX /fp:strict`; it deliberately returns `provider_failed` before emitting
a partial source draw. Therefore it does not yet claim 16-case parity or
production readiness.
