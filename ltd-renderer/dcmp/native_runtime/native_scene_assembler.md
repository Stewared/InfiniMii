# Native scene assembler ABI 1

`native_scene_assembler.{h,cpp}` is the cache-neutral, fail-closed scene
assembly boundary for the current accepted-output fixture set. It owns native
Parts selection, multi-model pose/bind evaluation, body and attachment
transforms, camera resolution, draw scheduling, and production geometry setup.
It does not rasterize or shade pixels, so `activation_ready` is deliberately
false.

## Immutable asset adapter

The caller supplies a synchronous `ltd_native_scene_get_model_fn`. The callback
returns a borrowed immutable `ltd_native_scene_model_view` containing:

- source-authenticated OBJ, BFRES catalog, and optional named-UV seals;
- position, normal, default-UV, triangle, and named-UV views;
- the topological EulerXYZ bone hierarchy and shape metadata;
- skin palettes, inverse binds, indices, and weights.

The assembler retains no callback pointers after `ltd_native_scene_assemble`
returns. All exported draw identities and geometry arrays are owned by the
opaque assembly object. The frozen decoded-cache getters can implement this
small adapter later; this ABI does not depend on cache classes or mutate them.
Missing assets, malformed arrays, invalid seals, changed shape inventories,
unknown models, and unsupported draw profiles fail closed.

## Exact admitted scope

ABI 1 admits only the native Parts results exercised by `mii0`, `mii1`,
`mii2`, and `mii4`:

- fixed posed assembly: `BodyBaseDefault`, `ClothTopsTshirtLong`,
  `ClothBottomsPantsLong`, and `ClothShoesStandard`;
- faceline: `MiiHead00` and `MiiHead14` (`Head816`, `Mask0`);
- attachments: `MiiEar00` (`Ear372`), `MiiNose06` (`Nose756`,
  `NoseLine12`), and `MiiBeard02` (`Beard468`);
- hair: `MiiHairAllLegacy121` (`Hair612`), `MiiHairBack000`, and
  `MiiHairFront029` (`Hair564EqualEndpoint`);
- body programs `Body324/336/348` after the four reference-outfit SystemParam
  cutlines, plus `Outfit984/936/912`.

Both `portrait` and `full_body` use the complete body/reference-outfit scene.
ABI 1 accepts only 128 and 512 output sizes. It resolves the checked bust or
EditorMiiPreview camera at that actual raster size; supersampling is a later
pipeline concern.

## Explicitly outside ABI 1

The broader accepted renderer inventory is not silently generalized. These
profiles/models remain outside this fixture-bounded assembler and therefore
return `PROFILE_UNIMPLEMENTED` when selected:

- `GlassFrame360`, `GlassLens60` opaque/translucent;
- `Decoration480/492`;
- `Hair396/408/420/432/672/708/1056/1116`;
- `Beard456`;
- `LegacyHeadwear96`;
- any other Parts-selected `ModelUnit` not named in the exact admitted list.

Material compilation, texture/mip lookup, face texture generation, draw-kernel
execution, coverage/depth/color ownership, postprocess, PNG encoding, and the
standalone request endpoint remain separate blockers. Consequently this module
must not be described or wired as a complete native renderer.

## Verification

Run:

```powershell
python tools/verify_native_scene_assembler.py
```

The verifier builds the combined assembler DLL twice with `/fp:strict`,
`/W4 /WX`, and `/Brepro`; requires byte identity and only `KERNEL32.dll`; then
compares all draw identities, schedule positions, transforms, submitted source
triangle IDs, world vertices/normals, projected screens, bounds,
denominators, material UV, `_u0`, and `_u2` arrays against the Python authority
for four fixtures × two views × two raster sizes. It also checks deterministic
repeat assembly and fail-closed missing-asset, malformed-seal, catalog-digest,
invalid-size, and broader-profile cases.

