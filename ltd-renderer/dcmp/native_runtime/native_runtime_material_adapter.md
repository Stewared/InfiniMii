# Native runtime material adapter

`native_runtime_material_adapter.{h,cpp}` is the CPython-free source-to-
publication boundary for the accepted LTD authority: `mii0`, `mii1`, `mii2`,
and `mii4`, in portrait/full-body at 128/512. It intentionally does not claim a
generic BFRES material interpreter.

The offline builder runs the accepted renderer as an oracle and emits only:

- bit-exact normalized material scalars and vectors;
- scene draw indices, program/family/priority/flags, and sampler roles;
- logical evidence, BNTX, mip-manifest, and every PNG mip path with exact
  SHA-256 and byte-length seals;
- exact LTD and effective 152-byte CharInfo identities;
- FacePlan/UGC identities and the one MiiNose06 NoseLine nine-mip identity.

It does not emit geometry, packed draw fields, decoded pixels, attachment
buffers, PNGs, or final images. The generated typed-record catalog SHA-256 is
recomputed from the compiled records during every `Build`, then compared with
the caller's independent expected pin. The live source bundle is also
independently pinned.

## Runtime contract

`BuildRequest` requires the repository root, exact LTD bytes, exact effective
CharInfo, view, raster size, both expected pins, a caller-owned
`DecodedAssetCache`, an already-authenticated `FacePlan`, and native-decoded
UGC RGBA8 (empty only for `mii1`).

`Build` then:

1. identifies exactly one accepted LTD/CharInfo case;
2. authenticates every evidence document used by the catalog;
3. reads and authenticates each required authored BNTX, complete manifest, and
   every mip PNG;
4. decodes complete chains into the supplied `DecodedAssetCache`;
5. creates immutable provider inputs whose recursive storage is bundle-owned;
6. copies FacePlan Head/Mask RGBA64 targets into bundle-owned storage;
7. authenticates UGC RGBA8, expands it exactly as `byte / 255.0`, and attaches
   the native `TexSrt`; and
8. for `mii1`, owns the authenticated nine-level NoseLine RGBA64 bank and its
   exact ABI1 manifest/decoded seals.

The operation is transactional. On any bad pin, unsupported case, missing or
changed byte, cache error, FacePlan mismatch, or UGC mismatch, the prior output
bundle remains unchanged.

## Orchestrator consumption

Keep `MaterialBundle` alive through `native_render_orchestrator::Prepare`:

```cpp
MaterialBundle bundle;
Status status = Build(request, &bundle, &error);

std::vector<native_render_orchestrator::MaterialPublication> materials;
for (const auto& source : bundle.publications()) {
  materials.push_back({source.scene_draw_index, source.material,
                       source.mip_chains});
}

const auto ugc = bundle.ugc();
native_render_orchestrator::UgcPublication orchestrator_ugc{
    ugc.source_key, ugc.rgba8, ugc.width, ugc.height, ugc.tex_srt};

const auto nose = bundle.noseline();
native_render_orchestrator::NoseLinePublication orchestrator_nose{
    nose.source_key, nose.mip_rgba, nose.levels,
    nose.texture_manifest_sha256, nose.decoded_mips_sha256};
```

The first material publication carries the complete unique static material
mip inventory; later publications carry empty mip spans, preventing duplicate
provider insertion. NoseLine mips are deliberately excluded from that material
inventory and supplied only by `noseline()`. Use
`face_views().generated_mask_source_key` and
`face_views().generated_head_albedo_source_key` as the two generated FacePlan
keys. `noseline().scene_draw_index` is an additional integration assertion
(`13` for the only NoseLine fixture); the ABI2 orchestrator locates that draw
from its assembled scene.

`MaterialBundle::Publish` is the legacy isolated convenience for a fresh
owned-cache provider and copies/reauthenticates every input.
`MaterialBundle::PublishTrusted` is the ABI 2 fast path for a fresh provider
created with this bundle's exact `DecodedAssetCache`. It hands the provider an
opaque, contract-sealed POD batch; the provider validates the complete
material/mip/scene/publication identity against resident cache views, then
retains an opaque shared-storage lease and borrows evidence bytes. No STL
ownership crosses the boundary. The cache must outlive the provider; the
external bundle need not, because the provider-held lease keeps its immutable
storage alive. Neither publication method may be called in addition to
orchestrator publication.

## Reproduction and verification

```powershell
python tools/build_native_runtime_material_catalog.py --check
python tools/verify_native_runtime_material_adapter.py
python tools/verify_native_runtime_material_adapter.py --focused-trusted
```

The verifier rebuilds the catalog from the accepted oracle, performs two
byte-identical MSVC `/O2 /MT /fp:strict /W4 /WX /Brepro` builds, exercises all
16 fixture/view/size cases, compares provider-normalized publication digests,
checks all mip callbacks and FacePlan/UGC/NoseLine views, and rejects catalog,
source-bundle, LTD, CharInfo, UGC, live-source, and missing-source mutations.
The focused trusted gate additionally compares legacy and trusted normalized
and complete mip-chain views/digests for mii4/mii1 portrait/128, rejects
null/owned/foreign caches and duplicate publication, destroys the external
bundle, and proves retained provider material/mip views remain exact until the
provider releases its lease. The resulting executable imports no Python or
NumPy runtime.
