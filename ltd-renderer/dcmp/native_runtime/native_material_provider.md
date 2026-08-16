# Native normalized material and authored mip provider ABI 2

`native_material_provider` is the standalone, immutable provider boundary for
the two inputs previously unavailable to `native_material_field_packer`:

1. source-authenticated normalized material records;
2. complete authored texture mip chains with explicit color-space identity.

The module contains no Python or NumPy dependency. The legacy constructor owns
a private `DecodedAssetCache`; ABI 2 also provides
`ltd_native_material_provider_create_with_borrowed_cache` so a host can reuse
an already-populated process cache. It publishes stable C ABI views and returns
a callback with the exact signature consumed by
`native_material_field_packer`.

The borrowed cache is never adopted or destroyed. Its owner must outlive the
provider and all provider views, and must not mutate the cache concurrently
with provider calls. Each mip-chain publication still supplies and
authenticates the authored BNTX, manifest, every ordered mip payload, every
source seal, dimensions, format, and color-space identity through
`DecodedAssetCache::decode_texture_mip_chain`. Only an authenticated immutable
cache hit is reused; a changed payload or identity fails closed. Destroying a
borrowed-cache provider leaves the cache and its resident views intact.

## Opaque trusted bundle publication

ABI 2 also has an adapter-only transactional publication path. The material
adapter presents an opaque POD batch whose callback authenticates the exact
adapter contract, catalog and source-bundle pins, LTD/effective-CharInfo case,
view/size, publication digest, scene indices, normalized sources, evidence
seals, and complete mip inventory. The provider accepts it only when it was
created with the same `DecodedAssetCache` that the bundle populated.

The provider obtains already-authenticated immutable mip views with cache
getters, recomputes each normalized-material digest and the ordered
scene/publication digest, and borrows evidence bytes. It retains an opaque
producer lease until provider destruction, so destroying or moving the
external `MaterialBundle` cannot invalidate provider views. No STL object
crosses the boundary. A null/owned/foreign cache, duplicate publication,
changed contract/pin/shape/seal, cache miss, or publication-digest mismatch
fails transactionally without retaining a lease or publishing partial state.

## Texture contract

`ltd_native_material_provider_publish_mip_chain` receives the original BNTX
bytes and seal, complete manifest bytes and seal, and every manifest-ordered
PNG level with its seal and dimensions. The BNTX `format` must agree with the
explicit linear/sRGB identity. The provider exposes, concurrently:

- original decoded RGBA8;
- normalized RGBA64;
- hardware-visible RGBA64 (IEC sRGB-decoded RGB or linear identity);
- per-level source/representation SHA-256 values;
- whole-chain source and representation SHA-256 values.

All views are borrowed, immutable, and valid until provider destruction.
Unknown keys and changed BNTX/manifest seals fail closed.

## Normalized material contract

`ltd_native_material_provider_publish_material` copies the typed material
view: identity, exact accepted GameAll program/family, state flags, dynamic
colors and constants, lighting/camera fields, texture roles, sampler address
and mip modes, and explicit hardware-sRGB selection. It accepts no JSON blob
or caller-supplied packed draw array.

Every record must authenticate at least its selected prepared BFRES catalog
(`renderer/assets/models/<resource>/bfres.json`) and material-state ledger.
Program ledgers, the color table, and the normalization implementation are
separate evidence roles when relevant. A canonical normalized-material digest
binds every typed value and evidence seal. All string/array storage is copied;
subsequent caller mutation cannot alter a published record.

## Verification

Run:

```powershell
python tools/verify_native_material_provider.py
```

The verifier builds twice under MSVC `/O2 /MT /fp:strict /W4 /WX /Brepro`,
rejects Python/NumPy imports, and executes all four authoritative fixtures at
portrait/full-body and 128/512. It compares every locally authored texture
binding, every mip byte/float representation and hash, all normalized
material/style/sampler/lighting inputs, and negative source-seal lookups with
the accepted Python renderer. Its focused ABI 2 gate additionally runs mii4
and mii1 portrait/128 through an empty borrowed cache and a second provider on
the same warm cache, requires identical material/texture views and digests,
mutates authored/manifest/mip source buffers to prove fail-closed
reauthentication, and destroys each provider before its cache. Run it with:

```powershell
python tools/verify_native_material_provider.py --focused-borrowed
```

The material-adapter verifier's focused gate compares legacy and opaque
publication views/digests, exercises lease survival after external bundle
destruction, and rejects foreign ownership:

```powershell
python tools/verify_native_runtime_material_adapter.py --focused-trusted
```

Temporary DLLs and objects are removed on exit.

This provider is intentionally not wired into `ltd_native_runtime` by this
isolated change; shared runtime integration is a separately serialized step.
