# Native scene cache adapter ABI 1

`native_scene_cache_adapter` is the CPython-free bridge from immutable decoded
assets to `native_scene_assembler` ABI 1. It does not read an active-parts JSON
manifest. The caller supplies the authenticated native Parts catalog and the
raw 152-byte CharInfo; the assembler performs `Catalog::Open` and `Select` and
asks this adapter only for the selected resource/model identities.

For each requested model the adapter canonicalizes beneath `model_root`, seals
and decodes `<model>.obj`, attaches the optional sealed
`<model>.texcoords.json`, and parses the exact model record from sealed
`bfres.json`. Its borrowed model view includes topology, named UVs, bones,
shapes, palettes, weights, and expanded 4x4 inverse-bind matrices. Every backing
allocation remains valid until adapter destruction. The persistent runtime can
borrow its existing `DecodedAssetCache` and already-authenticated IconPose via
`create_borrowed_scene_cache_adapter`; the standalone owning constructor exists
for verification. `ltd_native_scene_cache_adapter_get_model` returns that same
borrowed immutable view so material-field and descriptor compilation never
reparse or duplicate a model selected by the scene.

The verifier builds twice with `/fp:strict /W4 /WX /Brepro`, requires identical
binaries, then compares all 16 authoritative combinations
(mii0/mii1/mii2/mii4, portrait/full body, 128/512) against the Python scene
oracle. It exhaustively covers draw identity/order, transforms, camera, source
triangle indices, projected geometry, bounds, material UV, `_u0`, and `_u2`,
then repeats every case through cache hits. Catalog mutation, unsupported size,
and broader-profile inputs fail closed.

This module only authenticates and assembles scene geometry. Its activation
flag is intentionally false: material compilation, draw execution,
postprocessing, PNG/report writes, and full-render admission remain separate.
