# Decoded asset cache getter boundary

`DecodedAssetCache` owns decoded OBJ meshes, attached named-UV channels, RGBA8
textures, and complete authored material mip chains. The getter API exposes
immutable C++20 views without copying the decoded arrays:

```cpp
auto decoded = cache.decode_obj(key, obj_sha256, obj_bytes);
cache.attach_named_uv(key, obj_sha256, model_name, sidecar_sha256, sidecar_bytes);
DecodedObjView object =
    cache.get_obj_with_named_uv(key, obj_sha256, sidecar_sha256);

auto texture_decode = cache.decode_png(key, png_sha256, png_bytes);
DecodedTextureView texture = cache.get_texture(key, png_sha256);

auto chain_decode = cache.decode_texture_mip_chain(chain_key, chain_source);
DecodedTextureMipChainView chain = cache.get_texture_mip_chain(
    chain_key, manifest_sha256, authored_bntx_sha256);
```

`DecodedObjView::mesh` exposes positions, legacy texture coordinates, normals,
and triangles. `named_uv_channels` is in lexical channel-name order; every
`DecodedNamedUvChannelView` contains its name, the complete position-indexed
`double` array (two scalars per OBJ position), finite-pair coverage count, and
SHA-256. Missing positions retain the accepted quiet-NaN representation.
`DecodedTextureView::texture` exposes the exact decoded RGBA8 byte array.

Each `DecodedTextureMipChainView` publishes every manifest-ordered authored
level in three simultaneous immutable forms:

- exact WIC-decoded RGBA8 source bytes;
- normalized float64 RGBA (`byte / 255.0`);
- hardware-visible float64 RGBA, with RGB decoded through the accepted IEC
  sRGB transfer only when the authenticated BNTX format is `_SRGB`; alpha is
  unchanged.

The sRGB byte conversion is a pinned 256-entry float64 table derived from the
accepted NumPy oracle. This avoids platform `pow` one-ULP drift before native
bilinear/trilinear filtering. Linear sources have byte-exact identical
normalized and sampled float64 arrays.

Publishing a chain authenticates the original BNTX bytes, the complete mip
manifest bytes, every PNG byte stream, level order, dimensions, format/color
space agreement, and all supplied SHA-256 seals. Metadata includes per-level
hashes plus aggregate RGBA8, normalized RGBA64, sampled RGBA64, and complete
identity hashes. A warm publication reauthenticates all supplied bytes and
fails closed if any identity, extent, or source seal changes.

## Ownership and lifetime

- A view, its pointers, its spans, and its string views remain valid until the
  owning `DecodedAssetCache` is destroyed. The cache is non-copyable,
  non-movable, and never evicts entries.
- Calling either OBJ `find` or `get` publishes that entry. Its first named-UV
  attachment must happen before publication. A later first attachment fails
  with `DECODED_ENTRY_PUBLISHED`; reattaching the already-authenticated
  sidecar is an idempotent no-op.
- A failed named-UV parse is transactional: it does not publish channel data,
  alter metadata, set the sidecar seal, or charge resident bytes.
- The legacy `decode_obj` result is intended for the decode/attach sequence;
  consumers that retain an immutable view must call `find_obj`, `get_obj`, or
  `get_obj_with_named_uv` after attachment.
- The cache is single-owner and not internally synchronized. A caller must not
  perform concurrent mutation or lookup without external synchronization.

## Keys and source identity

Keys are opaque `std::wstring` values. They must be nonempty and contain no
NUL. The cache neither canonicalizes nor case-folds them: the host supplies one
canonical, case-folded key and must use the exact same value on every call.
Consequently, path aliases and differently cased keys are distinct entries.

Every decode and lookup requires a 64-character lowercase hexadecimal SHA-256
seal. Decode calls recompute the digest of the supplied bytes, including on a
warm hit. This prevents changed bytes from being returned under a previously
cached declaration. Lookup behavior is deliberately unambiguous:

- absent `find_*` key: `std::nullopt`;
- absent `get_*` key: `DECODED_CACHE_MISS`;
- resident key with another seal: `DECODED_SOURCE_CHANGED`;
- malformed key/seal: `DECODED_KEY_INVALID` or
  `DECODED_SOURCE_SEAL_INVALID`;
- bytes that do not match their declared seal:
  `DECODED_SOURCE_HASH_MISMATCH`;
- named-UV getter before attachment: `NAMED_UV_NOT_ATTACHED`.

Privacy, filesystem authorization, canonical-path policy, and source-seal
admission remain host responsibilities. The cache accepts no path by itself.

## Isolated verification

Run from the repository root:

```powershell
python tools/verify_decoded_asset_cache_getters.py
```

The verifier does not build or invoke `ltd_native_runtime`. It compiles a
temporary `/O2 /MT /fp:strict /W4 /WX /Brepro` consumer twice and requires the
executables to be byte-identical. Through the public getter views it hashes
every active decoded asset in mii0, mii1, mii2, and mii4 and compares against
the accepted Python `load_obj`/Pillow cache results. It also covers exact-key
non-aliasing, malformed and changed seals, warm-byte mutation, transactional
sidecar parse failure, missing named UV, late attachment rejection,
idempotent attachment, and pointer/span stability across cache growth.

This boundary closes the decoded-cache getter blocker for an in-process native
scene assembler. Linking the cache and consuming these views in the main
runtime remains a separate serialized integration step.
