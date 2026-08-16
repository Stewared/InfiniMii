# Native PartsIndex selector

`native_parts_selector.cpp` is the standalone C++20 implementation of the
accepted `tools/build_mii_active_parts.py` selection boundary. Runtime code
does not import Python, parse JSON/BYML, inspect Ryujinx configuration, or walk
the converted asset tree.

## Offline catalog

Generate or verify the checked catalog from the repository root:

```powershell
python tools/build_native_parts_catalog.py --write
python tools/build_native_parts_catalog.py --check
```

The builder uses the existing authenticated PartsIndex authority. This keeps
its bounds-checked BYML-v7 node-`0x20` fallback and the checked special-Mii
runtime profile as the single offline source of truth. It emits:

- `native_runtime/generated/native_parts_catalog.bin`: compact runtime data;
- `native_runtime/generated/native_parts_catalog.json`: human-readable input
  identities, source-bundle digest, counts, and catalog SHA-256.

The v1 binary has 738 selector-relevant rows, 982 model-resource links, six
exact 152-byte SDK-default templates, and a deduplicated string table. It is
currently 122,591 bytes with SHA-256
`d8d56e7ee1e291e2e4cc213ef88521b594093a83952747f1d3c8ab0ca5b00523`.

Catalog generation is deterministic. The verifier generates it twice and
compares both binary and provenance JSON byte-for-byte.

## Integration API

Include `native_parts_selector.h` and compile `native_parts_selector.cpp` into
the host. The minimal sequence is:

```cpp
std::unique_ptr<infinimii::native_parts::Catalog> catalog;
std::string error;
if (!infinimii::native_parts::Catalog::Open(
        catalog_bytes, admitted_catalog_sha256, &catalog, &error)) {
  // fail closed
}

infinimii::native_parts::Selection selection;
if (!infinimii::native_parts::Select(
        *catalog, raw_char_info_152_bytes, &selection, &error)) {
  // fail closed
}
```

`Catalog::Open` copies and owns the catalog bytes. Views in `CatalogEntry` and
`Selection` remain valid for the lifetime of that `Catalog`. The host must
supply the independently admitted 32-byte catalog SHA-256. A self-declared
digest from the same file is intentionally not accepted as authentication.
Open also validates section arithmetic, strict category/selector ordering,
string/model spans, normalization templates, and semantic flags.

`Selection` contains:

- the title-effective 152-byte CharInfoEx and normalization action/default;
- all 23 logical records in the accepted order;
- exact selector/category/resolution/enabled/Nothing/gate/projection state;
- a pointer to the selected catalog row and its complete model-resource list;
- insertion-order-deduplicated active `ModelUnit` and texture inventories.

The ABI fixes active inventory capacity at 64 entries and fails closed on
overflow. No current selection approaches that boundary.

## Exact behavior retained

- Special-origin normalization occurs before every lookup. CreateId is
  preserved and the SDK default index is `(gender ? 3 : 0) + CreateId[15] % 3`.
- Effective main Hair must resolve or the whole selection fails.
- HairFront is gated only by the effective Hair row's
  `IsAttachableHairFront`.
- Mole selector is exactly `1` when face-flag bit 7 is set and `0` otherwise;
  the same bit gates rendering.
- HairBack remains a named editor-state record with no invented Parts category.
- Missing non-Hair rows are unresolved with `title_lookup_empty`; no nearby or
  legacy selector is substituted.
- `FileName` ending in `Nothing` takes projection precedence over a disabled
  gate. A resolved row with no texture/model payload remains disabled without
  inventing an inactive projection.
- Only enabled records contribute resources. Active models include role
  exactly equal to `ModelUnit`; conditional/hat alternatives stay inactive.

## Verification

Run:

```powershell
python tools/verify_native_parts_selector.py
```

The verifier compiles the source twice with MSVC C++20, `/W4 /WX /O2 /MT`
and linker `/Brepro`, then requires byte-identical executables. It compares
the native result field-for-field against `tools/build_mii_active_parts.py` for
mii0, mii1, mii2, mii4 and the three converted LTDs currently present in
`renderer/infinimii_output/source_bundle`. Targeted temporary LTD mutations
cover special-region SDK-default replacement, mole-on gating, and an unresolved
non-Hair selector.

It additionally rejects wrong admitted hashes, byte-mutated catalogs,
rehash-mutated magic/profile/string references, truncated CharInfoEx, invalid
gender/region, and an unresolved main Hair selector. Temporary compiler and
fixture artifacts are removed automatically.

The frozen 3,152-record external corpus manifest referenced by the classic
runtime profile is not present in this checkout. Therefore this module's
checked corpus claim is deliberately limited to the four production fixtures,
all three available converted fixtures, and the three targeted semantic cases.
The verifier can be extended later when that authenticated corpus is supplied;
the runtime ABI and catalog do not need to change.
