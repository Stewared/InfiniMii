# Native face-plan ABI 1

`native_face_plan` is the CPython-free boundary between an effective 152-byte
LTD CharInfo record and the face textures consumed by the standalone renderer.
Its current sealed domain is the four authoritative fixtures `mii0`, `mii1`,
`mii2`, and `mii4`. Inputs outside that domain fail closed; they do not silently
fall back to a catalog neighbor.

## Build contract

Call `infinimii::native_face_plan::Build` with:

- the authenticated native Parts catalog and its independently pinned SHA-256;
- the exact 152-byte effective CharInfo record;
- a live `DecodedAssetCache` containing the selected face sprites and faceline
  resources.

The call first runs native Parts selection, checks the fixture/source seals,
checks every selected record and inventory identity, and then builds the plan.
It is transactional: failure leaves the caller's existing `FacePlan` unchanged.
The process must use round-to-nearest floating-point mode. Null, short,
non-finite, mutated, missing, or source-mismatched inputs are rejected.

`FacePlan` owns all returned storage. References and spans obtained from it stay
valid until that `FacePlan` is mutated or destroyed; cache asset views obey the
separate immutable `DecodedAssetCache` lifetime contract during `Build` only.

## Outputs

The immutable plan exposes:

- ten palette roles (skin, two hair colors, beard, eye, eye shadow, brow,
  mouth, mustache, and stubble) as RGBA8 plus exact sRGB and IEC-linear binary64;
- source-sealed ordinary-layer records, including placement, affine transform,
  selected point mip, mirroring, shader, and `RotateAxis` metadata;
- the final and mesh Mask0 RGBA8 views at 256 by 256;
- the generated Mask0 RGBA64 view used by native field packing;
- optional Head816 RGBA8 and generated RGBA64 views at 128 by 256.

No final render or fixture image is embedded. The generated catalog contains
only authenticated source metadata, constants, fixture fingerprints, and
expected digests. The runtime composes pixels through `native_face_runtime` and
retrieves decoded resources through the cache getter API.

For field-packer integration, `generated_mask_rgba64()` is the complete Mask0
input and `generated_head_albedo_rgba64()` is the complete Head816 input when
`has_head_albedo()` is true. Spider-Man Noir uses the wrinkle Head816 target;
Johnny Thunder uses the faceline Head816 target.

## Reproducibility and verification

Regenerate the source-sealed catalog with:

```powershell
python tools\build_native_face_plan_catalog.py
```

Run direct target, palette, source-seal, mutation, and reproducible-build checks:

```powershell
python tools\verify_native_face_plan.py --skip-final-renders --json
```

Omit `--skip-final-renders` for the 16-case final-PNG A/B matrix (four fixtures,
portrait and full-body, 128 and 512 pixels). The verifier builds twice with
MSVC `/O2 /MT /fp:strict /permissive- /utf-8 /W4 /WX /Brepro`, rejects Python
imports, and requires byte-identical executables and final PNGs.

This module does not yet claim arbitrary LTD CharInfo coverage. Broadening the
domain requires authenticated source evidence, regenerated catalog records, and
the same direct-target and final-output admission checks.
