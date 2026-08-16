# Standalone current-draw runtime

`native_draw_runtime.h` exposes a CPython-free, allocation-free C ABI for the
current accepted `Body324`, `Body336`, `Body348`, `Ear372`, `Nose756`, and
`Mask0` whole-draw pixel kernels. The caller owns all buffers. Color is linear
RGB binary64; depth and optional target alpha are binary64. Images may have
explicit byte row strides, while already flattened triangle and texture banks
are tight arrays with explicit counts.

Call `ltd_draw_runtime_require` at startup with the header's ABI and contract
fingerprint. Reject any non-OK result. The contract also publishes both exact
renderer source hashes from which this subset was extracted.

## Inputs supplied by the standalone renderer

The API begins after mesh transforms, projection, culling, bounds calculation,
and mip selection. A standalone EXE supplies:

- Shared attachments: current linear RGB64, depth64, and optional alpha64.
- Every draw: selected screen triangles (`count*3*3`), inclusive int64 bounds
  (`count*4`), and signed raster denominators (`count`).
- Ear372/Nose756: selected vertex normals, linear base color, light direction,
  light/ambient colors and intensities, and exact perspective flag `1`.
- Body324/336/348: selected world vertices, vertex normals and material UVs;
  packed RGBA64 albedo/skin/normal mip banks; per-triangle lower/upper mip
  indices and blend amounts; point normal-mip index; face color; lighting.
- Mask0: selected normals and UVs, generated/user RGBA64 textures, lighting,
  perspective/mode flags, and the six UGC affine coefficients. World vertices
  from the old Python extension ABI were unused by the accepted kernel and are
  deliberately absent here.

Asset parsing, evidence and material fingerprint validation, mesh transforms,
projection/front-face filtering, mip decisions, draw scheduling, and final PNG
encoding remain host concerns. They do not require Python and already have
native-runtime counterparts or explicit input records elsewhere.

## Remaining current-draw profiles

The following profiles use distinct shader/texture ABIs and are not claimed by
ABI 1:

- `Head816`: albedo plus packed point normal mips, two UV sets, normal-valid
  lane flags, cheap-SSS inputs, and optional generated faceline alpha.
- `Hair612`, equal-endpoint `Hair564`, `Beard468`: shared 33-scalar anisotropic
  ABI, MIM texture, tangent frame, camera and per-triangle perspective inputs.
- `OutfitTops984`, `OutfitBottoms936`, `OutfitShoes912`: shared opaque outfit
  albedo/normal response and its per-profile authenticated geometry.

Those can be added as ABI-compatible new entry points after their independent
fixture matrix is extracted; callers must continue using the existing accepted
implementation or fail closed until then.

## Verification

```powershell
python native_runtime/native_draw_runtime_verify.py --samples 1
```

The verifier builds twice with strict floating-point and reproducible-link
settings, compares binaries, checks shared-library imports, static-links a
host-free smoke EXE, runs fail-closed ABI/buffer tests, A/B compares every
intercepted subset draw against the existing extension from identical
attachment snapshots, and compares final PNGs for four authoritative fixtures
in portrait/full-body views at 128 and 512 pixels. All build/output products
use automatically removed temporary directories.
