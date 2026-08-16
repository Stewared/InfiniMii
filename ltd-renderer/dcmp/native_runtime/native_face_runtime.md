# Native face runtime integration boundary

`native_face_runtime.h` is a C ABI for the exact dense pixel kernels used by
the current face and faceline targets. It has no CPython, NumPy, Pillow, asset
loader, or renderer-host dependency. The caller owns every input and output
buffer and may static-link `native_face_runtime.c` or build it as a shared
library.

At startup, call `ltd_face_runtime_require` with
`LTD_FACE_RUNTIME_ABI_VERSION` and `LTD_FACE_RUNTIME_CONTRACT_SHA256`. Reject
the runtime if it returns anything other than `LTD_FACE_RUNTIME_OK`. The
contract also publishes the SHA-256 of the exact CPython extension source from
which these loops were extracted.

## Inputs the standalone renderer supplies

The API intentionally starts after asset/evidence selection and before dense
sampling. A standalone integration already has, or must recover, these exact
in-process values:

- For each MiiMask placement: decoded source RGBA8 pixels, the six inverse
  Pillow-affine coefficients in `a0..a5` expression order, output dimensions,
  and the mirrored flag.
- For a shaded placement: shader kind `1..5` plus the exact binary64 C1/C2 RGB
  constants selected by the placement. Unshaded sampling additionally selects
  byte-plane (`0`) or float32-plane (`1`) Pillow behavior.
- For the title blend/store target: zero to 21 shaded RGBA64 layers, sorted by
  unique dispatcher case `0..20`. The four target images and both per-draw
  audit stacks are caller-allocated RGBA8 buffers.
- For Noir's wrinkle target: decoded source RGBA8, skin RGBA8, and the final
  left/right/bottom/top clip bounds. The host must preserve the existing
  float32-FMA transform construction before widening those four bounds to
  binary64 for this call.
- For Johnny's target: the exact 256x512 source RGBA8, skin RGBA8, and four-lane
  binary64 C1/C2 shader constants.

Asset path resolution, evidence/Parts validation, mip/LOD selection, affine
matrix construction, shader routing, color-table lookup, texture decoding,
cache policy, audit SHA-256, and report assembly remain host responsibilities.
None of those require Python; they are simply outside this buffer-kernel ABI.

## Buffer rules

Images are top-left, row-major RGBA. Strides and capacities are expressed in
bytes. RGBA64 pointers and strides must be aligned for `double`. Destinations
must not overlap each other or any source. Dimensions are capped at 4096, mask
layers at 21, and faceline output is fixed at 128x256. Calls fail closed for a
wrong floating-point rounding mode, stale ABI/contract identity, non-finite
numeric inputs, invalid ranges, undersized buffers, or aliases.

## Reproducible proof

Run:

```powershell
python native_runtime/native_face_runtime_verify.py --samples 1
```

The verifier builds the shared library twice under strict floating-point and
reproducible-link settings, compares the binaries, checks imports, static-links
and runs a host-free smoke executable, exercises negative ABI/buffer cases, and
A/B compares all four authoritative fixtures. The final matrix covers portrait
and full-body PNGs at 128 and 512 pixels. All build products live in a temporary
directory and are removed after the verifier process exits.
