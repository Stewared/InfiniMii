# Native NoseLine12 kernel

`native_noseline12.h` and `native_noseline12.c` implement the accepted
MiiNose06 `NoseLine__mt_NoseLine` draw as a standalone C17 ABI. The module
does not allocate, parse assets, import CPython, or depend on NumPy.

The source evidence describes a **four-vertex, two-triangle** carrier. Earlier
task wording calling it four triangles was incorrect. The sealed triangles are
OBJ indices `(402,403,404)` and `(404,403,405)`, represented by local indices
`(0,1,2)` and `(2,1,3)`. Only Kestron/mii1 selects MiiNose06 among the four
authoritative fixtures; mii0, mii2, and mii4 submit no NoseLine12 draw.

## Exact draw contract

The caller supplies the four projected `(x, y, reciprocal-depth)` vertices,
the complete decoded nine-level RGBA64 mip bank, and exact source seals. The
kernel performs:

- counter-clockwise front-face admission and two submitted triangles;
- pixel-center coverage with the accepted `-1e-7` edge threshold;
- reverse-depth `GEQUAL` early depth;
- perspective-correct UV interpolation;
- affine screen-gradient LOD, point selection of the nearest mip;
- repeat/repeat bilinear sampling with OBJ V orientation;
- sampled red `GEQUAL 0.5` coverage;
- opaque linear RGB replacement with the IEC-sRGB decode of `#221817`;
- depth replacement and optional target-alpha replacement with one.

The report distinguishes submitted triangles, selected mip per triangle,
early-depth candidate fragments, alpha-selected fragments, and writes. A
shared-edge pixel may be counted once per submitted triangle, matching the
generic rasterizer's ordered execution.

## Admission and lifetime

Call `ltd_noseline12_require` at integration startup with the published ABI
and contract fingerprint. Each draw additionally requires exact fingerprints
for MiiNose06.obj, the texture manifest, and the decoded mip bank. The decoded
mip content is rehashed before a draw, so changing values without changing the
declared seal fails closed.

All pointers and storage remain caller-owned and must stay alive for the call.
Color, depth, optional alpha, input, report, and mip storage must be disjoint.
Dimensions, strides, capacities, mip layout, finite input and attachment
values, and the round-to-nearest floating-point mode are validated before any
write. Failed validation leaves the report and attachments unchanged. The
kernel temporarily holds and restores the caller's floating-point environment
during accepted arithmetic.

## Isolated verification

Run from the repository root:

```powershell
python tools/verify_native_noseline12.py
```

The verifier builds the DLL twice with MSVC `/W4 /WX /O2 /MT /fp:strict` and
`/Brepro`, requires byte-identical binaries and no Python dependency, and
checks source/content mutation, capacity, nonfinite, alias, ABI, contract, and
optional-alpha behavior. It installs an isolated draw hook for Kestron and
compares the C attachments directly with the unaccelerated generic
`software_renderer` draw. It then requires byte-identical final PNGs and
reports for portrait/full-body at 128 and 512 pixels using the native-resolution
production profile (`supersample_factor=1`).

This module is not linked into `ltd_native_runtime` yet. Integration is a
separate serialized step after this source boundary freezes.
