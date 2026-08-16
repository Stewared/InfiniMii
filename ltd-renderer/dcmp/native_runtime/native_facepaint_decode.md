# Native ShareMii facepaint decoder ABI 1

`native_facepaint_decode.{h,cpp}` implements the complete current ShareMii v3
embedded facepaint decode without Python or NumPy:

- exactly one known-content-size Zstandard frame per payload;
- 256×256 RGBA8 NVN block-linear (`blockHeight=16` GOBs) Canvas deswizzle;
- 128×128 NVN block-linear BC1-block UGC deswizzle;
- exact little-endian BC1 RGB565 endpoint, selector, four-color, and
  three-color-plus-transparent decode to 512×512 RGBA8;
- exact float32 `FacePaintSize`, `FacePaintOffset`, derived binder SRT, and the
  documented portable ModeMaya affine.

The C ABI accepts the already parsed container version, presence flags, and
compressed spans. This is intentional: the standalone runtime already owns
LTD framing and can hand these immutable spans directly to the decoder. A v2
or v3 file with no declared payloads returns `ABSENT`; embedded data on a
non-v3 container and incomplete v3 pairs fail closed.

## Ownership and zstd boundary

Canvas and UGC outputs are fixed-size buffers owned by the caller. The decoder
allocates only bounded temporary decompression storage and returns no heap
object. Inputs and outputs must not overlap. It validates both compressed
frames before changing caller output.

The caller supplies a four-function native zstd table matching
`ZSTD_findFrameCompressedSize`, `ZSTD_getFrameContentSize`, `ZSTD_decompress`,
and `ZSTD_isError`. This lets the existing standalone executable reuse its
already loaded `libzstd.dll`; the decoder DLL itself has no dynamic-loader,
filesystem, subprocess, or Python dependency. `ZSTD_CONTENTSIZE_UNKNOWN` is
`UINT64_MAX`; `ZSTD_CONTENTSIZE_ERROR` is `UINT64_MAX-1`.

## Scope and readiness

This module is decode-complete for the authoritative ShareMii facepaint
contract, but it does not change whole-renderer activation readiness. Native
Mask0 material binding, sampling, coverage, draw execution, and end-to-end PNG
parity remain separate pipeline responsibilities.

Run the isolated verifier with:

```powershell
python tools/verify_native_facepaint_decode.py
```

It performs byte-identical strict `/Brepro` dual builds, requires only
`KERNEL32.dll`, compares every decoded byte to
`renderer/share_mii_facepaint.py` for `mii0`, `mii1`, `mii2`, and `mii4`,
checks every TexSrt float bit, verifies caller-buffer guard bytes and repeat
determinism, and exercises malformed versions, flags, buffers, zstd adapters,
magic, trailing/concatenated/truncated frames, unknown/wrong content sizes,
and absent records.

