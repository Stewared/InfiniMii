# Native draw runtime ABI 2

`native_draw_runtime_v2.h` exposes the remaining accepted whole-draw kernels as
a CPython-free C buffer ABI. The ABI-2 translation unit includes the frozen ABI-1
implementation, so consumers compile **only** `native_draw_runtime_v2.c` to get
both ABI generations in one DLL or static object. Do not compile
`native_draw_runtime.c` separately into that same binary.

## Exact scope

ABI 2 adds three calls:

- `ltd_draw_head816`: current Head816, including optional albedo, normal mapping,
  alpha cutoff, geometric-normal fallback, and the accepted perspective path.
- `ltd_draw_hair`: the shared exact kernel selected by mandatory profile
  `612` (Hair612), `564` (Hair564 equal-endpoint), or `468` (Beard468).
- `ltd_draw_outfit`: the shared exact kernel selected by mandatory profile
  `984` (tops), `936` (bottoms), or `912` (shoes).

Together with ABI 1, this covers every accepted current whole-draw profile:
Head816; Hair612/564EqualEndpoint/Beard468; Outfit984/936/912;
Body324/336/348; Ear372; Nose756; and Mask0. No shader/profile inference occurs
inside the library.

All inputs and caller-owned attachments are plain C descriptors. There are no
Python, NumPy, STL, filesystem, asset-loader, or PNG dependencies. The caller
retains ownership and lifetime responsibility for every input and output buffer.
Only color, depth, and optional alpha attachments are mutated.

## Admission and fail-closed boundary

The standalone ABI consumes already flattened, authenticated draw payloads. The
host must preserve the production material/model admission boundary before
constructing these inputs. ABI 2 seals that boundary with:

- ABI version: `2`
- contract SHA-256:
  `6f136e1133dbce3396157a53907fa0167743443c798a40d57fa40cff9192e5f2`
- accepted wrapper SHA-256:
  `405365df31ca29e5938acb63ec59a53b30c7130c4fbc6e1d97d83bfc910ae7d4`
- accepted current kernel SHA-256:
  `14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d`

The contract digest is SHA-256 over this UTF-8 canonical record:

```text
ltd.native.draw.runtime.v2|abi=2|base_contract=64db57c14e2ccf01eff2f24fa158caf7ef7635877f75645a3fa109c792cce283|ops=head816,hair612,hair564equal,beard468,outfit984,outfit936,outfit912|kernel=14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d|wrapper=405365df31ca29e5938acb63ec59a53b30c7130c4fbc6e1d97d83bfc910ae7d4
```

Call `ltd_draw_runtime_v2_require` before dispatch. The runtime rejects unknown
profiles, malformed/count-mismatched buffers, aliased or undersized attachments,
non-finite values, invalid flags, wrong rounding mode, and a Hair564 versus
anisotropy-execution mismatch. It does not silently select a nearby profile.

Hair `parameters` is the accepted 33-double flat parameter record. Profile 564
requires parameter 32 (`execute_anisotropy`) to be zero; profiles 612 and 468
require it to be one. Parameters 26 and 27 are boolean, parameter 25 is exactly
`-1` or `1`, and the reserved field must be zero. Outfit inputs require the
accepted perspective flag (`1`) and an explicit 984/936/912 profile.

## Reproducible verification

From the repository root:

```powershell
python native_runtime/native_draw_runtime_v2_verify.py --asset-root ..\ltdDemo_converted_assets
```

On Windows the verifier builds twice with MSVC x64 `/O2 /MT /fp:strict /W4
/WX /std:c17 /Brepro`, verifies byte-identical DLLs and the dependency table,
and statically links/runs `native_draw_runtime_v2_smoke.c`. Build products live
only in temporary directories.

It first gates a focused mii1/mii2 portrait@128 pass. It then directly compares
all 80 accepted per-draw calls against the production CPython extension and
requires byte-identical color/depth/alpha buffers plus exact fragment counts.
Finally it requires byte-identical final PNGs for all four authoritative LTD
fixtures, portrait and full-body, at 128 and 512 pixels (16 cases). Source seals
and negative ABI/profile/flag/attachment tests are mandatory.
