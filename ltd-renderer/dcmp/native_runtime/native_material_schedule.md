# Native material schedule ABI 1

`native_material_schedule.h` and `.cpp` provide a standalone C ABI that turns
normalized Parts/DecodedAssetCache draw records into immutable dispatch records
for `native_draw_runtime` ABI 1 and ABI 2. The module has no Python, NumPy,
filesystem, or asset-decoding dependency; all strings, transforms, packed draw
fields, mip extents, and decoded-chain hashes are supplied by the caller.

The compiler preserves the accepted renderer order (pre-head prefix, stable
opaque priority order, then translucent draws), validates source seals and exact
material fingerprints, and emits texture-plan and packed-ABI SHA-256 digests.
It recognizes Body 324/336/348, Outfit 984/936/912, Mask 0, Head 816, Ear 372,
Nose 756, Hair 612/564, and Beard 468. Unsupported records such as NoseLine 12
remain in scheduling order but are not dispatched.

The Ear 372 fingerprint requires UV and normal geometry; clockwise winding is
the only accepted flag variation between the paired authoritative ear draws.
Unknown profiles, stale source seals, malformed bindings, and insufficient
output capacity fail closed.

Run the reproducible oracle verifier from the repository root:

```powershell
python native_runtime\native_material_schedule_verify.py --asset-root ..\ltdDemo_converted_assets
```

It builds the DLL twice with MSVC `/W4 /WX /O2 /MT /fp:strict /Brepro`, checks
the dependency inventory, then compares draw order, profiles, triangle counts,
transforms, texture-plan hashes, and packed ABI-input hashes for the four
authoritative fixtures in portrait/full-body views at 128 and 512 pixels (16
cases). It also exercises source-seal and bounded-output rejection paths. Build
products live only in temporary directories and are removed on exit.
