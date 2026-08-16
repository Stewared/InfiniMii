# Native draw descriptor builder ABI 1

This module is the source-sealed bridge between immutable scene/material
records and the pointer-bearing `native_draw_runtime` ABI 1/2 inputs. A build
request combines one `native_material_schedule` source/output pair with the
matching scene draw and model provenance view. The builder verifies dependency
contracts, schedule identity, transforms, triangle counts, texture-plan and
packed-input hashes, scene geometry, material UV routing, Head816 `_u0`/`_u2`
selection, and source-triangle normal validity.

Every packed field is copied into type-aligned storage owned by an opaque
`ltd_native_draw_descriptor`. Exactly one typed command pointer is returned for
Body324/336/348, Ear372/Nose756, Mask0, Head816, Hair612/564, Beard468, or
Outfit984/936/912. All pointers remain valid until the descriptor is destroyed;
the caller retains ownership only of writable render attachments. Unknown
profiles and any source, schedule, scene, model, field, texture, or nonfinite
drift fail closed.

On Windows, validation of the canonical packed-field SHA-256 streams the
domain, profile header, per-field headers, and field bytes through the system
BCrypt SHA-256 provider. The canonical byte sequence and ABI 1 contract are
unchanged; texture-plan hashing remains on the existing implementation.
BCrypt provider, property, update, or finalization failures fail closed as a
source mismatch, while allocation failures retain the existing allocation
failure status.

Run the verifier from the repository root:

```powershell
python tools\verify_native_draw_descriptor_builder.py --asset-root ..\ltdDemo_converted_assets
```

The verifier builds the C++ DLL twice with MSVC `/W4 /WX /O2 /MT /fp:strict
/Brepro`, checks that the binaries and dependencies are identical, and routes
all 252 accepted typed draws through the resulting descriptors and standalone
ABI1/ABI2 runtimes. It compares every attachment-changing draw directly with
the current extension and all final PNG bytes for four authoritative fixtures,
portrait/full-body, at 128/512 (16 cases). It also checks stale seals, packed
digest drift, direct canonical-byte digest equivalence, packed-field byte
mutation and malformed-field rejection, scene-count drift, and ABI mismatch
rejection. The Windows dependency inventory includes the system `bcrypt.dll`.

This ABI deliberately consumes scheduler-authenticated packed fields. Removing
that prepack dependency belongs to the native material/field producer boundary;
the descriptor builder itself never interprets Python or NumPy objects.
