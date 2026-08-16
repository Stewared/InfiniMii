# Native render orchestrator ABI 4

`Prepare` authenticates and owns the selected Parts result, scene assembly,
face targets, normalized materials, mip publications, packed fields,
descriptors, and the single mixed draw schedule. It does not render or cache an
output image.

Production requests may provide the source-authenticated runtime material
adapter bundle. In that mode the bundle is the sole authority for normalized
materials, mip publications, generated face targets and keys, UGC pixels and
TexSrt, and NoseLine mips/seals. Request-side material and dynamic publications
must be empty. `Prepare` binds the bundle's LTD/publication/view/size report to
the frame, rebuilds FacePlan from raw CharInfo and byte-compares its generated
targets with the bundle, validates the bundle's NoseLine scene slot, then
creates the provider over the same decoded-asset cache through the adapter's
opaque retained lease. Every required value is copied into pack/plan ownership
and the provider lease is released before `Prepare` returns. Isolated callers
may omit the bundle and retain the ABI 3 typed-publication path.

`Execute` retains ABI 2's one-shot behavior. A successful call consumes the
one-shot admission bit; a second call fails transactionally.

`DetachRequestContext` clears every caller-borrowed pointer/span retained in
the request shell and permanently disables legacy `Execute` for that plan. It
is idempotent. A plan must be detached before `ExecuteReusable` accepts it.

`ExecuteReusable` re-rasterizes an already authenticated detached plan. It always
creates a new pipeline/frame and returns newly transferred pixels and a newly
encoded PNG. Callers must serialize calls for one `PreparedRender` and must
authenticate the complete plan key and live source set before each cache hit.
It is not an output cache.

Every reusable call requires a fresh `ExecutionContext`. In particular, the
PNG encoder and cancellation pointers from the original `Request` must not be
relied on after the original request owners expire. Production callers open
and authenticate the PNG backend for the current request, pass that encoder in
the context, retain it through the synchronous call, and then close it. A null
encoder fails before changing the output.

Every reusable call also reauthenticates linked module ABI/contracts and
checks that the current thread still uses `FE_TONEAREST`. It temporarily binds
the fresh context during synchronous execution and restores the detached null
state on every return.

An admitted reusable-plan key must include at least:

- exact LTD/input SHA-256 and effective CharInfo/Parts selection identity;
- view, raster size, supersampling/presentation identity, and draw limits;
- active-parts, asset-index, scene-plan, material-plan, and publication seals;
- Parts/material catalog and source-bundle pins;
- scene model, pose, material evidence, authored texture, mip-manifest, mip
  level, face-plan, UGC, and NoseLine source identities;
- field/schedule/descriptor/draw/pipeline/orchestrator ABI contracts; and
- the currently authenticated PNG backend identity.

Metadata-only file freshness is not accepted as source authentication. A
caller may either re-read and hash each authoritative source for every request
or retain handles opened without write/delete sharing after the first exact
hash. A mismatch, unavailable dependency, cancellation, or missing execution
context fails closed and leaves the caller's output unchanged.

The retained isolated profiler compiles ABI 4 reproducibly and verifies all 16
authoritative fixture/view/size cases. For each case it performs two reusable
executions, compares both with the embedded accepted PNG byte-for-byte, checks
cancellation/null-context/legacy-after-detach transactionality, and confirms a
separate undetached plan's original one-shot `Execute` can succeed exactly
once.
