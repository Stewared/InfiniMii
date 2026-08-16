# Native render pipeline ABI 2

`native_render_pipeline` is a compile-clean, CPython-free orchestration boundary for the
current portable renderer. It authenticates the linked scene, pose, geometry, raster,
draw-v2, face, postprocess, and PNG ABIs; owns frame/depth/alpha, face-target, transfer,
and PNG buffers; applies the stable native draw schedule; and dispatches immutable typed
draw inputs synchronously. The PNG encoder is borrowed and must already be opened against
the absolute, authenticated zlib-ng compatibility DLL.

The pipeline production gate is active for the four authenticated LTD fixtures, both
supported views, and 128/512 output. The owning standalone orchestrator constructs and
source-authenticates every precompiled draw descriptor before entering this ABI. Individual
profile rows remain kernel-capability metadata rather than a second activation gate.

## Ownership and state

The pipeline copies the five 64-character lower-case SHA-256 request seals, then owns every
destination allocation until the next `begin_frame` or destruction. Draw descriptors and
all recursively referenced mesh/texture arrays are borrowed only during the synchronous
`execute_precompiled_draws` call. Output and face views are immutable and pipeline-owned.
The state sequence is `idle -> frame -> draws -> finished`; a mid-draw failure makes the
current frame unusable, while a fresh `begin_frame` replaces completed or failed state.
Cancellation is sampled at every bounded stage and between draws.

The source seals are a fail-closed transport boundary, not a hash producer. The standalone
request owner calculates them from authenticated LTD, Parts, asset-index, scene-plan, and
material-plan inputs before calling this ABI.

## Profile boundary

ABI 2 dispatches Head816; Body324/336/348; Ear372; Nose756; Mask0; Hair612;
Hair564EqualEndpoint; Beard468; OutfitTops984/Bottoms936/Shoes912; and the strict
NoseLine12 bridge. Their support rows
set `kernel_available=true`; material compilation is owned by the linked material provider
and field packer outside this pipeline.

NoseLine12 remains the bridge's exact source-authenticated MiiNose06 carrier and sealed
nine-level texture contract. It is accepted as a typed scene+texture view in the same
scheduled command array as every draw. The stable scene scheduler executes Mask0,
NoseLine12, then Head816 in a single loop; there is no separate NoseLine pass or batch.
The bridge remains transactional, and any identity, topology, UV, texture-seal, or kernel
failure fails the frame before finish can expose it.

The exact fail-closed kernel list is GlassFrame360, GlassLens60 opaque,
GlassLens60 translucent, Decoration480, Decoration492, Hair396, Hair408, Hair420,
Hair432, Hair672, Hair708, Hair1056, Hair1116, Beard456, and LegacyHeadwear96. Submitting
any of these returns `PROFILE_UNIMPLEMENTED` before a framebuffer mutation.

## Activation scope

Activation is deliberately limited to the four source-authenticated fixtures and the exact
view/size/presentation matrix admitted by the standalone runtime. Unsupported fixtures,
presentation contexts, profiles, or source identities fail closed before publication.

These are current-portable-output requirements. They do not establish title-native GPU
shader, scene, or postprocess evidence and must not be described as a recovered title
renderer.
