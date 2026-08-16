# Native NoseLine pipeline bridge ABI 1

This small adapter connects the accepted `native_scene_assembler` NoseLine12
draw to the frozen `native_noseline12` kernel without weakening either source
contract. It requires the exact MiiNose06/profile 14/group identity, opaque
depth-writing state, two candidate/submitted triangles, source indices
370/371, bit-identical shared carrier vertices, and sealed material/`_u0` UV
topology. It extracts OBJ carriers 402..405 and delegates transactionally to
the frozen kernel using caller-owned RGB/depth/optional-alpha attachments.

The texture handoff is deliberately typed rather than pretending NoseLine is a
normal material role: it carries the complete nine-level linear RGBA64 mip bank
plus the frozen global-manifest and decoded-chain seals. A later standalone
runtime integration must populate this view from the immutable mip-chain cache
and keep it alive synchronously through the draw.

The isolated verifier proves the full mii1 schedule places Mask0, NoseLine12,
and Head816 at indices 12, 13, and 14; checks all four portrait/full-body and
128/512 cases byte-for-byte against a direct kernel call; rejects an identity
mutation transactionally; and reruns the four production final-PNG A/B cases.

Activation remains false. Linking this bridge does not by itself make the
standalone renderer production-ready; the complete scheduled command inventory,
material provider, face plan, reporting, and all-16 final render admission must
also succeed.

