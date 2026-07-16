# Bundled Tomodachi renderer

This directory is the self-contained native Mii render runtime used by
InfiniMii. It contains the decomp-backed CPU renderer, the full extracted
Tomodachi Life body/headwear catalogs, their audited material/LUT sidecars,
and only the common model resources that the runtime actually reads. The
bundled `assets/FFLResHigh.dat` is the preferred face-texture source for all
eleven FFL texture categories: beard, cap, eye, eyebrow, faceline, makeup,
glasses, mole, mouth, mustache, and noseline. CFL remains the source of the
feature shapes and is the per-record texture fallback when the high resource
does not contain a usable record.

The checked-in `bin/win32-x64` executables are built from `src` with the root
`CMakeLists.txt`. Other platforms can build equivalent binaries with:

```sh
cmake -S native/tomodachi -B native/tomodachi/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/tomodachi/build --config Release
```

The default CLI mode retains the audited 512x1088 orthographic portrait
viewport. Passing `--full-body` selects a 512x512 perspective viewport using
FFL.js `BodyUtilities.getWholeBodyCamera`: 15-degree vertical field of view
and the source height-dependent camera Y/Z formula. The native FFL-coordinate
scene is bridged through `BodyUtilities.attachHeadToBody`'s exact 1/7 head
scale and the attached physical body's model root. No per-Mii bounds fit or
post-render crop participates in full-body placement.

Renderer inputs use MiiJS's forward-ported Switch representation. Feature
colors are direct indices into the 100-entry common-color tables, faceline
colors use the 10-entry Switch table, and Tomodachi hair-dye mode 1 affects
hair while mode 2 affects hair and eyebrows. Facial hair is not dyed. Modern
glasses types 9-19 are mapped through MiiJS's supported Switch-to-Ver3 table
before the nine-entry CFL glasses resource is read. The face mask follows
FFL's two-pass blend, which keeps eyebrows in front of overlapping eyes and
reconstructs feature alpha over a genuinely transparent mask background.
The resource header, rather than its filename, selects the official layout.
The supplied file identifies as the linear AFL-high variant and therefore has
the AFL eye, eyebrow, and mouth counts. The loader also supports the tiled
default FFL layout using the vendored GX2 address calculation. Only the base
mip is needed by this CPU portrait renderer. The high resource's cap table is
intentionally sparse (14 of 132 records); missing records are not fabricated.
FFL RG8 glass keeps its red coverage and green tint-intensity channels
distinct: modulation mode 4 uses G for color and R for alpha. Mode 3 likewise
follows `FFLModulateParam` by premultiplying tint RGB with texture R before
the raw-mask blend.

Set `TOMODACHI_NATIVE_RENDERER_BIN_DIR` only to point at a locally built pair
of `render_body_model` and `render_headwear_model` executables. InfiniMii uses
the bundled Windows x64 pair by default and never reads the original Decomp or
ResearchingTomodachi worktrees at runtime.

Catalog selection mirrors `render_infinimii_tl.py`: regular clothes item zero
uses the Mii favorite color, file zero selects the gender/Special variants,
and all other outfit/headwear models and colors come from the catalog rows.
`Foreign` does not imply the `Ot` island-lookalike body because the stored Mii
object has no island scene context that would justify that choice.

The decompressor is miniz 3.1.2, vendored under `vendor/miniz`. The GX2
address/surface subset under `vendor/nintexutils` was copied from the local
`Decomp/reference_repos/FFL-Testing/ninTexUtils` source used by the supported
FFL implementation. Their license texts and fuller provenance are recorded in
`NOTICE.md`.
