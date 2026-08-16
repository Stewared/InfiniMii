# LTD runtime layout

`dcmp` contains the renderer source, checked contracts, manifests, build
helpers, and native-runtime source used by InfiniMii. These files are tracked
with the application so they move together.

Three large LTD asset directories are intentionally not tracked:

```text
ltd-renderer/ltdDemo_converted_assets/
ltd-renderer/ltdDemo_filesystem/
ltd-renderer/dcmp/renderer/assets/
```

The prepared asset bundle may also contain the ignored shader-work, title
geometry, reference images, and checked tool binaries already named in the
repository `.gitignore`. Drop or merge the bundle's `ltd-renderer` directory at
the repository root. InfiniMii uses this layout automatically; no environment
path is required.

For a nonstandard deployment, `LTD_RENDERER_ROOT` and
`LTD_RENDERER_ASSET_ROOT` may be absolute paths or paths relative to the
InfiniMii repository root.

Install the Python dependencies before rendering:

```bash
python -m pip install -r ltd-renderer/dcmp/renderer/requirements.txt
```

The native acceleration modules are host- and Python-ABI-specific. Build them
locally with `npm run build:native-ltd-renderer`; generated binaries remain
ignored.
