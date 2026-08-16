# InfiniMii
Browse, share, and convert Miis across the formats supported by MiiJS
Import older Mii formats and preserve them in the LTD-backed storage path
See the average face across all Miis uploaded
Make Special Miis on a whim
Work with the Miis inside Amiibos
Store up to 50 private Miis for access from any device with a web browser
Comprehensive guide to transfer Miis directly to and from any console without ever modding it
Build your own with the equally open source [MiiJS](https://github.com/Stewared/MiiJS)

Stored Miis can be downloaded in every supported export format except when the
record's source era is `LTD`. LTD-era records preserve their authoritative
container and may only be downloaded as `.ltd`; this is enforced by the server,
not just by format menus.

# Running Your Own
## Installing
```bash
git clone https://github.com/Stewared/InfiniMii
cd InfiniMii
npm ci
```

InfiniMii requires Node.js 20.19 or newer. LTD rendering also requires Python
and the packages pinned in `ltd-renderer/dcmp/renderer/requirements.txt`:

```bash
python -m venv .venv
# Windows
.venv\Scripts\python -m pip install -r ltd-renderer/dcmp/renderer/requirements.txt
# macOS/Linux
.venv/bin/python -m pip install -r ltd-renderer/dcmp/renderer/requirements.txt
```

Point `LTD_RENDERER_PYTHON` at the virtual environment's Python executable if
`python` on `PATH` is not that interpreter.

## Make env.json
Copy `example.env.json` to `env.json` and fill out each of the required fields with your variables.

The email instructions and code are designed for use with Zoho Mail, and mileage may vary for other email providers.

### LTD renderer and asset drop

The LTD renderer source, native-runtime source, manifests, and checked runtime
contracts live in this repository under `ltd-renderer/dcmp`. The large
game-derived asset payloads are deliberately ignored by Git. A working checkout
has this layout:

```text
ltd-renderer/
├── dcmp/
│   ├── renderer/
│   │   └── assets/                 # ignored asset drop
│   ├── manifests/
│   ├── native_runtime/
│   └── tools/
├── ltdDemo_converted_assets/       # ignored asset drop
└── ltdDemo_filesystem/             # ignored checked source assets
```

Merge the prepared `ltd-renderer` asset bundle into the repository root; no
machine-specific path edits are needed. The defaults are
`./ltd-renderer/dcmp` and `./ltd-renderer/ltdDemo_converted_assets`.

- `LTD_RENDERER_ROOT` optionally overrides the tracked `dcmp` directory.
- `LTD_RENDERER_ASSET_ROOT` optionally overrides the converted asset directory.
  Relative overrides are resolved from the InfiniMii repository root, not the
  shell's working directory. Absolute overrides are also supported.
- `LTD_RENDERER_PYTHON` is optional. Set it to an absolute Python executable when
  `python` is not the right interpreter for the service account.
- `LTD_RENDERER_PERSISTENT_WORKER` is optional and defaults to `true`. The
  process-local pool reuses checked Python evidence/model caches while each
  request keeps its own temporary workspace. Set it to `false` to force the
  one-process-per-render compatibility path.

Build the source-sealed native acceleration modules with the same Python
interpreter configured by `LTD_RENDERER_PYTHON` before starting InfiniMii:

```bash
npm run build:native-ltd-renderer
```

On Windows, that command also builds the standalone native LTD runtime. The
application handshakes with it at runtime and uses it only when the executable
reports that its complete pixel pipeline is activated; otherwise the existing
checked renderer remains the compatibility path. Native output is subjected to
the same PNG, source-hash, view, dimension, presentation-context, and render-
report validation before it can enter the image cache.

The generated extension modules are host- and Python-ABI-specific deployment
artifacts and should not be committed. Their ABI and C-source hashes are
checked at import, and InfiniMii includes both the sources and built modules in
the renderer cache revision. If a module is absent or stale, rendering remains
correct through the slower Python fallback.

The repository-relative defaults are deterministic in production. If a service
uses an external asset volume, set an explicit absolute override; on Windows,
escape backslashes in JSON, for example `"D:\\InfiniMiiAssets\\dcmp"`.


## Setup Storage
For local development, `npm run dev` will automatically start an in-memory MongoDB instance if no MongoDB URI is configured.

For persistent storage or production, set `MONGODB_URI` in your shell before starting the app. If `MONGODB_URI` is unset in production, the app falls back to `mongodb://127.0.0.1:27017/infinimii`.

A default Mii ID and such will need to be set. You can use MiiJS to get the necessary JSON if the site won't initialize without one. Paste the JSON into the miis array, and add the following fields to it.
```json
{
    "id":"default",
    "uploader":"USERNAME",
    "desc":"DESCRIPTION",
    "votes":1,
    "official":false,
    "uploadedOn":"148148148148",
    "console":"3DS"
}
```

Once you sign up for the website, find yourself in the `users` model storage, and add the 'administrator' role to your roles array.

## LTD uploads, downloads, and renders

Native LTD uploads are validated and retained byte-for-byte. Older supported Mii
formats are normalized and converted through the pinned LTD-capable MiiJS build
before they enter the LTD render/download path. The original LTD bytes, their
hash, conversion provenance, and render provenance are stored separately from
the query-friendly Mii fields.

Rendering is era-aware. Classic records use the bundled native Tomodachi Life
renderer through internal era-specific profiles. Native/effective LTD records
use the configured LtDRender `dcmp` renderer. These are explicit routes rather
than fallbacks: a selected renderer failure does not silently publish pixels
made by a different renderer.

The Mii Dashboard exposes TL and LTD through “Render As” for supported classic
Miis. LTD-era source files are temporarily unavailable in both the Dashboard
and Kidomatic. The generated `average` Mii remains exempt from LTD-exclusive
capability locks because it is a site utility rather than a source-file archive
entry.

The portable renderer is intentionally fail-closed. Its frozen, hash-bound
selector, component, and runtime-profile evidence admits all 3,152 usable
records in the validated local InfiniMii corpus. Those records are admitted by
their resolved classic resources and evidence, not by Mii ID or whole-file
allowlisting. Native LTDs outside that checked classic selector, runtime-profile,
and evidence domain remain rejected. This coverage does not claim arbitrary
wardrobe or clothing, Canvas/UGC, or other app-specific payload support.

Every usable record in the frozen corpus is expected to render; a failure is an
acceptance failure. A native LTD outside the checked domain remains stored and
can still be downloaded as LTD, but InfiniMii does not create an approximate or
fake render for it. When its missing image is requested, the route returns the
generic `static/assets/ltd-render-unavailable.svg` placeholder with an
`X-InfiniMii-Render-Status: unsupported` response header. A cached LTD PNG is
served only when Mongo records the same canonical LTD hash, renderer revision,
capability, resource signature, view, and size. Classic images use a separate
cache identity bound to the logical profile, backend, native render plan,
output hash, and stored-record update. Consequently a stale LTD-rendered PNG
cannot satisfy a classic-renderer cache check. Otherwise the requested image is
regenerated lazily and replaced atomically; no site-wide render is started.

There is no startup scan or automatic bulk render. New uploads and missing image
requests render only the Mii involved. The background rerender worker accepts
only explicit queue records with `intent: "ltd"` and the current renderer
revision, and it skips records without an existing image cache. Do **not** run
`npm run rerender:all-images` as part of this rollout.

Before enabling this policy behind a CDN, purge cached QR/static-temp and
console-CFSD URLs for records classified as `LTD`, then verify those LTD origins
return 410 with `Cache-Control: no-store`. Non-LTD records retain those export
routes. The server cannot revoke copies already held in individual browser
caches.

The native renderer under `native/tomodachi` is the production classic-renderer
backend. Build it before serving non-LTD renders or running the native semantic
tests:

```bash
npm run build:native-renderer
```

### MiiJS provenance

`package.json` pins the whole archive
`vendor/miijs-3.1.0-ltd-workspace.tgz`. It was packed from the audited MiiJS
worktree based on commit `9734717986f6954c90692c29d5da93985bd72d4d`, including
the coordinated LTD changes that are not yet published in that commit; its SHA-256 is
`ccc6a4f1b1fa3ab02db27934ba42bfb1d65801e45cd03295a12f36b0a95629b1`.
The public registry package `miijs@3.1.0` does not contain this coordinated LTD
codec/conversion work. See `vendor/README.md` before replacing the archive.

### Era-aware download policy

InfiniMii exposes every supported MiiJS export format for ordinary Wii, DS,
3DS, Wii U, Switch, and legacy records. Only Miis classified in the `LTD` era
are restricted to the canonical `.ltd` format. The same server-side policy is
applied to direct exports, dashboard conversions, cached/generated QR assets,
console API CFSD output, Wii Remote imports, Amiibo insertion, and legacy Wii
downloads; UI format menus are not the authorization boundary.

Native LTD uploads remain restricted when their authenticated byte provenance
is present even if a stale record is missing its backfilled era. Missing or
unknown era values on non-native records are not treated as LTD. Read paths
also reconcile stale `era: "LTD"` values against authoritative official
categories, Tomodachi Life data, and declared classic consoles until the
validated era backfill is committed. The generated `average` Mii (John/Jane
Doe) is specifically exempt from LTD-exclusive capability locks, so every
export remains available even when LTD is selected as an ordinary renderer.

`npm run backfill:mii-era` is read-only by default. Its summary reports stored
LTD IDs separately from authenticated native LTD IDs and lists every stale LTD
row with its corrected target era and classification basis.

## Running
```bash
npm run dev
```

For a production-style start:

```bash
MONGODB_URI="mongodb://127.0.0.1:27017/infinimii" npm start
```

## Testing

Run the JavaScript importer, rendering, cache, asset, and metadata suites with:

```bash
npm test
```

After building the native renderer, run both JavaScript and native semantic tests with:

```bash
npm run test:all
```
