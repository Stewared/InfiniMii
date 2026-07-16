# InfiniMii
Browse, share, and download Miis
Convert from any Mii format to any other format
See the average face across all Miis uploaded
Make Special Miis on a whim
Work with the Miis inside Amiibos
Store up to 50 private Miis for access from any device with a web browser
Transfer Miis between systems with no limitations
Backport 3DS Miis to the Wii
Comprehensive guide to transfer Miis directly to and from any console without ever modding it
Generate and scan QR codes
Build your own with the equally open source [MiiJS](https://github.com/Stewared/MiiJS)

# Running Your Own
## Installing
```bash
git clone https://github.com/Stewared/InfiniMii
cd InfiniMii
npm i
```
## Make env.json
Copy `example.env.json` to `env.json` and fill out each of the required fields with your variables.

The email instructions and code are designed for use with Zoho Mail, and mileage may vary for other email providers.


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

## Native Mii portraits

Standard Mii portraits and full-body images are rendered locally through the bundled, decomp-backed Tomodachi renderer and full wardrobe catalog in `native/tomodachi`. This applies to both TL and non-TL Miis. Portraits retain the site's established face framing, while full-body images use the source-backed FFL whole-body camera. Both modes produce transparent output at the requested dimensions.

Windows x64 binaries are bundled. On other platforms, build the same checked-in C sources before starting the site (the systemd installer does this automatically):

```bash
npm run build:native-renderer
```

After restoring a database that predates MiiJS's TL outfit/hat palette fields, place the private audited recovery report in `native/tomodachi/local-audit` and run `npm run migrate:tl-palette-selectors`. Regenerate every stored image cache with `npm run rerender:all-images`.

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
