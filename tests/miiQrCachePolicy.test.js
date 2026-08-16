import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    isCurrentMiiQrCacheAsset,
    publishMiiQrCacheIdentity
} from "../miiQrCachePolicy.js";

test("QR cache identity binds source, console, portrait, and the current renderer policy", async () => {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-qr-cache-"));
    const qrPath = path.join(root, "mii.png");
    const portraitPath = path.join(root, "portrait.png");
    const source = {
        id: "qrCachePolicyTest",
        era: "RCD",
        meta: { name: "Ironman", type: "Default" },
        general: { height: 64 }
    };
    try {
        await fs.promises.writeFile(qrPath, "qr-v1");
        await fs.promises.writeFile(portraitPath, "portrait-v1");
        assert.equal(await isCurrentMiiQrCacheAsset(source, qrPath, "3DS", portraitPath), false);

        await publishMiiQrCacheIdentity(source, qrPath, "3DS", portraitPath);
        assert.equal(await isCurrentMiiQrCacheAsset(source, qrPath, "3DS", portraitPath), true);
        assert.equal(await isCurrentMiiQrCacheAsset(source, qrPath, "WIIU", portraitPath), false);
        assert.equal(
            await isCurrentMiiQrCacheAsset({ ...source, general: { height: 65 } }, qrPath, "3DS", portraitPath),
            false
        );
        assert.equal(
            await isCurrentMiiQrCacheAsset({ ...source, era: "CFCD" }, qrPath, "3DS", portraitPath),
            false
        );

        await fs.promises.writeFile(portraitPath, "portrait-v2");
        assert.equal(await isCurrentMiiQrCacheAsset(source, qrPath, "3DS", portraitPath), false);

        await fs.promises.writeFile(portraitPath, "portrait-v1");
        await fs.promises.writeFile(qrPath, "corrupted-qr");
        assert.equal(await isCurrentMiiQrCacheAsset(source, qrPath, "3DS", portraitPath), false);
    } finally {
        await fs.promises.rm(root, { recursive: true, force: true });
    }
});
