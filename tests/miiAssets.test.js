import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
    deleteMiiAssets,
    ensureMiiAssetDirectories,
    getMiiAssetPaths,
    moveMiiAssets
} from "../miiAssets.js";

test("moves and deletes a Mii's asset set concurrently", async () => {
    ensureMiiAssetDirectories();
    const id = `asset-test-${process.pid}-${Date.now()}`;
    const publicPaths = getMiiAssetPaths(id, false);
    const privatePaths = getMiiAssetPaths(id, true);
    const activeKeys = ["imgPath", "qrPath", "qrWiiPath", "qrTomodachiPath"];

    try {
        await Promise.all(activeKeys.map(key => fs.promises.writeFile(publicPaths[key], key)));
        await moveMiiAssets(id, false, true);

        for (const key of activeKeys) {
            assert.equal(await fs.promises.readFile(privatePaths[key], "utf8"), key);
            await assert.rejects(fs.promises.access(publicPaths[key]), { code: "ENOENT" });
            assert.equal(path.isAbsolute(privatePaths[key]), true);
        }

        await fs.promises.writeFile(publicPaths.imgPath, "destination-only");
        await moveMiiAssets(id, true, false);
        assert.equal(await fs.promises.readFile(publicPaths.imgPath, "utf8"), "imgPath");
        await moveMiiAssets(id, true, false);
        assert.equal(await fs.promises.readFile(publicPaths.imgPath, "utf8"), "imgPath");

        await deleteMiiAssets(id, false);
        for (const key of activeKeys) {
            await assert.rejects(fs.promises.access(publicPaths[key]), { code: "ENOENT" });
        }
    } finally {
        await Promise.all([
            deleteMiiAssets(id, false),
            deleteMiiAssets(id, true)
        ]);
    }
});
