import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
    getAverageMiiPresentation,
    selectMostCommonMiiRendererProfile
} from "../averageMiiPresentation.js";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const indexSource = fs.readFileSync(path.join(testDirectory, "..", "index.js"), "utf8");

test("average Mii chooses the website's most common renderer profile", () => {
    assert.equal(selectMostCommonMiiRendererProfile({ TL: 1773, RFL: 1378, LTD: 4 }), "TL");
    assert.equal(selectMostCommonMiiRendererProfile(new Map([
        ["TL", 12],
        ["RFL", 20],
        ["LTD", 3]
    ])), "RFL");
});

test("average renderer ties have a stable non-LTD preference", () => {
    assert.equal(selectMostCommonMiiRendererProfile({ TL: 5, RFL: 5, LTD: 5 }), "TL");
    assert.equal(selectMostCommonMiiRendererProfile({ RFL: 5, LTD: 5 }), "RFL");
    assert.equal(selectMostCommonMiiRendererProfile({}), "TL");
});

test("average presentation maps renderer style to an explicit synthetic era", () => {
    assert.deepEqual(getAverageMiiPresentation("TL"), {
        rendererProfile: "TL",
        era: "CHARINFO",
        console: "Mii Studio"
    });
    assert.deepEqual(getAverageMiiPresentation("RFL"), {
        rendererProfile: "RFL",
        era: "RCD",
        console: "Wii"
    });
    assert.deepEqual(getAverageMiiPresentation("LTD"), {
        rendererProfile: "LTD",
        era: "LTD",
        console: "LTD"
    });
    assert.throws(() => getAverageMiiPresentation("unknown"), /Unsupported/);
});

test("average refresh bypasses source-era inference and refreshes matching QR assets", () => {
    const setAverageBody = indexSource.match(/async function setAverageMii\(\)\{([\s\S]*?)\n\}\n\nasync function syncAverageMiiAssets/)?.[1] || "";
    const syncAverageBody = indexSource.match(/async function syncAverageMiiAssets\(avgMii\) \{([\s\S]*?)\n\}\n\nasync function refreshAverageMiiAssets/)?.[1] || "";
    assert.match(setAverageBody, /selectMostCommonMiiRendererProfile/);
    assert.match(setAverageBody, /rendererStyleCursor = Miis\.find\(\{[\s\S]*?private: false,[\s\S]*?published: true,[\s\S]*?id: \{ \$ne: "average" \}/);
    assert.match(setAverageBody, /collectWebsiteRendererProfileCounts\(rendererStyleCursor\)/);
    assert.match(indexSource, /collectWebsiteRendererProfileCounts[\s\S]*?hasRenderableMiiPageData\(mii\)/);
    assert.doesNotMatch(setAverageBody, /rendererStyleCursor[\s\S]*?AVERAGE_MII_EXCLUDED_TAGS/);
    assert.match(setAverageBody, /avg\.era = averagePresentation\.era/);
    assert.doesNotMatch(setAverageBody, /assignMiiEra\s*\(/);
    assert.match(syncAverageBody, /ensureCurrentStoredMiiImageAsset/);
    assert.match(syncAverageBody, /syncStoredMiiQrAssets\(avgMii, \{ isPrivate: false, onlyMissing: false \}\)/);
});
