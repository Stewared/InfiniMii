import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ejs from "ejs";

import {
    MII_FACEPAINT_CLASSIFICATION_POLICY,
    MII_FACEPAINT_FILTER_OPTIONS,
    MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD,
    MII_FACEPAINT_TOTAL_PIXELS,
    applyMiiFacepaintSearchFilter,
    buildBlockedContentConditions,
    classifyDecodedLtdFacepaintBc1,
    combineRequestedMiiContentFilters,
    getMiiContentSettingsExemptIds,
    getMiiFacepaintUsage,
    getRequestedMiiFacepaintFilters,
    isMiiBlockedByEraOrFacepaint,
    isMiiExemptFromEraOrFacepaintSettings,
    isMiiExemptFromContentSettings,
    normalizeBlockedFacepaintUsages,
    normalizeBlockedMiiEras,
    preserveMiiContentSettingsExemptions
} from "../miiContentFilters.js";
import { MII_ERA_FILTER_OPTIONS } from "../miiEraSearchFilters.js";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const searchControlsTemplate = path.join(testDirectory, "..", "ejsFiles", "advancedSearchControls.ejs");
const legacySearchFiltersTemplate = path.join(testDirectory, "..", "ejsFiles", "advancedSearchFilters.ejs");
const miiPageTemplate = path.join(testDirectory, "..", "ejsFiles", "miiPage.ejs");
const settingsTemplate = path.join(testDirectory, "..", "ejsFiles", "settings.ejs");
const indexSource = await fs.readFile(path.join(testDirectory, "..", "index.js"), "utf8");
const databaseSource = await fs.readFile(path.join(testDirectory, "..", "database.js"), "utf8");
const backfillSource = await fs.readFile(
    path.join(testDirectory, "..", "scripts", "backfillMiiFacepaintUsage.js"),
    "utf8"
);

function transparentBc1Surface(opaqueBlockCount = 0) {
    const bytes = new Uint8Array(MII_FACEPAINT_TOTAL_PIXELS / 2);
    for (let offset = 0; offset < bytes.length; offset += 8) {
        // color0 <= color1 and selector 3 makes every pixel transparent.
        bytes[offset + 4] = 0xff;
        bytes[offset + 5] = 0xff;
        bytes[offset + 6] = 0xff;
        bytes[offset + 7] = 0xff;
    }
    for (let block = 0; block < opaqueBlockCount; block += 1) {
        const offset = block * 8;
        // color0 > color1 selects BC1 four-color mode, where all 16 pixels are opaque.
        bytes[offset] = 1;
        bytes[offset + 4] = 0;
        bytes[offset + 5] = 0;
        bytes[offset + 6] = 0;
        bytes[offset + 7] = 0;
    }
    return bytes;
}

test("settings era values canonicalize TL without accepting unknown eras", () => {
    assert.deepEqual(
        normalizeBlockedMiiEras(["ltd", "TL", "CFCD", "bogus", "RCD"]),
        ["RCD", "CFCD", "LTD"]
    );
});

test("facepaint block values are ordered, canonical, and limited to painted categories", () => {
    assert.deepEqual(normalizeBlockedFacepaintUsages(["FULL", "partial", "none", "bogus"]), [
        "partial",
        "full"
    ]);
    assert.deepEqual(MII_FACEPAINT_FILTER_OPTIONS.map(option => option.label), [
        "Uses Partial Facepaint",
        "Uses Full Facepaint"
    ]);
});

test("native BC1 alpha measurement applies the versioned site coverage boundary", () => {
    const blocksAtFullThreshold = MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD / 16;
    assert.equal(classifyDecodedLtdFacepaintBc1(transparentBc1Surface()).usage, "none");

    const partial = classifyDecodedLtdFacepaintBc1(
        transparentBc1Surface(blocksAtFullThreshold - 1)
    );
    assert.equal(partial.usage, "partial");
    assert.equal(partial.opaquePixels, MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD - 16);

    const full = classifyDecodedLtdFacepaintBc1(
        transparentBc1Surface(blocksAtFullThreshold)
    );
    assert.equal(full.usage, "full");
    assert.equal(full.opaquePixels, MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD);
    assert.equal(full.policy, MII_FACEPAINT_CLASSIFICATION_POLICY);
    assert.equal(full.source, "ltd-ugc-bc1-alpha");
    assert.throws(
        () => classifyDecodedLtdFacepaintBc1(new Uint8Array(8)),
        /must decode to 131072 BC1 bytes/
    );
});

test("classic makeup is not misidentified as LTD facepaint", () => {
    assert.equal(getMiiFacepaintUsage({ era: "CFCD", face: { makeup: 11 } }), "none");
    assert.equal(getMiiFacepaintUsage({ era: "LTD", facepaintUsage: "partial" }), "partial");
});

test("search facepaint toggles are opt-in inclusion filters", () => {
    assert.deepEqual(getRequestedMiiFacepaintFilters({}), {
        facepaintUsages: [],
        excludedFacepaintUsages: ["partial", "full"],
        facepaintFiltersConfigured: false,
        isActive: false
    });
    assert.deepEqual(getRequestedMiiFacepaintFilters({
        facepaintFiltersConfigured: "1",
        facepaintUsages: "partial"
    }), {
        facepaintUsages: ["partial"],
        excludedFacepaintUsages: ["full"],
        facepaintFiltersConfigured: true,
        isActive: true
    });

    const query = { private: false };
    applyMiiFacepaintSearchFilter(query, {
        facepaintFiltersConfigured: true,
        facepaintUsages: ["partial"]
    });
    assert.deepEqual(query, {
        private: false,
        $and: [{ facepaintUsage: { $in: ["partial"] } }]
    });

    assert.deepEqual(getRequestedMiiFacepaintFilters({
        facepaintFiltersConfigured: "1"
    }), {
        facepaintUsages: [],
        excludedFacepaintUsages: ["partial", "full"],
        facepaintFiltersConfigured: true,
        isActive: false
    });
});

test("combining content filters does not let inactive facepaint mask an active era filter", () => {
    assert.deepEqual(combineRequestedMiiContentFilters(
        {
            eras: ["LTD"],
            eraFiltersConfigured: true,
            isActive: true
        },
        {
            facepaintUsages: [],
            facepaintFiltersConfigured: true,
            isActive: false
        }
    ), {
        eras: ["LTD"],
        eraFiltersConfigured: true,
        facepaintUsages: [],
        facepaintFiltersConfigured: true,
        eraFiltersActive: true,
        facepaintFiltersActive: false,
        isActive: true
    });
});

test("viewer blocks map CFCD to legacy TL storage and apply in memory", () => {
    const user = {
        miiPfp: "MyPfp",
        blockedMiiEras: ["CFCD"],
        blockedFacepaintUsages: ["full"]
    };
    assert.deepEqual(buildBlockedContentConditions(user), [
        {
            $or: [
                { id: { $in: ["average", "MyPfp"] } },
                { era: { $nin: ["CFCD", "TL"] } }
            ]
        },
        {
            $or: [
                { id: { $in: ["average", "MyPfp"] } },
                { facepaintUsage: { $nin: ["full"] } }
            ]
        }
    ]);
    assert.equal(isMiiBlockedByEraOrFacepaint({ era: "TL" }, user), true);
    assert.equal(isMiiBlockedByEraOrFacepaint({ era: "RCD", facepaintUsage: "full" }, user), true);
    assert.equal(isMiiBlockedByEraOrFacepaint({ era: "RCD", facepaintUsage: "partial" }, user), false);
});

test("Average and only the current viewer profile Mii bypass Settings era and facepaint blocks", () => {
    const user = {
        miiPfp: "Own12",
        blockedMiiEras: ["LTD"],
        blockedFacepaintUsages: ["full"]
    };

    assert.deepEqual(getMiiContentSettingsExemptIds(user), ["average", "Own12"]);
    assert.equal(isMiiExemptFromEraOrFacepaintSettings({ id: "average" }, user), true);
    assert.equal(isMiiExemptFromEraOrFacepaintSettings({ id: "Own12" }, user), true);
    assert.equal(isMiiExemptFromEraOrFacepaintSettings({ id: "Other" }, user), false);
    assert.equal(isMiiExemptFromContentSettings({ id: "average" }, user), true);
    assert.deepEqual(
        preserveMiiContentSettingsExemptions({ tags: { $nin: ["blocked"] } }, user),
        {
            $or: [
                { id: { $in: ["average", "Own12"] } },
                { tags: { $nin: ["blocked"] } }
            ]
        }
    );
    assert.deepEqual(
        preserveMiiContentSettingsExemptions({ tags: { $nin: ["blocked"] } }, null),
        { tags: { $nin: ["blocked"] } }
    );
    assert.equal(isMiiBlockedByEraOrFacepaint({
        id: "average",
        era: "LTD",
        facepaintUsage: "full"
    }, user), false);
    assert.equal(isMiiBlockedByEraOrFacepaint({
        id: "Own12",
        era: "LTD",
        facepaintUsage: "full"
    }, user), false);
    assert.equal(isMiiBlockedByEraOrFacepaint({
        id: "Other",
        era: "LTD",
        facepaintUsage: "full"
    }, user), true);

    // Malformed/tampered session values never become query exemptions.
    assert.deepEqual(getMiiContentSettingsExemptIds({ miiPfp: { $ne: null } }), ["average"]);
    assert.deepEqual(getMiiContentSettingsExemptIds({ miiPfp: "../Own12" }), ["average"]);
});

test("advanced search renders source-era and facepaint allow toggles", async () => {
    const html = await ejs.renderFile(searchControlsTemplate, {
        formAction: "/searchResults",
        query: {},
        renderSearchFields: false,
        renderMiiAdvancedFilters: true,
        renderTagFilters: false,
        renderCategoryFilters: false,
        advancedSearchFilters: {
            eras: MII_ERA_FILTER_OPTIONS.map(option => option.value),
            facepaintUsages: ["partial", "full"]
        },
        miiEraFilterOptions: MII_ERA_FILTER_OPTIONS,
        miiFacepaintFilterOptions: MII_FACEPAINT_FILTER_OPTIONS,
        favoriteColorOptions: [],
        birthdayMonthOptions: [],
        birthdayDayOptions: []
    });
    assert.equal(html.match(/name="facepaintUsages"/g)?.length, 2);
    assert.match(html, /name="facepaintFiltersConfigured" value="1"/);
    assert.match(html, /Uses Partial Facepaint/);
    assert.match(html, /Uses Full Facepaint/);
    assert.match(html, /show only Miis using that amount of facepaint/);
});

test("advanced search leaves facepaint inclusion unchecked by default", async () => {
    const html = await ejs.renderFile(searchControlsTemplate, {
        formAction: "/searchResults",
        query: {},
        renderSearchFields: false,
        renderMiiAdvancedFilters: true,
        renderTagFilters: false,
        renderCategoryFilters: false,
        advancedSearchFilters: {},
        miiEraFilterOptions: MII_ERA_FILTER_OPTIONS,
        miiFacepaintFilterOptions: MII_FACEPAINT_FILTER_OPTIONS,
        favoriteColorOptions: [],
        birthdayMonthOptions: [],
        birthdayDayOptions: []
    });
    assert.equal(html.match(/name="facepaintUsages"[\s\S]*?checked/g)?.length || 0, 0);
});

test("gender stays out of search controls and the visible Mii page template", async () => {
    const [searchControlsSource, legacySearchFiltersSource, miiPageSource] = await Promise.all([
        fs.readFile(searchControlsTemplate, "utf8"),
        fs.readFile(legacySearchFiltersTemplate, "utf8"),
        fs.readFile(miiPageTemplate, "utf8")
    ]);

    assert.doesNotMatch(searchControlsSource, /name=["']gender["']/i);
    assert.doesNotMatch(legacySearchFiltersSource, /name=["']gender["']/i);
    assert.doesNotMatch(miiPageSource, /genderLabel|>\s*Gender\s*</i);
});

test("settings source persists era and facepaint blocking controls", async () => {
    const source = await fs.readFile(settingsTemplate, "utf8");
    assert.match(source, /data-blocked-mii-era/);
    assert.match(source, /data-blocked-facepaint-usage/);
    assert.match(source, /blockedMiiEras/);
    assert.match(source, /blockedFacepaintUsages/);
});

test("settings preferences and browse visibility are wired through storage and queries", () => {
    assert.match(databaseSource, /blockedMiiEras/);
    assert.match(databaseSource, /blockedFacepaintUsages/);
    assert.match(databaseSource, /facepaintUsage/);
    assert.match(indexSource, /conditions\.push\(\.\.\.buildBlockedContentConditions\(user\)\)/);
    assert.match(indexSource, /applyMiiFacepaintSearchFilter\(query, filters\)/);
    assert.match(indexSource, /facepaintUsage:\s*1/);
    assert.match(indexSource, /preserveMiiContentSettingsExemptions\(condition, user\)/);
    assert.match(indexSource, /!settingsExempt\s*&&\s*isMiiBlockedByCategoryForUser/);
    assert.match(indexSource, /blockableHiddenIds = hiddenMiiIds\.filter/);
    assert.match(indexSource, /The Average Mii cannot be hidden/);
    assert.match(indexSource, /Your current profile Mii cannot be hidden/);

    const visibilityStart = indexSource.indexOf("function getMiiVisibilityConditionsForUser");
    const visibilityEnd = indexSource.indexOf("function mapRequestedTagsToCatalog", visibilityStart);
    assert.ok(visibilityStart >= 0 && visibilityEnd > visibilityStart);
    const visibilitySource = indexSource.slice(visibilityStart, visibilityEnd);
    assert.match(visibilitySource, /blockedTags\.forEach/);
    assert.match(visibilitySource, /blockedCategories\.forEach/);
    assert.match(visibilitySource, /preserveMiiContentSettingsExemptions/);
    assert.match(visibilitySource, /blockableHiddenIds/);

    const routeStart = indexSource.indexOf("site.post('/updateContentPreferences'");
    const routeEnd = indexSource.indexOf("site.post('/updateExternalMiiPreference'", routeStart);
    assert.ok(routeStart >= 0 && routeEnd > routeStart);
    const route = indexSource.slice(routeStart, routeEnd);
    assert.match(route, /normalizeBlockedMiiEras\(requestedBlockedMiiEras\)/);
    assert.match(route, /normalizeBlockedFacepaintUsages\(requestedBlockedFacepaintUsages\)/);
    assert.match(route, /blockedMiiEras,/);
    assert.match(route, /blockedFacepaintUsages/);
});

test("facepaint metadata backfill is dry-run by default and CAS-bound to source bytes", () => {
    assert.match(backfillSource, /const write = process\.argv\.includes\("--write"\)/);
    assert.match(backfillSource, /actualSha256 = crypto\.createHash\("sha256"\)/);
    assert.match(backfillSource, /stored ltdSha256 does not match ltdData/);
    assert.match(backfillSource, /\{ _id: mii\._id, ltdSha256: storedSha256 \}/);
    assert.match(backfillSource, /\{ _id: mii\._id, ltdSha256: null, ltdData: bytes \}/);
    assert.match(backfillSource, /timestamps:\s*false/);
    assert.match(backfillSource, /titleDefinesPartialOrFull:\s*false/);
});
