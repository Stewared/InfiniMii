import test from "node:test";
import assert from "node:assert/strict";

import {
    matchesEffectiveMiiSearchFilters,
    resolveEffectiveMiiSearchClassification,
    withEffectiveMiiSearchClassification
} from "../miiEffectiveSearchFilters.js";

test("effective era filtering ignores a stale stored LTD value", () => {
    const stale = {
        id: "classic",
        era: "LTD",
        console: "3DS",
        meta: { console: "3DS" },
        officialCategories: ["3DS/Games"]
    };
    const classification = resolveEffectiveMiiSearchClassification(stale);
    assert.deepEqual(classification, { era: "CFCD", facepaintUsage: "none" });
    assert.equal(matchesEffectiveMiiSearchFilters(classification, {
        eraFiltersConfigured: true,
        eras: ["LTD"]
    }), false);
    assert.equal(matchesEffectiveMiiSearchFilters(classification, {
        eraFiltersConfigured: true,
        eras: ["CFCD"]
    }), true);
});

test("facepaint search selection includes painted categories and excludes none", () => {
    const filters = {
        facepaintFiltersConfigured: true,
        facepaintUsages: ["partial", "full"]
    };
    assert.equal(matchesEffectiveMiiSearchFilters({ era: "LTD", facepaintUsage: "none" }, filters), false);
    assert.equal(matchesEffectiveMiiSearchFilters({ era: "LTD", facepaintUsage: "partial" }, filters), true);
    assert.equal(matchesEffectiveMiiSearchFilters({ era: "LTD", facepaintUsage: "full" }, filters), true);
});

test("viewer blockers use effective classifications", () => {
    assert.equal(matchesEffectiveMiiSearchFilters(
        { era: "CFCD", facepaintUsage: "none" },
        {},
        { blockedMiiEras: ["CFCD"] }
    ), false);
    assert.equal(matchesEffectiveMiiSearchFilters(
        { era: "LTD", facepaintUsage: "full" },
        {},
        { blockedFacepaintUsages: ["full"] }
    ), false);
});

test("viewer Settings preserve Average and their own PFP without weakening explicit Search", () => {
    const viewer = {
        miiPfp: "Own12",
        blockedMiiEras: ["LTD"],
        blockedFacepaintUsages: ["full"]
    };
    const classification = { era: "LTD", facepaintUsage: "full" };

    assert.equal(matchesEffectiveMiiSearchFilters(
        classification, {}, viewer, { id: "average" }
    ), true);
    assert.equal(matchesEffectiveMiiSearchFilters(
        classification, {}, viewer, { id: "Own12" }
    ), true);
    assert.equal(matchesEffectiveMiiSearchFilters(
        classification, {}, viewer, { id: "Other" }
    ), false);

    assert.equal(matchesEffectiveMiiSearchFilters(
        classification,
        { eraFiltersConfigured: true, eras: ["RCD"] },
        viewer,
        { id: "Own12" }
    ), false);
    assert.equal(matchesEffectiveMiiSearchFilters(
        classification,
        { facepaintFiltersConfigured: true, facepaintUsages: ["partial"] },
        viewer,
        { id: "average" }
    ), false);
});

test("classification-only source fields are removed before rendering cards", () => {
    const card = withEffectiveMiiSearchClassification({
        id: "abc",
        era: "LTD",
        facepaintUsage: "none",
        ltdData: Buffer.from([1, 2, 3]),
        ltdCharInfo: { secret: true },
        ltdConversionReport: { source: true },
        ltdVersion: 3,
        tl: { island: true },
        ltdProvenance: {
            kind: "native-upload",
            sourceFormat: "ltd",
            codec: "private-classification-input",
            byteExact: true
        }
    }, { era: "CFCD", facepaintUsage: "none" });

    assert.equal(card.era, "CFCD");
    assert.equal("ltdData" in card, false);
    assert.equal("ltdCharInfo" in card, false);
    assert.equal("ltdConversionReport" in card, false);
    assert.equal("tl" in card, false);
    assert.equal("codec" in card.ltdProvenance, false);
    assert.equal("byteExact" in card.ltdProvenance, false);
    assert.deepEqual(resolveEffectiveMiiSearchClassification(card), {
        era: "CFCD",
        facepaintUsage: "none"
    });
});
