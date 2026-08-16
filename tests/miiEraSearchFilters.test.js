import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ejs from "ejs";

import { MII_ERA_VALUES } from "../miiEra.js";
import {
    MII_ERA_FILTER_OPTIONS,
    applyMiiEraSearchFilter,
    getRequestedMiiEraFilters
} from "../miiEraSearchFilters.js";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const searchControlsTemplate = path.join(testDirectory, "..", "ejsFiles", "advancedSearchControls.ejs");

test("era filter options expose every canonical era in classifier order", () => {
    assert.deepEqual(
        MII_ERA_FILTER_OPTIONS.map(option => option.value),
        MII_ERA_VALUES
    );
    assert.match(MII_ERA_FILTER_OPTIONS.find(option => option.value === "CFCD").label, /Tomodachi Life/);
});

test("era filters default to every era enabled", () => {
    assert.deepEqual(getRequestedMiiEraFilters({}), {
        eras: ["RCD", "CFCD", "FFCD", "CHARINFO", "LTD"],
        excludedEras: [],
        eraFiltersConfigured: false,
        isActive: false
    });
});

test("configured era filters are canonicalized, deduplicated, and ordered", () => {
    assert.deepEqual(getRequestedMiiEraFilters({
        eraFiltersConfigured: "1",
        eras: ["ltd", "RCD", "tl", "CFCD", "unknown"]
    }), {
        eras: ["RCD", "CFCD", "LTD"],
        excludedEras: ["FFCD", "CHARINFO"],
        eraFiltersConfigured: true,
        isActive: true
    });
});

test("an explicitly empty era selection stays empty", () => {
    assert.deepEqual(getRequestedMiiEraFilters({ eraFiltersConfigured: "true" }), {
        eras: [],
        excludedEras: ["RCD", "CFCD", "FFCD", "CHARINFO", "LTD"],
        eraFiltersConfigured: true,
        isActive: true
    });
});

test("an era parameter configures filtering for direct links", () => {
    assert.deepEqual(getRequestedMiiEraFilters({ era: "CHARINFO" }).eras, ["CHARINFO"]);
});

test("applying all enabled eras leaves an existing query unchanged", () => {
    const query = { private: false };
    assert.equal(applyMiiEraSearchFilter(query, {}), query);
    assert.deepEqual(query, { private: false });
});

test("CFCD filtering includes legacy TL storage and preserves existing clauses", () => {
    const existingClause = { published: true };
    const query = { private: false, $and: [existingClause] };

    applyMiiEraSearchFilter(query, {
        eraFiltersConfigured: true,
        eras: ["RCD", "CFCD"]
    });

    assert.deepEqual(query, {
        private: false,
        $and: [
            existingClause,
            { era: { $in: ["RCD", "CFCD", "TL"] } }
        ]
    });
});

test("turning every era off creates a no-match era condition", () => {
    const query = {};
    applyMiiEraSearchFilter(query, { eraFiltersConfigured: true });
    assert.deepEqual(query, { $and: [{ era: { $in: [] } }] });
});

test("advanced search renders one default-on toggle per era and a configured marker", async () => {
    const html = await ejs.renderFile(searchControlsTemplate, {
        formAction: "/searchResults",
        query: {},
        renderSearchFields: false,
        renderMiiAdvancedFilters: true,
        renderTagFilters: false,
        renderCategoryFilters: false,
        advancedSearchFilters: getRequestedMiiEraFilters({}),
        miiEraFilterOptions: MII_ERA_FILTER_OPTIONS,
        favoriteColorOptions: [],
        birthdayMonthOptions: [],
        birthdayDayOptions: []
    });

    assert.equal(html.match(/name="eras"/g)?.length, MII_ERA_VALUES.length);
    assert.equal(html.match(/name="eras"[\s\S]*?checked/g)?.length, MII_ERA_VALUES.length);
    assert.match(html, /name="eraFiltersConfigured" value="1"/);
    assert.match(html, /Turn off an era to exclude it from search results\./);
});
