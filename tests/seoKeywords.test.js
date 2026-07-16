import assert from "node:assert/strict";
import test from "node:test";

import { buildSeoKeywordList, parseCsvKeywordContent } from "../seoKeywords.js";

test("parses quoted SEO keyword CSV values", () => {
    assert.deepEqual(
        parseCsvKeywordContent('one,"two, value","escaped ""quote"""'),
        ["one", "two, value", 'escaped "quote"']
    );
});

test("selects deterministic bounded keywords without duplicate seeds", () => {
    assert.deepEqual(buildSeoKeywordList(
        ["Link", "link", "The Legend of Zelda"],
        { context: ["Nintendo 3DS QR"], limit: 6, asArray: true }
    ), [
        "Link",
        "The Legend of Zelda",
        "3ds mii qr",
        "qr codes for miis 3ds",
        "3ds",
        "3ds qr"
    ]);
});

test("can omit unrelated general fallback keywords", () => {
    assert.deepEqual(buildSeoKeywordList([], {
        context: [],
        fallbackToGeneral: false,
        limit: 3,
        asArray: true
    }), ["mii", "miis", "miijs"]);
});
