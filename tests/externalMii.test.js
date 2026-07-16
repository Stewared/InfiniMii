import assert from "node:assert/strict";
import test from "node:test";

import {
    getExternalMiiSource,
    normalizeExternalMiiPreference,
    validateExternalMiiMetadata
} from "../externalMii.js";

test("normalizes complete external source metadata", () => {
    const result = validateExternalMiiMetadata({
        extURL: " https://example.com/mii/1 ",
        extTitle: " Example   Archive ",
        extUser: " Creator ",
        extUserURL: "https://example.com/users/creator"
    });

    assert.deepEqual(result, {
        value: {
            extURL: "https://example.com/mii/1",
            extTitle: "Example Archive",
            extUser: "Creator",
            extUserURL: "https://example.com/users/creator"
        }
    });
    assert.deepEqual(getExternalMiiSource(result.value), {
        title: "Example Archive",
        url: "https://example.com/mii/1",
        user: "Creator",
        userUrl: "https://example.com/users/creator"
    });
});

test("rejects unsafe or incomplete external source metadata", () => {
    assert.match(validateExternalMiiMetadata({}).error, /all external source fields/i);
    assert.match(validateExternalMiiMetadata({
        extURL: "https://user:password@example.com/mii/1",
        extTitle: "Example",
        extUser: "",
        extUserURL: ""
    }).error, /without embedded credentials/i);
    assert.equal(getExternalMiiSource({ extTitle: "Example", extURL: "javascript:alert(1)" }), null);
});

test("normalizes persisted external navigation preferences", () => {
    assert.equal(normalizeExternalMiiPreference(" GO "), "go");
    assert.equal(normalizeExternalMiiPreference("stay"), "stay");
    assert.equal(normalizeExternalMiiPreference("invalid"), "ask");
});
