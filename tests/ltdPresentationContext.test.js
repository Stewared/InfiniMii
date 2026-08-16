import assert from "node:assert/strict";
import test from "node:test";

import {
    getFavoriteShirtPolicy,
    getLtdPresentationContextSha256,
    getStoredLtdPresentationContextIdentity,
    INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
    INFINIMII_FAVORITE_SHIRT_RGB,
    LTD_PRESENTATION_CONTEXT_KIND,
    normalizeLtdPresentationContext,
    resolveStoredLtdPresentationContext
} from "../ltdPresentationContext.js";

const LTD_SHA256 = "a".repeat(64);

function convertedRecord(sourceHairType) {
    return {
        id: "legacy-hat",
        ltdSha256: LTD_SHA256,
        hair: { type: sourceHairType },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            byteExactSourceClaimed: false,
            appearanceProjectionExact: true
        }
    };
}

test("only lossy legacy hair 34/57 conversions produce a headwear context", () => {
    for (const sourceHairType of [34, 57]) {
        const context = resolveStoredLtdPresentationContext(convertedRecord(sourceHairType));
        assert.deepEqual(context, {
            schemaVersion: 1,
            kind: LTD_PRESENTATION_CONTEXT_KIND,
            ltdSha256: LTD_SHA256,
            canonicalHairType: 45,
            sourceHairType
        });
        assert.match(getLtdPresentationContextSha256(context), /^[0-9a-f]{64}$/);
    }
    assert.equal(resolveStoredLtdPresentationContext(convertedRecord(45)), null);
    assert.equal(resolveStoredLtdPresentationContext(convertedRecord(57), { canonicalHairType: 44 }), null);
});

test("native LTD and unverified stored objects cannot request source-only presentation state", () => {
    const native = convertedRecord(57);
    native.ltdProvenance.kind = "native-upload";
    native.general = { favoriteColor: 3 };
    assert.equal(resolveStoredLtdPresentationContext(native), null);

    const incomplete = convertedRecord(57);
    delete incomplete.ltdProvenance.appearanceProjectionExact;
    incomplete.general = { favoriteColor: 3 };
    assert.equal(resolveStoredLtdPresentationContext(incomplete), null);

    const missingProvenance = convertedRecord(45);
    delete missingProvenance.ltdProvenance;
    missingProvenance.general = { favoriteColor: 3 };
    assert.equal(resolveStoredLtdPresentationContext(missingProvenance), null);

    assert.throws(
        () => normalizeLtdPresentationContext({
            schemaVersion: 1,
            kind: LTD_PRESENTATION_CONTEXT_KIND,
            ltdSha256: LTD_SHA256,
            canonicalHairType: 45,
            sourceHairType: 56
        }),
        /outside the checked legacy-headwear domain/
    );
    assert.throws(
        () => normalizeLtdPresentationContext({
            schemaVersion: 1,
            kind: LTD_PRESENTATION_CONTEXT_KIND,
            ltdSha256: LTD_SHA256,
            canonicalHairType: 45,
            sourceHairType: "57"
        }),
        /field types are invalid/
    );
});

test("context identity changes between no hat, knit, and cap", () => {
    const none = getStoredLtdPresentationContextIdentity(convertedRecord(45));
    const knit = getStoredLtdPresentationContextIdentity(convertedRecord(34));
    const cap = getStoredLtdPresentationContextIdentity(convertedRecord(57));
    assert.equal(new Set([none.sha256, knit.sha256, cap.sha256]).size, 3);
    assert.equal(none.kind, "none");
    assert.equal(knit.kind, LTD_PRESENTATION_CONTEXT_KIND);
    assert.equal(cap.kind, LTD_PRESENTATION_CONTEXT_KIND);
});

test("all 12 stored favorite colors produce distinct LTD-bound context identities", () => {
    const identities = new Set();
    for (let favoriteColor = 0; favoriteColor < 12; favoriteColor += 1) {
        const source = {
            ...convertedRecord(45),
            general: { favoriteColor }
        };
        const context = resolveStoredLtdPresentationContext(source);
        assert.deepEqual(context, {
            schemaVersion: 1,
            kind: INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
            ltdSha256: LTD_SHA256,
            favoriteColor,
            legacyHeadwearSourceType: null
        });
        assert.deepEqual(getFavoriteShirtPolicy(context), {
            policy: INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
            favoriteColor,
            rgbHex: INFINIMII_FAVORITE_SHIRT_RGB[favoriteColor],
            authoredVariation: [8, 3, 4, 10, 11, 16, 14, 6, 15, 1, 0, 0][favoriteColor],
            authoredAlbedo: `ClothTopsTshirtLongTexDefault_Body_Alb.${String([8, 3, 4, 10, 11, 16, 14, 6, 15, 1, 0, 0][favoriteColor]).padStart(2, "0")}`,
            sourceField: "general.favoriteColor",
            titleExact: false
        });
        identities.add(getLtdPresentationContextSha256(context));
    }
    assert.equal(identities.size, 12);
});

test("favorite-shirt context composes with a source-backed legacy hat", () => {
    const source = {
        ...convertedRecord(57),
        general: { favoriteColor: 6 }
    };
    const context = resolveStoredLtdPresentationContext(source);
    assert.equal(context.kind, INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND);
    assert.equal(context.favoriteColor, 6);
    assert.equal(context.legacyHeadwearSourceType, 57);
});

test("missing or invalid favorite color preserves the existing context behavior", () => {
    assert.equal(resolveStoredLtdPresentationContext({
        ...convertedRecord(45),
        general: {}
    }), null);
    assert.equal(resolveStoredLtdPresentationContext({
        ...convertedRecord(45),
        general: { favoriteColor: 12 }
    }), null);
    assert.equal(resolveStoredLtdPresentationContext({
        ...convertedRecord(45),
        general: { favoriteColor: "3" }
    }), null);
    assert.equal(
        resolveStoredLtdPresentationContext({
            ...convertedRecord(34),
            general: { favoriteColor: -1 }
        })?.kind,
        LTD_PRESENTATION_CONTEXT_KIND
    );
});
