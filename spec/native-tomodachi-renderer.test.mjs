import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import sharp from "sharp";

import {
    normalizeNativeTomodachiGlassesType,
    planNativeTomodachiRender
} from "../nativeTomodachiRenderer.js";
import {
    canUseNativeTomodachiRendererForOptions,
    tomodachiFullBodyRenderCacheKey,
    transformTomodachiFullBodyRender
} from "../tomodachiRenderTransform.js";

const EXPECTED_NATIVE_GLASSES_TYPES = Object.freeze([
    0, 1, 2, 3, 4, 5, 6, 7, 8,
    // Modern types 9-19 use MiiJS's audited modern-to-legacy selector table.
    1, 2, 1, 3, 7, 7, 6, 7, 8, 7, 7
]);

test("normalizes every supported Mii glasses type for the legacy CFL resource", () => {
    for (let type = 0; type < EXPECTED_NATIVE_GLASSES_TYPES.length; type += 1) {
        assert.equal(
            normalizeNativeTomodachiGlassesType(type),
            EXPECTED_NATIVE_GLASSES_TYPES[type],
            `glasses type ${type}`
        );
    }
});

test("rejects glasses types outside the supported Mii schema", () => {
    for (const type of [-1, 20, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "unknown"]) {
        assert.throws(
            () => normalizeNativeTomodachiGlassesType(type),
            /expected 0-19/
        );
    }
});

test("plans already-decoded Mongo Mii fields without reparsing them as an encoded file", async () => {
    const decoded = {
        meta: { type: "Default" },
        general: {
            favoriteColor: 0,
            gender: 0,
            height: 64,
            weight: 64
        },
        glasses: {
            type: 13,
            color: 0,
            size: 4,
            yPosition: 10
        }
    };

    const directPlan = await planNativeTomodachiRender(decoded);
    const wrappedPlan = await planNativeTomodachiRender({ fields: decoded });
    const documentPlan = await planNativeTomodachiRender({
        toObject: () => decoded
    });

    // Modern type 13 maps to legacy selector 7 in that same source table.
    assert.equal(directPlan.canonical.glasses_type, 7);
    assert.equal(wrappedPlan.canonical.glasses_type, 7);
    assert.equal(documentPlan.canonical.glasses_type, 7);
    assert.equal(directPlan.cacheKey, wrappedPlan.cacheKey);
    assert.equal(directPlan.cacheKey, documentPlan.cacheKey);
});

test("preserves source hair and plans headwear from the authoritative CGFX HeadType", async () => {
    const cases = [
        { item: "b100", hair: 121, archive: "headwear_headwear177", typeId: 2, headType: 6, metadataVariant: -1 },
        { item: "1d00", hair: 49, archive: "headwear_headwear029", typeId: 0, headType: 5, metadataVariant: 0 },
        { item: "1900", hair: 67, archive: "headwear_headwear025", typeId: 0, headType: 7, metadataVariant: -1 },
        { item: "0c00", hair: 38, archive: "headwear_headwear012", typeId: 1, headType: 8, metadataVariant: -1 },
        { item: "0e00", hair: 79, archive: "headwear_headwear014", typeId: 2, headType: 10, metadataVariant: 0 }
    ];

    for (const expected of cases) {
        const plan = await planNativeTomodachiRender({
            meta: { type: "Default" },
            general: { favoriteColor: 0, gender: 0, height: 64, weight: 64 },
            hair: { type: expected.hair, color: 1 },
            tl: {
                clothing: {
                    outfit: "0000",
                    outfitColor: 0,
                    hat: expected.item,
                    hatColor: 0
                }
            }
        });

        assert.equal(plan.canonical.hair_type, expected.hair);
        assert.equal(plan.headwear.archive, expected.archive);
        assert.equal(plan.headwear.typeId, expected.typeId);
        assert.equal(plan.headwear.headType, expected.headType);
        assert.equal(plan.headwear.metadataVariant, expected.metadataVariant);
    }
});

test("plans the source-backed 512-square full-body mode for all height extrema", async () => {
    assert.equal(canUseNativeTomodachiRendererForOptions({ fullBody: true }), true);

    for (const height of [0, 64, 127]) {
        const decoded = {
            meta: { type: "Default" },
            general: {
                favoriteColor: 0,
                gender: 0,
                height,
                weight: 64
            }
        };
        const portrait = await planNativeTomodachiRender(decoded);
        const fullBody = await planNativeTomodachiRender(decoded, { fullBody: true });

        assert.equal(fullBody.mode, "full-body");
        assert.deepEqual(fullBody.viewport, { width: 512, height: 512 });
        assert.equal(fullBody.canonical.height, height);
        assert.notEqual(fullBody.cacheKey, portrait.cacheKey);
    }
});

test("full-body transform keys transparency without cropping or moving pixels", async () => {
    const width = 512;
    const height = 512;
    const source = Buffer.alloc(width * height * 4);
    for (let offset = 0; offset < source.length; offset += 4) {
        source[offset] = 0xf7;
        source[offset + 1] = 0xf8;
        source[offset + 2] = 0xfb;
        source[offset + 3] = 0xff;
    }
    const subjectX = 123;
    const subjectY = 234;
    const subjectOffset = (subjectY * width + subjectX) * 4;
    source[subjectOffset] = 0x21;
    source[subjectOffset + 1] = 0x43;
    source[subjectOffset + 2] = 0x65;
    const sha256 = crypto.createHash("sha256").update(source).digest("hex");

    const output = await transformTomodachiFullBodyRender({
        sourceBuffer: source,
        id: "full-body-position-test",
        sourceSha256: sha256,
        sourceIsRaw: true
    });
    const { data, info } = await sharp(output).ensureAlpha().raw().toBuffer({
        resolveWithObject: true
    });
    assert.deepEqual(
        { width: info.width, height: info.height, channels: info.channels },
        { width, height, channels: 4 }
    );
    for (let y = 0; y < height; y += 1) {
        for (let x = 0; x < width; x += 1) {
            const alpha = data[(y * width + x) * 4 + 3];
            assert.equal(alpha, x === subjectX && y === subjectY ? 255 : 0);
        }
    }
    assert.match(
        tomodachiFullBodyRenderCacheKey("render", sha256),
        /^ffl-whole-body-camera-v1:/
    );
});
