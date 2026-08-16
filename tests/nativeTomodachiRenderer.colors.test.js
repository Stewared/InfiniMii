import assert from "node:assert/strict";
import test from "node:test";
import { planNativeTomodachiRender } from "../nativeTomodachiRenderer.js";
import { INFINIMII_FAVORITE_SHIRT_RGB } from "../ltdPresentationContext.js";

function minimalMii(overrides = {}) {
    return {
        ...overrides,
        general: {
            favoriteColor: 0,
            gender: 0,
            ...overrides.general
        },
        meta: {
            name: "Color Test",
            ...overrides.meta
        }
    };
}

test("native plan uses MiiJS canonical color defaults", async () => {
    const plan = await planNativeTomodachiRender(minimalMii());

    assert.equal(plan.canonical.hair_color, 1);
    assert.equal(plan.canonical.eyebrow_color, 1);
    assert.equal(plan.canonical.eye_color, 8);
    assert.equal(plan.canonical.mouth_color, 19);
    assert.equal(plan.canonical.beard_color, 8);
    assert.equal(plan.canonical.glasses_color, 8);
});

test("native plan preserves low and extended Switch common-color indices", async () => {
    const plan = await planNativeTomodachiRender(minimalMii({
        hair: { color: 0 },
        eyebrows: { color: 4 },
        eyes: { color: 5 },
        mouth: { color: 71 },
        beard: { color: 99 },
        glasses: { color: 2 },
        face: { color: 9 }
    }));

    assert.equal(plan.canonical.hair_color, 0);
    assert.equal(plan.canonical.eyebrow_color, 4);
    assert.equal(plan.canonical.eye_color, 5);
    assert.equal(plan.canonical.mouth_color, 71);
    assert.equal(plan.canonical.beard_color, 99);
    assert.equal(plan.canonical.glasses_color, 2);
    assert.equal(plan.canonical.face_color, 9);
});

test("native Tomodachi preview still reuses the established 12-color palette", async () => {
    for (let favoriteColor = 0; favoriteColor < INFINIMII_FAVORITE_SHIRT_RGB.length; favoriteColor += 1) {
        const plan = await planNativeTomodachiRender(minimalMii({ general: { favoriteColor } }));
        assert.equal(plan.body.itemIndex, 0);
        assert.equal(plan.body.rgb, INFINIMII_FAVORITE_SHIRT_RGB[favoriteColor]);
    }
});
