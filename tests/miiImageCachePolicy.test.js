import assert from "node:assert/strict";
import test from "node:test";

import {
    buildStandardMiiRenderPortraitCasFilter,
    buildStandardMiiRenderReadyState,
    isCurrentReadyStandardMiiRender,
    persistStandardMiiRenderPortraitStateCas,
    publishCasGuardedStandardMiiImage
} from "../miiImageCachePolicy.js";

const KEY = "a".repeat(64);
const OUTPUT = "b".repeat(64);
const REVISION = "c".repeat(64);

function readyState(profile = "TL") {
    return {
        status: "ready",
        rendererProfile: profile,
        rendererBackend: "TL",
        rendererRevision: REVISION,
        rendererCacheKey: KEY,
        outputSha256: OUTPUT,
        view: "portrait",
        size: 512,
        renderedAt: new Date("2026-08-12T00:00:00.000Z")
    };
}

test("standard render identity distinguishes logical TL and RFL profiles", () => {
    const mii = { imageRender: { portrait: readyState("TL") } };
    assert.equal(isCurrentReadyStandardMiiRender(mii, {
        profile: "TL", backend: "TL", rendererCacheKey: KEY, rendererRevision: REVISION
    }), true);
    assert.equal(isCurrentReadyStandardMiiRender(mii, {
        profile: "RFL", backend: "TL", rendererCacheKey: KEY, rendererRevision: REVISION
    }), false);
});

test("a stale LTD cache can never satisfy the standard renderer cache", () => {
    const staleLtd = {
        ltdRender: { portrait: { status: "ready", outputSha256: OUTPUT } }
    };
    assert.equal(isCurrentReadyStandardMiiRender(staleLtd, {
        profile: "TL", backend: "TL", rendererCacheKey: KEY, rendererRevision: REVISION
    }), false);
});

test("standard cache CAS binds stored identity, source hash, and prior state", () => {
    const mii = {
        id: "ironman",
        miiHash: "mii-v3:source",
        updatedAt: new Date("2026-08-12T01:02:03.000Z"),
        imageRender: { portrait: readyState("TL") }
    };
    const filter = buildStandardMiiRenderPortraitCasFilter(mii);
    assert.equal(filter.id, "ironman");
    assert.equal(filter.miiHash, "mii-v3:source");
    assert.deepEqual(filter.updatedAt, new Date("2026-08-12T01:02:03.000Z"));
    assert.ok(filter.$and.some(clause => clause["imageRender.portrait.rendererProfile"] === "TL"));
    assert.ok(filter.$and.some(clause => clause["imageRender.portrait.rendererCacheKey"] === KEY));
});

test("standard cache CAS rejects a concurrent appearance edit even when miiHash is unchanged", async () => {
    const observed = {
        id: "same-face-different-clothes",
        miiHash: "mii-v3:face-only",
        updatedAt: new Date("2026-08-12T01:00:00.000Z")
    };
    const concurrentlyEdited = {
        ...observed,
        updatedAt: new Date("2026-08-12T01:00:01.000Z")
    };
    let matched = false;
    const state = { ...readyState(), status: "publishing", publishToken: "token" };
    delete state.renderedAt;
    state.checkedAt = new Date("2026-08-12T01:00:00.500Z");
    const committed = await persistStandardMiiRenderPortraitStateCas({
        mii: observed,
        state,
        updateOne: async (filter) => {
            matched = filter.updatedAt.getTime() === concurrentlyEdited.updatedAt.getTime();
            return { matchedCount: matched ? 1 : 0 };
        }
    });
    assert.equal(matched, false);
    assert.equal(committed, false);
});

test("ready state is built only from complete TL/RFL render results", () => {
    const state = buildStandardMiiRenderReadyState({
        buffer: Buffer.from("png"),
        rendererProfile: "RFL",
        rendererBackend: "TL",
        rendererRevision: REVISION,
        rendererCacheKey: KEY,
        outputSha256: OUTPUT
    }, new Date("2026-08-12T00:00:00.000Z"));
    assert.deepEqual(state, readyState("RFL"));
    assert.throws(() => buildStandardMiiRenderReadyState({
        buffer: Buffer.from("png"),
        rendererProfile: "LTD",
        rendererBackend: "LTD",
        rendererRevision: REVISION,
        rendererCacheKey: KEY,
        outputSha256: OUTPUT
    }));
});

test("standard CAS uses imageRender and never writes ltdRender", async () => {
    let observedFilter;
    let observedUpdate;
    const mii = { id: "classic", miiHash: "mii-v3:classic" };
    const state = { ...readyState(), status: "publishing", publishToken: "token" };
    delete state.renderedAt;
    state.checkedAt = new Date("2026-08-12T00:00:00.000Z");
    assert.equal(await persistStandardMiiRenderPortraitStateCas({
        mii,
        state,
        updateOne: async (filter, update) => {
            observedFilter = filter;
            observedUpdate = update;
            return { matchedCount: 1 };
        }
    }), true);
    assert.equal(observedFilter.id, "classic");
    assert.deepEqual(observedUpdate, { $set: { "imageRender.portrait": state } });
    assert.equal(JSON.stringify(observedUpdate).includes("ltdRender"), false);
});

test("publication rechecks the claimed token before replacing the shared image", async () => {
    const state = readyState();
    let current = { id: "classic", imageRender: {} };
    let published = false;
    const committed = await publishCasGuardedStandardMiiImage({
        readyState: state,
        publishToken: "owner-token",
        withPublishLock: async task => await task(),
        resolveCurrentMii: async () => current,
        claimPublishing: async (_mii, publishing) => {
            current = { id: "classic", imageRender: { portrait: publishing } };
            return true;
        },
        validateClaimedMii: async () => true,
        publishAsset: async () => { published = true; },
        finalizeReady: async () => true
    });
    assert.equal(committed, true);
    assert.equal(published, true);
});

test("publication refuses a stolen or changed claim without touching the image", async () => {
    let current = { id: "classic", imageRender: {} };
    let published = false;
    const committed = await publishCasGuardedStandardMiiImage({
        readyState: readyState(),
        publishToken: "owner-token",
        withPublishLock: async task => await task(),
        resolveCurrentMii: async () => current,
        claimPublishing: async (_mii, publishing) => {
            current = {
                id: "classic",
                imageRender: { portrait: { ...publishing, publishToken: "other-owner" } }
            };
            return true;
        },
        validateClaimedMii: async () => true,
        publishAsset: async () => { published = true; },
        finalizeReady: async () => true
    });
    assert.equal(committed, false);
    assert.equal(published, false);
});

test("publication revalidates the source render identity after claiming", async () => {
    let current = { id: "classic", imageRender: {} };
    let published = false;
    const committed = await publishCasGuardedStandardMiiImage({
        readyState: readyState(),
        publishToken: "owner-token",
        withPublishLock: async task => await task(),
        resolveCurrentMii: async () => current,
        claimPublishing: async (_mii, publishing) => {
            current = { id: "classic", general: { favoriteColor: 7 }, imageRender: { portrait: publishing } };
            return true;
        },
        validateClaimedMii: async claimed => claimed?.general?.favoriteColor !== 7,
        publishAsset: async () => { published = true; },
        finalizeReady: async () => true
    });
    assert.equal(committed, false);
    assert.equal(published, false);
});
