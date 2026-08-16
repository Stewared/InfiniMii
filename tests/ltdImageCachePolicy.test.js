import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    LTD_RENDER_BACKGROUND_MODE,
    LTD_RENDER_RASTER_PROFILE,
    buildLtdRenderPortraitCasFilter,
    canAccessPrivateMiiAsset,
    createRendererRevisionSnapshot,
    ensureCurrentLtdImageAsset,
    isCurrentReadyLtdRender,
    persistLtdRenderPortraitStateCas,
    publishCasGuardedLtdImage
} from "../ltdImageCachePolicy.js";
import {
    renameMiiImageWithRetry,
    selectLtdRenderAuthorizationSnapshot,
    withMiiImagePublishLock,
    writeMiiImageBuffer
} from "../miiImageRenderer.js";
import { getStoredLtdPresentationContextIdentity } from "../ltdPresentationContext.js";
import { LTD_PROFILE_POLICY_ID } from "../ltdCanonical.js";

const LTD_SHA256 = "a".repeat(64);
const RENDERER_REVISION = "b".repeat(64);
const RESOURCE_SIGNATURE = "c".repeat(64);
const OUTPUT_SHA256 = "d".repeat(64);
const PRESENTATION_CONTEXT = getStoredLtdPresentationContextIdentity({});
const RENDER_IDENTITY_FIELDS = Object.freeze({
    presentationContextKind: PRESENTATION_CONTEXT.kind,
    presentationContextSha256: PRESENTATION_CONTEXT.sha256,
    rasterProfile: LTD_RENDER_RASTER_PROFILE
});

test("authorization does not substitute a stale collapsed-hair presentation context", () => {
    const provenance = {
        kind: "canonical-regenerated-charinfo",
        sourceKind: "normalized-site-fields",
        byteExactSourceClaimed: false,
        appearanceProjectionExact: true
    };
    const canonical = {
        storedFields: { ltdSha256: LTD_SHA256, ltdProvenance: provenance },
        parsed: { charInfo: { hairType: 45 } }
    };
    const edited = { id: "headwear", hair: { type: 57 }, ltdProvenance: provenance };
    const stored = {
        id: "headwear",
        ltdSha256: LTD_SHA256,
        hair: { type: 34 },
        ltdProvenance: provenance
    };
    assert.equal(selectLtdRenderAuthorizationSnapshot(edited, canonical, stored), null);
    assert.equal(
        selectLtdRenderAuthorizationSnapshot(
            { ...edited, hair: { type: 34 } },
            canonical,
            stored
        ),
        stored
    );
});

test("render-state CAS binds the source discriminator even when LTD bytes are unchanged", () => {
    const observed = {
        id: "headwear",
        ltdSha256: LTD_SHA256,
        hair: { type: 57 },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            byteExactSourceClaimed: false,
            appearanceProjectionExact: true,
            profilePolicy: LTD_PROFILE_POLICY_ID
        }
    };
    const filter = buildLtdRenderPortraitCasFilter(observed);
    assert.equal(filter["hair.type"], 57);
    assert.equal(filter["ltdProvenance.kind"], observed.ltdProvenance.kind);
    assert.equal(filter["ltdProvenance.sourceKind"], observed.ltdProvenance.sourceKind);
    assert.equal(filter["ltdProvenance.byteExactSourceClaimed"], false);
    assert.equal(filter["ltdProvenance.appearanceProjectionExact"], true);
    assert.equal(
        buildLtdRenderPortraitCasFilter({ ...observed, hair: { type: "57" } })["hair.type"],
        "57"
    );
    const absent = buildLtdRenderPortraitCasFilter({
        id: observed.id,
        ltdSha256: observed.ltdSha256,
        hair: { type: 57 },
        ltdProvenance: { kind: observed.ltdProvenance.kind }
    });
    assert.deepEqual(absent["ltdProvenance.appearanceProjectionExact"], { $exists: false });
});

function readyMii(overrides = {}) {
    return {
        id: "cache1",
        uploader: "owner",
        ltdSha256: LTD_SHA256,
        ltdRender: {
            portrait: {
                status: "ready",
                ltdSha256: LTD_SHA256,
                rendererRevision: RENDERER_REVISION,
                capabilityKey: "checked-capability",
                resourceSignature: RESOURCE_SIGNATURE,
                outputSha256: OUTPUT_SHA256,
                view: "portrait",
                size: 512,
                backgroundMode: LTD_RENDER_BACKGROUND_MODE,
                ...RENDER_IDENTITY_FIELDS
            }
        },
        ...overrides
    };
}

async function pathExists(filePath) {
    return fs.promises.access(filePath, fs.constants.F_OK)
        .then(() => true)
        .catch(() => false);
}

test("a stale legacy PNG is atomically replaced by an LTD render on demand", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-cache-stale-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "stale.png");
    await fs.promises.writeFile(assetPath, "legacy-render");

    const staleMii = { id: "cache1", uploader: "owner", ltdSha256: LTD_SHA256 };
    let currentMii = staleMii;
    let renders = 0;
    const generated = await ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: staleMii,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        resolveCurrentMii: async () => currentMii,
        renderAndWrite: async (_mii, destinationPath) => {
            renders += 1;
            await writeMiiImageBuffer(Buffer.from("ltd-render"), destinationPath);
            currentMii = readyMii();
        }
    });

    assert.equal(generated, true);
    assert.equal(renders, 1);
    assert.equal(await fs.promises.readFile(assetPath, "utf8"), "ltd-render");
    assert.deepEqual(
        (await fs.promises.readdir(directory)).filter(name => name.endsWith(".tmp")),
        []
    );
});

test("a current ready LTD PNG is served without rendering again", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-cache-ready-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "ready.png");
    await fs.promises.writeFile(assetPath, "current-ltd-render");

    const mii = readyMii();
    let resolves = 0;
    let renders = 0;
    const cached = await ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: mii,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        resolveCurrentMii: async () => {
            resolves += 1;
            return mii;
        },
        renderAndWrite: async () => {
            renders += 1;
        }
    });

    assert.equal(cached, true);
    assert.equal(resolves, 0);
    assert.equal(renders, 0);
    assert.equal(isCurrentReadyLtdRender(mii, RENDERER_REVISION), true);
    assert.equal(isCurrentReadyLtdRender(mii, "d".repeat(64)), false);

    const missingCapability = readyMii();
    delete missingCapability.ltdRender.portrait.capabilityKey;
    assert.equal(isCurrentReadyLtdRender(missingCapability, RENDERER_REVISION), false);

    const opaqueLegacyState = readyMii();
    delete opaqueLegacyState.ltdRender.portrait.backgroundMode;
    assert.equal(isCurrentReadyLtdRender(opaqueLegacyState, RENDERER_REVISION), false);

    let revisionResolutions = 0;
    const getRevision = createRendererRevisionSnapshot(() => {
        revisionResolutions += 1;
        return RENDERER_REVISION;
    });
    assert.equal(getRevision(), RENDERER_REVISION);
    assert.equal(getRevision(), RENDERER_REVISION);
    assert.equal(revisionResolutions, 1);
});

test("a QWvah PNG cannot use the ready fast path without the exact current historical source policy", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-cache-qwvah-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "QWvah.png");
    await fs.promises.writeFile(assetPath, "wrong-pre-policy-render");

    const staleQWvah = readyMii({
        id: "QWvah",
        console: "Wii",
        official: true,
        published: true,
        private: false,
        officialSource: "Nintendo",
        meta: { console: "Wii" },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            historicalSchemaPolicy: "infinimii-explicit-historical-schema-v1",
            historicalSchema: "raw-wii-palettes",
            historicalSourceRecordSha256: "6078e6c7d1fd63ce7d43deba1053c757e725ac7c09a03d9a6613e47754ecfb67"
        }
    });
    assert.equal(isCurrentReadyLtdRender(staleQWvah, RENDERER_REVISION), false);

    let renders = 0;
    let currentMii = staleQWvah;
    const generated = await ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: staleQWvah,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        resolveCurrentMii: async () => currentMii,
        renderAndWrite: async (_mii, destinationPath) => {
            renders += 1;
            await writeMiiImageBuffer(Buffer.from("corrected-source-backed-render"), destinationPath);
            currentMii = readyMii();
        }
    });

    assert.equal(generated, true);
    assert.equal(renders, 1);
    assert.equal(await fs.promises.readFile(assetPath, "utf8"), "corrected-source-backed-render");
});

test("legacy 34/57 headwear context is part of the ready cache identity", () => {
    const legacyHeadwear = readyMii({
        hair: { type: 57 },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            byteExactSourceClaimed: false,
            appearanceProjectionExact: true,
            profilePolicy: LTD_PROFILE_POLICY_ID
        }
    });
    assert.equal(isCurrentReadyLtdRender(legacyHeadwear, RENDERER_REVISION), false);

    const identity = getStoredLtdPresentationContextIdentity(legacyHeadwear);
    legacyHeadwear.ltdRender.portrait.presentationContextKind = identity.kind;
    legacyHeadwear.ltdRender.portrait.presentationContextSha256 = identity.sha256;
    assert.equal(isCurrentReadyLtdRender(legacyHeadwear, RENDERER_REVISION), true);

    legacyHeadwear.hair.type = 34;
    assert.equal(isCurrentReadyLtdRender(legacyHeadwear, RENDERER_REVISION), false);
});

test("favorite-color edits invalidate ready pixels and are bound by render-state CAS", () => {
    const colored = readyMii({
        general: { favoriteColor: 2 },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            byteExactSourceClaimed: false,
            appearanceProjectionExact: true,
            profilePolicy: LTD_PROFILE_POLICY_ID
        }
    });
    const identity = getStoredLtdPresentationContextIdentity(colored);
    colored.ltdRender.portrait.presentationContextKind = identity.kind;
    colored.ltdRender.portrait.presentationContextSha256 = identity.sha256;
    assert.equal(isCurrentReadyLtdRender(colored, RENDERER_REVISION), true);

    const observedFilter = buildLtdRenderPortraitCasFilter(colored);
    assert.equal(observedFilter["general.favoriteColor"], 2);
    colored.general.favoriteColor = 9;
    assert.equal(isCurrentReadyLtdRender(colored, RENDERER_REVISION), false);
    assert.equal(matchesCasFilter(colored, observedFilter), false);
});

test("private image cache use remains behind owner or moderator authorization", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-cache-private-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "private.png");
    await fs.promises.writeFile(assetPath, "private-current-render");

    const privateMii = readyMii({ private: true });
    const owner = { username: "owner" };
    const stranger = { username: "stranger" };
    assert.equal(canAccessPrivateMiiAsset(privateMii, owner), true);
    assert.equal(canAccessPrivateMiiAsset(privateMii, stranger), false);
    assert.equal(canAccessPrivateMiiAsset(privateMii, stranger, true), true);
    assert.equal(canAccessPrivateMiiAsset(privateMii, null, true), false);

    let unauthorizedRenders = 0;
    const unauthorized = await ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: canAccessPrivateMiiAsset(privateMii, stranger) ? privateMii : null,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        resolveCurrentMii: async () => privateMii,
        renderAndWrite: async () => {
            unauthorizedRenders += 1;
        }
    });
    assert.equal(unauthorized, false);
    assert.equal(unauthorizedRenders, 0);

    let ownerRenders = 0;
    const authorized = await ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: privateMii,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        resolveCurrentMii: async () => privateMii,
        renderAndWrite: async () => {
            ownerRenders += 1;
        }
    });
    assert.equal(authorized, true);
    assert.equal(ownerRenders, 0);
});

test("concurrent stale requests share one generation and only return after ready state commits", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-cache-concurrent-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "concurrent.png");
    const staleMii = { id: "cache1", ltdSha256: LTD_SHA256 };
    let currentMii = staleMii;
    let renders = 0;
    const request = () => ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: staleMii,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        resolveCurrentMii: async () => currentMii,
        renderAndWrite: async (_mii, destinationPath) => {
            renders += 1;
            await new Promise(resolve => setImmediate(resolve));
            await writeMiiImageBuffer(Buffer.from("one-shared-render"), destinationPath);
            currentMii = readyMii();
        }
    });

    assert.deepEqual(await Promise.all([request(), request(), request()]), [true, true, true]);
    assert.equal(renders, 1);
    assert.equal(await fs.promises.readFile(assetPath, "utf8"), "one-shared-render");
});

function getNestedValue(document, dottedPath) {
    return dottedPath.split(".").reduce((value, part) => value?.[part], document);
}

function matchesCasFilter(document, filter) {
    if (document.id !== filter.id || document.ltdSha256 !== filter.ltdSha256) return false;
    const directClauses = Object.entries(filter)
        .filter(([key]) => !["id", "ltdSha256", "$and"].includes(key))
        .map(([key, expected]) => ({ [key]: expected }));
    return [...directClauses, ...filter.$and].every(clause => {
        const [key, expected] = Object.entries(clause)[0];
        const actual = getNestedValue(document, key);
        if (expected && typeof expected === "object" && expected.$exists === false) {
            return actual === undefined;
        }
        if (actual instanceof Date && expected instanceof Date) {
            return actual.getTime() === expected.getTime();
        }
        return actual === expected;
    });
}

test("render-state CAS rejects a provenance backfill that changes presentation context", () => {
    const observed = {
        id: "headwear",
        ltdSha256: LTD_SHA256,
        hair: { type: 57 },
        ltdProvenance: { kind: "canonical-regenerated-charinfo" },
        ltdRender: {}
    };
    const current = structuredClone(observed);
    Object.assign(current.ltdProvenance, {
        sourceKind: "normalized-site-fields",
        byteExactSourceClaimed: false,
        appearanceProjectionExact: true
    });
    assert.equal(matchesCasFilter(current, buildLtdRenderPortraitCasFilter(observed)), false);
});

test("render-state CAS rejects a stale in-flight revision and propagates database failure", async () => {
    const observed = readyMii();
    const databaseRecord = structuredClone(observed);
    databaseRecord.ltdRender.portrait.renderedAt = new Date("2026-08-10T00:00:00.000Z");
    observed.ltdRender.portrait.renderedAt = databaseRecord.ltdRender.portrait.renderedAt;
    const filter = buildLtdRenderPortraitCasFilter(observed);
    assert.equal(matchesCasFilter(databaseRecord, filter), true);

    const newerRevision = "d".repeat(64);
    const newerState = {
        ...observed.ltdRender.portrait,
        rendererRevision: newerRevision,
        renderedAt: new Date("2026-08-10T00:01:00.000Z")
    };
    const updateOne = async (candidate, update) => {
        if (!matchesCasFilter(databaseRecord, candidate)) return { matchedCount: 0 };
        databaseRecord.ltdRender.portrait = structuredClone(update.$set["ltdRender.portrait"]);
        return { matchedCount: 1 };
    };

    assert.equal(await persistLtdRenderPortraitStateCas({
        mii: observed,
        state: newerState,
        updateOne
    }), true);
    assert.equal(databaseRecord.ltdRender.portrait.rendererRevision, newerRevision);

    const staleState = {
        ...observed.ltdRender.portrait,
        renderedAt: new Date("2026-08-10T00:02:00.000Z")
    };
    assert.equal(await persistLtdRenderPortraitStateCas({
        mii: observed,
        state: staleState,
        updateOne
    }), false);
    assert.equal(databaseRecord.ltdRender.portrait.rendererRevision, newerRevision);

    await assert.rejects(
        persistLtdRenderPortraitStateCas({
            mii: { ...observed, ltdRender: { portrait: newerState } },
            state: newerState,
            updateOne: async () => { throw new Error("database unavailable"); }
        }),
        /database unavailable/
    );
});

test("ready cache state is rejected when the published file hash does not match", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-cache-hash-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "hash.png");
    await fs.promises.writeFile(assetPath, "tampered");
    let currentMii = readyMii();
    let renders = 0;
    let observedHash = "e".repeat(64);

    assert.equal(await ensureCurrentLtdImageAsset({
        assetPath,
        initialMii: currentMii,
        rendererRevision: RENDERER_REVISION,
        fileExists: pathExists,
        getFileSha256: async () => observedHash,
        resolveCurrentMii: async () => currentMii,
        renderAndWrite: async () => {
            renders += 1;
            observedHash = OUTPUT_SHA256;
            currentMii = readyMii();
            return true;
        }
    }), true);
    assert.equal(renders, 1);
});

test("tokenized CAS publication prevents an old-identity writer from overwriting the winner", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-publish-race-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "race.png");
    const newLtdSha256 = "e".repeat(64);
    let databaseRecord = {
        id: "cache1",
        ltdSha256: newLtdSha256,
        ltdRender: {}
    };
    const publications = [];

    const runWriter = async ({ ltdSha256, outputSha256, token, bytes }) => {
        const readyState = {
            status: "ready",
            ltdSha256,
            rendererRevision: RENDERER_REVISION,
            capabilityKey: "checked-capability",
            resourceSignature: RESOURCE_SIGNATURE,
            outputSha256,
            view: "portrait",
            size: 512,
            backgroundMode: LTD_RENDER_BACKGROUND_MODE,
            ...RENDER_IDENTITY_FIELDS,
            renderedAt: new Date()
        };
        return await publishCasGuardedLtdImage({
            readyState,
            publishToken: token,
            withPublishLock: task => withMiiImagePublishLock(assetPath, task),
            resolveCurrentMii: async () => structuredClone(databaseRecord),
            claimPublishing: async (currentMii, publishingState) => {
                if (currentMii.ltdSha256 !== publishingState.ltdSha256) return false;
                databaseRecord.ltdRender.portrait = structuredClone(publishingState);
                return true;
            },
            publishAsset: async () => {
                publications.push(token);
                await writeMiiImageBuffer(Buffer.from(bytes), assetPath);
            },
            finalizeReady: async (claimedMii, finalState) => {
                if (databaseRecord.ltdRender.portrait?.publishToken
                    !== claimedMii.ltdRender.portrait?.publishToken) return false;
                databaseRecord.ltdRender.portrait = structuredClone(finalState);
                return true;
            }
        });
    };

    const [oldCommitted, newCommitted] = await Promise.all([
        runWriter({
            ltdSha256: LTD_SHA256,
            outputSha256: "f".repeat(64),
            token: "old-process-token",
            bytes: "old-loser"
        }),
        runWriter({
            ltdSha256: newLtdSha256,
            outputSha256: OUTPUT_SHA256,
            token: "new-process-token",
            bytes: "new-winner"
        })
    ]);

    assert.equal(oldCommitted, false);
    assert.equal(newCommitted, true);
    assert.deepEqual(publications, ["new-process-token"]);
    assert.equal(await fs.promises.readFile(assetPath, "utf8"), "new-winner");
    assert.equal(databaseRecord.ltdRender.portrait.status, "ready");
    assert.equal(databaseRecord.ltdRender.portrait.outputSha256, OUTPUT_SHA256);
});

test("a renderer revision must claim against the state that authorized its render", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-publish-revision-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "revision.png");
    let databaseRecord = {
        id: "cache1",
        ltdSha256: LTD_SHA256,
        ltdRender: {
            portrait: {
                status: "unsupported",
                ltdSha256: LTD_SHA256,
                rendererRevision: "0".repeat(64),
                backgroundMode: LTD_RENDER_BACKGROUND_MODE,
                checkedAt: new Date("2026-08-10T00:00:00.000Z")
            }
        }
    };
    const sharedObservation = structuredClone(databaseRecord);
    const publications = [];

    const persistFromObservation = async (observation, state) => {
        const filter = buildLtdRenderPortraitCasFilter(observation);
        if (!matchesCasFilter(databaseRecord, filter)) return false;
        databaseRecord.ltdRender.portrait = structuredClone(state);
        return true;
    };
    const runRevision = async ({ revision, outputSha256, token, bytes }) => {
        const readyState = {
            status: "ready",
            ltdSha256: LTD_SHA256,
            rendererRevision: revision,
            capabilityKey: "checked-capability",
            resourceSignature: RESOURCE_SIGNATURE,
            outputSha256,
            view: "portrait",
            size: 512,
            backgroundMode: LTD_RENDER_BACKGROUND_MODE,
            ...RENDER_IDENTITY_FIELDS,
            renderedAt: new Date()
        };
        return await publishCasGuardedLtdImage({
            readyState,
            publishToken: token,
            withPublishLock: task => withMiiImagePublishLock(assetPath, task),
            resolveCurrentMii: async () => structuredClone(databaseRecord),
            claimPublishing: async (_currentMii, publishingState) =>
                await persistFromObservation(sharedObservation, publishingState),
            publishAsset: async () => {
                publications.push(token);
                await writeMiiImageBuffer(Buffer.from(bytes), assetPath);
            },
            finalizeReady: async (claimedMii, finalState) =>
                await persistFromObservation(claimedMii, finalState)
        });
    };

    assert.equal(await runRevision({
        revision: "e".repeat(64),
        outputSha256: OUTPUT_SHA256,
        token: "new-revision",
        bytes: "new-revision-winner"
    }), true);
    assert.equal(await runRevision({
        revision: RENDERER_REVISION,
        outputSha256: "f".repeat(64),
        token: "old-revision",
        bytes: "old-revision-loser"
    }), false);

    assert.deepEqual(publications, ["new-revision"]);
    assert.equal(await fs.promises.readFile(assetPath, "utf8"), "new-revision-winner");
    assert.equal(databaseRecord.ltdRender.portrait.rendererRevision, "e".repeat(64));
});

test("LTD publication revalidates the source route after claiming", async () => {
    let databaseRecord = readyMii();
    databaseRecord.ltdRender = {};
    let published = false;
    const readyState = readyMii().ltdRender.portrait;

    const committed = await publishCasGuardedLtdImage({
        readyState,
        publishToken: "route-revalidation-token",
        withPublishLock: async task => await task(),
        resolveCurrentMii: async () => structuredClone(databaseRecord),
        claimPublishing: async (_currentMii, publishingState) => {
            databaseRecord.ltdRender.portrait = structuredClone(publishingState);
            databaseRecord.era = "CHARINFO";
            return true;
        },
        validateClaimedMii: async claimedMii => claimedMii.era === "LTD",
        publishAsset: async () => { published = true; },
        finalizeReady: async () => true
    });

    assert.equal(committed, false);
    assert.equal(published, false);
});

test("legacy lazy conversion publishes from its post-canonicalization authorization snapshot", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-legacy-auth-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "legacy.png");
    const legacyInput = { id: "cache1" };
    let databaseRecord = { id: "cache1", ltdSha256: LTD_SHA256, ltdRender: {} };
    const canonical = { storedFields: { ltdSha256: LTD_SHA256 } };
    const authorizationMii = selectLtdRenderAuthorizationSnapshot(
        legacyInput,
        canonical,
        structuredClone(databaseRecord)
    );
    assert.equal(authorizationMii.ltdSha256, LTD_SHA256);

    const readyState = readyMii().ltdRender.portrait;
    const persistFrom = async (observation, state) => {
        if (!matchesCasFilter(databaseRecord, buildLtdRenderPortraitCasFilter(observation))) return false;
        databaseRecord.ltdRender.portrait = structuredClone(state);
        return true;
    };
    const committed = await publishCasGuardedLtdImage({
        readyState,
        publishToken: "legacy-post-canonical-token",
        withPublishLock: task => withMiiImagePublishLock(assetPath, task),
        resolveCurrentMii: async () => structuredClone(databaseRecord),
        claimPublishing: async (_currentMii, publishingState) =>
            await persistFrom(authorizationMii, publishingState),
        publishAsset: async () => await writeMiiImageBuffer(Buffer.from("legacy-render"), assetPath),
        finalizeReady: async (claimedMii, finalState) => await persistFrom(claimedMii, finalState)
    });
    assert.equal(committed, true);
    assert.equal(await fs.promises.readFile(assetPath, "utf8"), "legacy-render");
    assert.equal(databaseRecord.ltdRender.portrait.status, "ready");

    assert.equal(selectLtdRenderAuthorizationSnapshot(
        legacyInput,
        canonical,
        { id: "cache1", ltdSha256: "e".repeat(64), ltdRender: {} }
    ), null);
});

test("same-path publication lock serializes independent writers", async t => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-publish-lock-"));
    t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
    const assetPath = path.join(directory, "locked.png");
    let active = 0;
    let maximumActive = 0;
    const task = async () => await withMiiImagePublishLock(assetPath, async () => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await new Promise(resolve => setTimeout(resolve, 30));
        active -= 1;
    });
    await Promise.all([task(), task()]);
    assert.equal(maximumActive, 1);
    assert.equal(await pathExists(`${assetPath}.publish.lock`), false);
});

test("Windows destination contention gets a narrow bounded rename retry", async () => {
    let attempts = 0;
    const delays = [];
    await renameMiiImageWithRetry("staged.tmp", "winner.png", {
        rename: async () => {
            attempts += 1;
            if (attempts < 3) {
                const error = new Error("scanner temporarily holds destination");
                error.code = attempts === 1 ? "EPERM" : "EBUSY";
                throw error;
            }
        },
        waitForRetry: async delay => delays.push(delay)
    });
    assert.equal(attempts, 3);
    assert.deepEqual(delays, [10, 25]);

    let nonRetryAttempts = 0;
    await assert.rejects(
        renameMiiImageWithRetry("staged.tmp", "winner.png", {
            rename: async () => {
                nonRetryAttempts += 1;
                const error = new Error("disk failure");
                error.code = "EIO";
                throw error;
            },
            waitForRetry: async () => assert.fail("EIO must not retry")
        }),
        /disk failure/
    );
    assert.equal(nonRetryAttempts, 1);
});
