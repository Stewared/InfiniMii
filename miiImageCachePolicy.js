const SHA256_PATTERN = /^[0-9a-f]{64}$/i;
const PORTRAIT_STATE_FIELDS = Object.freeze([
    "status",
    "rendererProfile",
    "rendererBackend",
    "rendererRevision",
    "rendererCacheKey",
    "outputSha256",
    "publishToken",
    "view",
    "size",
    "renderedAt",
    "checkedAt"
]);

function stateCasClauses(state) {
    return PORTRAIT_STATE_FIELDS.map((field) => {
        const path = `imageRender.portrait.${field}`;
        return Object.prototype.hasOwnProperty.call(state || {}, field)
            ? { [path]: state[field] }
            : { [path]: { $exists: false } };
    });
}

function sourceHashClause(mii) {
    const miiHash = String(mii?.miiHash || "").trim();
    return miiHash ? { miiHash } : { miiHash: { $exists: false } };
}

function updatedAtClause(mii) {
    const updatedAt = mii?.updatedAt;
    if (updatedAt === undefined) return { updatedAt: { $exists: false } };
    const date = updatedAt instanceof Date ? updatedAt : new Date(updatedAt);
    if (Number.isNaN(date.getTime())) {
        throw new TypeError("Stored Mii updatedAt is invalid for standard render-state CAS.");
    }
    return { updatedAt: date };
}

export function buildStandardMiiRenderPortraitCasFilter(mii) {
    const id = String(mii?.id || "").trim();
    if (!id) throw new TypeError("A stored Mii ID is required for standard render-state CAS.");
    return {
        id,
        ...sourceHashClause(mii),
        ...updatedAtClause(mii),
        $and: stateCasClauses(mii?.imageRender?.portrait)
    };
}

export function buildStandardMiiRenderReadyState(rendered, renderedAt = new Date()) {
    if (
        !Buffer.isBuffer(rendered?.buffer)
        || !["TL", "RFL"].includes(rendered?.rendererProfile)
        || rendered?.rendererBackend !== "TL"
        || !SHA256_PATTERN.test(String(rendered?.rendererRevision || ""))
        || !SHA256_PATTERN.test(String(rendered?.rendererCacheKey || ""))
    ) throw new TypeError("A complete standard renderer result is required.");
    const outputSha256 = String(rendered.outputSha256 || "").toLowerCase();
    if (!SHA256_PATTERN.test(outputSha256)) throw new TypeError("A rendered output SHA-256 is required.");
    return {
        status: "ready",
        rendererProfile: rendered.rendererProfile,
        rendererBackend: rendered.rendererBackend,
        rendererRevision: rendered.rendererRevision,
        rendererCacheKey: rendered.rendererCacheKey,
        outputSha256,
        view: "portrait",
        size: 512,
        renderedAt
    };
}

export function isCurrentReadyStandardMiiRender(mii, identity) {
    const state = mii?.imageRender?.portrait;
    return state?.status === "ready"
        && ["TL", "RFL"].includes(identity?.profile)
        && identity?.backend === "TL"
        && SHA256_PATTERN.test(String(identity?.rendererRevision || ""))
        && SHA256_PATTERN.test(String(identity?.rendererCacheKey || ""))
        && state.rendererProfile === identity.profile
        && state.rendererBackend === identity.backend
        && String(state.rendererRevision || "").toLowerCase()
            === String(identity.rendererRevision).toLowerCase()
        && String(state.rendererCacheKey || "").toLowerCase()
            === String(identity.rendererCacheKey).toLowerCase()
        && SHA256_PATTERN.test(String(state.outputSha256 || ""))
        && state.view === "portrait"
        && state.size === 512;
}

function matchedCount(result) {
    for (const value of [result?.matchedCount, result?.n, result?.modifiedCount, result?.nModified]) {
        if (Number.isInteger(value)) return value;
    }
    return 0;
}

export async function persistStandardMiiRenderPortraitStateCas({ mii, state, updateOne }) {
    if (typeof updateOne !== "function") throw new TypeError("updateOne must be a function.");
    if (
        !["publishing", "ready"].includes(state?.status)
        || !["TL", "RFL"].includes(state?.rendererProfile)
        || state?.rendererBackend !== "TL"
        || !SHA256_PATTERN.test(String(state?.rendererRevision || ""))
        || !SHA256_PATTERN.test(String(state?.rendererCacheKey || ""))
        || !SHA256_PATTERN.test(String(state?.outputSha256 || ""))
        || state?.view !== "portrait"
        || state?.size !== 512
    ) throw new TypeError("Standard render state is incomplete.");
    const result = await updateOne(
        buildStandardMiiRenderPortraitCasFilter(mii),
        { $set: { "imageRender.portrait": state } }
    );
    return matchedCount(result) === 1;
}

function publishingStateMatches(mii, expected) {
    const actual = mii?.imageRender?.portrait;
    return actual?.status === "publishing"
        && actual.rendererProfile === expected.rendererProfile
        && actual.rendererBackend === expected.rendererBackend
        && String(actual.rendererRevision || "").toLowerCase() === String(expected.rendererRevision).toLowerCase()
        && String(actual.rendererCacheKey || "").toLowerCase() === String(expected.rendererCacheKey).toLowerCase()
        && String(actual.outputSha256 || "").toLowerCase() === String(expected.outputSha256).toLowerCase()
        && actual.publishToken === expected.publishToken
        && actual.view === "portrait"
        && actual.size === 512;
}

export async function publishCasGuardedStandardMiiImage({
    readyState,
    publishToken,
    withPublishLock,
    resolveCurrentMii,
    claimPublishing,
    validateClaimedMii,
    publishAsset,
    finalizeReady
}) {
    for (const [name, value] of Object.entries({
        withPublishLock,
        resolveCurrentMii,
        claimPublishing,
        validateClaimedMii,
        publishAsset,
        finalizeReady
    })) {
        if (typeof value !== "function") throw new TypeError(`${name} must be a function.`);
    }
    if (
        readyState?.status !== "ready"
        || !["TL", "RFL"].includes(readyState?.rendererProfile)
        || readyState?.rendererBackend !== "TL"
        || !SHA256_PATTERN.test(String(readyState?.rendererRevision || ""))
        || !SHA256_PATTERN.test(String(readyState?.rendererCacheKey || ""))
        || !SHA256_PATTERN.test(String(readyState?.outputSha256 || ""))
        || readyState?.view !== "portrait"
        || readyState?.size !== 512
        || typeof publishToken !== "string"
        || !publishToken
    ) throw new TypeError("A complete standard render identity and publication token are required.");
    const publishingState = {
        ...readyState,
        status: "publishing",
        publishToken,
        checkedAt: new Date()
    };
    delete publishingState.renderedAt;

    return Boolean(await withPublishLock(async () => {
        const currentMii = await resolveCurrentMii();
        if (!currentMii || !await claimPublishing(currentMii, publishingState)) return false;
        const claimedMii = await resolveCurrentMii();
        if (!publishingStateMatches(claimedMii, publishingState)) return false;
        if (!await validateClaimedMii(claimedMii, readyState)) return false;
        await publishAsset();
        return await finalizeReady(claimedMii, readyState);
    }));
}
