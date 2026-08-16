import { isStoredLtdCanonicalizationCurrent } from "./ltdCanonical.js";
import { getStoredLtdPresentationContextIdentity } from "./ltdPresentationContext.js";

const SHA256_PATTERN = /^[0-9a-f]{64}$/i;
const pendingImageGenerations = new Map();
export const LTD_RENDER_BACKGROUND_MODE = "transparent";
export const LTD_RENDER_RASTER_PROFILE = "native-resolution-v1";

export function createRendererRevisionSnapshot(resolveRevision) {
    let revision;
    return () => {
        if (revision === undefined) revision = resolveRevision();
        return revision;
    };
}

export function isCurrentReadyLtdRender(mii, rendererRevision) {
    const state = mii?.ltdRender?.portrait;
    const ltdSha256 = String(mii?.ltdSha256 || "");
    const revision = String(rendererRevision || "");
    const presentationContext = getStoredLtdPresentationContextIdentity(mii);

    return isStoredLtdCanonicalizationCurrent(mii)
        && state?.status === "ready"
        && SHA256_PATTERN.test(ltdSha256)
        && String(state.ltdSha256 || "").toLowerCase() === ltdSha256.toLowerCase()
        && SHA256_PATTERN.test(revision)
        && String(state.rendererRevision || "").toLowerCase() === revision.toLowerCase()
        && typeof state.capabilityKey === "string"
        && state.capabilityKey.length > 0
        && SHA256_PATTERN.test(String(state.resourceSignature || ""))
        && SHA256_PATTERN.test(String(state.outputSha256 || ""))
        && state.view === "portrait"
        && state.size === 512
        && state.backgroundMode === LTD_RENDER_BACKGROUND_MODE
        && state.presentationContextKind === presentationContext.kind
        && String(state.presentationContextSha256 || "").toLowerCase()
            === presentationContext.sha256
        && state.rasterProfile === LTD_RENDER_RASTER_PROFILE;
}

function portraitStateCasClauses(state) {
    const clauses = [];
    for (const field of [
        "status",
        "ltdSha256",
        "rendererRevision",
        "backgroundMode",
        "presentationContextKind",
        "presentationContextSha256",
        "rasterProfile",
        "capabilityKey",
        "resourceSignature",
        "outputSha256",
        "publishToken",
        "view",
        "size",
        "renderedAt",
        "checkedAt"
    ]) {
        const key = `ltdRender.portrait.${field}`;
        clauses.push(Object.prototype.hasOwnProperty.call(state || {}, field)
            ? { [key]: state[field] }
            : { [key]: { $exists: false } });
    }
    return clauses;
}

export function buildLtdRenderPortraitCasFilter(mii) {
    const id = String(mii?.id || "").trim();
    const ltdSha256 = String(mii?.ltdSha256 || "").toLowerCase();
    if (!id || !SHA256_PATTERN.test(ltdSha256)) {
        throw new TypeError("A stored Mii ID and current LTD SHA-256 are required for render-state CAS.");
    }
    const filter = {
        id,
        ltdSha256,
        $and: portraitStateCasClauses(mii?.ltdRender?.portrait)
    };
    // The lossy legacy 34/57 -> LTD 45 bridge can change presentation while
    // leaving the canonical LTD SHA unchanged. Bind every available source
    // discriminator that determines the external presentation context so a
    // concurrent source-only edit cannot authorize stale pixels.
    const sourceHairType = mii?.hair?.type;
    if (sourceHairType === undefined) {
        filter["hair.type"] = { $exists: false };
    } else if (
        sourceHairType === null
        || Number.isInteger(sourceHairType)
        || (typeof sourceHairType === "string" && /^\d{1,3}$/.test(sourceHairType))
    ) {
        filter["hair.type"] = sourceHairType;
    } else {
        throw new TypeError("Stored Mii hair.type is invalid for render-state CAS.");
    }
    // FavoriteColor is absent from the canonical LTD bytes but controls the
    // explicit InfiniMii default-shirt policy. Bind it independently so a
    // dashboard/source edit cannot publish pixels rendered for an older color.
    const favoriteColor = mii?.general?.favoriteColor;
    if (favoriteColor === undefined) {
        filter["general.favoriteColor"] = { $exists: false };
    } else if (
        favoriteColor === null
        || (Number.isInteger(favoriteColor) && favoriteColor >= 0 && favoriteColor <= 11)
    ) {
        filter["general.favoriteColor"] = favoriteColor;
    } else {
        throw new TypeError("Stored Mii general.favoriteColor is invalid for render-state CAS.");
    }
    for (const key of [
        "kind",
        "sourceKind",
        "byteExactSourceClaimed",
        "appearanceProjectionExact"
    ]) {
        const value = mii?.ltdProvenance?.[key];
        const field = `ltdProvenance.${key}`;
        if (value === undefined) {
            filter[field] = { $exists: false };
        } else if (["string", "boolean"].includes(typeof value) || value === null) {
            filter[field] = value;
        } else {
            throw new TypeError(`Stored Mii ${field} is invalid for render-state CAS.`);
        }
    }
    return filter;
}

function matchedUpdateCount(result) {
    for (const value of [result?.matchedCount, result?.n, result?.modifiedCount, result?.nModified]) {
        if (Number.isInteger(value)) return value;
    }
    return 0;
}

export async function persistLtdRenderPortraitStateCas({ mii, state, updateOne }) {
    if (typeof updateOne !== "function") throw new TypeError("updateOne must be a function.");
    const ltdSha256 = String(mii?.ltdSha256 || "").toLowerCase();
    const stateSha256 = String(state?.ltdSha256 || "").toLowerCase();
    const rendererRevision = String(state?.rendererRevision || "").toLowerCase();
    const presentationContext = getStoredLtdPresentationContextIdentity(mii);
    if (
        !SHA256_PATTERN.test(ltdSha256)
        || stateSha256 !== ltdSha256
        || !SHA256_PATTERN.test(rendererRevision)
        || state?.backgroundMode !== LTD_RENDER_BACKGROUND_MODE
        || state?.presentationContextKind !== presentationContext.kind
        || String(state?.presentationContextSha256 || "").toLowerCase()
            !== presentationContext.sha256
        || state?.rasterProfile !== LTD_RENDER_RASTER_PROFILE
    ) {
        throw new TypeError("Render state does not match the current transparent LTD render identity.");
    }
    const result = await updateOne(
        buildLtdRenderPortraitCasFilter(mii),
        { $set: { "ltdRender.portrait": state } }
    );
    return matchedUpdateCount(result) === 1;
}

function publishingStateMatches(mii, expected) {
    const actual = mii?.ltdRender?.portrait;
    return actual?.status === "publishing"
        && String(actual.ltdSha256 || "").toLowerCase() === String(expected.ltdSha256 || "").toLowerCase()
        && String(actual.rendererRevision || "").toLowerCase() === String(expected.rendererRevision || "").toLowerCase()
        && actual.backgroundMode === LTD_RENDER_BACKGROUND_MODE
        && actual.presentationContextKind === expected.presentationContextKind
        && String(actual.presentationContextSha256 || "").toLowerCase()
            === String(expected.presentationContextSha256 || "").toLowerCase()
        && actual.rasterProfile === LTD_RENDER_RASTER_PROFILE
        && actual.capabilityKey === expected.capabilityKey
        && String(actual.resourceSignature || "").toLowerCase() === String(expected.resourceSignature || "").toLowerCase()
        && String(actual.outputSha256 || "").toLowerCase() === String(expected.outputSha256 || "").toLowerCase()
        && actual.publishToken === expected.publishToken
        && actual.view === expected.view
        && actual.size === expected.size;
}

export async function publishCasGuardedLtdImage({
    readyState,
    publishToken,
    withPublishLock,
    resolveCurrentMii,
    claimPublishing,
    validateClaimedMii = async () => true,
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
        || readyState?.backgroundMode !== LTD_RENDER_BACKGROUND_MODE
        || typeof readyState?.presentationContextKind !== "string"
        || !SHA256_PATTERN.test(String(readyState?.presentationContextSha256 || ""))
        || readyState?.rasterProfile !== LTD_RENDER_RASTER_PROFILE
        || !SHA256_PATTERN.test(String(readyState?.ltdSha256 || ""))
        || !SHA256_PATTERN.test(String(readyState?.rendererRevision || ""))
        || !SHA256_PATTERN.test(String(readyState?.resourceSignature || ""))
        || !SHA256_PATTERN.test(String(readyState?.outputSha256 || ""))
        || typeof readyState?.capabilityKey !== "string"
        || !readyState.capabilityKey
        || readyState?.view !== "portrait"
        || readyState?.size !== 512
        || typeof publishToken !== "string"
        || !publishToken
    ) {
        throw new TypeError("A complete ready render identity and publication token are required.");
    }

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

        // The CAS claim is the authority to publish. Re-read it before touching
        // the shared path so an old-identity renderer cannot publish after a
        // newer identity has replaced its claim in Mongo.
        const claimedMii = await resolveCurrentMii();
        if (!publishingStateMatches(claimedMii, publishingState)) return false;
        if (!await validateClaimedMii(claimedMii, readyState)) return false;

        await publishAsset();
        // Never delete on a failed final CAS. Another process may already own
        // the newer state/path; the tokenized publishing state plus filesystem
        // lock ensures a loser cannot remove or overwrite that winner.
        return await finalizeReady(claimedMii, readyState);
    }));
}

export function canAccessPrivateMiiAsset(privateMii, user, isModerator = false) {
    if (!privateMii || !user) return false;
    return privateMii.uploader === user.username || isModerator === true;
}

export async function runLtdImageGenerationSingleFlight(assetPath, task) {
    const pending = pendingImageGenerations.get(assetPath);
    if (pending) return await pending;

    const generation = Promise.resolve().then(task);
    const trackedGeneration = generation.finally(() => {
        if (pendingImageGenerations.get(assetPath) === trackedGeneration) {
            pendingImageGenerations.delete(assetPath);
        }
    });
    pendingImageGenerations.set(assetPath, trackedGeneration);
    return await trackedGeneration;
}

export async function ensureCurrentLtdImageAsset({
    assetPath,
    initialMii,
    rendererRevision,
    fileExists,
    getFileSha256,
    resolveCurrentMii,
    renderAndWrite
}) {
    if (!initialMii) return false;

    const hasCurrentFile = async mii => {
        if (!isCurrentReadyLtdRender(mii, rendererRevision) || !await fileExists(assetPath)) return false;
        if (typeof getFileSha256 !== "function") return true;
        try {
            return String(await getFileSha256(assetPath)).toLowerCase()
                === String(mii.ltdRender.portrait.outputSha256).toLowerCase();
        } catch {
            return false;
        }
    };

    if (await hasCurrentFile(initialMii)) return true;

    const pending = pendingImageGenerations.get(assetPath);
    if (pending) {
        await pending;
        const currentMii = await resolveCurrentMii();
        if (!currentMii) return false;
        if (await hasCurrentFile(currentMii)) return true;
        return await ensureCurrentLtdImageAsset({
            assetPath,
            initialMii: currentMii,
            rendererRevision,
            fileExists,
            getFileSha256,
            resolveCurrentMii,
            renderAndWrite
        });
    }

    return Boolean(await runLtdImageGenerationSingleFlight(assetPath, async () => {
        const currentMii = await resolveCurrentMii();
        if (!currentMii) return false;
        if (await hasCurrentFile(currentMii)) return true;

        const written = await renderAndWrite(currentMii, assetPath);
        if (written === false) {
            const winnerMii = await resolveCurrentMii();
            return Boolean(winnerMii && await hasCurrentFile(winnerMii));
        }

        const committedMii = await resolveCurrentMii();
        return Boolean(committedMii && await hasCurrentFile(committedMii));
    }));
}
