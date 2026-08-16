import crypto from "node:crypto";
import fs from "node:fs";

import { ensureCanonicalLtdForMii } from "./ltdCanonical.js";
import { renderLtdImage } from "./ltdImageRenderer.js";
import {
    getNativeTomodachiRendererRevision,
    planNativeTomodachiRender,
    renderNativeTomodachiMii
} from "./nativeTomodachiRenderer.js";
import {
    canUseNativeTomodachiRendererForOptions,
    normalizeNativeTomodachiRenderSize,
    transformTomodachiFaceRender,
    transformTomodachiFullBodyRender
} from "./tomodachiRenderTransform.js";
import {
    getLtdPresentationContextSha256,
    resolveStoredLtdPresentationContext
} from "./ltdPresentationContext.js";
import { resolveMiiRendererRoute } from "./miiRendererRouting.js";

const WINDOWS_RENAME_RETRY_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);
const DEFAULT_RENAME_RETRY_DELAYS_MS = Object.freeze([10, 25, 50, 100]);
const PUBLISH_LOCK_WAIT_MS = 15_000;
const PUBLISH_LOCK_POLL_MS = 20;
const PUBLISH_LOCK_STALE_MS = 120_000;
const STANDARD_RENDER_IDENTITY_VERSION = "infinimii-standard-render-route-v1";

function wait(delayMs) {
    return new Promise(resolve => setTimeout(resolve, delayMs));
}

export function sha256MiiImageBuffer(imageBuffer) {
    return crypto.createHash("sha256").update(imageBuffer).digest("hex");
}

export async function getMiiImageFileSha256(filePath) {
    return sha256MiiImageBuffer(await fs.promises.readFile(filePath));
}

export async function renameMiiImageWithRetry(sourcePath, destinationPath, {
    rename = fs.promises.rename,
    retryDelaysMs = DEFAULT_RENAME_RETRY_DELAYS_MS,
    waitForRetry = wait
} = {}) {
    let attempt = 0;
    while (true) {
        try {
            await rename(sourcePath, destinationPath);
            return;
        } catch (error) {
            const delayMs = retryDelaysMs[attempt];
            if (!WINDOWS_RENAME_RETRY_CODES.has(error?.code) || delayMs === undefined) {
                throw error;
            }
            attempt += 1;
            await waitForRetry(delayMs);
        }
    }
}

export async function withMiiImagePublishLock(destinationPath, task, {
    waitMs = PUBLISH_LOCK_WAIT_MS,
    pollMs = PUBLISH_LOCK_POLL_MS,
    staleMs = PUBLISH_LOCK_STALE_MS
} = {}) {
    if (typeof task !== "function") throw new TypeError("publish-lock task must be a function.");
    const lockPath = `${destinationPath}.publish.lock`;
    const deadline = Date.now() + waitMs;
    const ownerToken = crypto.randomBytes(16).toString("hex");
    let lockHandle;

    while (!lockHandle) {
        try {
            lockHandle = await fs.promises.open(lockPath, "wx", 0o600);
        } catch (error) {
            if (error?.code !== "EEXIST") throw error;
            try {
                const stat = await fs.promises.stat(lockPath);
                if (Date.now() - stat.mtimeMs > staleMs) {
                    await fs.promises.rm(lockPath, { force: true });
                    continue;
                }
            } catch (statError) {
                if (statError?.code === "ENOENT") continue;
                throw statError;
            }
            if (Date.now() >= deadline) {
                const timeout = new Error("Timed out waiting for the Mii image publication lock.");
                timeout.code = "IMAGE_PUBLISH_LOCK_TIMEOUT";
                throw timeout;
            }
            await wait(pollMs);
        }
    }

    try {
        await lockHandle.writeFile(JSON.stringify({
            ownerToken,
            pid: process.pid,
            acquiredAt: new Date().toISOString()
        }));
        return await task();
    } finally {
        await lockHandle.close().catch(() => {});
        try {
            const current = JSON.parse(await fs.promises.readFile(lockPath, "utf8"));
            if (current?.ownerToken === ownerToken) {
                await fs.promises.rm(lockPath, { force: true });
            }
        } catch {
            // A stale-lock recovery may have replaced this owner's file. Never
            // remove a lock whose ownership can no longer be proven.
        }
    }
}

// The LTD implementation remains isolated behind the shared era-aware image
// boundary below.  LTD cache provenance is returned only by this path.
export function selectLtdRenderAuthorizationSnapshot(mii, canonical, storedIdentity) {
    const recordId = String(mii?.id || "").trim();
    const canonicalSha256 = String(canonical?.storedFields?.ltdSha256 || "").toLowerCase();
    const canonicalHairType = canonical?.parsed?.charInfo?.hairType;
    if (
        !recordId
        || storedIdentity?.id !== recordId
        || String(storedIdentity?.ltdSha256 || "").toLowerCase() !== canonicalSha256
    ) return null;
    const prospectiveSource = {
        ...mii,
        ltdSha256: canonicalSha256,
        ltdProvenance: canonical?.storedFields?.ltdProvenance || mii?.ltdProvenance
    };
    const prospectiveContext = resolveStoredLtdPresentationContext(prospectiveSource, {
        canonicalHairType
    });
    const storedContext = resolveStoredLtdPresentationContext(storedIdentity, {
        canonicalHairType
    });
    if (
        getLtdPresentationContextSha256(prospectiveContext)
        !== getLtdPresentationContextSha256(storedContext)
    ) return null;
    return storedIdentity;
}

async function renderLtdMiiImageResult(mii, options = {}) {
    const canonical = await ensureCanonicalLtdForMii(mii, { persist: true });
    let authorizationMii = null;
    if (mii?.id) {
        const { Miis } = await import("./database.js");
        const storedIdentity = await Miis.findOne({ id: mii.id })
            .select("id ltdSha256 ltdRender general.favoriteColor hair.type ltdProvenance")
            .lean();
        authorizationMii = selectLtdRenderAuthorizationSnapshot(mii, canonical, storedIdentity);
    }
    const presentationSource = authorizationMii || {
        ...mii,
        ltdSha256: canonical?.storedFields?.ltdSha256,
        ltdProvenance: canonical?.storedFields?.ltdProvenance || mii?.ltdProvenance
    };
    const presentationContext = presentationSource
        ? resolveStoredLtdPresentationContext(presentationSource, {
            canonicalHairType: canonical?.parsed?.charInfo?.hairType
        })
        : null;
    let rendered;
    try {
        rendered = await renderLtdImage(canonical.bytes, {
            ...options,
            presentationContext
        });
    } catch (error) {
        if (error && typeof error === "object") error.authorizationMii = authorizationMii;
        throw error;
    }
    return { ...rendered, canonical, authorizationMii };
}

async function renderTlMiiImageResult(mii, options, route) {
    if (!canUseNativeTomodachiRendererForOptions(options)) {
        const error = new Error("The TL renderer does not support the requested render options.");
        error.code = "UNSUPPORTED_TL_RENDER_OPTIONS";
        error.status = 422;
        throw error;
    }
    const size = normalizeNativeTomodachiRenderSize(options?.size);
    if (size === null) {
        const error = new Error("The TL renderer size must resolve to a value from 64 through 2048.");
        error.code = "UNSUPPORTED_TL_RENDER_OPTIONS";
        error.status = 422;
        throw error;
    }
    const native = await renderNativeTomodachiMii(mii, options);
    const sourceSha256 = sha256MiiImageBuffer(native.buffer);
    const transform = options?.fullBody
        ? transformTomodachiFullBodyRender
        : transformTomodachiFaceRender;
    const buffer = await transform({
        sourceBuffer: native.buffer,
        sourceSha256,
        sourceIsRaw: true,
        id: String(mii?.id || "transient-mii"),
        size
    });
    return {
        buffer,
        outputSha256: sha256MiiImageBuffer(buffer),
        canonical: null,
        authorizationMii: null,
        provenance: null,
        rendererProfile: route.profile,
        rendererBackend: route.backend,
        rendererRevision: getStandardRendererRevision(),
        rendererLocked: route.locked,
        rendererDefaultProfile: route.defaultProfile,
        rendererCacheKey: getStandardRendererCacheKey(route, native.cacheKey, options, size)
    };
}

function getStandardRendererCacheKey(route, nativeCacheKey, options, size) {
    return crypto.createHash("sha256").update(JSON.stringify({
        version: STANDARD_RENDER_IDENTITY_VERSION,
        profile: route.profile,
        backend: route.backend,
        rendererRevision: getStandardRendererRevision(),
        nativeCacheKey,
        view: options?.fullBody ? "full-body" : "portrait",
        size
    })).digest("hex");
}

function getStandardRendererRevision() {
    return crypto.createHash("sha256").update(JSON.stringify({
        version: STANDARD_RENDER_IDENTITY_VERSION,
        native: getNativeTomodachiRendererRevision()
    })).digest("hex");
}

export async function getMiiImageRenderIdentity(mii, options = {}) {
    const route = resolveMiiRendererRoute(mii, {
        requestedProfile: options?.rendererProfile,
        sourceEra: options?.sourceEra,
        ltdExclusive: options?.ltdExclusive
    });
    if (route.backend === "LTD") {
        return Object.freeze({ ...route, rendererCacheKey: "" });
    }
    if (!canUseNativeTomodachiRendererForOptions(options)) {
        const error = new Error("The TL renderer does not support the requested render options.");
        error.code = "UNSUPPORTED_TL_RENDER_OPTIONS";
        error.status = 422;
        throw error;
    }
    const size = normalizeNativeTomodachiRenderSize(options?.size);
    if (size === null) {
        const error = new Error("The TL renderer size must resolve to a value from 64 through 2048.");
        error.code = "UNSUPPORTED_TL_RENDER_OPTIONS";
        error.status = 422;
        throw error;
    }
    const plan = await planNativeTomodachiRender(mii, options);
    return Object.freeze({
        ...route,
        rendererRevision: getStandardRendererRevision(),
        rendererCacheKey: getStandardRendererCacheKey(route, plan.cacheKey, options, size),
        view: options?.fullBody ? "full-body" : "portrait",
        size
    });
}

// Sole shared Mii-image rendering boundary. CFCD/legacy TL and the other
// currently classic profiles use TL; RCD uses the logical RFL adapter (whose
// backend is TL until native RFL is implemented); LTD-exclusive sources remain
// locked to the LTD renderer. Explicit dashboard overrides enter here too.
export async function renderStoredMiiImageResult(mii, options = {}) {
    const route = resolveMiiRendererRoute(mii, {
        requestedProfile: options?.rendererProfile,
        sourceEra: options?.sourceEra,
        ltdExclusive: options?.ltdExclusive
    });
    const renderOptions = { ...options };
    delete renderOptions.rendererProfile;
    delete renderOptions.sourceEra;
    delete renderOptions.ltdExclusive;

    if (route.backend === "LTD") {
        const result = await renderLtdMiiImageResult(mii, renderOptions);
        return {
            ...result,
            rendererProfile: route.profile,
            rendererBackend: route.backend,
            rendererLocked: route.locked,
            rendererDefaultProfile: route.defaultProfile
        };
    }
    return await renderTlMiiImageResult(mii, renderOptions, route);
}

export async function renderStoredMiiImage(mii, options = {}) {
    return (await renderStoredMiiImageResult(mii, options)).buffer;
}

export async function writeMiiImageBuffer(imageBuffer, destinationPath) {
    const temporaryPath = `${destinationPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
        await fs.promises.writeFile(temporaryPath, imageBuffer);
        await renameMiiImageWithRetry(temporaryPath, destinationPath);
    } finally {
        await fs.promises.rm(temporaryPath, { force: true });
    }
}

export async function writeStoredMiiImage(mii, destinationPath, options = {}) {
    const imageBuffer = await renderStoredMiiImage(mii, options);
    await writeMiiImageBuffer(imageBuffer, destinationPath);
    return imageBuffer;
}
