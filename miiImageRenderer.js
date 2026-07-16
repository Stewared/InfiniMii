import crypto from "crypto";
import fs from "fs";
import miijs from "miijs";
import {
    planNativeTomodachiRender,
    renderNativeTomodachiPlan
} from "./nativeTomodachiRenderer.js";
import {
    canUseNativeTomodachiRendererForOptions,
    MII_IMAGE_SIZE,
    normalizeNativeTomodachiRenderSize,
    transformTomodachiFaceRender,
    transformTomodachiFullBodyRender
} from "./tomodachiRenderTransform.js";

const MAX_TRANSFORMED_FACE_CACHE_ENTRIES = 256;
const transformedFaces = new Map();
const pendingTransformedFaces = new Map();

function rememberTransformedFace(key, buffer) {
    if (transformedFaces.has(key)) transformedFaces.delete(key);
    transformedFaces.set(key, buffer);
    while (transformedFaces.size > MAX_TRANSFORMED_FACE_CACHE_ENTRIES) {
        transformedFaces.delete(transformedFaces.keys().next().value);
    }
}

function miiLabel(mii) {
    const plain = mii && typeof mii.toObject === "function"
        ? mii.toObject({ depopulate: true, flattenMaps: true })
        : mii;
    return String(plain?.id || plain?.meta?.name || "Mii");
}

async function renderNativeFace(mii, options) {
    const fullBody = Boolean(options?.fullBody);
    const size = normalizeNativeTomodachiRenderSize(options?.size ?? MII_IMAGE_SIZE);
    const plan = await planNativeTomodachiRender(mii, { fullBody });
    const cacheKey = `${plan.mode}:${plan.cacheKey}:${size}`;
    const cached = transformedFaces.get(cacheKey);
    if (cached) {
        transformedFaces.delete(cacheKey);
        transformedFaces.set(cacheKey, cached);
        return cached;
    }

    const existingTransform = pendingTransformedFaces.get(cacheKey);
    if (existingTransform) return existingTransform;

    const pendingTransform = (async () => {
        const native = await renderNativeTomodachiPlan(plan);
        const sourceSha256 = crypto.createHash("sha256").update(native.buffer).digest("hex");

        const transform = fullBody
            ? transformTomodachiFullBodyRender
            : transformTomodachiFaceRender;
        const buffer = await transform({
            sourceBuffer: native.buffer,
            id: miiLabel(mii),
            sourceSha256,
            size,
            sourceIsRaw: true
        });
        rememberTransformedFace(cacheKey, buffer);
        return buffer;
    })();
    pendingTransformedFaces.set(cacheKey, pendingTransform);
    try {
        return await pendingTransform;
    } finally {
        if (pendingTransformedFaces.get(cacheKey) === pendingTransform) {
            pendingTransformedFaces.delete(cacheKey);
        }
    }
}

export async function renderStoredMiiImage(mii, options = {}) {
    if (canUseNativeTomodachiRendererForOptions(options)) {
        return renderNativeFace(mii, options);
    }
    // Expression and caller-supplied resource/body rendering remain explicit
    // MiiJS features; normal portrait and full-body renders use the native path.
    return miijs.renderMii(mii, options);
}

export async function writeMiiImageBuffer(imageBuffer, destinationPath) {
    const temporaryPath = `${destinationPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
        await fs.promises.writeFile(temporaryPath, imageBuffer);
        await fs.promises.rename(temporaryPath, destinationPath);
    } finally {
        await fs.promises.rm(temporaryPath, { force: true });
    }
}

export async function writeStoredMiiImage(mii, destinationPath, options = {}) {
    const imageBuffer = await renderStoredMiiImage(mii, options);
    await writeMiiImageBuffer(imageBuffer, destinationPath);
    return imageBuffer;
}
