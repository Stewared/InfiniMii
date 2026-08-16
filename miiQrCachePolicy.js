import crypto from "node:crypto";
import fs from "node:fs";

import { getMiiDownloadPolicyPayloadHash } from "./miiDownloadPolicyToken.js";
import {
    getMiiImageFileSha256,
    getMiiImageRenderIdentity,
    renameMiiImageWithRetry
} from "./miiImageRenderer.js";

export const MII_QR_CACHE_POLICY_VERSION = "infinimii-canvas-free-qr-v1";

function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

export function getMiiQrCacheIdentity(
    mii,
    qrConsole,
    portraitSha256 = "",
    qrSha256 = "",
    renderIdentity = {}
) {
    return sha256(JSON.stringify({
        version: MII_QR_CACHE_POLICY_VERSION,
        qrConsole: String(qrConsole || "").trim().toUpperCase(),
        sourceSha256: getMiiDownloadPolicyPayloadHash(mii),
        portraitSha256: String(portraitSha256 || "").trim().toLowerCase(),
        qrSha256: String(qrSha256 || "").trim().toLowerCase(),
        rendererProfile: String(renderIdentity?.profile || ""),
        rendererBackend: String(renderIdentity?.backend || ""),
        rendererRevision: String(renderIdentity?.rendererRevision || ""),
        rendererCacheKey: String(renderIdentity?.rendererCacheKey || "")
    }));
}

export function getMiiQrCacheIdentityPath(qrPath) {
    return `${qrPath}.identity`;
}

export async function readMiiQrPortraitSha256(portraitPath) {
    if (!portraitPath) return "";
    try {
        return await getMiiImageFileSha256(portraitPath);
    } catch (error) {
        if (error?.code === "ENOENT") return "";
        throw error;
    }
}

export async function isCurrentMiiQrCacheAsset(mii, qrPath, qrConsole, portraitPath) {
    try {
        const [qrStat, storedIdentity, portraitSha256, qrSha256, renderIdentity] = await Promise.all([
            fs.promises.stat(qrPath),
            fs.promises.readFile(getMiiQrCacheIdentityPath(qrPath), "utf8"),
            readMiiQrPortraitSha256(portraitPath),
            getMiiImageFileSha256(qrPath),
            getMiiImageRenderIdentity(mii)
        ]);
        return qrStat.size > 0
            && storedIdentity.trim() === getMiiQrCacheIdentity(
                mii,
                qrConsole,
                portraitSha256,
                qrSha256,
                renderIdentity
            );
    } catch (error) {
        if (error?.code === "ENOENT") return false;
        throw error;
    }
}

export async function publishMiiQrCacheIdentity(mii, qrPath, qrConsole, portraitPath) {
    const [portraitSha256, qrSha256, renderIdentity] = await Promise.all([
        readMiiQrPortraitSha256(portraitPath),
        getMiiImageFileSha256(qrPath),
        getMiiImageRenderIdentity(mii)
    ]);
    const identityPath = getMiiQrCacheIdentityPath(qrPath);
    const temporaryPath = `${identityPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
        await fs.promises.writeFile(
            temporaryPath,
            `${getMiiQrCacheIdentity(mii, qrConsole, portraitSha256, qrSha256, renderIdentity)}\n`,
            "utf8"
        );
        await renameMiiImageWithRetry(temporaryPath, identityPath);
    } finally {
        await fs.promises.rm(temporaryPath, { force: true });
    }
}
