import miijs from "miijs";

import { cloneSerializable } from "./miiDataUtils.js";
import { renderStoredMiiImage } from "./miiImageRenderer.js";

// Miitopia QR support remains available in MiiJS but is intentionally hidden
// on InfiniMii until the site feature is ready to be enabled.
export const ENABLE_MIITOPIA_QRS = false;

export function isMiitopiaQrConsole(input) {
    const cleaned = String(input || "").trim().toUpperCase().replace(/[\s_-]+/g, "");
    return cleaned === "MIITOPIA" || cleaned === "MT" || cleaned === "MTE";
}

export function normalizeQrConsole(input) {
    const cleaned = String(input || "").trim().toUpperCase().replace(/[\s_-]+/g, "");
    if (cleaned === "TOMODACHI" || cleaned === "TOMODACHILIFE" || cleaned === "TL" || cleaned === "TLE") {
        return "TOMODACHI";
    }
    if (isMiitopiaQrConsole(cleaned)) return ENABLE_MIITOPIA_QRS ? "MIITOPIA" : "3DS";
    if (cleaned === "WIIU") return "WIIU";
    return "3DS";
}

export function normalizeMiiFieldsForExport(fields) {
    if (!fields || typeof fields !== "object") return fields;

    const normalized = { ...fields };
    normalized.meta = fields.meta && typeof fields.meta === "object" ? { ...fields.meta } : {};
    normalized.perms = fields.perms && typeof fields.perms === "object" ? { ...fields.perms } : {};
    if (!normalized.meta.type) normalized.meta.type = "Default";
    return normalized;
}

export function canReuseMiiInstanceForExport(fields, { special = false } = {}) {
    return Boolean(
        !special
        && fields
        && typeof fields === "object"
        && fields.meta
        && typeof fields.meta === "object"
        && fields.meta.type
        && fields.perms
        && typeof fields.perms === "object"
    );
}

export function hasDecodedTomodachiLifeData(mii) {
    const tlData = mii?.tl;
    if (tlData === null || tlData === undefined) return false;
    if (typeof tlData !== "object") return true;
    return Object.keys(tlData).length > 0;
}

export function getTrimmedMiiString(value) {
    return typeof value === "string" ? value.replace(/\s+/g, " ").trim() : "";
}

export function getMiitopiaWarCry(mii) {
    return getTrimmedMiiString(mii?.mt?.warCry);
}

export function getTomodachiLifeCatchphrase(mii) {
    return getTrimmedMiiString(mii?.tl?.catchphrase);
}

export function canGenerateMiitopiaQr(mii) {
    return ENABLE_MIITOPIA_QRS && Boolean(getMiitopiaWarCry(mii) || getTomodachiLifeCatchphrase(mii));
}

export function getDefaultQrConsoleForMii(mii) {
    if (hasDecodedTomodachiLifeData(mii)) return "TOMODACHI";
    if (canGenerateMiitopiaQr(mii)) return "MIITOPIA";
    return "3DS";
}

export function buildMiitopiaQrMii(mii) {
    const warCry = getMiitopiaWarCry(mii);
    const catchphrase = getTomodachiLifeCatchphrase(mii);
    if (!warCry && !catchphrase) return mii;

    const nextMii = cloneSerializable(mii) || {};
    if (!getMiitopiaWarCry(nextMii)) {
        nextMii.mt = nextMii.mt && typeof nextMii.mt === "object" && !Array.isArray(nextMii.mt)
            ? nextMii.mt
            : {};
        nextMii.mt.warCry = catchphrase;
    }
    return nextMii;
}

export async function makeRenderedQrFromPayload(qrPayload, miiFields, qrOptions = {}) {
    const nextQrOptions = { ...(qrOptions || {}) };

    if (!nextQrOptions.image && !nextQrOptions.noRenderMii) {
        try {
            const overlayPng = await renderStoredMiiImage(miiFields, nextQrOptions);
            nextQrOptions.image = Buffer.isBuffer(overlayPng) ? overlayPng : Buffer.from(overlayPng);
        } catch (error) {
            console.warn(`Unable to render Mii overlay for QR: ${error?.message || error}`);
        }
    }

    if (!nextQrOptions.label && miiFields?.meta?.name) {
        nextQrOptions.label = miiFields.meta.name;
    }

    return miijs.makeQR(qrPayload, nextQrOptions);
}
