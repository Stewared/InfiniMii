// Rerender miis slowly in background
// This is used when we change how rendering works to make sure all miis are consistent.
// We manually run DB queries to find miis that need to be rerendered, then add their IDs into the rerender database collection.

import "./setEnvs.js";
import { fileURLToPath } from "url";
import { dirname } from "path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import fs from "fs";
import path from "path";
import miijs from "miijs";
import { connectionPromise, Miis, RerenderQueue } from "./database.js";
import { sendWebhookPayload } from "./monitoring.js";


const rerenderInterval = 5000;
const idleRerenderInterval = 60000;
// MT QR rerendering is temporarily disabled on the InfiniMii site.
const ENABLE_MIITOPIA_QRS = false;

// TODO (cleanup) unify utils in a single file for ease of recreation in the future?
function normalizeQrConsole(input) {
    const cleaned = String(input || "").trim().toUpperCase().replace(/[\s_-]+/g, "");
    if (["TOMODACHI", "TOMODACHILIFE", "TL", "TLE"].includes(cleaned)) return "TOMODACHI";
    // if (["MIITOPIA", "MT", "MTE"].includes(cleaned)) return "MIITOPIA";
    if (ENABLE_MIITOPIA_QRS && ["MIITOPIA", "MT", "MTE"].includes(cleaned)) return "MIITOPIA";
    if (cleaned === "WIIU") return "WIIU";
    return "3DS";
}

function hasDecodedTomodachiLifeData(mii) {
    const tlData = mii?.tl;
    if (tlData === null || tlData === undefined) return false;
    if (typeof tlData !== "object") return true;
    return Object.keys(tlData).length > 0;
}

function getTrimmedMiiString(value) {
    return typeof value === "string" ? value.replace(/\s+/g, " ").trim() : "";
}

function canGenerateMiitopiaQr(mii) {
    return ENABLE_MIITOPIA_QRS && Boolean(getTrimmedMiiString(mii?.mt?.warCry) || getTrimmedMiiString(mii?.tl?.catchphrase));
}

function buildMiitopiaQrMii(mii) {
    const warCry = getTrimmedMiiString(mii?.mt?.warCry);
    const catchphrase = getTrimmedMiiString(mii?.tl?.catchphrase);
    if (!warCry && !catchphrase) return mii;

    const nextMii = structuredClone(mii);
    if (!getTrimmedMiiString(nextMii?.mt?.warCry)) {
        nextMii.mt = nextMii.mt && typeof nextMii.mt === "object" && !Array.isArray(nextMii.mt)
            ? nextMii.mt
            : {};
        nextMii.mt.warCry = catchphrase;
    }
    return nextMii;
}

function normalizeMiiFieldsForExport(fields) {
    if (!fields || typeof fields !== "object") return fields;
    const normalized = { ...fields };
    normalized.meta = fields.meta && typeof fields.meta === "object" ? { ...fields.meta } : {};
    normalized.perms = fields.perms && typeof fields.perms === "object" ? { ...fields.perms } : {};
    if (!normalized.meta.type) normalized.meta.type = "Default";
    return normalized;
}

async function makeRenderedQrFromPayload(qrPayload, miiFields, qrOptions = {}) {
    const nextQrOptions = { ...(qrOptions || {}) };

    if (!nextQrOptions.image && !nextQrOptions.noRenderMii) {
        try {
            const overlayPng = await miijs.renderMii(miiFields, nextQrOptions);
            nextQrOptions.image = Buffer.isBuffer(overlayPng) ? overlayPng : Buffer.from(overlayPng);
        } catch (e) {
            console.warn(`Unable to render Mii overlay for QR: ${e?.message || e}`);
        }
    }

    if (!nextQrOptions.label && miiFields?.meta?.name) {
        nextQrOptions.label = miiFields.meta.name;
    }

    return miijs.makeQR(qrPayload, nextQrOptions);
}

async function renderQrBuffer(miiData, qrConsole) {
    const sourceInstance = await miijs.Mii.create(miiData);
    const exportFields = normalizeMiiFieldsForExport(sourceInstance.fields);
    const normalizedConsole = normalizeQrConsole(qrConsole);
    let qrFields = exportFields;
    let qrFormat = normalizedConsole === "WIIU" ? "ffed" : "cfed";
    if (normalizedConsole === "TOMODACHI") {
        if (!hasDecodedTomodachiLifeData(exportFields)) return null;
        qrFormat = "tle";
    } else if (normalizedConsole === "MIITOPIA") {
        if (!canGenerateMiitopiaQr(exportFields)) return null;
        qrFields = buildMiitopiaQrMii(exportFields);
        qrFormat = "mte";
    }

    const miiInstance = await miijs.Mii.create(qrFields);
    const qrPayload = await miiInstance.encode(qrFormat);
    return makeRenderedQrFromPayload(qrPayload, miiInstance.fields);
}

function getMiiAssetPaths(miiId, isPrivate) {
    const imgDir = isPrivate ? "privateMiiImgs" : "miiImgs";
    const qr3dsDir = isPrivate ? "privateMiiQRs" : "miiQRs";
    const qrWiiDir = isPrivate ? "privateMiiQRsWii" : "miiQRsWii";
    const qrTomodachiDir = isPrivate ? "privateMiiQRsTomodachi" : "miiQRsTomodachi";
    const qrMiitopiaDir = isPrivate ? "privateMiiQRsMiitopia" : "miiQRsMiitopia";
    return {
        imgPath: path.join(__dirname, "static", imgDir, `${miiId}.png`),
        qrPath: path.join(__dirname, "static", qr3dsDir, `${miiId}.png`),
        qrWiiPath: path.join(__dirname, "static", qrWiiDir, `${miiId}.png`),
        qrTomodachiPath: path.join(__dirname, "static", qrTomodachiDir, `${miiId}.png`),
        qrMiitopiaPath: path.join(__dirname, "static", qrMiitopiaDir, `${miiId}.png`),
    };
}

async function isCached(filePath) {
    return fs.promises.access(filePath, fs.constants.F_OK).then(() => true).catch(() => false);
}

async function rerenderNext() {
    const next = await RerenderQueue.findOne().sort({ addedAt: 1 });
    if (!next) return false;

    const { miiId } = next;

    const miiDoc = await Miis.findOne({ id: miiId });
    if (!miiDoc) {
        await RerenderQueue.deleteOne({ miiId });
        return true;
    }

    const isPrivate = Boolean(miiDoc.private);
    const { imgPath, qrPath, qrWiiPath, qrTomodachiPath, qrMiitopiaPath } = getMiiAssetPaths(miiId, isPrivate);

    const [hasImg, hasQr, hasQrWii, hasQrTomodachi, cachedQrMiitopia] = await Promise.all([
        isCached(imgPath),
        isCached(qrPath),
        isCached(qrWiiPath),
        isCached(qrTomodachiPath),
        isCached(qrMiitopiaPath),
    ]);
    // MT QR cache files are ignored while site support is paused.
    const hasQrMiitopia = ENABLE_MIITOPIA_QRS && cachedQrMiitopia;

    if (!hasImg && !hasQr && !hasQrWii && !hasQrTomodachi && !hasQrMiitopia) {
        await RerenderQueue.deleteOne({ miiId });
        return true;
    }

    const miiData = miiDoc.toObject();

    const [imgBuffer, qrBuffer, qrWiiBuffer, qrTomodachiBuffer, qrMiitopiaBuffer] = await Promise.all([
        hasImg ? miijs.renderMii(miiData) : null,
        hasQr ? renderQrBuffer(miiData, "3DS") : null,
        hasQrWii ? renderQrBuffer(miiData, "WIIU") : null,
        hasQrTomodachi ? renderQrBuffer(miiData, "TOMODACHI") : null,
        hasQrMiitopia ? renderQrBuffer(miiData, "MIITOPIA") : null,
    ]);

    await Promise.all([
        hasImg ? fs.promises.writeFile(imgPath, imgBuffer) : null,
        hasQr ? fs.promises.writeFile(qrPath, qrBuffer) : null,
        hasQrWii ? fs.promises.writeFile(qrWiiPath, qrWiiBuffer) : null,
        hasQrTomodachi && qrTomodachiBuffer ? fs.promises.writeFile(qrTomodachiPath, qrTomodachiBuffer) : null,
        hasQrMiitopia && qrMiitopiaBuffer ? fs.promises.writeFile(qrMiitopiaPath, qrMiitopiaBuffer) : null,
    ]);
    
    console.log(`[rerender] Rerendered ${miiId}`);
    await RerenderQueue.deleteOne({ miiId });
    return true;
}

async function rerenderThread() {
    await connectionPromise; // might run this directly sometimes

    let foundLast = false;
    while (true) {
        try {
            foundLast = await rerenderNext();

            // Wait longer before querying if there wasn't anything there last time
            await new Promise(r => setTimeout(r, foundLast ? rerenderInterval : idleRerenderInterval));
        } catch (e) {
            // Report error, this shouldn't ever happen
            const err = `Rerenderer failed with error:\n\`\`\`${e.stack || e}\`\`\``;
            sendWebhookPayload({
                content: err.length > 4000 ? err.substring(0, 4000) : err
            }); 
    
            foundLast = false;
            await new Promise(r => setTimeout(r, idleRerenderInterval));
        }
    }
}

export function startRerenderer() {
    rerenderThread().catch(e => {
        const err = `Rerenderer failed with error:\n\`\`\`${e.stack || e}\`\`\``;
        sendWebhookPayload({
            content: err.length > 4000 ? err.substring(0, 4000) : err
        }); 
    });
}
