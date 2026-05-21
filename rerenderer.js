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

// TODO (cleanup) unify utils in a single file for ease of recreation in the future?
function normalizeQrConsole(input) {
    const cleaned = String(input || "").trim().toUpperCase().replace(/[\s_-]+/g, "");
    if (cleaned === "WIIU") return "WIIU";
    return "3DS";
}

function normalizeMiiFieldsForExport(fields) {
    if (!fields || typeof fields !== "object") return fields;
    const normalized = { ...fields };
    normalized.meta = fields.meta && typeof fields.meta === "object" ? { ...fields.meta } : {};
    normalized.perms = fields.perms && typeof fields.perms === "object" ? { ...fields.perms } : {};
    if (!normalized.meta.type) normalized.meta.type = "Default";
    return normalized;
}

async function renderQrBuffer(miiData, qrConsole) {
    const sourceInstance = await miijs.Mii.create(miiData);
    const exportFields = normalizeMiiFieldsForExport(sourceInstance.fields);
    const miiInstance = await miijs.Mii.create(exportFields);
    const qrFormat = normalizeQrConsole(qrConsole) === "WIIU" ? "ffed" : "cfed";
    const qrPayload = await miiInstance.encode(qrFormat);
    return miijs.makeQR(qrPayload, {});
}

function getMiiAssetPaths(miiId, isPrivate) {
    const imgDir = isPrivate ? "privateMiiImgs" : "miiImgs";
    const qr3dsDir = isPrivate ? "privateMiiQRs" : "miiQRs";
    const qrWiiDir = isPrivate ? "privateMiiQRsWii" : "miiQRsWii";
    return {
        imgPath: path.join(__dirname, "static", imgDir, `${miiId}.png`),
        qrPath: path.join(__dirname, "static", qr3dsDir, `${miiId}.png`),
        qrWiiPath: path.join(__dirname, "static", qrWiiDir, `${miiId}.png`),
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
    const { imgPath, qrPath, qrWiiPath } = getMiiAssetPaths(miiId, isPrivate);

    const [hasImg, hasQr, hasQrWii] = await Promise.all([
        isCached(imgPath),
        isCached(qrPath),
        isCached(qrWiiPath),
    ]);

    if (!hasImg && !hasQr && !hasQrWii) {
        await RerenderQueue.deleteOne({ miiId });
        return true;
    }

    const miiData = miiDoc.toObject();

    const [imgBuffer, qrBuffer, qrWiiBuffer] = await Promise.all([
        hasImg ? miijs.renderMii(miiData) : null,
        hasQr ? renderQrBuffer(miiData, "3DS") : null,
        hasQrWii ? renderQrBuffer(miiData, "WIIU") : null,
    ]);

    await Promise.all([
        hasImg ? fs.promises.writeFile(imgPath, imgBuffer) : null,
        hasQr ? fs.promises.writeFile(qrPath, qrBuffer) : null,
        hasQrWii ? fs.promises.writeFile(qrWiiPath, qrWiiBuffer) : null,
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
