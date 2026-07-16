// Rerender miis slowly in background
// This is used when we change how rendering works to make sure all miis are consistent.
// We manually run DB queries to find miis that need to be rerendered, then add their IDs into the rerender database collection.

import "./setEnvs.js";
import fs from "fs";
import miijs from "miijs";
import { renderStoredMiiImage, writeMiiImageBuffer } from "./miiImageRenderer.js";
import { getMiiAssetPaths } from "./miiAssets.js";
import {
    ENABLE_MIITOPIA_QRS,
    buildMiitopiaQrMii,
    canReuseMiiInstanceForExport,
    canGenerateMiitopiaQr,
    hasDecodedTomodachiLifeData,
    makeRenderedQrFromPayload,
    normalizeMiiFieldsForExport,
    normalizeQrConsole
} from "./miiQrUtils.js";
import { connectionPromise, Miis, RerenderQueue } from "./database.js";
import { sendWebhookPayload } from "./monitoring.js";


const rerenderInterval = 5000;
const idleRerenderInterval = 60000;
async function renderQrBuffer(miiData, qrConsole) {
    const sourceInstance = await miijs.Mii.create(miiData);
    const exportFields = normalizeMiiFieldsForExport(sourceInstance.fields);
    const canReuseSourceInstance = canReuseMiiInstanceForExport(sourceInstance.fields);
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

    const miiInstance = canReuseSourceInstance && qrFields === exportFields
        ? sourceInstance
        : await miijs.Mii.create(qrFields);
    const qrPayload = await miiInstance.encode(qrFormat);
    return makeRenderedQrFromPayload(qrPayload, miiInstance.fields);
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
        ENABLE_MIITOPIA_QRS ? isCached(qrMiitopiaPath) : false,
    ]);
    // MT QR cache files are ignored while site support is paused.
    const hasQrMiitopia = ENABLE_MIITOPIA_QRS && cachedQrMiitopia;

    if (!hasImg && !hasQr && !hasQrWii && !hasQrTomodachi && !hasQrMiitopia) {
        await RerenderQueue.deleteOne({ miiId });
        return true;
    }

    const miiData = miiDoc.toObject();

    const [imgBuffer, qrBuffer, qrWiiBuffer, qrTomodachiBuffer, qrMiitopiaBuffer] = await Promise.all([
        hasImg ? renderStoredMiiImage(miiData) : null,
        hasQr ? renderQrBuffer(miiData, "3DS") : null,
        hasQrWii ? renderQrBuffer(miiData, "WIIU") : null,
        hasQrTomodachi ? renderQrBuffer(miiData, "TOMODACHI") : null,
        hasQrMiitopia ? renderQrBuffer(miiData, "MIITOPIA") : null,
    ]);

    await Promise.all([
        hasImg ? writeMiiImageBuffer(imgBuffer, imgPath) : null,
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
