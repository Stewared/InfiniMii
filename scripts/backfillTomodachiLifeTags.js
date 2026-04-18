import "../setEnvs.js";

import fs from "fs";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";
import miijs from "miijs";
import { connectionPromise, Miis, Settings } from "../database.js";

const TOMODACHI_LIFE_TAG = "Tomodachi Life";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const QR_DIRECTORIES = [
    path.join(PROJECT_ROOT, "static", "miiQRs"),
    path.join(PROJECT_ROOT, "static", "privateMiiQRs")
];

function normalizeTagValue(tag) {
    if (typeof tag !== "string") return "";
    return tag
        .replace(/\s+/g, " ")
        .replace(/[<>]/g, "")
        .trim();
}

function normalizeTagList(rawTags) {
    const source = Array.isArray(rawTags) ? rawTags : [rawTags];
    const flattened = source.flatMap(tag => {
        if (typeof tag !== "string") return [];
        return tag.split(",");
    });

    const normalized = [];
    const seen = new Set();

    for (const rawTag of flattened) {
        const tag = normalizeTagValue(rawTag);
        if (!tag) continue;

        const lower = tag.toLowerCase();
        if (seen.has(lower)) continue;

        seen.add(lower);
        normalized.push(tag);
    }

    return normalized;
}

function hasDecodedTomodachiLifeData(mii) {
    const tlData = mii?.tl;
    if (tlData === null || tlData === undefined) return false;
    if (typeof tlData !== "object") return true;
    return Object.keys(tlData).length > 0;
}

function buildUpdatedTags(rawTags) {
    const autoTagKey = TOMODACHI_LIFE_TAG.toLowerCase();
    const existingTags = normalizeTagList(rawTags).filter(
        tag => tag.toLowerCase() !== autoTagKey
    );
    return [...existingTags, TOMODACHI_LIFE_TAG];
}

function getGenerated3dsQrFiles() {
    const qrByMiiId = new Map();

    for (const qrDirectory of QR_DIRECTORIES) {
        if (!fs.existsSync(qrDirectory)) {
            console.log(`[backfill] Skipping missing QR directory: ${qrDirectory}`);
            continue;
        }

        const qrFiles = fs.readdirSync(qrDirectory, { withFileTypes: true })
            .filter(entry => entry.isFile() && entry.name.toLowerCase().endsWith(".png"));

        for (const qrFile of qrFiles) {
            const miiId = path.basename(qrFile.name, path.extname(qrFile.name));
            if (!miiId || qrByMiiId.has(miiId)) continue;

            qrByMiiId.set(miiId, {
                miiId,
                qrPath: path.join(qrDirectory, qrFile.name)
            });
        }
    }

    return [...qrByMiiId.values()];
}

async function decodeQrMiiData(qrPath) {
    const mii = await miijs.Mii.create(qrPath);
    return mii.fields;
}

async function main() {
    await connectionPromise;
    console.log("[backfill] Connected to MongoDB.");

    const qrFiles = getGenerated3dsQrFiles();
    console.log(`[backfill] Found ${qrFiles.length} generated 3DS QR files to scan.`);

    const miiIds = qrFiles.map(({ miiId }) => miiId);
    const storedMiis = await Miis.find({ id: { $in: miiIds } })
        .select("_id id meta.name tags tl")
        .lean();
    const storedMiiById = new Map(storedMiis.map(mii => [mii.id, mii]));

    const bulkOps = [];
    let scannedCount = 0;
    let decodedWithTlCount = 0;
    let missingMiiCount = 0;
    let decodeFailureCount = 0;
    let alreadyCurrentCount = 0;

    for (const { miiId, qrPath } of qrFiles) {
        const storedMii = storedMiiById.get(miiId);
        if (!storedMii) {
            missingMiiCount++;
            continue;
        }

        scannedCount++;
        if (scannedCount % 50 === 0) {
            console.log(`[backfill] Scanned ${scannedCount}/${qrFiles.length} QR files...`);
        }

        let decodedMii;
        try {
            decodedMii = await decodeQrMiiData(qrPath);
        } catch (error) {
            decodeFailureCount++;
            console.warn(`[backfill] Could not decode QR for ${miiId}: ${error.message}`);
            continue;
        }

        if (!hasDecodedTomodachiLifeData(decodedMii)) {
            continue;
        }

        decodedWithTlCount++;
        const currentTags = normalizeTagList(storedMii.tags || []);
        const nextTags = buildUpdatedTags(currentTags);
        const nextTl = decodedMii.tl;
        const shouldUpdateTags = JSON.stringify(currentTags) !== JSON.stringify(nextTags);
        const shouldUpdateTl = JSON.stringify(storedMii.tl ?? null) !== JSON.stringify(nextTl);

        if (!shouldUpdateTags && !shouldUpdateTl) {
            alreadyCurrentCount++;
            continue;
        }

        bulkOps.push({
            updateOne: {
                filter: { _id: storedMii._id },
                update: {
                    $set: {
                        tl: nextTl,
                        tags: nextTags
                    }
                }
            }
        });
    }

    if (bulkOps.length > 0) {
        const result = await Miis.bulkWrite(bulkOps);
        console.log(
            `[backfill] Updated ${result.modifiedCount || bulkOps.length} Mii records with TL data and the ${TOMODACHI_LIFE_TAG} tag.`
        );
    } else {
        console.log("[backfill] No Mii records needed TL data or tag updates.");
    }

    await Settings.findByIdAndUpdate(
        "global",
        {
            $addToSet: {
                miiTags: TOMODACHI_LIFE_TAG
            }
        },
        {
            new: true,
            upsert: true,
            setDefaultsOnInsert: true
        }
    );

    console.log(`[backfill] Ensured "${TOMODACHI_LIFE_TAG}" exists in the global tag catalog.`);
    console.log(`[backfill] QR files matched to Miis: ${scannedCount}`);
    console.log(`[backfill] QR files with decoded TL data: ${decodedWithTlCount}`);
    console.log(`[backfill] Already current: ${alreadyCurrentCount}`);
    console.log(`[backfill] Missing database records for QR files: ${missingMiiCount}`);
    console.log(`[backfill] QR decode failures: ${decodeFailureCount}`);
    console.log("[backfill] Done.");
}

main()
    .catch((error) => {
        console.error("[backfill] Failed:", error);
        process.exitCode = 1;
    })
    .finally(async () => {
        try {
            if (mongoose.connection.readyState !== 0) {
                await mongoose.disconnect();
            }
        } catch (disconnectError) {
            console.error("[backfill] Failed to disconnect cleanly:", disconnectError);
            process.exitCode = 1;
        }
    });
