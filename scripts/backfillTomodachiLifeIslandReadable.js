import "../setEnvs.js";

import crypto from "crypto";
import mongoose from "mongoose";
import { islandAddresses } from "../node_modules/miijs/data.js";
import { connectionPromise, Miis } from "../database.js";

const BATCH_SIZE = 100;
const DRY_RUN = process.argv.includes("--dry-run");

function hasDecodedTomodachiLifeData(mii) {
    const tlData = mii?.tl;
    if (tlData === null || tlData === undefined) return false;
    if (typeof tlData !== "object") return true;
    return Object.keys(tlData).length > 0;
}

function normalizeReadableAddress(value) {
    return String(value ?? "")
        .replace(/\r\n?/g, "\n")
        .trim();
}

function getIslandIdObject(mii) {
    const islandId = mii?.tl?.island?.id;
    if (!islandId || typeof islandId !== "object" || Array.isArray(islandId)) {
        return null;
    }
    return islandId;
}

function getIslandIdHex(mii) {
    const islandId = mii?.tl?.island?.id;
    const rawIslandId = typeof islandId === "string"
        ? islandId
        : getIslandIdObject(mii)?.id;
    const normalized = String(rawIslandId ?? "")
        .replace(/[^0-9a-f]/gi, "")
        .toUpperCase();
    return normalized.length === 32 ? normalized : "";
}

function deriveReadableIslandAddress(mii) {
    const islandIdHex = getIslandIdHex(mii);
    if (!islandIdHex) return "";

    const islandName = String(mii?.tl?.island?.name ?? "").trim() || "no name";
    const digest = crypto
        .createHmac("sha1", Buffer.from("this is a tempolary key.\0", "ascii"))
        .update(Buffer.from(islandIdHex, "hex"))
        .digest();

    const hash = (BigInt(digest.readUInt32LE(4)) << 32n) | BigInt(digest.readUInt32LE(0));
    const wordCount = BigInt(islandAddresses.length);
    const ocean = islandAddresses[Number(hash % wordCount)];
    const isles = islandAddresses[Number((hash >> 10n) % wordCount)];
    const num1 = Number((hash >> 20n) % 1000n);
    const num2 = Number((hash >> 30n) % 1000n);

    return normalizeReadableAddress(`${islandName} Island\n${num1}-${num2} ${isles} Isles\n${ocean} Ocean`);
}

function buildIslandIdUpdateValue(mii, readable) {
    const islandId = mii?.tl?.island?.id;
    const id = getIslandIdHex(mii);
    if (islandId && typeof islandId === "object" && !Array.isArray(islandId)) {
        return {
            ...islandId,
            id,
            readable
        };
    }

    return {
        id,
        readable
    };
}

async function flushBulkOps(bulkOps) {
    if (bulkOps.length === 0) return 0;
    const ops = bulkOps.splice(0, bulkOps.length);
    const result = await Miis.bulkWrite(ops);
    return result.modifiedCount || ops.length;
}

async function main() {
    await connectionPromise;
    console.log("[backfill] Connected to MongoDB.");

    const query = {
        tl: {
            $exists: true,
            $ne: null
        }
    };
    const totalCount = await Miis.countDocuments(query);
    console.log(`[backfill] Found ${totalCount} Mii records with Tomodachi Life data${DRY_RUN ? " (dry run)" : ""}.`);

    const cursor = Miis.find(query).lean().cursor();
    const bulkOps = [];
    let scannedCount = 0;
    let tlCount = 0;
    let alreadyCurrentCount = 0;
    let queuedUpdateCount = 0;
    let modifiedCount = 0;
    let missingIslandIdCount = 0;
    let invalidIslandIdShapeCount = 0;
    let deriveFailureCount = 0;

    for await (const mii of cursor) {
        scannedCount++;
        if (scannedCount % 100 === 0) {
            console.log(`[backfill] Scanned ${scannedCount}/${totalCount} records...`);
        }

        if (!hasDecodedTomodachiLifeData(mii)) continue;
        tlCount++;

        const islandId = mii?.tl?.island?.id;
        if (Array.isArray(islandId) || (islandId && typeof islandId !== "string" && typeof islandId !== "object")) {
            invalidIslandIdShapeCount++;
            continue;
        }

        if (!getIslandIdHex(mii)) {
            missingIslandIdCount++;
            continue;
        }

        let readable;
        try {
            readable = deriveReadableIslandAddress(mii);
        } catch (error) {
            deriveFailureCount++;
            if (deriveFailureCount <= 10) {
                console.warn(`[backfill] Could not derive island address for ${mii.id || mii._id}: ${error.message}`);
            }
            continue;
        }

        if (!readable) {
            missingIslandIdCount++;
            continue;
        }

        const currentReadable = normalizeReadableAddress(mii?.tl?.island?.id?.readable);
        const nextIslandId = buildIslandIdUpdateValue(mii, readable);
        if (currentReadable === readable && typeof mii?.tl?.island?.id === "object") {
            alreadyCurrentCount++;
            continue;
        }

        queuedUpdateCount++;
        if (!DRY_RUN) {
            bulkOps.push({
                updateOne: {
                    filter: { _id: mii._id },
                    update: {
                        $set: {
                            "tl.island.id": nextIslandId
                        }
                    }
                }
            });
        }

        if (bulkOps.length >= BATCH_SIZE) {
            modifiedCount += await flushBulkOps(bulkOps);
        }
    }

    if (!DRY_RUN) {
        modifiedCount += await flushBulkOps(bulkOps);
    }

    console.log(`[backfill] TL records checked: ${tlCount}`);
    console.log(`[backfill] ${DRY_RUN ? "Would update" : "Updated"} ${DRY_RUN ? queuedUpdateCount : modifiedCount} Mii records with tl.island.id.readable.`);
    console.log(`[backfill] Already current: ${alreadyCurrentCount}`);
    console.log(`[backfill] Missing or invalid island ID: ${missingIslandIdCount}`);
    console.log(`[backfill] Unsupported island ID shape: ${invalidIslandIdShapeCount}`);
    console.log(`[backfill] MiiJS derivation failures: ${deriveFailureCount}`);
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
