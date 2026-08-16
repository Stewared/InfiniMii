import "../setEnvs.js";

import crypto from "node:crypto";
import mongoose from "mongoose";
import miijs from "miijs";

import { connectionPromise, Miis } from "../database.js";
import {
    MII_FACEPAINT_CLASSIFICATION_POLICY,
    MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD,
    MII_FACEPAINT_TOTAL_PIXELS,
    classifyLtdFacepaintUsage
} from "../miiContentFilters.js";

const write = process.argv.includes("--write");
const BATCH_SIZE = 250;

function asBuffer(value) {
    if (Buffer.isBuffer(value)) return Buffer.from(value);
    if (value?.buffer && Buffer.isBuffer(value.buffer)) return Buffer.from(value.buffer);
    if (value?.type === "Buffer" && Array.isArray(value.data)) return Buffer.from(value.data);
    if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    return null;
}

async function main() {
    await connectionPromise;
    const cursor = Miis.find({ ltdData: { $exists: true, $ne: null } })
        .select("+ltdData id ltdSha256 facepaintUsage facepaintCoverage")
        .lean()
        .cursor();
    const counts = {
        scanned: 0,
        none: 0,
        partial: 0,
        full: 0,
        changed: 0,
        persisted: 0,
        skippedConcurrent: 0,
        failed: 0
    };
    let operations = [];

    const flush = async () => {
        if (!write || operations.length === 0) {
            operations = [];
            return;
        }
        const result = await Miis.bulkWrite(operations, { ordered: true, timestamps: false });
        counts.persisted += Number(result.modifiedCount || 0);
        counts.skippedConcurrent += operations.length - Number(result.matchedCount || 0);
        operations = [];
    };

    for await (const mii of cursor) {
        counts.scanned += 1;
        try {
            const bytes = asBuffer(mii.ltdData);
            if (!bytes) throw new TypeError("stored ltdData is not bytes");
            const actualSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
            const storedSha256 = String(mii.ltdSha256 || "").trim().toLowerCase();
            if (storedSha256 && storedSha256 !== actualSha256) {
                throw new TypeError("stored ltdSha256 does not match ltdData");
            }
            const classification = classifyLtdFacepaintUsage(miijs.parseLtdContainer(bytes));
            counts[classification.usage] += 1;
            if (
                mii.facepaintUsage === classification.usage
                && JSON.stringify(mii.facepaintCoverage || null) === JSON.stringify(classification)
            ) continue;

            counts.changed += 1;
            operations.push({
                updateOne: {
                    // The source hash is the CAS identity. A concurrent LTD
                    // replacement wins, and its classification is left for a
                    // later run rather than receiving stale metadata.
                    filter: storedSha256
                        ? { _id: mii._id, ltdSha256: storedSha256 }
                        : { _id: mii._id, ltdSha256: null, ltdData: bytes },
                    update: {
                        $set: {
                            facepaintUsage: classification.usage,
                            facepaintCoverage: classification
                        }
                    }
                }
            });
            if (operations.length >= BATCH_SIZE) await flush();
        } catch (error) {
            counts.failed += 1;
            console.error(`[facepaint backfill] ${mii.id}: ${error.message}`);
        }
    }
    await flush();
    console.log(JSON.stringify({
        mode: write ? "write" : "dry-run",
        classification: {
            measurement: "native LTD UGC BC1 opaque pixels",
            policy: MII_FACEPAINT_CLASSIFICATION_POLICY,
            titleDefinesPartialOrFull: false,
            fullAtOrAboveOpaquePixels: MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD,
            totalTexturePixels: MII_FACEPAINT_TOTAL_PIXELS
        },
        ...counts
    }, null, 2));
    if (counts.failed > 0) process.exitCode = 1;
}

try {
    await main();
} finally {
    await mongoose.disconnect();
}
