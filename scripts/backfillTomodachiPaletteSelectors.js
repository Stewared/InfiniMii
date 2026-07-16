import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import "../setEnvs.js";
import { cleanupMongoResources, connectionPromise, Miis } from "../database.js";

const MODULE_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPORT_PATH = path.resolve(
    MODULE_DIRECTORY,
    "..",
    "native",
    "tomodachi",
    "local-audit",
    "infinimii_original_tl_palette_selectors.json"
);

function stable(value) {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === "object") {
        const result = {};
        for (const key of Object.keys(value).sort()) result[key] = stable(value[key]);
        return result;
    }
    return value;
}

function sha256Json(value) {
    return crypto
        .createHash("sha256")
        .update(Buffer.from(JSON.stringify(stable(value)), "utf8"))
        .digest("hex");
}

function sourceRenderObject(mii) {
    return {
        id: mii.id,
        general: mii.general,
        meta: mii.meta,
        hair: mii.hair,
        face: mii.face,
        eyes: mii.eyes,
        eyebrows: mii.eyebrows,
        nose: mii.nose,
        mouth: mii.mouth,
        beard: mii.beard,
        glasses: mii.glasses,
        mole: mii.mole,
        tl: mii.tl
    };
}

function littleEndianHexWord(value) {
    if (typeof value !== "string" || !/^[0-9a-fA-F]{4}$/.test(value)) {
        throw new Error(`Invalid TL wardrobe word ${JSON.stringify(value)}`);
    }
    return Number.parseInt(`${value.slice(2, 4)}${value.slice(0, 2)}`, 16);
}

function selector(value, label) {
    const number = Number(value);
    if (!Number.isInteger(number) || number < 0 || number > 15) {
        throw new Error(`Invalid ${label} selector ${JSON.stringify(value)}`);
    }
    return number;
}

function reportPathFromArgs() {
    const argument = process.argv.slice(2).find(value => value.startsWith("--report="));
    return argument ? path.resolve(argument.slice("--report=".length)) : DEFAULT_REPORT_PATH;
}

async function main() {
    const reportPath = reportPathFromArgs();
    const report = JSON.parse(await fs.promises.readFile(reportPath, "utf8"));
    if (report?.schema_version !== 1 || !Array.isArray(report?.recoveries)) {
        throw new Error(`Unsupported Tomodachi palette recovery report: ${reportPath}`);
    }

    const recoveries = new Map();
    for (const recovery of report.recoveries) {
        const id = String(recovery?.infini_mii_id || "");
        if (!/^[A-Za-z0-9_-]+$/.test(id) || recoveries.has(id)) {
            throw new Error(`Invalid or duplicate recovery id ${JSON.stringify(id)}`);
        }
        recoveries.set(id, recovery);
    }
    if (recoveries.size !== Number(report?.audit_summary?.matching_tl_qr_payloads)) {
        throw new Error("Tomodachi palette recovery summary does not match its records");
    }

    await connectionPromise;
    const documents = await Miis.find({
        tl: { $type: "object" },
        $expr: { $gt: [{ $size: { $objectToArray: "$tl" } }, 0] }
    }).lean();
    const documentsById = new Map(documents.map(document => [String(document.id), document]));
    for (const id of recoveries.keys()) {
        if (!documentsById.has(id)) throw new Error(`Recovery target ${id} is missing from Mongo`);
    }

    const operations = [];
    let recoveredCount = 0;
    let defaultedCount = 0;
    let alreadyCompleteCount = 0;

    for (const document of documents) {
        const id = String(document.id);
        const clothing = document?.tl?.clothing;
        if (!clothing || typeof clothing !== "object" || Array.isArray(clothing)) {
            throw new Error(`${id}: TL record has no clothing object`);
        }

        const recovery = recoveries.get(id);
        const targetOutfitColor = recovery
            ? selector(recovery.body_color_slot, `${id} outfit`)
            : 0;
        const targetHatColor = recovery
            ? selector(recovery.headwear_color_slot, `${id} hat`)
            : 0;
        const hasOutfitColor = Object.hasOwn(clothing, "outfitColor");
        const hasHatColor = Object.hasOwn(clothing, "hatColor");

        if (hasOutfitColor && selector(clothing.outfitColor, `${id} existing outfit`) !== targetOutfitColor) {
            throw new Error(`${id}: existing outfit selector conflicts with the audited value`);
        }
        if (hasHatColor && selector(clothing.hatColor, `${id} existing hat`) !== targetHatColor) {
            throw new Error(`${id}: existing hat selector conflicts with the audited value`);
        }

        if (recovery) {
            if (littleEndianHexWord(clothing.outfit) !== Number(recovery.body_item_index)) {
                throw new Error(`${id}: outfit changed since the palette audit`);
            }
            const auditedHeadwearIndex = recovery.headwear_item_index === null
                || recovery.headwear_item_index === undefined
                ? 0xffff
                : Number(recovery.headwear_item_index);
            if (littleEndianHexWord(clothing.hat) !== auditedHeadwearIndex) {
                throw new Error(`${id}: headwear changed since the palette audit`);
            }
            if (!hasOutfitColor && !hasHatColor) {
                const currentHash = sha256Json(sourceRenderObject(document));
                if (currentHash !== String(recovery.source_render_object_sha256)) {
                    throw new Error(`${id}: stored render fields changed since the palette audit`);
                }
            }
            recoveredCount += 1;
        } else {
            defaultedCount += 1;
        }

        if (hasOutfitColor && hasHatColor) {
            alreadyCompleteCount += 1;
            continue;
        }

        operations.push({
            updateOne: {
                filter: {
                    id,
                    $and: [
                        {
                            $or: [
                                { "tl.clothing.outfitColor": { $exists: false } },
                                { "tl.clothing.outfitColor": targetOutfitColor }
                            ]
                        },
                        {
                            $or: [
                                { "tl.clothing.hatColor": { $exists: false } },
                                { "tl.clothing.hatColor": targetHatColor }
                            ]
                        }
                    ]
                },
                update: {
                    $set: {
                        "tl.clothing.outfitColor": targetOutfitColor,
                        "tl.clothing.hatColor": targetHatColor
                    }
                }
            }
        });
    }

    if (operations.length > 0) {
        const result = await Miis.bulkWrite(operations, { ordered: true });
        if (result.matchedCount !== operations.length) {
            throw new Error(
                `Palette migration matched ${result.matchedCount}/${operations.length} records; a concurrent conflicting write occurred`
            );
        }
    }

    console.log(JSON.stringify({
        tlRecords: documents.length,
        auditedRecoveries: recoveredCount,
        documentedZeroFallbacks: defaultedCount,
        alreadyComplete: alreadyCompleteCount,
        updated: operations.length
    }));
}

main()
    .finally(() => cleanupMongoResources())
    .catch(error => {
        console.error(error?.stack || error);
        process.exitCode = 1;
    });
