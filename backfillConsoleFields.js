import "./setEnvs.js";
import miijs from "miijs";
import { cleanupMongoResources, connectionPromise, Miis } from "./database.js";
import { getMiiIdentityHash } from "./miiIdentityHash.js";

const MII_DATA_TOP_LEVEL_KEYS = Object.freeze([
    "console",
    "meta",
    "perms",
    "general",
    "face",
    "hair",
    "eyes",
    "eyebrows",
    "nose",
    "mouth",
    "beard",
    "glasses",
    "mole",
    "tl",
    "mt"
]);

const OFFICIAL_TAG_CONSOLE_PRIORITY = Object.freeze([
    { console: "DS", keys: ["ds", "nintendods"] },
    { console: "Wii", keys: ["wii", "nintendowii"] },
    { console: "3DS", keys: ["3ds", "nintendo3ds"] },
    { console: "Wii U", keys: ["wiiu", "nintendowiiu"] },
    { console: "Switch", keys: ["switch", "nintendoswitch"] }
]);

function getArgValue(name) {
    const prefix = `${name}=`;
    const match = process.argv.find(arg => arg.startsWith(prefix));
    return match ? match.slice(prefix.length) : "";
}

function normalizeTagKey(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "");
}

function getOfficialConsoleFromTags(mii) {
    if (!mii?.official) return "";

    const topLevelCategoryTags = (Array.isArray(mii.officialCategories) ? mii.officialCategories : [])
        .map(path => String(path || "").split(/[>/]/)[0]);
    const tagKeys = new Set([
        ...(Array.isArray(mii.tags) ? mii.tags : []),
        ...topLevelCategoryTags
    ].map(normalizeTagKey).filter(Boolean));
    if (tagKeys.size === 0) return "";

    for (const candidate of OFFICIAL_TAG_CONSOLE_PRIORITY) {
        if (candidate.keys.some(key => tagKeys.has(key))) {
            return candidate.console;
        }
    }

    return "";
}

function toMiiDataOnly(mii) {
    if (!mii || typeof mii !== "object") return mii;

    const out = {};
    for (const key of MII_DATA_TOP_LEVEL_KEYS) {
        if (!Object.prototype.hasOwnProperty.call(mii, key)) continue;
        out[key] = mii[key];
    }

    return out;
}

function hasMeaningfulIdentifier(value) {
    const normalized = String(value || "")
        .trim()
        .replace(/[^a-fA-F0-9]/g, "");
    return Boolean(normalized && !/^0+$/.test(normalized));
}

function hasSwitchIdentifier(mii) {
    return hasMeaningfulIdentifier(mii?.meta?.miiId) || hasMeaningfulIdentifier(mii?.meta?.systemId);
}

function hasTomodachiLifeData(mii) {
    const tlData = mii?.tl;
    if (tlData === null || tlData === undefined) return false;
    if (typeof tlData !== "object") return true;
    return Object.keys(tlData).length > 0;
}

function getOriginalDevice(mii) {
    const value = Number.parseInt(mii?.meta?.originalDevice, 10);
    return Number.isInteger(value) ? value : null;
}

function refine3dsConsole(mii) {
    if (getOriginalDevice(mii) === 4) {
        return {
            console: "Wii U",
            reason: "CFCD round-trip hash match with Wii U original device"
        };
    }

    if (hasTomodachiLifeData(mii)) {
        return {
            console: "TL 3DS",
            reason: "CFCD round-trip hash match with Tomodachi Life data"
        };
    }

    return {
        console: "3DS",
        reason: "CFCD round-trip hash match"
    };
}

async function roundTripIdentityMatches(miiData, format, originalHash) {
    if (!originalHash) return false;

    try {
        const sourceMii = await miijs.Mii.create(miiData);
        const encoded = await sourceMii.encode(format);
        const decodedMii = await miijs.Mii.create(encoded);
        const decodedHash = getMiiIdentityHash(decodedMii.fields);
        return Boolean(decodedHash && decodedHash === originalHash);
    } catch (error) {
        return false;
    }
}

async function inferConsole(mii) {
    const officialConsole = getOfficialConsoleFromTags(mii);
    if (officialConsole) {
        return {
            console: officialConsole,
            reason: "official tag"
        };
    }

    const miiData = toMiiDataOnly(mii);
    const originalHash = getMiiIdentityHash(miiData);

    if (await roundTripIdentityMatches(miiData, "rcd", originalHash)) {
        return {
            console: "Wii",
            reason: "RCD round-trip hash match"
        };
    }

    if (await roundTripIdentityMatches(miiData, "cfcd", originalHash)) {
        return refine3dsConsole(miiData);
    }

    if (hasSwitchIdentifier(miiData)) {
        return {
            console: "Switch",
            reason: "Mii ID or System ID present"
        };
    }

    return {
        console: "Mii Studio",
        reason: "fallback"
    };
}

function getExistingConsole(mii) {
    return String(mii?.console || mii?.meta?.console || "").trim();
}

async function main() {
    const dryRun = process.argv.includes("--dry-run");
    const limit = Number.parseInt(getArgValue("--limit"), 10);
    const counters = {
        checked: 0,
        changed: 0,
        unchanged: 0,
        failed: 0
    };

    await connectionPromise;

    console.log(`[console-backfill] Starting${dryRun ? " dry run" : ""}.`);

    const query = {};
    const cursor = Miis.find(query).cursor();

    for await (const mii of cursor) {
        if (Number.isInteger(limit) && limit > 0 && counters.checked >= limit) {
            break;
        }

        counters.checked += 1;

        try {
            const { console: consoleValue, reason } = await inferConsole(mii);
            const existingConsole = getExistingConsole(mii);

            if (existingConsole === consoleValue && mii?.meta?.console === consoleValue) {
                counters.unchanged += 1;
                continue;
            }

            counters.changed += 1;
            const id = mii.id || String(mii._id);
            console.log(`[console-backfill] ${id}: ${existingConsole || "(blank)"} -> ${consoleValue} (${reason})`);

            if (!dryRun) {
                await Miis.updateOne(
                    { _id: mii._id },
                    {
                        $set: {
                            console: consoleValue,
                            "meta.console": consoleValue
                        }
                    }
                );
            }
        } catch (error) {
            counters.failed += 1;
            console.warn(`[console-backfill] Failed ${mii?.id || mii?._id}: ${error.message}`);
        }
    }

    console.log(`[console-backfill] Done. Checked ${counters.checked}, changed ${counters.changed}, unchanged ${counters.unchanged}, failed ${counters.failed}.`);
    if (dryRun) {
        console.log("[console-backfill] Dry run only; no records were updated.");
    }
}

main()
    .catch((error) => {
        console.error("[console-backfill] Fatal error:", error);
        process.exitCode = 1;
    })
    .finally(async () => {
        await cleanupMongoResources();
    });
