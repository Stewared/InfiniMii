const MII_CHARACTERS_ORIGIN = "https://www.miicharacters.com";
const MII_CHARACTERS_TITLE = "MiiCharacters";
const DEFAULT_DESCRIPTION = "Imported from MiiCharacters.com.";
const DEFAULT_START = 1;
const DEFAULT_MAX = 3;
const DEFAULT_DELAY_MS = 3000;

function decodeHtmlEntities(value) {
    const namedEntities = {
        amp: "&",
        apos: "'",
        gt: ">",
        lt: "<",
        nbsp: " ",
        quot: '"'
    };

    return String(value || "").replace(
        /&(#(?:x[0-9a-f]+|\d+)|[a-z]+);/gi,
        (entity, body) => {
            if (body[0] === "#") {
                const hexadecimal = body[1]?.toLowerCase() === "x";
                const parsed = Number.parseInt(body.slice(hexadecimal ? 2 : 1), hexadecimal ? 16 : 10);
                return Number.isInteger(parsed) && parsed >= 0 && parsed <= 0x10ffff
                    ? String.fromCodePoint(parsed)
                    : entity;
            }
            return namedEntities[body.toLowerCase()] ?? entity;
        }
    );
}

function htmlToText(value) {
    return decodeHtmlEntities(
        String(value || "")
            .replace(/<br\s*\/?\s*>/gi, " ")
            .replace(/<[^>]*>/g, " ")
    )
        .replace(/\s+/g, " ")
        .trim();
}

function parsePositiveInteger(value, label, fallback) {
    if (value === undefined || value === null || value === "") return fallback;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`${label} must be a positive integer.`);
    }
    return parsed;
}

function parseNonNegativeInteger(value, label, fallback) {
    if (value === undefined || value === null || value === "") return fallback;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
        throw new Error(`${label} must be a non-negative integer.`);
    }
    return parsed;
}

function parseOptionValue(args, index, name) {
    const argument = args[index];
    const prefix = `${name}=`;
    if (argument.startsWith(prefix)) {
        return { value: argument.slice(prefix.length), consumed: 0 };
    }
    if (argument === name && index + 1 < args.length) {
        return { value: args[index + 1], consumed: 1 };
    }
    return null;
}

function parseArguments(args = process.argv.slice(2), env = process.env) {
    const options = {
        start: parsePositiveInteger(env.MIICHARACTERS_IMPORT_START, "MIICHARACTERS_IMPORT_START", DEFAULT_START),
        max: parsePositiveInteger(env.MIICHARACTERS_IMPORT_MAX, "MIICHARACTERS_IMPORT_MAX", DEFAULT_MAX),
        delayMs: parseNonNegativeInteger(env.MIICHARACTERS_IMPORT_DELAY_MS, "MIICHARACTERS_IMPORT_DELAY_MS", DEFAULT_DELAY_MS),
        uploader: String(env.MIICHARACTERS_IMPORT_UPLOADER || "").trim(),
        write: false,
        help: false
    };

    for (let index = 0; index < args.length; index += 1) {
        const argument = args[index];
        if (argument === "--help" || argument === "-h") {
            options.help = true;
            continue;
        }
        if (argument === "--write") {
            options.write = true;
            continue;
        }
        if (argument === "--dry-run") {
            options.write = false;
            continue;
        }

        const start = parseOptionValue(args, index, "--start");
        if (start) {
            options.start = parsePositiveInteger(start.value, "--start", DEFAULT_START);
            index += start.consumed;
            continue;
        }
        const max = parseOptionValue(args, index, "--max");
        if (max) {
            options.max = parsePositiveInteger(max.value, "--max", DEFAULT_MAX);
            index += max.consumed;
            continue;
        }
        const delay = parseOptionValue(args, index, "--delay-ms");
        if (delay) {
            options.delayMs = parseNonNegativeInteger(delay.value, "--delay-ms", DEFAULT_DELAY_MS);
            index += delay.consumed;
            continue;
        }
        const uploader = parseOptionValue(args, index, "--uploader");
        if (uploader) {
            options.uploader = String(uploader.value || "").trim();
            index += uploader.consumed;
            continue;
        }

        throw new Error(`Unknown argument: ${argument}`);
    }

    if (options.max < options.start) {
        throw new Error("--max must be greater than or equal to --start.");
    }
    if (options.write && !options.uploader) {
        throw new Error("--write requires --uploader=<existing InfiniMii username> or MIICHARACTERS_IMPORT_UPLOADER.");
    }
    return options;
}

function pageUrlFor(index) {
    return `${MII_CHARACTERS_ORIGIN}/index.php?mii=${index}`;
}

function resolveMiiCharactersUrl(value) {
    const decoded = decodeHtmlEntities(value).trim();
    if (!decoded) return "";
    const resolved = new URL(decoded, `${MII_CHARACTERS_ORIGIN}/`);
    if (resolved.protocol !== "https:" && resolved.protocol !== "http:") return "";
    if (resolved.hostname.toLowerCase() !== "www.miicharacters.com" && resolved.hostname.toLowerCase() !== "miicharacters.com") {
        return "";
    }
    resolved.protocol = "https:";
    resolved.hostname = "www.miicharacters.com";
    return resolved.href;
}

function parseMiiCharactersPage(html, index) {
    const source = String(html || "");
    const escapedIndex = String(index).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const qrCandidates = [];
    const qrPattern = new RegExp(
        `["']([^"']*miis\\/qr_(large|thumb)\\/${escapedIndex}_[^"'<>?]+?\\.jpe?g(?:\\?[^"']*)?)["']`,
        "gi"
    );
    let qrMatch;
    while ((qrMatch = qrPattern.exec(source)) !== null) {
        const url = resolveMiiCharactersUrl(qrMatch[1]);
        if (url) qrCandidates.push({ url, size: qrMatch[2].toLowerCase() });
    }
    const qr = qrCandidates.find(candidate => candidate.size === "large") || qrCandidates[0] || null;
    if (!qr) return null;

    const creatorBlock = /<p\b[^>]*class=["'][^"']*\bcreator\b[^"']*["'][^>]*>([\s\S]*?)<\/p>/i.exec(source)?.[1] || "";
    const creatorAnchor = /<a\b[^>]*href=["']([^"']*[?&]u=(\d+)[^"']*)["'][^>]*>([\s\S]*?)<\/a>/i.exec(creatorBlock);
    const extUser = creatorAnchor ? htmlToText(creatorAnchor[3]) : "";
    const extUserURL = creatorAnchor && extUser
        ? `${MII_CHARACTERS_ORIGIN}/index.php?u=${creatorAnchor[2]}`
        : "";
    const descriptionBlock = /<p\b[^>]*class=["'][^"']*\bdescription\b[^"']*["'][^>]*>([\s\S]*?)<\/p>/i.exec(source)?.[1] || "";

    return {
        qrURL: qr.url,
        description: htmlToText(descriptionBlock) || DEFAULT_DESCRIPTION,
        externalSource: {
            extURL: pageUrlFor(index),
            extTitle: MII_CHARACTERS_TITLE,
            extUser: extUser && extUserURL ? extUser : "",
            extUserURL: extUser && extUserURL ? extUserURL : ""
        }
    };
}

function getUniqueHashMatch(hashIndex, hash) {
    const matches = hashIndex.get(hash) || [];
    if (matches.length <= 1) return matches[0] || null;
    const ids = matches
        .map(mii => String(mii?.id || mii?._id || "unknown"))
        .sort((left, right) => left.localeCompare(right));
    throw new Error(`Identity hash matched multiple stored Miis (${ids.join(", ")}); refusing an ambiguous update.`);
}

function delay(milliseconds) {
    return milliseconds > 0
        ? new Promise(resolve => setTimeout(resolve, milliseconds))
        : Promise.resolve();
}

async function fetchChecked(url) {
    const response = await fetch(url, {
        headers: {
            "User-Agent": "InfiniMii MiiCharacters importer/1.0"
        },
        redirect: "follow"
    });
    if (!response.ok) {
        throw new Error(`Request failed with HTTP ${response.status}: ${url}`);
    }
    return response;
}

async function readResponseText(response) {
    const contentType = String(response.headers?.get?.("content-type") || "");
    const declaredCharset = /charset\s*=\s*["']?([^;\s"']+)/i.exec(contentType)?.[1]?.toLowerCase() || "";
    const encoding = ["iso-8859-1", "latin1", "latin-1", "windows-1252"].includes(declaredCharset)
        ? "windows-1252"
        : "utf-8";
    return new TextDecoder(encoding).decode(await response.arrayBuffer());
}

async function loadSiteOperations({ write }) {
    process.env.INFINIMII_NO_SERVER_START = "true";
    if (!write) process.env.MONGODB_AUTO_INDEX = "false";

    // Environment configuration must load before database.js reads its URI.
    await import("./setEnvs.js");
    const [site, database, identity] = await Promise.all([
        import("./index.js"),
        import("./database.js"),
        import("./miiIdentityHash.js")
    ]);
    await database.connectionPromise;
    return { ...site, ...database, ...identity };
}

async function buildIdentityIndex(Miis, getMiiIdentityHash) {
    const storedMiis = await Miis.find({ id: { $exists: true } }).lean();
    const byHash = new Map();
    for (const mii of storedMiis) {
        const hash = getMiiIdentityHash(mii);
        if (!hash) continue;
        const matches = byHash.get(hash) || [];
        matches.push(mii);
        byHash.set(hash, matches);
    }
    return { byHash, storedCount: storedMiis.length };
}

async function validateUploader(options, operations) {
    if (!options.write) return null;
    const uploader = await operations.Users.findOne({ username: options.uploader }).lean();
    if (!uploader) {
        throw new Error(`InfiniMii uploader account ${JSON.stringify(options.uploader)} does not exist.`);
    }
    if (!operations.isAccountVerifiedForUploads(uploader)) {
        throw new Error(`InfiniMii uploader account ${JSON.stringify(options.uploader)} is not verified for uploads.`);
    }
    if (await operations.isBanned(uploader)) {
        throw new Error(`InfiniMii uploader account ${JSON.stringify(options.uploader)} is banned.`);
    }
    return uploader;
}

async function processMiiCharactersIndex(index, options, operations, hashIndex, fetcher = fetchChecked) {
    const pageURL = pageUrlFor(index);
    const pageResponse = await fetcher(pageURL);
    const parsed = parseMiiCharactersPage(await readResponseText(pageResponse), index);
    if (!parsed) {
        return { index, pageURL, status: "skipped", reason: "No QR image on page" };
    }

    const qrResponse = await fetcher(parsed.qrURL);
    const decoded = await operations.createMiiData(Buffer.from(await qrResponse.arrayBuffer()));
    const hash = operations.getMiiIdentityHash(decoded);
    if (!hash) throw new Error("Decoded Mii did not produce an identity hash.");
    const matchingMii = getUniqueHashMatch(hashIndex, hash);

    if (matchingMii) {
        if (options.write) {
            const replacementFields = {
                ...matchingMii,
                meta: structuredClone(decoded.meta || {}),
                general: structuredClone(decoded.general || {})
            };
            const updated = await operations.saveDashboardMiiFields(matchingMii, replacementFields, {
                description: parsed.description
            });
            const matches = hashIndex.get(hash) || [];
            hashIndex.set(hash, matches.map(mii => mii._id?.toString() === matchingMii._id?.toString() ? updated : mii));
        }
        return {
            index,
            pageURL,
            status: options.write ? "updated" : "would-update",
            id: matchingMii.id,
            name: decoded.meta?.name || "",
            hash
        };
    }

    if (!options.write) {
        return {
            index,
            pageURL,
            status: "would-upload",
            name: decoded.meta?.name || "",
            hash,
            externalSource: parsed.externalSource
        };
    }

    const persisted = await operations.persistUploadedMii(decoded, {
        uploader: options.uploader,
        wantsPublic: true,
        desc: parsed.description,
        externalSource: parsed.externalSource
    });
    const persistedMii = { ...persisted.mii, private: false };
    hashIndex.set(hash, [persistedMii]);
    return {
        index,
        pageURL,
        status: "uploaded",
        id: persisted.mii.id,
        name: persisted.mii.meta?.name || "",
        hash,
        externalSource: parsed.externalSource
    };
}

function printHelp() {
    console.log(`Usage: node fillin.cjs [options]

Imports Mii QR codes from MiiCharacters.com. The default mode is read-only.

Options:
  --start <n>       First MiiCharacters numeric ID (default: ${DEFAULT_START})
  --max <n>         Last MiiCharacters numeric ID, inclusive (default: ${DEFAULT_MAX})
  --delay-ms <n>    Delay between requests/items (default: ${DEFAULT_DELAY_MS})
  --dry-run         Decode and compare without writes (default)
  --write           Persist updates/uploads
  --uploader <name> Existing, upload-eligible InfiniMii account; required with --write
  --help            Show this help

Environment equivalents: MIICHARACTERS_IMPORT_START, MIICHARACTERS_IMPORT_MAX,
MIICHARACTERS_IMPORT_DELAY_MS, and MIICHARACTERS_IMPORT_UPLOADER.`);
}

async function main(args = process.argv.slice(2)) {
    const options = parseArguments(args);
    if (options.help) {
        printHelp();
        return;
    }

    const operations = await loadSiteOperations(options);
    const summary = {
        dryRun: !options.write,
        start: options.start,
        max: options.max,
        storedMiisCompared: 0,
        updated: 0,
        uploaded: 0,
        wouldUpdate: 0,
        wouldUpload: 0,
        skipped: 0,
        failed: 0
    };

    try {
        await validateUploader(options, operations);
        const identityIndex = await buildIdentityIndex(operations.Miis, operations.getMiiIdentityHash);
        summary.storedMiisCompared = identityIndex.storedCount;
        console.log(JSON.stringify({ mode: options.write ? "write" : "dry-run", ...summary }));

        for (let index = options.start; index <= options.max; index += 1) {
            try {
                const result = await processMiiCharactersIndex(index, options, operations, identityIndex.byHash);
                const summaryKey = {
                    updated: "updated",
                    uploaded: "uploaded",
                    "would-update": "wouldUpdate",
                    "would-upload": "wouldUpload",
                    skipped: "skipped"
                }[result.status];
                if (summaryKey) summary[summaryKey] += 1;
                console.log(JSON.stringify(result));
            } catch (error) {
                summary.failed += 1;
                console.error(JSON.stringify({
                    index,
                    pageURL: pageUrlFor(index),
                    status: "failed",
                    error: error?.message || String(error)
                }));
            }
            if (index < options.max) await delay(options.delayMs);
        }
        console.log(JSON.stringify({ summary }));
        if (summary.failed > 0) process.exitCode = 1;
    } finally {
        await operations.cleanupMongoResources();
    }
}

module.exports = {
    getUniqueHashMatch,
    htmlToText,
    main,
    pageUrlFor,
    parseArguments,
    parseMiiCharactersPage,
    processMiiCharactersIndex,
    resolveMiiCharactersUrl
};

if (require.main === module) {
    main().catch(error => {
        console.error(error?.stack || error);
        process.exitCode = 1;
    });
}
