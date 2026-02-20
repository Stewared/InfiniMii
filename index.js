import "./setEnvs.js";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import helmet from 'helmet';
import miijs from "miijs";
import crypto from 'crypto';
import fs from "fs";
import ejs from 'ejs';
import express from "express";
import path from "path";
import nodemailer from "nodemailer";
import cookieParser from 'cookie-parser';
import compression from 'compression';
import multer from 'multer';
import FormData from 'form-data';
import https from 'https';
import { RegExpMatcher, englishDataset, englishRecommendedTransformers } from 'obscenity';
import { doubleMetaphone } from 'double-metaphone';
import validator from 'validator';
import jwt from 'jsonwebtoken';
import { STATUS_CODES } from 'http';
import { isDeepStrictEqual } from 'node:util';
import { rateLimit } from 'express-rate-limit';
import ms from 'ms';
import dns from "dns";
import { connectionPromise, Miis, Users, Settings, ReservedUsername } from "./database.js";
import { renderIcon, icons } from "./icons.js";

dns.setServers(['1.1.1.1', '8.8.8.8']);

const defaultMiisPerPage = 16;
const profileMiisPerPage = 18;
const HOME_PREVIEW_COUNT = 6;
const PRIVATE_MII_LIMIT = process.env.privateMiiLimit;
const baseUrl = process.env.baseUrl;

const EXPORT_FORMAT_LABELS = {
    qr: "QR Code (PNG)",
    rcd: "Wii RSD (.rcd)",
    rsd: "Wii RCD (.rsd)",
    ncd: "DS NCD (.ncd)",
    nsd: "DS NSD (.nsd)",
    cfcd: "3DS CFCD (.cfcd)",
    cfsd: "3DS CFSD (.cfsd)",
    cfed: "3DS CFED (QR Encrypted, .cfed)",
    ffcd: "Wii U FFCD (.ffcd)",
    ffsd: "Wii U FFSD (.ffsd)",
    ffed: "Wii U FFED (QR Encrypted, .ffed)",
    mt: "Miitomo MT (.mt)",
    mte: "Miitomo MTE (.mte)",
    tlc: "Tomodachi Life TLC (.tlc)",
    tls: "Tomodachi Life TLS (.tls)",
    tle: "Tomodachi Life TLE (.tle)",
    nfcd: "Switch NFCD (.nfcd)",
    nfsd: "Switch NFSD (.nfsd)",
    charinfo: "Switch CHARINFO (.charinfo)",
    mnms: "My Nintendo Mii Studio (.mnms)"
};

const EXPORT_FORMAT_ORDER = [
    "qr",
    "rcd",
    "rsd",
    "ncd",
    "nsd",
    "cfcd",
    "cfsd",
    "cfed",
    "ffcd",
    "ffsd",
    "ffed",
    "tlc",
    "tls",
    "tle",
    "mt",
    "mte",
    "nfcd",
    "nfsd",
    "charinfo",
    "mnms"
];

function buildExportFormats() {
    const availableFormats = new Set(
        Object.keys(miijs.formats || {})
            .map(fmt => fmt.toLowerCase())
            .filter(fmt => !fmt.startsWith("ntag"))
    );
    const formats = [];

    for (const code of EXPORT_FORMAT_ORDER) {
        if (code === "qr" || availableFormats.has(code)) {
            formats.push({
                value: code,
                label: EXPORT_FORMAT_LABELS[code] || `${code.toUpperCase()} (.${code})`
            });
        }
    }

    for (const code of availableFormats) {
        if (!formats.some(fmt => fmt.value === code)) {
            formats.push({
                value: code,
                label: EXPORT_FORMAT_LABELS[code] || `${code.toUpperCase()} (.${code})`
            });
        }
    }

    return formats;
}

const EXPORT_FORMATS = buildExportFormats();
const EXPORT_FORMAT_SET = new Set(EXPORT_FORMATS.map(fmt => fmt.value));
const SEARCH_FIELD_VALUES = ["uploader", "name", "description"];
const SEARCH_FIELD_SET = new Set(SEARCH_FIELD_VALUES);
const MII_CHILD_STAGE_LABELS = [
    "Newborn",
    "Infant",
    "Child",
    "Teen",
    "Young Adult",
    "Adult"
];
const INSTRUCTION_CONSOLE_VALUES = new Set(["DS", "WII", "3DS", "WIIU", "SWITCH", "SWITCH2"]);
const MAX_MII_TAG_LENGTH = 40;
const MAX_COMPANY_SOURCE_NAME_LENGTH = 15;
const DEFAULT_OFFICIAL_COMPANY_SOURCE = "Nintendo";

function normalizeExportFormat(input) {
    if (!input) return null;
    let cleaned = String(input).trim().toLowerCase();
    if (!cleaned) return null;
    if (cleaned.startsWith(".")) cleaned = cleaned.slice(1);

    if (["qr", "qrcode", "png", "jpg", "jpeg", "3dsqr"].includes(cleaned)) {
        return "qr";
    }
    if (["wii", "wiibin", "mii"].includes(cleaned)) {
        return "rsd";
    }
    if (["3dsbin", "3dsbin_decrypted"].includes(cleaned)) {
        return "cfsd";
    }
    if (["3dsbin_encrypted"].includes(cleaned)) {
        return "cfed";
    }

    if (EXPORT_FORMAT_SET.has(cleaned)) return cleaned;

    const keyMatch = Object.keys(miijs.MiiFormats || {}).find(key => key.toLowerCase() === cleaned);
    if (keyMatch) {
        const value = miijs.MiiFormats[keyMatch];
        if (typeof value === "string" && EXPORT_FORMAT_SET.has(value)) {
            return value;
        }
    }

    return null;
}

function parseBooleanLike(value) {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value === 1;
    if (typeof value !== "string") return false;

    const cleaned = value.trim().toLowerCase();
    return cleaned === "true" || cleaned === "1" || cleaned === "yes" || cleaned === "on";
}

function normalizeQrConsole(input) {
    const cleaned = String(input || "").trim().toUpperCase().replace(/[\s_-]+/g, "");
    if (cleaned === "WIIU") return "WIIU";
    return "3DS";
}

function normalizeInstructionConsole(input) {
    const cleaned = String(input || "").trim().toUpperCase().replace(/[\s_-]+/g, "");
    if (INSTRUCTION_CONSOLE_VALUES.has(cleaned)) return cleaned;

    if (cleaned === "THREEDS" || cleaned === "NINTENDO3DS") return "3DS";
    if (cleaned === "NDS" || cleaned === "NINTENDODS") return "DS";
    if (cleaned === "NINTENDOWIIU") return "WIIU";
    if (cleaned === "NINTENDOSWITCH") return "SWITCH";
    if (cleaned === "NINTENDOSWITCH2") return "SWITCH2";

    return "3DS";
}

function isLegacyNintendoBrowserUserAgent(userAgent) {
    const ua = String(userAgent || "");
    if (!ua) return false;

    const lowerUa = ua.toLowerCase();
    if (lowerUa.includes("nintendo 3ds")) return true;
    if (lowerUa.includes("new nintendo 3ds")) return true;
    if (lowerUa.includes("nintendo wiiu")) return true;
    if (lowerUa.includes("nintendo wii u")) return true;
    if (lowerUa.includes("mobile nintendobrowser/")) return true;

    // New 3DS "Request Mobile Websites" mode can mimic iPhone UA closely.
    const looksLikeNew3dsMobileMode =
        lowerUa.includes("iphone") &&
        lowerUa.includes("applewebkit/536.26") &&
        lowerUa.includes("version/6.0") &&
        lowerUa.includes("mobile/10a403") &&
        lowerUa.includes("safari/8536.25");

    return looksLikeNew3dsMobileMode;
}

function isLegacyNintendoBrowserRequest(req) {
    return isLegacyNintendoBrowserUserAgent(req.get("user-agent"));
}

function buildMiiStringFallbackCandidates(input) {
    if (typeof input !== "string") return [];

    const trimmed = input.trim();
    if (!trimmed) return [];

    const candidates = [];
    const compact = trimmed.replace(/\s+/g, "");

    if (compact && compact !== trimmed) {
        candidates.push(compact);
    }

    let hexCandidate = compact;
    if (/^0x/i.test(hexCandidate)) {
        hexCandidate = hexCandidate.slice(2);
    }

    if (/^[0-9a-fA-F]+$/.test(hexCandidate) && hexCandidate.length % 2 === 0) {
        try {
            candidates.push(Buffer.from(hexCandidate, "hex"));
        } catch (e) { }
    }

    if (/^[A-Za-z0-9+/]+={0,2}$/.test(compact) && compact.length >= 8) {
        try {
            const decoded = Buffer.from(compact, "base64");
            if (decoded.length > 0) {
                candidates.push(decoded);
            }
        } catch (e) { }
    }

    return candidates;
}

function getExportOptionsFromRequest(req) {
    const source = req.method === "GET" ? req.query : req.body;
    return {
        special: parseBooleanLike(source?.special),
        qrConsole: normalizeQrConsole(source?.qrConsole)
    };
}

function safeMiiFilename(name, fallback = "mii") {
    const base = (name || "")
        .toString()
        .replace(/[^a-z0-9-_]+/gi, "_")
        .replace(/^_+|_+$/g, "")
        .slice(0, 80);
    return base || fallback;
}

function isQrImageInput(input) {
    if (typeof input === "string") {
        const normalized = input.trim().toLowerCase();
        if (normalized.startsWith("data:image/png") || normalized.startsWith("data:image/jpeg") || normalized.startsWith("data:image/jpg")) {
            return true;
        }

        const pathWithoutQuery = normalized.split("?")[0];
        return pathWithoutQuery.endsWith(".png") || pathWithoutQuery.endsWith(".jpg") || pathWithoutQuery.endsWith(".jpeg");
    }

    if (Buffer.isBuffer(input) || input instanceof Uint8Array || input instanceof ArrayBuffer) {
        try {
            const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
            const formats = miijs.detectMiiFormat(bytes);
            return formats.includes("png") || formats.includes("jpg");
        } catch {
            return false;
        }
    }

    return false;
}

async function decodeQrImageInput(input) {
    let scanInput = input;

    if (typeof input === "string") {
        if (/^https?:\/\//i.test(input)) {
            const response = await fetch(input);
            if (!response.ok) {
                throw new Error(`Failed to fetch QR image: ${response.status}`);
            }
            scanInput = Buffer.from(await response.arrayBuffer());
        } else if (/^data:image\//i.test(input)) {
            const commaIndex = input.indexOf(",");
            if (commaIndex === -1) {
                throw new Error("Invalid data URI image input");
            }
            const base64 = input.slice(commaIndex + 1).replace(/\s+/g, "");
            scanInput = Buffer.from(base64, "base64");
        } else {
            scanInput = await fs.promises.readFile(input);
        }
    } else if (input instanceof ArrayBuffer) {
        scanInput = Buffer.from(input);
    }

    const decoded = await miijs.scanQR(scanInput);
    if (!decoded) {
        throw new Error("Detected image input, but QR decoding failed");
    }
    return decoded;
}

async function createMiiData(input, debug) {
    const parsedInput = isQrImageInput(input) ? await decodeQrImageInput(input) : input;
    try {
        const mii = await miijs.Mii.create(parsedInput, debug);
        return mii.fields;
    } catch (originalError) {
        const fallbacks = buildMiiStringFallbackCandidates(parsedInput);
        for (const fallbackInput of fallbacks) {
            try {
                const mii = await miijs.Mii.create(fallbackInput, debug);
                return mii.fields;
            } catch (e) { }
        }
        throw originalError;
    }
}

const MII_COMPARISON_IGNORED_TOP_LEVEL_FIELDS = new Set([
    "_id",
    "__v",
    "id",
    "uploader",
    "desc",
    "votes",
    "official",
    "officialsource",
    "uploadedon",
    "officialcategories",
    "published",
    "private",
    "blockedfrompublishing",
    "blockreason",
    "contributor",
    "console",
    "createdat",
    "updatedat"
]);

const MII_COMPARISON_IGNORED_ROOT_SUBTREES = new Set(["perms", "meta", "tl", "mt"]);
const MII_COMPARISON_IGNORED_GENERAL_FIELDS = new Set(["name", "creatorname", "height", "weight"]);

function getComparableMiiSource(mii) {
    if (!mii || typeof mii !== "object") return mii;
    if (mii.fields && typeof mii.fields === "object") return mii.fields;
    return mii;
}

function normalizeMiiForComparison(mii) {
    const source = getComparableMiiSource(mii);
    if (!source || typeof source !== "object") return source;

    const plain = typeof source.toObject === "function"
        ? source.toObject({ depopulate: true, virtuals: false, getters: false, minimize: false })
        : source;

    const visit = (value, parentKey = "") => {
        if (value === null || typeof value !== "object") return value;
        if (Array.isArray(value)) return value.map(item => visit(item, parentKey));

        const out = {};
        for (const [key, child] of Object.entries(value)) {
            const lowerKey = key.toLowerCase();
            const lowerParentKey = parentKey.toLowerCase();

            if (!parentKey) {
                if (MII_COMPARISON_IGNORED_TOP_LEVEL_FIELDS.has(lowerKey)) continue;
                if (MII_COMPARISON_IGNORED_ROOT_SUBTREES.has(lowerKey)) continue;
            }

            if (lowerParentKey === "general" && MII_COMPARISON_IGNORED_GENERAL_FIELDS.has(lowerKey)) {
                continue;
            }

            out[key] = visit(child, key);
        }
        return out;
    };

    return visit(plain);
}

function areMiisTheSame(miiA, miiB) {
    return isDeepStrictEqual(normalizeMiiForComparison(miiA), normalizeMiiForComparison(miiB));
}

async function findMatchingMii(candidateMii, { includePrivate = true, excludeId } = {}) {
    const query = includePrivate ? {} : { private: false };
    if (excludeId) query.id = { $ne: excludeId };

    const existingMiis = await Miis.find(query).lean();

    for (const existingMii of existingMiis) {
        if (areMiisTheSame(candidateMii, existingMii)) {
            return existingMii;
        }
    }

    return null;
}

function getDuplicateMiiErrorMessage(matchingMiiId) {
    return `This Mii already exists (Mii ID: ${matchingMiiId}). If you believe this is incorrect, you can dispute it by contacting Stewared at /contact.`;
}

function parseQuickUploadConfig(content) {
    const parsed = {};
    for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#") || line.startsWith(";")) continue;
        const separatorIndex = line.indexOf("=");
        if (separatorIndex === -1) continue;

        const key = line.slice(0, separatorIndex).trim().toLowerCase();
        const value = line.slice(separatorIndex + 1).trim();
        if (key) parsed[key] = value;
    }
    return parsed;
}

function getQuickUploadMetadata(dirPath = "./quickUploads") {
    const metadata = {
        uploader: "Bulk Uploader",
        official: false
    };

    const uploadIniPath = path.join(dirPath, "upload.ini");
    if (fs.existsSync(uploadIniPath)) {
        const parsed = parseQuickUploadConfig(fs.readFileSync(uploadIniPath, "utf-8"));
        if (parsed.uploader) metadata.uploader = parsed.uploader;
        if (parsed.official) {
            const officialValue = parsed.official.toLowerCase();
            metadata.official = officialValue === "true" || officialValue === "1" || officialValue === "yes";
        }
        return metadata;
    }

    const uploaderTxtPath = path.join(dirPath, "uploader.txt");
    if (fs.existsSync(uploaderTxtPath)) {
        const uploader = fs.readFileSync(uploaderTxtPath, "utf-8").trim();
        if (uploader) metadata.uploader = uploader.split(/\r?\n/)[0].trim() || metadata.uploader;
    }

    return metadata;
}

async function exportMiiToBuffer(miiInput, format, options = {}) {
    const sourceInstance = await miijs.Mii.create(miiInput);
    let miiInstance = sourceInstance;

    if (options.special) {
        const specialFields = structuredClone(sourceInstance.fields || {});
        if (!specialFields.meta || typeof specialFields.meta !== "object") {
            specialFields.meta = {};
        }
        specialFields.meta.type = "Special";
        miiInstance = await miijs.Mii.create(specialFields);
    }

    if (format === "qr") {
        const qrConsole = normalizeQrConsole(options.qrConsole || options.device);
        const qrBuffer = await miiInstance.toQR(qrConsole, options.qrOptions || {});
        return {
            buffer: qrBuffer,
            contentType: "image/png",
            extension: "png"
        };
    }

    const buffer = miiInstance.encode(format);
    return {
        buffer,
        contentType: "application/octet-stream",
        extension: format
    };
}

async function writeQrPng(miiInput, outputPath, qrConsole = "3DS") {
    const { buffer } = await exportMiiToBuffer(miiInput, "qr", { qrConsole });
    await fs.promises.writeFile(outputPath, buffer);
}

async function sendExportResponse(res, miiInput, format, nameHint, options = {}) {
    const normalized = normalizeExportFormat(format);
    if (!normalized) {
        res.json({ error: "Invalid format specified" });
        return false;
    }

    const { buffer, contentType, extension } = await exportMiiToBuffer(miiInput, normalized, options);
    const safeName = safeMiiFilename(nameHint, "mii");

    let filename;
    if (normalized === "qr") {
        filename = `${safeName}_QR.${extension}`;
    } else {
        filename = `${safeName}.${extension}`;
    }

    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", contentType);
    res.send(buffer);
    return true;
}

async function exportMiiById(req, res) {
    const miiId = req.query.id;
    if (!miiId) {
        res.json({ error: "Invalid Mii ID" });
        return;
    }

    let mii = await getMiiById(miiId, true);
    let miiInput = mii;

    if (mii?.private) {
        const isOwner = req.user && mii.uploader === req.user.username;
        const isModerator = req.user && canModerate(req.user);
        if (!isOwner && !isModerator) {
            res.json({ error: "Access denied. This is a private Mii." });
            return;
        }
    }

    if (!mii) {
        const tempPath = `./static/temp/${miiId}.bin`;
        if (fs.existsSync(tempPath)) {
            miiInput = tempPath;
        } else {
            res.json({ error: "Invalid Mii ID" });
            return;
        }
    }

    try {
        const miiInstance = await miijs.Mii.create(miiInput);
        const miiName = miiInstance?.fields?.meta?.name || mii?.meta?.name || "mii";
        await sendExportResponse(res, miiInstance.fields, req.query.format, miiName, getExportOptionsFromRequest(req));
    } catch (e) {
        console.error("Error exporting Mii:", e);
        res.json({ error: "Failed to export Mii: " + e.message });
    }
}

const swearList = englishDataset.containers.map(c => c.metadata.originalWord).filter(Boolean);
var globalSalt = process.env.salt;
const upload = multer({
    dest: './uploads/',
    filename: (req, file, cb) => {
        const ext = file.originalname.split('.').pop(); // keep extension
        const hash = crypto.randomBytes(16).toString('hex');
        cb(null, `${hash}.${ext}`);
    }
});

// TODO: consider splitting lightening ratelimits if you have an account, say an extra allotment per account in addition to normal ones.
const ratelimitOptions = {
	standardHeaders: 'draft-8', // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
	ipv6Subnet: 56, // Set to 60 or 64 to be less aggressive, or 52 or 48 to be more aggressive
    message: async function(req, res) {
        const count = req.rateLimit.used;
        const limitWas = req.rateLimit.limit;
        if (count-limitWas === 1 || count % 5 === 0) {
            // For the first while, post into discord for every ratelimit request to track abuse and make sure we don't need to lighten limits
            await makeReport(JSON.stringify({
                embeds: [{
                    type: "rich",
                    title: "Ratelimit Triggered",
                    description: 
                        `Triggered by IP: ${req.ip}\n` + // This is here for better protection, and so we can block people, and check if it's a VPN first.
                        `Endpoint: ${req.originalUrl}\n` +
                        `Method: ${req.method}\n` +
                        `User Agent: ${req.headers['user-agent']}\n` +
                        `Count: ${count}`,
                        // `Query: ${JSON.stringify(req.query)}\n`
                    color: 0xff3c00,
                }]
            }));
        }
        return "Too many requests, try again in a few seconds."
    },
    handler: async function(req, res, next, options) {
        const message = await ratelimitOptions.message(req, res);
        if (req.accepts('html')) {
            return sendError(res, req, message, 429);
        }
        return res.status(429).json({ error: message });
    }
    
}
const defaultRatelimiter = rateLimit({
	windowMs: ms("5s"),
	limit: 5,//1 req per sec
    ...ratelimitOptions
})
const highGeneralRatelimit = rateLimit({ // General pages like root, etc
	windowMs: ms("10s"),
	limit: 20,//2 req per sec
    ...ratelimitOptions
})
const miiListRatelimiter = rateLimit({ // Limiter just for search endpoints
	windowMs: ms("15s"),
	limit: 30,//2 req per sec
    ...ratelimitOptions
})

function bitStringToBuffer(bitString) {
  const byteLength = Math.ceil(bitString.length / 8);
  const buffer = Buffer.alloc(byteLength);

  for (let i = 0; i < bitString.length; i++) {
    if (bitString[i] === '1') {
      buffer[i >> 3] |= 1 << (7 - (i & 7));
    }
  }

  return buffer;
}

//#region Database
async function getSettings() {
    let settings = await Settings.findById("global");
    if (!settings) {
        settings = await Settings.create({
            _id: "global",
            highlightedMii: null,
            highlightedMiiChangeDay: null,
            bannedIPs: [],
            officialCategories: { categories: [] },
            officialCompanySources: [DEFAULT_OFFICIAL_COMPANY_SOURCE],
            miiTags: []
        });
    }
    return settings;
}

async function updateSettings(updates) {
    return await Settings.findByIdAndUpdate("global", updates, { new: true, upsert: true });
}

async function getAllMiis(includePrivate = false) {
    const query = includePrivate ? {} : { private: false };
    return await Miis.find(query).lean();
}

async function getMiiById(id, includePrivate = false) {
    const query = { id };
    if (!includePrivate) query.private = false;
    return await Miis.findOne(query).lean();
}

async function resolveMiiIdForImport(id, req) {
    const trimmedId = typeof id === "string" ? id.trim() : "";
    if (!trimmedId) {
        return { error: "No Mii ID provided" };
    }

    const publishedMii = await getMiiById(trimmedId, false);
    if (publishedMii) {
        return { mii: publishedMii };
    }

    const privateMii = await Miis.findOne({ id: trimmedId, private: true }).lean();
    if (!privateMii) {
        return { error: "Invalid Mii ID - Mii not found" };
    }

    const isOwner = req.user && privateMii.uploader === req.user.username;
    const isModerator = req.user && canModerate(req.user);

    if (!isOwner && !isModerator) {
        return { error: "You do not have permission to use this private Mii" };
    }

    return { mii: privateMii };
}

async function resolveMiiInputForInstructions(req, { allowFile = false } = {}) {
    const source = req.method === "GET" ? req.query : req.body;

    if (allowFile && req.file?.path) {
        return req.file.path;
    }

    const rawMiiData = typeof source?.miiData === "string" ? source.miiData.trim() : "";
    if (rawMiiData) {
        return rawMiiData;
    }

    const miiId = typeof source?.id === "string"
        ? source.id.trim()
        : (typeof source?.miiId === "string" ? source.miiId.trim() : "");
    if (miiId) {
        const resolved = await resolveMiiIdForImport(miiId, req);
        if (!resolved.error) {
            return resolved.mii;
        }

        const tempPath = `./static/temp/${miiId}.bin`;
        if (fs.existsSync(tempPath)) {
            return tempPath;
        }

        throw new Error(resolved.error || "Invalid Mii ID");
    }

    return null;
}

async function getUserByUsername(username, lean=true) {
    let userPromise = Users.findOne({ username });
    if (lean) userPromise = userPromise.lean();
    return await userPromise;
}

async function ensureUploaderAutoLike(username, miiId, minimumVotes = 1) {
    const normalizedUsername = String(username || "").trim();
    const normalizedMiiId = String(miiId || "").trim();
    if (!normalizedUsername || !normalizedMiiId) return;

    await Users.updateOne(
        { username: normalizedUsername },
        { $addToSet: { votedFor: normalizedMiiId } }
    );

    if (Number.isFinite(minimumVotes) && minimumVotes > 0) {
        await Miis.updateOne(
            {
                id: normalizedMiiId,
                $or: [
                    { votes: { $exists: false } },
                    { votes: { $lt: minimumVotes } }
                ]
            },
            { $set: { votes: minimumVotes } }
        );
    }
}

async function getAllUsers() {
    return await Users.find({}).lean();
}
//#endregion

const ejsFunctions = {
    "decodeColor": (colorIndex) => (["Red", "#dd5e17", "#e2cd5e", "Lime", "Green", "Blue", "Cyan", "#e65ba1", "Purple", "Brown", "White", "Black"][colorIndex] || colorIndex)
}

/** Build EJS variables for the page. `user` is assumed to be the logged in user */
async function getSendables(req, title, user) { 
    const currentPath = req.path;
    const queryString = Object.keys(req.query).length > 0 
        ? '?' + new URLSearchParams(req.query).toString() 
        : '';
    const settings = await getSettings();
    const allUsers = await getAllUsers();
    const availableTags = getMiiTags(settings);
    const selectedTags = mapRequestedTagsToCatalog(req.query?.tags, availableTags);
    const searchFieldsExplicitlyConfigured = parseBooleanLike(req.query?.searchFieldsConfigured);
    const selectedSearchFields = getRequestedSearchFields(req.query);

    // Build information related to the current user
    let userPfpMiiColor = null;
    const currentUser = req.user?.username || "Default";
    const pfp = req.user?.miiPfp || "00000";

    if (req.user) {
        let userPfpMii = await getMiiById(pfp, true);
        if(!userPfpMii) userPfpMii=await getMiiById("average",true);
        userPfpMiiColor = userPfpMii.general.favoriteColor;
    }
    
    
    var send = {
        icons,
        ...ejsFunctions,
        highlightedMii: settings.highlightedMii,
        bannedIPs: settings.bannedIPs,
        officialCategories: settings.officialCategories,
        officialCompanySources: getOfficialCompanySources(settings),
        availableTags,
        selectedTags,
        selectedSearchFields,
        searchFieldsExplicitlyConfigured,
        howToTitle: "How To",
        currentPath: currentPath + queryString,
        thisUser: currentUser, // *username
        user: req.user,
        isModerator: canModerate(req.user),
        isOfficial: isOfficial(req.user),
        isResearcher: isResearcher(req.user),
        isAdmin: isAdmin(req.user),
        pfp: pfp,
        query: req.query,
        discordInvite: process.env.discordInvite,
        githubLink: process.env.githubLink,
        baseUrl: baseUrl,
        title: title,
        exportFormats: EXPORT_FORMATS,
        favoriteColors: Array.isArray(miijs.FavoriteColors) ? miijs.FavoriteColors : [],
        userPfpMiiColor: userPfpMiiColor ?? "#111111",
        highlightedMiiData: await getMiiById(settings.highlightedMii, false),
        averageMiiData: await getMiiById("average", false),
    };

    send.currentFilter=send.currentFilter||"";
    return send;
}

//#region Roles
// Role System - Array-based for multiple roles
const ROLES = {
    TEMP_BANNED: 'tempBanned',
    PERM_BANNED: 'permBanned', 
    BASIC: 'basic',
    SUPPORTER: 'supporter',
    RESEARCHER: 'researcher',
    MODERATOR: 'moderator',
    ADMINISTRATOR: 'administrator'
};
const OFFICIAL_ROLES = [ ROLES.RESEARCHER, ROLES.ADMINISTRATOR ];

const ROLE_DISPLAY = {
    [ROLES.TEMP_BANNED]: `${renderIcon('ban', { size: 14 })} Temporarily Banned`,
    [ROLES.PERM_BANNED]: `${renderIcon('ban', { size: 14 })} Permanently Banned`,
    [ROLES.BASIC]: 'User',
    [ROLES.SUPPORTER]: `${renderIcon('heart-filled', { size: 14 })} Supporter`,
    [ROLES.RESEARCHER]: `${renderIcon('flask', { size: 14 })} Researcher`,
    [ROLES.MODERATOR]: `${renderIcon('shield', { size: 14 })} Moderator`,
    [ROLES.ADMINISTRATOR]: `${renderIcon('crown', { size: 14 })} Administrator`
};

// Helper functions for role system
function getUserRoles(user) {
    if (Array.isArray(user?.roles)) {
        return user.roles;
    }
    return [ROLES.BASIC];
}

function hasRole(user, role) {
    const roles = getUserRoles(user);
    return roles.includes(role);
}

function canUploadOfficial(user) {
    return hasRole(user, ROLES.RESEARCHER) || 
           hasRole(user, ROLES.ADMINISTRATOR);
}

function canModerate(user) {
    return hasRole(user, ROLES.MODERATOR) || 
           hasRole(user, ROLES.ADMINISTRATOR);
}

function isOfficial(user) {
    return hasRole(user, ROLES.RESEARCHER) ||
        hasRole(user, ROLES.ADMINISTRATOR);

}

// Permission to edit official Miis
function isResearcher(user) {
    return hasRole(user, ROLES.RESEARCHER) || 
           hasRole(user, ROLES.ADMINISTRATOR);
}

function isAdmin(user) {
    return hasRole(user, ROLES.ADMINISTRATOR);
}

async function isBanned(user) {
    const roles = getUserRoles(user);
    if (roles.includes(ROLES.PERM_BANNED)) return true;
    if (roles.includes(ROLES.TEMP_BANNED)) {
        if (user.banExpires && Date.now() < user.banExpires) {
            return true;
        }
        else if (user.banExpires) {
            // Unban user - remove temp ban role
            user.roles = user.roles.filter(r => r !== ROLES.TEMP_BANNED);
            delete user.banExpires;
            await Users.findOneAndUpdate({ username: user.username }, { 
                roles: user.roles,
                $unset: { banExpires: 1 }
            });
            return false;
        }
        return true;
    }
    return false;
}

function ensureBasicRole(user) {
    if (!user.roles || user.roles.length === 0) {
        user.roles = [ROLES.BASIC];
    }
    // NOTE: this does not save
}

function addRole(user, role) {
    ensureBasicRole(user);
    if (!user.roles.includes(role)) {
        user.roles.push(role);
    }
}

function removeRole(user, role) {
    ensureBasicRole(user);
    user.roles = user.roles.filter(r => r !== role);
    ensureBasicRole(user);
}
//#endregion

function createToken(user) {
    const payload = {
        username: user.username,
        email: user.email,
        tokenVersion: user.tokenVersion || 0
    };
    return jwt.sign(payload, process.env.JWT_SECRET || "beta_testing_only_secret", { 
        expiresIn: '30d',
        algorithm: 'HS256'
    });
}

function getOfficialCategoryTree(settings) {
    if (!settings.officialCategories || typeof settings.officialCategories !== "object") {
        settings.officialCategories = { categories: [] };
    }
    if (!Array.isArray(settings.officialCategories.categories)) {
        settings.officialCategories.categories = [];
    }
    return settings.officialCategories.categories;
}

// Find a category node by exact path
function findCategoryByPath(path, tree) {
    if (!path || !Array.isArray(tree)) return null;

    for (const node of tree) {
        if (node.path === path) return node;
        if (node.children && node.children.length > 0) {
            const found = findCategoryByPath(path, node.children);
            if (found) return found;
        }
    }

    return null;
}

// TODO_DB: verify
// Get all leaf categories (categories with no children) as flat array
function getAllLeafCategories(tree, result = []) {
    if (!tree) return result;
    tree.forEach(node => {
        if (node.children && node.children.length > 0) {
            getAllLeafCategories(node.children, result);
        } else {
            result.push(node);
        }
    });
    return result;
}

function getLeafCategoryPathSet(tree) {
    return new Set(getAllLeafCategories(tree, []).map(node => node.path).filter(Boolean));
}

function normalizeCategoryPaths(rawCategories) {
    const source = Array.isArray(rawCategories) ? rawCategories : [rawCategories];
    return [...new Set(source
        .map(category => typeof category === "string" ? category.trim() : "")
        .filter(Boolean))];
}

function normalizeCategoryColor(color, fallback = "#999999") {
    if (typeof color !== "string") return fallback;
    const trimmed = color.trim();
    return /^#[0-9A-Fa-f]{6}$/.test(trimmed) ? trimmed : fallback;
}

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
        if (tag.length > MAX_MII_TAG_LENGTH) continue;

        const lower = tag.toLowerCase();
        if (seen.has(lower)) continue;

        seen.add(lower);
        normalized.push(tag);
    }

    return normalized;
}

function normalizeCompanySourceName(source) {
    if (typeof source !== "string") return "";
    return source
        .replace(/\s+/g, " ")
        .replace(/[<>]/g, "")
        .trim();
}

function normalizeOfficialCompanySourceList(rawSources) {
    const source = Array.isArray(rawSources) ? rawSources : [rawSources];
    const normalized = [];
    const seen = new Set();

    for (const rawSource of source) {
        const value = normalizeCompanySourceName(rawSource);
        if (!value) continue;
        if (!validate(value)) continue;
        if (value.length > MAX_COMPANY_SOURCE_NAME_LENGTH) continue;
        if (isBad(value)) continue;

        const key = value.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        normalized.push(value);
    }

    if (!seen.has(DEFAULT_OFFICIAL_COMPANY_SOURCE.toLowerCase())) {
        normalized.unshift(DEFAULT_OFFICIAL_COMPANY_SOURCE);
    }

    const defaultSource = normalized.find(
        sourceName => sourceName.toLowerCase() === DEFAULT_OFFICIAL_COMPANY_SOURCE.toLowerCase()
    ) || DEFAULT_OFFICIAL_COMPANY_SOURCE;
    const sortedOthers = normalized
        .filter(sourceName => sourceName.toLowerCase() !== defaultSource.toLowerCase())
        .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));

    return [defaultSource, ...sortedOthers];
}

function getOfficialCompanySources(settings) {
    const normalized = normalizeOfficialCompanySourceList(settings?.officialCompanySources || []);
    if (settings) {
        settings.officialCompanySources = normalized;
    }
    return normalized;
}

async function ensureOfficialCompanySourceAccount(sourceName) {
    const normalizedSource = normalizeCompanySourceName(sourceName);
    if (!normalizedSource) return;

    const existingUser = await getUserByUsername(normalizedSource);
    if (existingUser) return;

    try {
        await Users.create({
            username: normalizedSource,
            salt: "",
            pass: "",
            creationDate: Date.now(),
            email: "",
            votedFor: [],
            miiPfp: "00000",
            roles: [ROLES.BASIC],
            verified: true
        });
    } catch (e) {
        if (e?.code !== 11000) {
            throw e;
        }
    }
}

async function resolveOfficialCompanySourceForUpload(req, settings) {
    const availableSources = getOfficialCompanySources(settings);
    const sourceMode = String(req.body?.officialSourceMode || "existing").trim().toLowerCase();
    const requestedExistingSource = normalizeCompanySourceName(req.body?.officialSourceExisting);
    const requestedNewSource = normalizeCompanySourceName(req.body?.officialSourceNew);
    const defaultSource = availableSources[0] || DEFAULT_OFFICIAL_COMPANY_SOURCE;
    const findCanonicalSource = (sourceName) => availableSources.find(
        existingSource => existingSource.toLowerCase() === sourceName.toLowerCase()
    );

    let selectedSource = defaultSource;
    let notice = null;
    let sourceListChanged = false;

    if (sourceMode === "new") {
        if (!requestedNewSource) {
            return { error: "Enter a company source name to create, or switch to an existing source." };
        }
        if (!validate(requestedNewSource) || requestedNewSource.length > MAX_COMPANY_SOURCE_NAME_LENGTH) {
            return { error: `Company source names must be between 1 and ${MAX_COMPANY_SOURCE_NAME_LENGTH} characters.` };
        }
        if (isBad(requestedNewSource)) {
            return { error: "Company source name contains disallowed text." };
        }

        const canonicalExisting = findCanonicalSource(requestedNewSource);
        if (canonicalExisting) {
            selectedSource = canonicalExisting;
        } else {
            const existingAccount = await getUserByUsername(requestedNewSource);
            if (existingAccount) {
                selectedSource = defaultSource;
                notice = `Company source "${requestedNewSource}" already exists as an account. Admins have been notified and will handle the discrepancy shortly. Using ${selectedSource} for now.`;
                makeReport(JSON.stringify({
                    embeds: [{
                        type: "rich",
                        title: "Official Source Account Conflict",
                        description: `${req.user.username} attempted to create an official company source with an existing account name.`,
                        color: 0xff8800,
                        fields: [
                            {
                                name: "Requested Source",
                                value: requestedNewSource,
                                inline: true
                            },
                            {
                                name: "Existing Account",
                                value: existingAccount.username,
                                inline: true
                            },
                            {
                                name: "Fallback Source",
                                value: selectedSource,
                                inline: true
                            }
                        ]
                    }]
                }));
            } else {
                selectedSource = requestedNewSource;
                availableSources.push(selectedSource);
                sourceListChanged = true;
            }
        }
    } else {
        const canonicalExisting = requestedExistingSource
            ? findCanonicalSource(requestedExistingSource)
            : null;
        selectedSource = canonicalExisting || defaultSource;
    }

    if (!findCanonicalSource(selectedSource)) {
        availableSources.push(selectedSource);
        sourceListChanged = true;
    }

    await ensureOfficialCompanySourceAccount(selectedSource);

    if (sourceListChanged) {
        const normalizedSources = normalizeOfficialCompanySourceList(availableSources);
        await updateSettings({ officialCompanySources: normalizedSources });
        settings.officialCompanySources = normalizedSources;
    }

    return { sourceName: selectedSource, notice };
}

function ensureUploadMiiPermissions(miiData) {
    if (!miiData || typeof miiData !== "object") return miiData;
    if (!miiData.perms || typeof miiData.perms !== "object") {
        miiData.perms = {};
    }
    miiData.perms.sharing = true;
    miiData.perms.copying = true;
    return miiData;
}

function getMiiTags(settings) {
    if (!Array.isArray(settings.miiTags)) {
        settings.miiTags = [];
    }
    settings.miiTags = normalizeTagList(settings.miiTags);
    return settings.miiTags;
}

function mapRequestedTagsToCatalog(requestedTags, catalogTags) {
    const requested = normalizeTagList(requestedTags);
    if (!requested.length) return [];

    const catalog = Array.isArray(catalogTags) ? catalogTags : [];
    const byLower = new Map(catalog.map(tag => [String(tag).toLowerCase(), tag]));
    const mapped = [];

    for (const requestedTag of requested) {
        const canonical = byLower.get(requestedTag.toLowerCase());
        if (canonical && !mapped.includes(canonical)) {
            mapped.push(canonical);
        }
    }

    return mapped;
}

function normalizeSearchFieldSelection(requestedFields, { defaultToAll = true } = {}) {
    const source = Array.isArray(requestedFields) ? requestedFields : [requestedFields];
    const normalized = [];
    const seen = new Set();

    for (const rawField of source) {
        const field = String(rawField || "").trim().toLowerCase();
        if (!SEARCH_FIELD_SET.has(field)) continue;
        if (seen.has(field)) continue;

        seen.add(field);
        normalized.push(field);
    }

    if (normalized.length === 0 && defaultToAll) {
        return [...SEARCH_FIELD_VALUES];
    }

    return normalized;
}

function getRequestedSearchFields(source = {}) {
    const hasExplicitFieldConfig = parseBooleanLike(source?.searchFieldsConfigured);
    return normalizeSearchFieldSelection(source?.searchIn, {
        defaultToAll: !hasExplicitFieldConfig
    });
}

function escapeRegex(input) {
    return String(input).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Get all categories (including parents) as flat array with paths
function getAllCategoriesFlat(tree, result = []) {
    if (!tree) return result;
    tree.forEach(node => {
        result.push(node);
        if (node.children && node.children.length > 0) {
            getAllCategoriesFlat(node.children, result);
        }
    });
    return result;
}

// Recursively update paths after a rename
function updateCategoryPaths(node, parentPath = '') {
    node.path = parentPath ? `${parentPath}/${node.name}` : node.name;
    if (node.children && node.children.length > 0) {
        node.children.forEach(child => {
            updateCategoryPaths(child, node.path);
        });
    }
}

// Find parent of a category by child path
function findParentByChildPath(path, tree) {
    if (!path || !Array.isArray(tree)) return null;

    for (const node of tree) {
        if (Array.isArray(node.children) && node.children.some(child => child.path === path)) {
            return node;
        }
        if (node.children && node.children.length > 0) {
            const found = findParentByChildPath(path, node.children);
            if (found) return found;
        }
    }

    return null;
}

// Rename category in all Miis that use it
async function renameCategoryInAllMiis(oldPath, newPath) {
    let count = 0;
    
    // Update all Miis (published and private)
    const miis = await Miis.find({
        official: true,
        officialCategories: oldPath
    });
    
    for (const mii of miis) {
        const index = mii.officialCategories.indexOf(oldPath);
        if (index > -1) {
            mii.officialCategories[index] = newPath;
            await Miis.findOneAndUpdate(
                { id: mii.id },
                { $set: { officialCategories: mii.officialCategories } }
            );
            count++;
        }
    }
    
    return count;
}

// Remove category from all Miis
async function removeCategoryFromAllMiis(path) {
    let count = 0;
    
    // Update all Miis
    const miis = await Miis.find({
        official: true,
        officialCategories: path
    });
    
    for (const mii of miis) {
        mii.officialCategories = mii.officialCategories.filter(c => c !== path);
        await Miis.findOneAndUpdate(
            { id: mii.id },
            { $set: { officialCategories: mii.officialCategories } }
        );
        count++;
    }
    
    return count;
}

// Get all descendant paths (for deletion)
function getAllDescendantPaths(node, result = []) {
    result.push(node.path);
    if (node.children && node.children.length > 0) {
        node.children.forEach(child => {
            getAllDescendantPaths(child, result);
        });
    }
    return result;
}

function sha256(str) {
    return crypto.createHash('sha256').update(`${str}${globalSalt}`).digest('hex');
}

function deleteMiiAssets(miiId, isPrivate) {
    const imgPath = isPrivate ? `./static/privateMiiImgs/${miiId}.png` : `./static/miiImgs/${miiId}.png`;
    const qrPath = isPrivate ? `./static/privateMiiQRs/${miiId}.png` : `./static/miiQRs/${miiId}.png`;
    try { fs.unlinkSync(imgPath); } catch (e) {}
    try { fs.unlinkSync(qrPath); } catch (e) {}
}

function isVPN(ip) {
    // Basic check - you might want to use a VPN detection API
    // For now, just check if it's a common VPN pattern
    // This is a placeholder - implement proper VPN detection if needed
    return false; // TODO: Implement VPN detection
}

function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// Seeded random number generator (Mulberry32)
function seededRandom(seed) {
    return function() {
        seed |= 0;
        seed = seed + 0x6D2B79F5 | 0;
        var t = Math.imul(seed ^ seed >>> 15, 1 | seed);
        t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
}

// Seeded shuffle using Fisher-Yates
function seededShuffle(array, seed) {
    const rng = seededRandom(seed);
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
}

function validate(what) {
    return /^(\d|\D){1,15}$/.test(what);
}

const swearMatcher = new RegExpMatcher({
    ...englishDataset.build(),
    ...englishRecommendedTransformers, // Full leet-speak detection
});
const badPhonetics = new Set(
    swearList.flatMap(w => doubleMetaphone(w).filter(Boolean))
);

/** Loose filter check that filters if it sounds phonetically similar to any bad word */
function soundsBad(str) {
    // Strict profanity check with full leet-speak
    if (swearMatcher.hasMatch(str)) return true;

    // Remove non-alphabetic for phonetic analysis
    const cleanStr = str.replace(/[^a-zA-Z]/g, '');
    if (cleanStr.length === 0) return false;
    
    const phonetics = doubleMetaphone(cleanStr);
    return phonetics.some(p => p && badPhonetics.has(p));
}

/** Check input against the filter explicitly including leetspeek */
function isBad(str) {
    return swearMatcher.hasMatch(str);
}

async function genId() {
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let attempt = 0;
    let length = 5;
    let newId;
    while (true) {
        newId = "";
        for (var i = 0; i < length; i++) {
            newId += chars[Math.floor(Math.random() * chars.length)];
        }
        let exists = await Miis.exists({ id: newId });
        let isProfane = soundsBad(newId) && attempt < 30; // prevent broken filter from hanging app

        if (!exists && !isProfane) break; // Stop once we find a suitable ID

        // If no ID is found several times in a row, increase the length.
        attempt++;
        if (attempt % 5 === 0) {
            length += 1;
        }
    }
    return newId;
}

function wilsonMethod(upvotes, uploadedOn) {
    // Constants for the Wilson Score Interval
    const z = 1.96; // 95% confidence interval
    
    // Calculate the fraction of upvotes
    const p = upvotes / (upvotes + 1); // Adding 1 to avoid division by zero
    
    // Calculate the "score"
    const score =
    (p + (z * z) / (2 * (upvotes + 1)) - z * Math.sqrt((p * (1 - p) + (z * z) / (4 * (upvotes + 1))) / (upvotes + 1))) /
    (1 + (z * z) / (upvotes + 1));
    
    // Calculate the hotness by considering the time elapsed
    const elapsedTime = (Date.now() - uploadedOn) / (1000 * 60 * 60); // Convert milliseconds to hours
    const hotness = score / elapsedTime;
    
    return hotness;
}

// Paginated API that queries database directly with skip/limit
async function paginatedApi(what, page = 1, perPage = defaultMiisPerPage, filter = null) {
    const skip = (page - 1) * perPage;
    const settings = await getSettings();
    
    let query = { private: false, id: { $ne: "average" } };
    let sort = {};
    
    switch(what) {
        case "random": { // TODO: this is random, but based on sort order. True random is possible but not deterministically
                         // QK, Kestron: I think this is more random than it was, I left the old code commented, reimplement if necessary.
            const totalCount = await Miis.countDocuments(query);
            // const pipeline = [
            //     { $match: query },
            //     {
            //         $addFields: {
            //             randomSort: {
            //                 $mod: [
            //                     { $add: [
            //                         { $toLong: "$uploadedOn" },
            //                         seed
            //                     ]},
            //                     999999
            //                 ]
            //             }
            //         }
            //     },
            //     { $sort: { randomSort: 1 } },
            //     { $skip: skip },
            //     { $limit: perPage }
            // ];
            const pipeline = [
                { $match: query },
                { $sample: { size: Math.min(totalCount, skip + perPage) } },
                { $skip: skip },
                { $limit: perPage }
            ];

            const items = await Miis.aggregate(pipeline);

            return {
                items,
                total: totalCount,
                page,
                perPage,
                totalPages: Math.ceil(totalCount / perPage)
            };
        }
        
        case "trending": {// TODO: rebrand to "trending"
            const now = Date.now();

            const pipeline = [
                { $match: query },
                {
                    $addFields: {
                        ageHours: {
                            $divide: [
                                { $subtract: [now, "$uploadedOn"] },
                                1000 * 60 * 60
                            ]
                        }
                    }
                },
                {
                    $addFields: {
                        hotness: {
                            $divide: [
                                "$votes",
                                {
                                    $pow: [
                                        { $add: ["$ageHours", 2] },
                                        1.5
                                    ]
                                }
                            ]
                        }
                    }
                },
                { $sort: { hotness: -1 } },
                { $skip: skip },
                { $limit: perPage }
            ];

            const [items, total] = await Promise.all([
                Miis.aggregate(pipeline),
                Miis.countDocuments(query)
            ]);

            return {
                items,
                total,
                page,
                perPage,
                totalPages: Math.ceil(total / perPage)
            };
        }

        case "top":
            sort = { votes: -1 };
            break;
        
        case "recent":
            sort = { uploadedOn: -1 };
            break;
        
        case "official":
            query.official = true;
            if (filter) {
                query.officialCategories = filter;
            }
            sort = { votes: -1 };
            break;
        
        case "search": {
            const filterObject =
                filter && typeof filter === "object" && !Array.isArray(filter)
                    ? filter
                    : { query: filter };

            const searchText = typeof filterObject.query === "string"
                ? filterObject.query.trim()
                : "";
            const selectedTags = mapRequestedTagsToCatalog(filterObject.tags, getMiiTags(settings));
            const selectedSearchFields = normalizeSearchFieldSelection(filterObject.searchIn, {
                defaultToAll: !parseBooleanLike(filterObject.searchFieldsConfigured)
            });

            if (selectedTags.length > 0) {
                query.tags = { $all: selectedTags };
            }

            if (searchText) {
                const searchRegex = new RegExp(escapeRegex(searchText), "i");
                const searchFilters = [];

                if (selectedSearchFields.includes("name")) {
                    searchFilters.push({ "meta.name": searchRegex });
                    searchFilters.push({ "meta.creatorName": searchRegex });
                }
                if (selectedSearchFields.includes("description")) {
                    searchFilters.push({ "desc": searchRegex });
                }
                if (selectedSearchFields.includes("uploader")) {
                    searchFilters.push({ "uploader": searchRegex });
                }

                if (searchFilters.length > 0) {
                    query.$or = searchFilters;
                }
            }

            sort = { votes: -1 };
            break;
        }
        
        default:
            return { items: [], total: 0, page: 1, perPage, totalPages: 0 };
    }
    
    // For simple sorted queries (best, recent, official without category)
    const totalCount = await Miis.countDocuments(query);
    const items = await Miis.find(query)
        .sort(sort)
        .skip(skip)
        .limit(perPage)
        .lean();
    
    return {
        items,
        total: totalCount,
        page,
        perPage,
        totalPages: Math.ceil(totalCount / perPage)
    };
}

// API for things that do not pagination (homepage categories and /api endpoint)
async function api(what,limit=50,begin=0,fltr){
    const allMiis = await Miis.find({ private: false, id: { $ne: "average" } }).lean();
    const settings = await getSettings();
    
    var newArr;
    switch(what){
        case "all":
            return allMiis;
        case "highlightedMii":
            return await getMiiById(settings.highlightedMii);
        case "getMii":
            return await getMiiById(fltr);
        case "random":
            newArr = shuffleArray([...allMiis]);
            break;
        case "trending":
            newArr = [...allMiis];
            newArr.sort((a, b) => {
                return wilsonMethod(b.votes, b.uploadedOn) - wilsonMethod(a.votes, a.uploadedOn);
            });
            break;
        case "top":
            newArr = [...allMiis];
            newArr.sort((a, b) => {
                return b.votes - a.votes;
            });
            break;
        case "recent":
            newArr=[...allMiis];
            newArr.sort((a, b) => {
                return b.uploadedOn - a.uploadedOn;
            });
            break;
        case "official":
            newArr = allMiis.filter(mii => mii.official);
            newArr.sort((a, b) => {
                return b.votes - a.votes;
            });
            break;
        case "search":
            fltr = fltr.toLowerCase();
            newArr = allMiis.filter(mii=>{
                return mii.meta.name.toLowerCase().includes(fltr)||mii.desc.toLowerCase().includes(fltr)||mii.uploader.toLowerCase().includes(fltr);
            });
            newArr.sort((a, b) => {
                return b.votes - a.votes;
            });
            break;
        default:
            throw new Error("No valid type specified");
    }
    return newArr.slice(begin,limit);
}

function hashPassword(password, s) {
    let salt;
    if (s) {
        salt = s;
    }
    else {
        salt = crypto.randomBytes(16).toString('hex');
    }
    const hash = crypto.pbkdf2Sync(password, salt + globalSalt, 1000, 64, 'sha256').toString('hex');
    return { salt, hash };
}
function validatePassword(password, salt, hash) {
    if (!password || !salt || !hash) return false;
    if (typeof password !== 'string' || typeof salt !== 'string' || typeof hash !== 'string') return false;
    return hashPassword(password, salt).hash === hash;
}

/** Generate cryptographically secure token used to verify email is accessible */
function genToken(length = 15) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const bytes = crypto.randomBytes(length);
    let token = "";

    for (let i = 0; i < length; i++) {
        token += chars[bytes[i] % chars.length];
    }
    return token;
}

async function sendEmail(to, subj, cont) {
    return new Promise((resolve, reject) => {
        nodemailer.createTransport({
            host: 'smtp.zoho.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.email,
                pass: process.env.emailPass
            }
        }).sendMail({
            from: process.env.email,
            to: to,
            subject: subj,
            html: cont
        }).catch(err => {
            reject("Error sending email");
            console.error('Error sending email:', err);
        }).then(info => {
            resolve("Email sent");
        });
    });
}
function normalizeReportAttachmentData(data) {
    if (Buffer.isBuffer(data)) return data;
    if (data instanceof Uint8Array) return Buffer.from(data);
    if (data instanceof ArrayBuffer) return Buffer.from(new Uint8Array(data));
    return data;
}

function makeReport(content, attachments = []) {
    try {
        const formData = new FormData();
        
        // Add the JSON payload
        formData.append('payload_json', content);
        
        // Add any file attachments
        attachments.forEach((attachment, index) => {
            try {
                const normalizedData = normalizeReportAttachmentData(attachment?.data);
                const isReadableStream = normalizedData && typeof normalizedData.pipe === 'function' && typeof normalizedData.on === 'function';
                const isAcceptableData = Buffer.isBuffer(normalizedData) || typeof normalizedData === 'string' || isReadableStream;

                if (!isAcceptableData) {
                    console.warn(`Skipping Discord attachment at index ${index}: unsupported data type`);
                    return;
                }

                formData.append(`files[${index}]`, normalizedData, {
                    filename: attachment?.filename || `attachment-${index}.bin`,
                    contentType: attachment?.contentType || 'application/octet-stream'
                });
            } catch (attachmentError) {
                console.error(`Error adding Discord attachment at index ${index}:`, attachmentError);
            }
        });
        
        // Send using form-data instead of JSON
        const url = new URL(process.env.hookUrl);
        
        const options = {
            hostname: url.hostname,
            path: url.pathname + url.search,
            method: 'POST',
            headers: formData.getHeaders()
        };
        
        const req = https.request(options, (res) => {
            if (res.statusCode !== 200 && res.statusCode !== 204) {
                console.error(`Discord webhook returned status ${res.statusCode}`);
            }
        });
        
        req.on('error', (error) => {
            console.error('Error sending to Discord:', error);
        });
        
        formData.pipe(req);
    } catch (error) {
        // Reports should never block user actions (uploads, moderation actions, etc.).
        console.error('Error preparing Discord report:', error);
    }
}


//Averaging Helpers
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function mean(nums) {
    if (!nums.length) return undefined;
    return nums.reduce((a, b) => a + b, 0) / nums.length;
}
function mode(arr) {
    const counts = new Map();
    const firstIndex = new Map();
    let best, bestCount = -1;
    arr.forEach((v, i) => {
        const c = (counts.get(v) ?? 0) + 1;
        counts.set(v, c);
        if (!firstIndex.has(v)) firstIndex.set(v, i);
        if (c > bestCount || (c === bestCount && firstIndex.get(v) < firstIndex.get(best))) {
            best = v; bestCount = c;
        }
    });
    return best;
}
function getNestedAsArrays(obj) {
    const ret = {};
    for (const [key, val] of Object.entries(obj)) {
        if (isPlainObject(val)) {
            ret[key] = getNestedAsArrays(val);
        }
        else {
            ret[key] = [val];
        }
    }
    return ret;
}
function populateNestedArrays(arrayObj, obj) {
    const ret = structuredClone(arrayObj);
    for (const [key, val] of Object.entries(obj)) {
        if (isPlainObject(val)) {
            if (!ret[key] || !isPlainObject(ret[key])) ret[key] = {};
            ret[key] = populateNestedArrays(ret[key], val);
        }
        else {
            if (!Array.isArray(ret[key])) ret[key] = [];
            ret[key].push(val);
        }
    }
    return ret;
}
async function getCollectedLeavesAcrossMiis(allMiis) {
    let acc;
    for (const mii of allMiis) {
        acc = acc ? populateNestedArrays(acc, mii) : getNestedAsArrays(mii);
    }
    return acc;
}
function mostCommonPageTypePair(pageArr, typeArr) {
    if (!Array.isArray(pageArr) || !Array.isArray(typeArr)) return null;
    const n = Math.min(pageArr.length, typeArr.length);
    const key = (p, t) => JSON.stringify([p, t]);
    const counts = new Map();
    const order = new Map();
    let bestKey, bestCount = -1;
    
    for (let i = 0; i < n; i++) {
        const p = pageArr[i], t = typeArr[i];
        if (p === undefined || p === null || t === undefined || t === null) continue;
        const k = key(p, t);
        const c = (counts.get(k) ?? 0) + 1;
        counts.set(k, c);
        if (!order.has(k)) order.set(k, i);
        if (c > bestCount || (c === bestCount && order.get(k) < order.get(bestKey))) {
            bestKey = k; bestCount = c;
        }
    }
    return bestKey ? JSON.parse(bestKey) : null; // [page, type]
}
function averageValuesForKey(key, values) {
    const vals = values.filter(v => v !== undefined && v !== null);
    if (!vals.length) return undefined;

    if (key==="type" || key==="color") {
        return mode(vals);
    }
    
    const allNumbers   = vals.every(v => typeof v === "number" && Number.isFinite(v));
    const allBooleans  = vals.every(v => typeof v === "boolean");
    const allStrings   = vals.every(v => typeof v === "string");
    const onlyNumOrBool = vals.every(v => typeof v === "number" || typeof v === "boolean");
    
    if (allNumbers) return Math.round(mean(vals));
    if (allBooleans) {
        const trues = vals.filter(Boolean).length;
        return trues >= (vals.length - trues); // modal boolean
    }
    if (onlyNumOrBool) {
        // booleans as 1/0, rounded mean
        const asNums = vals.map(v => (typeof v === "boolean" ? (v ? 1 : 0) : v));
        return Math.round(mean(asNums));
    }
    if (allStrings) return mode(vals);
    
    // Heterogeneous fallback → mode
    return mode(vals);
}
function averageObjectWithPairs(node, parentKey = "") {
    // Leaf arrays
    if (Array.isArray(node)) {
        return averageValuesForKey(parentKey, node);
    }
    
    // Non-object leaves
    if (!isPlainObject(node)) return node;
    
    // Special handling: resolve modal (page,type) pair if both are present as leaves/arrays
    const hasPage = Object.prototype.hasOwnProperty.call(node, "page");
    const hasType = Object.prototype.hasOwnProperty.call(node, "type");
    const pageIsLeaf = hasPage && !isPlainObject(node.page);
    const typeIsLeaf = hasType && !isPlainObject(node.type);
    
    const out = {};
    
    if (hasPage && hasType && pageIsLeaf && typeIsLeaf) {
        const pageArr = Array.isArray(node.page) ? node.page : [node.page];
        const typeArr = Array.isArray(node.type) ? node.type : [node.type];
        
        const pair = mostCommonPageTypePair(pageArr, typeArr);
        if (pair) {
            const [bestPage, bestType] = pair;
            out.page = bestPage;
            out.type = bestType;
        }
        else {
            // Fallbacks if no pair resolved
            out.page = averageValuesForKey("page", pageArr);
            out.type = averageValuesForKey("type", typeArr);
        }
        
        // Process any siblings at this level
        for (const [k, v] of Object.entries(node)) {
            if (k === "page" || k === "type") continue;
            out[k] = averageObjectWithPairs(v, k);
        }
        return out;
    }
    
    // General case: recurse
    for (const [k, v] of Object.entries(node)) {
        out[k] = averageObjectWithPairs(v, k);
    }
    return out;
}
async function setAverageMii(){
    const pipeline = [
        {
            $match: {
                published: true,
                private: false,
                id: { $ne: "average" }
            }
        },
        {
            $project: {
                _id: 0,
                general: 1,
                hair: 1,
                face: 1,
                eyes: 1,
                eyebrows: 1,
                nose: 1,
                mouth: 1,
                beard: 1,
                glasses: 1,
                mole: 1
            }
        }
    ];
    const allMiis = await Miis.aggregate(pipeline);


    const leaves = await getCollectedLeavesAcrossMiis(allMiis);
    var avg=averageObjectWithPairs(leaves);
    delete avg._id;
    avg.id = "average";
    avg.meta = { 
        name: `J${avg.general.gender===0?"ohn":"ane"} Doe`, 
        creatorName: "InfiniMii", 
        type: "3DS"
    };
    avg.desc="The most common or average features and placements of those features across all Miis on the website";
    avg.uploader = "Everyone";
    avg.votes = 0;
    avg.uploadedOn = Date.now();
    avg.private = false;
    avg.published = true;
    
    // Upsert average Mii
    await Miis.findOneAndUpdate(
        { id: "average" },
        { $set: avg },
        { upsert: true, new: true }
    );
    
    return avg;
}

// Sitemap generation functions
function generateSitemapXML(urls) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n';
    xml += '        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n';
    
    urls.forEach(url => {
        xml += '  <url>\n';
        xml += `    <loc>${url.loc}</loc>\n`;
        if (url.lastmod) xml += `    <lastmod>${url.lastmod}</lastmod>\n`;
        if (url.changefreq) xml += `    <changefreq>${url.changefreq}</changefreq>\n`;
        if (url.priority) xml += `    <priority>${url.priority}</priority>\n`;
        
        // Add image sitemap data if present
        if (url.images && url.images.length > 0) {
            url.images.forEach(img => {
                xml += '    <image:image>\n';
                xml += `      <image:loc>${img.loc}</image:loc>\n`;
                if (img.title) xml += `      <image:title>${escapeXml(img.title)}</image:title>\n`;
                if (img.caption) xml += `      <image:caption>${escapeXml(img.caption)}</image:caption>\n`;
                xml += '    </image:image>\n';
            });
        }
        
        xml += '  </url>\n';
    });
    
    xml += '</urlset>';
    return xml;
}

function escapeXml(unsafe) {
    return unsafe.replace(/[<>&'"]/g, (c) => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

import 'express-async-errors'; // Inject express to make router async errors handle the same as sync errors (dropping down to next() handler)
const site = express();
site.use(express.json());
site.use(express.urlencoded({ extended: true }));
site.use(express.static(path.join(__dirname + '/static')));
site.use(express.static(path.join(__dirname + '/static/css')));
site.use(express.static(path.join(__dirname + '/static/js')));
site.use(express.static(path.join(__dirname + '/static/assets')));
site.use(cookieParser());
site.use('/favicon.ico', express.static('static/favicon.ico'));


//#region Middleware

// Security middleware
site.use(helmet({ contentSecurityPolicy: false }));
site.use((req, res, next) => {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Content Security Policy (adjust as needed)
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: blob: https:; " +
        "connect-src 'self' https://www.google-analytics.com;"
    );
    
    next();
});

// Auth middleware (using JWTs)
site.use(async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return next(); // Not logged in, keep req.user undefined
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET || "beta_testing_only_secret", { // TODO REMOVE
            algorithms: ['HS256']
        });
        const user = await Users.findOne({ 
            username: payload.username,
            email: payload.email,
            tokenVersion: payload.tokenVersion
        });
        // TODO: exploit where you change your username/email, and old token can still access it....
        // SOLUTION: on email/username change, increase token version

        // Optional: check token version to allow invalidation
        if (!user) {
            res.clearCookie('token');
            res.clearCookie('username');
            return next();
        }

        req.user = user; // attach full DB user
        next();
    } catch (err) {
        // jwt.verify failed, clear.
        res.clearCookie('token');
        res.clearCookie('username');
        next();
    }
})

// Ban middleware
site.use(async (req, res, next) => {
    // Check if user is banned
    if (req.user) {
        if (req.user) {
            // Check IP ban
            const clientIPs = [req.headers['x-forwarded-for'], req.socket.remoteAddress]
                .filter(Boolean)
                .map(ip => sha256(ip));
            const settings = await getSettings();
            if (settings.bannedIPs.some(ip => clientIPs.includes(ip))) {
                res.clearCookie('username');
                res.clearCookie('token');
                if (req.accepts('html')) {
                    return await sendError(res, req, 'Your IP address has been permanently banned.', 403);
                } else {
                    return res.status(403).json({error: 'Your IP address has been permanently banned.'});
                }
            }
            
            // Check user ban
            if (await isBanned(req.user)) {
                // Allow access to logout only
                if (req.path === '/logout') {
                    return next();
                }
                
                if (hasRole(req.user, ROLES.TEMP_BANNED) && req.user.banExpires) {
                    const timeLeft = Math.ceil((req.user.banExpires - Date.now()) / (1000 * 60 * 60));
                    const message = `You are temporarily banned. Time remaining: ${timeLeft} hours. Reason: ${req.user.banReason || 'No reason provided'}`;
                    if (req.accepts('html')) {
                        return await sendError(res, req, message, 403);
                    } else {
                        return res.status(403).json({error: message});
                    }
                }
                else {
                    const message = `You are permanently banned. Reason: ${req.user.banReason || 'No reason provided'}`;
                    if (req.accepts('html')) {
                        return await sendError(res, req, message, 403);
                    } else {
                        return res.status(403).json({error: message});
                    }
                }
            }
        }
    }
    next();
});

// Compression middleware
site.use(compression({
    level: 6,
    threshold: 100 * 1024, // Only compress if response > 100kb
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

// Redirect Nintendo 3DS / Wii U browser traffic to a legacy-compatible upload page.
site.use((req, res, next) => {
    if (req.method !== "GET") return next();
    if (!isLegacyNintendoBrowserRequest(req)) return next();

    const pathLower = String(req.path || "").toLowerCase();
    if (!pathLower) return next();

    // Never redirect upload/static/image routes or resource requests.
    if (pathLower === "/legacy-upload" || pathLower.startsWith("/legacy-upload/")) return next();
    if (pathLower.startsWith("/uploadmii")) return next();
    if (pathLower.startsWith("/api/")) return next();
    if (pathLower.startsWith("/render")) return next();
    if (pathLower.startsWith("/miiimgs")) return next();
    if (pathLower.startsWith("/miiqrs")) return next();
    if (pathLower.startsWith("/privatemiiimgs")) return next();
    if (pathLower.startsWith("/privatemiiqrs")) return next();
    if (pathLower.includes(".")) return next();

    // Only redirect full document navigations, not images/assets/upload requests.
    const acceptHeader = String(req.get("accept") || "").toLowerCase();
    if (acceptHeader.includes("image/")) return next();
    const wantsHtmlDocument =
        acceptHeader.includes("text/html") ||
        acceptHeader.includes("application/xhtml+xml");
    if (!wantsHtmlDocument) return next();

    const fetchDest = String(req.get("sec-fetch-dest") || "").toLowerCase();
    if (fetchDest && fetchDest !== "document") return next();

    return res.redirect("/legacy-upload");
});

//#endregion

// Patch ejs renderFile to resolve the ejsPartials at root, making includes shorter
ejs.renderFile = ((orig) => {
    return function (file, data, opts = {}, cb) {
        return orig.call(
            this,
            file,
            data,
            {
                views: [
                    path.join(__dirname, 'ejsFiles'),
                    path.join(__dirname, 'ejsPartials')
                ],
                ...opts
            },
            cb
        );
    };
})(ejs.renderFile)

function renderEjs(file, inp) {
    return new Promise((resolve, reject) => {
        ejs.renderFile(file, inp, {}, function(err, str) {
            if (err) {
                reject(err);
            } else {
                resolve(str);
            }
        });
    });
}

async function sendError(res, req, message, status) {
    return res.status(status).send(await renderEjs("./ejsFiles/error.ejs", {
        message: message,
        status: `${status} ${STATUS_CODES[status]}`,
        ...(await getSendables(req))
    }));
}

//#region Static handling

  
// Require auth on private Mii images
site.use('/privateMiiImgs', async (req, res, next) => {
    const miiId = req.path.split('/').pop().split('.')[0];
    
    const privateMii = await Miis.findOne({ id: miiId, private: true }).lean();
    if (privateMii) {
        const isOwner = privateMii.uploader === req.user.username;
        const isModerator = req.user && canModerate(req.user);
        
        if (isModerator || isOwner) {
            next();
        } else {
            if (req.accepts('html')) {
                res.status(403).json({ error: 'Access denied' });
            } else {
                await sendError(res, req, "Access denied. This is a private Mii.", 403);
            }
        }
    } else {
        next();
    }
});

// Require auth on private Mii QRs
site.use('/privateMiiQRs', async (req, res, next) => {
    const miiId = req.path.split('/').pop().split('.')[0];
    
    const privateMii = await Miis.findOne({ id: miiId, private: true }).lean();
    if (privateMii) {
        const isOwner = privateMii.uploader === req.user.username;
        const isModerator = req.user && canModerate(req.user);
        
        if (isOwner || isModerator) {
            next();
        } else {
            return sendError(res, req, "Access denied. This is a private Mii.", 403);
        }
    } else {
        next();
    }
});

// Render missing private Mii images on demand
site.use('/privateMiiImgs', async (req, res, next) => {
    const miiId = req.path.split('/').pop()?.split('.')?.[0];
    if (!miiId) return next();

    const imgPath = `./static/privateMiiImgs/${miiId}.png`;
    if (fs.existsSync(imgPath)) {
        return res.sendFile(path.join(__dirname, 'static', 'privateMiiImgs', `${miiId}.png`));
    }

    const mii = await Miis.findOne({ id: miiId, private: true }).lean();
    if (!mii) return next();

    try {
        await fs.promises.writeFile(imgPath, await miijs.renderMii(mii));
        return res.sendFile(path.join(__dirname, 'static', 'privateMiiImgs', `${miiId}.png`));
    } catch (e) {
        return next(e);
    }
});

// Render missing private Mii QRs on demand
site.use('/privateMiiQRs', async (req, res, next) => {
    const miiId = req.path.split('/').pop()?.split('.')?.[0];
    if (!miiId) return next();

    const qrPath = `./static/privateMiiQRs/${miiId}.png`;
    if (fs.existsSync(qrPath)) {
        return res.sendFile(path.join(__dirname, 'static', 'privateMiiQRs', `${miiId}.png`));
    }

    const mii = await Miis.findOne({ id: miiId, private: true }).lean();
    if (!mii) return next();

    try {
        await writeQrPng(mii, qrPath);
        return res.sendFile(path.join(__dirname, 'static', 'privateMiiQRs', `${miiId}.png`));
    } catch (e) {
        return next(e);
    }
});

// Render missing public Mii images on demand
site.use('/miiImgs', async (req, res, next) => {
    const miiId = req.path.split('/').pop()?.split('.')?.[0];
    if (!miiId) return next();

    const imgPath = `./static/miiImgs/${miiId}.png`;
    if (fs.existsSync(imgPath)) {
        return res.sendFile(path.join(__dirname, 'static', 'miiImgs', `${miiId}.png`));
    }

    const mii = await Miis.findOne({ id: miiId, private: false }).lean();
    if (!mii) return next();

    try {
        await fs.promises.writeFile(imgPath, await miijs.renderMii(mii));
        return res.sendFile(path.join(__dirname, 'static', 'miiImgs', `${miiId}.png`));
    } catch (e) {
        return next(e);
    }
});

// Render missing public Mii QRs on demand
site.use('/miiQRs', async (req, res, next) => {
    const miiId = req.path.split('/').pop()?.split('.')?.[0];
    if (!miiId) return next();

    const qrPath = `./static/miiQRs/${miiId}.png`;
    if (fs.existsSync(qrPath)) {
        return res.sendFile(path.join(__dirname, 'static', 'miiQRs', `${miiId}.png`));
    }

    const mii = await Miis.findOne({ id: miiId, private: false }).lean();
    if (!mii) return next();

    try {
        await writeQrPng(mii, qrPath);
        return res.sendFile(path.join(__dirname, 'static', 'miiQRs', `${miiId}.png`));
    } catch (e) {
        return next(e);
    }
});

// Static assets caching
site.use('/static', express.static(path.join(__dirname, 'static'), {
    maxAge: '7d',
    etag: true
}));

//#endregion

async function requireAuth(req, res, next) {
    if (!req.user) {
        // TODO_AUTH: redirect to /login with a ?next
        return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
        // return sendError(res, req, "Authentication required.", 401);
    }
    next();
}
function requireRole(roles) {
    // Returns middleware when called
    if (!Array.isArray(roles)) {
        roles = [ roles  ];
    }
    return async (req, res, next) => {
        if (!req.user) {
            // TODO_AUTH: redirect to /login with a ?next
            await sendError(res, req, "Authentication required.", 401);
        }
        const userRoles = getUserRoles(req.user);
        const hasRequiredRole = roles.some(role => userRoles.includes(role));
        if (!hasRequiredRole && !userRoles.includes(ROLES.ADMINISTRATOR)) {
            return sendError(res, req, "Insufficient permissions.", 403);
        }
        next();
    }
}

connectionPromise.then(() => { // TODO: server error page if DB fails
    site.listen(process.env.PORT || 8080, async () => {
        console.log("Starting, do not stop...");

        // Ensure directories exist
        if (!fs.existsSync('./static/privateMiiImgs')) {
            fs.mkdirSync('./static/privateMiiImgs', { recursive: true });
        }
        if (!fs.existsSync('./static/privateMiiQRs')) {
            fs.mkdirSync('./static/privateMiiQRs', { recursive: true });
        }
        if (!fs.existsSync('./static/temp')) {
            fs.mkdirSync('./static/temp', { recursive: true });
        }

        // Initialize settings if not exists
        const settings = await getSettings();
        const existingCompanySources = Array.isArray(settings.officialCompanySources)
            ? [...settings.officialCompanySources]
            : [];
        const normalizedCompanySources = getOfficialCompanySources(settings);
        if (!isDeepStrictEqual(existingCompanySources, normalizedCompanySources)) {
            await updateSettings({ officialCompanySources: normalizedCompanySources });
        }
        await Promise.all(normalizedCompanySources.map(source => ensureOfficialCompanySourceAccount(source)));
        console.log("Settings initialized");

        // For Quickly Uploading Batches of Miis
        if (fs.existsSync('./quickUploads')) {
            const quickUploadMetadata = getQuickUploadMetadata("./quickUploads");
            await Promise.all(
                fs.readdirSync("./quickUploads").map(async (file) => {
                    const lowerName = file.toLowerCase();
                    if (lowerName === "upload.ini" || lowerName === "uploader.txt") return;
                    if (lowerName.endsWith(".txt")) return;

                    try {
                        const mii = await createMiiData(`./quickUploads/${file}`);
                        const matchingMii = await findMatchingMii(mii);
                        if (matchingMii) {
                            fs.unlinkSync(`./quickUploads/${file}`);
                            console.warn(`[quickUploads] Skipping ${file}: already exists as Mii ID ${matchingMii.id}`);
                            return;
                        }

                        mii.uploadedOn = Date.now();
                        mii.uploader = quickUploadMetadata.uploader;
                        mii.official = quickUploadMetadata.official;
                        mii.votes = 1;
                        mii.id = await genId();
                        mii.desc = "Uploaded in Bulk";
                        mii.private = false;
                        mii.published = true;
                        ensureUploadMiiPermissions(mii);

                        await Miis.create(mii);

                        fs.unlinkSync(`./quickUploads/${file}`);
                        console.log(`Added ${mii.meta?.name || file} from quick uploads`);
                    } catch (e) {
                        console.warn(`Couldn't process ${file}: ${e.message}`);
                        // fs.unlinkSync(`./quickUploads/${file}`);
                    }
                })
            );
            console.log("Finished Checking Quick Uploads Folder");
        }

        console.log(`Generating new average Mii...`);
        await setAverageMii();
        setInterval(async () => await setAverageMii(), 1800000);//30 Mins
        // TODO: it's passing it without all the fields
        const avgMii = await getMiiById("average");

        if (avgMii) {
            fs.promises.writeFile(`./static/miiImgs/average.png`, await miijs.renderMii(avgMii)).catch(() => console.log);
            await writeQrPng(avgMii, `./static/miiQRs/average.png`).catch(() => console.log);
        }

        fs.readdirSync("./uploads").forEach(failedUploadFile=>{
            fs.unlinkSync(`./uploads/${failedUploadFile}`);
        });

        console.log(`Cleared all failed uploads\n\nAll setup finished.\nOnline`);
    });
});

site.get('/', highGeneralRatelimit, async (req, res) => {
    let toSend = await getSendables(req, "InfiniMii");
    toSend.title = "InfiniMii";
    toSend.miiCategories={
        "Random": { miis: (await paginatedApi("random", 1, HOME_PREVIEW_COUNT)).items, link: "./random" },
        "Trending": { miis: (await paginatedApi("trending", 1, HOME_PREVIEW_COUNT)).items, link: "./trending" },
        "Top": { miis: (await paginatedApi("top", 1, HOME_PREVIEW_COUNT)).items, link: "./top" },
        "Recent": { miis: (await paginatedApi("recent", 1, HOME_PREVIEW_COUNT)).items, link: "./recent" },
        "Official": { miis: (await paginatedApi("official", 1, HOME_PREVIEW_COUNT)).items, link: "./official" }
    };
    
    ejs.renderFile(toSend.thisUser.toLowerCase() === "default" ? './ejsFiles/about.ejs' : './ejsFiles/index.ejs', toSend, {}, function (err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
//The following up to and including /recent are all sorted before being renders in miis.ejs, meaning the file is recycled. / is currently just a clone of /trending. /official and /search is more of the same but with a slight change to make Highlighted Mii still work without the full Mii array
site.get('/random', miiListRatelimiter, async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    const perPage = 32;
    
    // Get or generate seed: use query param if provided, otherwise generate random seed
    // On page 1 without seed, generate new random seed. On subsequent pages, seed must be passed.
    const seed = req.query.seed || Math.floor(Math.random() * 1000000).toString();
    
    const paginatedData = await paginatedApi("random", page, perPage, seed);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage,
        seed: paginatedData.seed // Pass seed to template for pagination links
    };
    
    toSend.title = "Random Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/trending', miiListRatelimiter, async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    
    const paginatedData = await paginatedApi("trending", page, defaultMiisPerPage);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Trending Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/top', miiListRatelimiter, async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    
    const paginatedData = await paginatedApi("top", page, defaultMiisPerPage);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Top Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/recent', miiListRatelimiter, async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;    const perRow = 5;
    
    const paginatedData = await paginatedApi("recent", page, defaultMiisPerPage);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Recent Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/official', miiListRatelimiter, async (req, res) => {
    let toSend = await getSendables(req);
    
    const page = parseInt(req.query.page) || 1;
    const filterCategory = req.query.category;
    
    // Get settings for categories
    const settings = await getSettings();
    const categories = getOfficialCategoryTree(settings);
    
    // Get all unique leaf categories (only categories that can be assigned to Miis)
    const leafCategories = getAllLeafCategories(categories);
    
    // Create category info with paths for display
    toSend.availableCategories = leafCategories.map(cat => ({
        name: cat.name,
        path: cat.path,
        color: cat.color,
        fullPath: cat.path // Show full path for clarity
    }));
    
    // Sort categories by path
    toSend.availableCategories.sort((a, b) => a.path.localeCompare(b.path));
    
    // Get paginated official Miis
    const paginatedData = await paginatedApi("official", page, defaultMiisPerPage, filterCategory);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    if (filterCategory) {
        toSend.currentFilter = filterCategory;
    }
    
    toSend.title = filterCategory 
        ? `Official Miis - ${filterCategory} - InfiniMii`
        : "Official Miis - InfiniMii";
    
    ejs.renderFile('./ejsFiles/official.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/searchResults', miiListRatelimiter, async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    const searchQuery = typeof req.query.q === "string" ? req.query.q.trim() : "";
    const selectedTags = Array.isArray(toSend.selectedTags) ? toSend.selectedTags : [];
    const selectedSearchFields = getRequestedSearchFields(req.query);
    
    const paginatedData = await paginatedApi("search", page, defaultMiisPerPage, {
        query: searchQuery,
        tags: selectedTags,
        searchIn: selectedSearchFields,
        searchFieldsConfigured: true
    });
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.searchQuery = searchQuery;
    const hasActiveSearchQuery = Boolean(searchQuery && selectedSearchFields.length > 0);
    if (hasActiveSearchQuery && selectedTags.length) {
        toSend.title = `Search '${searchQuery}' + Tags - InfiniMii`;
    } else if (hasActiveSearchQuery) {
        toSend.title = `Search '${searchQuery}' - InfiniMii`;
    } else if (selectedTags.length) {
        toSend.title = `Tagged Miis - InfiniMii`;
    } else {
        toSend.title = "Search - InfiniMii";
    }

    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/search', async (req, res) => {
    ejs.renderFile('./ejsFiles/search.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/opensearch.xml', (req, res) => {
    const resolvedBaseUrl = (baseUrl || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>InfiniMii</ShortName>
  <Description>Search InfiniMii for Mii characters</Description>
  <InputEncoding>UTF-8</InputEncoding>
  <Url type="text/html" method="get" template="${resolvedBaseUrl}/searchResults?q={searchTerms}&amp;page={startPage?}" />
</OpenSearchDescription>`;

    res.header('Content-Type', 'application/opensearchdescription+xml; charset=UTF-8');
    res.send(xml);
});
site.get('/transferInstructions', async (req, res) => {
    ejs.renderFile('./ejsFiles/transferInstructions.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});

const LEGACY_PREVIEW_FALLBACK_PNG = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z6wAAAABJRU5ErkJggg==",
    "base64"
);

function detectImageMime(buf) {
    if (!buf || buf.length < 4) return null;

    // PNG
    if (
        buf.length >= 8 &&
        buf[0] === 0x89 &&
        buf[1] === 0x50 &&
        buf[2] === 0x4e &&
        buf[3] === 0x47 &&
        buf[4] === 0x0d &&
        buf[5] === 0x0a &&
        buf[6] === 0x1a &&
        buf[7] === 0x0a
    ) {
        return "image/png";
    }

    // BMP
    if (buf[0] === 0x42 && buf[1] === 0x4d) {
        return "image/bmp";
    }

    // JPEG
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
        return "image/jpeg";
    }

    return null;
}

function sendLegacyImageBuffer(res, data, mime) {
    res.setHeader("Content-Type", mime || "application/octet-stream");
    return res.send(data);
}

async function readLegacyImageFromFile(filePath) {
    if (!filePath || !fs.existsSync(filePath)) return null;
    try {
        const data = await fs.promises.readFile(filePath);
        const mime = detectImageMime(data);
        if (!mime) return null;
        return { data, mime };
    } catch (e) {
        return null;
    }
}

async function renderLegacyPreviewImage(miiData) {
    if (!miiData) return null;
    try {
        // Keep legacy previews very small for 3DS/Wii U browsers.
        const rendered = await miijs.renderMii(miiData, { size: 128 });
        const mime = detectImageMime(rendered);
        if (!mime) return null;
        return { data: rendered, mime };
    } catch (e) {
        return null;
    }
}

function applyLegacyResponseCompatibilityHeaders(res) {
    // Some legacy browsers behave better with permissive/simple response headers.
    res.removeHeader("Content-Security-Policy");
    res.removeHeader("X-Content-Security-Policy");
    res.removeHeader("X-WebKit-CSP");
    res.removeHeader("X-Frame-Options");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
}

async function renderLegacyUploadPage(req, res, options = {}) {
    const settings = await getSettings();
    const highlightedMii = settings?.highlightedMii || null;

    const [highlightedMiiData, averageMiiData] = await Promise.all([
        highlightedMii ? getMiiById(highlightedMii, false) : Promise.resolve(null),
        getMiiById("average", false)
    ]);

    const toSend = {
        title: "Legacy Upload - InfiniMii",
        highlightedMiiData,
        averageMiiData,
        legacyCacheBuster: Date.now().toString(36),
        legacyUploadError: options.error || "",
        legacyUploadSuccess: options.success || "",
        legacyUploadedMii: options.uploadedMii || null,
        legacyFormValues: options.formValues || {
            username: "",
            desc: "",
            visibility: "private"
        }
    };

    applyLegacyResponseCompatibilityHeaders(res);
    res.setHeader("Content-Type", "text/html; charset=utf-8");

    ejs.renderFile('./ejsFiles/uploadLegacy.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
}

async function sendLegacyPreviewFallback(res) {
    applyLegacyResponseCompatibilityHeaders(res);
    return sendLegacyImageBuffer(res, LEGACY_PREVIEW_FALLBACK_PNG, "image/png");
}

async function sendLegacyHighlightedPreview(req, res) {
    applyLegacyResponseCompatibilityHeaders(res);
    const settings = await getSettings();
    const highlightedId = settings?.highlightedMii;
    const highlightedMii = highlightedId ? await getMiiById(highlightedId, true) : null;

    const rendered = await renderLegacyPreviewImage(highlightedMii);
    if (rendered) {
        return sendLegacyImageBuffer(res, rendered.data, rendered.mime);
    }

    if (highlightedId) {
        const publicPath = path.join(__dirname, "static", "miiImgs", `${highlightedId}.png`);
        const publicImage = await readLegacyImageFromFile(publicPath);
        if (publicImage) {
            return sendLegacyImageBuffer(res, publicImage.data, publicImage.mime);
        }

        const privatePath = path.join(__dirname, "static", "privateMiiImgs", `${highlightedId}.png`);
        const privateImage = await readLegacyImageFromFile(privatePath);
        if (privateImage) {
            return sendLegacyImageBuffer(res, privateImage.data, privateImage.mime);
        }
    }

    return sendLegacyPreviewFallback(res);
}

async function sendLegacyAveragePreview(req, res) {
    applyLegacyResponseCompatibilityHeaders(res);
    const averageMii = await getMiiById("average", true);

    const rendered = await renderLegacyPreviewImage(averageMii);
    if (rendered) {
        return sendLegacyImageBuffer(res, rendered.data, rendered.mime);
    }

    const averagePath = path.join(__dirname, "static", "miiImgs", "average.png");
    const averageImage = await readLegacyImageFromFile(averagePath);
    if (averageImage) {
        return sendLegacyImageBuffer(res, averageImage.data, averageImage.mime);
    }

    return sendLegacyPreviewFallback(res);
}

site.get('/legacy-upload/highlighted.png', sendLegacyHighlightedPreview);
site.get('/legacy-upload/average.png', sendLegacyAveragePreview);
site.get('/legacy-upload/highlighted.bmp', sendLegacyHighlightedPreview);
site.get('/legacy-upload/average.bmp', sendLegacyAveragePreview);
site.get('/highlighted.png', sendLegacyHighlightedPreview);
site.get('/average.png', sendLegacyAveragePreview);
site.get('/highlighted.bmp', sendLegacyHighlightedPreview);
site.get('/average.bmp', sendLegacyAveragePreview);

site.get('/legacy-upload', async (req, res) => {
    if (!isLegacyNintendoBrowserRequest(req)) {
        return res.redirect('/upload');
    }

    await renderLegacyUploadPage(req, res);
});

site.post('/legacy-upload', upload.single('mii'), async (req, res) => {
    const formValues = {
        username: String(req.body.username || "").trim(),
        desc: String(req.body.desc || "").trim(),
        visibility: String(req.body.visibility || "private").toLowerCase() === "published" ? "published" : "private"
    };

    const cleanupUpload = () => {
        try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
    };

    try {
        const password = String(req.body.password || "");
        if (!formValues.username || !password) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: "Username and password are required.",
                formValues
            });
            return;
        }

        const user = await getUserByUsername(formValues.username);
        if (!user || !validatePassword(password, user.salt, user.pass)) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: "Invalid username or password.",
                formValues
            });
            return;
        }

        if (!user.verified) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: "This account must be verified before uploading.",
                formValues
            });
            return;
        }

        if (await isBanned(user)) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: "This account is currently banned and cannot upload.",
                formValues
            });
            return;
        }

        if (!req.file?.path) {
            await renderLegacyUploadPage(req, res, {
                error: "Please choose a Mii file to upload.",
                formValues
            });
            return;
        }

        if (!formValues.desc) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: "A description is required.",
                formValues
            });
            return;
        }

        const wantsPublic = formValues.visibility === "published";

        if (!wantsPublic) {
            const privateMiisCount = await Miis.countDocuments({ uploader: user.username, private: true });
            if (privateMiisCount >= Number(PRIVATE_MII_LIMIT)) {
                cleanupUpload();
                await renderLegacyUploadPage(req, res, {
                    error: `You have reached the private Mii limit of ${PRIVATE_MII_LIMIT}.`,
                    formValues
                });
                return;
            }
        }

        let mii;
        try {
            mii = await createMiiData(req.file.path);
        } catch (e) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: `Failed to read this file as a Mii. ${e.message || ""}`.trim(),
                formValues
            });
            return;
        }

        const matchingMii = await findMatchingMii(mii);
        if (matchingMii) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: getDuplicateMiiErrorMessage(matchingMii.id),
                formValues
            });
            return;
        }

        mii.id = await genId();
        mii.uploadedOn = Date.now();
        mii.uploader = user.username;
        mii.desc = formValues.desc.slice(0, 250);
        mii.votes = 1;
        mii.official = false;
        mii.published = wantsPublic;
        mii.blockedFromPublishing = false;
        ensureUploadMiiPermissions(mii);

        const miiImageData = await miijs.renderMii(mii);
        if (wantsPublic) {
            fs.writeFileSync(`./static/miiImgs/${mii.id}.png`, miiImageData);
            await writeQrPng(mii, `./static/miiQRs/${mii.id}.png`);
        } else {
            fs.writeFileSync(`./static/privateMiiImgs/${mii.id}.png`, miiImageData);
            await writeQrPng(mii, `./static/privateMiiQRs/${mii.id}.png`);
        }

        await Miis.create({
            ...mii,
            id: mii.id,
            private: !wantsPublic
        });
        await ensureUploaderAutoLike(user.username, mii.id, 1);

        makeReport(JSON.stringify({
            embeds: [{
                type: "rich",
                title: `Legacy Browser Upload (${wantsPublic ? "Published" : "Private"})`,
                description: mii.desc,
                color: 0x00aaff,
                fields: [
                    {
                        name: "Mii Name",
                        value: mii.meta?.name || "Unknown",
                        inline: true
                    },
                    {
                        name: "Uploaded by",
                        value: `[${user.username}](https://infinimii.com/user/${encodeURIComponent(user.username)})`,
                        inline: true
                    },
                    {
                        name: "Browser",
                        value: isLegacyNintendoBrowserUserAgent(req.get("user-agent")) ? "Nintendo 3DS / Wii U" : "Unknown",
                        inline: true
                    }
                ],
                image: {
                    url: `attachment://${mii.id}.png`
                },
                footer: {
                    text: `View: https://infinimii.com/mii/${mii.id}`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${mii.id}.png`,
                contentType: 'image/png'
            }
        ]);

        cleanupUpload();
        await renderLegacyUploadPage(req, res, {
            success: `Upload complete. ${wantsPublic ? "Your Mii is now published." : "Your Mii was saved as private."}`,
            uploadedMii: {
                id: mii.id,
                name: mii.meta?.name || "Unknown",
                published: wantsPublic
            },
            formValues: {
                username: formValues.username,
                desc: "",
                visibility: "private"
            }
        });
    } catch (e) {
        console.error("Legacy upload error:", e);
        cleanupUpload();
        await renderLegacyUploadPage(req, res, {
            error: "Upload failed. Please verify your credentials and file, then try again.",
            formValues
        });
    }
});

site.get('/upload', requireAuth, async (req, res) => {
    let toSend = await getSendables(req);
    toSend.fromAmiibo = null;
    // Check if coming from Amiibo extraction
    if (req.query.fromAmiibo) {
        const tempMiiId = req.query.fromAmiibo;
        const tempImgPath = `./static/miiImgs/${tempMiiId}.png`;
        const tempBinPath = `./static/temp/${tempMiiId}.bin`;
        
        if (fs.existsSync(tempImgPath) && fs.existsSync(tempBinPath)) {
            // Read the Mii data
            try {
                const binData = fs.readFileSync(tempBinPath);
                const mii = await createMiiData(binData);
                
                toSend.fromAmiibo = {
                    id: tempMiiId,
                    name: mii.meta.name || "Unknown",
                    creator: mii.meta.creatorName || "Unknown"
                };
            } catch (e) {
                console.error('Error reading temp Amiibo Mii:', e);
            }
        }
    }
    
    ejs.renderFile('./ejsFiles/upload.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/verify', async (req, res) => {
    // CSRF, but it's fine here, nothing bad can be done.
    const user = await getUserByUsername(req.query.user);
    if (!user) {
        res.json({error: "User not found"});
        return;
    }
    
    if (user.verificationToken && validatePassword(req.query.token, user.salt, user.verificationToken)) {
        await Users.findOneAndUpdate(
            { username: req.query.user },
            { 
                $unset: { verificationToken: "" },
                $set: { 
                    verified: true 
                }
            }
        );
        
        // Get updated user and create JWT
        const updatedUser = await getUserByUsername(req.query.user);
        const jwtToken = createToken(updatedUser);
        
        res.cookie("username", req.query.user, { 
            maxAge: ms("30 days") // 1 Month
        });
        res.cookie("token", jwtToken, { 
            maxAge: ms("30 days"), // 1 Month
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        res.redirect(`/user/${encodeURIComponent(req.query.user)}`); 
    }
    else {
        return await sendError(res, req, "Bad request, try again", 400);
    }
});

site.get('/verifyEmailChange', async (req, res) => {
    // Endpoint to verify and complete email change
    const user = await getUserByUsername(req.query.user);
    if (!user) {
        return await sendError(res, req, "User not found", 404);
    }
    
    // Check if there's a pending email change
    if (!user.pendingEmail || !user.pendingEmailToken) {
        return await sendError(res, req, "No pending email change found", 400);
    }
    
    // Check if token has expired
    if (user.pendingEmailExpires && Date.now() > user.pendingEmailExpires) {
        await Users.findOneAndUpdate(
            { username: req.query.user },
            { 
                $unset: { 
                    pendingEmail: "",
                    pendingEmailToken: "",
                    pendingEmailExpires: ""
                }
            }
        );
        return await sendError(res, req, "Verification link has expired. Please request a new email change.", 400);
    }
    
    // Verify token
    if (validatePassword(req.query.token, user.salt, user.pendingEmailToken)) {
        const oldEmail = user.email;
        
        // Increment token version to invalidate old JWTs (security - email is in JWT payload)
        const newTokenVersion = (user.tokenVersion || 0) + 1;
        
        // Update email and clear pending fields
        await Users.findOneAndUpdate(
            { username: req.query.user },
            { 
                $set: { 
                    email: user.pendingEmail,
                    tokenVersion: newTokenVersion
                },
                $unset: { 
                    pendingEmail: "",
                    pendingEmailToken: "",
                    pendingEmailExpires: ""
                }
            }
        );
        
        // Get updated user and create new JWT with new email
        const updatedUser = await getUserByUsername(req.query.user);
        const jwtToken = createToken(updatedUser);
        
        // Set new JWT token cookie
        res.cookie("username", req.query.user, { 
            maxAge: ms("30 days")
        });
        res.cookie("token", jwtToken, { 
            maxAge: ms("30 days"),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Email Changed Successfully`,
                description: `User ${req.query.user} successfully verified and changed their email`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'User',
                        value: req.query.user,
                        inline: true
                    }
                ]
            }]
        }));
        
        // Notify old email about successful change
        sendEmail(oldEmail, "InfiniMii Email Changed", `Hi ${req.query.user}, your email has been successfully changed on InfiniMii. If this was not you, please contact support immediately by replying to this email.`);
        
        res.redirect(`/user/${encodeURIComponent(req.query.user)}`);
    }
    else {
        return await sendError(res, req, "Invalid verification token", 400);
    }
});

site.post('/deleteMii', async (req, res) => { // TODO: csrf here, make post
    try {
        if (!req.user) {
            return res.json({ error: "Not logged in" });
        }

        const actorUsername = req.user.username;
        const isModerator = canModerate(req.user);
        const miiId = String(req.body?.id || req.body?.miiId || req.query?.id || "").trim();

        if (!miiId) {
            return res.json({ error: "Mii ID required" });
        }

        // Try to find the Mii (could be public or private)
        const mii = await getMiiById(miiId, true);
        if (!mii) {
            return res.json({ error: "Mii not found" });
        }

        // Check permissions
        const isOwner = mii.uploader === actorUsername;
        if (!isOwner && !isModerator) {
            return res.json({ error: "Permission denied" });
        }

        const d = new Date();
        const imgPath = mii.private ? `./static/privateMiiImgs/${mii.id}.png` : `./static/miiImgs/${mii.id}.png`;

        let miiImageData;
        try {
            miiImageData = fs.readFileSync(imgPath);
        } catch (e) {
            miiImageData = null;
        }

        const attachments = miiImageData ? [{
            data: miiImageData,
            filename: `${mii.id}.png`,
            contentType: 'image/png'
        }] : [];

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (mii.official ? "Official " : "") + (mii.private ? "Private " : "Published ") + `Mii Deleted by ` + actorUsername,
                "description": mii.desc,
                "color": mii.private ? 0xff6600 : 0xff0000,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name || "Unknown",
                        "inline": true
                    },
                    {
                        "name": `${mii.official ? "Uploaded" : "Made"} by`,
                        "value": `[${mii.uploader}](https://infinimii.com/user/${encodeURIComponent(mii.uploader)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name (embedded in Mii file)`,
                        "value": mii.meta?.creatorName || "Unknown",
                        "inline": true
                    }
                ],
                ...(miiImageData ? {
                    "image": {
                        "url": `attachment://${mii.id}.png`
                    }
                } : {}),
                "footer": {
                    "text": `Deleted at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), attachments);

        // Delete from database and filesystem
        await Miis.findOneAndDelete({ id: miiId });
        deleteMiiAssets(mii.id, mii.private);

        const redirect = mii.private ? "/myPrivateMiis" : `/user/${encodeURIComponent(mii.uploader)}`;
        res.json({ okay: true, redirect });

        if (isModerator && !isOwner) {
            const uploader = await getUserByUsername(mii.uploader);
            if (uploader?.email) {
                sendEmail(
                    uploader.email,
                    `Mii Deleted - InfiniMii`,
                    `Hi ${mii.uploader}, one of your Miis "${mii.meta?.name || "Unknown"}" has been deleted by a Moderator. You can reply to this email to receive support.`
                );
            }
        }
    } catch (e) {
        console.error('Error deleting Mii:', e);
        res.json({ error: 'Server error' });
    }
});
// Update Mii Field (Moderator+, plus Researchers for official Miis)
site.post('/updateMiiField', requireAuth, async (req, res) => {
    try {
        const { id, field, value } = req.body;

        if (!id || !field || value === undefined) {
            return res.json({ error: 'Missing parameters' });
        }

        const mii = await getMiiById(id, true);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        const canUseModeratorTools = canModerate(req.user);
        const canResearchOfficial = isResearcher(req.user) && mii.official;
        if (!canUseModeratorTools && !canResearchOfficial) {
            return res.json({ error: 'Insufficient permissions' });
        }

        const isResearcherOnlyActor = canResearchOfficial && !canUseModeratorTools;
        const researcherAllowedFields = new Set(['name', 'desc', 'creatorName']);
        if (isResearcherOnlyActor && !researcherAllowedFields.has(field)) {
            return res.json({ error: 'Researchers can only edit name, description, and creator name on official Miis' });
        }

        // Store old value for logging
        let oldValue;
        let updates = {};

        // Update the appropriate field
        switch (field) {
            case 'name':
                oldValue = mii.meta.name;
                updates['meta.name'] = value;
                break;
            case 'desc':
                oldValue = mii.desc;
                updates.desc = value;
                break;
            case 'creatorName':
                oldValue = mii.meta.creatorName;
                updates['meta.creatorName'] = value;
                break;
            case 'uploader':
                // Validate new uploader exists
                const newUploader = await getUserByUsername(value);
                if (!newUploader) {
                    return res.json({ error: 'User does not exist' });
                }
                
                oldValue = mii.uploader;
                
                updates.uploader = value;
                if (mii.official) {
                    updates.officialSource = value;
                }
                break;
            default:
                return res.json({ error: 'Invalid field' });
        }

        await Miis.findOneAndUpdate({ id }, { $set: updates });

        const actorRoleLabel = isAdmin(req.user)
            ? 'Administrator'
            : (canUseModeratorTools ? 'Moderator' : 'Researcher');

        // Log to Discord
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Mii ${field} Updated`,
                description: `${actorRoleLabel} ${req.cookies.username} updated ${field}`,
                color: 0xFFA500,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                        inline: true
                    },
                    {
                        name: 'Field',
                        value: field,
                        inline: true
                    },
                    {
                        name: 'Old Value',
                        value: oldValue || 'N/A',
                        inline: false
                    },
                    {
                        name: 'New Value',
                        value: value,
                        inline: false
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${id}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error updating Mii field:', e);
        res.json({ error: 'Server error' });
    }
});
// Regenerate QR Code (Moderator only)
site.post('/regenerateQR', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    const { id } = req.body;
    const qrConsole = normalizeQrConsole(req.body?.qrConsole);
    const mii = await getMiiById(id, true);

    if (!mii) {
        return res.json({ error: 'Mii not found' });
    }

    // Regenerate the QR code
    const qrPath = mii.private ? `./static/privateMiiQRs/${id}.png` : `./static/miiQRs/${id}.png`;
    await writeQrPng(mii, qrPath, qrConsole);

    // Log to Discord
    makeReport(JSON.stringify({
        embeds: [{
            type: 'rich',
            title: `QR Code Regenerated`,
            description: `Moderator ${req.cookies.username} regenerated QR code`,
            color: 0x00AFF0,
            fields: [
                {
                    name: 'Mii',
                    value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                    inline: true
                }
            ],
            thumbnail: {
                url: `https://infinimii.com/miiImgs/${id}.png`
            }
        }]
    }));

    res.json({ okay: true });
});
// Add Role to User (Admin only)
site.post('/addUserRole', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const { username, role } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        if (!Object.values(ROLES).includes(role)) {
            return res.json({ error: 'Invalid role' });
        }

        addRole(targetUser, role);
        await Users.findOneAndUpdate({ username }, { roles: targetUser.roles });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Role Added to User`,
                description: `Administrator ${req.cookies.username} added a role`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Role Added',
                        value: ROLE_DISPLAY[role],
                        inline: true
                    },
                    {
                        name: 'Current Roles',
                        value: getUserRoles(targetUser).map(r => ROLE_DISPLAY[r]).join(', '),
                        inline: false
                    }
                ]
            }]
        }));
        if(['researcher','moderator','administrator'].includes(role.toLowerCase())){
            sendEmail(targetUser.email,`New Role Added - InfiniMii`,`Congratulations ${username}, you were made a ${role[0].toUpperCase()}${role.slice(1,role.length)} on InfiniMii!`);
        }

        res.json({ roles: targetUser.roles });
    } catch (e) {
        console.error('Error adding user role:', e);
        res.json({ error: 'Server error' });
    }
});

// Remove Role from User (Admin only)
site.post('/removeUserRole', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const { username, role } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }
        if (!Object.values(ROLES).includes(role)) {
            return res.json({ error: 'Invalid role' });
        }

        removeRole(targetUser, role);
        await Users.findOneAndUpdate({ username }, { roles: targetUser.roles });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Role Removed from User`,
                description: `Administrator ${req.cookies.username} removed a role`,
                color: 0xFF9900,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Role Removed',
                        value: ROLE_DISPLAY[role],
                        inline: true
                    },
                    {
                        name: 'Current Roles',
                        value: getUserRoles(targetUser).map(r => ROLE_DISPLAY[r]).join(', '),
                        inline: false
                    }
                ]
            }]
        }));

        res.json({ roles: targetUser.roles });
    } catch (e) {
        console.error('Error removing user role:', e);
        res.json({ error: 'Server error' });
    }
});

// Temporary Ban User (Moderator+)
site.post('/tempBanUser', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { username, hours, reason } = req.body;
        const targetUser = await getUserByUsername(username);
        const normalizedHours = Number(hours);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }
        if (!Number.isInteger(normalizedHours) || normalizedHours < 1 || normalizedHours > 24 * 365) {
            return res.json({ error: 'Hours must be an integer between 1 and 8760' });
        }

        // Moderators can't ban admins or other moderators
        if (!isAdmin(req.user) && canModerate(targetUser)) {
            return res.json({ error: 'Cannot ban moderators or administrators' });
        }

        addRole(targetUser, ROLES.TEMP_BANNED);
        const banExpires = Date.now() + (normalizedHours * 60 * 60 * 1000);
        
        await Users.findOneAndUpdate(
            { username },
            {
                $set: {
                    roles: targetUser.roles,
                    banExpires,
                    banReason: reason
                }
            }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `User Temporarily Banned`,
                description: `${req.cookies.username} temporarily banned a user`,
                color: 0xFF9900,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Duration',
                        value: `${normalizedHours} hours`,
                        inline: true
                    },
                    {
                        name: 'Reason',
                        value: reason || 'No reason provided',
                        inline: false
                    }
                ]
            }]
        }));
        sendEmail(targetUser.email,`Ban - InfiniMii`,`Hi ${username}, you were banned on InfiniMii for the next ${normalizedHours} hours. ${reason?`Reason: ${reason}`:`No reason was specified at this time.`} Understand that repeated violations may result in a permanent ban and account deletion. You may reply to this email for support.`);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error temp banning user:', e);
        res.json({ error: 'Server error' });
    }
});

// Permanent Ban User (Admin only)
site.post('/permBanUser', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const { username, reason } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        // If user records contain stored IP hashes, add them to the global deny list.
        const storedIpHashes = Array.isArray(targetUser.ipHashes)
            ? targetUser.ipHashes
                .filter(ip => typeof ip === "string" && ip.trim())
                .map(ip => ip.trim())
            : [];
        if (storedIpHashes.length > 0) {
            await updateSettings({ $addToSet: { bannedIPs: { $each: storedIpHashes } } });
        }

        // Delete all user's Miis (public + private)
        const userMiis = await Miis.find({ uploader: targetUser.username }).select('id private').lean();
        for (const mii of userMiis) {
            try {
                deleteMiiAssets(mii.id, Boolean(mii.private));
            } catch (e) {
                console.error(`Error deleting Mii ${mii.id}:`, e);
            }
        }
        await Miis.deleteMany({ uploader: targetUser.username });

        // Delete user account
        await Users.findOneAndDelete({ username });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `User Permanently Banned`,
                description: `${req.cookies.username} permanently banned a user`,
                color: 0xFF0000,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Miis Deleted',
                        value: userMiis.length.toString(),
                        inline: true
                    },
                    {
                        name: 'IP Banned',
                        value: storedIpHashes.length > 0 ? `Yes (${storedIpHashes.length} stored hash${storedIpHashes.length === 1 ? '' : 'es'})` : 'No stored IP data',
                        inline: true
                    },
                    {
                        name: 'Reason',
                        value: reason || 'No reason provided',
                        inline: false
                    }
                ]
            }]
        }));
        sendEmail(targetUser.email,`Permanent Ban - InfiniMii`,`Hi ${username}, due to repeated and/or serious violations of rules on InfiniMii, you have been permanently banned from the website. ${reason?`Reason: ${reason}`:`No reason was provided at this time.`} This will prevent you from making any new accounts in the future, and all uploaded Miis have been deleted. If you feel this is in error, you may reply to this email to receive support.`)

        res.json({ okay: true });
    } catch (e) {
        console.error('Error perm banning user:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete All User Miis (Moderator+)
site.post('/deleteAllUserMiis', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { username } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        const userMiis = await Miis.find({ uploader: targetUser.username }).select('id private').lean();
        let deletedCount = 0;

        for (const mii of userMiis) {
            try {
                deleteMiiAssets(mii.id, Boolean(mii.private));
                deletedCount++;
            } catch (e) {
                console.error(`Error deleting Mii ${mii.id}:`, e);
            }
        }
        await Miis.deleteMany({ uploader: targetUser.username });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `All User Miis Deleted`,
                description: `${req.cookies.username} deleted all Miis from user ${username}`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Miis Deleted',
                        value: deletedCount.toString(),
                        inline: true
                    }
                ]
            }]
        }));
        //There is very very little reason this will not precede a ban, so we're not going to bother emailing the user for this one.

        res.json({ deletedCount });
    } catch (e) {
        console.error('Error deleting all user Miis:', e);
        res.json({ error: 'Server error' });
    }
});

// Change Username (Moderator+)
site.post('/changeUsername', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { oldUsername, newUsername } = req.body;

        if (!validate(newUsername)) {
            return res.json({ error: 'Invalid username format' });
        }

        const existing = await getUserByUsername(newUsername);
        if (existing) {
            return res.json({ error: 'Username already taken' });
        }
        
        // Check if username is reserved
        const reserved = await ReservedUsername.findOne({ username: newUsername });
        if (reserved) {
            return res.json({ error: 'This username is reserved. Please try choose a different username.' });
        }

        const user = await getUserByUsername(oldUsername);
        if (!user) {
            return res.json({ error: 'User not found' });
        }
        
        // Reserve the old username for 30 days (JWT expiry period)
        const reserveUntil = new Date(Date.now() + ms('30 days'));
        try {
            await ReservedUsername.create({
                username: oldUsername,
                expiresAt: reserveUntil
            });
        } catch (e) {
            // Ignore duplicate key error - username already reserved
            if (e.code !== 11000) throw e;
        }
        
        // Increment token version to invalidate old tokens
        const newTokenVersion = (user.tokenVersion || 0) + 1;

        // Update username in User document
        await Users.findOneAndUpdate(
            { username: oldUsername },
            { 
                username: newUsername,
                tokenVersion: newTokenVersion,
                lastUsernameChange: Date.now()
            }
        );

        // Update uploader field in all user's Miis
        await Miis.updateMany(
            { uploader: oldUsername },
            { $set: { uploader: newUsername } }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Username Changed (Moderator)`,
                description: `${req.cookies.username} changed a username`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'Old Username',
                        value: oldUsername,
                        inline: true
                    },
                    {
                        name: 'New Username',
                        value: newUsername,
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(user.email,`Username Changed - InfiniMii`,`Hi ${oldUsername}, a moderator has changed your username to ${newUsername}. This will be what you login with moving forward. You can reply to this email to receive support.`);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing username:', e);
        res.json({ error: 'Server error' });
    }
});

// Toggle Mii Official Status (Moderator+)
site.post('/toggleMiiOfficial', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { id, official } = req.body;
        const officialInput = typeof official === "string" ? official.trim().toLowerCase() : official;
        const validOfficialInput =
            typeof officialInput === "boolean" ||
            officialInput === 0 ||
            officialInput === 1 ||
            ["true", "false", "1", "0", "yes", "no", "on", "off"].includes(officialInput);

        if (!id || official === undefined) {
            return res.json({ error: 'Missing parameters' });
        }
        if (!validOfficialInput) {
            return res.json({ error: 'Invalid official value' });
        }
        const normalizedOfficial = parseBooleanLike(official);

        const mii = await getMiiById(id, true);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        const oldStatus = mii.official;
        
        const toggleUpdates = { official: normalizedOfficial };
        if (normalizedOfficial && !mii.officialSource) {
            toggleUpdates.officialSource = mii.uploader;
        }
        await Miis.findOneAndUpdate(
            { id },
            { $set: toggleUpdates }
        );

        // Log to Discord
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title:  `Mii Marked as ${normalizedOfficial?'O':"Uno"}fficial`,
                description: `Moderator ${req.cookies.username} changed official status`,
                color: normalizedOfficial ? 0xFFD700 : 0x808080,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                        inline: true
                    },
                    {
                        name: 'Old Status',
                        value: oldStatus ? 'Official' : 'Not Official',
                        inline: true
                    },
                    {
                        name: 'New Status',
                        value: normalizedOfficial ? 'Official' : 'Not Official',
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${id}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error toggling official status:', e);
        res.json({ error: 'Server error' });
    }
});

// Main sitemap endpoint
site.get('/sitemap.xml', async (req, res) => {
    const urls = [
        {
            loc: baseUrl + '/',
            lastmod: new Date().toISOString().split('T')[0],
            changefreq: 'daily',
            priority: '1.0'
        },
        {
            loc: baseUrl + '/random',
            changefreq: 'always',
            priority: '0.8'
        },
        {
            loc: baseUrl + '/trending',
            changefreq: 'hourly',
            priority: '0.9'
        },
        {
            loc: baseUrl + '/top',
            changefreq: 'daily',
            priority: '0.9'
        },
        {
            loc: baseUrl + '/recent',
            changefreq: 'hourly',
            priority: '0.8'
        },
        {
            loc: baseUrl + '/official',
            changefreq: 'weekly',
            priority: '0.9'
        },
        {
            loc: baseUrl + '/search',
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: baseUrl + '/upload',
            changefreq: 'monthly',
            priority: '0.6'
        },
        {
            loc: baseUrl + '/convert',
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: baseUrl + '/qr',
            changefreq: 'monthly',
            priority: '0.7'
        }
    ];
    
    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// Mii-specific sitemap (separate for better organization)
site.get('/sitemap-miis.xml', async (req, res) => {
    // TODO: I believe that this xml must be linked to by the first one
    const urls = [];
    
    // Add all published Miis
    const allMiis = await getAllMiis(false);
    allMiis.forEach(mii => {
        const lastmod = mii.uploadedOn ? new Date(mii.uploadedOn).toISOString().split('T')[0] : new Date().toISOString().split('T')[0];
        
        urls.push({
            loc: `${baseUrl}/mii/${miiId}`,
            lastmod: lastmod,
            changefreq: 'weekly',
            priority: mii.official ? '0.9' : '0.7',
            images: [
                {
                    loc: `${baseUrl}/miiImgs/${miiId}.png`,
                    title: `${mii.meta.name} - Mii Character`,
                    caption: mii.desc || `${mii.meta.name} Mii character for Nintendo systems`
                },
                {
                    loc: `${baseUrl}/miiQRs/${miiId}.png`,
                    title: `${mii.meta.name} - QR Code`,
                    caption: `QR Code for ${mii.meta.name} - Scan with 3DS, Wii U, Tomodachi Life, or Miitomo`
                }
            ]
        });
    });
    
    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// // User profiles sitemap
// site.get('/sitemap-users.xml', async (req, res) => {
//     // TODO: I believe that this xml must be linked to by the first one
//     const urls = [];
//     const allUsers = await getAllUsers();
//     allUsers.forEach(user => {
//         if (user.username !== 'default' && user.username !== 'Nintendo') {
//             urls.push({
//                 loc: `${baseUrl}/user/${encodeURIComponent(user.username)}`,
//                 changefreq: 'weekly',
//                 priority: '0.6'
//             });
//         }
//     });
//     res.header('Content-Type', 'application/xml');
//     res.send(generateSitemapXML(urls));
// });

// Sitemap index
site.get('/sitemap-index.xml', async (req, res) => {
    // TODO: I believe that this xml must be linked to by the first one
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    
    const sitemaps = [
        { loc: `${baseUrl}/sitemap.xml`, lastmod: new Date().toISOString().split('T')[0] },
        { loc: `${baseUrl}/sitemap-miis.xml`, lastmod: new Date().toISOString().split('T')[0] },
        { loc: `${baseUrl}/sitemap-users.xml`, lastmod: new Date().toISOString().split('T')[0] }
    ];
    
    sitemaps.forEach(sitemap => {
        xml += '  <sitemap>\n';
        xml += `    <loc>${sitemap.loc}</loc>\n`;
        xml += `    <lastmod>${sitemap.lastmod}</lastmod>\n`;
        xml += '  </sitemap>\n';
    });
    
    xml += '</sitemapindex>';
    
    res.header('Content-Type', 'application/xml');
    res.send(xml);
});

// ========== AMIIBO ENDPOINTS ==========

// Amiibo tools page
site.get('/amiibo', async (req, res) => {
    ejs.renderFile('./ejsFiles/amiibo.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});

// Wiimote Mii extraction tools page
site.get('/wiimote', async (req, res) => {
    ejs.renderFile('./ejsFiles/wiimote.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});

site.post('/api/wiimote/importData', upload.single('miiFile'), async (req, res) => {
    try {
        let source = String(req.body.source || "").trim();
        if (!source) {
            if (req.file) source = "rcd";
            else if (typeof req.body.miiId === "string" && req.body.miiId.trim()) source = "miiId";
            else if (typeof req.body.miiData === "string" && req.body.miiData.trim()) source = "raw";
        }

        let miiInput;

        if (source === "miiId") {
            const resolved = await resolveMiiIdForImport(req.body.miiId, req);
            if (resolved.error) {
                res.status(400).json({ error: resolved.error });
                return;
            }

            miiInput = resolved.mii;
        } else if (source === "rcd") {
            if (!req.file) {
                res.status(400).json({ error: "No .rcd file uploaded" });
                return;
            }

            const originalExt = path.extname(req.file.originalname || "").toLowerCase();
            if (originalExt !== ".rcd") {
                res.status(400).json({ error: "Only .rcd files are supported for Wiimote import" });
                return;
            }

            miiInput = req.file.path;
        } else if (source === "raw") {
            const rawMiiData = String(req.body.miiData || "").trim();
            if (!rawMiiData) {
                res.status(400).json({ error: "No Mii data provided" });
                return;
            }

            miiInput = await createMiiData(rawMiiData);
        } else {
            res.status(400).json({ error: "Invalid import source" });
            return;
        }

        const miiInstance = await miijs.Mii.create(miiInput);
        const wiimoteData = miiInstance.encode("rcd");

        if (!wiimoteData || wiimoteData.length !== 74) {
            res.status(400).json({ error: "Converted Mii data is not valid for Wii Remote slots" });
            return;
        }

        res.json({
            miiData: Buffer.from(wiimoteData).toString("base64"),
            name: miiInstance?.fields?.meta?.name || "Unknown"
        });
    } catch (e) {
        console.error("Error preparing Wiimote import data:", e);
        res.status(500).json({ error: "Failed to prepare Mii for Wiimote import: " + e.message });
    } finally {
        if (req.file?.path) {
            try { fs.unlinkSync(req.file.path); } catch (cleanupError) { }
        }
    }
});

// Extract Mii from Amiibo
site.post('/extractMiiFromAmiibo', upload.single('amiibo'), async (req, res) => {
    try {
        if (!req.file) {
            res.json({ error: 'No Amiibo file uploaded' });
            return;
        }
        
        // Read the Amiibo dump
        const amiiboDump = fs.readFileSync("./uploads/" + req.file.filename);
        
        // Extract Mii data from the Amiibo dump
        const miiData = miijs.extractMiiFromAmiibo(amiiboDump);
        
        // Convert to JSON
        const mii = await createMiiData(miiData);
        
        // Generate ID and save temporarily
        const tempId = await genId();
        mii.id = tempId;
        mii.uploadedOn = Date.now();
        mii.uploader = "temp_" + tempId;
        mii.desc = "Extracted from Amiibo";
        mii.votes = 0;
        mii.official = false;
        
        // Render images with FFL - save to temp location
        const miiImage = await miijs.renderMii(mii);
        fs.writeFileSync("./static/miiImgs/" + tempId + ".png", miiImage);
        await writeQrPng(mii, "./static/miiQRs/" + tempId + ".png");
        
        // Also save the decrypted bin data for upload
        fs.writeFileSync("./static/temp/" + tempId + ".bin", miiData);
        
        // Clean up upload
        try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
        
        res.json({ mii: mii });
    } catch (e) {
    //     console.error('Error extracting Mii from Amiibo:', e); Commented because this block will be hit any time they don't upload a valid Amiibo
        try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
        res.json({ error: 'Failed to extract Mii from Amiibo: ' + e.message }); // TODO: don't send message
    }
});

// Insert Mii into Amiibo
// Insert Mii into Amiibo
site.post('/insertMiiIntoAmiibo', upload.fields([
    { name: 'amiibo', maxCount: 1 },
    { name: 'mii', maxCount: 1 }
]), async (req, res) => {
    try {
        if (!req.files.amiibo || !req.files.amiibo[0]) {
            res.json({ error: 'No Amiibo file uploaded' });
            return;
        }
        
        // Read the Amiibo dump
        const amiiboDump = fs.readFileSync(req.files.amiibo[0].path);
        
        let miiData;
        const miiFile = req.files.mii?.[0];
        const miiId = typeof req.body.miiId === "string" ? req.body.miiId.trim() : "";
        const rawMiiData = typeof req.body.miiData === "string" ? req.body.miiData.trim() : "";

        // Auto-detect Mii source by provided input so users do not need to specify a source type.
        if (miiFile?.path) {
            try {
                miiData = await createMiiData(miiFile.path);
            } catch (e) {
                res.json({ error: 'Failed to read Mii file: ' + e.message });
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e2) { }
                try { fs.unlinkSync(miiFile.path); } catch (e2) { }
                return;
            } finally {
                try { fs.unlinkSync(miiFile.path); } catch (e) { }
            }
        } else if (miiId) {
            const resolved = await resolveMiiIdForImport(miiId, req);
            if (resolved.error) {
                res.json({ error: resolved.error });
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
                return;
            }
            miiData = resolved.mii;
        } else if (rawMiiData) {
            try {
                miiData = await createMiiData(rawMiiData);
            } catch (e) {
                res.json({ error: 'Failed to parse pasted Mii data: ' + e.message });
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e2) { }
                return;
            }
        } else {
            res.json({ error: 'No Mii source provided. Upload a file, enter a Mii ID, or paste raw Mii data.' });
            try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
            return;
        }

        // Insert Mii into Amiibo
        const modifiedAmiibo = miijs.insertMiiIntoAmiibo(amiiboDump, miiData);
        
        // Clean up
        try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
        
        // Send modified Amiibo
        res.setHeader('Content-Disposition', 'attachment; filename="amiibo_modified.bin"');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(modifiedAmiibo);
        
    } catch (e) {
        console.error('Error inserting Mii into Amiibo:', e);
        try { 
            if (req.files.amiibo) fs.unlinkSync(req.files.amiibo[0].path);
            if (req.files.mii) fs.unlinkSync(req.files.mii[0].path);
        } catch (cleanupErr) { }
        res.json({ error: 'Failed to insert Mii into Amiibo: ' + e.message });
    }
});
// Upload extracted Amiibo Mii
site.post('/uploadExtractedAmiibo', async (req, res) => {
    try {
        // Check authentication
        if (!req.user) {
            res.json({error: "Please log in to upload Miis"});
            return;
        }
        const tempMiiId = req.body.miiId;
        
        // Check private Mii limit
        const privateMiisCount = await Miis.countDocuments({ uploader: req.user.username, private: true });
        if (privateMiisCount >= PRIVATE_MII_LIMIT) {
            res.json({error: `You have reached the limit of ${PRIVATE_MII_LIMIT} private Miis. Please publish or delete some before uploading more.`});
            return;
        }
        
        // Check if temporary files exist
        const tempImgPath = `./static/miiImgs/${tempMiiId}.png`;
        const tempQrPath = `./static/miiQRs/${tempMiiId}.png`;
        
        if (!fs.existsSync(tempImgPath) || !fs.existsSync(tempQrPath)) {
            res.json({error: "Extracted Mii data not found. Please extract again."});
            return;
        }

        // Create the Mii object from extracted QR first so we can duplicate-check before moving files.
        const mii = await createMiiData(tempQrPath);
        const matchingMii = await findMatchingMii(mii);
        if (matchingMii) {
            res.json({ error: getDuplicateMiiErrorMessage(matchingMii.id) });
            return;
        }

        // Generate new ID for the actual upload
        const newMiiId = await genId();

        // Move files from temp location to private folders
        fs.renameSync(tempImgPath, `./static/privateMiiImgs/${newMiiId}.png`);
        fs.renameSync(tempQrPath, `./static/privateMiiQRs/${newMiiId}.png`);

        mii.id = newMiiId;
        mii.uploadedOn = Date.now();
        mii.uploader = req.user.username;
        mii.desc = "Extracted from Amiibo";
        mii.votes = 1;
        mii.official = false;
        mii.published = false;
        mii.blockedFromPublishing = false;
        ensureUploadMiiPermissions(mii);
        
        // Store in database as private Mii
        await Miis.create({
            ...mii,
            id: newMiiId,
            private: true
        });
        await ensureUploaderAutoLike(req.user.username, newMiiId, 1);
        
        // Send to Discord for moderator review
        var d = new Date();
        const miiImagePath = `./static/privateMiiImgs/${newMiiId}.png`;
        const miiImageData = fs.readFileSync(miiImagePath);

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": `Private Mii Uploaded (Extracted from Amiibo)`,
                "description": mii.desc,
                "color": 0x00aaff,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name || "Unknown",
                        "inline": true
                    },
                    {
                        "name": `Uploaded by`,
                        "value": `[${req.user.username}](https://infinimii.com/user/${encodeURIComponent(req.user.username)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name`,
                        "value": mii.meta?.creatorName || "Unknown",
                        "inline": true
                    }
                ],
                "image": {
                    "url": `attachment://${newMiiId}.png`
                },
                "footer": {
                    "text": `View: https://infinimii.com/mii/${newMiiId} | Uploaded at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${newMiiId}.png`,
                contentType: 'image/png'
            }
        ]);
        
        // Redirect to private Miis page
        // res.redirect("/myPrivateMiis");
        res.json({ redirect: "/myPrivateMiis" }); 
        
    } catch (e) {
        console.error('Error uploading extracted Amiibo Mii:', e);
        res.json({error: "Server error: " + e.message});
    }
});

async function renderMiiEndpoint(req, res) {
    try {
        const miiData = req.body?.miiData || req.query?.miiData;
        
        if (!miiData) {
            res.status(400).json({ error: 'No Mii data provided' });
            return;
        }
        
        let mii;
        try {
            mii = await createMiiData(miiData);
        } catch (e) {
            res.status(400).json({ error: 'Invalid Mii data: ' + e.message });
            return;
        }

        // Render the Mii
        const miiImage = await miijs.renderMii(mii);
        const pngBuffer = Buffer.isBuffer(miiImage) ? miiImage : Buffer.from(miiImage);

        // miijs render output can vary by backend (BMP or PNG), so set MIME by magic bytes.
        let contentType = 'application/octet-stream';
        if (pngBuffer.length >= 2 && pngBuffer[0] === 0x42 && pngBuffer[1] === 0x4D) {
            contentType = 'image/bmp';
        } else if (
            pngBuffer.length >= 8 &&
            pngBuffer[0] === 0x89 &&
            pngBuffer[1] === 0x50 &&
            pngBuffer[2] === 0x4E &&
            pngBuffer[3] === 0x47
        ) {
            contentType = 'image/png';
        } else if (
            pngBuffer.length >= 3 &&
            pngBuffer[0] === 0xFF &&
            pngBuffer[1] === 0xD8 &&
            pngBuffer[2] === 0xFF
        ) {
            contentType = 'image/jpeg';
        }
        
        // Send rendered image bytes with correct MIME.
        res.setHeader('Content-Type', contentType);
        res.send(pngBuffer);
        
    } catch (e) {
        console.error('Error rendering Mii:', e);
        res.status(500).json({ error: 'Failed to render Mii: ' + e.message });
    }
}

// Render Mii from binary data
site.get('/render', async (req, res) => {
    await renderMiiEndpoint(req, res);
});
site.post('/render', async (req, res) => {
    await renderMiiEndpoint(req, res);
});
site.post('/api/renderMii', async (req, res) => {
    await renderMiiEndpoint(req, res);
});

// ========== DOWNLOAD / EXPORT ENDPOINTS ==========

// Unified export endpoint (by Mii ID)
site.get('/exportMii', async (req, res) => {
    await exportMiiById(req, res);
});

// Unified export endpoint (by uploaded file)
site.post('/exportMii', upload.single('mii'), async (req, res) => {
    try {
        const format = req.body.format;
        const normalized = normalizeExportFormat(format);
        if (!normalized) {
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
            res.json({ error: "Invalid format specified" });
            return;
        }

        const miiInput = req.file?.path || req.body.miiData;
        if (!miiInput) {
            res.json({ error: "No Mii data provided" });
            return;
        }

        const miiData = await createMiiData(miiInput);
        const miiName = miiData?.meta?.name || "mii";

        try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }

        await sendExportResponse(res, miiData, normalized, miiName, getExportOptionsFromRequest(req));
    } catch (e) {
        console.error("Error exporting Mii:", e);
        try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e2) { }
        res.json({ error: "Failed to export Mii: " + e.message });
    }
});

// Backwards-compatible endpoint
site.get('/downloadMii', async (req, res) => {
    await exportMiiById(req, res);
});

// Change User PFP (Moderator+)
site.post('/changeUserPfp', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { username, miiId } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        const mii = await getMiiById(miiId, false);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        await Users.findOneAndUpdate(
            { username },
            { miiPfp: miiId }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `User PFP Changed`,
                description: `${req.cookies.username} changed profile picture for ${username}`,
                color: 0x00CCFF,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'New PFP Mii ID',
                        value: miiId,
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${miiId}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing user PFP:', e);
        res.json({ error: 'Server error' });
    }
});
site.post('/voteMii', requireAuth, async (req, res) => {
    if (!req.query.id) {
        res.json({error: "No ID specified"});
        return;
    }
    try {
        const mii = await getMiiById(req.query.id, false);
        if (!mii) {
            res.json({error: "Mii not found"});
            return;
        }

        const isUploaderOrContributor = Boolean(
            req.user?.username &&
            (mii.uploader === req.user.username || mii.contributor === req.user.username)
        );
        if (isUploaderOrContributor) {
            await ensureUploaderAutoLike(req.user.username, req.query.id, 1);
            res.send("LockedLiked");
            return;
        }
        // Unlike (atomic)
        const unlikeResult = await Users.updateOne(
            { username: req.user.username, votedFor: req.query.id },
            { $pull: { votedFor: req.query.id } }
        );
        if (unlikeResult.modifiedCount > 0) {
            await Miis.updateOne(
                { id: req.query.id, votes: { $gt: 0 } },
                { $inc: { votes: -1 } }
            );
            res.send("Unliked");
            return;
        }

        // Like (atomic)
        const likeResult = await Users.updateOne(
            { username: req.user.username, votedFor: { $ne: req.query.id } },
            { $addToSet: { votedFor: req.query.id } }
        );
        if (likeResult.modifiedCount > 0) {
            await Miis.updateOne(
                { id: req.query.id },
                { $inc: { votes: 1 } }
            );
            res.send("Liked");
            return;
        }

        res.send("NoChange");
    }
    catch (e) {
        res.json({error: e}); // TOOD: don't send error
        return;
    }
});
site.get('/mii/:id', async (req, res) => {
    let inp = await getSendables(req);
    const miiId = req.params.id;
    
    // Try to get Mii (public or private)
    const mii = await getMiiById(miiId, true);
    
    if (!mii) {
        return sendError(res, req, "404 Mii not found", 404);
    }
    
    // Check access for private Miis
    if (mii.private) {
        const user = await getUserByUsername(req.cookies.username);
        const isModerator = user && canModerate(user);
        const isOwner = mii.uploader === req.cookies.username;
        
        if (!isOwner && !isModerator) {
            return sendError(res, req, "Access denied. This is a private Mii.", 403);
        }
        inp.isPrivate = true;
    } else {
        inp.isPrivate = false;
    }
    
    inp.mii = mii;
    inp.height=miijs.miiHeightToMeasurements(inp.mii.general.height);
    inp.weight=miijs.miiWeightToMeasurements(inp.mii.general.height,inp.mii.general.weight);
    const uploaderUser = await getUserByUsername(mii.uploader);
    inp.uploaderPfp = uploaderUser?.miiPfp || "00000";
    inp.officialSourceName = mii.official
        ? (normalizeCompanySourceName(mii.officialSource || mii.uploader) || DEFAULT_OFFICIAL_COMPANY_SOURCE)
        : "";
    inp.canEditOfficialMii = mii.official && (canModerate(req.user) || isResearcher(req.user));
    inp.canManageOfficialCategories = mii.official && isResearcher(req.user);

    // Override mii color for this page
    inp.userPfpMiiColor = mii.general.favoriteColor;

    // debugger

    ejs.renderFile('./ejsFiles/miiPage.ejs', inp, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/user/:username', async (req, res) => {
    const targetUsername = decodeURIComponent(req.params.username);
    const targetUser = await getUserByUsername(targetUsername);
    
    if (!targetUser) {
       return sendError(res, req, "User not found", 404);
    }
    if (targetUsername === "Nintendo") { // a s'ti mret hcraes a ton si odnetniN ,tnavelerrI :nortseK # comment preserved for posterity
        res.redirect('/official');
        return;
    }
    let inp = await getSendables(req);
    inp.targetUser = targetUser;
    const requestedPage = Number.parseInt(req.query.page, 10);
    const currentPageCandidate = Number.isFinite(requestedPage) && requestedPage > 0 ? requestedPage : 1;

    const profileFilter = {
        uploader: targetUsername,
        private: false,
        published: true
    };

    const [totalMiis, likeSummary] = await Promise.all([
        Miis.countDocuments(profileFilter),
        Miis.aggregate([
            { $match: profileFilter },
            { $group: { _id: null, totalLikes: { $sum: { $ifNull: ["$votes", 0] } } } }
        ])
    ]);

    const totalPages = Math.max(1, Math.ceil(totalMiis / profileMiisPerPage));
    const currentPage = Math.min(currentPageCandidate, totalPages);
    const skip = (currentPage - 1) * profileMiisPerPage;

    inp.displayedMiis = await Miis.find(profileFilter)
        .sort({ uploadedOn: -1, _id: -1 })
        .skip(skip)
        .limit(profileMiisPerPage)
        .lean();
    inp.profileStats = {
        totalMiis,
        totalLikes: likeSummary?.[0]?.totalLikes || 0
    };
    inp.pagination = {
        currentPage,
        totalPages,
        total: totalMiis,
        perPage: profileMiisPerPage
    };
    
    ejs.renderFile('./ejsFiles/userPage.ejs', inp, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/about', async (req, res) => {
    ejs.renderFile('./ejsFiles/about.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/privacy', async (req, res) => {
    ejs.renderFile('./ejsFiles/privacy.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/tos', async (req, res) => {
    ejs.renderFile('./ejsFiles/tos.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/guidelines', async (req, res) => {
    ejs.renderFile('./ejsFiles/guidelines.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/signup', async (req, res) => {
    ejs.renderFile('./ejsFiles/signup.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/login', async (req, res) => {
    const next = req.query.next || '/';

    ejs.renderFile('./ejsFiles/login.ejs', {
        next: next,
        ...(await getSendables(req))
    }, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});

site.get('/requestPasswordReset', async (req, res) => {
    ejs.renderFile('./ejsFiles/requestPasswordReset.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});

site.get('/resetPassword', async (req, res) => {
    const username = req.query.user;
    const token = req.query.token;
    
    ejs.renderFile('./ejsFiles/resetPassword.ejs', {
        username: username,
        token: token,
        ...(await getSendables(req))
    }, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});

site.get('/logout', async (req, res) => { // TODO: make this a POST request to prevent CSRF
    try {
        await res.clearCookie('username');
        await res.clearCookie('token');
        res.redirect("/");
    }
    catch (e) {
        console.log(e);
    }
});
site.get('/convert', async (req, res) => {
    ejs.renderFile('./ejsFiles/convert.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/calculator', async (req, res) => {
    ejs.renderFile('./ejsFiles/calc.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/miiChild', async (req, res) => {
    ejs.renderFile('./ejsFiles/miiChild.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/qr', async (req, res) => {
    ejs.renderFile('./ejsFiles/qr.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/settings', async (req, res) => {
    if (!req.user) {
        res.redirect("/");
        return;
    }
    var toSend= await getSendables(req);
    ejs.renderFile('./ejsFiles/settings.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/myPrivateMiis', requireAuth, async (req, res) => {
    var toSend = await getSendables(req, undefined, req.user);
    
    const privateMiis = await Miis.find({ uploader: req.user.username, private: true }).lean();

    toSend.privateMiis = privateMiis;
    toSend.privateLimit = PRIVATE_MII_LIMIT;
    
    ejs.renderFile('./ejsFiles/myPrivateMiis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/manageCategories', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    var toSend = await getSendables(req, undefined, req.user);
    const settings = await getSettings();
    toSend.officialCategories = settings.officialCategories || {};
    
    ejs.renderFile('./ejsFiles/manageCategories.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.post('/changePfp', requireAuth, async (req, res) => {
    if (req.body.id?.length > 0) {
        const mii = await getMiiById(req.body.id);
        if (mii) {
            await Users.findOneAndUpdate(
                { username: req.cookies.username },
                { $set: { miiPfp: req.body.id } }
            );
            res.json({ okay: true });
        } else {
            res.json({error: "Invalid Mii ID"});
        }
    }
    else {
        res.json({error: "Invalid Mii ID"});
    }
});
site.post('/changeUser', requireAuth, async (req, res) => {   // change username  
    const newUsername = req.body.newUser;
    const oldUsername = req.cookies.username;
    const existingUser = await getUserByUsername(newUsername);
    
    if (validate(newUsername) && !existingUser) {
        // Update all Miis uploaded by this user
        await Miis.updateMany(
            { uploader: oldUsername },
            { uploader: newUsername }
        );
        
        // Update username
        await Users.findOneAndUpdate(
            { username: oldUsername },
            { username: newUsername }
        );
        
        var d = new Date();
        const updatedUser = await getUserByUsername(newUsername);
        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": `Username Changed`,
                "description": `${oldUsername} is now ${newUsername}`,
                "color": 0xff0000,
                "thumbnail": {
                    "url": `https://infinimii.com/miiImgs/${updatedUser?.miiPfp || '00000'}.png`,
                    "height": 0,
                    "width": 0
                },
                "footer": {
                    "text": `Changed at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                },
                "url": `https://infinimii.com/user/${encodeURIComponent(newUsername)}`
            }]
        }));
        res.cookie('username', newUsername, { maxAge: ms("30 days") });
        res.json({ okay: true });
    }
    else {
        res.json({error: "Username invalid"});
    }
});
site.post('/changeHighlightedMii', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {    
    const miiId = req.body.id;
    if (miiId?.length > 0) {
        const mii = await getMiiById(miiId, false);
        if (!mii) {
            res.json({error: "Invalid Mii ID"});
            return;
        }
        
        const currentDate = new Date();
        await updateSettings({
            highlightedMii: miiId,
            highlightedMiiChangeDay: currentDate.getDate()
        });
        
        res.json({ okay: true });
        let miiImageData;
        try {
            miiImageData = fs.readFileSync(`./static/miiImgs/${mii.id}.png`);
        } catch(e) {
            try {
                miiImageData = fs.readFileSync(`./static/miiImgs/${mii.id}.png`);
            } catch(e2) {
                miiImageData = null;
            }
        }

        const attachments = miiImageData ? [{
            data: miiImageData,
            filename: `${mii.id}.png`,
            contentType: 'image/png'
        }] : [];

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (mii.official ? "Official " : "") + `Mii set as Highlighted Mii`,
                "description": mii.desc,
                "color": 0xff0000,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta.name,
                        "inline": true
                    },
                    {
                        "name": `Uploaded by`,
                        "value": `[${mii.uploader}](https://infinimii.com/user/${encodeURIComponent(mii.uploader)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name (embedded in Mii file)`,
                        "value": mii.meta.creatorName,
                        "inline": true
                    }
                ],
                ...(miiImageData ? {
                    "image": {
                        "url": `attachment://${mii.id}.png`
                    }
                } : {}),
                "footer": {
                    "text": `New Highlighted Mii set by ${req.cookies.username}`
                },
                "url": `https://infinimii.com/mii/` + mii.id
            }]
        }), attachments);
    }
    else {
        res.json({error: "Invalid Mii ID"});
    }
});
site.post('/reportMii', async (req,res)=>{
    const mii = await getMiiById(req.body.id, false);
    makeReport(JSON.stringify({
        embeds: [{
            "type": "rich",
            "title": (mii.official ? "Official " : "") + `Mii has been reported`,
            "description": req.body.what,
            "color": 0xff0000,
            "fields": [
                {
                    "name": `Mii Name`,
                    "value": mii.meta.name,
                    "inline": true
                },
                {
                    "name":"Description",
                    "value":mii.desc,
                    "inline":true
                },
                {
                    "name": `Uploaded by`,
                    "value": `[${mii.uploader}](https://infinimii.com/user/${encodeURIComponent(mii.uploader)})`,
                    "inline": true
                },
                {
                    "name": `Mii Creator Name (embedded in Mii file)`,
                    "value": mii.meta.creatorName,
                    "inline": true
                }
            ],
            "thumbnail": {
                "url": `https://infinimii.com/miiImgs/${mii.id}.png`,
                "height": 0,
                "width": 0
            },
            "footer": {
                "text": `Mii has been reported by ${req.cookies.username?req.cookies.username:"Anonymous"}`
            },
            "url": `https://infinimii.com/mii/` + mii.id
        }]
    }));
    res.json({ okay: true });
});
site.get('/miiWii',async (req,res)=>{
    const fetchedMii = await getMiiById(req.query.id, false);
    let miiInstance = await miijs.Mii.create(fetchedMii);
    if (parseBooleanLike(req.query.special)) {
        const specialFields = structuredClone(miiInstance.fields || {});
        if (!specialFields.meta || typeof specialFields.meta !== "object") {
            specialFields.meta = {};
        }
        specialFields.meta.type = "Special";
        miiInstance = await miijs.Mii.create(specialFields);
    }
    console.log(miiInstance.fields.meta.name);
    const miiBuffer = miiInstance.encode(miijs.MiiFormats.RSD);
    console.log(miiBuffer);
    console.log((await miijs.Mii.create(miiBuffer))?.fields?.meta?.name);
    res.setHeader('Content-Disposition', `attachment; filename="${req.query.id}.mii"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(miiBuffer);
});
site.get('/faq', async (req, res) => {
    ejs.renderFile('./ejsFiles/faq.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/cite', async (req, res) => {
    ejs.renderFile('./ejsFiles/cite.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
// Change Email (User)
site.post('/changeEmail', requireAuth, async (req, res) => {
    try {
        const { newEmail } = req.body;
        const oldEmail = req.user.email;

        // Basic email validation
        // TODO: real email validation with library
        if (!newEmail || !newEmail.includes('@') || !newEmail.includes('.')) {
            return res.json({ error: 'Invalid email format' });
        }

        // Check if new email is same as current
        if (req.user.email === newEmail) {
            return res.json({ error: 'New email is the same as current email' });
        }

        var token = genToken();
        let link = "https://infinimii.com/verifyEmailChange?user=" + encodeURIComponent(req.cookies.username) + "&token=" + encodeURIComponent(token);
        
        // Store pending email and verification token, but keep current email active
        // This way user can still login with their account even if they enter wrong email
        await Users.findOneAndUpdate(
            { username: req.cookies.username },
            { 
                $set: { 
                    pendingEmail: newEmail,
                    pendingEmailToken: hashPassword(token, req.user.salt).hash,
                    pendingEmailExpires: Date.now() + ms("24h")
                }
            }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Email Change Requested`,
                description: `User ${req.cookies.username} requested to change their email`,
                color: 0x00CCFF,
                fields: [
                    {
                        name: 'User',
                        value: req.cookies.username,
                        inline: true
                    }
                ]
            }]
        }));

        sendEmail(oldEmail, "InfiniMii Email Change Request", `Hi ${req.cookies.username}, we received a request to change your email on InfiniMii. If this was not you, please reply to this email to receive support.`);
        sendEmail(newEmail, "InfiniMii Email Verification", `Hi ${req.cookies.username}, we received a request to change your email on InfiniMii. Please verify your new email by clicking this link: ${link}. This link will expire in 24 hours. If this was not you, please ignore this email.`);


        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing email:', e);
        res.json({ error: 'Server error' });
    }
});

// Change Password (User)
site.post('/changePassword', requireAuth, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;

        // Verify old password
        if (!validatePassword(oldPassword, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Old password is incorrect' });
        }

        // Hash new password with existing salt
        const newHashed = hashPassword(newPassword, req.user.salt);

        // Increment token version to invalidate old tokens
        const newTokenVersion = (req.user.tokenVersion || 0) + 1;

        await Users.findOneAndUpdate(
            { username: req.cookies.username },
            { 
                pass: newHashed.hash,
                tokenVersion: newTokenVersion
            }
        );

        // Get updated user and create new JWT
        const updatedUser = await getUserByUsername(req.cookies.username);
        const newToken = createToken(updatedUser);

        // Set new JWT token cookie
        res.cookie("token", newToken, { 
            maxAge: ms("30 days"),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Password Changed`,
                description: `User ${req.cookies.username} changed their password`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'User',
                        value: req.cookies.username,
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`Password Changed - InfiniMii`,`Hi ${req.cookies.username}, your password was recently changed on InfiniMii. If this was not you, you can reply to this email to receive support.`);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing password:', e);
        res.json({ error: 'Server error' });
    }
});

// Reset Password (User)
site.post('/resetPassword', async (req, res) => {
    const { username, token, newPassword } = req.body;
    
    if (!username || !token || !newPassword) {
        return res.json({ error: 'Missing required fields' });
    }
            
    const user = await getUserByUsername(username);
    if (!user) {
        return res.json({ error: 'Invalid reset link' });
    }
    
    // Check if token is expired
    if (!user.resetPasswordExpires || user.resetPasswordExpires < Date.now()) {
        return res.json({ error: 'Reset link has expired. Please request a new one.' });
    }
    
    // Verify token
    const tokenHash = hashPassword(token, user.salt).hash;
    if (tokenHash !== user.resetPasswordToken) {
        return res.json({ error: 'Invalid reset link' });
    }
    
    // Hash new password and increment token version
    const newHashed = hashPassword(newPassword, user.salt);
    const newTokenVersion = (user.tokenVersion || 0) + 1;
    
    await Users.findOneAndUpdate(
        { username: username },
        { 
            pass: newHashed.hash,
            tokenVersion: newTokenVersion,
            resetPasswordToken: null,
            resetPasswordExpires: null
        }
    );
    
    sendEmail(user.email, 'Password Changed - InfiniMii',
        `Hi ${username},\n\nYour password was successfully reset. If you didn't do this, please reply to this email immediately.\n\nYou can now log in with your new password.`
    );
    
    makeReport(JSON.stringify({
        embeds: [{
            type: 'rich',
            title: `Password Reset Complete`,
            description: `User ${username} successfully reset their password`,
            color: 0x00FF00
        }]
    }));
    
    res.json({ message: 'Password reset successfully! You can now log in with your new password.', redirect: '/login' });
});

// Request Password Reset
site.post('/requestPasswordReset', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email || !validator.isEmail(email)) {
            return res.json({ error: 'Invalid email address' });
        }
        
        const normalizedEmail = validator.normalizeEmail(email);
        const user = await Users.findOne({ email: normalizedEmail });
        
        // Don't reveal if user exists for security
        if (!user) {
            return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
        }
        
        // Generate reset token
        const resetToken = genToken();
        const resetTokenHash = hashPassword(resetToken, user.salt).hash;
        const resetExpires = Date.now() + ms("1h");
        
        await Users.findOneAndUpdate(
            { username: user.username },
            { 
                resetPasswordToken: resetTokenHash,
                resetPasswordExpires: resetExpires
            }
        );
        
        const resetLink = `https://infinimii.com/resetPassword?user=${encodeURIComponent(user.username)}&token=${encodeURIComponent(resetToken)}`;
        
        sendEmail(normalizedEmail, 'Password Reset - InfiniMii', 
            `Hi ${user.username},\n` +
            `\n` +
            `We received a request to reset your password.\n` +
            `If you didn't request this, please ignore this email.\n` +
            `\n` +
            `${resetLink}\n`
        );
        
        res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    } catch (e) {
        console.error('Error requesting password reset:', e);
        res.json({ error: 'Server error' });
    }
});

// User Self-Service Username Change
site.post('/changeSelfUsername', requireAuth, async (req, res) => {
    try {
        const { newUsername, password } = req.body;
        
        // Verify password
        if (!validatePassword(password, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Incorrect password' });
        }
        
        // Validate new username
        if (!validate(newUsername)) {
            return res.json({ error: 'Invalid username format. Username must be 3-20 alphanumeric characters or underscores.' });
        }
        
        if (isBad(newUsername)) {
            return res.json({ error: 'Username contains inappropriate content' });
        }
        
        // Check if username change is allowed (once per month)
        const lastChange = req.user.lastUsernameChange || 0;
        const oneMonthAgo = Date.now() - ms("30 days");
        
        if (lastChange > oneMonthAgo) {
            const nextAllowed = new Date(lastChange + ms("30 days"));
            return res.json({ 
                error: `You can only change your username once per month. You can change it again on ${nextAllowed.toLocaleDateString()}.` 
            });
        }
        
        // Check if username is taken
        const existing = await getUserByUsername(newUsername);
        if (existing) {
            return res.json({ error: 'Username already taken' });
        }
        
        // Check if username is reserved
        const reserved = await ReservedUsername.findOne({ username: newUsername });
        if (reserved) {
            return res.json({ error: 'This username is temporarily unavailable. Please try again later or choose a different username.' });
        }
        
        // All checks fine, swap usernames
        const oldUsername = req.user.username;
        
        // Reserve the old username for 30 days (JWT expiry period)
        const reserveUntil = new Date(Date.now() + ms("30 days"));
        await ReservedUsername.create({
            username: oldUsername,
            expiresAt: reserveUntil
        }).catch(()=>{});
        
        // Increment token version to invalidate old tokens
        const newTokenVersion = (req.user.tokenVersion || 0) + 1;
        
        // Update username
        await Users.findOneAndUpdate(
            { username: oldUsername },
            { 
                username: newUsername,
                lastUsernameChange: Date.now(),
                tokenVersion: newTokenVersion
            }
        );
        
        // Update uploader field in all user's Miis
        await Miis.updateMany(
            { uploader: oldUsername },
            { uploader: newUsername }
        );
        
        // Get updated user and create new JWT
        const updatedUser = await getUserByUsername(newUsername);
        const newToken = createToken(updatedUser);
        
        // Set new JWT token and username cookies
        res.cookie('token', newToken, {
            maxAge: ms("30 days"),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        res.cookie('username', newUsername, {
            maxAge: ms("30 days")
        });
        
        sendEmail(req.user.email, 'Username Changed - InfiniMii',
            `Hi ${oldUsername},\n\nYour username has been changed to ${newUsername}. This is what you'll use to log in from now on.\n\nYou won't be able to change your username again for 30 days.\n\nIf you didn't make this change, please reply to this email immediately.`
        );
        
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Self Username Changed`,
                description: `User changed their username`,
                color: 0x00AAFF,
                fields: [
                    {
                        name: 'Old Username',
                        value: oldUsername,
                        inline: true
                    },
                    {
                        name: 'New Username',
                        value: newUsername,
                        inline: true
                    }
                ]
            }]
        }));
        
        res.json({ message: 'Username changed successfully!', redirect: '/settings' });
    } catch (e) {
        console.error('Error changing username:', e);
        res.json({ error: 'Server error' });
    }
});


// Delete All User's Miis (User - own miis only)
site.post('/deleteAllMyMiis', requireAuth, async (req, res) => {
    try {
        const miis = await Miis.find({ uploader: req.user.username, private: false, published: true }).lean();
        const miiIds = miis.map(m => m.id);
        let deletedCount = 0;

        for (const miiId of miiIds) {
            try {
                const mii = await getMiiById(miiId, false);
                if (mii) {
                    // Delete files
                    try { fs.unlinkSync(`./static/miiImgs/${miiId}.png`); } catch(e) {}
                    try { fs.unlinkSync(`./static/miiQRs/${miiId}.png`); } catch(e) {}
                    
                    // Delete Mii from database
                    await Miis.deleteOne({ id: miiId });
                    deletedCount++;
                }
            } catch(e) {
                console.error(`Error deleting Mii ${miiId}:`, e);
            }
        }

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `User Deleted All Their Miis`,
                description: `${req.cookies.username} deleted all their own Miis`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'User',
                        value: req.cookies.username,
                        inline: true
                    },
                    {
                        name: 'Miis Deleted',
                        value: deletedCount.toString(),
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`All Miis Deleted - InfiniMii`,`Hi ${req.cookies.username}, we received a request to delete all of your Miis. If this wasn't you, reply to this email to receive support.`);
        res.json({ deletedCount });
    } catch (e) {
        console.error('Error deleting all user Miis:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete Account (User)
site.post('/deleteAccount', requireAuth, async (req, res) => {
    try {
        const username = req.user.username;
        const { password } = req.body;

        // Verify password
        if (!validatePassword(password, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Password is incorrect' });
        }

        // Transfer Miis to a special "Deleted User" account
        let deletedUser = await getUserByUsername("[Deleted User]");
        if (!deletedUser) {
            await Users.create({
                username: "[Deleted User]",
                salt: "",
                pass: "",
                creationDate: Date.now(),
                email: "",
                votedFor: [],
                miiPfp: "00000",
                roles: [ROLES.BASIC],
            });
        }

        // Transfer all Miis to deleted user account
        await Miis.updateMany(
            { uploader: username },
            { uploader: "[Deleted User]" }
        );

        // Delete user account
        await Users.deleteOne({ username });

        // Clear cookies
        res.clearCookie('username');
        res.clearCookie('token');

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Account Deleted`,
                description: `User ${username} deleted their account`,
                color: 0xFF0000,
                fields: [
                    {
                        name: 'Username',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Miis Transferred',
                        value: (await Miis.countDocuments({ uploader: username })).toString(),
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`Account Deleted - InfiniMii`,`Hi ${req.cookies.username}, we received a request to delete your account. We're sorry to see you go! If this wasn't you, please reply to this email to receive support.`)
        res.json({ okay: true });
    } catch (e) {
        console.error('Error deleting account:', e);
        res.json({ error: 'Server error' });
    }
});

async function handleGetInstructionsRequest(req, res, { allowFile = false } = {}) {
    try {
        const source = req.method === "GET" ? req.query : req.body;
        const instructionConsole = normalizeInstructionConsole(source?.console || source?.format);

        const miiInput = await resolveMiiInputForInstructions(req, { allowFile });
        if (!miiInput) {
            res.json({ error: "No Mii data provided" });
            return;
        }

        const mii = await createMiiData(miiInput);
        const consoleType = miijs.ConsoleFormats?.[instructionConsole] || instructionConsole;
        const instructions = miijs.makeInstructions(mii, consoleType);

        res.json({
            instructions,
            miiName: mii?.meta?.name || "Unknown",
            console: instructionConsole
        });
    } catch (e) {
        console.error('Error generating instructions:', e);
        res.json({ error: 'Failed to generate instructions: ' + e.message });
    } finally {
        if (allowFile && req.file?.path) {
            try { fs.unlinkSync(req.file.path); } catch (cleanupError) { }
        }
    }
}

site.get('/getInstructions', async (req, res) => {
    await handleGetInstructionsRequest(req, res);
});

site.post('/getInstructions', upload.single('mii'), async (req, res) => {
    await handleGetInstructionsRequest(req, res, { allowFile: true });
});

site.post('/uploadMii', requireAuth, upload.single('mii'), async (req, res) => {
    try {
        const uploader = req.user.username;
        const isOfficialUpload = parseBooleanLike(req.body.official);
        let wantsPublic = req.body.makePublic === 'on' || req.body.makePublic === true || req.body.makePublic === 'true';
        let officialSource = null;
        let officialSourceNotice = null;
        let officialSettings = null;
        const rawMiiDataInput = typeof req.body.miiData === "string" ? req.body.miiData : "";
        const normalizedRawMiiData = rawMiiDataInput.replace(/\s+/g, "");
        const providedMiiName = typeof req.body.miiName === "string" ? req.body.miiName.trim() : "";
        const isNinetyTwoCharCode = normalizedRawMiiData.length === 92;

        // Check if trying to upload official Mii without permission
        if (isOfficialUpload && !canUploadOfficial(req.user)) {
            res.json({'error': 'Only Researchers and Administrators can upload official Miis'});
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
            return;
        }
        if (isOfficialUpload) {
            wantsPublic = true;
            officialSettings = await getSettings();

            const sourceResolution = await resolveOfficialCompanySourceForUpload(req, officialSettings);
            if (sourceResolution.error) {
                res.json({ error: sourceResolution.error });
                try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
                return;
            }

            officialSource = sourceResolution.sourceName;
            officialSourceNotice = sourceResolution.notice;
        }

        // Check private Mii limit
        if (!wantsPublic) {
            const privateMiisCount = await Miis.countDocuments({ uploader: req.user.username, private: true });
            if (privateMiisCount >= Number(PRIVATE_MII_LIMIT)) {
                res.json({error: `You have reached the limit of ${PRIVATE_MII_LIMIT} private Miis. Please publish or delete some before uploading more.`});
                try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
                return;
            }
        }

        if (isNinetyTwoCharCode && !providedMiiName) {
            res.json({ error: "Please enter a name for 92-character Mii Studio codes." });
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
            return;
        }
        
        // TODO: catch errors here and request that they make sure they selected the right upload type

        let mii;
        try {
            const fromAmiiboId = typeof req.body.fromAmiibo === "string" ? req.body.fromAmiibo.trim() : "";

            if (fromAmiiboId && !req.file && !req.body.miiData) {
                // Uploading from Amiibo extraction
                const tempMiiId = fromAmiiboId;
                const tempBinPath = `./static/temp/${tempMiiId}.bin`;

                if (!fs.existsSync(tempBinPath)) {
                    res.json({ error: 'Amiibo Mii data not found. Please extract again.' });
                    return;
                }

                try {
                    mii = await createMiiData(tempBinPath);

                    // Clean up temp files
                    try { fs.unlinkSync(tempBinPath); } catch (e) { }
                    try { fs.unlinkSync(`./static/miiImgs/${tempMiiId}.png`); } catch (e) { }
                    try { fs.unlinkSync(`./static/miiQRs/${tempMiiId}.png`); } catch (e) { }
                } catch (e) {
                    console.error('Error reading Amiibo Mii:', e);
                    res.json({ error: `Invalid Amiibo Mii data: ${e.message}` });
                    return;
                }
            }
            else {
                if (req.body.miiData) {
                    mii = await createMiiData(req.body.miiData);
                } else {
                    if (!req.file) {
                        res.json({ error: 'No file uploaded' });
                        return;
                    }
                    mii = await createMiiData(req.file.path);
                }
            }
        } catch (e) {
            console.error('Error processing Mii file:', e);
            res.json({error: `Failed to process file. Please double-check that you selected the correct file. ${e.message || ''}`});
            return;
        } finally {
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
        }

        if (isNinetyTwoCharCode && providedMiiName) {
            if (!mii.meta || typeof mii.meta !== "object") {
                mii.meta = {};
            }
            mii.meta.name = providedMiiName;
        }

        const matchingMii = await findMatchingMii(mii);
        if (matchingMii) {
            res.json({ error: getDuplicateMiiErrorMessage(matchingMii.id) });
            return;
        }

        // Add official Mii categorization
        if (isOfficialUpload) {
            mii.officialCategories = [];
            
            const validLeafPaths = getLeafCategoryPathSet(
                getOfficialCategoryTree(officialSettings || await getSettings())
            );
            mii.officialCategories = normalizeCategoryPaths(req.body.categories)
                .filter(path => validLeafPaths.has(path));
        } else {
            mii.officialCategories = [];
        }
        
        mii.id = await genId();
        mii.uploadedOn = Date.now();
        mii.uploader = isOfficialUpload ? officialSource : uploader;
        mii.contributor = isOfficialUpload ? uploader : undefined;
        mii.officialSource = isOfficialUpload ? officialSource : undefined;
        mii.desc = req.body.desc;
        mii.votes = 1;
        mii.official = isOfficialUpload;
        mii.published = wantsPublic;
        mii.blockedFromPublishing = false;
        ensureUploadMiiPermissions(mii);
        
        // Save to correct folders
        const miiImageData = await miijs.renderMii(mii);
        if (wantsPublic) {
            fs.writeFileSync("./static/miiImgs/" + mii.id + ".png", miiImageData);
            await writeQrPng(mii, "./static/miiQRs/" + mii.id + ".png");
        } else {
            fs.writeFileSync("./static/privateMiiImgs/" + mii.id + ".png", miiImageData);
            await writeQrPng(mii, "./static/privateMiiQRs/" + mii.id + ".png");
        }
        
        // Store in database
        await Miis.create({
            ...mii,
            id: mii.id,
            private: !wantsPublic
        });
        await ensureUploaderAutoLike(uploader, mii.id, 1);
        
        // Send to Discord for moderator review
        var d = new Date();
        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (isOfficialUpload ? "Official " : "") + `${wantsPublic ? "Public" : "Private"} Mii Uploaded`,
                "description": mii.desc,
                "color": 0x00aaff,
                "fields": isOfficialUpload
                    ? [
                        {
                            "name": `Mii Name`,
                            "value": mii.meta?.name || "Unknown",
                            "inline": true
                        },
                        {
                            "name": "Official Source",
                            "value": `[${officialSource}](https://infinimii.com/user/${encodeURIComponent(officialSource)})`,
                            "inline": true
                        },
                        {
                            "name": "Contributed by",
                            "value": `[${uploader}](https://infinimii.com/user/${encodeURIComponent(uploader)})`,
                            "inline": true
                        },
                        {
                            "name": `Mii Creator Name`,
                            "value": mii.meta?.creatorName || "Unknown",
                            "inline": true
                        }
                    ]
                    : [
                        {
                            "name": `Mii Name`,
                            "value": mii.meta?.name || "Unknown",
                            "inline": true
                        },
                        {
                            "name": `Uploaded by`,
                            "value": `[${uploader}](https://infinimii.com/user/${encodeURIComponent(uploader)})`,
                            "inline": true
                        },
                        {
                            "name": `Mii Creator Name`,
                            "value": mii.meta?.creatorName || "Unknown",
                            "inline": true
                        }
                    ],
                "image": {
                    "url": `attachment://${mii.id}.png`
                },
                "footer": {
                    "text": `View: https://infinimii.com/mii/${mii.id} | Uploaded at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${mii.id}.png`,
                contentType: 'image/png'
            }
        ]);
        
        setTimeout(() => {
            const responsePayload = {
                redirect: isOfficialUpload ? "/official" : "/myPrivateMiis"
            };
            if (officialSourceNotice) {
                responsePayload.notice = officialSourceNotice;
            }
            res.json(responsePayload);
        }, 2000); // TODO: jank

        // TODO: does rendering lag this? If so, 

    } catch (e) {
        console.error('Error uploading Mii:', e);
        res.json({error: `Server error while uploading. Please verify you uploaded the right file and try again.`});
        try { if (req.file) fs.unlinkSync("./uploads/" + req.file.filename); } catch (e2) { }
    }
});
// Update Official Mii Categories (Researcher+)
site.post('/updateOfficialCategories', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { miiId, categories } = req.body;

        if (!miiId || !Array.isArray(categories)) {
            return res.json({ error: 'Missing parameters' });
        }

        const mii = await getMiiById(miiId, false);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        if (!mii.official) {
            return res.json({ error: 'This is not an official Mii' });
        }

        const oldCategories = mii.officialCategories || [];
        const requestedCategories = normalizeCategoryPaths(categories);
        const settings = await getSettings();
        const categoryTree = getOfficialCategoryTree(settings);
        const validLeafPaths = getLeafCategoryPathSet(categoryTree);
        const newCategories = requestedCategories.filter(path => validLeafPaths.has(path));

        if (newCategories.length !== requestedCategories.length) {
            return res.json({ error: 'One or more categories are invalid. Only existing leaf categories can be assigned.' });
        }
        
        await Miis.findOneAndUpdate(
            { id: miiId },
            { $set: { officialCategories: newCategories } }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Official Mii Categories Updated`,
                description: `${req.cookies.username} updated categories for an official Mii`,
                color: 0x00AAFF,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta?.name || "Unknown"}](https://infinimii.com/mii/${miiId})`,
                        inline: true
                    },
                    {
                        name: 'Old Categories',
                        value: oldCategories.length ? oldCategories.join(', ') : 'None',
                        inline: false
                    },
                    {
                        name: 'New Categories',
                        value: newCategories.length ? newCategories.join(', ') : 'None',
                        inline: false
                    }
                ]
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error updating official categories:', e);
        res.json({ error: 'Server error' });
    }
});

// Get global Mii tags
site.get('/getMiiTags', async (req, res) => {
    try {
        const settings = await getSettings();
        res.json({ tags: getMiiTags(settings) });
    } catch (e) {
        console.error('Error getting Mii tags:', e);
        res.json({ error: 'Server error' });
    }
});

// Add a new global Mii tag (Moderator+)
site.post('/addMiiTag', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const rawTag = typeof req.body?.tag === "string" ? req.body.tag : "";
        const tag = normalizeTagValue(rawTag);

        if (!tag) {
            return res.json({ error: 'Tag name required' });
        }
        if (tag.includes(',')) {
            return res.json({ error: 'Tag names cannot include commas' });
        }
        if (tag.length > MAX_MII_TAG_LENGTH) {
            return res.json({ error: `Tag names must be ${MAX_MII_TAG_LENGTH} characters or fewer` });
        }

        const settings = await getSettings();
        const tags = getMiiTags(settings);
        const exists = tags.some(existing => existing.toLowerCase() === tag.toLowerCase());

        if (exists) {
            return res.json({ error: 'Tag already exists' });
        }

        tags.push(tag);
        tags.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        await updateSettings({ miiTags: tags });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Mii Tag Created`,
                description: `${req.cookies.username} created a new Mii tag`,
                color: 0x00AAFF,
                fields: [
                    {
                        name: 'Tag',
                        value: tag,
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ okay: true, tags });
    } catch (e) {
        console.error('Error adding Mii tag:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete a global Mii tag and remove it from all Miis (Moderator+)
site.post('/deleteMiiTag', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const rawTag = typeof req.body?.tag === "string" ? req.body.tag : "";
        const requestedTag = normalizeTagValue(rawTag);

        if (!requestedTag) {
            return res.json({ error: 'Tag name required' });
        }

        const settings = await getSettings();
        const tags = getMiiTags(settings);
        const tagToDelete = tags.find(tag => tag.toLowerCase() === requestedTag.toLowerCase());

        if (!tagToDelete) {
            return res.json({ error: 'Tag not found' });
        }

        const nextTags = tags.filter(tag => tag.toLowerCase() !== requestedTag.toLowerCase());
        await updateSettings({ miiTags: nextTags });

        const updateResult = await Miis.updateMany(
            { tags: tagToDelete },
            { $pull: { tags: tagToDelete } }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Mii Tag Deleted`,
                description: `${req.cookies.username} deleted a Mii tag`,
                color: 0xFF9900,
                fields: [
                    {
                        name: 'Tag',
                        value: tagToDelete,
                        inline: true
                    },
                    {
                        name: 'Miis Updated',
                        value: String(updateResult?.modifiedCount || 0),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ okay: true, tags: nextTags, updatedMiis: updateResult?.modifiedCount || 0 });
    } catch (e) {
        console.error('Error deleting Mii tag:', e);
        res.json({ error: 'Server error' });
    }
});

// Update tag assignments for a Mii (Moderator+)
site.post('/updateMiiTags', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const miiId = typeof req.body?.miiId === "string" ? req.body.miiId.trim() : "";
        const rawTags = req.body?.tags;

        if (!miiId) {
            return res.json({ error: 'Missing Mii ID' });
        }
        if (!Array.isArray(rawTags)) {
            return res.json({ error: 'Tags must be an array' });
        }

        const mii = await getMiiById(miiId, true);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        const settings = await getSettings();
        const availableTags = getMiiTags(settings);
        const requestedTags = normalizeTagList(rawTags);
        const normalizedTags = mapRequestedTagsToCatalog(requestedTags, availableTags);

        if (normalizedTags.length !== requestedTags.length) {
            return res.json({ error: 'One or more tags are invalid. Please use only existing tags.' });
        }

        const oldTags = normalizeTagList(mii.tags || []);

        await Miis.findOneAndUpdate(
            { id: miiId },
            { $set: { tags: normalizedTags } }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Mii Tags Updated`,
                description: `${req.cookies.username} updated tags for a Mii`,
                color: 0x00AAFF,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta?.name || "Unknown"}](https://infinimii.com/mii/${miiId})`,
                        inline: true
                    },
                    {
                        name: 'Old Tags',
                        value: oldTags.length ? oldTags.join(', ') : 'None',
                        inline: false
                    },
                    {
                        name: 'New Tags',
                        value: normalizedTags.length ? normalizedTags.join(', ') : 'None',
                        inline: false
                    }
                ]
            }]
        }));

        res.json({ okay: true, tags: normalizedTags });
    } catch (e) {
        console.error('Error updating Mii tags:', e);
        res.json({ error: 'Server error' });
    }
});

// Get all official categories (nested structure)
site.get('/getOfficialCategories', async (req, res) => {
    try {
        const settings = await getSettings();
        res.json({ categories: { categories: getOfficialCategoryTree(settings) } });
    } catch (e) {
        console.error('Error getting categories:', e);
        res.json({ error: 'Server error' });
    }
});

// Add new category (can be root or nested under a parent)
site.post('/addCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { name, color, parentPath } = req.body;

        if (!name || !name.trim()) {
            return res.json({ error: 'Category name required' });
        }

        const categoryName = name.trim();
        if (categoryName.includes('/')) {
            return res.json({ error: 'Category names cannot include "/"' });
        }
        const categoryColor = normalizeCategoryColor(color);
        const normalizedParentPath = typeof parentPath === "string" && parentPath.trim() ? parentPath.trim() : null;
        
        const settings = await getSettings();
        const categoryTree = getOfficialCategoryTree(settings);
        // Determine where to add the category
        let targetArray;
        let newPath;
        
        if (!normalizedParentPath) {
            // Add as root category
            targetArray = categoryTree;
            newPath = categoryName;
            
            // Check if already exists at root
            if (targetArray.find(c => c.name === categoryName)) {
                return res.json({ error: 'Category already exists at this level' });
            }
        } else {
            // Add as child of parent
            const parent = findCategoryByPath(normalizedParentPath, categoryTree);
            if (!parent) {
                return res.json({ error: 'Parent category not found' });
            }
            if (!Array.isArray(parent.children)) {
                parent.children = [];
            }
            
            targetArray = parent.children;
            newPath = `${normalizedParentPath}/${categoryName}`;
            
            // Check if already exists under this parent
            if (targetArray.find(c => c.name === categoryName)) {
                return res.json({ error: 'Category already exists under this parent' });
            }
        }

        const newCategory = {
            name: categoryName,
            color: categoryColor,
            path: newPath,
            children: []
        };
        
        targetArray.push(newCategory);

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `New Category Created`,
                description: `${req.cookies.username} created a new category`,
                color: parseInt(categoryColor.replace('#', ''), 16),
                fields: [
                    {
                        name: 'Category Name',
                        value: categoryName,
                        inline: true
                    },
                    {
                        name: 'Path',
                        value: newPath,
                        inline: true
                    },
                    {
                        name: 'Parent',
                        value: normalizedParentPath || 'Root',
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: categoryTree });
    } catch (e) {
        console.error('Error adding category:', e);
        res.json({ error: 'Server error' });
    }
});

// Rename category and update all Miis using it or its descendants
site.post('/renameCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { path, newName } = req.body;
        const normalizedPath = typeof path === "string" ? path.trim() : "";
        const newNameTrimmed = typeof newName === "string" ? newName.trim() : "";

        if (!normalizedPath || !newNameTrimmed) {
            return res.json({ error: 'Path and new name required' });
        }
        if (newNameTrimmed.includes('/')) {
            return res.json({ error: 'Category names cannot include "/"' });
        }

        const settings = await getSettings();
        const categoryTree = getOfficialCategoryTree(settings);
        const category = findCategoryByPath(normalizedPath, categoryTree);
        if (!category) {
            return res.json({ error: 'Category not found' });
        }

        const oldName = category.name;
        const oldPath = category.path;

        // Check if sibling with same name exists
        const parent = findParentByChildPath(normalizedPath, categoryTree);
        const siblings = parent ? parent.children : categoryTree;
        if (siblings.find(c => c.name === newNameTrimmed && c.path !== normalizedPath)) {
            return res.json({ error: 'A category with this name already exists at this level' });
        }

        // Get all paths that will change (this category and all descendants)
        const pathsToUpdate = getAllDescendantPaths(category);
        
        // Update the name
        category.name = newNameTrimmed;
        
        // Rebuild paths for this category and all descendants
        const parentPath = parent?.path || "";
        updateCategoryPaths(category, parentPath);
        
        // Get new paths after update
        const newPaths = getAllDescendantPaths(category);
        
        // Update all Miis that use any of these paths
        let totalUpdated = 0;
        for (let i = 0; i < pathsToUpdate.length; i++) {
            const updated = await renameCategoryInAllMiis(pathsToUpdate[i], newPaths[i]);
            totalUpdated += updated;
        }

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Category Renamed`,
                description: `${req.cookies.username} renamed a category`,
                color: parseInt(category.color?.replace('#', '') || '999999', 16),
                fields: [
                    {
                        name: 'Old Name',
                        value: oldName,
                        inline: true
                    },
                    {
                        name: 'New Name',
                        value: newNameTrimmed,
                        inline: true
                    },
                    {
                        name: 'Old Path',
                        value: oldPath,
                        inline: false
                    },
                    {
                        name: 'New Path',
                        value: category.path,
                        inline: false
                    },
                    {
                        name: 'Miis Updated',
                        value: totalUpdated.toString(),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: categoryTree, updatedMiis: totalUpdated });
    } catch (e) {
        console.error('Error renaming category:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete category and all its descendants, remove from all Miis
site.post('/deleteCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { path } = req.body;
        const normalizedPath = typeof path === "string" ? path.trim() : "";

        if (!normalizedPath) {
            return res.json({ error: 'Category path required' });
        }

        const settings = await getSettings();
        const categoryTree = getOfficialCategoryTree(settings);
        const category = findCategoryByPath(normalizedPath, categoryTree);
        if (!category) {
            return res.json({ error: 'Category not found' });
        }

        // Get all paths to remove (category and all descendants)
        const pathsToRemove = getAllDescendantPaths(category);
        
        // Remove from parent's children array
        const parent = findParentByChildPath(normalizedPath, categoryTree);
        if (parent) {
            parent.children = parent.children.filter(c => c.path !== normalizedPath);
        } else {
            // Remove from root
            const rootIndex = categoryTree.findIndex(c => c.path === normalizedPath);
            if (rootIndex > -1) categoryTree.splice(rootIndex, 1);
        }
        
        // Remove all paths from all Miis
        let totalUpdated = 0;
        for (const pathToRemove of pathsToRemove) {
            const updated = await removeCategoryFromAllMiis(pathToRemove);
            totalUpdated += updated;
        }

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Category Deleted`,
                description: `${req.cookies.username} deleted a category and all its descendants`,
                color: 0xFF0000,
                fields: [
                    {
                        name: 'Category',
                        value: category.name,
                        inline: true
                    },
                    {
                        name: 'Path',
                        value: normalizedPath,
                        inline: true
                    },
                    {
                        name: 'Descendants Deleted',
                        value: (pathsToRemove.length - 1).toString(),
                        inline: true
                    },
                    {
                        name: 'Miis Updated',
                        value: totalUpdated.toString(),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: getOfficialCategoryTree(settings), updatedMiis: totalUpdated });
    } catch (e) {
        console.error('Error deleting category:', e);
        res.json({ error: 'Server error' });
    }
});

// Move category to a new parent
site.post('/moveCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { categoryPath, newParentPath } = req.body;
        const normalizedCategoryPath = typeof categoryPath === "string" ? categoryPath.trim() : "";
        const normalizedNewParentPath = typeof newParentPath === "string" && newParentPath.trim()
            ? newParentPath.trim()
            : null;

        if (!normalizedCategoryPath) {
            return res.json({ error: 'Category path required' });
        }

        const settings = await getSettings();
        const categoryTree = getOfficialCategoryTree(settings);
        const category = findCategoryByPath(normalizedCategoryPath, categoryTree);
        if (!category) {
            return res.json({ error: 'Category not found' });
        }

        // Prevent moving to self or descendant
        if (normalizedNewParentPath && normalizedNewParentPath.startsWith(normalizedCategoryPath + '/')) {
            return res.json({ error: 'Cannot move category to its own descendant' });
        }

        if (normalizedNewParentPath === normalizedCategoryPath) {
            return res.json({ error: 'Cannot move category to itself' });
        }

        // Get all paths before move
        const oldPaths = getAllDescendantPaths(category);

        const oldParent = findParentByChildPath(normalizedCategoryPath, categoryTree);
        const oldParentPath = oldParent?.path || null;
        if (normalizedNewParentPath === oldParentPath) {
            return res.json({ error: 'Category is already under that parent' });
        }

        // Add to new parent
        let newParentNode;
        let newSiblings;
        if (!normalizedNewParentPath) {
            // Move to root
            newSiblings = categoryTree;
            newParentNode = null;
        } else {
            newParentNode = findCategoryByPath(normalizedNewParentPath, categoryTree);
            if (!newParentNode) {
                return res.json({ error: 'New parent category not found' });
            }
            if (!Array.isArray(newParentNode.children)) {
                newParentNode.children = [];
            }
            newSiblings = newParentNode.children;
        }

        // Check for name conflict
        if (newSiblings.find(c => c.name === category.name && c.path !== normalizedCategoryPath)) {
            return res.json({ error: 'A category with this name already exists at the destination' });
        }

        // Remove from current parent
        if (oldParent) {
            oldParent.children = oldParent.children.filter(c => c.path !== normalizedCategoryPath);
        } else {
            const rootIndex = categoryTree.findIndex(c => c.path === normalizedCategoryPath);
            if (rootIndex > -1) categoryTree.splice(rootIndex, 1);
        }

        newSiblings.push(category);

        // Update paths
        updateCategoryPaths(category, normalizedNewParentPath || '');

        // Get new paths after move
        const newPaths = getAllDescendantPaths(category);

        // Update all Miis
        let totalUpdated = 0;
        for (let i = 0; i < oldPaths.length; i++) {
            const updated = await renameCategoryInAllMiis(oldPaths[i], newPaths[i]);
            totalUpdated += updated;
        }

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Category Moved`,
                description: `${req.cookies.username} moved a category`,
                color: 0x9C27B0,
                fields: [
                    {
                        name: 'Category',
                        value: category.name,
                        inline: true
                    },
                    {
                        name: 'Old Path',
                        value: oldPaths[0],
                        inline: false
                    },
                    {
                        name: 'New Path',
                        value: category.path,
                        inline: false
                    },
                    {
                        name: 'Miis Updated',
                        value: totalUpdated.toString(),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: getOfficialCategoryTree(settings), updatedMiis: totalUpdated });
    } catch (e) {
        console.error('Error moving category:', e);
        res.json({ error: 'Server error' });
    }
});
// Publish a private Mii
site.post('/publishMii', requireAuth,  async (req, res) => {
    try {
        const miiId = String(req.body?.miiId || "").trim();
        if (!miiId) {
            return res.json({ error: 'Mii ID required' });
        }

        const mii = await Miis.findOne({ id: miiId, private: true }).lean();
        if (!mii || mii.uploader !== req.user.username) {
            return res.json({ error: 'Mii not found in your private collection' });
        }

        // Check if blocked from publishing
        if (mii.blockedFromPublishing) {
            return res.json({ error: 'This Mii has been blocked from publishing by a moderator. Please contact support if you believe this is an error.' });
        }

        const publicImgPath = `./static/miiImgs/${mii.id}.png`;
        const publicQrPath = `./static/miiQRs/${mii.id}.png`;
        let miiImageData = null;

        // Because private assets are protected, we regenerate in public folders.
        if (fs.existsSync(publicImgPath)) {
            try {
                miiImageData = fs.readFileSync(publicImgPath);
            } catch (e) {
                miiImageData = null;
            }
        }
        if (!miiImageData) {
            miiImageData = await miijs.renderMii(mii);
            fs.writeFileSync(publicImgPath, miiImageData);
        }
        if (!fs.existsSync(publicQrPath)) {
            await writeQrPng(mii, publicQrPath);
        }

        // Update Mii status to published and public
        await Miis.findOneAndUpdate(
            { id: miiId },
            { $set: { private: false, published: true } }
        );

        // Remove private files after successful publish
        deleteMiiAssets(miiId, true);

        // Notify Discord
        const d = new Date();
        const attachments = miiImageData ? [{
            data: miiImageData,
            filename: `${miiId}.png`,
            contentType: 'image/png'
        }] : [];

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (mii.official ? "Official " : "") + `Mii Published`,
                "description": mii.desc,
                "color": 0x00ff00,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name || "Unknown",
                        "inline": true
                    },
                    {
                        "name": `Published by`,
                        "value": `[${req.user.username}](https://infinimii.com/user/${encodeURIComponent(req.user.username)})`,
                        "inline": true
                    }
                ],
                ...(miiImageData ? {
                    "image": {
                        "url": `attachment://${miiId}.png`
                    }
                } : {}),
                "footer": {
                    "text": `View: https://infinimii.com/mii/${miiId} | Published at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), attachments);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error publishing Mii:', e);
        res.json({ error: 'Server error' });
    }
});
// Block a private Mii from being published (Moderator only)
site.post('/blockMiiFromPublishing', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const miiId = String(req.body?.miiId || "").trim();
        const reason = typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
        if (!miiId) {
            return res.json({ error: 'Mii ID required' });
        }

        const mii = await Miis.findOne({ id: miiId, private: true, published: false }).lean();
        if (!mii) {
            return res.json({ error: 'Unpublished Mii not found' });
        }

        await Miis.findOneAndUpdate(
            { id: miiId },
            { 
                $set: { 
                    blockedFromPublishing: true,
                    blockReason: reason || 'No reason provided'
                }
            }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Private Mii Blocked from Publishing`,
                description: `${req.cookies.username} blocked a private Mii from being published`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'Mii Name',
                        value: mii.meta.name,
                        inline: true
                    },
                    {
                        name: 'Uploader',
                        value: mii.uploader,
                        inline: true
                    },
                    {
                        name: 'Reason',
                        value: reason || 'No reason provided'
                    }
                ]
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error blocking Mii:', e);
        res.json({ error: 'Server error' });
    }
});

// Unblock a private Mii from being published (Moderator only)
site.post('/unblockMiiFromPublishing', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const miiId = String(req.body?.miiId || "").trim();
        if (!miiId) {
            return res.json({ error: 'Mii ID required' });
        }

        const mii = await Miis.findOne({ id: miiId, private: true }).lean();
        if (!mii) {
            return res.json({ error: 'Private Mii not found' });
        }

        await Miis.findOneAndUpdate(
            { id: miiId },
            {
                $set: { blockedFromPublishing: false },
                $unset: { blockReason: 1 }
            }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Private Mii Unblocked`,
                description: `${req.cookies.username} unblocked a private Mii for publishing`,
                color: 0x00AA00,
                fields: [
                    {
                        name: 'Mii Name',
                        value: mii.meta?.name || 'Unknown',
                        inline: true
                    },
                    {
                        name: 'Uploader',
                        value: mii.uploader,
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error unblocking Mii:', e);
        res.json({ error: 'Server error' });
    }
});
site.post('/convertMii', upload.single('mii'), async (req, res) => {
    try {
        const miiInput = req.file?.path || req.body.miiData;
        if (!miiInput) {
            res.json({ error: "No Mii data provided" });
            return;
        }

        let desiredFormat = req.body.format;
        if (!desiredFormat && req.body.toType) {
            if (req.body.toType.includes("Wii")) desiredFormat = "wii";
            else if (req.body.toType.includes("3DS") || req.body.toType.includes("Wii U")) desiredFormat = "cfsd";
        }

        const normalized = normalizeExportFormat(desiredFormat);
        if (!normalized) {
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
            res.json({ error: "Invalid format specified" });
            return;
        }

        const miiData = await createMiiData(miiInput);
        const miiName = miiData?.meta?.name || "mii";

        try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }

        await sendExportResponse(res, miiData, normalized, miiName, getExportOptionsFromRequest(req));
    } catch (e) {
        console.error("Error converting Mii:", e);
        try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e2) { }
        res.json({error: "Conversion failed. Please verify you selected the right format and uploaded the right file."});
    }
});
site.post('/makeMiiChild', defaultRatelimiter, upload.fields([
    { name: 'parentA', maxCount: 1 },
    { name: 'parentB', maxCount: 1 }
]), async (req, res) => {
    const uploadedPaths = [];
    try {
        const parentAFile = req.files?.parentA?.[0];
        const parentBFile = req.files?.parentB?.[0];

        if (parentAFile?.path) uploadedPaths.push(parentAFile.path);
        if (parentBFile?.path) uploadedPaths.push(parentBFile.path);

        if (!parentAFile || !parentBFile) {
            res.json({ error: "Please upload both parent Mii files." });
            return;
        }

        const parentAData = await createMiiData(parentAFile.path);
        const parentBData = await createMiiData(parentBFile.path);
        const parentA = await miijs.Mii.create(parentAData);
        const parentB = await miijs.Mii.create(parentBData);

        const options = {};

        const childName = typeof req.body.childName === "string" ? req.body.childName.trim() : "";
        if (childName) {
            options.name = childName;
        }

        if (typeof req.body.childGender === "string" && req.body.childGender !== "") {
            const parsedGender = Number.parseInt(req.body.childGender, 10);
            if (![0, 1].includes(parsedGender)) {
                res.json({ error: "Child gender must be Male (0) or Female (1)." });
                return;
            }
            options.gender = parsedGender;
        }

        if (typeof req.body.childFavoriteColor === "string" && req.body.childFavoriteColor !== "") {
            const parsedFavoriteColor = Number.parseInt(req.body.childFavoriteColor, 10);
            const maxFavoriteColor = Array.isArray(miijs.FavoriteColors) ? (miijs.FavoriteColors.length - 1) : 11;
            if (!Number.isInteger(parsedFavoriteColor) || parsedFavoriteColor < 0 || parsedFavoriteColor > maxFavoriteColor) {
                res.json({ error: "Invalid favorite color selected." });
                return;
            }
            // `makeMiiChild` checks truthiness for favoriteColor, so preserve explicit red (0) as a truthy value.
            options.favoriteColor = parsedFavoriteColor === 0 ? "0" : parsedFavoriteColor;
        }

        const childStages = await miijs.makeMiiChild(
            parentA,
            parentB,
            Object.keys(options).length > 0 ? options : undefined
        );

        if (!Array.isArray(childStages) || childStages.length === 0) {
            res.json({ error: "Child generation failed. Please try different parent files." });
            return;
        }

        const enrichedChildren = await Promise.all(childStages.map(async (childStage, index) => {
            const stage = structuredClone(childStage);

            if (typeof stage?.general?.favoriteColor === "string") {
                const parsedColor = Number(stage.general.favoriteColor);
                if (!Number.isNaN(parsedColor)) {
                    stage.general.favoriteColor = parsedColor;
                }
            }

            const miiImageData = await miijs.renderMii(stage);
            const renderDataUri = `data:image/png;base64,${Buffer.from(miiImageData).toString('base64')}`;

            const miiHeight = Number(stage?.general?.height ?? 0);
            const miiWeight = Number(stage?.general?.weight ?? 0);

            return {
                ...stage,
                stageIndex: index,
                stageLabel: MII_CHILD_STAGE_LABELS[index] || `Stage ${index + 1}`,
                renderDataUri,
                heightMeasurements: miijs.miiHeightToMeasurements(miiHeight),
                weightMeasurements: miijs.miiWeightToMeasurements(miiHeight, miiWeight)
            };
        }));

        res.json({ children: enrichedChildren });
    } catch (e) {
        console.error("Error generating Mii child:", e);
        res.json({ error: `Failed to generate child Miis: ${e.message}` });
    } finally {
        for (const filePath of uploadedPaths) {
            try { fs.unlinkSync(filePath); } catch (e) { }
        }
    }
});
site.post('/signup', async (req, res) => {
    // TODO: JWT model

    // Field validation
    if (!validator.isEmail(req.body.email)) {
        res.json({ error: "Invalid email address" });
        return;
    }
    const cleanEmail = validator.normalizeEmail(req.body.email);

    // Validate username
    const existingUsername = await getUserByUsername(req.body.username);
    if (existingUsername) {
        res.json({ error: "Username already taken" });
        return;
    }
    
    // Check if username is reserved
    const reserved = await ReservedUsername.findOne({ username: req.body.username });
    if (reserved) {
        res.json({ error: "This username is temporarily unavailable. Please try again later or choose a different username." });
        return;
    }
    
    if (isBad(req.body.username) || existingUsername || !validate(req.body.username)) {
        res.json({ error: "Username invalid" });
        return;
    }

    // Account does not already exist
    const existingUserEmail = await Users.exists({ email: cleanEmail })
    if (existingUserEmail) {
        res.json({ error: "Email already in use" });
        return;
    }
    
    // Check IP ban
    const clientIPs = [req.headers['x-forwarded-for'], req.socket.remoteAddress]
        .filter(Boolean)
        .map(ip => sha256(ip))
    const settings = await getSettings();
    if (settings.bannedIPs.some( ip => clientIPs.includes(ip))) {
        return res.json({ error: 'This IP address has been permanently banned from creating accounts.' });
    }
    
    var hashedPassword = hashPassword(req.body.pass);
    var token = genToken();
    
    await Users.create({
        username: req.body.username,
        salt: hashedPassword.salt,
        pass: hashedPassword.hash,
        verificationToken: hashPassword(token, hashedPassword.salt).hash,
        creationDate: Date.now(),
        email: cleanEmail,
        roles: [ ROLES.BASIC ],
    });
    
    let link = "https://infinimii.com/verify?user=" + encodeURIComponent(req.body.username) + "&token=" + encodeURIComponent(token);
    sendEmail(cleanEmail, "InfiniMii Verification", 
        "Welcome to InfiniMii! If you initiated this message, verify your email by clicking this link: " + link
    );
    res.json({ message: "Check your email to verify your account!" });
});
site.post('/login', async (req, res) => {
    const user = await getUserByUsername(req.body.username);
    if (!user) {
        res.json({ error: "Invalid username or password" });
        return;
    }
    
    if (validatePassword(req.body.pass, user.salt, user.pass)) {
        if (user.verified) {
            // Create JWT token
            const token = createToken(user);
            
            res.cookie('token', token, {
                maxAge: ms("30 days"), // 1 Month
                httpOnly: true, // Prevent XSS leaking - TODO: changing username should require password because it should return a JWT with a version increase
                secure: process.env.NODE_ENV === 'production', // HTTPS only in production
                sameSite: 'lax' // CSRF protection
            });
            res.cookie('username', req.body.username, { 
                maxAge: ms("30 days") 
            });
        }
        else {
            res.json({ error: "Email not verified yet" }); 
            // TODO: should this prevent login until email validated? Maybe add a resend code button.
            // TODO: if email is never validated, the username is lost... give them maybe 24 hours to verify their email before deleting the account...
            return;
        }
        
        res.json({ redirect: "/" });
    } else {
        res.json({ error: "Invalid username or password" });
    }
});

site.get("/error", async(req, res) => {
    let crash = undefined.field;
});

// Error-handling middleware at the bottom of the stack
site.use(async (err, req, res, next) => {
    console.error(err);
    // TODO: remove try catch from all endpoints in favor of this handler

    // Check what the client accepts
    if (!req.accepts('html')) {
        // If it doesn't want HTML at all, serve it json.
        res.status(500).json({
            error: {
                message: err.message || 'Internal Server Error',
                // optional: stack trace in dev
                ...(process.env.NODE_ENV === 'development' && { stack: `DEV STACK: ` + err.stack }),
            }
        });
    } else {
        return await sendError(res, req, "Internal Server Error. Please try again later.", 500);
    }
});

process.on('unhandledRejection', (reason, rejectedPromise) => console.log(reason));

process.on('uncaughtException', (error) => console.log(error));


setInterval(async () => {
    var curTime = new Date();
    const settings = await getSettings();
    if (curTime.getHours() === 22 && settings.highlightedMiiChangeDay !== curTime.getDay()) {
        makeReport("**Don't forget to set a new Highlighted Mii!**");
    }
}, ms("1h"));

// TODO: reset password functionality which should increase token version

// TODO: vulnerability where if username and email are changed, and someone else signs up with the old email and old username, the first user can access their account
// To fix this, simply create a reserveUsername field in mongo, that lasts as long as the JWTs do to make sure they are defintiely expired. 
// If trying to move to or create a user with the name of a reserved username, return the standard json error to be shown on the page like usual.
// Also at the same time, prevent users from changing their name more than once a month. Make sure this is known on the settings page.

// Remove most try-catches to let 500 handler take it

///// Utils:
// - Look for opening <% without closing one
// <%(?![\s\S]*%>)
