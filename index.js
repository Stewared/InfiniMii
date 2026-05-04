import "./setEnvs.js";
import { rawConsoleError, scheduleDailyWebhookReminder, sendWebhookPayload } from "./monitoring.js";
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
import { unzipSync } from "fflate";
import { RegExpMatcher, englishDataset, englishRecommendedTransformers } from 'obscenity';
import { doubleMetaphone } from 'double-metaphone';
import validator from 'validator';
import jwt from 'jsonwebtoken';
import { STATUS_CODES } from 'http';
import { isDeepStrictEqual } from 'node:util';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import ms from 'ms';
import dns from "dns";
import { connectionPromise, Miis, Users, Settings, ReservedUsername } from "./database.js";
import { renderIcon, icons } from "./icons.js";
import {
    SEARCH_FALLBACK_CANDIDATE_LIMIT,
    buildMiiSearchMatchClauses,
    buildMiiSearchPlan,
    buildMiiSearchScoreExpression,
    getMiiSearchSort,
    normalizeSearchText,
    normalizeSearchFieldSelection,
    rankMiiSearchCandidates
} from "./searchUtils.js";
import {
    MII_IDENTITY_HASH_PREFIX,
    getMiiIdentityHash,
    hasCurrentMiiIdentityHashVersion,
    setMiiIdentityHash
} from "./miiIdentityHash.js";

dns.setServers(['1.1.1.1', '8.8.8.8']);
fs.mkdirSync(path.join(__dirname, "static", "miiImgs"), { recursive: true });
fs.mkdirSync(path.join(__dirname, "static", "miiQRs"), { recursive: true });
fs.mkdirSync(path.join(__dirname, "static", "miiQRsWii"), { recursive: true });
fs.mkdirSync(path.join(__dirname, "static", "privateMiiImgs"), { recursive: true });
fs.mkdirSync(path.join(__dirname, "static", "privateMiiQRs"), { recursive: true });
fs.mkdirSync(path.join(__dirname, "static", "privateMiiQRsWii"), { recursive: true });

const defaultMiisPerPage = 16;
const profileMiisPerPage = 18;
// Fetch enough cards for the homepage so the client can keep each section to
// one fitted row on wide layouts and fuller preview rows on narrow layouts.
const HOME_PREVIEW_COUNT = 16;
const FULL_ROW_BROWSE_REQUEST_LIMIT = defaultMiisPerPage + HOME_PREVIEW_COUNT;
const FULL_ROW_PROFILE_REQUEST_LIMIT = profileMiisPerPage + HOME_PREVIEW_COUNT;
const GLOBAL_ASSET_VERSION = "20260423-pagination-bounds-1";
const RSS_FEED_MII_LIMIT = 50;
const INDEXNOW_API_ENDPOINT = "https://api.indexnow.org/indexnow";
const INDEXNOW_MAX_URLS_PER_REQUEST = 10000;
const PRIVATE_MII_LIMIT = process.env.privateMiiLimit;
const baseUrl = process.env.baseUrl;
const PAYPAL_DONATE_URL = "https://www.paypal.com/donate?business=kestron@kestron.com&no_recurring=0&item_name=Stewared&item_number=InfiniMii";
const AVERAGE_MII_REFRESH_WINDOW_MS = ms("10m");
const UPLOAD_WEBHOOK_IMAGE_READY_TIMEOUT_MS = ms("10s");
const TRENDING_TIME_DECAY_EXPONENT = 1.25;
const MII_RENDER_IMAGE_WIDTH = 512;
const MII_RENDER_IMAGE_HEIGHT = 512;
const MII_SITEMAP_PAGE_SIZE = 5000;
const ERRORING_FILES_DIR = path.join(__dirname, "erroringFiles");
const ERRORING_FILE_SIZE_LIMIT_BYTES = 100 * 1024 * 1024;
const WEBHOOK_ATTACHMENT_MAX_BYTES = 8 * 1024 * 1024;
const ERRORING_FILE_KEEP_COUNT = 10;
const SEO_KEYWORDS_CSV_PATH = path.join(__dirname, "seoKeywords.csv");
const SEO_KEYWORD_META_LIMIT = 48;
const SEO_KEYWORD_MAX_LENGTH = 80;
const REPORT_MII_CATEGORIES = Object.freeze([
    "Rendered Incorrectly",
    "Inappropriate",
    "Disrespectful",
    "I Made This Mii",
    "Someone Else Made This Mii",
    "I Did Not Give Permission To Make This Mii Of Me",
    "Other"
]);
const REPORT_MII_CATEGORY_SET = new Set(REPORT_MII_CATEGORIES);
const REPORT_MII_DETAILS_MAX_LENGTH = 4000;
const OFFICIAL_ZIP_MAX_ENTRIES = 250;
const OFFICIAL_ZIP_MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const OFFICIAL_ZIP_MAX_TOTAL_BYTES = 32 * 1024 * 1024;

let cachedSeoKeywords = null;
let loggedSeoKeywordLoadError = false;
let cachedIndexNowKey = null;
let loggedIndexNowConfigError = false;

const SEO_KEYWORD_STOPWORDS = new Set([
    "and",
    "app",
    "are",
    "browse",
    "character",
    "characters",
    "community",
    "download",
    "for",
    "from",
    "guide",
    "infini",
    "infinimii",
    "latest",
    "mii",
    "miis",
    "nintendo",
    "official",
    "page",
    "search",
    "share",
    "the",
    "tool",
    "tools",
    "upload",
    "with"
]);

const SEO_KEYWORD_SHORT_TOKENS = new Set([
    "ds",
    "mt",
    "qr"
]);

const SIMILAR_MII_QUERY_LIMIT = 96;
const SIMILAR_MII_TOKEN_QUERY_LIMIT = 8;
const SIMILAR_MII_TAG_TERM_LIMIT = 40;
const SIMILAR_MII_DESCRIPTION_TERM_LIMIT = 40;
const SIMILAR_MII_GENERIC_TERMS = new Set([
    "about",
    "also",
    "and",
    "are",
    "because",
    "been",
    "but",
    "can",
    "avatar",
    "avatars",
    "character",
    "characters",
    "desc",
    "description",
    "for",
    "from",
    "had",
    "has",
    "have",
    "in",
    "into",
    "is",
    "it",
    "its",
    "like",
    "made",
    "make",
    "mii",
    "miis",
    "no",
    "none",
    "of",
    "on",
    "or",
    "provided",
    "that",
    "the",
    "their",
    "then",
    "this",
    "to",
    "was",
    "were",
    "will",
    "with"
]);

const EXPORT_FORMAT_LABELS = {
    qr: "QR Code (PNG)",
    rcd: "Wii RCD (.rcd)",
    rsd: "Wii RSD (.rsd)",
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
const MII_CHILD_STAGE_LABELS = [
    "Newborn",
    "Infant",
    "Child",
    "Teen",
    "Young Adult",
    "Adult"
];
const DEFAULT_USER_PFP_MII_ID = "QfK19";
const BLANK_MII_ID = "00000";
const INSTRUCTION_CONSOLE_VALUES = new Set(["DS", "WII", "3DS", "WIIU", "SWITCH", "SWITCH2"]);
const MAX_MII_TAG_LENGTH = 40;
const MAX_MANUAL_MII_ID_LENGTH = 10;
const MAX_COMPANY_SOURCE_NAME_LENGTH = 15;
const DEFAULT_OFFICIAL_COMPANY_SOURCE = "Nintendo";
const AVERAGE_MII_EXCLUDED_TAGS = ["Face Art","Animal"];
const TOMODACHI_LIFE_TAG = "Tomodachi Life";

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

function toSafeInlineScriptJson(value, space = 0) {
    const json = JSON.stringify(value, null, space);
    if (typeof json !== "string") {
        return "null";
    }

    return json
        .replace(/</g, "\\u003C")
        .replace(/>/g, "\\u003E")
        .replace(/&/g, "\\u0026")
        .replace(/\u2028/g, "\\u2028")
        .replace(/\u2029/g, "\\u2029");
}

function getSafeRedirectPath(target, fallback = "/") {
    const fallbackPath = typeof fallback === "string" && fallback.startsWith("/")
        ? fallback
        : "/";
    const candidate = typeof target === "string"
        ? target.trim()
        : "";

    if (!candidate) return fallbackPath;
    if (!candidate.startsWith("/")) return fallbackPath;
    if (candidate.startsWith("//")) return fallbackPath;

    try {
        const parsed = new URL(candidate, "https://infinimii.local");
        if (parsed.origin !== "https://infinimii.local") return fallbackPath;
        return `${parsed.pathname}${parsed.search}${parsed.hash}` || fallbackPath;
    } catch {
        return fallbackPath;
    }
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

function isByteArray(value) {
    return Array.isArray(value) && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255);
}

function normalizeMiiInput(input) {
    if (typeof input === "string") {
        const trimmed = input.trim();
        if (!trimmed) return "";

        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                return normalizeMiiInput(JSON.parse(trimmed));
            } catch (e) { }
        }

        return trimmed;
    }

    if (Array.isArray(input)) {
        if (isByteArray(input)) {
            try {
                return Buffer.from(input);
            } catch (e) {
                return input;
            }
        }

        for (const item of input) {
            const normalized = normalizeMiiInput(item);
            if (normalized !== "" && normalized !== null && normalized !== undefined) {
                return normalized;
            }
        }

        return input;
    }

    if (Buffer.isBuffer(input) || input instanceof ArrayBuffer) {
        return input;
    }

    if (ArrayBuffer.isView(input)) {
        return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    }

    if (!input || typeof input !== "object") {
        return input;
    }

    if (typeof input.toJSON === "function") {
        try {
            const serialized = input.toJSON();
            if (serialized && serialized !== input) {
                return normalizeMiiInput(serialized);
            }
        } catch (e) { }
    }

    if (input.type === "Buffer" && isByteArray(input.data)) {
        try {
            return Buffer.from(input.data);
        } catch (e) {
            return input;
        }
    }

    if (Object.prototype.hasOwnProperty.call(input, "fields") && input.fields && typeof input.fields === "object") {
        return normalizeMiiInput(input.fields);
    }

    if (Object.prototype.hasOwnProperty.call(input, "miiData")) {
        return normalizeMiiInput(input.miiData);
    }

    return input;
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
    const normalizedInput = normalizeMiiInput(input);
    const parsedInput = isQrImageInput(normalizedInput) ? await decodeQrImageInput(normalizedInput) : normalizedInput;
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

async function findMatchingMii(candidateMii, { includePrivate = true, excludeId, includeGeneral = false } = {}) {
    const candidateHash = getMiiIdentityHash(candidateMii, { includeGeneral });
    const lookupHash = includeGeneral ? getMiiIdentityHash(candidateMii) : candidateHash;
    const query = includePrivate ? {} : { private: false };
    if (excludeId) query.id = { $ne: excludeId };
    if (lookupHash) {
        query.$or = [
            { miiHash: lookupHash },
            { miiHash: { $not: new RegExp(`^${MII_IDENTITY_HASH_PREFIX}`) } },
            { miiHash: { $exists: false } },
            { miiHash: null },
            { miiHash: "" }
        ];
    }

    const existingMiis = await Miis.find(query).lean();

    for (const existingMii of existingMiis) {
        const existingHash = !includeGeneral && hasCurrentMiiIdentityHashVersion(existingMii.miiHash)
            ? existingMii.miiHash
            : getMiiIdentityHash(existingMii, { includeGeneral });
        if (candidateHash && existingHash === candidateHash) {
            return existingMii;
        }
    }

    return null;
}

async function backfillMiiIdentityHashes() {
    const cursor = Miis.find({}).cursor();

    let updatedCount = 0;
    for await (const mii of cursor) {
        const miiHash = getMiiIdentityHash(mii);
        if (!miiHash || mii.miiHash === miiHash) continue;

        await Miis.updateOne(
            { _id: mii._id },
            { $set: { miiHash } }
        );
        updatedCount++;

        if (updatedCount % 100 === 0) {
            await yieldToEventLoop();
        }
    }

    if (updatedCount > 0) {
        console.log(`[miiHash] Updated ${updatedCount} Mii identity hash${updatedCount === 1 ? "" : "es"}.`);
    }
}

function getDuplicateMiiErrorMessage(matchingMiiId) {
    return `This Mii already exists (Mii ID: ${matchingMiiId}). If you believe this is incorrect, you can dispute it by contacting Stewared at /contact.`;
}

function getDuplicateMiiErrorHtml(matchingMiiId) {
    const duplicateMiiId = String(matchingMiiId ?? "");
    const duplicateMiiUrl = `/mii/${encodeURIComponent(duplicateMiiId)}`;
    return `This Mii already exists (<a href="${duplicateMiiUrl}">Mii ID: ${escapeHtmlText(duplicateMiiId)}</a>). If you believe this is incorrect, you can dispute it by <a href="/contact">contacting Stewared</a>.`;
}

function getDuplicateMiiErrorPayload(matchingMiiId) {
    return {
        error: getDuplicateMiiErrorMessage(matchingMiiId),
        errorHtml: getDuplicateMiiErrorHtml(matchingMiiId)
    };
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

function getUploadedFileExtension(file) {
    const originalName = typeof file?.originalname === "string" ? file.originalname : "";
    const fallbackName = typeof file?.filename === "string" ? file.filename : "";
    return path.extname(originalName || fallbackName).toLowerCase();
}

function isZipUpload(file) {
    if (!file) return false;
    if (getUploadedFileExtension(file) === ".zip") {
        return true;
    }

    const mimeType = typeof file?.mimetype === "string" ? file.mimetype.toLowerCase() : "";
    return mimeType === "application/zip" || mimeType === "application/x-zip-compressed";
}

function shouldIgnoreOfficialZipEntry(entryName) {
    const normalizedName = String(entryName || "").replace(/\\/g, "/").trim();
    if (!normalizedName || normalizedName.endsWith("/")) {
        return true;
    }

    if (normalizedName.startsWith("__MACOSX/")) {
        return true;
    }

    const baseName = path.posix.basename(normalizedName).toLowerCase();
    return baseName === ".ds_store" || baseName === "thumbs.db";
}

async function extractOfficialZipEntries(filePath) {
    let archiveEntries;
    try {
        archiveEntries = unzipSync(await fs.promises.readFile(filePath));
    } catch (error) {
        throw new Error("Could not open the ZIP archive. Make sure it is a valid .zip file.");
    }

    const extractedEntries = [];
    let totalExtractedBytes = 0;

    for (const [entryName, rawEntryData] of Object.entries(archiveEntries)) {
        const normalizedName = String(entryName || "").replace(/\\/g, "/");
        if (shouldIgnoreOfficialZipEntry(normalizedName)) {
            continue;
        }

        const entryBuffer = Buffer.from(rawEntryData);
        if (!entryBuffer.length) {
            continue;
        }

        if (entryBuffer.length > OFFICIAL_ZIP_MAX_ENTRY_BYTES) {
            throw new Error(
                `The file "${path.posix.basename(normalizedName)}" is too large. Each ZIP entry must stay under 8 MB.`
            );
        }

        totalExtractedBytes += entryBuffer.length;
        if (totalExtractedBytes > OFFICIAL_ZIP_MAX_TOTAL_BYTES) {
            throw new Error("This ZIP is too large once extracted. Keep the total extracted file size under 32 MB.");
        }

        extractedEntries.push({
            name: normalizedName,
            data: entryBuffer
        });

        if (extractedEntries.length > OFFICIAL_ZIP_MAX_ENTRIES) {
            throw new Error(`ZIP uploads can include at most ${OFFICIAL_ZIP_MAX_ENTRIES} files at a time.`);
        }
    }

    return extractedEntries;
}

function getClientIpAddress(req) {
    const directIp = typeof req?.ip === 'string' ? req.ip.trim() : '';
    if (directIp) return directIp;

    if (Array.isArray(req?.ips)) {
        const forwardedIp = req.ips.find((ip) => typeof ip === 'string' && ip.trim());
        if (forwardedIp) return forwardedIp.trim();
    }

    const forwardedFor = typeof req?.headers?.['x-forwarded-for'] === 'string'
        ? req.headers['x-forwarded-for'].split(',').map((ip) => ip.trim()).find(Boolean)
        : '';
    if (forwardedFor) return forwardedFor;

    const realIp = typeof req?.headers?.['x-real-ip'] === 'string' ? req.headers['x-real-ip'].trim() : '';
    if (realIp) return realIp;

    const socketIp = typeof req?.socket?.remoteAddress === 'string' ? req.socket.remoteAddress.trim() : '';
    if (socketIp) return socketIp;

    const connectionIp = typeof req?.connection?.remoteAddress === 'string' ? req.connection.remoteAddress.trim() : '';
    if (connectionIp) return connectionIp;

    return 'unknown';
}

function rateLimitKeyGenerator(req) {
    const clientIp = getClientIpAddress(req);
    if (clientIp !== 'unknown') return ipKeyGenerator(clientIp, 56);

    // Keep unknown-IP requests isolated enough to avoid broad collateral limits.
    const ua = typeof req?.headers?.['user-agent'] === 'string' ? req.headers['user-agent'] : 'unknown-ua';
    const method = typeof req?.method === 'string' ? req.method : 'UNKNOWN';
    const route = typeof req?.originalUrl === 'string' ? req.originalUrl : (typeof req?.url === 'string' ? req.url : '/');
    return `unknown:${method}:${route}:${ua}`;
}

// TODO: consider splitting lightening ratelimits if you have an account, say an extra allotment per account in addition to normal ones.
const ratelimitOptions = {
	standardHeaders: 'draft-8', // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
    keyGenerator: rateLimitKeyGenerator,
    message: async function(req, res) {
        const count = req.rateLimit.used;
        const limitWas = req.rateLimit.limit;
        const clientIp = getClientIpAddress(req);
        if (count-limitWas === 1 || count % 5 === 0) {
            // For the first while, post into discord for every ratelimit request to track abuse and make sure we don't need to lighten limits
            await makeReport(JSON.stringify({
                embeds: [{
                    type: "rich",
                    title: "Ratelimit Triggered",
                    description: 
                        `Triggered by IP: ${clientIp}\n` + // This is here for better protection, and so we can block people, and check if it's a VPN first.
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
const SETTINGS_CACHE_TTL_MS = 5000;
let cachedSettings = null;
let cachedSettingsLoadedAt = 0;
let cachedSettingsPromise = null;

function cloneSettings(settings) {
    return settings ? structuredClone(settings) : settings;
}

function normalizeSettingsRecord(settings) {
    if (!settings) return settings;
    const normalized = typeof settings.toObject === "function"
        ? settings.toObject()
        : settings;

    if (typeof normalized.defaultUserPfpMii !== "string" || !normalized.defaultUserPfpMii.trim()) {
        normalized.defaultUserPfpMii = DEFAULT_USER_PFP_MII_ID;
    }

    if (typeof normalized.highlightedMiiReminderSentOn !== "string" || !normalized.highlightedMiiReminderSentOn.trim()) {
        normalized.highlightedMiiReminderSentOn = null;
    }

    return normalized;
}

function getDefaultUserPfpMiiId(settings) {
    const configured = typeof settings?.defaultUserPfpMii === "string"
        ? settings.defaultUserPfpMii.trim()
        : "";
    return configured || DEFAULT_USER_PFP_MII_ID;
}

async function backfillMissingUserPfpSetFlags() {
    const missingPfpSetQuery = {
        $or: [
            { pfpSet: { $exists: false } },
            { pfpSet: null }
        ]
    };

    const [defaultResult, customResult] = await Promise.all([
        Users.updateMany(
            {
                $and: [
                    missingPfpSetQuery,
                    { miiPfp: DEFAULT_USER_PFP_MII_ID }
                ]
            },
            { $set: { pfpSet: false } }
        ),
        Users.updateMany(
            {
                $and: [
                    missingPfpSetQuery,
                    {
                        $or: [
                            { miiPfp: { $ne: DEFAULT_USER_PFP_MII_ID } },
                            { miiPfp: { $exists: false } },
                            { miiPfp: null },
                            { miiPfp: "" }
                        ]
                    }
                ]
            },
            { $set: { pfpSet: true } }
        )
    ]);

    const updatedCount = (defaultResult.modifiedCount || 0) + (customResult.modifiedCount || 0);
    if (updatedCount > 0) {
        console.log(`[pfpSet] Backfilled ${updatedCount} user profile-picture flags.`);
    }
}

function invalidateSettingsCache(nextValue = null) {
    cachedSettings = nextValue ? normalizeSettingsRecord(nextValue) : null;
    cachedSettingsLoadedAt = nextValue ? Date.now() : 0;
    cachedSettingsPromise = null;
}

async function loadSettingsFromDatabase() {
    let settings = await Settings.findById("global").lean();
    if (!settings) {
        settings = normalizeSettingsRecord(await Settings.create({
            _id: "global",
            highlightedMii: null,
            defaultUserPfpMii: DEFAULT_USER_PFP_MII_ID,
            highlightedMiiChangeDay: null,
            highlightedMiiReminderSentOn: null,
            bannedIPs: [],
            officialCategories: { categories: [] },
            officialCompanySources: [DEFAULT_OFFICIAL_COMPANY_SOURCE],
            miiTags: []
        }));
    } else {
        const hasDefaultUserPfpMii = typeof settings.defaultUserPfpMii === "string" && settings.defaultUserPfpMii.trim();
        if (!hasDefaultUserPfpMii) {
            settings = normalizeSettingsRecord(await Settings.findByIdAndUpdate(
                "global",
                { defaultUserPfpMii: DEFAULT_USER_PFP_MII_ID },
                { new: true, lean: true }
            ));
        } else {
            settings = normalizeSettingsRecord(settings);
        }
    }
    cachedSettings = settings;
    cachedSettingsLoadedAt = Date.now();
    return settings;
}

async function getSettings() {
    const now = Date.now();
    if (cachedSettings && (now - cachedSettingsLoadedAt) < SETTINGS_CACHE_TTL_MS) {
        return cloneSettings(cachedSettings);
    }

    if (!cachedSettingsPromise) {
        cachedSettingsPromise = loadSettingsFromDatabase()
            .finally(() => {
                cachedSettingsPromise = null;
            });
    }

    return cloneSettings(await cachedSettingsPromise);
}

async function updateSettings(updates) {
    const settings = await Settings.findByIdAndUpdate("global", updates, {
        new: true,
        upsert: true,
        lean: true
    });
    invalidateSettingsCache(settings);
    return cloneSettings(settings);
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

function sanitizeErroringFilePart(value, fallback = "upload") {
    const normalized = String(value || "")
        .trim()
        .replace(/[^a-zA-Z0-9_-]+/g, "_")
        .replace(/^_+|_+$/g, "");

    if (!normalized) return fallback;
    return normalized.slice(0, 64);
}

function getSafeErroringExtension(reqFile) {
    const originalExt = path.extname(reqFile?.originalname || "") || path.extname(reqFile?.path || "");
    if (!originalExt) return ".bin";

    const normalized = originalExt
        .toLowerCase()
        .replace(/[^a-z0-9.]/g, "");

    if (!normalized.startsWith(".")) return ".bin";
    if (normalized.length > 12) return ".bin";
    return normalized;
}

async function trimErroringFilesDir() {
    try {
        const entries = await fs.promises.readdir(ERRORING_FILES_DIR, { withFileTypes: true });
        const filesWithStats = await Promise.all(entries
            .filter(entry => entry.isFile())
            .map(async entry => {
                const fullPath = path.join(ERRORING_FILES_DIR, entry.name);
                const stats = await fs.promises.stat(fullPath);
                return {
                    fullPath,
                    mtimeMs: stats.mtimeMs
                };
            }));

        filesWithStats.sort((a, b) => b.mtimeMs - a.mtimeMs);
        const filesToDelete = filesWithStats.slice(ERRORING_FILE_KEEP_COUNT);

        await Promise.all(filesToDelete.map(file => fs.promises.unlink(file.fullPath).catch(() => {})));
    } catch (e) {
        console.error("Error trimming erroringFiles directory:", e);
    }
}

async function dumpFailingUploadFile(reqFile, error, context = "upload") {
    if (!reqFile?.path) return null;

    try {
        const sourcePath = reqFile.path;
        const sourceStats = await fs.promises.stat(sourcePath);
        if (!sourceStats.isFile()) return null;

        if (sourceStats.size > ERRORING_FILE_SIZE_LIMIT_BYTES) {
            console.warn(`Skipping failing file dump (over 100MB): ${reqFile.originalname || path.basename(sourcePath)} (${sourceStats.size} bytes)`);
            return null;
        }

        await fs.promises.mkdir(ERRORING_FILES_DIR, { recursive: true });

        const timestamp = new Date().toISOString().replace(/[.:]/g, "-");
        const safeContext = sanitizeErroringFilePart(context, "upload");
        const sourceBaseName = sanitizeErroringFilePart(path.basename(reqFile.originalname || sourcePath, path.extname(reqFile.originalname || sourcePath)), "file");
        const safeExt = getSafeErroringExtension(reqFile);
        const uniqueSuffix = crypto.randomBytes(4).toString("hex");
        const destinationName = `${timestamp}_${safeContext}_${sourceBaseName}_${uniqueSuffix}${safeExt}`;
        const destinationPath = path.join(ERRORING_FILES_DIR, destinationName);

        await fs.promises.copyFile(sourcePath, destinationPath);
        await trimErroringFilesDir();

        const errorMessage = typeof error?.message === "string" ? error.message : String(error || "Unknown error");
        console.warn(`Saved failing upload to ${destinationPath}: ${errorMessage}`);
        return {
            destinationPath,
            originalName: reqFile.originalname || path.basename(sourcePath),
            contentType: reqFile.mimetype || "application/octet-stream",
            size: Math.trunc(sourceStats.size)
        };
    } catch (dumpError) {
        console.error("Failed to save failing upload file:", dumpError);
        return null;
    }
}

function estimateRawMiiPayloadSizeBytes(rawInput) {
    const normalizedInput = typeof rawInput === "string" ? rawInput.trim() : "";
    if (!normalizedInput) return 0;

    const collapsed = normalizedInput.replace(/\s+/g, "");
    if (collapsed && /^[0-9a-fA-F]+$/.test(collapsed) && collapsed.length % 2 === 0) {
        return collapsed.length / 2;
    }

    if (collapsed && /^[A-Za-z0-9+/=_-]+$/.test(collapsed)) {
        try {
            const base64Normalized = collapsed.replace(/-/g, "+").replace(/_/g, "/");
            const paddingLength = (4 - (base64Normalized.length % 4 || 4)) % 4;
            const decoded = Buffer.from(base64Normalized + "=".repeat(paddingLength), "base64");
            if (decoded.length > 0) {
                return decoded.length;
            }
        } catch (e) { }
    }

    return Buffer.byteLength(normalizedInput, "utf8");
}

async function getSubmittedMiiSizeBytes({ reqFile = null, rawInput = "", filePath = "" } = {}) {
    if (Number.isFinite(reqFile?.size) && reqFile.size >= 0) {
        return Math.trunc(reqFile.size);
    }

    const normalizedPath = typeof filePath === "string" ? filePath.trim() : "";
    if (normalizedPath) {
        try {
            const stats = await fs.promises.stat(normalizedPath);
            if (stats.isFile()) {
                return Math.trunc(stats.size);
            }
        } catch (e) { }
    }

    return estimateRawMiiPayloadSizeBytes(rawInput);
}

function isInvalidMiiTypeError(error) {
    const errorMessage = typeof error?.message === "string"
        ? error.message
        : String(error || "");

    return /Could not find any decode?able formats/i.test(errorMessage);
}

async function buildInvalidMiiTypeErrorPayload({ reqFile = null, rawInput = "", filePath = "" } = {}) {
    const sizeBytes = await getSubmittedMiiSizeBytes({ reqFile, rawInput, filePath });
    const normalizedSize = Number.isFinite(sizeBytes) && sizeBytes >= 0 ? Math.trunc(sizeBytes) : 0;

    return {
        error: `This is not a valid Mii type. Filesize: ${normalizedSize} bytes. For support, contact Stewared.`,
        errorHtml: `This is not a valid Mii type. Filesize: ${normalizedSize} bytes. For support, <a href="/contact">contact Stewared</a>.`
    };
}

async function buildInvalidMiiWebhookAttachment({ reqFile = null, rawInput = "", filePath = "" } = {}) {
    const normalizedPath = typeof filePath === "string" ? filePath.trim() : "";
    if (normalizedPath) {
        try {
            const stats = await fs.promises.stat(normalizedPath);
            if (stats.isFile()) {
                if (stats.size > WEBHOOK_ATTACHMENT_MAX_BYTES) {
                    return {
                        skippedReason: `Attachment skipped because the file is ${stats.size} bytes, over the Discord upload limit.`
                    };
                }

                return {
                    attachment: {
                        data: await fs.promises.readFile(normalizedPath),
                        filename: reqFile?.originalname || path.basename(normalizedPath),
                        contentType: reqFile?.mimetype || "application/octet-stream"
                    }
                };
            }
        } catch (e) { }
    }

    const normalizedRawInput = typeof rawInput === "string" ? rawInput.trim() : "";
    if (normalizedRawInput) {
        const rawBuffer = Buffer.from(normalizedRawInput, "utf8");
        if (rawBuffer.length > WEBHOOK_ATTACHMENT_MAX_BYTES) {
            return {
                skippedReason: `Attachment skipped because the raw input is ${rawBuffer.length} bytes, over the Discord upload limit.`
            };
        }

        return {
            attachment: {
                data: rawBuffer,
                filename: "submitted-mii-data.txt",
                contentType: "text/plain; charset=utf-8"
            }
        };
    }

    return { skippedReason: "No file payload was available to attach." };
}

async function sendInvalidMiiInputToWebhook({
    req,
    error,
    context = "upload",
    reqFile = null,
    rawInput = "",
    filePath = ""
} = {}) {
    try {
        const sizeBytes = await getSubmittedMiiSizeBytes({ reqFile, rawInput, filePath });
        const normalizedSize = Number.isFinite(sizeBytes) && sizeBytes >= 0 ? Math.trunc(sizeBytes) : 0;
        const attachmentInfo = await buildInvalidMiiWebhookAttachment({ reqFile, rawInput, filePath });
        const userLabel = normalizeReportText(req?.user?.username, 80) || "Anonymous";
        const endpoint = String(req?.originalUrl || req?.path || "Unknown").trim() || "Unknown";
        const errorMessage = normalizeReportText(error?.message || error, 3000) || "Unknown error";
        const sourceType = reqFile?.path
            ? "Uploaded file"
            : (rawInput ? "Raw code input" : (filePath ? "Temporary file" : "Unknown"));
        const filename = reqFile?.originalname
            || (typeof filePath === "string" && filePath.trim() ? path.basename(filePath.trim()) : "");

        const fields = [
            {
                name: "Context",
                value: truncateText(context, 1024),
                inline: true
            },
            {
                name: "User",
                value: truncateText(userLabel, 1024),
                inline: true
            },
            {
                name: "Input Type",
                value: truncateText(sourceType, 1024),
                inline: true
            },
            {
                name: "Endpoint",
                value: truncateText(endpoint, 1024),
                inline: false
            },
            {
                name: "Filesize",
                value: `${normalizedSize} bytes`,
                inline: true
            }
        ];

        if (filename) {
            fields.push({
                name: "Filename",
                value: truncateText(filename, 1024),
                inline: true
            });
        }

        if (attachmentInfo?.skippedReason) {
            fields.push({
                name: "Attachment",
                value: truncateText(attachmentInfo.skippedReason, 1024),
                inline: false
            });
        }

        const webhookSent = await sendWebhookPayload(JSON.stringify({
            embeds: [{
                type: "rich",
                title: "Invalid Mii input received",
                description: truncateText(errorMessage, 4096),
                color: 0xff8844,
                fields,
                timestamp: new Date().toISOString()
            }]
        }), attachmentInfo?.attachment ? [attachmentInfo.attachment] : []);

        if (!webhookSent) {
            rawConsoleError("Invalid Mii input webhook skipped because hookUrl is not configured.");
        }
    } catch (webhookError) {
        rawConsoleError("Failed to upload invalid Mii input to the webhook:", webhookError);
    }
}

async function sendSavedFailingUploadToWebhook({
    req,
    error,
    context = "upload",
    dumpedUpload = null
} = {}) {
    if (!dumpedUpload?.destinationPath) return;

    try {
        const attachmentInfo = await buildInvalidMiiWebhookAttachment({
            reqFile: {
                originalname: dumpedUpload.originalName,
                mimetype: dumpedUpload.contentType
            },
            filePath: dumpedUpload.destinationPath
        });
        const userLabel = normalizeReportText(req?.user?.username, 80) || "Anonymous";
        const endpoint = String(req?.originalUrl || req?.path || "Unknown").trim() || "Unknown";
        const errorMessage = normalizeReportText(error?.message || error, 3000) || "Unknown error";
        const relativeSavedPath = path.relative(__dirname, dumpedUpload.destinationPath).replace(/\\/g, "/");

        const fields = [
            {
                name: "Context",
                value: truncateText(context, 1024),
                inline: true
            },
            {
                name: "User",
                value: truncateText(userLabel, 1024),
                inline: true
            },
            {
                name: "Endpoint",
                value: truncateText(endpoint, 1024),
                inline: false
            },
            {
                name: "Saved File",
                value: truncateText(relativeSavedPath || path.basename(dumpedUpload.destinationPath), 1024),
                inline: false
            },
            {
                name: "Original Filename",
                value: truncateText(dumpedUpload.originalName || path.basename(dumpedUpload.destinationPath), 1024),
                inline: true
            },
            {
                name: "Filesize",
                value: `${Math.trunc(dumpedUpload.size || 0)} bytes`,
                inline: true
            }
        ];

        if (attachmentInfo?.skippedReason) {
            fields.push({
                name: "Attachment",
                value: truncateText(attachmentInfo.skippedReason, 1024),
                inline: false
            });
        }

        const webhookSent = await sendWebhookPayload(JSON.stringify({
            embeds: [{
                type: "rich",
                title: "Saved failing upload captured",
                description: truncateText(errorMessage, 4096),
                color: 0xff8844,
                fields,
                timestamp: new Date().toISOString()
            }]
        }), attachmentInfo?.attachment ? [attachmentInfo.attachment] : []);

        if (!webhookSent) {
            rawConsoleError("Failing upload webhook skipped because hookUrl is not configured.");
        }
    } catch (webhookError) {
        rawConsoleError("Failed to upload saved failing file to the webhook:", webhookError);
    }
}

async function getUserByUsername(username, lean=true) {
    let userPromise = Users.findOne({ username });
    if (lean) userPromise = userPromise.lean();
    return await userPromise;
}

async function countUsersWhoVotedForMii(miiId) {
    const normalizedMiiId = String(miiId || "").trim();
    if (!normalizedMiiId) return 0;
    return Users.countDocuments({ votedFor: normalizedMiiId });
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

function isMiiLikeLockedForUser(mii, user) {
    return Boolean(
        !mii?.official &&
        user?.username &&
        (mii.uploader === user.username || mii.contributor === user.username)
    );
}

async function decrementMiiVote(miiId, { minimumVotes = 0 } = {}) {
    const normalizedMiiId = String(miiId || "").trim();
    const normalizedMinimumVotes = Number.isFinite(Number(minimumVotes))
        ? Math.max(0, Number(minimumVotes))
        : 0;
    if (!normalizedMiiId) return;

    await Miis.updateOne(
        { id: normalizedMiiId, votes: { $gt: normalizedMinimumVotes } },
        { $inc: { votes: -1 } }
    );

    if (normalizedMinimumVotes > 0) {
        await Miis.updateOne(
            {
                id: normalizedMiiId,
                $or: [
                    { votes: { $exists: false } },
                    { votes: { $lt: normalizedMinimumVotes } }
                ]
            },
            { $set: { votes: normalizedMinimumVotes } }
        );
    }
}

async function ensureOfficialMiiSeedLikes() {
    await Miis.updateMany(
        {
            official: true,
            $or: [
                { votes: { $exists: false } },
                { votes: { $lt: 1 } }
            ]
        },
        { $set: { votes: 1 } }
    );
}

function parseCsvKeywordContent(content) {
    const values = [];
    let current = "";
    let inQuotes = false;

    for (let i = 0; i < content.length; i++) {
        const char = content[i];

        if (char === '"') {
            if (inQuotes && content[i + 1] === '"') {
                current += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
            continue;
        }

        if (!inQuotes && (char === "," || char === "\n" || char === "\r")) {
            values.push(current);
            current = "";
            continue;
        }

        current += char;
    }

    values.push(current);
    return values;
}

function normalizeSeoKeyword(keyword) {
    const normalized = String(keyword || "")
        .replace(/[\u0000-\u001f\u007f]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();

    if (normalized.length < 2 || normalized.length > SEO_KEYWORD_MAX_LENGTH) return "";
    return normalized;
}

function uniqueSeoKeywords(keywords) {
    const seen = new Set();
    const uniqueKeywords = [];

    keywords
        .map(normalizeSeoKeyword)
        .filter(Boolean)
        .forEach((keyword) => {
            const key = keyword.toLowerCase();
            if (seen.has(key)) return;
            seen.add(key);
            uniqueKeywords.push(keyword);
        });

    return uniqueKeywords;
}

function parseKeywordInput(input) {
    if (Array.isArray(input)) {
        return input.flatMap(parseKeywordInput);
    }

    if (typeof input === "undefined" || input === null) return [];
    return parseCsvKeywordContent(String(input));
}

function getSeoKeywordCatalog() {
    if (cachedSeoKeywords) return cachedSeoKeywords;

    try {
        const csv = fs.readFileSync(SEO_KEYWORDS_CSV_PATH, "utf8");
        cachedSeoKeywords = uniqueSeoKeywords(parseCsvKeywordContent(csv));
    } catch (error) {
        cachedSeoKeywords = [];
        if (!loggedSeoKeywordLoadError) {
            loggedSeoKeywordLoadError = true;
            console.warn(`[seo] Could not load seoKeywords.csv: ${error.message}`);
        }
    }

    return cachedSeoKeywords;
}

function getSeoKeywordTokens(values) {
    return new Set(
        parseKeywordInput(values)
            .join(" ")
            .toLowerCase()
            .split(/[^a-z0-9.]+/g)
            .map(token => token.trim())
            .filter(token => (token.length > 2 || SEO_KEYWORD_SHORT_TOKENS.has(token)) && !SEO_KEYWORD_STOPWORDS.has(token))
    );
}

function scoreSeoKeyword(keyword, tokens) {
    const normalized = keyword.toLowerCase();
    let score = 0;

    tokens.forEach((token) => {
        if (normalized === token) {
            score += 8;
        } else if (normalized.startsWith(`${token} `) || normalized.endsWith(` ${token}`)) {
            score += 4;
        } else if (normalized.includes(token)) {
            score += token.length > 4 ? 3 : 1;
        }
    });

    if (normalized.includes("mii")) score += 1;
    return score;
}

function clampSeoKeywordLimit(limit, fallbackLimit) {
    const numericLimit = Number(limit);
    if (!Number.isFinite(numericLimit) || numericLimit <= 0) return fallbackLimit;
    return Math.min(Math.floor(numericLimit), SEO_KEYWORD_META_LIMIT);
}

function buildSeoKeywordList(seedValues = [], options = {}) {
    const limit = clampSeoKeywordLimit(options.limit, SEO_KEYWORD_META_LIMIT);
    const seedKeywords = uniqueSeoKeywords(parseKeywordInput(seedValues));
    const tokens = getSeoKeywordTokens([
        seedKeywords,
        options.context || [],
        options.contextValues || []
    ]);
    const seen = new Set(seedKeywords.map(keyword => keyword.toLowerCase()));
    const catalog = getSeoKeywordCatalog();
    const rankedCatalogKeywords = catalog
        .filter(keyword => !seen.has(keyword.toLowerCase()))
        .map(keyword => ({
            keyword,
            score: scoreSeoKeyword(keyword, tokens)
        }))
        .filter(item => item.score > 0)
        .sort((a, b) => b.score - a.score || a.keyword.length - b.keyword.length)
        .map(item => item.keyword);
    const combined = uniqueSeoKeywords([
        ...seedKeywords,
        ...rankedCatalogKeywords
    ]);

    if (combined.length < limit && options.fallbackToGeneral !== false) {
        combined.push(
            ...catalog.filter(keyword => !combined.some(existing => existing.toLowerCase() === keyword.toLowerCase()))
        );
    }

    const output = uniqueSeoKeywords(combined).slice(0, limit);
    return options.asArray ? output : output.join(", ");
}

function getMiiAttribution(mii) {
    const uploaderName = String(mii?.uploader || "").trim();
    const sourceName = mii?.official
        ? (normalizeCompanySourceName(mii?.officialSource || uploaderName) || DEFAULT_OFFICIAL_COMPANY_SOURCE)
        : uploaderName;
    const label = sourceName || "Unknown";

    return {
        label,
        prefix: mii?.official ? "Source" : "By",
        url: label && label !== "Unknown" ? `/user/${encodeURIComponent(label)}` : "",
        isOfficialSource: Boolean(mii?.official)
    };
}

//#endregion

const ejsFunctions = {
    "decodeColor": (colorIndex) => (["Red", "#dd5e17", "#e2cd5e", "Lime", "Green", "Blue", "Cyan", "#e65ba1", "Purple", "Brown", "White", "Black"][colorIndex] || colorIndex),
    buildSeoKeywordList,
    getMiiAttribution,
    toScriptJson: (value, space = 0) => toSafeInlineScriptJson(value, space)
}

/** Build EJS variables for the page. `user` is assumed to be the logged in user */
async function getSendables(req, title, user) { 
    const currentPath = req.path;
    const queryString = Object.keys(req.query).length > 0 
        ? '?' + new URLSearchParams(req.query).toString() 
        : '';
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const settings = await getSettings();
    const availableTags = getMiiTags(settings);
    const selectedTags = mapRequestedTagsToCatalog(req.query?.tags, availableTags);
    const searchFieldsExplicitlyConfigured = parseBooleanLike(req.query?.searchFieldsConfigured);
    const selectedSearchFields = getRequestedSearchFields(req.query);

    // Build information related to the current user
    let userPfpMiiColor = null;
    const currentUser = req.user?.username || "Default";
    const pfp = req.user?.miiPfp || "00000";
    const [
        highlightedMiiData,
        averageMiiData,
        userPfpMii
    ] = await Promise.all([
        getMiiById(settings.highlightedMii, false),
        getMiiById("average", false),
        req.user ? getMiiById(pfp, true) : Promise.resolve(null)
    ]);

    if (req.user) {
        userPfpMiiColor = (userPfpMii || averageMiiData)?.general?.favoriteColor ?? null;
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
        prevUrl: undefined,
        nextUrl: undefined,
        discordInvite: process.env.discordInvite,
        githubLink: process.env.githubLink,
        paypalDonateUrl: PAYPAL_DONATE_URL,
        assetVersion: GLOBAL_ASSET_VERSION,
        baseUrl: resolvedBaseUrl,
        title: title,
        exportFormats: EXPORT_FORMATS,
        favoriteColors: Array.isArray(miijs.FavoriteColors) ? miijs.FavoriteColors : [],
        userPfpMiiColor: userPfpMiiColor ?? "#111111",
        highlightedMiiData,
        averageMiiData,
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

function getDisplayMiiName(mii) {
    const candidate = mii?.meta?.name ?? mii?.name ?? "";
    const normalized = String(candidate || "").trim();
    return normalized || "Unknown Mii";
}

function uniqueTextValues(values) {
    const source = Array.isArray(values) ? values : [values];
    const flattened = source.flatMap(value => Array.isArray(value) ? value : [value]);
    const normalized = [];
    const seen = new Set();

    for (const value of flattened) {
        const text = String(value || "").trim();
        if (!text) continue;

        const key = text.toLowerCase();
        if (seen.has(key)) continue;

        seen.add(key);
        normalized.push(text);
    }

    return normalized;
}

function getMiiFavoriteColorLabel(colorIndex) {
    const favoriteColors = [
        "Red",
        "Orange",
        "Yellow",
        "Lime",
        "Green",
        "Blue",
        "Cyan",
        "Pink",
        "Purple",
        "Brown",
        "White",
        "Black"
    ];
    const parsedIndex = Number.parseInt(colorIndex, 10);
    return Number.isInteger(parsedIndex) && favoriteColors[parsedIndex]
        ? favoriteColors[parsedIndex]
        : "";
}

function getMiiGenderLabel(gender) {
    const parsedGender = Number.parseInt(gender, 10);
    if (parsedGender === 0) return "Male";
    if (parsedGender === 1) return "Female";
    return "";
}

function getConsoleLabel(rawConsole) {
    const original = typeof rawConsole === "string" ? rawConsole.trim() : "";
    if (!original) return "";

    const normalized = original.toUpperCase();
    const consoleLabels = {
        "3DS": "3DS",
        "WII": "Wii",
        "WIIU": "Wii U",
        "SWITCH": "Switch",
        "MIITOMO": "Miitomo",
        "DS": "DS",
        "DSI": "DSi",
        "TOMODACHI LIFE": "Tomodachi Life"
    };

    return consoleLabels[normalized] || original;
}

function getReadableBirthdayLabel(month, day) {
    const monthNames = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const parsedMonth = Number.parseInt(month, 10);
    const parsedDay = Number.parseInt(day, 10);

    if (!Number.isInteger(parsedMonth) || parsedMonth < 1 || parsedMonth > 12) return "";
    if (!Number.isInteger(parsedDay) || parsedDay < 1 || parsedDay > 31) return "";

    return `${monthNames[parsedMonth]} ${parsedDay}`;
}

function normalizeTimestampValue(value) {
    if (value instanceof Date) {
        const timestamp = value.getTime();
        return Number.isFinite(timestamp) ? timestamp : undefined;
    }

    const numericValue = Number(value);
    return Number.isFinite(numericValue) ? numericValue : undefined;
}

function getUserJoinTimestamp(user) {
    return normalizeTimestampValue(user?.joinedOn)
        ?? normalizeTimestampValue(user?.creationDate)
        ?? normalizeTimestampValue(user?.createdAt);
}

function getMiiCategoryDetails(rawPaths, categoryConfig) {
    const normalizedPaths = normalizeCategoryPaths(rawPaths);
    const categoryTree = Array.isArray(categoryConfig?.categories)
        ? categoryConfig.categories
        : (Array.isArray(categoryConfig) ? categoryConfig : []);

    return normalizedPaths.map((path) => {
        const node = findCategoryByPath(path, categoryTree);
        const pathSegments = path.split("/").map(segment => segment.trim()).filter(Boolean);
        const fallbackName = pathSegments[pathSegments.length - 1] || path;

        return {
            path,
            name: node?.name || fallbackName,
            fullPath: node?.fullPath || path,
            color: normalizeCategoryColor(node?.color),
            url: `/official?category=${encodeURIComponent(path)}`
        };
    });
}

function buildMiiSeoDetails(mii, categoryConfig, options = {}) {
    const miiName = getDisplayMiiName(mii);
    const creatorName = String(mii?.meta?.creatorName || "").trim();
    const uploaderName = String(mii?.uploader || "").trim();
    const contributorName = String(mii?.contributor || "").trim();
    const officialSourceName = mii?.official
        ? (String(options.officialSourceName || "").trim()
            || normalizeCompanySourceName(mii?.officialSource || mii?.uploader)
            || DEFAULT_OFFICIAL_COMPANY_SOURCE)
        : "";
    const consoleLabel = getConsoleLabel(mii?.meta?.console || mii?.console || "");
    const favoriteColorName = getMiiFavoriteColorLabel(mii?.general?.favoriteColor);
    const genderLabel = getMiiGenderLabel(mii?.general?.gender);
    const birthdayLabel = getReadableBirthdayLabel(mii?.general?.birthMonth, mii?.general?.birthday);
    const categoryDetails = getMiiCategoryDetails(mii?.officialCategories || [], categoryConfig);
    const categoryNames = categoryDetails.map(category => category.name);
    const tagList = uniqueTextValues(normalizeTagList(mii?.tags || []));
    const archiveTypeLabel = mii?.private
        ? "Private Mii"
        : (mii?.official ? "Official Mii" : "Community Mii");
    const typeLabel = String(mii?.meta?.type || "").trim().toLowerCase() === "special"
        ? "Special Mii"
        : "Standard Mii";
    const primaryOwnerLabel = mii?.official ? officialSourceName : uploaderName;

    const metaDescriptionParts = [
        `Download ${miiName}, an ${archiveTypeLabel.toLowerCase()}${mii?.official ? ` from ${officialSourceName}` : (uploaderName ? ` uploaded by ${uploaderName}` : "")}${creatorName ? ` with creator name ${creatorName}` : ""}.`,
        consoleLabel
            ? `Includes QR code access and export options for ${consoleLabel} Mii workflows.`
            : "Includes QR code access and export options for Nintendo Mii workflows.",
        categoryNames.length
            ? `Filed under ${categoryNames.slice(0, 3).join(", ")}.`
            : "",
        tagList.length
            ? `Tagged ${tagList.slice(0, 4).join(", ")}.`
            : ""
    ].filter(Boolean);

    const searchTopicPhrases = uniqueTextValues([
        `${miiName} Mii`,
        `${miiName} Mii QR code`,
        `${miiName} Mii download`,
        `${miiName} Mii character`,
        creatorName ? `${creatorName} Mii` : "",
        primaryOwnerLabel ? `${primaryOwnerLabel} Mii` : "",
        mii?.official && officialSourceName ? `${officialSourceName} official Mii` : "",
        consoleLabel ? `${miiName} ${consoleLabel}` : "",
        favoriteColorName ? `${favoriteColorName} Mii` : "",
        genderLabel ? `${genderLabel} Mii` : "",
        ...tagList.map(tag => `${tag} Mii`),
        ...categoryNames.map(name => `${name} Mii`)
    ]).slice(0, 20);

    const keywordList = uniqueTextValues([
        miiName,
        `${miiName} Mii`,
        `${miiName} Mii QR code`,
        `${miiName} Mii download`,
        `${miiName} Mii character`,
        creatorName ? `${creatorName} Mii` : "",
        primaryOwnerLabel ? `${primaryOwnerLabel} Mii` : "",
        mii?.official && officialSourceName ? `${officialSourceName} official Mii` : "",
        consoleLabel ? `${miiName} ${consoleLabel}` : "",
        favoriteColorName ? `${favoriteColorName} Mii` : "",
        genderLabel ? `${genderLabel} Mii` : "",
        ...tagList,
        ...categoryNames
    ]).slice(0, 28);

    return {
        name: miiName,
        creatorName,
        uploaderName,
        contributorName,
        officialSourceName,
        consoleLabel,
        favoriteColorName,
        genderLabel,
        birthdayLabel,
        categoryDetails,
        categoryNames,
        tagList,
        archiveTypeLabel,
        typeLabel,
        primaryOwnerLabel,
        searchTopicPhrases,
        keywordList,
        metaDescription: metaDescriptionParts.join(" ").replace(/\s+/g, " ").trim()
    };
}

function buildCuratedMiiCollections(collections, limitPerCollection = 5) {
    const usedIds = new Set();
    const curatedCollections = [];

    for (const collection of collections) {
        const items = Array.isArray(collection?.items) ? collection.items : [];
        const curatedItems = [];

        for (const item of items) {
            const id = String(item?.id || "").trim();
            if (!id || usedIds.has(id)) continue;

            usedIds.add(id);
            curatedItems.push(item);

            if (curatedItems.length >= limitPerCollection) {
                break;
            }
        }

        if (curatedItems.length > 0) {
            curatedCollections.push({
                ...collection,
                items: curatedItems
            });
        }
    }

    return curatedCollections;
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

function normalizeSimilarMiiText(value) {
    return normalizeSearchText(value).replace(/\s+/g, " ").trim();
}

function getComparableMiiName(mii) {
    const candidates = [mii?.meta?.name, mii?.name];

    for (const candidate of candidates) {
        const name = String(candidate ?? "")
            .replace(/\s+/g, " ")
            .trim();
        if (name) return name;
    }

    return "";
}

function getSimilarMiiDescriptionText(mii) {
    const description = String(mii?.desc ?? mii?.description ?? "")
        .replace(/\s+/g, " ")
        .trim();
    const normalizedDescription = normalizeSimilarMiiText(description);

    if (!normalizedDescription || normalizedDescription === "no description provided") {
        return "";
    }

    return description;
}

function getSimilarMiiTerms(value, { limit = SIMILAR_MII_DESCRIPTION_TERM_LIMIT } = {}) {
    const normalized = normalizeSimilarMiiText(value);
    const rawTerms = normalized.match(/[\p{L}\p{N}]+/gu) || [];
    const terms = [];
    const seen = new Set();

    for (const rawTerm of rawTerms) {
        const term = rawTerm.trim();
        if (!term || (term === "s" && rawTerms.length > 1)) continue;
        if (term.length < 3 && !SEO_KEYWORD_SHORT_TOKENS.has(term)) continue;
        if (SIMILAR_MII_GENERIC_TERMS.has(term)) continue;
        if (seen.has(term)) continue;

        seen.add(term);
        terms.push(term);

        if (terms.length >= limit) {
            break;
        }
    }

    return terms;
}

function countSetMatches(sourceSet, candidateSet) {
    let count = 0;

    for (const value of sourceSet) {
        if (candidateSet.has(value)) {
            count += 1;
        }
    }

    return count;
}

function getSimilarMiiTagKeys(tags) {
    return normalizeTagList(tags)
        .map(normalizeSimilarMiiText)
        .filter(Boolean);
}

function getSimilarMiiTagTerms(tags, { limit = SIMILAR_MII_TAG_TERM_LIMIT } = {}) {
    return getSimilarMiiTerms(normalizeTagList(tags).join(" "), { limit });
}

function buildContainsCaseInsensitiveRegex(value) {
    const normalized = String(value ?? "").trim();
    return normalized ? new RegExp(escapeRegExp(normalized), "i") : null;
}

function buildSimilarMiiContext(mii) {
    const currentTags = normalizeTagList(mii?.tags || []);
    const tagKeys = getSimilarMiiTagKeys(currentTags);
    const tagTerms = getSimilarMiiTagTerms(currentTags);
    const descriptionTerms = getSimilarMiiTerms(getSimilarMiiDescriptionText(mii));

    return {
        name: normalizeSimilarMiiText(getComparableMiiName(mii)),
        currentTags,
        tagKeySet: new Set(tagKeys),
        tagTermSet: new Set(tagTerms),
        descriptionTermSet: new Set(descriptionTerms),
        tagTerms,
        descriptionTerms
    };
}

function scoreSimilarMiiCandidate(candidate, context) {
    const candidateName = normalizeSimilarMiiText(getComparableMiiName(candidate));
    const candidateTagKeySet = new Set(getSimilarMiiTagKeys(candidate?.tags || []));
    const candidateTagTermSet = new Set(getSimilarMiiTagTerms(candidate?.tags || [], {
        limit: SIMILAR_MII_TAG_TERM_LIMIT * 2
    }));
    const candidateDescriptionTermSet = new Set(getSimilarMiiTerms(getSimilarMiiDescriptionText(candidate), {
        limit: SIMILAR_MII_DESCRIPTION_TERM_LIMIT * 2
    }));
    const exactTagMatches = countSetMatches(context.tagKeySet, candidateTagKeySet);

    return {
        sameName: Boolean(context.name && candidateName && candidateName === context.name),
        exactTagSetMatch: Boolean(
            context.tagKeySet.size > 0
            && exactTagMatches === context.tagKeySet.size
            && candidateTagKeySet.size === context.tagKeySet.size
        ),
        exactTagMatches,
        similarTagTermMatches: countSetMatches(context.tagTermSet, candidateTagTermSet),
        descriptionTermMatches: countSetMatches(context.descriptionTermSet, candidateDescriptionTermSet)
    };
}

function hasSimilarMiiSignal(score) {
    return Boolean(
        score.sameName
        || score.exactTagMatches > 0
        || score.similarTagTermMatches > 0
        || score.descriptionTermMatches > 0
    );
}

function compareSimilarMiiEntries(left, right) {
    return Number(right.score.sameName) - Number(left.score.sameName)
        || Number(right.score.exactTagSetMatch) - Number(left.score.exactTagSetMatch)
        || right.score.exactTagMatches - left.score.exactTagMatches
        || right.score.similarTagTermMatches - left.score.similarTagTermMatches
        || right.score.descriptionTermMatches - left.score.descriptionTermMatches
        || (right.mii?.votes || 0) - (left.mii?.votes || 0)
        || (right.mii?.uploadedOn || 0) - (left.mii?.uploadedOn || 0)
        || String(left.mii?.id || "").localeCompare(String(right.mii?.id || ""));
}

function rankSimilarMiiCandidates(candidates, context, limit = 8) {
    const uniqueCandidates = new Map();

    for (const candidate of candidates) {
        const id = String(candidate?.id || "").trim();
        if (!id || uniqueCandidates.has(id)) continue;
        uniqueCandidates.set(id, candidate);
    }

    return [...uniqueCandidates.values()]
        .map((candidate) => ({
            mii: candidate,
            score: scoreSimilarMiiCandidate(candidate, context)
        }))
        .filter((entry) => hasSimilarMiiSignal(entry.score))
        .sort(compareSimilarMiiEntries)
        .slice(0, limit)
        .map((entry) => entry.mii);
}

async function findSimilarMiis(mii, visibilityFilter, limit = 8) {
    const context = buildSimilarMiiContext(mii);
    const candidateQueries = [];
    const sort = getStablePopularitySort();
    const name = getComparableMiiName(mii);

    if (name) {
        const nameRegex = buildExactCaseInsensitiveRegex(name);
        candidateQueries.push(
            Miis.find({
                ...visibilityFilter,
                $or: [
                    { "meta.name": nameRegex },
                    { name: nameRegex }
                ]
            })
                .sort(sort)
                .limit(SIMILAR_MII_QUERY_LIMIT)
                .lean()
        );
    }

    if (context.currentTags.length > 0) {
        candidateQueries.push(
            Miis.find({
                ...visibilityFilter,
                tags: { $in: context.currentTags.map(buildExactCaseInsensitiveRegex) }
            })
                .sort(sort)
                .limit(SIMILAR_MII_QUERY_LIMIT)
                .lean()
        );
    }

    const tagTermRegexes = context.tagTerms
        .slice(0, SIMILAR_MII_TOKEN_QUERY_LIMIT)
        .map(buildContainsCaseInsensitiveRegex)
        .filter(Boolean);
    if (tagTermRegexes.length > 0) {
        candidateQueries.push(
            Miis.find({
                ...visibilityFilter,
                tags: { $in: tagTermRegexes }
            })
                .sort(sort)
                .limit(SIMILAR_MII_QUERY_LIMIT)
                .lean()
        );
    }

    const descriptionTermRegexes = context.descriptionTerms
        .slice(0, SIMILAR_MII_TOKEN_QUERY_LIMIT)
        .map(buildContainsCaseInsensitiveRegex)
        .filter(Boolean);
    if (descriptionTermRegexes.length > 0) {
        candidateQueries.push(
            Miis.find({
                ...visibilityFilter,
                $or: descriptionTermRegexes.map((regex) => ({ desc: regex }))
            })
                .sort(sort)
                .limit(SIMILAR_MII_QUERY_LIMIT)
                .lean()
        );
    }

    if (candidateQueries.length === 0) {
        return [];
    }

    const candidateGroups = await Promise.all(candidateQueries);
    return rankSimilarMiiCandidates(candidateGroups.flat(), context, limit);
}

function hasDecodedTomodachiLifeData(mii) {
    const tlData = mii?.tl;
    if (tlData === null || tlData === undefined) return false;
    if (typeof tlData !== "object") return true;
    return Object.keys(tlData).length > 0;
}

function getTomodachiLifeDisplayValue(value, fallback = "Unknown") {
    const normalized = String(value ?? "")
        .replace(/\s+/g, " ")
        .trim();
    return normalized || fallback;
}

function buildTomodachiLifeUploadWebhookFields(mii) {
    if (!hasDecodedTomodachiLifeData(mii)) return [];

    const tl = mii.tl || {};
    const firstName = getTomodachiLifeDisplayValue(tl.firstName);
    const lastName = getTomodachiLifeDisplayValue(tl.lastName);
    const islandName = getTomodachiLifeDisplayValue(tl.island?.name);
    const catchphrase = getTomodachiLifeDisplayValue(tl.catchphrase);

    return [{
        name: "Tomodachi Life",
        value: truncateText(
            `In Tomodachi Life, this Mii is named ${firstName} ${lastName}, and comes from ${islandName} Island. Their catchphrase is ${catchphrase}.`,
            1024
        ),
        inline: false
    }];
}

async function applyAutomaticDecodedMiiTags(mii) {
    if (!mii || typeof mii !== "object") return mii;
    if (!hasDecodedTomodachiLifeData(mii)) return mii;

    const autoTags = [TOMODACHI_LIFE_TAG];
    const autoTagKeys = new Set(autoTags.map(tag => tag.toLowerCase()));
    const existingTags = normalizeTagList(mii.tags || []).filter(
        tag => !autoTagKeys.has(tag.toLowerCase())
    );

    mii.tags = [...existingTags, ...autoTags];
    await updateSettings({
        $addToSet: {
            miiTags: { $each: autoTags }
        }
    });
    return mii;
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

function getUserOwnedPublicMiiQuery(username) {
    return {
        private: false,
        published: true,
        id: { $ne: "average" },
        $or: [
            { uploader: username },
            { officialSource: username },
            { contributor: username }
        ]
    };
}

async function syncUnsetUserProfilePictures() {
    const cursor = Users.find({ pfpSet: { $ne: true } })
        .select("username")
        .cursor();

    let updatedCount = 0;
    for await (const user of cursor) {
        const username = String(user?.username || "").trim();
        if (!username) continue;

        const topMii = await Miis.findOne(getUserOwnedPublicMiiQuery(username))
            .sort(getStablePopularitySort())
            .select("id")
            .lean();

        if (!topMii?.id) continue;

        const result = await Users.updateOne(
            { username, pfpSet: { $ne: true } },
            { $set: { miiPfp: topMii.id, pfpSet: false } }
        );
        updatedCount += result.modifiedCount || 0;

        if (updatedCount > 0 && updatedCount % 100 === 0) {
            await yieldToEventLoop();
        }
    }

    if (updatedCount > 0) {
        console.log(`[pfp] Updated ${updatedCount} unset user profile picture${updatedCount === 1 ? "" : "s"}.`);
    }

    return updatedCount;
}

async function ensureOfficialCompanySourceAccount(sourceName, settings = null) {
    const normalizedSource = normalizeCompanySourceName(sourceName);
    if (!normalizedSource) return;

    const existingUser = await getUserByUsername(normalizedSource);
    if (existingUser) return;

    try {
        const resolvedSettings = settings || await getSettings();
        await Users.create({
            username: normalizedSource,
            salt: "",
            pass: "",
            creationDate: Date.now(),
            email: "",
            votedFor: [],
            miiPfp: getDefaultUserPfpMiiId(resolvedSettings),
            pfpSet: false,
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

    await ensureOfficialCompanySourceAccount(selectedSource, settings);

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

async function persistUploadedMii(mii, {
    uploader,
    wantsPublic,
    isOfficialUpload = false,
    officialSource = null,
    desc = "",
    officialCategories = []
} = {}) {
    const normalizedOfficialCategories = isOfficialUpload ? normalizeCategoryPaths(officialCategories) : [];

    mii.officialCategories = normalizedOfficialCategories;
    mii.id = await genId();
    mii.uploadedOn = Date.now();
    mii.uploader = isOfficialUpload ? officialSource : uploader;
    mii.contributor = isOfficialUpload ? uploader : undefined;
    mii.officialSource = isOfficialUpload ? officialSource : undefined;
    mii.desc = desc;
    mii.votes = 1;
    mii.official = isOfficialUpload;
    mii.published = wantsPublic;
    mii.blockedFromPublishing = false;
    setMiiIdentityHash(mii);
    await applyAutomaticDecodedMiiTags(mii);
    ensureUploadMiiPermissions(mii);

    const { imgPath, qrPath, qrWiiPath } = getMiiAssetPaths(mii.id, !wantsPublic);
    const assetPaths = {
        img: imgPath,
        qr3ds: qrPath,
        qrWii: qrWiiPath
    };

    try {
        await Promise.all([
            writeRenderedMiiImage(mii, assetPaths.img),
            writeQrPng(mii, assetPaths.qr3ds, "3DS"),
            writeQrPng(mii, assetPaths.qrWii, "WIIU")
        ]);
        await Miis.create({
            ...mii,
            id: mii.id,
            private: !wantsPublic
        });
    } catch (error) {
        await Promise.all([
            fs.promises.unlink(assetPaths.img).catch(() => {}),
            fs.promises.unlink(assetPaths.qr3ds).catch(() => {}),
            fs.promises.unlink(assetPaths.qrWii).catch(() => {})
        ]);
        throw error;
    }

    if (!isOfficialUpload) {
        await ensureUploaderAutoLike(uploader, mii.id, 1);
    }

    return { mii, assetPaths };
}

async function mergeOfficialCategoriesIntoDuplicateMii(matchingMii, officialCategories) {
    if (!matchingMii?.id || !matchingMii.official) return null;

    const categoriesToMerge = normalizeCategoryPaths(officialCategories);
    if (categoriesToMerge.length === 0) return null;

    const existingCategories = normalizeCategoryPaths(matchingMii.officialCategories);
    const existingCategorySet = new Set(existingCategories);
    const categoriesToAdd = categoriesToMerge.filter(categoryPath => !existingCategorySet.has(categoryPath));
    if (categoriesToAdd.length === 0) return null;

    const mergedCategories = normalizeCategoryPaths([...existingCategories, ...categoriesToAdd]);
    const result = await Miis.updateOne(
        { id: matchingMii.id, official: true },
        { $addToSet: { officialCategories: { $each: categoriesToAdd } } }
    );
    if (!result.modifiedCount) return null;

    return {
        ...matchingMii,
        officialCategories: mergedCategories
    };
}

const officialZipMiiHashLocks = new Map();

async function withOfficialZipMiiHashLock(miiHash, task) {
    if (!miiHash) {
        return task();
    }

    // ZIP uploads run in the background; serialize duplicate check + save per Mii hash.
    const previousLock = officialZipMiiHashLocks.get(miiHash) || Promise.resolve();
    let releaseLock;
    const currentLock = new Promise((resolve) => {
        releaseLock = resolve;
    });
    const lockTail = previousLock.catch(() => {}).then(() => currentLock);
    officialZipMiiHashLocks.set(miiHash, lockTail);

    await previousLock.catch(() => {});
    try {
        return await task();
    } finally {
        releaseLock();
        if (officialZipMiiHashLocks.get(miiHash) === lockTail) {
            officialZipMiiHashLocks.delete(miiHash);
        }
    }
}

function buildOfficialZipUploadSummary({
    uploadedCount = 0,
    duplicateCategoryMergeCount = 0,
    duplicateCount = 0,
    invalidCount = 0,
    failedCount = 0
} = {}) {
    const parts = [`Uploaded ${uploadedCount} official Mii${uploadedCount === 1 ? "" : "s"} from the ZIP archive.`];
    if (duplicateCategoryMergeCount > 0) {
        parts.push(`Merged categories onto ${duplicateCategoryMergeCount} duplicate official Mii${duplicateCategoryMergeCount === 1 ? "" : "s"}.`);
    }
    if (duplicateCount > 0) {
        parts.push(`Skipped ${duplicateCount} duplicate${duplicateCount === 1 ? "" : "s"}.`);
    }
    if (invalidCount > 0) {
        parts.push(`Skipped ${invalidCount} file${invalidCount === 1 ? "" : "s"} that could not be decoded.`);
    }
    if (failedCount > 0) {
        parts.push(`Skipped ${failedCount} file${failedCount === 1 ? "" : "s"} that failed during processing.`);
    }
    return parts.join(" ");
}

function buildOfficialZipUploadFailureMessage({
    duplicateCategoryMergeCount = 0,
    duplicateCount = 0,
    invalidCount = 0,
    failedCount = 0
} = {}) {
    const parts = ["No new Miis were uploaded from this ZIP archive."];
    if (duplicateCategoryMergeCount > 0) {
        parts.push(`Merged categories onto ${duplicateCategoryMergeCount} duplicate official Mii${duplicateCategoryMergeCount === 1 ? "" : "s"}.`);
    }
    if (duplicateCount > 0) {
        parts.push(`${duplicateCount} file${duplicateCount === 1 ? "" : "s"} matched Miis already in the archive.`);
    }
    if (invalidCount > 0) {
        parts.push(`${invalidCount} file${invalidCount === 1 ? "" : "s"} could not be decoded as Miis.`);
    }
    if (failedCount > 0) {
        parts.push(`${failedCount} file${failedCount === 1 ? "" : "s"} failed during processing.`);
    }
    return parts.join(" ");
}

async function sendOfficialZipUploadReport({
    uploader,
    officialSource,
    description,
    officialCategories,
    uploadedMiis,
    duplicateCategoryMergeCount,
    duplicateCount,
    invalidCount,
    failedCount
}) {
    const previewNames = uploadedMiis
        .slice(0, 12)
        .map(({ mii }) => getDisplayMiiName(mii))
        .join(", ");
    const moreCount = Math.max(0, uploadedMiis.length - 12);
    const uploadedNames = previewNames
        ? `${previewNames}${moreCount > 0 ? `, +${moreCount} more` : ""}`
        : "Unknown";
    const uploadedIds = uploadedMiis
        .slice(0, 8)
        .map(({ mii }) => `[${mii.id}](https://infinimii.com/mii/${encodeURIComponent(mii.id)})`)
        .join(", ");
    const uploadedAt = new Date();

    await makeReport(JSON.stringify({
        embeds: [{
            type: "rich",
            title: "Official ZIP Mii Upload",
            description: truncateText(description || buildOfficialZipUploadSummary({
                uploadedCount: uploadedMiis.length,
                duplicateCategoryMergeCount,
                duplicateCount,
                invalidCount,
                failedCount
            }), 4096),
            color: 0x00aaff,
            fields: [
                {
                    name: "Uploaded Count",
                    value: String(uploadedMiis.length),
                    inline: true
                },
                {
                    name: "Official Source",
                    value: `[${officialSource}](https://infinimii.com/user/${encodeURIComponent(officialSource)})`,
                    inline: true
                },
                {
                    name: "Contributed by",
                    value: `[${uploader}](https://infinimii.com/user/${encodeURIComponent(uploader)})`,
                    inline: true
                },
                {
                    name: "Categories",
                    value: officialCategories.length > 0
                        ? truncateText(officialCategories.join(", "), 1024)
                        : "None",
                    inline: false
                },
                {
                    name: "Uploaded Miis",
                    value: truncateText(uploadedNames, 1024),
                    inline: false
                },
                {
                    name: "Sample IDs",
                    value: uploadedIds || "Unavailable",
                    inline: false
                },
                {
                    name: "Skipped",
                    value: `Duplicates: ${duplicateCount}\nCategory merges: ${duplicateCategoryMergeCount}\nInvalid: ${invalidCount}\nProcessing failures: ${failedCount}`,
                    inline: false
                }
            ],
            footer: {
                text: `Uploaded at ${uploadedAt.getHours()}:${uploadedAt.getMinutes()}, ${uploadedAt.toDateString()} UTC`
            }
        }]
    }));
}

async function processOfficialZipUpload({
    zipFilePath,
    description,
    rawCategories,
    uploader,
    officialSource,
    officialSourceNotice,
    officialSettings,
    resolvedBaseUrl
}) {
    const archiveEntries = await extractOfficialZipEntries(zipFilePath);
    if (archiveEntries.length === 0) {
        return { error: "The ZIP archive did not contain any files to process." };
    }

    const validLeafPaths = getLeafCategoryPathSet(
        getOfficialCategoryTree(officialSettings || await getSettings())
    );
    const officialCategories = normalizeCategoryPaths(rawCategories)
        .filter(categoryPath => validLeafPaths.has(categoryPath));
    const duplicateEntries = [];
    const invalidEntries = [];
    const failedEntries = [];
    const uploadedMiis = [];
    const categoryMergedDuplicateMiis = [];
    const categoryMergedDuplicateMiiIds = new Set();
    const seenArchiveHashes = new Set();

    for (const entry of archiveEntries) {
        try {
            const mii = await createMiiData(entry.data);
            const miiHash = getMiiIdentityHash(mii, { includeGeneral: true });

            const entryResult = await withOfficialZipMiiHashLock(miiHash, async () => {
                if (miiHash && seenArchiveHashes.has(miiHash)) {
                    return { status: "duplicate" };
                }

                const matchingMii = await findMatchingMii(mii, { includeGeneral: true });
                if (matchingMii) {
                    let mergedMii = null;
                    try {
                        mergedMii = await mergeOfficialCategoriesIntoDuplicateMii(matchingMii, officialCategories);
                    } catch (error) {
                        console.error(`[official zip upload] Failed to merge duplicate categories for ${entry.name}:`, error);
                    }
                    if (miiHash) {
                        seenArchiveHashes.add(miiHash);
                    }
                    return { status: "duplicate", mergedMii };
                }

                try {
                    const persistedUpload = await persistUploadedMii(mii, {
                        uploader,
                        wantsPublic: true,
                        isOfficialUpload: true,
                        officialSource,
                        desc: description,
                        officialCategories
                    });
                    if (miiHash) {
                        seenArchiveHashes.add(miiHash);
                    }
                    return { status: "uploaded", persistedUpload };
                } catch (error) {
                    console.error(`[official zip upload] Failed to save ${entry.name}:`, error);
                    return { status: "failed" };
                }
            });

            if (entryResult.status === "uploaded") {
                uploadedMiis.push(entryResult.persistedUpload);
            } else if (entryResult.status === "duplicate") {
                duplicateEntries.push(entry.name);
                if (entryResult.mergedMii && !categoryMergedDuplicateMiiIds.has(entryResult.mergedMii.id)) {
                    categoryMergedDuplicateMiiIds.add(entryResult.mergedMii.id);
                    categoryMergedDuplicateMiis.push(entryResult.mergedMii);
                }
            } else if (entryResult.status === "failed") {
                failedEntries.push(entry.name);
            }
        } catch (error) {
            invalidEntries.push(entry.name);
        }

        if ((uploadedMiis.length + duplicateEntries.length + invalidEntries.length + failedEntries.length) % 10 === 0) {
            await yieldToEventLoop();
        }
    }

    if (uploadedMiis.length === 0 && categoryMergedDuplicateMiis.length === 0) {
        return {
            error: buildOfficialZipUploadFailureMessage({
                duplicateCategoryMergeCount: categoryMergedDuplicateMiis.length,
                duplicateCount: duplicateEntries.length,
                invalidCount: invalidEntries.length,
                failedCount: failedEntries.length
            })
        };
    }

    try {
        await sendOfficialZipUploadReport({
            uploader,
            officialSource,
            description,
            officialCategories,
            uploadedMiis,
            duplicateCategoryMergeCount: categoryMergedDuplicateMiis.length,
            duplicateCount: duplicateEntries.length,
            invalidCount: invalidEntries.length,
            failedCount: failedEntries.length
        });
    } catch (error) {
        console.error("[official zip upload] Failed to send upload report:", error);
    }

    const changedPublicMiis = [
        ...uploadedMiis.map(({ mii }) => ({ ...mii, private: false, published: true })),
        ...categoryMergedDuplicateMiis
    ];
    if (changedPublicMiis.length > 0) {
        notifyIndexNow(
            buildIndexNowUrlsForMiis(
                resolvedBaseUrl,
                changedPublicMiis
            ),
            resolvedBaseUrl,
            "upload-mii-zip"
        );
    }

    const summaryNotice = buildOfficialZipUploadSummary({
        uploadedCount: uploadedMiis.length,
        duplicateCategoryMergeCount: categoryMergedDuplicateMiis.length,
        duplicateCount: duplicateEntries.length,
        invalidCount: invalidEntries.length,
        failedCount: failedEntries.length
    });

    return {
        redirect: "/official",
        notice: [officialSourceNotice, summaryNotice].filter(Boolean).join(" ")
    };
}

function startOfficialZipUploadProcessing(options) {
    const zipFilePath = options?.zipFilePath;

    void (async () => {
        try {
            const result = await processOfficialZipUpload(options);
            if (result?.error) {
                console.warn(`[official zip upload] ${result.error}`);
            }
        } catch (error) {
            console.error("[official zip upload] Background processing failed:", error);
        } finally {
            if (zipFilePath) {
                try { await fs.promises.unlink(zipFilePath); } catch (cleanupError) { }
            }
        }
    })();
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

function getRequestedSearchFields(source = {}) {
    const hasExplicitFieldConfig = parseBooleanLike(source?.searchFieldsConfigured);
    return normalizeSearchFieldSelection(source?.searchIn, {
        defaultToAll: !hasExplicitFieldConfig
    });
}

function escapeRegex(input) {
    return String(input).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getAverageMiiCandidateMatch(extraMatch = {}) {
    const excludedTagPattern = new RegExp(
        `^(${AVERAGE_MII_EXCLUDED_TAGS.map(escapeRegex).join("|")})$`,
        "i"
    );

    return {
        published: true,
        private: false,
        id: { $ne: "average" },
        tags: {
            $not: {
                $elemMatch: {
                    $regex: excludedTagPattern
                }
            }
        },
        ...extraMatch
    };
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

function getMiiAssetPaths(miiId, isPrivate) {
    const qr3dsDir = isPrivate ? "privateMiiQRs" : "miiQRs";
    const qrWiiDir = isPrivate ? "privateMiiQRsWii" : "miiQRsWii";

    return {
        imgPath: isPrivate ? `./static/privateMiiImgs/${miiId}.png` : `./static/miiImgs/${miiId}.png`,
        qrPath: `./static/${qr3dsDir}/${miiId}.png`,
        qrWiiPath: `./static/${qrWiiDir}/${miiId}.png`
    };
}

function deleteMiiAssets(miiId, isPrivate) {
    const { imgPath, qrPath, qrWiiPath } = getMiiAssetPaths(miiId, isPrivate);
    try { fs.unlinkSync(imgPath); } catch (e) {}
    try { fs.unlinkSync(qrPath); } catch (e) {}
    try { fs.unlinkSync(qrWiiPath); } catch (e) {}
}

async function moveMiiAssets(miiId, fromPrivate, toPrivate) {
    const sourcePaths = getMiiAssetPaths(miiId, fromPrivate);
    const destinationPaths = getMiiAssetPaths(miiId, toPrivate);

    if (fs.existsSync(sourcePaths.imgPath)) {
        try { await fs.promises.unlink(destinationPaths.imgPath); } catch (e) {}
        await fs.promises.rename(sourcePaths.imgPath, destinationPaths.imgPath);
    }

    if (fs.existsSync(sourcePaths.qrPath)) {
        try { await fs.promises.unlink(destinationPaths.qrPath); } catch (e) {}
        await fs.promises.rename(sourcePaths.qrPath, destinationPaths.qrPath);
    }

    if (fs.existsSync(sourcePaths.qrWiiPath)) {
        try { await fs.promises.unlink(destinationPaths.qrWiiPath); } catch (e) {}
        await fs.promises.rename(sourcePaths.qrWiiPath, destinationPaths.qrWiiPath);
    }

    return destinationPaths;
}

function escapeRegExp(value) {
    return String(value ?? "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildExactCaseInsensitiveRegex(value) {
    return new RegExp(`^${escapeRegExp(String(value ?? "").trim())}$`, "i");
}

function normalizeMiiIdInput(rawId) {
    return typeof rawId === "string" ? rawId.trim() : "";
}

function isProtectedMiiId(miiId) {
    return normalizeMiiIdInput(miiId).toLowerCase() === "average";
}

function isValidManualMiiId(miiId) {
    const normalizedId = normalizeMiiIdInput(miiId);
    return Boolean(
        normalizedId &&
        normalizedId.length <= MAX_MANUAL_MII_ID_LENGTH &&
        /^[A-Za-z0-9]+$/.test(normalizedId) &&
        !isProtectedMiiId(normalizedId)
    );
}

function replaceArrayValueUnique(values, oldValue, newValue) {
    const previousValue = normalizeMiiIdInput(oldValue);
    const nextValue = normalizeMiiIdInput(newValue);
    const seen = new Set();
    const nextValues = [];

    for (const rawValue of Array.isArray(values) ? values : []) {
        const normalized = normalizeMiiIdInput(rawValue);
        const candidate = normalized === previousValue ? nextValue : normalized;
        if (!candidate || seen.has(candidate)) continue;
        seen.add(candidate);
        nextValues.push(candidate);
    }

    return nextValues;
}

function removeArrayValues(values, valuesToRemove) {
    const blockedValues = valuesToRemove instanceof Set
        ? valuesToRemove
        : new Set((Array.isArray(valuesToRemove) ? valuesToRemove : [valuesToRemove]).map(normalizeMiiIdInput).filter(Boolean));

    const seen = new Set();
    const nextValues = [];

    for (const rawValue of Array.isArray(values) ? values : []) {
        const normalized = normalizeMiiIdInput(rawValue);
        if (!normalized || blockedValues.has(normalized) || seen.has(normalized)) continue;
        seen.add(normalized);
        nextValues.push(normalized);
    }

    return nextValues;
}

async function renameMiiAssets(oldId, newId, isPrivate) {
    const sourcePaths = getMiiAssetPaths(oldId, isPrivate);
    const destinationPaths = getMiiAssetPaths(newId, isPrivate);

    if (fs.existsSync(sourcePaths.imgPath)) {
        try { await fs.promises.unlink(destinationPaths.imgPath); } catch (e) {}
        await fs.promises.rename(sourcePaths.imgPath, destinationPaths.imgPath);
    }

    if (fs.existsSync(sourcePaths.qrPath)) {
        try { await fs.promises.unlink(destinationPaths.qrPath); } catch (e) {}
        await fs.promises.rename(sourcePaths.qrPath, destinationPaths.qrPath);
    }

    if (fs.existsSync(sourcePaths.qrWiiPath)) {
        try { await fs.promises.unlink(destinationPaths.qrWiiPath); } catch (e) {}
        await fs.promises.rename(sourcePaths.qrWiiPath, destinationPaths.qrWiiPath);
    }

    return destinationPaths;
}

async function ensureStoredMiiAssets(mii) {
    if (!mii?.id) return;

    const { imgPath, qrPath, qrWiiPath } = getMiiAssetPaths(mii.id, Boolean(mii.private));

    if (!fs.existsSync(imgPath)) {
        const renderedImage = await miijs.renderMii(mii);
        await fs.promises.writeFile(imgPath, renderedImage);
    }

    if (!fs.existsSync(qrPath)) {
        await writeQrPng(mii, qrPath, "3DS");
    }

    if (!fs.existsSync(qrWiiPath)) {
        await writeQrPng(mii, qrWiiPath, "WIIU");
    }
}

async function replaceStoredMiiIdReferences(oldId, newId) {
    const previousId = normalizeMiiIdInput(oldId);
    const nextId = normalizeMiiIdInput(newId);

    if (!previousId || !nextId || previousId === nextId) {
        return {
            updatedVoteUsers: 0,
            updatedPfpUsers: 0,
            settingsUpdated: false
        };
    }

    const usersWithVotes = await Users.find({ votedFor: previousId })
        .select("username votedFor")
        .lean();

    const voteOps = usersWithVotes
        .map((user) => {
            const nextVotes = replaceArrayValueUnique(user.votedFor, previousId, nextId);
            if (JSON.stringify(nextVotes) === JSON.stringify(Array.isArray(user.votedFor) ? user.votedFor : [])) {
                return null;
            }
            return {
                updateOne: {
                    filter: { username: user.username },
                    update: { $set: { votedFor: nextVotes } }
                }
            };
        })
        .filter(Boolean);

    if (voteOps.length > 0) {
        await Users.bulkWrite(voteOps);
    }

    const pfpUpdateResult = await Users.updateMany(
        { miiPfp: previousId },
        { $set: { miiPfp: nextId } }
    );

    const settings = await getSettings();
    const settingsUpdates = {};

    if (normalizeMiiIdInput(settings?.highlightedMii) === previousId) {
        settingsUpdates.highlightedMii = nextId;
    }

    if (normalizeMiiIdInput(settings?.defaultUserPfpMii) === previousId) {
        settingsUpdates.defaultUserPfpMii = nextId;
    }

    if (Object.keys(settingsUpdates).length > 0) {
        await updateSettings(settingsUpdates);
    }

    return {
        updatedVoteUsers: voteOps.length,
        updatedPfpUsers: pfpUpdateResult?.modifiedCount || 0,
        settingsUpdated: Object.keys(settingsUpdates).length > 0
    };
}

async function cleanupDeletedMiiReferences(rawMiiIds, { fallbackProfileMiiId = BLANK_MII_ID } = {}) {
    const deletedIds = [...new Set(
        (Array.isArray(rawMiiIds) ? rawMiiIds : [rawMiiIds])
            .map(normalizeMiiIdInput)
            .filter(Boolean)
    )];

    if (deletedIds.length === 0) {
        return {
            updatedVoteUsers: 0,
            updatedPfpUsers: 0,
            settingsUpdated: false
        };
    }

    const deletedIdSet = new Set(deletedIds);
    const usersWithVotes = await Users.find({ votedFor: { $in: deletedIds } })
        .select("username votedFor")
        .lean();

    const voteOps = usersWithVotes
        .map((user) => {
            const nextVotes = removeArrayValues(user.votedFor, deletedIdSet);
            if (JSON.stringify(nextVotes) === JSON.stringify(Array.isArray(user.votedFor) ? user.votedFor : [])) {
                return null;
            }
            return {
                updateOne: {
                    filter: { username: user.username },
                    update: { $set: { votedFor: nextVotes } }
                }
            };
        })
        .filter(Boolean);

    if (voteOps.length > 0) {
        await Users.bulkWrite(voteOps);
    }

    const pfpUpdateResult = await Users.updateMany(
        { miiPfp: { $in: deletedIds } },
        { $set: { miiPfp: fallbackProfileMiiId, pfpSet: false } }
    );

    const settings = await getSettings();
    const settingsUpdates = {};

    if (deletedIdSet.has(normalizeMiiIdInput(settings?.highlightedMii))) {
        settingsUpdates.highlightedMii = fallbackProfileMiiId;
    }

    if (deletedIdSet.has(normalizeMiiIdInput(settings?.defaultUserPfpMii))) {
        settingsUpdates.defaultUserPfpMii = fallbackProfileMiiId;
    }

    if (Object.keys(settingsUpdates).length > 0) {
        await updateSettings(settingsUpdates);
    }

    return {
        updatedVoteUsers: voteOps.length,
        updatedPfpUsers: pfpUpdateResult?.modifiedCount || 0,
        settingsUpdated: Object.keys(settingsUpdates).length > 0
    };
}

async function updateStoredMiiId(mii, newId) {
    const previousId = normalizeMiiIdInput(mii?.id);
    const nextId = normalizeMiiIdInput(newId);

    if (!previousId || !nextId) {
        throw new Error("Missing Mii ID");
    }
    if (previousId === nextId) {
        throw new Error("New Mii ID matches the current ID");
    }

    const updatedMii = await Miis.findOneAndUpdate(
        { id: previousId },
        { $set: { id: nextId } },
        { new: true, lean: true }
    );

    if (!updatedMii) {
        throw new Error("Mii not found");
    }

    await renameMiiAssets(previousId, nextId, Boolean(mii?.private));
    await replaceStoredMiiIdReferences(previousId, nextId);
    await ensureStoredMiiAssets(updatedMii);

    return updatedMii;
}

async function deleteStoredMiisAndCleanup(miis, options = {}) {
    const items = (Array.isArray(miis) ? miis : [miis])
        .filter((mii) => mii && normalizeMiiIdInput(mii.id))
        .map((mii) => ({
            id: normalizeMiiIdInput(mii.id),
            private: Boolean(mii.private)
        }));

    const uniqueMiis = items.filter(
        (mii, index) => items.findIndex((candidate) => candidate.id === mii.id) === index
    );

    const deletedIds = uniqueMiis.map((mii) => mii.id);
    if (deletedIds.length === 0) {
        return {
            deletedIds: [],
            deletedCount: 0
        };
    }

    for (const mii of uniqueMiis) {
        deleteMiiAssets(mii.id, mii.private);
    }

    await Miis.deleteMany({ id: { $in: deletedIds } });
    await cleanupDeletedMiiReferences(deletedIds, options);

    return {
        deletedIds,
        deletedCount: deletedIds.length
    };
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

const USERNAME_REGEX = /^[A-Za-z0-9_.-]{3,20}$/;

function normalizeUsernameInput(value) {
    return String(value || "").trim();
}

function isValidUsername(value) {
    return USERNAME_REGEX.test(normalizeUsernameInput(value));
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
    let chars = "ABCDEGHIJLMNOQRTUWXYZabcdeghijlmnoqrtuwxyz012345789";
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

function getStablePopularitySort() {
    return { votes: -1, uploadedOn: -1, _id: -1 };
}

function getStableRecencySort() {
    return { uploadedOn: -1, _id: -1 };
}

async function getTrendingPaginatedResult(query, page, perPage, skip, now = Date.now()) {
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
                                TRENDING_TIME_DECAY_EXPONENT
                            ]
                        }
                    ]
                }
            }
        },
        { $sort: { hotness: -1, uploadedOn: -1, _id: -1 } },
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
        start: skip,
        totalPages: Math.ceil(total / perPage)
    };
}

async function getFallbackSearchPaginatedResult(baseQuery, searchPlan, page, perPage, skip) {
    const candidates = await Miis.find(baseQuery)
        .sort(getStablePopularitySort())
        .limit(SEARCH_FALLBACK_CANDIDATE_LIMIT)
        .lean();
    const rankedCandidates = rankMiiSearchCandidates(candidates, searchPlan);

    return {
        items: rankedCandidates.slice(skip, skip + perPage),
        total: rankedCandidates.length,
        page,
        perPage,
        start: skip,
        totalPages: Math.ceil(rankedCandidates.length / perPage)
    };
}

function normalizePaginationWindow(pageOrOptions = 1, perPage = defaultMiisPerPage) {
    const normalizedPerPage = Number.isFinite(Number(perPage)) && Number(perPage) > 0
        ? Math.floor(Number(perPage))
        : defaultMiisPerPage;

    if (pageOrOptions && typeof pageOrOptions === "object" && !Array.isArray(pageOrOptions)) {
        const requestedStart = Number.parseInt(pageOrOptions.start, 10);
        const start = Number.isFinite(requestedStart) && requestedStart > 0 ? requestedStart : 0;
        const requestedPage = Number.parseInt(pageOrOptions.page, 10);
        const page = Number.isFinite(requestedPage) && requestedPage > 0
            ? requestedPage
            : Math.floor(start / normalizedPerPage) + 1;

        return {
            page,
            perPage: normalizedPerPage,
            start
        };
    }

    const requestedPage = Number.parseInt(pageOrOptions, 10);
    const page = Number.isFinite(requestedPage) && requestedPage > 0 ? requestedPage : 1;

    return {
        page,
        perPage: normalizedPerPage,
        start: (page - 1) * normalizedPerPage
    };
}

function getRequestedStartOffset(query, perPage = defaultMiisPerPage) {
    const requestedStart = Number.parseInt(query?.start, 10);
    if (Number.isFinite(requestedStart) && requestedStart >= 0) {
        return requestedStart;
    }

    const requestedPage = Number.parseInt(query?.page, 10);
    if (Number.isFinite(requestedPage) && requestedPage > 1) {
        return (requestedPage - 1) * perPage;
    }

    return 0;
}

// Paginated API that queries database directly with skip/limit
async function paginatedApi(what, pageOrOptions = 1, perPage = defaultMiisPerPage, filter = null) {
    const paginationWindow = normalizePaginationWindow(pageOrOptions, perPage);
    const page = paginationWindow.page;
    const requestLimit = paginationWindow.perPage;
    const skip = paginationWindow.start;
    const settings = await getSettings();
    
    let query = { private: false, id: { $ne: "average" } };
    let sort = {};
    
    switch(what) {
        case "random": { // TODO: this is random, but based on sort order. True random is possible but not deterministically
                         // QK, Kestron: I think this is more random than it was, I left the old code commented, reimplement if necessary.
            const totalCount = await Miis.countDocuments(query);
            if (totalCount === 0) {
                return {
                    items: [],
                    total: 0,
                    page,
                    perPage: requestLimit,
                    start: skip,
                    totalPages: 0
                };
            }
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
                { $sample: { size: Math.min(totalCount, skip + requestLimit) } },
                { $skip: skip },
                { $limit: requestLimit }
            ];

            const items = await Miis.aggregate(pipeline);

            return {
                items,
                total: totalCount,
                page,
                perPage: requestLimit,
                start: skip,
                totalPages: Math.ceil(totalCount / requestLimit)
            };
        }
        
        case "trending": { // TODO: rebrand to "trending"
            return getTrendingPaginatedResult(query, page, perPage, skip);
        }

        case "officialTrending": {
            query.official = true;
            if (filter) {
                query.officialCategories = filter;
            }
            return getTrendingPaginatedResult(query, page, perPage, skip);
        }

        case "top":
            sort = getStablePopularitySort();
            break;
        
        case "recent":
            sort = getStableRecencySort();
            break;
        
        case "official":
            query.official = true;
            if (filter) {
                query.officialCategories = filter;
            }
            sort = getStablePopularitySort();
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
            const searchPlan = buildMiiSearchPlan(searchText, selectedSearchFields);

            if (selectedTags.length > 0) {
                query.tags = { $all: selectedTags };
            }

            if (searchPlan.active) {
                const baseSearchQuery = { ...query };
                const searchMatchClauses = buildMiiSearchMatchClauses(searchPlan);
                if (searchMatchClauses.length > 0) {
                    query.$and = [
                        ...(Array.isArray(query.$and) ? query.$and : []),
                        ...searchMatchClauses
                    ];
                }

                const [items, totalCount] = await Promise.all([
                    Miis.aggregate([
                        { $match: query },
                        { $addFields: { searchScore: buildMiiSearchScoreExpression(searchPlan) } },
                        { $sort: getMiiSearchSort() },
                        { $skip: skip },
                        { $limit: requestLimit }
                    ]),
                    Miis.countDocuments(query)
                ]);

                if (totalCount > 0) {
                    return {
                        items,
                        total: totalCount,
                        page,
                        perPage: requestLimit,
                        start: skip,
                        totalPages: Math.ceil(totalCount / requestLimit)
                    };
                }

                return getFallbackSearchPaginatedResult(baseSearchQuery, searchPlan, page, requestLimit, skip);
            }

            sort = getStablePopularitySort();
            break;
        }
        
        default:
            return { items: [], total: 0, page: 1, perPage: requestLimit, start: skip, totalPages: 0 };
    }
    
    // For simple sorted queries (best, recent, official without category)
    const totalCount = await Miis.countDocuments(query);
    const items = await Miis.find(query)
        .sort(sort)
        .skip(skip)
        .limit(requestLimit)
        .lean();
    
    return {
        items,
        total: totalCount,
        page,
        perPage: requestLimit,
        start: skip,
        totalPages: Math.ceil(totalCount / requestLimit)
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

function truncateText(value, maxLength = 1024) {
    const normalized = String(value ?? "");
    if (normalized.length <= maxLength) {
        return normalized;
    }

    return normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd() + "…";
}

function normalizeReportText(value, maxLength = REPORT_MII_DETAILS_MAX_LENGTH) {
    const normalized = String(value ?? "")
        .replace(/\r\n/g, "\n")
        .replace(/\u0000/g, "")
        .trim();

    if (!normalized) {
        return "";
    }

    return truncateText(normalized, maxLength);
}

function escapeHtmlText(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#39;"
    }[character]));
}

function formatHtmlMultilineText(value) {
    return escapeHtmlText(value).replace(/\n/g, "<br>");
}

function buildMiiReportReference(date = new Date()) {
    return `MII-${date.toISOString().slice(0, 10).replace(/-/g, "")}-${genToken(6).toUpperCase()}`;
}

function buildContactReference(date = new Date()) {
    return `CONTACT-${date.toISOString().slice(0, 10).replace(/-/g, "")}-${genToken(6).toUpperCase()}`;
}

function buildMiiReportFollowUpEmail({ reportReference, reporterName, category, details, miiName, miiUrl }) {
    const normalizedReporterName = normalizeReportText(reporterName, 80);
    const greetingName = normalizedReporterName && normalizedReporterName !== "Anonymous"
        ? normalizedReporterName
        : "there";
    const safeMiiUrl = escapeHtmlText(miiUrl);
    const safeDiscordInvite = process.env.discordInvite ? escapeHtmlText(process.env.discordInvite) : "";

    return `
        <p>Hi ${escapeHtmlText(greetingName)},</p>
        <p>Thanks for reporting an issue with <strong>${escapeHtmlText(miiName)}</strong> on InfiniMii.</p>
        <p>Your reference code is <strong>${escapeHtmlText(reportReference)}</strong>.</p>
        <p>We opened this email thread so you can reply directly if you want to add more context or corrections.</p>
        <p><strong>Category:</strong> ${escapeHtmlText(category)}</p>
        <p><strong>Mii page:</strong> <a href="${safeMiiUrl}">${safeMiiUrl}</a></p>
        <p><strong>Details:</strong><br>${formatHtmlMultilineText(details)}</p>
        ${safeDiscordInvite ? `<p>If you prefer, you can also reach the team in Discord: <a href="${safeDiscordInvite}">${safeDiscordInvite}</a></p>` : ""}
        <p>InfiniMii</p>
    `;
}

function buildContactSupportEmail({
    contactReference,
    reporterName,
    reporterEmail,
    subject,
    details,
    loggedInUsername = "",
    sourceUrl = ""
}) {
    const safeSourceUrl = sourceUrl ? escapeHtmlText(sourceUrl) : "";

    return `
        <p>A new contact request was submitted through InfiniMii.</p>
        <p><strong>Reference:</strong> ${escapeHtmlText(contactReference)}</p>
        <p><strong>Name:</strong> ${escapeHtmlText(reporterName || "Not provided")}</p>
        <p><strong>Email:</strong> ${reporterEmail ? `<a href="mailto:${escapeHtmlText(reporterEmail)}">${escapeHtmlText(reporterEmail)}</a>` : "Not provided"}</p>
        ${loggedInUsername ? `<p><strong>Logged-in user:</strong> ${escapeHtmlText(loggedInUsername)}</p>` : ""}
        <p><strong>Subject:</strong> ${escapeHtmlText(subject)}</p>
        <p><strong>Message:</strong><br>${formatHtmlMultilineText(details)}</p>
        ${safeSourceUrl ? `<p><strong>Submitted from:</strong> <a href="${safeSourceUrl}">${safeSourceUrl}</a></p>` : ""}
        <p>InfiniMii</p>
    `;
}

function buildContactFollowUpEmail({
    contactReference,
    reporterName,
    subject,
    details
}) {
    const safeDiscordInvite = process.env.discordInvite ? escapeHtmlText(process.env.discordInvite) : "";

    return `
        <p>Hi ${escapeHtmlText(reporterName || "there")},</p>
        <p>Thanks for contacting Stewared about InfiniMii.</p>
        <p>Your reference code is <strong>${escapeHtmlText(contactReference)}</strong>.</p>
        <p>We opened this email thread so you can reply directly if you want to add more context.</p>
        <p><strong>Subject:</strong> ${escapeHtmlText(subject)}</p>
        <p><strong>Message:</strong><br>${formatHtmlMultilineText(details)}</p>
        ${safeDiscordInvite ? `<p>If you want faster back-and-forth, you can also reach the team in Discord: <a href="${safeDiscordInvite}">${safeDiscordInvite}</a></p>` : ""}
        <p>InfiniMii</p>
    `;
}

async function sendEmail(to, subj, cont, extraMailOptions = {}) {
    const mailOptions = {};

    if (extraMailOptions && typeof extraMailOptions === "object" && !Array.isArray(extraMailOptions)) {
        for (const key of ["replyTo", "text", "attachments", "cc", "bcc"]) {
            if (key in extraMailOptions) {
                mailOptions[key] = extraMailOptions[key];
            }
        }
    }

    try {
        await nodemailer.createTransport({
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
            html: cont,
            ...mailOptions
        });

        return "Email sent";
    } catch (err) {
        console.error('Error sending email:', err);
        throw new Error("Error sending email");
    }
}

async function sendContactWebhookNotification({
    contactReference,
    reporterName,
    reporterEmail,
    subject,
    details,
    loggedInUsername = "",
    sourceUrl = ""
}) {
    try {
        const webhookSent = await sendWebhookPayload(JSON.stringify({
            content: "New InfiniMii contact form submission",
            allowed_mentions: {
                parse: []
            },
            embeds: [{
                type: "rich",
                title: `Contact form submitted [${contactReference}]`,
                description: truncateText(details, 4096),
                color: 0x4f9cff,
                fields: [
                    {
                        name: "Name",
                        value: truncateText(reporterName || "Anonymous", 1024),
                        inline: true
                    },
                    {
                        name: "Email",
                        value: truncateText(reporterEmail || "Not provided", 1024),
                        inline: true
                    },
                    {
                        name: "Follow-up available",
                        value: reporterEmail ? "Yes" : "No email provided",
                        inline: true
                    },
                    {
                        name: "Subject",
                        value: truncateText(subject, 1024),
                        inline: false
                    },
                    ...(loggedInUsername ? [{
                        name: "Logged-in user",
                        value: truncateText(loggedInUsername, 1024),
                        inline: true
                    }] : []),
                    ...(sourceUrl ? [{
                        name: "Source",
                        value: truncateText(sourceUrl, 1024),
                        inline: false
                    }] : [])
                ],
                timestamp: new Date().toISOString()
            }]
        }));

        if (!webhookSent) {
            rawConsoleError("Contact webhook skipped because hookUrl is not configured.");
        }
    } catch (webhookError) {
        rawConsoleError("Error sending contact webhook notification:", webhookError);
    }
}

function makeReport(content, attachments = []) {
    return sendWebhookPayload(content, attachments).catch((error) => {
        // Reports should never block user actions (uploads, moderation actions, etc.).
        rawConsoleError('Error sending webhook report:', error);
    });
}

function getUtcDateKey(date = new Date()) {
    return date.toISOString().slice(0, 10);
}

async function sendHighlightedMiiReminderIfDue(date = new Date()) {
    const currentDateKey = getUtcDateKey(date);
    const settings = await getSettings();

    if (settings.highlightedMiiReminderSentOn === currentDateKey) {
        return false;
    }

    const reminderUrl = `${baseUrl || "https://infinimii.com"}/`;
    const didSendReminder = await sendWebhookPayload(JSON.stringify({
        embeds: [{
            type: "rich",
            title: "Remember to update the Highlighted Mii",
            description: "Daily reminder to rotate the highlighted Mii.",
            color: 0xffcc00,
            url: reminderUrl,
            timestamp: date.toISOString()
        }]
    }));

    if (!didSendReminder) {
        return false;
    }

    await updateSettings({
        highlightedMiiReminderSentOn: currentDateKey
    });

    return true;
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

function yieldToEventLoop() {
    return new Promise((resolve) => setImmediate(resolve));
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
    const ret = arrayObj;
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
    for (let i = 0; i < allMiis.length; i++) {
        const mii = allMiis[i];
        acc = acc ? populateNestedArrays(acc, mii) : getNestedAsArrays(mii);

        if (i > 0 && i % 100 === 0) {
            await yieldToEventLoop();
        }
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
            $match: getAverageMiiCandidateMatch()
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

    if (allMiis.length === 0) {
        await Miis.deleteOne({ id: "average" });
        return null;
    }


    const leaves = await getCollectedLeavesAcrossMiis(allMiis);
    var avg=averageObjectWithPairs(leaves);
    delete avg._id;
    avg.id = "average";
    avg.meta = { 
        name: `J${avg.general.gender===0?"ohn":"ane"} Doe`, 
        creatorName: "InfiniMii"
    };
    avg.desc="The most common or average features and placements of those features across all Miis on the website.";
    avg.uploader = "Community";
    avg.uploadedOn = Date.now();
    avg.private = false;
    avg.published = true;
    avg.votes = await countUsersWhoVotedForMii("average");
    setMiiIdentityHash(avg);
    
    // Upsert average Mii
    await Miis.findOneAndUpdate(
        { id: "average" },
        { $set: avg },
        { upsert: true, new: true }
    );
    
    return avg;
}

async function syncAverageMiiAssets(avgMii) {
    if (avgMii) {
        const renderedAverageMii = await miijs.renderMii(avgMii);
        await Promise.all([
            fs.promises.writeFile("./static/miiImgs/average.png", renderedAverageMii),
            writeQrPng(avgMii, "./static/miiQRs/average.png", "3DS"),
            writeQrPng(avgMii, "./static/miiQRsWii/average.png", "WIIU")
        ]);
        return;
    }

    await Promise.allSettled([
        fs.promises.unlink("./static/miiImgs/average.png"),
        fs.promises.unlink("./static/miiQRs/average.png"),
        fs.promises.unlink("./static/miiQRsWii/average.png")
    ]);
}

async function refreshAverageMiiAssets() {
    await setAverageMii();
    const avgMii = await getMiiById("average");
    await Promise.all([
        syncAverageMiiAssets(avgMii),
        syncUnsetUserProfilePictures()
    ]);
    return avgMii;
}

async function hasRecentAverageAffectingUpload(windowMs = AVERAGE_MII_REFRESH_WINDOW_MS) {
    const cutoff = Date.now() - windowMs;
    const recentUpload = await Miis.exists(getAverageMiiCandidateMatch({
        uploadedOn: { $gte: cutoff }
    }));

    return Boolean(recentUpload);
}

let averageMiiRefreshPromise = null;
let averageMiiRefreshTimer = null;
let averageMiiRefreshPendingReason = null;

function queueAverageMiiRefresh(reason = "manual") {
    averageMiiRefreshPendingReason = reason;

    if (averageMiiRefreshPromise || averageMiiRefreshTimer) {
        return;
    }

    averageMiiRefreshTimer = setTimeout(() => {
        averageMiiRefreshTimer = null;

        averageMiiRefreshPromise = (async () => {
            while (averageMiiRefreshPendingReason) {
                const currentReason = averageMiiRefreshPendingReason;
                averageMiiRefreshPendingReason = null;
                const startedAt = Date.now();

                try {
                    console.log(`[average] Refresh started (${currentReason}).`);
                    await refreshAverageMiiAssets();
                    console.log(`[average] Refresh completed in ${Date.now() - startedAt}ms.`);
                } catch (error) {
                    console.error("[average] Failed to refresh average Mii:", error);
                }
            }
        })().finally(() => {
            averageMiiRefreshPromise = null;
            if (averageMiiRefreshPendingReason) {
                queueAverageMiiRefresh(averageMiiRefreshPendingReason);
            }
        });
    }, 0);
}

// Sitemap generation functions
function generateSitemapXML(urls) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n';
    xml += '        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n';
    
    urls.forEach(url => {
        xml += '  <url>\n';
        xml += `    <loc>${escapeXml(url.loc)}</loc>\n`;
        if (url.lastmod) xml += `    <lastmod>${escapeXml(url.lastmod)}</lastmod>\n`;
        if (url.changefreq) xml += `    <changefreq>${escapeXml(url.changefreq)}</changefreq>\n`;
        if (url.priority) xml += `    <priority>${escapeXml(url.priority)}</priority>\n`;
        
        // Add image sitemap data if present
        if (url.images && url.images.length > 0) {
            url.images.forEach(img => {
                xml += '    <image:image>\n';
                xml += `      <image:loc>${escapeXml(img.loc)}</image:loc>\n`;
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
    return String(unsafe).replace(/[<>&'"]/g, (c) => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

function toRssDate(value, fallback = new Date()) {
    const date = value ? new Date(value) : fallback;
    return Number.isNaN(date.getTime()) ? fallback.toUTCString() : date.toUTCString();
}

function getMiiFeedName(mii) {
    return mii?.meta?.name || mii?.name || "Unknown Mii";
}

function getMiiFeedDescription(mii) {
    const name = getMiiFeedName(mii);
    const description = typeof mii?.desc === "string" && mii.desc.trim()
        ? mii.desc.trim()
        : `${name} Mii character uploaded to InfiniMii.`;
    const uploader = typeof mii?.uploader === "string" && mii.uploader.trim()
        ? mii.uploader.trim()
        : "Unknown uploader";

    return `${description} Uploaded by ${uploader}. View, download, scan a QR code, or convert this Mii on InfiniMii.`;
}

function getMiiFeedDescriptionHtml(mii, imageUrl) {
    const description = getMiiFeedDescription(mii);
    const imageAlt = `${getMiiFeedName(mii)} Mii image`;

    return `<img src="${imageUrl}" title="${description}" alt="${imageAlt}" width="${MII_RENDER_IMAGE_WIDTH}" height="${MII_RENDER_IMAGE_HEIGHT}" /><br />${description}`;
}

function getResolvedBaseUrlFromRequest(req) {
    return (baseUrl || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
}

function isValidIndexNowKey(key) {
    return /^[A-Za-z0-9-]{8,128}$/.test(String(key || "").trim());
}

function getIndexNowKey() {
    if (cachedIndexNowKey !== null) return cachedIndexNowKey;

    const envKey = String(process.env.INDEXNOW_KEY || "").trim();
    if (isValidIndexNowKey(envKey)) {
        cachedIndexNowKey = envKey;
        return cachedIndexNowKey;
    }

    if (!loggedIndexNowConfigError) {
        loggedIndexNowConfigError = true;
        console.warn("[indexnow] Missing or invalid INDEXNOW_KEY in env.json; IndexNow submissions are disabled.");
    }

    cachedIndexNowKey = "";
    return cachedIndexNowKey;
}

function getIndexNowKeyLocation(resolvedBaseUrl) {
    const key = getIndexNowKey();
    if (!key) return "";
    return `${resolvedBaseUrl}/${encodeURIComponent(key)}.txt`;
}

function isPublicSubmissionHost(hostname) {
    const normalizedHost = String(hostname || "").trim().toLowerCase();
    if (!normalizedHost) return false;
    if (normalizedHost === "localhost" || normalizedHost === "127.0.0.1" || normalizedHost === "::1") {
        return false;
    }
    return !normalizedHost.endsWith(".local");
}

function normalizeIndexNowUrl(url, resolvedBaseUrl) {
    if (!url) return "";

    try {
        const base = new URL(resolvedBaseUrl);
        const resolvedUrl = new URL(url, resolvedBaseUrl);
        if (!["http:", "https:"].includes(resolvedUrl.protocol)) return "";
        if (resolvedUrl.host !== base.host) return "";
        resolvedUrl.hash = "";
        return resolvedUrl.toString();
    } catch {
        return "";
    }
}

function uniqueIndexNowUrls(urls, resolvedBaseUrl) {
    const seen = new Set();
    const uniqueUrls = [];

    (Array.isArray(urls) ? urls : [urls])
        .flatMap((value) => Array.isArray(value) ? value : [value])
        .map((value) => normalizeIndexNowUrl(value, resolvedBaseUrl))
        .filter(Boolean)
        .forEach((value) => {
            if (seen.has(value)) return;
            seen.add(value);
            uniqueUrls.push(value);
        });

    return uniqueUrls;
}

function getIndexNowCollectionUrls(resolvedBaseUrl) {
    return [
        `${resolvedBaseUrl}/`,
        `${resolvedBaseUrl}/recent`,
        `${resolvedBaseUrl}/top`,
        `${resolvedBaseUrl}/trending`
    ];
}

function getUserProfileUrl(resolvedBaseUrl, username) {
    const normalizedUsername = String(username || "").trim();
    return normalizedUsername
        ? `${resolvedBaseUrl}/user/${encodeURIComponent(normalizedUsername)}`
        : "";
}

function getMiiPageUrl(resolvedBaseUrl, miiId) {
    const normalizedMiiId = String(miiId || "").trim();
    return normalizedMiiId
        ? `${resolvedBaseUrl}/mii/${encodeURIComponent(normalizedMiiId)}`
        : "";
}

function buildIndexNowUrlsForMiis(resolvedBaseUrl, miis, options = {}) {
    const urls = [];

    if (options.includeCollectionPages !== false) {
        urls.push(...getIndexNowCollectionUrls(resolvedBaseUrl));
    }

    if (Array.isArray(options.extraUrls)) {
        urls.push(...options.extraUrls);
    }

    (Array.isArray(miis) ? miis : [miis]).forEach((mii) => {
        if (!mii || !mii.id) return;
        if (mii.private || mii.published === false) return;

        const encodedMiiId = encodeURIComponent(mii.id);

        urls.push(getMiiPageUrl(resolvedBaseUrl, mii.id));
        urls.push(`${resolvedBaseUrl}/miiImgs/${encodedMiiId}.png`);
        urls.push(getUserProfileUrl(resolvedBaseUrl, mii.uploader));

        if (mii.official || options.includeOfficialListing) {
            urls.push(`${resolvedBaseUrl}/official`);
        }
    });

    return uniqueIndexNowUrls(urls, resolvedBaseUrl);
}

async function submitIndexNowUrls(urls, resolvedBaseUrl, reason = "update") {
    const normalizedBaseUrl = String(resolvedBaseUrl || "").trim().replace(/\/+$/, "");
    if (!normalizedBaseUrl) {
        return { submitted: 0, skipped: true, reason: "missing-base-url" };
    }

    const base = new URL(normalizedBaseUrl);
    if (!isPublicSubmissionHost(base.hostname)) {
        return { submitted: 0, skipped: true, reason: "non-public-host" };
    }

    const key = getIndexNowKey();
    if (!key) {
        return { submitted: 0, skipped: true, reason: "missing-key" };
    }

    const urlList = uniqueIndexNowUrls(urls, normalizedBaseUrl);
    if (urlList.length === 0) {
        return { submitted: 0, skipped: true, reason: "no-urls" };
    }

    const keyLocation = getIndexNowKeyLocation(normalizedBaseUrl);
    let submittedCount = 0;

    for (let offset = 0; offset < urlList.length; offset += INDEXNOW_MAX_URLS_PER_REQUEST) {
        const chunk = urlList.slice(offset, offset + INDEXNOW_MAX_URLS_PER_REQUEST);
        const response = await fetch(INDEXNOW_API_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json; charset=utf-8"
            },
            body: JSON.stringify({
                host: base.host,
                key,
                keyLocation,
                urlList: chunk
            }),
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok && response.status !== 202) {
            const responseBody = (await response.text().catch(() => "")).trim();
            throw new Error(
                `IndexNow ${reason} submission failed with ${response.status}${responseBody ? `: ${responseBody}` : ""}`
            );
        }

        submittedCount += chunk.length;
    }

    return { submitted: submittedCount, skipped: false };
}

function notifyIndexNow(urls, resolvedBaseUrl, reason = "update") {
    void submitIndexNowUrls(urls, resolvedBaseUrl, reason).catch((error) => {
        console.warn(`[indexnow] ${reason} failed: ${error.message}`);
    });
}

function toAbsoluteSiteUrl(req, value = "/") {
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const trimmed = String(value || "").trim();

    if (!trimmed) return `${resolvedBaseUrl}/`;
    if (/^https?:\/\//i.test(trimmed)) return trimmed;

    return trimmed.startsWith("/")
        ? `${resolvedBaseUrl}${trimmed}`
        : `${resolvedBaseUrl}/${trimmed.replace(/^\/+/, "")}`;
}

function buildRequestPathWithStart(req, startOffset) {
    const params = new URLSearchParams();

    Object.entries(req.query || {}).forEach(([key, value]) => {
        if (key === "page" || key === "start") return;

        if (Array.isArray(value)) {
            value
                .filter(item => typeof item !== "undefined" && item !== null && `${item}`.trim() !== "")
                .forEach(item => params.append(key, String(item)));
            return;
        }

        if (typeof value === "undefined" || value === null) return;
        const normalized = String(value).trim();
        if (!normalized) return;
        params.append(key, normalized);
    });

    const normalizedStart = Number.isFinite(Number(startOffset)) && Number(startOffset) > 0
        ? Math.floor(Number(startOffset))
        : 0;

    if (normalizedStart > 0) {
        params.set("start", String(normalizedStart));
    }

    const queryString = params.toString();
    return queryString ? `${req.path}?${queryString}` : req.path;
}

function buildRequestPathWithPage(req, pageNumber) {
    const params = new URLSearchParams();

    Object.entries(req.query || {}).forEach(([key, value]) => {
        if (Array.isArray(value)) {
            value
                .filter(item => typeof item !== "undefined" && item !== null && `${item}`.trim() !== "")
                .forEach(item => params.append(key, String(item)));
            return;
        }

        if (typeof value === "undefined" || value === null) return;
        const normalized = String(value).trim();
        if (!normalized) return;
        params.append(key, normalized);
    });

    if (pageNumber > 1) {
        params.set("page", String(pageNumber));
    } else {
        params.delete("page");
    }

    const queryString = params.toString();
    return queryString ? `${req.path}?${queryString}` : req.path;
}

function getLastStartOffset(total, requestLimit = defaultMiisPerPage) {
    const normalizedTotal = Number.isFinite(Number(total)) && Number(total) > 0
        ? Math.floor(Number(total))
        : 0;
    const normalizedRequestLimit = Number.isFinite(Number(requestLimit)) && Number(requestLimit) > 0
        ? Math.floor(Number(requestLimit))
        : defaultMiisPerPage;

    if (normalizedTotal <= 0) return 0;
    return Math.floor((normalizedTotal - 1) / normalizedRequestLimit) * normalizedRequestLimit;
}

function buildStartPagination(req, start, total, requestLimit = defaultMiisPerPage) {
    const normalizedStart = Number.isFinite(Number(start)) && Number(start) > 0
        ? Math.floor(Number(start))
        : 0;
    const normalizedTotal = Number.isFinite(Number(total)) && Number(total) > 0
        ? Math.floor(Number(total))
        : 0;
    const normalizedRequestLimit = Number.isFinite(Number(requestLimit)) && Number(requestLimit) > 0
        ? Math.floor(Number(requestLimit))
        : defaultMiisPerPage;

    return {
        mode: "offset",
        start: normalizedStart,
        total: normalizedTotal,
        requestLimit: normalizedRequestLimit,
        baseCount: defaultMiisPerPage,
        currentPage: Math.floor(normalizedStart / normalizedRequestLimit) + 1,
        totalPages: Math.max(1, Math.ceil(Math.max(1, normalizedTotal) / normalizedRequestLimit)),
        prevUrl: normalizedStart > 0
            ? buildRequestPathWithStart(req, Math.max(0, normalizedStart - normalizedRequestLimit))
            : undefined,
        nextUrl: normalizedTotal > normalizedStart + 1
            ? buildRequestPathWithStart(req, normalizedStart + normalizedRequestLimit)
            : undefined
    };
}

function attachPaginationMeta(req, toSend, pagination) {
    toSend.prevUrl = undefined;
    toSend.nextUrl = undefined;
    if (!pagination || pagination.totalPages <= 1) return;

    if (pagination.currentPage > 1) {
        toSend.prevUrl = buildRequestPathWithPage(req, pagination.currentPage - 1);
    }

    if (pagination.currentPage < pagination.totalPages) {
        toSend.nextUrl = buildRequestPathWithPage(req, pagination.currentPage + 1);
    }
}

function getNewestUploadedOn(items) {
    if (!Array.isArray(items) || items.length === 0) return undefined;

    const timestamps = items
        .map(item => Number(item?.uploadedOn))
        .filter(timestamp => Number.isFinite(timestamp) && timestamp > 0);

    if (timestamps.length === 0) return undefined;
    return new Date(Math.max(...timestamps)).toISOString();
}

function getNewestRssDate(items) {
    if (!Array.isArray(items) || items.length === 0) return new Date();

    const timestamps = items
        .map(item => Number(item?.uploadedOn))
        .filter(timestamp => Number.isFinite(timestamp) && timestamp > 0);

    return timestamps.length > 0
        ? new Date(Math.max(...timestamps))
        : new Date();
}

function generateMiiUploadRssXML(miis, req) {
    const feedMiis = Array.isArray(miis) ? miis : [];
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const recentUrl = `${resolvedBaseUrl}/recent`;
    const feedUrl = `${resolvedBaseUrl}/feed.xml`;
    const lastBuildDate = getNewestRssDate(feedMiis);

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:media="http://search.yahoo.com/mrss/">\n';
    xml += '  <channel>\n';
    xml += '    <title>InfiniMii Recent Mii Uploads</title>\n';
    xml += `    <link>${escapeXml(recentUrl)}</link>\n`;
    xml += `    <atom:link href="${escapeXml(feedUrl)}" rel="self" type="application/rss+xml" />\n`;
    xml += '    <description>Recently uploaded public Mii characters on InfiniMii.</description>\n';
    xml += '    <language>en-us</language>\n';
    xml += '    <generator>InfiniMii</generator>\n';
    xml += `    <lastBuildDate>${escapeXml(lastBuildDate.toUTCString())}</lastBuildDate>\n`;
    xml += '    <ttl>60</ttl>\n';
    xml += '    <image>\n';
    xml += `      <url>${escapeXml(`${resolvedBaseUrl}/banner.png`)}</url>\n`;
    xml += '      <title>InfiniMii</title>\n';
    xml += `      <link>${escapeXml(resolvedBaseUrl || "/")}</link>\n`;
    xml += '    </image>\n';

    feedMiis.forEach((mii) => {
        const miiId = mii?.id;
        if (!miiId) return;

        const name = getMiiFeedName(mii);
        const encodedMiiId = encodeURIComponent(miiId);
        const itemUrl = `${resolvedBaseUrl}/mii/${encodedMiiId}`;
        const imageUrl = `${resolvedBaseUrl}/miiImgs/${encodedMiiId}.png`;
        const title = `${name} Mii${mii.official ? " (Official)" : ""}`;
        const creator = typeof mii?.uploader === "string" && mii.uploader.trim()
            ? mii.uploader.trim()
            : "Unknown uploader";

        xml += '    <item>\n';
        xml += `      <title>${escapeXml(title)}</title>\n`;
        xml += `      <link>${escapeXml(itemUrl)}</link>\n`;
        xml += `      <guid isPermaLink="true">${escapeXml(itemUrl)}</guid>\n`;
        xml += `      <pubDate>${escapeXml(toRssDate(mii.uploadedOn, lastBuildDate))}</pubDate>\n`;
        xml += `      <dc:creator>${escapeXml(creator)}</dc:creator>\n`;
        xml += `      <description>${escapeXml(getMiiFeedDescriptionHtml(mii, imageUrl))}</description>\n`;
        xml += `      <media:thumbnail url="${escapeXml(imageUrl)}" width="${MII_RENDER_IMAGE_WIDTH}" height="${MII_RENDER_IMAGE_HEIGHT}" />\n`;
        xml += `      <media:content url="${escapeXml(imageUrl)}" medium="image" type="image/png" width="${MII_RENDER_IMAGE_WIDTH}" height="${MII_RENDER_IMAGE_HEIGHT}" />\n`;

        if (mii.official) {
            xml += '      <category>Official Miis</category>\n';
        }

        const categories = [
            ...(Array.isArray(mii.officialCategories) ? mii.officialCategories : []),
            ...(Array.isArray(mii.tags) ? mii.tags : [])
        ];
        [...new Set(categories)]
            .filter(category => typeof category === "string" && category.trim())
            .slice(0, 8)
            .forEach(category => {
                xml += `      <category>${escapeXml(category.trim())}</category>\n`;
            });

        xml += '    </item>\n';
    });

    xml += '  </channel>\n';
    xml += '</rss>';
    return xml;
}

function generateSitemapIndexXML(sitemaps) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    sitemaps.forEach((sitemap) => {
        xml += '  <sitemap>\n';
        xml += `    <loc>${escapeXml(sitemap.loc)}</loc>\n`;
        if (sitemap.lastmod) {
            xml += `    <lastmod>${escapeXml(sitemap.lastmod)}</lastmod>\n`;
        }
        xml += '  </sitemap>\n';
    });

    xml += '</sitemapindex>';
    return xml;
}

function getPublicMiiSitemapQuery() {
    return {
        private: false,
        published: { $ne: false }
    };
}

function getSitemapPageCount(itemCount, pageSize = MII_SITEMAP_PAGE_SIZE) {
    const normalizedItemCount = Math.max(0, Number(itemCount) || 0);
    const normalizedPageSize = Math.max(1, Number(pageSize) || MII_SITEMAP_PAGE_SIZE);
    return Math.max(1, Math.ceil(normalizedItemCount / normalizedPageSize));
}

function getMiiSitemapLoc(resolvedBaseUrl, pageNumber, totalPages) {
    return totalPages <= 1
        ? `${resolvedBaseUrl}/sitemap-miis.xml`
        : `${resolvedBaseUrl}/sitemap-miis-${pageNumber}.xml`;
}

function buildMiiSitemapIndexEntries(resolvedBaseUrl, totalPages, lastmod) {
    return Array.from({ length: totalPages }, (_, index) => ({
        loc: getMiiSitemapLoc(resolvedBaseUrl, index + 1, totalPages),
        lastmod
    }));
}

function getMiiSitemapPageNumber(rawPage) {
    const pageNumber = Number.parseInt(String(rawPage || ""), 10);
    return Number.isFinite(pageNumber) && pageNumber > 0 ? pageNumber : 1;
}

async function getPublicMiiSitemapCount() {
    return await Miis.countDocuments(getPublicMiiSitemapQuery());
}

async function getPublicMiisForSitemapPage(pageNumber) {
    const safePageNumber = Math.max(1, Number(pageNumber) || 1);
    return await Miis.find(getPublicMiiSitemapQuery())
        .select("id meta.name name desc official uploadedOn updatedAt")
        .sort({ uploadedOn: -1, _id: -1 })
        .skip((safePageNumber - 1) * MII_SITEMAP_PAGE_SIZE)
        .limit(MII_SITEMAP_PAGE_SIZE)
        .lean();
}

function getSitemapDate(value, fallback = new Date()) {
    const date = value ? new Date(value) : fallback;
    return Number.isFinite(date.getTime())
        ? date.toISOString().split("T")[0]
        : fallback.toISOString().split("T")[0];
}

function buildMiiSitemapUrls(miis, resolvedBaseUrl) {
    return (Array.isArray(miis) ? miis : [])
        .map((mii) => {
            const miiId = mii?.id;
            if (!miiId) return null;

            const encodedMiiId = encodeURIComponent(miiId);
            const miiName = mii?.meta?.name || mii?.name || "Unknown Mii";
            const lastmod = getSitemapDate(mii.updatedAt || mii.uploadedOn);

            return {
                loc: `${resolvedBaseUrl}/mii/${encodedMiiId}`,
                lastmod,
                changefreq: "daily",
                priority: mii.official ? "0.9" : "0.7",
                images: [
                    {
                        loc: `${resolvedBaseUrl}/miiImgs/${encodedMiiId}.png`,
                        title: `${miiName} Mii character preview`,
                        caption: mii.desc || `${miiName} Mii character for Nintendo systems`
                    },
                    {
                        loc: `${resolvedBaseUrl}/miiQRs/${encodedMiiId}.png`,
                        title: `${miiName} Mii QR code`,
                        caption: `QR code for ${miiName} - Scan with 3DS, Wii U, Tomodachi Life, or Miitomo`
                    },
                    {
                        loc: `${resolvedBaseUrl}/miiQRsWii/${encodedMiiId}.png`,
                        title: `${miiName} Mii Wii U QR code`,
                        caption: `Wii U QR code for ${miiName}`
                    }
                ]
            };
        })
        .filter(Boolean);
}

async function sendMiiSitemapPage(req, res, pageNumber) {
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const totalMiis = await getPublicMiiSitemapCount();
    const totalPages = getSitemapPageCount(totalMiis);

    if (pageNumber > totalPages) {
        res.status(404).header("Content-Type", "application/xml");
        res.send(generateSitemapXML([]));
        return;
    }

    const miis = await getPublicMiisForSitemapPage(pageNumber);
    res.header("Content-Type", "application/xml");
    res.send(generateSitemapXML(buildMiiSitemapUrls(miis, resolvedBaseUrl)));
}

import 'express-async-errors'; // Inject express to make router async errors handle the same as sync errors (dropping down to next() handler)
const site = express();
// Cloudflare Tunnel terminates upstream and forwards from localhost with X-Forwarded-* headers.
site.set("trust proxy", "loopback");
site.use(express.json());
site.use(express.urlencoded({ extended: true }));
site.use(express.static(path.join(__dirname + '/static'), {
    setHeaders: (res, filePath) => {
        if (isPublicGeneratedImagePath(filePath)) {
            applyPublicImageSeoHeaders(res);
        }
        if (filePath.endsWith(path.join('static', 'miiImgs', 'average.png'))) {
            applyNoCacheHeaders(res);
        }
    }
}));
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

const privateAssetMiiCacheKey = Symbol("privateAssetMii");
const assetGenerationTasks = new Map();

function getRequestedMiiId(req) {
    return req.path.split('/').pop()?.split('.')?.[0] || "";
}

function getMiiAssetPath(dirName, miiId) {
    return path.join(__dirname, 'static', dirName, `${miiId}.png`);
}

async function fileExists(filePath) {
    try {
        await fs.promises.access(filePath, fs.constants.F_OK);
        return true;
    } catch {
        return false;
    }
}

async function waitForFileOrTimeout(filePath, {
    timeoutMs = UPLOAD_WEBHOOK_IMAGE_READY_TIMEOUT_MS,
    pollIntervalMs = 250
} = {}) {
    const deadline = Date.now() + Math.max(0, Number(timeoutMs) || 0);

    while (!(await fileExists(filePath))) {
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0) {
            return false;
        }

        await new Promise((resolve) => {
            setTimeout(resolve, Math.min(pollIntervalMs, remainingMs));
        });
    }

    return true;
}

function queueUploadWebhookReport(embed, {
    imagePath = "",
    imageFilename = "",
    attachments = []
} = {}) {
    void (async () => {
        let reportEmbed = embed;
        const reportAttachments = Array.isArray(attachments) ? [...attachments] : [];

        if (imagePath) {
            const imageReady = await waitForFileOrTimeout(imagePath);
            if (imageReady) {
                try {
                    const imageData = await fs.promises.readFile(imagePath);
                    const contentType = detectImageMime(imageData) || "image/png";
                    const requestedFilename = imageFilename || path.basename(imagePath);
                    const filename = contentType === "image/bmp" && requestedFilename.toLowerCase().endsWith(".png")
                        ? requestedFilename.replace(/\.png$/i, ".bmp")
                        : requestedFilename;
                    reportAttachments.push({
                        data: imageData,
                        filename,
                        contentType
                    });
                    reportEmbed = {
                        ...reportEmbed,
                        image: {
                            ...(reportEmbed?.image || {}),
                            url: `attachment://${filename}`
                        }
                    };
                } catch (error) {
                    rawConsoleError("Error reading upload render for webhook report:", error);
                }
            }
        }

        await makeReport(JSON.stringify({
            embeds: [reportEmbed]
        }), reportAttachments);
    })().catch((error) => {
        rawConsoleError("Error queueing upload webhook report:", error);
    });
}

async function runSingleFlightTask(map, key, task) {
    const existingTask = map.get(key);
    if (existingTask) {
        return await existingTask;
    }

    const taskPromise = (async () => await task())();
    map.set(key, taskPromise);

    try {
        return await taskPromise;
    } finally {
        if (map.get(key) === taskPromise) {
            map.delete(key);
        }
    }
}

async function ensureGeneratedAsset(assetPath, generator) {
    if (await fileExists(assetPath)) {
        return true;
    }

    return await runSingleFlightTask(assetGenerationTasks, assetPath, async () => {
        if (await fileExists(assetPath)) {
            return true;
        }
        return Boolean(await generator());
    });
}

async function resolvePrivateAssetMii(req) {
    if (Object.prototype.hasOwnProperty.call(req, privateAssetMiiCacheKey)) {
        return req[privateAssetMiiCacheKey];
    }

    const miiId = getRequestedMiiId(req);
    req[privateAssetMiiCacheKey] = miiId
        ? await Miis.findOne({ id: miiId, private: true }).lean()
        : null;
    return req[privateAssetMiiCacheKey];
}

async function requirePrivateMiiAssetAccess(req, res, next) {
    const privateMii = await resolvePrivateAssetMii(req);
    if (!privateMii) {
        return next();
    }

    const isOwner = Boolean(req.user && privateMii.uploader === req.user.username);
    const isModerator = Boolean(req.user && canModerate(req.user));

    if (isOwner || isModerator) {
        return next();
    }

    if (req.baseUrl === "/privateMiiQRs" || req.baseUrl === "/privateMiiQRsWii") {
        return await sendError(res, req, "Access denied. This is a private Mii.", 403);
    }

    if (req.accepts('html')) {
        return await sendError(res, req, "Access denied. This is a private Mii.", 403);
    }

    return res.status(403).json({ error: 'Access denied' });
}

async function writeRenderedMiiImage(mii, assetPath) {
    await fs.promises.writeFile(assetPath, await miijs.renderMii(mii));
}

async function writeRenderedMiiQr(mii, assetPath, qrConsole = "3DS") {
    await writeQrPng(mii, assetPath, qrConsole);
}

site.use('/privateMiiImgs', requirePrivateMiiAssetAccess);
site.use('/privateMiiQRs', requirePrivateMiiAssetAccess);
site.use('/privateMiiQRsWii', requirePrivateMiiAssetAccess);

// Render missing private Mii images on demand
site.use('/privateMiiImgs', async (req, res, next) => {
    const miiId = getRequestedMiiId(req);
    if (!miiId) return next();

    const imgPath = getMiiAssetPath('privateMiiImgs', miiId);
    if (await fileExists(imgPath)) {
        return res.sendFile(imgPath);
    }

    try {
        const generated = await ensureGeneratedAsset(imgPath, async () => {
            const mii = await resolvePrivateAssetMii(req);
            if (!mii) return false;
            await writeRenderedMiiImage(mii, imgPath);
            return true;
        });

        if (generated) {
            return res.sendFile(imgPath);
        }
        return next();
    } catch (e) {
        return next(e);
    }
});

// Render missing private Mii QRs on demand
site.use('/privateMiiQRs', async (req, res, next) => {
    const miiId = getRequestedMiiId(req);
    if (!miiId) return next();

    const qrPath = getMiiAssetPath('privateMiiQRs', miiId);
    if (await fileExists(qrPath)) {
        return res.sendFile(qrPath);
    }

    try {
        const generated = await ensureGeneratedAsset(qrPath, async () => {
            const mii = await resolvePrivateAssetMii(req);
            if (!mii) return false;
            await writeRenderedMiiQr(mii, qrPath, "3DS");
            return true;
        });

        if (generated) {
            return res.sendFile(qrPath);
        }
        return next();
    } catch (e) {
        return next(e);
    }
});

// Render missing private Mii Wii QRs on demand
site.use('/privateMiiQRsWii', async (req, res, next) => {
    const miiId = getRequestedMiiId(req);
    if (!miiId) return next();

    const qrPath = getMiiAssetPath('privateMiiQRsWii', miiId);
    if (await fileExists(qrPath)) {
        return res.sendFile(qrPath);
    }

    try {
        const generated = await ensureGeneratedAsset(qrPath, async () => {
            const mii = await resolvePrivateAssetMii(req);
            if (!mii) return false;
            await writeRenderedMiiQr(mii, qrPath, "WIIU");
            return true;
        });

        if (generated) {
            return res.sendFile(qrPath);
        }
        return next();
    } catch (e) {
        return next(e);
    }
});

// Render missing public Mii images on demand
site.use('/miiImgs', async (req, res, next) => {
    const miiId = getRequestedMiiId(req);
    if (!miiId) return next();

    const imgPath = getMiiAssetPath('miiImgs', miiId);
    const shouldDisableCache = miiId === "average";
    if (await fileExists(imgPath)) {
        applyPublicImageSeoHeaders(res);
        return shouldDisableCache
            ? sendFileWithoutCache(res, imgPath)
            : res.sendFile(imgPath);
    }

    try {
        const generated = await ensureGeneratedAsset(imgPath, async () => {
            const mii = await Miis.findOne({ id: miiId, private: false }).lean();
            if (!mii) return false;
            await writeRenderedMiiImage(mii, imgPath);
            return true;
        });

        if (generated) {
            applyPublicImageSeoHeaders(res);
            return shouldDisableCache
                ? sendFileWithoutCache(res, imgPath)
                : res.sendFile(imgPath);
        }
        applyNoCacheHeaders(res);
        return next();
    } catch (e) {
        return next(e);
    }
});

// Render missing public Mii QRs on demand
site.use('/miiQRs', async (req, res, next) => {
    const miiId = getRequestedMiiId(req);
    if (!miiId) return next();

    const qrPath = getMiiAssetPath('miiQRs', miiId);
    if (await fileExists(qrPath)) {
        applyPublicImageSeoHeaders(res);
        return res.sendFile(qrPath);
    }

    try {
        const generated = await ensureGeneratedAsset(qrPath, async () => {
            const mii = await Miis.findOne({ id: miiId, private: false }).lean();
            if (!mii) return false;
            await writeRenderedMiiQr(mii, qrPath, "3DS");
            return true;
        });

        if (generated) {
            applyPublicImageSeoHeaders(res);
            return res.sendFile(qrPath);
        }
        return next();
    } catch (e) {
        return next(e);
    }
});

// Render missing public Mii Wii QRs on demand
site.use('/miiQRsWii', async (req, res, next) => {
    const miiId = getRequestedMiiId(req);
    if (!miiId) return next();

    const qrPath = getMiiAssetPath('miiQRsWii', miiId);
    if (await fileExists(qrPath)) {
        applyPublicImageSeoHeaders(res);
        return res.sendFile(qrPath);
    }

    try {
        const generated = await ensureGeneratedAsset(qrPath, async () => {
            const mii = await Miis.findOne({ id: miiId, private: false }).lean();
            if (!mii) return false;
            await writeRenderedMiiQr(mii, qrPath, "WIIU");
            return true;
        });

        if (generated) {
            applyPublicImageSeoHeaders(res);
            return res.sendFile(qrPath);
        }
        return next();
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
        if (!fs.existsSync('./static/miiQRsWii')) {
            fs.mkdirSync('./static/miiQRsWii', { recursive: true });
        }
        if (!fs.existsSync('./static/privateMiiQRsWii')) {
            fs.mkdirSync('./static/privateMiiQRsWii', { recursive: true });
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
        await Promise.all(normalizedCompanySources.map(source => ensureOfficialCompanySourceAccount(source, settings)));
        await ensureOfficialMiiSeedLikes();
        await backfillMissingUserPfpSetFlags();
        setTimeout(() => {
            backfillMiiIdentityHashes().catch((error) => {
                console.error("[miiHash] Failed to backfill Mii identity hashes:", error);
            });
        }, 0);
        console.log("Settings initialized");
        getIndexNowKey();

        scheduleDailyWebhookReminder({
            hourUtc: 12,
            minuteUtc: 0,
            label: "Highlighted Mii reminder",
            task: async (currentDate) => {
                await sendHighlightedMiiReminderIfDue(currentDate);
            }
        });

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
                        const matchingMii = await findMatchingMii(mii, { includeGeneral: quickUploadMetadata.official });
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
                        setMiiIdentityHash(mii);
                        await applyAutomaticDecodedMiiTags(mii);
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

        console.log(`[average] Scheduling background average Mii refresh.`);
        queueAverageMiiRefresh("startup");
        setInterval(async () => {
            try {
                if (averageMiiRefreshPromise || averageMiiRefreshTimer) {
                    return;
                }

                if (await hasRecentAverageAffectingUpload()) {
                    console.log("[average] Recent public upload detected. Queueing average Mii refresh.");
                    queueAverageMiiRefresh("recent upload");
                }
            } catch (error) {
                console.error("[average] Failed to check average Mii refresh status:", error);
            }
        }, AVERAGE_MII_REFRESH_WINDOW_MS);

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
        "Official": { miis: (await paginatedApi("officialTrending", 1, HOME_PREVIEW_COUNT)).items, link: "./official" }
    };
    
    ejs.renderFile('./ejsFiles/index.ejs', toSend, {}, function (err, str) {
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
    const perPage = FULL_ROW_BROWSE_REQUEST_LIMIT;
    const seed = Math.floor(Math.random() * 1000000).toString();

    const paginatedData = await paginatedApi("random", 1, perPage, seed);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        mode: "random",
        start: 0,
        total: paginatedData.items.length,
        requestLimit: paginatedData.perPage,
        baseCount: defaultMiisPerPage
    };
    toSend.currentPath = req.path;
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);
    
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
    const start = getRequestedStartOffset(req.query, defaultMiisPerPage);
    
    const paginatedData = await paginatedApi("trending", { start }, FULL_ROW_BROWSE_REQUEST_LIMIT);
    if (paginatedData.total > 0 && start >= paginatedData.total) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(paginatedData.total, paginatedData.perPage)));
    }
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = buildStartPagination(req, paginatedData.start, paginatedData.total, paginatedData.perPage);
    toSend.currentPath = buildRequestPathWithStart(req, paginatedData.start);
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);
    
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
    const start = getRequestedStartOffset(req.query, defaultMiisPerPage);
    
    const paginatedData = await paginatedApi("top", { start }, FULL_ROW_BROWSE_REQUEST_LIMIT);
    if (paginatedData.total > 0 && start >= paginatedData.total) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(paginatedData.total, paginatedData.perPage)));
    }
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = buildStartPagination(req, paginatedData.start, paginatedData.total, paginatedData.perPage);
    toSend.currentPath = buildRequestPathWithStart(req, paginatedData.start);
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);
    
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
    const start = getRequestedStartOffset(req.query, defaultMiisPerPage);
    
    const paginatedData = await paginatedApi("recent", { start }, FULL_ROW_BROWSE_REQUEST_LIMIT);
    if (paginatedData.total > 0 && start >= paginatedData.total) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(paginatedData.total, paginatedData.perPage)));
    }
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = buildStartPagination(req, paginatedData.start, paginatedData.total, paginatedData.perPage);
    toSend.currentPath = buildRequestPathWithStart(req, paginatedData.start);
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);
    
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
    
    const start = getRequestedStartOffset(req.query, defaultMiisPerPage);
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
    const paginatedData = await paginatedApi("official", { start }, FULL_ROW_BROWSE_REQUEST_LIMIT, filterCategory);
    if (paginatedData.total > 0 && start >= paginatedData.total) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(paginatedData.total, paginatedData.perPage)));
    }
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = buildStartPagination(req, paginatedData.start, paginatedData.total, paginatedData.perPage);
    toSend.currentPath = buildRequestPathWithStart(req, paginatedData.start);
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);
    
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
    const start = getRequestedStartOffset(req.query, defaultMiisPerPage);
    const searchQuery = typeof req.query.q === "string" ? req.query.q.trim() : "";
    const selectedTags = Array.isArray(toSend.selectedTags) ? toSend.selectedTags : [];
    const selectedSearchFields = getRequestedSearchFields(req.query);
    
    const paginatedData = await paginatedApi("search", { start }, FULL_ROW_BROWSE_REQUEST_LIMIT, {
        query: searchQuery,
        tags: selectedTags,
        searchIn: selectedSearchFields,
        searchFieldsConfigured: true
    });
    if (paginatedData.total > 0 && start >= paginatedData.total) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(paginatedData.total, paginatedData.perPage)));
    }
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = buildStartPagination(req, paginatedData.start, paginatedData.total, paginatedData.perPage);
    toSend.currentPath = buildRequestPathWithStart(req, paginatedData.start);
    
    toSend.searchQuery = searchQuery;
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);
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
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
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
site.get('/:indexNowKey.txt', (req, res, next) => {
    const requestedKey = String(req.params.indexNowKey || "").trim();
    const configuredKey = getIndexNowKey();

    if (!configuredKey || requestedKey !== configuredKey) {
        return next();
    }

    res.type('text/plain; charset=UTF-8');
    res.send(configuredKey);
});
site.get('/feed.xml', async (req, res) => {
    const recentMiis = await Miis.find({
        private: false,
        id: { $ne: "average" }
    })
        .sort({ uploadedOn: -1, _id: -1 })
        .limit(RSS_FEED_MII_LIMIT)
        .lean();

    res.header('Content-Type', 'application/rss+xml; charset=UTF-8');
    res.send(generateMiiUploadRssXML(recentMiis, req));
});
site.get('/rss.xml', (req, res) => {
    res.redirect(301, '/feed.xml');
});
site.get('/transferInstructions', async (req, res) => {
    res.redirect(301, '/guides/transfer');
});
site.get('/guides/transfer', async (req, res) => {
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
    applyNoCacheHeaders(res);
}

const NO_CACHE_RESPONSE_HEADERS = Object.freeze({
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0"
});
const PUBLIC_GENERATED_IMAGE_DIRS = new Set(["miiImgs", "miiQRs", "miiQRsWii"]);

function isPublicGeneratedImagePath(filePath) {
    if (path.extname(filePath).toLowerCase() !== ".png") {
        return false;
    }

    const relativePath = path.relative(path.join(__dirname, "static"), filePath);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
        return false;
    }

    return PUBLIC_GENERATED_IMAGE_DIRS.has(relativePath.split(path.sep)[0]);
}

function applyPublicImageSeoHeaders(res) {
    res.setHeader("X-Robots-Tag", "index, follow, max-image-preview:large");
}

function applyNoCacheHeaders(res) {
    for (const [headerName, headerValue] of Object.entries(NO_CACHE_RESPONSE_HEADERS)) {
        res.setHeader(headerName, headerValue);
    }
}

function sendFileWithoutCache(res, filePath) {
    return res.sendFile(filePath, {
        headers: NO_CACHE_RESPONSE_HEADERS
    });
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
        legacyUploadErrorHtml: options.errorHtml || "",
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
            const dumpedUpload = await dumpFailingUploadFile(req.file, e, "legacy-upload");
            if (dumpedUpload) {
                await sendSavedFailingUploadToWebhook({
                    req,
                    error: e,
                    context: "legacy-upload",
                    dumpedUpload
                });
            }
            const invalidMiiTypeError = isInvalidMiiTypeError(e)
                ? await buildInvalidMiiTypeErrorPayload({
                    reqFile: req.file,
                    filePath: dumpedUpload?.destinationPath || req.file?.path
                })
                : null;
            if (invalidMiiTypeError && !dumpedUpload) {
                await sendInvalidMiiInputToWebhook({
                    req,
                    error: e,
                    context: "legacy-upload",
                    reqFile: req.file,
                    filePath: req.file?.path
                });
            }
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: invalidMiiTypeError?.error || `Failed to read this file as a Mii. ${e.message || ""}`.trim(),
                formValues
            });
            return;
        }

        const matchingMii = await findMatchingMii(mii);
        if (matchingMii) {
            cleanupUpload();
            await renderLegacyUploadPage(req, res, {
                error: getDuplicateMiiErrorMessage(matchingMii.id),
                errorHtml: getDuplicateMiiErrorHtml(matchingMii.id),
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
        setMiiIdentityHash(mii);
        await applyAutomaticDecodedMiiTags(mii);
        ensureUploadMiiPermissions(mii);

        const assetPaths = wantsPublic
            ? {
                img: `./static/miiImgs/${mii.id}.png`,
                qr3ds: `./static/miiQRs/${mii.id}.png`,
                qrWii: `./static/miiQRsWii/${mii.id}.png`
            }
            : {
                img: `./static/privateMiiImgs/${mii.id}.png`,
                qr3ds: `./static/privateMiiQRs/${mii.id}.png`,
                qrWii: `./static/privateMiiQRsWii/${mii.id}.png`
            };
        await Promise.all([
            writeRenderedMiiImage(mii, assetPaths.img),
            writeQrPng(mii, assetPaths.qr3ds, "3DS"),
            writeQrPng(mii, assetPaths.qrWii, "WIIU")
        ]);

        await Miis.create({
            ...mii,
            id: mii.id,
            private: !wantsPublic
        });
        await ensureUploaderAutoLike(user.username, mii.id, 1);

        const legacyUploadReportEmbed = {
            type: "rich",
            title: `Legacy Browser Upload (${wantsPublic ? "Published" : "Private"})`,
            url: `https://infinimii.com/mii/${mii.id}`,
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
            ].concat(buildTomodachiLifeUploadWebhookFields(mii)),
            footer: {
                text: `View: https://infinimii.com/mii/${mii.id}`
            }
        };
        if (wantsPublic) {
            legacyUploadReportEmbed.image = {
                url: `https://infinimii.com/miiImgs/${encodeURIComponent(mii.id)}.png`
            };
        }
        queueUploadWebhookReport(legacyUploadReportEmbed, {
            imagePath: assetPaths.img
        });

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
            maxAge: ms("30 days"), // 1 Month
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
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
            maxAge: ms("30 days"),
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
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

        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
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

        // Delete from database, assets, and stored references
        await deleteStoredMiisAndCleanup([mii]);

        const redirect = mii.private ? "/myPrivateMiis" : `/user/${encodeURIComponent(mii.uploader)}`;
        res.json({ okay: true, redirect });

        if (!mii.private && mii.published !== false) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, mii),
                resolvedBaseUrl,
                "delete-mii"
            );
        }

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
// Update Mii Field (Moderator+, Researchers for official Miis, and unlocked uploaders for metadata)
site.post('/updateMiiField', requireAuth, async (req, res) => {
    try {
        const { id, field, value } = req.body;
        const requestedField = String(field || '').trim();
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);

        if (!id || !requestedField || value === undefined) {
            return res.json({ error: 'Missing parameters' });
        }

        const mii = await getMiiById(id, true);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        const editableMetadataFields = new Set(['name', 'desc', 'creatorName']);
        const canUseModeratorTools = canModerate(req.user);
        const canResearchOfficial = isResearcher(req.user) && mii.official;
        const isUploader = Boolean(req.user?.username && mii.uploader === req.user.username);
        const isMetadataField = editableMetadataFields.has(requestedField);
        const isUserEditLocked = Boolean(mii.lockedFromUserEdits);
        const canUploaderEditMetadata = isUploader && isMetadataField && !isUserEditLocked;

        if (requestedField === 'lockedFromUserEdits' && !canUseModeratorTools) {
            return res.json({ error: 'Only moderators can change the uploader edit lock' });
        }

        if (
            requestedField !== 'lockedFromUserEdits' &&
            !canUseModeratorTools &&
            !canResearchOfficial &&
            !canUploaderEditMetadata
        ) {
            if (isUploader && isMetadataField && isUserEditLocked) {
                return res.json({ error: 'This Mii has been locked from uploader edits by a moderator' });
            }
            return res.json({ error: 'Insufficient permissions' });
        }

        const isResearcherOnlyActor = canResearchOfficial && !canUseModeratorTools;
        const researcherAllowedFields = new Set(['name', 'desc', 'creatorName']);
        if (isResearcherOnlyActor && !researcherAllowedFields.has(requestedField)) {
            return res.json({ error: 'Researchers can only edit name, description, and creator name on official Miis' });
        }

        // Store old value for logging
        let oldValue;
        let normalizedValue = value;
        let updates = {};

        // Update the appropriate field
        switch (requestedField) {
            case 'name':
                if (typeof value !== 'string') {
                    return res.json({ error: 'Mii name must be a string' });
                }
                normalizedValue = value.trim();
                if (!normalizedValue) {
                    return res.json({ error: 'Mii name is required' });
                }
                if (normalizedValue.length > 10) {
                    return res.json({ error: 'Mii name must be 10 characters or fewer' });
                }
                oldValue = mii.meta.name;
                updates['meta.name'] = normalizedValue;
                break;
            case 'desc':
                if (typeof value !== 'string') {
                    return res.json({ error: 'Description must be a string' });
                }
                normalizedValue = value;
                if (!normalizedValue.trim()) {
                    return res.json({ error: 'Description is required' });
                }
                oldValue = mii.desc;
                updates.desc = normalizedValue;
                break;
            case 'creatorName':
                if (typeof value !== 'string') {
                    return res.json({ error: 'Creator name must be a string' });
                }
                normalizedValue = value.trim();
                if (normalizedValue.length > 10) {
                    return res.json({ error: 'Creator name must be 10 characters or fewer' });
                }
                oldValue = mii.meta.creatorName;
                updates['meta.creatorName'] = normalizedValue;
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
            case 'lockedFromUserEdits':
                if (typeof value !== 'boolean') {
                    return res.json({ error: 'Uploader edit lock must be true or false' });
                }
                normalizedValue = Boolean(value);
                oldValue = mii.lockedFromUserEdits ? 'Locked' : 'Unlocked';
                updates.lockedFromUserEdits = normalizedValue;
                break;
            default:
                return res.json({ error: 'Invalid field' });
        }

        await Miis.findOneAndUpdate({ id }, { $set: updates });

        const actorRoleLabel = isAdmin(req.user)
            ? 'Administrator'
            : (canUseModeratorTools ? 'Moderator' : (canResearchOfficial ? 'Researcher' : 'Uploader'));

        // Log to Discord
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `Mii ${requestedField} Updated`,
                description: `${actorRoleLabel} ${req.user.username} updated ${requestedField}`,
                color: 0xFFA500,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                        inline: true
                    },
                    {
                        name: 'Field',
                        value: requestedField,
                        inline: true
                    },
                    {
                        name: 'Old Value',
                        value: String(oldValue || 'N/A'),
                        inline: false
                    },
                    {
                        name: 'New Value',
                        value: String(
                            requestedField === 'lockedFromUserEdits'
                                ? (normalizedValue ? 'Locked' : 'Unlocked')
                                : (normalizedValue || 'N/A')
                        ),
                        inline: false
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${id}.png`
                }
            }]
        }));

        if (!mii.private && mii.published !== false) {
            const updatedMii = {
                ...mii,
                uploader: requestedField === "uploader" ? normalizedValue : mii.uploader
            };
            const extraUrls = requestedField === "uploader"
                ? [getUserProfileUrl(resolvedBaseUrl, oldValue)]
                : [];
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedMii, {
                    extraUrls,
                    includeOfficialListing: Boolean(mii.official)
                }),
                resolvedBaseUrl,
                `update-mii-${requestedField}`
            );
        }

        res.json({ okay: true });
    } catch (e) {
        console.error('Error updating Mii field:', e);
        res.json({ error: 'Server error' });
    }
});
// Change Mii ID (Moderator+ for generated IDs, Admin for manual IDs)
site.post('/changeMiiId', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const currentId = normalizeMiiIdInput(req.body?.miiId || req.body?.id);
        const requestedNewId = normalizeMiiIdInput(req.body?.newId);
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);

        if (!currentId) {
            return res.json({ error: 'Mii ID required' });
        }
        if (isProtectedMiiId(currentId)) {
            return res.json({ error: 'This Mii ID cannot be changed' });
        }

        const mii = await getMiiById(currentId, true);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        let nextId = requestedNewId;
        let changeMode = 'generated';

        if (requestedNewId) {
            if (!isAdmin(req.user)) {
                return res.json({ error: 'Only administrators can set a Mii ID directly' });
            }
            if (!isValidManualMiiId(requestedNewId)) {
                return res.json({ error: `Custom Mii IDs must be alphanumeric and ${MAX_MANUAL_MII_ID_LENGTH} characters or fewer` });
            }
            if (soundsBad(requestedNewId)) {
                return res.json({ error: 'That Mii ID is not allowed' });
            }
            changeMode = 'direct';
        } else {
            nextId = await genId();
        }

        if (nextId === currentId) {
            return res.json({ error: 'New Mii ID matches the current ID' });
        }

        const idInUse = await Miis.exists({ id: nextId });
        if (idInUse) {
            return res.json({ error: 'That Mii ID is already in use' });
        }

        const updatedMii = await updateStoredMiiId(mii, nextId);

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: changeMode === 'direct' ? 'Mii ID Set Directly' : 'Mii ID Regenerated',
                description: `${isAdmin(req.user) ? 'Administrator' : 'Moderator'} ${req.cookies.username} changed a Mii ID`,
                color: 0x00CCFF,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${updatedMii.meta?.name || 'Unknown'}](https://infinimii.com/mii/${updatedMii.id})`,
                        inline: true
                    },
                    {
                        name: 'Old ID',
                        value: currentId,
                        inline: true
                    },
                    {
                        name: 'New ID',
                        value: updatedMii.id,
                        inline: true
                    },
                    {
                        name: 'Mode',
                        value: changeMode === 'direct' ? 'Direct Set' : 'Generated',
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${updatedMii.id}.png`
                }
            }]
        }));

        const redirect = `/mii/${encodeURIComponent(updatedMii.id)}`;
        res.json({ okay: true, newId: updatedMii.id, redirect });

        if (!mii.private && mii.published !== false) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedMii, {
                    extraUrls: [getMiiPageUrl(resolvedBaseUrl, currentId)],
                    includeOfficialListing: Boolean(updatedMii.official)
                }),
                resolvedBaseUrl,
                changeMode === 'direct' ? 'set-mii-id' : 'regenerate-mii-id'
            );
        }
    } catch (e) {
        console.error('Error changing Mii ID:', e);
        res.json({ error: 'Server error' });
    }
});
// Regenerate QR Code (Moderator only)
site.post('/regenerateQR', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    const { id } = req.body;
    const mii = await getMiiById(id, true);

    if (!mii) {
        return res.json({ error: 'Mii not found' });
    }

    // Regenerate both QR previews so the page tabs stay synchronized.
    const { qrPath, qrWiiPath } = getMiiAssetPaths(id, Boolean(mii.private));
    await Promise.all([
        writeQrPng(mii, qrPath, "3DS"),
        writeQrPng(mii, qrWiiPath, "WIIU")
    ]);

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
// Regenerate Render Image (Moderator only)
site.post('/regenerateRender', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    const { id } = req.body;
    const mii = await getMiiById(id, true);

    if (!mii) {
        return res.json({ error: 'Mii not found' });
    }

    const { imgPath } = getMiiAssetPaths(id, mii.private);
    const renderedImage = await miijs.renderMii(mii);
    await fs.promises.writeFile(imgPath, renderedImage);

    makeReport(JSON.stringify({
        embeds: [{
            type: 'rich',
            title: `Render Image Regenerated`,
            description: `Moderator ${req.cookies.username} regenerated render image`,
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
// Clear Tomodachi Life metadata (Admin only)
site.post('/clearMiiTlData', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const id = normalizeMiiIdInput(req.body?.id || req.body?.miiId);
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);

        if (!id) {
            return res.json({ error: 'Mii ID required' });
        }

        const mii = await getMiiById(id, true);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        const currentTags = normalizeTagList(mii.tags || []);
        const nextTags = currentTags.filter(
            tag => tag.toLowerCase() !== TOMODACHI_LIFE_TAG.toLowerCase()
        );
        const hadTlData = hasDecodedTomodachiLifeData(mii);
        const hadTomodachiLifeTag = nextTags.length !== currentTags.length;

        if (!hadTlData && !hadTomodachiLifeTag) {
            return res.json({ okay: true, unchanged: true });
        }

        await Miis.findOneAndUpdate(
            { id },
            {
                $unset: { tl: "" },
                $set: { tags: nextTags }
            }
        );

        const updatedMii = {
            ...mii,
            tags: nextTags
        };
        delete updatedMii.tl;

        const { qrPath, qrWiiPath } = getMiiAssetPaths(id, Boolean(mii.private));
        await Promise.all([
            writeQrPng(updatedMii, qrPath, "3DS"),
            writeQrPng(updatedMii, qrWiiPath, "WIIU")
        ]);

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: 'Tomodachi Life Data Cleared',
                description: `Administrator ${req.cookies.username} cleared Tomodachi Life data from a Mii`,
                color: 0xF7C02D,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta?.name || "Unknown"}](https://infinimii.com/mii/${id})`,
                        inline: true
                    },
                    {
                        name: 'Tomodachi Life Tag Removed',
                        value: hadTomodachiLifeTag ? 'Yes' : 'No',
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/${mii.private ? 'privateMiiImgs' : 'miiImgs'}/${id}.png`
                }
            }]
        }));

        res.json({ okay: true });

        if (!mii.private && mii.published !== false) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedMii, {
                    includeOfficialListing: Boolean(updatedMii.official)
                }),
                resolvedBaseUrl,
                'clear-mii-tl-data'
            );
        }
    } catch (e) {
        console.error('Error clearing Mii TL data:', e);
        res.json({ error: 'Server error' });
    }
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
                        value: role,
                        inline: true
                    },
                    {
                        name: 'Current Roles',
                        value: getUserRoles(targetUser).map(r => r).join(', '),
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
                        value: role,
                        inline: true
                    },
                    {
                        name: 'Current Roles',
                        value: getUserRoles(targetUser).map(r => r).join(', '),
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

        // Delete all user's Miis (public + private) and remove stored references
        const userMiis = await Miis.find({ uploader: targetUser.username }).select('id private').lean();
        await deleteStoredMiisAndCleanup(userMiis);

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
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        const userMiis = await Miis.find({ uploader: targetUser.username }).select('id private published official uploader').lean();
        const publicUserMiis = userMiis.filter((mii) => !mii.private && mii.published !== false);
        const cleanupResult = await deleteStoredMiisAndCleanup(userMiis);
        const deletedCount = cleanupResult.deletedCount;

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

        if (publicUserMiis.length > 0) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, publicUserMiis, {
                    extraUrls: [getUserProfileUrl(resolvedBaseUrl, targetUser.username)]
                }),
                resolvedBaseUrl,
                "delete-all-user-miis"
            );
        }
    } catch (e) {
        console.error('Error deleting all user Miis:', e);
        res.json({ error: 'Server error' });
    }
});

// Change Username (Moderator+)
site.post('/changeUsername', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const normalizedOldUsername = normalizeUsernameInput(req.body?.oldUsername);
        const normalizedNewUsername = normalizeUsernameInput(req.body?.newUsername);
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);

        if (!isValidUsername(normalizedNewUsername)) {
            return res.json({ error: 'Invalid username format. Username must be 3-20 characters using only letters, numbers, underscores, hyphens, or periods.' });
        }

        const existing = await getUserByUsername(normalizedNewUsername);
        if (existing) {
            return res.json({ error: 'Username already taken' });
        }
        
        // Check if username is reserved
        const reserved = await ReservedUsername.findOne({ username: normalizedNewUsername });
        if (reserved) {
            return res.json({ error: 'This username is reserved. Please try choose a different username.' });
        }

        const user = await getUserByUsername(normalizedOldUsername);
        if (!user) {
            return res.json({ error: 'User not found' });
        }

        const publicUserMiis = await Miis.find({
            uploader: normalizedOldUsername,
            private: false,
            published: true
        }).select('id official private published').lean();
        
        // Reserve the old username for 30 days (JWT expiry period)
        const reserveUntil = new Date(Date.now() + ms('30 days'));
        try {
            await ReservedUsername.create({
                username: normalizedOldUsername,
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
            { username: normalizedOldUsername },
            { 
                username: normalizedNewUsername,
                tokenVersion: newTokenVersion,
                lastUsernameChange: Date.now()
            }
        );

        // Update uploader field in all user's Miis
        await Miis.updateMany(
            { uploader: normalizedOldUsername },
            { $set: { uploader: normalizedNewUsername } }
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
                        value: normalizedOldUsername,
                        inline: true
                    },
                    {
                        name: 'New Username',
                        value: normalizedNewUsername,
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(user.email,`Username Changed - InfiniMii`,`Hi ${normalizedOldUsername}, a moderator has changed your username to ${normalizedNewUsername}. This will be what you login with moving forward. You can reply to this email to receive support.`);

        if (publicUserMiis.length > 0) {
            const updatedMiis = publicUserMiis.map((mii) => ({ ...mii, uploader: normalizedNewUsername }));
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedMiis, {
                    extraUrls: [
                        getUserProfileUrl(resolvedBaseUrl, normalizedOldUsername),
                        getUserProfileUrl(resolvedBaseUrl, normalizedNewUsername)
                    ]
                }),
                resolvedBaseUrl,
                "change-username"
            );
        } else {
            notifyIndexNow(
                [
                    getUserProfileUrl(resolvedBaseUrl, normalizedOldUsername),
                    getUserProfileUrl(resolvedBaseUrl, normalizedNewUsername)
                ],
                resolvedBaseUrl,
                "change-username"
            );
        }

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
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
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
        if (normalizedOfficial && (!Number.isFinite(Number(mii.votes)) || Number(mii.votes) < 1)) {
            toggleUpdates.votes = 1;
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

        if (!mii.private && mii.published !== false) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, { ...mii, official: normalizedOfficial }, {
                    includeOfficialListing: oldStatus || normalizedOfficial
                }),
                resolvedBaseUrl,
                "toggle-official"
            );
        }

        res.json({ okay: true });
    } catch (e) {
        console.error('Error toggling official status:', e);
        res.json({ error: 'Server error' });
    }
});

// Main sitemap endpoint
site.get('/sitemap.xml', async (req, res) => {
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const today = new Date().toISOString().split('T')[0];
    const totalMiiSitemapPages = getSitemapPageCount(await getPublicMiiSitemapCount());
    const sitemaps = [
        { loc: `${resolvedBaseUrl}/sitemap-pages.xml`, lastmod: today },
        ...buildMiiSitemapIndexEntries(resolvedBaseUrl, totalMiiSitemapPages, today),
        { loc: `${resolvedBaseUrl}/sitemap-users.xml`, lastmod: today }
    ];

    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapIndexXML(sitemaps));
});

site.get('/sitemap-pages.xml', async (req, res) => {
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const today = new Date().toISOString().split('T')[0];
    const urls = [
        {
            loc: `${resolvedBaseUrl}/`,
            lastmod: today,
            changefreq: 'daily',
            priority: '1.0'
        },
        {
            loc: `${resolvedBaseUrl}/trending`,
            changefreq: 'hourly',
            priority: '0.9'
        },
        {
            loc: `${resolvedBaseUrl}/top`,
            changefreq: 'daily',
            priority: '0.9'
        },
        {
            loc: `${resolvedBaseUrl}/recent`,
            changefreq: 'hourly',
            priority: '0.8'
        },
        {
            loc: `${resolvedBaseUrl}/official`,
            changefreq: 'daily',
            priority: '0.9'
        },
        {
            loc: `${resolvedBaseUrl}/search`,
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: `${resolvedBaseUrl}/convert`,
            changefreq: 'monthly',
            priority: '0.8'
        },
        {
            loc: `${resolvedBaseUrl}/qr`,
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: `${resolvedBaseUrl}/amiibo`,
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: `${resolvedBaseUrl}/wiimote`,
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: `${resolvedBaseUrl}/calculator`,
            changefreq: 'monthly',
            priority: '0.6'
        },
        {
            loc: `${resolvedBaseUrl}/miiChild`,
            changefreq: 'monthly',
            priority: '0.6'
        },
        {
            loc: `${resolvedBaseUrl}/guides/transfer`,
            changefreq: 'monthly',
            priority: '0.8'
        },
        {
            loc: `${resolvedBaseUrl}/guides/formats`,
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: `${resolvedBaseUrl}/guides/comparisons`,
            changefreq: 'monthly',
            priority: '0.6'
        },
        {
            loc: `${resolvedBaseUrl}/faq`,
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: `${resolvedBaseUrl}/about`,
            changefreq: 'monthly',
            priority: '0.6'
        },
        {
            loc: `${resolvedBaseUrl}/cite`,
            changefreq: 'monthly',
            priority: '0.5'
        },
        {
            loc: `${resolvedBaseUrl}/contact`,
            changefreq: 'monthly',
            priority: '0.5'
        },
        {
            loc: `${resolvedBaseUrl}/privacy`,
            changefreq: 'yearly',
            priority: '0.3'
        },
        {
            loc: `${resolvedBaseUrl}/tos`,
            changefreq: 'yearly',
            priority: '0.3'
        },
        {
            loc: `${resolvedBaseUrl}/guidelines`,
            changefreq: 'yearly',
            priority: '0.3'
        }
    ];

    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// Mii-specific sitemap (separate for better organization)
site.get('/sitemap-miis.xml', async (req, res) => {
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const today = new Date().toISOString().split('T')[0];
    const totalMiiSitemapPages = getSitemapPageCount(await getPublicMiiSitemapCount());

    res.header('Content-Type', 'application/xml');
    if (totalMiiSitemapPages > 1) {
        res.send(generateSitemapIndexXML(buildMiiSitemapIndexEntries(resolvedBaseUrl, totalMiiSitemapPages, today)));
        return;
    }

    await sendMiiSitemapPage(req, res, 1);
});

site.get(/^\/sitemap-miis-(\d+)\.xml$/, async (req, res) => {
    await sendMiiSitemapPage(req, res, getMiiSitemapPageNumber(req.params[0]));
});

// User profiles sitemap
site.get('/sitemap-users.xml', async (req, res) => {
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const publicUploaders = await Miis.aggregate([
        {
            $match: {
                private: false,
                published: true,
                uploader: { $nin: ['default', 'Nintendo', '[Deleted User]'] }
            }
        },
        {
            $group: {
                _id: '$uploader',
                lastUploaded: { $max: '$uploadedOn' }
            }
        },
        { $sort: { _id: 1 } }
    ]);

    const urls = publicUploaders.map((summary) => ({
        loc: `${resolvedBaseUrl}/user/${encodeURIComponent(summary._id)}`,
        lastmod: summary.lastUploaded
            ? new Date(summary.lastUploaded).toISOString().split('T')[0]
            : undefined,
        changefreq: 'daily',
        priority: '0.6'
    }));

    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// Sitemap index
site.get('/sitemap-index.xml', async (req, res) => {
    res.redirect(301, '/sitemap.xml');
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
        await fs.promises.writeFile("./static/miiImgs/" + tempId + ".png", miiImage);
        await writeQrPng(mii, "./static/miiQRs/" + tempId + ".png");
        
        // Also save the decrypted bin data for upload
        await fs.promises.writeFile("./static/temp/" + tempId + ".bin", miiData);
        
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
            res.json(getDuplicateMiiErrorPayload(matchingMii.id));
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
        setMiiIdentityHash(mii);
        await applyAutomaticDecodedMiiTags(mii);
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
                ].concat(buildTomodachiLifeUploadWebhookFields(mii)),
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
        const dumpedUpload = req.file?.path
            ? await dumpFailingUploadFile(req.file, e, "exportMii")
            : null;
        if (dumpedUpload) {
            await sendSavedFailingUploadToWebhook({
                req,
                error: e,
                context: "exportMii",
                dumpedUpload
            });
        }
        if (isInvalidMiiTypeError(e)) {
            if (!dumpedUpload) {
                await sendInvalidMiiInputToWebhook({
                    req,
                    error: e,
                    context: "exportMii",
                    reqFile: req.file,
                    rawInput: typeof req.body?.miiData === "string" ? req.body.miiData : "",
                    filePath: req.file?.path
                });
            }
            const invalidMiiTypeError = await buildInvalidMiiTypeErrorPayload({
                reqFile: req.file,
                rawInput: typeof req.body?.miiData === "string" ? req.body.miiData : "",
                filePath: dumpedUpload?.destinationPath || req.file?.path
            });
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e2) { }
            res.json(invalidMiiTypeError);
            return;
        }
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
            { $set: { miiPfp: miiId, pfpSet: true } }
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

        if (isMiiLikeLockedForUser(mii, req.user)) {
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
            const minimumVotes = mii.official ? 1 : 0;
            const currentVotes = Number.isFinite(Number(mii.votes)) ? Number(mii.votes) : 0;
            await decrementMiiVote(req.query.id, {
                minimumVotes
            });
            if (minimumVotes > 0 && currentVotes <= minimumVotes) {
                res.send("UnlikedSeeded");
                return;
            }
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
        const isModerator = Boolean(req.user && canModerate(req.user));
        const isOwner = Boolean(req.user && mii.uploader === req.user.username);
        
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
    inp.pageUpdatedAt = mii?.updatedAt
        ? new Date(mii.updatedAt).toISOString()
        : (mii?.uploadedOn ? new Date(mii.uploadedOn).toISOString() : undefined);
    inp.miiSeo = buildMiiSeoDetails(mii, inp.officialCategories, {
        officialSourceName: inp.officialSourceName
    });
    inp.reportMiiCategories = REPORT_MII_CATEGORIES;

    const relatedVisibilityFilter = {
        private: false,
        published: true,
        id: { $ne: miiId }
    };
    const sameArchiveOwnerQuery = mii.official
        ? {
            official: true,
            officialSource: mii.officialSource || mii.uploader
        }
        : { uploader: mii.uploader };

    const [sameArchiveOwnerMiis, similarMiis, relatedCategoryMiis, archiveOwnerSummary] = await Promise.all([
        Miis.find({ ...relatedVisibilityFilter, ...sameArchiveOwnerQuery })
            .sort({ votes: -1, uploadedOn: -1 })
            .limit(8)
            .lean(),
        findSimilarMiis(mii, relatedVisibilityFilter, 8),
        inp.miiSeo.categoryDetails.length > 0
            ? Miis.find({
                ...relatedVisibilityFilter,
                officialCategories: { $in: inp.miiSeo.categoryDetails.map(category => category.path).slice(0, 6) }
            })
                .sort({ votes: -1, uploadedOn: -1 })
                .limit(8)
                .lean()
            : Promise.resolve([]),
        Miis.aggregate([
            {
                $match: {
                    uploader: mii.uploader,
                    private: false,
                    published: true
                }
            },
            {
                $group: {
                    _id: null,
                    totalMiis: { $sum: 1 },
                    totalLikes: { $sum: { $ifNull: ["$votes", 0] } }
                }
            }
        ])
    ]);

    inp.archiveOwnerStats = {
        totalMiis: archiveOwnerSummary?.[0]?.totalMiis || 0,
        totalLikes: archiveOwnerSummary?.[0]?.totalLikes || 0
    };
    inp.relatedCollections = buildCuratedMiiCollections([
        {
            title: mii.official
                ? `More official Miis from ${inp.miiSeo.officialSourceName}`
                : `More Miis from ${inp.miiSeo.uploaderName}`,
            description: mii.official
                ? `Browse other preserved official Miis filed under the ${inp.miiSeo.officialSourceName} archive.`
                : `Browse additional Miis uploaded by ${inp.miiSeo.uploaderName}.`,
            items: sameArchiveOwnerMiis
        },
        {
            title: "Similar Miis",
            description: "These Miis share matching names, exact or similar tags, and description topics.",
            items: similarMiis
        },
        {
            title: "Miis in matching official categories",
            description: "These official archive entries share the same source categories.",
            items: relatedCategoryMiis
        }
    ], 5);

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
    let inp = await getSendables(req);
    inp.targetUser = targetUser;
    inp.isOfficialCompanySourceProfile = (Array.isArray(inp.officialCompanySources) ? inp.officialCompanySources : [])
        .some(sourceName => String(sourceName).toLowerCase() === targetUsername.toLowerCase());
    const selectedProfileSort = req.query.sort === "latest" ? "latest" : "popular";
    const profileStart = getRequestedStartOffset(req.query, profileMiisPerPage);

    const profileFilter = {
        uploader: targetUsername,
        private: false,
        published: true
    };
    const profileListSort = selectedProfileSort === "popular"
        ? getStablePopularitySort()
        : getStableRecencySort();

    const [profileSummaryRows, topTagsRows, topCategoryRows, topCreatorRows, featuredMiis] = await Promise.all([
        Miis.aggregate([
            { $match: profileFilter },
            {
                $group: {
                    _id: null,
                    totalMiis: { $sum: 1 },
                    totalLikes: { $sum: { $ifNull: ["$votes", 0] } },
                    officialCount: {
                        $sum: {
                            $cond: ["$official", 1, 0]
                        }
                    },
                    latestUploadOn: { $max: "$uploadedOn" },
                    firstUploadOn: { $min: "$uploadedOn" }
                }
            }
        ]),
        Miis.aggregate([
            { $match: profileFilter },
            { $unwind: "$tags" },
            { $group: { _id: "$tags", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 10 }
        ]),
        Miis.aggregate([
            { $match: profileFilter },
            { $unwind: "$officialCategories" },
            { $group: { _id: "$officialCategories", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 8 }
        ]),
        Miis.aggregate([
            {
                $match: {
                    ...profileFilter,
                    "meta.creatorName": { $exists: true, $type: "string", $ne: "" }
                }
            },
            { $group: { _id: "$meta.creatorName", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 8 }
        ]),
        Miis.find(profileFilter)
            .sort(getStablePopularitySort())
            .limit(4)
            .lean()
    ]);

    const profileSummary = profileSummaryRows?.[0] || {
        totalMiis: 0,
        totalLikes: 0,
        officialCount: 0,
        latestUploadOn: undefined,
        firstUploadOn: undefined
    };
    const totalMiis = profileSummary.totalMiis || 0;
    if (totalMiis > 0 && profileStart >= totalMiis) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(totalMiis, FULL_ROW_PROFILE_REQUEST_LIMIT)));
    }
    const skip = profileStart;

    inp.displayedMiis = await Miis.find(profileFilter)
        .sort(profileListSort)
        .skip(skip)
        .limit(FULL_ROW_PROFILE_REQUEST_LIMIT)
        .lean();
    const topCategories = getMiiCategoryDetails(
        topCategoryRows.map(row => row?._id).filter(Boolean),
        inp.officialCategories
    );
    inp.profileStats = {
        totalMiis,
        totalLikes: profileSummary.totalLikes || 0,
        officialCount: profileSummary.officialCount || 0,
        communityCount: Math.max(0, totalMiis - (profileSummary.officialCount || 0)),
        latestUploadOn: profileSummary.latestUploadOn,
        firstUploadOn: profileSummary.firstUploadOn,
        memberSince: getUserJoinTimestamp(targetUser)
    };
    inp.profileHighlights = {
        topTags: topTagsRows.map(row => row?._id).filter(Boolean),
        topCategories,
        creatorNames: topCreatorRows.map(row => row?._id).filter(Boolean),
        featuredMiis,
        featuredNames: uniqueTextValues(featuredMiis.map(getDisplayMiiName)).slice(0, 6)
    };
    inp.profileSort = selectedProfileSort;
    inp.pagination = buildStartPagination(req, profileStart, totalMiis, FULL_ROW_PROFILE_REQUEST_LIMIT);
    inp.pagination.baseCount = profileMiisPerPage;
    inp.pagination.totalPages = Math.max(1, Math.ceil(Math.max(1, totalMiis) / profileMiisPerPage));
    inp.pagination.currentPage = Math.min(inp.pagination.totalPages, Math.floor(profileStart / profileMiisPerPage) + 1);
    inp.currentPath = buildRequestPathWithStart(req, profileStart);
    inp.pageUpdatedAt = profileSummary.latestUploadOn
        ? new Date(profileSummary.latestUploadOn).toISOString()
        : undefined;
    
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
site.get('/contact', async (req, res) => {
    ejs.renderFile('./ejsFiles/contact.ejs', await getSendables(req), {}, function(err, str) {
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
    const next = getSafeRedirectPath(req.query.next, '/');

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
site.get('/myLikedMiis', requireAuth, async (req, res) => {
    let toSend = await getSendables(req, undefined, req.user);
    const start = getRequestedStartOffset(req.query, defaultMiisPerPage);
    const likedSort = req.query.sort === "likes" ? "likes" : "latest";
    const likedMiiIds = Array.isArray(req.user?.votedFor)
        ? req.user.votedFor.map(id => String(id || "").trim()).filter(Boolean)
        : [];
    const likedMiisQuery = {
        private: false,
        published: true,
        id: {
            $in: likedMiiIds,
            $ne: "average"
        },
        uploader: { $ne: req.user.username },
        contributor: { $ne: req.user.username }
    };
    const sort = likedSort === "likes"
        ? getStablePopularitySort()
        : getStableRecencySort();
    const totalLikedMiis = likedMiiIds.length > 0
        ? await Miis.countDocuments(likedMiisQuery)
        : 0;
    if (totalLikedMiis > 0 && start >= totalLikedMiis) {
        return res.redirect(buildRequestPathWithStart(req, getLastStartOffset(totalLikedMiis, FULL_ROW_BROWSE_REQUEST_LIMIT)));
    }

    toSend.displayedMiis = likedMiiIds.length > 0
        ? await Miis.find(likedMiisQuery)
            .sort(sort)
            .skip(start)
            .limit(FULL_ROW_BROWSE_REQUEST_LIMIT)
            .lean()
        : [];
    toSend.pagination = buildStartPagination(req, start, totalLikedMiis, FULL_ROW_BROWSE_REQUEST_LIMIT);
    toSend.currentPath = buildRequestPathWithStart(req, start);
    toSend.pageUpdatedAt = getNewestUploadedOn(toSend.displayedMiis);

    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
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
                { username: req.user.username },
                { $set: { miiPfp: req.body.id, pfpSet: true } }
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
    const newUsername = normalizeUsernameInput(req.body?.newUser);
    const oldUsername = req.user.username;
    const existingUser = await getUserByUsername(newUsername);
    
    if (isValidUsername(newUsername) && !existingUser) {
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
        const updatedToken = createToken(updatedUser);
        res.cookie('token', updatedToken, {
            maxAge: ms("30 days"),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        res.cookie('username', newUsername, {
            maxAge: ms("30 days"),
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
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
site.post('/reportMii', defaultRatelimiter, async (req,res)=>{
    const miiId = String(req.body?.id ?? "").trim();
    const category = String(req.body?.category ?? "").trim();
    const details = normalizeReportText(req.body?.details, REPORT_MII_DETAILS_MAX_LENGTH);
    const rawEmail = String(req.body?.email ?? "").trim();
    let reporterEmail = "";

    if (!miiId) {
        return res.status(400).json({ error: "Missing Mii ID" });
    }

    if (!REPORT_MII_CATEGORY_SET.has(category)) {
        return res.status(400).json({ error: "Please choose a valid report category." });
    }

    if (!details) {
        return res.status(400).json({ error: "Please include extra details about the issue." });
    }

    if (rawEmail) {
        if (!validator.isEmail(rawEmail)) {
            return res.status(400).json({ error: "Invalid email address" });
        }

        const normalizedEmail = validator.normalizeEmail(rawEmail);
        if (!normalizedEmail || typeof normalizedEmail !== "string") {
            return res.status(400).json({ error: "Invalid email address" });
        }

        reporterEmail = normalizedEmail;
    }

    const mii = await getMiiById(miiId, false);
    if (!mii) {
        return res.status(404).json({ error: "Mii not found" });
    }

    const publicBaseUrl = baseUrl || "https://infinimii.com";
    const reportReference = buildMiiReportReference();
    const reporterName = normalizeReportText(req.user?.username, 80) || "Anonymous";
    const miiName = normalizeReportText(mii?.meta?.name || mii?.name || "Unknown Mii", 128) || "Unknown Mii";
    const uploaderName = normalizeReportText(mii?.uploader, 128) || "Unknown uploader";
    const creatorName = normalizeReportText(mii?.meta?.creatorName, 256) || "Not set";
    const miiDescription = normalizeReportText(mii?.desc, 1000) || "No description provided";
    const miiUrl = `${publicBaseUrl}/mii/${encodeURIComponent(mii.id)}`;
    const uploaderUrl = `${publicBaseUrl}/user/${encodeURIComponent(uploaderName)}`;

    try {
        const webhookSent = await sendWebhookPayload(JSON.stringify({
            embeds: [{
                type: "rich",
                title: (mii.official ? "Official " : "") + "Mii problem reported",
                description: truncateText(details, 4096),
                color: 0xff0000,
                fields: [
                    {
                        name: "Category",
                        value: truncateText(category, 1024),
                        inline: true
                    },
                    {
                        name: "Reported by",
                        value: truncateText(reporterName, 1024),
                        inline: true
                    },
                    {
                        name: "Reporter Email",
                        value: truncateText(reporterEmail || "Not provided", 1024),
                        inline: true
                    },
                    {
                        name: "Mii Name",
                        value: truncateText(miiName, 1024),
                        inline: true
                    },
                    {
                        name: "Uploaded by",
                        value: `[${truncateText(uploaderName, 256)}](${uploaderUrl})`,
                        inline: true
                    },
                    {
                        name: "Mii Creator Name (embedded in Mii file)",
                        value: truncateText(creatorName, 1024),
                        inline: true
                    },
                    {
                        name: "Description",
                        value: truncateText(miiDescription, 1024),
                        inline: false
                    }
                ],
                thumbnail: {
                    url: `${publicBaseUrl}/miiImgs/${encodeURIComponent(mii.id)}.png`,
                    height: 0,
                    width: 0
                },
                footer: {
                    text: `Report ${reportReference}${reporterEmail ? " • Follow-up email requested" : ""}`
                },
                timestamp: new Date().toISOString(),
                url: miiUrl
            }]
        }));

        if (!webhookSent) {
            rawConsoleError("Mii report webhook skipped because hookUrl is not configured.");
            return res.status(503).json({ error: "Reports are temporarily unavailable. Please try again later." });
        }

        let followUpEmailSent = false;
        let warning = "";

        if (reporterEmail) {
            try {
                await sendEmail(
                    reporterEmail,
                    `InfiniMii report received [${reportReference}]`,
                    buildMiiReportFollowUpEmail({
                        reportReference,
                        reporterName,
                        category,
                        details,
                        miiName,
                        miiUrl
                    })
                );
                followUpEmailSent = true;
            } catch (emailError) {
                rawConsoleError("Error sending Mii report follow-up email:", emailError);
                warning = "Your report was sent, but we could not start the follow-up email thread.";
            }
        }

        return res.json({ okay: true, reportReference, followUpEmailSent, warning });
    } catch (error) {
        rawConsoleError("Error processing Mii report:", error);
        return res.status(500).json({ error: "Failed to submit report. Please try again in a moment." });
    }
});
site.post('/contact', defaultRatelimiter, upload.none(), async (req, res) => {
    const rawName = String(req.body?.name ?? "").trim();
    const rawEmail = String(req.body?.email ?? "").trim();
    const subject = normalizeReportText(req.body?.subject, 160);
    const details = normalizeReportText(req.body?.details, 4000);
    const reporterName = normalizeReportText(rawName || req.user?.username, 80) || "Anonymous";
    let reporterEmail = "";

    if (rawEmail) {
        if (!validator.isEmail(rawEmail)) {
            return res.status(400).json({ error: "Please enter a valid email address." });
        }

        const normalizedEmail = validator.normalizeEmail(rawEmail);
        if (!normalizedEmail || typeof normalizedEmail !== "string") {
            return res.status(400).json({ error: "Please enter a valid email address." });
        }

        reporterEmail = normalizedEmail;
    }

    if (!subject) {
        return res.status(400).json({ error: "Please include a subject." });
    }

    if (!details) {
        return res.status(400).json({ error: "Please include details in your message." });
    }

    const contactReference = buildContactReference();
    const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
    const sourceUrl = `${resolvedBaseUrl}/contact`;
    const loggedInUsername = normalizeReportText(req.user?.username, 80);

    try {
        await sendContactWebhookNotification({
            contactReference,
            reporterName,
            reporterEmail,
            subject,
            details,
            loggedInUsername,
            sourceUrl
        });

        await sendEmail(
            process.env.email,
            `InfiniMii contact request [${contactReference}] ${subject}`,
            buildContactSupportEmail({
                contactReference,
                reporterName,
                reporterEmail,
                subject,
                details,
                loggedInUsername,
                sourceUrl
            }),
            reporterEmail ? { replyTo: reporterEmail } : {}
        );

        let followUpEmailSent = false;
        let warning = "";

        if (reporterEmail) {
            try {
                await sendEmail(
                    reporterEmail,
                    `InfiniMii contact received [${contactReference}]`,
                    buildContactFollowUpEmail({
                        contactReference,
                        reporterName,
                        subject,
                        details
                    })
                );
                followUpEmailSent = true;
            } catch (emailError) {
                rawConsoleError("Error sending contact follow-up email:", emailError);
                warning = "Your message was sent, but we could not start the follow-up email thread.";
            }
        }

        return res.json({ okay: true, contactReference, followUpEmailSent, warning });
    } catch (error) {
        rawConsoleError("Error sending contact request:", error);
        return res.status(500).json({ error: "Failed to send your message. Please try again in a moment." });
    }
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
site.get('/guides/formats', async (req, res) => {
    ejs.renderFile('./ejsFiles/formatGuide.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/guides/comparisons', async (req, res) => {
    ejs.renderFile('./ejsFiles/comparisons.ejs', await getSendables(req), {}, function(err, str) {
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
        const currentUsername = req.user.username;

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
        let link = "https://infinimii.com/verifyEmailChange?user=" + encodeURIComponent(currentUsername) + "&token=" + encodeURIComponent(token);
        
        // Store pending email and verification token, but keep current email active
        // This way user can still login with their account even if they enter wrong email
        await Users.findOneAndUpdate(
            { username: currentUsername },
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
                description: `User ${currentUsername} requested to change their email`,
                color: 0x00CCFF,
                fields: [
                    {
                        name: 'User',
                        value: currentUsername,
                        inline: true
                    }
                ]
            }]
        }));

        sendEmail(oldEmail, "InfiniMii Email Change Request", `Hi ${currentUsername}, we received a request to change your email on InfiniMii. If this was not you, please reply to this email to receive support.`);
        sendEmail(newEmail, "InfiniMii Email Verification", `Hi ${currentUsername}, we received a request to change your email on InfiniMii. Please verify your new email by clicking this link: ${link}. This link will expire in 24 hours. If this was not you, please ignore this email.`);


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
        const currentUsername = req.user.username;

        // Verify old password
        if (!validatePassword(oldPassword, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Old password is incorrect' });
        }

        // Hash new password with existing salt
        const newHashed = hashPassword(newPassword, req.user.salt);

        // Increment token version to invalidate old tokens
        const newTokenVersion = (req.user.tokenVersion || 0) + 1;

        await Users.findOneAndUpdate(
            { username: currentUsername },
            { 
                pass: newHashed.hash,
                tokenVersion: newTokenVersion
            }
        );

        // Get updated user and create new JWT
        const updatedUser = await getUserByUsername(currentUsername);
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
                description: `User ${currentUsername} changed their password`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'User',
                        value: currentUsername,
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`Password Changed - InfiniMii`,`Hi ${currentUsername}, your password was recently changed on InfiniMii. If this was not you, you can reply to this email to receive support.`);

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
            color: 0x00FF00,
            fields: [
                {
                    name: 'User',
                    value: username,
                    inline: true
                }
            ]
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
        const newUsername = normalizeUsernameInput(req.body?.newUsername);
        const { password } = req.body;
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
        
        // Verify password
        if (!validatePassword(password, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Incorrect password' });
        }
        
        // Validate new username
        if (!isValidUsername(newUsername)) {
            return res.json({ error: 'Invalid username format. Username must be 3-20 characters using letters, numbers, underscores, hyphens, or periods.' });
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
        const publicUserMiis = await Miis.find({
            uploader: oldUsername,
            private: false,
            published: true
        }).select('id official private published').lean();
        
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
            maxAge: ms("30 days"),
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
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

        if (publicUserMiis.length > 0) {
            const updatedMiis = publicUserMiis.map((mii) => ({ ...mii, uploader: newUsername }));
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedMiis, {
                    extraUrls: [
                        getUserProfileUrl(resolvedBaseUrl, oldUsername),
                        getUserProfileUrl(resolvedBaseUrl, newUsername)
                    ]
                }),
                resolvedBaseUrl,
                "change-self-username"
            );
        } else {
            notifyIndexNow(
                [
                    getUserProfileUrl(resolvedBaseUrl, oldUsername),
                    getUserProfileUrl(resolvedBaseUrl, newUsername)
                ],
                resolvedBaseUrl,
                "change-self-username"
            );
        }
        
        res.json({ message: 'Username changed successfully!', redirect: '/settings' });
    } catch (e) {
        console.error('Error changing username:', e);
        res.json({ error: 'Server error' });
    }
});


// Delete All User's Miis (User - own miis only)
site.post('/deleteAllMyMiis', requireAuth, async (req, res) => {
    try {
        const currentUsername = req.user.username;
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
        const miis = await Miis.find({ uploader: req.user.username, private: false, published: true }).lean();
        const cleanupResult = await deleteStoredMiisAndCleanup(miis);
        const deletedCount = cleanupResult.deletedCount;

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `User Deleted All Their Miis`,
                description: `${currentUsername} deleted all their own Miis`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'User',
                        value: currentUsername,
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
        sendEmail(req.user.email,`All Miis Deleted - InfiniMii`,`Hi ${currentUsername}, we received a request to delete all of your Miis. If this wasn't you, reply to this email to receive support.`);
        res.json({ deletedCount });

        if (miis.length > 0) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, miis, {
                    extraUrls: [getUserProfileUrl(resolvedBaseUrl, currentUsername)]
                }),
                resolvedBaseUrl,
                "delete-all-my-miis"
            );
        }
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
            const settings = await getSettings();
            await Users.create({
                username: "[Deleted User]",
                salt: "",
                pass: "",
                creationDate: Date.now(),
                email: "",
                votedFor: [],
                miiPfp: getDefaultUserPfpMiiId(settings),
                pfpSet: false,
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
        sendEmail(req.user.email,`Account Deleted - InfiniMii`,`Hi ${username}, we received a request to delete your account. We're sorry to see you go! If this wasn't you, please reply to this email to receive support.`)
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
        if (allowFile && req.file?.path) {
            const dumpedUpload = await dumpFailingUploadFile(req.file, e, "getInstructions");
            if (dumpedUpload) {
                await sendSavedFailingUploadToWebhook({
                    req,
                    error: e,
                    context: "getInstructions",
                    dumpedUpload
                });
            }
        }
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
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
        const isOfficialUpload = parseBooleanLike(req.body.official);
        let wantsPublic = req.body.makePublic === 'on' || req.body.makePublic === true || req.body.makePublic === 'true';
        let officialSource = null;
        let officialSourceNotice = null;
        let officialSettings = null;
        const rawMiiDataInput = typeof req.body.miiData === "string" ? req.body.miiData : "";
        const normalizedRawMiiData = rawMiiDataInput.replace(/\s+/g, "");
        const providedMiiName = typeof req.body.miiName === "string" ? req.body.miiName.trim() : "";
        const isNinetyTwoCharCode = normalizedRawMiiData.length === 92;
        const hasZipUpload = isZipUpload(req.file);

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

        if (hasZipUpload && normalizedRawMiiData) {
            res.json({ error: "Use either a ZIP file upload or raw Mii data, not both in the same submission." });
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
            return;
        }

        if (hasZipUpload && !isOfficialUpload) {
            res.json({ error: "ZIP uploads are only allowed in the Official Mii upload form." });
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
            return;
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
        let tempBinPath = "";
        let cleanupUploadedRequestFile = true;
        try {
            const fromAmiiboId = typeof req.body.fromAmiibo === "string" ? req.body.fromAmiibo.trim() : "";

            if (hasZipUpload) {
                if (fromAmiiboId) {
                    res.json({ error: "ZIP uploads are not supported for extracted Amiibo uploads." });
                    return;
                }

                cleanupUploadedRequestFile = false;
                startOfficialZipUploadProcessing({
                    zipFilePath: req.file.path,
                    description: req.body.desc,
                    rawCategories: req.body.categories,
                    uploader,
                    officialSource,
                    officialSourceNotice,
                    officialSettings,
                    resolvedBaseUrl
                });
                res.json({ redirect: "/official" });
                return;
            }

            if (fromAmiiboId && !req.file && !req.body.miiData) {
                // Uploading from Amiibo extraction
                const tempMiiId = fromAmiiboId;
                tempBinPath = `./static/temp/${tempMiiId}.bin`;

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
                    if (isInvalidMiiTypeError(e)) {
                        await sendInvalidMiiInputToWebhook({
                            req,
                            error: e,
                            context: "uploadMii-amiibo",
                            filePath: tempBinPath
                        });
                        res.json(await buildInvalidMiiTypeErrorPayload({
                            filePath: tempBinPath
                        }));
                        return;
                    }
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
            const dumpedUpload = req.file?.path
                ? await dumpFailingUploadFile(req.file, e, "uploadMii")
                : null;
            if (dumpedUpload) {
                await sendSavedFailingUploadToWebhook({
                    req,
                    error: e,
                    context: "uploadMii",
                    dumpedUpload
                });
            }
            console.error('Error processing Mii file:', e);
            if (isInvalidMiiTypeError(e)) {
                if (!dumpedUpload) {
                    await sendInvalidMiiInputToWebhook({
                        req,
                        error: e,
                        context: "uploadMii",
                        reqFile: req.file,
                        rawInput: typeof req.body?.miiData === "string" ? req.body.miiData : "",
                        filePath: req.file?.path || tempBinPath
                    });
                }
                res.json({
                    error: "Failed to process file. Please double-check that you selected the correct file. Could not find any decodeable formats. If this is a QR code, make sure it is clear and not blurry."
                });
                return;
            }
            res.json({error: `Failed to process file. Please double-check that you selected the correct file. ${e.message || ''}`});
            return;
        } finally {
            try { if (cleanupUploadedRequestFile && req.file?.path) fs.unlinkSync(req.file.path); } catch (e) { }
        }

        if (isNinetyTwoCharCode && providedMiiName) {
            if (!mii.meta || typeof mii.meta !== "object") {
                mii.meta = {};
            }
            mii.meta.name = providedMiiName;
        }

        const matchingMii = await findMatchingMii(mii, { includeGeneral: isOfficialUpload });
        if (matchingMii) {
            res.json(getDuplicateMiiErrorPayload(matchingMii.id));
            return;
        }

        const validLeafPaths = isOfficialUpload
            ? getLeafCategoryPathSet(
                getOfficialCategoryTree(officialSettings || await getSettings())
            )
            : null;
        const officialCategories = isOfficialUpload
            ? normalizeCategoryPaths(req.body.categories)
                .filter(categoryPath => validLeafPaths.has(categoryPath))
            : [];
        const persistedUpload = await persistUploadedMii(mii, {
            uploader,
            wantsPublic,
            isOfficialUpload,
            officialSource,
            desc: req.body.desc,
            officialCategories
        });
        mii = persistedUpload.mii;
        
        // Send to Discord for moderator review
        var d = new Date();
        const uploadReportEmbed = {
            "type": "rich",
            "title": (isOfficialUpload ? "Official " : "") + `${wantsPublic ? "Public" : "Private"} Mii Uploaded`,
            "description": mii.desc,
            "color": 0x00aaff,
            "fields": (isOfficialUpload
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
                ]).concat(buildTomodachiLifeUploadWebhookFields(mii)),
            "footer": {
                "text": `View: https://infinimii.com/mii/${mii.id} | Uploaded at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
            }
        };
        if (wantsPublic) {
            uploadReportEmbed.image = {
                "url": `https://infinimii.com/miiImgs/${encodeURIComponent(mii.id)}.png`
            };
        }
        queueUploadWebhookReport(uploadReportEmbed, {
            imagePath: persistedUpload.assetPaths?.img || getMiiAssetPath(wantsPublic ? "miiImgs" : "privateMiiImgs", mii.id),
            imageFilename: `${mii.id}.png`
        });
        
        const responsePayload = {
            redirect: !isOfficialUpload && wantsPublic
                ? `/mii/${mii.id}`
                : (isOfficialUpload ? "/official" : "/myPrivateMiis")
        };
        if (officialSourceNotice) {
            responsePayload.notice = officialSourceNotice;
        }
        res.json(responsePayload);

        if (wantsPublic) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, { ...mii, private: false, published: true }),
                resolvedBaseUrl,
                "upload-mii"
            );
        }
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

// Rename a global Mii tag and update every Mii that uses it (Moderator+)
site.post('/renameMiiTag', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
        const requestedOldTag = normalizeTagValue(req.body?.oldTag);
        const nextTag = normalizeTagValue(req.body?.newTag);

        if (!requestedOldTag) {
            return res.json({ error: 'Existing tag name required' });
        }
        if (!nextTag) {
            return res.json({ error: 'New tag name required' });
        }
        if (nextTag.includes(',')) {
            return res.json({ error: 'Tag names cannot include commas' });
        }
        if (nextTag.length > MAX_MII_TAG_LENGTH) {
            return res.json({ error: `Tag names must be ${MAX_MII_TAG_LENGTH} characters or fewer` });
        }

        const settings = await getSettings();
        const tags = getMiiTags(settings);
        const sourceTag = tags.find((tag) => tag.toLowerCase() === requestedOldTag.toLowerCase());

        if (!sourceTag) {
            return res.json({ error: 'Tag not found' });
        }
        if (sourceTag === nextTag) {
            return res.json({ error: 'No changes submitted' });
        }

        const tagKeysToRewrite = new Set([sourceTag.toLowerCase(), nextTag.toLowerCase()]);
        const nextTags = tags
            .filter((tag) => !tagKeysToRewrite.has(tag.toLowerCase()))
            .concat(nextTag)
            .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

        await updateSettings({ miiTags: nextTags });

        const matchingTagRegexes = [...new Set([sourceTag, nextTag].map((tag) => buildExactCaseInsensitiveRegex(tag)))];
        const affectedMiis = await Miis.find({
            tags: { $in: matchingTagRegexes }
        })
            .select('id tags private published official uploader')
            .lean();

        const updatedPublicMiis = [];
        const tagOps = affectedMiis
            .map((mii) => {
                const nextAssignedTags = normalizeTagList(
                    (Array.isArray(mii.tags) ? mii.tags : []).map((tag) => (
                        tagKeysToRewrite.has(String(tag || '').toLowerCase()) ? nextTag : tag
                    ))
                );

                if (JSON.stringify(nextAssignedTags) === JSON.stringify(Array.isArray(mii.tags) ? mii.tags : [])) {
                    return null;
                }

                if (!mii.private && mii.published !== false) {
                    updatedPublicMiis.push({ ...mii, tags: nextAssignedTags });
                }

                return {
                    updateOne: {
                        filter: { id: mii.id },
                        update: { $set: { tags: nextAssignedTags } }
                    }
                };
            })
            .filter(Boolean);

        if (tagOps.length > 0) {
            await Miis.bulkWrite(tagOps);
        }

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: 'Mii Tag Renamed',
                description: `${req.cookies.username} edited a Mii tag`,
                color: 0x00AAFF,
                fields: [
                    {
                        name: 'Old Tag',
                        value: sourceTag,
                        inline: true
                    },
                    {
                        name: 'New Tag',
                        value: nextTag,
                        inline: true
                    },
                    {
                        name: 'Miis Updated',
                        value: String(tagOps.length),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ okay: true, tags: nextTags, updatedMiis: tagOps.length });

        if (updatedPublicMiis.length > 0) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedPublicMiis),
                resolvedBaseUrl,
                'rename-mii-tag'
            );
        }
    } catch (e) {
        console.error('Error renaming Mii tag:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete a global Mii tag and remove it from all Miis (Moderator+)
site.post('/deleteMiiTag', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
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

        const matchingMiis = await Miis.find({
            tags: buildExactCaseInsensitiveRegex(tagToDelete)
        })
            .select('id tags private published official uploader')
            .lean();

        const updatedPublicMiis = [];
        const tagOps = matchingMiis
            .map((mii) => {
                const nextAssignedTags = normalizeTagList(
                    (Array.isArray(mii.tags) ? mii.tags : []).filter(
                        (tag) => String(tag || '').toLowerCase() !== requestedTag.toLowerCase()
                    )
                );

                if (JSON.stringify(nextAssignedTags) === JSON.stringify(Array.isArray(mii.tags) ? mii.tags : [])) {
                    return null;
                }

                if (!mii.private && mii.published !== false) {
                    updatedPublicMiis.push({ ...mii, tags: nextAssignedTags });
                }

                return {
                    updateOne: {
                        filter: { id: mii.id },
                        update: { $set: { tags: nextAssignedTags } }
                    }
                };
            })
            .filter(Boolean);

        if (tagOps.length > 0) {
            await Miis.bulkWrite(tagOps);
        }

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
                        value: String(tagOps.length),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ okay: true, tags: nextTags, updatedMiis: tagOps.length });

        if (updatedPublicMiis.length > 0) {
            notifyIndexNow(
                buildIndexNowUrlsForMiis(resolvedBaseUrl, updatedPublicMiis),
                resolvedBaseUrl,
                'delete-mii-tag'
            );
        }
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
        const resolvedBaseUrl = getResolvedBaseUrlFromRequest(req);
        const miiId = String(req.body?.miiId || "").trim();
        const publishedOn = Date.now();
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

        // Update Mii status to published and public
        await Miis.findOneAndUpdate(
            { id: miiId },
            { $set: { private: false, published: true, uploadedOn: publishedOn } }
        );
        mii.private = false;
        mii.published = true;
        mii.uploadedOn = publishedOn;

        const {
            qrPath: publicQrPath,
            qrWiiPath: publicQrWiiPath
        } = getMiiAssetPaths(mii.id, false);

        await moveMiiAssets(mii.id, true, false);

        if (!fs.existsSync(publicQrPath)) {
            await writeQrPng(mii, publicQrPath, "3DS");
        }
        if (!fs.existsSync(publicQrWiiPath)) {
            await writeQrPng(mii, publicQrWiiPath, "WIIU");
        }

        // Clean up any remaining private files after successful publish
        deleteMiiAssets(miiId, true);

        // Notify Discord
        const d = new Date();
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
                "image": {
                    "url": `https://infinimii.com/miiImgs/${encodeURIComponent(miiId)}.png`
                },
                "footer": {
                    "text": `View: https://infinimii.com/mii/${miiId} | Published at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }));

        res.json({ okay: true });

        notifyIndexNow(
            buildIndexNowUrlsForMiis(resolvedBaseUrl, { ...mii, private: false, published: true }),
            resolvedBaseUrl,
            "publish-mii"
        );
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
        const dumpedUpload = req.file?.path
            ? await dumpFailingUploadFile(req.file, e, "convertMii")
            : null;
        if (dumpedUpload) {
            await sendSavedFailingUploadToWebhook({
                req,
                error: e,
                context: "convertMii",
                dumpedUpload
            });
        }
        if (isInvalidMiiTypeError(e)) {
            if (!dumpedUpload) {
                await sendInvalidMiiInputToWebhook({
                    req,
                    error: e,
                    context: "convertMii",
                    reqFile: req.file,
                    rawInput: typeof req.body?.miiData === "string" ? req.body.miiData : "",
                    filePath: req.file?.path
                });
            }
            const invalidMiiTypeError = await buildInvalidMiiTypeErrorPayload({
                reqFile: req.file,
                rawInput: typeof req.body?.miiData === "string" ? req.body.miiData : "",
                filePath: dumpedUpload?.destinationPath || req.file?.path
            });
            try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (e2) { }
            res.json(invalidMiiTypeError);
            return;
        }
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
    // Field validation
    if (!validator.isEmail(req.body.email)) {
        res.json({ error: "Invalid email address" });
        return;
    }
    const cleanEmail = validator.normalizeEmail(req.body.email);

    const normalizedUsername = normalizeUsernameInput(req.body?.username);

    if (!isValidUsername(normalizedUsername)) {
        return res.json({ error: 'Username invalid. Use 3-20 characters: letters, numbers, underscores, hyphens, or periods only.' });
    }

    // Validate username
    const existingUsername = await getUserByUsername(normalizedUsername);
    if (existingUsername) {
        res.json({ error: "Username already taken" });
        return;
    }
    
    // Check if username is reserved
    const reserved = await ReservedUsername.findOne({ username: normalizedUsername });
    if (reserved) {
        res.json({ error: "This username is temporarily unavailable. Please try again later or choose a different username." });
        return;
    }
    
    if (isBad(normalizedUsername) || existingUsername) {
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
        username: normalizedUsername,
        salt: hashedPassword.salt,
        pass: hashedPassword.hash,
        verificationToken: hashPassword(token, hashedPassword.salt).hash,
        creationDate: Date.now(),
        email: cleanEmail,
        miiPfp: getDefaultUserPfpMiiId(settings),
        pfpSet: false,
        roles: [ ROLES.BASIC ],
    });
    
    let link = "https://infinimii.com/verify?user=" + encodeURIComponent(normalizedUsername) + "&token=" + encodeURIComponent(token);
    await sendEmail(cleanEmail, "InfiniMii Verification", 
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
                maxAge: ms("30 days"),
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax'
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
    if (process.env.NODE_ENV === 'development') {
        throw new Error('Intentional test error route');
    }
    return sendError(res, req, "This diagnostic route is disabled outside development.", 404);
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

process.on('unhandledRejection', (reason) => console.error('Unhandled promise rejection:', reason));

process.on('uncaughtException', (error) => console.error('Uncaught exception:', error));


// TODO: reset password functionality which should increase token version

// TODO: vulnerability where if username and email are changed, and someone else signs up with the old email and old username, the first user can access their account
// To fix this, simply create a reserveUsername field in mongo, that lasts as long as the JWTs do to make sure they are defintiely expired. 
// If trying to move to or create a user with the name of a reserved username, return the standard json error to be shown on the page like usual.
// Also at the same time, prevent users from changing their name more than once a month. Make sure this is known on the settings page.

// Remove most try-catches to let 500 handler take it

///// Utils:
// - Look for opening <% without closing one
// <%(?![\s\S]*%>)
