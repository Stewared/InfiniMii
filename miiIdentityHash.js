import crypto from "crypto";
import miijs from "miijs";

const MII_IDENTITY_HASH_FIELDS = [
    "hair",
    "face",
    "eyes",
    "eyebrows",
    "nose",
    "mouth",
    "beard",
    "glasses",
    "mole"
];

const MII_IDENTITY_HASH_VERSION = "mii-face-v4";
const MII_OFFICIAL_IDENTITY_HASH_VERSION = "mii-face-general-v2";
const LTD_IDENTITY_HASH_VERSION = "mii-ltd-face-v1";
const LTD_OFFICIAL_IDENTITY_HASH_VERSION = "mii-ltd-face-general-v1";
const MII_IDENTITY_HASH_PREFIX = `${MII_IDENTITY_HASH_VERSION}:`;
const CURRENT_MII_IDENTITY_HASH_PATTERN = `(?:${MII_IDENTITY_HASH_VERSION}|${MII_OFFICIAL_IDENTITY_HASH_VERSION}|${LTD_IDENTITY_HASH_VERSION}|${LTD_OFFICIAL_IDENTITY_HASH_VERSION}):`;

const MOUTH_TYPES_WITH_HASHED_COLOR = new Set([
    1,
    5,
    0,
    13,
    7,
    4,
    11,
    27,
    24,
    29
]);

const EYE_TYPES_WITH_IGNORED_COLOR = new Set([
    0x1a,
    0x17,
    0x22,
    0x15,
    0x0d,
    0x0e,
    0x2f
]);

function getFeatureType(feature) {
    const type = Number(feature?.type);
    return Number.isFinite(type) ? type : null;
}

function areEyebrowsOffForMiiIdentityHash(eyebrows) {
    if (!eyebrows || typeof eyebrows !== "object") return false;
    if (eyebrows.on === false) return true;
    return eyebrows.type === 23;
}

function areGlassesOffForMiiIdentityHash(glasses) {
    if (!glasses || typeof glasses !== "object") return false;
    return glasses.type === 0;
}

function isMoleOffForMiiIdentityHash(mole) {
    if (!mole || typeof mole !== "object") return false;
    return mole.on === false;
}

function isHairIgnoredForMiiIdentityHash(hair) {
    if (!hair || typeof hair !== "object") return false;
    return hair.type === 30;
}

function normalizeFeatureForMiiIdentityHash(field, value) {
    const normalized = normalizeValueForMiiIdentityHash(value);
    if (normalized === null || typeof normalized !== "object") return normalized;

    if (field === "eyebrows" && areEyebrowsOffForMiiIdentityHash(normalized)) {
        return null;
    }

    if (field === "glasses" && areGlassesOffForMiiIdentityHash(normalized)) {
        return null;
    }

    if (field === "mole" && isMoleOffForMiiIdentityHash(normalized)) {
        return null;
    }

    if (field === "hair" && isHairIgnoredForMiiIdentityHash(normalized)) {
        return null;
    }

    if (field === "mouth" && !MOUTH_TYPES_WITH_HASHED_COLOR.has(getFeatureType(normalized))) {
        delete normalized.color;
    }

    if (field === "eyes" && EYE_TYPES_WITH_IGNORED_COLOR.has(getFeatureType(normalized))) {
        delete normalized.color;
    }

    return normalized;
}

function hasCurrentMiiIdentityHashVersion(value) {
    return typeof value === "string" && new RegExp(`^${CURRENT_MII_IDENTITY_HASH_PATTERN}`).test(value);
}

function getComparableMiiSource(mii) {
    if (!mii || typeof mii !== "object") return mii;
    if (mii.fields && typeof mii.fields === "object") return mii.fields;
    return mii;
}

function getPlainComparableMiiSource(mii) {
    const source = getComparableMiiSource(mii);
    if (!source || typeof source !== "object") return source;

    return typeof source.toObject === "function"
        ? source.toObject({ depopulate: true, virtuals: false, getters: false, minimize: false })
        : source;
}

function normalizeMiiForIdentityHash(mii) {
    const plain = getPlainComparableMiiSource(mii);
    if (!plain || typeof plain !== "object") return plain;

    try {
        const mnmsBuffer = miijs.encodeMii(plain, miijs.MiiFormats.MNMS);
        return miijs.decodeMii(mnmsBuffer);
    } catch (error) {
        console.warn("[miiHash] Failed to normalize Mii through MNMS before hashing; falling back to stored fields:", error.message);
        return plain;
    }
}

function normalizeValueForMiiIdentityHash(value) {
    if (value === undefined) return null;
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map(normalizeValueForMiiIdentityHash);

    const out = {};
    for (const key of Object.keys(value).sort()) {
        const normalized = normalizeValueForMiiIdentityHash(value[key]);
        if (normalized !== undefined) {
            out[key] = normalized;
        }
    }
    return out;
}

function getMiiIdentityHashVersion({ includeGeneral = false } = {}) {
    return includeGeneral ? MII_OFFICIAL_IDENTITY_HASH_VERSION : MII_IDENTITY_HASH_VERSION;
}

function getLtdIdentityHash(mii, { includeGeneral = false } = {}) {
    const source = getPlainComparableMiiSource(mii);
    const appearanceHash = String(source?.ltdAppearanceHash || "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(appearanceHash)) return "";
    const version = includeGeneral ? LTD_OFFICIAL_IDENTITY_HASH_VERSION : LTD_IDENTITY_HASH_VERSION;
    const payload = includeGeneral
        ? `${appearanceHash}:${JSON.stringify(normalizeValueForMiiIdentityHash(source.general))}`
        : appearanceHash;
    const digest = crypto.createHash("sha256").update(`${version}:${payload}`).digest("hex");
    return `${version}:${digest}`;
}

function getMiiIdentityHashPayload(mii, { includeGeneral = false } = {}) {
    const source = normalizeMiiForIdentityHash(mii);
    if (!source || typeof source !== "object") return source;

    const payload = Object.fromEntries(
        MII_IDENTITY_HASH_FIELDS.map((field) => [
            field,
            normalizeFeatureForMiiIdentityHash(field, source[field])
        ])
    );

    if (includeGeneral) {
        payload.general = normalizeValueForMiiIdentityHash(source.general);
    }

    return payload;
}

function getClassicMiiIdentityHash(mii, options = {}) {
    const payload = getMiiIdentityHashPayload(mii, options);
    if (!payload || typeof payload !== "object") return "";
    const hashVersion = getMiiIdentityHashVersion(options);

    const digest = crypto
        .createHash("sha256")
        .update(`${hashVersion}:${JSON.stringify(payload)}`)
        .digest("hex");

    return `${hashVersion}:${digest}`;
}

function getMiiIdentityHashCandidates(mii, options = {}) {
    const hashes = [];
    const ltdHash = getLtdIdentityHash(mii, options);
    if (ltdHash) hashes.push(ltdHash);
    const classicHash = getClassicMiiIdentityHash(mii, options);
    if (classicHash && !hashes.includes(classicHash)) hashes.push(classicHash);
    return hashes;
}

// Mongo stores the ordinary (appearance-only) identity hash for every record,
// including official Miis. Callers may still compare includeGeneral candidates
// after loading those records, but the database prefilter must use the stored
// appearance namespace or it cannot retrieve them.
function getMiiIdentityLookupHashCandidates(mii) {
    return getMiiIdentityHashCandidates(mii, { includeGeneral: false });
}

function getMiiIdentityHash(mii, options = {}) {
    return getMiiIdentityHashCandidates(mii, options)[0] || "";
}

function setMiiIdentityHash(mii) {
    if (!mii || typeof mii !== "object") return mii;
    mii.miiHash = getMiiIdentityHash(mii);
    return mii;
}

function areMiisTheSame(miiA, miiB) {
    const hashA = getMiiIdentityHash(miiA);
    const hashB = getMiiIdentityHash(miiB);
    return Boolean(hashA && hashB && hashA === hashB);
}

export {
    MII_IDENTITY_HASH_PREFIX,
    CURRENT_MII_IDENTITY_HASH_PATTERN,
    areMiisTheSame,
    getMiiIdentityHash,
    getMiiIdentityHashCandidates,
    getMiiIdentityLookupHashCandidates,
    getMiiIdentityHashPayload,
    getMiiIdentityHashVersion,
    hasCurrentMiiIdentityHashVersion,
    setMiiIdentityHash
};
