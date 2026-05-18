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
const MII_IDENTITY_HASH_PREFIX = `${MII_IDENTITY_HASH_VERSION}:`;

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
    return typeof value === "string" && value.startsWith(MII_IDENTITY_HASH_PREFIX);
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

function getMiiIdentityHash(mii, options = {}) {
    const payload = getMiiIdentityHashPayload(mii, options);
    if (!payload || typeof payload !== "object") return "";
    const hashVersion = getMiiIdentityHashVersion(options);

    const digest = crypto
        .createHash("sha256")
        .update(`${hashVersion}:${JSON.stringify(payload)}`)
        .digest("hex");

    return `${hashVersion}:${digest}`;
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
    areMiisTheSame,
    getMiiIdentityHash,
    getMiiIdentityHashPayload,
    getMiiIdentityHashVersion,
    hasCurrentMiiIdentityHashVersion,
    setMiiIdentityHash
};
