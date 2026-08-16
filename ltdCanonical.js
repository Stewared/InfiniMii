import crypto from "node:crypto";
import fs from "node:fs";

import miijs from "miijs";

import { classifyLtdFacepaintUsage } from "./miiContentFilters.js";
import { toMiiDataOnly } from "./miiDataUtils.js";

export const LTD_MAX_BYTES = 1024 * 1024;
// ShareMii application v3.0 predates .ltd file-format v3 and reads the Mii
// block from byte 5. Emit the older v2 envelope so both that release and newer
// ShareMii releases copy the correct 156-byte block into the save.
export const LTD_PROFILE_POLICY_ID = "sharemii-import-safe-v2/4";
export const LTD_CREATE_ID_POLICY_ID = "infinimii-charinfo-record-id-sha256-v1";
export const LTD_HISTORICAL_SCHEMA_POLICY_ID = "infinimii-explicit-historical-schema-v1";
export const LTD_CODEC_ID =
    "miijs-workspace-3.1.0+sha256:ccc6a4f1b1fa3ab02db27934ba42bfb1d65801e45cd03295a12f36b0a95629b1";

const CREATE_ID_DOMAIN = Buffer.from(
    "LtDRender/InfiniMii/CharInfo-to-LTD/CreateId/v1\0",
    "utf8"
);
const trustedMiiInputs = new WeakSet();

// InfiniMii historically stored a small, explicitly audited subset of Wii
// records with their palette selectors still in Wii wire-table space. This is
// an ID-keyed source declaration, not a range or console heuristic. QWvah is
// frozen by LtDRender's source bundle as raw-wii-palettes with source-record
// SHA-256 6078e6c7d1fd63ce7d43deba1053c757e725ac7c09a03d9a6613e47754ecfb67.
const RAW_WII_PALETTES = Object.freeze({
    "hair.color": Object.freeze([8, 1, 2, 3, 4, 5, 6, 7]),
    "eyebrows.color": Object.freeze([8, 1, 2, 3, 4, 5, 6, 7]),
    "beard.color": Object.freeze([8, 1, 2, 3, 4, 5, 6, 7]),
    "eyes.color": Object.freeze([8, 9, 10, 11, 12, 13]),
    "mouth.color": Object.freeze([19, 20, 21, 22, 23]),
    "glasses.color": Object.freeze([8, 14, 15, 16, 17, 18, 0])
});
const HISTORICAL_SOURCE_PROJECTION_KEYS = Object.freeze([
    "id",
    "console",
    "official",
    "private",
    "published",
    "officialSource",
    "general",
    "meta",
    "perms",
    "hair",
    "face",
    "eyes",
    "eyebrows",
    "nose",
    "mouth",
    "beard",
    "glasses",
    "mole"
]);
const EXPLICIT_HISTORICAL_SCHEMAS = new Map([
    ["QWvah", Object.freeze({
        historicalSchema: "raw-wii-palettes",
        sourceRecordSha256: "6078e6c7d1fd63ce7d43deba1053c757e725ac7c09a03d9a6613e47754ecfb67"
    })]
]);

// ShareMii copies these 18 values directly into the game's typed save arrays.
// Four of them are hash-backed enums, so zero is not a neutral value: it is an
// unknown enum that can crash the game after import. These defaults are the
// source-backed scalar values used when the LTD save editor creates a new
// ordinary Mii (pinned source, addMii.ts lines 174-244):
// https://github.com/alexislours/ltd-save-editor/blob/d2afc2cf8774374e8f5365d15130a1e4fa5cc1d5/src/lib/mii/ownership/addMii.ts#L174-L244
// The ShareMii importer writes the same 18 slots without normalization
// (applyMii.ts lines 381-403):
// https://github.com/alexislours/ltd-save-editor/blob/d2afc2cf8774374e8f5365d15130a1e4fa5cc1d5/packages/ltd-sharemii/src/applyMii.ts#L381-L403
// DirectAge's -1 sentinel is independently present in the checked native v2
// Kestron/Emma fixtures and v3 Johnny Thunder fixture; the v3 evidence is
// hash-bound as aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d
// in LtDRender/renderer/share_mii_v3_source.json.
const SHAREMII_IMPORT_SAFE_SCALARS = Object.freeze({
    sociability: 4,
    audaciousness: 4,
    activeness: 4,
    commonsense: 4,
    gaiety: 4,
    voiceFormant: 28,
    voiceSpeed: 25,
    voiceIntonation: 0,
    voicePitch: 28,
    voiceTension: 5,
    birthdayYear: 2008,
    birthdayDay: 1,
    birthdayDirectAge: -1,
    birthdayMonth: 1
});

const SHAREMII_IMPORT_SAFE_LOVE_GENDER = Object.freeze([0, 1, 0]);
// Voice.PresetType is a different enum domain from gender. The title editor's
// source-backed new-Mii path writes murmur3_x86_32("Boy") (0x232634c7) for
// every default it creates. The checked native v3 Johnny Thunder fixture uses
// the also-valid Custom preset (0x62db55f7). For the other three enum domains, the checked native
// v2 Kestron fixture
// (c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b)
// carries Male/He/Male. The checked native v2 Emma fixture
// (d3098f9156c7ec7a7fa99c38954f1c460b3e7031313fc4e6e5ab6031c4e18776)
// carries Female/She/Female. Keep gameplay identity consistent with the
// source CharInfo gender instead of applying the editor's male-only new-Mii
// default to female downloads.
const SHAREMII_IMPORT_SAFE_ENUMS = Object.freeze({
    male: Object.freeze({
        voicePresetTypeHash: 0x232634c7, // murmur3_x86_32("Boy")
        faceGenderHash: 0x0ddcbe76, // murmur3_x86_32("Male")
        pronounTypeHash: 0x3be5d8d4, // murmur3_x86_32("He")
        clothStyleHash: 0x0ddcbe76 // murmur3_x86_32("Male")
    }),
    female: Object.freeze({
        voicePresetTypeHash: 0x232634c7, // title new-Mii default: "Boy"
        faceGenderHash: 0x3b1f8b15, // murmur3_x86_32("Female")
        pronounTypeHash: 0x25af6ee5, // murmur3_x86_32("She")
        clothStyleHash: 0x3b1f8b15 // murmur3_x86_32("Female")
    })
});

// These are the complete enum domains published by the pinned LTD save-data
// schema. ShareMii writes the four hash-backed values straight into EnumArray
// fields, so a structurally valid container can still corrupt a save when one
// of these values is zero or otherwise outside its domain.
const SHAREMII_NATIVE_ENUM_DOMAINS = Object.freeze({
    voicePresetTypeHash: new Set([
        0xa122d1d6, // Pet
        0x52dfc8a2, // System
        0x62db55f7, // Custom
        0x232634c7, // Boy
        0xc0de537a, // Girl
        0x0ddcbe76, // Male
        0x3b1f8b15, // Female
        0x796a7e74, // OldMan
        0xef3c3813, // OldWoman
        0x4a840a24, // BigCharacter
        0xf3e65968, // SmallCharacter
        0x7dac65b1, // RobotL
        0x689e0dd8 // RobotS
    ]),
    faceGenderHash: new Set([
        0x0ddcbe76, // Male
        0x3b1f8b15, // Female
        0x1053df72 // Third
    ]),
    pronounTypeHash: new Set([
        0x30b2e387, // Unset
        0x3be5d8d4, // He
        0x25af6ee5, // She
        0x5677305f // They
    ]),
    clothStyleHash: new Set([
        0x0ddcbe76, // Male
        0x3b1f8b15, // Female
        0xa9021713 // Both
    ])
});

export function getShareMiiImportSafePersonality(gender) {
    // CharInfo uses 0 for male and 1 for female. Invalid/missing legacy input
    // uses InfiniMii's deterministic male fallback instead of inventing a hash.
    const enumValues = gender === 1
        ? SHAREMII_IMPORT_SAFE_ENUMS.female
        : SHAREMII_IMPORT_SAFE_ENUMS.male;
    return Object.freeze({ ...SHAREMII_IMPORT_SAFE_SCALARS, ...enumValues });
}

/**
 * Validate the narrow native ShareMii fields that are known to be copied into
 * typed game-save arrays. This deliberately does not require InfiniMii's
 * generated defaults: legitimate native personality and voice values remain
 * byte-authoritative, while invalid enum hashes are rejected, never rewritten.
 */
export function assertNativeLtdShareMiiImportSafety(value) {
    let parsed;
    try {
        parsed = value?.personalityAndVoice && value?.charInfo
            ? value
            : miijs.parseLtdContainer(value);
    } catch (error) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            `This LTD cannot be imported safely by ShareMii: ${error.message}`,
            { cause: error }
        );
    }

    const personality = parsed?.personalityAndVoice;
    for (const [field, domain] of Object.entries(SHAREMII_NATIVE_ENUM_DOMAINS)) {
        const value = Number(personality?.[field]);
        // The file stores these values as signed i32, while the save schema
        // treats EnumArray elements as unsigned name hashes.
        const unsigned = value >>> 0;
        if (!Number.isInteger(value) || !domain.has(unsigned)) {
            throw new LtdCanonicalError(
                "LTD_SHAREMII_IMPORT_UNSAFE",
                `This LTD cannot be imported safely by ShareMii: personalityAndVoice.${field} has an unknown enum hash (0x${unsigned.toString(16).padStart(8, "0")}).`
            );
        }
    }
    return parsed;
}

/**
 * Build a download-only v2 envelope for a native v3 LTD. ShareMii application
 * v3.0 predates the v3 wire layout and otherwise copies the Mii block one byte
 * late. The stored native bytes remain authoritative and untouched; this
 * derivative preserves the raw Mii, personality/name/pronunciation, the three
 * interpreted love-gender flags, and both compressed facepaint payloads.
 * Newer ShareMii releases normalize this v2 envelope back to the original v3
 * semantics.
 */
export function buildShareMiiV3CompatibleLtdDownload(value) {
    const bytes = normalizeBuffer(value);
    if (!bytes) throw new TypeError("Expected LTD bytes.");
    const parsed = assertNativeLtdShareMiiImportSafety(bytes);
    if (parsed.version !== 3) return Buffer.from(bytes);

    const sections = parsed.serializedSections;
    const required = [
        "miiBlock",
        "personalityAndVoice",
        "displayName",
        "pronunciation",
        "sexuality",
        "canvasTexturePayload",
        "ugcTexturePayload"
    ];
    for (const field of required) {
        const section = sections?.[field];
        if (!Number.isInteger(section?.offset) || !Number.isInteger(section?.byteLength)) {
            throw new LtdCanonicalError(
                "LTD_SHAREMII_IMPORT_UNSAFE",
                `This native LTD cannot be exported safely for ShareMii 3.0: missing ${field} wire bounds.`
            );
        }
    }
    const slice = field => {
        const section = sections[field];
        return bytes.subarray(section.offset, section.offset + section.byteLength);
    };
    const miiBlock = slice("miiBlock");
    const personality = slice("personalityAndVoice");
    const displayName = slice("displayName");
    const pronunciation = slice("pronunciation");
    const sexuality = slice("sexuality");
    const canvas = slice("canvasTexturePayload");
    const ugc = slice("ugcTexturePayload");
    if (
        miiBlock.length !== 156
        || personality.length !== 72
        || displayName.length !== 64
        || pronunciation.length !== 128
        || sexuality.length !== 4
    ) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            "This native LTD cannot be exported safely for ShareMii 3.0: its fixed-width v3 sections are invalid."
        );
    }

    const hasCanvas = parsed.header?.hasCanvas === true;
    const hasUgcTexture = parsed.header?.hasUgcTexture === true;
    if (
        sexuality[3] !== 0
        || hasCanvas !== hasUgcTexture
        || hasCanvas !== (canvas.length > 0)
        || hasUgcTexture !== (ugc.length > 0)
    ) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            "This native LTD uses v3-only sexuality or texture state that cannot be represented safely for ShareMii 3.0."
        );
    }

    const header = Buffer.from([
        2,
        hasCanvas ? 1 : 0,
        hasUgcTexture ? 1 : 0,
        Number(parsed.header?.reserved || 0) & 0xff,
        0
    ]);
    const marker = Buffer.alloc(3, 0xa3);
    const compatible = Buffer.concat([
        header,
        miiBlock,
        personality,
        displayName,
        pronunciation,
        sexuality.subarray(0, 3),
        marker,
        canvas,
        marker,
        ugc
    ]);

    let reparsed;
    try {
        reparsed = miijs.parseLtdContainer(compatible);
    } catch (error) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            `The ShareMii 3.0 compatibility export did not parse: ${error.message}`,
            { cause: error }
        );
    }
    const compatibleSections = reparsed.serializedSections;
    const compatibleSlice = field => {
        const section = compatibleSections[field];
        return compatible.subarray(section.offset, section.offset + section.byteLength);
    };
    const parity = [
        ["miiBlock", miiBlock],
        ["personalityAndVoice", personality],
        ["displayName", displayName],
        ["pronunciation", pronunciation],
        ["canvasTexturePayload", canvas],
        ["ugcTexturePayload", ugc]
    ];
    if (
        reparsed.version !== 2
        || reparsed.header?.hasCanvas !== parsed.header?.hasCanvas
        || reparsed.header?.hasUgcTexture !== parsed.header?.hasUgcTexture
        || !parity.every(([field, expected]) => compatibleSlice(field).equals(expected))
        || !compatibleSlice("sexuality").equals(sexuality.subarray(0, 3))
    ) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            "The ShareMii 3.0 compatibility export did not preserve the native LTD payload."
        );
    }
    // ShareMii 3.0 locates both texture sections with naïve first/last A3x3
    // searches. Refuse a derivative whose payload contains a colliding
    // sentinel instead of letting the old importer merge or truncate textures.
    const canvasMarkerOffset = compatibleSections.canvasMarker.offset;
    const ugcMarkerOffset = compatibleSections.ugcTextureMarker.offset;
    if (
        compatible.indexOf(marker) !== canvasMarkerOffset
        || compatible.lastIndexOf(marker) !== ugcMarkerOffset
    ) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            "This native LTD contains a texture sentinel collision that ShareMii 3.0 cannot import safely."
        );
    }
    return compatible;
}

function getExplicitLtdProfile(gender) {
    return Object.freeze({
        version: 2,
        header: Object.freeze({
            hasCanvas: false,
            hasUgcTexture: false,
            reserved: 0,
            legacyPadding: 0
        }),
        personalityAndVoice: getShareMiiImportSafePersonality(gender),
        pronunciation: "",
        loveGenderRaw: Buffer.from(SHAREMII_IMPORT_SAFE_LOVE_GENDER),
        canvasTexturePayload: Buffer.alloc(0),
        ugcTexturePayload: Buffer.alloc(0)
    });
}

export class LtdCanonicalError extends Error {
    constructor(code, message, options = {}) {
        super(message, options);
        this.name = "LtdCanonicalError";
        this.code = code;
    }
}

export function makeTrustedMiiFileInput(filePath, { declaredLtd = false } = {}) {
    const input = Object.freeze({
        kind: "trusted-mii-file",
        path: String(filePath || ""),
        declaredLtd: declaredLtd === true
    });
    trustedMiiInputs.add(input);
    return input;
}

export function makeTrustedMiiBytesInput(bytes, { declaredLtd = false } = {}) {
    const normalized = normalizeBuffer(bytes);
    if (!normalized) throw new TypeError("Expected trusted Mii bytes.");
    const input = Object.freeze({
        kind: "trusted-mii-bytes",
        bytes: normalized,
        declaredLtd: declaredLtd === true
    });
    trustedMiiInputs.add(input);
    return input;
}

export function isTrustedMiiFileInput(input) {
    return Boolean(input && trustedMiiInputs.has(input) && input.kind === "trusted-mii-file");
}

export function isTrustedMiiBytesInput(input) {
    return Boolean(input && trustedMiiInputs.has(input) && input.kind === "trusted-mii-bytes");
}

function assertLtdCodecAvailable() {
    const available = (
        miijs?.MiiFormats?.LTD === "ltd"
        && miijs?.formats?.ltd
        && typeof miijs?.parseLtdContainer === "function"
        && typeof miijs?.convertMii === "function"
    );
    if (!available) {
        throw new LtdCanonicalError(
            "LTD_CODEC_UNAVAILABLE",
            "The installed MiiJS build does not include the coordinated LTD codec and conversion API."
        );
    }
}

function sha256(bytes) {
    return crypto.createHash("sha256").update(bytes).digest("hex");
}

function normalizeBuffer(value) {
    if (Buffer.isBuffer(value)) return Buffer.from(value);
    if (value instanceof ArrayBuffer) return Buffer.from(value);
    if (ArrayBuffer.isView(value)) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value?.type === "Buffer" && Array.isArray(value.data)) {
        return Buffer.from(value.data);
    }
    if (value?.buffer && Buffer.isBuffer(value.buffer)) {
        return Buffer.from(value.buffer);
    }
    return null;
}

async function readCandidateBytes(input) {
    const direct = normalizeBuffer(input);
    if (direct) return { bytes: direct, explicitLtd: false };

    if (isTrustedMiiBytesInput(input)) {
        const bytes = normalizeBuffer(input.bytes);
        if (!bytes) {
            throw new LtdCanonicalError("INVALID_LTD", "Trusted Mii bytes are invalid.");
        }
        return { bytes, explicitLtd: input.declaredLtd === true };
    }

    if (isTrustedMiiFileInput(input)) {
        const filePath = String(input.path || "");
        const stat = await fs.promises.stat(filePath);
        if (!stat.isFile()) {
            throw new LtdCanonicalError("INVALID_LTD", "Trusted Mii upload path is not a regular file.");
        }
        if (stat.size > LTD_MAX_BYTES) {
            if (input.declaredLtd) {
                throw new LtdCanonicalError("LTD_TOO_LARGE", `LTD files may not exceed ${LTD_MAX_BYTES} bytes.`);
            }
            return null;
        }
        return {
            bytes: await fs.promises.readFile(filePath),
            explicitLtd: input.declaredLtd === true
        };
    }

    if (typeof input !== "string") return null;
    const value = input.trim();
    if (!value) return null;

    if (/^data:application\/(?:octet-stream|x-ltd);base64,/i.test(value)) {
        return {
            bytes: Buffer.from(value.slice(value.indexOf(",") + 1), "base64"),
            explicitLtd: /^data:application\/x-ltd;base64,/i.test(value)
        };
    }

    const compact = value.replace(/\s+/g, "");
    if (compact.length <= LTD_MAX_BYTES * 2 + 2) {
        const hex = compact.replace(/^0x/i, "");
        if (hex.length > 0 && hex.length % 2 === 0 && /^[0-9a-f]+$/i.test(hex)) {
            return { bytes: Buffer.from(hex, "hex"), explicitLtd: false };
        }
    }
    if (
        compact.length >= 8
        && compact.length <= Math.ceil(LTD_MAX_BYTES / 3) * 4 + 4
        && /^[a-z0-9+/]+={0,2}$/i.test(compact)
    ) {
        return { bytes: Buffer.from(compact, "base64"), explicitLtd: false };
    }

    return null;
}

function clonePlain(value) {
    if (value === undefined) return undefined;
    if (value === null || typeof value !== "object") return value;
    if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) return Array.from(value);
    if (Array.isArray(value)) return value.map(clonePlain);
    const out = {};
    for (const [key, child] of Object.entries(value)) out[key] = clonePlain(child);
    return out;
}

function getNestedValue(object, fieldPath) {
    return fieldPath.split(".").reduce((value, key) => value?.[key], object);
}

function setNestedValue(object, fieldPath, value) {
    const keys = fieldPath.split(".");
    const finalKey = keys.pop();
    let cursor = object;
    for (const key of keys) {
        if (!cursor[key] || typeof cursor[key] !== "object") cursor[key] = {};
        cursor = cursor[key];
    }
    cursor[finalKey] = value;
}

function resolveExplicitHistoricalSchema(recordId, mii) {
    const id = String(recordId || mii?.id || "").trim();
    if (!id) return null;
    const declaration = EXPLICIT_HISTORICAL_SCHEMAS.get(id);
    return declaration ? { recordId: id, ...declaration } : null;
}

function canonicalHistoricalJsonValue(value) {
    if (value === undefined) return { $type: "undefined" };
    if (value instanceof Date) return { $date: value.toISOString() };
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        return { $bytes: Buffer.from(value).toString("hex") };
    }
    if (Array.isArray(value)) return value.map(canonicalHistoricalJsonValue);
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.keys(value).sort().map(key => [
            key,
            canonicalHistoricalJsonValue(value[key])
        ]));
    }
    return value;
}

export function getHistoricalSourceRecordSha256(mii) {
    const snapshot = Object.fromEntries(HISTORICAL_SOURCE_PROJECTION_KEYS
        .filter(key => Object.prototype.hasOwnProperty.call(mii || {}, key))
        .map(key => [key, structuredClone(mii[key])]));
    const canonical = JSON.stringify(canonicalHistoricalJsonValue(snapshot));
    return sha256(Buffer.from(canonical, "utf8"));
}

function assertHistoricalSourceIdentity(mii, declaration) {
    const actualSha256 = getHistoricalSourceRecordSha256(mii);
    if (actualSha256 !== declaration.sourceRecordSha256) {
        throw new LtdCanonicalError(
            "LTD_HISTORICAL_SOURCE_MISMATCH",
            `${declaration.recordId} is declared as ${declaration.historicalSchema}, but its exact audited source-record fingerprint does not match.`
        );
    }
}

export function applyRawWiiPaletteSchema(sourceFields, { recordId = "declared source" } = {}) {
    const fields = clonePlain(sourceFields);
    const transformations = [];
    for (const [fieldPath, table] of Object.entries(RAW_WII_PALETTES)) {
        const sourceValue = getNestedValue(fields, fieldPath);
        if (!Number.isInteger(sourceValue) || sourceValue < 0 || sourceValue >= table.length) {
            throw new LtdCanonicalError(
                "LTD_HISTORICAL_SOURCE_MISMATCH",
                `${recordId} raw-wii-palettes requires ${fieldPath} to be an integer from 0 through ${table.length - 1}.`
            );
        }
        const targetValue = table[sourceValue];
        setNestedValue(fields, fieldPath, targetValue);
        transformations.push({
            code: "explicit_raw_wii_palette_to_canonical_miijs_v3",
            sourcePath: fieldPath,
            targetPath: fieldPath,
            sourceValue,
            targetValue,
            sourceBacked: true,
            provenance: "FFLiMiiData.cpp-a784e6c+MiiPort-15a3032"
        });
    }
    return { fields, transformations };
}

function applyExplicitHistoricalSchema(sourceFields, declaration) {
    if (!declaration) return { fields: sourceFields, transformations: [] };
    if (declaration.historicalSchema === "raw-wii-palettes") {
        return applyRawWiiPaletteSchema(sourceFields, { recordId: declaration.recordId });
    }
    throw new LtdCanonicalError(
        "LTD_HISTORICAL_SCHEMA_UNSUPPORTED",
        `Unsupported explicit historical schema: ${declaration.historicalSchema}.`
    );
}

function storedLtdUsesHistoricalDeclaration(mii, declaration) {
    if (!declaration) return true;
    const provenance = mii?.ltdProvenance;
    return provenance?.historicalSchemaPolicy === LTD_HISTORICAL_SCHEMA_POLICY_ID
        && provenance?.historicalSchema === declaration.historicalSchema
        && provenance?.historicalSourceRecordSha256 === declaration.sourceRecordSha256;
}

function generatedStoredLtdNeedsProfileUpgrade(mii) {
    const provenance = mii?.ltdProvenance;
    if (provenance?.kind !== "canonical-regenerated-charinfo") return false;
    if (provenance?.profilePolicy !== LTD_PROFILE_POLICY_ID) return true;
    const stored = getStoredLtdBytes(mii);
    if (!stored) return false;
    try {
        assertGeneratedLtdShareMiiCompatibility(stored);
        return false;
    } catch (error) {
        if (error instanceof LtdCanonicalError && error.code === "LTD_SHAREMII_IMPORT_UNSAFE") {
            return true;
        }
        throw error;
    }
}

export function isStoredLtdCanonicalizationCurrent(mii) {
    const provenance = mii?.ltdProvenance;
    if (provenance?.kind === "native-upload") return true;
    if (generatedStoredLtdNeedsProfileUpgrade(mii)) return false;
    const declaration = resolveExplicitHistoricalSchema(mii?.id, mii);
    if (!declaration) return true;
    return storedLtdUsesHistoricalDeclaration(mii, declaration)
        && getHistoricalSourceRecordSha256(mii) === declaration.sourceRecordSha256;
}

function stripNonQueryCharInfoFields(charInfo) {
    const out = clonePlain(charInfo || {});
    delete out.nameBytes;
    delete out.uuid;
    return out;
}

export function projectLtdFieldsForSite(fields) {
    const ltd = fields?.ltd;
    const charInfo = ltd?.charInfo;
    if (!ltd || !charInfo) {
        throw new LtdCanonicalError("INVALID_LTD", "Decoded LTD data is missing CharInfoEx.");
    }

    const faceFlags = charInfo.faceFlags || {};
    const hairFlags = charInfo.hairStyleFlags || {};
    const displayName = String(ltd.displayName || fields?.meta?.name || charInfo.name || "").trim();
    return {
        console: "LTD",
        meta: {
            name: displayName || charInfo.name || "no name",
            creatorName: "",
            console: "LTD",
            type: faceFlags.specialMii ? "Special" : "Default",
            miiId: String(charInfo.uuidRaw || fields?.meta?.miiId || "").toUpperCase()
        },
        general: {
            gender: charInfo.gender,
            height: charInfo.height,
            weight: charInfo.build
        },
        perms: {},
        face: {
            type: charInfo.facelineType,
            color: charInfo.facelineColor,
            flags: charInfo.faceFlagsRaw
        },
        hair: {
            type: charInfo.hairType,
            color: charInfo.hairColorPrimary,
            secondaryColor: charInfo.hairColorSecondary,
            frontType: charInfo.hairFrontType,
            backType: charInfo.hairBackType,
            flipped: Boolean(faceFlags.bangsSide),
            styleFlags: charInfo.hairStyleFlagsRaw,
            leftSide: Boolean(hairFlags.leftSide),
            rightSide: Boolean(hairFlags.rightSide)
        },
        eyes: {
            type: charInfo.eyeType,
            color: charInfo.eyeColor,
            size: charInfo.eyeScale,
            squash: charInfo.eyeAspect,
            rotation: charInfo.eyeRotate,
            distanceApart: charInfo.eyeX,
            yPosition: charInfo.eyeY
        },
        eyebrows: {
            type: charInfo.eyebrowType,
            color: charInfo.eyebrowColor,
            size: charInfo.eyebrowScale,
            squash: charInfo.eyebrowAspect,
            rotation: charInfo.eyebrowRotate,
            distanceApart: charInfo.eyebrowX,
            yPosition: charInfo.eyebrowY
        },
        nose: {
            type: charInfo.noseType,
            size: charInfo.noseScale,
            yPosition: charInfo.noseY
        },
        mouth: {
            type: charInfo.mouthType,
            color: charInfo.mouthColor,
            size: charInfo.mouthScale,
            squash: charInfo.mouthAspect,
            rotation: charInfo.mouthRotate,
            yPosition: charInfo.mouthY
        },
        beard: {
            type: charInfo.beardType,
            color: charInfo.beardColor,
            stubbleType: charInfo.stubbleType,
            stubbleColor: charInfo.stubbleColor,
            mustache: {
                type: charInfo.mustacheType,
                color: charInfo.mustacheColor,
                size: charInfo.mustacheScale,
                squash: charInfo.mustacheAspect,
                yPosition: charInfo.mustacheY
            }
        },
        glasses: {
            type: charInfo.glassPrimaryType,
            color: charInfo.glassPrimaryColor,
            size: charInfo.glassScale,
            squash: charInfo.glassAspect,
            yPosition: charInfo.glassY,
            lensMaterialMode: charInfo.glassLensMaterialMode,
            lensColor: charInfo.glassLensColor
        },
        mole: {
            on: Boolean(faceFlags.moleEnabled),
            active: Boolean(faceFlags.moleEnabled),
            size: charInfo.moleScale,
            xPosition: charInfo.moleX,
            yPosition: charInfo.moleY
        },
        ltdCharInfo: stripNonQueryCharInfoFields(charInfo)
    };
}

function summarizeConversionReport(report) {
    const fieldCounts = {};
    for (const key of [
        "copied",
        "transformed",
        "generated",
        "defaulted",
        "overridden",
        "dropped",
        "approximated",
        "required"
    ]) {
        fieldCounts[key] = Array.isArray(report?.fields?.[key]) ? report.fields[key].length : 0;
    }
    return {
        version: report?.version,
        status: report?.status,
        sourceFormat: report?.sourceFormat,
        targetFormat: report?.targetFormat,
        mode: report?.mode,
        summary: clonePlain(report?.summary || {}),
        verification: clonePlain(report?.verification || {}),
        fieldCounts
    };
}

function buildStoredFields(bytes, parsed, provenance, report = null) {
    const charInfoSection = parsed?.serializedSections?.charInfo;
    if (!charInfoSection || charInfoSection.byteLength !== 152) {
        throw new LtdCanonicalError("INVALID_LTD", "LTD CharInfoEx section metadata is invalid.");
    }
    const appearanceHasher = crypto.createHash("sha256");
    appearanceHasher.update("infinimii-ltd-appearance-v1\0");
    appearanceHasher.update(bytes.subarray(
        charInfoSection.offset + 0x2b,
        charInfoSection.offset + charInfoSection.byteLength
    ));
    appearanceHasher.update(Buffer.from(parsed.canvasTexturePayload?.data || []));
    appearanceHasher.update(Buffer.from(parsed.ugcTexturePayload?.data || []));
    const facepaintCoverage = classifyLtdFacepaintUsage(parsed);
    return {
        ltdData: Buffer.from(bytes),
        ltdSha256: sha256(bytes),
        ltdAppearanceHash: appearanceHasher.digest("hex"),
        ltdVersion: parsed.version,
        ltdProvenance: provenance,
        ltdConversionReport: report ? summarizeConversionReport(report) : undefined,
        facepaintUsage: facepaintCoverage.usage,
        facepaintCoverage
    };
}

export async function parseNativeLtdUpload(input) {
    assertLtdCodecAvailable();
    const candidate = await readCandidateBytes(input);
    if (!candidate) return null;
    if (candidate.bytes.length > LTD_MAX_BYTES) {
        throw new LtdCanonicalError("LTD_TOO_LARGE", `LTD files may not exceed ${LTD_MAX_BYTES} bytes.`);
    }

    let parsed;
    try {
        parsed = miijs.parseLtdContainer(candidate.bytes);
    } catch (error) {
        if (candidate.explicitLtd) {
            throw new LtdCanonicalError("INVALID_LTD", `Invalid LTD file: ${error.message}`, { cause: error });
        }
        return null;
    }

    try {
        const instance = await miijs.Mii.create(candidate.bytes);
        const encoded = Buffer.from(await instance.encode(miijs.MiiFormats.LTD));
        if (!encoded.equals(candidate.bytes)) {
            throw new LtdCanonicalError(
                "LTD_NOT_LOSSLESS",
                "The LTD codec did not reproduce the uploaded bytes exactly."
            );
        }
        assertNativeLtdShareMiiImportSafety(parsed);
        const projection = projectLtdFieldsForSite(instance.fields);
        Object.assign(projection, buildStoredFields(candidate.bytes, parsed, {
            kind: "native-upload",
            codec: LTD_CODEC_ID,
            sourceFormat: "ltd",
            byteExact: true
        }));
        return { bytes: Buffer.from(candidate.bytes), fields: projection, parsed };
    } catch (error) {
        if (error instanceof LtdCanonicalError) throw error;
        throw new LtdCanonicalError("INVALID_LTD", `Invalid LTD file: ${error.message}`, { cause: error });
    }
}

function deterministicCreateId(recordId, charInfoBytes) {
    const sourceHash = Buffer.from(sha256(charInfoBytes), "ascii");
    const id = crypto
        .createHash("sha256")
        .update(CREATE_ID_DOMAIN)
        .update(String(recordId || "unassigned"), "utf8")
        .update(Buffer.from([0]))
        .update(sourceHash)
        .digest()
        .subarray(0, 16);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    return id;
}

function validateConvertedResult(result) {
    const compared = Number(result?.report?.verification?.comparedBytes);
    const projectionExact = result?.report?.verification?.appearanceProjectionExact;
    const mismatchOffsets = result?.report?.verification?.mismatchOffsets;
    if (
        result?.report?.status !== "converted"
        || result?.report?.targetFormat !== "ltd"
        || compared !== 152
        || projectionExact !== true
        || !Array.isArray(mismatchOffsets)
        || mismatchOffsets.length !== 0
    ) {
        throw new LtdCanonicalError(
            "LTD_CONVERSION_NOT_VERIFIED",
            "MiiJS did not verify the complete 152-byte CharInfoEx projection."
        );
    }
}

function assertShareMiiField(condition, field, expected, actual) {
    if (condition) return;
    throw new LtdCanonicalError(
        "LTD_SHAREMII_IMPORT_UNSAFE",
        `Generated LTD is not safe for ShareMii import: ${field} must be ${expected}, got ${actual}.`
    );
}

/**
 * Enforce the exact game-importable v2 contract used for generated LTD files.
 * The v2 envelope is intentional: it remains accepted by current ShareMii and
 * avoids the one-byte Mii-block shift in ShareMii application v3.0.
 * Native uploads deliberately do not pass through this profile validator: they
 * remain authoritative and byte-exact.
 */
export function assertGeneratedLtdShareMiiCompatibility(value) {
    const bytes = normalizeBuffer(value);
    if (!bytes) throw new TypeError("Expected generated LTD bytes.");
    let parsed;
    try {
        parsed = miijs.parseLtdContainer(bytes);
    } catch (error) {
        throw new LtdCanonicalError(
            "LTD_SHAREMII_IMPORT_UNSAFE",
            `Generated LTD is not a valid ShareMii container: ${error.message}`,
            { cause: error }
        );
    }

    const expect = (condition, field, expected, actual) =>
        assertShareMiiField(condition, field, expected, actual);
    expect(bytes.length === 434, "byteLength", 434, bytes.length);
    expect(parsed.version === 2, "version", 2, parsed.version);
    expect(parsed.originalVersion === 2, "originalVersion", 2, parsed.originalVersion);
    expect(parsed.header?.hasCanvas === false, "header.hasCanvas", false, parsed.header?.hasCanvas);
    expect(parsed.header?.hasUgcTexture === false, "header.hasUgcTexture", false, parsed.header?.hasUgcTexture);
    expect(parsed.header?.reserved === 0, "header.reserved", 0, parsed.header?.reserved);
    expect(parsed.header?.legacyPadding === 0, "header.legacyPadding", 0, parsed.header?.legacyPadding);
    expect(parsed.header?.charInfoLength === 152, "header.charInfoLength", 152, parsed.header?.charInfoLength);
    expect(parsed.charInfo?.schemaVersion === 45, "charInfo.schemaVersion", 45, parsed.charInfo?.schemaVersion);
    expect(parsed.displayName === parsed.charInfo?.name, "displayName", "the CharInfoEx name", parsed.displayName);
    expect(parsed.pronunciation === "", "pronunciation", "an empty string", parsed.pronunciation);
    expect(parsed.canvasMarker === "a3a3a3", "canvasMarker", "a3a3a3", parsed.canvasMarker);
    expect(parsed.ugcTextureMarker === "a3a3a3", "ugcTextureMarker", "a3a3a3", parsed.ugcTextureMarker);
    expect(parsed.canvasTexturePayload?.byteLength === 0, "canvasTexturePayload.byteLength", 0, parsed.canvasTexturePayload?.byteLength);
    expect(parsed.ugcTexturePayload?.byteLength === 0, "ugcTexturePayload.byteLength", 0, parsed.ugcTexturePayload?.byteLength);

    const expectedSections = {
        formatHeader: [0, 5],
        miiBlock: [5, 156],
        charInfo: [9, 152],
        personalityAndVoice: [161, 72],
        displayName: [233, 64],
        pronunciation: [297, 128],
        sexuality: [425, 3],
        canvasMarker: [428, 3],
        canvasTexturePayload: [431, 0],
        ugcTextureMarker: [431, 3],
        ugcTexturePayload: [434, 0]
    };
    for (const [field, [offset, byteLength]] of Object.entries(expectedSections)) {
        const section = parsed.serializedSections?.[field];
        expect(section?.offset === offset, `serializedSections.${field}.offset`, offset, section?.offset);
        expect(section?.byteLength === byteLength, `serializedSections.${field}.byteLength`, byteLength, section?.byteLength);
    }

    expect(
        parsed.charInfo?.gender === 0 || parsed.charInfo?.gender === 1,
        "charInfo.gender",
        "0 or 1",
        parsed.charInfo?.gender
    );
    const expectedPersonality = getShareMiiImportSafePersonality(parsed.charInfo.gender);
    for (const [field, expected] of Object.entries(expectedPersonality)) {
        const actual = parsed.personalityAndVoice?.[field];
        expect(
            Number.isInteger(actual) && actual >= -0x80000000 && actual <= 0x7fffffff,
            `personalityAndVoice.${field} signedness`,
            "a signed 32-bit integer",
            actual
        );
        expect(actual === expected, `personalityAndVoice.${field}`, expected, actual);
    }
    const loveGender = parsed.loveGender?.raw;
    expect(
        Array.isArray(loveGender)
            && loveGender.length === SHAREMII_IMPORT_SAFE_LOVE_GENDER.length
            && loveGender.every((value, index) => value === SHAREMII_IMPORT_SAFE_LOVE_GENDER[index]),
        "loveGender.raw",
        SHAREMII_IMPORT_SAFE_LOVE_GENDER.join(","),
        Array.isArray(loveGender) ? loveGender.join(",") : loveGender
    );
    return parsed;
}

/**
 * Return true only for the exact current site-generated compatibility
 * envelope. This byte-intrinsic check is also used at native-source trust
 * boundaries so changing provenance metadata cannot turn a generated LTD
 * into authenticated native evidence.
 */
export function isGeneratedLtdShareMiiCompatibility(value) {
    try {
        assertGeneratedLtdShareMiiCompatibility(value);
        return true;
    } catch {
        return false;
    }
}

export async function canonicalizeMiiToLtd(mii, { recordId } = {}) {
    assertLtdCodecAvailable();
    const historicalDeclaration = resolveExplicitHistoricalSchema(recordId, mii);
    const stored = getStoredLtdBytes(mii);
    if (stored) {
        if (mii?.ltdSha256 && sha256(stored) !== String(mii.ltdSha256).toLowerCase()) {
            throw new LtdCanonicalError("LTD_HASH_MISMATCH", "Stored LTD bytes do not match their SHA-256.");
        }
        const nativeUpload = mii?.ltdProvenance?.kind === "native-upload";
        if (nativeUpload || isStoredLtdCanonicalizationCurrent(mii)) {
            const parsed = miijs.parseLtdContainer(stored);
            if (nativeUpload) assertNativeLtdShareMiiImportSafety(parsed);
            return {
                bytes: stored,
                parsed,
                storedFields: buildStoredFields(stored, parsed, clonePlain(mii?.ltdProvenance || {
                    kind: "stored",
                    codec: LTD_CODEC_ID
                }), mii?.ltdConversionReport)
            };
        }
    }

    try {
        if (historicalDeclaration) assertHistoricalSourceIdentity(mii, historicalDeclaration);
        const sourceFields = toMiiDataOnly(mii);
        const historicalResult = applyExplicitHistoricalSchema(sourceFields, historicalDeclaration);
        const source = await miijs.Mii.create(historicalResult.fields);
        const charInfo = Buffer.from(await source.encode(miijs.MiiFormats.CHARINFO));
        if (charInfo.length !== 88) {
            throw new LtdCanonicalError("CHARINFO_GENERATION_FAILED", "Canonical CharInfo must be exactly 88 bytes.");
        }
        deterministicCreateId(recordId || mii?.id, charInfo).copy(charInfo, 0);

        const result = await miijs.convertMii(charInfo, miijs.MiiFormats.LTD, {
            sourceFormat: miijs.MiiFormats.CHARINFO,
            mode: "source-backed",
            ltdProfile: getExplicitLtdProfile(source.fields?.general?.gender)
        });
        validateConvertedResult(result);
        const bytes = Buffer.from(result.data);
        const parsed = assertGeneratedLtdShareMiiCompatibility(bytes);
        const decoded = await miijs.Mii.create(bytes);
        const roundTrip = Buffer.from(await decoded.encode(miijs.MiiFormats.LTD));
        if (!roundTrip.equals(bytes)) {
            throw new LtdCanonicalError("LTD_NOT_LOSSLESS", "Generated LTD bytes did not round-trip exactly.");
        }

        const provenance = {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            sourceFormat: "charinfo",
            codec: LTD_CODEC_ID,
            profilePolicy: LTD_PROFILE_POLICY_ID,
            createIdPolicy: LTD_CREATE_ID_POLICY_ID,
            byteExactSourceClaimed: false,
            appearanceProjectionExact: true,
            ...(historicalDeclaration ? {
                historicalSchemaPolicy: LTD_HISTORICAL_SCHEMA_POLICY_ID,
                historicalSchema: historicalDeclaration.historicalSchema,
                historicalSourceRecordSha256: historicalDeclaration.sourceRecordSha256,
                historicalTransformations: historicalResult.transformations
            } : {})
        };
        return {
            bytes,
            parsed,
            fields: decoded.fields,
            report: result.report,
            storedFields: buildStoredFields(bytes, parsed, provenance, result.report),
            ...(stored ? {
                replacesStoredLtd: {
                    previousSha256: sha256(stored),
                    reason: generatedStoredLtdNeedsProfileUpgrade(mii)
                        ? "sharemii-import-safety-profile-upgrade"
                        : "explicit-historical-schema-policy-upgrade",
                    policy: generatedStoredLtdNeedsProfileUpgrade(mii)
                        ? LTD_PROFILE_POLICY_ID
                        : LTD_HISTORICAL_SCHEMA_POLICY_ID,
                    ...(historicalDeclaration ? {
                        historicalSchema: historicalDeclaration.historicalSchema
                    } : {})
                }
            } : {})
        };
    } catch (error) {
        if (error instanceof LtdCanonicalError) throw error;
        throw new LtdCanonicalError(
            "LTD_CONVERSION_FAILED",
            `Could not build a source-backed LTD projection: ${error.message}`,
            { cause: error }
        );
    }
}

export async function ensureCanonicalLtdForMii(mii, { persist = true } = {}) {
    let source = mii;
    const recordId = String(mii?.id || "").trim();

    if (!getStoredLtdBytes(source) && recordId && persist) {
        const { Miis } = await import("./database.js");
        const stored = await Miis.findOne({ id: recordId })
            // `+ltdData` overrides the schema-level exclusion without turning
            // this into an inclusion-only projection. Existing records that do
            // not have LTD data yet must be converted from their complete
            // stored appearance, never from a card/list projection.
            .select("+ltdData")
            .lean();
        if (stored) source = mergeStoredMiiForCanonicalization(mii, stored);
    }

    let canonical = await canonicalizeMiiToLtd(source, { recordId });
    if (!recordId || !persist) return canonical;

    const { Miis } = await import("./database.js");
    const previousStored = getStoredLtdBytes(source);
    if (!previousStored) {
        await Miis.updateOne(
            {
                id: recordId,
                $or: [
                    { ltdData: { $exists: false } },
                    { ltdData: null }
                ]
            },
            { $set: canonical.storedFields }
        );
    } else if (canonical.replacesStoredLtd) {
        await Miis.updateOne(
            {
                id: recordId,
                $or: [
                    { ltdSha256: canonical.replacesStoredLtd.previousSha256 },
                    {
                        ltdSha256: { $exists: false },
                        ltdData: previousStored
                    },
                    {
                        ltdSha256: null,
                        ltdData: previousStored
                    }
                ]
            },
            {
                $set: canonical.storedFields,
                $unset: { ltdRender: "" }
            }
        );
    } else {
        return canonical;
    }
    const winner = await Miis.findOne({ id: recordId })
        .select("+ltdData")
        .lean();
    if (getStoredLtdBytes(winner)) {
        canonical = await canonicalizeMiiToLtd({ ...mii, ...winner }, { recordId });
    }
    return canonical;
}

export function getStoredLtdBytes(mii) {
    return normalizeBuffer(mii?.ltdData || mii?.ltdSource?.bytes);
}

export function getLtdSha256(bytes) {
    const normalized = normalizeBuffer(bytes);
    if (!normalized) throw new TypeError("Expected LTD bytes.");
    return sha256(normalized);
}

export function mergeStoredMiiForCanonicalization(input, stored) {
    return stored ? { ...input, ...stored } : input;
}

assertLtdCodecAvailable();
