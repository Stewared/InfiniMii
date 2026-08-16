import { isDeepStrictEqual } from "node:util";

import miijs from "miijs";

import {
    LTD_CODEC_ID,
    isGeneratedLtdShareMiiCompatibility,
    getStoredLtdBytes,
    getLtdSha256,
    projectLtdFieldsForSite
} from "./ltdCanonical.js";
import { cloneSerializable, toMiiDataOnly } from "./miiDataUtils.js";

export const MII_ERA_CLASSIFIER_ID = "infinimii-source-authority-semantic-round-trip-v2";

export const MII_ERA_ORDER = Object.freeze([
    Object.freeze({ era: "RCD", format: miijs.MiiFormats.RCD }),
    Object.freeze({ era: "CFCD", format: miijs.MiiFormats.CFCD }),
    Object.freeze({ era: "FFCD", format: miijs.MiiFormats.FFCD }),
    Object.freeze({ era: "CHARINFO", format: miijs.MiiFormats.CHARINFO }),
    Object.freeze({ era: "LTD", format: miijs.MiiFormats.LTD })
]);

export const MII_ERA_VALUES = Object.freeze(MII_ERA_ORDER.map(candidate => candidate.era));

const MII_ERA_VALUE_SET = new Set(MII_ERA_VALUES);

const SEMANTIC_DEFAULTS = Object.freeze({
    general: Object.freeze({
        gender: 0,
        favoriteColor: 0,
        height: 64,
        weight: 64
    }),
    meta: Object.freeze({
        name: "no name",
        type: "Default"
    }),
    face: Object.freeze({ type: 0, color: 0, feature: 0, makeup: 0 }),
    hair: Object.freeze({ type: 0, color: 1, flipped: false }),
    eyes: Object.freeze({
        type: 0,
        color: 8,
        size: 4,
        squash: 3,
        rotation: 0,
        distanceApart: 2,
        yPosition: 12
    }),
    eyebrows: Object.freeze({
        type: 0,
        color: 1,
        size: 4,
        squash: 3,
        rotation: 6,
        distanceApart: 2,
        yPosition: 7
    }),
    nose: Object.freeze({ type: 1, size: 4, yPosition: 9 }),
    mouth: Object.freeze({ type: 23, color: 19, size: 4, squash: 3, yPosition: 13 }),
    beard: Object.freeze({ type: 0, color: 8 }),
    mustache: Object.freeze({ type: 0, size: 4, yPosition: 10 }),
    glasses: Object.freeze({ type: 0, color: 8, size: 4, yPosition: 10 }),
    mole: Object.freeze({ on: false, size: 4, xPosition: 2, yPosition: 20 })
});

const APPEARANCE_GROUPS = Object.freeze([
    "face", "hair", "eyes", "eyebrows", "nose", "mouth", "beard", "glasses", "mole"
]);
const APP_DATA_KEYS = Object.freeze(["tl", "mt", "miitopia"]);
const DERIVED_TL_ISLAND_FIELDS = new Set(["readable", "ocean", "isles", "num1", "num2"]);

export class MiiEraClassificationError extends Error {
    constructor(message, { attempts = [], cause } = {}) {
        super(message, cause ? { cause } : undefined);
        this.name = "MiiEraClassificationError";
        this.code = "MII_ERA_NOT_LOSSLESS";
        this.attempts = attempts;
    }
}

function own(object, key) {
    return Object.prototype.hasOwnProperty.call(object || {}, key);
}

function normalizedMarker(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "");
}

function normalizedCategorySegment(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}

function officialCategoryParts(input) {
    const source = plainObject(input);
    return (Array.isArray(source?.officialCategories) ? source.officialCategories : [])
        .map(path => String(path || "").split(/[>/]/).map(normalizedCategorySegment).filter(Boolean))
        .filter(parts => parts.length > 0);
}

function hasMeaningfulTomodachiData(source) {
    const tl = source?.tl;
    return tl !== null && tl !== undefined && (
        typeof tl !== "object" || Array.isArray(tl) || Object.keys(tl).length > 0
    );
}

function hasTomodachiMarker(source, categories) {
    if (hasMeaningfulTomodachiData(source)) return true;
    return categories.some(parts => (
        (parts[0] === "3ds" || parts[0] === "nintendo 3ds")
        && parts.slice(1).some(part => normalizedMarker(part) === "tomodachilife")
    ));
}

function hasNativeLtdClaim(source) {
    const provenance = source?.ltdProvenance;
    return provenance?.kind === "native-upload" || provenance?.sourceFormat === "ltd";
}

/**
 * Native LTD is a source-era claim, not an encode target.  A generated LTD
 * projection is deliberately ineligible: otherwise the final candidate would
 * prove itself by generating the very evidence it is meant to discover.
 */
export function hasAuthenticatedNativeLtdEvidence(input) {
    const source = plainObject(input);
    const provenance = source?.ltdProvenance;
    const provenanceKeys = provenance && typeof provenance === "object"
        ? Object.keys(provenance).sort()
        : [];
    if (
        provenance?.kind !== "native-upload"
        || provenance?.codec !== LTD_CODEC_ID
        || provenance?.sourceFormat !== "ltd"
        || provenance?.byteExact !== true
        || !isDeepStrictEqual(provenanceKeys, ["byteExact", "codec", "kind", "sourceFormat"])
        || source?.ltdConversionReport != null
        || !source?.ltdCharInfo
        || normalizedCategorySegment(source?.meta?.console || source?.console) !== "ltd"
    ) {
        return false;
    }
    const bytes = getStoredLtdBytes(source);
    const expectedHash = String(source?.ltdSha256 || "").trim().toLowerCase();
    if (!bytes || !/^[a-f0-9]{64}$/.test(expectedHash) || getLtdSha256(bytes) !== expectedHash) {
        return false;
    }
    try {
        const parsed = miijs.parseLtdContainer(bytes);
        const generatedCompatibilityEnvelope = isGeneratedLtdShareMiiCompatibility(bytes);
        return (parsed?.version === 2 || parsed?.version === 3)
            && Number(source?.ltdVersion) === Number(parsed.version)
            // Provenance is self-asserted storage metadata. Reject the exact
            // current generated compatibility envelope even when a caller
            // relabels it as native-upload. Native v2/v3 files remain
            // eligible after structural and byte-exact authentication.
            && !generatedCompatibilityEnvelope;
    } catch {
        return false;
    }
}

/**
 * Return authoritative source/category evidence in strict precedence order.
 * Category roots are exact: "Wii U" cannot accidentally satisfy "Wii".
 */
export function getMiiEraSourceExpectation(input) {
    const source = plainObject(input);
    const categories = officialCategoryParts(source);
    const roots = new Set(categories.map(parts => parts[0]));

    if (roots.has("wii") || roots.has("nintendo wii") || roots.has("ds") || roots.has("nintendo ds")) {
        return Object.freeze({ era: "RCD", valid: true, basis: "official-wii-or-ds-category" });
    }
    if (roots.has("3ds") || roots.has("nintendo 3ds") || roots.has("tl") || roots.has("tomodachi life")) {
        return Object.freeze({ era: "CFCD", valid: true, basis: "official-3ds-category" });
    }
    if (hasTomodachiMarker(source, categories)) {
        return Object.freeze({ era: "CFCD", valid: true, basis: "tomodachi-life-source-marker" });
    }
    if (roots.has("switch") || roots.has("nintendo switch")) {
        return Object.freeze({ era: "CHARINFO", valid: true, basis: "official-switch-category" });
    }
    if (roots.has("wii u") || roots.has("nintendo wii u")) {
        return Object.freeze({ era: "FFCD", valid: true, basis: "official-wii-u-category" });
    }

    if (hasNativeLtdClaim(source)) {
        return Object.freeze({
            era: "LTD",
            valid: hasAuthenticatedNativeLtdEvidence(source),
            basis: "native-ltd-upload"
        });
    }
    return null;
}

function declaredConsoleFallback(input) {
    const source = plainObject(input);
    const declared = normalizedCategorySegment(source?.meta?.console || source?.console);
    if (declared === "wii" || declared === "nintendo wii" || declared === "ds" || declared === "nintendo ds") {
        return Object.freeze({ era: "RCD", basis: "declared-console-fallback" });
    }
    if (declared === "3ds" || declared === "nintendo 3ds" || declared === "tl 3ds") {
        return Object.freeze({ era: "CFCD", basis: "declared-console-fallback" });
    }
    if (declared === "switch" || declared === "nintendo switch" || declared === "mii studio") {
        return Object.freeze({ era: "CHARINFO", basis: "declared-console-fallback" });
    }
    if (declared === "wii u" || declared === "nintendo wii u") {
        return Object.freeze({ era: "FFCD", basis: "declared-console-fallback" });
    }
    return null;
}

/**
 * Resolve the best synchronous era signal available on a stored/read model.
 *
 * The database temporarily contains stale `era: "LTD"` values written by an
 * earlier classifier which mistook the site's generated LTD render container
 * for source-format evidence.  Authoritative categories and title data take
 * precedence over that stale field, matching classifyMiiEra().  A declared
 * classic console is used only to repair an LTD value (or fill a missing
 * value); it never overrides an already classified non-LTD era.
 *
 * This helper intentionally does not attempt a codec round trip. The backfill
 * remains the source of truth for persistent classification; this is the
 * read-path bridge which prevents stale rows from receiving LTD-only behavior
 * before that migration is committed.
 */
export function getMiiEraRuntimeResolution(input) {
    const source = plainObject(input);
    const storedEraValue = String(source?.era || "").trim().toUpperCase();
    const storedEra = storedEraValue === "TL" ? "CFCD" : storedEraValue;
    const expectation = getMiiEraSourceExpectation(source);

    if (expectation?.valid && expectation.era !== "LTD") {
        return Object.freeze({
            era: expectation.era,
            basis: expectation.basis,
            storedEra: storedEra || null,
            corrected: Boolean(storedEra && storedEra !== expectation.era)
        });
    }

    if (MII_ERA_VALUE_SET.has(storedEra) && storedEra !== "LTD") {
        return Object.freeze({
            era: storedEra,
            basis: "stored-era",
            storedEra,
            corrected: storedEraValue === "TL"
        });
    }

    if (expectation?.valid) {
        return Object.freeze({
            era: expectation.era,
            basis: expectation.basis,
            storedEra: storedEra || null,
            corrected: Boolean(storedEra && storedEra !== expectation.era)
        });
    }

    // An invalid native-LTD claim is not evidence for a classic era. Preserve
    // an explicit LTD value so restricted operations continue to fail closed.
    if (expectation && !expectation.valid) {
        return Object.freeze({
            era: storedEra || null,
            basis: "invalid-source-evidence-fail-closed",
            storedEra: storedEra || null,
            corrected: false
        });
    }

    const fallback = declaredConsoleFallback(source);
    if ((storedEra === "LTD" || !storedEra) && fallback) {
        return Object.freeze({
            era: fallback.era,
            basis: storedEra === "LTD"
                ? `stale-ltd-${fallback.basis}`
                : fallback.basis,
            storedEra: storedEra || null,
            corrected: storedEra === "LTD"
        });
    }

    return Object.freeze({
        era: MII_ERA_VALUE_SET.has(storedEra) ? storedEra : null,
        basis: storedEra === "LTD" ? "stored-ltd-no-contradicting-authority" : "unresolved",
        storedEra: storedEra || null,
        corrected: false
    });
}

export function resolveMiiEraForRuntime(input) {
    return getMiiEraRuntimeResolution(input).era;
}

export function validateMiiEraClassification(input, result) {
    const expectation = getMiiEraSourceExpectation(input);
    const violations = [];
    if (expectation && !expectation.valid) {
        violations.push({
            code: "invalid-source-evidence",
            expectedEra: expectation.era,
            basis: expectation.basis
        });
    } else if (expectation && result?.era !== expectation.era) {
        violations.push({
            code: "source-era-mismatch",
            expectedEra: expectation.era,
            actualEra: result?.era || null,
            basis: expectation.basis
        });
    }
    if (result?.era === "LTD" && !hasAuthenticatedNativeLtdEvidence(input)) {
        violations.push({ code: "non-native-ltd", actualEra: "LTD" });
    }
    return Object.freeze({ valid: violations.length === 0, expectation, violations });
}

function plainObject(input) {
    if (input?.fields && typeof input.fields === "object") return input.fields;
    if (typeof input?.toObject === "function") return input.toObject({ depopulate: true });
    return input || {};
}

function stableSemanticValue(value, path = "") {
    if (value === undefined) return undefined;
    if (value instanceof Date) return value.toISOString();
    if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
        return { $bytes: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex") };
    }
    if (value instanceof ArrayBuffer) return { $bytes: Buffer.from(value).toString("hex") };
    if (Array.isArray(value)) return value.map((entry, index) => stableSemanticValue(entry, `${path}.${index}`));
    if (!value || typeof value !== "object") return value;

    const result = {};
    for (const key of Object.keys(value).sort()) {
        if (path === "tl.island.id" && DERIVED_TL_ISLAND_FIELDS.has(key)) continue;
        const normalized = stableSemanticValue(value[key], path ? `${path}.${key}` : key);
        if (normalized !== undefined) result[key] = normalized;
    }
    return result;
}

function semanticGroup(source, group, defaults, { includeExtensions = true } = {}) {
    const supplied = source?.[group] && typeof source[group] === "object" ? source[group] : {};
    const result = {};
    for (const [key, fallback] of Object.entries(defaults)) {
        result[key] = own(supplied, key) ? stableSemanticValue(supplied[key], `${group}.${key}`) : fallback;
    }

    // Unknown fields are meaningful extensions, not provenance. Keeping them
    // here prevents a classic format from being called lossless after silently
    // dropping LTD selectors such as eye highlights, stubble, or lens data.
    if (!includeExtensions) return result;
    for (const key of Object.keys(supplied).sort()) {
        if (own(defaults, key)) continue;
        if (group === "mole" && key === "active") continue; // Alias of mole.on in the LTD query projection.
        if (group === "beard" && key === "mustache") continue;
        const normalized = stableSemanticValue(supplied[key], `${group}.${key}`);
        if (normalized !== undefined) result[key] = normalized;
    }
    return result;
}

function semanticFieldsFromLtd(fields) {
    const projected = projectLtdFieldsForSite(fields);
    // projectLtdFieldsForSite intentionally exposes the complete CharInfoEx
    // query projection. It is semantic here; byte offsets, UUID spellings and
    // the rest of the container envelope are verified by the LTD byte check.
    return projected;
}

/**
 * Build the equality document used for the five classic/modern candidates.
 *
 * Included: visible Mii selectors, name/type, and TL/MT/Miitopia application
 * data. Missing classic
 * selector fields receive MiiJS's rendering defaults so (for example) a Wii
 * Mii does not become non-Wii merely because RCD omits a default squash value.
 *
 * Excluded: database metadata, classic profile/permission bookkeeping, and
 * wire provenance (IDs, birthdays, creator/device data, timestamps, source
 * console, checksums, slots/pages, and derived TL address text). Those values
 * do not change the represented appearance or its title-specific app data.
 * LTD uses its canonical container as the authority and has a separate,
 * byte-exact decode/encode/decode contract in defaultAttempt().
 */
export function getMiiEraSemanticSnapshot(input) {
    let source = plainObject(input);
    if (source?.ltd) source = semanticFieldsFromLtd(source);

    const snapshot = {
        general: semanticGroup(source, "general", SEMANTIC_DEFAULTS.general, { includeExtensions: false }),
        meta: semanticGroup(source, "meta", SEMANTIC_DEFAULTS.meta, { includeExtensions: false })
    };

    for (const group of APPEARANCE_GROUPS) {
        const defaults = group === "beard" ? SEMANTIC_DEFAULTS.beard : SEMANTIC_DEFAULTS[group];
        snapshot[group] = semanticGroup(source, group, defaults);
    }
    const mustache = source?.beard?.mustache;
    snapshot.beard.mustache = semanticGroup(
        { mustache },
        "mustache",
        SEMANTIC_DEFAULTS.mustache
    );

    for (const key of APP_DATA_KEYS) {
        if (own(source, key)) snapshot[key] = stableSemanticValue(source[key], key);
    }

    // Native LTD uploads carry fields that have no classic equivalent. The
    // full query projection is compared for format attempts; exact LTD bytes
    // are checked separately, so wire-only UUID/name byte arrays stay out.
    if (own(source, "ltdCharInfo")) {
        const charInfo = cloneSerializable(source.ltdCharInfo);
        if (charInfo && typeof charInfo === "object") {
            delete charInfo.uuidRaw;
            delete charInfo.uuid;
            delete charInfo.nameBytes;
        }
        snapshot.ltdCharInfo = stableSemanticValue(charInfo, "ltdCharInfo");
    }

    return stableSemanticValue(snapshot);
}

async function encodeCandidate(input, candidate) {
    if (candidate.era === "LTD") {
        if (!hasAuthenticatedNativeLtdEvidence(input)) {
            throw new MiiEraClassificationError("LTD era requires authenticated byte-exact native-upload evidence.");
        }
        return Buffer.from(getStoredLtdBytes(plainObject(input)));
    }

    const fields = toMiiDataOnly(plainObject(input));
    fields.general ||= {};
    if (!own(fields.general, "favoriteColor")) fields.general.favoriteColor = SEMANTIC_DEFAULTS.general.favoriteColor;
    // MiiJS enforces these Special-Mii wire invariants on its own cloned
    // encoder object and emits a warning each time. Apply the identical value
    // up front so a collection backfill does not produce thousands of expected
    // warnings; permissions are outside the appearance/app-data comparison.
    if (fields.meta?.type === "Special") {
        fields.perms ||= {};
        if (candidate.era === "RCD") fields.perms.mingle = false;
        if (candidate.era === "CFCD" || candidate.era === "FFCD") {
            fields.perms.sharing = false;
        }
    }
    const instance = await miijs.Mii.create(fields);
    return Buffer.from(await instance.encode(candidate.format));
}

async function decodeCandidate(bytes) {
    return await miijs.Mii.create(bytes);
}

function semanticDifferencePaths(left, right, path = "", output = []) {
    if (output.length >= 16 || Object.is(left, right)) return output;
    if (!left || !right || typeof left !== "object" || typeof right !== "object") {
        output.push(path || "$");
        return output;
    }
    if (Array.isArray(left) !== Array.isArray(right)) {
        output.push(path || "$");
        return output;
    }
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    for (const key of [...keys].sort()) {
        if (output.length >= 16) break;
        const childPath = path ? `${path}.${key}` : key;
        if (!own(left, key) || !own(right, key)) {
            output.push(childPath);
            continue;
        }
        semanticDifferencePaths(left[key], right[key], childPath, output);
    }
    return output;
}

async function defaultAttempt(input, candidate, sourceSnapshot) {
    const encoded = await encodeCandidate(input, candidate);
    const decoded = await decodeCandidate(encoded);

    // LTD is a native-container source claim, not another projection test.
    // We require authenticated stored bytes, exact re-encoding, and an
    // identical second decode so forged or nondeterministic evidence fails.
    if (candidate.era === "LTD") {
        const reencoded = Buffer.from(await decoded.encode(miijs.MiiFormats.LTD));
        if (!reencoded.equals(encoded)) {
            return { lossless: false, reason: "ltd-byte-round-trip-mismatch" };
        }
        const decodedAgain = await decodeCandidate(reencoded);
        if (!isDeepStrictEqual(
            stableSemanticValue(decoded.fields, "ltd"),
            stableSemanticValue(decodedAgain.fields, "ltd")
        )) {
            return { lossless: false, reason: "ltd-decoded-object-round-trip-mismatch" };
        }
        return { lossless: true };
    }

    const decodedSnapshot = getMiiEraSemanticSnapshot(decoded);
    if (!isDeepStrictEqual(sourceSnapshot, decodedSnapshot)) {
        const appDataMismatchKeys = APP_DATA_KEYS.filter(key => (
            own(sourceSnapshot, key) !== own(decodedSnapshot, key)
            || (own(sourceSnapshot, key) && !isDeepStrictEqual(sourceSnapshot[key], decodedSnapshot[key]))
        ));
        return {
            lossless: false,
            reason: "semantic-mismatch",
            mismatchPaths: semanticDifferencePaths(sourceSnapshot, decodedSnapshot),
            ...(appDataMismatchKeys.length ? { appDataMismatchKeys } : {})
        };
    }

    return { lossless: true };
}

function summarizedAttemptError(error) {
    return {
        name: String(error?.name || "Error"),
        code: error?.code ? String(error.code) : undefined,
        message: String(error?.message || error || "Unknown era classification error")
    };
}

/**
 * Return the first lossless era in the required fixed order. `attemptEra` is
 * injectable solely so ordering/short-circuit behavior can be unit-tested.
 */
export async function classifyMiiEra(input, { attemptEra = defaultAttempt } = {}) {
    const sourceSnapshot = getMiiEraSemanticSnapshot(input);
    const attempts = [];

    const expectation = getMiiEraSourceExpectation(input);
    if (expectation) {
        const candidate = MII_ERA_ORDER.find(entry => entry.era === expectation.era);
        if (!expectation.valid) {
            attempts.push({
                era: expectation.era,
                format: candidate?.format,
                lossless: false,
                reason: "invalid-source-evidence"
            });
            return { era: null, classifier: MII_ERA_CLASSIFIER_ID, authority: expectation, attempts };
        }
        if (expectation.era !== "LTD") {
            attempts.push({
                era: expectation.era,
                format: candidate?.format,
                lossless: true,
                reason: expectation.basis
            });
            return {
                era: expectation.era,
                classifier: MII_ERA_CLASSIFIER_ID,
                authority: expectation,
                attempts
            };
        }
        try {
            const outcome = await attemptEra(input, candidate, sourceSnapshot);
            const lossless = outcome === true || outcome?.lossless === true;
            attempts.push({
                era: candidate.era,
                format: candidate.format,
                lossless,
                reason: lossless ? expectation.basis : String(outcome?.reason || "native-ltd-validation-failed")
            });
            return {
                era: lossless ? "LTD" : null,
                classifier: MII_ERA_CLASSIFIER_ID,
                authority: expectation,
                attempts
            };
        } catch (error) {
            attempts.push({
                era: candidate.era,
                format: candidate.format,
                lossless: false,
                error: summarizedAttemptError(error)
            });
            return { era: null, classifier: MII_ERA_CLASSIFIER_ID, authority: expectation, attempts };
        }
    }

    for (const candidate of MII_ERA_ORDER) {
        // With no authenticated native source evidence, LTD is ineligible.
        if (candidate.era === "LTD") continue;
        try {
            const outcome = await attemptEra(input, candidate, sourceSnapshot);
            const lossless = outcome === true || outcome?.lossless === true;
            attempts.push({
                era: candidate.era,
                format: candidate.format,
                lossless,
                ...(outcome && typeof outcome === "object" ? {
                    ...(outcome.reason ? { reason: String(outcome.reason) } : {}),
                    ...(Array.isArray(outcome.mismatchPaths)
                        ? { mismatchPaths: outcome.mismatchPaths.map(String).slice(0, 16) }
                        : {}),
                    ...(Array.isArray(outcome.appDataMismatchKeys)
                        ? { appDataMismatchKeys: outcome.appDataMismatchKeys.map(String) }
                        : {})
                } : {})
            });
            if (lossless) {
                return { era: candidate.era, classifier: MII_ERA_CLASSIFIER_ID, attempts };
            }
        } catch (error) {
            attempts.push({
                era: candidate.era,
                format: candidate.format,
                lossless: false,
                error: summarizedAttemptError(error)
            });
        }
    }

    // Some edited/site-generated records no longer fit their source wire
    // format losslessly. A declared non-LTD console may resolve only that
    // otherwise-unclassified tail; it never overrides categories or a
    // successful semantic round trip, and it can never manufacture LTD.
    const fallback = declaredConsoleFallback(input);
    if (fallback) {
        attempts.push({
            era: fallback.era,
            format: MII_ERA_ORDER.find(candidate => candidate.era === fallback.era)?.format,
            lossless: false,
            reason: fallback.basis
        });
        return {
            era: fallback.era,
            classifier: MII_ERA_CLASSIFIER_ID,
            authority: fallback,
            attempts
        };
    }

    return { era: null, classifier: MII_ERA_CLASSIFIER_ID, attempts };
}

export async function assignMiiEra(mii, options = {}) {
    const result = await classifyMiiEra(mii, options);
    if (!result.era) {
        throw new MiiEraClassificationError(
            "This Mii has no authoritative source-era marker and does not round-trip losslessly through RCD, CFCD, FFCD, or CHARINFO.",
            { attempts: result.attempts }
        );
    }
    mii.era = result.era;
    return result;
}
