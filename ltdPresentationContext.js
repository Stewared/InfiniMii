import crypto from "node:crypto";

const CONTEXT_DOMAIN = "InfiniMii/LTD/presentation-context/v1\0";
export const LTD_PRESENTATION_CONTEXT_KIND = "legacy-collapsed-hair-headwear-v1";
export const INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND = "infinimii-favorite-shirt-v1";
export const LTD_PRESENTATION_CONTEXT_NONE = "none";
export const INFINIMII_FAVORITE_SHIRT_RGB = Object.freeze([
    "D21E14", "FF6E19", "FFD820", "78D220", "007830", "0A48B4",
    "3CAAE0", "F55A7D", "7328AD", "483818", "E0E0E0", "181814"
]);
export const INFINIMII_FAVORITE_SHIRT_VARIATIONS = Object.freeze([
    8, 3, 4, 10, 11, 16, 14, 6, 15, 1, 0, 0
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/i;
const LEGACY_HEADWEAR_SOURCE_TYPES = new Set([34, 57]);

function sha256Text(value) {
    return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeLegacyHeadwearContext(context) {
    const expectedKeys = new Set([
        "schemaVersion", "kind", "ltdSha256", "canonicalHairType", "sourceHairType"
    ]);
    if (Object.keys(context).some(key => !expectedKeys.has(key)) || Object.keys(context).length !== expectedKeys.size) {
        throw new TypeError("LTD presentation context schema is invalid.");
    }
    if (
        typeof context.schemaVersion !== "number"
        || typeof context.kind !== "string"
        || typeof context.ltdSha256 !== "string"
        || typeof context.canonicalHairType !== "number"
        || typeof context.sourceHairType !== "number"
        || !Number.isInteger(context.schemaVersion)
        || !Number.isInteger(context.canonicalHairType)
        || !Number.isInteger(context.sourceHairType)
    ) {
        throw new TypeError("LTD presentation context field types are invalid.");
    }
    const normalized = {
        schemaVersion: context.schemaVersion,
        kind: context.kind,
        ltdSha256: context.ltdSha256.toLowerCase(),
        canonicalHairType: context.canonicalHairType,
        sourceHairType: context.sourceHairType
    };
    if (
        normalized.schemaVersion !== 1
        || normalized.kind !== LTD_PRESENTATION_CONTEXT_KIND
        || !SHA256_PATTERN.test(normalized.ltdSha256)
        || normalized.canonicalHairType !== 45
        || !LEGACY_HEADWEAR_SOURCE_TYPES.has(normalized.sourceHairType)
    ) {
        throw new TypeError("LTD presentation context is outside the checked legacy-headwear domain.");
    }
    return Object.freeze(normalized);
}

function normalizeFavoriteShirtContext(context) {
    const expectedKeys = new Set([
        "schemaVersion", "kind", "ltdSha256", "favoriteColor", "legacyHeadwearSourceType"
    ]);
    if (Object.keys(context).some(key => !expectedKeys.has(key)) || Object.keys(context).length !== expectedKeys.size) {
        throw new TypeError("LTD favorite-shirt presentation context schema is invalid.");
    }
    if (
        context.schemaVersion !== 1
        || context.kind !== INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
        || typeof context.ltdSha256 !== "string"
        || !SHA256_PATTERN.test(context.ltdSha256)
        || !Number.isInteger(context.favoriteColor)
        || context.favoriteColor < 0
        || context.favoriteColor >= INFINIMII_FAVORITE_SHIRT_RGB.length
        || (
            context.legacyHeadwearSourceType !== null
            && !LEGACY_HEADWEAR_SOURCE_TYPES.has(context.legacyHeadwearSourceType)
        )
    ) {
        throw new TypeError("LTD presentation context is outside the InfiniMii favorite-shirt policy domain.");
    }
    return Object.freeze({
        schemaVersion: 1,
        kind: INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
        ltdSha256: context.ltdSha256.toLowerCase(),
        favoriteColor: context.favoriteColor,
        legacyHeadwearSourceType: context.legacyHeadwearSourceType
    });
}

export function normalizeLtdPresentationContext(context) {
    if (!context || typeof context !== "object" || Array.isArray(context)) {
        throw new TypeError("LTD presentation context must be an object.");
    }
    if (context.kind === INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND) {
        return normalizeFavoriteShirtContext(context);
    }
    return normalizeLegacyHeadwearContext(context);
}

export function getLtdPresentationContextSha256(context) {
    if (!context) return sha256Text(`${CONTEXT_DOMAIN}${LTD_PRESENTATION_CONTEXT_NONE}`);
    const normalized = normalizeLtdPresentationContext(context);
    if (normalized.kind === INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND) {
        return sha256Text(
            `${CONTEXT_DOMAIN}${normalized.kind}\0${normalized.ltdSha256}\0${normalized.favoriteColor}\0${normalized.legacyHeadwearSourceType ?? "none"}`
        );
    }
    return sha256Text(
        `${CONTEXT_DOMAIN}${normalized.kind}\0${normalized.ltdSha256}\0${normalized.canonicalHairType}\0${normalized.sourceHairType}`
    );
}

function isSourceBackedCanonicalRegeneration(mii) {
    const provenance = mii?.ltdProvenance;
    return provenance?.kind === "canonical-regenerated-charinfo"
        && provenance?.sourceKind === "normalized-site-fields"
        && provenance?.byteExactSourceClaimed === false
        && provenance?.appearanceProjectionExact === true;
}

function resolveLegacyHeadwearSourceType(mii, canonicalHairType) {
    const sourceHairType = Number(mii?.hair?.type);
    return isSourceBackedCanonicalRegeneration(mii)
        && LEGACY_HEADWEAR_SOURCE_TYPES.has(sourceHairType)
        && Number(canonicalHairType) === 45
        ? sourceHairType
        : null;
}

// This is an explicit InfiniMii presentation policy, not a title claim. The
// ShareMii/LTD projection cannot retain FavoriteColor, so only the original
// stored/source CharInfo field may opt in and the result is bound to LTD bytes.
export function resolveStoredLtdPresentationContext(mii, { canonicalHairType = 45 } = {}) {
    const ltdSha256 = String(mii?.ltdSha256 || "").toLowerCase();
    if (!SHA256_PATTERN.test(ltdSha256)) return null;

    const sourceBackedCanonicalRegeneration = isSourceBackedCanonicalRegeneration(mii);
    const legacyHeadwearSourceType = resolveLegacyHeadwearSourceType(mii, canonicalHairType);
    const favoriteColor = mii?.general?.favoriteColor;
    if (
        sourceBackedCanonicalRegeneration
        && Number.isInteger(favoriteColor)
        && favoriteColor >= 0
        && favoriteColor < INFINIMII_FAVORITE_SHIRT_RGB.length
    ) {
        return normalizeLtdPresentationContext({
            schemaVersion: 1,
            kind: INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
            ltdSha256,
            favoriteColor,
            legacyHeadwearSourceType
        });
    }

    if (legacyHeadwearSourceType === null) return null;
    return normalizeLtdPresentationContext({
        schemaVersion: 1,
        kind: LTD_PRESENTATION_CONTEXT_KIND,
        ltdSha256,
        canonicalHairType: 45,
        sourceHairType: legacyHeadwearSourceType
    });
}

export function getFavoriteShirtPolicy(context) {
    if (!context) return null;
    const normalized = normalizeLtdPresentationContext(context);
    if (normalized.kind !== INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND) return null;
    return Object.freeze({
        policy: INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
        favoriteColor: normalized.favoriteColor,
        rgbHex: INFINIMII_FAVORITE_SHIRT_RGB[normalized.favoriteColor],
        authoredVariation: INFINIMII_FAVORITE_SHIRT_VARIATIONS[normalized.favoriteColor],
        authoredAlbedo: `ClothTopsTshirtLongTexDefault_Body_Alb.${String(INFINIMII_FAVORITE_SHIRT_VARIATIONS[normalized.favoriteColor]).padStart(2, "0")}`,
        sourceField: "general.favoriteColor",
        titleExact: false
    });
}

export function getLegacyHeadwearSourceType(context) {
    if (!context) return null;
    const normalized = normalizeLtdPresentationContext(context);
    return normalized.kind === INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
        ? normalized.legacyHeadwearSourceType
        : normalized.sourceHairType;
}

export function getStoredLtdPresentationContextIdentity(mii) {
    const context = resolveStoredLtdPresentationContext(mii);
    return {
        kind: context?.kind || LTD_PRESENTATION_CONTEXT_NONE,
        sha256: getLtdPresentationContextSha256(context)
    };
}
