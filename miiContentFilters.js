import { decompress as decompressZstandard } from "fzstd";

export const BLOCKABLE_MII_ERA_VALUES = Object.freeze([
    "RCD",
    "CFCD",
    "FFCD",
    "CHARINFO",
    "LTD"
]);

export const MII_FACEPAINT_USAGE_NONE = "none";
export const MII_FACEPAINT_USAGE_PARTIAL = "partial";
export const MII_FACEPAINT_USAGE_FULL = "full";

export const MII_FACEPAINT_FILTER_OPTIONS = Object.freeze([
    Object.freeze({
        value: MII_FACEPAINT_USAGE_PARTIAL,
        label: "Uses Partial Facepaint"
    }),
    Object.freeze({
        value: MII_FACEPAINT_USAGE_FULL,
        label: "Uses Full Facepaint"
    })
]);

export const MII_FACEPAINT_BLOCKABLE_VALUES = Object.freeze(
    MII_FACEPAINT_FILTER_OPTIONS.map(option => option.value)
);

export const MII_FACEPAINT_CLASSIFIER_VERSION = 1;
export const MII_FACEPAINT_CLASSIFICATION_POLICY = "infinimii-opaque-coverage-v1";
export const MII_FACEPAINT_TOTAL_PIXELS = 512 * 512;
export const AVERAGE_MII_ID = "average";
// ShareMii stores the native texture but no partial/full enum. InfiniMii policy
// v1 calls at least one eighth of the complete UGC texture "full". That exact,
// BC1-block-aligned boundary lies well inside the audited corpus gap between
// the localized sample (1,421 pixels) and full-face samples (60,198+ pixels).
// It is a stable site policy, not a title-defined semantic; changing it requires
// a classifier-version bump and a metadata backfill.
export const MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD = MII_FACEPAINT_TOTAL_PIXELS / 8;

const MII_ERA_ALIASES = new Map([
    ...BLOCKABLE_MII_ERA_VALUES.map(era => [era, era]),
    ["TL", "CFCD"]
]);

function own(object, key) {
    return Object.prototype.hasOwnProperty.call(object || {}, key);
}

function firstValue(value) {
    return Array.isArray(value) ? value[0] : value;
}

function parseBooleanLike(value) {
    const normalized = firstValue(value);
    if (typeof normalized === "boolean") return normalized;
    if (typeof normalized === "number") return normalized === 1;
    if (typeof normalized !== "string") return false;
    return ["1", "true", "yes", "on"].includes(normalized.trim().toLowerCase());
}

function asList(value) {
    if (Array.isArray(value)) return value;
    return value == null ? [] : [value];
}

export function normalizeBlockedMiiEras(value) {
    const selected = new Set();
    for (const item of asList(value)) {
        if (typeof item !== "string") continue;
        const era = MII_ERA_ALIASES.get(item.trim().toUpperCase());
        if (era) selected.add(era);
    }
    return BLOCKABLE_MII_ERA_VALUES.filter(era => selected.has(era));
}

export function normalizeBlockedFacepaintUsages(value) {
    const selected = new Set(
        asList(value)
            .filter(item => typeof item === "string")
            .map(item => item.trim().toLowerCase())
    );
    return MII_FACEPAINT_BLOCKABLE_VALUES.filter(usage => selected.has(usage));
}

function normalizeContentExemptionMiiId(value) {
    if (typeof value !== "string") return "";
    const normalized = value.trim();
    // Stored/manual Mii IDs are short alphanumeric values. Keep the fixed
    // Average Mii identifier explicit and reject malformed session data so it
    // can never broaden a Mongo query through an unexpected value type.
    if (normalized === AVERAGE_MII_ID) return normalized;
    return /^[A-Za-z0-9]{1,10}$/.test(normalized) ? normalized : "";
}

/**
 * Content preferences are display settings, not access controls. The Average
 * Mii and the signed-in viewer's current profile Mii must remain reachable
 * even when one of their tags, categories, era, facepaint classifications, or
 * IDs is selected in Settings.
 */
export function getMiiContentSettingsExemptIds(user) {
    const ids = [AVERAGE_MII_ID];
    const profileMiiId = normalizeContentExemptionMiiId(user?.miiPfp);
    if (profileMiiId && !ids.includes(profileMiiId)) ids.push(profileMiiId);
    return ids;
}

export function isMiiExemptFromEraOrFacepaintSettings(mii, user) {
    const miiId = normalizeContentExemptionMiiId(mii?.id);
    return Boolean(miiId && getMiiContentSettingsExemptIds(user).includes(miiId));
}

/** Generic name for the same identity exemption. Keep the older exported
 * name for compatibility with callers that specifically evaluate effective
 * era/facepaint classifications. */
export function isMiiExemptFromContentSettings(mii, user) {
    return isMiiExemptFromEraOrFacepaintSettings(mii, user);
}

/** Preserve the two protected identities while applying one stored-content
 * preference predicate. Anonymous defaults are intentionally not Settings
 * preferences and therefore are not wrapped here. */
export function preserveMiiContentSettingsExemptions(condition, user) {
    if (!user) return condition;
    return {
        $or: [
            { id: { $in: getMiiContentSettingsExemptIds(user) } },
            condition
        ]
    };
}

export function classifyDecodedLtdFacepaintBc1(blockLinearBytes) {
    const bytes = blockLinearBytes instanceof Uint8Array
        ? blockLinearBytes
        : new Uint8Array(blockLinearBytes || []);
    if (bytes.byteLength !== MII_FACEPAINT_TOTAL_PIXELS / 2) {
        throw new TypeError(
            `LTD UGC facepaint must decode to ${MII_FACEPAINT_TOTAL_PIXELS / 2} BC1 bytes.`
        );
    }

    let opaquePixels = 0;
    for (let offset = 0; offset < bytes.byteLength; offset += 8) {
        const color0 = bytes[offset] | (bytes[offset + 1] << 8);
        const color1 = bytes[offset + 2] | (bytes[offset + 3] << 8);
        if (color0 > color1) {
            opaquePixels += 16;
            continue;
        }

        const selectors = (
            bytes[offset + 4]
            | (bytes[offset + 5] << 8)
            | (bytes[offset + 6] << 16)
            | (bytes[offset + 7] << 24)
        ) >>> 0;
        for (let pixel = 0; pixel < 16; pixel += 1) {
            if (((selectors >>> (pixel * 2)) & 0x03) !== 0x03) opaquePixels += 1;
        }
    }
    const usage = opaquePixels === 0
        ? MII_FACEPAINT_USAGE_NONE
        : (opaquePixels >= MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD
            ? MII_FACEPAINT_USAGE_FULL
            : MII_FACEPAINT_USAGE_PARTIAL);
    return Object.freeze({
        usage,
        classifierVersion: MII_FACEPAINT_CLASSIFIER_VERSION,
        policy: MII_FACEPAINT_CLASSIFICATION_POLICY,
        source: "ltd-ugc-bc1-alpha",
        opaquePixels,
        totalPixels: MII_FACEPAINT_TOTAL_PIXELS,
        fullThresholdPixels: MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD,
        coverage: opaquePixels / MII_FACEPAINT_TOTAL_PIXELS
    });
}

/**
 * Measure visible LTD facepaint from the native ShareMii payload itself.
 * Canvas is editor state; UGC BC1 alpha is the title render texture, and block
 * order cannot affect the number of opaque pixels. No screenshot, name, tag,
 * compressed-size guess, or projected classic Mii field participates. The
 * resulting partial/full grouping uses InfiniMii's versioned coverage policy;
 * ShareMii does not store those labels.
 */
export function classifyLtdFacepaintUsage(parsedLtd) {
    const hasCanvas = parsedLtd?.header?.hasCanvas === true;
    const hasUgcTexture = parsedLtd?.header?.hasUgcTexture === true;
    if (hasCanvas !== hasUgcTexture) {
        throw new TypeError("LTD facepaint Canvas and UGC presence flags must agree.");
    }
    if (!hasCanvas) {
        return Object.freeze({
            usage: MII_FACEPAINT_USAGE_NONE,
            classifierVersion: MII_FACEPAINT_CLASSIFIER_VERSION,
            policy: MII_FACEPAINT_CLASSIFICATION_POLICY,
            source: "ltd-ugc-bc1-alpha",
            opaquePixels: 0,
            totalPixels: MII_FACEPAINT_TOTAL_PIXELS,
            fullThresholdPixels: MII_FACEPAINT_FULL_OPAQUE_PIXEL_THRESHOLD,
            coverage: 0
        });
    }

    const encoded = parsedLtd?.ugcTexturePayload?.data;
    if (!encoded || Number(parsedLtd?.ugcTexturePayload?.byteLength || 0) < 1) {
        throw new TypeError("LTD UGC facepaint is flagged present but has no payload.");
    }
    return classifyDecodedLtdFacepaintBc1(decompressZstandard(encoded));
}

export function getMiiFacepaintUsage(mii) {
    const value = String(mii?.facepaintUsage || "").trim().toLowerCase();
    return [
        MII_FACEPAINT_USAGE_NONE,
        MII_FACEPAINT_USAGE_PARTIAL,
        MII_FACEPAINT_USAGE_FULL
    ].includes(value) ? value : MII_FACEPAINT_USAGE_NONE;
}

export function getRequestedMiiFacepaintFilters(source = {}) {
    const configuredKey = own(source, "facepaintFiltersConfigured")
        ? "facepaintFiltersConfigured"
        : (own(source, "miiFacepaintFiltersConfigured") ? "miiFacepaintFiltersConfigured" : null);
    const selectionKey = ["facepaintUsages", "facepaintUsage", "allowedFacepaintUsages"]
        .find(key => own(source, key));
    const explicitlyConfigured = configuredKey
        ? parseBooleanLike(source[configuredKey])
        : Boolean(selectionKey);
    // Search facepaint controls are opt-in inclusion filters. Merely submitting
    // the form's configured marker with neither box selected means "Any";
    // selecting one or both categories means show only those painted Miis.
    // Settings use normalizeBlockedFacepaintUsages() independently as blockers.
    const selectedUsages = explicitlyConfigured && selectionKey
        ? normalizeBlockedFacepaintUsages(source[selectionKey])
        : [];
    const selectedSet = new Set(selectedUsages);
    const excludedFacepaintUsages = MII_FACEPAINT_BLOCKABLE_VALUES
        .filter(usage => !selectedSet.has(usage));

    return {
        facepaintUsages: selectedUsages,
        excludedFacepaintUsages,
        facepaintFiltersConfigured: explicitlyConfigured,
        isActive: selectedUsages.length > 0
    };
}

/** Preserve each content filter group's activity when their normalized
 * results are combined. Both normalizers expose `isActive`, so a plain object
 * spread would otherwise let the later facepaint value mask an era-only
 * selection in the search UI. */
export function combineRequestedMiiContentFilters(eraFilters = {}, facepaintFilters = {}) {
    return {
        ...eraFilters,
        ...facepaintFilters,
        eraFiltersActive: Boolean(eraFilters.isActive),
        facepaintFiltersActive: Boolean(facepaintFilters.isActive),
        isActive: Boolean(eraFilters.isActive || facepaintFilters.isActive)
    };
}

/** Apply positive facepaint inclusion to a stored-metadata query. Search's
 * production path resolves the same predicate from native data before paging. */
export function applyMiiFacepaintSearchFilter(query, filters = {}) {
    if (!query || typeof query !== "object" || Array.isArray(query)) return query;
    const normalized = getRequestedMiiFacepaintFilters(filters);
    if (!normalized.isActive) return query;
    query.$and = [
        ...(Array.isArray(query.$and) ? query.$and : []),
        { facepaintUsage: { $in: normalized.facepaintUsages } }
    ];
    return query;
}

export function buildBlockedContentConditions(user) {
    if (!user) return [];
    const blockedEras = normalizeBlockedMiiEras(user.blockedMiiEras);
    const blockedStoredEras = blockedEras.flatMap(era => era === "CFCD" ? ["CFCD", "TL"] : [era]);
    const blockedFacepaintUsages = normalizeBlockedFacepaintUsages(user.blockedFacepaintUsages);
    return [
        ...(blockedStoredEras.length > 0
            ? [preserveMiiContentSettingsExemptions(
                { era: { $nin: blockedStoredEras } },
                user
            )]
            : []),
        ...(blockedFacepaintUsages.length > 0
            ? [preserveMiiContentSettingsExemptions(
                { facepaintUsage: { $nin: blockedFacepaintUsages } },
                user
            )]
            : [])
    ];
}

export function isMiiBlockedByEraOrFacepaint(mii, user) {
    if (!mii || !user) return false;
    if (isMiiExemptFromEraOrFacepaintSettings(mii, user)) return false;
    const era = MII_ERA_ALIASES.get(String(mii.era || "").trim().toUpperCase());
    if (era && normalizeBlockedMiiEras(user.blockedMiiEras).includes(era)) return true;
    return normalizeBlockedFacepaintUsages(user.blockedFacepaintUsages)
        .includes(getMiiFacepaintUsage(mii));
}
