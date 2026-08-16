import miijs from "miijs";

import { getStoredLtdBytes } from "./ltdCanonical.js";
import { resolveMiiEraForRuntime } from "./miiEra.js";
import {
    MII_FACEPAINT_USAGE_NONE,
    classifyLtdFacepaintUsage,
    getRequestedMiiFacepaintFilters,
    isMiiExemptFromEraOrFacepaintSettings,
    normalizeBlockedFacepaintUsages,
    normalizeBlockedMiiEras
} from "./miiContentFilters.js";
import { getRequestedMiiEraFilters } from "./miiEraSearchFilters.js";

const effectiveClassificationMarker = Symbol("infinimii.effectiveMiiClassification");

/**
 * Fields which are not normally needed by a Mii card, but are required to
 * resolve stale era/facepaint metadata from its authoritative source.
 */
export const MII_EFFECTIVE_SEARCH_SELECT = [
    "+ltdData",
    "ltdVersion",
    "ltdCharInfo",
    "ltdConversionReport",
    "ltdProvenance.codec",
    "ltdProvenance.byteExact",
    "tl"
].join(" ");

export const MII_EFFECTIVE_SEARCH_PROJECT = Object.freeze({
    ltdData: 1,
    ltdVersion: 1,
    ltdCharInfo: 1,
    ltdConversionReport: 1,
    ltdProvenance: 1,
    tl: 1
});

function normalizeEffectiveEra(value) {
    const normalized = String(value || "").trim().toUpperCase();
    return normalized === "TL" ? "CFCD" : normalized;
}

/**
 * Resolve what Search must display and filter on. Stored era and facepaint
 * columns are only migration caches; they are never accepted as authoritative
 * for a native LTD result.
 */
export function resolveEffectiveMiiSearchClassification(mii) {
    const preclassified = mii?.[effectiveClassificationMarker];
    if (preclassified?.era && preclassified?.facepaintUsage) {
        return preclassified;
    }
    const era = normalizeEffectiveEra(resolveMiiEraForRuntime(mii));
    let facepaintUsage = MII_FACEPAINT_USAGE_NONE;

    // Facepaint is an LTD-native feature. Avoid parsing the site's generated
    // LTD export cache for the thousands of classic Miis which cannot use it.
    if (era === "LTD") {
        const ltdBytes = getStoredLtdBytes(mii);
        if (ltdBytes) {
            try {
                facepaintUsage = classifyLtdFacepaintUsage(
                    miijs.parseLtdContainer(ltdBytes)
                ).usage;
            } catch {
                // A corrupt/unverifiable source cannot be asserted to contain
                // facepaint. Era authentication independently fails closed in
                // resolveMiiEraForRuntime().
                facepaintUsage = MII_FACEPAINT_USAGE_NONE;
            }
        }
    }

    return Object.freeze({ era: era || null, facepaintUsage });
}

/** Search facepaint controls are positive/inclusion filters. Settings remain
 * negative blockers and are applied separately through the viewer argument. */
export function matchesEffectiveMiiSearchFilters(
    classification,
    filters = {},
    viewer = null,
    mii = null
) {
    const eraFilters = getRequestedMiiEraFilters(filters);
    const facepaintFilters = getRequestedMiiFacepaintFilters(filters);
    const era = normalizeEffectiveEra(classification?.era);
    const facepaintUsage = String(
        classification?.facepaintUsage || MII_FACEPAINT_USAGE_NONE
    ).trim().toLowerCase();

    if (eraFilters.isActive && !eraFilters.eras.includes(era)) return false;
    if (
        facepaintFilters.isActive
        && !facepaintFilters.facepaintUsages.includes(facepaintUsage)
    ) return false;

    // Explicit Search controls remain authoritative even for the two Settings
    // exemptions. Only the viewer's negative era/facepaint preferences are
    // bypassed for Average and that viewer's own current profile Mii.
    if (viewer && !isMiiExemptFromEraOrFacepaintSettings(mii, viewer)) {
        if (normalizeBlockedMiiEras(viewer.blockedMiiEras).includes(era)) return false;
        if (
            normalizeBlockedFacepaintUsages(viewer.blockedFacepaintUsages)
                .includes(facepaintUsage)
        ) return false;
    }
    return true;
}

export function classifyAndMatchEffectiveMiiSearchFilters(mii, filters = {}, viewer = null) {
    const classification = resolveEffectiveMiiSearchClassification(mii);
    return Object.freeze({
        classification,
        matches: matchesEffectiveMiiSearchFilters(classification, filters, viewer, mii)
    });
}

/**
 * Do not leak the large source container or classification-only fields into
 * EJS/structured-data output. Preserve the small provenance subset Mii cards
 * already consume.
 */
export function withEffectiveMiiSearchClassification(mii, classification) {
    const effectiveClassification = Object.freeze({
        era: classification?.era || null,
        facepaintUsage: classification?.facepaintUsage || MII_FACEPAINT_USAGE_NONE
    });
    const result = {
        ...mii,
        era: effectiveClassification.era,
        facepaintUsage: effectiveClassification.facepaintUsage
    };
    delete result.ltdData;
    delete result.ltdVersion;
    delete result.ltdCharInfo;
    delete result.ltdConversionReport;
    delete result.tl;

    if (result.ltdProvenance && typeof result.ltdProvenance === "object") {
        const provenance = result.ltdProvenance;
        result.ltdProvenance = {
            kind: provenance.kind,
            sourceFormat: provenance.sourceFormat,
            sourceKind: provenance.sourceKind,
            byteExactSourceClaimed: provenance.byteExactSourceClaimed,
            appearanceProjectionExact: provenance.appearanceProjectionExact
        };
    }
    Object.defineProperty(result, effectiveClassificationMarker, {
        value: effectiveClassification,
        enumerable: false,
        configurable: false,
        writable: false
    });
    return result;
}
