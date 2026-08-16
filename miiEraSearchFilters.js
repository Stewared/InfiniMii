import { MII_ERA_VALUES } from "./miiEra.js";

const MII_ERA_LABELS = Object.freeze({
    RCD: "RCD (Wii / Nintendo DS)",
    CFCD: "CFCD (Nintendo 3DS / Tomodachi Life)",
    FFCD: "FFCD (Wii U)",
    CHARINFO: "CHARINFO (Nintendo Switch)",
    LTD: "LTD"
});

const MII_ERA_ALIASES = new Map([
    ...MII_ERA_VALUES.map(era => [era, era]),
    ["TL", "CFCD"]
]);

const STORED_MII_ERAS = Object.freeze({
    RCD: Object.freeze(["RCD"]),
    // TL was the legacy database value for the same 3DS/Tomodachi-era bucket.
    CFCD: Object.freeze(["CFCD", "TL"]),
    FFCD: Object.freeze(["FFCD"]),
    CHARINFO: Object.freeze(["CHARINFO"]),
    LTD: Object.freeze(["LTD"])
});

export const MII_ERA_FILTER_OPTIONS = Object.freeze(MII_ERA_VALUES.map(era => Object.freeze({
    value: era,
    label: MII_ERA_LABELS[era] || era
})));

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

function normalizeRequestedEraValues(value) {
    const requestedValues = Array.isArray(value) ? value : [value];
    const selectedSet = new Set();

    for (const requestedValue of requestedValues) {
        if (typeof requestedValue !== "string") continue;
        const canonicalEra = MII_ERA_ALIASES.get(requestedValue.trim().toUpperCase());
        if (canonicalEra) selectedSet.add(canonicalEra);
    }

    return MII_ERA_VALUES.filter(era => selectedSet.has(era));
}

/**
 * Resolve the checked era toggles from a request-like object.
 *
 * All eras are enabled until the form's configured marker is submitted. The
 * marker lets an intentionally empty checkbox set mean "show no eras" rather
 * than being mistaken for the default state.
 */
export function getRequestedMiiEraFilters(source = {}) {
    const configuredKey = own(source, "eraFiltersConfigured")
        ? "eraFiltersConfigured"
        : (own(source, "miiEraFiltersConfigured") ? "miiEraFiltersConfigured" : null);
    const selectionKey = ["eras", "miiEras", "era", "selectedEras"]
        .find(key => own(source, key));
    const explicitlyConfigured = configuredKey
        ? parseBooleanLike(source[configuredKey])
        : Boolean(selectionKey);
    const selectedEras = explicitlyConfigured
        ? normalizeRequestedEraValues(selectionKey ? source[selectionKey] : [])
        : [...MII_ERA_VALUES];
    const selectedSet = new Set(selectedEras);
    const excludedEras = MII_ERA_VALUES.filter(era => !selectedSet.has(era));

    return {
        eras: selectedEras,
        excludedEras,
        eraFiltersConfigured: explicitlyConfigured,
        isActive: excludedEras.length > 0
    };
}

/** Add the selected-era constraint to an existing Mongo query. */
export function applyMiiEraSearchFilter(query, filters = {}) {
    if (!query || typeof query !== "object" || Array.isArray(query)) return query;

    const normalizedFilters = getRequestedMiiEraFilters(filters);
    if (!normalizedFilters.isActive) return query;

    const storedEras = normalizedFilters.eras.flatMap(era => STORED_MII_ERAS[era] || []);
    query.$and = [
        ...(Array.isArray(query.$and) ? query.$and : []),
        { era: { $in: storedEras } }
    ];
    return query;
}

