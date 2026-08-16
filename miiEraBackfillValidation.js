import miijs from "miijs";

import {
    LTD_CODEC_ID,
    isGeneratedLtdShareMiiCompatibility
} from "./ltdCanonical.js";

// This module deliberately does not import miiEra.js. The backfill uses it as
// an independent check that raw official-category precedence agrees with the
// classifier result, rather than asking the classifier to validate itself.

function normalizedCategorySegment(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}

function officialCategoryRoots(input) {
    const categories = Array.isArray(input?.officialCategories) ? input.officialCategories : [];
    return new Set(categories.map(path => (
        normalizedCategorySegment(String(path || "").split(/[>/]/, 1)[0])
    )).filter(Boolean));
}

function hasRoot(roots, ...aliases) {
    return aliases.some(alias => roots.has(alias));
}

/**
 * Independently derive the era imposed by raw official-category roots.
 * Presence in officialCategories is the authority; the separate `official`
 * flag is audited as consistency metadata and does not disable a category.
 */
export function getBackfillOfficialCategoryExpectation(input) {
    const roots = officialCategoryRoots(input);
    if (hasRoot(roots, "wii", "nintendo wii")) {
        return Object.freeze({ era: "RCD", basis: "official-wii-category" });
    }
    if (hasRoot(roots, "ds", "nintendo ds")) {
        return Object.freeze({ era: "RCD", basis: "official-ds-category" });
    }
    if (hasRoot(roots, "3ds", "nintendo 3ds", "tl", "tomodachi life")) {
        return Object.freeze({ era: "CFCD", basis: "official-3ds-or-tl-category" });
    }
    if (hasRoot(roots, "switch", "nintendo switch")) {
        return Object.freeze({ era: "CHARINFO", basis: "official-switch-category" });
    }
    if (hasRoot(roots, "wii u", "nintendo wii u")) {
        return Object.freeze({ era: "FFCD", basis: "official-wii-u-category" });
    }
    return null;
}

export function validateBackfillOfficialCategoryEra(input, actualEra) {
    const expectation = getBackfillOfficialCategoryExpectation(input);
    if (!expectation) {
        return Object.freeze({ checked: false, valid: true, expectation: null, violation: null });
    }
    const normalizedActualEra = actualEra || null;
    const valid = normalizedActualEra === expectation.era;
    return Object.freeze({
        checked: true,
        valid,
        expectation,
        violation: valid ? null : Object.freeze({
            code: "raw-official-category-era-mismatch",
            expectedEra: expectation.era,
            actualEra: normalizedActualEra,
            basis: expectation.basis
        })
    });
}

/**
 * Independently audit LTD eligibility at the storage boundary. This repeats
 * the migration's current-corpus trust contract without importing the
 * classifier helper: native provenance must have the exact upload shape,
 * generated conversion residue is forbidden, and bytes must be a nonempty
 * stored payload with a matching SHA-256 supplied by the caller.
 */
export async function validateBackfillLtdEraEvidence(input, actualEra, { storedBytes, storedSha256 } = {}) {
    if (actualEra !== "LTD") {
        return Object.freeze({ checked: false, valid: true, violation: null });
    }
    const provenance = input?.ltdProvenance;
    const keys = provenance && typeof provenance === "object" ? Object.keys(provenance).sort() : [];
    const expectedHash = String(input?.ltdSha256 || "").trim().toLowerCase();
    let parsed = null;
    let byteExactRoundTrip = false;
    try {
        parsed = miijs.parseLtdContainer(storedBytes);
        const decoded = await miijs.Mii.create(storedBytes);
        const reencoded = Buffer.from(await decoded.encode(miijs.MiiFormats.LTD));
        byteExactRoundTrip = reencoded.equals(storedBytes);
    } catch {
        parsed = null;
        byteExactRoundTrip = false;
    }
    // Repeat the classifier's byte-intrinsic exclusion independently of its
    // provenance decision. A generated compatibility envelope cannot become
    // native LTD evidence merely by relabeling its metadata.
    const intrinsicNativeShape = Boolean(parsed)
        && !isGeneratedLtdShareMiiCompatibility(storedBytes);
    const declaredConsole = normalizedCategorySegment(input?.meta?.console || input?.console);
    const valid = Boolean(
        Buffer.isBuffer(storedBytes)
        && storedBytes.length > 0
        && /^[a-f0-9]{64}$/.test(expectedHash)
        && String(storedSha256 || "").toLowerCase() === expectedHash
        && provenance?.kind === "native-upload"
        && provenance?.codec === LTD_CODEC_ID
        && provenance?.sourceFormat === "ltd"
        && provenance?.byteExact === true
        && keys.length === 4
        && keys.includes("codec")
        && keys.includes("kind")
        && keys.includes("sourceFormat")
        && keys.includes("byteExact")
        && input?.ltdConversionReport == null
        && input?.ltdCharInfo
        && declaredConsole === "ltd"
        && Number(input?.ltdVersion) === Number(parsed?.version)
        && byteExactRoundTrip
        && intrinsicNativeShape
    );
    return Object.freeze({
        checked: true,
        valid,
        violation: valid ? null : Object.freeze({ code: "independent-non-native-ltd" })
    });
}
