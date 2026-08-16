import {
    hasAuthenticatedNativeLtdEvidence,
    resolveMiiEraForRuntime
} from "./miiEra.js";

const KNOWN_NON_LTD_ERAS = new Set(["RCD", "TL", "CFCD", "FFCD", "CHARINFO"]);

export const LTD_EXCLUSIVE_FEATURE_EXEMPT_MII_IDS = Object.freeze(["average"]);
const LTD_EXCLUSIVE_FEATURE_EXEMPT_MII_ID_SET = new Set(LTD_EXCLUSIVE_FEATURE_EXEMPT_MII_IDS);

export const LTD_ONLY_EXPORT_FORMATS = Object.freeze([
    Object.freeze({ value: "ltd", label: "Living the Dream ShareMii (.ltd)" })
]);

export const LTD_ONLY_DOWNLOAD_MESSAGE =
    "LTD-era Miis can only be downloaded or exported in LTD format.";

export const LTD_WORKSPACE_UNAVAILABLE_CODE = "LTD_WORKSPACE_UNAVAILABLE";
export const LTD_WORKSPACE_UNAVAILABLE_MESSAGES = Object.freeze({
    dashboard: "LTD-era Miis are temporarily unavailable in the Mii Dashboard.",
    kidomatic: "LTD-era Miis are temporarily unavailable in Kidomatic.",
    workspace: "LTD-era Miis are temporarily unavailable in this workspace."
});

export class LtdOnlyDownloadError extends Error {
    constructor(message = LTD_ONLY_DOWNLOAD_MESSAGE) {
        super(message);
        this.name = "LtdOnlyDownloadError";
        this.code = "LTD_ONLY_DOWNLOAD";
        this.status = 400;
    }
}

function normalizeLtdWorkspaceFeature(value) {
    const normalized = String(value || "").trim().toLowerCase();
    if (["dashboard", "mii-dashboard", "miidashboard"].includes(normalized)) return "dashboard";
    if (normalized === "kidomatic") return "kidomatic";
    return "workspace";
}

export function getLtdWorkspaceUnavailableMessage(feature) {
    return LTD_WORKSPACE_UNAVAILABLE_MESSAGES[normalizeLtdWorkspaceFeature(feature)];
}

export class LtdWorkspaceUnavailableError extends Error {
    constructor(feature = "workspace") {
        const normalizedFeature = normalizeLtdWorkspaceFeature(feature);
        super(getLtdWorkspaceUnavailableMessage(normalizedFeature));
        this.name = "LtdWorkspaceUnavailableError";
        this.code = LTD_WORKSPACE_UNAVAILABLE_CODE;
        this.status = 422;
        this.feature = normalizedFeature;
    }
}

export function normalizeMiiDownloadEra(value) {
    return typeof value === "string" ? value.trim().toUpperCase() : "";
}

function getMiiPolicyId(mii) {
    const source = mii?.fields && typeof mii.fields === "object" ? mii.fields : mii;
    const value = source?.id ?? mii?.id;
    return typeof value === "string" ? value.trim() : "";
}

/**
 * The generated Average Mii is a site utility rather than a source-file
 * archive entry. It may still use LTD rendering/canonical data, but LTD-only
 * capabilities must never make it impossible to export in classic formats.
 */
export function isLtdExclusiveFeatureExemptMii(mii) {
    return LTD_EXCLUSIVE_FEATURE_EXEMPT_MII_ID_SET.has(getMiiPolicyId(mii));
}

export function isLtdEraMii(mii, _options = {}) {
    const era = normalizeMiiDownloadEra(resolveMiiEraForRuntime(mii));
    if (era === "LTD") return true;
    if (KNOWN_NON_LTD_ERAS.has(era)) return false;

    // Native LTD uploads carry their source-era evidence independently of the
    // backfilled era field. Keep them fail-closed if that field is absent or
    // unknown, but an explicit classified non-LTD era has higher precedence.
    return hasAuthenticatedNativeLtdEvidence(mii);
}

/**
 * True only when LTD-exclusive capabilities must be enforced. Rendering with
 * LTD is an ordinary renderer choice and is deliberately outside this lock.
 */
export function isLtdExclusiveFeatureLockedMii(mii, options = {}) {
    return isLtdEraMii(mii, options) && !isLtdExclusiveFeatureExemptMii(mii);
}

/**
 * Temporarily keep LTD-exclusive Miis out of decoded workspaces.
 *
 * Dashboard JSON intentionally contains only ordinary Mii data, so a native
 * LTD loses its era, provenance, and authoritative bytes there. Preserve the
 * remaining `console: "LTD"` marker as a workspace-only restriction without
 * weakening the ordinary runtime-era precedence rules. In particular, an
 * explicit/classified classic era and the generated Average Mii exemption
 * continue to win.
 */
export function isLtdWorkspaceAccessUnavailable(mii, options = {}) {
    if (isLtdExclusiveFeatureExemptMii(mii)) return false;
    if (isLtdExclusiveFeatureLockedMii(mii, options)) return true;

    const era = normalizeMiiDownloadEra(resolveMiiEraForRuntime(mii));
    if (KNOWN_NON_LTD_ERAS.has(era)) return false;

    const source = mii?.fields && typeof mii.fields === "object" ? mii.fields : mii;
    return [source?.console, source?.meta?.console]
        .some(value => normalizeMiiDownloadEra(value) === "LTD");
}

export function assertLtdWorkspaceAccessAvailable(mii, feature, options = {}) {
    if (isLtdWorkspaceAccessUnavailable(mii, options)) {
        throw new LtdWorkspaceUnavailableError(feature);
    }
    return true;
}

export function getMiiDownloadPolicy(mii, options = {}) {
    const era = normalizeMiiDownloadEra(resolveMiiEraForRuntime(mii));
    if (isLtdExclusiveFeatureExemptMii(mii)) {
        return Object.freeze({
            era,
            ltdOnly: false,
            ltdExclusiveExempt: true,
            reason: "ltd-exclusive-feature-exempt",
            message: ""
        });
    }

    if (isLtdExclusiveFeatureLockedMii(mii, options)) {
        return Object.freeze({
            era: "LTD",
            ltdOnly: true,
            ltdExclusiveExempt: false,
            reason: "ltd-era",
            message: LTD_ONLY_DOWNLOAD_MESSAGE
        });
    }

    return Object.freeze({
        era,
        ltdOnly: false,
        ltdExclusiveExempt: false,
        reason: "non-ltd-era",
        message: ""
    });
}

export function getAllowedExportFormats(mii, allFormats, options = {}) {
    const formats = Array.isArray(allFormats) ? allFormats : [];
    if (!getMiiDownloadPolicy(mii, options).ltdOnly) return formats;

    const ltdFormat = formats.find(format => (
        String(format?.value || "").trim().toLowerCase() === "ltd"
    ));
    return ltdFormat ? [ltdFormat] : LTD_ONLY_EXPORT_FORMATS;
}

export function assertMiiDownloadFormat(mii, value, options = {}) {
    let normalized = String(value || "").trim().toLowerCase();
    if (normalized.startsWith(".")) normalized = normalized.slice(1);

    const policy = getMiiDownloadPolicy(mii, options);
    if (policy.ltdOnly && normalized !== "ltd") {
        throw new LtdOnlyDownloadError(policy.message);
    }
    return normalized;
}

export function sendLtdOnlyDownloadError(req, res, error = null, status = 410) {
    const message = error?.message || LTD_ONLY_DOWNLOAD_MESSAGE;
    res.setHeader("Cache-Control", "no-store");
    if (req.accepts("json")) {
        return res.status(status).json({
            error: message,
            code: "LTD_ONLY_DOWNLOAD"
        });
    }
    return res.status(status).type("text/plain").send(message);
}
