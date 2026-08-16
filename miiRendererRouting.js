import { resolveMiiEraForRuntime } from "./miiEra.js";
import {
    getMiiDownloadPolicy,
    isLtdExclusiveFeatureLockedMii
} from "./ltdOnlyDownloadPolicy.js";

export const MII_RENDERER_PROFILES = Object.freeze(["TL", "RFL", "LTD"]);

// RFL rendering is a logical profile even before its native implementation is
// available.  Keeping this mapping at one boundary makes the future switch
// from the TL backend to RFL explicit and prevents route code from depending
// on today's temporary delegate.
export const MII_RENDERER_BACKENDS = Object.freeze({
    TL: "TL",
    RFL: "TL",
    LTD: "LTD"
});

export class MiiRendererSelectionError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "MiiRendererSelectionError";
        this.code = code;
        this.status = 400;
    }
}

export function normalizeMiiRendererProfile(value, { allowEmpty = true } = {}) {
    const profile = String(value || "").trim().toUpperCase();
    if (!profile && allowEmpty) return "";
    if (MII_RENDERER_PROFILES.includes(profile)) return profile;
    throw new MiiRendererSelectionError(
        "INVALID_MII_RENDERER_PROFILE",
        "The requested renderer is unavailable."
    );
}

function normalizedEra(value) {
    const era = String(value || "").trim().toUpperCase();
    return era === "TL" ? "CFCD" : era;
}

function inferEraFromConsole(mii) {
    const declared = String(mii?.meta?.console || mii?.console || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
    if (["wii", "nintendo wii", "ds", "nintendo ds"].includes(declared)) return "RCD";
    if (["3ds", "nintendo 3ds", "tl 3ds", "tomodachi life"].includes(declared)) return "CFCD";
    if (["wii u", "nintendo wii u"].includes(declared)) return "FFCD";
    if (["switch", "nintendo switch", "mii studio"].includes(declared)) return "CHARINFO";
    if (declared === "ltd") return "LTD";
    return "";
}

export function getDefaultMiiRendererProfile(mii, { sourceEra, ltdExclusive } = {}) {
    const era = normalizedEra(sourceEra || resolveMiiEraForRuntime(mii) || inferEraFromConsole(mii));
    if (era === "LTD") return "LTD";
    if (era === "RCD") return "RFL";
    // CFCD (including legacy TL), FFCD, CHARINFO, and unclassified classic
    // data use the implemented TL/native backend by default.
    return "TL";
}

export function resolveMiiRendererRoute(mii, {
    requestedProfile,
    sourceEra,
    ltdExclusive
} = {}) {
    const policy = getMiiDownloadPolicy(mii, { storedRecord: Boolean(mii?.id) });
    const locked = isLtdExclusiveFeatureLockedMii(mii, { storedRecord: Boolean(mii?.id) })
        || ltdExclusive === true;
    const defaultProfile = getDefaultMiiRendererProfile(mii, { sourceEra, ltdExclusive: locked });
    const requested = normalizeMiiRendererProfile(requestedProfile);

    if (locked && requested && requested !== "LTD") {
        throw new MiiRendererSelectionError(
            "LTD_RENDERER_LOCKED",
            "This LTD-exclusive Mii must be rendered with the LTD renderer."
        );
    }

    const profile = locked ? "LTD" : (requested || defaultProfile);
    return Object.freeze({
        profile,
        backend: MII_RENDERER_BACKENDS[profile],
        defaultProfile,
        locked,
        sourceEra: normalizedEra(sourceEra || resolveMiiEraForRuntime(mii) || policy.era || inferEraFromConsole(mii))
    });
}
