import { MII_RENDERER_PROFILES } from "./miiRendererRouting.js";

const AVERAGE_RENDERER_PROFILE_PRIORITY = Object.freeze(["TL", "RFL", "LTD"]);

const AVERAGE_PRESENTATION_BY_PROFILE = Object.freeze({
    TL: Object.freeze({
        rendererProfile: "TL",
        era: "CHARINFO",
        console: "Mii Studio"
    }),
    RFL: Object.freeze({
        rendererProfile: "RFL",
        era: "RCD",
        console: "Wii"
    }),
    LTD: Object.freeze({
        rendererProfile: "LTD",
        era: "LTD",
        console: "LTD"
    })
});

export function selectMostCommonMiiRendererProfile(counts) {
    const source = counts instanceof Map
        ? counts
        : new Map(Object.entries(counts && typeof counts === "object" ? counts : {}));
    let selected = AVERAGE_RENDERER_PROFILE_PRIORITY[0];
    let selectedCount = -1;

    for (const profile of AVERAGE_RENDERER_PROFILE_PRIORITY) {
        const count = Number(source.get(profile));
        const normalizedCount = Number.isFinite(count) && count >= 0 ? count : 0;
        if (normalizedCount > selectedCount) {
            selected = profile;
            selectedCount = normalizedCount;
        }
    }

    return selected;
}

export function getAverageMiiPresentation(profile) {
    const normalized = String(profile || "").trim().toUpperCase();
    if (!MII_RENDERER_PROFILES.includes(normalized)) {
        throw new TypeError(`Unsupported average-Mii renderer profile: ${profile}`);
    }
    return AVERAGE_PRESENTATION_BY_PROFILE[normalized];
}

