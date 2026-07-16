export const EXTERNAL_MII_PREFERENCES = Object.freeze(["ask", "stay", "go"]);
export const EXTERNAL_MII_PREFERENCE_SET = new Set(EXTERNAL_MII_PREFERENCES);

const EXTERNAL_MII_URL_MAX_LENGTH = 2048;
const EXTERNAL_MII_TITLE_MAX_LENGTH = 160;
const EXTERNAL_MII_USER_MAX_LENGTH = 160;

function normalizeExternalMiiText(value, maxLength) {
    if (typeof value !== "string") return "";
    const normalized = value
        .replace(/[\u0000-\u001f\u007f]/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    if (!normalized || normalized.length > maxLength) return "";
    return normalized;
}

function normalizeExternalMiiUrl(value) {
    if (typeof value !== "string") return "";
    const candidate = value.trim();
    if (
        !candidate
        || candidate.length > EXTERNAL_MII_URL_MAX_LENGTH
        || /[\u0000-\u001f\u007f]/.test(candidate)
    ) {
        return "";
    }

    try {
        const parsed = new URL(candidate);
        if (!parsed.hostname || parsed.username || parsed.password) return "";
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
        return parsed.href;
    } catch {
        return "";
    }
}

export function getExternalMiiSource(mii) {
    const title = normalizeExternalMiiText(mii?.extTitle, EXTERNAL_MII_TITLE_MAX_LENGTH);
    const url = normalizeExternalMiiUrl(mii?.extURL);
    if (!title || !url) return null;

    const user = normalizeExternalMiiText(mii?.extUser, EXTERNAL_MII_USER_MAX_LENGTH);
    const userUrl = user ? normalizeExternalMiiUrl(mii?.extUserURL) : "";

    return {
        title,
        url,
        user: user && userUrl ? user : "",
        userUrl: user && userUrl ? userUrl : ""
    };
}

export function validateExternalMiiMetadata(input) {
    const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
    const fields = ["extURL", "extTitle", "extUser", "extUserURL"];
    if (!fields.every(field => Object.prototype.hasOwnProperty.call(source, field))) {
        return { error: "Submit all external source fields together; use empty strings to clear optional values." };
    }
    if (!fields.every(field => typeof source[field] === "string")) {
        return { error: "External source fields must be strings." };
    }

    const rawURL = source.extURL.trim();
    const rawTitle = source.extTitle.trim();
    const rawUser = source.extUser.trim();
    const rawUserURL = source.extUserURL.trim();

    if (!rawURL && !rawTitle && !rawUser && !rawUserURL) {
        return { value: { extURL: "", extTitle: "", extUser: "", extUserURL: "" } };
    }
    if (!rawURL || !rawTitle) {
        return { error: "External source URL and title must be provided together." };
    }

    const extTitle = normalizeExternalMiiText(rawTitle, EXTERNAL_MII_TITLE_MAX_LENGTH);
    if (!extTitle) {
        return { error: `External source titles must be ${EXTERNAL_MII_TITLE_MAX_LENGTH} characters or fewer.` };
    }
    const extURL = normalizeExternalMiiUrl(rawURL);
    if (!extURL) {
        return { error: "External source URLs must be valid HTTP or HTTPS URLs without embedded credentials." };
    }
    if (Boolean(rawUser) !== Boolean(rawUserURL)) {
        return { error: "External uploader name and URL must be provided together." };
    }

    let extUser = "";
    let extUserURL = "";
    if (rawUser) {
        extUser = normalizeExternalMiiText(rawUser, EXTERNAL_MII_USER_MAX_LENGTH);
        if (!extUser) {
            return { error: `External uploader names must be ${EXTERNAL_MII_USER_MAX_LENGTH} characters or fewer.` };
        }
        extUserURL = normalizeExternalMiiUrl(rawUserURL);
        if (!extUserURL) {
            return { error: "External uploader URLs must be valid HTTP or HTTPS URLs without embedded credentials." };
        }
    }

    return { value: { extURL, extTitle, extUser, extUserURL } };
}

export function normalizeExternalMiiPreference(value) {
    const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
    return EXTERNAL_MII_PREFERENCE_SET.has(normalized) ? normalized : "ask";
}
