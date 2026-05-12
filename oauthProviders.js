import crypto from "crypto";
import validator from "validator";

const DEFAULT_AUTHORIZATION_RESPONSE_TYPE = "code";
const DEFAULT_TOKEN_AUTH_METHOD = "client_secret_post";
const DEFAULT_OAUTH_PROMPT = "";
const USER_AGENT = "InfiniMii OAuth";
const OIDC_DISCOVERY_CACHE = new Map();

function getEnv(name) {
    return String(process.env[name] || "").trim();
}

function getEnvMultiline(name) {
    return getEnv(name).replace(/\\n/g, "\n");
}

function splitScopes(value, fallback = []) {
    const configured = String(value || "").trim();
    if (!configured) return fallback;
    return configured
        .split(/[\s,]+/g)
        .map(scope => scope.trim())
        .filter(Boolean);
}

function getProviderEnv(prefix, suffix, fallbacks = []) {
    const keys = [`${prefix}_${suffix}`, ...fallbacks];
    for (const key of keys) {
        const value = getEnv(key);
        if (value) return value;
    }
    return "";
}

function boolFromProvider(value) {
    if (value === true) return true;
    if (value === false) return false;
    if (typeof value === "number") return value === 1;
    if (typeof value !== "string") return false;
    return ["true", "1", "yes", "verified"].includes(value.trim().toLowerCase());
}

export function normalizeOAuthEmail(email) {
    const rawEmail = String(email || "").trim();
    if (!rawEmail || !validator.isEmail(rawEmail)) return "";
    const normalized = validator.normalizeEmail(rawEmail);
    return typeof normalized === "string" ? normalized : "";
}

function toStringOrEmpty(value) {
    if (value === null || typeof value === "undefined") return "";
    return String(value).trim();
}

function normalizeProfile(provider, profile) {
    const providerUserId = toStringOrEmpty(profile?.providerUserId || profile?.id || profile?.sub);
    const email = normalizeOAuthEmail(profile?.email);

    return {
        provider: provider.key,
        providerUserId,
        email,
        emailVerified: boolFromProvider(profile?.emailVerified) || Boolean(provider.trustEmailWhenPresent && email),
        displayName: toStringOrEmpty(profile?.displayName || profile?.name),
        username: toStringOrEmpty(profile?.username || profile?.preferredUsername),
        avatarUrl: toStringOrEmpty(profile?.avatarUrl || profile?.picture)
    };
}

function getByPath(source, path) {
    const keys = String(path || "").split(".").filter(Boolean);
    let current = source;
    for (const key of keys) {
        if (!current || typeof current !== "object") return undefined;
        current = current[key];
    }
    return current;
}

function decodeJwtPayload(token) {
    const parts = String(token || "").split(".");
    if (parts.length < 2) return {};
    try {
        const encoded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        const padded = encoded.padEnd(encoded.length + ((4 - encoded.length % 4) % 4), "=");
        return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    } catch {
        return {};
    }
}

function base64Url(input) {
    return Buffer.from(input)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function derSignatureToJose(signature) {
    let offset = 0;
    if (signature[offset++] !== 0x30) {
        throw new Error("Invalid Apple client secret signature.");
    }

    const readLength = () => {
        let length = signature[offset++];
        if (length & 0x80) {
            const bytes = length & 0x7f;
            length = 0;
            for (let i = 0; i < bytes; i++) {
                length = (length << 8) | signature[offset++];
            }
        }
        return length;
    };

    readLength();

    const readInteger = () => {
        if (signature[offset++] !== 0x02) {
            throw new Error("Invalid Apple client secret signature integer.");
        }
        const length = readLength();
        let value = signature.subarray(offset, offset + length);
        offset += length;
        while (value.length > 32 && value[0] === 0) value = value.subarray(1);
        if (value.length < 32) {
            value = Buffer.concat([Buffer.alloc(32 - value.length), value]);
        }
        return value;
    };

    return base64Url(Buffer.concat([readInteger(), readInteger()]));
}

function createAppleClientSecret(provider) {
    const configuredSecret = getEnv("APPLE_CLIENT_SECRET");
    if (configuredSecret) return configuredSecret;

    const teamId = getEnv("APPLE_TEAM_ID");
    const keyId = getEnv("APPLE_KEY_ID");
    const privateKey = getEnvMultiline("APPLE_PRIVATE_KEY");

    if (!teamId || !keyId || !privateKey) {
        return "";
    }

    const now = Math.floor(Date.now() / 1000);
    const header = {
        alg: "ES256",
        kid: keyId,
        typ: "JWT"
    };
    const payload = {
        iss: teamId,
        iat: now,
        exp: now + (60 * 60 * 24 * 30),
        aud: "https://appleid.apple.com",
        sub: provider.clientId
    };
    const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}`;
    const signer = crypto.createSign("SHA256");
    signer.update(signingInput);
    signer.end();
    return `${signingInput}.${derSignatureToJose(signer.sign(privateKey))}`;
}

async function fetchJson(url, {
    accessToken = "",
    provider = null,
    headers = {}
} = {}) {
    const requestHeaders = {
        Accept: "application/json",
        "User-Agent": USER_AGENT,
        ...headers
    };

    if (accessToken) {
        requestHeaders.Authorization = `Bearer ${accessToken}`;
    }
    if (provider?.key === "twitch" && provider.clientId) {
        requestHeaders["Client-ID"] = provider.clientId;
    }

    const response = await fetch(url, { headers: requestHeaders });
    const data = await parseProviderResponse(response);
    if (!response.ok) {
        throw new Error(data?.error_description || data?.message || data?.error || `OAuth request failed with ${response.status}`);
    }
    return data;
}

async function parseProviderResponse(response) {
    const text = await response.text();
    if (!text) return {};
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("json") || text.trim().startsWith("{")) {
        try {
            return JSON.parse(text);
        } catch {
            return { raw: text };
        }
    }
    return Object.fromEntries(new URLSearchParams(text));
}

async function fetchOidcDiscovery(issuerUrl) {
    const issuer = String(issuerUrl || "").trim().replace(/\/+$/g, "");
    if (!issuer) return null;
    if (OIDC_DISCOVERY_CACHE.has(issuer)) return OIDC_DISCOVERY_CACHE.get(issuer);

    const discoveryPromise = fetchJson(`${issuer}/.well-known/openid-configuration`)
        .catch(error => {
            OIDC_DISCOVERY_CACHE.delete(issuer);
            throw error;
        });
    OIDC_DISCOVERY_CACHE.set(issuer, discoveryPromise);
    return discoveryPromise;
}

async function resolveGithubProfile(provider, tokens) {
    const user = await fetchJson(provider.userinfoEndpoint, { accessToken: tokens.access_token, provider });
    let email = normalizeOAuthEmail(user.email);
    let emailVerified = false;

    try {
        const emails = await fetchJson("https://api.github.com/user/emails", {
            accessToken: tokens.access_token,
            provider
        });
        if (Array.isArray(emails)) {
            const primaryEmail = emails.find(item => item.primary && item.verified) ||
                emails.find(item => item.verified) ||
                emails.find(item => item.primary);
            email = normalizeOAuthEmail(primaryEmail?.email) || email;
            emailVerified = boolFromProvider(primaryEmail?.verified);
        }
    } catch {
        emailVerified = Boolean(email);
    }

    return normalizeProfile(provider, {
        providerUserId: user.id,
        email,
        emailVerified,
        displayName: user.name || user.login,
        username: user.login,
        avatarUrl: user.avatar_url
    });
}

async function resolveAppleProfile(provider, tokens) {
    const payload = decodeJwtPayload(tokens.id_token);
    return normalizeProfile(provider, {
        providerUserId: payload.sub,
        email: payload.email,
        emailVerified: payload.email_verified,
        displayName: payload.name,
        username: payload.email ? String(payload.email).split("@")[0] : ""
    });
}

async function resolveLineProfile(provider, tokens) {
    const profile = await fetchJson(provider.userinfoEndpoint, { accessToken: tokens.access_token, provider });
    const idTokenPayload = decodeJwtPayload(tokens.id_token);
    return normalizeProfile(provider, {
        providerUserId: idTokenPayload.sub || profile.userId,
        email: idTokenPayload.email,
        emailVerified: idTokenPayload.email_verified,
        displayName: profile.displayName || idTokenPayload.name,
        username: profile.displayName,
        avatarUrl: profile.pictureUrl || idTokenPayload.picture
    });
}

async function resolvePatreonProfile(provider, tokens) {
    const profile = await fetchJson(provider.userinfoEndpoint, { accessToken: tokens.access_token, provider });
    const user = profile?.data || {};
    const attrs = user?.attributes || {};
    return normalizeProfile(provider, {
        providerUserId: user.id,
        email: attrs.email,
        emailVerified: Boolean(attrs.email),
        displayName: attrs.full_name,
        username: attrs.vanity,
        avatarUrl: attrs.image_url
    });
}

async function resolveXProfile(provider, tokens) {
    const profile = await fetchJson(provider.userinfoEndpoint, { accessToken: tokens.access_token, provider });
    const user = profile?.data || {};
    return normalizeProfile(provider, {
        providerUserId: user.id,
        email: user.confirmed_email,
        emailVerified: Boolean(user.confirmed_email),
        displayName: user.name,
        username: user.username,
        avatarUrl: user.profile_image_url
    });
}

async function resolveSteamProfile(provider, tokens) {
    const token = String(tokens?.access_token || "").trim();
    if (!token) {
        throw new Error("Steam did not return an OAuth access token.");
    }

    const details = await fetchJson(`${provider.userinfoEndpoint}?access_token=${encodeURIComponent(token)}`, { provider });
    const data = details?.response || details || {};
    const steamId = toStringOrEmpty(data.steamid || data.steam_id || data.accountid || data.account_id);

    return normalizeProfile(provider, {
        providerUserId: steamId,
        displayName: steamId ? `Steam ${steamId}` : "Steam",
        username: steamId ? `steam-${steamId}` : ""
    });
}

async function resolveDefaultUserInfoProfile(provider, tokens) {
    let profile = {};
    if (provider.userinfoEndpoint) {
        profile = await fetchJson(provider.userinfoEndpoint, { accessToken: tokens.access_token, provider });
    }

    const idTokenPayload = decodeJwtPayload(tokens.id_token);
    const raw = { ...idTokenPayload, ...profile };

    if (provider.key === "twitch") {
        const twitchUser = Array.isArray(raw.data) ? raw.data[0] : raw;
        return normalizeProfile(provider, {
            providerUserId: twitchUser.id,
            email: twitchUser.email,
            emailVerified: Boolean(twitchUser.email),
            displayName: twitchUser.display_name || twitchUser.login,
            username: twitchUser.login,
            avatarUrl: twitchUser.profile_image_url
        });
    }

    if (provider.key === "facebook") {
        return normalizeProfile(provider, {
            providerUserId: raw.id,
            email: raw.email,
            emailVerified: Boolean(raw.email),
            displayName: raw.name,
            username: raw.name,
            avatarUrl: raw.picture?.data?.url
        });
    }

    if (provider.key === "reddit") {
        return normalizeProfile(provider, {
            providerUserId: raw.id || raw.name,
            displayName: raw.name,
            username: raw.name,
            avatarUrl: raw.icon_img
        });
    }

    if (provider.key === "amazon") {
        return normalizeProfile(provider, {
            providerUserId: raw.user_id || raw.sub,
            email: raw.email,
            emailVerified: Boolean(raw.email),
            displayName: raw.name,
            username: raw.name
        });
    }

    if (provider.key === "spotify") {
        return normalizeProfile(provider, {
            providerUserId: raw.id,
            email: raw.email,
            emailVerified: Boolean(raw.email),
            displayName: raw.display_name,
            username: raw.display_name || raw.id,
            avatarUrl: Array.isArray(raw.images) && raw.images[0] ? raw.images[0].url : ""
        });
    }

    if (provider.key === "custom-oauth") {
        return normalizeProfile(provider, {
            providerUserId: getByPath(raw, provider.idField),
            email: getByPath(raw, provider.emailField),
            emailVerified: getByPath(raw, provider.emailVerifiedField),
            displayName: getByPath(raw, provider.nameField),
            username: getByPath(raw, provider.usernameField),
            avatarUrl: getByPath(raw, provider.avatarField)
        });
    }

    return normalizeProfile(provider, {
        providerUserId: raw.sub || raw.id || raw.user_id,
        email: raw.email || raw.mail || raw.userPrincipalName || raw.preferred_username,
        emailVerified: raw.email_verified || raw.verified_email,
        displayName: raw.name || raw.display_name || raw.localizedFirstName,
        username: raw.preferred_username || raw.nickname || raw.login || raw.name,
        avatarUrl: raw.picture || raw.avatar_url
    });
}

const PROVIDER_DEFINITIONS = [
    {
        key: "google",
        envPrefix: "GOOGLE",
        displayName: "Google",
        iconText: "G",
        iconUrl: "https://www.google.com/favicon.ico",
        authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
        userinfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
        scopes: ["openid", "email", "profile"]
    },
    {
        key: "discord",
        envPrefix: "DISCORD",
        displayName: "Discord",
        iconText: "D",
        iconUrl: "https://discord.com/assets/847541504914fd33810e70a0ea73177e.ico",
        authorizationEndpoint: "https://discord.com/oauth2/authorize",
        tokenEndpoint: "https://discord.com/api/oauth2/token",
        userinfoEndpoint: "https://discord.com/api/users/@me",
        scopes: ["identify", "email"],
        mapProfile: raw => ({
            providerUserId: raw.id,
            email: raw.email,
            emailVerified: raw.verified,
            displayName: raw.global_name || raw.username,
            username: raw.username,
            avatarUrl: raw.avatar ? `https://cdn.discordapp.com/avatars/${raw.id}/${raw.avatar}.png` : ""
        })
    },
    {
        key: "github",
        envPrefix: "GITHUB",
        displayName: "GitHub",
        iconText: "GH",
        iconUrl: "https://github.com/favicon.ico",
        authorizationEndpoint: "https://github.com/login/oauth/authorize",
        tokenEndpoint: "https://github.com/login/oauth/access_token",
        userinfoEndpoint: "https://api.github.com/user",
        scopes: ["read:user", "user:email"],
        profileResolver: resolveGithubProfile
    },
    {
        key: "microsoft",
        envPrefix: "MICROSOFT",
        displayName: "Microsoft",
        iconText: "M",
        iconUrl: "https://www.microsoft.com/favicon.ico",
        scopes: ["openid", "email", "profile", "User.Read"],
        trustEmailWhenPresent: true,
        buildEndpoints: () => {
            const tenant = getEnv("MICROSOFT_TENANT_ID") || "common";
            const base = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0`;
            return {
                authorizationEndpoint: `${base}/authorize`,
                tokenEndpoint: `${base}/token`,
                userinfoEndpoint: "https://graph.microsoft.com/oidc/userinfo"
            };
        }
    },
    {
        key: "apple",
        envPrefix: "APPLE",
        displayName: "Apple",
        iconText: "A",
        iconUrl: "https://www.apple.com/favicon.ico",
        authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
        tokenEndpoint: "https://appleid.apple.com/auth/token",
        scopes: ["name", "email"],
        trustEmailWhenPresent: true,
        profileResolver: resolveAppleProfile,
        getClientSecret: createAppleClientSecret,
        isConfigured: provider => Boolean(provider.clientId && createAppleClientSecret(provider))
    },
    {
        key: "facebook",
        envPrefix: "FACEBOOK",
        displayName: "Facebook",
        iconText: "F",
        iconUrl: "https://www.facebook.com/favicon.ico",
        authorizationEndpoint: "https://www.facebook.com/v18.0/dialog/oauth",
        tokenEndpoint: "https://graph.facebook.com/v18.0/oauth/access_token",
        userinfoEndpoint: "https://graph.facebook.com/me?fields=id,name,email,picture",
        scopes: ["email", "public_profile"],
        clientIdFallbacks: ["FACEBOOK_APP_ID"],
        clientSecretFallbacks: ["FACEBOOK_APP_SECRET"],
        trustEmailWhenPresent: true
    },
    {
        key: "x",
        envPrefix: "X",
        displayName: "X / Twitter",
        iconText: "X",
        iconUrl: "https://x.com/favicon.ico",
        authorizationEndpoint: "https://x.com/i/oauth2/authorize",
        tokenEndpoint: "https://api.x.com/2/oauth2/token",
        userinfoEndpoint: "https://api.x.com/2/users/me?user.fields=confirmed_email,profile_image_url",
        scopes: ["users.read", "users.email"],
        tokenAuthMethod: "client_secret_basic",
        pkce: true,
        profileResolver: resolveXProfile,
        clientIdFallbacks: ["TWITTER_CLIENT_ID"],
        clientSecretFallbacks: ["TWITTER_CLIENT_SECRET"]
    },
    {
        key: "twitch",
        envPrefix: "TWITCH",
        displayName: "Twitch",
        iconText: "T",
        iconUrl: "https://www.twitch.tv/favicon.ico",
        authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
        tokenEndpoint: "https://id.twitch.tv/oauth2/token",
        userinfoEndpoint: "https://api.twitch.tv/helix/users",
        scopes: ["user:read:email"],
        trustEmailWhenPresent: true
    },
    {
        key: "steam",
        envPrefix: "STEAM",
        displayName: "Steam",
        iconText: "S",
        iconUrl: "https://store.steampowered.com/favicon.ico",
        authorizationEndpoint: "https://steamcommunity.com/oauth/login",
        tokenEndpoint: "",
        userinfoEndpoint: "https://api.steampowered.com/ISteamUserOAuth/GetTokenDetails/v1/",
        scopes: [],
        responseType: "token",
        supportsSignup: false,
        tokenResponseMode: "fragment",
        profileResolver: resolveSteamProfile,
        isConfigured: provider => Boolean(provider.clientId && provider.authorizationEndpoint && provider.userinfoEndpoint)
    }
];

function buildConfiguredProvider(definition) {
    const prefix = definition.envPrefix;
    const clientId = getProviderEnv(prefix, "CLIENT_ID", definition.clientIdFallbacks || []);
    const clientSecret = getProviderEnv(prefix, "CLIENT_SECRET", definition.clientSecretFallbacks || []);
    const endpointOverrides = definition.buildEndpoints ? definition.buildEndpoints() : {};

    const provider = {
        ...definition,
        authorizationEndpoint: getProviderEnv(prefix, "AUTHORIZATION_URL") || endpointOverrides.authorizationEndpoint || definition.authorizationEndpoint,
        tokenEndpoint: getProviderEnv(prefix, "TOKEN_URL") || endpointOverrides.tokenEndpoint || definition.tokenEndpoint,
        userinfoEndpoint: getProviderEnv(prefix, "USERINFO_URL") || endpointOverrides.userinfoEndpoint || definition.userinfoEndpoint,
        callbackUrl: getProviderEnv(prefix, "CALLBACK_URL"),
        clientId,
        clientSecret,
        scopes: splitScopes(getProviderEnv(prefix, "SCOPES"), definition.scopes || []),
        displayName: getProviderEnv(prefix, "DISPLAY_NAME") || definition.displayName,
        iconText: getProviderEnv(prefix, "ICON_TEXT") || definition.iconText || definition.displayName.slice(0, 1),
        iconUrl: getProviderEnv(prefix, "ICON_URL") || definition.iconUrl || "",
        tokenAuthMethod: getProviderEnv(prefix, "TOKEN_AUTH_METHOD") || definition.tokenAuthMethod || DEFAULT_TOKEN_AUTH_METHOD
    };

    let isConfigured = false;
    try {
        isConfigured = typeof definition.isConfigured === "function"
            ? definition.isConfigured(provider)
            : Boolean(provider.clientId && provider.clientSecret && provider.authorizationEndpoint && provider.tokenEndpoint);
    } catch {
        isConfigured = false;
    }

    return {
        ...provider,
        enabled: isConfigured
    };
}

function buildOidcProvider() {
    const issuerUrl = getEnv("OIDC_ISSUER_URL").replace(/\/+$/g, "");
    const provider = {
        key: "oidc",
        envPrefix: "OIDC",
        displayName: getEnv("OIDC_DISPLAY_NAME") || getEnv("OIDC_PROVIDER_NAME") || "OpenID Connect",
        iconText: getEnv("OIDC_ICON_TEXT") || "OIDC",
        iconUrl: getEnv("OIDC_ICON_URL"),
        clientId: getEnv("OIDC_CLIENT_ID"),
        clientSecret: getEnv("OIDC_CLIENT_SECRET"),
        issuerUrl,
        callbackUrl: getEnv("OIDC_CALLBACK_URL"),
        scopes: splitScopes(getEnv("OIDC_SCOPES"), ["openid", "email", "profile"]),
        tokenAuthMethod: getEnv("OIDC_TOKEN_AUTH_METHOD") || DEFAULT_TOKEN_AUTH_METHOD,
        authorizationEndpoint: "",
        tokenEndpoint: "",
        userinfoEndpoint: "",
        trustEmailWhenPresent: getEnv("OIDC_TRUST_EMAIL") === "true",
        enabled: Boolean(issuerUrl && getEnv("OIDC_CLIENT_ID") && getEnv("OIDC_CLIENT_SECRET"))
    };
    return provider;
}

function buildCustomOAuthProvider() {
    const provider = {
        key: "custom-oauth",
        envPrefix: "CUSTOM_OAUTH",
        displayName: getEnv("CUSTOM_OAUTH_DISPLAY_NAME") || "Custom OAuth",
        iconText: getEnv("CUSTOM_OAUTH_ICON_TEXT") || "OAuth",
        iconUrl: getEnv("CUSTOM_OAUTH_ICON_URL"),
        clientId: getEnv("CUSTOM_OAUTH_CLIENT_ID"),
        clientSecret: getEnv("CUSTOM_OAUTH_CLIENT_SECRET"),
        authorizationEndpoint: getEnv("CUSTOM_OAUTH_AUTHORIZATION_URL"),
        tokenEndpoint: getEnv("CUSTOM_OAUTH_TOKEN_URL"),
        userinfoEndpoint: getEnv("CUSTOM_OAUTH_USERINFO_URL"),
        callbackUrl: getEnv("CUSTOM_OAUTH_CALLBACK_URL"),
        scopes: splitScopes(getEnv("CUSTOM_OAUTH_SCOPES"), ["profile", "email"]),
        tokenAuthMethod: getEnv("CUSTOM_OAUTH_TOKEN_AUTH_METHOD") || DEFAULT_TOKEN_AUTH_METHOD,
        idField: getEnv("CUSTOM_OAUTH_ID_FIELD") || "id",
        emailField: getEnv("CUSTOM_OAUTH_EMAIL_FIELD") || "email",
        emailVerifiedField: getEnv("CUSTOM_OAUTH_EMAIL_VERIFIED_FIELD") || "email_verified",
        nameField: getEnv("CUSTOM_OAUTH_NAME_FIELD") || "name",
        usernameField: getEnv("CUSTOM_OAUTH_USERNAME_FIELD") || "username",
        avatarField: getEnv("CUSTOM_OAUTH_AVATAR_FIELD") || "avatar_url",
        trustEmailWhenPresent: getEnv("CUSTOM_OAUTH_TRUST_EMAIL") === "true"
    };

    return {
        ...provider,
        enabled: Boolean(provider.clientId && provider.clientSecret && provider.authorizationEndpoint && provider.tokenEndpoint && provider.userinfoEndpoint)
    };
}

function getAllConfiguredProviders() {
    return PROVIDER_DEFINITIONS.map(buildConfiguredProvider);
}

export function getOAuthProviderSummaries({ enabledOnly = true } = {}) {
    return getAllConfiguredProviders()
        .filter(provider => !enabledOnly || provider.enabled)
        .map(provider => ({
            key: provider.key,
            displayName: provider.displayName,
            iconText: provider.iconText,
            iconUrl: provider.iconUrl,
            enabled: provider.enabled,
            supportsSignup: provider.supportsSignup !== false
        }));
}

export function getEnabledOAuthProviderSummaries() {
    return getOAuthProviderSummaries({ enabledOnly: true });
}

export async function getOAuthProvider(providerKey) {
    const provider = getAllConfiguredProviders().find(candidate => candidate.key === providerKey);
    if (!provider || !provider.enabled) return null;

    return provider;
}

export function getOAuthRedirectUri(provider, baseUrl) {
    return provider.callbackUrl || `${String(baseUrl || "").replace(/\/+$/g, "")}/auth/${encodeURIComponent(provider.key)}/callback`;
}

export function buildOAuthAuthorizationUrl(provider, {
    redirectUri,
    state,
    codeChallenge
}) {
    const url = new URL(provider.authorizationEndpoint);
    url.searchParams.set("client_id", provider.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", provider.responseType || DEFAULT_AUTHORIZATION_RESPONSE_TYPE);
    url.searchParams.set("state", state);

    if (provider.pkce && codeChallenge) {
        url.searchParams.set("code_challenge", codeChallenge);
        url.searchParams.set("code_challenge_method", "S256");
    }

    const scope = (provider.scopes || []).join(" ");
    if (scope) {
        url.searchParams.set("scope", scope);
    }

    const prompt = getProviderEnv(provider.envPrefix || provider.key.toUpperCase(), "PROMPT") || DEFAULT_OAUTH_PROMPT;
    if (prompt) {
        url.searchParams.set("prompt", prompt);
    }

    return url.toString();
}

export async function exchangeOAuthCodeForProfile(provider, {
    accessToken = "",
    code,
    redirectUri,
    codeVerifier = ""
}) {
    const accessTokenPayload = accessToken ? { access_token: String(accessToken).trim() } : null;
    if (accessTokenPayload?.access_token) {
        const profile = typeof provider.profileResolver === "function"
            ? await provider.profileResolver(provider, accessTokenPayload)
            : await resolveDefaultUserInfoProfile(provider, accessTokenPayload);

        if (!profile.providerUserId) {
            throw new Error(`${provider.displayName} did not return a usable account identifier.`);
        }

        return {
            tokens: accessTokenPayload,
            profile
        };
    }

    const tokenBody = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri
    });

    const headers = {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT
    };

    const clientSecret = typeof provider.getClientSecret === "function"
        ? provider.getClientSecret(provider)
        : provider.clientSecret;

    if (provider.pkce && codeVerifier) {
        tokenBody.set("code_verifier", codeVerifier);
    }

    if (provider.tokenAuthMethod === "client_secret_basic") {
        headers.Authorization = `Basic ${Buffer.from(`${provider.clientId}:${clientSecret}`).toString("base64")}`;
    } else {
        tokenBody.set("client_id", provider.clientId);
        tokenBody.set("client_secret", clientSecret);
    }

    const response = await fetch(provider.tokenEndpoint, {
        method: "POST",
        headers,
        body: tokenBody
    });
    const tokens = await parseProviderResponse(response);

    if (!response.ok || tokens.error) {
        throw new Error(tokens.error_description || tokens.error || `OAuth token exchange failed with ${response.status}`);
    }

    const profile = typeof provider.profileResolver === "function"
        ? await provider.profileResolver(provider, tokens)
        : normalizeProfile(
            provider,
            typeof provider.mapProfile === "function"
                ? provider.mapProfile(await fetchJson(provider.userinfoEndpoint, { accessToken: tokens.access_token, provider }), tokens)
                : await resolveDefaultUserInfoProfile(provider, tokens)
        );

    if (!profile.providerUserId) {
        throw new Error(`${provider.displayName} did not return a usable account identifier.`);
    }

    return {
        tokens,
        profile
    };
}
