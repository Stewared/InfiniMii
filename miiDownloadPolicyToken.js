import crypto from "node:crypto";

import { toMiiDataOnly } from "./miiDataUtils.js";

const TOKEN_VERSION = 1;
const TOKEN_POLICY = "ltd-only";
const TOKEN_ERA = "LTD";
const TOKEN_CONTEXT = "infinimii-mii-download-policy-v1";
const DEFAULT_TOKEN_TTL_MS = 60 * 60 * 1000;
const MAX_TOKEN_LENGTH = 4096;

function stableJsonValue(value) {
    if (value === undefined || typeof value === "function" || typeof value === "symbol") {
        return undefined;
    }
    if (value === null || typeof value === "string" || typeof value === "boolean") return value;
    if (typeof value === "number") return Number.isFinite(value) ? value : null;
    if (typeof value === "bigint") return value.toString();
    if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
        return Array.from(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
    if (value instanceof ArrayBuffer) return Array.from(Buffer.from(value));
    if (value instanceof Date) return value.toISOString();
    if (Array.isArray(value)) {
        return value.map(entry => stableJsonValue(entry) ?? null);
    }
    if (!value || typeof value !== "object") return null;

    const result = {};
    for (const key of Object.keys(value).sort()) {
        const normalized = stableJsonValue(value[key]);
        if (normalized !== undefined) result[key] = normalized;
    }
    return result;
}

export function getMiiDownloadPolicyPayloadHash(miiInput) {
    const normalized = stableJsonValue(toMiiDataOnly(miiInput));
    return crypto
        .createHash("sha256")
        .update(JSON.stringify(normalized ?? null))
        .digest("hex");
}

function signBody(encodedBody, secret) {
    return crypto
        .createHmac("sha256", String(secret))
        .update(`${TOKEN_CONTEXT}.${encodedBody}`)
        .digest();
}

function safeEqual(left, right) {
    const leftBuffer = Buffer.isBuffer(left) ? left : Buffer.from(left || "");
    const rightBuffer = Buffer.isBuffer(right) ? right : Buffer.from(right || "");
    return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function createMiiDownloadPolicyToken(miiInput, {
    secret,
    now = Date.now(),
    ttlMs = DEFAULT_TOKEN_TTL_MS
} = {}) {
    if (!secret) throw new Error("A server secret is required to sign a Mii download policy token.");
    const issuedAt = Math.trunc(Number(now));
    const lifetime = Math.max(1, Math.trunc(Number(ttlMs)) || DEFAULT_TOKEN_TTL_MS);
    const body = {
        v: TOKEN_VERSION,
        policy: TOKEN_POLICY,
        era: TOKEN_ERA,
        miiSha256: getMiiDownloadPolicyPayloadHash(miiInput),
        iat: issuedAt,
        exp: issuedAt + lifetime
    };
    const encodedBody = Buffer.from(JSON.stringify(body)).toString("base64url");
    const signature = signBody(encodedBody, secret).toString("base64url");
    return `${encodedBody}.${signature}`;
}

function invalidResult(reason, present = true) {
    return Object.freeze({ present, valid: false, ltdOnly: false, era: "", reason });
}

export function verifyMiiDownloadPolicyToken(token, miiInput, {
    secret,
    now = Date.now()
} = {}) {
    const normalizedToken = typeof token === "string" ? token.trim() : "";
    if (!normalizedToken) return invalidResult("missing", false);
    if (!secret || normalizedToken.length > MAX_TOKEN_LENGTH) return invalidResult("malformed");

    const parts = normalizedToken.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) return invalidResult("malformed");

    let suppliedSignature;
    let body;
    try {
        suppliedSignature = Buffer.from(parts[1], "base64url");
        body = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    } catch {
        return invalidResult("malformed");
    }
    if (!safeEqual(suppliedSignature, signBody(parts[0], secret))) return invalidResult("bad-signature");
    if (
        !body
        || typeof body !== "object"
        || body.v !== TOKEN_VERSION
        || body.policy !== TOKEN_POLICY
        || body.era !== TOKEN_ERA
        || !/^[a-f0-9]{64}$/.test(String(body.miiSha256 || ""))
        || !Number.isSafeInteger(body.iat)
        || !Number.isSafeInteger(body.exp)
        || body.exp <= body.iat
    ) {
        return invalidResult("invalid-claims");
    }
    if (Number(now) >= body.exp) return invalidResult("expired");
    if (!safeEqual(body.miiSha256, getMiiDownloadPolicyPayloadHash(miiInput))) {
        return invalidResult("wrong-payload");
    }

    return Object.freeze({
        present: true,
        valid: true,
        ltdOnly: true,
        era: TOKEN_ERA,
        policy: TOKEN_POLICY,
        issuedAt: body.iat,
        expiresAt: body.exp,
        reason: "verified"
    });
}

