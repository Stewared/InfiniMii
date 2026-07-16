import fs from "node:fs";
import { fileURLToPath } from "node:url";

const SEO_KEYWORDS_CSV_PATH = fileURLToPath(new URL("./seoKeywords.csv", import.meta.url));
const SEO_KEYWORD_META_LIMIT = 48;
const SEO_KEYWORD_MAX_LENGTH = 80;

const SEO_KEYWORD_STOPWORDS = new Set([
    "and", "app", "are", "browse", "character", "characters", "community",
    "download", "for", "from", "guide", "infini", "infinimii", "latest",
    "mii", "miis", "nintendo", "official", "page", "search", "share", "the",
    "tool", "tools", "upload", "with"
]);

export const SEO_KEYWORD_SHORT_TOKENS = new Set(["ds", "mt", "qr"]);

let cachedCatalog = null;
let loggedCatalogLoadError = false;

export function parseCsvKeywordContent(content) {
    const values = [];
    let current = "";
    let inQuotes = false;

    for (let index = 0; index < content.length; index += 1) {
        const character = content[index];
        if (character === '"') {
            if (inQuotes && content[index + 1] === '"') {
                current += '"';
                index += 1;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (!inQuotes && (character === "," || character === "\n" || character === "\r")) {
            values.push(current);
            current = "";
        } else {
            current += character;
        }
    }

    values.push(current);
    return values;
}

function normalizeSeoKeyword(keyword) {
    const normalized = String(keyword || "")
        .replace(/[\u0000-\u001f\u007f]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    return normalized.length >= 2 && normalized.length <= SEO_KEYWORD_MAX_LENGTH ? normalized : "";
}

function uniqueSeoKeywords(keywords) {
    const seen = new Set();
    const output = [];
    for (const value of keywords) {
        const keyword = normalizeSeoKeyword(value);
        if (!keyword) continue;
        const key = keyword.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        output.push(keyword);
    }
    return output;
}

function parseKeywordInput(input) {
    if (Array.isArray(input)) {
        const output = [];
        for (const value of input) output.push(...parseKeywordInput(value));
        return output;
    }
    if (input === undefined || input === null) return [];
    return parseCsvKeywordContent(String(input));
}

function getSeoKeywordCatalog() {
    if (cachedCatalog) return cachedCatalog;

    try {
        const keywords = uniqueSeoKeywords(parseCsvKeywordContent(fs.readFileSync(SEO_KEYWORDS_CSV_PATH, "utf8")));
        cachedCatalog = Object.freeze(keywords.map(keyword => Object.freeze({
            keyword,
            normalized: keyword.toLowerCase()
        })));
    } catch (error) {
        cachedCatalog = Object.freeze([]);
        if (!loggedCatalogLoadError) {
            loggedCatalogLoadError = true;
            console.warn(`[seo] Could not load seoKeywords.csv: ${error.message}`);
        }
    }
    return cachedCatalog;
}

function getSeoKeywordTokens(values) {
    const tokens = new Set();
    const text = parseKeywordInput(values).join(" ").toLowerCase();
    for (const rawToken of text.split(/[^a-z0-9.]+/g)) {
        const token = rawToken.trim();
        if (!token) continue;
        if (token.length <= 2 && !SEO_KEYWORD_SHORT_TOKENS.has(token)) continue;
        if (!SEO_KEYWORD_STOPWORDS.has(token)) tokens.add(token);
    }
    return tokens;
}

function scoreSeoKeyword(normalizedKeyword, tokens) {
    let score = 0;
    for (const token of tokens) {
        if (normalizedKeyword === token) score += 8;
        else if (normalizedKeyword.startsWith(`${token} `) || normalizedKeyword.endsWith(` ${token}`)) score += 4;
        else if (normalizedKeyword.includes(token)) score += token.length > 4 ? 3 : 1;
    }
    if (normalizedKeyword.includes("mii")) score += 1;
    return score;
}

function insertRankedKeyword(ranked, entry, maximum) {
    let low = 0;
    let high = ranked.length;
    while (low < high) {
        const middle = (low + high) >>> 1;
        const current = ranked[middle];
        const comparison = current.score - entry.score || entry.keyword.length - current.keyword.length;
        if (comparison < 0) high = middle;
        else low = middle + 1;
    }
    ranked.splice(low, 0, entry);
    if (ranked.length > maximum) ranked.pop();
}

function clampSeoKeywordLimit(limit) {
    const numericLimit = Number(limit);
    if (!Number.isFinite(numericLimit) || numericLimit <= 0) return SEO_KEYWORD_META_LIMIT;
    return Math.min(Math.floor(numericLimit), SEO_KEYWORD_META_LIMIT);
}

export function buildSeoKeywordList(seedValues = [], options = {}) {
    const limit = clampSeoKeywordLimit(options.limit);
    const seedKeywords = uniqueSeoKeywords(parseKeywordInput(seedValues)).slice(0, limit);
    const tokens = getSeoKeywordTokens([seedKeywords, options.context || [], options.contextValues || []]);
    const seen = new Set(seedKeywords.map(keyword => keyword.toLowerCase()));
    const catalog = getSeoKeywordCatalog();
    const ranked = [];
    const remaining = Math.max(0, limit - seedKeywords.length);

    if (remaining > 0) {
        for (const item of catalog) {
            if (seen.has(item.normalized)) continue;
            const score = scoreSeoKeyword(item.normalized, tokens);
            if (score > 0) insertRankedKeyword(ranked, { ...item, score }, remaining);
        }
    }

    const output = [...seedKeywords];
    for (const item of ranked) {
        if (output.length >= limit) break;
        seen.add(item.normalized);
        output.push(item.keyword);
    }

    if (output.length < limit && options.fallbackToGeneral !== false) {
        for (const item of catalog) {
            if (seen.has(item.normalized)) continue;
            seen.add(item.normalized);
            output.push(item.keyword);
            if (output.length >= limit) break;
        }
    }

    return options.asArray ? output : output.join(", ");
}
