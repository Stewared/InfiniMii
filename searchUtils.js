import { doubleMetaphone } from "double-metaphone";

export const SEARCH_FIELD_VALUES = ["uploader", "name", "description"];
export const SEARCH_FIELD_SET = new Set(SEARCH_FIELD_VALUES);
export const SEARCH_FALLBACK_CANDIDATE_LIMIT = 3000;

const SEARCH_TOKEN_LIMIT = 8;
const SEARCH_TOKEN_MAX_LENGTH = 48;
const SEARCH_FALLBACK_FIELD_TOKEN_LIMIT = 160;
const SEARCH_STOPWORDS = new Set([
    "a",
    "an",
    "and",
    "by",
    "character",
    "characters",
    "for",
    "from",
    "in",
    "mii",
    "miis",
    "of",
    "on",
    "the",
    "to",
    "with"
]);

const SEARCH_FIELD_SPECS = Object.freeze([
    {
        field: "name",
        path: "meta.name",
        weight: 480,
        getValue: (mii) => mii?.meta?.name
    },
    {
        field: "name",
        path: "meta.creatorName",
        weight: 320,
        getValue: (mii) => mii?.meta?.creatorName
    },
    {
        field: "uploader",
        path: "uploader",
        weight: 260,
        getValue: (mii) => mii?.uploader
    },
    {
        field: "description",
        path: "desc",
        weight: 190,
        getValue: (mii) => mii?.desc
    }
]);

const SEARCH_CHAR_VARIANTS = Object.freeze({
    a: "a\u00e0\u00e1\u00e2\u00e3\u00e4\u00e5\u0101\u0103\u0105\u01ce\u01df\u01e1\u01fb\u0201\u0203\u0227\u1ea1\u1ea3\u1ea5\u1ea7\u1ea9\u1eab\u1ead\u1eaf\u1eb1\u1eb3\u1eb5\u1eb7",
    c: "c\u00e7\u0107\u0109\u010b\u010d",
    d: "d\u010f\u0111\u1e0b\u1e0d",
    e: "e\u00e8\u00e9\u00ea\u00eb\u0113\u0115\u0117\u0119\u011b\u0205\u0207\u0229\u1eb9\u1ebb\u1ebd\u1ebf\u1ec1\u1ec3\u1ec5\u1ec7",
    g: "g\u011d\u011f\u0121\u0123\u01e7\u01f5",
    h: "h\u0125\u0127\u1e23\u1e25",
    i: "i\u00ec\u00ed\u00ee\u00ef\u0129\u012b\u012d\u012f\u01d0\u0209\u020b\u1ec9\u1ecb",
    l: "l\u013a\u013c\u013e\u0142",
    n: "n\u00f1\u0144\u0146\u0148\u01f9\u1e45\u1e47",
    o: "o\u00f2\u00f3\u00f4\u00f5\u00f6\u00f8\u014d\u014f\u0151\u01d2\u01ff\u020d\u020f\u022b\u022d\u022f\u0231\u1ecd\u1ecf\u1ed1\u1ed3\u1ed5\u1ed7\u1ed9\u1edb\u1edd\u1edf\u1ee1\u1ee3",
    r: "r\u0155\u0157\u0159\u1e59\u1e5b",
    s: "s\u015b\u015d\u015f\u0161\u1e61\u1e63\u00df",
    t: "t\u0163\u0165\u0167\u1e6b\u1e6d",
    u: "u\u00f9\u00fa\u00fb\u00fc\u0169\u016b\u016d\u016f\u0171\u0173\u01d4\u01d6\u01d8\u01da\u01dc\u0215\u0217\u1ee5\u1ee7\u1ee9\u1eeb\u1eed\u1eef\u1ef1",
    y: "y\u00fd\u00ff\u0177\u1e8f\u1ef3\u1ef5\u1ef7\u1ef9",
    z: "z\u017a\u017c\u017e\u1e93"
});

const phoneticCache = new Map();

export function normalizeSearchFieldSelection(requestedFields, { defaultToAll = true } = {}) {
    const source = Array.isArray(requestedFields) ? requestedFields : [requestedFields];
    const normalized = [];
    const seen = new Set();

    for (const rawField of source) {
        const field = String(rawField || "").trim().toLowerCase();
        if (!SEARCH_FIELD_SET.has(field)) continue;
        if (seen.has(field)) continue;

        seen.add(field);
        normalized.push(field);
    }

    if (normalized.length === 0 && defaultToAll) {
        return [...SEARCH_FIELD_VALUES];
    }

    return normalized;
}

export function normalizeSearchText(value) {
    return String(value ?? "")
        .normalize("NFKD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[\u2018\u2019\u201a\u201b\u2032\u00b4`]/g, "'")
        .replace(/[\u201c\u201d\u201e\u201f\u2033]/g, '"')
        .toLowerCase()
        .trim();
}

function splitSearchTokens(value) {
    const normalized = normalizeSearchText(value);
    const rawTokens = normalized.match(/[\p{L}\p{N}]+/gu) || [];
    const tokens = [];
    const seen = new Set();

    for (const rawToken of rawTokens) {
        const token = rawToken.slice(0, SEARCH_TOKEN_MAX_LENGTH);
        if (!token || (token === "s" && rawTokens.length > 1)) continue;
        if (seen.has(token)) continue;

        seen.add(token);
        tokens.push(token);
    }

    return tokens;
}

export function getSearchTokens(value) {
    const tokens = splitSearchTokens(value);
    const meaningfulTokens = tokens.filter((token) => !SEARCH_STOPWORDS.has(token));
    return (meaningfulTokens.length > 0 ? meaningfulTokens : tokens).slice(0, SEARCH_TOKEN_LIMIT);
}

function escapeRegexCharacter(value) {
    return String(value).replace(/[\\\]^$.*+?()[\]{}|-]/g, "\\$&");
}

function buildLooseTokenPattern(token) {
    let pattern = "";

    for (const char of String(token || "")) {
        const variants = SEARCH_CHAR_VARIANTS[char];
        pattern += variants ? `[${variants}]` : escapeRegexCharacter(char);
    }

    return pattern;
}

function buildLooseTokenRegExp(token) {
    return new RegExp(buildLooseTokenPattern(token), "i");
}

function buildAdjacentPhraseRegExp(tokens) {
    if (!tokens.length) return null;
    const pattern = tokens.map(buildLooseTokenPattern).join("[\\s\\S]{0,4}");
    return new RegExp(pattern, "i");
}

function buildExactPhraseRegExp(tokens) {
    if (!tokens.length) return null;
    const pattern = tokens.map(buildLooseTokenPattern).join("[\\s\\S]{0,4}");
    return new RegExp(`^\\s*${pattern}\\s*$`, "i");
}

function buildStartsWithPhraseRegExp(tokens) {
    if (!tokens.length) return null;
    const pattern = tokens.map(buildLooseTokenPattern).join("[\\s\\S]{0,4}");
    return new RegExp(`^\\s*${pattern}`, "i");
}

function buildOrderedTokenRegExp(tokens) {
    if (tokens.length < 2) return null;
    const pattern = tokens.map(buildLooseTokenPattern).join("[\\s\\S]{0,80}");
    return new RegExp(pattern, "i");
}

function getSelectedSearchFieldSpecs(selectedSearchFields) {
    const selectedFieldSet = new Set(normalizeSearchFieldSelection(selectedSearchFields, {
        defaultToAll: false
    }));
    return SEARCH_FIELD_SPECS.filter((spec) => selectedFieldSet.has(spec.field));
}

export function buildMiiSearchPlan(searchText, selectedSearchFields) {
    const tokens = getSearchTokens(searchText);
    const fieldSpecs = getSelectedSearchFieldSpecs(selectedSearchFields);

    return {
        active: Boolean(String(searchText || "").trim() && tokens.length > 0 && fieldSpecs.length > 0),
        rawQuery: String(searchText ?? ""),
        normalizedQuery: normalizeSearchText(searchText).replace(/\s+/g, " "),
        tokens,
        fieldSpecs,
        tokenRegexes: tokens.map(buildLooseTokenRegExp),
        exactPhraseRegex: buildExactPhraseRegExp(tokens),
        startsWithPhraseRegex: buildStartsWithPhraseRegExp(tokens),
        adjacentPhraseRegex: buildAdjacentPhraseRegExp(tokens),
        orderedTokenRegex: buildOrderedTokenRegExp(tokens)
    };
}

export function buildMiiSearchMatchClauses(searchPlan) {
    if (!searchPlan?.active) return [];

    return searchPlan.tokenRegexes.map((tokenRegex) => ({
        $or: searchPlan.fieldSpecs.map((fieldSpec) => ({
            [fieldSpec.path]: tokenRegex
        }))
    }));
}

function mongoStringInput(path) {
    return { $ifNull: [`$${path}`, ""] };
}

function mongoRegexMatch(input, regex) {
    return { $regexMatch: { input, regex } };
}

function mongoScoreIf(condition, score) {
    return { $cond: [condition, score, 0] };
}

export function buildMiiSearchScoreExpression(searchPlan) {
    if (!searchPlan?.active) return 0;

    const scoreParts = [];

    for (const fieldSpec of searchPlan.fieldSpecs) {
        const input = mongoStringInput(fieldSpec.path);
        const tokenMatches = searchPlan.tokenRegexes.map((tokenRegex) => mongoRegexMatch(input, tokenRegex));
        const tokenWeight = Math.max(12, Math.round(fieldSpec.weight / Math.max(searchPlan.tokens.length, 2)));

        if (searchPlan.exactPhraseRegex) {
            scoreParts.push(mongoScoreIf(
                mongoRegexMatch(input, searchPlan.exactPhraseRegex),
                fieldSpec.weight + 1200
            ));
        }

        if (searchPlan.startsWithPhraseRegex) {
            scoreParts.push(mongoScoreIf(
                mongoRegexMatch(input, searchPlan.startsWithPhraseRegex),
                fieldSpec.weight + 780
            ));
        }

        if (searchPlan.adjacentPhraseRegex) {
            scoreParts.push(mongoScoreIf(
                mongoRegexMatch(input, searchPlan.adjacentPhraseRegex),
                fieldSpec.weight + 560
            ));
        }

        if (searchPlan.orderedTokenRegex) {
            scoreParts.push(mongoScoreIf(
                mongoRegexMatch(input, searchPlan.orderedTokenRegex),
                fieldSpec.weight + 340
            ));
        }

        if (tokenMatches.length > 1) {
            scoreParts.push(mongoScoreIf(
                { $and: tokenMatches },
                fieldSpec.weight + 220
            ));
        }

        for (const tokenMatch of tokenMatches) {
            scoreParts.push(mongoScoreIf(tokenMatch, tokenWeight));
        }
    }

    return scoreParts.length > 0 ? { $add: scoreParts } : 0;
}

export function getMiiSearchSort() {
    return { searchScore: -1, votes: -1, uploadedOn: -1, _id: -1 };
}

function getFieldComparableTokens(value) {
    return splitSearchTokens(value).slice(0, SEARCH_FALLBACK_FIELD_TOKEN_LIMIT);
}

function getPhoneticCodes(token) {
    const normalizedToken = normalizeSearchText(token);
    if (normalizedToken.length < 3) return [];
    if (phoneticCache.has(normalizedToken)) return phoneticCache.get(normalizedToken);

    const codes = doubleMetaphone(normalizedToken)
        .filter(Boolean)
        .map((code) => String(code).trim())
        .filter(Boolean);
    const uniqueCodes = [...new Set(codes)];

    phoneticCache.set(normalizedToken, uniqueCodes);
    return uniqueCodes;
}

function hasPhoneticOverlap(leftToken, rightToken) {
    const leftCodes = getPhoneticCodes(leftToken);
    const rightCodes = getPhoneticCodes(rightToken);

    for (const leftCode of leftCodes) {
        for (const rightCode of rightCodes) {
            if (leftCode === rightCode) return true;
            if (Math.min(leftCode.length, rightCode.length) >= 2) {
                if (leftCode.startsWith(rightCode) || rightCode.startsWith(leftCode)) return true;
            }
        }
    }

    return false;
}

function getEditDistanceWithin(left, right, maxDistance) {
    if (Math.abs(left.length - right.length) > maxDistance) {
        return maxDistance + 1;
    }

    let previous = Array.from({ length: right.length + 1 }, (_, index) => index);

    for (let leftIndex = 0; leftIndex < left.length; leftIndex += 1) {
        const current = [leftIndex + 1];
        let rowMinimum = current[0];

        for (let rightIndex = 0; rightIndex < right.length; rightIndex += 1) {
            const substitutionCost = left[leftIndex] === right[rightIndex] ? 0 : 1;
            const nextDistance = Math.min(
                previous[rightIndex + 1] + 1,
                current[rightIndex] + 1,
                previous[rightIndex] + substitutionCost
            );

            current.push(nextDistance);
            rowMinimum = Math.min(rowMinimum, nextDistance);
        }

        if (rowMinimum > maxDistance) {
            return maxDistance + 1;
        }

        previous = current;
    }

    return previous[right.length];
}

function getTokenSimilarity(queryToken, candidateToken) {
    if (!queryToken || !candidateToken) return 0;
    if (queryToken === candidateToken) return 1;

    const shorterLength = Math.min(queryToken.length, candidateToken.length);
    if (shorterLength >= 3) {
        if (queryToken.startsWith(candidateToken) || candidateToken.startsWith(queryToken)) {
            return 0.86;
        }

        if (queryToken.includes(candidateToken) || candidateToken.includes(queryToken)) {
            return 0.74;
        }
    }

    const maxEditDistance = queryToken.length >= 7 ? 2 : (queryToken.length >= 4 ? 1 : 0);
    if (maxEditDistance > 0) {
        const editDistance = getEditDistanceWithin(queryToken, candidateToken, maxEditDistance);
        if (editDistance <= maxEditDistance) {
            return editDistance === 1 ? 0.72 : 0.58;
        }
    }

    if (shorterLength >= 3 && hasPhoneticOverlap(queryToken, candidateToken)) {
        return 0.54;
    }

    return 0;
}

function getBestTokenSimilarity(queryToken, candidateTokens) {
    let bestSimilarity = 0;

    for (const candidateToken of candidateTokens) {
        bestSimilarity = Math.max(bestSimilarity, getTokenSimilarity(queryToken, candidateToken));
        if (bestSimilarity === 1) break;
    }

    return bestSimilarity;
}

export function scoreMiiSearchCandidate(mii, searchPlan) {
    if (!searchPlan?.active) return 0;

    let score = 0;

    for (const fieldSpec of searchPlan.fieldSpecs) {
        const value = String(fieldSpec.getValue(mii) ?? "");
        if (!value.trim()) continue;

        const normalizedValue = normalizeSearchText(value).replace(/\s+/g, " ");
        const fieldTokens = getFieldComparableTokens(value);
        let fieldScore = 0;

        if (searchPlan.normalizedQuery && normalizedValue === searchPlan.normalizedQuery) {
            fieldScore += fieldSpec.weight + 1200;
        }

        if (searchPlan.startsWithPhraseRegex?.test(value)) {
            fieldScore += fieldSpec.weight + 780;
        }

        if (searchPlan.adjacentPhraseRegex?.test(value)) {
            fieldScore += fieldSpec.weight + 560;
        }

        if (searchPlan.orderedTokenRegex?.test(value)) {
            fieldScore += fieldSpec.weight + 340;
        }

        let matchedTokens = 0;
        let similarityScore = 0;

        for (const queryToken of searchPlan.tokens) {
            const directTokenMatch = buildLooseTokenRegExp(queryToken).test(value);
            const bestSimilarity = directTokenMatch
                ? 1
                : getBestTokenSimilarity(queryToken, fieldTokens);

            if (bestSimilarity > 0) {
                matchedTokens += 1;
            }

            similarityScore += bestSimilarity;
        }

        if (matchedTokens === searchPlan.tokens.length) {
            fieldScore += fieldSpec.weight + 190;
        }

        fieldScore += (similarityScore / Math.max(searchPlan.tokens.length, 1)) * fieldSpec.weight;
        score += fieldScore;
    }

    return score;
}

export function rankMiiSearchCandidates(candidates, searchPlan) {
    const threshold = searchPlan.tokens.length > 1 ? 90 : 60;

    return candidates
        .map((mii) => ({
            mii,
            searchScore: scoreMiiSearchCandidate(mii, searchPlan)
        }))
        .filter((entry) => entry.searchScore >= threshold)
        .sort((a, b) => (
            b.searchScore - a.searchScore
            || (b.mii?.votes || 0) - (a.mii?.votes || 0)
            || (b.mii?.uploadedOn || 0) - (a.mii?.uploadedOn || 0)
            || String(b.mii?._id || "").localeCompare(String(a.mii?._id || ""))
        ))
        .map((entry) => ({
            ...entry.mii,
            searchScore: entry.searchScore
        }));
}
