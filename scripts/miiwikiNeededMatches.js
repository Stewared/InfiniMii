import mongoose from "mongoose";

const MIIWIKI_URL = "https://miiwiki.org/wiki/List_of_official_Miis";
const NEEDED_IMAGE_URL = "https://cdn.miiwiki.org/thumb/2/2c/Needed.png/180px-Needed.png";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/infinimii";

function decodeHtml(text) {
    const named = {
        amp: "&",
        apos: "'",
        lt: "<",
        gt: ">",
        nbsp: " ",
        quot: "\""
    };

    return String(text)
        .replace(/&#x([0-9a-f]+);/giu, (_, value) => String.fromCodePoint(parseInt(value, 16)))
        .replace(/&#(\d+);/gu, (_, value) => String.fromCodePoint(parseInt(value, 10)))
        .replace(/&([a-z]+);/giu, (match, name) => named[name.toLowerCase()] ?? match);
}

function textFromHtml(html) {
    return decodeHtml(String(html).replace(/<[^>]+>/gu, "")).replace(/\s+/gu, " ").trim();
}

function normalizeName(value) {
    return decodeHtml(value)
        .normalize("NFD")
        .replace(/\p{Diacritic}/gu, "")
        .toLowerCase()
        .replace(/&/gu, "and")
        .replace(/\bthe\b/gu, "")
        .replace(/\bnintendo\b/gu, "")
        .replace(/\bseries\b/gu, "")
        .replace(/[^a-z0-9]+/gu, "");
}

function stripParenthetical(value) {
    return value.replace(/\s*\([^)]*\)\s*/gu, " ").replace(/\s+/gu, " ").trim();
}

function sectionKeys(sectionTitle) {
    const baseTitle = stripParenthetical(sectionTitle);
    const keys = new Set([
        normalizeName(sectionTitle),
        normalizeName(baseTitle)
    ]);

    const manualAliases = {
        "mariokartwii": ["mariokartwii", "mariokart"],
        "mariokart7": ["mariokart7"],
        "supersmashbrosfor3dswiiu": [
            "supersmashbrosfor3ds",
            "supersmashbrosforwiiu",
            "supersmashbrosfor3dswiiu"
        ],
        "supersmashbrosfor3ds": ["supersmashbrosfor3ds"],
        "supersmashbrosforwiiu": ["supersmashbrosforwiiu"],
        "streetpassmiiplaza": ["streetpassmiiplaza"],
        "swapnote": ["swapnote", "swapdoodle"],
        "switchsports": ["switchsports"],
        "nintendoswitchsports": ["switchsports"],
        "miitopia3ds": ["miitopia"],
        "miitopiaswitch": ["miitopia"],
        "mypokemonranch": ["mypokemonranch"],
        "wiisportsclub": ["wiisportsclub"],
        "miichannel": ["miichannel", "miimaker"]
    };

    for (const key of [...keys]) {
        for (const alias of manualAliases[key] ?? []) {
            keys.add(alias);
        }
    }

    return keys;
}

function platformHints(sectionTitle) {
    const lower = sectionTitle.toLowerCase();
    const hints = new Set();

    if (lower.includes("(3ds)") || lower.includes("nintendo 3ds")) hints.add("3DS");
    if (lower.includes("(switch)") || lower.includes("nintendo switch")) hints.add("Switch");
    if (lower.includes("wii u")) hints.add("Wii U");
    if (lower.includes("nintendo ds") || lower.includes(" ds")) hints.add("DS");

    return hints;
}

function flattenCategories(categories, output = []) {
    for (const category of categories ?? []) {
        if (!category?.path) continue;

        const segments = String(category.path).split("/");
        output.push({
            name: category.name,
            path: category.path,
            leaf: segments.at(-1),
            root: segments[0],
            normalizedLeaf: normalizeName(segments.at(-1)),
            normalizedPath: normalizeName(category.path)
        });

        flattenCategories(category.children, output);
    }

    return output;
}

function parseNeededSections(html) {
    const h3Pattern = /<h3\b[^>]*>[\s\S]*?<span class="mw-headline"[^>]*>([\s\S]*?)<\/span>[\s\S]*?<\/h3>/giu;
    const headings = [...html.matchAll(h3Pattern)].map((match) => ({
        title: textFromHtml(match[1]),
        start: match.index,
        end: match.index + match[0].length
    }));

    return headings
        .map((heading, index) => {
            const nextHeading = headings[index + 1]?.start ?? html.indexOf("<h2", heading.end);
            const sectionHtml = html.slice(heading.end, nextHeading === -1 ? html.length : nextHeading);
            const neededCount = sectionHtml.split(NEEDED_IMAGE_URL).length - 1;
            return {
                title: heading.title,
                neededCount
            };
        })
        .filter((section) => section.neededCount > 0);
}

function categoryMatchesForSection(section, categories) {
    const keys = sectionKeys(section.title);
    const hints = platformHints(section.title);

    return categories.filter((category) => {
        const leafMatches = category.normalizedLeaf.length >= 5 && [...keys].some((key) => (
            key.length >= 5 &&
            (category.normalizedLeaf === key ||
                category.normalizedLeaf.includes(key) ||
                key.includes(category.normalizedLeaf))
        ));

        if (!leafMatches) return false;
        if (hints.size === 0) return true;

        return hints.has(category.root) || category.path === category.leaf;
    });
}

async function getOfficialCategoryData() {
    await mongoose.connect(MONGODB_URI);

    const db = mongoose.connection.db;
    const settings = await db.collection("settings").findOne({});
    const configuredCategories = flattenCategories(settings?.officialCategories?.categories ?? []);
    const counts = await db.collection("miis").aggregate([
        { $unwind: "$officialCategories" },
        { $group: { _id: "$officialCategories", count: { $sum: 1 } } }
    ]).toArray();

    await mongoose.disconnect();

    const countByPath = new Map(counts.map((item) => [item._id, item.count]));
    return configuredCategories.map((category) => ({
        ...category,
        miiCount: countByPath.get(category.path) ?? 0
    }));
}

const response = await fetch(MIIWIKI_URL);
if (!response.ok) {
    throw new Error(`Failed to fetch ${MIIWIKI_URL}: ${response.status} ${response.statusText}`);
}

const html = await response.text();
const neededSections = parseNeededSections(html);
const categories = await getOfficialCategoryData();
const matches = neededSections.map((section) => ({
    ...section,
    matches: categoryMatchesForSection(section, categories)
        .sort((a, b) => a.path.localeCompare(b.path))
        .map(({ path, miiCount }) => ({ path, miiCount }))
}));

console.log(JSON.stringify({
    source: MIIWIKI_URL,
    neededImageUrl: NEEDED_IMAGE_URL,
    neededSections,
    matches: matches.filter((section) => section.matches.length > 0),
    unmatched: matches.filter((section) => section.matches.length === 0)
}, null, 2));
